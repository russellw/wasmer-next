//! Live adapter for the SDK's retained public virtual-network provider type.
use crate::service::Services;
use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, Wake, Waker},
};
use tokio::sync::Notify;
use virtual_net::{
    DynVirtualNetworking, NetworkError, SocketStatus, VirtualTcpSocket, VirtualUdpSocket,
};
use wasixv2_abi::Errno;
use wasixv2_vnet::{
    Answer, Backend, BackendDatagram, BackendStream, Domain, Found, InboundSink, Lookup,
    LookupDone, LookupError, Publication, Room, Shutdown, StreamState,
};
use wasixv2_wait::{PollMask, PollTable, Pollable, WaitQueue};

fn errno(error: NetworkError) -> Errno {
    wasixv2_vnet_host::errno_from_io(&virtual_net::net_error_into_io_err(error))
}
fn any(domain: Domain) -> SocketAddr {
    match domain {
        Domain::Inet => (Ipv4Addr::UNSPECIFIED, 0).into(),
        Domain::Inet6 => (Ipv6Addr::UNSPECIFIED, 0).into(),
    }
}
fn mask() -> PollMask {
    PollMask::IN | PollMask::OUT | PollMask::ERR | PollMask::HUP
}
struct TaskWake(Waker);
impl wasixv2_wait::WaitEntry for TaskWake {
    fn wake(&self, _: PollMask) -> bool {
        self.0.wake_by_ref();
        true
    }
}
struct QueueWake(WaitQueue);
impl Wake for QueueWake {
    fn wake(self: Arc<Self>) {
        self.0.wake(mask());
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.wake(mask());
    }
}
fn waker(queue: &WaitQueue) -> Waker {
    Waker::from(Arc::new(QueueWake(queue.clone())))
}
#[derive(Default)]
struct Cancellation {
    closed: std::sync::atomic::AtomicBool,
    changed: Notify,
}
impl Cancellation {
    fn close(&self) -> bool {
        let first = !self.closed.swap(true, std::sync::atomic::Ordering::AcqRel);
        if first {
            self.changed.notify_waiters();
        }
        first
    }
    fn closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Acquire)
    }
}

struct CancelOnDrop(Arc<Cancellation>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}
trait Endpoint: Send + Sync {
    fn close(&self);
}
#[derive(Default)]
struct State {
    failure: Option<String>,
    closed: bool,
    active: usize,
    endpoints: Vec<Weak<dyn Endpoint>>,
}
struct Group {
    state: Mutex<State>,
    changed: Notify,
    services: Services,
}
struct Lease(Arc<Group>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().active -= 1;
        self.0.changed.notify_waiters();
    }
}
impl Group {
    fn resource(self: &Arc<Self>) -> Result<Lease, Errno> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(Errno::ENETDOWN);
        }
        state.active = state.active.checked_add(1).ok_or(Errno::ENOBUFS)?;
        Ok(Lease(self.clone()))
    }
    fn record_close(&self, result: virtual_net::Result<()>) {
        if let Err(error) = result {
            self.state
                .lock()
                .unwrap()
                .failure
                .get_or_insert_with(|| error.to_string());
        }
    }
    fn spawn(
        self: &Arc<Self>,
        work: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), Errno> {
        {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Err(Errno::ENETDOWN);
            }
            state.active = state.active.checked_add(1).ok_or(Errno::ENOBUFS)?;
        }
        let lease = Lease(self.clone());
        self.services
            .cleanup(async move {
                work.await;
                drop(lease);
                Ok(())
            })
            .map_err(|_| Errno::EIO)
    }
    fn cleanup(
        self: &Arc<Self>,
        work: impl Future<Output = virtual_net::Result<()>> + Send + 'static,
    ) {
        {
            let mut state = self.state.lock().unwrap();
            state.active = state
                .active
                .checked_add(1)
                .expect("network cleanup count exhausted");
        }
        let lease = Lease(self.clone());
        let group = self.clone();
        self.services
            .cleanup(async move {
                if let Err(error) = work.await {
                    group
                        .state
                        .lock()
                        .unwrap()
                        .failure
                        .get_or_insert_with(|| error.to_string());
                }
                drop(lease);
                Ok(())
            })
            .expect("live network resource retains its service cleanup lease");
    }
    async fn wait_scoped<T>(
        &self,
        cancel: &Cancellation,
        work: impl Future<Output = T>,
    ) -> Option<T> {
        tokio::pin!(work);
        loop {
            let canceled = cancel.changed.notified();
            tokio::pin!(canceled);
            canceled.as_mut().enable();
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.closed() || cancel.closed() {
                return None;
            }
            tokio::select! {biased;_=&mut canceled=>{},_=&mut changed=>{},result=&mut work=>return Some(result)}
        }
    }
    fn register(&self, endpoint: Arc<dyn Endpoint>) -> Result<(), Errno> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            drop(state);
            endpoint.close();
            return Err(Errno::ENETDOWN);
        }
        state
            .endpoints
            .retain(|endpoint| endpoint.strong_count() > 0);
        state.endpoints.push(Arc::downgrade(&endpoint));
        Ok(())
    }
    fn closed(&self) -> bool {
        self.state.lock().unwrap().closed
    }
    async fn wait<T>(&self, work: impl Future<Output = T>) -> Option<T> {
        tokio::pin!(work);
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.closed() {
                return None;
            }
            tokio::select! { biased; _=&mut changed=>{}, result=&mut work=>return Some(result) }
        }
    }
    async fn close(&self) -> io::Result<()> {
        let endpoints = {
            let mut state = self.state.lock().unwrap();
            state.closed = true;
            std::mem::take(&mut state.endpoints)
        };
        for endpoint in endpoints.into_iter().filter_map(|e| e.upgrade()) {
            endpoint.close();
        }
        self.changed.notify_waiters();
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.state.lock().unwrap().active == 0 {
                break;
            }
            changed.await;
        }
        self.state
            .lock()
            .unwrap()
            .failure
            .clone()
            .map_or(Ok(()), |message| Err(io::Error::other(message)))
    }
}
pub(crate) struct ProviderNetwork {
    control: Arc<Controls>,
    provider: DynVirtualNetworking,
    group: Arc<Group>,
}
impl ProviderNetwork {
    pub(crate) fn new(provider: DynVirtualNetworking, services: Services) -> Arc<Self> {
        let group = Arc::new(Group {
            state: Mutex::default(),
            changed: Notify::new(),
            services,
        });
        let control = Arc::new(Controls {
            provider: provider.clone(),
            group: group.clone(),
            serial: Arc::new(tokio::sync::Mutex::new(())),
        });
        Arc::new(Self {
            provider,
            group,
            control,
        })
    }

    /// Host-side readiness probe using the same provider and owned job scope.
    pub(crate) async fn probe_tcp(
        self: &Arc<Self>,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> virtual_net::Result<()> {
        let cancellation = Arc::new(Cancellation::default());
        let _cancel = CancelOnDrop(cancellation.clone());
        let (send, result) = tokio::sync::oneshot::channel();
        let group = self.group.clone();
        let provider = self.provider.clone();
        self.group
            .spawn(async move {
                let mut outcome = match group
                    .wait_scoped(&cancellation, provider.connect_tcp(local, peer))
                    .await
                {
                    Some(Ok(mut socket)) => {
                        let ready = group
                            .wait_scoped(
                                &cancellation,
                                futures::future::poll_fn(|cx| {
                                    if let Err(error) = socket.set_handler(cx.waker().into()) {
                                        return Poll::Ready(Err(error));
                                    }
                                    match socket.status() {
                                        Ok(SocketStatus::Opened) => Poll::Ready(Ok(())),
                                        Ok(SocketStatus::Opening) => {
                                            if let Poll::Ready(Err(error)) =
                                                socket.poll_write_ready(cx)
                                            {
                                                return Poll::Ready(Err(error));
                                            }
                                            match socket.status() {
                                                Ok(SocketStatus::Opened) => Poll::Ready(Ok(())),
                                                Ok(SocketStatus::Failed) => {
                                                    Poll::Ready(Err(socket
                                                        .last_error()
                                                        .ok()
                                                        .flatten()
                                                        .unwrap_or(
                                                            NetworkError::ConnectionRefused,
                                                        )))
                                                }
                                                Ok(SocketStatus::Closed) => {
                                                    Poll::Ready(Err(NetworkError::ConnectionReset))
                                                }
                                                Err(error) => Poll::Ready(Err(error)),
                                                Ok(SocketStatus::Opening) => Poll::Pending,
                                            }
                                        }
                                        Ok(SocketStatus::Failed) => Poll::Ready(Err(socket
                                            .last_error()
                                            .ok()
                                            .flatten()
                                            .unwrap_or(NetworkError::ConnectionRefused))),
                                        Ok(SocketStatus::Closed) => {
                                            Poll::Ready(Err(NetworkError::ConnectionReset))
                                        }
                                        Err(error) => Poll::Ready(Err(error)),
                                    }
                                }),
                            )
                            .await
                            .unwrap_or(Err(NetworkError::ConnectionAborted));
                        socket.remove_handler();
                        let closed = socket.close();
                        group.record_close(closed);
                        ready.and(closed)
                    }
                    Some(Err(error)) => Err(error),
                    None => Err(NetworkError::ConnectionAborted),
                };
                if group.closed() || cancellation.closed() {
                    outcome = Err(NetworkError::ConnectionAborted);
                }
                let _ = send.send(outcome);
            })
            .map_err(|_| NetworkError::ConnectionAborted)?;
        result.await.unwrap_or(Err(NetworkError::ConnectionAborted))
    }

    pub(crate) async fn close(&self) -> io::Result<()> {
        self.group.close().await
    }
}
enum Socket<T> {
    Pending,
    Ready(T),
    Failed(Option<Errno>),
    Closed,
}
struct Stream {
    group: Arc<Group>,
    service_lease: Mutex<Option<crate::service::Lease>>,
    resource_lease: Mutex<Option<Lease>>,
    cancellation: Arc<Cancellation>,
    options: Mutex<Vec<(i32, i32, Vec<u8>)>>,
    socket: Mutex<Socket<Box<dyn VirtualTcpSocket + Sync>>>,
    queue: WaitQueue,
    peer: SocketAddr,
}
impl Stream {
    fn new(group: Arc<Group>, queue: WaitQueue, peer: SocketAddr) -> Result<Arc<Self>, Errno> {
        let resource = group.resource()?;
        let lease = group
            .services
            .retain_cleanup()
            .map_err(|_| Errno::ENETDOWN)?;
        Ok(Arc::new(Self {
            group,
            service_lease: Mutex::new(Some(lease)),
            resource_lease: Mutex::new(Some(resource)),
            cancellation: Arc::default(),
            options: Mutex::default(),
            socket: Mutex::new(Socket::Pending),
            queue,
            peer,
        }))
    }
    fn ready(&self, result: virtual_net::Result<Box<dyn VirtualTcpSocket + Sync>>) {
        let mut state = self.socket.lock().unwrap();
        if matches!(*state, Socket::Closed) {
            if let Ok(mut socket) = result {
                self.group.record_close(socket.close());
            }
            return;
        }
        *state = match result {
            Ok(mut socket) => {
                match socket
                    .set_handler((&waker(&self.queue)).into())
                    .and_then(|()| {
                        for (level, name, value) in self.options.lock().unwrap().iter() {
                            apply_stream_option(socket.as_mut(), *level, *name, value)?;
                        }
                        Ok(())
                    }) {
                    Ok(()) => Socket::Ready(socket),
                    Err(error) => {
                        self.group.record_close(socket.close());
                        Socket::Failed(Some(errno(error)))
                    }
                }
            }
            Err(error) => Socket::Failed(Some(errno(error))),
        };
        drop(state);
        self.queue.wake(mask());
    }
    fn with<T>(
        &self,
        f: impl FnOnce(&mut (dyn VirtualTcpSocket + Sync)) -> virtual_net::Result<T>,
    ) -> Result<T, Errno> {
        match &mut *self.socket.lock().unwrap() {
            Socket::Ready(socket) => f(socket.as_mut()).map_err(errno),
            Socket::Pending => Err(Errno::EAGAIN),
            Socket::Failed(error) => Err(error.unwrap_or(Errno::ECONNRESET)),
            Socket::Closed => Err(Errno::ENOTCONN),
        }
    }
}
impl Endpoint for Stream {
    fn close(&self) {
        if !self.cancellation.close() {
            return;
        }
        let old = std::mem::replace(&mut *self.socket.lock().unwrap(), Socket::Closed);
        let lease = self.service_lease.lock().unwrap().take();
        let resource = self.resource_lease.lock().unwrap().take();
        self.group.cleanup(async move {
            let result = if let Socket::Ready(mut socket) = old {
                socket.remove_handler();
                socket.close()
            } else {
                Ok(())
            };
            drop(lease);
            drop(resource);
            result
        });
        self.queue.wake(mask());
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.close();
    }
}
impl Pollable for Stream {
    fn poll(&self, mut table: Option<&mut PollTable<'_>>) -> PollMask {
        if let Some(table) = &mut table {
            table.wait_on(&self.queue);
        }
        let mut state = self.socket.lock().unwrap();
        let mut events = PollMask::empty();
        match &mut *state {
            Socket::Pending => {}
            Socket::Closed => return PollMask::HUP | PollMask::IN,
            Socket::Failed(_) => return PollMask::ERR | PollMask::HUP,
            Socket::Ready(socket) => {
                let wake = waker(&self.queue);
                let mut cx = Context::from_waker(&wake);
                match socket.poll_read_ready(&mut cx) {
                    Poll::Ready(Ok(_)) => events |= PollMask::IN,
                    Poll::Ready(Err(_)) => events |= PollMask::ERR,
                    _ => {}
                }
                match socket.poll_write_ready(&mut cx) {
                    Poll::Ready(Ok(_)) => events |= PollMask::OUT,
                    Poll::Ready(Err(_)) => events |= PollMask::ERR,
                    _ => {}
                }
                if matches!(socket.status(), Ok(SocketStatus::Closed)) {
                    events |= PollMask::HUP | PollMask::IN;
                }
            }
        }
        events
    }
}
impl BackendStream for Stream {
    fn state(&self) -> StreamState {
        match &*self.socket.lock().unwrap() {
            Socket::Pending => StreamState::Connecting,
            Socket::Ready(socket) => match socket.status() {
                Ok(SocketStatus::Opening) => StreamState::Connecting,
                Ok(SocketStatus::Opened) => StreamState::Established,
                _ => StreamState::Closed,
            },
            _ => StreamState::Closed,
        }
    }
    fn read(&self, buf: &mut [u8], peek: bool) -> Result<usize, Errno> {
        self.with(|s| virtual_net::try_recv_initialized(s, buf, peek))
    }
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        self.with(|s| s.try_send(buf))
    }
    fn write_urgent(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EOPNOTSUPP)
    }
    fn read_urgent(&self, _: bool) -> Result<u8, Errno> {
        Err(Errno::EOPNOTSUPP)
    }
    fn at_mark(&self) -> bool {
        false
    }
    fn shutdown(&self, how: Shutdown) -> Result<(), Errno> {
        self.with(|s| {
            s.shutdown(match how {
                Shutdown::Read => std::net::Shutdown::Read,
                Shutdown::Write => std::net::Shutdown::Write,
                Shutdown::Both => std::net::Shutdown::Both,
            })
        })
    }
    fn take_error(&self) -> Option<Errno> {
        match &mut *self.socket.lock().unwrap() {
            Socket::Failed(error) => error.take(),
            Socket::Ready(socket) => socket.last_error().ok().flatten().map(errno),
            _ => None,
        }
    }
    fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    fn input_len(&self) -> usize {
        self.with(|s| {
            let wake = waker(&self.queue);
            match s.poll_read_ready(&mut Context::from_waker(&wake)) {
                Poll::Ready(result) => result,
                Poll::Pending => Ok(0),
            }
        })
        .unwrap_or(0)
    }
    fn set_option(&self, level: i32, name: i32, value: &[u8]) -> Result<(), Errno> {
        validate_stream_option(level, name, value).map_err(errno)?;
        let mut state = self.socket.lock().unwrap();
        match &mut *state {
            Socket::Ready(socket) => {
                apply_stream_option(socket.as_mut(), level, name, value).map_err(errno)
            }
            Socket::Pending => {
                let mut options = self.options.lock().unwrap();
                options.retain(|(l, n, _)| (*l, *n) != (level, name));
                options.push((level, name, value.to_vec()));
                Ok(())
            }
            Socket::Failed(e) => Err(e.unwrap_or(Errno::ECONNRESET)),
            Socket::Closed => Err(Errno::ENOTCONN),
        }
    }
}
fn validate_stream_option(level: i32, name: i32, value: &[u8]) -> virtual_net::Result<()> {
    let length = match (level, name) {
        (1, 13) => 8,
        (6, 1) | (1, 9) | (1, 5) | (1, 7) | (1, 8) | (0, 2) | (41, 16) => 4,
        _ => return Ok(()),
    };
    if value.len() < length {
        Err(NetworkError::InvalidInput)
    } else {
        Ok(())
    }
}
fn apply_stream_option(
    socket: &mut (dyn VirtualTcpSocket + Sync),
    level: i32,
    name: i32,
    value: &[u8],
) -> virtual_net::Result<()> {
    validate_stream_option(level, name, value)?;
    if !matches!(
        (level, name),
        (1, 13) | (6, 1) | (1, 9) | (1, 5) | (1, 7) | (1, 8) | (0, 2) | (41, 16)
    ) {
        return Ok(());
    }
    let n = i32::from_le_bytes(value[..4].try_into().unwrap());
    match (level, name) {
        (1, 13) => {
            let seconds = i32::from_le_bytes(value[4..8].try_into().unwrap());
            if seconds < 0 {
                return Err(NetworkError::InvalidInput);
            }
            socket.set_linger((n != 0).then(|| std::time::Duration::from_secs(seconds as u64)))
        }
        (6, 1) => socket.set_nodelay(n != 0),
        (1, 9) => socket.set_keepalive(n != 0),
        (1, 5) => socket.set_dontroute(n != 0),
        (1, 7) => socket.set_send_buf_size(n.max(0) as usize),
        (1, 8) => socket.set_recv_buf_size(n.max(0) as usize),
        (0, 2) | (41, 16) => socket.set_ttl(n as u32),
        _ => Ok(()),
    }
}

struct Datagram {
    group: Arc<Group>,
    service_lease: Mutex<Option<crate::service::Lease>>,
    resource_lease: Mutex<Option<Lease>>,
    cancellation: Arc<Cancellation>,
    socket: Mutex<Socket<Box<dyn VirtualUdpSocket + Sync>>>,
    queue: WaitQueue,
    peer: Mutex<Option<SocketAddr>>,
}
impl Datagram {
    fn new(group: Arc<Group>, queue: WaitQueue) -> Result<Arc<Self>, Errno> {
        let resource = group.resource()?;
        let lease = group
            .services
            .retain_cleanup()
            .map_err(|_| Errno::ENETDOWN)?;
        Ok(Arc::new(Self {
            group,
            service_lease: Mutex::new(Some(lease)),
            resource_lease: Mutex::new(Some(resource)),
            cancellation: Arc::default(),
            socket: Mutex::new(Socket::Pending),
            queue,
            peer: Mutex::new(None),
        }))
    }
    fn ready(&self, result: virtual_net::Result<Box<dyn VirtualUdpSocket + Sync>>) {
        let mut state = self.socket.lock().unwrap();
        if matches!(*state, Socket::Closed) {
            return;
        }
        *state = match result {
            Ok(mut socket) => match socket.set_handler((&waker(&self.queue)).into()) {
                Ok(()) => Socket::Ready(socket),
                Err(e) => Socket::Failed(Some(errno(e))),
            },
            Err(e) => Socket::Failed(Some(errno(e))),
        };
        drop(state);
        self.queue.wake(mask());
    }
    fn with<T>(
        &self,
        f: impl FnOnce(&mut (dyn VirtualUdpSocket + Sync)) -> virtual_net::Result<T>,
    ) -> Result<T, Errno> {
        match &mut *self.socket.lock().unwrap() {
            Socket::Ready(s) => f(s.as_mut()).map_err(errno),
            Socket::Pending => Err(Errno::EAGAIN),
            Socket::Failed(e) => Err(e.unwrap_or(Errno::EIO)),
            Socket::Closed => Err(Errno::ENETDOWN),
        }
    }
}
impl Endpoint for Datagram {
    fn close(&self) {
        if !self.cancellation.close() {
            return;
        }
        let old = std::mem::replace(&mut *self.socket.lock().unwrap(), Socket::Closed);
        let lease = self.service_lease.lock().unwrap().take();
        let resource = self.resource_lease.lock().unwrap().take();
        self.group.cleanup(async move {
            if let Socket::Ready(mut socket) = old {
                socket.remove_handler();
            }
            drop(lease);
            drop(resource);
            Ok(())
        });
        self.queue.wake(mask());
    }
}
impl Drop for Datagram {
    fn drop(&mut self) {
        self.close();
    }
}
impl Pollable for Datagram {
    fn poll(&self, mut table: Option<&mut PollTable<'_>>) -> PollMask {
        if let Some(table) = &mut table {
            table.wait_on(&self.queue);
        }
        let mut events = match self.recv_from(&mut [], true) {
            Ok(_) => PollMask::IN,
            Err(Errno::EAGAIN) => PollMask::empty(),
            Err(_) => PollMask::ERR,
        };
        let wake = waker(&self.queue);
        let mut cx = Context::from_waker(&wake);
        match &mut *self.socket.lock().unwrap() {
            Socket::Ready(socket) => match socket.poll_write_ready(&mut cx) {
                Poll::Ready(Ok(_)) => events |= PollMask::OUT,
                Poll::Ready(Err(_)) => events |= PollMask::ERR,
                _ => {}
            },
            Socket::Closed => events |= PollMask::ERR | PollMask::HUP,
            Socket::Failed(_) => events |= PollMask::ERR,
            Socket::Pending => {}
        }
        events
    }
}
impl BackendDatagram for Datagram {
    fn send_to(&self, data: &[u8], to: SocketAddr) -> Result<usize, Errno> {
        self.with(|s| s.try_send_to(data, to))
    }
    fn connect(&self, peer: Option<SocketAddr>) -> Result<(), Errno> {
        *self.peer.lock().unwrap() = peer;
        Ok(())
    }
    fn take_error(&self) -> Option<Errno> {
        match &mut *self.socket.lock().unwrap() {
            Socket::Failed(e) => e.take(),
            Socket::Ready(s) => s.last_error().ok().flatten().map(errno),
            _ => None,
        }
    }
    fn recv_from(&self, buf: &mut [u8], peek: bool) -> Result<(usize, usize, SocketAddr), Errno> {
        let peer = *self.peer.lock().unwrap();
        let mut discarded = false;
        let result = self.with(|socket| {
            let wake = waker(&self.queue);
            let mut cx = Context::from_waker(&wake);
            match socket.poll_read_ready(&mut cx) {
                Poll::Pending => return Err(NetworkError::WouldBlock),
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Ready(Ok(_)) => {}
            }
            let mut full = vec![0; 65535];
            let (n, from) = virtual_net::try_recv_from_initialized(socket, &mut full, peek)?;
            if peer.is_some_and(|peer| peer != from) {
                if peek {
                    virtual_net::try_recv_from_initialized(socket, &mut full, false)?;
                }
                discarded = true;
                return Err(NetworkError::WouldBlock);
            }
            let copied = n.min(buf.len());
            buf[..copied].copy_from_slice(&full[..copied]);
            Ok((copied, n, from))
        });
        // One rejected packet per entry keeps provider work bounded; request
        // another readiness check after releasing the socket lock.
        if discarded {
            self.queue.wake(PollMask::IN);
        }
        result
    }
    fn input_len(&self) -> usize {
        self.recv_from(&mut [], true)
            .map(|(_, full, _)| full)
            .unwrap_or(0)
    }
    fn set_option(&self, level: i32, name: i32, value: &[u8]) -> Result<(), Errno> {
        let bytes: [u8; 4] = value.try_into().map_err(|_| Errno::EINVAL)?;
        let n = i32::from_le_bytes(bytes);
        self.with(|s| match (level, name) {
            (1, 6) => s.set_broadcast(n != 0),
            (0, 2) | (41, 16) => s.set_ttl(n as u32),
            (0, 33) => s.set_multicast_ttl_v4(n as u32),
            (0, 34) => s.set_multicast_loop_v4(n != 0),
            (41, 19) => s.set_multicast_loop_v6(n != 0),
            _ => Ok(()),
        })
    }
}
struct Published {
    host: SocketAddr,
    cancellation: Arc<Cancellation>,
}
impl Publication for Published {
    fn host_addr(&self) -> SocketAddr {
        self.host
    }
}
impl Drop for Published {
    fn drop(&mut self) {
        self.cancellation.close();
    }
}
impl Backend for ProviderNetwork {
    fn provider(&self) -> Option<Arc<dyn wasixv2_vnet::provider::Provider>> {
        Some(self.control.clone())
    }
    fn connect(&self, peer: SocketAddr, queue: WaitQueue) -> Result<Arc<dyn BackendStream>, Errno> {
        let stream = Stream::new(self.group.clone(), queue, peer)?;
        self.group.register(stream.clone())?;
        let output = Arc::downgrade(&stream);
        let cancellation = stream.cancellation.clone();
        let provider = self.provider.clone();
        let local = any(if peer.is_ipv4() {
            Domain::Inet
        } else {
            Domain::Inet6
        });
        let group = self.group.clone();
        self.group.spawn(async move {
            if let Some(result) = group
                .wait_scoped(&cancellation, provider.connect_tcp(local, peer))
                .await
            {
                if let Some(output) = output.upgrade() {
                    output.ready(result);
                } else if let Ok(mut socket) = result {
                    group.record_close(socket.close());
                }
            }
        })?;
        Ok(stream)
    }
    fn datagram(
        &self,
        domain: Domain,
        queue: WaitQueue,
    ) -> Result<Arc<dyn BackendDatagram>, Errno> {
        let socket = Datagram::new(self.group.clone(), queue)?;
        self.group.register(socket.clone())?;
        let output = Arc::downgrade(&socket);
        let cancellation = socket.cancellation.clone();
        let provider = self.provider.clone();
        let group = self.group.clone();
        self.group.spawn(async move {
            if let Some(result) = group
                .wait_scoped(&cancellation, provider.bind_udp(any(domain), false, false))
                .await
                && let Some(output) = output.upgrade()
            {
                output.ready(result);
            }
        })?;
        Ok(socket)
    }
    fn publish(
        &self,
        host: SocketAddr,
        _backlog: u32,
        sink: Arc<dyn InboundSink>,
    ) -> io::Result<Box<dyn Publication>> {
        if host.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "asynchronous custom provider publication requires an explicit port",
            ));
        }
        let cancellation = Arc::new(Cancellation::default());
        let stop = cancellation.clone();
        let group = self.group.clone();
        let provider = self.provider.clone();
        self.group.spawn(async move{
            let Some(Ok(mut listener))=group.wait_scoped(&stop,provider.listen_tcp(host,host.is_ipv6(),false,false)).await else{return;};
            loop{
                let canceled=stop.changed.notified();tokio::pin!(canceled);canceled.as_mut().enable();
                let closing=group.changed.notified();tokio::pin!(closing);closing.as_mut().enable();
                if stop.closed()||group.closed(){break;}
                let mut registrations=Vec::new();
                let accepted=futures::future::poll_fn(|cx|{
                    registrations.clear();
                    let mut register=|queue:&WaitQueue,_:PollMask|{registrations.push(queue.add(Arc::new(TaskWake(cx.waker().clone()))));};
                    let mut table=PollTable::new(PollMask::empty(),&mut register);
                    match sink.poll_room(Some(&mut table)){Room::Gone=>return Poll::Ready(None),Room::Full=>return Poll::Pending,Room::Ready=>{}}
                    if listener.set_handler(cx.waker().into()).is_err(){return Poll::Ready(None);}
                    match listener.try_accept(){Ok(result)=>Poll::Ready(Some(result)),Err(NetworkError::WouldBlock)=>Poll::Pending,Err(_)=>Poll::Ready(None)}
                });
                tokio::select!{ result=accepted=>{let Some((socket,peer))=result else{break;};let queue=WaitQueue::default();let Ok(stream)=Stream::new(group.clone(),queue.clone(),peer)else{break;};stream.ready(Ok(socket));if group.register(stream.clone()).is_err(){break;}
                    if stop.closed()||group.closed(){stream.close();break;}let _=sink.incoming(stream,queue);}, _=&mut canceled=>{}, _=&mut closing=>{} }
            }
            listener.remove_handler();
        }).map_err(|e|io::Error::from_raw_os_error(e.0))?;
        Ok(Box::new(Published { host, cancellation }))
    }
    fn lookup(&self, lookup: Lookup, done: LookupDone) {
        let Lookup::Name(name) = lookup else {
            done(Err(LookupError::Failed));
            return;
        };
        let provider = self.provider.clone();
        let completion = Arc::new(Mutex::new(Some(done)));
        let output = completion.clone();
        let group = self.group.clone();
        if self
            .group
            .spawn(async move {
                let result = match group.wait(provider.resolve(&name, None, None)).await {
                    Some(Ok(addrs)) if !group.closed() => Ok(Found {
                        answer: Answer::Addrs {
                            canonical: name,
                            addrs,
                        },
                        ttl: 0,
                    }),
                    _ => Err(LookupError::Failed),
                };
                let done = output.lock().unwrap().take();
                if let Some(done) = done {
                    done(result);
                }
            })
            .is_err()
        {
            let done = completion.lock().unwrap().take();
            if let Some(done) = done {
                done(Err(LookupError::Failed));
            }
        }
    }
}
#[cfg(test)]
mod tests;

struct Controls {
    provider: DynVirtualNetworking,
    group: Arc<Group>,
    serial: Arc<tokio::sync::Mutex<()>>,
}
impl wasixv2_vnet::provider::Provider for Controls {
    fn start(&self, request: wasixv2_vnet::provider::Request, done: wasixv2_vnet::provider::Done) {
        use wasixv2_vnet::provider::{Completion, Snapshot};
        let provider = self.provider.clone();
        let serial = self.serial.clone();
        let group = self.group.clone();
        let completion = Arc::new(Mutex::new(Some(done)));
        let output = completion.clone();
        if self
            .group
            .spawn(async move {
                let mut snapshot = Snapshot::default();
                let mut reconciliation = None;
                let mutates = request.mutates();
                let changes_active = matches!(
                    request,
                    wasixv2_vnet::provider::Request::Bridge { .. }
                        | wasixv2_vnet::provider::Request::Unbridge
                );
                let result = if let Some(_serial) = group.wait(serial.lock()).await {
                    match group
                        .wait(control(provider.as_ref(), request, &mut snapshot))
                        .await
                    {
                        Some(result) => result,
                        None => {
                            if mutates {
                                reconciliation = Some(Errno::ENETDOWN);
                                snapshot.active_unknown = changes_active;
                            }
                            Err(Errno::ENETDOWN)
                        }
                    }
                } else {
                    Err(Errno::ENETDOWN)
                };
                let done = output.lock().unwrap().take();
                if let Some(done) = done {
                    done(Completion {
                        result,
                        snapshot,
                        reconciliation,
                    });
                }
            })
            .is_err()
        {
            let done = completion.lock().unwrap().take();
            if let Some(done) = done {
                done(Completion::error(Errno::ENETDOWN));
            }
        }
    }
}
async fn control(
    provider: &dyn virtual_net::VirtualNetworking,
    request: wasixv2_vnet::provider::Request,
    snapshot: &mut wasixv2_vnet::provider::Snapshot,
) -> Result<wasixv2_vnet::provider::Reply, Errno> {
    use wasixv2_vnet::provider::{Cidr, Reply, Request, Route, Security};
    let reply = match request {
        Request::Bridge {
            network,
            token,
            security,
        } => {
            let security = match security {
                Security::Unencrypted => virtual_net::StreamSecurity::Unencrypted,
                Security::AnyEncryption => virtual_net::StreamSecurity::AnyEncryption,
                Security::ClassicEncryption => virtual_net::StreamSecurity::ClassicEncryption,
                Security::DoubleEncryption => virtual_net::StreamSecurity::DoubleEncryption,
            };
            provider
                .bridge(&network, &token, security)
                .await
                .map_err(errno)?;
            snapshot.active = Some(true);
            Reply::None
        }
        Request::Unbridge => {
            provider.unbridge().await.map_err(errno)?;
            snapshot.active = Some(false);
            Reply::None
        }
        Request::Dhcp => Reply::Acquired(provider.dhcp_acquire().await.map_err(errno)?),
        Request::AddAddress(cidr) => {
            provider.ip_add(cidr.ip, cidr.prefix).await.map_err(errno)?;
            Reply::None
        }
        Request::RemoveAddress(ip) => {
            provider.ip_remove(ip).await.map_err(errno)?;
            Reply::None
        }
        Request::ClearAddresses => {
            provider.ip_clear().await.map_err(errno)?;
            Reply::None
        }
        Request::Addresses => {
            let addresses = provider
                .ip_list()
                .await
                .map_err(errno)?
                .into_iter()
                .map(|ip| Cidr {
                    ip: ip.ip,
                    prefix: ip.prefix,
                })
                .collect::<Vec<_>>();
            snapshot.addresses = Some(addresses.clone());
            Reply::Addresses(addresses)
        }
        Request::Mac => {
            let mac = provider.mac().await.map_err(errno)?;
            snapshot.mac = Some(mac);
            Reply::Mac(mac)
        }
        Request::Gateway(ip) => {
            provider.gateway_set(ip).await.map_err(errno)?;
            Reply::None
        }
        Request::AddRoute(route) => {
            provider
                .route_add(
                    virtual_net::IpCidr {
                        ip: route.cidr.ip,
                        prefix: route.cidr.prefix,
                    },
                    route.via_router,
                    route.preferred_until.map(std::time::Duration::from_nanos),
                    route.expires_at.map(std::time::Duration::from_nanos),
                )
                .await
                .map_err(errno)?;
            Reply::None
        }
        Request::RemoveRoute(ip) => {
            provider.route_remove(ip).await.map_err(errno)?;
            Reply::None
        }
        Request::ClearRoutes => {
            provider.route_clear().await.map_err(errno)?;
            Reply::None
        }
        Request::Routes => {
            let routes = provider
                .route_list()
                .await
                .map_err(errno)?
                .into_iter()
                .map(|r| {
                    Ok(Route {
                        cidr: Cidr {
                            ip: r.cidr.ip,
                            prefix: r.cidr.prefix,
                        },
                        via_router: r.via_router,
                        preferred_until: r
                            .preferred_until
                            .map(|t| u64::try_from(t.as_nanos()))
                            .transpose()
                            .map_err(|_| Errno::EOVERFLOW)?,
                        expires_at: r
                            .expires_at
                            .map(|t| u64::try_from(t.as_nanos()))
                            .transpose()
                            .map_err(|_| Errno::EOVERFLOW)?,
                    })
                })
                .collect::<Result<Vec<_>, Errno>>()?;
            snapshot.routes = Some(routes.clone());
            Reply::Routes(routes)
        }
    };
    Ok(reply)
}
