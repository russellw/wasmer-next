//! Live canonical-network adapter for the SDK-owned provider factories.
use crate::{
    network_api::{
        BoundTcp, DynNetworkProvider, NetworkCloseMode, NetworkResult, TcpListener, TcpStream,
        UdpSocket,
    },
    service::Services,
};
use std::{
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, Weak},
    task::{Poll, Waker},
};
use tokio::sync::Notify;
use wasixv2_abi::Errno;
use wasixv2_vnet::{
    Answer, Backend, BackendDatagram, BackendStream, Domain, Found, InboundSink, Lookup,
    LookupContext, LookupDone, LookupError, Publication, Room, Shutdown, StreamState,
};
use wasixv2_wait::{PollMask, PollTable, Pollable, WaitQueue};
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
    owner_cancel: Arc<Cancellation>,
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
    async fn close_resource<'a>(
        &'a self,
        close: impl Fn(NetworkCloseMode) -> futures::future::BoxFuture<'a, NetworkResult<()>> + Send,
    ) -> NetworkResult<()> {
        let canceled = self.owner_cancel.changed.notified();
        tokio::pin!(canceled);
        canceled.as_mut().enable();
        if self.owner_cancel.closed() {
            return close(NetworkCloseMode::Cancel).await;
        }
        let normal = close(NetworkCloseMode::Normal);
        tokio::pin!(normal);
        tokio::select! {
            biased;
            result = &mut normal => result,
            _ = &mut canceled => {
                // Retain the owning Normal future: escalation is another request on the
                // SAME resource/completion, never cancellation by dropping its waiter.
                let (normal, cancel) = tokio::join!(normal, close(NetworkCloseMode::Cancel));
                normal.and(cancel)
            }
        }
    }
    fn resource(self: &Arc<Self>) -> Result<Lease, Errno> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(Errno::ENETDOWN);
        }
        state.active = state.active.checked_add(1).ok_or(Errno::ENOBUFS)?;
        Ok(Lease(self.clone()))
    }
    fn record_close(&self, result: NetworkResult<()>) {
        if let Err(error) = result {
            self.state
                .lock()
                .unwrap()
                .failure
                .get_or_insert_with(|| format!("{error:?}"));
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
    fn cleanup(self: &Arc<Self>, work: impl Future<Output = NetworkResult<()>> + Send + 'static) {
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
                        .get_or_insert_with(|| format!("{error:?}"));
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
    provider: DynNetworkProvider,
    group: Arc<Group>,
}
impl ProviderNetwork {
    pub(crate) fn new(provider: DynNetworkProvider, services: Services) -> Arc<Self> {
        let group = Arc::new(Group {
            owner_cancel: Arc::default(),
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
    fn resolve_lookup(
        &self,
        lookup: Lookup,
        port: Option<u16>,
        contextual: bool,
        done: LookupDone,
    ) {
        let Lookup::Name(name) = lookup else {
            return done(Err(if contextual {
                LookupError::Provider(Errno::EINVAL)
            } else {
                LookupError::Failed
            }));
        };
        let provider = self.provider.clone();
        let completion = Arc::new(Mutex::new(Some(done)));
        let output = completion.clone();
        let group = self.group.clone();
        if let Err(error) = self.group.spawn(async move {
            let result = match group.wait(provider.resolve(&name, port, None)).await {
                Some(Ok(addrs)) if !group.closed() => Ok(Found {
                    answer: Answer::Addrs {
                        canonical: name,
                        addrs,
                    },
                    ttl: 0,
                }),
                Some(Err(error)) if contextual => Err(LookupError::Provider(error)),
                _ if contextual => Err(LookupError::Provider(Errno::ENETDOWN)),
                _ => Err(LookupError::Failed),
            };
            let done = output.lock().unwrap().take();
            if let Some(done) = done {
                done(result);
            }
        }) {
            let done = completion.lock().unwrap().take();
            if let Some(done) = done {
                done(Err(if contextual {
                    LookupError::Provider(error)
                } else {
                    LookupError::Failed
                }));
            }
        }
    }
    pub(crate) async fn probe_tcp(
        self: &Arc<Self>,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> NetworkResult<()> {
        let cancellation = Arc::new(Cancellation::default());
        let _cancel = CancelOnDrop(cancellation.clone());
        let (send, result) = tokio::sync::oneshot::channel();
        let group = self.group.clone();
        let provider = self.provider.clone();
        self.group.spawn(async move {
            let queue = WaitQueue::new();
            let mut outcome = match group
                .wait_scoped(
                    &cancellation,
                    provider.connect_tcp(local, peer, queue.clone()),
                )
                .await
            {
                Some(Ok(socket)) => {
                    let ready = group
                        .wait_scoped(&cancellation, connected(&*socket, &queue))
                        .await
                        .unwrap_or(Err(Errno::ECONNABORTED));
                    let closed = group.close_resource(|mode| socket.close(mode)).await;
                    group.record_close(closed);
                    ready.and(closed)
                }
                Some(Err(error)) => Err(error),
                None => Err(Errno::ECONNABORTED),
            };
            if group.closed() || cancellation.closed() {
                outcome = Err(Errno::ECONNABORTED);
            }
            let _ = send.send(outcome);
        })?;
        result.await.unwrap_or(Err(Errno::ECONNABORTED))
    }
    pub(crate) fn cancel_handle(&self) -> NetworkCancel {
        NetworkCancel(self.group.owner_cancel.clone())
    }
    pub(crate) fn cancel(&self) {
        self.group.owner_cancel.close();
    }
    pub(crate) async fn close(&self) -> io::Result<()> {
        self.group.close().await
    }
}
/// Only the run's cancellation signal; retaining ProcessHandle cannot retain its Machine/group.
#[derive(Clone)]
pub(crate) struct NetworkCancel(Arc<Cancellation>);
impl NetworkCancel {
    pub(crate) fn cancel(&self) {
        self.0.close();
    }
    #[cfg(test)]
    pub(crate) fn requested(&self) -> bool {
        self.0.closed()
    }
}

async fn connected(socket: &dyn TcpStream, queue: &WaitQueue) -> NetworkResult<()> {
    let mut registrations = Vec::new();
    futures::future::poll_fn(|cx| {
        registrations.clear();
        let mut register = |queue: &WaitQueue, _: PollMask| {
            registrations.push(queue.add(Arc::new(TaskWake(cx.waker().clone()))));
        };
        let mut table = PollTable::new(mask(), &mut register);
        table.wait_on(queue);
        let ready = socket.poll(Some(&mut table));
        match socket.state() {
            StreamState::Established => Poll::Ready(Ok(())),
            StreamState::Closed => {
                Poll::Ready(Err(socket.take_error().unwrap_or(Errno::ECONNRESET)))
            }
            StreamState::Connecting if ready.intersects(PollMask::ERR | PollMask::HUP) => {
                Poll::Ready(Err(socket.take_error().unwrap_or(Errno::ECONNREFUSED)))
            }
            StreamState::Connecting => Poll::Pending,
        }
    })
    .await
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
    socket: Mutex<Socket<Arc<dyn TcpStream>>>,
    queue: WaitQueue,
    peer: SocketAddr,
    error: Mutex<Option<Errno>>,
}
impl Stream {
    fn new(group: Arc<Group>, queue: WaitQueue, peer: SocketAddr) -> NetworkResult<Arc<Self>> {
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
            error: Mutex::default(),
        }))
    }
    fn ready(&self, result: NetworkResult<Arc<dyn TcpStream>>) {
        let mut state = self.socket.lock().unwrap();
        if matches!(*state, Socket::Closed) {
            drop(state);
            if let Ok(socket) = result {
                let group = self.group.clone();
                self.group
                    .cleanup(async move { group.close_resource(|mode| socket.close(mode)).await });
            }
            return;
        }
        *state = match result {
            Ok(socket) => {
                let configured =
                    self.options
                        .lock()
                        .unwrap()
                        .iter()
                        .try_for_each(|(level, name, value)| {
                            socket.set_socket_option(*level, *name, value)
                        });
                match configured {
                    Ok(()) => Socket::Ready(socket),
                    Err(error) => {
                        let group = self.group.clone();
                        self.group.cleanup(async move {
                            group.close_resource(|mode| socket.close(mode)).await
                        });
                        Socket::Failed(Some(error))
                    }
                }
            }
            Err(error) => Socket::Failed(Some(error)),
        };
        drop(state);
        self.queue.wake(mask());
    }
    fn with<T>(&self, f: impl FnOnce(&dyn TcpStream) -> NetworkResult<T>) -> NetworkResult<T> {
        let socket = match &*self.socket.lock().unwrap() {
            Socket::Ready(socket) => socket.clone(),
            Socket::Pending => return Err(Errno::EAGAIN),
            Socket::Failed(error) => return Err(error.unwrap_or(Errno::ECONNRESET)),
            Socket::Closed => return Err(Errno::ENOTCONN),
        };
        f(&*socket)
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
        let group = self.group.clone();
        self.group.cleanup(async move {
            let result = if let Socket::Ready(socket) = old {
                group.close_resource(|mode| socket.close(mode)).await
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
        let socket = match &*self.socket.lock().unwrap() {
            Socket::Ready(socket) => socket.clone(),
            Socket::Pending => return PollMask::empty(),
            Socket::Closed => return PollMask::IN | PollMask::HUP,
            Socket::Failed(_) => return PollMask::ERR | PollMask::HUP,
        };
        let mut events = socket.poll(table);
        if self.error.lock().unwrap().is_some() {
            events |= PollMask::ERR;
        }
        events
    }
}
impl BackendStream for Stream {
    fn provider_local_addr(&self) -> Option<NetworkResult<SocketAddr>> {
        Some(self.with(|s| s.local_addr()))
    }
    fn state(&self) -> StreamState {
        self.with(|s| Ok(s.state())).unwrap_or_else(|e| {
            if e == Errno::EAGAIN {
                StreamState::Connecting
            } else {
                StreamState::Closed
            }
        })
    }
    fn tcp_established(&self) -> bool {
        self.with(|s| Ok(s.tcp_established())).unwrap_or(false)
    }
    fn read(&self, buf: &mut [u8], peek: bool) -> NetworkResult<usize> {
        self.with(|s| s.read(buf, peek))
    }
    fn write(&self, buf: &[u8]) -> NetworkResult<usize> {
        self.with(|s| s.write(buf))
    }
    fn write_more(&self, data: &[u8], more: bool, mss: usize) -> NetworkResult<usize> {
        self.with(|s| s.write_more(data, more, mss))
    }
    fn push(&self) {
        let result = self.with(|s| {
            s.push();
            s.flush()
        });
        if let Err(error) = result
            && error != Errno::EAGAIN
        {
            self.error.lock().unwrap().get_or_insert(error);
            self.queue.wake(PollMask::ERR);
        }
    }
    fn corked_len(&self) -> usize {
        self.with(|s| Ok(s.corked_len())).unwrap_or(0)
    }
    fn write_urgent(&self, data: &[u8]) -> NetworkResult<usize> {
        self.with(|s| s.write_urgent(data))
    }
    fn read_urgent(&self, peek: bool) -> NetworkResult<u8> {
        self.with(|s| s.read_urgent(peek))
    }
    fn at_mark(&self) -> bool {
        self.with(|s| Ok(s.at_mark())).unwrap_or(false)
    }
    fn shutdown(&self, how: Shutdown) -> NetworkResult<()> {
        self.with(|s| s.shutdown(how))
    }
    fn take_error(&self) -> Option<Errno> {
        if let Some(error) = self.error.lock().unwrap().take() {
            return Some(error);
        }
        let mut state = self.socket.lock().unwrap();
        match &mut *state {
            Socket::Failed(error) => error.take(),
            Socket::Ready(socket) => socket.take_error(),
            _ => None,
        }
    }
    fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    fn input_len(&self) -> usize {
        self.with(|s| Ok(s.input_len())).unwrap_or(0)
    }
    fn output_len(&self) -> usize {
        self.with(|s| Ok(s.output_len())).unwrap_or(0)
    }
    fn set_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        let state = self.socket.lock().unwrap();
        match &*state {
            Socket::Ready(socket) => socket.set_socket_option(level, name, value),
            Socket::Pending => {
                let mut options = self.options.lock().unwrap();
                options.retain(|(l, n, _)| (*l, *n) != (level, name));
                options.push((level, name, value.to_vec()));
                Ok(())
            }
            Socket::Failed(error) => Err(error.unwrap_or(Errno::ECONNRESET)),
            Socket::Closed => Err(Errno::ENOTCONN),
        }
    }
}
struct Datagram {
    group: Arc<Group>,
    service_lease: Mutex<Option<crate::service::Lease>>,
    resource_lease: Mutex<Option<Lease>>,
    cancellation: Arc<Cancellation>,
    socket: Mutex<Socket<Arc<dyn UdpSocket>>>,
    queue: WaitQueue,
    options: Mutex<Vec<(i32, i32, Vec<u8>)>>,
    peer: Mutex<Option<Option<SocketAddr>>>,
}
impl Datagram {
    fn new(group: Arc<Group>, queue: WaitQueue) -> NetworkResult<Arc<Self>> {
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
            options: Mutex::default(),
            peer: Mutex::default(),
        }))
    }
    fn ready(&self, result: NetworkResult<Arc<dyn UdpSocket>>) {
        let mut state = self.socket.lock().unwrap();
        if matches!(*state, Socket::Closed) {
            drop(state);
            if let Ok(socket) = result {
                let group = self.group.clone();
                self.group
                    .cleanup(async move { group.close_resource(|mode| socket.close(mode)).await });
            }
            return;
        }
        *state = match result {
            Ok(socket) => {
                let configured = (|| {
                    for (level, name, value) in self.options.lock().unwrap().iter() {
                        socket.set_socket_option(*level, *name, value)?;
                    }
                    if let Some(peer) = *self.peer.lock().unwrap()
                        && socket.peer_addr()? != peer
                    {
                        socket.connect(peer)?;
                    }
                    Ok(())
                })();
                match configured {
                    Ok(()) => Socket::Ready(socket),
                    Err(error) => {
                        let group = self.group.clone();
                        self.group.cleanup(async move {
                            group.close_resource(|mode| socket.close(mode)).await
                        });
                        Socket::Failed(Some(error))
                    }
                }
            }
            Err(error) => Socket::Failed(Some(error)),
        };
        drop(state);
        self.queue.wake(mask());
    }
    fn with<T>(&self, f: impl FnOnce(&dyn UdpSocket) -> NetworkResult<T>) -> NetworkResult<T> {
        let socket = match &*self.socket.lock().unwrap() {
            Socket::Ready(socket) => socket.clone(),
            Socket::Pending => return Err(Errno::EAGAIN),
            Socket::Failed(error) => return Err(error.unwrap_or(Errno::EIO)),
            Socket::Closed => return Err(Errno::ENETDOWN),
        };
        f(&*socket)
    }
    fn local_addr(&self) -> NetworkResult<SocketAddr> {
        self.with(|s| s.local_addr())
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
        let group = self.group.clone();
        self.group.cleanup(async move {
            let result = if let Socket::Ready(socket) = old {
                group.close_resource(|mode| socket.close(mode)).await
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
        self.with(|s| Ok(s.poll(table))).unwrap_or_else(|error| {
            if error == Errno::EAGAIN {
                PollMask::empty()
            } else {
                PollMask::ERR | PollMask::HUP
            }
        })
    }
}
impl BackendDatagram for Datagram {
    fn send_to(&self, data: &[u8], to: SocketAddr) -> NetworkResult<usize> {
        self.with(|s| s.send_to(data, to))
    }
    fn connect(&self, peer: Option<SocketAddr>) -> NetworkResult<()> {
        let state = self.socket.lock().unwrap();
        match &*state {
            Socket::Ready(socket) => {
                if socket.peer_addr()? == peer {
                    Ok(())
                } else {
                    socket.connect(peer)
                }
            }
            Socket::Pending => {
                *self.peer.lock().unwrap() = Some(peer);
                Ok(())
            }
            Socket::Failed(error) => Err(error.unwrap_or(Errno::EIO)),
            Socket::Closed => Err(Errno::ENETDOWN),
        }
    }
    fn take_error(&self) -> Option<Errno> {
        let mut state = self.socket.lock().unwrap();
        match &mut *state {
            Socket::Ready(socket) => socket.take_error(),
            Socket::Failed(error) => error.take(),
            _ => None,
        }
    }
    fn recv_from(&self, buf: &mut [u8], peek: bool) -> NetworkResult<(usize, usize, SocketAddr)> {
        self.with(|s| s.recv_from(buf, peek))
    }
    fn input_len(&self) -> usize {
        self.with(|s| Ok(s.input_len())).unwrap_or(0)
    }
    fn set_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        let state = self.socket.lock().unwrap();
        match &*state {
            Socket::Ready(socket) => socket.set_socket_option(level, name, value),
            Socket::Pending => {
                let mut options = self.options.lock().unwrap();
                options.retain(|(l, n, _)| (*l, *n) != (level, name));
                options.push((level, name, value.to_vec()));
                Ok(())
            }
            Socket::Failed(error) => Err(error.unwrap_or(Errno::EIO)),
            Socket::Closed => Err(Errno::ENETDOWN),
        }
    }
    fn take_queued_error(&self) -> Option<wasixv2_vnet::QueuedError> {
        self.with(|s| Ok(s.take_queued_error())).ok().flatten()
    }
    fn attach(&self, queue: Option<WaitQueue>) -> NetworkResult<()> {
        self.with(|s| s.attach(queue))
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
    fn endpoint_namespace(&self) -> Option<Arc<dyn wasixv2_vnet::endpoint::EndpointProvider>> {
        Some(Arc::new(NamespaceEndpoints {
            provider: self.provider.clone(),
            group: self.group.clone(),
        }))
    }
    fn connect(&self, peer: SocketAddr, queue: WaitQueue) -> NetworkResult<Arc<dyn BackendStream>> {
        let stream = Stream::new(self.group.clone(), queue.clone(), peer)?;
        self.group.register(stream.clone())?;
        let output = Arc::downgrade(&stream);
        let cancellation = stream.cancellation.clone();
        let provider = self.provider.clone();
        let group = self.group.clone();
        let local = any(if peer.is_ipv4() {
            Domain::Inet
        } else {
            Domain::Inet6
        });
        self.group.spawn(async move {
            if let Some(result) = group
                .wait_scoped(&cancellation, provider.connect_tcp(local, peer, queue))
                .await
            {
                if let Some(output) = output.upgrade() {
                    output.ready(result);
                } else if let Ok(socket) = result {
                    let closed = group.close_resource(|mode| socket.close(mode)).await;
                    group.record_close(closed);
                }
            }
        })?;
        Ok(stream)
    }
    fn datagram(
        &self,
        domain: Domain,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn BackendDatagram>> {
        let socket = Datagram::new(self.group.clone(), queue.clone())?;
        self.group.register(socket.clone())?;
        let output = Arc::downgrade(&socket);
        let cancellation = socket.cancellation.clone();
        let provider = self.provider.clone();
        let group = self.group.clone();
        self.group.spawn(async move {
            if let Some(result) = group
                .wait_scoped(
                    &cancellation,
                    provider.bind_udp(any(domain), false, false, false, queue),
                )
                .await
            {
                if let Some(output) = output.upgrade() {
                    output.ready(result);
                } else if let Ok(socket) = result {
                    let closed = group.close_resource(|mode| socket.close(mode)).await;
                    group.record_close(closed);
                }
            }
        })?;
        Ok(socket)
    }
    fn publish(
        &self,
        host: SocketAddr,
        backlog: u32,
        sink: Arc<dyn InboundSink>,
    ) -> io::Result<Box<dyn Publication>> {
        if host.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ordinary asynchronous publication requires an explicit port",
            ));
        }
        let cancellation = Arc::new(Cancellation::default());
        let stop = cancellation.clone();
        let group = self.group.clone();
        let provider = self.provider.clone();
        self.group
            .spawn(async move {
                let queue = WaitQueue::new();
                let Some(result) = group
                    .wait_scoped(
                        &stop,
                        provider.listen_tcp(
                            host,
                            host.is_ipv6(),
                            false,
                            false,
                            backlog,
                            queue.clone(),
                        ),
                    )
                    .await
                else {
                    return;
                };
                let listener = match result {
                    Ok(listener) => listener,
                    Err(_) => return,
                };
                let incoming = sink.clone();
                serve_listener(
                    &group,
                    &stop,
                    &*listener,
                    &queue,
                    move |stream, queue| incoming.incoming(stream, queue),
                    move |table| sink.poll_room(table),
                )
                .await;
                group.record_close(group.close_resource(|mode| listener.close(mode)).await);
            })
            .map_err(|error| io::Error::from_raw_os_error(error.0))?;
        Ok(Box::new(Published { host, cancellation }))
    }
    fn supports_contextual_lookup(&self) -> bool {
        true
    }
    fn lookup_contextual(&self, lookup: Lookup, context: LookupContext, done: LookupDone) {
        self.resolve_lookup(lookup, context.port, true, done);
    }
    fn lookup(&self, lookup: Lookup, done: LookupDone) {
        self.resolve_lookup(lookup, None, false, done);
    }
}
async fn serve_listener(
    group: &Arc<Group>,
    stop: &Cancellation,
    listener: &dyn TcpListener,
    queue: &WaitQueue,
    mut incoming: impl FnMut(Arc<dyn BackendStream>, WaitQueue) -> bool,
    mut room: impl FnMut(Option<&mut PollTable<'_>>) -> Room,
) {
    loop {
        let mut registrations = Vec::new();
        let accepted = futures::future::poll_fn(|cx| {
            registrations.clear();
            let mut register = |queue: &WaitQueue, _: PollMask| {
                registrations.push(queue.add(Arc::new(TaskWake(cx.waker().clone()))));
            };
            let mut table = PollTable::new(mask(), &mut register);
            table.wait_on(queue);
            match room(Some(&mut table)) {
                Room::Gone => return Poll::Ready(None),
                Room::Full => return Poll::Pending,
                Room::Ready => {}
            }
            let events = listener.poll(Some(&mut table));
            let stream_queue = WaitQueue::new();
            match listener.try_accept(stream_queue.clone()) {
                Ok((socket, peer)) => Poll::Ready(Some((socket, peer, stream_queue))),
                Err(Errno::EAGAIN) if !events.intersects(PollMask::ERR | PollMask::HUP) => {
                    Poll::Pending
                }
                Err(_) => Poll::Ready(None),
            }
        });
        let Some(Some((socket, peer, queue))) = group.wait_scoped(stop, accepted).await else {
            break;
        };
        let stream = match Stream::new(group.clone(), queue.clone(), peer) {
            Ok(stream) => stream,
            Err(_) => {
                group.record_close(group.close_resource(|mode| socket.close(mode)).await);
                break;
            }
        };
        stream.ready(Ok(socket));
        if group.register(stream.clone()).is_err() {
            break;
        }
        if stop.closed() || group.closed() {
            stream.close();
            break;
        }
        let _ = incoming(stream, queue);
    }
}
struct Controls {
    provider: DynNetworkProvider,
    group: Arc<Group>,
    serial: Arc<tokio::sync::Mutex<()>>,
}
impl wasixv2_vnet::provider::Provider for Controls {
    fn start(&self, request: wasixv2_vnet::provider::Request, done: wasixv2_vnet::provider::Done) {
        use wasixv2_vnet::provider::{Completion, Request, Snapshot};
        let provider = self.provider.clone();
        let group = self.group.clone();
        let serial = self.serial.clone();
        let completion = Arc::new(Mutex::new(Some(done)));
        let output = completion.clone();
        if self
            .group
            .spawn(async move {
                let mutates = request.mutates();
                let changes_active = matches!(request, Request::Bridge { .. } | Request::Unbridge);
                let result = if let Some(_serial) = group.wait(serial.lock()).await {
                    group
                        .wait(provider.control(request))
                        .await
                        .unwrap_or_else(|| Completion {
                            result: Err(Errno::ENETDOWN),
                            snapshot: Snapshot {
                                active_unknown: changes_active,
                                ..Snapshot::default()
                            },
                            reconciliation: mutates.then_some(Errno::ENETDOWN),
                        })
                } else {
                    Completion::error(Errno::ENETDOWN)
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
                done(Completion::error(Errno::ENETDOWN));
            }
        }
    }
}
mod endpoints;
use endpoints::NamespaceEndpoints;
#[cfg(test)]
mod tests;
