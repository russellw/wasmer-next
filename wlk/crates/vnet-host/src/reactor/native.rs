//! Opt-in native factories and owned descriptor retirement on the existing reactor.

use super::*;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsFd,
    task::{Poll as FuturePoll, Waker as TaskWaker},
};
use wasixv2_vnet::endpoint::{DatagramInfo, DatagramReceiver};

pub(super) const RX_BUDGET: usize = 64;
const INSTALL_BUDGET: usize = RX_BUDGET * 4;
const INSTALL_TIMEOUT: Duration = Duration::from_secs(1);

struct WaitEntryWaker(TaskWaker);
impl WaitEntry for WaitEntryWaker {
    fn wake(&self, _: PollMask) -> bool {
        self.0.wake_by_ref();
        true
    }
}

// These three monotonic native completions have no interrupt or timer. Keep only the
// canonical queue registration across polls; dropping this subscriber never revokes its owner.
async fn wait_native<T>(queue: &WaitQueue, mut ready: impl FnMut() -> Option<T>) -> T {
    let mut registration = None;
    std::future::poll_fn(|cx| {
        drop(registration.take());
        registration = Some(queue.add(Arc::new(WaitEntryWaker(cx.waker().clone()))));
        match ready() {
            Some(value) => FuturePoll::Ready(value),
            None => FuturePoll::Pending,
        }
    })
    .await
}

/// Completion of retirement of the actual socket, not an OS thread join.
#[derive(Clone)]
pub struct NativeClose(Arc<CloseState>);
struct CloseState {
    requested: AtomicBool,
    cancelled: AtomicBool,
    finished: AtomicBool,
    error: Mutex<Option<Errno>>,
    queue: WaitQueue,
}
impl NativeClose {
    fn new() -> Self {
        Self(Arc::new(CloseState {
            requested: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            error: Mutex::new(None),
            queue: WaitQueue::new(),
        }))
    }
    fn completed() -> Self {
        let close = Self::new();
        close.finish();
        close
    }
    fn finish(&self) {
        self.0.finished.store(true, Ordering::Release);
        self.0.queue.wake(PollMask::IN);
    }
    fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
        self.request();
    }
    fn request(&self) {
        self.request_error(None);
    }
    fn request_error(&self, error: Option<Errno>) {
        let mut first = self.0.error.lock().unwrap();
        if !self.0.requested.load(Ordering::Acquire) {
            *first = error;
            self.0.requested.store(true, Ordering::Release);
        }
    }
    pub(super) fn requested(&self) -> bool {
        self.0.requested.load(Ordering::Acquire)
    }
    /// Joins retirement even when the public wrapper is still retained. This future is Send.
    pub async fn wait(&self) -> Result<(), Errno> {
        wait_native(&self.0.queue, || {
            self.0
                .finished
                .load(Ordering::Acquire)
                .then(|| self.0.error.lock().unwrap().map_or(Ok(()), Err))
        })
        .await
    }
}
/// This field is LAST in each socket-bearing object: acknowledgement follows fd destruction.
pub(super) struct Retirement(pub(super) NativeClose);
impl Drop for Retirement {
    fn drop(&mut self) {
        self.0.finish();
    }
}
trait Retirable: Send + Sync {
    fn retire(&self, error: Errno);
}
#[derive(Default)]
pub(super) struct Control {
    stopping: bool,
    pending: Vec<Retire>,
    // Weak lifecycle ownership only; no address/port registry or additional I/O driver.
    live: Vec<Weak<dyn Retirable>>,
    // Tokens only: pending reads never extend descriptor ownership.
    readable: std::collections::HashSet<Token>,
}
impl Control {
    fn track<T: Retirable + 'static>(&mut self, resource: &Arc<T>) {
        self.live.retain(|r| r.strong_count() != 0);
        let erased: Arc<dyn Retirable> = resource.clone();
        self.live.push(Arc::downgrade(&erased));
    }
}
struct OwnedSocket {
    sock: socket2::Socket,
    retirement: Retirement,
}
enum Retire {
    Stream(Arc<HostStream>),
    Datagram(Arc<HostDatagram>),
    Listener {
        queued: VecDeque<AcceptedSocket>,
        publication: HostPublication,
    },
    Bound(OwnedSocket),
    Receive {
        socket: Weak<DgramShared>,
        ticket: usize,
        receiver: Arc<dyn DatagramReceiver>,
        state: Arc<ReceiveState>,
    },
}
fn enqueue(backend: &Weak<Shared>, resource: Retire) {
    if let Some(shared) = backend.upgrade() {
        let mut control = shared.native.lock().unwrap();
        if !shared.native_finished.load(Ordering::Acquire) {
            control.pending.push(resource);
            drop(control);
            let _ = shared.waker.wake();
            return;
        }
        drop(control);
        dispose(Some(&shared), resource, None);
    } else {
        dispose(None, resource, None);
    }
}

fn ready(shared: &Shared) -> Result<MutexGuard<'_, Control>, Errno> {
    let control = shared.native.lock().unwrap();
    if control.stopping || shared.stop.load(Ordering::Acquire) {
        Err(Errno::ENETDOWN)
    } else {
        Ok(control)
    }
}
pub(super) fn stop(shared: &Shared) {
    let mut control = shared.native.lock().unwrap();
    control.stopping = true;
    shared.stop.store(true, Ordering::Release);
}
fn dispose(
    shared: Option<&Shared>,
    resource: Retire,
    orphans: Option<&mut HashMap<Token, Arc<StreamShared>>>,
) {
    match resource {
        Retire::Stream(stream) => {
            let socket = &stream.0;
            let close = &socket._retirement.as_ref().expect("selected stream").0;
            if shared.is_none_or(|s| s.stop.load(Ordering::Acquire)) {
                close.cancel();
            }
            let defer = {
                let mut state = socket.state();
                state.released = true;
                state.abort |= !state.rx.is_empty() || close.0.cancelled.load(Ordering::Acquire);
                let linger = state.linger.filter(|t| !t.is_zero());
                if !state.abort
                    && state.connected
                    && !state.reset
                    && !state.failed
                    && let Some(linger) = linger
                {
                    let now = Instant::now();
                    state.closed_at = Some(now);
                    state.orphan_deadline = now.checked_add(linger);
                    state.host_wr_shut = true;
                    let _ = socket.sock.shutdown(std::net::Shutdown::Write);
                    true
                } else {
                    false
                }
            };
            if defer && let (Some(shared), Some(orphans)) = (shared, orphans) {
                orphans.insert(socket.token, socket.clone());
                socket.kick();
                let _ = shared.waker.wake();
            } else if let Some(shared) = shared {
                finish_stream(socket, shared);
            } else {
                // No driver remains: this is owner cancellation, never a graceful linger wait.
                let _ = socket.sock.set_linger(Some(Duration::ZERO));
                socket.state().gone = true;
            }
            socket
                .wq
                .wake(PollMask::IN | PollMask::OUT | PollMask::ERR | PollMask::HUP);
            drop(stream);
        }
        Retire::Datagram(datagram) => {
            let receiver = datagram
                .0
                .state()
                .receiver
                .take()
                .and_then(|slot| slot.lease.upgrade());
            if let Some(receiver) = receiver {
                receiver.state.revoked.store(true, Ordering::Release);
                let error = datagram
                    .0
                    .retirement
                    .as_ref()
                    .and_then(|r| *r.0.0.error.lock().unwrap())
                    .unwrap_or(Errno::ECANCELED);
                finish_receive(&receiver.state, &receiver.receiver, error);
            }
            if let Some(shared) = shared {
                let fd = datagram.0.sock.as_raw_fd();
                let _ = shared.registry.deregister(&mut SourceFd(&fd));
                shared.remove(datagram.0.token);
                shared
                    .native
                    .lock()
                    .unwrap()
                    .readable
                    .remove(&datagram.0.token);
            }
            datagram
                .0
                .wake(PollMask::IN | PollMask::OUT | PollMask::ERR | PollMask::HUP);
            drop(datagram);
        }
        Retire::Listener {
            queued,
            publication,
        } => {
            publication.shared.room.lock().unwrap().clear();
            if let Some(shared) = shared {
                shared
                    .listeners
                    .lock()
                    .unwrap()
                    .retain(|l| l.token != publication.shared.token);
            }
            drop(queued);
            drop(publication);
        }
        Retire::Bound(socket) => {
            let _ = socket.sock.set_linger(Some(Duration::ZERO));
            drop(socket);
        }
        Retire::Receive {
            socket,
            ticket,
            receiver,
            state,
        } => {
            if let Some(socket) = socket.upgrade() {
                remove_receiver(&socket, ticket);
            }
            finish_receive(&state, &receiver, Errno::ECANCELED);
        }
    }
}
// Linux v6.8 net/ipv4/tcp.c::__tcp_close and net/core/stream.c::sk_stream_closing:
// linger waits in FIN_WAIT1/CLOSING/LAST_ACK, then the kernel owns any remaining delivery.
// TCP_INFO is the same actual-state query used by HostStream::tcp_established; it does not
// certify peer application consumption. Keep the wait on the existing orphan timer.
#[cfg(target_os = "linux")]
fn linger_pending(socket: &socket2::Socket) -> io::Result<bool> {
    let mut state = [0u8; 1];
    let mut len = 1 as libc::socklen_t;
    // SAFETY: the live owned fd and writable one-byte state/length buffers span this call.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            state.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if len != 1 {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    Ok(matches!(state[0], 4 | 9 | 11))
}
#[cfg(not(target_os = "linux"))]
fn linger_pending(_: &socket2::Socket) -> io::Result<bool> {
    Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
}
fn finish_stream(socket: &StreamShared, shared: &Shared) {
    let (abort, linger) = {
        let mut state = socket.state();
        state.abort |= socket
            ._retirement
            .as_ref()
            .is_some_and(|r| r.0.0.cancelled.load(Ordering::Acquire));
        (state.abort, state.linger)
    };
    // Exclusive retirement has already honored positive linger progress/deadline. Disable
    // its blocking destructor wait now, retaining accepted OS bytes unless explicitly aborted.
    if abort || linger.is_some() {
        let setting = abort.then_some(Duration::ZERO);
        if let Err(error) = socket.sock.set_linger(setting)
            && let Some(retirement) = &socket._retirement
        {
            let mut first = retirement.0.0.error.lock().unwrap();
            if first.is_none() {
                *first = Some(errno_from_io(&error));
            }
        }
    }
    socket.close(shared);
    shared
        .dirty
        .lock()
        .unwrap()
        .retain(|s| s.token != socket.token);
    socket
        .wq
        .wake(PollMask::IN | PollMask::OUT | PollMask::ERR | PollMask::HUP);
}
/// Progress of selected normal close, sharing the ordinary orphan map/timer.
pub(super) fn closing(socket: &StreamShared, shared: &Shared, now: Instant) -> Option<Instant> {
    let retirement = socket._retirement.as_ref().expect("selected close");
    let deadline = socket.state().orphan_deadline;
    let cancelled = retirement.0.0.cancelled.load(Ordering::Acquire);
    let pending = if cancelled {
        false
    } else {
        linger_pending(&socket.sock).unwrap_or(true)
    };
    if pending
        && let Some(deadline) = deadline
        && now < deadline
    {
        return Some(deadline.min(now + Duration::from_millis(10)));
    }
    finish_stream(socket, shared);
    None
}

pub(super) fn drain(shared: &Shared, orphans: &mut HashMap<Token, Arc<StreamShared>>) {
    loop {
        let pending = std::mem::take(&mut shared.native.lock().unwrap().pending);
        if pending.is_empty() {
            break;
        }
        for resource in pending {
            dispose(Some(shared), resource, Some(&mut *orphans));
        }
    }
}

pub(super) fn schedule_read(shared: &Shared, token: Token) {
    let mut control = shared.native.lock().unwrap();
    if !control.stopping && !shared.native_finished.load(Ordering::Acquire) {
        control.readable.insert(token);
        drop(control);
        let _ = shared.waker.wake();
    }
}
pub(super) fn receive_pending(
    shared: &Shared,
    buf: &mut [u8],
    orphans: &mut HashMap<Token, Arc<StreamShared>>,
) -> bool {
    let pending = std::mem::take(&mut shared.native.lock().unwrap().readable);
    for token in pending {
        // Close commands are authoritative even if they race this turn's snapshot.
        drain(shared, orphans);
        if let Some(Entry::Datagram(datagram)) = shared.entry(token) {
            datagram.receive_all(buf);
        }
    }
    !shared.native.lock().unwrap().readable.is_empty()
}

pub(super) fn shutdown(
    shared: &Shared,
    orphans: &mut HashMap<Token, Arc<StreamShared>>,
    error: Errno,
) {
    let live = {
        let mut control = shared.native.lock().unwrap();
        control.stopping = true;
        shared.stop.store(true, Ordering::Release);
        control
            .live
            .drain(..)
            .filter_map(|r| r.upgrade())
            .collect::<Vec<_>>()
    };
    for resource in live {
        resource.retire(error);
    }
    for socket in orphans.values() {
        if let Some(retirement) = &socket._retirement {
            retirement.0.request_error(Some(error));
            retirement.0.cancel();
            finish_stream(socket, shared);
        }
    }
    orphans.retain(|_, socket| socket._retirement.is_none());
    loop {
        drain(shared, orphans);
        let control = shared.native.lock().unwrap();
        if control.pending.is_empty() {
            shared.native_finished.store(true, Ordering::Release);
            break;
        }
    }
}

/// A selected TCP stream with canonical RX and writes accepted directly by its host socket.
pub struct NativeStream {
    inner: Mutex<Option<Arc<HostStream>>>,
    backend: Weak<Shared>,
    close: NativeClose,
    peer: SocketAddr,
}
impl NativeStream {
    fn register(
        shared: &Arc<Shared>,
        control: &mut Control,
        socket: OwnedSocket,
        peer: SocketAddr,
        connected: bool,
        queue: WaitQueue,
    ) -> Result<Arc<Self>, Errno> {
        let OwnedSocket { sock, retirement } = socket;
        let close = retirement.0.clone();
        let inner =
            HostStream::register_inner(shared, sock, peer, connected, queue, Some(retirement))
                .map_err(|e| errno_from_io(&e))?;
        let stream = Arc::new(Self {
            inner: Mutex::new(Some(inner)),
            backend: Arc::downgrade(shared),
            close,
            peer,
        });
        control.track(&stream);
        Ok(stream)
    }
    fn with<T>(&self, work: impl FnOnce(&HostStream) -> Result<T, Errno>) -> Result<T, Errno> {
        let inner = self.inner.lock().unwrap();
        if self.close.requested() {
            return Err(Errno::EBADF);
        }
        work(inner.as_deref().ok_or(Errno::EBADF)?)
    }
    pub fn local_addr(&self) -> Result<SocketAddr, Errno> {
        self.with(|s| {
            s.0.sock
                .local_addr()
                .map_err(|e| errno_from_io(&e))?
                .as_socket()
                .ok_or(Errno::EAFNOSUPPORT)
        })
    }
    pub fn set_option(&self, level: i32, name: i32, value: &[u8]) -> Result<(), Errno> {
        self.with(|s| {
            socket_option(&s.0.sock, level, name, value)?;
            // Retain canonical urgent/linger/keepalive state after the real setter succeeds.
            s.set_option(level, name, value)
        })
    }
    pub fn flush(&self) -> Result<(), Errno> {
        // Every accepted prefix already belongs to the OS socket, like native Write::flush.
        self.with(|_| Ok(()))
    }
    fn write_socket(&self, bytes: &[u8], urgent: bool) -> Result<usize, Errno> {
        self.with(|stream| {
            let mut state = stream.0.state();
            if state.err.is_some() || state.wr_shut || state.reset || state.failed {
                return Err(state.err.take().unwrap_or(Errno::EPIPE));
            }
            if !state.connected {
                return Err(Errno::EAGAIN);
            }
            let result = if urgent {
                stream.0.sock.send_out_of_band(bytes)
            } else {
                stream.0.sock.send(bytes)
            };
            result.map_err(|error| {
                if error.kind() == io::ErrorKind::WouldBlock {
                    state.host_writable = false;
                }
                errno_from_io(&error)
            })
        })
    }
    /// Escalates this same physical close; previously accepted OS bytes may be aborted.
    pub fn cancel(&self) -> NativeClose {
        self.close.cancel();
        let close = self.close();
        if let Some(shared) = self.backend.upgrade() {
            let _ = shared.waker.wake();
        }
        close
    }
    pub fn close(&self) -> NativeClose {
        self.close.request();
        let inner = self.inner.lock().unwrap().take();
        if let Some(inner) = inner {
            enqueue(&self.backend, Retire::Stream(inner));
        }
        self.close.clone()
    }
}
impl Retirable for NativeStream {
    fn retire(&self, e: Errno) {
        self.close.request_error(Some(e));
        self.cancel();
    }
}
impl Drop for NativeStream {
    fn drop(&mut self) {
        self.close();
    }
}
impl Pollable for NativeStream {
    fn poll(&self, _: Option<&mut PollTable<'_>>) -> PollMask {
        self.with(|s| Ok(s.poll(None)))
            .unwrap_or(PollMask::ERR | PollMask::HUP | PollMask::IN)
    }
}
impl BackendStream for NativeStream {
    fn provider_local_addr(&self) -> Option<Result<SocketAddr, Errno>> {
        Some(self.local_addr())
    }
    fn state(&self) -> Phase {
        self.with(|s| Ok(s.state())).unwrap_or(Phase::Closed)
    }
    fn read(&self, b: &mut [u8], peek: bool) -> Result<usize, Errno> {
        self.with(|s| s.read(b, peek))
    }
    fn write(&self, b: &[u8]) -> Result<usize, Errno> {
        self.write_socket(b, false)
    }
    fn write_more(&self, b: &[u8], _more: bool, _mss: usize) -> Result<usize, Errno> {
        // Packetization hints do not expand the prefix accepted by the native socket.
        self.write_socket(b, false)
    }
    fn push(&self) {
        let _ = self.with(|s| {
            s.push();
            Ok(())
        });
    }
    fn corked_len(&self) -> usize {
        self.with(|s| Ok(s.corked_len())).unwrap_or(0)
    }
    fn write_urgent(&self, b: &[u8]) -> Result<usize, Errno> {
        self.write_socket(b, true)
    }
    fn read_urgent(&self, peek: bool) -> Result<u8, Errno> {
        self.with(|s| s.read_urgent(peek))
    }
    fn at_mark(&self) -> bool {
        self.with(|s| Ok(s.at_mark())).unwrap_or(false)
    }
    fn shutdown(&self, how: Shutdown) -> Result<(), Errno> {
        self.with(|s| s.shutdown(how))
    }
    fn take_error(&self) -> Option<Errno> {
        self.with(|s| Ok(s.take_error()))
            .unwrap_or(Some(Errno::EBADF))
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
    fn set_option(&self, l: i32, n: i32, v: &[u8]) -> Result<(), Errno> {
        NativeStream::set_option(self, l, n, v)
    }
}

/// A bound TCP descriptor. Exactly one connect/listen transition consumes its raw socket.
pub struct NativeBoundTcp {
    state: Mutex<BoundState>,
    backend: Weak<Shared>,
    close: Mutex<NativeClose>,
    closed: AtomicBool,
    local: SocketAddr,
}
enum BoundState {
    Bound(Option<OwnedSocket>),
    Stream(Weak<NativeStream>),
    Listener(Weak<NativeListener>),
}
impl NativeBoundTcp {
    pub fn local_addr(&self) -> Result<SocketAddr, Errno> {
        let target = {
            let state = self.state.lock().unwrap();
            if self.closed.load(Ordering::Acquire) {
                return Err(Errno::EBADF);
            }
            match &*state {
                BoundState::Bound(Some(_)) => return Ok(self.local),
                BoundState::Bound(None) => return Err(Errno::EBADF),
                BoundState::Stream(s) => (Some(s.clone()), None),
                BoundState::Listener(l) => (None, Some(l.clone())),
            }
        };
        match target {
            (Some(s), _) => s.upgrade().ok_or(Errno::EBADF)?.local_addr(),
            (_, Some(l)) => l.upgrade().ok_or(Errno::EBADF)?.local_addr(),
            _ => unreachable!(),
        }
    }
    pub fn connect(&self, peer: SocketAddr, queue: WaitQueue) -> Result<Arc<NativeStream>, Errno> {
        let shared = self.backend.upgrade().ok_or(Errno::ENETDOWN)?;
        let mut control = ready(&shared)?;
        let mut state = self.state.lock().unwrap();
        if self.closed.load(Ordering::Acquire) {
            return Err(Errno::EBADF);
        }
        let BoundState::Bound(socket) = &mut *state else {
            return Err(Errno::EINVAL);
        };
        let socket = socket.take().ok_or(Errno::EINVAL)?;
        let connected = match socket.sock.connect(&peer.into()) {
            Ok(()) => true,
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => false,
            Err(e) => {
                let _ = socket.sock.set_linger(Some(Duration::ZERO));
                self.closed.store(true, Ordering::Release);
                self.close.lock().unwrap().request();
                return Err(errno_from_io(&e));
            }
        };
        let stream =
            match NativeStream::register(&shared, &mut control, socket, peer, connected, queue) {
                Ok(stream) => stream,
                Err(error) => {
                    self.closed.store(true, Ordering::Release);
                    self.close.lock().unwrap().request();
                    return Err(error);
                }
            };
        *self.close.lock().unwrap() = NativeClose::completed();
        *state = BoundState::Stream(Arc::downgrade(&stream));
        Ok(stream)
    }
    pub fn listen(&self, backlog: u32, queue: WaitQueue) -> Result<Arc<NativeListener>, Errno> {
        let shared = self.backend.upgrade().ok_or(Errno::ENETDOWN)?;
        let mut control = ready(&shared)?;
        let mut state = self.state.lock().unwrap();
        if self.closed.load(Ordering::Acquire) {
            return Err(Errno::EBADF);
        }
        let BoundState::Bound(socket) = &mut *state else {
            return Err(Errno::EINVAL);
        };
        let socket = socket.take().ok_or(Errno::EINVAL)?;
        let listener = match NativeListener::register(&shared, &mut control, socket, backlog, queue)
        {
            Ok(listener) => listener,
            Err(error) => {
                self.closed.store(true, Ordering::Release);
                self.close.lock().unwrap().request();
                return Err(error);
            }
        };
        *self.close.lock().unwrap() = NativeClose::completed();
        *state = BoundState::Listener(Arc::downgrade(&listener));
        Ok(listener)
    }
    pub fn set_option(&self, level: i32, name: i32, value: &[u8]) -> Result<(), Errno> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Errno::EBADF);
        }
        enum Target {
            Stream(Weak<NativeStream>),
            Listener(Weak<NativeListener>),
        }
        let target = {
            let state = self.state.lock().unwrap();
            if self.closed.load(Ordering::Acquire) {
                return Err(Errno::EBADF);
            }
            match &*state {
                BoundState::Bound(Some(s)) => return socket_option(&s.sock, level, name, value),
                BoundState::Bound(None) => return Err(Errno::EBADF),
                BoundState::Stream(s) => Target::Stream(s.clone()),
                BoundState::Listener(l) => Target::Listener(l.clone()),
            }
        };
        match target {
            Target::Stream(s) => s
                .upgrade()
                .ok_or(Errno::EBADF)?
                .set_option(level, name, value),
            Target::Listener(l) => l
                .upgrade()
                .ok_or(Errno::EBADF)?
                .set_option(level, name, value),
        }
    }
    pub fn close(&self) -> NativeClose {
        let (close, socket) = {
            let mut state = self.state.lock().unwrap();
            self.closed.store(true, Ordering::Release);
            let close = self.close.lock().unwrap().clone();
            close.request();
            let socket = match &mut *state {
                BoundState::Bound(socket) => socket.take(),
                BoundState::Stream(_) | BoundState::Listener(_) => None,
            };
            (close, socket)
        };
        if let Some(socket) = socket {
            enqueue(&self.backend, Retire::Bound(socket));
        }
        close
    }
}
impl Retirable for NativeBoundTcp {
    fn retire(&self, e: Errno) {
        self.close.lock().unwrap().request_error(Some(e));
        self.close();
    }
}
impl Drop for NativeBoundTcp {
    fn drop(&mut self) {
        self.close();
    }
}

struct AcceptedSocket {
    socket: Option<socket2::Socket>,
    peer: SocketAddr,
}
impl Drop for AcceptedSocket {
    fn drop(&mut self) {
        if let Some(socket) = &self.socket {
            let _ = socket.set_linger(Some(Duration::ZERO));
        }
    }
}
struct AcceptState {
    closed: bool,
    capacity: usize,
    queue: VecDeque<AcceptedSocket>,
}
pub(super) struct NativeAccept {
    state: Mutex<AcceptState>,
    queue: WaitQueue,
    room: WaitQueue,
}
impl NativeAccept {
    pub(super) fn closed(&self) -> bool {
        self.state.lock().unwrap().closed
    }
    pub(super) fn poll_room(&self, table: Option<&mut PollTable<'_>>) -> Room {
        if let Some(table) = table {
            table.wait_on(&self.room);
        }
        let state = self.state.lock().unwrap();
        if state.closed {
            Room::Gone
        } else if state.queue.len() >= state.capacity {
            Room::Full
        } else {
            Room::Ready
        }
    }
    pub(super) fn incoming(&self, socket: socket2::Socket, peer: SocketAddr) {
        let mut accepted = Some(AcceptedSocket {
            socket: Some(socket),
            peer,
        });
        let mut state = self.state.lock().unwrap();
        if !state.closed && state.queue.len() < state.capacity {
            state.queue.push_back(accepted.take().unwrap());
        }
        drop(state);
        // Rejected/unpublished accepted fds must not inherit a blocking positive linger.
        drop(accepted);
        self.queue.wake(PollMask::IN);
    }
}
/// A native listener with a bounded queue of raw accepted sockets on the SAME reactor.
pub struct NativeListener {
    inner: Mutex<Option<HostPublication>>,
    accept: Arc<NativeAccept>,
    backend: Weak<Shared>,
    close: NativeClose,
}
impl NativeListener {
    fn register(
        shared: &Arc<Shared>,
        control: &mut Control,
        socket: OwnedSocket,
        backlog: u32,
        queue: WaitQueue,
    ) -> Result<Arc<Self>, Errno> {
        socket
            .sock
            .listen(backlog.min(i32::MAX as u32) as i32)
            .map_err(|e| {
                let _ = socket.sock.set_linger(Some(Duration::ZERO));
                errno_from_io(&e)
            })?;
        let accept = Arc::new(NativeAccept {
            state: Mutex::new(AcceptState {
                closed: false,
                capacity: backlog.clamp(1, 4096) as usize,
                queue: VecDeque::new(),
            }),
            queue,
            room: WaitQueue::new(),
        });
        let addr = socket
            .sock
            .local_addr()
            .map_err(|e| errno_from_io(&e))?
            .as_socket()
            .ok_or(Errno::EAFNOSUPPORT)?;
        let OwnedSocket { sock, retirement } = socket;
        let close = retirement.0.clone();
        let publication = HostBackend::register_listener_inner(
            shared,
            sock,
            ListenerSink::Native(accept.clone()),
            addr,
            Some(retirement),
        )
        .map_err(|e| errno_from_io(&e))?;
        let listener = Arc::new(Self {
            inner: Mutex::new(Some(publication)),
            accept,
            backend: Arc::downgrade(shared),
            close,
        });
        control.track(&listener);
        Ok(listener)
    }
    pub fn local_addr(&self) -> Result<SocketAddr, Errno> {
        self.inner
            .lock()
            .unwrap()
            .as_ref()
            .map(|p| p.addr)
            .ok_or(Errno::EBADF)
    }
    pub fn try_accept(&self, queue: WaitQueue) -> Result<Arc<NativeStream>, Errno> {
        let shared = self.backend.upgrade().ok_or(Errno::ENETDOWN)?;
        let mut control = ready(&shared)?;
        let mut state = self.accept.state.lock().unwrap();
        if state.closed || self.close.requested() {
            return Err(Errno::EBADF);
        }
        let mut accepted = state.queue.pop_front().ok_or(Errno::EAGAIN)?;
        drop(state);
        let socket = accepted
            .socket
            .take()
            .expect("accepted descriptor is owned once");
        let peer = accepted.peer;
        let owned = OwnedSocket {
            sock: socket,
            retirement: Retirement(NativeClose::new()),
        };
        let result = NativeStream::register(&shared, &mut control, owned, peer, true, queue);
        drop(control);
        self.accept.room.wake(PollMask::OUT);
        result
    }
    pub fn set_backlog(&self, backlog: u32) -> Result<(), Errno> {
        let inner = self.inner.lock().unwrap();
        let p = inner.as_ref().ok_or(Errno::EBADF)?;
        p.shared
            .sock
            .listen(backlog.min(i32::MAX as u32) as i32)
            .map_err(|e| errno_from_io(&e))?;
        self.accept.state.lock().unwrap().capacity = backlog.clamp(1, 4096) as usize;
        drop(inner);
        self.accept.room.wake(PollMask::OUT);
        Ok(())
    }
    pub fn set_option(&self, l: i32, n: i32, v: &[u8]) -> Result<(), Errno> {
        let inner = self.inner.lock().unwrap();
        let p = inner.as_ref().ok_or(Errno::EBADF)?;
        socket_option(&p.shared.sock, l, n, v)
    }
    pub fn cancel(&self) -> NativeClose {
        self.close()
    }
    pub fn close(&self) -> NativeClose {
        self.close.request();
        let inner = self.inner.lock().unwrap().take();
        let queued = {
            let mut state = self.accept.state.lock().unwrap();
            state.closed = true;
            std::mem::take(&mut state.queue)
        };
        self.accept.queue.wake(PollMask::ERR | PollMask::HUP);
        self.accept.room.wake(PollMask::HUP);
        if let Some(publication) = inner {
            enqueue(
                &self.backend,
                Retire::Listener {
                    queued,
                    publication,
                },
            );
        }
        self.close.clone()
    }
}
impl Pollable for NativeListener {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        if let Some(table) = table {
            table.wait_on(&self.accept.queue);
        }
        let state = self.accept.state.lock().unwrap();
        if state.closed {
            PollMask::ERR | PollMask::HUP
        } else if state.queue.is_empty() {
            PollMask::empty()
        } else {
            PollMask::IN
        }
    }
}
impl Retirable for NativeListener {
    fn retire(&self, e: Errno) {
        self.close.request_error(Some(e));
        self.close();
    }
}
impl Drop for NativeListener {
    fn drop(&mut self) {
        self.close();
    }
}

/// Owned installation on one actual descriptor. Readiness waiters borrow this owner;
/// closing/dropping it withdraws only its captured ticket, never a replacement or the fd.
pub struct NativeReceiveLease {
    socket: Weak<DgramShared>,
    backend: Weak<Shared>,
    ticket: usize,
    receiver: Arc<dyn DatagramReceiver>,
    state: Arc<ReceiveState>,
}
struct ReceiveState {
    revoked: AtomicBool,
    result: Mutex<ReceiveResult>,
    queue: WaitQueue,
}
#[derive(Default)]
struct ReceiveResult {
    ready: Option<Result<(), Errno>>,
    finishing: bool,
    closed: bool,
}
pub(super) struct ReceiveSlot {
    ticket: usize,
    lease: Weak<NativeReceiveLease>,
    remaining: usize,
    deadline: Instant,
    installed: bool,
}
impl NativeReceiveLease {
    pub async fn wait_ready(&self) -> Result<(), Errno> {
        wait_native(&self.state.queue, || {
            self.state.result.lock().unwrap().ready
        })
        .await
    }
    pub fn cancel(&self) {
        if !self.state.revoked.swap(true, Ordering::AcqRel) {
            enqueue(
                &self.backend,
                Retire::Receive {
                    socket: self.socket.clone(),
                    ticket: self.ticket,
                    receiver: self.receiver.clone(),
                    state: self.state.clone(),
                },
            );
        }
    }
    /// Joins driver revocation and all synchronous callbacks; this is not an fd-close ack.
    pub async fn close(&self) -> Result<(), Errno> {
        self.cancel();
        wait_native(&self.state.queue, || {
            self.state.result.lock().unwrap().closed.then_some(())
        })
        .await;
        Ok(())
    }
}
impl Drop for NativeReceiveLease {
    fn drop(&mut self) {
        self.cancel();
    }
}
fn finish_receive(state: &ReceiveState, receiver: &Arc<dyn DatagramReceiver>, error: Errno) {
    {
        let mut result = state.result.lock().unwrap();
        if result.finishing {
            return;
        }
        result.finishing = true;
        result.ready.get_or_insert(Err(error));
    }
    state.queue.wake(PollMask::ERR);
    // Receiver callbacks may reenter this socket or enqueue replacement/control work.
    receiver.failed(error);
    state.result.lock().unwrap().closed = true;
    state.queue.wake(PollMask::IN);
}
fn remove_receiver(socket: &DgramShared, ticket: usize) {
    let removed = {
        let mut data = socket.state();
        if data.receiver.as_ref().is_some_and(|r| r.ticket == ticket) {
            data.receiver = None;
            true
        } else {
            false
        }
    };
    // A revoked observation may have consumed a readable edge without reading the fd.
    // Resume Pull through the same coalesced continuation, never wait for another edge.
    if removed
        && !socket.retirement.as_ref().is_some_and(|r| r.0.requested())
        && let Some(shared) = socket.backend.upgrade()
    {
        schedule_read(&shared, socket.token);
    }
}
fn fail_receive(socket: &DgramShared, lease: &NativeReceiveLease, error: Errno) {
    remove_receiver(socket, lease.ticket);
    lease.state.revoked.store(true, Ordering::Release);
    finish_receive(&lease.state, &lease.receiver, error);
}

/// Every observation retains its original consumer even if another thread requests install.
enum ReceiveObservation {
    Pull,
    Install(Arc<NativeReceiveLease>),
    Sink(Arc<NativeReceiveLease>),
    Gone,
}
fn observation(socket: &DgramShared) -> ReceiveObservation {
    let captured = socket
        .state()
        .receiver
        .as_ref()
        .map(|slot| (slot.lease.clone(), slot.installed));
    match captured {
        None => ReceiveObservation::Pull,
        Some((weak, installed)) => match weak.upgrade() {
            Some(lease) if !lease.state.revoked.load(Ordering::Acquire) => {
                if installed {
                    ReceiveObservation::Sink(lease)
                } else {
                    ReceiveObservation::Install(lease)
                }
            }
            _ => ReceiveObservation::Gone,
        },
    }
}

fn install_live(socket: &DgramShared, lease: &NativeReceiveLease) -> bool {
    !lease.state.revoked.load(Ordering::Acquire)
        && !socket.retirement.as_ref().is_some_and(|r| r.0.requested())
        && socket
            .state()
            .receiver
            .as_ref()
            .is_some_and(|r| r.ticket == lease.ticket)
}
/// Selected-only receive pump, on the same driver as descriptor retirement.
pub(super) fn receive_selected(socket: &DgramShared, buf: &mut [u8]) -> (PollMask, bool) {
    let mut wake = PollMask::empty();
    let mut failed = false;
    for _ in 0..RX_BUDGET {
        if socket.retirement.as_ref().is_some_and(|r| r.0.requested()) {
            return (wake, false);
        }
        let captured = observation(socket);
        if matches!(&captured, ReceiveObservation::Gone) {
            return (wake, false);
        }
        if let ReceiveObservation::Install(lease) = &captured {
            let permitted = {
                let mut data = socket.state();
                data.receiver
                    .as_mut()
                    .filter(|r| r.ticket == lease.ticket)
                    .is_some_and(|slot| {
                        if slot.remaining == 0 || Instant::now() >= slot.deadline {
                            return false;
                        }
                        slot.remaining -= 1;
                        true
                    })
            };
            if !permitted {
                fail_receive(socket, lease, Errno::EBUSY);
                return (wake, false);
            }
        }
        match receive_packet(&socket.sock, buf) {
            Ok((n, info)) => {
                failed = false;
                match captured {
                    ReceiveObservation::Pull => {
                        let mut data = socket.state();
                        // A concurrent install clears the old queue and owns later observations;
                        // this pre-install observation must not be queued after that clear.
                        if data.receiver.is_none()
                            && data.attached
                            && data.queued <= DGRAM_BUF
                            && data.queue.len() < DGRAM_BUF / 64
                        {
                            data.queued += n;
                            data.queue
                                .push_back((buf[..n].to_vec(), info.source, Some(info)));
                            wake |= PollMask::IN | PollMask::RDNORM;
                        }
                    }
                    ReceiveObservation::Install(_) => {} // Drain, never post-hoc label old bytes.
                    ReceiveObservation::Sink(lease) => {
                        if install_live(socket, &lease) {
                            lease.receiver.received(info, &buf[..n]);
                        }
                        // No state write follows a foreign callback. Next observation rechecks ticket.
                    }
                    ReceiveObservation::Gone => unreachable!(),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if let ReceiveObservation::Install(lease) = captured {
                    if !install_live(socket, &lease) {
                        return (wake, false);
                    }
                    {
                        let mut data = socket.state();
                        let Some(slot) =
                            data.receiver.as_mut().filter(|r| r.ticket == lease.ticket)
                        else {
                            return (wake, false);
                        };
                        slot.installed = true;
                    }
                    // Empty-queue cutover, not wire age: no recvmsg occurs between EAGAIN,
                    // installing this exact sink and its same-driver Ready report.
                    lease.receiver.ready();
                    if install_live(socket, &lease) {
                        let mut result = lease.state.result.lock().unwrap();
                        if !lease.state.revoked.load(Ordering::Acquire) {
                            result.ready.get_or_insert(Ok(()));
                        }
                        drop(result);
                        lease.state.queue.wake(PollMask::OUT);
                    }
                }
                return (wake, false);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                if let ReceiveObservation::Install(lease) = &captured {
                    fail_receive(socket, lease, errno_from_io(&error));
                    return (wake, false);
                }
                {
                    let mut data = socket.state();
                    if data.attached && (data.connected.is_some() || data.recverr.contains(&true)) {
                        data.err = Some(errno_from_io(&error));
                        wake |= PollMask::ERR;
                    }
                }
                // A one-shot UDP/ICMP error is socket state, not receiver retirement. Match
                // the existing pump's one retry so queued data behind that error cannot lose
                // its readable edge; a persistent error stops without a continuation spin.
                if matches!(captured, ReceiveObservation::Sink(_)) && !failed {
                    failed = true;
                    continue;
                }
                return (wake, false);
            }
        }
    }
    (wake, true)
}

/// A selected native UDP descriptor. Receive uses the canonical full-length/peek queue.
pub struct NativeDatagram {
    inner: Mutex<Option<Arc<HostDatagram>>>,
    backend: Weak<Shared>,
    close: NativeClose,
}
impl NativeDatagram {
    fn with<T>(&self, work: impl FnOnce(&HostDatagram) -> Result<T, Errno>) -> Result<T, Errno> {
        let inner = self.inner.lock().unwrap();
        if self.close.requested() {
            return Err(Errno::EBADF);
        }
        work(inner.as_deref().ok_or(Errno::EBADF)?)
    }
    pub fn local_addr(&self) -> Result<SocketAddr, Errno> {
        self.with(|s| s.0.sock.local_addr().map_err(|e| errno_from_io(&e)))
    }
    pub fn peer_addr(&self) -> Result<Option<SocketAddr>, Errno> {
        self.with(|s| match s.0.sock.peer_addr() {
            Ok(peer) => Ok(Some(peer)),
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Ok(None),
            Err(e) => Err(errno_from_io(&e)),
        })
    }
    pub fn set_option(&self, l: i32, n: i32, v: &[u8]) -> Result<(), Errno> {
        self.with(|s| {
            if RECVERR.contains(&(l, n)) {
                let value = v.get(..4).ok_or(Errno::EINVAL)?;
                let value = i32::from_le_bytes(value.try_into().unwrap());
                s.set_option(l, n, &i32::from(value != 0).to_le_bytes())
            } else {
                socket_option(&s.0.sock, l, n, v)
            }
        })
    }
    /// Takes sole receive authority. Success means admission only; the lease's borrowed
    /// readiness wait completes after the bounded driver cutover (or an authoritative error).
    pub fn install_receiver(
        &self,
        receiver: Arc<dyn DatagramReceiver>,
    ) -> Result<Arc<NativeReceiveLease>, Errno> {
        let datagram = self.inner.lock().unwrap().clone().ok_or(Errno::EBADF)?;
        let shared = self.backend.upgrade().ok_or(Errno::ENETDOWN)?;
        let mut control = ready(&shared)?;
        let mut data = datagram.0.state();
        if self.close.requested() {
            return Err(Errno::EBADF);
        }
        if data.receiver.is_some() {
            return Err(Errno::EBUSY);
        }
        let lease = Arc::new(NativeReceiveLease {
            socket: Arc::downgrade(&datagram.0),
            backend: self.backend.clone(),
            ticket: shared.token().0,
            receiver,
            state: Arc::new(ReceiveState {
                revoked: AtomicBool::new(false),
                result: Mutex::default(),
                queue: WaitQueue::new(),
            }),
        });
        let old_bytes: usize = data.queue.drain(..).map(|(bytes, _, _)| bytes.len()).sum();
        data.queued -= old_bytes;
        data.receiver = Some(ReceiveSlot {
            ticket: lease.ticket,
            lease: Arc::downgrade(&lease),
            remaining: INSTALL_BUDGET,
            deadline: Instant::now() + INSTALL_TIMEOUT,
            installed: false,
        });
        control.readable.insert(datagram.0.token);
        drop(data);
        drop(control);
        let _ = shared.waker.wake();
        Ok(lease)
    }
    /// One received datagram: copied bytes, full length, source and actual destination.
    /// Zero length and peek are preserved; a wildcard local bind is never fabricated as a destination.
    pub fn recv_packet(
        &self,
        buf: &mut [u8],
        peek: bool,
    ) -> Result<(usize, usize, DatagramInfo), Errno> {
        self.with(|s| {
            let mut state = s.0.state();
            if state.receiver.is_some() {
                return Err(Errno::EBUSY);
            }
            let (data, _, info) = state.queue.front().ok_or(Errno::EAGAIN)?;
            let info = info.ok_or(Errno::EIO)?;
            let full = data.len();
            let copied = buf.len().min(full);
            buf[..copied].copy_from_slice(&data[..copied]);
            if !peek {
                state.queue.pop_front();
                state.queued -= full;
            }
            Ok((copied, full, info))
        })
    }
    pub fn cancel(&self) -> NativeClose {
        self.close()
    }
    pub fn close(&self) -> NativeClose {
        self.close.request();
        let inner = self.inner.lock().unwrap().take();
        if let Some(inner) = inner {
            enqueue(&self.backend, Retire::Datagram(inner));
        }
        self.close.clone()
    }
}
impl Retirable for NativeDatagram {
    fn retire(&self, e: Errno) {
        self.close.request_error(Some(e));
        self.close();
    }
}
impl Drop for NativeDatagram {
    fn drop(&mut self) {
        self.close();
    }
}
impl Pollable for NativeDatagram {
    fn poll(&self, _: Option<&mut PollTable<'_>>) -> PollMask {
        self.with(|s| Ok(s.poll(None)))
            .unwrap_or(PollMask::ERR | PollMask::HUP)
    }
}
impl BackendDatagram for NativeDatagram {
    fn send_to(&self, b: &[u8], to: SocketAddr) -> Result<usize, Errno> {
        self.with(|s| s.send_to(b, to))
    }
    fn connect(&self, p: Option<SocketAddr>) -> Result<(), Errno> {
        self.with(|s| s.connect(p))
    }
    fn take_error(&self) -> Option<Errno> {
        self.with(|s| Ok(s.take_error()))
            .unwrap_or(Some(Errno::EBADF))
    }
    fn recv_from(&self, b: &mut [u8], peek: bool) -> Result<(usize, usize, SocketAddr), Errno> {
        self.recv_packet(b, peek)
            .map(|(copied, full, info)| (copied, full, info.source))
    }
    fn input_len(&self) -> usize {
        self.with(|s| Ok(s.input_len())).unwrap_or(0)
    }
    fn set_option(&self, l: i32, n: i32, v: &[u8]) -> Result<(), Errno> {
        NativeDatagram::set_option(self, l, n, v)
    }
    fn take_queued_error(&self) -> Option<QueuedError> {
        self.with(|s| Ok(s.take_queued_error())).unwrap_or(None)
    }
}

fn bind_socket(
    local: SocketAddr,
    datagram: bool,
    v6only: bool,
    reuse_port: bool,
    reuse_addr: bool,
    close: NativeClose,
) -> Result<OwnedSocket, Errno> {
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(local),
        if datagram {
            socket2::Type::DGRAM
        } else {
            socket2::Type::STREAM
        },
        None,
    )
    .map_err(|e| errno_from_io(&e))?;
    let owned = OwnedSocket {
        sock,
        retirement: Retirement(close),
    };
    let s = &owned.sock;
    s.set_nonblocking(true).map_err(|e| errno_from_io(&e))?;
    if local.is_ipv6() {
        s.set_only_v6(v6only).map_err(|e| errno_from_io(&e))?;
    }
    s.set_reuse_address(reuse_addr)
        .map_err(|e| errno_from_io(&e))?;
    s.set_reuse_port(reuse_port)
        .map_err(|e| errno_from_io(&e))?;
    if datagram {
        enable_pktinfo(s, local.is_ipv6())?;
        own_multicast_only(s, local.is_ipv6(), v6only)?;
    }
    s.bind(&local.into()).map_err(|e| errno_from_io(&e))?;
    Ok(owned)
}
impl HostBackend {
    pub fn connect_tcp(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
        queue: WaitQueue,
    ) -> Result<Arc<NativeStream>, Errno> {
        let mut control = ready(&self.shared)?;
        let close = NativeClose::new();
        // Direct connect is distinct from bind_tcp. The literal requested source is used;
        // the old unbound profile supplies any:0 here, never a synthetic namespace address.
        let sock = socket2::Socket::new(
            socket2::Domain::for_address(peer),
            socket2::Type::STREAM,
            None,
        )
        .map_err(|e| errno_from_io(&e))?;
        let socket = OwnedSocket {
            sock,
            retirement: Retirement(close),
        };
        socket
            .sock
            .set_nonblocking(true)
            .map_err(|e| errno_from_io(&e))?;
        if !local.ip().is_unspecified() || local.port() != 0 {
            socket
                .sock
                .bind(&local.into())
                .map_err(|e| errno_from_io(&e))?;
        }
        let connected = match socket.sock.connect(&peer.into()) {
            Ok(()) => true,
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => false,
            Err(e) => return Err(errno_from_io(&e)),
        };
        NativeStream::register(&self.shared, &mut control, socket, peer, connected, queue)
    }
    pub fn bind_tcp(
        &self,
        local: SocketAddr,
        v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
    ) -> Result<Arc<NativeBoundTcp>, Errno> {
        let mut control = ready(&self.shared)?;
        let close = NativeClose::new();
        let socket = bind_socket(local, false, v6only, reuse_port, reuse_addr, close.clone())?;
        let local = socket
            .sock
            .local_addr()
            .map_err(|e| errno_from_io(&e))?
            .as_socket()
            .ok_or(Errno::EAFNOSUPPORT)?;
        let bound = Arc::new(NativeBoundTcp {
            state: Mutex::new(BoundState::Bound(Some(socket))),
            backend: Arc::downgrade(&self.shared),
            close: Mutex::new(close),
            closed: AtomicBool::new(false),
            local,
        });
        control.track(&bound);
        Ok(bound)
    }
    pub fn listen_tcp(
        &self,
        local: SocketAddr,
        v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
        backlog: u32,
        queue: WaitQueue,
    ) -> Result<Arc<NativeListener>, Errno> {
        let mut control = ready(&self.shared)?;
        let socket = bind_socket(
            local,
            false,
            v6only,
            reuse_port,
            reuse_addr,
            NativeClose::new(),
        )?;
        NativeListener::register(&self.shared, &mut control, socket, backlog, queue)
    }
    pub fn bind_udp(
        &self,
        local: SocketAddr,
        v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
        queue: WaitQueue,
    ) -> Result<Arc<NativeDatagram>, Errno> {
        let mut control = ready(&self.shared)?;
        let close = NativeClose::new();
        let socket = bind_socket(local, true, v6only, reuse_port, reuse_addr, close.clone())?;
        let OwnedSocket { sock, retirement } = socket;
        let sock = UdpSocket::from_std(std::net::UdpSocket::from(sock));
        let inner =
            Self::register_datagram_inner(&self.shared, sock, Some(queue), false, Some(retirement))
                .map_err(|e| errno_from_io(&e))?;
        let datagram = Arc::new(NativeDatagram {
            inner: Mutex::new(Some(inner)),
            backend: Arc::downgrade(&self.shared),
            close,
        });
        control.track(&datagram);
        Ok(datagram)
    }
    /// Original host lookup spelling/search behavior on this backend's existing resolver workers.
    /// `dns_server` is intentionally unused, matching the previous native host provider.
    pub fn resolve_host(
        &self,
        host: &str,
        port: Option<u16>,
        dns_server: Option<IpAddr>,
        done: LookupDone,
    ) {
        self.resolver.lookup_host(host, port, dns_server, done);
    }
}

fn socket_option<S: AsFd>(socket: &S, level: i32, name: i32, value: &[u8]) -> Result<(), Errno> {
    let int = || {
        value
            .get(..4)
            .map(|v| i32::from_le_bytes(v.try_into().unwrap()))
            .ok_or(Errno::EINVAL)
    };
    let s = socket2::SockRef::from(socket);
    let native = match (level, name) {
        (1, 2) => (libc::SOL_SOCKET, libc::SO_REUSEADDR),
        (1, 5) => (libc::SOL_SOCKET, libc::SO_DONTROUTE),
        (1, 6) => (libc::SOL_SOCKET, libc::SO_BROADCAST),
        (1, 7) => (libc::SOL_SOCKET, libc::SO_SNDBUF),
        (1, 8) => (libc::SOL_SOCKET, libc::SO_RCVBUF),
        (1, 9) => (libc::SOL_SOCKET, libc::SO_KEEPALIVE),
        (1, 10) => (libc::SOL_SOCKET, libc::SO_OOBINLINE),
        (1, 15) => (libc::SOL_SOCKET, libc::SO_REUSEPORT),
        (1, 13) => {
            let on = int()?;
            let secs = value
                .get(4..8)
                .map(|v| i32::from_le_bytes(v.try_into().unwrap()))
                .ok_or(Errno::EINVAL)?;
            if secs < 0 {
                return Err(Errno::EINVAL);
            }
            return s
                .set_linger((on != 0).then(|| Duration::from_secs(secs as u64)))
                .map_err(|e| errno_from_io(&e));
        }
        (6, 1) => (libc::IPPROTO_TCP, libc::TCP_NODELAY),
        #[cfg(target_os = "linux")]
        (6, 4) => (libc::IPPROTO_TCP, libc::TCP_KEEPIDLE),
        #[cfg(target_os = "linux")]
        (6, 5) => (libc::IPPROTO_TCP, libc::TCP_KEEPINTVL),
        #[cfg(target_os = "linux")]
        (6, 6) => (libc::IPPROTO_TCP, libc::TCP_KEEPCNT),
        (0, 2) => (libc::IPPROTO_IP, libc::IP_TTL),
        (0, 32) => {
            if value.len() < 4 {
                return Err(Errno::EINVAL);
            }
            if value.len() < 12 {
                let address = Ipv4Addr::from(<[u8; 4]>::try_from(&value[..4]).unwrap());
                return s
                    .set_multicast_if_v4(&address)
                    .map_err(|e| errno_from_io(&e));
            }
            #[cfg(target_os = "linux")]
            {
                let request = libc::ip_mreqn {
                    imr_multiaddr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(value[..4].try_into().unwrap()),
                    },
                    imr_address: libc::in_addr {
                        s_addr: u32::from_ne_bytes(value[4..8].try_into().unwrap()),
                    },
                    imr_ifindex: i32::from_le_bytes(value[8..12].try_into().unwrap()),
                };
                // SAFETY: a live fd and initialized native ip_mreqn with its exact size.
                let rc = unsafe {
                    libc::setsockopt(
                        s.as_raw_fd(),
                        libc::IPPROTO_IP,
                        libc::IP_MULTICAST_IF,
                        (&request as *const libc::ip_mreqn).cast(),
                        std::mem::size_of_val(&request) as libc::socklen_t,
                    )
                };
                return if rc < 0 {
                    Err(errno_from_io(&io::Error::last_os_error()))
                } else {
                    Ok(())
                };
            }
            #[cfg(not(target_os = "linux"))]
            return Err(Errno::EOPNOTSUPP);
        }
        (0, 33) => (libc::IPPROTO_IP, libc::IP_MULTICAST_TTL),
        (0, 34) => (libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP),
        (41, 16) => (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS),
        (41, 17) => (libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF),
        (41, 18) => (libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS),
        (41, 19) => (libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP),
        (41, 26) => (libc::IPPROTO_IPV6, libc::IPV6_V6ONLY),
        (0, 35 | 36) => {
            if value.len() < 8 {
                return Err(Errno::EINVAL);
            }
            let group = Ipv4Addr::from(<[u8; 4]>::try_from(&value[..4]).unwrap());
            let address = Ipv4Addr::from(<[u8; 4]>::try_from(&value[4..8]).unwrap());
            let index = value
                .get(8..12)
                .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
                .unwrap_or(0);
            let interface = if index == 0 {
                socket2::InterfaceIndexOrAddress::Address(address)
            } else {
                socket2::InterfaceIndexOrAddress::Index(index)
            };
            return (if name == 35 {
                s.join_multicast_v4_n(&group, &interface)
            } else {
                s.leave_multicast_v4_n(&group, &interface)
            })
            .map_err(|e| errno_from_io(&e));
        }
        (41, 20 | 21) => {
            if value.len() < 20 {
                return Err(Errno::EINVAL);
            }
            let group = Ipv6Addr::from(<[u8; 16]>::try_from(&value[..16]).unwrap());
            let index = u32::from_le_bytes(value[16..20].try_into().unwrap());
            return (if name == 20 {
                s.join_multicast_v6(&group, index)
            } else {
                s.leave_multicast_v6(&group, index)
            })
            .map_err(|e| errno_from_io(&e));
        }
        _ => return Err(Errno::EOPNOTSUPP),
    };
    let n = int()?;
    // SAFETY: fd is borrowed from this live socket, and n is an initialized native int
    // of exactly the length passed. Host constants are mapped above, never guest pointers.
    let rc = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            native.0,
            native.1,
            (&n as *const i32).cast(),
            std::mem::size_of_val(&n) as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(errno_from_io(&io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn own_multicast_only(socket: &socket2::Socket, v6: bool, v6only: bool) -> Result<(), Errno> {
    let off: libc::c_int = 0;
    for (enabled, level, name) in [
        (!v6 || !v6only, libc::IPPROTO_IP, libc::IP_MULTICAST_ALL),
        (v6, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_ALL),
    ] {
        if !enabled {
            continue;
        }
        // SAFETY: owned live fd, initialized native int, exact size. Selected sockets never
        // enable global membership leakage; default HostBackend sockets do not call here.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                name,
                (&off as *const libc::c_int).cast(),
                std::mem::size_of_val(&off) as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(errno_from_io(&io::Error::last_os_error()));
        }
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn own_multicast_only(_: &socket2::Socket, _: bool, _: bool) -> Result<(), Errno> {
    Err(Errno::EOPNOTSUPP)
}

#[cfg(target_os = "linux")]
fn enable_pktinfo(socket: &socket2::Socket, v6: bool) -> Result<(), Errno> {
    let on: libc::c_int = 1;
    let (level, name) = if v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    } else {
        (libc::IPPROTO_IP, libc::IP_PKTINFO)
    };
    // SAFETY: live socket and initialized native int, with its exact size.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&on as *const libc::c_int).cast(),
            std::mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(errno_from_io(&io::Error::last_os_error()))
    } else {
        Ok(())
    }
}
#[cfg(not(target_os = "linux"))]
fn enable_pktinfo(_: &socket2::Socket, _: bool) -> Result<(), Errno> {
    Err(Errno::EOPNOTSUPP)
}

#[cfg(target_os = "linux")]
pub(super) fn receive_packet(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, DatagramInfo)> {
    let mut control = [0u64; 16];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: recvmsg writes into the owned address/control buffers and initialized byte
    // slice, all of which outlive the call. Its address length is retained by try_init.
    let ((count, msg), source) = unsafe {
        socket2::SockAddr::try_init(|storage, len| {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_name = storage.cast();
            msg.msg_namelen = *len;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = std::mem::size_of_val(&control) as _;
            let n = libc::recvmsg(
                socket.as_raw_fd(),
                &mut msg,
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            );
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            *len = msg.msg_namelen;
            Ok((n as usize, msg))
        })
    }?;
    if count > buf.len() || msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
    }
    let source = source
        .as_socket()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EAFNOSUPPORT))?;
    let port = socket.local_addr()?.port();
    let mut destination = None;
    // SAFETY: the OS filled control; each typed value is length-checked and read unaligned,
    // and libc's CMSG traversal stays within the returned msg_controllen.
    unsafe {
        let mut current = libc::CMSG_FIRSTHDR(&msg);
        while !current.is_null() {
            let header = &*current;
            let data = libc::CMSG_DATA(current);
            let length = (header.cmsg_len as usize)
                .saturating_sub(data.offset_from(current.cast()) as usize);
            if header.cmsg_level == libc::IPPROTO_IP
                && header.cmsg_type == libc::IP_PKTINFO
                && length >= std::mem::size_of::<libc::in_pktinfo>()
            {
                let info = std::ptr::read_unaligned(data.cast::<libc::in_pktinfo>());
                destination = Some(DatagramInfo {
                    source,
                    destination: SocketAddr::new(
                        Ipv4Addr::from(u32::from_be(info.ipi_addr.s_addr)).into(),
                        port,
                    ),
                    interface: info.ipi_ifindex as u32,
                });
            } else if header.cmsg_level == libc::IPPROTO_IPV6
                && header.cmsg_type == libc::IPV6_PKTINFO
                && length >= std::mem::size_of::<libc::in6_pktinfo>()
            {
                let info = std::ptr::read_unaligned(data.cast::<libc::in6_pktinfo>());
                let address = Ipv6Addr::from(info.ipi6_addr.s6_addr);
                let scope = if address.is_unicast_link_local() || address.is_multicast() {
                    info.ipi6_ifindex
                } else {
                    0
                };
                destination = Some(DatagramInfo {
                    source,
                    destination: SocketAddrV6::new(address, port, 0, scope).into(),
                    interface: info.ipi6_ifindex,
                });
            }
            current = libc::CMSG_NXTHDR(&msg, current);
        }
    }
    Ok((
        count,
        destination.ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?,
    ))
}
#[cfg(not(target_os = "linux"))]
pub(super) fn receive_packet(_: &UdpSocket, _: &mut [u8]) -> io::Result<(usize, DatagramInfo)> {
    Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
}

#[cfg(test)]
mod tests;
