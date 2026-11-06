//! TCP sockets: binding, listening with accept and SYN queues, connecting inside the namespace
//! over an in-memory [`Conn`] or outside it over a backend stream.

use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
};

use wasixv2_abi::{Errno, MsgFlags, SocketLevel, SocketOption, TcpOption};
use wasixv2_wait::{PollMask, PollTable, Pollable, WaitQueue, poll_wait};

use crate::{
    Accepted, BackendStream, Domain, NetResult, PortEntry, Publication, RecvMsg, Room, SendMsg,
    Shutdown, Socket, SocketKind, StreamState,
    addr::{canonical, connect_target, present, unbound},
    endpoint::{
        AttemptGate, EndpointBindPurpose, EndpointBindRequest, EndpointBound, EndpointChoice,
        EndpointKind, EndpointMember, EndpointQuery, EndpointSourceId, EndpointTarget,
        pending::PendingStream, runtime::SocketEndpoint,
    },
    net::{Net, Path},
    opts::{self, Changed, SockOpts},
    ports::{BindSpec, SockId},
    stream::{Buffers, Conn},
};

/// What carries a connected socket's bytes.
#[derive(Clone)]
enum Transport {
    /// In-namespace connection; the `usize` is this socket's side.
    Local(Arc<Conn>, usize),
    /// Through the backend.
    Remote(Arc<dyn BackendStream>),
}

enum Phase {
    Pending,
    Established,
    Failed,
}

/// External provider routing owns its source without inventing a namespace route/interface.
enum ConnectRoute {
    Namespace(Path),
    Provider {
        target: EndpointTarget,
        source: IpAddr,
    },
}

impl Transport {
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Local(a, side), Self::Local(b, other)) => side == other && Arc::ptr_eq(a, b),
            (Self::Remote(a), Self::Remote(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }

    fn phase(&self) -> Phase {
        match self {
            Self::Local(c, side) => {
                if c.is_established() {
                    Phase::Established
                } else if c.is_done(*side) {
                    Phase::Failed
                } else {
                    Phase::Pending
                }
            }
            Self::Remote(s) => match s.state() {
                StreamState::Connecting => Phase::Pending,
                StreamState::Established => Phase::Established,
                StreamState::Closed => Phase::Failed,
            },
        }
    }

    /// The transport's readiness. Both kinds wake the socket's own queue, which the socket
    /// registers on.
    fn poll(&self) -> PollMask {
        match self {
            Self::Local(c, side) => c.poll(*side),
            Self::Remote(s) => s.poll(None),
        }
    }

    fn read(&self, buf: &mut [u8], peek: bool) -> NetResult<usize> {
        match self {
            Self::Local(c, side) => c.read(*side, buf, peek),
            Self::Remote(s) => s.read(buf, peek),
        }
    }

    fn write_more(&self, data: &[u8], urgent: bool, more: bool, mss: usize) -> NetResult<usize> {
        match self {
            Self::Local(c, side) => c.write_more(*side, data, urgent, more, mss),
            Self::Remote(s) if urgent => s.write_urgent(data),
            Self::Remote(s) => s.write_more(data, more, mss),
        }
    }

    fn push(&self) {
        match self {
            Self::Local(c, side) => c.push(*side),
            Self::Remote(s) => s.push(),
        }
    }
    fn corked_len(&self) -> usize {
        match self {
            Self::Local(c, side) => c.corked_len(*side),
            Self::Remote(s) => s.corked_len(),
        }
    }

    fn tcp_established(&self) -> bool {
        match self {
            Self::Local(c, side) => c.tcp_established(*side),
            Self::Remote(s) => s.tcp_established(),
        }
    }

    fn read_urgent(&self, peek: bool) -> NetResult<u8> {
        match self {
            Self::Local(c, side) => c.read_urgent(*side, peek),
            Self::Remote(s) => s.read_urgent(peek),
        }
    }

    fn at_mark(&self) -> bool {
        match self {
            Self::Local(c, side) => c.at_mark(*side),
            Self::Remote(s) => s.at_mark(),
        }
    }

    fn shutdown(&self, how: Shutdown) -> NetResult<()> {
        match self {
            Self::Local(c, side) => {
                c.shutdown(*side, how);
                Ok(())
            }
            Self::Remote(s) => s.shutdown(how),
        }
    }

    /// `tcp_close` (or `tcp_disconnect` with `abort`). Dropping a backend stream closes it.
    fn close(self, abort: bool) {
        match self {
            Self::Local(c, side) => c.close(side, abort),
            Self::Remote(s) => {
                if abort {
                    let mut linger = [0u8; 8];
                    linger[..4].copy_from_slice(&1i32.to_le_bytes());
                    let _ = s.set_option(
                        SocketLevel::SOL_SOCKET.0,
                        SocketOption::SO_LINGER.0,
                        &linger,
                    );
                }
            }
        }
    }

    fn take_error(&self) -> Option<Errno> {
        match self {
            Self::Local(c, side) => c.take_error(*side),
            Self::Remote(s) => s.take_error(),
        }
    }

    fn input_len(&self) -> usize {
        match self {
            Self::Local(c, side) => c.input_len(*side),
            Self::Remote(s) => s.input_len(),
        }
    }

    /// `tcp_done` happened: reset, refused or aborted.
    fn is_done(&self) -> bool {
        match self {
            Self::Local(c, side) => c.is_done(*side),
            Self::Remote(s) => s.state() == StreamState::Closed,
        }
    }
}

/// What became of a published connection offered to a listener.
pub(crate) enum Offer {
    Queued,
    /// The queue filled or closed meanwhile; the connection was closed.
    Dropped,
    /// Not taken and untouched, for another listener.
    Declined(Arc<dyn BackendStream>),
}

enum State {
    Closed,
    Listening(Arc<Listener>),
    Connecting(Transport, SocketAddr),
    Connected(Transport, SocketAddr),
}

struct Inner {
    opts: SockOpts,
    cork_timer: Option<Box<dyn Fn(bool) + Send + Sync>>,
    cork_armed: bool,
    /// Canonical bound address, once bound.
    local: Option<SocketAddr>,
    policy_bind: Option<SocketAddr>,
    bind_pending: Option<EndpointSourceId>,
    bind_admission: Weak<crate::endpoint::bind::Admission>,
    endpoint_bound: Option<Arc<dyn EndpointBound>>,
    endpoint_selected: bool,
    /// `SOCK_BINDPORT_LOCK`: the port was chosen by `bind`, so it survives a disconnect.
    port_locked: bool,
    /// `SOCK_BINDADDR_LOCK`: the address was chosen by `bind`, so a disconnect keeps it.
    addr_locked: bool,
    /// What `getsockname` reports once an autobound port went back to the table while
    /// unbound: `inet_put_port` clears `inet_num` but leaves `inet_sport`.
    put_back: Option<SocketAddr>,
    /// `inet_rcv_saddr` of a bind that took no port (`IP_BIND_ADDRESS_NO_PORT`): the address
    /// the port taken later by `connect` or `listen` goes with.
    saddr: Option<std::net::IpAddr>,
    state: State,
    /// `sk_err` while not connected.
    err: Option<Errno>,
    /// A connect failed asynchronously; the next `connect` reports it.
    failed: bool,
    rd_shut: bool,
    wr_shut: bool,
}

/// A TCP socket of a [`Net`].
pub struct TcpSocket {
    net: Arc<Net>,
    id: SockId,
    endpoint: SocketEndpoint,
    domain: AtomicU8,
    /// `sk_uid`, for `SO_REUSEPORT`.
    uid: u32,
    /// `sock_i_ino`: the inode of the socket's file, 0 until it has one.
    ino: AtomicU64,
    wq: WaitQueue,
    me: Weak<TcpSocket>,
    /// The listener while listening; a leaf lock so lookups under the network lock can reach
    /// it without taking the socket lock.
    listener: Mutex<Option<Arc<Listener>>>,
    inner: Mutex<Inner>,
}

/// A listening socket's queues (`inet_connection_sock`'s accept queue and SYN queue).
pub(crate) struct Listener {
    wq: WaitQueue,
    /// Woken when the accept queue makes room or the listener closes, for a backend holding
    /// published connections back while it is full (see [`crate::InboundSink::poll_room`]).
    room: WaitQueue,
    inner: Mutex<ListenerInner>,
    publication: Mutex<Option<Box<dyn Publication>>>,
}

struct ListenerInner {
    backlog: u32,
    closed: bool,
    /// Established connections waiting for `accept`.
    ready: VecDeque<(Arc<TcpSocket>, SocketAddr)>,
    /// Connections that arrived while the accept queue was full; the clients stay in
    /// `SYN_SENT` until `accept` makes room, standing in for SYN retransmission.
    syn: VecDeque<(Arc<TcpSocket>, Arc<Conn>, SocketAddr)>,
}

impl ListenerInner {
    /// `sk_acceptq_is_full`: one more than the backlog fits.
    fn full(&self) -> bool {
        self.ready.len() > self.backlog as usize
    }
}

fn bufs(o: &SockOpts) -> Buffers {
    Buffers {
        sndbuf: o.sndbuf,
        rcvbuf: o.rcvbuf,
        rcvlowat: o.rcvlowat,
        urginline: o.flag(SocketLevel::SOL_SOCKET.0, SocketOption::SO_OOBINLINE.0),
    }
}

/// Applies the options a backend stream acts on to a stream made after they were set.
fn replay_options(stream: &dyn BackendStream, opts: &SockOpts) {
    for (level, name, value) in opts.backend_options() {
        let _ = stream.set_option(level, name, &value);
    }
}

impl TcpSocket {
    pub(crate) fn new(net: Arc<Net>, domain: Domain, uid: u32) -> Arc<Self> {
        Self::with_state(
            net,
            domain,
            uid,
            SockOpts::new(SocketKind::Stream, domain),
            None,
            State::Closed,
            WaitQueue::new(),
        )
    }

    /// A socket whose one wait queue is `wq`: everything that changes its readiness, its own
    /// transport included, wakes that queue.
    fn with_state(
        net: Arc<Net>,
        domain: Domain,
        uid: u32,
        opts: SockOpts,
        local: Option<SocketAddr>,
        state: State,
        wq: WaitQueue,
    ) -> Arc<Self> {
        let id = net.next_id();
        Arc::new_cyclic(|me| Self {
            net,
            id,
            endpoint: SocketEndpoint::new(id),
            domain: AtomicU8::new(domain as u8),
            uid,
            ino: AtomicU64::new(0),
            wq,
            me: me.clone(),
            listener: Mutex::new(None),
            inner: Mutex::new(Inner {
                opts,
                cork_timer: None,
                cork_armed: false,
                local,
                policy_bind: None,
                bind_pending: None,
                bind_admission: Weak::new(),
                endpoint_bound: None,
                endpoint_selected: false,
                port_locked: false,
                addr_locked: false,
                put_back: None,
                saddr: None,
                state,
                err: None,
                failed: false,
                rd_shut: false,
                wr_shut: false,
            }),
        })
    }

    fn provider_bind(
        &self,
        requested: SocketAddr,
        privileged: bool,
        explicit: bool,
        purpose: EndpointBindPurpose,
    ) -> NetResult<Option<Box<dyn crate::BindAdmission>>> {
        let Some(namespace) = self.net.endpoints() else {
            return Ok(None);
        };
        let external = namespace.external;
        let original_bind = if explicit {
            Some(requested)
        } else {
            self.lock().policy_bind
        };
        let requested = original_bind.unwrap_or(requested);
        if explicit || matches!(purpose, EndpointBindPurpose::Listen { .. }) {
            self.net.admit(requested, crate::PolicyDirection::Inbound)?;
        }
        let (request, admission, freebind) = {
            let mut g = self.lock();
            if !explicit {
                if g.local.is_some() {
                    return Ok(None);
                }
                if let Some(admission) = g.bind_admission.upgrade() {
                    return Ok(Some(admission.subscribe()));
                }
            }
            if !explicit && g.policy_bind != original_bind {
                return Err(Errno::EAGAIN);
            }
            let requested = original_bind.unwrap_or(requested);
            let request_explicit = original_bind.is_some();
            let addr = canonical(requested);
            let freebind = g.opts.flag(0, wasixv2_abi::IpOption::IP_FREEBIND.0);
            if !external {
                self.net.check_bind(addr, privileged, freebind)?;
            }
            // External capability alone does not select an address authority. Its pure
            // choice below precedes the selected security check and any provider work.
            if matches!(requested, SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some())
                && g.opts.v6only
            {
                return Err(Errno::EINVAL);
            }
            if g.bind_pending.is_some()
                || g.local.is_some()
                || !matches!(g.state, State::Closed)
                || (explicit && g.saddr.is_some())
            {
                return Err(Errno::EINVAL);
            }
            self.endpoint.renew(&namespace);
            let source_id = self.endpoint.source();
            let request = EndpointBindRequest {
                source_id,
                kind: EndpointKind::Stream,
                requested,
                explicit: request_explicit,
                purpose: if request_explicit {
                    EndpointBindPurpose::Bind
                } else {
                    purpose
                },
                domain: self.domain(),
                v6only: g.opts.v6only,
                reuse_addr: g.opts.reuseaddr,
                reuse_port: g.opts.reuseport,
            };
            let commit = self.me.clone();
            let cancel = self.me.clone();
            let active = self.me.clone();
            let admission = crate::endpoint::bind::Admission::new(
                self.wq.clone(),
                move |actual, bound| {
                    let socket = commit.upgrade().ok_or(Errno::ECANCELED)?;
                    let actual = crate::endpoint::bind::validate(request, actual)?;
                    socket.net.check_bind(
                        actual,
                        privileged,
                        freebind || external || requested.ip().is_unspecified(),
                    )?;
                    let mut g = socket.lock();
                    if g.bind_pending != Some(source_id)
                        || socket.endpoint.source() != source_id
                        || (
                            socket.domain(),
                            g.opts.v6only,
                            g.opts.reuseaddr,
                            g.opts.reuseport,
                        ) != (
                            request.domain,
                            request.v6only,
                            request.reuse_addr,
                            request.reuse_port,
                        )
                    {
                        return Err(Errno::ECANCELED);
                    }
                    socket.net.tcp_bind(
                        socket.id,
                        socket.spec(&g.opts, actual.ip()),
                        actual.port(),
                        socket.me.clone(),
                    )?;
                    g.local = Some(actual);
                    g.policy_bind = request.explicit.then_some(requested);
                    g.saddr = None;
                    g.port_locked = request.explicit && requested.port() != 0;
                    g.addr_locked |=
                        request.explicit && !canonical(requested).ip().is_unspecified();
                    g.bind_pending = None;
                    g.bind_admission = Weak::new();
                    g.endpoint_bound = Some(bound);

                    Ok(())
                },
                move || {
                    if let Some(socket) = cancel.upgrade() {
                        socket.cancel_bind(source_id);
                    }
                },
                move || {
                    active.upgrade().is_some_and(|socket| {
                        let g = socket.inner.lock().unwrap();
                        g.bind_pending == Some(source_id) && socket.endpoint.source() == source_id
                    })
                },
            );
            g.bind_pending = Some(source_id);
            g.bind_admission = Arc::downgrade(&admission);
            (request, admission, freebind)
        };
        // The synchronous factory must not block; the lease represents all pending work.
        let result = (|| {
            if external && !namespace.provider.select_bind(&request)? {
                // Pure namespace selection accepts no physical work. The ordinary bind
                // path below repeats all namespace address/route validation.
                return Ok(None);
            }
            if explicit || matches!(request.purpose, EndpointBindPurpose::Listen { .. }) {
                self.net.admit(requested, crate::PolicyDirection::Inbound)?;
            }
            {
                let g = self.lock();
                if g.bind_pending != Some(request.source_id)
                    || self.endpoint.source() != request.source_id
                    || g.local.is_some()
                    || !matches!(g.state, State::Closed)
                    || (explicit && g.saddr.is_some())
                {
                    return Err(Errno::ECANCELED);
                }
                if matches!(requested, SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some())
                    && g.opts.v6only
                {
                    return Err(Errno::EINVAL);
                }
                let current_freebind = g.opts.flag(0, wasixv2_abi::IpOption::IP_FREEBIND.0);
                self.net.check_bind(
                    canonical(requested),
                    privileged,
                    current_freebind || external,
                )?;
                if self.domain() != request.domain
                    || g.opts.v6only != request.v6only
                    || g.opts.reuseaddr != request.reuse_addr
                    || g.opts.reuseport != request.reuse_port
                    || current_freebind != freebind
                {
                    return Err(Errno::ECANCELED);
                }
            }
            // No socket/namespace guard crosses the accepted foreign factory call.
            namespace.provider.bind(request, self.wq.clone())
        })();
        admission.install(result.clone());
        match result {
            Ok(Some(_)) => Ok(Some(admission.subscribe())),
            other => {
                self.cancel_bind(request.source_id);
                other.map(|_| None)
            }
        }
    }

    fn cancel_bind(&self, source: EndpointSourceId) {
        let mut g = self.lock();
        if g.bind_pending == Some(source) {
            g.bind_pending = None;
            g.bind_admission = Weak::new();
            if let Some(ns) = self.net.endpoints() {
                self.endpoint.renew(&ns);
            }
            drop(g);
            self.wq.wake(PollMask::empty());
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        let mut g = self.inner.lock().unwrap();
        self.refresh(&mut g);
        g
    }

    /// ipv6_sockglue.c requires TCP_ESTABLISHED for IPV6_ADDRFORM.
    fn addrform_peer(g: &Inner) -> Option<std::net::IpAddr> {
        match &g.state {
            State::Connected(t, peer) if t.tcp_established() => Some(peer.ip()),
            _ => None,
        }
    }

    fn spec(&self, o: &SockOpts, ip: std::net::IpAddr) -> BindSpec {
        BindSpec {
            family: self.domain(),
            addr: ip,
            v6only: o.v6only,
            reuseaddr: o.reuseaddr,
            reuseport: o.reuseport,
            uid: self.uid,
        }
    }

    /// Completes a connection attempt the far side has decided.
    fn refresh(&self, g: &mut Inner) {
        let State::Connecting(t, peer) = &g.state else {
            return;
        };
        let t = t.clone();
        let peer = *peer;
        let actual = if g.endpoint_selected {
            match &t {
                Transport::Remote(stream) => stream.provider_local_addr(),
                _ => None,
            }
        } else {
            None
        };
        let mut failure = None;
        if let Some(actual) = actual {
            match actual {
                Err(Errno::EAGAIN) => return,
                Err(error) => failure = Some(error),
                Ok(actual) => {
                    let actual = canonical(actual);
                    let previous = g.local.expect("connecting source reserved");
                    let requested = g.policy_bind.map(canonical);
                    if actual.port() == 0
                        || actual.is_ipv4() != peer.is_ipv4()
                        || requested.is_some_and(|request| {
                            !request.ip().is_unspecified() && request.ip() != actual.ip()
                        })
                        || (g.endpoint_bound.is_some() && previous.port() != actual.port())
                    {
                        failure = Some(Errno::EPROTO);
                    } else if actual != previous {
                        let result = self.net.state().tcp.replace_bound(
                            self.id,
                            previous.port(),
                            self.spec(&g.opts, actual.ip()),
                            actual.port(),
                            self.me.clone(),
                        );
                        match result {
                            Ok(()) => {
                                g.local = Some(actual);
                                self.net
                                    .state()
                                    .tcp
                                    .set_remote(self.id, actual.port(), Some(peer));
                            }
                            Err(error) => failure = Some(error),
                        }
                    }
                }
            }
        }
        if failure.is_none() {
            match t.phase() {
                Phase::Pending => return,
                Phase::Established => {
                    g.state = State::Connected(t, peer);
                    return;
                }
                Phase::Failed => failure = t.take_error().or(Some(Errno::ECONNREFUSED)),
            }
        }
        // No alternate address or replay after provider acceptance or an adoption conflict.
        if let Transport::Remote(stream) = &t {
            let _ = stream.shutdown(Shutdown::Both);
        }
        g.err = failure;
        g.failed = true;
        g.rd_shut = true;
        g.wr_shut = true;
        g.state = State::Closed;
        g.endpoint_selected = false;
        self.put_port(g);
    }

    /// `inet_put_port` unless the user bound the port.
    fn put_port(&self, g: &mut Inner) {
        if !g.port_locked
            && let Some(local) = g.local.take()
        {
            self.net.state().tcp.unbind(self.id, local.port());
            g.put_back = Some(local);
            g.endpoint_bound = None;
        }
    }

    fn autobind(&self, g: &mut Inner) -> NetResult<()> {
        if g.bind_pending.is_some() {
            return Err(Errno::EALREADY);
        }
        if g.local.is_none() {
            let ip = g.saddr.unwrap_or(self.domain_any());
            let port = self
                .net
                .tcp_bind(self.id, self.spec(&g.opts, ip), 0, self.me.clone())?;
            g.local = Some(SocketAddr::new(ip, port));
        }
        Ok(())
    }

    fn domain_any(&self) -> std::net::IpAddr {
        match self.domain() {
            Domain::Inet => std::net::Ipv4Addr::UNSPECIFIED.into(),
            Domain::Inet6 => std::net::Ipv6Addr::UNSPECIFIED.into(),
        }
    }

    pub(crate) fn port_entry(&self) -> Option<PortEntry> {
        let g = self.inner.lock().unwrap();
        let local = present(self.domain(), g.local?);
        let (peer, listening, rx_queue, tx_queue) = match &g.state {
            State::Connected(t, p) => {
                let tx = match t {
                    Transport::Local(c, side) => c.output_len(*side),
                    Transport::Remote(s) => s.output_len(),
                };
                (Some(present(self.domain(), *p)), false, t.input_len(), tx)
            }
            State::Connecting(_, p) => (Some(present(self.domain(), *p)), false, 0, 0),
            State::Listening(l) => {
                let l = l.inner.lock().unwrap();
                (None, true, l.ready.len(), l.backlog as usize)
            }
            State::Closed => (None, false, 0, 0),
        };
        Some(PortEntry {
            kind: SocketKind::Stream,
            local,
            peer,
            listening,
            uid: self.uid,
            inode: self.ino.load(Ordering::Relaxed),
            rx_queue,
            tx_queue,
            v6only: g.opts.v6only,
            port_locked: g.port_locked,
            bound_dev: self.net.device_index(&g.opts.bind_device),
        })
    }

    /// Stops listening (`inet_csk_listen_stop`): established children are reset, clients
    /// still in the SYN queue are refused.
    fn stop_listening(&self, g: &mut Inner) {
        if !matches!(g.state, State::Listening(_)) {
            return;
        }
        if let Some(namespace) = self.net.endpoints() {
            self.endpoint.renew(&namespace);
        }
        let State::Listening(l) = std::mem::replace(&mut g.state, State::Closed) else {
            unreachable!("checked above");
        };
        *self.listener.lock().unwrap() = None;
        if let Some(local) = g.local {
            self.net
                .state()
                .tcp
                .set_listening(self.id, local.port(), false);
        }
        l.publication.lock().unwrap().take();
        let (ready, syn) = {
            let mut li = l.inner.lock().unwrap();
            li.closed = true;
            (std::mem::take(&mut li.ready), std::mem::take(&mut li.syn))
        };
        for (child, _) in ready {
            child.release_inner(true);
        }
        for (child, conn, _) in syn {
            conn.refuse();
            child.release_inner(true);
        }
        l.room.wake(PollMask::empty());
        self.wq.wake(PollMask::empty());
    }

    /// `tcp_disconnect` of a connection in progress or established: the peer is reset (from
    /// `SYN_SENT` there is none yet), and unless the connection had already ended
    /// (`tcp_need_reset`, or `SYN_SENT`) the socket's own `sk_err` becomes `ECONNRESET`.
    fn abort_connection(&self, g: &mut Inner) {
        if let State::Connecting(t, _) | State::Connected(t, _) =
            std::mem::replace(&mut g.state, State::Closed)
        {
            if !t.is_done() {
                g.err = Some(Errno::ECONNRESET);
            }
            t.close(true);
        }
    }

    /// `inet_bhash2_reset_saddr`: back to the wildcard source address unless `bind` chose it.
    fn reset_saddr(&self, g: &mut Inner) {
        if g.addr_locked {
            return;
        }
        g.saddr = None;
        if let Some(local) = g.local.filter(|l| !l.ip().is_unspecified()) {
            let any = self.domain_any();
            self.net.state().tcp.rehash(self.id, local.port(), any);
            g.local = Some(SocketAddr::new(any, local.port()));
        }
    }

    fn release_inner(&self, abort: bool) {
        let mut g = self.inner.lock().unwrap();
        self.stop_listening(&mut g);
        if let Some(namespace) = self.net.endpoints() {
            self.endpoint.renew(&namespace);
        }
        let abort = abort || g.opts.linger == Some(0);
        let old = std::mem::replace(&mut g.state, State::Closed);
        if let Some(local) = g.local.take() {
            self.net.state().tcp.unbind(self.id, local.port());
        }
        // `inet_release`: `ip_mc_drop_socket`, `ipv6_sock_mc_close`.
        g.opts.mc.drop_all(&self.net);
        drop(g);
        if let State::Connecting(t, _) | State::Connected(t, _) = old {
            t.close(abort);
        }
    }

    /// A child for a connection to the listener `self`, sharing its port, with `wq` as its
    /// queue.
    fn new_child(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
        wq: WaitQueue,
        transport: impl FnOnce(&WaitQueue, &SockOpts) -> Transport,
    ) -> Arc<TcpSocket> {
        let (opts, addr_locked) = {
            let g = self.inner.lock().unwrap();
            (g.opts.inherit(), g.addr_locked)
        };
        let child = Self::with_state(
            self.net.clone(),
            self.domain(),
            self.uid,
            opts.clone(),
            Some(local),
            State::Closed,
            wq,
        );
        let t = transport(&child.wq, &opts);
        {
            let mut g = child.inner.lock().unwrap();
            // net/core/sock.c sk_clone_lock inherits the address lock, but
            // clears SOCK_BINDPORT_LOCK even when the listener chose its port.
            g.addr_locked = addr_locked;
            g.state = State::Connected(t, peer);
        }
        self.net.state().tcp.inherit(
            child.id,
            self.spec(&opts, local.ip()),
            local.port(),
            peer,
            Arc::downgrade(&child),
        );
        child
    }

    /// Whether the accept queue can take a published connection; `table` registers on the
    /// queue woken when that may have changed.
    pub(crate) fn poll_room(&self, table: Option<&mut PollTable<'_>>) -> Room {
        let Some(l) = self.listener.lock().unwrap().clone() else {
            return Room::Gone;
        };
        let mut table = table;
        poll_wait(&mut table, &l.room);
        let li = l.inner.lock().unwrap();
        match (li.closed, li.full()) {
            (true, _) => Room::Gone,
            (false, true) => Room::Full,
            (false, false) => Room::Ready,
        }
    }

    /// A connection accepted by the backend for a published port; `wq` is the queue the stream
    /// wakes.
    pub(crate) fn endpoint_room(
        &self,
        source: EndpointSourceId,
        _peer: SocketAddr,
        _destination: SocketAddr,
        table: Option<&mut PollTable<'_>>,
    ) -> Room {
        if self.endpoint.source() != source {
            return Room::Gone;
        }
        self.poll_room(table)
    }

    pub(crate) fn incoming_endpoint(
        &self,
        source: EndpointSourceId,
        gate: &AttemptGate,
        stream: Arc<dyn BackendStream>,
        wq: WaitQueue,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> Offer {
        self.incoming_scoped(Some((source, gate)), stream, wq, local, peer)
    }

    pub(crate) fn incoming_remote(
        &self,
        stream: Arc<dyn BackendStream>,
        wq: WaitQueue,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> Offer {
        self.incoming_scoped(None, stream, wq, local, peer)
    }

    fn incoming_scoped(
        &self,
        scope: Option<(EndpointSourceId, &AttemptGate)>,
        stream: Arc<dyn BackendStream>,
        wq: WaitQueue,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> Offer {
        if scope.is_some_and(|(source, _)| self.endpoint.source() != source) {
            return Offer::Declined(stream);
        }
        let Some(l) = self.listener.lock().unwrap().clone() else {
            return Offer::Declined(stream);
        };
        {
            let li = l.inner.lock().unwrap();
            if li.closed || li.full() {
                return Offer::Declined(stream);
            }
        }
        let child = self.new_child(local, peer, wq, |_, opts| {
            replay_options(&*stream, opts);
            Transport::Remote(stream)
        });
        let mut li = l.inner.lock().unwrap();
        if li.closed
            || li.full()
            || scope.is_some_and(|(source, _)| self.endpoint.source() != source)
        {
            drop(li);
            child.release_inner(true);
            return Offer::Dropped;
        }
        let queued = match scope {
            Some((source, gate)) => self
                .endpoint
                .commit(source, || gate.commit(|| li.ready.push_back((child, peer))))
                .flatten()
                .is_some(),
            None => {
                li.ready.push_back((child, peer));
                true
            }
        };
        drop(li);
        if queued {
            l.wq.wake(PollMask::IN | PollMask::RDNORM);
            Offer::Queued
        } else {
            Offer::Dropped
        }
    }

    /// Connects to a listener of `target`, this namespace or the one across a veth.
    fn connect_local(&self, g: &mut Inner, dst: SocketAddr, target: &Net) -> NetResult<()> {
        let local = g.local.expect("bound before connecting");
        let Some(listening) = target.find_listener(dst, local) else {
            self.put_port(g);
            return Err(Errno::ECONNREFUSED);
        };
        let Some(l) = listening.listener.lock().unwrap().clone() else {
            self.put_port(g);
            return Err(Errno::ECONNREFUSED);
        };
        let client_bufs = bufs(&g.opts);
        let mut conn = None;
        let child = listening.new_child(dst, local, WaitQueue::new(), |child_wq, child_opts| {
            let c = Arc::new(Conn::new(
                [self.wq.clone(), child_wq.clone()],
                [client_bufs, bufs(child_opts)],
                false,
            ));
            conn = Some(c.clone());
            Transport::Local(c, 1)
        });
        let conn = conn.expect("transport built");
        let mut li = l.inner.lock().unwrap();
        if li.closed {
            drop(li);
            child.release_inner(true);
            self.put_port(g);
            return Err(Errno::ECONNREFUSED);
        }
        self.net
            .state()
            .tcp
            .set_remote(self.id, local.port(), Some(dst));
        let t = Transport::Local(conn.clone(), 0);
        if li.full() {
            li.syn.push_back((child, conn, local));
            g.state = State::Connecting(t, dst);
            return Err(Errno::EINPROGRESS);
        }
        conn.establish();
        li.ready.push_back((child, local));
        drop(li);
        l.wq.wake(PollMask::IN | PollMask::RDNORM);
        g.state = State::Connected(t, dst);
        Ok(())
    }
}

impl Listener {
    /// Takes the next established connection and moves SYN-queue entries up while room.
    fn pop(&self) -> Option<(Arc<TcpSocket>, SocketAddr)> {
        let mut li = self.inner.lock().unwrap();
        let next = li.ready.pop_front()?;
        let mut drop_list = Vec::new();
        while !li.full() {
            let Some((child, conn, peer)) = li.syn.pop_front() else {
                break;
            };
            if conn.is_closed(0) {
                drop_list.push(child);
                continue;
            }
            conn.establish();
            li.ready.push_back((child, peer));
        }
        drop(li);
        for child in drop_list {
            child.release_inner(true);
        }
        self.room.wake(PollMask::empty());
        Some(next)
    }
}

impl Pollable for TcpSocket {
    /// `tcp_poll` and `inet_csk_listen_poll`.
    fn poll(&self, mut table: Option<&mut PollTable<'_>>) -> PollMask {
        // The one queue, whatever the state: the transport wakes it too.
        poll_wait(&mut table, &self.wq);
        let g = self.lock();
        match &g.state {
            State::Listening(l) => {
                if l.inner.lock().unwrap().ready.is_empty() {
                    PollMask::empty()
                } else {
                    PollMask::IN | PollMask::RDNORM
                }
            }
            State::Connecting(t, _) | State::Connected(t, _) => {
                let waiting_local = g.endpoint_selected
                    && matches!(&g.state, State::Connecting(..))
                    && matches!(t, Transport::Remote(stream) if stream.provider_local_addr() == Some(Err(Errno::EAGAIN)));
                let t = t.clone();
                drop(g);
                let events = t.poll();
                if waiting_local {
                    events & !(PollMask::OUT | PollMask::WRNORM)
                } else {
                    events
                }
            }
            State::Closed => {
                let mut m = PollMask::HUP | PollMask::OUT | PollMask::WRNORM;
                if g.rd_shut {
                    m |= PollMask::IN | PollMask::RDNORM | PollMask::RDHUP;
                }
                if g.err.is_some() {
                    m |= PollMask::ERR;
                }
                m
            }
        }
    }
}

impl Socket for TcpSocket {
    fn set_cork_timer(&self, arm: Box<dyn Fn(bool) + Send + Sync>) {
        self.lock().cork_timer = Some(arm);
    }

    fn cork_expire(&self) {
        let mut g = self.lock();
        g.cork_armed = false;
        let transport = match &g.state {
            State::Connected(t, _) => Some(t.clone()),
            _ => None,
        };
        drop(g);
        if let Some(t) = transport {
            t.push();
        }
    }

    fn domain(&self) -> Domain {
        if self.domain.load(Ordering::Acquire) == Domain::Inet6 as u8 {
            Domain::Inet6
        } else {
            Domain::Inet
        }
    }

    fn kind(&self) -> SocketKind {
        SocketKind::Stream
    }

    fn protocol(&self) -> i32 {
        6
    }

    fn bind(&self, addr: SocketAddr, privileged: bool) -> NetResult<()> {
        self.net.admit(addr, crate::PolicyDirection::Inbound)?;
        let requested = addr;
        let mapped = matches!(addr, SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some());
        let addr = canonical(addr);
        let mut g = self.lock();
        if mapped && g.opts.v6only {
            return Err(Errno::EINVAL);
        }
        let freebind = g.opts.flag(0, wasixv2_abi::IpOption::IP_FREEBIND.0);
        self.net.check_bind(addr, privileged, freebind)?;
        if g.bind_pending.is_some() || g.local.is_some() || !matches!(g.state, State::Closed) {
            return Err(Errno::EINVAL);
        }
        // `__inet_bind`: without a port, the address waits for the port `connect` picks.
        if addr.port() == 0
            && g.opts
                .flag(0, wasixv2_abi::IpOption::IP_BIND_ADDRESS_NO_PORT.0)
        {
            g.policy_bind = Some(requested);
            g.saddr = Some(addr.ip());
            g.addr_locked |= !addr.ip().is_unspecified();
            return Ok(());
        }
        let port = self.net.tcp_bind(
            self.id,
            self.spec(&g.opts, addr.ip()),
            addr.port(),
            self.me.clone(),
        )?;
        g.policy_bind = Some(requested);
        g.local = Some(SocketAddr::new(addr.ip(), port));
        g.saddr = None;
        g.port_locked = addr.port() != 0;
        g.addr_locked |= !addr.ip().is_unspecified();
        Ok(())
    }

    fn bind_admission(
        &self,
        requested: SocketAddr,
        privileged: bool,
    ) -> NetResult<Option<Box<dyn crate::BindAdmission>>> {
        self.provider_bind(requested, privileged, true, EndpointBindPurpose::Bind)
    }

    fn autobind_admission(
        &self,
        operation: crate::endpoint::EndpointAutobind<'_>,
        privileged: bool,
    ) -> NetResult<Option<Box<dyn crate::BindAdmission>>> {
        match operation {
            crate::endpoint::EndpointAutobind::Listen(backlog) => self.provider_bind(
                unbound(self.domain()),
                privileged,
                false,
                EndpointBindPurpose::Listen { backlog },
            ),
            _ => Ok(None),
        }
    }

    fn listen(&self, backlog: u32) -> NetResult<()> {
        let mut g = loop {
            let requested = self.lock().policy_bind;
            self.net.admit(
                requested.unwrap_or(unbound(self.domain())),
                crate::PolicyDirection::Inbound,
            )?;
            let g = self.lock();
            if g.policy_bind == requested {
                break g;
            }
        };
        if g.bind_pending.is_some() {
            return Err(Errno::EALREADY);
        }
        match &g.state {
            State::Listening(l) => {
                l.inner.lock().unwrap().backlog = backlog;
                if let Some(p) = l.publication.lock().unwrap().as_ref() {
                    p.set_backlog(backlog);
                }
                // A larger queue may have room for connections held back.
                l.room.wake(PollMask::empty());
                let group = self.net.endpoints().map(|ns| {
                    let group = ns.join_tcp(
                        &self.endpoint,
                        self.me.clone(),
                        EndpointMember {
                            source_id: self.endpoint.source(),
                            local: g.local.unwrap(),
                            requested_bind: g.policy_bind,
                            binding: g.endpoint_bound.clone(),
                        },
                        self.domain(),
                        g.opts.v6only,
                        backlog,
                    );
                    (ns, group)
                });
                drop(g);
                if let Some((ns, group)) = group {
                    ns.refresh(&group);
                }
                return Ok(());
            }
            State::Connecting(..) | State::Connected(..) => return Err(Errno::EINVAL),
            State::Closed => {}
        }
        self.autobind(&mut g)?;
        let local = g.local.expect("bound");
        self.net.state().tcp.listen(self.id, local.port())?;
        let l = Arc::new(Listener {
            wq: self.wq.clone(),
            room: WaitQueue::new(),
            inner: Mutex::new(ListenerInner {
                backlog,
                closed: false,
                ready: VecDeque::new(),
                syn: VecDeque::new(),
            }),
            publication: Mutex::new(None),
        });
        *self.listener.lock().unwrap() = Some(l.clone());
        g.state = State::Listening(l.clone());
        g.rd_shut = false;
        g.wr_shut = false;
        let group = self.net.endpoints().map(|ns| {
            let group = ns.join_tcp(
                &self.endpoint,
                self.me.clone(),
                EndpointMember {
                    source_id: self.endpoint.source(),
                    local,
                    requested_bind: g.policy_bind,
                    binding: g.endpoint_bound.clone(),
                },
                self.domain(),
                g.opts.v6only,
                backlog,
            );
            (ns, group)
        });
        let provider_bound = g.endpoint_bound.is_some();
        drop(g);
        if let Some((ns, group)) = group {
            ns.refresh(&group);
        }
        if !provider_bound {
            self.auto_publish(&l, local, backlog);
        }
        Ok(())
    }

    fn accept(&self) -> NetResult<Accepted> {
        let l = self.listener.lock().unwrap().clone().ok_or(Errno::EINVAL)?;
        let (socket, peer) = l.pop().ok_or(Errno::EAGAIN)?;
        // Historical host networking admits the accepted peer as an outbound address.
        if self.net.config.policy.as_ref().is_some_and(|p| {
            !p.allows_socket(
                present(self.domain(), peer),
                crate::PolicyDirection::Outbound,
            )
        }) {
            return Err(Errno::EPERM);
        }
        Ok(Accepted {
            socket,
            peer: present(self.domain(), peer),
        })
    }

    fn connect(&self, addr: SocketAddr) -> NetResult<()> {
        let mut admission = self.net.admit(addr, crate::PolicyDirection::Outbound)?;
        let mapped = matches!(addr, SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some());
        let dst = connect_target(canonical(addr));
        // Canonical table keys omit IPv6 scope/flow, but the physical provider needs the
        // literal sockaddr. Wildcard connect retains its existing loopback translation.
        let provider_dst = if canonical(addr).ip().is_unspecified() {
            dst
        } else {
            addr
        };
        let mut g = self.lock();
        if g.bind_pending.is_some() {
            return Err(Errno::EALREADY);
        }
        match &g.state {
            State::Listening(_) | State::Connected(..) => return Err(Errno::EISCONN),
            State::Connecting(..) => return Err(Errno::EALREADY),
            State::Closed if g.failed => {
                // `__inet_stream_connect` after an asynchronous failure: report it once.
                g.failed = false;
                return Err(g.err.take().unwrap_or(Errno::ECONNABORTED));
            }
            State::Closed => {}
        }
        if mapped && g.opts.v6only {
            return Err(Errno::ENETUNREACH);
        }
        // An opt-in external provider may own an address/route absent from this namespace.
        // Keep the ordinary route error intact until pure selection chooses its owner.
        let mut path = self.net.path(dst, g.local.map(|l| l.ip()).or(g.saddr));
        if admission == crate::net::Admission::DnsOnly && !matches!(&path, Ok(Path::Dns { .. })) {
            return Err(Errno::EPERM);
        }
        let mut provider_route = None;
        if let Some(namespace) = self.net.endpoints() {
            if !namespace.external
                && let Err(error) = &path
            {
                return Err(*error);
            }
            // Every new association attempt has an identity even after an immediate refusal.
            self.endpoint.renew(&namespace);
            loop {
                let external_candidate =
                    namespace.external && self.net.external_route_candidate(dst)?;
                let eligible = match &path {
                    Ok(Path::Local { net: None, .. }) => true,
                    Ok(Path::Backend { .. }) => namespace.external,
                    Err(Errno::ENETUNREACH | Errno::EADDRNOTAVAIL) => external_candidate,
                    // Explicit route denial, DNS and private/veth paths keep their authority.
                    _ => false,
                };
                if !eligible {
                    break;
                }
                let source = self.endpoint.source();
                let bound = g.local;
                let saddr = g.saddr;
                let v6only = g.opts.v6only;
                let requested_bind = g.policy_bind;
                let binding = g.endpoint_bound.clone();
                let provider_source =
                    bound.map(|local| local.ip()).or(saddr).unwrap_or_else(|| {
                        if dst.is_ipv4() {
                            std::net::Ipv4Addr::UNSPECIFIED.into()
                        } else {
                            std::net::Ipv6Addr::UNSPECIFIED.into()
                        }
                    });
                let provider_source = if namespace.external {
                    provider_source
                } else {
                    path.as_ref().unwrap().src()
                };
                let effective =
                    SocketAddr::new(provider_source, bound.map_or(0, |local| local.port()));
                let query = EndpointQuery {
                    kind: EndpointKind::Stream,
                    source_id: source,
                    bound,
                    requested_bind,
                    binding: binding.clone(),
                    effective_source: Some(effective),
                    destination: dst,
                    local_binding: namespace.hint(EndpointKind::Stream, dst, effective),
                };
                drop(g);
                let choice = namespace.provider.select(&query)?;
                // Selection admits no transport work. Recheck policy before the factory.
                admission = self.net.admit(addr, crate::PolicyDirection::Outbound)?;
                g = self.lock();
                if g.bind_pending.is_some() {
                    return Err(Errno::EALREADY);
                }
                if !matches!(g.state, State::Closed) {
                    return Err(if matches!(g.state, State::Connecting(..)) {
                        Errno::EALREADY
                    } else {
                        Errno::EISCONN
                    });
                }
                let next = self.net.path(dst, g.local.map(|l| l.ip()).or(g.saddr));
                let same_path = match (&path, &next) {
                    (Ok(old), Ok(new)) => old.endpoint_same(new),
                    (Err(old), Err(new)) => old == new,
                    _ => false,
                };
                let same_binding = match (&binding, &g.endpoint_bound) {
                    (None, None) => true,
                    (Some(old), Some(new)) => Arc::ptr_eq(old, new),
                    _ => false,
                };
                if source != self.endpoint.source()
                    || bound != g.local
                    || saddr != g.saddr
                    || v6only != g.opts.v6only
                    || requested_bind != g.policy_bind
                    || !same_binding
                    || !same_path
                    || (namespace.external
                        && external_candidate != self.net.external_route_candidate(dst)?)
                {
                    path = next;
                    continue;
                }
                if let EndpointChoice::Provider(target) = choice {
                    if admission == crate::net::Admission::DnsOnly {
                        return Err(Errno::EPERM);
                    }
                    provider_route = Some(ConnectRoute::Provider {
                        target,
                        source: provider_source,
                    });
                }
                break;
            }
        }
        let route = match provider_route {
            Some(route) => route,
            None => ConnectRoute::Namespace(path?),
        };
        if admission == crate::net::Admission::DnsOnly
            && !matches!(&route, ConnectRoute::Namespace(Path::Dns { .. }))
        {
            return Err(Errno::EPERM);
        }
        // Nothing answers out there: Linux's connect fails once neighbour resolution gives up.
        if matches!(&route, ConnectRoute::Namespace(Path::Nowhere { .. })) {
            return Err(Errno::EHOSTUNREACH);
        }
        let src = match &route {
            ConnectRoute::Namespace(path) => path.src(),
            ConnectRoute::Provider { source, .. } => *source,
        };
        match g.local {
            None => {
                let port = self.net.tcp_bind_connect(
                    self.id,
                    self.spec(&g.opts, src),
                    dst,
                    self.me.clone(),
                )?;
                g.local = Some(SocketAddr::new(src, port));
            }
            Some(local) if local.ip().is_unspecified() => {
                self.net.state().tcp.rehash(self.id, local.port(), src);
                g.local = Some(SocketAddr::new(src, local.port()));
            }
            Some(_) => {}
        }
        g.rd_shut = false;
        g.wr_shut = false;
        g.err = None;
        g.endpoint_selected = matches!(&route, ConnectRoute::Provider { .. });
        let path = match route {
            ConnectRoute::Namespace(path) => path,
            ConnectRoute::Provider { target, .. } => {
                let namespace = self.net.endpoints().unwrap();
                let source = self.endpoint.source();
                let local = g.local.unwrap();
                let pending = PendingStream::new(dst, self.wq.clone());
                let reserved: Arc<dyn BackendStream> = pending.clone();
                g.state = State::Connecting(Transport::Remote(reserved.clone()), dst);
                drop(g);
                let result = namespace.provider.connect(
                    target,
                    source,
                    local,
                    provider_dst,
                    self.wq.clone(),
                );
                let failure = result.as_ref().err().copied();
                let mut g = self.lock();
                let current = self.endpoint.source() == source
                    && matches!(&g.state,State::Connecting(Transport::Remote(stream),_) if Arc::ptr_eq(stream,&reserved));
                if current {
                    match result {
                        Ok(stream) => {
                            if canonical(stream.peer_addr()) != dst {
                                pending.complete(Err(Errno::EPROTO));
                            } else {
                                replay_options(&*stream, &g.opts);
                                pending.complete(Ok(stream));
                            }
                        }
                        Err(e) => pending.complete(Err(e)),
                    }
                    self.refresh(&mut g);
                    if let Some(error) = failure {
                        g.failed = false;
                        g.err = None;
                        return Err(error);
                    }
                } else {
                    drop(g);
                    drop(result);
                    pending.complete(Err(Errno::ECANCELED));
                    return Err(Errno::ECANCELED);
                }
                return Err(Errno::EINPROGRESS);
            }
        };
        match path {
            Path::Local { net, .. } => {
                let target = net.unwrap_or_else(|| self.net.clone());
                self.connect_local(&mut g, dst, &target)
            }
            Path::Nowhere { .. } => unreachable!("refused above"),
            Path::Dns { .. } => {
                let stream = self.net.dns_connect(dst, self.wq.clone());
                g.state = State::Connecting(Transport::Remote(stream), dst);
                Err(Errno::EINPROGRESS)
            }
            Path::Backend { host_dst, .. } => {
                let backend = self.net.backend.clone().ok_or(Errno::ENETUNREACH)?;
                match backend.connect(host_dst, self.wq.clone()) {
                    Ok(stream) => {
                        replay_options(&*stream, &g.opts);
                        g.state = State::Connecting(Transport::Remote(stream), dst);
                        Err(Errno::EINPROGRESS)
                    }
                    Err(e) => {
                        self.put_port(&mut g);
                        Err(e)
                    }
                }
            }
        }
    }

    fn disconnect(&self) -> NetResult<()> {
        // `tcp_disconnect`: abort whatever is going on and return to CLOSE, which gives back
        // an autobound port (`tcp_set_state` calls `inet_put_port`) and the source address.
        let mut g = self.lock();
        self.stop_listening(&mut g);
        if let Some(namespace) = self.net.endpoints() {
            self.endpoint.renew(&namespace);
        }
        self.abort_connection(&mut g);
        g.rd_shut = false;
        g.wr_shut = false;
        g.failed = false;
        self.reset_saddr(&mut g);
        self.put_port(&mut g);
        drop(g);
        self.wq.wake(PollMask::empty());
        Ok(())
    }

    fn shutdown(&self, how: Shutdown) -> NetResult<()> {
        let mut g = self.lock();
        match &g.state {
            State::Listening(_) => {
                if how != Shutdown::Write {
                    self.stop_listening(&mut g);
                }
                Ok(())
            }
            // `inet_shutdown` in `SYN_SENT` disconnects (`tcp_disconnect`).
            State::Connecting(..) => {
                if let Some(namespace) = self.net.endpoints() {
                    self.endpoint.renew(&namespace);
                }
                self.abort_connection(&mut g);
                self.reset_saddr(&mut g);
                self.put_port(&mut g);
                drop(g);
                self.wq.wake(PollMask::empty());
                Ok(())
            }
            // A connection reset or refused is in CLOSE: the shutdown is recorded, the
            // answer is ENOTCONN.
            State::Connected(t, _) if t.is_done() => {
                let t = t.clone();
                drop(g);
                let _ = t.shutdown(how);
                self.wq.wake(PollMask::empty());
                Err(Errno::ENOTCONN)
            }
            State::Connected(t, _) => {
                let t = t.clone();
                drop(g);
                t.shutdown(how)
            }
            State::Closed => {
                // `inet_shutdown` on a CLOSE socket: record it, wake pollers, ENOTCONN.
                g.rd_shut |= how != Shutdown::Write;
                g.wr_shut |= how != Shutdown::Read;
                drop(g);
                self.wq.wake(PollMask::empty());
                Err(Errno::ENOTCONN)
            }
        }
    }

    fn send(&self, msg: SendMsg<'_>) -> NetResult<usize> {
        // Linux's TCP ignores a destination address on a connected socket.
        let mut g = self.lock();
        let t = match &g.state {
            State::Connected(t, _) => t.clone(),
            State::Connecting(..) => return Err(Errno::EAGAIN),
            State::Listening(_) | State::Closed => {
                return Err(g.err.take().unwrap_or(Errno::EPIPE));
            }
        };
        let more = msg.flags.contains(MsgFlags::MSG_MORE)
            || g.opts.flag(SocketLevel::SOL_TCP.0, TcpOption::TCP_CORK.0);
        let mss = if g.opts.user_mss != 0 {
            g.opts.user_mss as usize
        } else {
            match &t {
                Transport::Local(..) => opts::TCP_MSS_LOOPBACK as usize,
                _ => 1460,
            }
        };
        drop(g);
        let result = t.write_more(msg.data, msg.flags.contains(MsgFlags::MSG_OOB), more, mss);
        let pending = t.corked_len() != 0;
        let mut g = self.lock();
        if !matches!(&g.state, State::Connected(current, _) if current.same(&t)) {
            return result;
        }
        if pending != g.cork_armed
            && let Some(arm) = &g.cork_timer
        {
            arm(pending);
            g.cork_armed = pending;
        }
        result
    }

    fn recv(&self, buf: &mut [u8], flags: MsgFlags) -> NetResult<RecvMsg> {
        if flags.0 & MsgFlags::MSG_OOB.0 != 0 {
            return self.recv_urgent(buf, flags);
        }
        if flags.0 & MsgFlags::MSG_ERRQUEUE.0 != 0 {
            return Err(Errno::EAGAIN);
        }
        let peek = flags.0 & MsgFlags::MSG_PEEK.0 != 0;
        let mut g = self.lock();
        let t = match &g.state {
            State::Connected(t, _) | State::Connecting(t, _) => t.clone(),
            State::Listening(_) => return Err(Errno::ENOTCONN),
            State::Closed => {
                if let Some(e) = g.err.take() {
                    return Err(e);
                }
                if g.rd_shut {
                    return Ok(RecvMsg::default());
                }
                return Err(Errno::ENOTCONN);
            }
        };
        drop(g);
        // MSG_TRUNC on TCP discards the bytes instead of copying them.
        let len = if flags.0 & MsgFlags::MSG_TRUNC.0 != 0 {
            let mut scratch = vec![0; buf.len()];
            t.read(&mut scratch, peek)?
        } else {
            t.read(buf, peek)?
        };
        Ok(RecvMsg {
            len,
            full_len: len,
            ..RecvMsg::default()
        })
    }

    fn local_addr(&self) -> NetResult<SocketAddr> {
        let g = self.lock();
        Ok(g.local
            .or(g.put_back)
            .or(g.saddr.map(|ip| SocketAddr::new(ip, 0)))
            .map_or(unbound(self.domain()), |a| present(self.domain(), a)))
    }

    fn peer_addr(&self) -> NetResult<SocketAddr> {
        let g = self.lock();
        match &g.state {
            State::Connected(t, peer) if !t.is_done() => Ok(present(self.domain(), *peer)),
            _ => Err(Errno::ENOTCONN),
        }
    }

    fn take_error(&self) -> Option<Errno> {
        let mut g = self.lock();
        match &g.state {
            State::Connected(t, _) | State::Connecting(t, _) => t.take_error().or(g.err.take()),
            _ => g.err.take(),
        }
    }

    fn input_len(&self) -> NetResult<usize> {
        let g = self.lock();
        match &g.state {
            State::Listening(_) => Err(Errno::EINVAL),
            State::Connected(t, _) | State::Connecting(t, _) => Ok(t.input_len()),
            State::Closed => Ok(0),
        }
    }

    fn at_mark(&self) -> NetResult<bool> {
        let g = self.lock();
        match &g.state {
            State::Connected(t, _) | State::Connecting(t, _) => Ok(t.at_mark()),
            _ => Ok(false),
        }
    }

    fn output_len(&self) -> NetResult<usize> {
        let g = self.lock();
        match &g.state {
            State::Listening(_) => Err(Errno::EINVAL),
            State::Connected(Transport::Local(c, side), _) => Ok(c.output_len(*side)),
            State::Connected(Transport::Remote(s), _) => Ok(s.output_len()),
            _ => Ok(0),
        }
    }

    fn set_option(&self, level: i32, name: i32, value: &[u8]) -> NetResult<()> {
        let mut g = self.lock();
        if (level, name)
            == (
                SocketLevel::SOL_IPV6.0,
                wasixv2_abi::Ipv6Option::IPV6_ADDRFORM.0,
            )
        {
            let peer = Self::addrform_peer(&g);
            g.opts.addrform(&self.net, value, peer, false)?;
            if let Some(local) = g.local {
                self.net
                    .state()
                    .tcp
                    .set_family(self.id, local.port(), Domain::Inet);
            }
            self.domain.store(Domain::Inet as u8, Ordering::Release);
            return Ok(());
        }
        if crate::mcast::handles(level, name) {
            return g.opts.set_mcast(&self.net, level, name, value);
        }
        let bound = g.local.is_some();
        let changed = g.opts.set(level, name, value, bound)?;
        match changed {
            Changed::Reuse => {
                if let Some(local) = g.local {
                    self.net.state().tcp.set_reuse(
                        self.id,
                        local.port(),
                        g.opts.reuseaddr,
                        g.opts.reuseport,
                    );
                }
            }
            Changed::Buffers => {
                if let State::Connected(Transport::Local(c, side), _) = &g.state {
                    c.set_buffers(*side, bufs(&g.opts));
                }
            }
            Changed::Nothing => {}
        }
        let mut push = None;
        if level == SocketLevel::SOL_TCP.0
            && ((name == TcpOption::TCP_NODELAY.0 && g.opts.flag(level, name))
                || (name == TcpOption::TCP_CORK.0 && !g.opts.flag(level, name)))
        {
            if let State::Connected(t, _) = &g.state {
                push = Some(t.clone());
            }
            if g.cork_armed {
                if let Some(arm) = &g.cork_timer {
                    arm(false);
                }
                g.cork_armed = false;
            }
        }
        if let State::Connected(Transport::Remote(s), _)
        | State::Connecting(Transport::Remote(s), _) = &g.state
        {
            let s = s.clone();
            drop(g);
            s.set_option(level, name, value)?;
        } else {
            drop(g);
        }
        if let Some(t) = push {
            t.push();
        }
        Ok(())
    }

    fn graft(&self, ino: u64) {
        self.ino.store(ino, Ordering::Relaxed);
    }

    fn get_option(&self, level: i32, name: i32, out: &mut [u8]) -> NetResult<usize> {
        let mut g = self.lock();
        if crate::mcast::handles(level, name) {
            return g.opts.get_mcast(&self.net, level, name, out);
        }
        if level == SocketLevel::SOL_SOCKET.0 && name == SocketOption::SO_ACCEPTCONN.0 {
            return Ok(opts::write_int(
                out,
                matches!(g.state, State::Listening(_)) as i32,
            ));
        }
        if level == SocketLevel::SOL_SOCKET.0 && name == SocketOption::SO_ERROR.0 {
            let err = match &g.state {
                State::Connected(t, _) | State::Connecting(t, _) => t.take_error(),
                _ => g.err.take(),
            };
            return Ok(opts::write_int(out, err.map_or(0, |e| e.0)));
        }
        let peer = if (level, name)
            == (
                SocketLevel::SOL_IPV6.0,
                wasixv2_abi::Ipv6Option::IPV6_ADDRFORM.0,
            ) {
            Self::addrform_peer(&g)
        } else {
            match &g.state {
                State::Connected(t, peer) if !t.is_done() => Some(peer.ip()),
                _ => None,
            }
        };
        if let Some(result) = g.opts.get_mtu(&self.net, peer, level, name, out) {
            return result;
        }
        if level == SocketLevel::SOL_TCP.0 && name == TcpOption::TCP_MAXSEG.0 {
            let mss = match &g.state {
                State::Connected(Transport::Local(..), _) => opts::TCP_MSS_LOOPBACK,
                State::Connected(..) => 1460,
                _ if g.opts.user_mss != 0 => g.opts.user_mss,
                _ => opts::TCP_MSS_DEFAULT,
            };
            return Ok(opts::write_int(out, mss));
        }
        if level == SocketLevel::SOL_TCP.0 && name == TcpOption::TCP_INFO.0 {
            // Synthesized: only `tcpi_state` is meaningful (DESIGN.md "Not supported").
            let state: u8 = match &g.state {
                State::Connected(t, _) if t.is_done() => 7,
                State::Connected(..) => 1,
                State::Connecting(..) => 2,
                State::Listening(_) => 10,
                State::Closed => 7,
            };
            let n = out.len().min(TCP_INFO_LEN);
            out[..n].fill(0);
            if n > 0 {
                out[0] = state;
            }
            return Ok(n);
        }
        g.opts.get(level, name, out)
    }
}

/// `sizeof(struct tcp_info)` in current Linux.
const TCP_INFO_LEN: usize = 248;

impl TcpSocket {
    /// `tcp_recvmsg` with `MSG_OOB` (`tcp_recv_urg`): the urgent byte, which `MSG_TRUNC` takes
    /// without copying and an empty buffer leaves with `MSG_TRUNC` set.
    fn recv_urgent(&self, buf: &mut [u8], flags: MsgFlags) -> NetResult<RecvMsg> {
        let g = self.lock();
        let t = match &g.state {
            State::Listening(_) => return Err(Errno::ENOTCONN),
            State::Connected(t, _) | State::Connecting(t, _) => t.clone(),
            // `tcp_disconnect` forgets the mark; a socket never connected has none.
            State::Closed => return Err(Errno::EINVAL),
        };
        drop(g);
        let byte = t.read_urgent(flags.contains(MsgFlags::MSG_PEEK))?;
        let mut out = MsgFlags::MSG_OOB;
        let len = match buf.first_mut() {
            Some(first) => {
                if !flags.contains(MsgFlags::MSG_TRUNC) {
                    *first = byte;
                }
                1
            }
            None => {
                out |= MsgFlags::MSG_TRUNC;
                0
            }
        };
        Ok(RecvMsg {
            len,
            full_len: len,
            flags: out,
            ..RecvMsg::default()
        })
    }

    /// Auto-publishing: mirror a non-loopback listener on the host. Failure is logged only.
    fn auto_publish(&self, l: &Listener, local: SocketAddr, backlog: u32) {
        let (Some(host_ip), Some(backend)) =
            (self.net.config.auto_publish, self.net.backend.as_ref())
        else {
            return;
        };
        if local.ip().is_loopback() {
            return;
        }
        let host = SocketAddr::new(host_ip, local.port());
        match backend.publish(host, backlog, self.net.inbound_sink(local)) {
            Ok(p) => *l.publication.lock().unwrap() = Some(p),
            Err(e) => tracing::warn!(%host, guest = %local, error = %e, "auto-publish failed"),
        }
    }
}

impl Drop for TcpSocket {
    /// The kernel dropped its last reference: `close`.
    fn drop(&mut self) {
        self.release_inner(false);
    }
}
