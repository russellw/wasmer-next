//! UDP sockets: datagrams move directly between the receive queues of a namespace's sockets;
//! datagrams for other destinations go through a backend datagram endpoint.

use std::{
    borrow::Cow,
    collections::{BTreeSet, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
};

use wasixv2_abi::{
    Errno, GuestLayout, IpOption, Ipv6Option, MsgFlags, SoEeOrigin, SockExtendedErr, SocketLevel,
    SocketOption,
};
use wasixv2_wait::{PollMask, PollTable, Pollable, WaitQueue, poll_wait};

use crate::{
    Accepted, BackendDatagram, Control, DatagramReadback, DatagramReadbackAdmission,
    DatagramReadbackValue, Domain, NetResult, PortEntry, Publication, QueuedError, RecvMsg,
    SendMsg, Shutdown, Socket, SocketKind,
    addr::{canonical, canonical_ip, present, sockaddr_bytes, unbound},
    bpf::{Arrival, PACKET_BROADCAST, PACKET_HOST, PACKET_LOOPBACK, PACKET_MULTICAST, SockFilter},
    cmsg::{self, SendCtl},
    endpoint::{
        AttemptGate, DatagramDelivery, EndpointBindPurpose, EndpointBindRequest, EndpointBound,
        EndpointChoice, EndpointDatagramTx, EndpointKind, EndpointMember, EndpointQuery,
        EndpointSource, EndpointSourceId, EndpointTarget, UdpTxConfig,
        runtime::{Namespace, SocketEndpoint},
    },
    icmp::{Back, IPPROTO_UDP, IPV4_HDR, IPV6_HDR, Quoted, UDP_HDR, udp_datagram},
    mcast::McRoute,
    net::{Net, Path, UdpRoute, serves},
    opts::{Changed, SockOpts},
    ports::{BindSpec, SockId},
};

/// What a queued datagram is charged against `SO_RCVBUF` on top of its payload, roughly the
/// `truesize` overhead of a small skb on 64-bit Linux.
const DGRAM_OVERHEAD: usize = 768;

/// The most `udp_sendmsg` takes at all, before the IP layer's own limit below.
const MAX_SEND: usize = 0xFFFF;
/// Largest UDP payload: 65535 minus the IP and UDP headers.
const MAX_V4_PAYLOAD: usize = 65507;
const MAX_V6_PAYLOAD: usize = 65527;

/// The options that make ICMP errors queue (`inet->recverr`, `np->recverr`).
const RECVERR: [(i32, i32); 2] = [
    (SocketLevel::SOL_IP.0, IpOption::IP_RECVERR.0),
    (SocketLevel::SOL_IPV6.0, Ipv6Option::IPV6_RECVERR.0),
];

struct Datagram {
    data: Vec<u8>,
    /// Canonical sender.
    from: SocketAddr,
    at: Arrival,
}

/// udp_sock::pending and the first send's cork metadata (udp_sendmsg/udpv6_sendmsg).
#[derive(Clone)]
struct Pending {
    policy_dst: SocketAddr,
    data: Vec<u8>,
    local: SocketAddr,
    dst: SocketAddr,
    scope: u32,
    ctl: SendCtl,
    now: std::time::Duration,
}

struct PreparedFlow<'a> {
    local: SocketAddr,
    dst: SocketAddr,
    scope: u32,
    ctl: SendCtl,
    data: Cow<'a, [u8]>,
}

/// Namespace paths and an admitted physical resource are distinct routing authorities.
enum ConnectRoute {
    Namespace(Path),
    External { source: IpAddr },
}
impl ConnectRoute {
    fn source(&self) -> IpAddr {
        match self {
            Self::Namespace(path) => path.src(),
            Self::External { source } => *source,
        }
    }
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Namespace(Path::Dns { src: a }), Self::Namespace(Path::Dns { src: b })) => {
                a == b
            }
            (
                Self::Namespace(Path::Nowhere {
                    src: a,
                    unresolved: x,
                }),
                Self::Namespace(Path::Nowhere {
                    src: b,
                    unresolved: y,
                }),
            ) => a == b && x == y,
            (
                Self::Namespace(Path::Local {
                    src: a,
                    net: Some(x),
                }),
                Self::Namespace(Path::Local {
                    src: b,
                    net: Some(y),
                }),
            ) => a == b && Arc::ptr_eq(x, y),
            (Self::Namespace(a), Self::Namespace(b)) => a.endpoint_same(b),
            (Self::External { source: a }, Self::External { source: b }) => a == b,
            _ => false,
        }
    }
}

#[derive(Clone)]
enum EndpointConnection {
    Local,
    Host,
    Peer(EndpointTarget),
}
#[derive(Clone)]
enum WriteSlot {
    Host(Arc<dyn BackendDatagram>),
    // Retain the selected peer identity while its unaccepted send is the poll witness.
    Peer { _target: EndpointTarget },
}
#[derive(Clone)]
struct WriteFocus {
    source: EndpointSourceId,
    revision: u64,
    slot: WriteSlot,
    _destination: SocketAddr,
}

struct Inner {
    opts: SockOpts,
    cork: bool,
    pending: Option<Pending>,
    local: Option<SocketAddr>,
    requested_bind: Option<SocketAddr>,
    bind_pending: Option<EndpointSourceId>,
    bind_admission: Weak<crate::endpoint::bind::Admission>,
    endpoint_bound: Option<Arc<dyn EndpointBound>>,
    /// Explicit source-only role captured ONCE from the admitted bound Arc.
    /// Ordinary backend presence never grants this capability.
    peer_datagram: Option<Arc<dyn BackendDatagram>>,
    /// `inet_rcv_saddr` of a bind that took no port (`IP_BIND_ADDRESS_NO_PORT`): the address
    /// the port taken later by `connect` or a send goes with.
    saddr: Option<IpAddr>,
    /// `SOCK_BINDADDR_LOCK` / `SOCK_BINDPORT_LOCK`.
    addr_locked: bool,
    port_locked: bool,
    peer: Option<SocketAddr>,
    policy_peer: Option<SocketAddr>,
    queue: VecDeque<Datagram>,
    /// `sk_rmem_alloc`, which the error queue is charged against too.
    queued: usize,
    err: Option<Errno>,
    /// `sk_error_queue`: errors of datagrams sent inside the namespace.
    errqueue: VecDeque<QueuedError>,
    rd_shut: bool,
    wr_shut: bool,
    /// The endpoint for traffic leaving the namespace, while the socket has one.
    backend: Option<Arc<dyn BackendDatagram>>,
    /// The publication the socket serves (its id and endpoint), whose endpoint is `backend`
    /// unless the socket is connected inside the namespace.
    published: Option<(u64, Arc<dyn BackendDatagram>)>,
    endpoint_tx: Option<Arc<dyn EndpointDatagramTx>>,
    endpoint_opening: bool,
    endpoint_revision: u64,
    endpoint_connection: Option<EndpointConnection>,
    endpoint_blocked: Option<WriteFocus>,
    endpoint_write_revision: u64,
    /// Replay keys only: values and memberships remain in canonical SockOpts/Mcast.
    endpoint_option_keys: BTreeSet<(i32, i32)>,
    /// Socket-wide; unlike a TX revision it is never reset by connect/disconnect.
    endpoint_option_version: u64,
}

fn policy_destination(g: &Inner, msg: &SendMsg<'_>) -> Option<SocketAddr> {
    g.pending
        .as_ref()
        .map(|p| p.policy_dst)
        .or(msg.to)
        .or(g.policy_peer)
}

/// A UDP socket of a [`Net`].
pub struct UdpSocket {
    net: Arc<Net>,
    id: SockId,
    endpoint: SocketEndpoint,
    domain: AtomicU8,
    /// `sk_uid`, for `SO_REUSEPORT`.
    uid: u32,
    /// `sock_i_ino`: the inode of the socket's file, 0 until it has one.
    ino: AtomicU64,
    wq: WaitQueue,
    me: Weak<UdpSocket>,
    inner: Mutex<Inner>,
    /// Serializes bounded selected-provider controls, not socket/network state or async waits.
    endpoint_control: Mutex<()>,
    /// The auto-publication of the bound port, for as long as the socket lives.
    auto_publication: Mutex<Option<Box<dyn Publication>>>,
}

/// The admitted callback owns the exact provider resource until terminal
/// completion. The subscription owns no guest memory and does not keep the
/// canonical socket alive after an interrupted syscall releases its fd owner.
struct ReadbackTxn {
    socket: Weak<UdpSocket>,
    bound: Arc<dyn EndpointBound>,
    backend: Arc<dyn BackendDatagram>,
    source: EndpointSourceId,
    query: DatagramReadback,
    domain: Domain,
    queue: WaitQueue,
    state: Mutex<ReadbackState>,
}
#[derive(Default)]
struct ReadbackState {
    started: bool,
    accepted: bool,
    result: Option<NetResult<DatagramReadbackValue>>,
}
struct ReadbackSubscription(Arc<ReadbackTxn>);
impl ReadbackTxn {
    fn current(&self) -> bool {
        let Some(socket) = self.socket.upgrade() else {
            return false;
        };
        let g = socket.lock();
        socket.endpoint.source() == self.source
            && g.endpoint_bound
                .as_ref()
                .is_some_and(|bound| Arc::ptr_eq(bound, &self.bound))
            && g.peer_datagram
                .as_ref()
                .is_some_and(|backend| Arc::ptr_eq(backend, &self.backend))
    }
    fn finish(&self, result: NetResult<DatagramReadbackValue>) {
        // A physical error is authoritative. Only a successful stale result
        // becomes cancellation; neither path can publish into a replacement.
        let result = result.and_then(|value| {
            if !self.query.accepts(value) {
                return Err(Errno::EPROTO);
            }
            if !self.current() {
                return Err(Errno::ECANCELED);
            }
            let address = |address: SocketAddr| {
                let address = if self.domain == Domain::Inet {
                    canonical(address)
                } else {
                    address
                };
                if self.domain == Domain::Inet && !address.is_ipv4() {
                    return Err(Errno::EPROTO);
                }
                // present maps v4 to v6-mapped for an AF_INET6 owner, and
                // leaves native IPv6 scope/flowinfo untouched.
                Ok(present(self.domain, address))
            };
            Ok(match value {
                DatagramReadbackValue::Local(value) => {
                    DatagramReadbackValue::Local(address(value)?)
                }
                DatagramReadbackValue::Peer(value) => {
                    DatagramReadbackValue::Peer(value.map(address).transpose()?)
                }
                value => value,
            })
        });
        let wake = {
            let mut state = self.state.lock().unwrap();
            if state.result.is_none() {
                state.result = Some(result);
            }
            state.accepted
        };
        if wake {
            self.queue.wake(PollMask::OUT | PollMask::ERR);
        }
    }
    fn drive(self: &Arc<Self>) {
        {
            let mut state = self.state.lock().unwrap();
            if state.started {
                return;
            }
            state.started = true;
        }
        if !self.current() {
            let mut state = self.state.lock().unwrap();
            state.accepted = true;
            state.result = Some(Err(Errno::ECANCELED));
            drop(state);
            self.queue.wake(PollMask::ERR);
            return;
        }
        let completed = self.clone();
        // No transaction, socket, namespace or endpoint-control guard crosses
        // this call. Its FnOnce callback may complete INLINE safely.
        let admission = self
            .backend
            .start_readback(self.query, Box::new(move |result| completed.finish(result)));
        {
            let mut state = self.state.lock().unwrap();
            match admission {
                Some(Ok(())) => {}
                Some(Err(error)) => {
                    state.result = Some(Err(if state.result.is_some() {
                        Errno::EPROTO
                    } else {
                        error
                    }));
                }
                None => {
                    // peer_datagram selected this explicit source-only profile.
                    // Unavailable actual readback cannot become a cached value.
                    state.result = Some(Err(if state.result.is_some() {
                        Errno::EPROTO
                    } else {
                        Errno::EOPNOTSUPP
                    }));
                }
            }
            state.accepted = true;
        }
        self.queue.wake(PollMask::OUT | PollMask::ERR);
    }
    fn result(&self) -> Option<NetResult<DatagramReadbackValue>> {
        let state = self.state.lock().unwrap();
        state.accepted.then_some(state.result).flatten()
    }
}
impl Pollable for ReadbackSubscription {
    fn poll(&self, mut table: Option<&mut PollTable<'_>>) -> PollMask {
        poll_wait(&mut table, &self.0.queue);
        self.0.drive();
        match self.0.result() {
            Some(Ok(_)) => PollMask::OUT,
            Some(Err(_)) => PollMask::ERR,
            None => PollMask::empty(),
        }
    }
}
impl DatagramReadbackAdmission for ReadbackSubscription {
    fn complete_result(&self) -> Option<NetResult<DatagramReadbackValue>> {
        self.0.drive();
        self.0.result()
    }
}

impl UdpSocket {
    pub(crate) fn new(net: Arc<Net>, domain: Domain, uid: u32) -> Arc<Self> {
        let id = net.next_id();
        Arc::new_cyclic(|me| Self {
            net,
            id,
            endpoint: SocketEndpoint::new(id),
            domain: AtomicU8::new(domain as u8),
            uid,
            ino: AtomicU64::new(0),
            wq: WaitQueue::new(),
            me: me.clone(),
            inner: Mutex::new(Inner {
                opts: SockOpts::new(SocketKind::Datagram, domain),
                cork: false,
                pending: None,
                local: None,
                requested_bind: None,
                bind_pending: None,
                bind_admission: Weak::new(),
                endpoint_bound: None,
                peer_datagram: None,
                saddr: None,
                addr_locked: false,
                port_locked: false,
                peer: None,
                policy_peer: None,
                queue: VecDeque::new(),
                queued: 0,
                err: None,
                errqueue: VecDeque::new(),
                rd_shut: false,
                wr_shut: false,
                backend: None,
                published: None,
                endpoint_tx: None,
                endpoint_opening: false,
                endpoint_revision: 1,
                endpoint_connection: None,
                endpoint_blocked: None,
                endpoint_write_revision: 0,
                endpoint_option_keys: BTreeSet::new(),
                endpoint_option_version: 0,
            }),
            endpoint_control: Mutex::new(()),
            auto_publication: Mutex::new(None),
        })
    }

    fn selected_option(level: i32, name: i32) -> bool {
        (level == SocketLevel::SOL_SOCKET.0
            && [SocketOption::SO_BROADCAST.0, SocketOption::SO_DONTROUTE.0].contains(&name))
            || (level == SocketLevel::SOL_IP.0
                && [
                    IpOption::IP_TTL.0,
                    IpOption::IP_MULTICAST_TTL.0,
                    IpOption::IP_MULTICAST_IF.0,
                    IpOption::IP_MULTICAST_LOOP.0,
                    IpOption::IP_ADD_MEMBERSHIP.0,
                    IpOption::IP_DROP_MEMBERSHIP.0,
                ]
                .contains(&name))
            || (level == SocketLevel::SOL_IPV6.0
                && [
                    Ipv6Option::IPV6_UNICAST_HOPS.0,
                    Ipv6Option::IPV6_MULTICAST_HOPS.0,
                    Ipv6Option::IPV6_MULTICAST_IF.0,
                    Ipv6Option::IPV6_MULTICAST_LOOP.0,
                    Ipv6Option::IPV6_ADD_MEMBERSHIP.0,
                    Ipv6Option::IPV6_DROP_MEMBERSHIP.0,
                ]
                .contains(&name))
    }

    fn selected_membership(level: i32, name: i32) -> bool {
        (level == SocketLevel::SOL_IP.0
            && [
                IpOption::IP_ADD_MEMBERSHIP.0,
                IpOption::IP_DROP_MEMBERSHIP.0,
            ]
            .contains(&name))
            || (level == SocketLevel::SOL_IPV6.0
                && [
                    Ipv6Option::IPV6_ADD_MEMBERSHIP.0,
                    Ipv6Option::IPV6_DROP_MEMBERSHIP.0,
                ]
                .contains(&name))
    }

    fn selected_option_value(&self, opts: &SockOpts, level: i32, name: i32) -> NetResult<Vec<u8>> {
        if level == SocketLevel::SOL_IP.0 && name == IpOption::IP_MULTICAST_IF.0 {
            let mut request = vec![0; 4];
            request.extend_from_slice(&opts.mc.addr4.octets());
            request.extend_from_slice(&opts.mc.requested_index4.to_le_bytes());
            return Ok(request);
        }
        let mut bytes = [0u8; 4];
        let n = if crate::mcast::handles(level, name) {
            opts.get_mcast(&self.net, level, name, &mut bytes)?
        } else {
            opts.get(level, name, &mut bytes)?
        };
        Ok(bytes[..n].to_vec())
    }

    fn selected_option_snapshot(&self, g: &Inner) -> NetResult<Vec<(i32, i32, Vec<u8>)>> {
        let mut options = Vec::new();
        for &(level, name) in &g.endpoint_option_keys {
            options.push((
                level,
                name,
                self.selected_option_value(&g.opts, level, name)?,
            ));
        }
        options.extend(g.opts.mc.backend_memberships()?);
        Ok(options)
    }

    fn set_selected_option(&self, level: i32, name: i32, value: &[u8]) -> NetResult<()> {
        // No state guard escapes into provider work. This gate serializes only bounded
        // nonreentrant controls; pending bind futures release it and reacquire at commit.
        let _control = self.endpoint_control.lock().unwrap();
        {
            let mut g = self.lock();
            if g.endpoint_bound.is_none() {
                let next_version = g
                    .endpoint_option_version
                    .checked_add(1)
                    .ok_or(Errno::EOVERFLOW)?;
                if crate::mcast::handles(level, name) {
                    g.opts.set_mcast(&self.net, level, name, value)?;
                } else {
                    let bound = g.local.is_some();
                    g.opts.set(level, name, value, bound)?;
                }
                if !Self::selected_membership(level, name) {
                    g.endpoint_option_keys.insert((level, name));
                }
                g.endpoint_option_version = next_version;
                return Ok(());
            }
        }
        let (next, prepared, bound, version) = {
            let g = self.lock();
            let mut next = g.opts.clone();
            let prepared = if crate::mcast::handles(level, name) {
                let prepared = next.prepare_selected_mcast(&self.net, level, name, value)?;
                next.mc = prepared.state().clone();
                Some(prepared)
            } else {
                next.set(level, name, value, g.local.is_some())?;
                None
            };
            (
                next,
                prepared,
                g.endpoint_bound.clone(),
                g.endpoint_option_version,
            )
        };
        let next_version = version.checked_add(1).ok_or(Errno::EOVERFLOW)?;
        let provider_value = if Self::selected_membership(level, name) {
            value.to_vec()
        } else {
            self.selected_option_value(&next, level, name)?
        };
        if let Some(bound) = &bound {
            bound.set_option(level, name, &provider_value)?;
        }
        let mut g = self.lock();
        // Source ids may change independently of the actual bound resource. The control
        // gate protects both renewals and this socket-wide version, avoiding stale-token close.
        let same = match (&bound, &g.endpoint_bound) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        if !same || version != g.endpoint_option_version {
            return Err(Errno::ECANCELED);
        }
        if let Some(mut prepared) = prepared {
            if let Some(bound) = &bound {
                prepared.admit_provider(bound);
            }
            match prepared.commit(&self.net) {
                Ok(mc) => g.opts.mc = mc,
                Err(error) => {
                    if bound.is_some() {
                        self.retire_selected_binding(&mut g);
                    }
                    return Err(error);
                }
            }
        } else {
            let bound_now = g.local.is_some();
            if let Err(error) = g.opts.set(level, name, &provider_value, bound_now) {
                if bound.is_some() {
                    self.retire_selected_binding(&mut g);
                }
                return Err(error);
            }
        }
        g.endpoint_option_version = next_version;
        if !Self::selected_membership(level, name) {
            g.endpoint_option_keys.insert((level, name));
        }
        Ok(())
    }

    fn retire_selected_binding(&self, g: &mut Inner) {
        if let Some(local) = g.local.take() {
            self.net.state().udp.unbind(self.id, local.port());
        }
        g.endpoint_bound = None;
        g.peer_datagram = None;
        g.peer = None;
        g.policy_peer = None;
        g.requested_bind = None;
        g.saddr = None;
        g.addr_locked = false;
        g.port_locked = false;
        g.backend = None;
        let _ = self.release_publication(g);
        if let Some(ns) = self.net.endpoints() {
            self.endpoint_reset(g, &ns);
        }
        self.wq.wake(PollMask::ERR | PollMask::HUP);
    }

    /// Changes only the captured external resource. Renew authority before a physical
    /// mutation so no old TX claim can configure the resource while its association changes.
    /// The caller holds the bounded control gate, but no state lock crosses provider calls.
    fn associate_bound<'a>(
        &'a self,
        mut g: MutexGuard<'a, Inner>,
        ns: &Namespace,
        peer: Option<SocketAddr>,
        selected_source: Option<EndpointSourceId>,
    ) -> (MutexGuard<'a, Inner>, NetResult<()>) {
        let Some(bound) = g.endpoint_bound.clone().filter(|_| ns.external) else {
            return (g, Ok(()));
        };
        let old_connection = g.endpoint_connection.clone();
        drop(g);
        let before_local = bound.local_addr();
        let before_peer = bound.datagram_peer_addr();
        g = self.lock();
        self.endpoint_reset(&mut g, ns);
        if let Some(source) = selected_source {
            self.endpoint.replace_source(ns, source);
        }
        let source = self.endpoint.source();
        drop(g);
        let result = bound.connect_datagram(source, peer);
        let after_local = bound.local_addr();
        let after_peer = bound.datagram_peer_addr();
        g = self.lock();
        let result = match result {
            None => Ok(()),
            Some(Err(error)) => {
                let unchanged = matches!((&before_local, &after_local), (Ok(a), Ok(b)) if a == b)
                    && matches!((&before_peer, &after_peer), (Some(Ok(a)), Some(Ok(b))) if a == b);
                if unchanged {
                    g.endpoint_connection = old_connection;
                    if let Some(local) = g.local {
                        self.endpoint_join(&g, local);
                    }
                } else {
                    self.retire_selected_binding(&mut g);
                }
                return (g, Err(error));
            }
            Some(Ok(())) => after_local.and_then(|actual| {
                let actual = canonical(actual);
                let previous = g.local.ok_or(Errno::ECANCELED)?;
                if actual.port() == 0 || actual.is_ipv4() != previous.is_ipv4() {
                    return Err(Errno::EPROTO);
                }
                if let Some(requested) = g.requested_bind {
                    let requested = canonical(requested);
                    if (requested.port() != 0 && requested.port() != actual.port())
                        || (!requested.ip().is_unspecified() && requested.ip() != actual.ip())
                    {
                        return Err(Errno::EPROTO);
                    }
                }
                self.net.state().udp.replace_bound(
                    self.id,
                    previous.port(),
                    self.spec(&g.opts, actual.ip()),
                    actual.port(),
                    self.me.clone(),
                )?;
                g.local = Some(actual);
                Ok(())
            }),
        };
        if result.is_err() {
            self.retire_selected_binding(&mut g);
        }
        (g, result)
    }

    fn provider_bind(
        &self,
        requested: SocketAddr,
        privileged: bool,
        explicit: bool,
    ) -> NetResult<Option<Box<dyn crate::BindAdmission>>> {
        let Some(namespace) = self.net.endpoints() else {
            return Ok(None);
        };
        let external = namespace.external;
        let original_bind = if explicit {
            Some(requested)
        } else {
            self.lock().requested_bind
        };
        let requested = original_bind.unwrap_or(requested);
        if explicit {
            self.net.admit(requested, crate::PolicyDirection::Inbound)?;
        }
        let _control = self.endpoint_control.lock().unwrap();
        let (request, admission) = {
            let mut g = self.lock();
            if !explicit {
                if g.local.is_some() {
                    return Ok(None);
                }
                if let Some(admission) = g.bind_admission.upgrade() {
                    return Ok(Some(admission.subscribe()));
                }
            }
            if !explicit && g.requested_bind != original_bind {
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
            if g.bind_pending.is_some() || g.local.is_some() || (explicit && g.saddr.is_some()) {
                return Err(Errno::EINVAL);
            }
            self.endpoint.renew(&namespace);
            let source_id = self.endpoint.source();
            let request = EndpointBindRequest {
                source_id,
                kind: EndpointKind::Datagram,
                requested,
                explicit: request_explicit,
                purpose: EndpointBindPurpose::Bind,
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
                    let peer_backend = bound.peer_datagram();
                    let _control = socket.endpoint_control.lock().unwrap();
                    let actual = crate::endpoint::bind::validate(request, actual)?;
                    let options = {
                        let g = socket.lock();
                        if g.bind_pending != Some(source_id)
                            || socket.endpoint.source() != source_id
                        {
                            return Err(Errno::ECANCELED);
                        }
                        if (g.opts.v6only, g.opts.reuseaddr, g.opts.reuseport)
                            != (request.v6only, request.reuse_addr, request.reuse_port)
                        {
                            return Err(Errno::ECANCELED);
                        }
                        if external {
                            socket.selected_option_snapshot(&g)?
                        } else {
                            Vec::new()
                        }
                    };
                    for (level, name, value) in options {
                        bound.set_option(level, name, &value)?;
                    }
                    socket.net.check_bind(
                        actual,
                        privileged,
                        freebind || external || requested.ip().is_unspecified(),
                    )?;
                    let mut g = socket.lock();
                    if g.bind_pending != Some(source_id) || socket.endpoint.source() != source_id {
                        return Err(Errno::ECANCELED);
                    }
                    socket.net.udp_bind(
                        socket.id,
                        socket.spec(&g.opts, actual.ip()),
                        actual.port(),
                        socket.me.clone(),
                    )?;
                    g.local = Some(actual);
                    g.requested_bind = request.explicit.then_some(requested);
                    g.saddr = None;
                    g.port_locked = request.explicit && requested.port() != 0;
                    g.addr_locked |=
                        request.explicit && !canonical(requested).ip().is_unspecified();
                    g.bind_pending = None;
                    g.bind_admission = Weak::new();
                    if external {
                        g.opts.mc.admit_provider(&bound);
                    }
                    g.endpoint_bound = Some(bound);
                    g.peer_datagram = peer_backend.clone();
                    if let Some(backend) = peer_backend {
                        g.backend = Some(backend);
                    }
                    socket.claim_publication(&mut g, None);
                    socket.endpoint_join(&g, actual);
                    let group = socket.endpoint.group();
                    let namespace = socket.net.endpoints();
                    drop(g);
                    drop(_control);
                    if let (Some(namespace), Some(group)) = (namespace, group) {
                        namespace.refresh(&group);
                    }
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
            (request, admission)
        };
        // Factories may reenter the socket; only the later bounded resource controls are
        // nonreentrant. Never retain even the control gate during a foreign factory.
        drop(_control);
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
                let _control = self.endpoint_control.lock().unwrap();
                let g = self.lock();
                if g.bind_pending != Some(request.source_id)
                    || self.endpoint.source() != request.source_id
                    || (g.opts.v6only, g.opts.reuseaddr, g.opts.reuseport)
                        != (request.v6only, request.reuse_addr, request.reuse_port)
                {
                    return Err(Errno::ECANCELED);
                }
                self.net.check_bind(
                    canonical(requested),
                    privileged,
                    g.opts.flag(0, wasixv2_abi::IpOption::IP_FREEBIND.0) || external,
                )?;
            }
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
        self.inner.lock().unwrap()
    }

    fn spec(&self, o: &SockOpts, ip: IpAddr) -> BindSpec {
        BindSpec {
            family: self.domain(),
            addr: ip,
            v6only: o.v6only,
            reuseaddr: o.reuseaddr,
            reuseport: o.reuseport,
            uid: self.uid,
        }
    }

    fn any(&self) -> IpAddr {
        match self.domain() {
            Domain::Inet => Ipv4Addr::UNSPECIFIED.into(),
            Domain::Inet6 => std::net::Ipv6Addr::UNSPECIFIED.into(),
        }
    }

    fn autobind(&self, g: &mut Inner) -> NetResult<SocketAddr> {
        if g.bind_pending.is_some() {
            return Err(Errno::EALREADY);
        }
        if let Some(local) = g.local {
            self.endpoint_join(g, local);
            return Ok(local);
        }
        let ip = g.saddr.unwrap_or(self.any());
        let port = self
            .net
            .udp_bind(self.id, self.spec(&g.opts, ip), 0, self.me.clone())?;
        let local = SocketAddr::new(ip, port);
        g.local = Some(local);
        self.endpoint_join(g, local);
        Ok(local)
    }

    fn endpoint_join(&self, g: &Inner, local: SocketAddr) {
        if let Some(ns) = self.net.endpoints() {
            ns.join_udp(
                &self.endpoint,
                self.me.clone(),
                EndpointMember {
                    source_id: self.endpoint.source(),
                    local,
                    requested_bind: g.requested_bind,
                    binding: g.endpoint_bound.clone(),
                },
                self.domain(),
                g.opts.v6only,
            );
        }
    }
    fn endpoint_config(&self, g: &Inner) -> UdpTxConfig {
        UdpTxConfig {
            source_id: self.endpoint.source(),
            revision: g.endpoint_revision,
            peer: g.peer,
            recv_v4_errors: g.opts.flag(RECVERR[0].0, RECVERR[0].1),
            recv_v6_errors: g.opts.flag(RECVERR[1].0, RECVERR[1].1),
        }
    }
    fn endpoint_reset(&self, g: &mut Inner, ns: &Namespace) {
        self.endpoint.renew(ns);
        g.endpoint_tx = None;
        g.endpoint_opening = false;
        g.endpoint_revision = 1;
        g.endpoint_connection = None;
        g.endpoint_blocked = None;
        g.endpoint_write_revision = 0;
        // This is the socket queue, not the publication gate queue. WaitEntry only records
        // readiness; it must not reenter socket state even when a wake holds its lock.
        self.wq.wake(PollMask::empty());
    }
    fn endpoint_same_route(previous: &UdpRoute, current: &UdpRoute) -> bool {
        match (previous, current) {
            (
                UdpRoute::External {
                    from: a,
                    interface: ai,
                },
                UdpRoute::External {
                    from: b,
                    interface: bi,
                },
            ) => a == b && ai == bi,
            (UdpRoute::Broadcast, UdpRoute::Broadcast) => true,
            (
                UdpRoute::Multicast {
                    from: a,
                    interface: ai,
                },
                UdpRoute::Multicast {
                    from: b,
                    interface: bi,
                },
            ) => a == b && ai == bi,

            (
                UdpRoute::Local {
                    from: a,
                    to: ta,
                    at: na,
                    iif: ia,
                    back_iif: ba,
                },
                UdpRoute::Local {
                    from: b,
                    to: tb,
                    at: nb,
                    iif: ib,
                    back_iif: bb,
                },
            ) => {
                a == b
                    && Arc::ptr_eq(na, nb)
                    && ia == ib
                    && ba == bb
                    && match (ta, tb) {
                        (None, None) => true,
                        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                        _ => false,
                    }
            }
            (UdpRoute::Backend { host_dst: a }, UdpRoute::Backend { host_dst: b }) => a == b,
            (UdpRoute::Dns { from: a }, UdpRoute::Dns { from: b }) => a == b,
            (
                UdpRoute::Nowhere {
                    from: a,
                    unresolved: ua,
                },
                UdpRoute::Nowhere {
                    from: b,
                    unresolved: ub,
                },
            ) => a == b && ua == ub,
            _ => false,
        }
    }
    /// Explicit unlocked factory/configuration path; no accepted payload is retried here.
    fn endpoint_prepare_tx(
        &self,
        ns: &Arc<Namespace>,
        source: EndpointSourceId,
    ) -> NetResult<Arc<dyn EndpointDatagramTx>> {
        loop {
            let mut g = self.lock();
            if self.endpoint.source() != source {
                return Err(Errno::ECANCELED);
            }
            let initial = self.endpoint_config(&g);
            let tx = if let Some(tx) = g.endpoint_tx.clone() {
                drop(g);
                tx
            } else {
                if g.endpoint_opening {
                    return Err(Errno::EAGAIN);
                }
                let local = g.local.ok_or(Errno::EINVAL)?;
                let group_id = self.endpoint.group_id().ok_or(Errno::EINVAL)?;
                let requested_bind = g.requested_bind;
                let binding = g.endpoint_bound.clone();
                g.endpoint_opening = true;
                drop(g);
                let result = ns.provider.datagram(
                    EndpointSource {
                        id: source,
                        group_id,
                        bound: local,
                        domain: self.domain(),
                        requested_bind,
                        binding,
                    },
                    initial,
                    self.wq.clone(),
                );
                let mut g = self.lock();
                if self.endpoint.source() != source {
                    drop(g);
                    drop(result);
                    return Err(Errno::ECANCELED);
                }
                g.endpoint_opening = false;
                let tx = match result {
                    Ok(tx) => tx,
                    Err(error) => {
                        drop(g);
                        self.wq.wake(PollMask::empty());
                        return Err(error);
                    }
                };
                g.endpoint_tx = Some(tx.clone());
                drop(g);
                self.wq.wake(PollMask::empty());
                tx
            };
            let config = {
                let g = self.lock();
                if self.endpoint.source() != source {
                    return Err(Errno::ECANCELED);
                }
                self.endpoint_config(&g)
            };
            tx.configure(config);
            let g = self.lock();
            if self.endpoint.source() != source {
                return Err(Errno::ECANCELED);
            }
            if g.endpoint_revision == config.revision {
                return Ok(tx);
            }
        }
    }
    fn endpoint_outcome(
        &self,
        source: EndpointSourceId,
        revision: u64,
        dispatch: u64,
        slot: WriteSlot,
        destination: SocketAddr,
        result: &NetResult<usize>,
    ) {
        let mut g = self.lock();
        if self.endpoint.source() == source
            && g.endpoint_revision == revision
            && g.endpoint_write_revision == dispatch
        {
            g.endpoint_blocked = if *result == Err(Errno::EAGAIN) {
                Some(WriteFocus {
                    source,
                    revision,
                    slot,
                    _destination: destination,
                })
            } else {
                None
            };
        }
    }

    fn multicast_takes(
        &self,
        g: &Inner,
        destination: SocketAddr,
        from: SocketAddr,
        interface: u32,
        external: bool,
    ) -> bool {
        let Some(local) = g.local else {
            return false;
        };
        let device = self.net.device_index(&g.opts.bind_device);
        let membership = if external {
            g.endpoint_bound.as_ref().is_some_and(|bound| {
                g.opts
                    .mc
                    .allows_selected(destination.ip(), from.ip(), interface, bound)
            })
        } else {
            g.opts.mc.allows(destination.ip(), from.ip(), interface)
        };
        serves(local, g.opts.v6only, canonical(destination))
            && g.peer.is_none_or(|peer| canonical(peer) == canonical(from))
            && (device == 0 || device == interface)
            && membership
    }

    pub(crate) fn deliver_endpoint_packet(
        &self,
        source: EndpointSourceId,
        gate: &AttemptGate,
        data: &[u8],
        info: crate::endpoint::DatagramInfo,
    ) -> DatagramDelivery {
        let from = info.source;
        let destination = info.destination;
        let at = Arrival {
            src: from.ip(),
            dst: destination.ip(),
            ttl: 64,
            traffic_class: 0,
            iif: info.interface,
            pkttype: if destination.ip().is_multicast() {
                PACKET_MULTICAST
            } else if matches!(info.destination.ip(), IpAddr::V4(ip) if ip.is_broadcast()) {
                PACKET_BROADCAST
            } else {
                PACKET_HOST
            },
        };
        let external = self.net.endpoints().is_some_and(|ns| ns.external);
        let (filter, port) = {
            let g = self.lock();
            if destination.ip().is_multicast()
                && !self.multicast_takes(&g, destination, from, info.interface, external)
            {
                return DatagramDelivery::Dropped;
            }
            let device = self.net.device_index(&g.opts.bind_device);
            if device != 0 && device != info.interface {
                return DatagramDelivery::Dropped;
            }
            (g.opts.filter.clone(), g.local.map_or(0, |a| a.port()))
        };
        let Some(data) = self.filtered(&filter, data, from, port, &at) else {
            return DatagramDelivery::Dropped;
        };
        let mut g = self.lock();
        if self.endpoint.source() != source {
            return DatagramDelivery::Retired;
        }
        if g.peer
            .is_some_and(|peer| canonical(peer) != canonical(from))
            || g.queued > g.opts.rcvbuf
            || (destination.ip().is_multicast()
                && !self.multicast_takes(&g, destination, from, info.interface, external))
            || {
                let device = self.net.device_index(&g.opts.bind_device);
                device != 0 && device != info.interface
            }
        {
            return DatagramDelivery::Dropped;
        }
        let result = self
            .endpoint
            .commit(source, || {
                gate.commit(|| {
                    g.queued += data.len() + DGRAM_OVERHEAD;
                    g.queue.push_back(Datagram {
                        data: data.to_vec(),
                        from,
                        at,
                    });
                })
            })
            .flatten();
        drop(g);
        if result.is_some() {
            self.wq.wake(PollMask::IN | PollMask::RDNORM);
            DatagramDelivery::Queued
        } else {
            DatagramDelivery::Retired
        }
    }

    pub(crate) fn port_entry(&self) -> Option<PortEntry> {
        let g = self.lock();
        Some(PortEntry {
            kind: SocketKind::Datagram,
            local: present(self.domain(), g.local?),
            peer: g.peer.map(|p| present(self.domain(), p)),
            listening: false,
            uid: self.uid,
            inode: self.ino.load(Ordering::Relaxed),
            rx_queue: g.queued,
            tx_queue: 0,
            v6only: g.opts.v6only,
            port_locked: g.port_locked,
            bound_dev: self.net.device_index(&g.opts.bind_device),
        })
    }

    /// `udp_queue_rcv_one_skb`: the socket's filter, then `__udp_enqueue_schedule_skb`, which
    /// drops when the queue already exceeds `SO_RCVBUF`.
    pub(crate) fn deliver(&self, data: &[u8], from: SocketAddr, at: &Arrival) {
        let (filter, port) = {
            let g = self.lock();
            (g.opts.filter.clone(), g.local.map_or(0, |l| l.port()))
        };
        let Some(data) = self.filtered(&filter, data, from, port, at) else {
            return;
        };
        let mut g = self.lock();
        if g.queued > g.opts.rcvbuf {
            return;
        }
        g.queued += data.len() + DGRAM_OVERHEAD;
        g.queue.push_back(Datagram {
            data: data.to_vec(),
            from,
            at: *at,
        });
        drop(g);
        self.wq.wake(PollMask::IN | PollMask::RDNORM);
    }

    /// `sk_filter_trim_cap` with the UDP header as the least kept: what of `data` the socket
    /// keeps, `None` for nothing.
    fn filtered<'a>(
        &self,
        filter: &SockFilter,
        data: &'a [u8],
        from: SocketAddr,
        port: u16,
        at: &Arrival,
    ) -> Option<&'a [u8]> {
        if !filter.attached() {
            return Some(data);
        }
        let udp = udp_datagram(from, SocketAddr::new(at.dst, port), data);
        let frame = self.net.frame(at, IPPROTO_UDP, &[], &udp, false);
        let keep = filter.trim(&frame.packet(), UDP_HDR)?;
        Some(&data[..keep - UDP_HDR])
    }

    /// A datagram from the backend endpoint, through the socket's filter: one the filter
    /// drops is taken off and the next one tried. It arrived on the uplink, for the bound
    /// address or the uplink's.
    fn backend_recv(
        &self,
        b: &dyn BackendDatagram,
        buf: &mut [u8],
        peek: bool,
        filter: &SockFilter,
    ) -> NetResult<(usize, usize, SocketAddr)> {
        if !filter.attached() {
            return b.recv_from(buf, peek);
        }
        let local = self.lock().local;
        let mut tmp = vec![0; MAX_SEND + 1];
        loop {
            let (n, _, host_from) = b.recv_from(&mut tmp, true)?;
            let from = self.net.guest_view(host_from);
            let uplink = self.net.uplink_index();
            let at = {
                let st = self.net.state();
                let bound = local.map(|l| canonical_ip(l.ip()));
                let dst = bound
                    .filter(|ip| !ip.is_unspecified())
                    .or_else(|| st.ifaces.source_on(uplink, from.ip()))
                    .unwrap_or(from.ip());
                Arrival {
                    src: from.ip(),
                    dst,
                    ttl: 64,
                    traffic_class: 0,
                    iif: uplink,
                    pkttype: PACKET_HOST,
                }
            };
            let port = local.map_or(0, |l| l.port());
            let kept = self
                .filtered(filter, &tmp[..n], from, port, &at)
                .map(<[u8]>::len);
            let Some(full) = kept else {
                b.recv_from(&mut tmp, false)?;
                continue;
            };
            let len = buf.len().min(full);
            buf[..len].copy_from_slice(&tmp[..len]);
            if !peek {
                b.recv_from(&mut tmp, false)?;
            }
            return Ok((len, full, host_from));
        }
    }

    /// The endpoint for traffic leaving the namespace, made on first use. It wakes this
    /// socket's queue, so waiters registered before it existed hear its datagrams.
    fn backend_endpoint(&self, g: &mut Inner) -> NetResult<Arc<dyn BackendDatagram>> {
        if let Some(peer) = &g.peer_datagram {
            return Ok(peer.clone());
        }
        if let Some(b) = &g.backend {
            return Ok(b.clone());
        }
        if let Some((_, ep)) = g.published.clone() {
            ep.attach(Some(self.wq.clone()))?;
            Self::forward_options(&g.opts, &*ep);
            g.backend = Some(ep.clone());
            return Ok(ep);
        }
        let backend = self.net.backend.as_ref().ok_or(Errno::ENETUNREACH)?;
        let b = backend.datagram(self.domain(), self.wq.clone())?;
        Self::forward_options(&g.opts, &*b);
        g.backend = Some(b.clone());
        Ok(b)
    }

    /// Takes a publication that reaches the socket's bound address, if one is free (`id`, or
    /// any). The socket's lock is held.
    fn claim_publication(&self, g: &mut Inner, id: Option<u64>) -> bool {
        if g.peer_datagram.is_some() {
            return false;
        }
        let Some(local) = g.local.filter(|_| g.published.is_none()) else {
            return false;
        };
        let sock = (self.id, self.me.clone());
        let Some((id, ep)) = self
            .net
            .claim_udp_publication(local, g.opts.v6only, sock, id)
        else {
            return false;
        };
        g.published = Some((id, ep));
        self.activate_publication(g);
        true
    }

    /// Offered publication `id` by the network: takes it if it reaches the bound address.
    pub(crate) fn adopt_publication(&self, id: u64) -> bool {
        self.claim_publication(&mut self.lock(), Some(id))
    }

    /// Publication `id` ended.
    pub(crate) fn lose_publication(&self, id: u64) {
        let mut g = self.lock();
        let Some((held, ep)) = g.published.take() else {
            return;
        };
        if held != id {
            g.published = Some((held, ep));
            return;
        }
        if g.backend.as_ref().is_some_and(|b| Arc::ptr_eq(b, &ep)) {
            g.backend = None;
        }
        drop(g);
        let _ = ep.attach(None);
    }

    /// Gives up the publication when the socket unbinds; the caller offers it on once no
    /// socket lock is held.
    fn release_publication(&self, g: &mut Inner) -> Option<u64> {
        let (id, ep) = g.published.take()?;
        if g.backend.as_ref().is_some_and(|b| Arc::ptr_eq(b, &ep)) {
            g.backend = None;
        }
        let _ = ep.attach(None);
        self.net.release_udp_publication(id, self.id);
        Some(id)
    }

    /// Makes the published endpoint serve the socket as fits its peer: unconnected, or
    /// connected outside the namespace (the endpoint then connected to the host's view of the
    /// peer), it is the socket's way in and out; connected inside the namespace, nothing from
    /// outside is for the socket, so the endpoint drops what arrives.
    fn activate_publication(&self, g: &mut Inner) {
        if g.peer_datagram.is_some() {
            return;
        }
        let Some((_, ep)) = g.published.clone() else {
            return;
        };
        let host_peer = match g.peer.map(|p| self.net.path(p, g.local.map(|l| l.ip()))) {
            None => None,
            Some(Ok(Path::Backend { host_dst, .. })) => Some(host_dst),
            Some(_) => {
                let _ = ep.attach(None);
                return;
            }
        };
        if let Err(e) = ep.attach(Some(self.wq.clone())) {
            tracing::warn!(error = ?e, "attaching a published UDP endpoint");
            return;
        }
        Self::forward_options(&g.opts, &*ep);
        if let Some(peer) = host_peer
            && let Err(e) = ep.connect(Some(peer))
        {
            tracing::debug!(error = ?e, "connecting a published UDP endpoint");
        }
        g.backend = Some(ep);
    }

    /// Auto-publishing: mirror an explicitly bound, non-loopback socket's port on the host.
    /// Failure is logged only.
    fn auto_publish(&self, local: SocketAddr) {
        let (Some(host_ip), Some(_)) = (self.net.config.auto_publish, self.net.backend.as_ref())
        else {
            return;
        };
        if local.ip().is_loopback() || self.lock().published.is_some() {
            return;
        }
        let host = SocketAddr::new(host_ip, local.port());
        match self.net.publish_udp(host, local) {
            Ok(p) => *self.auto_publication.lock().unwrap() = Some(p),
            Err(e) => tracing::warn!(%host, guest = %local, error = %e, "auto-publish failed"),
        }
    }

    /// Hands the options a backend endpoint acts on to one made after they were set.
    fn forward_options(opts: &SockOpts, b: &dyn BackendDatagram) {
        for (level, name) in RECVERR {
            if opts.flag(level, name) {
                Self::forward_option(b, level, name, &1i32.to_le_bytes());
            }
        }
    }

    fn forward_option(b: &dyn BackendDatagram, level: i32, name: i32, value: &[u8]) {
        if let Err(e) = b.set_option(level, name, value) {
            tracing::debug!(level, name, error = ?e, "backend datagram option not applied");
        }
    }

    /// An ICMP error quoting a datagram the socket sent to `dst` (`__udp4_lib_err`,
    /// `__udp6_lib_err`): with `IP_RECVERR` (or `IPV6_RECVERR` for an IPv6 destination) it is
    /// queued and becomes the pending error; without, only a hard error to a connected socket
    /// is reported.
    pub(crate) fn icmp_error(&self, q: &Quoted<'_>, dst: SocketAddr, payload: &[u8]) {
        let mut g = self.lock();
        let (level_name, origin) = match dst {
            SocketAddr::V4(_) => (RECVERR[0], SoEeOrigin::SO_EE_ORIGIN_ICMP),
            SocketAddr::V6(_) => (RECVERR[1], SoEeOrigin::SO_EE_ORIGIN_ICMP6),
        };
        if g.opts.flag(level_name.0, level_name.1) {
            let e = QueuedError {
                errno: q.errno,
                origin,
                type_: q.type_,
                code: q.code,
                info: q.info,
                data: 0,
                offender: Some(SocketAddr::new(q.offender, 0)),
                dst: Some(dst),
                payload: payload.to_vec(),
            };
            Self::queue_error(&mut g, e);
        } else if !q.hard || g.peer.is_none() {
            return;
        }
        g.err = Some(q.errno);
        drop(g);
        self.wq.wake(PollMask::ERR);
    }

    /// `__ip_append_data` and `__ip6_append_data`'s size check: a datagram of `len` bytes
    /// (UDP header included) that may not be fragmented and does not fit the `mtu` of the
    /// link it leaves by is `EMSGSIZE`, and with `IP_RECVERR` (`IPV6_RECVERR`) a local error
    /// naming the MTU is queued (`ip_local_error`, `ipv6_local_error`).
    /// With `IPV6_DONTFRAG`, the path MTU is also left for `IPV6_RECVPATHMTU`
    /// (`ipv6_local_rxpmtu`), with the flow's interface `oif`.
    fn check_mtu(
        g: &mut Inner,
        dst: IpAddr,
        oif: u32,
        mtu: Option<u32>,
        len: usize,
        dontfrag: Option<bool>,
    ) -> NetResult<()> {
        let v6 = dst.is_ipv6();
        let Some(mtu) = mtu else {
            return Ok(());
        };
        let mtu = g.opts.fragment_mtu(mtu, v6);
        let header = if v6 { IPV6_HDR } else { IPV4_HDR };
        if len + header <= mtu as usize || !g.opts.dont_fragment(v6, dontfrag) {
            return Ok(());
        }
        if let IpAddr::V6(v6) = dst {
            g.opts.local_rxpmtu(v6, oif, mtu, dontfrag);
        }
        if g.opts
            .flag(RECVERR[usize::from(v6)].0, RECVERR[usize::from(v6)].1)
        {
            let port = g.peer.map_or(0, |p| p.port());
            Self::queue_error(g, QueuedError::local(Errno::EMSGSIZE, mtu, dst, port));
        }
        Err(Errno::EMSGSIZE)
    }

    /// `sock_queue_err_skb`: dropped when the receive buffer is full.
    fn queue_error(g: &mut Inner, e: QueuedError) {
        let size = e.payload.len() + DGRAM_OVERHEAD;
        if g.queued + size >= g.opts.rcvbuf {
            return;
        }
        g.queued += size;
        g.errqueue.push_back(e);
    }

    /// `sock_dequeue_err_skb`: the oldest local entry, leaving the next ICMP entry's errno, or
    /// none, as the pending error.
    fn dequeue_error(g: &mut Inner) -> Option<QueuedError> {
        let e = g.errqueue.pop_front()?;
        g.queued -= e.payload.len() + DGRAM_OVERHEAD;
        match g.errqueue.front() {
            Some(next) if next.is_icmp() => g.err = Some(next.errno),
            _ if e.is_icmp() => g.err = None,
            _ => {}
        }
        Some(e)
    }

    /// `ip_recv_error` / `ipv6_recv_error`: one entry of the error queue, never waiting.
    fn recv_error(&self, buf: &mut [u8]) -> NetResult<RecvMsg> {
        let mut g = self.lock();
        let e = match Self::dequeue_error(&mut g) {
            Some(e) => {
                let more = !g.errqueue.is_empty();
                drop(g);
                if more {
                    self.wq.wake(PollMask::ERR);
                }
                e
            }
            None => {
                let backend = g.backend.clone();
                let peer = g.endpoint_tx.clone();
                drop(g);
                if let Some(mut e) = backend.and_then(|b| b.take_queued_error()) {
                    e.dst = e.dst.map(|a| self.net.guest_view(a));
                    e.offender = e.offender.map(|a| self.net.guest_view(a));
                    e
                } else {
                    peer.and_then(|tx| tx.take_queued_error())
                        .ok_or(Errno::EAGAIN)?
                }
            }
        };
        Ok(error_result(self.domain(), &e, buf))
    }

    /// `sock_error`: the socket's pending error, else the backend endpoint's.
    fn take_err(g: &mut Inner) -> Option<Errno> {
        g.err
            .take()
            .or_else(|| g.backend.as_ref().and_then(|b| b.take_error()))
            .or_else(|| g.endpoint_tx.as_ref().and_then(|tx| tx.take_error()))
    }
}

impl UdpSocket {
    /// The interface and source address of a datagram to the group `dst`
    /// (`udp_sendmsg`, `udpv6_sendmsg`, `ip4_datagram_connect`): the interface the control
    /// messages name, else the destination's scope, the socket's device, then
    /// `IP_MULTICAST_IF`; the source the control messages name, else the bound address (not a
    /// group or broadcast address, which leave the source to the device), then
    /// `IP_MULTICAST_IF`'s.
    /// `fl6->flowi6_oif` as `udpv6_sendmsg` sets it: the control messages' interface, else
    /// the destination's scope, the socket's device, the sticky `IPV6_PKTINFO`'s, and for a
    /// group `IPV6_MULTICAST_IF`'s.
    fn flow_oif(&self, g: &Inner, dst: Option<SocketAddr>, scope: u32, ctl: &SendCtl) -> u32 {
        let group = dst.is_some_and(|d| d.ip().is_multicast());
        let mc_oif = match (group, dst) {
            (true, Some(d)) => g.opts.mc.interface(d.ip()).0,
            _ => 0,
        };
        [
            ctl.oif,
            scope,
            self.net.device_index(&g.opts.bind_device),
            g.opts.sticky_pktinfo.1,
            mc_oif,
        ]
        .into_iter()
        .find(|&i| i != 0)
        .unwrap_or(0)
    }

    fn mc_route(
        &self,
        g: &Inner,
        dst: SocketAddr,
        scope: u32,
        ctl: Option<&SendCtl>,
    ) -> NetResult<McRoute> {
        let group = dst.ip();
        let (mc_oif, mc_src) = g.opts.mc.interface(group);
        let ctl_oif = ctl.map_or(0, |c| c.oif);
        let sticky_oif = match group {
            IpAddr::V6(_) => g.opts.sticky_pktinfo.1,
            IpAddr::V4(_) => 0,
        };
        let oif = [
            ctl_oif,
            scope,
            self.net.device_index(&g.opts.bind_device),
            sticky_oif,
            mc_oif,
        ]
        .into_iter()
        .find(|&i| i != 0)
        .unwrap_or(0);
        let bound = g
            .local
            .map(|l| l.ip())
            .or(g.saddr)
            .filter(|ip| ip.is_ipv4() == group.is_ipv4())
            .filter(|ip| !ip.is_unspecified() && !ip.is_multicast())
            .filter(|ip| *ip != IpAddr::V4(Ipv4Addr::BROADCAST));
        let src = ctl
            .and_then(|c| c.src)
            .map(canonical_ip)
            .or(bound)
            .or(mc_src);
        self.net.mc_route(group, oif, src)
    }

    /// `inet_sendmsg` and `udp_sendmsg`/`udpv6_sendmsg`, failing in their order: autobind,
    /// the size and flags, the destination, the control messages, the route, the payload
    /// limit, then (`sock_alloc_send_pskb`) a pending error and a shut down sender.
    fn send_policy<'a>(
        &'a self,
        msg: &SendMsg<'_>,
    ) -> NetResult<(
        MutexGuard<'a, Inner>,
        Option<SocketAddr>,
        crate::net::Admission,
    )> {
        let mut g = self.lock();
        let mut admission = crate::net::Admission::Allowed;
        if self.net.config.policy.is_some() {
            loop {
                let dst = policy_destination(&g, msg);
                drop(g);
                if let Some(dst) = dst {
                    admission = self.net.admit(dst, crate::PolicyDirection::Outbound)?;
                }
                g = self.lock();
                if policy_destination(&g, msg) == dst {
                    break;
                }
            }
        }
        let dst = policy_destination(&g, msg);
        Ok((g, dst, admission))
    }

    fn connect_path(
        &self,
        g: &Inner,
        addr: SocketAddr,
        admission: crate::net::Admission,
    ) -> NetResult<Path> {
        let dst = canonical(addr);
        let path = match dst.ip().is_multicast() {
            // `ip4_datagram_connect` routes a group by `IP_MULTICAST_IF`.
            true => {
                let route = self.mc_route(g, dst, scope_of(addr), None)?;
                Path::Nowhere {
                    src: route.src,
                    unresolved: false,
                }
            }
            false => self.net.path(dst, g.local.map(|l| l.ip()).or(g.saddr))?,
        };
        if admission == crate::net::Admission::DnsOnly && !matches!(path, Path::Dns { .. }) {
            return Err(Errno::EPERM);
        }
        Ok(path)
    }

    fn connect_route(
        &self,
        g: &Inner,
        addr: SocketAddr,
        admission: crate::net::Admission,
    ) -> NetResult<ConnectRoute> {
        let namespace = self.connect_path(g, addr, admission);
        if admission == crate::net::Admission::Allowed
            && g.endpoint_bound.is_some()
            && self.net.endpoints().is_some_and(|ns| ns.external)
            && self.net.external_route_candidate(canonical(addr))?
            && (addr.ip().is_multicast()
                || matches!(namespace, Err(Errno::ENETUNREACH | Errno::EADDRNOTAVAIL)))
        {
            return Ok(ConnectRoute::External {
                source: g.local.map_or(self.any(), |local| local.ip()),
            });
        }
        namespace.map(ConnectRoute::Namespace)
    }

    fn send_dns_source(
        &self,
        g: &Inner,
        msg: &SendMsg<'_>,
        policy_dst: Option<SocketAddr>,
        admission: crate::net::Admission,
    ) -> NetResult<Option<IpAddr>> {
        let dns_source = if admission == crate::net::Admission::DnsOnly {
            let dst = canonical(policy_dst.ok_or(Errno::EDESTADDRREQ)?);
            let ctl = match &g.pending {
                Some(pending) => pending.ctl,
                None => cmsg::udp(msg.control, self.domain(), dst.is_ipv4(), msg.net_raw)?,
            };
            let local = g
                .local
                .unwrap_or(SocketAddr::new(g.saddr.unwrap_or(self.any()), 0));
            // Select the actual route before autobind or consuming a cork. Keep that
            // decision for this datagram, even if interface configuration changes later.
            match self.net.udp_route(local, dst, &ctl)? {
                UdpRoute::Dns { from } => Some(from.ip()),
                _ => return Err(Errno::EPERM),
            }
        } else {
            None
        };
        Ok(dns_source)
    }

    fn send_head(&self, g: &Inner, msg: &SendMsg<'_>) -> NetResult<()> {
        if msg.data.len() > MAX_SEND {
            return Err(Errno::EMSGSIZE);
        }
        if msg.flags.0 & MsgFlags::MSG_OOB.0 != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        if self.domain() == Domain::Inet6
            && g.pending.as_ref().is_some_and(|p| p.dst.is_ipv6())
            && msg.to.is_some_and(|to| canonical(to).is_ipv4())
        {
            // udpv6_sendmsg delegates mapped IPv4 to udp_sendmsg, which
            // rejects a pending AF_INET6 cork without consuming it.
            return Err(if g.opts.v6only {
                Errno::ENETUNREACH
            } else {
                Errno::EINVAL
            });
        }
        Ok(())
    }

    fn prepare_flow<'b>(
        &self,
        g: &Inner,
        msg: &SendMsg<'b>,
        local: SocketAddr,
        pending: Option<Pending>,
    ) -> NetResult<PreparedFlow<'b>> {
        let (local, dst, scope, ctl, data) = match pending {
            Some(mut pending) => {
                let max = if pending.dst.is_ipv4() {
                    MAX_V4_PAYLOAD
                } else {
                    MAX_V6_PAYLOAD
                };
                if pending.data.len() + msg.data.len() > max {
                    return Err(Errno::EMSGSIZE);
                }
                pending.data.extend_from_slice(msg.data);
                (
                    pending.local,
                    pending.dst,
                    pending.scope,
                    pending.ctl,
                    Cow::Owned(pending.data),
                )
            }
            None => {
                let dst = match msg.to.map(canonical) {
                    Some(d) if d.port() == 0 => return Err(Errno::EINVAL),
                    Some(d) => d,
                    None => g.peer.ok_or(Errno::EDESTADDRREQ)?,
                };
                if self.domain() == Domain::Inet6 && dst.is_ipv4() && g.opts.v6only {
                    return Err(Errno::ENETUNREACH);
                }
                let mut ctl = cmsg::udp(msg.control, self.domain(), dst.is_ipv4(), msg.net_raw)?;
                let default_ttl = if dst.ip().is_multicast() {
                    g.opts.mc.ttl_loop(dst.ip()).0
                } else {
                    g.opts.unicast_ttl(self.domain())
                };
                ctl.ttl = Some(ctl.ttl.unwrap_or(default_ttl));
                (
                    local,
                    dst,
                    msg.to.map_or(0, scope_of),
                    ctl,
                    Cow::Borrowed(msg.data),
                )
            }
        };
        Ok(PreparedFlow {
            local,
            dst,
            scope,
            ctl,
            data,
        })
    }

    fn check_broadcast(&self, g: &Inner, dst: SocketAddr, len: usize) -> NetResult<bool> {
        if !matches!(dst.ip(), IpAddr::V4(v4) if v4.is_broadcast()) {
            return Ok(false);
        }
        // Broadcast is not carried (TODO); Linux still checks SO_BROADCAST.
        if !g
            .opts
            .flag(SocketLevel::SOL_SOCKET.0, SocketOption::SO_BROADCAST.0)
        {
            return Err(Errno::EACCES);
        }
        if len > MAX_V4_PAYLOAD {
            return Err(Errno::EMSGSIZE);
        }
        Ok(true)
    }

    fn check_payload(
        &self,
        g: &mut Inner,
        dst: SocketAddr,
        scope: u32,
        ctl: &SendCtl,
        len: usize,
        mtu: Option<u32>,
    ) -> NetResult<()> {
        let max = if dst.is_ipv4() {
            MAX_V4_PAYLOAD
        } else {
            MAX_V6_PAYLOAD
        };
        if len > max {
            return Err(Errno::EMSGSIZE);
        }
        if let Some(size) = ctl.gso_size {
            cmsg::check_segments(len, size)?;
        } else {
            let oif = self.flow_oif(g, Some(dst), scope, ctl);
            Self::check_mtu(g, dst.ip(), oif, mtu, len + UDP_HDR, ctl.dontfrag)?;
        }
        if let Some(error) = Self::take_err(g) {
            return Err(error);
        }
        if g.wr_shut {
            return Err(Errno::EPIPE);
        }
        Ok(())
    }

    fn check_unicast(
        &self,
        g: &mut Inner,
        flow: &PreparedFlow<'_>,
        dns_source: Option<IpAddr>,
        physical: bool,
    ) -> NetResult<UdpRoute> {
        let PreparedFlow {
            local,
            dst,
            scope,
            ctl,
            data,
        } = flow;
        let (local, dst, scope) = (*local, *dst, *scope);
        let route = match dns_source {
            Some(src) => UdpRoute::Dns {
                from: SocketAddr::new(src, local.port()),
            },
            None => match self.net.udp_route(local, dst, ctl) {
                Ok(route) => route,
                Err(Errno::ENETUNREACH | Errno::EADDRNOTAVAIL)
                    if physical && self.net.external_route_candidate(dst)? =>
                {
                    return self.external_route(g, local, dst, scope, ctl, data.len());
                }
                Err(error) => return Err(error),
            },
        };
        self.check_payload(g, dst, scope, ctl, data.len(), self.net.mtu_to(dst.ip()))?;
        Ok(route)
    }

    fn external_route(
        &self,
        g: &mut Inner,
        local: SocketAddr,
        dst: SocketAddr,
        scope: u32,
        ctl: &SendCtl,
        len: usize,
    ) -> NetResult<UdpRoute> {
        if !self.net.external_route_candidate(dst)? {
            return Err(Errno::EAGAIN);
        }
        self.check_broadcast(g, dst, len)?;
        // Per-packet physical interface overrides have no old provider operation. Socket
        // multicast interface selection is applied to the same resource by setsockopt.
        if ctl.oif != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        self.check_payload(g, dst, scope, ctl, len, None)?;
        let (interface, mc_source) = if dst.ip().is_multicast() {
            g.opts.mc.physical_interface(dst.ip())
        } else {
            (0, None)
        };
        let bound = (!local.ip().is_unspecified()).then_some(local.ip());
        let source = ctl
            .src
            .map(canonical_ip)
            .or(bound)
            .or(mc_source)
            .unwrap_or(local.ip());
        if source.is_ipv4() != dst.is_ipv4()
            || bound.is_some_and(|bound| !source.is_unspecified() && source != bound)
        {
            return Err(Errno::EINVAL);
        }
        Ok(UdpRoute::External {
            from: SocketAddr::new(source, local.port()),
            interface,
        })
    }

    fn check_multicast(
        &self,
        g: &mut Inner,
        dst: SocketAddr,
        scope: u32,
        ctl: &SendCtl,
        len: usize,
    ) -> NetResult<McRoute> {
        let route = self.mc_route(g, dst, scope, Some(ctl))?;
        self.check_payload(g, dst, scope, ctl, len, self.net.link_mtu(route.oif))?;
        Ok(route)
    }

    fn revalidate_endpoint_route(
        &self,
        g: &mut Inner,
        route: &UdpRoute,
        flow: &PreparedFlow<'_>,
        physical: bool,
    ) -> NetResult<UdpRoute> {
        let PreparedFlow {
            local,
            dst,
            scope,
            ctl,
            data,
        } = flow;
        let (local, dst, scope, len) = (*local, *dst, *scope, data.len());
        match route {
            UdpRoute::External { .. } => self.external_route(g, local, dst, scope, ctl, len),
            UdpRoute::Broadcast => {
                if !self.check_broadcast(g, dst, len)? {
                    return Err(Errno::EAGAIN);
                }
                if physical {
                    // The admitted resource owns its physical route/MTU. Apply the same
                    // selected validation and literal-hint limits as external multicast.
                    self.external_route(g, local, dst, scope, ctl, len)?;
                }
                Ok(UdpRoute::Broadcast)
            }
            UdpRoute::Multicast { .. } => {
                let route = self.check_multicast(g, dst, scope, ctl, len)?;
                Ok(UdpRoute::Multicast {
                    from: SocketAddr::new(route.src, local.port()),
                    interface: route.oif,
                })
            }
            _ => self.net.udp_route(local, dst, ctl),
        }
    }

    fn send_locked<'a>(
        &'a self,
        mut g: MutexGuard<'a, Inner>,
        msg: SendMsg<'_>,
        policy_dst: Option<SocketAddr>,
        admission: crate::net::Admission,
    ) -> NetResult<usize> {
        let dns_source = self.send_dns_source(&g, &msg, policy_dst, admission)?;
        // `inet_send_prepare`: an unbound socket is bound first, `EAGAIN` if that fails.
        let local = self.autobind(&mut g).map_err(|_| Errno::EAGAIN)?;
        self.send_head(&g, &msg)?;
        // Appends skip the new destination and ancillary data, using the first send's
        // flow (net/ipv4/udp.c udp_sendmsg, do_append_data).
        let pending = g.pending.take();
        let flow = self.prepare_flow(&g, &msg, local, pending)?;
        let PreparedFlow {
            local,
            dst,
            scope,
            ctl,
            ..
        } = &flow;
        let (local, dst, scope, ctl) = (*local, *dst, *scope, *ctl);
        let msg = SendMsg {
            data: &flow.data,
            ..msg
        };
        let cork = g.cork || msg.flags.contains(MsgFlags::MSG_MORE);
        let broadcast = self.check_broadcast(&g, dst, msg.data.len())?;
        let external = self.net.endpoints().is_some_and(|ns| ns.external);
        if broadcast && (!external || g.endpoint_bound.is_none()) {
            if cork {
                g.pending = Some(Pending {
                    policy_dst: policy_dst.unwrap_or(dst),
                    data: msg.data.to_vec(),
                    local,
                    dst,
                    scope,
                    ctl,
                    now: msg.now,
                });
            }
            return Ok(msg.data.len());
        }
        if dst.ip().is_multicast() && !external {
            return self.send_multicast(g, local, dst, scope, &ctl, msg, policy_dst);
        }
        let mut route = if external
            && g.endpoint_bound.is_some()
            && dst.ip().is_multicast()
            && self.net.external_route_candidate(dst)?
        {
            self.external_route(&mut g, local, dst, scope, &ctl, msg.data.len())?
        } else if broadcast {
            // Pure selection decides ownership before provider-only pending-error,
            // shutdown/GSO/MTU validation. Namespace broadcast retains its old fast path.
            UdpRoute::Broadcast
        } else if dst.ip().is_multicast() {
            let route = self.check_multicast(&mut g, dst, scope, &ctl, msg.data.len())?;
            UdpRoute::Multicast {
                from: SocketAddr::new(route.src, local.port()),
                interface: route.oif,
            }
        } else {
            let physical = external && g.endpoint_bound.is_some() && dns_source.is_none();
            self.check_unicast(&mut g, &flow, dns_source, physical)?
        };
        if cork && !broadcast {
            g.pending = Some(Pending {
                policy_dst: policy_dst.unwrap_or(dst),
                data: msg.data.to_vec(),
                local,
                dst,
                scope,
                ctl,
                now: msg.now,
            });
            return Ok(msg.data.len());
        }
        if let Some(ns) = self.net.endpoints() {
            let source = self.endpoint.source();
            let revision = g.endpoint_revision;
            let config = self.endpoint_config(&g);
            let local_binding = g.local;
            let connected = g.endpoint_connection.clone();
            let eligible = matches!(&route,UdpRoute::Local {at,..} if Arc::ptr_eq(at,&self.net))
                || (ns.external
                    && matches!(&route, UdpRoute::Backend { .. } | UdpRoute::External { .. }))
                || (ns.external
                    && matches!(&route, UdpRoute::Multicast { .. } | UdpRoute::Broadcast)
                    && self.net.external_route_candidate(dst).unwrap_or(false));
            let effective = match &route {
                UdpRoute::Local { from, .. }
                | UdpRoute::Multicast { from, .. }
                | UdpRoute::External { from, .. } => *from,
                _ => local,
            };
            let group = self.endpoint.group();
            let query = EndpointQuery {
                kind: EndpointKind::Datagram,
                source_id: source,
                bound: local_binding,
                requested_bind: g.requested_bind,
                binding: g.endpoint_bound.clone(),
                effective_source: Some(effective),
                destination: dst,
                local_binding: ns.hint(EndpointKind::Datagram, dst, effective),
            };
            drop(g);
            if let Some(group) = group {
                ns.refresh(&group);
            }
            let choice = if eligible {
                match connected {
                    Some(EndpointConnection::Peer(target)) if config.peer == Some(dst) => {
                        EndpointChoice::Provider(target)
                    }
                    Some(EndpointConnection::Local | EndpointConnection::Host)
                        if config.peer == Some(dst) =>
                    {
                        EndpointChoice::Namespace
                    }
                    _ => ns.provider.select(&query)?,
                }
            } else {
                EndpointChoice::Namespace
            };
            let current_admission = self
                .net
                .admit(policy_dst.unwrap_or(dst), crate::PolicyDirection::Outbound)?;
            if current_admission != admission {
                return Err(Errno::EPERM);
            }
            g = self.lock();
            if source != self.endpoint.source() || g.local != local_binding {
                return Err(Errno::ECANCELED);
            }
            if matches!(choice, EndpointChoice::Namespace)
                && matches!(route, UdpRoute::External { .. })
            {
                // Namespace ownership retains its actual validation and errors. No physical
                // operation was accepted by pure selection, so there is no provider fallback.
                route = if dst.ip().is_multicast() {
                    let route = self.check_multicast(&mut g, dst, scope, &ctl, msg.data.len())?;
                    UdpRoute::Multicast {
                        from: SocketAddr::new(route.src, local.port()),
                        interface: route.oif,
                    }
                } else {
                    self.check_unicast(&mut g, &flow, dns_source, false)?
                };
            }
            let physical = matches!(choice, EndpointChoice::Provider(_));
            // Publication refresh and pure selection may reenter this socket or change its
            // route. Both choices must pass current validation before any dispatch accepts
            // data. The cork has already been gathered: a stale snapshot fails unaccepted
            // rather than recursively appending or replaying the message.
            if !broadcast || physical {
                if let Some(error) = Self::take_err(&mut g) {
                    return Err(error);
                }
                if g.wr_shut {
                    return Err(Errno::EPIPE);
                }
            }
            let current_route = self.revalidate_endpoint_route(&mut g, &route, &flow, physical)?;
            if !Self::endpoint_same_route(&route, &current_route) {
                return Err(Errno::EAGAIN);
            }
            if cork {
                g.pending = Some(Pending {
                    policy_dst: policy_dst.unwrap_or(dst),
                    data: msg.data.to_vec(),
                    local,
                    dst,
                    scope,
                    ctl,
                    now: msg.now,
                });
                return Ok(msg.data.len());
            }
            if let EndpointChoice::Provider(target) = choice {
                g.endpoint_blocked = None;
                g.endpoint_write_revision = g.endpoint_write_revision.saturating_add(1);
                let dispatch = g.endpoint_write_revision;
                drop(g);
                let tx = match self.endpoint_prepare_tx(&ns, source) {
                    Ok(tx) => tx,
                    Err(error) => {
                        let result = Err(error);
                        self.endpoint_outcome(
                            source,
                            revision,
                            dispatch,
                            WriteSlot::Peer { _target: target },
                            dst,
                            &result,
                        );
                        return result;
                    }
                };
                let current_admission = self
                    .net
                    .admit(policy_dst.unwrap_or(dst), crate::PolicyDirection::Outbound)?;
                if current_admission != admission {
                    return Err(Errno::EPERM);
                }
                let current = {
                    let mut g = self.lock();
                    if source != self.endpoint.source() {
                        return Err(Errno::ECANCELED);
                    }
                    if let Some(error) = Self::take_err(&mut g) {
                        return Err(error);
                    }
                    if g.wr_shut {
                        return Err(Errno::EPIPE);
                    }
                    let current_route =
                        self.revalidate_endpoint_route(&mut g, &route, &flow, true)?;
                    if !Self::endpoint_same_route(&route, &current_route) {
                        return Err(Errno::EAGAIN);
                    }
                    g.endpoint_revision
                };
                let segment = ctl.gso_size.unwrap_or(usize::MAX).max(1);
                let send = |bytes: &[u8]| {
                    let physical_destination = match dst {
                        SocketAddr::V6(mut address) => {
                            address.set_scope_id(scope);
                            SocketAddr::V6(address)
                        }
                        address => address,
                    };
                    let n = tx.send_to(current, &target, effective, physical_destination, bytes)?;
                    if n == bytes.len() {
                        Ok(n)
                    } else {
                        Err(Errno::EPROTO)
                    }
                };
                let result = if msg.data.len() <= segment {
                    send(msg.data)
                } else {
                    let mut result = Ok(msg.data.len());
                    for (i, chunk) in msg.data.chunks(segment).enumerate() {
                        if let Err(error) = send(chunk) {
                            if i == 0 {
                                result = Err(error);
                            }
                            break;
                        }
                    }
                    result
                };
                self.endpoint_outcome(
                    source,
                    current,
                    dispatch,
                    WriteSlot::Peer { _target: target },
                    dst,
                    &result,
                );
                return result;
            }
            g.endpoint_blocked = None;
            g.endpoint_write_revision = g.endpoint_write_revision.saturating_add(1);
        }
        // `UDP_SEGMENT`: the payload leaves as datagrams of the segment size.
        let segment = ctl.gso_size.unwrap_or(usize::MAX).max(1);
        let ttl = ctl.ttl.unwrap_or_else(|| g.opts.unicast_ttl(self.domain()));
        let traffic_class = Self::traffic_class(&g, &ctl, dst.ip());
        match route {
            UdpRoute::External { .. } => Err(Errno::ECANCELED),
            UdpRoute::Broadcast => Ok(msg.data.len()),
            UdpRoute::Multicast { .. } => {
                self.send_multicast(g, local, dst, scope, &ctl, msg, policy_dst)
            }
            UdpRoute::Local {
                from,
                to,
                at,
                iif,
                back_iif,
            } => {
                drop(g);
                let arrival = Arrival {
                    src: from.ip(),
                    dst: dst.ip(),
                    ttl,
                    traffic_class,
                    iif,
                    pkttype: PACKET_HOST,
                };
                let back = Back {
                    net: self.net.clone(),
                    iif: back_iif,
                };
                // Each segment is a datagram of its own; raw UDP sockets there see it first.
                // Nobody taking it there, the namespace answers with a port unreachable.
                let arrive = |data: &[u8]| {
                    at.raw_udp_copy(from, dst, &arrival, data);
                    match &to {
                        Some(target) => target.deliver(data, from, &arrival),
                        None => at.udp_unreachable(from, dst, data, iif, back.clone(), msg.now),
                    }
                };
                if msg.data.is_empty() {
                    arrive(msg.data);
                }
                msg.data.chunks(segment).for_each(arrive);
                Ok(msg.data.len())
            }
            // Lost on a link where nothing answers; where no neighbour does, the sender hears
            // of it.
            UdpRoute::Nowhere { from, unresolved } => {
                drop(g);
                if unresolved {
                    let udp = udp_datagram(from, dst, msg.data);
                    self.net
                        .neighbour_failed(from.ip(), dst.ip(), IPPROTO_UDP, &udp, msg.now);
                }
                Ok(msg.data.len())
            }
            // The namespace's DNS server takes each segment as a datagram of its own.
            UdpRoute::Dns { from } => {
                drop(g);
                if msg.data.is_empty() {
                    self.net.dns_datagram(from, dst, msg.data, msg.now);
                }
                for chunk in msg.data.chunks(segment) {
                    self.net.dns_datagram(from, dst, chunk, msg.now);
                }
                Ok(msg.data.len())
            }
            UdpRoute::Backend { host_dst } => {
                let b = self.backend_endpoint(&mut g)?;
                let source = self.endpoint.source();
                let revision = g.endpoint_revision;
                let dispatch = g.endpoint_write_revision;
                drop(g);
                if msg.data.len() <= segment {
                    let result = b.send_to(msg.data, host_dst);
                    if self.net.endpoints().is_some() {
                        self.endpoint_outcome(
                            source,
                            revision,
                            dispatch,
                            WriteSlot::Host(b),
                            dst,
                            &result,
                        );
                    }
                    return result;
                }
                // One GSO send is one skb on Linux: it fails whole or goes out whole.
                let mut result = Ok(msg.data.len());
                for (i, chunk) in msg.data.chunks(segment).enumerate() {
                    match b.send_to(chunk, host_dst) {
                        Ok(_) => {}
                        Err(e) => {
                            if i == 0 {
                                result = Err(e);
                            }
                            // Already accepted segments are never replayed.
                            break;
                        }
                    }
                }
                if self.net.endpoints().is_some() {
                    self.endpoint_outcome(
                        source,
                        revision,
                        dispatch,
                        WriteSlot::Host(b),
                        dst,
                        &result,
                    );
                }
                result
            }
        }
    }

    /// A send to the group `dst`, which each socket of the namespaces it reaches that is
    /// bound to the port and allows the group gets a copy of (`__udp4_lib_mcast_deliver`,
    /// `__udp6_lib_mcast_deliver`).
    #[allow(clippy::too_many_arguments)] // The route and policy destinations are intentionally distinct.
    fn send_multicast(
        &self,
        mut g: MutexGuard<'_, Inner>,
        local: SocketAddr,
        dst: SocketAddr,
        scope: u32,
        ctl: &SendCtl,
        msg: SendMsg<'_>,
        policy_dst: Option<SocketAddr>,
    ) -> NetResult<usize> {
        let data = msg.data;
        let cork = g.cork || msg.flags.contains(MsgFlags::MSG_MORE);
        let route = self.check_multicast(&mut g, dst, scope, ctl, data.len())?;
        if cork {
            g.pending = Some(Pending {
                policy_dst: policy_dst.unwrap_or(dst),
                data: data.to_vec(),
                local,
                dst,
                scope,
                ctl: *ctl,
                now: msg.now,
            });
            return Ok(data.len());
        }
        let (ttl, looped) = g.opts.mc.ttl_loop(dst.ip());
        let ttl = ctl.ttl.unwrap_or(ttl);
        let traffic_class = Self::traffic_class(&g, ctl, dst.ip());
        drop(g);
        let from = SocketAddr::new(route.src, local.port());
        let segment = ctl.gso_size.unwrap_or(usize::MAX).max(1);
        for (net, iif) in self
            .net
            .mc_receivers(dst.ip(), route.src, route.oif, looped, ttl)
        {
            // The sender's own namespace gets the looped-back copy (`dev_loopback_xmit`).
            let at = Arrival {
                src: from.ip(),
                dst: dst.ip(),
                ttl,
                traffic_class,
                iif,
                pkttype: match Arc::ptr_eq(&net, &self.net) {
                    true => PACKET_LOOPBACK,
                    false => PACKET_MULTICAST,
                },
            };
            if data.is_empty() {
                net.udp_mcast_deliver(dst, from, &at, data);
            }
            for chunk in data.chunks(segment) {
                net.udp_mcast_deliver(dst, from, &at, chunk);
            }
        }
        Ok(data.len())
    }

    // Linux net/ipv6/udp.c:udpv6_sendmsg resolves an unspecified per-message
    // class from the sticky socket option before building the packet.
    fn traffic_class(g: &Inner, ctl: &SendCtl, dst: IpAddr) -> u8 {
        if dst.is_ipv4() {
            return 0;
        }
        ctl.traffic_class.unwrap_or_else(|| {
            u8::try_from(
                g.opts
                    .int(SocketLevel::SOL_IPV6.0, Ipv6Option::IPV6_TCLASS.0),
            )
            .unwrap_or(0)
        })
    }

    /// Linux net/ipv6/datagram.c:ip6_datagram_recv_ctl emits common packet
    /// info, then specific hop/class fields and finally legacy RFC2292 fields.
    fn controls(&self, g: &Inner, d: &Datagram) -> Vec<Control> {
        if self.domain() != Domain::Inet6 {
            return Vec::new();
        }
        let level = SocketLevel::SOL_IPV6.0;
        let mut out = Vec::new();
        let dst = match d.at.dst {
            IpAddr::V4(a) => a.to_ipv6_mapped(),
            IpAddr::V6(a) => a,
        };
        let info = |kind| Control {
            level,
            kind,
            data: cmsg::in6_pktinfo(dst, d.at.iif),
        };
        let int = |kind, value: u8| Control {
            level,
            kind,
            data: i32::from(value).to_le_bytes().to_vec(),
        };
        if g.opts.flag(level, Ipv6Option::IPV6_RECVPKTINFO.0) {
            out.push(info(Ipv6Option::IPV6_PKTINFO.0));
        }
        // Mapped IPv4 datagrams only take the common IPv6 packet-info path.
        if d.at.dst.is_ipv4() {
            return out;
        }
        if g.opts.flag(level, Ipv6Option::IPV6_RECVHOPLIMIT.0) {
            out.push(int(Ipv6Option::IPV6_HOPLIMIT.0, d.at.ttl));
        }
        if g.opts.flag(level, Ipv6Option::IPV6_RECVTCLASS.0) {
            out.push(int(Ipv6Option::IPV6_TCLASS.0, d.at.traffic_class));
        }
        if g.opts.flag(level, crate::opts::IPV6_2292PKTINFO) {
            out.push(info(crate::opts::IPV6_2292PKTINFO));
        }
        if g.opts.flag(level, crate::opts::IPV6_2292HOPLIMIT) {
            out.push(int(crate::opts::IPV6_2292HOPLIMIT, d.at.ttl));
        }
        out
    }

    /// `__udp_is_mcast_sock`, `__udp_v6_is_mcast_sock`: takes a datagram to the group `dst`
    /// from `from` that arrived on interface `iif` if the socket is bound to the port and to
    /// the group or a wildcard of its family, connected to nobody else, on no other device,
    /// and allows the group (`ip_mc_sf_allow`, `inet6_mc_check`).
    fn deliver_multicast(&self, dst: SocketAddr, from: SocketAddr, at: &Arrival, data: &[u8]) {
        let g = self.lock();
        let takes = self.multicast_takes(&g, dst, from, at.iif, false);
        drop(g);
        if takes {
            self.deliver(data, from, at);
        }
    }
}

impl Net {
    /// A datagram to the group `dst` arrived on interface `iif`: every socket bound to its
    /// port is offered it.
    pub(crate) fn udp_mcast_deliver(
        &self,
        dst: SocketAddr,
        from: SocketAddr,
        at: &Arrival,
        data: &[u8],
    ) {
        self.raw_udp_copy(from, dst, at, data);
        let socks = self.state().udp_on_port(dst.port());
        for sock in socks.iter().filter_map(Weak::upgrade) {
            sock.deliver_multicast(dst, from, at, data);
        }
    }
}

/// The interface a link-scoped IPv6 destination names (`sin6_scope_id`), 0 for none.
fn scope_of(addr: SocketAddr) -> u32 {
    match addr {
        SocketAddr::V6(v6) => v6.scope_id(),
        SocketAddr::V4(_) => 0,
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        if let Some(ns) = self.net.endpoints() {
            self.endpoint.renew(&ns);
        }
        let g = self.inner.get_mut().unwrap();
        g.opts.mc.drop_all(&self.net);
        let local = g.local.take();
        let published = g.published.take();
        if let Some(local) = local {
            self.net.state().udp.unbind(self.id, local.port());
        }
        // The next socket bound where the publication reaches takes it over.
        if let Some((id, ep)) = published {
            let _ = ep.attach(None);
            self.net.release_udp_publication(id, self.id);
            self.net.offer_udp_publication(id);
        }
    }
}

impl Pollable for UdpSocket {
    /// `udp_poll` / `datagram_poll`.
    fn poll(&self, mut table: Option<&mut PollTable<'_>>) -> PollMask {
        poll_wait(&mut table, &self.wq);
        loop {
            let g = self.lock();
            let mut m = PollMask::empty();
            if g.err.is_some() || !g.errqueue.is_empty() {
                m |= PollMask::ERR;
            }
            if g.rd_shut {
                m |= PollMask::RDHUP | PollMask::IN | PollMask::RDNORM;
            }
            if g.rd_shut && g.wr_shut {
                m |= PollMask::HUP;
            }
            if !g.queue.is_empty() {
                m |= PollMask::IN | PollMask::RDNORM;
            }
            let backend = g.backend.clone();
            let peer = g.endpoint_tx.clone();
            let opening = g.endpoint_opening;
            let source = self.endpoint.source();
            let revision = g.endpoint_revision;
            let dispatch = g.endpoint_write_revision;
            let blocked = g
                .endpoint_blocked
                .as_ref()
                .filter(|f| f.source == source && f.revision == revision)
                .cloned();
            let connection = g.endpoint_connection.clone();
            let opted = self.net.endpoints().is_some();
            drop(g);
            let host_mask = backend.as_ref().map_or(PollMask::OUT, |b| b.poll(None));
            let peer_mask = peer.as_ref().map_or(
                if opening {
                    PollMask::empty()
                } else {
                    PollMask::OUT
                },
                |tx| tx.poll_tx(revision),
            );
            m |= host_mask & (PollMask::IN | PollMask::RDNORM | PollMask::ERR);
            m |= peer_mask & PollMask::ERR;
            let writable = if !opted {
                host_mask.contains(PollMask::OUT)
            } else {
                match blocked.map(|focus| focus.slot) {
                    Some(WriteSlot::Host(slot)) => slot.poll(None).contains(PollMask::OUT),
                    Some(WriteSlot::Peer { .. }) => peer_mask.contains(PollMask::OUT),
                    None => match connection {
                        Some(EndpointConnection::Host) => host_mask.contains(PollMask::OUT),
                        Some(EndpointConnection::Peer(_)) => peer_mask.contains(PollMask::OUT),
                        _ => true,
                    },
                }
            };
            let g = self.lock();
            if opted
                && (self.endpoint.source() != source
                    || g.endpoint_revision != revision
                    || g.endpoint_write_revision != dispatch)
            {
                drop(g);
                continue;
            }
            if writable {
                m |= PollMask::OUT | PollMask::WRNORM | PollMask::WRBAND;
            }
            return m;
        }
    }
}

impl Socket for UdpSocket {
    fn domain(&self) -> Domain {
        if self.domain.load(Ordering::Acquire) == Domain::Inet6 as u8 {
            Domain::Inet6
        } else {
            Domain::Inet
        }
    }

    fn kind(&self) -> SocketKind {
        SocketKind::Datagram
    }

    fn protocol(&self) -> i32 {
        17
    }

    fn bind(&self, addr: SocketAddr, privileged: bool) -> NetResult<()> {
        let requested = addr;
        self.net.admit(addr, crate::PolicyDirection::Inbound)?;
        let control = self
            .net
            .endpoints()
            .map(|_| self.endpoint_control.lock().unwrap());
        let mapped = matches!(addr, SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some());
        let addr = canonical(addr);
        let mut g = self.lock();
        if mapped && g.opts.v6only {
            return Err(Errno::EINVAL);
        }
        let freebind = g.opts.flag(0, wasixv2_abi::IpOption::IP_FREEBIND.0);
        self.net.check_bind(addr, privileged, freebind)?;
        if g.bind_pending.is_some() || g.local.is_some() {
            return Err(Errno::EINVAL);
        }
        // `__inet_bind`: without a port, the address waits for the port autobind picks.
        if addr.port() == 0 && g.opts.flag(0, IpOption::IP_BIND_ADDRESS_NO_PORT.0) {
            g.requested_bind = Some(requested);
            g.saddr = Some(addr.ip());
            g.addr_locked |= !addr.ip().is_unspecified();
            return Ok(());
        }
        let port = self.net.udp_bind(
            self.id,
            self.spec(&g.opts, addr.ip()),
            addr.port(),
            self.me.clone(),
        )?;
        let local = SocketAddr::new(addr.ip(), port);
        g.local = Some(local);
        g.requested_bind = Some(requested);
        g.saddr = None;
        g.addr_locked |= !addr.ip().is_unspecified();
        g.port_locked = addr.port() != 0;
        self.claim_publication(&mut g, None);
        self.endpoint_join(&g, local);
        let group = self.endpoint.group();
        let ns = self.net.endpoints();
        drop(g);
        drop(control);
        if let (Some(ns), Some(group)) = (ns, group) {
            ns.refresh(&group);
        }
        self.auto_publish(local);
        Ok(())
    }

    fn bind_admission(
        &self,
        requested: SocketAddr,
        privileged: bool,
    ) -> NetResult<Option<Box<dyn crate::BindAdmission>>> {
        self.provider_bind(requested, privileged, true)
    }

    fn autobind_admission(
        &self,
        operation: crate::endpoint::EndpointAutobind<'_>,
        privileged: bool,
    ) -> NetResult<Option<Box<dyn crate::BindAdmission>>> {
        if self.net.endpoints().is_none() || self.lock().local.is_some() {
            return Ok(None);
        }
        let physical = if let Some(namespace) = self.net.endpoints().filter(|ns| ns.external) {
            let request = {
                let g = self.lock();
                EndpointBindRequest {
                    source_id: self.endpoint.source(),
                    kind: EndpointKind::Datagram,
                    requested: g.requested_bind.unwrap_or(SocketAddr::new(self.any(), 0)),
                    explicit: g.requested_bind.is_some(),
                    purpose: EndpointBindPurpose::Bind,
                    domain: self.domain(),
                    v6only: g.opts.v6only,
                    reuse_addr: g.opts.reuseaddr,
                    reuse_port: g.opts.reuseport,
                }
            };
            namespace.provider.select_bind(&request)?
        } else {
            false
        };
        // Shared preparation validates without accepting bytes or consuming the live cork.
        match operation {
            crate::endpoint::EndpointAutobind::Listen(_) => return Ok(None),
            crate::endpoint::EndpointAutobind::Connect(destination) => {
                let admission = self
                    .net
                    .admit(destination, crate::PolicyDirection::Outbound)?;
                let g = self.lock();
                if self.domain() == Domain::Inet6
                    && canonical(destination).is_ipv4()
                    && g.opts.v6only
                {
                    return Err(Errno::ENETUNREACH);
                }
                if physical {
                    self.check_broadcast(&g, canonical(destination), 0)?;
                }
                match self.connect_path(&g, destination, admission) {
                    Ok(_) => {}
                    Err(error)
                        if physical
                            && admission == crate::net::Admission::Allowed
                            && (destination.ip().is_multicast()
                                || matches!(error, Errno::ENETUNREACH | Errno::EADDRNOTAVAIL)) => {}
                    Err(error) => return Err(error),
                }
            }
            crate::endpoint::EndpointAutobind::Send(msg) => {
                let (mut g, destination, admission) = self.send_policy(msg)?;
                let dns_source = self.send_dns_source(&g, msg, destination, admission)?;
                self.send_head(&g, msg)?;
                let local = SocketAddr::new(g.saddr.unwrap_or(self.any()), 0);
                let flow = self.prepare_flow(&g, msg, local, g.pending.clone())?;
                if physical
                    && flow.dst.ip().is_multicast()
                    && self.net.external_route_candidate(flow.dst).unwrap_or(false)
                {
                    self.external_route(
                        &mut g,
                        local,
                        flow.dst,
                        flow.scope,
                        &flow.ctl,
                        flow.data.len(),
                    )?;
                } else if self.check_broadcast(&g, flow.dst, flow.data.len())? {
                    // Broadcast's existing path intentionally skips pending socket errors.
                } else if flow.dst.ip().is_multicast() {
                    self.check_multicast(&mut g, flow.dst, flow.scope, &flow.ctl, flow.data.len())?;
                } else {
                    self.check_unicast(&mut g, &flow, dns_source, physical)?;
                }
            }
        }
        self.provider_bind(SocketAddr::new(self.any(), 0), privileged, false)
    }

    fn listen(&self, _backlog: u32) -> NetResult<()> {
        Err(Errno::EOPNOTSUPP)
    }

    fn accept(&self) -> NetResult<Accepted> {
        Err(Errno::EOPNOTSUPP)
    }

    /// `ip4_datagram_connect`: sets the default peer, binds if needed, and takes the route's
    /// source address if bound to the wildcard.
    fn connect(&self, addr: SocketAddr) -> NetResult<()> {
        let admission = self.net.admit(addr, crate::PolicyDirection::Outbound)?;
        let mut control = self
            .net
            .endpoints()
            .map(|_| self.endpoint_control.lock().unwrap());
        let dst = canonical(addr);
        let mut g = self.lock();
        let mut path = self.connect_route(&g, addr, admission)?;
        let mut selected = None;
        let namespace = self.net.endpoints();
        let mut next_source = None;
        if let Some(ns) = &namespace {
            if ns.external {
                self.check_broadcast(&g, dst, 0)?;
            }
            let candidate = EndpointSourceId(self.net.next_id());
            next_source = Some(candidate);
            if matches!(path, ConnectRoute::Namespace(Path::Local { net: None, .. }))
                || (ns.external
                    && (matches!(
                        path,
                        ConnectRoute::Namespace(Path::Backend { .. })
                            | ConnectRoute::External { .. }
                    ) || ((dst.ip().is_multicast()
                        || matches!(dst.ip(), IpAddr::V4(ip) if ip.is_broadcast()))
                        && self.net.external_route_candidate(dst).unwrap_or(false))))
            {
                let previous = self.endpoint.source();
                let option_version = g.endpoint_option_version;
                let bound = g.local;
                let saddr = g.saddr;
                let effective = SocketAddr::new(path.source(), bound.map_or(0, |a| a.port()));
                let query = EndpointQuery {
                    kind: EndpointKind::Datagram,
                    source_id: candidate,
                    bound,
                    requested_bind: g.requested_bind,
                    binding: g.endpoint_bound.clone(),
                    effective_source: Some(effective),
                    destination: dst,
                    local_binding: ns.hint(EndpointKind::Datagram, dst, effective),
                };
                drop(g);
                drop(control.take());
                let choice = ns.provider.select(&query)?;
                control = Some(self.endpoint_control.lock().unwrap());
                g = self.lock();
                if previous != self.endpoint.source()
                    || bound != g.local
                    || saddr != g.saddr
                    || option_version != g.endpoint_option_version
                {
                    return Err(Errno::ECANCELED);
                }
                let current = self.connect_route(&g, addr, admission)?;
                if !current.same(&path) {
                    return Err(Errno::EAGAIN);
                }
                if let EndpointChoice::Provider(target) = choice {
                    selected = Some(target);
                } else if matches!(path, ConnectRoute::External { .. }) {
                    path = ConnectRoute::Namespace(self.connect_path(&g, addr, admission)?);
                }
            }
        }
        if namespace.is_some() {
            let witness = (
                self.endpoint.source(),
                g.local,
                g.saddr,
                g.endpoint_option_version,
            );
            // Pure provider selection may reenter policy configuration. No physical operation
            // is accepted until the caller's current authorization is checked again.
            drop(g);
            drop(control.take());
            let current_admission = self.net.admit(addr, crate::PolicyDirection::Outbound)?;
            control = namespace
                .as_ref()
                .map(|_| self.endpoint_control.lock().unwrap());
            g = self.lock();
            if current_admission != admission {
                return Err(Errno::EPERM);
            }
            if witness
                != (
                    self.endpoint.source(),
                    g.local,
                    g.saddr,
                    g.endpoint_option_version,
                )
            {
                return Err(Errno::ECANCELED);
            }
            let current_route = if selected.is_some() {
                self.connect_route(&g, addr, admission)?
            } else {
                ConnectRoute::Namespace(self.connect_path(&g, addr, admission)?)
            };
            if !current_route.same(&path) {
                return Err(Errno::EAGAIN);
            }
        }
        if let Some(ns) = &namespace {
            let (current, result) =
                self.associate_bound(g, ns, selected.as_ref().map(|_| addr), next_source);
            g = current;
            if let Err(error) = result {
                let group = self.endpoint.group();
                drop(g);
                drop(control);
                if let Some(group) = group {
                    ns.refresh(&group);
                }
                return Err(error);
            }
            // A physical mutation already renewed authority before calling the provider.
            if ns.external && g.endpoint_bound.is_some() {
                next_source = Some(self.endpoint.source());
            }
        }
        let src = path.source();
        let local = self.autobind(&mut g)?;
        if local.ip().is_unspecified() && g.endpoint_bound.is_none() {
            self.net.state().udp.rehash(self.id, local.port(), src);
            g.local = Some(SocketAddr::new(src, local.port()));
        }
        self.net
            .state()
            .udp
            .set_remote(self.id, local.port(), Some(dst));
        if let (Some(ns), Some(source)) = (&namespace, next_source) {
            if self.endpoint.source() != source {
                self.endpoint_reset(&mut g, ns);
                self.endpoint.replace_source(ns, source);
            }
            let bound = g.local.unwrap();
            self.endpoint_join(&g, bound);
        }
        let provider_selected = selected.is_some();
        let endpoint_connection = if let Some(target) = selected {
            EndpointConnection::Peer(target)
        } else if matches!(path, ConnectRoute::Namespace(Path::Backend { .. })) {
            EndpointConnection::Host
        } else {
            EndpointConnection::Local
        };
        match path {
            ConnectRoute::External { .. } | ConnectRoute::Namespace(Path::Backend { .. })
                if provider_selected =>
            {
                g.backend = g.peer_datagram.clone();
                if let Some((_, ep)) = &g.published {
                    let _ = ep.attach(None);
                }
            }
            // The host endpoint filters by the peer and reports its ICMP errors.
            ConnectRoute::Namespace(Path::Backend { host_dst, .. }) => {
                self.backend_endpoint(&mut g)?.connect(Some(host_dst))?
            }
            // The association moved inside the namespace, to a link of its own, or to the DNS
            // server, whose answers are delivered as local datagrams: nothing the backend
            // receives is for us now.
            ConnectRoute::Namespace(
                Path::Local { .. } | Path::Dns { .. } | Path::Nowhere { .. },
            ) => {
                g.backend = g.peer_datagram.clone();
                if let Some((_, ep)) = &g.published {
                    let _ = ep.attach(None);
                }
            }
            ConnectRoute::External { .. } => return Err(Errno::ECANCELED),
        }
        g.peer = Some(dst);
        g.policy_peer = Some(addr);
        if namespace.is_some() {
            g.endpoint_connection = Some(endpoint_connection);
        }
        let group = self.endpoint.group();
        drop(g);
        drop(control);
        if let (Some(ns), Some(group)) = (namespace, group) {
            ns.refresh(&group);
        }
        Ok(())
    }

    /// `udp_disconnect`.
    fn disconnect(&self) -> NetResult<()> {
        let control = self
            .net
            .endpoints()
            .map(|_| self.endpoint_control.lock().unwrap());
        let mut g = self.lock();
        let namespace = self.net.endpoints();
        let mut renewed = false;
        if let Some(ns) = &namespace {
            renewed = ns.external && g.endpoint_bound.is_some();
            let (current, result) = self.associate_bound(g, ns, None, None);
            g = current;
            if let Err(error) = result {
                let group = self.endpoint.group();
                drop(g);
                drop(control);
                if let Some(group) = group {
                    ns.refresh(&group);
                }
                return Err(error);
            }
        }
        g.peer = None;
        g.policy_peer = None;
        if let Some(b) = &g.backend {
            b.connect(None)?;
        }
        let mut released = None;
        if let Some(local) = g.local {
            let mut st = self.net.state();
            st.udp.set_remote(self.id, local.port(), None);
            if !g.port_locked && g.endpoint_bound.is_none() {
                st.udp.unbind(self.id, local.port());
                g.local = None;
                g.endpoint_bound = None;
                // An address `bind` chose stays without the port (`inet_reset_saddr` only
                // for an unlocked one).
                g.saddr = g.addr_locked.then_some(local.ip());
                drop(st);
                released = self.release_publication(&mut g);
            } else if !g.addr_locked && g.endpoint_bound.is_none() {
                st.udp.rehash(self.id, local.port(), self.any());
                g.local = Some(SocketAddr::new(self.any(), local.port()));
            }
        }
        // Unconnected again, a socket whose publication was detached while connected inside
        // the namespace hears from outside again; one connected outside kept its queue.
        if g.published.is_some() && g.backend.is_none() {
            self.activate_publication(&mut g);
        }
        if let Some(ns) = &namespace {
            if !renewed {
                self.endpoint_reset(&mut g, ns);
            }
            if let Some(local) = g.local {
                self.endpoint_join(&g, local);
            }
        }
        let group = self.endpoint.group();
        drop(g);
        drop(control);
        if let (Some(ns), Some(group)) = (namespace, group) {
            ns.refresh(&group);
        }
        if let Some(id) = released {
            self.net.offer_udp_publication(id);
        }
        Ok(())
    }

    fn shutdown(&self, how: Shutdown) -> NetResult<()> {
        let mut g = self.lock();
        g.rd_shut |= how != Shutdown::Write;
        g.wr_shut |= how != Shutdown::Read;
        let connected = g.peer.is_some();
        drop(g);
        self.wq.wake(PollMask::empty());
        // `inet_shutdown` on an unconnected socket records the shutdown but says ENOTCONN.
        if connected {
            Ok(())
        } else {
            Err(Errno::ENOTCONN)
        }
    }

    fn send(&self, msg: SendMsg<'_>) -> NetResult<usize> {
        let len = msg.data.len();
        let (g, dst, admission) = self.send_policy(&msg)?;
        self.send_locked(g, msg, dst, admission).map(|_| len)
    }

    fn recv(&self, buf: &mut [u8], flags: MsgFlags) -> NetResult<RecvMsg> {
        if flags.contains(MsgFlags::MSG_ERRQUEUE) {
            return self.recv_error(buf);
        }
        let peek = flags.0 & MsgFlags::MSG_PEEK.0 != 0;
        let mut g = self.lock();
        if let Some(r) = g.opts.recv_rxpmtu() {
            return Ok(r);
        }
        // `__skb_try_recv_datagram` reports a pending error before queued data.
        if let Some(e) = Self::take_err(&mut g) {
            return Err(e);
        }
        if let Some(d) = g.queue.front() {
            // Copied out under the lock, so a peek takes no copy of the datagram.
            let (full, from) = (d.data.len(), d.from);
            let control = self.controls(&g, d);
            let len = buf.len().min(full);
            buf[..len].copy_from_slice(&d.data[..len]);
            if !peek {
                g.queue.pop_front();
                g.queued -= full + DGRAM_OVERHEAD;
            }
            let mut result = dgram_result(self.domain(), len, full, from);
            result.control = control;
            return Ok(result);
        }
        let backend = g.backend.clone();
        let rd_shut = g.rd_shut;
        let filter = g.opts.filter.clone();
        drop(g);
        if let Some(b) = backend {
            match self.backend_recv(&*b, buf, peek, &filter) {
                Ok((len, full_len, from)) => {
                    let from = self.net.guest_view(from);
                    return Ok(dgram_result(self.domain(), len, full_len, from));
                }
                Err(Errno::EAGAIN) => {}
                Err(e) => return Err(e),
            }
        }
        if rd_shut {
            return Ok(RecvMsg::default());
        }
        Err(Errno::EAGAIN)
    }

    fn local_addr(&self) -> NetResult<SocketAddr> {
        let _control = self
            .net
            .endpoints()
            .map(|_| self.endpoint_control.lock().unwrap());
        let g = self.lock();
        if let Some(bound) = g
            .endpoint_bound
            .clone()
            .filter(|_| self.net.endpoints().is_some_and(|ns| ns.external))
        {
            drop(g);
            let actual = bound.local_addr()?;
            return Ok(present(self.domain(), actual));
        }
        Ok(g.local
            .or(g.saddr.map(|ip| SocketAddr::new(ip, 0)))
            .map_or(unbound(self.domain()), |a| present(self.domain(), a)))
    }

    fn peer_addr(&self) -> NetResult<SocketAddr> {
        let g = self.lock();
        g.peer
            .map(|p| present(self.domain(), p))
            .ok_or(Errno::ENOTCONN)
    }

    fn take_error(&self) -> Option<Errno> {
        Self::take_err(&mut self.lock())
    }

    fn input_len(&self) -> NetResult<usize> {
        let g = self.lock();
        if let Some(d) = g.queue.front() {
            return Ok(d.data.len());
        }
        Ok(g.backend.as_ref().map_or(0, |b| b.input_len()))
    }

    fn set_option(&self, level: i32, name: i32, value: &[u8]) -> NetResult<()> {
        if self.net.endpoints().is_some_and(|ns| ns.external) && Self::selected_option(level, name)
        {
            return self.set_selected_option(level, name, value);
        }
        let _control = self
            .net
            .endpoints()
            .map(|_| self.endpoint_control.lock().unwrap());
        let mut g = self.lock();
        if (level, name) == (17, 1 /* UDP_CORK */) {
            g.cork = crate::opts::read_int(value)? != 0;
            if !g.cork
                && let Some(pending) = &g.pending
            {
                let now = pending.now;
                // udp_lib_setsockopt ignores push errors; the cork is still cleared.
                drop(g);
                drop(_control);
                let _ = self.send(SendMsg {
                    data: &[],
                    to: None,
                    control: &[],
                    flags: MsgFlags(0),
                    net_raw: false,
                    now,
                });
            }
            return Ok(());
        }
        if (level, name)
            == (
                SocketLevel::SOL_IPV6.0,
                wasixv2_abi::Ipv6Option::IPV6_ADDRFORM.0,
            )
        {
            let peer = g.peer.map(|p| p.ip());
            let pending_v6 = g.pending.as_ref().is_some_and(|p| p.dst.is_ipv6());
            g.opts.addrform(&self.net, value, peer, pending_v6)?;
            if let Some(local) = g.local {
                self.net
                    .state()
                    .udp
                    .set_family(self.id, local.port(), Domain::Inet);
            }
            self.domain.store(Domain::Inet as u8, Ordering::Release);
            let ns = self.net.endpoints();
            if let Some(ns) = &ns {
                let connection = g.endpoint_connection.clone();
                self.endpoint_reset(&mut g, ns);
                g.endpoint_connection = connection;
                if let Some(local) = g.local {
                    self.endpoint_join(&g, local);
                }
            }
            let group = self.endpoint.group();
            drop(g);
            drop(_control);
            if let (Some(ns), Some(group)) = (ns, group) {
                ns.refresh(&group);
            }
            return Ok(());
        }
        if crate::mcast::handles(level, name) {
            return g.opts.set_mcast(&self.net, level, name, value);
        }
        let bound = g.local.is_some();
        let changed = g.opts.set(level, name, value, bound)?;
        if RECVERR.contains(&(level, name)) {
            g.endpoint_revision = g.endpoint_revision.saturating_add(1);
            // Turning either off purges the whole queue (`skb_errqueue_purge`), leaving the
            // pending error as it is.
            if !g.opts.flag(level, name) {
                let purged: usize = g
                    .errqueue
                    .drain(..)
                    .map(|e| e.payload.len() + DGRAM_OVERHEAD)
                    .sum();
                g.queued -= purged;
            }
            if let Some(b) = &g.backend {
                let on = i32::from(g.opts.flag(level, name));
                Self::forward_option(&**b, level, name, &on.to_le_bytes());
            }
        }
        if changed == Changed::Reuse
            && let Some(local) = g.local
        {
            self.net.state().udp.set_reuse(
                self.id,
                local.port(),
                g.opts.reuseaddr,
                g.opts.reuseport,
            );
        }
        let configuration = if RECVERR.contains(&(level, name)) {
            g.endpoint_tx
                .clone()
                .map(|tx| (tx, self.endpoint_config(&g)))
        } else {
            None
        };
        drop(g);
        drop(_control);
        if let Some((tx, config)) = configuration {
            tx.configure(config);
        }
        Ok(())
    }

    fn graft(&self, ino: u64) {
        self.ino.store(ino, Ordering::Relaxed);
    }

    fn datagram_readback_admission(
        &self,
        query: DatagramReadback,
    ) -> NetResult<Option<Box<dyn DatagramReadbackAdmission>>> {
        let (bound, backend, source, domain) = {
            let g = self.lock();
            // The old connected UDP peer is canonical first. Querying the
            // remote provider instead would lose the original logical peer.
            if query == DatagramReadback::Peer && g.peer.is_some() {
                return Ok(None);
            }
            let Some(bound) = g.endpoint_bound.clone() else {
                return Ok(None);
            };
            let Some(backend) = g.peer_datagram.clone() else {
                return Ok(None);
            };
            (bound, backend, self.endpoint.source(), self.domain())
        };
        // The bound hook ran ONCE during bind capture. Readbacks validate the
        // captured role, never call a live capability selector again.
        if let Some((level, name)) = query.option_key() {
            // Reuse the existing canonical scalar validation (no SO_ERROR or
            // other consuming getter is in this closed set). No duplicate
            // getter runs on the default-None path.
            self.get_option(level, name, &mut [0; 4])?;
        }
        {
            let g = self.lock();
            if self.endpoint.source() != source
                || !g
                    .endpoint_bound
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &bound))
                || !g
                    .peer_datagram
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &backend))
            {
                return Err(Errno::ECANCELED);
            }
        }
        Ok(Some(Box::new(ReadbackSubscription(Arc::new(
            ReadbackTxn {
                socket: self.me.clone(),
                bound,
                backend,
                source,
                query,
                domain,
                queue: self.wq.clone(),
                state: Mutex::new(ReadbackState::default()),
            },
        )))))
    }

    fn get_option(&self, level: i32, name: i32, out: &mut [u8]) -> NetResult<usize> {
        let mut g = self.lock();
        if (level, name) == (17, 1 /* UDP_CORK */) {
            return Ok(crate::opts::write_int(out, i32::from(g.cork)));
        }
        if level == SocketLevel::SOL_SOCKET.0 && name == SocketOption::SO_ERROR.0 {
            let e = Self::take_err(&mut g).map_or(0, |e| e.0);
            return Ok(crate::opts::write_int(out, e));
        }
        if level == SocketLevel::SOL_SOCKET.0 && name == SocketOption::SO_ACCEPTCONN.0 {
            return Ok(crate::opts::write_int(out, 0));
        }
        if crate::mcast::handles(level, name) {
            return g.opts.get_mcast(&self.net, level, name, out);
        }
        if let Some(result) = g
            .opts
            .get_mtu(&self.net, g.peer.map(|p| p.ip()), level, name, out)
        {
            return result;
        }
        g.opts.get(level, name, out)
    }
}

/// What `ip_recv_error` / `ipv6_recv_error` return for `e`: the quoted payload, cut to `buf`
/// with `MSG_TRUNC` but its copied length returned even with `MSG_TRUNC` asked for, the
/// quoted datagram's destination as the sender, and the extended error with its offender in
/// the socket family's control message.
pub(crate) fn error_result(domain: Domain, e: &QueuedError, buf: &mut [u8]) -> RecvMsg {
    let len = buf.len().min(e.payload.len());
    buf[..len].copy_from_slice(&e.payload[..len]);
    let mut flags = MsgFlags::MSG_ERRQUEUE;
    if len < e.payload.len() {
        flags |= MsgFlags::MSG_TRUNC;
    }
    let ee = SockExtendedErr {
        ee_errno: e.errno.0 as u32,
        ee_origin: e.origin.0,
        ee_type: e.type_,
        ee_code: e.code,
        ee_pad: 0,
        ee_info: e.info,
        ee_data: e.data,
    };
    let mut data = vec![0; SockExtendedErr::SIZE];
    ee.write_to(&mut data);
    data.extend(sockaddr_bytes(domain, e.offender));
    let (level, kind) = match domain {
        Domain::Inet => RECVERR[0],
        Domain::Inet6 => RECVERR[1],
    };
    RecvMsg {
        len,
        full_len: len,
        from: e.dst.map(|d| present(domain, canonical(d))),
        flags,
        control: vec![Control { level, kind, data }],
    }
}

fn dgram_result(domain: Domain, len: usize, full_len: usize, from: SocketAddr) -> RecvMsg {
    RecvMsg {
        len,
        full_len,
        from: Some(present(domain, from)),
        flags: if full_len > len {
            MsgFlags::MSG_TRUNC
        } else {
            MsgFlags(0)
        },
        control: Vec::new(),
    }
}
