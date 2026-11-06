//! Real namespace/port-table admission tests with a deliberately pending provider lease.
use super::*;
use crate::{
    Backend, BackendDatagram, BackendStream, InboundSink, Net, NetConfig, Network, Publication,
    Socket, SocketKind,
};
use std::{
    io,
    sync::{
        Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

#[derive(Default)]
struct Gate {
    result: Mutex<Option<Result<SocketAddr, Errno>>>,
    queue: WaitQueue,
}
struct Bound {
    gate: Arc<Gate>,
    drops: Arc<AtomicUsize>,
}
impl EndpointBound for Bound {
    fn local_addr(&self) -> Result<SocketAddr, Errno> {
        self.gate
            .result
            .lock()
            .unwrap()
            .unwrap_or(Err(Errno::EAGAIN))
    }
}
impl Pollable for Bound {
    fn poll(&self, mut table: Option<&mut PollTable<'_>>) -> PollMask {
        wasixv2_wait::poll_wait(&mut table, &self.gate.queue);
        match self.local_addr() {
            Ok(_) => PollMask::OUT,
            Err(Errno::EAGAIN) => PollMask::empty(),
            Err(_) => PollMask::ERR,
        }
    }
}
impl Drop for Bound {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
#[derive(Default)]
struct Provider {
    decline: AtomicBool,
    gate: Arc<Gate>,
    drops: Arc<AtomicUsize>,
    requests: Mutex<Vec<EndpointBindRequest>>,
    leases: Mutex<Vec<Weak<Bound>>>,
    groups: Arc<Mutex<Vec<EndpointGroupSpec>>>,
}
impl Provider {
    fn ready(&self, addr: &str) {
        *self.gate.result.lock().unwrap() = Some(Ok(addr.parse().unwrap()));
        self.gate.queue.wake(PollMask::OUT);
    }
}
struct Lease {
    reporter: PublicationReporter,
    groups: Arc<Mutex<Vec<EndpointGroupSpec>>>,
    group: EndpointGroupSpec,
}
impl EndpointLease for Lease {
    fn reporter(&self) -> &PublicationReporter {
        &self.reporter
    }
    fn update_members(&self, revision: u64, members: Arc<[EndpointMember]>) {
        let mut group = self.group.clone();
        group.revision = revision;
        group.members = members;
        self.groups.lock().unwrap().push(group);
    }
}
impl Pollable for Lease {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.reporter.poll(table)
    }
}
impl EndpointProvider for Provider {
    fn bind(
        &self,
        request: EndpointBindRequest,
        _: WaitQueue,
    ) -> Result<Option<Arc<dyn EndpointBound>>, Errno> {
        self.requests.lock().unwrap().push(request);
        if self.decline.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let bound = Arc::new(Bound {
            gate: self.gate.clone(),
            drops: self.drops.clone(),
        });
        self.leases.lock().unwrap().push(Arc::downgrade(&bound));
        Ok(Some(bound))
    }
    fn publish_tcp(
        &self,
        group: EndpointGroupSpec,
        _: u32,
        _: Arc<dyn EndpointStreamIngress>,
        reporter: PublicationReporter,
    ) -> Result<Arc<dyn EndpointLease>, Errno> {
        self.groups.lock().unwrap().push(group.clone());
        reporter.ready();
        Ok(Arc::new(Lease {
            reporter,
            groups: self.groups.clone(),
            group,
        }))
    }
    fn publish_udp(
        &self,
        group: EndpointGroupSpec,
        _: Arc<dyn EndpointDatagramIngress>,
        reporter: PublicationReporter,
    ) -> Result<Arc<dyn EndpointLease>, Errno> {
        self.groups.lock().unwrap().push(group.clone());
        reporter.ready();
        Ok(Arc::new(Lease {
            reporter,
            groups: self.groups.clone(),
            group,
        }))
    }
}
struct Adapter(Arc<Provider>);
impl Backend for Adapter {
    fn endpoint_namespace(&self) -> Option<Arc<dyn EndpointProvider>> {
        Some(self.0.clone())
    }
    fn connect(&self, _: SocketAddr, _: WaitQueue) -> Result<Arc<dyn BackendStream>, Errno> {
        Err(Errno::EOPNOTSUPP)
    }
    fn datagram(&self, _: Domain, _: WaitQueue) -> Result<Arc<dyn BackendDatagram>, Errno> {
        Err(Errno::EOPNOTSUPP)
    }
    fn publish(
        &self,
        _: SocketAddr,
        _: u32,
        _: Arc<dyn InboundSink>,
    ) -> io::Result<Box<dyn Publication>> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
fn setup(kind: SocketKind) -> (Arc<Net>, Arc<Provider>, Arc<dyn Socket>) {
    let provider = Arc::new(Provider::default());
    let net = Net::new(
        NetConfig::default(),
        Some(Arc::new(Adapter(provider.clone()))),
    );
    let socket = net.socket(Domain::Inet, kind, 0, 1).unwrap();
    (net, provider, socket)
}

#[test]
fn pending_explicit_zero_commits_actual_address_once() {
    for kind in [SocketKind::Stream, SocketKind::Datagram] {
        let (net, provider, socket) = setup(kind);
        let requested = "127.0.0.1:0".parse().unwrap();
        let admission = socket.bind_admission(requested, false).unwrap().unwrap();
        assert_eq!(admission.complete(), Err(Errno::EAGAIN));
        assert_eq!(socket.local_addr().unwrap().port(), 0);
        assert!(net.endpoint_publications().is_empty());
        let request = provider.requests.lock().unwrap()[0];
        assert_eq!(request.requested, requested);
        assert!(request.explicit);
        provider.ready("127.0.0.1:43121");
        assert_eq!(admission.complete(), Ok(()));
        assert_eq!(admission.complete(), Ok(()));
        assert_eq!(
            socket.local_addr().unwrap(),
            "127.0.0.1:43121".parse().unwrap()
        );
        drop(admission);
        if kind == SocketKind::Stream {
            socket.listen(1).unwrap();
        }
        let groups = provider.groups.lock().unwrap();
        let member = &groups.last().unwrap().members[0];
        assert_eq!(member.requested_bind, Some(requested));
        let original: Arc<dyn EndpointBound> =
            provider.leases.lock().unwrap()[0].upgrade().unwrap();
        assert!(Arc::ptr_eq(member.binding.as_ref().unwrap(), &original));
    }
}

#[test]
fn dropping_pending_admission_retires_lease_and_allows_rebind() {
    let (_, provider, socket) = setup(SocketKind::Datagram);
    let admission = socket
        .bind_admission("127.0.0.1:0".parse().unwrap(), false)
        .unwrap()
        .unwrap();
    drop(admission);
    assert_eq!(provider.drops.load(Ordering::SeqCst), 1);
    provider.ready("127.0.0.1:43122");
    assert_eq!(socket.local_addr().unwrap().port(), 0);
    let retry = socket
        .bind_admission("127.0.0.1:0".parse().unwrap(), false)
        .unwrap()
        .unwrap();
    assert_eq!(retry.complete(), Ok(()));
    let requests = provider.requests.lock().unwrap();
    assert_ne!(requests[0].source_id, requests[1].source_id);
}

#[test]
fn canonical_conflict_does_not_publish_or_lose_existing_binding() {
    let (net, provider, socket) = setup(SocketKind::Datagram);
    let occupied = net
        .socket(Domain::Inet, SocketKind::Datagram, 0, 1)
        .unwrap();
    let addr = "127.0.0.1:43123".parse().unwrap();
    occupied.bind(addr, false).unwrap();
    let before = provider.groups.lock().unwrap().len();
    let admission = socket
        .bind_admission("127.0.0.1:0".parse().unwrap(), false)
        .unwrap()
        .unwrap();
    provider.ready("127.0.0.1:43123");
    assert_eq!(admission.complete(), Err(Errno::EADDRINUSE));
    drop(admission);
    assert_eq!(occupied.local_addr().unwrap(), addr);
    assert_eq!(socket.local_addr().unwrap().port(), 0);
    assert_eq!(provider.groups.lock().unwrap().len(), before);
    assert_eq!(provider.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn checks_precede_provider_and_second_explicit_bind_is_not_a_subscription() {
    let (_, provider, socket) = setup(SocketKind::Stream);
    assert_eq!(
        socket
            .bind_admission("127.0.0.1:80".parse().unwrap(), false)
            .err(),
        Some(Errno::EACCES)
    );
    assert!(provider.requests.lock().unwrap().is_empty());
    let first = socket
        .bind_admission("127.0.0.1:0".parse().unwrap(), false)
        .unwrap()
        .unwrap();
    assert_eq!(
        socket
            .bind_admission("127.0.0.1:43124".parse().unwrap(), false)
            .err(),
        Some(Errno::EINVAL)
    );
    assert_eq!(provider.requests.lock().unwrap().len(), 1);
    drop(first);
}

#[test]
fn implicit_udp_subscriptions_share_one_owner_and_keep_literal_none() {
    let (_, provider, socket) = setup(SocketKind::Datagram);
    let destination = "127.0.0.1:45000".parse().unwrap();
    let a = socket
        .autobind_admission(EndpointAutobind::Connect(destination), false)
        .unwrap()
        .unwrap();
    let b = socket
        .autobind_admission(EndpointAutobind::Connect(destination), false)
        .unwrap()
        .unwrap();
    assert_eq!(provider.requests.lock().unwrap().len(), 1);
    drop(a);
    assert_eq!(provider.drops.load(Ordering::SeqCst), 0);
    assert_eq!(b.complete(), Err(Errno::EAGAIN));
    provider.ready("0.0.0.0:43125");
    assert_eq!(b.complete(), Ok(()));
    drop(b);
    let groups = provider.groups.lock().unwrap();
    assert_eq!(groups.last().unwrap().members[0].requested_bind, None);
    let request = provider.requests.lock().unwrap()[0];
    assert!(!request.explicit);
    assert_eq!(request.requested, "0.0.0.0:0".parse().unwrap());
}

#[test]
fn invalid_actual_address_does_not_commit() {
    for actual in ["127.0.0.1:0", "127.0.0.2:43126"] {
        let (_, provider, socket) = setup(SocketKind::Stream);
        let admission = socket
            .bind_admission("127.0.0.1:0".parse().unwrap(), false)
            .unwrap()
            .unwrap();
        provider.ready(actual);
        assert_eq!(admission.complete(), Err(Errno::EPROTO));
        drop(admission);
        assert_eq!(socket.local_addr().unwrap().port(), 0);
    }
}

#[test]
fn implicit_udp_cancel_rebind_then_send_uses_provider_port() {
    let (net, provider, socket) = setup(SocketKind::Datagram);
    let receiver = net
        .socket(Domain::Inet, SocketKind::Datagram, 0, 1)
        .unwrap();
    let destination = "127.0.0.1:45001".parse().unwrap();
    receiver.bind(destination, false).unwrap();
    let admission = socket
        .autobind_admission(EndpointAutobind::Connect(destination), false)
        .unwrap()
        .unwrap();
    drop(admission);
    assert_eq!(provider.drops.load(Ordering::SeqCst), 1);
    let message = crate::SendMsg {
        data: b"one",
        to: Some(destination),
        flags: wasixv2_abi::MsgFlags::empty(),
        control: &[],
        net_raw: false,
        now: std::time::Duration::ZERO,
    };
    let admission = socket
        .autobind_admission(EndpointAutobind::Send(&message), false)
        .unwrap()
        .unwrap();
    provider.ready("0.0.0.0:43127");
    admission.complete().unwrap();
    drop(admission);
    assert_eq!(socket.send(message), Ok(3));
    let mut bytes = [0; 8];
    let received = receiver
        .recv(&mut bytes, wasixv2_abi::MsgFlags::empty())
        .unwrap();
    assert_eq!(&bytes[..received.len], b"one");
    assert_eq!(received.from.unwrap().port(), 43127);
}

#[test]
fn invalid_udp_send_does_not_start_provider_binding() {
    let (_, provider, socket) = setup(SocketKind::Datagram);
    let message = crate::SendMsg {
        data: b"one",
        to: Some("127.0.0.1:45002".parse().unwrap()),
        flags: wasixv2_abi::MsgFlags::MSG_OOB,
        control: &[],
        net_raw: false,
        now: std::time::Duration::ZERO,
    };
    assert_eq!(
        socket
            .autobind_admission(EndpointAutobind::Send(&message), false)
            .err(),
        Some(Errno::EOPNOTSUPP)
    );
    assert!(provider.requests.lock().unwrap().is_empty());
}

#[test]
fn disconnect_retires_pending_bind_before_provider_is_ready() {
    let (_, provider, socket) = setup(SocketKind::Datagram);
    let admission = socket
        .autobind_admission(
            EndpointAutobind::Connect("127.0.0.1:45003".parse().unwrap()),
            false,
        )
        .unwrap()
        .unwrap();
    socket.disconnect().unwrap();
    assert_eq!(admission.complete(), Err(Errno::ECANCELED));
    drop(admission);
    assert_eq!(provider.drops.load(Ordering::SeqCst), 1);
    assert_eq!(socket.local_addr().unwrap().port(), 0);
}

struct Readback {
    inner: Arc<dyn BackendStream>,
    _peer: Arc<dyn BackendStream>,
    local: SocketAddr,
}
impl Pollable for Readback {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.inner.poll(table)
    }
}
impl BackendStream for Readback {
    fn provider_local_addr(&self) -> Option<Result<SocketAddr, Errno>> {
        Some(Ok(self.local))
    }
    fn state(&self) -> crate::StreamState {
        self.inner.state()
    }
    fn read(&self, bytes: &mut [u8], peek: bool) -> Result<usize, Errno> {
        self.inner.read(bytes, peek)
    }
    fn write(&self, bytes: &[u8]) -> Result<usize, Errno> {
        self.inner.write(bytes)
    }
    fn write_urgent(&self, bytes: &[u8]) -> Result<usize, Errno> {
        self.inner.write_urgent(bytes)
    }
    fn read_urgent(&self, peek: bool) -> Result<u8, Errno> {
        self.inner.read_urgent(peek)
    }
    fn at_mark(&self) -> bool {
        self.inner.at_mark()
    }
    fn shutdown(&self, how: crate::Shutdown) -> Result<(), Errno> {
        self.inner.shutdown(how)
    }
    fn take_error(&self) -> Option<Errno> {
        self.inner.take_error()
    }
    fn peer_addr(&self) -> SocketAddr {
        self.inner.peer_addr()
    }
    fn input_len(&self) -> usize {
        self.inner.input_len()
    }
}
struct ConnectProvider {
    external: bool,
    fallbacks: AtomicUsize,
    binding: Arc<Provider>,
    actual: SocketAddr,
    queries: Mutex<Vec<EndpointQuery>>,
}
impl EndpointProvider for ConnectProvider {
    fn select_external(&self) -> bool {
        self.external
    }
    fn bind(
        &self,
        request: EndpointBindRequest,
        queue: WaitQueue,
    ) -> Result<Option<Arc<dyn EndpointBound>>, Errno> {
        self.binding.bind(request, queue)
    }
    fn select(&self, query: &EndpointQuery) -> Result<EndpointChoice, Errno> {
        self.queries.lock().unwrap().push(query.clone());
        Ok(EndpointChoice::Provider(EndpointTarget::new(())))
    }
    fn connect(
        &self,
        _: EndpointTarget,
        _: EndpointSourceId,
        _: SocketAddr,
        remote: SocketAddr,
        queue: WaitQueue,
    ) -> Result<Arc<dyn BackendStream>, Errno> {
        let [inner, peer] =
            crate::MemoryStream::pair([self.actual, remote], [queue, WaitQueue::new()]);
        Ok(Arc::new(Readback {
            inner,
            _peer: peer,
            local: self.actual,
        }))
    }
}
struct ConnectAdapter(Arc<ConnectProvider>);
impl Backend for ConnectAdapter {
    fn endpoint_namespace(&self) -> Option<Arc<dyn EndpointProvider>> {
        Some(self.0.clone())
    }
    fn connect(&self, _: SocketAddr, _: WaitQueue) -> Result<Arc<dyn BackendStream>, Errno> {
        self.0.fallbacks.fetch_add(1, Ordering::SeqCst);
        Err(Errno::EHOSTUNREACH)
    }
    fn datagram(&self, _: Domain, _: WaitQueue) -> Result<Arc<dyn BackendDatagram>, Errno> {
        Err(Errno::EOPNOTSUPP)
    }
    fn publish(
        &self,
        _: SocketAddr,
        _: u32,
        _: Arc<dyn InboundSink>,
    ) -> io::Result<Box<dyn Publication>> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
#[test]
fn unbound_tcp_reports_actual_provider_local_without_explicit_bind() {
    let provider = Arc::new(ConnectProvider {
        external: false,
        fallbacks: AtomicUsize::new(0),
        binding: Arc::new(Provider::default()),
        actual: "127.0.0.1:43128".parse().unwrap(),
        queries: Mutex::default(),
    });
    let net = Net::new(
        NetConfig::default(),
        Some(Arc::new(ConnectAdapter(provider.clone()))),
    );
    let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
    let remote = "127.0.0.1:45004".parse().unwrap();
    let result = socket.connect(remote);
    assert!(result == Ok(()) || result == Err(Errno::EINPROGRESS));
    assert_eq!(socket.local_addr().unwrap(), provider.actual);
    assert_eq!(socket.peer_addr().unwrap(), remote);
    assert!(provider.binding.requests.lock().unwrap().is_empty());
    let queries = provider.queries.lock().unwrap();
    assert_eq!(queries[0].requested_bind, None);
    assert!(queries[0].binding.is_none());
}

#[test]
fn explicit_tcp_connection_retains_same_admitted_bound_token() {
    let binding = Arc::new(Provider::default());
    binding.ready("127.0.0.1:43129");
    let provider = Arc::new(ConnectProvider {
        external: false,
        fallbacks: AtomicUsize::new(0),
        binding: binding.clone(),
        actual: "127.0.0.1:43129".parse().unwrap(),
        queries: Mutex::default(),
    });
    let net = Net::new(
        NetConfig::default(),
        Some(Arc::new(ConnectAdapter(provider.clone()))),
    );
    let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
    let requested = "127.0.0.1:0".parse().unwrap();
    let admission = socket.bind_admission(requested, false).unwrap().unwrap();
    admission.complete().unwrap();
    drop(admission);
    let _ = socket.connect("127.0.0.1:45005".parse().unwrap());
    assert_eq!(socket.local_addr().unwrap(), provider.actual);
    let queries = provider.queries.lock().unwrap();
    assert_eq!(queries[0].requested_bind, Some(requested));
    let original: Arc<dyn EndpointBound> = binding.leases.lock().unwrap()[0].upgrade().unwrap();
    assert!(Arc::ptr_eq(queries[0].binding.as_ref().unwrap(), &original));
}

#[test]
fn actual_tcp_source_conflict_is_terminal_without_replay_or_stale_reservation() {
    let provider = Arc::new(ConnectProvider {
        external: false,
        fallbacks: AtomicUsize::new(0),
        binding: Arc::new(Provider::default()),
        actual: "127.0.0.1:43130".parse().unwrap(),
        queries: Mutex::default(),
    });
    let net = Net::new(
        NetConfig::default(),
        Some(Arc::new(ConnectAdapter(provider.clone()))),
    );
    let occupied = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
    occupied.bind(provider.actual, false).unwrap();
    let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
    let remote = "127.0.0.1:45006".parse().unwrap();
    assert_eq!(socket.connect(remote), Err(Errno::EINPROGRESS));
    assert_eq!(socket.connect(remote), Err(Errno::EADDRINUSE));
    assert_eq!(provider.queries.lock().unwrap().len(), 1);
    assert_eq!(net.state().tcp.entries().count(), 1);
    assert_eq!(occupied.local_addr().unwrap(), provider.actual);
}

#[test]
fn ipv6_zero_bind_preserves_requested_and_actual_family() {
    for kind in [SocketKind::Stream, SocketKind::Datagram] {
        let provider = Arc::new(Provider::default());
        provider.ready("[::1]:43131");
        let net = Net::new(
            NetConfig::default(),
            Some(Arc::new(Adapter(provider.clone()))),
        );
        let socket = net.socket(Domain::Inet6, kind, 0, 1).unwrap();
        let requested = "[::1]:0".parse().unwrap();
        let admission = socket.bind_admission(requested, false).unwrap().unwrap();
        admission.complete().unwrap();
        drop(admission);
        assert_eq!(socket.local_addr().unwrap(), "[::1]:43131".parse().unwrap());
        let request = provider.requests.lock().unwrap()[0];
        assert_eq!(request.requested, requested);
        assert_eq!(request.domain, Domain::Inet6);
    }
}

#[test]
fn reuse_members_keep_distinct_original_requests_and_bound_leases() {
    let (net, provider, first) = setup(SocketKind::Stream);
    provider.ready("127.0.0.1:43132");
    let second = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
    for socket in [&first, &second] {
        socket
            .set_option(
                wasixv2_abi::SocketLevel::SOL_SOCKET.0,
                wasixv2_abi::SocketOption::SO_REUSEPORT.0,
                &1i32.to_le_bytes(),
            )
            .unwrap();
    }
    let a = first
        .bind_admission("127.0.0.1:0".parse().unwrap(), false)
        .unwrap()
        .unwrap();
    a.complete().unwrap();
    drop(a);
    first.listen(1).unwrap();
    let b = second
        .bind_admission("127.0.0.1:43132".parse().unwrap(), false)
        .unwrap()
        .unwrap();
    b.complete().unwrap();
    drop(b);
    second.listen(2).unwrap();
    let groups = provider.groups.lock().unwrap();
    let group = groups.last().unwrap();
    assert_eq!(group.members.len(), 2);
    let requests: Vec<_> = group
        .members
        .iter()
        .map(|m| m.requested_bind.unwrap().port())
        .collect();
    assert!(requests.contains(&0));
    assert!(requests.contains(&43132));
    assert!(!Arc::ptr_eq(
        group.members[0].binding.as_ref().unwrap(),
        group.members[1].binding.as_ref().unwrap()
    ));
}

#[test]
fn external_selection_is_opt_in_and_preserves_original_destination_and_actual_source() {
    for external in [false, true] {
        let provider = Arc::new(ConnectProvider {
            external,
            fallbacks: AtomicUsize::new(0),
            binding: Arc::new(Provider::default()),
            actual: "192.0.2.44:43133".parse().unwrap(),
            queries: Mutex::default(),
        });
        let net = Net::new(
            NetConfig::host_default(),
            Some(Arc::new(ConnectAdapter(provider.clone()))),
        );
        let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
        let destination = "198.51.100.7:45007".parse().unwrap();
        let result = socket.connect(destination);
        if external {
            assert!(result == Ok(()) || result == Err(Errno::EINPROGRESS));
            assert_eq!(socket.local_addr().unwrap(), provider.actual);
            let queries = provider.queries.lock().unwrap();
            assert_eq!(queries.len(), 1);
            assert_eq!(queries[0].destination, destination);
            assert_eq!(queries[0].requested_bind, None);
            assert_eq!(provider.fallbacks.load(Ordering::SeqCst), 0);
        } else {
            assert_eq!(result, Err(Errno::EHOSTUNREACH));
            assert!(provider.queries.lock().unwrap().is_empty());
            assert_eq!(provider.fallbacks.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn external_selection_does_not_intercept_namespace_dns() {
    let provider = Arc::new(ConnectProvider {
        external: true,
        fallbacks: AtomicUsize::new(0),
        binding: Arc::new(Provider::default()),
        actual: "192.0.2.44:43134".parse().unwrap(),
        queries: Mutex::default(),
    });
    let config = NetConfig::host_default();
    let destination = SocketAddr::new(config.dns_server[0], 53);
    let net = Net::new(config, Some(Arc::new(ConnectAdapter(provider.clone()))));
    let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
    let _ = socket.connect(destination);
    assert!(provider.queries.lock().unwrap().is_empty());
    assert_eq!(provider.fallbacks.load(Ordering::SeqCst), 0);
}

#[test]
fn unbound_listen_uses_distinct_direct_listen_purpose_and_same_lease() {
    let (_, provider, socket) = setup(SocketKind::Stream);
    let admission = socket
        .autobind_admission(EndpointAutobind::Listen(7), false)
        .unwrap()
        .unwrap();
    let request = provider.requests.lock().unwrap()[0];
    assert!(!request.explicit);
    assert_eq!(request.purpose, EndpointBindPurpose::Listen { backlog: 7 });
    assert_eq!(request.requested, "0.0.0.0:0".parse().unwrap());
    provider.ready("0.0.0.0:43135");
    admission.complete().unwrap();
    drop(admission);
    socket.listen(7).unwrap();
    assert_eq!(
        socket.local_addr().unwrap(),
        "0.0.0.0:43135".parse().unwrap()
    );
    let groups = provider.groups.lock().unwrap();
    let member = &groups.last().unwrap().members[0];
    assert_eq!(member.requested_bind, None);
    let bound: Arc<dyn EndpointBound> = provider.leases.lock().unwrap()[0].upgrade().unwrap();
    assert!(Arc::ptr_eq(member.binding.as_ref().unwrap(), &bound));
}

#[test]
fn declined_noport_bind_preserves_namespace_autobind_and_original_request() {
    for kind in [SocketKind::Stream, SocketKind::Datagram] {
        let (_, provider, socket) = setup(kind);
        provider.decline.store(true, Ordering::SeqCst);
        socket
            .set_option(
                0,
                wasixv2_abi::IpOption::IP_BIND_ADDRESS_NO_PORT.0,
                &1i32.to_le_bytes(),
            )
            .unwrap();
        let requested = "127.0.0.1:0".parse().unwrap();
        assert!(socket.bind_admission(requested, false).unwrap().is_none());
        socket.bind(requested, false).unwrap();
        assert_eq!(socket.local_addr().unwrap(), requested);
        let operation = if kind == SocketKind::Stream {
            EndpointAutobind::Listen(1)
        } else {
            EndpointAutobind::Connect("127.0.0.1:45010".parse().unwrap())
        };
        assert!(
            socket
                .autobind_admission(operation, false)
                .unwrap()
                .is_none()
        );
        if kind == SocketKind::Stream {
            socket.listen(1).unwrap();
        } else {
            socket.connect("127.0.0.1:45010".parse().unwrap()).unwrap();
        }
        assert_ne!(socket.local_addr().unwrap().port(), 0);
        let requests = provider.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|r| r.requested == requested && r.explicit)
        );
    }
}

#[test]
fn admitted_udp_connect_and_disconnect_preserve_actual_wildcard_binding() {
    for (domain, requested, actual, remote) in [
        (
            Domain::Inet,
            "0.0.0.0:0",
            "0.0.0.0:43136",
            "127.0.0.1:45011",
        ),
        (Domain::Inet6, "[::]:0", "[::]:43137", "[::1]:45012"),
    ] {
        let provider = Arc::new(Provider::default());
        provider.ready(actual);
        let net = Net::new(
            NetConfig::default(),
            Some(Arc::new(Adapter(provider.clone()))),
        );
        let socket = net.socket(domain, SocketKind::Datagram, 0, 1).unwrap();
        let admission = socket
            .bind_admission(requested.parse().unwrap(), false)
            .unwrap()
            .unwrap();
        admission.complete().unwrap();
        drop(admission);
        let original: Arc<dyn EndpointBound> =
            provider.leases.lock().unwrap()[0].upgrade().unwrap();
        socket.connect(remote.parse().unwrap()).unwrap();
        assert_eq!(socket.local_addr().unwrap(), actual.parse().unwrap());
        socket.disconnect().unwrap();
        assert_eq!(socket.local_addr().unwrap(), actual.parse().unwrap());
        socket.connect(remote.parse().unwrap()).unwrap();
        assert_eq!(socket.local_addr().unwrap(), actual.parse().unwrap());
        let groups = provider.groups.lock().unwrap();
        assert!(Arc::ptr_eq(
            groups.last().unwrap().members[0].binding.as_ref().unwrap(),
            &original
        ));
    }
}

#[test]
fn broadcast_port_and_ancillary_failures_precede_provider_side_effects() {
    let (_, provider, socket) = setup(SocketKind::Datagram);
    let bad_control = [crate::Control {
        level: 0,
        kind: wasixv2_abi::IpOption::IP_TTL.0,
        data: vec![1],
    }];
    for (to, control, expected) in [
        ("255.255.255.255:45013", &[][..], Errno::EACCES),
        ("127.0.0.1:0", &[][..], Errno::EINVAL),
        ("127.0.0.1:45013", &bad_control[..], Errno::EINVAL),
    ] {
        let msg = crate::SendMsg {
            data: b"x",
            to: Some(to.parse().unwrap()),
            flags: wasixv2_abi::MsgFlags::empty(),
            control,
            net_raw: false,
            now: std::time::Duration::ZERO,
        };
        assert_eq!(
            socket
                .autobind_admission(EndpointAutobind::Send(&msg), false)
                .err(),
            Some(expected)
        );
        assert!(provider.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn dont_fragment_mtu_failure_precedes_provider_binding() {
    let provider = Arc::new(Provider::default());
    let net = Net::new(
        NetConfig::host_default(),
        Some(Arc::new(Adapter(provider.clone()))),
    );
    let socket = net
        .socket(Domain::Inet, SocketKind::Datagram, 0, 1)
        .unwrap();
    socket
        .set_option(
            0,
            wasixv2_abi::IpOption::IP_MTU_DISCOVER.0,
            &2i32.to_le_bytes(),
        )
        .unwrap();
    let bytes = vec![0; 1473];
    let msg = crate::SendMsg {
        data: &bytes,
        to: Some("198.51.100.8:45014".parse().unwrap()),
        flags: wasixv2_abi::MsgFlags::empty(),
        control: &[],
        net_raw: false,
        now: std::time::Duration::ZERO,
    };
    assert_eq!(
        socket
            .autobind_admission(EndpointAutobind::Send(&msg), false)
            .err(),
        Some(Errno::EMSGSIZE)
    );
    assert!(provider.requests.lock().unwrap().is_empty());
}

#[test]
fn pending_socket_error_is_observed_before_new_provider_bind() {
    let (_, provider, socket) = setup(SocketKind::Datagram);
    provider.decline.store(true, Ordering::SeqCst);
    let destination = "127.0.0.1:45015".parse().unwrap();
    socket.connect(destination).unwrap();
    let first = crate::SendMsg {
        data: b"x",
        to: None,
        flags: wasixv2_abi::MsgFlags::empty(),
        control: &[],
        net_raw: false,
        now: std::time::Duration::ZERO,
    };
    socket.send(first).unwrap();
    socket.disconnect().unwrap();
    provider.decline.store(false, Ordering::SeqCst);
    let before = provider.requests.lock().unwrap().len();
    let msg = crate::SendMsg {
        data: b"y",
        to: Some(destination),
        flags: wasixv2_abi::MsgFlags::empty(),
        control: &[],
        net_raw: false,
        now: std::time::Duration::ZERO,
    };
    assert_eq!(
        socket
            .autobind_admission(EndpointAutobind::Send(&msg), false)
            .err(),
        Some(Errno::ECONNREFUSED)
    );
    assert_eq!(provider.requests.lock().unwrap().len(), before);
}

#[test]
fn prebind_validation_and_cancellation_do_not_consume_a_pending_cork() {
    let (net, provider, socket) = setup(SocketKind::Datagram);
    let receiver = net
        .socket(Domain::Inet, SocketKind::Datagram, 0, 1)
        .unwrap();
    let destination = "127.0.0.1:45016".parse().unwrap();
    receiver.bind(destination, false).unwrap();
    let first = crate::SendMsg {
        data: b"a",
        to: Some(destination),
        flags: wasixv2_abi::MsgFlags::MSG_MORE,
        control: &[],
        net_raw: false,
        now: std::time::Duration::ZERO,
    };
    socket.send(first).unwrap();
    socket.disconnect().unwrap();
    let next = crate::SendMsg {
        data: b"b",
        to: Some(destination),
        flags: wasixv2_abi::MsgFlags::empty(),
        control: &[],
        net_raw: false,
        now: std::time::Duration::ZERO,
    };
    let admission = socket
        .autobind_admission(EndpointAutobind::Send(&next), false)
        .unwrap()
        .unwrap();
    drop(admission);
    assert_eq!(provider.drops.load(Ordering::SeqCst), 1);
    assert_eq!(socket.send(next), Ok(1));
    let mut bytes = [0; 8];
    let result = receiver
        .recv(&mut bytes, wasixv2_abi::MsgFlags::empty())
        .unwrap();
    assert_eq!(&bytes[..result.len], b"ab");
}
