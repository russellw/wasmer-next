use super::ProviderNetwork;
use crate::network_api::{
    DatagramInfo, DatagramReceiveLease, DatagramReceiver, DynNetworkProvider, NetworkCloseMode,
    NetworkProvider, NetworkResult as NetResult, ReceivedDatagram, TcpListener, TcpStream,
    UdpSocket,
};
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use wasixv2_abi::Errno;
use wasixv2_vnet::{
    Answer, Backend, BackendDatagram, BackendStream, Found, InboundSink, Lookup, LookupDone,
    LookupError, Room, StreamState,
};
use wasixv2_wait::{PollMask, PollTable, Pollable, WaitQueue};

const WAIT: Duration = Duration::from_secs(2);

async fn wait_until(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("provider service operation did not reach the expected state");
}

#[derive(Clone)]
struct Gate {
    started: Arc<Notify>,
    canceled: Arc<AtomicUsize>,
}

impl Gate {
    fn new() -> Self {
        Self {
            started: Arc::new(Notify::new()),
            canceled: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn stop(&self) {
        self.started.notify_one();
        let _drop = DropMark(self.canceled.clone());
        std::future::pending::<()>().await;
    }

    async fn wait_started(&self) {
        tokio::time::timeout(WAIT, self.started.notified())
            .await
            .expect("provider operation did not start");
    }
}

struct DropMark(Arc<AtomicUsize>);

impl Drop for DropMark {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct TestTcp {
    socket: Arc<wasixv2_vnet::MemoryStream>,
    local: SocketAddr,
}
impl TestTcp {
    fn pair(local: SocketAddr, peer: SocketAddr) -> (Arc<Self>, Arc<Self>) {
        let [one, two] =
            wasixv2_vnet::MemoryStream::pair([local, peer], [WaitQueue::new(), WaitQueue::new()]);
        (
            Arc::new(Self { socket: one, local }),
            Arc::new(Self {
                socket: two,
                local: peer,
            }),
        )
    }
}
impl Pollable for TestTcp {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.socket.poll(table)
    }
}
impl BackendStream for TestTcp {
    fn state(&self) -> StreamState {
        self.socket.state()
    }
    fn read(&self, buf: &mut [u8], peek: bool) -> NetResult<usize> {
        self.socket.read(buf, peek)
    }
    fn write(&self, data: &[u8]) -> NetResult<usize> {
        self.socket.write(data)
    }
    fn write_urgent(&self, data: &[u8]) -> NetResult<usize> {
        self.socket.write_urgent(data)
    }
    fn read_urgent(&self, peek: bool) -> NetResult<u8> {
        self.socket.read_urgent(peek)
    }
    fn at_mark(&self) -> bool {
        self.socket.at_mark()
    }
    fn shutdown(&self, how: wasixv2_vnet::Shutdown) -> NetResult<()> {
        self.socket.shutdown(how)
    }
    fn take_error(&self) -> Option<Errno> {
        self.socket.take_error()
    }
    fn peer_addr(&self) -> SocketAddr {
        self.socket.peer_addr()
    }
    fn input_len(&self) -> usize {
        self.socket.input_len()
    }
}
#[async_trait::async_trait]
impl TcpStream for TestTcp {
    fn local_addr(&self) -> NetResult<SocketAddr> {
        Ok(self.local)
    }
    fn flush(&self) -> NetResult<()> {
        Ok(())
    }
    fn set_socket_option(&self, level: i32, name: i32, value: &[u8]) -> NetResult<()> {
        self.socket.set_option(level, name, value)
    }
    async fn close(&self, _mode: NetworkCloseMode) -> NetResult<()> {
        self.socket.shutdown(wasixv2_vnet::Shutdown::Both)
    }
}

type ResolveCall = (String, Option<u16>, Option<IpAddr>);

struct FakeProvider {
    tcp: Mutex<Option<Arc<dyn TcpStream>>>,
    udp: Mutex<Option<Arc<dyn UdpSocket>>>,
    listener: Mutex<Option<Arc<dyn TcpListener>>>,
    connect_gate: Option<Gate>,
    resolve_gate: Option<Gate>,
    dns_answer: Vec<IpAddr>,
    tcp_calls: Mutex<Vec<(SocketAddr, SocketAddr)>>,
    udp_calls: Mutex<Vec<(SocketAddr, bool, bool)>>,
    listen_calls: Mutex<Vec<(SocketAddr, bool, bool, bool)>>,
    resolve_calls: Mutex<Vec<ResolveCall>>,
}

impl std::fmt::Debug for FakeProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeProvider").finish_non_exhaustive()
    }
}

impl FakeProvider {
    fn new() -> Self {
        Self {
            tcp: Mutex::new(None),
            udp: Mutex::new(None),
            listener: Mutex::new(None),
            connect_gate: None,
            resolve_gate: None,
            dns_answer: Vec::new(),
            tcp_calls: Mutex::new(Vec::new()),
            udp_calls: Mutex::new(Vec::new()),
            listen_calls: Mutex::new(Vec::new()),
            resolve_calls: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl NetworkProvider for FakeProvider {
    async fn connect_tcp(
        &self,
        addr: SocketAddr,
        peer: SocketAddr,
        _queue: WaitQueue,
    ) -> NetResult<Arc<dyn TcpStream>> {
        self.tcp_calls.lock().unwrap().push((addr, peer));
        if let Some(gate) = &self.connect_gate {
            gate.stop().await;
        }
        self.tcp.lock().unwrap().take().ok_or(Errno::ECONNREFUSED)
    }

    async fn bind_udp(
        &self,
        addr: SocketAddr,
        _v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
        queue: WaitQueue,
    ) -> NetResult<Arc<dyn UdpSocket>> {
        self.udp_calls
            .lock()
            .unwrap()
            .push((addr, reuse_port, reuse_addr));
        let socket = self
            .udp
            .lock()
            .unwrap()
            .take()
            .ok_or(Errno::EADDRNOTAVAIL)?;
        socket.attach(Some(queue))?;
        Ok(socket)
    }

    async fn listen_tcp(
        &self,
        addr: SocketAddr,
        only_v6: bool,
        reuse_port: bool,
        reuse_addr: bool,
        _backlog: u32,
        _queue: WaitQueue,
    ) -> NetResult<Arc<dyn TcpListener>> {
        self.listen_calls
            .lock()
            .unwrap()
            .push((addr, only_v6, reuse_port, reuse_addr));
        self.listener
            .lock()
            .unwrap()
            .take()
            .ok_or(Errno::EADDRNOTAVAIL)
    }

    async fn resolve(
        &self,
        host: &str,
        port: Option<u16>,
        dns_server: Option<IpAddr>,
    ) -> NetResult<Vec<IpAddr>> {
        self.resolve_calls
            .lock()
            .unwrap()
            .push((host.to_owned(), port, dns_server));
        if let Some(gate) = &self.resolve_gate {
            gate.stop().await;
        }
        Ok(self.dns_answer.clone())
    }
}

fn services_network(
    provider: Arc<FakeProvider>,
) -> (Arc<ProviderNetwork>, crate::service::Services) {
    let services = crate::service::Services::new().expect("start provider services");
    let provider: DynNetworkProvider = provider;
    (ProviderNetwork::new(provider, services.clone()), services)
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_provider_keeps_custom_peer_peek_and_remote_half_close() {
    let peer = "198.51.100.24:8443".parse().unwrap();
    let (local_socket, remote_socket) = TestTcp::pair("192.0.2.7:40123".parse().unwrap(), peer);
    let provider = Arc::new(FakeProvider::new());
    *provider.tcp.lock().unwrap() = Some(local_socket);
    let (network, services) = services_network(provider.clone());

    let stream = network
        .connect(peer, WaitQueue::default())
        .expect("start provider-backed TCP connection");
    wait_until(|| stream.state() == StreamState::Established).await;
    assert_eq!(stream.peer_addr(), peer);
    assert_eq!(
        *provider.tcp_calls.lock().unwrap(),
        vec![("0.0.0.0:0".parse().unwrap(), peer)]
    );

    assert_eq!(remote_socket.write(b"hello").unwrap(), 5);
    remote_socket
        .shutdown(wasixv2_vnet::Shutdown::Write)
        .unwrap();

    let mut first = [0; 3];
    assert_eq!(stream.read(&mut first, true).unwrap(), 3);
    assert_eq!(&first, b"hel");
    let mut repeated = [0; 3];
    assert_eq!(stream.read(&mut repeated, true).unwrap(), 3);
    assert_eq!(repeated, first);
    let mut rest = [0; 8];
    assert_eq!(stream.read(&mut rest, false).unwrap(), 5);
    assert_eq!(&rest[..5], b"hello");
    assert_eq!(stream.read(&mut rest, false).unwrap(), 0);

    network.close().await.expect("close network adapter");
    services.close().await.expect("join provider services");
}

#[derive(Clone, Debug)]
struct Packet {
    bytes: Vec<u8>,
    from: SocketAddr,
}

#[derive(Debug)]
struct FakeUdp {
    addr: SocketAddr,
    packets: Arc<Mutex<VecDeque<Packet>>>,
    peer: Mutex<Option<SocketAddr>>,
    queue: Mutex<WaitQueue>,
    closed: AtomicBool,
}
impl FakeUdp {
    fn new(addr: SocketAddr, packets: Arc<Mutex<VecDeque<Packet>>>) -> Self {
        Self {
            addr,
            packets,
            peer: Mutex::default(),
            queue: Mutex::default(),
            closed: AtomicBool::new(false),
        }
    }
}
impl Pollable for FakeUdp {
    fn poll(&self, mut table: Option<&mut PollTable<'_>>) -> PollMask {
        if let Some(table) = &mut table {
            table.wait_on(&self.queue.lock().unwrap());
        }
        if self.closed.load(Ordering::SeqCst) {
            return PollMask::HUP;
        }
        let mut mask = PollMask::OUT;
        if !self.packets.lock().unwrap().is_empty() {
            mask |= PollMask::IN;
        }
        mask
    }
}
impl BackendDatagram for FakeUdp {
    fn send_to(&self, data: &[u8], _: SocketAddr) -> NetResult<usize> {
        Ok(data.len())
    }
    fn connect(&self, peer: Option<SocketAddr>) -> NetResult<()> {
        *self.peer.lock().unwrap() = peer;
        Ok(())
    }
    fn take_error(&self) -> Option<Errno> {
        None
    }
    fn recv_from(&self, buf: &mut [u8], peek: bool) -> NetResult<(usize, usize, SocketAddr)> {
        let mut packets = self.packets.lock().unwrap();
        let packet = packets.front().cloned().ok_or(Errno::EAGAIN)?;
        if self
            .peer
            .lock()
            .unwrap()
            .is_some_and(|peer| peer != packet.from)
        {
            packets.pop_front();
            drop(packets);
            let queue = self.queue.lock().unwrap().clone();
            queue.wake(PollMask::IN);
            return Err(Errno::EAGAIN);
        }
        let copied = buf.len().min(packet.bytes.len());
        buf[..copied].copy_from_slice(&packet.bytes[..copied]);
        if !peek {
            packets.pop_front();
        }
        Ok((copied, packet.bytes.len(), packet.from))
    }
    fn input_len(&self) -> usize {
        self.packets
            .lock()
            .unwrap()
            .front()
            .map_or(0, |packet| packet.bytes.len())
    }
    fn attach(&self, queue: Option<WaitQueue>) -> NetResult<()> {
        *self.queue.lock().unwrap() = queue.ok_or(Errno::EINVAL)?;
        Ok(())
    }
}
#[async_trait::async_trait]
impl UdpSocket for FakeUdp {
    // This pull-only fixture explicitly does not provide a producer driver.
    fn install_receiver(
        &self,
        _: Arc<dyn DatagramReceiver>,
    ) -> NetResult<Arc<dyn DatagramReceiveLease>> {
        Err(Errno::EOPNOTSUPP)
    }
    fn peer_addr(&self) -> NetResult<Option<SocketAddr>> {
        Ok(*self.peer.lock().unwrap())
    }
    fn local_addr(&self) -> NetResult<SocketAddr> {
        Ok(self.addr)
    }
    fn recv_packet(&self, buf: &mut [u8], peek: bool) -> NetResult<ReceivedDatagram> {
        self.recv_from(buf, peek).map(|(copied, full, source)| {
            (
                copied,
                full,
                DatagramInfo {
                    source,
                    destination: self.addr,
                    interface: 0,
                },
            )
        })
    }
    fn set_socket_option(&self, _: i32, _: i32, _: &[u8]) -> NetResult<()> {
        Err(Errno::EOPNOTSUPP)
    }
    async fn close(&self, _mode: NetworkCloseMode) -> NetResult<()> {
        self.closed.store(true, Ordering::SeqCst);
        let queue = self.queue.lock().unwrap().clone();
        queue.wake(PollMask::HUP);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_provider_preserves_peek_truncation_zero_packets_and_custom_peer() {
    let peer = "203.0.113.9:5300".parse().unwrap();
    let foreign = "203.0.113.10:5300".parse().unwrap();
    let payload = b"provider datagram".to_vec();
    let packets = Arc::new(Mutex::new(VecDeque::from([
        Packet {
            bytes: b"ignore foreign sender".to_vec(),
            from: foreign,
        },
        Packet {
            bytes: payload.clone(),
            from: peer,
        },
        Packet {
            bytes: Vec::new(),
            from: peer,
        },
    ])));
    let provider = Arc::new(FakeProvider::new());
    *provider.udp.lock().unwrap() = Some(Arc::new(FakeUdp::new(
        "192.0.2.7:49000".parse().unwrap(),
        packets.clone(),
    )));
    let (network, services) = services_network(provider.clone());

    let queue = WaitQueue::default();
    let datagram = network
        .datagram(wasixv2_vnet::Domain::Inet, queue.clone())
        .expect("start provider-backed UDP socket");
    wait_until(|| datagram.poll(None).contains(PollMask::OUT)).await;
    assert_eq!(
        *provider.udp_calls.lock().unwrap(),
        vec![("0.0.0.0:0".parse().unwrap(), false, false)]
    );
    datagram.connect(Some(peer)).unwrap();

    struct InputWake(AtomicBool);
    impl wasixv2_wait::WaitEntry for InputWake {
        fn wake(&self, events: PollMask) -> bool {
            if events.contains(PollMask::IN) {
                self.0.store(true, Ordering::SeqCst);
            }
            true
        }
    }
    let wake = Arc::new(InputWake(AtomicBool::new(false)));
    let registration = queue.add(wake.clone());
    let mut short = [0xa5; 4];
    assert_eq!(datagram.recv_from(&mut short, true), Err(Errno::EAGAIN));
    assert_eq!(short, [0xa5; 4]);
    {
        let packets = packets.lock().unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets.front().unwrap().from, peer);
        assert_eq!(packets.front().unwrap().bytes, payload);
    }
    assert!(wake.0.load(Ordering::SeqCst));
    drop(registration);

    let first = datagram.recv_from(&mut short, true).unwrap();
    assert_eq!(first, (short.len(), payload.len(), peer));
    assert_eq!(&short, &payload[..short.len()]);

    let mut repeated = [0; 4];
    assert_eq!(
        datagram.recv_from(&mut repeated, true).unwrap(),
        (repeated.len(), payload.len(), peer)
    );
    assert_eq!(repeated, short);

    let mut full = vec![0; payload.len()];
    assert_eq!(
        datagram.recv_from(&mut full, false).unwrap(),
        (payload.len(), payload.len(), peer)
    );
    assert_eq!(full, payload);

    let mut empty = [];
    assert_eq!(datagram.recv_from(&mut empty, false).unwrap(), (0, 0, peer));
    assert_eq!(datagram.recv_from(&mut empty, false), Err(Errno::EAGAIN));

    network.close().await.expect("close network adapter");
    services.close().await.expect("join provider services");
}

#[tokio::test(flavor = "multi_thread")]
async fn close_joins_pending_connect_and_dns_and_rejects_new_work() {
    let connect_gate = Gate::new();
    let resolve_gate = Gate::new();
    let peer = "198.51.100.45:9443".parse().unwrap();
    let (local_socket, _remote_socket) = TestTcp::pair("192.0.2.9:40123".parse().unwrap(), peer);
    let mut provider = FakeProvider::new();
    provider.tcp = Mutex::new(Some(local_socket));
    provider.connect_gate = Some(connect_gate.clone());
    provider.resolve_gate = Some(resolve_gate.clone());
    let provider = Arc::new(provider);
    let (network, services) = services_network(provider.clone());

    let stream = network
        .connect(peer, WaitQueue::default())
        .expect("start pending TCP connect");
    let (done_send, done_recv) = tokio::sync::oneshot::channel();
    let done: LookupDone = Box::new(move |result| {
        let _ = done_send.send(result);
    });
    network.lookup(Lookup::Name("custom.invalid".into()), done);
    connect_gate.wait_started().await;
    resolve_gate.wait_started().await;

    let closing_network = network.clone();
    let mut close = tokio::spawn(async move { closing_network.close().await });
    wait_until(|| network.group.closed()).await;
    assert!(
        matches!(
            network.connect(peer, WaitQueue::default()),
            Err(Errno::ENETDOWN)
        ),
        "close must reject new connections"
    );

    let (addr_send, addr_recv) = tokio::sync::oneshot::channel();
    network.lookup(
        Lookup::Addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55))),
        Box::new(move |result| {
            let _ = addr_send.send(result);
        }),
    );
    assert_eq!(addr_recv.await.unwrap(), Err(LookupError::Failed));

    tokio::time::timeout(WAIT, &mut close)
        .await
        .expect("close cancels and joins pending provider operations")
        .expect("close task did not panic")
        .expect("network close succeeds");
    assert_eq!(done_recv.await.unwrap(), Err(LookupError::Failed));
    assert_eq!(connect_gate.canceled.load(Ordering::SeqCst), 1);
    assert_eq!(resolve_gate.canceled.load(Ordering::SeqCst), 1);
    assert_eq!(
        *provider.tcp_calls.lock().unwrap(),
        vec![("0.0.0.0:0".parse().unwrap(), peer)]
    );
    assert_eq!(
        *provider.resolve_calls.lock().unwrap(),
        vec![("custom.invalid".into(), None, None)]
    );
    assert_eq!(stream.read(&mut [0; 1], false), Err(Errno::ENOTCONN));
    services.close().await.expect("join provider services");
}

#[tokio::test(flavor = "multi_thread")]
async fn name_lookup_returns_only_the_custom_provider_answer() {
    let answer = vec![
        "192.0.2.55".parse().unwrap(),
        "2001:db8::55".parse().unwrap(),
    ];
    let mut provider = FakeProvider::new();
    provider.dns_answer = answer.clone();
    let provider = Arc::new(provider);
    let (network, services) = services_network(provider.clone());

    let (done_send, done_recv) = tokio::sync::oneshot::channel();
    network.lookup(
        Lookup::Name("custom.invalid".into()),
        Box::new(move |result| {
            let _ = done_send.send(result);
        }),
    );
    assert_eq!(
        tokio::time::timeout(WAIT, done_recv)
            .await
            .expect("provider DNS lookup completes")
            .unwrap()
            .unwrap(),
        Found {
            answer: Answer::Addrs {
                canonical: "custom.invalid".into(),
                addrs: answer,
            },
            ttl: 0,
        }
    );

    let (addr_send, addr_recv) = tokio::sync::oneshot::channel();
    network.lookup(
        Lookup::Addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55))),
        Box::new(move |result| {
            let _ = addr_send.send(result);
        }),
    );
    assert_eq!(addr_recv.await.unwrap(), Err(LookupError::Failed));
    assert_eq!(
        *provider.resolve_calls.lock().unwrap(),
        vec![("custom.invalid".into(), None, None)],
        "unsupported lookup forms must not fall back to host resolution"
    );

    network.close().await.expect("close network adapter");
    services.close().await.expect("join provider services");
}

#[derive(Debug)]
struct FakeListener {
    addr: SocketAddr,
    handler_set: Arc<AtomicBool>,
    removed: Arc<AtomicUsize>,
}

impl Pollable for FakeListener {
    fn poll(&self, _: Option<&mut PollTable<'_>>) -> PollMask {
        self.handler_set.store(true, Ordering::SeqCst);
        PollMask::empty()
    }
}
#[async_trait::async_trait]
impl TcpListener for FakeListener {
    fn try_accept(&self, _: WaitQueue) -> NetResult<(Arc<dyn TcpStream>, SocketAddr)> {
        Err(Errno::EAGAIN)
    }
    fn local_addr(&self) -> NetResult<SocketAddr> {
        Ok(self.addr)
    }
    fn set_backlog(&self, _: u32) -> NetResult<()> {
        Ok(())
    }
    fn set_socket_option(&self, _: i32, _: i32, _: &[u8]) -> NetResult<()> {
        Err(Errno::EOPNOTSUPP)
    }
    async fn close(&self, _mode: NetworkCloseMode) -> NetResult<()> {
        self.removed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct ReadySink;

impl InboundSink for ReadySink {
    fn poll_room(&self, _: Option<&mut PollTable<'_>>) -> Room {
        Room::Ready
    }

    fn incoming(&self, _: Arc<dyn BackendStream>, _: WaitQueue) -> bool {
        false
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn publication_drop_cancels_listener_and_close_joins_its_lease() {
    let host = "203.0.113.70:45678".parse().unwrap();
    let handler_set = Arc::new(AtomicBool::new(false));
    let removed = Arc::new(AtomicUsize::new(0));
    let provider = Arc::new(FakeProvider::new());
    *provider.listener.lock().unwrap() = Some(Arc::new(FakeListener {
        addr: host,
        handler_set: handler_set.clone(),
        removed: removed.clone(),
    }));
    let (network, services) = services_network(provider.clone());

    let publication = network
        .publish(host, 17, Arc::new(ReadySink))
        .expect("publish through custom provider");
    assert_eq!(publication.host_addr(), host);
    wait_until(|| handler_set.load(Ordering::SeqCst)).await;
    assert_eq!(
        *provider.listen_calls.lock().unwrap(),
        vec![(host, false, false, false)]
    );

    drop(publication);
    tokio::time::timeout(WAIT, network.close())
        .await
        .expect("close joins canceled listener")
        .expect("network close succeeds");
    assert_eq!(removed.load(Ordering::SeqCst), 1);
    services.close().await.expect("join provider services");
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_endpoint_preserves_fresh_defaults_failed_revision_and_same_bound_source_fence() {
    use wasixv2_vnet::endpoint::{
        EndpointBindPurpose, EndpointBindRequest, EndpointChoice, EndpointGroupId, EndpointKind,
        EndpointQuery, EndpointSource, EndpointSourceId, UdpTxConfig,
    };
    let local: SocketAddr = "192.0.2.7:49000".parse().unwrap();
    let peer: SocketAddr = "203.0.113.9:5300".parse().unwrap();
    let other: SocketAddr = "203.0.113.10:5300".parse().unwrap();
    let socket = Arc::new(FakeUdp::new(local, Arc::new(Mutex::default())));
    let provider = Arc::new(FakeProvider::new());
    *provider.udp.lock().unwrap() = Some(socket.clone());
    let (network, services) = services_network(provider.clone());
    let endpoints = network.endpoint_namespace().unwrap();
    let queue = WaitQueue::new();
    let first = EndpointSourceId(10);
    let bound = endpoints
        .bind(
            EndpointBindRequest {
                source_id: first,
                kind: EndpointKind::Datagram,
                requested: "0.0.0.0:0".parse().unwrap(),
                explicit: true,
                purpose: EndpointBindPurpose::Bind,
                domain: wasixv2_vnet::Domain::Inet,
                v6only: false,
                reuse_addr: false,
                reuse_port: false,
            },
            queue.clone(),
        )
        .unwrap()
        .unwrap();
    wait_until(|| bound.local_addr() == Ok(local)).await;
    let source = |id| EndpointSource {
        id,
        group_id: EndpointGroupId(1),
        bound: local,
        domain: wasixv2_vnet::Domain::Inet,
        requested_bind: Some("0.0.0.0:0".parse().unwrap()),
        binding: Some(bound.clone()),
    };
    let config = |source_id, revision, peer, recv_v4_errors| UdpTxConfig {
        source_id,
        revision,
        peer,
        recv_v4_errors,
        recv_v6_errors: false,
    };
    let query = EndpointQuery {
        kind: EndpointKind::Datagram,
        source_id: first,
        bound: Some(local),
        requested_bind: Some("0.0.0.0:0".parse().unwrap()),
        binding: Some(bound.clone()),
        effective_source: Some(local),
        destination: peer,
        local_binding: false,
    };
    let EndpointChoice::Provider(target) = endpoints.select(&query).unwrap() else {
        panic!("configured provider selected");
    };
    assert_eq!(bound.connect_datagram(first, Some(peer)), Some(Ok(())));
    let tx = endpoints
        .datagram(source(first), config(first, 1, None, false), queue.clone())
        .unwrap();
    assert_eq!(
        socket.peer_addr(),
        Ok(Some(peer)),
        "TX configuration metadata must not reconnect/disconnect the core-owned association"
    );
    // This provider rejects every option callback: untouched false defaults must not call it.
    assert_eq!(tx.send_to(1, &target, local, peer, b"one"), Ok(3));
    tx.configure(config(first, 2, Some(peer), true));
    assert_eq!(tx.take_error(), Some(Errno::EOPNOTSUPP));
    assert_eq!(
        tx.send_to(2, &target, local, peer, b"two"),
        Err(Errno::EAGAIN)
    );
    assert_eq!(
        tx.send_to(1, &target, local, peer, b"old"),
        Err(Errno::EAGAIN),
        "failed newer configuration invalidates the previously applied revision"
    );
    tx.configure(config(first, 1, None, false));
    assert_eq!(
        socket.peer_addr(),
        Ok(Some(peer)),
        "an older desired revision cannot replay physical state after a newer failure"
    );
    let second = EndpointSourceId(11);
    assert_eq!(bound.connect_datagram(second, Some(other)), Some(Ok(())));
    tx.configure(config(first, 3, Some(peer), false));
    assert_eq!(
        socket.peer_addr(),
        Ok(Some(other)),
        "a retained old TX must not mutate the same bound socket after source renewal"
    );
    assert_eq!(
        tx.send_to(3, &target, local, peer, b"stale"),
        Err(Errno::ECANCELED)
    );
    assert!(
        matches!(
            endpoints.datagram(source(first), config(first, 4, None, false), queue),
            Err(Errno::ECANCELED)
        ),
        "TX construction cannot reauthorize an old captured source"
    );
    network.close().await.unwrap();
    services.close().await.unwrap();
    assert!(socket.closed.load(Ordering::SeqCst));
}

// Empty controlled driver: unlike the pull-only FakeUdp this owns one push registration.
// Callbacks are intentionally synchronous at installation, as custom providers may be.
struct PushUdp {
    socket: FakeUdp,
    receiver: Mutex<Option<Arc<dyn DatagramReceiver>>>,
    lease: Arc<PushReceiveLease>,
    before_ready: Mutex<Option<wasixv2_vnet::endpoint::DatagramDelivery>>,
}
impl std::fmt::Debug for PushUdp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushUdp").finish_non_exhaustive()
    }
}
impl Pollable for PushUdp {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.socket.poll(table)
    }
}
impl BackendDatagram for PushUdp {
    fn send_to(&self, bytes: &[u8], peer: SocketAddr) -> NetResult<usize> {
        self.socket.send_to(bytes, peer)
    }
    fn connect(&self, peer: Option<SocketAddr>) -> NetResult<()> {
        self.socket.connect(peer)
    }
    fn take_error(&self) -> Option<Errno> {
        self.socket.take_error()
    }
    fn recv_from(&self, bytes: &mut [u8], peek: bool) -> NetResult<(usize, usize, SocketAddr)> {
        if self.receiver.lock().unwrap().is_some() {
            return Err(Errno::EBUSY);
        }
        self.socket.recv_from(bytes, peek)
    }
    fn input_len(&self) -> usize {
        self.socket.input_len()
    }
    fn attach(&self, queue: Option<WaitQueue>) -> NetResult<()> {
        self.socket.attach(queue)
    }
}
#[async_trait::async_trait]
impl UdpSocket for PushUdp {
    fn install_receiver(
        &self,
        receiver: Arc<dyn DatagramReceiver>,
    ) -> NetResult<Arc<dyn DatagramReceiveLease>> {
        {
            let mut current = self.receiver.lock().unwrap();
            if current.is_some() {
                return Err(Errno::EBUSY);
            }
            *current = Some(receiver.clone());
        }
        let info = DatagramInfo {
            source: "203.0.113.9:5300".parse().unwrap(),
            destination: self.socket.addr,
            interface: 0,
        };
        *self.before_ready.lock().unwrap() = Some(receiver.received(info, b"before-ready"));
        receiver.ready();
        Ok(self.lease.clone())
    }
    fn peer_addr(&self) -> NetResult<Option<SocketAddr>> {
        UdpSocket::peer_addr(&self.socket)
    }
    fn recv_packet(&self, bytes: &mut [u8], peek: bool) -> NetResult<ReceivedDatagram> {
        if self.receiver.lock().unwrap().is_some() {
            return Err(Errno::EBUSY);
        }
        self.socket.recv_packet(bytes, peek)
    }
    fn local_addr(&self) -> NetResult<SocketAddr> {
        self.socket.local_addr()
    }
    fn set_socket_option(&self, level: i32, name: i32, value: &[u8]) -> NetResult<()> {
        self.socket.set_socket_option(level, name, value)
    }
    async fn close(&self, mode: NetworkCloseMode) -> NetResult<()> {
        self.socket.close(mode).await
    }
}
#[derive(Default)]
struct PushReceiveLease {
    closing: AtomicBool,
    acknowledged: AtomicBool,
    changed: Notify,
}
#[async_trait::async_trait]
impl DatagramReceiveLease for PushReceiveLease {
    async fn wait_ready(&self) -> NetResult<()> {
        Ok(())
    }
    async fn close(&self) -> NetResult<()> {
        self.closing.store(true, Ordering::SeqCst);
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.acknowledged.load(Ordering::SeqCst) {
                return Ok(());
            }
            changed.await;
        }
    }
}
impl Drop for PushReceiveLease {
    fn drop(&mut self) {
        self.closing.store(true, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_endpoint_push_registration_fences_callbacks_and_joins_withdrawal() {
    use wasixv2_abi::MsgFlags;
    use wasixv2_vnet::endpoint::{DatagramDelivery, PublicationState};
    use wasixv2_vnet::{Domain, Net, NetConfig, Network, SocketKind};

    let services = crate::service::Services::new().unwrap();
    let provider = Arc::new(FakeProvider::new());
    let local = "127.0.0.1:43138".parse().unwrap();
    let push = Arc::new(PushUdp {
        socket: FakeUdp::new(local, Arc::default()),
        receiver: Mutex::default(),
        lease: Arc::default(),
        before_ready: Mutex::default(),
    });
    *provider.udp.lock().unwrap() = Some(push.clone());
    let network = ProviderNetwork::new(provider.clone(), services.clone());
    let net = Net::new(NetConfig::default(), Some(network.clone()));
    let socket = net
        .socket(Domain::Inet, SocketKind::Datagram, 0, 1)
        .unwrap();
    let admission = socket.bind_admission(local, false).unwrap().unwrap();
    tokio::time::timeout(WAIT, async {
        loop {
            match admission.complete() {
                Ok(()) => break,
                Err(Errno::EAGAIN) => tokio::task::yield_now().await,
                Err(error) => panic!("canonical bind failed: {error:?}"),
            }
        }
    })
    .await
    .unwrap();
    drop(admission);
    wait_until(|| {
        net.endpoint_publications()
            .iter()
            .any(|status| status.state == PublicationState::Ready)
    })
    .await;
    assert_eq!(
        *push.before_ready.lock().unwrap(),
        Some(DatagramDelivery::Dropped)
    );
    assert_eq!(push.recv_packet(&mut [0; 1], false), Err(Errno::EBUSY));
    let receiver = push.receiver.lock().unwrap().as_ref().unwrap().clone();
    let info = DatagramInfo {
        source: "203.0.113.9:5300".parse().unwrap(),
        destination: local,
        interface: 0,
    };
    assert_eq!(
        receiver.received(info, b"ready-member"),
        DatagramDelivery::Queued
    );
    let mut bytes = [0; 32];
    let message = socket.recv(&mut bytes, MsgFlags::empty()).unwrap();
    assert_eq!(&bytes[..message.len], b"ready-member");
    assert_eq!(message.from, Some(info.source));
    assert_eq!(
        socket.recv(&mut bytes, MsgFlags::empty()),
        Err(Errno::EAGAIN)
    );
    assert_eq!(provider.udp_calls.lock().unwrap().len(), 1);

    drop(socket);
    wait_until(|| push.lease.closing.load(Ordering::SeqCst)).await;
    assert!(net.endpoint_publications().is_empty());
    receiver.ready();
    receiver.failed(Errno::EIO);
    assert_eq!(receiver.received(info, b"late"), DatagramDelivery::Retired);
    assert!(net.endpoint_publications().is_empty());
    let closing = tokio::spawn({
        let network = network.clone();
        async move { network.close().await }
    });
    wait_until(|| network.group.closed()).await;
    assert!(
        !closing.is_finished(),
        "Group close must retain the accepted receive lease until its withdrawal ACK"
    );
    push.lease.acknowledged.store(true, Ordering::SeqCst);
    push.lease.changed.notify_waiters();
    tokio::time::timeout(WAIT, closing)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    services.close().await.unwrap();
}
