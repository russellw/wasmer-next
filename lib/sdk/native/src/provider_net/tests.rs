use super::ProviderNetwork;
use std::{
    collections::VecDeque,
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown as TcpShutdown, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::Notify;
use virtual_net::tcp_pair::TcpSocketHalf;
use virtual_net::{
    DynVirtualNetworking, InterestHandler, NetworkError, Result as NetResult, SocketStatus,
    VirtualConnectedSocket, VirtualConnectionlessSocket, VirtualIoSource, VirtualNetworking,
    VirtualSocket, VirtualTcpListener, VirtualTcpSocket, VirtualUdpSocket,
};
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

struct FakeProvider {
    tcp: Mutex<Option<Box<dyn VirtualTcpSocket + Sync>>>,
    udp: Mutex<Option<Box<dyn VirtualUdpSocket + Sync>>>,
    listener: Mutex<Option<Box<dyn VirtualTcpListener + Sync>>>,
    connect_gate: Option<Gate>,
    resolve_gate: Option<Gate>,
    dns_answer: Vec<IpAddr>,
    tcp_calls: Mutex<Vec<(SocketAddr, SocketAddr)>>,
    udp_calls: Mutex<Vec<(SocketAddr, bool, bool)>>,
    listen_calls: Mutex<Vec<(SocketAddr, bool, bool, bool)>>,
    resolve_calls: Mutex<Vec<(String, Option<u16>, Option<IpAddr>)>>,
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
impl VirtualNetworking for FakeProvider {
    async fn connect_tcp(
        &self,
        addr: SocketAddr,
        peer: SocketAddr,
    ) -> NetResult<Box<dyn VirtualTcpSocket + Sync>> {
        self.tcp_calls.lock().unwrap().push((addr, peer));
        if let Some(gate) = &self.connect_gate {
            gate.stop().await;
        }
        self.tcp
            .lock()
            .unwrap()
            .take()
            .ok_or(NetworkError::ConnectionRefused)
    }

    async fn bind_udp(
        &self,
        addr: SocketAddr,
        reuse_port: bool,
        reuse_addr: bool,
    ) -> NetResult<Box<dyn VirtualUdpSocket + Sync>> {
        self.udp_calls
            .lock()
            .unwrap()
            .push((addr, reuse_port, reuse_addr));
        self.udp
            .lock()
            .unwrap()
            .take()
            .ok_or(NetworkError::AddressNotAvailable)
    }

    async fn listen_tcp(
        &self,
        addr: SocketAddr,
        only_v6: bool,
        reuse_port: bool,
        reuse_addr: bool,
    ) -> NetResult<Box<dyn VirtualTcpListener + Sync>> {
        self.listen_calls
            .lock()
            .unwrap()
            .push((addr, only_v6, reuse_port, reuse_addr));
        self.listener
            .lock()
            .unwrap()
            .take()
            .ok_or(NetworkError::AddressNotAvailable)
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
    let provider: DynVirtualNetworking = provider;
    (ProviderNetwork::new(provider, services.clone()), services)
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_provider_keeps_custom_peer_peek_and_remote_half_close() {
    let peer = "198.51.100.24:8443".parse().unwrap();
    let (local_socket, mut remote_socket) =
        TcpSocketHalf::channel(64, "192.0.2.7:40123".parse().unwrap(), peer);
    let provider = Arc::new(FakeProvider::new());
    *provider.tcp.lock().unwrap() = Some(Box::new(local_socket));
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

    assert_eq!(remote_socket.try_send(b"hello").unwrap(), 5);
    remote_socket.shutdown(TcpShutdown::Write).unwrap();

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
    broadcast: bool,
    loop_v4: bool,
    loop_v6: bool,
    multicast_ttl_v4: u32,
    ttl: u32,
}

impl FakeUdp {
    fn new(addr: SocketAddr, packets: Arc<Mutex<VecDeque<Packet>>>) -> Self {
        Self {
            addr,
            packets,
            broadcast: false,
            loop_v4: false,
            loop_v6: false,
            multicast_ttl_v4: 1,
            ttl: 64,
        }
    }
}

impl VirtualIoSource for FakeUdp {
    fn remove_handler(&mut self) {}

    fn poll_read_ready(&mut self, _: &mut Context<'_>) -> Poll<NetResult<usize>> {
        match self.packets.lock().unwrap().front() {
            Some(packet) => Poll::Ready(Ok(packet.bytes.len())),
            None => Poll::Pending,
        }
    }

    fn poll_write_ready(&mut self, _: &mut Context<'_>) -> Poll<NetResult<usize>> {
        Poll::Ready(Ok(usize::MAX))
    }
}

impl VirtualSocket for FakeUdp {
    fn set_ttl(&mut self, ttl: u32) -> NetResult<()> {
        self.ttl = ttl;
        Ok(())
    }

    fn ttl(&self) -> NetResult<u32> {
        Ok(self.ttl)
    }

    fn addr_local(&self) -> NetResult<SocketAddr> {
        Ok(self.addr)
    }

    fn status(&self) -> NetResult<SocketStatus> {
        Ok(SocketStatus::Opened)
    }

    fn set_handler(&mut self, _: Box<dyn InterestHandler + Send + Sync>) -> NetResult<()> {
        Ok(())
    }
}

impl VirtualConnectionlessSocket for FakeUdp {
    fn try_send_to(&mut self, data: &[u8], _: SocketAddr) -> NetResult<usize> {
        Ok(data.len())
    }

    fn try_recv_from(
        &mut self,
        buf: &mut [MaybeUninit<u8>],
        peek: bool,
    ) -> NetResult<(usize, SocketAddr)> {
        let mut packets = self.packets.lock().unwrap();
        let packet = packets.front().cloned().ok_or(NetworkError::WouldBlock)?;
        for (slot, byte) in buf.iter_mut().zip(packet.bytes.iter()) {
            slot.write(*byte);
        }
        if !peek {
            packets.pop_front();
        }
        Ok((packet.bytes.len(), packet.from))
    }
}

impl VirtualUdpSocket for FakeUdp {
    fn set_broadcast(&mut self, broadcast: bool) -> NetResult<()> {
        self.broadcast = broadcast;
        Ok(())
    }

    fn broadcast(&self) -> NetResult<bool> {
        Ok(self.broadcast)
    }

    fn set_multicast_loop_v4(&mut self, val: bool) -> NetResult<()> {
        self.loop_v4 = val;
        Ok(())
    }

    fn multicast_loop_v4(&self) -> NetResult<bool> {
        Ok(self.loop_v4)
    }

    fn set_multicast_loop_v6(&mut self, val: bool) -> NetResult<()> {
        self.loop_v6 = val;
        Ok(())
    }

    fn multicast_loop_v6(&self) -> NetResult<bool> {
        Ok(self.loop_v6)
    }

    fn set_multicast_ttl_v4(&mut self, ttl: u32) -> NetResult<()> {
        self.multicast_ttl_v4 = ttl;
        Ok(())
    }

    fn multicast_ttl_v4(&self) -> NetResult<u32> {
        Ok(self.multicast_ttl_v4)
    }

    fn join_multicast_v4(&mut self, _: Ipv4Addr, _: Ipv4Addr) -> NetResult<()> {
        Ok(())
    }

    fn leave_multicast_v4(&mut self, _: Ipv4Addr, _: Ipv4Addr) -> NetResult<()> {
        Ok(())
    }

    fn join_multicast_v6(&mut self, _: Ipv6Addr, _: u32) -> NetResult<()> {
        Ok(())
    }

    fn leave_multicast_v6(&mut self, _: Ipv6Addr, _: u32) -> NetResult<()> {
        Ok(())
    }

    fn addr_peer(&self) -> NetResult<Option<SocketAddr>> {
        Ok(None)
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
    *provider.udp.lock().unwrap() = Some(Box::new(FakeUdp::new(
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
    let (local_socket, _remote_socket) =
        TcpSocketHalf::channel(64, "192.0.2.9:40123".parse().unwrap(), peer);
    let mut provider = FakeProvider::new();
    provider.tcp = Mutex::new(Some(Box::new(local_socket)));
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

impl VirtualIoSource for FakeListener {
    fn remove_handler(&mut self) {
        self.removed.fetch_add(1, Ordering::SeqCst);
    }

    fn poll_read_ready(&mut self, _: &mut Context<'_>) -> Poll<NetResult<usize>> {
        Poll::Pending
    }

    fn poll_write_ready(&mut self, _: &mut Context<'_>) -> Poll<NetResult<usize>> {
        Poll::Ready(Ok(0))
    }
}

impl VirtualTcpListener for FakeListener {
    fn try_accept(&mut self) -> NetResult<(Box<dyn VirtualTcpSocket + Sync>, SocketAddr)> {
        Err(NetworkError::WouldBlock)
    }

    fn set_handler(&mut self, _: Box<dyn InterestHandler + Send + Sync>) -> NetResult<()> {
        self.handler_set.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn addr_local(&self) -> NetResult<SocketAddr> {
        Ok(self.addr)
    }

    fn set_ttl(&mut self, _: u8) -> NetResult<()> {
        Ok(())
    }

    fn ttl(&self) -> NetResult<u8> {
        Ok(64)
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
    *provider.listener.lock().unwrap() = Some(Box::new(FakeListener {
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
