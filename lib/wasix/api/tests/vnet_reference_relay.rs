//! Actual v1 reference relay over bounded framed channels, with real loopback sockets.
//! Websocket ownership/framing belongs to the worker-local transport and is not exercised here.
#![cfg(unix)]
use std::{
    future::Future,
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, UdpSocket},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::mpsc;
use virtual_net::{
    RemoteNetworkingServer, RemoteNetworkingServerDriver,
    host::LocalNetworking,
    meta::{MessageRequest, MessageResponse},
};
use wasixv2_abi::Errno;
use wasixv2_vnet::{Answer, Backend, Domain, Lookup, Shutdown, StreamState};
use wasixv2_vnet_web::{
    Capabilities, Classic, Config, Driver, FrameTransport, Transport, WebBackend,
};
use wasixv2_wait::WaitQueue;

struct ReferenceRelay {
    tx: Option<mpsc::Sender<MessageRequest>>,
    rx: mpsc::Receiver<MessageResponse>,
    driver: Pin<Box<RemoteNetworkingServerDriver>>,
    _reference: RemoteNetworkingServer,
}
impl ReferenceRelay {
    fn new() -> Self {
        Self::with_provider(Arc::new(LocalNetworking::new()))
    }
    fn with_provider(provider: Arc<dyn virtual_net::VirtualNetworking>) -> Self {
        let (tx, requests) = mpsc::channel(8);
        let (responses, rx) = mpsc::channel(8);
        let (reference, driver) =
            RemoteNetworkingServer::new_from_mpsc(responses, requests, provider);
        Self {
            tx: Some(tx),
            rx,
            driver: Box::pin(driver),
            _reference: reference,
        }
    }
}
impl FrameTransport for ReferenceRelay {
    fn poll_send(&mut self, cx: &mut Context<'_>, frame: &[u8]) -> Poll<Result<(), Errno>> {
        if self.driver.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(Errno::ECONNABORTED));
        }
        let (message, used) =
            bincode::serde::decode_from_slice(frame, bincode::config::legacy()).unwrap();
        assert_eq!(used, frame.len());
        match self.tx.as_ref().unwrap().try_send(message) {
            Ok(()) => {
                cx.waker().wake_by_ref();
                Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => Poll::Pending,
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(Errno::ECONNABORTED)),
        }
    }
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Vec<u8>, Errno>> {
        let _ = self.driver.as_mut().poll(cx);
        self.rx.poll_recv(cx).map(|message| {
            message
                .map(|message| {
                    bincode::serde::encode_to_vec(message, bincode::config::legacy()).unwrap()
                })
                .ok_or(Errno::ECONNABORTED)
        })
    }
    fn poll_closed(&mut self, cx: &mut Context<'_>) -> Poll<Errno> {
        if self.driver.as_mut().poll(cx).is_ready() {
            Poll::Ready(Errno::ECONNABORTED)
        } else {
            Poll::Pending
        }
    }
    fn close(&mut self) {
        self.tx.take();
        self.rx.close();
    }
}
async fn drive_until(
    stage: &str,
    driver: &mut Driver,
    relay: &mut dyn Transport,
    mut ready: impl FnMut() -> bool,
) {
    tokio::time::timeout(
        Duration::from_secs(5),
        futures_util::future::poll_fn(|cx| {
            assert!(driver.poll(cx, relay).is_pending(), "relay driver failed");
            if ready() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .unwrap_or_else(|_| panic!("local relay timed out: {stage}"));
}

fn exercise(ip: IpAddr) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let capabilities = Capabilities::classic(ip.is_ipv6());
        let (backend, mut driver) = WebBackend::new(Config::default(), capabilities).unwrap();
        let mut relay = Classic::new(ReferenceRelay::new(), capabilities);
        let listener = TcpListener::bind(SocketAddr::new(ip, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let (finished, finish) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut data = [0; 12];
            peer.read_exact(&mut data).unwrap();
            peer.write_all(&data).unwrap();
            let mut rest = Vec::new();
            peer.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty());
            finished.send(()).unwrap();
        });
        let stream = backend.connect(address, WaitQueue::new()).unwrap();
        drive_until("connect", &mut driver, &mut relay, || stream.state() != StreamState::Connecting).await;
        assert_eq!(stream.state(), StreamState::Established);
        assert_eq!(stream.take_error(), None);
        assert_eq!(stream.write(b"hello relay!"), Ok(12));
        let mut received = Vec::new();
        drive_until("echo", &mut driver, &mut relay, || {
            let mut data = [0; 16];
            if let Ok(n) = stream.read(&mut data, false) { received.extend_from_slice(&data[..n]); }
            received.len() == 12
        }).await;
        assert_eq!(received, b"hello relay!");
        stream.shutdown(Shutdown::Write).unwrap();
        // Stock relay omits EOF events. Assert local FIN reaches the peer without claiming
        // the stock server can report a remote half-close (model tests cover that event).
        drive_until("shutdown", &mut driver, &mut relay, || finish.try_recv().is_ok()).await;
        server.join().unwrap();

        let udp = UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let address = udp.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut data = [0; 16];
            let (n, sender) = udp.recv_from(&mut data).unwrap();
            udp.send_to(&data[..n], sender).unwrap();
        });
        let domain = if ip.is_ipv4() { Domain::Inet } else { Domain::Inet6 };
        let datagram = backend.datagram(domain, WaitQueue::new()).unwrap();
        let mut submitted = false;
        let mut reply = None;
        drive_until("udp", &mut driver, &mut relay, || {
            if !submitted {
                match datagram.send_to(b"packet", address) {
                    Ok(6) => submitted = true,
                    Err(Errno::EAGAIN) => {},
                    other => panic!("unexpected send: {other:?}"),
                }
            }
            let mut data = [0; 3];
            if let Ok((n, full, from)) = datagram.recv_from(&mut data, false) { reply = Some((data, n, full, from)); }
            reply.is_some()
        }).await;
        assert_eq!(reply, Some((*b"pac", 3, 6, address)));
        server.join().unwrap();

        let found = Arc::new(Mutex::new(None));
        let output = found.clone();
        backend.lookup(Lookup::Name("localhost".into()), Box::new(move |result| *output.lock().unwrap() = Some(result)));
        drive_until("dns", &mut driver, &mut relay, || found.lock().unwrap().is_some()).await;
        let found = found.lock().unwrap().take().unwrap().unwrap();
        assert!(matches!(found.answer, Answer::Addrs { addrs, .. } if addrs.iter().any(|ip| ip.is_loopback())));
    });
}
#[test]
fn reference_relay_tcp_udp_dns_ipv4() {
    exercise("127.0.0.1".parse().unwrap());
}
#[test]
fn reference_relay_tcp_udp_dns_ipv6() {
    exercise("::1".parse().unwrap());
}

#[derive(Default)]
struct Ingress(Mutex<Vec<Arc<dyn wasixv2_vnet::BackendStream>>>);
impl wasixv2_vnet::InboundSink for Ingress {
    fn poll_room(&self, _: Option<&mut wasixv2_wait::PollTable<'_>>) -> wasixv2_vnet::Room {
        wasixv2_vnet::Room::Ready
    }
    fn incoming(&self, stream: Arc<dyn wasixv2_vnet::BackendStream>, _: WaitQueue) -> bool {
        self.0.lock().unwrap().push(stream);
        true
    }
}
fn ephemeral_publications(ip: IpAddr) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (backend, mut driver) =
                WebBackend::new(Config::default(), Capabilities::classic_fidelity(true)).unwrap();
            let mut relay =
                Classic::new(ReferenceRelay::new(), Capabilities::classic_fidelity(true));
            let sink = Arc::new(Ingress::default());
            let mut bind =
                Box::pin(backend.publish_resolved(SocketAddr::new(ip, 0), 4, sink.clone()));
            let publication = tokio::time::timeout(
                Duration::from_secs(5),
                futures_util::future::poll_fn(|cx| {
                    assert!(driver.poll(cx, &mut relay).is_pending());
                    bind.as_mut().poll(cx)
                }),
            )
            .await
            .unwrap()
            .unwrap();
            drop(bind);
            let host = publication.host_addr();
            assert_eq!(host.ip(), ip);
            assert_ne!(host.port(), 0);
            let mut client = std::net::TcpStream::connect(host).unwrap();
            client.write_all(b"ingress").unwrap();
            drive_until("ephemeral TCP ingress", &mut driver, &mut relay, || {
                !sink.0.lock().unwrap().is_empty()
            })
            .await;
            let stream = sink.0.lock().unwrap().pop().unwrap();
            let mut bytes = Vec::new();
            drive_until("ephemeral TCP bytes", &mut driver, &mut relay, || {
                let mut buf = [0; 16];
                if let Ok(n) = stream.read(&mut buf, false) {
                    bytes.extend_from_slice(&buf[..n]);
                }
                bytes.len() == 7
            })
            .await;
            assert_eq!(bytes, b"ingress");
            drop(stream);
            drop(client);
            drop(publication);

            let mut bind = Box::pin(backend.publish_datagram_resolved(SocketAddr::new(ip, 0)));
            let (endpoint, publication) = tokio::time::timeout(
                Duration::from_secs(5),
                futures_util::future::poll_fn(|cx| {
                    assert!(driver.poll(cx, &mut relay).is_pending());
                    bind.as_mut().poll(cx)
                }),
            )
            .await
            .unwrap()
            .unwrap();
            drop(bind);
            let host = publication.host_addr();
            assert_eq!(host.ip(), ip);
            assert_ne!(host.port(), 0);
            endpoint.attach(Some(WaitQueue::new())).unwrap();
            let client = UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
            client.set_nonblocking(true).unwrap();
            client.send_to(b"udp", host).unwrap();
            let mut received = None;
            drive_until("ephemeral UDP ingress", &mut driver, &mut relay, || {
                let mut buf = [0; 8];
                if let Ok((n, _, peer)) = endpoint.recv_from(&mut buf, false) {
                    received = Some((buf[..n].to_vec(), peer));
                }
                received.is_some()
            })
            .await;
            let (bytes, peer) = received.unwrap();
            assert_eq!(bytes, b"udp");
            assert_eq!(endpoint.send_to(b"reply", peer), Ok(5));
            let mut received = None;
            drive_until(
                "ephemeral UDP reply source",
                &mut driver,
                &mut relay,
                || {
                    let mut buf = [0; 8];
                    if let Ok((n, peer)) = client.recv_from(&mut buf) {
                        received = Some((buf[..n].to_vec(), peer));
                    }
                    received.is_some()
                },
            )
            .await;
            assert_eq!(received, Some((b"reply".to_vec(), host)));
        });
}
#[test]
fn stock_relay_ephemeral_tcp_udp_publication_ipv4() {
    ephemeral_publications("127.0.0.1".parse().unwrap());
}
#[test]
fn stock_relay_ephemeral_tcp_udp_publication_ipv6() {
    ephemeral_publications("::1".parse().unwrap());
}

/// Same original server and wire producer as the socket relay tests, with a configured
/// provider that makes bridge admission and exact route values observable.
#[derive(Debug)]
struct ConfiguredReference {
    sockets: LocalNetworking,
    state: Mutex<ConfiguredState>,
    fail_readback: std::sync::atomic::AtomicBool,
    changing: std::sync::atomic::AtomicBool,
}
#[derive(Debug, Default)]
struct ConfiguredState {
    bridged: bool,
    addresses: Vec<virtual_net::IpCidr>,
    routes: Vec<virtual_net::IpRoute>,
    calls: Vec<&'static str>,
}
impl ConfiguredReference {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            sockets: LocalNetworking::new(),
            state: Mutex::new(ConfiguredState {
                addresses: vec![virtual_net::IpCidr {
                    ip: "10.0.2.15".parse().unwrap(),
                    prefix: 24,
                }],
                ..ConfiguredState::default()
            }),
            fail_readback: std::sync::atomic::AtomicBool::new(false),
            changing: std::sync::atomic::AtomicBool::new(false),
        })
    }
}
#[async_trait::async_trait]
impl virtual_net::VirtualNetworking for ConfiguredReference {
    async fn bridge(
        &self,
        network: &str,
        token: &str,
        security: virtual_net::StreamSecurity,
    ) -> virtual_net::Result<()> {
        assert_eq!(
            (network, token, security),
            (
                "tenant",
                "credential",
                virtual_net::StreamSecurity::DoubleEncryption
            )
        );
        assert!(
            !self
                .changing
                .swap(true, std::sync::atomic::Ordering::SeqCst)
        );
        tokio::task::yield_now().await;
        let mut state = self.state.lock().unwrap();
        state.bridged = true;
        state.calls.push("bridge");
        self.changing
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    async fn unbridge(&self) -> virtual_net::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.bridged = false;
        state.calls.push("unbridge");
        Ok(())
    }
    async fn dhcp_acquire(&self) -> virtual_net::Result<Vec<IpAddr>> {
        let mut state = self.state.lock().unwrap();
        state.calls.push("dhcp");
        state.addresses = vec![virtual_net::IpCidr {
            ip: "192.0.2.9".parse().unwrap(),
            prefix: 24,
        }];
        Ok(state.addresses.iter().map(|a| a.ip).collect())
    }
    async fn ip_add(&self, ip: IpAddr, prefix: u8) -> virtual_net::Result<()> {
        self.state
            .lock()
            .unwrap()
            .addresses
            .push(virtual_net::IpCidr { ip, prefix });
        Ok(())
    }
    async fn ip_remove(&self, ip: IpAddr) -> virtual_net::Result<()> {
        self.state.lock().unwrap().addresses.retain(|a| a.ip != ip);
        Ok(())
    }
    async fn ip_clear(&self) -> virtual_net::Result<()> {
        self.state.lock().unwrap().addresses.clear();
        Ok(())
    }
    async fn ip_list(&self) -> virtual_net::Result<Vec<virtual_net::IpCidr>> {
        assert!(
            !self.changing.load(std::sync::atomic::Ordering::SeqCst),
            "readback raced mutation ACK"
        );
        if self
            .fail_readback
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(virtual_net::NetworkError::IOError);
        }
        let mut state = self.state.lock().unwrap();
        state.calls.push("addresses");
        Ok(state.addresses.clone())
    }
    async fn mac(&self) -> virtual_net::Result<[u8; 6]> {
        Ok([2, 1, 2, 3, 4, 5])
    }
    async fn gateway_set(&self, ip: IpAddr) -> virtual_net::Result<()> {
        self.state
            .lock()
            .unwrap()
            .routes
            .push(virtual_net::IpRoute {
                cidr: virtual_net::IpCidr {
                    ip: if ip.is_ipv4() {
                        IpAddr::from([0, 0, 0, 0])
                    } else {
                        IpAddr::from([0u16; 8])
                    },
                    prefix: 0,
                },
                via_router: ip,
                preferred_until: None,
                expires_at: None,
            });
        Ok(())
    }
    async fn route_add(
        &self,
        cidr: virtual_net::IpCidr,
        via_router: IpAddr,
        preferred_until: Option<Duration>,
        expires_at: Option<Duration>,
    ) -> virtual_net::Result<()> {
        self.state
            .lock()
            .unwrap()
            .routes
            .push(virtual_net::IpRoute {
                cidr,
                via_router,
                preferred_until,
                expires_at,
            });
        Ok(())
    }
    async fn route_remove(&self, ip: IpAddr) -> virtual_net::Result<()> {
        self.state
            .lock()
            .unwrap()
            .routes
            .retain(|r| r.cidr.ip != ip);
        Ok(())
    }
    async fn route_clear(&self) -> virtual_net::Result<()> {
        self.state.lock().unwrap().routes.clear();
        Ok(())
    }
    async fn route_list(&self) -> virtual_net::Result<Vec<virtual_net::IpRoute>> {
        Ok(self.state.lock().unwrap().routes.clone())
    }
    async fn connect_tcp(
        &self,
        addr: SocketAddr,
        peer: SocketAddr,
    ) -> virtual_net::Result<Box<dyn virtual_net::VirtualTcpSocket + Sync>> {
        if !self.state.lock().unwrap().bridged {
            return Err(virtual_net::NetworkError::NotConnected);
        }
        self.sockets.connect_tcp(addr, peer).await
    }
}
async fn provider_call(
    net: &Arc<wasixv2_vnet::Net>,
    driver: &mut Driver,
    relay: &mut dyn Transport,
    operation: wasixv2_vnet::provider::Request,
) -> wasixv2_vnet::provider::Completion {
    use wasixv2_vnet::Network;
    let result = Arc::new(Mutex::new(None));
    let output = result.clone();
    net.provider().unwrap().start(
        operation,
        Box::new(move |done| *output.lock().unwrap() = Some(done)),
    );
    drive_until("provider control", driver, relay, || {
        result.lock().unwrap().is_some()
    })
    .await;
    result.lock().unwrap().take().unwrap()
}
#[test]
fn configured_classic_provider_controls_deadlines_reconciliation_and_same_transport() {
    use wasixv2_vnet::{
        Network,
        provider::{Cidr, Readback, Reply, Request, Route, Security},
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let reference=ConfiguredReference::new();
        let mut capabilities=Capabilities::classic(true);
        capabilities.provider=Some(Readback {addresses:true,mac:true,routes:true});
        let (backend,mut driver)=WebBackend::new(Config::default(),capabilities).unwrap();
        let net=wasixv2_vnet::Net::new(wasixv2_vnet::NetConfig::host_default(),Some(backend.clone()));
        let mut relay=Classic::new(ReferenceRelay::with_provider(reference.clone()),capabilities);
        let bridge=|| Request::Bridge {network:"tenant".into(),token:"credential".into(),security:Security::DoubleEncryption};
        assert_eq!(provider_call(&net,&mut driver,&mut relay,bridge()).await.result,Ok(Reply::None));
        assert_eq!(reference.state.lock().unwrap().calls[..2],["bridge","addresses"]);
        // Accepted control completion remains live even when the guest-facing waiter is gone.
        let (send,receive)=tokio::sync::oneshot::channel();
        net.provider().unwrap().start(Request::Dhcp,Box::new(move |done| {let _=send.send(done);}));
        drop(receive);
        drive_until("canceled DHCP publishes",&mut driver,&mut relay,|| net.interfaces().iter().flat_map(|i| &i.addresses).any(|a| a.addr=="192.0.2.9".parse::<IpAddr>().unwrap())).await;
        let route=Route {cidr:Cidr {ip:"0.0.0.0".parse().unwrap(),prefix:0},via_router:"192.0.2.1".parse().unwrap(),preferred_until:Some(0),expires_at:Some(u64::MAX)};
        assert_eq!(provider_call(&net,&mut driver,&mut relay,Request::AddRoute(route.clone())).await.result,Ok(Reply::None));
        assert_eq!(provider_call(&net,&mut driver,&mut relay,Request::Routes).await.result,Ok(Reply::Routes(vec![route])));
        { let state=reference.state.lock().unwrap(); let old=&state.routes[0];
        assert_eq!(old.preferred_until,Some(Duration::ZERO));assert_eq!(old.expires_at,Some(Duration::from_nanos(u64::MAX))); }
        // A postcommit getter failure is distinct from provider refusal and disables stale routing.
        reference.fail_readback.store(true,std::sync::atomic::Ordering::SeqCst);
        let result=provider_call(&net,&mut driver,&mut relay,Request::AddAddress(Cidr {ip:"192.0.2.10".parse().unwrap(),prefix:24})).await;
        assert_eq!(result.result,Err(Errno::EIO));assert_eq!(result.reconciliation,Some(Errno::EIO));
        assert!(net.interfaces().iter().filter(|i| i.name=="eth0").all(|i| i.flags&1==0));
        assert!(provider_call(&net,&mut driver,&mut relay,Request::Addresses).await.result.is_ok());
        assert!(net.interfaces().iter().filter(|i| i.name=="eth0").all(|i| i.flags&1!=0));
        // Execute the real v1 imports through Machine/Kernel and this same original relay.
        let wasm=wat::parse_str(r#"(module
          (import "wasix_32v1" "port_bridge" (func $bridge (param i32 i32 i32 i32 i32) (result i32)))
          (import "wasix_32v1" "port_dhcp_acquire" (func $dhcp (result i32)))
          (import "wasix_32v1" "port_route_clear" (func $clear (result i32)))
          (import "wasix_32v1" "port_route_add" (func $add (param i32 i32 i32 i32) (result i32)))
          (import "wasix_32v1" "port_route_list" (func $routes (param i32 i32) (result i32)))
          (import "wasix_32v1" "port_addr_list" (func $addresses (param i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
          (memory (export "memory") 1)
          (data (i32.const 100) "\01\00\00\00\00\00\00")
          (data (i32.const 200) "\01\00\c0\00\02\01")
          (data (i32.const 400) "tenantcredential")
          (func $ok (param $value i32) (param $step i32)
            (if (local.get $value) (then (call $exit (local.get $step)) unreachable)))
          (func $assert (param $value i32) (param $step i32)
            (if (i32.eqz (local.get $value)) (then (call $exit (local.get $step)) unreachable)))
          (func (export "_start")
            (call $ok (call $bridge (i32.const 400) (i32.const 6) (i32.const 406) (i32.const 10) (i32.const 3)) (i32.const 1))
            (call $ok (call $dhcp) (i32.const 2))
            (call $ok (call $clear) (i32.const 3))
            (i32.store8 (i32.const 300) (i32.const 1))
            (i32.store8 (i32.const 320) (i32.const 1))
            (i64.store (i32.const 328) (i64.const -1))
            (call $ok (call $add (i32.const 100) (i32.const 200) (i32.const 300) (i32.const 320)) (i32.const 4))
            (call $assert (i32.eq (call $routes (i32.const 1000) (i32.const 8)) (i32.const 61)) (i32.const 5))
            (call $assert (i32.eq (i32.load (i32.const 8)) (i32.const 1)) (i32.const 6))
            (call $ok (call $routes (i32.const 1000) (i32.const 8)) (i32.const 7))
            (call $assert (i32.eq (i32.load8_u (i32.const 1144)) (i32.const 1)) (i32.const 8))
            (call $assert (i64.eqz (i64.load (i32.const 1152))) (i32.const 9))
            (call $assert (i32.eq (i32.load8_u (i32.const 1160)) (i32.const 1)) (i32.const 10))
            (call $assert (i64.eq (i64.load (i32.const 1168)) (i64.const -1)) (i32.const 11))
            (call $ok (call $addresses (i32.const 2000) (i32.const 8)) (i32.const 12))
            (call $assert (i32.eq (i32.load8_u (i32.const 2006)) (i32.const 24)) (i32.const 13))
            (call $assert (i32.eq (call $bridge (i32.const 400) (i32.const 6) (i32.const 406) (i32.const 10) (i32.const 99)) (i32.const 28)) (i32.const 14))
            (call $exit (i32.const 0))))"#).unwrap();
        let machine=wasixv2::Machine::builder().user(wasixv2::Credentials::new(0,0)).network(net.clone()).build();
        let run=machine.run(&wasm,wasixv2::Stdio::from_fns(|_| {}, |_| {}));
        let mut run=std::pin::pin!(run);
        let status=tokio::time::timeout(Duration::from_secs(10),futures_util::future::poll_fn(|cx| {
            assert!(driver.poll(cx,&mut relay).is_pending());
            run.as_mut().poll(cx)
        })).await.unwrap().unwrap();
        assert_eq!(status,0,"v1 configured-provider guest check {status}");
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();let address=listener.local_addr().unwrap();
        let server=std::thread::spawn(move || {let (mut peer,_)=listener.accept().unwrap();peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();let mut byte=[0];peer.read_exact(&mut byte).unwrap();assert_eq!(byte,[b'x']);});
        let stream=backend.connect(address,WaitQueue::new()).unwrap();
        drive_until("postbridge socket uses configured transport",&mut driver,&mut relay,|| stream.state()!=StreamState::Connecting).await;
        assert_eq!(stream.state(),StreamState::Established);assert_eq!(stream.write(b"x"),Ok(1));
        drive_until("postbridge data",&mut driver,&mut relay,|| stream.output_len()==0).await;
        server.join().unwrap();
        assert_eq!(provider_call(&net,&mut driver,&mut relay,Request::Unbridge).await.result,Ok(Reply::None));
        let stream=backend.connect(address,WaitQueue::new()).unwrap();
        drive_until("unbridge affects actual socket provider",&mut driver,&mut relay,|| stream.state()!=StreamState::Connecting).await;
        assert_eq!(stream.state(),StreamState::Closed);assert_eq!(stream.take_error(),Some(Errno::ENOTCONN));
    });
}
