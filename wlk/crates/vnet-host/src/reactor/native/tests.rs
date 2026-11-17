//! Actual native sockets and canonical reactor lifecycle, following reactor.rs's siblings.
use super::*;
use std::{
    future::Future,
    io::{Read, Write},
    pin::pin,
    sync::atomic::AtomicUsize,
    task::{Context, Poll, Wake, Waker},
};
use wasixv2_vnet::Answer;

fn eventually<T>(mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(value) = check() {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "existing native reactor did not make progress"
        );
        thread::sleep(Duration::from_millis(1));
    }
}
struct ThreadWake(thread::Thread);
impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}
fn complete<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut cx = Context::from_waker(&waker);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => return value,
            Poll::Pending => {
                assert!(
                    Instant::now() < deadline,
                    "actual socket retirement did not finish"
                );
                thread::park_timeout(Duration::from_millis(20));
            }
        }
    }
}
fn closed(close: NativeClose) {
    fn send<T: Send>(_: &T) {}
    let waiting = close.wait();
    send(&waiting);
    complete(waiting).unwrap();
}
struct CountWake(AtomicUsize);
impl WaitEntry for CountWake {
    fn wake(&self, _: PollMask) -> bool {
        self.0.fetch_add(1, Ordering::SeqCst);
        true
    }
}
fn watch(queue: &WaitQueue) -> (Arc<CountWake>, WaitRegistration) {
    let count = Arc::new(CountWake(AtomicUsize::new(0)));
    let registration = queue.add(count.clone());
    (count, registration)
}
fn accept(listener: &std::net::TcpListener) -> std::net::TcpStream {
    listener.set_nonblocking(true).unwrap();
    eventually(|| match listener.accept() {
        Ok((stream, _)) => Some(stream),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => None,
        Err(e) => panic!("accept: {e}"),
    })
}

fn read_exact_native(stream: &NativeStream, bytes: &mut [u8]) {
    let mut offset = 0;
    eventually(|| match stream.read(&mut bytes[offset..], false) {
        Ok(0) => panic!("stream ended before expected bytes"),
        Ok(count) => {
            offset += count;
            (offset == bytes.len()).then_some(())
        }
        Err(Errno::EAGAIN) => None,
        Err(error) => panic!("native stream read: {error:?}"),
    });
}

#[test]
fn bound_tcp_transfer_close_preserves_child_and_child_close_releases_actual_fd() {
    let backend = HostBackend::new().unwrap();
    let peer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bound = backend
        .bind_tcp("127.0.0.1:0".parse().unwrap(), false, false, false)
        .unwrap();
    let local = bound.local_addr().unwrap();
    bound
        .set_option(1, 13, &[1_i32.to_le_bytes(), 1_i32.to_le_bytes()].concat())
        .unwrap();
    assert_ne!(local.port(), 0);
    let queue = WaitQueue::new();
    let (count, _registration) = watch(&queue);
    let stream = bound.connect(peer.local_addr().unwrap(), queue).unwrap();
    let mut other = accept(&peer);
    eventually(|| (stream.state() == Phase::Established).then_some(()));
    assert_eq!(stream.local_addr().unwrap(), local);
    count.0.store(0, Ordering::SeqCst);
    other.write_all(b"payload").unwrap();
    eventually(|| (count.0.load(Ordering::SeqCst) > 0).then_some(()));
    let mut bytes = [0; 7];
    read_exact_native(&stream, &mut bytes);
    assert_eq!(&bytes, b"payload");
    // The bound token owns no fd after transfer. Closing it cannot poison the child's close
    // state or retire the live stream, even while both public objects remain retained.
    assert_eq!(bound.local_addr().unwrap(), stream.local_addr().unwrap());
    let completion = bound.close();
    closed(completion.clone());
    assert_eq!(stream.write(b"still live").unwrap(), 10);
    other
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut live = [0; 10];
    other.read_exact(&mut live).unwrap();
    assert_eq!(&live, b"still live");
    // Explicit linger-zero allows immediate rebind; ordinary FIN is tested separately.
    stream
        .set_option(1, 13, &[1_i32.to_le_bytes(), 0_i32.to_le_bytes()].concat())
        .unwrap();
    closed(stream.close());
    assert!(stream.read(&mut bytes, false).is_err());
    assert!(bound.local_addr().is_err());
    // Both public Arcs are retained; completion is about actual fd ownership, not Arc drop.
    let rebound = std::net::TcpListener::bind(local).unwrap();
    drop(rebound);
    closed(completion);
}

#[test]
fn direct_connect_and_bound_listener_share_existing_reactor_and_preserve_accept_queue_waker() {
    let backend = HostBackend::new().unwrap();
    let bound = backend
        .bind_tcp("127.0.0.1:0".parse().unwrap(), false, false, false)
        .unwrap();
    let local = bound.local_addr().unwrap();
    let listener = bound.listen(2, WaitQueue::new()).unwrap();
    assert_eq!(listener.local_addr().unwrap(), local);
    assert_eq!(bound.local_addr().unwrap(), listener.local_addr().unwrap());
    bound.set_option(1, 2, &1_i32.to_le_bytes()).unwrap();
    closed(bound.close());
    listener.set_backlog(4).unwrap();
    let client = backend
        .connect_tcp("0.0.0.0:0".parse().unwrap(), local, WaitQueue::new())
        .unwrap();
    let queue = WaitQueue::new();
    let (count, _registration) = watch(&queue);
    let server = eventually(|| match listener.try_accept(queue.clone()) {
        Ok(stream) => Some(stream),
        Err(Errno::EAGAIN) => None,
        Err(e) => panic!("accept: {e:?}"),
    });
    assert_eq!(server.local_addr().unwrap(), local);
    eventually(|| (client.state() == Phase::Established).then_some(()));
    count.0.store(0, Ordering::SeqCst);
    assert_eq!(client.write(b"wake").unwrap(), 4);
    eventually(|| (count.0.load(Ordering::SeqCst) > 0).then_some(()));
    let mut bytes = [0; 4];
    read_exact_native(&server, &mut bytes);
    assert_eq!(&bytes, b"wake");
    eventually(|| client.flush().ok());
    closed(listener.close());
    // Already accepted streams belong to their new owners, not the retired listener.
    assert_eq!(server.write(b"ok").unwrap(), 2);
    closed(server.close());
    closed(client.close());
}

#[test]
fn listener_close_drains_unaccepted_raw_descriptors_before_ack_and_rebind() {
    let backend = HostBackend::new().unwrap();
    let listener = backend
        .listen_tcp(
            "127.0.0.1:0".parse().unwrap(),
            false,
            false,
            false,
            1,
            WaitQueue::new(),
        )
        .unwrap();
    let local = listener.local_addr().unwrap();
    let mut peer = std::net::TcpStream::connect(local).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    eventually(|| listener.poll(None).contains(PollMask::IN).then_some(()));
    assert_eq!(listener.accept.state.lock().unwrap().queue.len(), 1);
    closed(listener.close());
    let mut byte = [0];
    match peer.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ) => {}
        other => panic!("queued accepted descriptor remained live: {other:?}"),
    }
    assert!(listener.accept.state.lock().unwrap().queue.is_empty());
    let rebound = std::net::TcpListener::bind(local).unwrap();
    drop(rebound);
}

#[test]
fn owner_shutdown_retires_retained_native_resources_and_rejects_late_bound_transition() {
    let backend = HostBackend::new().unwrap();
    let shared = Arc::downgrade(&backend.shared);
    let bound = backend
        .bind_tcp("127.0.0.1:0".parse().unwrap(), false, false, false)
        .unwrap();
    let local = bound.local_addr().unwrap();
    let udp = backend
        .bind_udp(
            "127.0.0.1:0".parse().unwrap(),
            false,
            false,
            false,
            WaitQueue::new(),
        )
        .unwrap();
    let udp_local = udp.local_addr().unwrap();
    drop(backend);
    assert!(
        shared.upgrade().is_none(),
        "resources must not retain HostBackend or its driver"
    );
    assert_eq!(complete(bound.close().wait()), Err(Errno::ENETDOWN));
    assert_eq!(complete(udp.close().wait()), Err(Errno::ENETDOWN));
    assert!(matches!(
        bound.connect("127.0.0.1:9".parse().unwrap(), WaitQueue::new()),
        Err(Errno::ENETDOWN)
    ));
    let rebound = std::net::TcpListener::bind(local).unwrap();
    drop(rebound);
    let rebound = std::net::UdpSocket::bind(udp_local).unwrap();
    drop(rebound);
}

#[test]
fn failed_bound_transition_releases_exact_source_and_cannot_be_reused() {
    let backend = HostBackend::new().unwrap();
    let bound = backend
        .bind_tcp("127.0.0.1:0".parse().unwrap(), false, false, false)
        .unwrap();
    let local = bound.local_addr().unwrap();
    assert!(
        bound
            .connect("[::1]:9".parse().unwrap(), WaitQueue::new())
            .is_err()
    );
    closed(bound.close());
    let rebound = std::net::TcpListener::bind(local).unwrap();
    drop(rebound);
}

#[cfg(target_os = "linux")]
fn udp_metadata(v6: bool) {
    let backend = HostBackend::new().unwrap();
    let local: SocketAddr = if v6 { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
    let udp = backend
        .bind_udp(local, v6, false, false, WaitQueue::new())
        .unwrap();
    let actual = udp.local_addr().unwrap();
    assert_ne!(actual.port(), 0);
    assert!(actual.ip().is_unspecified());
    let destination: SocketAddr = SocketAddr::new(
        if v6 {
            Ipv6Addr::LOCALHOST.into()
        } else {
            Ipv4Addr::LOCALHOST.into()
        },
        actual.port(),
    );
    let peer = std::net::UdpSocket::bind(if v6 { "[::1]:0" } else { "127.0.0.1:0" }).unwrap();
    peer.send_to(b"abcdef", destination).unwrap();
    let mut small = [0; 2];
    let (copied, full, info) = eventually(|| match udp.recv_packet(&mut small, true) {
        Ok(packet) => Some(packet),
        Err(Errno::EAGAIN) => None,
        Err(e) => panic!("recv: {e:?}"),
    });
    assert_eq!((copied, full), (2, 6));
    assert_eq!(&small, b"ab");
    assert_eq!(info.destination, destination);
    assert_eq!(info.source, peer.local_addr().unwrap());
    // Loopback's real interface index comes from pktinfo for both address families.
    // SAFETY: lo is a static terminated C string; this function reads it and owns no pointer.
    let index = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    assert_ne!(index, 0);
    assert_eq!(info.interface, index);
    assert_eq!(udp.recv_packet(&mut small, true).unwrap(), (2, 6, info));
    let mut full_buffer = [0; 8];
    assert_eq!(
        udp.recv_packet(&mut full_buffer, false).unwrap(),
        (6, 6, info)
    );
    assert_eq!(&full_buffer[..6], b"abcdef");
    peer.send_to(&[], destination).unwrap();
    let empty = eventually(|| match udp.recv_packet(&mut [], false) {
        Ok(packet) => Some(packet),
        Err(Errno::EAGAIN) => None,
        Err(e) => panic!("zero: {e:?}"),
    });
    assert_eq!(empty, (0, 0, info));
    udp.connect(Some(peer.local_addr().unwrap())).unwrap();
    assert_eq!(udp.peer_addr().unwrap(), Some(peer.local_addr().unwrap()));
    udp.connect(None).unwrap();
    assert_eq!(udp.peer_addr().unwrap(), None);
    closed(udp.close());
    let rebound = std::net::UdpSocket::bind(actual).unwrap();
    drop(rebound);
}
#[test]
#[cfg(target_os = "linux")]
fn selected_udp_v4_keeps_actual_destination_interface_truncation_peek_and_zero() {
    udp_metadata(false);
}
#[test]
#[cfg(target_os = "linux")]
fn selected_udp_v6_keeps_actual_destination_interface_truncation_peek_and_zero() {
    udp_metadata(true);
}

#[test]
#[cfg(target_os = "linux")]
fn native_options_reach_same_udp_socket_and_fail_without_synthetic_success() {
    let backend = HostBackend::new().unwrap();
    let udp = backend
        .bind_udp(
            "0.0.0.0:0".parse().unwrap(),
            false,
            false,
            false,
            WaitQueue::new(),
        )
        .unwrap();
    udp.set_option(1, 6, &1_i32.to_le_bytes()).unwrap();
    udp.set_option(0, 2, &87_i32.to_le_bytes()).unwrap();
    udp.set_option(0, 34, &0_i32.to_le_bytes()).unwrap();
    udp.set_option(0, 33, &7_i32.to_le_bytes()).unwrap();
    udp.with(|d| {
        let sock = socket2::SockRef::from(&d.0.sock);
        assert!(sock.broadcast().unwrap());
        assert_eq!(sock.ttl_v4().unwrap(), 87);
        assert!(!sock.multicast_loop_v4().unwrap());
        assert_eq!(sock.multicast_ttl_v4().unwrap(), 7);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        udp.set_option(0, 2, &999_i32.to_le_bytes()),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        udp.set_option(-1, -1, &0_i32.to_le_bytes()),
        Err(Errno::EOPNOTSUPP)
    );
    udp.with(|d| {
        assert_eq!(socket2::SockRef::from(&d.0.sock).ttl_v4().unwrap(), 87);
        Ok(())
    })
    .unwrap();
    let mut membership = vec![224, 0, 0, 251, 127, 0, 0, 1];
    udp.set_option(0, 35, &membership).unwrap();
    udp.set_option(0, 36, &membership).unwrap();
    membership[..4].copy_from_slice(&[1, 2, 3, 4]);
    assert_eq!(udp.set_option(0, 35, &membership), Err(Errno::EINVAL));
    closed(udp.close());
}

#[test]
fn direct_host_resolution_uses_existing_workers_original_spelling_and_port_contract() {
    let backend = HostBackend::new().unwrap();
    for (host, port) in [("127.0.0.1", Some(80)), ("127.0.0.1:81", Some(82))] {
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        backend.resolve_host(
            host,
            port,
            Some("192.0.2.1".parse().unwrap()),
            Box::new(move |result| {
                send.send(result).unwrap();
            }),
        );
        let found = receive
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap();
        let Answer::Addrs { canonical, addrs } = found.answer else {
            panic!("name result")
        };
        assert_eq!(canonical, host);
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }
}

#[test]
fn close_completion_waits_for_last_actual_socket_reference_and_purges_driver_work() {
    let backend = HostBackend::new().unwrap();
    let peer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let stream = backend
        .connect_tcp(
            "0.0.0.0:0".parse().unwrap(),
            peer.local_addr().unwrap(),
            WaitQueue::new(),
        )
        .unwrap();
    let _peer = accept(&peer);
    eventually(|| (stream.state() == Phase::Established).then_some(()));
    stream
        .set_option(1, 13, &[1_i32.to_le_bytes(), 0_i32.to_le_bytes()].concat())
        .unwrap();
    let held = stream.inner.lock().unwrap().as_ref().unwrap().0.clone();
    let local = stream.local_addr().unwrap();
    // This is the same socket-bearing Arc an in-flight reactor entry retains.
    let close = stream.close();
    eventually(|| {
        let removed = !backend
            .shared
            .entries
            .lock()
            .unwrap()
            .contains_key(&held.token);
        let clean = !backend
            .shared
            .dirty
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.token == held.token);
        (removed && clean).then_some(())
    });
    let mut waiting = pin!(close.wait());
    let wake = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut cx = Context::from_waker(&wake);
    assert!(waiting.as_mut().poll(&mut cx).is_pending());
    assert_eq!(held.sock.local_addr().unwrap().as_socket(), Some(local));
    drop(held);
    complete(waiting).unwrap();
    let rebound = std::net::TcpListener::bind(local).unwrap();
    drop(rebound);
}

#[test]
fn explicit_close_keeps_first_result_when_owner_shutdown_races_retirement() {
    let backend = HostBackend::new().unwrap();
    let bound = backend
        .bind_tcp("127.0.0.1:0".parse().unwrap(), false, false, false)
        .unwrap();
    let local = bound.local_addr().unwrap();
    let close = bound.close();
    drop(backend);
    closed(close.clone());
    closed(close);
    let rebound = std::net::TcpListener::bind(local).unwrap();
    drop(rebound);
}

// Holds the real reactor in an ordinary queue wake, outside all reactor/socket locks.
// Drop always releases it before backend teardown, including assertion failures.
struct ReactorPause {
    release: Option<std::sync::mpsc::SyncSender<()>>,
    _registration: WaitRegistration,
    _trigger: Arc<NativeDatagram>,
}
struct PauseWake {
    entered: std::sync::mpsc::SyncSender<()>,
    release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}
impl WaitEntry for PauseWake {
    fn wake(&self, events: PollMask) -> bool {
        if events.contains(PollMask::IN) {
            let receiver = self.release.lock().unwrap().take();
            if let Some(receiver) = receiver {
                self.entered.send(()).unwrap();
                receiver.recv_timeout(Duration::from_secs(3)).unwrap();
            }
        }
        true
    }
}
impl ReactorPause {
    fn new(backend: &HostBackend) -> Self {
        let (entered, receive) = std::sync::mpsc::sync_channel(1);
        let (release, wait) = std::sync::mpsc::sync_channel(1);
        let queue = WaitQueue::new();
        let registration = queue.add(Arc::new(PauseWake {
            entered,
            release: Mutex::new(Some(wait)),
        }));
        let trigger = backend
            .bind_udp("127.0.0.1:0".parse().unwrap(), false, false, false, queue)
            .unwrap();
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.send_to(b"hold", trigger.local_addr().unwrap())
            .unwrap();
        receive.recv_timeout(Duration::from_secs(3)).unwrap();
        Self {
            release: Some(release),
            _registration: registration,
            _trigger: trigger,
        }
    }
}
impl Drop for ReactorPause {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

#[test]
fn normal_close_preserves_os_accepted_prefix_while_reactor_is_held() {
    let backend = HostBackend::new().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let stream = backend
        .connect_tcp(
            "0.0.0.0:0".parse().unwrap(),
            listener.local_addr().unwrap(),
            WaitQueue::new(),
        )
        .unwrap();
    let mut peer = accept(&listener);
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    eventually(|| (stream.state() == Phase::Established).then_some(()));
    let paused = ReactorPause::new(&backend);
    let payload = b"accepted before ordinary close";
    assert_eq!(stream.write(payload).unwrap(), payload.len());
    assert_eq!(stream.output_len(), 0, "no selected user-space TX queue");
    let close = stream.close();
    let mut waiting = pin!(close.wait());
    let wake = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut cx = Context::from_waker(&wake);
    assert!(waiting.as_mut().poll(&mut cx).is_pending());
    drop(paused);
    complete(waiting).unwrap();
    let mut received = Vec::new();
    peer.read_to_end(&mut received).unwrap();
    assert_eq!(received, payload);
}

#[test]
fn selected_blocked_writer_close_wakes_original_queue_and_releases_actual_fd() {
    let backend = HostBackend::new().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let queue = WaitQueue::new();
    let (wakes, _registration) = watch(&queue);
    let stream = backend
        .connect_tcp(
            "0.0.0.0:0".parse().unwrap(),
            listener.local_addr().unwrap(),
            queue,
        )
        .unwrap();
    let peer = accept(&listener);
    eventually(|| (stream.state() == Phase::Established).then_some(()));
    stream.set_option(1, 7, &4096_i32.to_le_bytes()).unwrap();
    socket2::SockRef::from(&peer)
        .set_recv_buffer_size(4096)
        .unwrap();
    stream
        .set_option(1, 13, &[1_i32.to_le_bytes(), 0_i32.to_le_bytes()].concat())
        .unwrap();
    let local = stream.local_addr().unwrap();
    let paused = ReactorPause::new(&backend);
    let bytes = vec![17; READ_CHUNK];
    let mut accepted = 0;
    loop {
        match stream.write(&bytes) {
            Ok(n) => {
                assert_ne!(n, 0);
                accepted += n;
                assert!(accepted < 32 * 1024 * 1024);
            }
            Err(Errno::EAGAIN) => break,
            other => panic!("blocked native write: {other:?}"),
        }
    }
    assert!(!stream.poll(None).contains(PollMask::OUT));
    assert_eq!(stream.output_len(), 0);
    wakes.0.store(0, Ordering::SeqCst);
    let close = stream.close();
    drop(paused);
    closed(close);
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert_eq!(stream.write(b"late"), Err(Errno::EBADF));
    let rebound = std::net::TcpListener::bind(local).unwrap();
    drop(rebound);
}

#[test]
fn selected_receive_budget_continues_without_another_edge_and_flood_close_finishes() {
    let backend = HostBackend::new().unwrap();
    let udp = backend
        .bind_udp(
            "127.0.0.1:0".parse().unwrap(),
            false,
            false,
            false,
            WaitQueue::new(),
        )
        .unwrap();
    let address = udp.local_addr().unwrap();
    let paused = ReactorPause::new(&backend);
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let count = RX_BUDGET + 8;
    for _ in 0..count {
        peer.send_to(b"x", address).unwrap();
    }
    drop(paused);
    // All packets predate release: draining beyond one budget cannot depend on a fresh edge.
    let mut received = 0;
    eventually(|| {
        while udp.recv_packet(&mut [0; 1], false).is_ok() {
            received += 1;
        }
        (received == count).then_some(())
    });
    struct Flood {
        stop: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<()>>,
    }
    impl Drop for Flood {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            self.worker.take().unwrap().join().unwrap();
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let sent = Arc::new(AtomicUsize::new(0));
    let sending = sent.clone();
    let worker = thread::spawn(move || {
        peer.set_nonblocking(true).unwrap();
        while !stopping.load(Ordering::Acquire) {
            let _ = peer.send_to(&[], address);
            sending.fetch_add(1, Ordering::SeqCst);
        }
    });
    let flood = Flood {
        stop,
        worker: Some(worker),
    };
    eventually(|| (sent.load(Ordering::SeqCst) > RX_BUDGET * 4).then_some(()));
    closed(udp.close());
    assert!(backend.shared.native.lock().unwrap().readable.is_empty());
    // Public wrapper and sending thread are retained until actual-close acknowledgement.
    let rebound = std::net::UdpSocket::bind(address).unwrap();
    drop(rebound);
    drop(flood);
}

fn slow_stream(
    backend: &HostBackend,
    queue: WaitQueue,
) -> (Arc<NativeStream>, std::net::TcpStream) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    // Set before the handshake so the peer advertises a deliberately small receive window.
    socket2::SockRef::from(&listener)
        .set_recv_buffer_size(4096)
        .unwrap();
    let stream = backend
        .connect_tcp(
            "0.0.0.0:0".parse().unwrap(),
            listener.local_addr().unwrap(),
            queue,
        )
        .unwrap();
    let peer = accept(&listener);
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    eventually(|| (stream.state() == Phase::Established).then_some(()));
    stream
        .set_option(1, 7, &(READ_CHUNK as i32).to_le_bytes())
        .unwrap();
    (stream, peer)
}
fn fill_native(stream: &NativeStream) -> usize {
    let bytes = vec![17; READ_CHUNK];
    let mut accepted = 0;
    loop {
        match stream.write(&bytes) {
            Ok(n) => {
                assert_ne!(n, 0);
                accepted += n;
                assert!(accepted < 32 * 1024 * 1024);
            }
            Err(Errno::EAGAIN) => return accepted,
            other => panic!("native send-buffer fill: {other:?}"),
        }
    }
}
fn in_linger(backend: &HostBackend, token: Token) -> bool {
    match backend.shared.entry(token) {
        Some(Entry::Stream(socket)) => {
            let state = socket.state();
            state.released && state.orphan_deadline.is_some() && !state.gone
        }
        _ => false,
    }
}

#[test]
fn selected_writable_edge_after_real_backpressure_wakes_original_waiters() {
    let backend = HostBackend::new().unwrap();
    let queue = WaitQueue::new();
    let (wakes, _registration) = watch(&queue);
    let (stream, mut peer) = slow_stream(&backend, queue);
    let pause = ReactorPause::new(&backend);
    let accepted = fill_native(&stream);
    assert!(!stream.poll(None).contains(PollMask::OUT));
    wakes.0.store(0, Ordering::SeqCst);
    drop(pause);
    let mut bytes = vec![0; accepted];
    peer.read_exact(&mut bytes).unwrap();
    assert!(bytes.iter().all(|byte| *byte == 17));
    eventually(|| {
        (wakes.0.load(Ordering::SeqCst) > 0 && stream.poll(None).contains(PollMask::OUT))
            .then_some(())
    });
    assert_eq!(stream.write(b"resume").unwrap(), 6);
    let mut bytes = [0; 6];
    peer.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"resume");
    closed(stream.close());
}

#[test]
#[cfg(target_os = "linux")]
fn positive_linger_progress_finishes_on_actual_tcp_state_before_deadline() {
    let backend = HostBackend::new().unwrap();
    let (stream, mut peer) = slow_stream(&backend, WaitQueue::new());
    stream
        .set_option(1, 13, &[1_i32.to_le_bytes(), 5_i32.to_le_bytes()].concat())
        .unwrap();
    let token = stream.inner.lock().unwrap().as_ref().unwrap().0.token;
    let accepted = fill_native(&stream);
    let start = Instant::now();
    let close = stream.close();
    eventually(|| in_linger(&backend, token).then_some(()));
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).unwrap();
    closed(close);
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(bytes.len(), accepted);
    assert!(bytes.iter().all(|byte| *byte == 17));
}

#[test]
#[cfg(target_os = "linux")]
fn positive_linger_deadline_preserves_os_delivery_without_blocking_siblings() {
    let backend = HostBackend::new().unwrap();
    let (stream, mut peer) = slow_stream(&backend, WaitQueue::new());
    stream
        .set_option(1, 13, &[1_i32.to_le_bytes(), 1_i32.to_le_bytes()].concat())
        .unwrap();
    let token = stream.inner.lock().unwrap().as_ref().unwrap().0.token;
    let accepted = fill_native(&stream);
    let start = Instant::now();
    let close = stream.close();
    eventually(|| in_linger(&backend, token).then_some(()));
    // The same reactor remains available during the configured linger interval.
    let sibling = backend
        .bind_udp(
            "127.0.0.1:0".parse().unwrap(),
            false,
            false,
            false,
            WaitQueue::new(),
        )
        .unwrap();
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"live", sibling.local_addr().unwrap())
        .unwrap();
    eventually(|| sibling.recv_packet(&mut [0; 4], false).ok());
    assert!(!close.0.finished.load(Ordering::Acquire));
    closed(close);
    assert!(start.elapsed() >= Duration::from_millis(800));
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).unwrap();
    assert_eq!(
        bytes.len(),
        accepted,
        "normal linger timeout must not reset accepted bytes"
    );
    assert!(bytes.iter().all(|byte| *byte == 17));
    closed(sibling.close());
}

#[test]
#[cfg(target_os = "linux")]
fn owner_cancel_escalates_same_inflight_linger_and_close_ack_under_racing_close() {
    let backend = HostBackend::new().unwrap();
    let (stream, _peer) = slow_stream(&backend, WaitQueue::new());
    stream
        .set_option(1, 13, &[1_i32.to_le_bytes(), 30_i32.to_le_bytes()].concat())
        .unwrap();
    let token = stream.inner.lock().unwrap().as_ref().unwrap().0.token;
    let local = stream.local_addr().unwrap();
    fill_native(&stream);
    let close = stream.close();
    eventually(|| in_linger(&backend, token).then_some(()));
    let other = stream.clone();
    let racing = thread::spawn(move || closed(other.close()));
    let start = Instant::now();
    let canceled = stream.cancel();
    assert!(Arc::ptr_eq(&close.0, &canceled.0));
    closed(canceled);
    closed(close);
    racing.join().unwrap();
    assert!(start.elapsed() < Duration::from_secs(2));
    let rebound = std::net::TcpListener::bind(local).unwrap();
    drop(rebound);
}

#[derive(Default)]
struct PacketReceiver {
    packets: Mutex<Vec<(DatagramInfo, Vec<u8>)>>,
    ready_count: AtomicUsize,
    errors: Mutex<Vec<Errno>>,
    ready_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    packet_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    failed_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl DatagramReceiver for PacketReceiver {
    fn ready(&self) {
        let hook = self.ready_hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        self.ready_count.fetch_add(1, Ordering::SeqCst);
    }
    fn failed(&self, error: Errno) {
        self.errors.lock().unwrap().push(error);
        let hook = self.failed_hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
    }
    fn received(
        &self,
        info: DatagramInfo,
        bytes: &[u8],
    ) -> wasixv2_vnet::endpoint::DatagramDelivery {
        assert_eq!(self.ready_count.load(Ordering::SeqCst), 1);
        self.packets.lock().unwrap().push((info, bytes.to_vec()));
        let hook = self.packet_hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        wasixv2_vnet::endpoint::DatagramDelivery::Queued
    }
}
fn native_udp(backend: &HostBackend) -> Arc<NativeDatagram> {
    backend
        .bind_udp(
            "127.0.0.1:0".parse().unwrap(),
            false,
            false,
            false,
            WaitQueue::new(),
        )
        .unwrap()
}
fn ready_receiver(lease: &NativeReceiveLease) {
    fn send<T: Send>(_: &T) {}
    let closing = lease.close();
    send(&closing);
    drop(closing); // An unpolled subscriber must not request owner revocation.
    let waiting = lease.wait_ready();
    send(&waiting);
    complete(waiting).unwrap();
}

#[test]
fn receiver_cutover_discards_old_native_and_kernel_queues_and_keeps_observation_metadata() {
    let backend = HostBackend::new().unwrap();
    let udp = native_udp(&backend);
    let address = udp.local_addr().unwrap();
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sender.send_to(b"old user queue", address).unwrap();
    eventually(|| (udp.input_len() > 0).then_some(()));
    let pause = ReactorPause::new(&backend);
    sender.send_to(b"old kernel queue", address).unwrap();
    let receiver = Arc::new(PacketReceiver::default());
    // This packet is transmitted after empty observation, inside Ready before its marker.
    // Its later recvmsg belongs to the new consumer; this is deliberately NOT wire-age proof.
    let gap_sender = sender.try_clone().unwrap();
    let weak_udp = Arc::downgrade(&udp);
    *receiver.ready_hook.lock().unwrap() = Some(Box::new(move || {
        let udp = weak_udp.upgrade().unwrap();
        assert_eq!(udp.local_addr().unwrap(), address);
        gap_sender.send_to(b"ready gap", address).unwrap();
    }));
    let lease = udp.install_receiver(receiver.clone()).unwrap();
    assert_eq!(udp.recv_packet(&mut [0; 32], false), Err(Errno::EBUSY));
    assert_eq!(udp.recv_from(&mut [0; 32], false), Err(Errno::EBUSY));
    // Dropping a readiness subscription does not cancel the owned installation.
    {
        let mut waiting = pin!(lease.wait_ready());
        let wake = Waker::from(Arc::new(ThreadWake(thread::current())));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(&wake))
                .is_pending()
        );
    }
    drop(pause);
    ready_receiver(&lease);
    eventually(|| (receiver.packets.lock().unwrap().len() == 1).then_some(()));
    sender.send_to(b"new", address).unwrap();
    eventually(|| (receiver.packets.lock().unwrap().len() == 2).then_some(()));
    let packets = receiver.packets.lock().unwrap();
    assert_eq!(packets[0].1, b"ready gap");
    assert_eq!(packets[1].1, b"new");
    assert_eq!(packets[0].0.destination, address);
    assert_eq!(packets[0].0.source, sender.local_addr().unwrap());
    assert_ne!(packets[0].0.interface, 0);
    drop(packets);
    complete(lease.close()).unwrap();
    // Receiver retirement does not claim physical-fd retirement or consume the socket.
    assert_eq!(udp.local_addr().unwrap(), address);
    sender.send_to(b"pull again", address).unwrap();
    eventually(|| udp.recv_packet(&mut [0; 16], false).ok());
    closed(udp.close());
}

#[test]
fn ready_reentry_revokes_only_its_ticket_and_late_old_cancel_cannot_retire_replacement() {
    let backend = HostBackend::new().unwrap();
    let udp = native_udp(&backend);
    let first = Arc::new(PacketReceiver::default());
    let pause = ReactorPause::new(&backend);
    let lease = udp.install_receiver(first.clone()).unwrap();
    let weak_lease = Arc::downgrade(&lease);
    let weak_udp = Arc::downgrade(&udp);
    *first.ready_hook.lock().unwrap() = Some(Box::new(move || {
        let udp = weak_udp.upgrade().unwrap();
        assert!(udp.local_addr().is_ok());
        weak_lease.upgrade().unwrap().cancel();
        assert!(matches!(
            udp.install_receiver(Arc::new(PacketReceiver::default())),
            Err(Errno::EBUSY)
        ));
    }));
    drop(pause);
    assert_eq!(complete(lease.wait_ready()), Err(Errno::ECANCELED));
    complete(lease.close()).unwrap();
    let second = Arc::new(PacketReceiver::default());
    let replacement = udp.install_receiver(second.clone()).unwrap();
    ready_receiver(&replacement);
    lease.cancel();
    drop(lease);
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"new ticket", udp.local_addr().unwrap())
        .unwrap();
    eventually(|| (second.packets.lock().unwrap().len() == 1).then_some(()));
    assert!(first.packets.lock().unwrap().is_empty());
    assert_eq!(*first.errors.lock().unwrap(), [Errno::ECANCELED]);
    assert!(second.errors.lock().unwrap().is_empty());
    complete(replacement.close()).unwrap();
    closed(udp.close());
}

struct ReleaseCallback(Option<std::sync::mpsc::SyncSender<()>>);
impl Drop for ReleaseCallback {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.send(());
        }
    }
}
#[test]
fn receive_close_and_actual_fd_close_both_join_inflight_unlocked_callback() {
    let backend = HostBackend::new().unwrap();
    let udp = native_udp(&backend);
    let address = udp.local_addr().unwrap();
    let receiver = Arc::new(PacketReceiver::default());
    let (entered, waiting) = std::sync::mpsc::sync_channel(1);
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    let release = ReleaseCallback(Some(release));
    let weak_udp = Arc::downgrade(&udp);
    *receiver.packet_hook.lock().unwrap() = Some(Box::new(move || {
        assert_eq!(weak_udp.upgrade().unwrap().local_addr().unwrap(), address);
        entered.send(()).unwrap();
        wait.recv_timeout(Duration::from_secs(3)).unwrap();
    }));
    let lease = udp.install_receiver(receiver.clone()).unwrap();
    ready_receiver(&lease);
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sender.send_to(b"in callback", address).unwrap();
    waiting.recv_timeout(Duration::from_secs(3)).unwrap();
    let mut receive_close = pin!(lease.close());
    let physical = udp.close(); // Succeeds while callback is held: no Native/transport lock.
    let mut physical_close = pin!(physical.wait());
    let wake = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut context = Context::from_waker(&wake);
    assert!(receive_close.as_mut().poll(&mut context).is_pending());
    assert!(physical_close.as_mut().poll(&mut context).is_pending());
    drop(release);
    complete(receive_close).unwrap();
    complete(physical_close).unwrap();
    assert_eq!(*receiver.errors.lock().unwrap(), [Errno::ECANCELED]);
    let rebound = std::net::UdpSocket::bind(address).unwrap();
    drop(rebound);
}

#[test]
fn provisional_receiver_drop_closes_without_ready_or_retaining_actual_resource() {
    let backend = HostBackend::new().unwrap();
    let udp = native_udp(&backend);
    let pause = ReactorPause::new(&backend);
    let receiver = Arc::new(PacketReceiver::default());
    let lease = udp.install_receiver(receiver.clone()).unwrap();
    let weak = Arc::downgrade(&lease);
    let status = lease.state.clone();
    drop(lease);
    assert!(weak.upgrade().is_none());
    drop(pause);
    eventually(|| status.result.lock().unwrap().closed.then_some(()));
    assert_eq!(receiver.ready_count.load(Ordering::SeqCst), 0);
    assert_eq!(*receiver.errors.lock().unwrap(), [Errno::ECANCELED]);
    let actual = udp.local_addr().unwrap();
    closed(udp.close());
    let rebound = std::net::UdpSocket::bind(actual).unwrap();
    drop(rebound);
}

#[test]
fn receive_install_budget_failure_is_authoritative_and_flood_cannot_starve_fd_close() {
    let backend = HostBackend::new().unwrap();
    let udp = native_udp(&backend);
    udp.set_option(1, 8, &(1024 * 1024_i32).to_le_bytes())
        .unwrap();
    let address = udp.local_addr().unwrap();
    let pause = ReactorPause::new(&backend);
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    // Exceed the TOTAL installation budget before the driver resumes, not just one turn.
    for _ in 0..INSTALL_BUDGET + 32 {
        sender.send_to(&[], address).unwrap();
    }
    let receiver = Arc::new(PacketReceiver::default());
    let lease = udp.install_receiver(receiver.clone()).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let worker = thread::spawn(move || {
        sender.set_nonblocking(true).unwrap();
        while !stopping.load(Ordering::Acquire) {
            let _ = sender.send_to(&[], address);
        }
    });
    struct FloodStop(Arc<AtomicBool>, Option<thread::JoinHandle<()>>);
    impl Drop for FloodStop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
            self.1.take().unwrap().join().unwrap();
        }
    }
    let flood = FloodStop(stop, Some(worker));
    drop(pause);
    assert_eq!(complete(lease.wait_ready()), Err(Errno::EBUSY));
    assert_eq!(receiver.ready_count.load(Ordering::SeqCst), 0);
    assert!(receiver.packets.lock().unwrap().is_empty());
    // wait_ready reports the failure before the synchronous failed callback finishes.
    complete(lease.close()).unwrap();
    assert_eq!(*receiver.errors.lock().unwrap(), [Errno::EBUSY]);
    closed(udp.close());
    let rebound = std::net::UdpSocket::bind(address).unwrap();
    drop(rebound);
    drop(flood);
}

#[cfg(target_os = "linux")]
fn socket_int<S: AsRawFd>(socket: &S, level: i32, name: i32) -> i32 {
    let mut value = 0_i32;
    let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: borrowed live socket and initialized integer/length buffers of exact size.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&mut value as *mut i32).cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(len as usize, std::mem::size_of_val(&value));
    value
}
#[test]
#[cfg(target_os = "linux")]
fn selected_multicast_is_member_affine_and_never_uses_another_sockets_membership() {
    let backend = HostBackend::new().unwrap();
    let first = backend
        .bind_udp(
            "0.0.0.0:0".parse().unwrap(),
            false,
            false,
            true,
            WaitQueue::new(),
        )
        .unwrap();
    let local = first.local_addr().unwrap();
    let second = backend
        .bind_udp(local, false, false, true, WaitQueue::new())
        .unwrap();
    let unjoined = backend
        .bind_udp(local, false, false, true, WaitQueue::new())
        .unwrap();
    let group = [224, 0, 0, 251];
    let membership = [group, [127, 0, 0, 1]].concat();
    first.set_option(0, 35, &membership).unwrap();
    second.set_option(0, 35, &membership).unwrap();
    for socket in [&first, &second, &unjoined] {
        socket
            .with(|socket| {
                assert_eq!(
                    socket_int(&socket.0.sock, libc::IPPROTO_IP, libc::IP_MULTICAST_ALL),
                    0
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(
            socket.set_option(0, 49, &1_i32.to_le_bytes()),
            Err(Errno::EOPNOTSUPP)
        );
    }
    let a = Arc::new(PacketReceiver::default());
    let b = Arc::new(PacketReceiver::default());
    let c = Arc::new(PacketReceiver::default());
    let leases = [
        first.install_receiver(a.clone()).unwrap(),
        second.install_receiver(b.clone()).unwrap(),
        unjoined.install_receiver(c.clone()).unwrap(),
    ];
    for lease in &leases {
        ready_receiver(lease);
    }
    let sender = native_udp(&backend);
    sender.set_option(0, 32, &[127, 0, 0, 1]).unwrap();
    sender.set_option(0, 34, &1_i32.to_le_bytes()).unwrap();
    let destination = SocketAddr::new(Ipv4Addr::from(group).into(), local.port());
    assert_eq!(sender.send_to(b"once", destination), Ok(4));
    eventually(|| {
        (a.packets.lock().unwrap().len() == 1 && b.packets.lock().unwrap().len() == 1).then_some(())
    });
    // Same-reactor control cutover follows the current event turn, plus a bounded negative
    // observation window; the actual SO_*_MULTICAST_ALL getters above prove the OS policy.
    let barrier = native_udp(&backend);
    let barrier_receiver = Arc::new(PacketReceiver::default());
    let barrier_lease = barrier.install_receiver(barrier_receiver).unwrap();
    ready_receiver(&barrier_lease);
    thread::sleep(Duration::from_millis(50));
    assert!(c.packets.lock().unwrap().is_empty());
    assert_eq!(a.packets.lock().unwrap().len(), 1);
    assert_eq!(b.packets.lock().unwrap().len(), 1);
    for receiver in [&a, &b] {
        let packets = receiver.packets.lock().unwrap();
        assert_eq!(packets[0].0.destination, destination);
        assert_eq!(packets[0].1, b"once");
        assert_ne!(packets[0].0.interface, 0);
    }
    // Preserve the original ip_mreqn interface hint without namespace index substitution.
    // SAFETY: static terminated name, no retained pointer.
    let index = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    let request = [
        [0; 4].as_slice(),
        [127, 0, 0, 1].as_slice(),
        index.to_le_bytes().as_slice(),
    ]
    .concat();
    sender.set_option(0, 32, &request).unwrap();
    assert_eq!(sender.send_to(b"indexed", destination), Ok(7));
    eventually(|| {
        (a.packets.lock().unwrap().len() == 2 && b.packets.lock().unwrap().len() == 2).then_some(())
    });
    for lease in &leases {
        complete(lease.close()).unwrap();
    }
    complete(barrier_lease.close()).unwrap();
    for socket in [first, second, unjoined, sender, barrier] {
        closed(socket.close());
    }
}

#[test]
#[cfg(target_os = "linux")]
fn selected_v6_and_dual_stack_disable_each_applicable_global_membership_policy() {
    let backend = HostBackend::new().unwrap();
    for only_v6 in [true, false] {
        let udp = backend
            .bind_udp(
                "[::]:0".parse().unwrap(),
                only_v6,
                false,
                false,
                WaitQueue::new(),
            )
            .unwrap();
        udp.with(|socket| {
            assert_eq!(
                socket_int(&socket.0.sock, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_ALL),
                0
            );
            if !only_v6 {
                assert_eq!(
                    socket_int(&socket.0.sock, libc::IPPROTO_IP, libc::IP_MULTICAST_ALL),
                    0
                );
            }
            Ok(())
        })
        .unwrap();
        closed(udp.close());
    }
}

#[test]
fn direct_host_lookup_preserves_native_ip_order_and_duplicates() {
    use std::net::ToSocketAddrs;
    let expected: Vec<_> = "localhost:0"
        .to_socket_addrs()
        .unwrap()
        .map(|address| address.ip())
        .collect();
    let backend = HostBackend::new().unwrap();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    backend.resolve_host(
        "localhost",
        None,
        None,
        Box::new(move |found| {
            send.send(found).unwrap();
        }),
    );
    let found = receive
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .unwrap();
    let Answer::Addrs { canonical, addrs } = found.answer else {
        panic!("name result")
    };
    assert_eq!(canonical, "localhost");
    assert_eq!(addrs, expected);
}

#[test]
fn failed_callback_can_install_replacement_without_stale_post_callback_state_writes() {
    let backend = HostBackend::new().unwrap();
    let udp = native_udp(&backend);
    let first = Arc::new(PacketReceiver::default());
    let old = udp.install_receiver(first.clone()).unwrap();
    ready_receiver(&old);
    let second = Arc::new(PacketReceiver::default());
    let replacement = Arc::new(Mutex::new(None));
    let store = replacement.clone();
    let target = second.clone();
    let weak = Arc::downgrade(&udp);
    *first.failed_hook.lock().unwrap() = Some(Box::new(move || {
        *store.lock().unwrap() = Some(weak.upgrade().unwrap().install_receiver(target).unwrap());
    }));
    complete(old.close()).unwrap();
    let current = replacement.lock().unwrap().take().unwrap();
    ready_receiver(&current);
    drop(old);
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"replacement", udp.local_addr().unwrap())
        .unwrap();
    eventually(|| (second.packets.lock().unwrap().len() == 1).then_some(()));
    assert!(second.errors.lock().unwrap().is_empty());
    complete(current.close()).unwrap();
    closed(udp.close());
}

#[cfg(target_os = "linux")]
fn unpublished_lingering_socket() -> (socket2::Socket, std::net::TcpStream) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    client.set_recv_buffer_size(4096).unwrap();
    client
        .connect(&listener.local_addr().unwrap().into())
        .unwrap();
    let peer = socket2::Socket::from(accept(&listener));
    peer.set_nonblocking(true).unwrap();
    peer.set_send_buffer_size(READ_CHUNK).unwrap();
    let mut accepted = 0;
    loop {
        match peer.send(&vec![19; READ_CHUNK]) {
            Ok(n) => {
                assert_ne!(n, 0);
                accepted += n;
                assert!(accepted < 32 * 1024 * 1024);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("actual unpublished send: {error}"),
        }
    }
    assert!(
        accepted > 8192,
        "accepted data exceeds the peer's advertised window"
    );
    peer.set_linger(Some(Duration::from_secs(30))).unwrap();
    (peer, std::net::TcpStream::from(client))
}

#[test]
#[cfg(target_os = "linux")]
fn rejected_raw_accept_with_positive_linger_cannot_block_the_canonical_driver() {
    let backend = HostBackend::new().unwrap();
    let listener = backend
        .listen_tcp(
            "127.0.0.1:0".parse().unwrap(),
            false,
            false,
            false,
            1,
            WaitQueue::new(),
        )
        .unwrap();
    closed(listener.close());
    let (peer, _client) = unpublished_lingering_socket();
    let receive = Arc::new(PacketReceiver::default());
    let sink = listener.accept.clone();
    let peer_address = peer.peer_addr().unwrap().as_socket().unwrap();
    *receive.ready_hook.lock().unwrap() = Some(Box::new(move || sink.incoming(peer, peer_address)));
    let udp = native_udp(&backend);
    let lease = udp.install_receiver(receive).unwrap();
    ready_receiver(&lease);
    complete(lease.close()).unwrap();
    closed(udp.close());
}

#[test]
#[cfg(target_os = "linux")]
fn failed_selected_stream_registration_aborts_unpublished_positive_linger_fd() {
    let backend = HostBackend::new().unwrap();
    let (peer, _client) = unpublished_lingering_socket();
    let receive = Arc::new(PacketReceiver::default());
    let backend_weak = Arc::downgrade(&backend);
    *receive.ready_hook.lock().unwrap() = Some(Box::new(move || {
        let backend = backend_weak.upgrade().unwrap();
        let mut control = ready(&backend.shared).unwrap();
        let descriptor = peer.as_raw_fd();
        // A genuine mio registration error after transfer, not a mocked close result.
        backend
            .shared
            .registry
            .register(
                &mut SourceFd(&descriptor),
                backend.shared.token(),
                Interest::READABLE,
            )
            .unwrap();
        let address = peer.peer_addr().unwrap().as_socket().unwrap();
        let close = NativeClose::new();
        let socket = OwnedSocket {
            sock: peer,
            retirement: Retirement(close.clone()),
        };
        let result = NativeStream::register(
            &backend.shared,
            &mut control,
            socket,
            address,
            true,
            WaitQueue::new(),
        );
        assert!(matches!(result, Err(Errno::EEXIST)));
        assert!(
            close.0.finished.load(Ordering::Acquire),
            "actual fd destruction precedes failure completion"
        );
    }));
    let udp = native_udp(&backend);
    let lease = udp.install_receiver(receive).unwrap();
    ready_receiver(&lease);
    complete(lease.close()).unwrap();
    closed(udp.close());
}

#[test]
#[cfg(target_os = "linux")]
fn connected_udp_one_shot_icmp_keeps_same_receiver_and_later_datagram_owner() {
    let backend = HostBackend::new().unwrap();
    let queue = WaitQueue::new();
    let (wakes, _registration) = watch(&queue);
    let udp = backend
        .bind_udp("127.0.0.1:0".parse().unwrap(), false, false, false, queue)
        .unwrap();
    let receiver = Arc::new(PacketReceiver::default());
    let lease = udp.install_receiver(receiver.clone()).unwrap();
    ready_receiver(&lease);
    let closed_peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer_address = closed_peer.local_addr().unwrap();
    drop(closed_peer);
    udp.connect(Some(peer_address)).unwrap();
    let local = udp.local_addr().unwrap();
    wakes.0.store(0, Ordering::SeqCst);
    assert_eq!(udp.send_to(b"icmp probe", peer_address), Ok(10));
    let error = eventually(|| udp.take_error());
    assert_eq!(error, Errno::ECONNREFUSED);
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(receiver.errors.lock().unwrap().is_empty());
    assert_eq!(receiver.ready_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        udp.inner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .0
            .state()
            .receiver
            .as_ref()
            .unwrap()
            .ticket,
        lease.ticket
    );
    // Reuse the original connected peer address. There is no reconnect, replacement source,
    // new receiver or publication that could conceal loss of the original receive owner.
    let peer = std::net::UdpSocket::bind(peer_address).unwrap();
    peer.send_to(b"after error", local).unwrap();
    eventually(|| (receiver.packets.lock().unwrap().len() == 1).then_some(()));
    let packets = receiver.packets.lock().unwrap();
    assert_eq!(packets[0].0.source, peer_address);
    assert_eq!(packets[0].0.destination, local);
    assert_eq!(packets[0].1, b"after error");
    drop(packets);
    assert!(receiver.errors.lock().unwrap().is_empty());
    complete(lease.close()).unwrap();
    closed(udp.close());
}
