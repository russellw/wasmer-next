//! Same driver/transport harness as backend.rs, with actual canonical Net admission.
use std::{
    collections::{BTreeSet, VecDeque},
    future::Future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use wasixv2_abi::Errno;
use wasixv2_vnet::{
    BackendStream, Domain, Net, NetConfig, Network, SocketKind,
    endpoint::{
        EndpointAutobind, EndpointBindPurpose, EndpointBindRequest, EndpointChoice, EndpointKind,
        EndpointProvider, EndpointQuery, EndpointSourceId,
    },
};
use wasixv2_vnet_web::{Capabilities, Command, Config, Driver, Event, Transport, WebBackend};
use wasixv2_wait::{PollMask, PollTable, WaitEntry, WaitQueue};

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}
struct Mock {
    caps: Capabilities,
    sent: Vec<Command>,
    events: VecDeque<Event>,
    blocked_accept: bool,
    blocked_local_addr: bool,
    ack_close_immediately: bool,
    open_limit: Option<usize>,
    opening: BTreeSet<u64>,
    revoked: BTreeSet<u64>,
}
impl Transport for Mock {
    fn capabilities(&self) -> Capabilities {
        self.caps
    }
    fn poll_send(&mut self, _: &mut Context<'_>, command: &Command) -> Poll<Result<(), Errno>> {
        if self.blocked_accept && matches!(command, Command::Accept { .. }) {
            return Poll::Pending;
        }
        if self.blocked_local_addr && matches!(command, Command::LocalAddr { .. }) {
            return Poll::Pending;
        }
        if self.ack_close_immediately
            && let Command::CloseSelected { request, socket } = command
        {
            self.events.push_back(Event::ProviderCloseAck {
                accept_pending: false,
                request: *request,
                socket: *socket,
                result: Ok(()),
            });
            self.blocked_accept = false;
        }
        if let Command::BindStream { socket, .. }
        | Command::ConnectFrom { socket, .. }
        | Command::ListenFrom { socket, .. }
        | Command::ListenReserved { socket, .. } = command
            && let Some(limit) = self.open_limit
        {
            if self.opening.len() >= limit {
                return Poll::Pending;
            }
            assert!(
                self.opening.insert(*socket),
                "accepted factory must not replay"
            );
        }
        self.sent.push(command.clone());
        Poll::Ready(Ok(()))
    }
    fn poll_recv(&mut self, _: &mut Context<'_>) -> Poll<Result<Event, Errno>> {
        self.events
            .pop_front()
            .map_or(Poll::Pending, |event| Poll::Ready(Ok(event)))
    }
    fn poll_recv_close(&mut self, _: &mut Context<'_>) -> Poll<Result<Event, Errno>> {
        let Some(index) = self.events.iter().position(|event| {
            matches!(event, Event::ProviderCloseAck { .. } | Event::LocalCloseUnconfirmed { .. }
                | Event::Sent { .. } | Event::SendError { .. } | Event::Writable { .. })
                || matches!(event, Event::Complete { request, .. } if self.sent.iter().any(|command| matches!(command,
                    Command::SetOption { request: Some(actual), .. } | Command::CloseSelected { request: actual, .. }
                    if actual == request)))
        }) else {
            return Poll::Pending;
        };
        Poll::Ready(Ok(self.events.remove(index).unwrap()))
    }
    fn revoke_open(&mut self, socket: u64) {
        self.opening.remove(&socket);
        self.revoked.insert(socket);
    }
    fn poll_closed(&mut self, _: &mut Context<'_>) -> Poll<Errno> {
        Poll::Pending
    }
    fn close(&mut self) {
        self.events.clear();
        self.opening.clear();
    }
}
struct Harness {
    backend: Arc<WebBackend>,
    driver: Driver,
    io: Mock,
}
impl Harness {
    fn new(bind: bool) -> Self {
        Self::profile(bind, false)
    }
    fn profile(bind: bool, external: bool) -> Self {
        Self::limited(bind, external, 8)
    }
    fn limited(bind: bool, external: bool, limit: usize) -> Self {
        Self::configured(bind, external, limit, false)
    }
    fn configured(bind: bool, external: bool, limit: usize, async_options: bool) -> Self {
        let caps = Capabilities {
            async_options,
            selected_endpoints: true,
            selected_bind: bind,
            selected_external: external,
            ..Capabilities::classic(true)
        };
        let (backend, driver) = WebBackend::new(
            Config {
                max_sockets: limit,
                ..Config::default()
            },
            caps,
        )
        .unwrap();
        Self {
            backend,
            driver,
            io: Mock {
                caps,
                sent: Vec::new(),
                events: VecDeque::new(),
                blocked_accept: false,
                blocked_local_addr: false,
                ack_close_immediately: false,
                open_limit: None,
                opening: BTreeSet::new(),
                revoked: BTreeSet::new(),
            },
        }
    }
    fn pump(&mut self) {
        assert!(
            self.driver
                .poll(
                    &mut Context::from_waker(futures_util::task::noop_waker_ref()),
                    &mut self.io
                )
                .is_pending()
        );
    }
    fn event(&mut self, event: Event) {
        self.io.events.push_back(event);
        self.pump();
    }
    fn provider(&self) -> Arc<dyn EndpointProvider> {
        self.backend
            .clone()
            .with_namespace_endpoints()
            .endpoint_namespace()
            .unwrap()
    }
    fn net(&self) -> Arc<Net> {
        Net::new(
            NetConfig::host_default(),
            Some(self.backend.clone().with_namespace_endpoints()),
        )
    }
}
fn request(purpose: EndpointBindPurpose) -> EndpointBindRequest {
    EndpointBindRequest {
        source_id: EndpointSourceId(7),
        kind: EndpointKind::Stream,
        requested: addr("0.0.0.0:0"),
        explicit: purpose == EndpointBindPurpose::Bind,
        purpose,
        domain: Domain::Inet,
        v6only: false,
        reuse_addr: true,
        reuse_port: false,
    }
}
struct Count(AtomicUsize);
impl WaitEntry for Count {
    fn wake(&self, _: PollMask) -> bool {
        self.0.fetch_add(1, Ordering::SeqCst);
        true
    }
}

#[test]
fn selected_bind_is_bind_only_and_keeps_literal_request_and_multiple_waiters() {
    let mut h = Harness::new(true);
    let provider = h.provider();
    let original = request(EndpointBindPurpose::Bind);
    let bound = provider.bind(original, WaitQueue::new()).unwrap().unwrap();
    let first = Arc::new(Count(AtomicUsize::new(0)));
    let second = Arc::new(Count(AtomicUsize::new(0)));
    let mut registrations = Vec::new();
    for waiter in [first.clone(), second.clone()] {
        let mut register = |queue: &WaitQueue, _| registrations.push(queue.add(waiter.clone()));
        assert!(
            bound
                .poll(Some(&mut PollTable::new(PollMask::empty(), &mut register)))
                .is_empty()
        );
    }
    assert_eq!(bound.local_addr(), Err(Errno::EAGAIN));
    h.pump();
    let (request, socket) = match h.io.sent.as_slice() {
        [
            Command::BindStream {
                request,
                socket,
                bind,
            },
        ] => {
            assert_eq!(*bind, original);
            (*request, *socket)
        }
        other => panic!("bind must not connect: {other:?}"),
    };
    drop(registrations.remove(0));
    h.event(Event::StreamBound {
        request,
        socket,
        result: Ok(addr("0.0.0.0:42001")),
    });
    assert_eq!(first.0.load(Ordering::SeqCst), 0);
    assert!(second.0.load(Ordering::SeqCst) > 0);
    assert_eq!(bound.local_addr(), Ok(addr("0.0.0.0:42001")));
    assert_eq!(
        h.io.sent.len(),
        1,
        "successful bind is not an implicit connect"
    );
}

#[test]
fn explicit_bind_connect_transfers_same_id_and_updates_actual_address() {
    let mut h = Harness::new(true);
    let provider = h.provider();
    let original = request(EndpointBindPurpose::Bind);
    let bound = provider.bind(original, WaitQueue::new()).unwrap().unwrap();
    h.pump();
    let (request, id) = match h.io.sent[0] {
        Command::BindStream {
            request, socket, ..
        } => (request, socket),
        _ => unreachable!(),
    };
    h.event(Event::StreamBound {
        request,
        socket: id,
        result: Ok(addr("0.0.0.0:42002")),
    });
    let query = EndpointQuery {
        kind: EndpointKind::Stream,
        source_id: original.source_id,
        bound: Some(addr("0.0.0.0:42002")),
        requested_bind: Some(original.requested),
        binding: Some(bound.clone()),
        effective_source: None,
        destination: addr("127.0.0.1:8080"),
        local_binding: true,
    };
    let EndpointChoice::Provider(target) = provider.select(&query).unwrap() else {
        panic!("missing selected resource");
    };
    let stream = provider
        .connect(
            target,
            original.source_id,
            query.bound.unwrap(),
            query.destination,
            WaitQueue::new(),
        )
        .unwrap();
    drop(query);
    drop(bound);
    h.pump();
    let request = match h.io.sent.last().unwrap() {
        Command::ConnectFrom {
            request,
            socket,
            requested_bind,
            bound_addr,
            ..
        } => {
            assert_eq!(*socket, id);
            assert_eq!(*requested_bind, Some(original.requested));
            assert_eq!(*bound_addr, Some(addr("0.0.0.0:42002")));
            *request
        }
        other => panic!("wrong same-resource operation: {other:?}"),
    };
    assert_eq!(
        stream.provider_local_addr(),
        Some(Ok(addr("0.0.0.0:42002")))
    );
    h.event(Event::StreamConnected {
        request,
        socket: id,
        result: Ok(addr("127.0.0.100:42002")),
    });
    assert_eq!(
        stream.provider_local_addr(),
        Some(Ok(addr("127.0.0.100:42002")))
    );
    assert_eq!(stream.state(), wasixv2_vnet::StreamState::Established);
    assert!(
        !h.io
            .sent
            .iter()
            .any(|command| matches!(command, Command::CloseSelected { .. }))
    );
}

#[test]
fn unbound_selected_connect_emits_no_bind_and_cannot_use_foreign_namespace_target() {
    let mut h = Harness::new(true);
    let provider = h.provider();
    let foreign = h.provider();
    let query = EndpointQuery {
        kind: EndpointKind::Stream,
        source_id: EndpointSourceId(9),
        bound: None,
        requested_bind: None,
        binding: None,
        effective_source: None,
        destination: addr("127.0.0.1:8080"),
        local_binding: false,
    };
    let EndpointChoice::Provider(target) = provider.select(&query).unwrap() else {
        panic!();
    };
    assert!(matches!(
        foreign.connect(
            target.clone(),
            query.source_id,
            addr("0.0.0.0:0"),
            query.destination,
            WaitQueue::new()
        ),
        Err(Errno::ECANCELED)
    ));
    let canonical_source = addr("127.0.0.1:43077");
    let _stream = provider
        .connect(
            target,
            query.source_id,
            canonical_source,
            query.destination,
            WaitQueue::new(),
        )
        .unwrap();
    h.pump();
    assert!(matches!(
        h.io.sent.as_slice(),
        [Command::ConnectFrom {
            local,
            requested_bind: None,
            bound_addr: None,
            ..
        }] if *local == canonical_source
    ));
}

#[test]
fn selected_close_is_shared_and_requires_actual_ack_not_send_acceptance() {
    let mut h = Harness::new(true);
    let provider = h.provider();
    let bound = provider
        .bind(request(EndpointBindPurpose::Bind), WaitQueue::new())
        .unwrap()
        .unwrap();
    h.pump();
    let (request, socket) = match h.io.sent[0] {
        Command::BindStream {
            request, socket, ..
        } => (request, socket),
        _ => unreachable!(),
    };
    h.event(Event::StreamBound {
        request,
        socket,
        result: Ok(addr("0.0.0.0:42003")),
    });
    let backend = h.backend.clone();
    let mut first = Box::pin(backend.close_endpoints());
    let mut second = Box::pin(backend.close_endpoints());
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    h.pump();
    let close =
        h.io.sent
            .iter()
            .filter_map(|command| match command {
                Command::CloseSelected {
                    request,
                    socket: id,
                } if *id == socket => Some(*request),
                _ => None,
            })
            .collect::<Vec<_>>();
    assert_eq!(close.len(), 1);
    assert!(first.as_mut().poll(&mut cx).is_pending());
    drop(first); // Only a subscription disappears; the resource still owns close.
    h.event(Event::ProviderCloseAck {
        accept_pending: false,
        request: close[0],
        socket,
        result: Ok(()),
    });
    assert_eq!(
        second.as_mut().poll(&mut cx),
        Poll::Ready(Ok(wasixv2_vnet_web::SelectedCloseReport::default()))
    );
    assert_eq!(bound.local_addr(), Err(Errno::ENETDOWN));
}

#[test]
fn canceled_unpolled_bind_accepts_no_provider_work() {
    let mut h = Harness::new(true);
    let provider = h.provider();
    let bound = provider
        .bind(request(EndpointBindPurpose::Bind), WaitQueue::new())
        .unwrap()
        .unwrap();
    drop(bound);
    h.pump();
    assert!(h.io.sent.is_empty());
}

#[test]
fn failed_close_keeps_the_actual_first_error_for_later_subscribers() {
    let mut h = Harness::new(true);
    let provider = h.provider();
    let _bound = provider
        .bind(request(EndpointBindPurpose::Bind), WaitQueue::new())
        .unwrap()
        .unwrap();
    h.pump();
    let (request, socket) = match h.io.sent[0] {
        Command::BindStream {
            request, socket, ..
        } => (request, socket),
        _ => unreachable!(),
    };
    h.event(Event::StreamBound {
        request,
        socket,
        result: Ok(addr("0.0.0.0:42005")),
    });
    let backend = h.backend.clone();
    let mut closing = Box::pin(backend.close_endpoints());
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(closing.as_mut().poll(&mut cx).is_pending());
    h.pump();
    let request =
        h.io.sent
            .iter()
            .find_map(|command| match command {
                Command::CloseSelected { request, .. } => Some(*request),
                _ => None,
            })
            .unwrap();
    h.event(Event::ProviderCloseAck {
        accept_pending: false,
        request,
        socket,
        result: Err(Errno::EIO),
    });
    assert_eq!(closing.as_mut().poll(&mut cx), Poll::Ready(Err(Errno::EIO)));
    drop(closing);
    assert_eq!(
        Box::pin(backend.close_endpoints()).as_mut().poll(&mut cx),
        Poll::Ready(Err(Errno::EIO))
    );
}

#[test]
fn canonical_unbound_listen_uses_listen_purpose_and_real_accepted_destination() {
    let mut h = Harness::new(true);
    let net = h.net();
    let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
    let admission = socket
        .autobind_admission(EndpointAutobind::Listen(0), false)
        .unwrap()
        .unwrap();
    h.pump();
    let (request, listener) = match h.io.sent[0] {
        Command::BindStream {
            request,
            socket,
            bind,
        } => {
            assert_eq!(bind.purpose, EndpointBindPurpose::Listen { backlog: 0 });
            assert!(!bind.explicit);
            (request, socket)
        }
        ref command => panic!("unbound listen is not bind+listen: {command:?}"),
    };
    h.event(Event::StreamBound {
        request,
        socket: listener,
        result: Ok(addr("0.0.0.0:42004")),
    });
    assert!(
        !h.io
            .sent
            .iter()
            .any(|command| matches!(command, Command::Accept { .. }))
    );
    admission.complete().unwrap();
    drop(admission);
    socket.listen(0).unwrap();
    h.pump();
    let child =
        h.io.sent
            .iter()
            .find_map(|command| match command {
                Command::Accept { socket, child } if *socket == listener => Some(*child),
                _ => None,
            })
            .unwrap();
    h.event(Event::AcceptedTo {
        socket: listener,
        child,
        peer: addr("127.0.0.100:32000"),
        local: addr("127.0.0.1:42004"),
    });
    let second =
        h.io.sent
            .iter()
            .rev()
            .find_map(|command| match command {
                Command::Accept { socket, child } if *socket == listener => Some(*child),
                _ => None,
            })
            .unwrap();
    assert_ne!(second, child);
    h.event(Event::AcceptedTo {
        socket: listener,
        child: second,
        peer: addr("127.0.0.100:32001"),
        local: addr("127.0.0.1:42004"),
    });
    let credits = h
        .io
        .sent
        .iter()
        .filter(|command| matches!(command, Command::Accept { socket, .. } if *socket == listener))
        .count();
    assert_eq!(
        credits, 2,
        "one held actual child prevents another credit while the canonical queue is full"
    );
    let accepted = socket.accept().unwrap();
    assert_eq!(accepted.peer, addr("127.0.0.100:32000"));
    assert_eq!(accepted.socket.local_addr(), Ok(addr("127.0.0.1:42004")));
    h.pump();
    assert_eq!(socket.accept().unwrap().peer, addr("127.0.0.100:32001"));
}

#[test]
fn namespace_reserved_profile_listens_on_canonical_port_with_original_zero_metadata() {
    let mut h = Harness::new(false);
    let net = h.net();
    let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
    assert!(
        socket
            .bind_admission(addr("127.0.0.1:0"), false)
            .unwrap()
            .is_none()
    );
    socket.bind(addr("127.0.0.1:0"), false).unwrap();
    let actual = socket.local_addr().unwrap();
    assert_ne!(actual.port(), 0);
    socket.listen(1).unwrap();
    h.pump();
    let (request, listener) = match h.io.sent[0] {
        Command::ListenReserved {
            request,
            socket,
            ref member,
            ..
        } => {
            assert_eq!(member.local, actual);
            assert_eq!(member.requested_bind, Some(addr("127.0.0.1:0")));
            assert!(member.binding.is_none());
            (request, socket)
        }
        ref command => panic!("reserved profile invented physical bind: {command:?}"),
    };
    assert!(
        !h.io
            .sent
            .iter()
            .any(|command| matches!(command, Command::Accept { .. }))
    );
    h.event(Event::StreamListening {
        request,
        socket: listener,
        result: Ok(actual),
    });
    assert!(
        h.io.sent.iter().any(
            |command| matches!(command, Command::Accept { socket, .. } if *socket == listener)
        )
    );
}

#[test]
fn admitted_bind_can_be_closed_without_its_completion_and_late_ready_cannot_revive_it() {
    let mut h = Harness::new(true);
    let provider = h.provider();
    let bound = provider
        .bind(request(EndpointBindPurpose::Bind), WaitQueue::new())
        .unwrap()
        .unwrap();
    h.pump();
    let (original, socket) = match h.io.sent[0] {
        Command::BindStream {
            request, socket, ..
        } => (request, socket),
        _ => unreachable!(),
    };
    drop(bound);
    let backend = h.backend.clone();
    let mut closing = Box::pin(backend.close_endpoints());
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(closing.as_mut().poll(&mut cx).is_pending());
    h.pump();
    let request =
        h.io.sent
            .iter()
            .find_map(|command| match command {
                Command::CloseSelected {
                    request,
                    socket: id,
                } if *id == socket => Some(*request),
                _ => None,
            })
            .unwrap();
    assert!(closing.as_mut().poll(&mut cx).is_pending());
    h.event(Event::ProviderCloseAck {
        accept_pending: false,
        request,
        socket,
        result: Ok(()),
    });
    assert_eq!(
        closing.as_mut().poll(&mut cx),
        Poll::Ready(Ok(wasixv2_vnet_web::SelectedCloseReport::default()))
    );
    h.event(Event::StreamBound {
        request: original,
        socket,
        result: Ok(addr("0.0.0.0:42006")),
    });
    assert!(!h.io.sent.iter().any(|command| matches!(
        command,
        Command::ConnectFrom { .. } | Command::Accept { .. }
    )));
}

#[test]
fn admitted_connect_and_listen_do_not_block_owner_close_on_their_first_reply() {
    for listen in [false, true] {
        let mut h = Harness::profile(false, true);
        let net = h.net();
        let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
        if listen {
            socket.bind(addr("127.0.0.1:0"), false).unwrap();
            socket.listen(1).unwrap();
        } else {
            assert_eq!(
                socket.connect(addr("198.51.100.1:80")),
                Err(Errno::EINPROGRESS)
            );
        }
        h.pump();
        assert!(matches!(
            h.io.sent[0],
            Command::ListenReserved { .. }
                | Command::ConnectFrom {
                    requested_bind: None,
                    ..
                }
        ));
        let backend = h.backend.clone();
        let mut closing = Box::pin(backend.close_endpoints());
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(closing.as_mut().poll(&mut cx).is_pending());
        h.pump();
        let (request, id) =
            h.io.sent
                .iter()
                .find_map(|command| match command {
                    Command::CloseSelected { request, socket } => Some((*request, *socket)),
                    _ => None,
                })
                .unwrap();
        h.event(Event::ProviderCloseAck {
            accept_pending: false,
            request,
            socket: id,
            result: Ok(()),
        });
        assert_eq!(
            closing.as_mut().poll(&mut cx),
            Poll::Ready(Ok(wasixv2_vnet_web::SelectedCloseReport::default()))
        );
    }
}

#[test]
fn listener_and_reserved_child_require_separate_actual_close_acks() {
    let mut h = Harness::new(false);
    let net = h.net();
    let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
    socket.bind(addr("127.0.0.1:0"), false).unwrap();
    let local = socket.local_addr().unwrap();
    socket.listen(1).unwrap();
    h.pump();
    let (request, listener) = match h.io.sent[0] {
        Command::ListenReserved {
            request, socket, ..
        } => (request, socket),
        _ => unreachable!(),
    };
    h.event(Event::StreamListening {
        request,
        socket: listener,
        result: Ok(local),
    });
    let child =
        h.io.sent
            .iter()
            .find_map(|command| match command {
                Command::Accept { child, .. } => Some(*child),
                _ => None,
            })
            .unwrap();
    let backend = h.backend.clone();
    let mut closing = Box::pin(backend.close_endpoints());
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(closing.as_mut().poll(&mut cx).is_pending());
    h.pump();
    let request_for = |id| {
        h.io.sent
            .iter()
            .find_map(|command| match command {
                Command::CloseSelected { request, socket } if *socket == id => Some(*request),
                _ => None,
            })
            .unwrap()
    };
    let parent_close = request_for(listener);
    let child_close = request_for(child);
    h.event(Event::ProviderCloseAck {
        accept_pending: false,
        request: parent_close,
        socket: listener,
        result: Ok(()),
    });
    assert!(
        closing.as_mut().poll(&mut cx).is_pending(),
        "parent close cannot acknowledge its child's resource"
    );
    h.event(Event::ProviderCloseAck {
        accept_pending: false,
        request: child_close,
        socket: child,
        result: Ok(()),
    });
    assert_eq!(
        closing.as_mut().poll(&mut cx),
        Poll::Ready(Ok(wasixv2_vnet_web::SelectedCloseReport::default()))
    );
}

#[test]
fn node_unbound_external_connection_exposes_actual_provider_source() {
    let mut h = Harness::profile(false, true);
    let net = h.net();
    let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
    assert_eq!(
        socket.connect(addr("198.51.100.1:80")),
        Err(Errno::EINPROGRESS)
    );
    h.pump();
    let (request, id) = match h.io.sent[0] {
        Command::ConnectFrom {
            request,
            socket,
            requested_bind: None,
            bound_addr: None,
            ..
        } => (request, socket),
        ref command => panic!("not an unbound selected host connect: {command:?}"),
    };
    let actual = addr("192.0.2.100:42007");
    h.event(Event::StreamConnected {
        request,
        socket: id,
        result: Ok(actual),
    });
    assert_eq!(socket.local_addr(), Ok(actual));
}

fn selected_stream(h: &mut Harness) -> (Arc<dyn BackendStream>, u64) {
    let provider = h.provider();
    let query = EndpointQuery {
        kind: EndpointKind::Stream,
        source_id: EndpointSourceId(99),
        bound: None,
        requested_bind: None,
        binding: None,
        effective_source: None,
        destination: addr("127.0.0.1:8080"),
        local_binding: false,
    };
    let EndpointChoice::Provider(target) = provider.select(&query).unwrap() else {
        panic!();
    };
    let stream = provider
        .connect(
            target,
            query.source_id,
            addr("0.0.0.0:0"),
            query.destination,
            WaitQueue::new(),
        )
        .unwrap();
    h.pump();
    let (request, socket) =
        h.io.sent
            .iter()
            .rev()
            .find_map(|command| match command {
                Command::ConnectFrom {
                    request, socket, ..
                } => Some((*request, *socket)),
                _ => None,
            })
            .unwrap();
    h.event(Event::StreamConnected {
        request,
        socket,
        result: Ok(addr("127.0.0.100:42010")),
    });
    (stream, socket)
}

type SelectedListener = (Arc<dyn wasixv2_vnet::Socket>, u64, u64, SocketAddr);
fn selected_listener(h: &mut Harness) -> SelectedListener {
    let net = h.net();
    let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
    socket.bind(addr("127.0.0.1:0"), false).unwrap();
    let local = socket.local_addr().unwrap();
    socket.listen(1).unwrap();
    h.pump();
    let (request, listener) =
        h.io.sent
            .iter()
            .rev()
            .find_map(|command| match command {
                Command::ListenReserved {
                    request, socket, ..
                } => Some((*request, *socket)),
                _ => None,
            })
            .unwrap();
    h.event(Event::StreamListening {
        request,
        socket: listener,
        result: Ok(local),
    });
    let child =
        h.io.sent
            .iter()
            .rev()
            .find_map(|command| match command {
                Command::Accept { socket, child } if *socket == listener => Some(*child),
                _ => None,
            })
            .unwrap();
    (socket, listener, child, local)
}
fn selected_close_request(h: &Harness, socket: u64) -> u64 {
    h.io.sent
        .iter()
        .rev()
        .find_map(|command| match command {
            Command::CloseSelected {
                request,
                socket: id,
            } if *id == socket => Some(*request),
            _ => None,
        })
        .unwrap()
}

#[test]
fn selected_close_drains_accepted_tx_but_unread_rx_requests_explicit_reset() {
    for unread in [false, true] {
        let mut h = Harness::new(true);
        let (stream, socket) = selected_stream(&mut h);
        if unread {
            h.event(Event::Data {
                socket,
                data: vec![1],
            });
        } else {
            assert_eq!(stream.write(b"accepted"), Ok(8));
        }
        drop(stream);
        let backend = h.backend.clone();
        let mut closing = Box::pin(backend.close_endpoints());
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(closing.as_mut().poll(&mut cx).is_pending());
        h.pump();
        if !unread {
            assert!(
                !h.io
                    .sent
                    .iter()
                    .any(|command| matches!(command, Command::CloseSelected { .. }))
            );
            let request =
                h.io.sent
                    .iter()
                    .find_map(|command| match command {
                        Command::Send { request, data, .. } => {
                            assert_eq!(data, b"accepted");
                            Some(*request)
                        }
                        _ => None,
                    })
                    .unwrap();
            h.event(Event::Sent {
                request,
                socket,
                amount: 8,
            });
        }
        let close_index =
            h.io.sent
                .iter()
                .position(|command| matches!(command, Command::CloseSelected { .. }))
                .unwrap();
        if unread {
            let reset_index =
                h.io.sent
                    .iter()
                    .position(|command| matches!(command, Command::Reset { .. }))
                    .unwrap();
            assert!(reset_index < close_index);
        } else {
            assert!(
                !h.io
                    .sent
                    .iter()
                    .any(|command| matches!(command, Command::Reset { .. }))
            );
        }
        let Command::CloseSelected { request, .. } = h.io.sent[close_index] else {
            unreachable!()
        };
        assert!(closing.as_mut().poll(&mut cx).is_pending());
        h.event(Event::ProviderCloseAck {
            accept_pending: false,
            request,
            socket,
            result: Ok(()),
        });
        assert_eq!(
            closing.as_mut().poll(&mut cx),
            Poll::Ready(Ok(wasixv2_vnet_web::SelectedCloseReport::default()))
        );
    }
}

#[test]
fn acknowledged_reset_then_last_wrapper_drop_releases_the_only_socket_slot() {
    let mut h = Harness::limited(true, false, 1);
    let (stream, socket) = selected_stream(&mut h);
    h.event(Event::Reset {
        socket,
        error: Errno::ECONNRESET,
    });
    let close_request =
        h.io.sent
            .iter()
            .find_map(|command| match command {
                Command::CloseSelected { request, .. } => Some(*request),
                _ => None,
            })
            .unwrap();
    h.event(Event::ProviderCloseAck {
        accept_pending: false,
        request: close_request,
        socket,
        result: Ok(()),
    });
    assert_eq!(stream.state(), wasixv2_vnet::StreamState::Closed);
    drop(stream);
    h.pump();
    assert!(
        h.provider()
            .bind(request(EndpointBindPurpose::Bind), WaitQueue::new())
            .unwrap()
            .is_some()
    );
}

#[test]
fn relisten_before_physical_command_preserves_same_revision_backlog_update() {
    for physical_bind in [false, true] {
        let mut h = Harness::new(physical_bind);
        let net = h.net();
        let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
        if let Some(admission) = socket.bind_admission(addr("127.0.0.1:0"), false).unwrap() {
            h.pump();
            let (request, id) = match h.io.sent[0] {
                Command::BindStream {
                    request, socket, ..
                } => (request, socket),
                _ => unreachable!(),
            };
            h.event(Event::StreamBound {
                request,
                socket: id,
                result: Ok(addr("127.0.0.1:42011")),
            });
            admission.complete().unwrap();
        } else {
            socket.bind(addr("127.0.0.1:0"), false).unwrap();
        }
        socket.listen(1).unwrap();
        socket.listen(7).unwrap();
        h.pump();
        assert!(h.io.sent.iter().any(|command| matches!(
            command,
            Command::ListenFrom { backlog: 7, .. } | Command::ListenReserved { backlog: 7, .. }
        )));
        assert!(!h.io.sent.iter().any(|command| matches!(
            command,
            Command::ListenFrom { backlog: 1, .. } | Command::ListenReserved { backlog: 1, .. }
        )));
    }
}

#[test]
fn unsent_selected_accept_is_retired_as_no_work_after_owner_cutoff() {
    let mut h = Harness::new(false);
    let net = h.net();
    let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
    socket.bind(addr("127.0.0.1:0"), false).unwrap();
    let local = socket.local_addr().unwrap();
    socket.listen(1).unwrap();
    h.pump();
    let (request, listener) = match h.io.sent[0] {
        Command::ListenReserved {
            request, socket, ..
        } => (request, socket),
        _ => unreachable!(),
    };
    h.io.blocked_accept = true;
    h.event(Event::StreamListening {
        request,
        socket: listener,
        result: Ok(local),
    });
    assert!(
        !h.io
            .sent
            .iter()
            .any(|command| matches!(command, Command::Accept { .. }))
    );
    let backend = h.backend.clone();
    let mut closing = Box::pin(backend.close_endpoints());
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(closing.as_mut().poll(&mut cx).is_pending());
    h.pump();
    let closes =
        h.io.sent
            .iter()
            .filter_map(|command| match command {
                Command::CloseSelected { request, socket } => Some((*request, *socket)),
                _ => None,
            })
            .collect::<Vec<_>>();
    assert_eq!(closes.len(), 1);
    assert_eq!(closes[0].1, listener);
    h.event(Event::ProviderCloseAck {
        accept_pending: false,
        request: closes[0].0,
        socket: listener,
        result: Ok(()),
    });
    assert_eq!(
        closing.as_mut().poll(&mut cx),
        Poll::Ready(Ok(wasixv2_vnet_web::SelectedCloseReport::default()))
    );
    assert!(
        !h.io
            .sent
            .iter()
            .any(|command| matches!(command, Command::Accept { .. }))
    );
}

#[test]
fn an_immediate_parent_close_ack_cannot_reclassify_a_cached_selected_accept() {
    let mut h = Harness::new(false);
    let net = h.net();
    let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
    socket.bind(addr("127.0.0.1:0"), false).unwrap();
    let local = socket.local_addr().unwrap();
    socket.listen(1).unwrap();
    h.pump();
    let (request, listener) = match h.io.sent[0] {
        Command::ListenReserved {
            request, socket, ..
        } => (request, socket),
        _ => unreachable!(),
    };
    h.io.blocked_accept = true;
    h.event(Event::StreamListening {
        request,
        socket: listener,
        result: Ok(local),
    });
    let backend = h.backend.clone();
    let mut closing = Box::pin(backend.close_endpoints());
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(closing.as_mut().poll(&mut cx).is_pending());
    // poll_send queues the ACK and opens transport capacity synchronously.
    // The very next Driver iteration receives it before revisiting cleanup.
    h.io.ack_close_immediately = true;
    h.pump();
    assert_eq!(
        closing.as_mut().poll(&mut cx),
        Poll::Ready(Ok(wasixv2_vnet_web::SelectedCloseReport::default()))
    );
    assert!(
        !h.io
            .sent
            .iter()
            .any(|command| matches!(command, Command::Accept { .. }))
    );
    assert_eq!(
        h.io.sent
            .iter()
            .filter(|command| matches!(command, Command::CloseSelected { .. }))
            .count(),
        1
    );
}

#[test]
fn unaccepted_connect_owner_close_keeps_a_retained_stream_safe_and_sends_no_work() {
    for held_by_driver in [false, true] {
        let mut h = Harness::limited(true, false, 1);
        h.io.open_limit = Some(0);
        let provider = h.provider();
        let query = EndpointQuery {
            kind: EndpointKind::Stream,
            source_id: EndpointSourceId(80),
            bound: None,
            requested_bind: None,
            binding: None,
            effective_source: None,
            destination: addr("127.0.0.1:8080"),
            local_binding: false,
        };
        let EndpointChoice::Provider(target) = provider.select(&query).unwrap() else {
            panic!()
        };
        let stream = provider
            .connect(
                target,
                query.source_id,
                addr("127.0.0.1:43078"),
                query.destination,
                WaitQueue::new(),
            )
            .unwrap();
        if held_by_driver {
            h.pump();
        }
        let backend = h.backend.clone();
        let mut closing = Box::pin(backend.close_endpoints());
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(closing.as_mut().poll(&mut cx).is_pending());
        h.pump();
        assert_eq!(
            closing.as_mut().poll(&mut cx),
            Poll::Ready(Ok(wasixv2_vnet_web::SelectedCloseReport::default()))
        );
        assert!(
            h.io.sent.is_empty(),
            "an unaccepted connect owns no physical resource to close"
        );
        assert_eq!(stream.state(), wasixv2_vnet::StreamState::Closed);
        assert!(!stream.tcp_established());
        assert!(stream.poll(None).contains(PollMask::ERR | PollMask::HUP));
        let mut bytes = [0; 8];
        assert_eq!(stream.read(&mut bytes, false), Err(Errno::ECONNABORTED));
        assert_eq!(stream.read(&mut bytes, false), Ok(0));
        assert_eq!(stream.write(b"not accepted"), Err(Errno::EPIPE));
        assert_eq!(stream.provider_local_addr(), Some(Err(Errno::ENETDOWN)));
        drop(stream);
        h.pump();
    }
}

#[test]
fn child_close_retires_its_pending_actual_address_without_poisoning_a_sibling() {
    let mut h = Harness::new(false);
    let net = h.net();
    let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
    socket.bind(addr("127.0.0.1:0"), false).unwrap();
    let local = socket.local_addr().unwrap();
    socket.listen(1).unwrap();
    h.pump();
    let (request, listener) = match h.io.sent[0] {
        Command::ListenReserved {
            request, socket, ..
        } => (request, socket),
        _ => unreachable!(),
    };
    h.event(Event::StreamListening {
        request,
        socket: listener,
        result: Ok(local),
    });
    let child =
        h.io.sent
            .iter()
            .find_map(|command| match command {
                Command::Accept { child, .. } => Some(*child),
                _ => None,
            })
            .unwrap();
    h.event(Event::Accepted {
        socket: listener,
        child,
        peer: addr("127.0.0.100:32002"),
    });
    let address_request =
        h.io.sent
            .iter()
            .find_map(|command| match command {
                Command::LocalAddr { request, socket } if *socket == child => Some(*request),
                _ => None,
            })
            .unwrap();
    let (sibling, _) = selected_stream(&mut h);
    drop(socket);
    h.pump();
    let close_for = |id| {
        h.io.sent
            .iter()
            .find_map(|command| match command {
                Command::CloseSelected { request, socket } if *socket == id => Some(*request),
                _ => None,
            })
            .unwrap()
    };
    let child_close = close_for(child);
    let parent_close = close_for(listener);
    h.event(Event::ProviderCloseAck {
        accept_pending: false,
        request: child_close,
        socket: child,
        result: Ok(()),
    });
    h.event(Event::LocalAddr {
        request: address_request,
        addr: local,
    });
    h.event(Event::Complete {
        request: address_request,
        result: Err(Errno::EIO),
    });
    assert_eq!(sibling.state(), wasixv2_vnet::StreamState::Established);
    assert_eq!(sibling.write(b"healthy"), Ok(7));
    h.event(Event::ProviderCloseAck {
        accept_pending: false,
        request: parent_close,
        socket: listener,
        result: Ok(()),
    });
}

#[test]
fn owner_close_with_a_live_wrapper_withdraws_full_pending_input_before_its_ack() {
    let mut h = Harness::new(true);
    let (stream, socket) = selected_stream(&mut h);
    // Four complete frames fill the existing 256 KiB RX queue. The fifth is
    // held by Driver::input and used to prevent all later control reception.
    for _ in 0..5 {
        h.event(Event::Data {
            socket,
            data: vec![1; 65536],
        });
    }
    let backend = h.backend.clone();
    let mut closing = Box::pin(backend.close_endpoints());
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(closing.as_mut().poll(&mut cx).is_pending());
    h.pump();
    let reset =
        h.io.sent
            .iter()
            .position(|command| matches!(command, Command::Reset { socket: id } if *id == socket))
            .unwrap();
    let (close_index, request) =
        h.io.sent
            .iter()
            .enumerate()
            .find_map(|(index, command)| match command {
                Command::CloseSelected {
                    request,
                    socket: id,
                } if *id == socket => Some((index, *request)),
                _ => None,
            })
            .unwrap();
    assert!(reset < close_index);
    assert!(closing.as_mut().poll(&mut cx).is_pending());
    h.event(Event::ProviderCloseAck {
        accept_pending: false,
        request,
        socket,
        result: Ok(()),
    });
    assert_eq!(
        closing.as_mut().poll(&mut cx),
        Poll::Ready(Ok(wasixv2_vnet_web::SelectedCloseReport::default()))
    );
    assert_eq!(stream.state(), wasixv2_vnet::StreamState::Closed);
    // Only the pending, unaccepted frame was withdrawn. The wrapper and its
    // already admitted bytes remain owned by the consumer until it drops them.
    let mut bytes = [0; 8];
    assert_eq!(stream.read(&mut bytes, false), Ok(8));
    assert_eq!(bytes, [1; 8]);
}

#[test]
fn selected_close_preempts_an_unaccepted_open_at_the_existing_ordinary_bound() {
    let mut h = Harness::limited(true, false, 128);
    h.io.open_limit = Some(63);
    let provider = h.provider();
    let mut bindings = Vec::new();
    for _ in 0..64 {
        bindings.push(
            provider
                .bind(request(EndpointBindPurpose::Bind), WaitQueue::new())
                .unwrap()
                .unwrap(),
        );
        h.pump();
    }
    assert_eq!(h.io.sent.len(), 63);
    let (old_request, old_socket) = match h.io.sent[0] {
        Command::BindStream {
            request, socket, ..
        } => (request, socket),
        _ => unreachable!(),
    };
    drop(bindings.remove(0));
    h.pump();
    let (close, socket) = match h.io.sent[63] {
        Command::CloseSelected { request, socket } => (request, socket),
        ref command => panic!("close must bypass the unaccepted 64th open: {command:?}"),
    };
    assert_eq!(socket, old_socket);
    assert!(h.io.revoked.contains(&old_socket));
    assert_eq!(h.io.opening.len(), 63);
    assert_eq!(
        h.io.sent
            .iter()
            .filter(|command| matches!(command, Command::BindStream { .. }))
            .count(),
        64
    );
    h.event(Event::ProviderCloseAck {
        accept_pending: false,
        request: close,
        socket,
        result: Ok(()),
    });
    // A canceled factory's late result cannot revive it or poison its sibling.
    h.event(Event::StreamBound {
        request: old_request,
        socket,
        result: Ok(addr("0.0.0.0:42050")),
    });
    let (request, socket) = match h.io.sent.last().unwrap() {
        Command::BindStream {
            request, socket, ..
        } => (*request, *socket),
        _ => unreachable!(),
    };
    h.event(Event::StreamBound {
        request,
        socket,
        result: Ok(addr("0.0.0.0:42051")),
    });
    assert_eq!(
        bindings.last().unwrap().local_addr(),
        Ok(addr("0.0.0.0:42051"))
    );
}

#[test]
fn a_preempted_actual_address_query_keeps_its_original_identity_and_owner() {
    let mut h = Harness::new(true);
    let (stream, old_socket) = selected_stream(&mut h);
    let bound = h
        .provider()
        .bind(request(EndpointBindPurpose::Bind), WaitQueue::new())
        .unwrap()
        .unwrap();
    h.pump();
    let (opening, socket) = match h.io.sent.last().unwrap() {
        Command::BindStream {
            request, socket, ..
        } => (*request, *socket),
        _ => unreachable!(),
    };
    h.io.blocked_local_addr = true;
    h.event(Event::Complete {
        request: opening,
        result: Ok(()),
    });
    assert_eq!(bound.local_addr(), Err(Errno::EAGAIN));
    drop(stream);
    h.pump();
    let close = h
        .io
        .sent
        .iter()
        .find_map(|command| match command {
            Command::CloseSelected { request, socket } if *socket == old_socket => Some(*request),
            _ => None,
        })
        .unwrap();
    h.event(Event::ProviderCloseAck {
        accept_pending: false,
        request: close,
        socket: old_socket,
        result: Ok(()),
    });
    h.io.blocked_local_addr = false;
    h.pump();
    let addresses: Vec<_> =
        h.io.sent
            .iter()
            .filter_map(|command| match command {
                Command::LocalAddr {
                    request,
                    socket: id,
                } if *id == socket => Some(*request),
                _ => None,
            })
            .collect();
    assert_eq!(addresses.len(), 1);
    h.event(Event::LocalAddr {
        request: addresses[0],
        addr: addr("0.0.0.0:42052"),
    });
    assert_eq!(bound.local_addr(), Ok(addr("0.0.0.0:42052")));
}

#[test]
fn selected_close_ack_passes_a_different_live_full_receive_frame() {
    let mut h = Harness::new(true);
    let (full, full_socket) = selected_stream(&mut h);
    let (closing, close_socket) = selected_stream(&mut h);
    for _ in 0..5 {
        h.event(Event::Data {
            socket: full_socket,
            data: vec![7; 65536],
        });
    }
    drop(closing);
    h.pump();
    let request = h
        .io
        .sent
        .iter()
        .find_map(|command| match command {
            Command::CloseSelected { request, socket } if *socket == close_socket => Some(*request),
            _ => None,
        })
        .unwrap();
    h.event(Event::ProviderCloseAck {
        accept_pending: false,
        request,
        socket: close_socket,
        result: Err(Errno::EIO),
    });
    assert!(
        h.io.events.is_empty(),
        "actual CloseACK must not wait on unrelated guest RX"
    );
    assert_eq!(full.state(), wasixv2_vnet::StreamState::Established);
    let mut received = vec![0; 256 * 1024];
    assert_eq!(full.read(&mut received, false), Ok(received.len()));
    assert!(received.iter().all(|byte| *byte == 7));
    h.pump();
    let mut remaining = vec![0; 65536];
    assert_eq!(full.read(&mut remaining, false), Ok(remaining.len()));
    assert!(
        remaining.iter().all(|byte| *byte == 7),
        "pending payload was not discarded for sibling cleanup"
    );
    assert_eq!(full.write(b"healthy"), Ok(7));
    h.pump();
    assert!(h.io.sent.iter().any(|command| matches!(command, Command::Send { socket, data, .. } if *socket == full_socket && data == b"healthy")));
}

#[test]
fn exact_late_accept_receipt_outlives_parent_or_child_close_and_releases_its_bounded_slot() {
    for child_first in [false, true] {
        let mut h = Harness::limited(false, true, 2);
        let (socket, listener, child, local) = selected_listener(&mut h);
        drop(socket);
        h.pump();
        let parent_request = selected_close_request(&h, listener);
        let child_request = selected_close_request(&h, child);
        let parent = Event::ProviderCloseAck {
            accept_pending: false,
            request: parent_request,
            socket: listener,
            result: Ok(()),
        };
        let child_ack = Event::ProviderCloseAck {
            accept_pending: true,
            request: child_request,
            socket: child,
            result: Ok(()),
        };
        if child_first {
            h.event(child_ack);
            h.event(parent);
        } else {
            h.event(parent);
            h.event(child_ack);
        }
        // Only the exact outstanding notification still owns the closed child.
        // It consumes the SAME max_sockets budget instead of an unbounded map.
        let (sibling, _) = selected_stream(&mut h);
        assert!(matches!(
            h.provider()
                .bind(request(EndpointBindPurpose::Bind), WaitQueue::new()),
            Err(Errno::ENOBUFS)
        ));
        h.event(Event::AcceptedTo {
            socket: listener,
            child,
            peer: addr("127.0.0.1:32010"),
            local,
        });
        assert_eq!(sibling.state(), wasixv2_vnet::StreamState::Established);
        assert_eq!(sibling.write(b"healthy"), Ok(7));
        assert!(
            h.provider()
                .bind(request(EndpointBindPurpose::Bind), WaitQueue::new())
                .unwrap()
                .is_some(),
            "consuming the exact late receipt releases the metadata slot"
        );
    }
}

#[test]
fn an_already_consumed_accept_receipt_is_not_recreated_by_close_ack() {
    let mut h = Harness::limited(false, true, 2);
    let (socket, listener, child, local) = selected_listener(&mut h);
    drop(socket);
    h.pump();
    let parent_request = selected_close_request(&h, listener);
    let child_request = selected_close_request(&h, child);
    h.event(Event::AcceptedTo {
        socket: listener,
        child,
        peer: addr("127.0.0.1:32011"),
        local,
    });
    h.event(Event::ProviderCloseAck {
        accept_pending: true,
        request: child_request,
        socket: child,
        result: Ok(()),
    });
    h.event(Event::ProviderCloseAck {
        accept_pending: false,
        request: parent_request,
        socket: listener,
        result: Ok(()),
    });
    let first = h
        .provider()
        .bind(request(EndpointBindPurpose::Bind), WaitQueue::new())
        .unwrap()
        .unwrap();
    let second = h
        .provider()
        .bind(request(EndpointBindPurpose::Bind), WaitQueue::new())
        .unwrap()
        .unwrap();
    assert!(matches!(
        h.provider()
            .bind(request(EndpointBindPurpose::Bind), WaitQueue::new()),
        Err(Errno::ENOBUFS)
    ));
    drop((first, second));
}

#[test]
fn withdrawn_unfulfilled_accept_credits_do_not_accumulate_metadata_tombstones() {
    let mut h = Harness::limited(false, true, 2);
    for _ in 0..4 {
        let (socket, listener, child, _) = selected_listener(&mut h);
        drop(socket);
        h.pump();
        let child_request = selected_close_request(&h, child);
        let parent_request = selected_close_request(&h, listener);
        h.event(Event::ProviderCloseAck {
            accept_pending: false,
            request: child_request,
            socket: child,
            result: Ok(()),
        });
        h.event(Event::ProviderCloseAck {
            accept_pending: false,
            request: parent_request,
            socket: listener,
            result: Ok(()),
        });
    }
}

#[test]
fn a_late_accept_must_match_its_exact_listener_receipt_before_any_delivery() {
    let mut h = Harness::limited(false, true, 2);
    let (socket, listener, child, local) = selected_listener(&mut h);
    h.io.events.push_back(Event::AcceptedTo {
        socket: listener + 10000,
        child,
        peer: addr("127.0.0.1:32012"),
        local,
    });
    assert_eq!(
        h.driver.poll(
            &mut Context::from_waker(futures_util::task::noop_waker_ref()),
            &mut h.io
        ),
        Poll::Ready(Err(Errno::EPROTO))
    );
    assert!(
        socket.accept().is_err(),
        "a mismatched notification never enters the guest accept queue"
    );
}

#[test]
fn old_wire_close_reports_local_success_without_claiming_remote_physical_join() {
    let mut h = Harness::new(true);
    let (stream, socket) = selected_stream(&mut h);
    drop(stream);
    h.pump();
    let request = selected_close_request(&h, socket);
    let backend = h.backend.clone();
    let mut closing = Box::pin(backend.close_endpoints());
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(closing.as_mut().poll(&mut cx).is_pending());
    // Original Classic ResponseType::None, not a new relay capability/tag.
    h.event(Event::Complete {
        request,
        result: Ok(()),
    });
    assert_eq!(
        closing.as_mut().poll(&mut cx),
        Poll::Ready(Ok(wasixv2_vnet_web::SelectedCloseReport {
            remote_cleanup_unconfirmed: true,
        }))
    );
}

#[test]
fn a_never_returning_remote_create_does_not_block_joined_local_session_retirement() {
    let mut h = Harness::limited(true, false, 2);
    let bound = h
        .provider()
        .bind(request(EndpointBindPurpose::Bind), WaitQueue::new())
        .unwrap()
        .unwrap();
    h.pump();
    let socket = match h.io.sent[0] {
        Command::BindStream { socket, .. } => socket,
        _ => unreachable!(),
    };
    let backend = h.backend.clone();
    let mut closing = Box::pin(backend.close_endpoints());
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(closing.as_mut().poll(&mut cx).is_pending());
    h.pump();
    let close_request = selected_close_request(&h, socket);
    // The embedder supplies this only AFTER the entire captured local callback
    // session has cut off/joined producers. No remote response/ACK exists.
    h.io.events.push_back(Event::LocalCloseUnconfirmed {
        request: close_request,
        socket,
        error: None,
    });
    h.io.events.push_back(Event::LocalCloseUnconfirmed {
        request: close_request,
        socket,
        error: Some(Errno::EIO),
    });
    assert_eq!(h.driver.poll(&mut cx, &mut h.io), Poll::Ready(Ok(())));
    assert_eq!(
        closing.as_mut().poll(&mut cx),
        Poll::Ready(Ok(wasixv2_vnet_web::SelectedCloseReport {
            remote_cleanup_unconfirmed: true,
        }))
    );
    assert!(h.io.opening.is_empty());
    assert!(
        h.io.events.is_empty(),
        "the joined local session retires duplicate/queued notifications"
    );
    let mut cached_close = Box::pin(backend.close_endpoints());
    assert_eq!(
        cached_close.as_mut().poll(&mut cx),
        Poll::Ready(Ok(wasixv2_vnet_web::SelectedCloseReport {
            remote_cleanup_unconfirmed: true,
        }))
    );
    assert_eq!(bound.local_addr(), Err(Errno::ENETDOWN));
    // A stale notification from that joined old session cannot touch a new
    // generation/resource on the same backend. IDs remain the original IDs.
    h.driver = h.backend.reconnect(h.io.caps).unwrap();
    let replacement = h
        .provider()
        .bind(request(EndpointBindPurpose::Bind), WaitQueue::new())
        .unwrap()
        .unwrap();
    h.pump();
    let (new_request, new_socket) = match h.io.sent.last().unwrap() {
        Command::BindStream {
            request, socket, ..
        } => (*request, *socket),
        _ => unreachable!(),
    };
    h.event(Event::LocalCloseUnconfirmed {
        request: close_request,
        socket,
        error: Some(Errno::EIO),
    });
    h.event(Event::StreamBound {
        request: new_request,
        socket: new_socket,
        result: Ok(addr("0.0.0.0:43080")),
    });
    assert_eq!(replacement.local_addr(), Ok(addr("0.0.0.0:43080")));
    assert_eq!(bound.local_addr(), Err(Errno::ENETDOWN));
    let mut new_close = Box::pin(backend.close_endpoints());
    assert!(new_close.as_mut().poll(&mut cx).is_pending());
    h.pump();
    let new_close_request = selected_close_request(&h, new_socket);
    h.event(Event::ProviderCloseAck {
        accept_pending: false,
        request: new_close_request,
        socket: new_socket,
        result: Ok(()),
    });
    assert_eq!(
        new_close.as_mut().poll(&mut cx),
        Poll::Ready(Ok(wasixv2_vnet_web::SelectedCloseReport::default())),
        "a new generation never reuses the retired owner's unconfirmed report"
    );
    drop(bound);
}

#[test]
fn a_late_remote_create_is_cleaned_up_on_the_same_id_and_keeps_the_first_errno() {
    let mut h = Harness::new(true);
    let bound = h
        .provider()
        .bind(request(EndpointBindPurpose::Bind), WaitQueue::new())
        .unwrap()
        .unwrap();
    h.pump();
    let (opening, socket) = match h.io.sent[0] {
        Command::BindStream {
            request, socket, ..
        } => (request, socket),
        _ => unreachable!(),
    };
    let backend = h.backend.clone();
    let mut closing = Box::pin(backend.close_endpoints());
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(closing.as_mut().poll(&mut cx).is_pending());
    h.pump();
    let first_close = selected_close_request(&h, socket);
    h.event(Event::Complete {
        request: first_close,
        result: Err(Errno::EBADF),
    });
    assert_eq!(
        closing.as_mut().poll(&mut cx),
        Poll::Ready(Err(Errno::EBADF))
    );
    // The original, still-owned operation finally identifies its real socket.
    // This schedules cleanup only, never a second bind or guest readiness.
    h.event(Event::Complete {
        request: opening,
        result: Ok(()),
    });
    let late_close = selected_close_request(&h, socket);
    assert_ne!(late_close, first_close);
    assert_eq!(
        h.io.sent
            .iter()
            .filter(|command| matches!(command, Command::BindStream { .. }))
            .count(),
        1
    );
    assert!(
        !h.io
            .sent
            .iter()
            .any(|command| matches!(command, Command::LocalAddr { .. }))
    );
    h.io.events.push_back(Event::LocalCloseUnconfirmed {
        request: late_close,
        socket,
        error: Some(Errno::EIO),
    });
    assert_eq!(
        h.driver.poll(&mut cx, &mut h.io),
        Poll::Ready(Err(Errno::EBADF))
    );
    let mut final_close = Box::pin(backend.close_endpoints());
    assert_eq!(
        final_close.as_mut().poll(&mut cx),
        Poll::Ready(Err(Errno::EBADF))
    );
    assert_eq!(bound.local_addr(), Err(Errno::EBADF));
}

#[test]
fn local_session_cutoff_retires_queued_late_accepts_without_delivering_or_waiting_on_them() {
    let mut h = Harness::limited(false, true, 3);
    let (full, full_socket) = selected_stream(&mut h);
    let (socket, listener, child, local) = selected_listener(&mut h);
    for _ in 0..5 {
        h.event(Event::Data {
            socket: full_socket,
            data: vec![9; 65536],
        });
    }
    drop(socket);
    h.pump();
    let child_request = selected_close_request(&h, child);
    // Pending accepted metadata is ordinary, while local-close has its reserved
    // slot. The event certifies the captured local producer scope is joined.
    h.io.events.push_back(Event::AcceptedTo {
        socket: listener,
        child,
        peer: addr("127.0.0.1:32013"),
        local,
    });
    h.io.events.push_back(Event::LocalCloseUnconfirmed {
        request: child_request,
        socket: child,
        error: None,
    });
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    assert_eq!(h.driver.poll(&mut cx, &mut h.io), Poll::Ready(Ok(())));
    assert!(
        h.io.events.is_empty(),
        "owned transport close retires its queued metadata"
    );
    assert_eq!(full.state(), wasixv2_vnet::StreamState::Closed);
    let mut retained = [0; 8];
    assert_eq!(full.read(&mut retained, false), Ok(8));
    assert_eq!(retained, [9; 8]);
}

#[test]
fn local_unconfirmed_result_requires_the_exact_admitted_close_request() {
    let mut h = Harness::new(true);
    let (stream, socket) = selected_stream(&mut h);
    drop(stream);
    h.pump();
    let real = selected_close_request(&h, socket);
    h.io.events.push_back(Event::LocalCloseUnconfirmed {
        request: real + 10000,
        socket,
        error: None,
    });
    assert_eq!(
        h.driver.poll(
            &mut Context::from_waker(futures_util::task::noop_waker_ref()),
            &mut h.io
        ),
        Poll::Ready(Err(Errno::EPROTO))
    );
}

#[test]
fn selected_close_drains_inflight_send_past_unrelated_live_full_receive() {
    let mut h = Harness::new(true);
    let (full, full_socket) = selected_stream(&mut h);
    let (closing, close_socket) = selected_stream(&mut h);
    assert_eq!(closing.write(b"accepted"), Ok(8));
    h.pump();
    let send =
        h.io.sent
            .iter()
            .find_map(|command| match command {
                Command::Send {
                    request,
                    socket,
                    data,
                } if *socket == close_socket => {
                    assert_eq!(data, b"accepted");
                    Some(*request)
                }
                _ => None,
            })
            .unwrap();
    for _ in 0..5 {
        h.event(Event::Data {
            socket: full_socket,
            data: vec![7; 65536],
        });
    }
    drop(closing);
    h.pump();
    assert!(!h.io.sent.iter().any(|command| matches!(command, Command::CloseSelected { socket, .. } if *socket == close_socket)),
        "normal close must first drain its accepted TX");
    h.event(Event::Sent {
        request: send,
        socket: close_socket,
        amount: 8,
    });
    let close = h.io.sent.iter().find_map(|command| match command {
        Command::CloseSelected { request, socket } if *socket == close_socket => Some(*request),
        _ => None,
    }).expect("the exact accepted Send receipt must progress without requiring the unrelated live sibling to read");
    assert!(
        !h.io
            .sent
            .iter()
            .any(|command| matches!(command, Command::Reset { socket } if *socket == close_socket)),
        "normal accepted-prefix drain is not owner cancellation"
    );
    h.event(Event::ProviderCloseAck {
        request: close,
        socket: close_socket,
        accept_pending: false,
        result: Ok(()),
    });
    assert_eq!(full.state(), wasixv2_vnet::StreamState::Established);
    let mut prefix = vec![0; 256 * 1024];
    assert_eq!(full.read(&mut prefix, false), Ok(prefix.len()));
    assert!(prefix.iter().all(|byte| *byte == 7));
    h.pump();
    let mut remainder = vec![0; 65536];
    assert_eq!(full.read(&mut remainder, false), Ok(remainder.len()));
    assert!(remainder.iter().all(|byte| *byte == 7));
    assert_eq!(full.write(b"healthy"), Ok(7));
}

#[test]
fn selected_normal_close_retries_eagain_after_actual_writable_past_full_sibling_rx() {
    let mut h = Harness::new(true);
    let (full, full_socket) = selected_stream(&mut h);
    let (stream, socket) = selected_stream(&mut h);
    stream.write(b"accepted").unwrap();
    h.pump();
    let send = |h: &Harness| {
        h.io.sent
            .iter()
            .rev()
            .find_map(|command| match command {
                Command::Send {
                    request,
                    socket: actual,
                    data,
                } if *actual == socket => Some((*request, data.clone())),
                _ => None,
            })
            .unwrap()
    };
    let first = send(&h);
    assert_eq!(first.1, b"accepted");
    for _ in 0..5 {
        h.event(Event::Data {
            socket: full_socket,
            data: vec![7; 65536],
        });
    }
    drop(stream);
    h.pump();
    h.event(Event::SendError {
        request: first.0,
        socket,
        error: Errno::EAGAIN,
    });
    assert_eq!(
        send(&h).0,
        first.0,
        "EAGAIN waits actual writable; it does not spin or replay accepted bytes"
    );
    h.event(Event::Writable { socket });
    let second = send(&h);
    assert_ne!(second.0, first.0);
    assert_eq!(second.1, b"accepted");
    h.event(Event::Sent {
        request: second.0,
        socket,
        amount: 4,
    });
    let third = send(&h);
    assert_ne!(third.0, second.0);
    assert_eq!(third.1, b"pted");
    h.event(Event::Sent {
        request: third.0,
        socket,
        amount: 4,
    });
    let close = selected_close_request(&h, socket);
    assert!(
        !h.io.sent.iter().any(
            |command| matches!(command, Command::Reset { socket: actual } if *actual == socket)
        )
    );
    h.event(Event::ProviderCloseAck {
        request: close,
        socket,
        accept_pending: false,
        result: Ok(()),
    });
    let mut prefix = vec![0; 256 * 1024];
    assert_eq!(full.read(&mut prefix, false), Ok(prefix.len()));
    assert!(prefix.iter().all(|byte| *byte == 7));
    h.pump();
    let mut suffix = vec![0; 65536];
    assert_eq!(full.read(&mut suffix, false), Ok(suffix.len()));
    assert!(suffix.iter().all(|byte| *byte == 7));
    assert_eq!(full.write(b"healthy"), Ok(7));
}

#[test]
fn exact_option_completion_error_and_canceled_late_ack_progress_past_full_live_sibling_rx() {
    use std::sync::Mutex;
    use wasixv2_abi::{SocketLevel, TcpOption};
    let mut h = Harness::configured(true, false, 8, true);
    let (full, full_socket) = selected_stream(&mut h);
    let (stream, socket) = selected_stream(&mut h);
    for _ in 0..5 {
        h.event(Event::Data {
            socket: full_socket,
            data: vec![7; 65536],
        });
    }
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut last = 0;
    let mut previous = None;
    for result in [Some(Ok(())), Some(Err(Errno::EPERM)), None] {
        let completed = results.clone();
        stream
            .start_options(
                vec![(
                    SocketLevel::SOL_TCP.0,
                    TcpOption::TCP_NODELAY.0,
                    1i32.to_le_bytes().to_vec(),
                )],
                Box::new(move |result| completed.lock().unwrap().push(result)),
            )
            .unwrap();
        h.pump();
        last =
            h.io.sent
                .iter()
                .rev()
                .find_map(|command| match command {
                    Command::SetOption {
                        request: Some(request),
                        socket: actual,
                        ..
                    } if *actual == socket => Some(*request),
                    _ => None,
                })
                .unwrap();
        if let Some(request) = previous {
            let before = results.lock().unwrap().len();
            h.event(Event::Complete {
                request,
                result: Ok(()),
            });
            assert_eq!(
                results.lock().unwrap().len(),
                before,
                "duplicate completed option cannot complete the new pending batch"
            );
        }
        if let Some(result) = result {
            h.event(Event::Complete {
                request: last,
                result,
            });
            previous = Some(last);
        }
    }
    assert_eq!(*results.lock().unwrap(), vec![Ok(()), Err(Errno::EPERM)]);
    drop(stream);
    h.pump();
    assert_eq!(
        *results.lock().unwrap(),
        vec![Ok(()), Err(Errno::EPERM), Err(Errno::ECANCELED)]
    );
    h.event(Event::Complete {
        request: last,
        result: Ok(()),
    });
    assert_eq!(
        results.lock().unwrap().len(),
        3,
        "late ACK cannot complete a canceled or replacement batch"
    );
    let close = selected_close_request(&h, socket);
    h.event(Event::ProviderCloseAck {
        request: close,
        socket,
        accept_pending: false,
        result: Ok(()),
    });
    let mut prefix = vec![0; 256 * 1024];
    assert_eq!(full.read(&mut prefix, false), Ok(prefix.len()));
    h.pump();
    let mut suffix = vec![0; 65536];
    assert_eq!(full.read(&mut suffix, false), Ok(suffix.len()));
    assert!(prefix.iter().chain(&suffix).all(|byte| *byte == 7));
    assert_eq!(full.state(), wasixv2_vnet::StreamState::Established);
}

#[test]
fn captured_writable_before_terminal_eagain_does_not_lose_the_only_edge_or_hang_normal_close() {
    let mut h = Harness::new(true);
    let (full, full_socket) = selected_stream(&mut h);
    let (stream, socket) = selected_stream(&mut h);
    stream.write(b"accepted").unwrap();
    h.pump();
    let send = |h: &Harness| {
        h.io.sent
            .iter()
            .rev()
            .find_map(|command| match command {
                Command::Send {
                    request,
                    socket: actual,
                    data,
                } if *actual == socket => Some((*request, data.clone())),
                _ => None,
            })
            .unwrap()
    };
    let first = send(&h);
    // Arming readiness for the actual send must not reduce existing local
    // bounded-buffer writability while a provider receipt is merely pending.
    assert!(stream.poll(None).contains(PollMask::OUT));
    for _ in 0..5 {
        h.event(Event::Data {
            socket: full_socket,
            data: vec![7; 65536],
        });
    }
    drop(stream);
    h.pump();
    // The actual JS Writable notification can beat decoding of an EAGAIN
    // already delivered into Rpc. There may be NO second Writable edge.
    h.event(Event::Writable { socket });
    assert_eq!(
        send(&h).0,
        first.0,
        "a readiness edge does not complete the actual inflight send"
    );
    h.event(Event::SendError {
        request: first.0,
        socket,
        error: Errno::EAGAIN,
    });
    let retry = send(&h);
    assert_ne!(
        retry.0, first.0,
        "terminal EAGAIN must preserve the later readiness edge"
    );
    assert_eq!(retry.1, b"accepted");
    h.event(Event::Sent {
        request: retry.0,
        socket,
        amount: 8,
    });
    let close = selected_close_request(&h, socket);
    assert!(
        !h.io.sent.iter().any(
            |command| matches!(command, Command::Reset { socket: actual } if *actual == socket)
        )
    );
    h.event(Event::ProviderCloseAck {
        request: close,
        socket,
        accept_pending: false,
        result: Ok(()),
    });
    let mut prefix = vec![0; 256 * 1024];
    assert_eq!(full.read(&mut prefix, false), Ok(prefix.len()));
    h.pump();
    let mut suffix = vec![0; 65536];
    assert_eq!(full.read(&mut suffix, false), Ok(suffix.len()));
    assert!(prefix.iter().chain(&suffix).all(|byte| *byte == 7));
    assert_eq!(full.write(b"healthy"), Ok(7));
}
