//! Same canonical Net/Driver harness as selected.rs, for stock peer-only UDP.
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
};
use wasixv2_abi::{Errno, MsgFlags, SocketLevel, SocketOption};
use wasixv2_vnet::{
    DatagramReadback, DatagramReadbackValue, Domain, Net, NetConfig, Network, SendMsg, Socket,
    SocketKind,
};
use wasixv2_vnet_web::{
    Capabilities, Command, Config, DatagramValue, Driver, Event, SocketControl, Transport,
    WebBackend,
};
fn address(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
struct Mock {
    caps: Capabilities,
    commands: Vec<Command>,
    events: VecDeque<Event>,
    hold_bind: bool,
}
impl Transport for Mock {
    fn capabilities(&self) -> Capabilities {
        self.caps
    }
    fn poll_send(&mut self, _: &mut Context<'_>, command: &Command) -> Poll<Result<(), Errno>> {
        if self.hold_bind && matches!(command, Command::BindDatagram { .. }) {
            return Poll::Pending;
        }
        self.commands.push(command.clone());
        Poll::Ready(Ok(()))
    }
    fn poll_recv(&mut self, _: &mut Context<'_>) -> Poll<Result<Event, Errno>> {
        self.events
            .pop_front()
            .map_or(Poll::Pending, |event| Poll::Ready(Ok(event)))
    }
    fn close(&mut self) {
        self.events.clear();
    }
}
struct Harness {
    driver: Driver,
    io: Mock,
    net: Arc<Net>,
    backend: Arc<WebBackend>,
}
impl Harness {
    fn new() -> Self {
        let caps = Capabilities {
            selected_endpoints: true,
            selected_bind: true,
            selected_external: true,
            async_options: true,
            ..Capabilities::classic(true)
        };
        let (backend, driver) = WebBackend::new(Config::default(), caps).unwrap();
        let net = Net::new(
            NetConfig::host_default(),
            Some(backend.clone().with_namespace_endpoints()),
        );
        Self {
            driver,
            net,
            backend,
            io: Mock {
                caps,
                commands: vec![],
                events: VecDeque::new(),
                hold_bind: false,
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
    fn bind(&mut self, port: u16) -> (Arc<dyn Socket>, u64) {
        let socket = self
            .net
            .socket(Domain::Inet, SocketKind::Datagram, 0, 1000)
            .unwrap();
        let admission = socket
            .bind_admission(address("0.0.0.0:0"), false)
            .unwrap()
            .unwrap();
        assert_eq!(admission.complete_result(), None);
        self.pump();
        let Command::BindDatagram {
            request,
            socket: id,
            bind,
        } = self.io.commands.last().unwrap().clone()
        else {
            panic!("selected bind must retain literal UDP request")
        };
        assert_eq!(bind.requested, address("0.0.0.0:0"));
        self.event(Event::Complete {
            request,
            result: Ok(()),
        });
        let Command::LocalAddr { request, .. } = self.io.commands.last().unwrap().clone() else {
            panic!("port zero must query SAME actual resource")
        };
        self.event(Event::LocalAddr {
            request,
            addr: SocketAddr::from(([0, 0, 0, 0], port)),
        });
        assert_eq!(admission.complete_result(), Some(Ok(())));
        (socket, id)
    }
}
#[test]
fn selected_udp_bind_uses_actual_port_and_same_source_only_receive_queue() {
    let mut h = Harness::new();
    let (socket, id) = h.bind(46021);
    let read = socket
        .datagram_readback_admission(DatagramReadback::Local)
        .unwrap()
        .unwrap();
    assert_eq!(read.complete_result(), None);
    h.pump();
    let Command::DatagramReadback {
        request,
        socket: owner,
        query,
    } = h.io.commands.last().unwrap().clone()
    else {
        panic!()
    };
    assert_eq!((owner, query), (id, DatagramReadback::Local));
    h.event(Event::LocalAddr {
        request,
        addr: address("127.0.0.1:46021"),
    });
    assert_eq!(
        read.complete_result(),
        Some(Ok(DatagramReadbackValue::Local(address("127.0.0.1:46021"))))
    );
    h.event(Event::Datagram {
        socket: id,
        data: vec![1, 2, 3],
        addr: address("192.0.2.10:99"),
    });
    let mut small = [0; 2];
    let peek = socket.recv(&mut small, MsgFlags::MSG_PEEK).unwrap();
    assert_eq!(
        (peek.len, peek.full_len, peek.from),
        (2, 3, Some(address("192.0.2.10:99")))
    );
    assert_eq!(small, [1, 2]);
    assert_eq!(
        socket.recv(&mut small, MsgFlags::empty()).unwrap().full_len,
        3
    );
    h.event(Event::Datagram {
        socket: id,
        data: vec![],
        addr: address("192.0.2.10:99"),
    });
    assert_eq!(socket.recv(&mut [], MsgFlags::empty()).unwrap().full_len, 0);
}
#[test]
fn queued_udp_setter_precedes_exact_readback_and_preserves_provider_error() {
    let mut h = Harness::new();
    let (socket, id) = h.bind(46022);
    socket
        .set_option(
            SocketLevel::SOL_SOCKET.0,
            SocketOption::SO_BROADCAST.0,
            &1i32.to_le_bytes(),
        )
        .unwrap();
    let read = socket
        .datagram_readback_admission(DatagramReadback::Broadcast)
        .unwrap()
        .unwrap();
    assert_eq!(read.complete_result(), None);
    h.pump();
    let Command::SetDatagramQueued {
        dispatch,
        socket: owner,
        control: SocketControl::Broadcast(true),
    } = h.io.commands.last().unwrap().clone()
    else {
        panic!("queued setter waits its local dispatch");
    };
    assert_eq!(owner, id);
    assert!(
        !h.io
            .commands
            .iter()
            .any(|command| matches!(command, Command::DatagramReadback { .. }))
    );
    h.event(Event::DatagramDispatched {
        request: dispatch,
        socket: id,
        result: Ok(()),
    });
    let commands = &h.io.commands;
    let Command::DatagramReadback {
        request,
        socket: owner,
        ..
    } = commands.last().unwrap().clone()
    else {
        panic!()
    };
    assert_eq!(owner, id);
    h.event(Event::Complete {
        request,
        result: Err(Errno::EACCES),
    });
    assert_eq!(read.complete_result(), Some(Err(Errno::EACCES)));
}
#[test]
fn driver_cutoff_settles_queued_and_admitted_readbacks_without_foreign_result() {
    let mut h = Harness::new();
    let (socket, _) = h.bind(46023);
    let admitted = socket
        .datagram_readback_admission(DatagramReadback::Ttl)
        .unwrap()
        .unwrap();
    assert_eq!(admitted.complete_result(), None);
    h.pump();
    let queued = socket
        .datagram_readback_admission(DatagramReadback::MulticastTtlV4)
        .unwrap()
        .unwrap();
    assert_eq!(queued.complete_result(), None);
    drop(h);
    assert_eq!(admitted.complete_result(), Some(Err(Errno::ECONNABORTED)));
    assert_eq!(queued.complete_result(), Some(Err(Errno::ECONNABORTED)));
}
#[test]
fn exact_typed_udp_reply_completes_the_captured_query() {
    let mut h = Harness::new();
    let (socket, _) = h.bind(46024);
    let read = socket
        .datagram_readback_admission(DatagramReadback::Ttl)
        .unwrap()
        .unwrap();
    assert_eq!(read.complete_result(), None);
    h.pump();
    let Command::DatagramReadback { request, .. } = h.io.commands.last().unwrap().clone() else {
        panic!()
    };
    h.event(Event::DatagramValue {
        request,
        value: DatagramValue::Ttl(37),
    });
    assert_eq!(
        read.complete_result(),
        Some(Ok(DatagramReadbackValue::Ttl(37)))
    );
}
#[test]
fn stock_getter_opcodes_and_scalar_response_bytes_match_original_protocol() {
    use wasixv2_vnet_web::codec;
    for (query, tag) in [
        (DatagramReadback::Ttl, 28u32),
        (DatagramReadback::Broadcast, 47),
        (DatagramReadback::MulticastLoopV4, 49),
        (DatagramReadback::MulticastLoopV6, 51),
        (DatagramReadback::MulticastTtlV4, 53),
        (DatagramReadback::Local, 25),
        (DatagramReadback::Peer, 26),
    ] {
        let mut bytes = 1u32.to_le_bytes().to_vec();
        bytes.extend(9u64.to_le_bytes());
        bytes.extend(tag.to_le_bytes());
        bytes.push(1);
        bytes.extend(17u64.to_le_bytes());
        assert_eq!(
            codec::encode(&Command::DatagramReadback {
                request: 17,
                socket: 9,
                query
            })
            .unwrap(),
            bytes
        );
    }
    let mut flag = 0u32.to_le_bytes().to_vec();
    flag.extend(17u64.to_le_bytes());
    flag.extend(4u32.to_le_bytes());
    flag.push(1);
    assert!(matches!(
        codec::decode(&flag),
        Ok(Event::DatagramValue {
            request: 17,
            value: DatagramValue::Flag(true)
        })
    ));
    let mut ttl = 0u32.to_le_bytes().to_vec();
    ttl.extend(18u64.to_le_bytes());
    ttl.extend(13u32.to_le_bytes());
    ttl.extend(37u32.to_le_bytes());
    assert!(matches!(
        codec::decode(&ttl),
        Ok(Event::DatagramValue {
            request: 18,
            value: DatagramValue::Ttl(37)
        })
    ));
    ttl.push(0);
    assert!(matches!(codec::decode(&ttl), Err(Errno::EPROTO)));
}

#[test]
fn accepted_udp_packet_and_setter_wait_local_dispatch_before_getter_without_remote_sent() {
    let mut h = Harness::new();
    let (socket, id) = h.bind(46026);
    socket
        .send(SendMsg {
            data: &[7, 8, 9],
            to: Some(address("192.0.2.9:9000")),
            flags: MsgFlags::empty(),
            control: &[],
            net_raw: false,
            now: std::time::Duration::ZERO,
        })
        .unwrap();
    socket
        .set_option(
            SocketLevel::SOL_SOCKET.0,
            SocketOption::SO_BROADCAST.0,
            &1i32.to_le_bytes(),
        )
        .unwrap();
    let read = socket
        .datagram_readback_admission(DatagramReadback::Broadcast)
        .unwrap()
        .unwrap();
    assert_eq!(read.complete_result(), None);
    h.pump();
    let Command::SendDatagramQueued {
        dispatch,
        socket: owner,
        data,
        addr,
    } = h.io.commands.last().unwrap().clone()
    else {
        panic!()
    };
    assert_eq!(owner, id);
    assert_eq!(data, [7, 8, 9]);
    assert_eq!(addr, address("192.0.2.9:9000"));
    let count = h.io.commands.len();
    h.pump();
    assert_eq!(h.io.commands.len(), count);
    // This is a LOCAL dispatch receipt. The stock server sends no normal Sent.
    h.event(Event::DatagramDispatched {
        request: dispatch,
        socket: id,
        result: Ok(()),
    });
    let Command::SetDatagramQueued {
        dispatch: second, ..
    } = h.io.commands.last().unwrap().clone()
    else {
        panic!()
    };
    h.event(Event::DatagramDispatched {
        request: second,
        socket: id,
        result: Ok(()),
    });
    let Command::DatagramReadback { request, .. } = h.io.commands.last().unwrap().clone() else {
        panic!()
    };
    h.event(Event::DatagramValue {
        request,
        value: DatagramValue::Flag(true),
    });
    assert_eq!(
        read.complete_result(),
        Some(Ok(DatagramReadbackValue::Flag(true)))
    );
}

#[test]
fn old_dispatch_receipt_after_same_bound_source_renewal_retires_only_its_prefix_and_keeps_sibling()
{
    for disconnect in [false, true] {
        let mut h = Harness::new();
        let (socket, id) = h.bind(47030);
        let (sibling, sibling_id) = h.bind(47031);
        let old = address("192.0.2.10:9000");
        let new = address("192.0.2.11:9001");
        socket
            .send(SendMsg {
                data: &[1, 2],
                to: Some(old),
                flags: MsgFlags::empty(),
                control: &[],
                net_raw: false,
                now: std::time::Duration::ZERO,
            })
            .unwrap();
        h.pump();
        let Command::SendDatagramQueued { dispatch, addr, .. } =
            h.io.commands.last().unwrap().clone()
        else {
            panic!()
        };
        assert_eq!(addr, old);
        socket.connect(new).unwrap();
        if disconnect {
            socket.disconnect().unwrap();
            socket.connect(new).unwrap();
        }
        assert_eq!(socket.peer_addr().unwrap(), new);
        socket
            .send(SendMsg {
                data: &[3, 4],
                to: None,
                flags: MsgFlags::empty(),
                control: &[],
                net_raw: false,
                now: std::time::Duration::ZERO,
            })
            .unwrap();
        sibling
            .send(SendMsg {
                data: &[5],
                to: Some(old),
                flags: MsgFlags::empty(),
                control: &[],
                net_raw: false,
                now: std::time::Duration::ZERO,
            })
            .unwrap();
        h.pump();
        h.event(Event::DatagramDispatched {
            request: dispatch,
            socket: id,
            result: Ok(()),
        });
        assert_eq!(socket.peer_addr().unwrap(), new);
        let sent =
            h.io.commands
                .iter()
                .filter_map(|command| match command {
                    Command::SendDatagramQueued {
                        dispatch,
                        socket,
                        data,
                        addr,
                    } => Some((*dispatch, *socket, data.clone(), *addr)),
                    _ => None,
                })
                .collect::<Vec<_>>();
        assert_eq!(
            sent.iter()
                .filter(|(_, owner, data, to)| *owner == id && data == &[1, 2] && *to == old)
                .count(),
            1,
            "accepted old prefix is never replayed"
        );
        let next = sent
            .iter()
            .find(|(_, owner, data, to)| *owner == id && data == &[3, 4] && *to == new)
            .unwrap();
        let other = sent
            .iter()
            .find(|(_, owner, data, _)| *owner == sibling_id && data == &[5])
            .unwrap();
        h.event(Event::DatagramDispatched {
            request: next.0,
            socket: id,
            result: Ok(()),
        });
        h.event(Event::DatagramDispatched {
            request: other.0,
            socket: sibling_id,
            result: Ok(()),
        });
        h.event(Event::Datagram {
            socket: sibling_id,
            data: vec![9],
            addr: old,
        });
        let mut byte = [0];
        assert_eq!(sibling.recv(&mut byte, MsgFlags::empty()).unwrap().len, 1);
        assert_eq!(byte, [9]);
    }
}

#[test]
fn sealed_owner_with_more_than_one_poll_budget_of_held_datagram_binds_never_replays_factory() {
    let mut h = Harness::new();
    h.io.hold_bind = true;
    let mut pending = Vec::new();
    for _ in 0..70 {
        let socket = h
            .net
            .socket(Domain::Inet, SocketKind::Datagram, 0, 1000)
            .unwrap();
        let bind = socket
            .bind_admission(address("0.0.0.0:0"), false)
            .unwrap()
            .unwrap();
        assert_eq!(bind.complete_result(), None);
        pending.push((socket, bind));
    }
    h.pump();
    assert!(h.io.commands.is_empty());
    let backend = h.backend.clone();
    let mut close = Box::pin(backend.close_endpoints());
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    use std::future::Future;
    assert!(close.as_mut().poll(&mut cx).is_pending());
    for _ in 0..4 {
        h.pump();
    }
    assert!(matches!(close.as_mut().poll(&mut cx), Poll::Ready(Ok(_))));
    h.io.hold_bind = false;
    for _ in 0..4 {
        h.pump();
    }
    assert!(
        h.io.commands.is_empty(),
        "cached command and cleanup entries cannot become physical BindDatagram work after seal, including across the 64-work yield"
    );
    drop(pending);
}
