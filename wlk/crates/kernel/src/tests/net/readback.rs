//! Optional peer-only UDP readback through the actual kernel and canonical Net.
use super::*;
use std::{
    future::Future,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use wasixv2_abi::{SaFlags, Sigaction, Signal, Sigset};
use wasixv2_syscalls::SysResult;
use wasixv2_vnet::endpoint::{
    EndpointBindRequest, EndpointBound, EndpointChoice, EndpointProvider, EndpointQuery,
    EndpointTarget,
};
use wasixv2_vnet::{
    Backend, BackendDatagram, BackendStream, DatagramReadback, DatagramReadbackValue, InboundSink,
    Net, NetConfig, Publication,
};

type ReadbackDone = Box<dyn FnOnce(Result<DatagramReadbackValue, Errno>) + Send>;
#[derive(Default)]
struct Datagram {
    pending: Mutex<Vec<(DatagramReadback, ReadbackDone)>>,
    inline: Mutex<Option<Result<DatagramReadbackValue, Errno>>>,
    starts: AtomicUsize,
}
impl Pollable for Datagram {
    fn poll(&self, _: Option<&mut PollTable<'_>>) -> PollMask {
        PollMask::OUT
    }
}
impl BackendDatagram for Datagram {
    fn send_to(&self, bytes: &[u8], _: SocketAddr) -> Result<usize, Errno> {
        Ok(bytes.len())
    }
    fn connect(&self, _: Option<SocketAddr>) -> Result<(), Errno> {
        Ok(())
    }
    fn take_error(&self) -> Option<Errno> {
        None
    }
    fn recv_from(&self, _: &mut [u8], _: bool) -> Result<(usize, usize, SocketAddr), Errno> {
        Err(Errno::EAGAIN)
    }
    fn input_len(&self) -> usize {
        0
    }
    fn start_readback(
        &self,
        query: DatagramReadback,
        done: ReadbackDone,
    ) -> Option<Result<(), Errno>> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        let inline = *self.inline.lock().unwrap();
        if let Some(value) = inline {
            done(value);
        } else {
            self.pending.lock().unwrap().push((query, done));
        }
        Some(Ok(()))
    }
}
struct Bound {
    local: SocketAddr,
    datagram: Arc<Datagram>,
    hooks: Arc<AtomicUsize>,
}
impl Pollable for Bound {
    fn poll(&self, _: Option<&mut PollTable<'_>>) -> PollMask {
        PollMask::OUT
    }
}
impl EndpointBound for Bound {
    fn local_addr(&self) -> Result<SocketAddr, Errno> {
        Ok(self.local)
    }
    fn peer_datagram(&self) -> Option<Arc<dyn BackendDatagram>> {
        self.hooks.fetch_add(1, Ordering::SeqCst);
        Some(self.datagram.clone())
    }
}
#[derive(Default)]
struct Provider {
    selected: AtomicBool,
    datagram: Arc<Datagram>,
    hooks: Arc<AtomicUsize>,
}
impl EndpointProvider for Provider {
    fn select(&self, _: &EndpointQuery) -> Result<EndpointChoice, Errno> {
        Ok(if self.selected.load(Ordering::SeqCst) {
            EndpointChoice::Provider(EndpointTarget::new(()))
        } else {
            EndpointChoice::Namespace
        })
    }
    fn bind(
        &self,
        request: EndpointBindRequest,
        _: WaitQueue,
    ) -> Result<Option<Arc<dyn EndpointBound>>, Errno> {
        let mut local = request.requested;
        local.set_port(49120);
        Ok(Some(Arc::new(Bound {
            local,
            datagram: self.datagram.clone(),
            hooks: self.hooks.clone(),
        })))
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
        panic!("readback must retain the admitted datagram, not allocate another")
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
fn configured() -> (Kernel, TaskId, FlatMemory, Arc<Provider>) {
    let provider = Arc::new(Provider::default());
    let net = Net::new(
        NetConfig::default(),
        Some(Arc::new(Adapter(provider.clone()))),
    );
    let (kernel, task, memory) =
        super::super::cred::machine_with(|kernel| kernel.with_network(net));
    (kernel, task, memory, provider)
}
fn bound(kernel: &Kernel, caller: &Caller<'_>, memory: &FlatMemory, family: AddressFamily) -> Fd {
    let fd = block_on(kernel.socket(caller, family, DGRAM, 0)).unwrap();
    let addr: SocketAddr = if family == AddressFamily::AF_INET6 {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse()
    .unwrap();
    let encoded = crate::socket::encode(addr);
    put(memory, 0x200, &encoded);
    assert_eq!(
        block_on(kernel.bind(caller, fd, GuestPtr::new(0x200), encoded.len() as u32)),
        Ok(0)
    );
    fd
}
fn ttl<'a>(
    kernel: &'a Kernel,
    caller: &'a Caller<'_>,
    fd: Fd,
) -> impl Future<Output = SysResult<i32>> + 'a {
    kernel.getsockopt(
        caller,
        fd,
        SocketLevel(0),
        2,
        GuestPtrMut::new(0x300),
        GuestPtrMut::new(0x2f0),
    )
}

#[test]
fn pending_signal_before_first_readback_poll_does_not_start_provider_work() {
    for signal in [Signal::SIGKILL, Signal::SIGSTOP] {
        let (kernel, task, memory, provider) = configured();
        let caller = Caller::new(task, &memory);
        let fd = bound(&kernel, &caller, &memory, AddressFamily::AF_INET);
        put(&memory, 0x2f0, &4u32.to_le_bytes());
        let readback = ttl(&kernel, &caller, fd);
        kernel.kill(task, signal).unwrap();
        assert_eq!(block_on(readback), Err(SysErr::Restart));
        assert_eq!(provider.datagram.starts.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn admitted_restartable_readback_returns_eintr_without_replay_or_late_copyout() {
    let (kernel, task, memory, provider) = configured();
    let caller = Caller::new(task, &memory);
    let fd = bound(&kernel, &caller, &memory, AddressFamily::AF_INET);
    let action = Sigaction {
        sa_handler: 7,
        sa_flags: SaFlags::SA_RESTART.0,
        sa_mask: Sigset { sig: [0; 2] },
    };
    block_on(write_value(&memory, GuestPtrMut::new(0x140), &action)).unwrap();
    assert_eq!(block_on(kernel.signal_callback_register(&caller, 3)), Ok(0));
    assert_eq!(
        block_on(kernel.rt_sigaction(
            &caller,
            Signal::SIGUSR1,
            GuestPtr::new(0x140),
            GuestPtrMut::NULL,
            8
        )),
        Ok(0)
    );
    put(&memory, 0x2f0, &4u32.to_le_bytes());
    put(&memory, 0x300, &[0xa5; 4]);
    let mut readback = Box::pin(ttl(&kernel, &caller, fd));
    assert!(readback.as_mut().now_or_never().is_none());
    assert_eq!(provider.datagram.starts.load(Ordering::SeqCst), 1);
    kernel.kill(task, Signal::SIGUSR1).unwrap();
    assert_eq!(block_on(readback), Err(SysErr::Errno(Errno::EINTR)));
    let (query, done) = provider.datagram.pending.lock().unwrap().remove(0);
    assert_eq!(query, DatagramReadback::Ttl);
    done(Ok(DatagramReadbackValue::Ttl(37)));
    assert_eq!(get(&memory, 0x300, 4), vec![0xa5; 4]);
    assert_eq!(provider.datagram.starts.load(Ordering::SeqCst), 1);
}

#[test]
fn inline_completed_errors_are_terminal_without_requery() {
    let (kernel, task, memory, provider) = configured();
    let caller = Caller::new(task, &memory);
    let fd = bound(&kernel, &caller, &memory, AddressFamily::AF_INET);
    for error in [Errno::EAGAIN, Errno::EACCES] {
        *provider.datagram.inline.lock().unwrap() = Some(Err(error));
        put(&memory, 0x2f0, &4u32.to_le_bytes());
        assert_eq!(
            block_on(ttl(&kernel, &caller, fd)),
            Err(SysErr::Errno(error))
        );
    }
    assert_eq!(provider.datagram.starts.load(Ordering::SeqCst), 2);
    assert_eq!(provider.hooks.load(Ordering::SeqCst), 1);
}

#[test]
fn bind_time_peer_role_survives_local_connect_disconnect_and_source_renewal() {
    for selected in [false, true] {
        let (kernel, task, memory, provider) = configured();
        provider.selected.store(selected, Ordering::SeqCst);
        let caller = Caller::new(task, &memory);
        let fd = bound(&kernel, &caller, &memory, AddressFamily::AF_INET);
        *provider.datagram.inline.lock().unwrap() = Some(Ok(DatagramReadbackValue::Ttl(37)));
        sockaddr(&memory, 0x240, 49121);
        assert_eq!(
            block_on(kernel.connect(&caller, fd, GuestPtr::new(0x240), 16)),
            Ok(0)
        );
        put(&memory, 0x2f0, &16u32.to_le_bytes());
        assert_eq!(
            block_on(kernel.getpeername(
                &caller,
                fd,
                GuestPtrMut::new(0x300),
                GuestPtrMut::new(0x2f0)
            )),
            Ok(0)
        );
        assert_eq!(
            read_sockaddr(&memory, 0x300),
            "127.0.0.1:49121".parse().unwrap()
        );
        assert_eq!(
            provider.datagram.starts.load(Ordering::SeqCst),
            0,
            "logical connected peer wins"
        );
        *provider.datagram.inline.lock().unwrap() = Some(Ok(DatagramReadbackValue::Local(
            "127.0.0.1:49120".parse().unwrap(),
        )));
        put(&memory, 0x2f0, &16u32.to_le_bytes());
        assert_eq!(
            block_on(kernel.getsockname(
                &caller,
                fd,
                GuestPtrMut::new(0x300),
                GuestPtrMut::new(0x2f0)
            )),
            Ok(0)
        );
        assert_eq!(
            read_sockaddr(&memory, 0x300),
            "127.0.0.1:49120".parse().unwrap()
        );
        *provider.datagram.inline.lock().unwrap() = Some(Ok(DatagramReadbackValue::Ttl(37)));
        put(&memory, 0x2f0, &4u32.to_le_bytes());
        assert_eq!(block_on(ttl(&kernel, &caller, fd)), Ok(0));
        assert_eq!(get(&memory, 0x300, 4), 37u32.to_le_bytes());
        put(&memory, 0x240, &[0; 16]);
        assert_eq!(
            block_on(kernel.connect(&caller, fd, GuestPtr::new(0x240), 16)),
            Ok(0)
        );
        *provider.datagram.inline.lock().unwrap() = Some(Ok(DatagramReadbackValue::Local(
            "127.0.0.1:49120".parse().unwrap(),
        )));
        put(&memory, 0x2f0, &16u32.to_le_bytes());
        assert_eq!(
            block_on(kernel.getsockname(
                &caller,
                fd,
                GuestPtrMut::new(0x300),
                GuestPtrMut::new(0x2f0)
            )),
            Ok(0)
        );
        assert_eq!(
            read_sockaddr(&memory, 0x300),
            "127.0.0.1:49120".parse().unwrap()
        );
        *provider.datagram.inline.lock().unwrap() = Some(Ok(DatagramReadbackValue::Ttl(37)));
        put(&memory, 0x2f0, &4u32.to_le_bytes());
        assert_eq!(block_on(ttl(&kernel, &caller, fd)), Ok(0));
        assert_eq!(
            provider.hooks.load(Ordering::SeqCst),
            1,
            "capability captured only at bind"
        );
        assert_eq!(provider.datagram.starts.load(Ordering::SeqCst), 4);
    }
}

#[test]
fn successful_async_addresses_use_owner_family_preserve_scope_and_truncate_after_encoding() {
    let (kernel, task, memory, provider) = configured();
    let caller = Caller::new(task, &memory);
    let fd = bound(&kernel, &caller, &memory, AddressFamily::AF_INET6);
    let mapped: SocketAddr = "127.0.0.1:49120".parse().unwrap();
    let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
        "fe80::1234".parse().unwrap(),
        49122,
        17,
        9,
    ));
    for (peer, physical) in [
        (false, mapped),
        (true, mapped),
        (false, scoped),
        (true, scoped),
    ] {
        *provider.datagram.inline.lock().unwrap() = Some(Ok(if peer {
            DatagramReadbackValue::Peer(Some(physical))
        } else {
            DatagramReadbackValue::Local(physical)
        }));
        let expected = crate::socket::encode(match physical {
            SocketAddr::V4(address) => SocketAddr::V6(std::net::SocketAddrV6::new(
                address.ip().to_ipv6_mapped(),
                address.port(),
                0,
                0,
            )),
            address => address,
        });
        for length in [5u32, 28] {
            put(&memory, 0x2f0, &length.to_le_bytes());
            put(&memory, 0x300, &[0xa5; 28]);
            let result = if peer {
                block_on(kernel.getpeername(
                    &caller,
                    fd,
                    GuestPtrMut::new(0x300),
                    GuestPtrMut::new(0x2f0),
                ))
            } else {
                block_on(kernel.getsockname(
                    &caller,
                    fd,
                    GuestPtrMut::new(0x300),
                    GuestPtrMut::new(0x2f0),
                ))
            };
            assert_eq!(result, Ok(0));
            assert_eq!(get(&memory, 0x2f0, 4), 28u32.to_le_bytes());
            assert_eq!(
                get(&memory, 0x300, length as usize),
                expected[..length as usize]
            );
            if length == 5 {
                assert_eq!(get(&memory, 0x305, 23), vec![0xa5; 23]);
            }
        }
    }
}

#[test]
fn source_renewal_retires_only_old_subscription_and_new_readback_uses_same_bind_capture() {
    let (kernel, task, memory, provider) = configured();
    let caller = Caller::new(task, &memory);
    let fd = bound(&kernel, &caller, &memory, AddressFamily::AF_INET);
    put(&memory, 0x2f0, &4u32.to_le_bytes());
    let mut old = Box::pin(ttl(&kernel, &caller, fd));
    assert!(old.as_mut().now_or_never().is_none());
    sockaddr(&memory, 0x240, 49121);
    assert_eq!(
        block_on(kernel.connect(&caller, fd, GuestPtr::new(0x240), 16)),
        Ok(0)
    );
    let (_, done) = provider.datagram.pending.lock().unwrap().remove(0);
    done(Ok(DatagramReadbackValue::Ttl(31)));
    assert_eq!(block_on(old), Err(SysErr::Errno(Errno::ECANCELED)));
    *provider.datagram.inline.lock().unwrap() = Some(Ok(DatagramReadbackValue::Ttl(37)));
    put(&memory, 0x2f0, &4u32.to_le_bytes());
    assert_eq!(block_on(ttl(&kernel, &caller, fd)), Ok(0));
    assert_eq!(get(&memory, 0x300, 4), 37u32.to_le_bytes());
    assert_eq!(provider.hooks.load(Ordering::SeqCst), 1);
    assert_eq!(provider.datagram.starts.load(Ordering::SeqCst), 2);
}

#[test]
fn impossible_provider_address_family_fails_before_copyout_but_original_error_wins() {
    let (kernel, task, memory, provider) = configured();
    let caller = Caller::new(task, &memory);
    let fd = bound(&kernel, &caller, &memory, AddressFamily::AF_INET);
    for result in [
        Ok(DatagramReadbackValue::Local(
            "[2001:db8::1]:9".parse().unwrap(),
        )),
        Ok(DatagramReadbackValue::Flag(false)),
        Err(Errno::EACCES),
    ] {
        *provider.datagram.inline.lock().unwrap() = Some(result);
        put(&memory, 0x2f0, &16u32.to_le_bytes());
        put(&memory, 0x300, &[0xa5; 16]);
        assert_eq!(
            block_on(kernel.getsockname(
                &caller,
                fd,
                GuestPtrMut::new(0x300),
                GuestPtrMut::new(0x2f0)
            )),
            Err(SysErr::Errno(if result.is_err() {
                Errno::EACCES
            } else {
                Errno::EPROTO
            }))
        );
        assert_eq!(get(&memory, 0x300, 16), vec![0xa5; 16]);
        assert_eq!(get(&memory, 0x2f0, 4), 16u32.to_le_bytes());
    }
}
