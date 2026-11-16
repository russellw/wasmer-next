//! Optional native bind admission driven through actual kernel syscalls.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use wasixv2_vnet::endpoint::{EndpointBindRequest, EndpointBound, EndpointProvider};
use wasixv2_vnet::{
    Backend, BackendDatagram, BackendStream, InboundSink, Net, NetConfig, Publication,
};

#[derive(Default)]
struct Provider {
    ready: Arc<Mutex<Option<SocketAddr>>>,
    queue: WaitQueue,
    dropped: Arc<AtomicUsize>,
    calls: Mutex<Vec<EndpointBindRequest>>,
}
struct Bound {
    ready: Arc<Mutex<Option<SocketAddr>>>,
    queue: WaitQueue,
    dropped: Arc<AtomicUsize>,
}
impl EndpointBound for Bound {
    fn local_addr(&self) -> Result<SocketAddr, Errno> {
        self.ready.lock().unwrap().ok_or(Errno::EAGAIN)
    }
}
impl Pollable for Bound {
    fn poll(&self, mut table: Option<&mut PollTable<'_>>) -> PollMask {
        poll_wait(&mut table, &self.queue);
        if self.ready.lock().unwrap().is_some() {
            PollMask::OUT
        } else {
            PollMask::empty()
        }
    }
}
impl Drop for Bound {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
impl EndpointProvider for Provider {
    fn bind(
        &self,
        request: EndpointBindRequest,
        _: WaitQueue,
    ) -> Result<Option<Arc<dyn EndpointBound>>, Errno> {
        self.calls.lock().unwrap().push(request);
        Ok(Some(Arc::new(Bound {
            ready: self.ready.clone(),
            queue: self.queue.clone(),
            dropped: self.dropped.clone(),
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
fn local(kernel: &Kernel, caller: &Caller<'_>, memory: &FlatMemory, fd: Fd) -> SocketAddr {
    put(memory, 0x2f0, &16u32.to_le_bytes());
    block_on(kernel.getsockname(caller, fd, GuestPtrMut::new(0x300), GuestPtrMut::new(0x2f0)))
        .unwrap();
    read_sockaddr(memory, 0x300)
}

#[test]
fn nonblocking_descriptor_bind_waits_and_getname_uses_actual_provider_port() {
    let (kernel, task, memory, provider) = configured();
    let caller = Caller::new(task, &memory);
    let fd = socket(&kernel, &caller, STREAM | 0x800);
    sockaddr(&memory, 0x200, 0);
    let mut bind = Box::pin(kernel.bind(&caller, fd, GuestPtr::new(0x200), 16));
    assert!(bind.as_mut().now_or_never().is_none());
    assert_eq!(local(&kernel, &caller, &memory, fd).port(), 0);
    *provider.ready.lock().unwrap() = Some("127.0.0.1:46101".parse().unwrap());
    provider.queue.wake(PollMask::OUT);
    assert_eq!(block_on(bind), Ok(0));
    assert_eq!(local(&kernel, &caller, &memory, fd).port(), 46101);
    assert_eq!(provider.calls.lock().unwrap()[0].requested.port(), 0);
}

#[test]
fn dropping_pending_bind_future_retires_owner_before_late_completion_and_rebind() {
    let (kernel, task, memory, provider) = configured();
    let caller = Caller::new(task, &memory);
    let fd = socket(&kernel, &caller, STREAM);
    sockaddr(&memory, 0x200, 0);
    let mut bind = Box::pin(kernel.bind(&caller, fd, GuestPtr::new(0x200), 16));
    assert!(bind.as_mut().now_or_never().is_none());
    drop(bind);
    assert_eq!(provider.dropped.load(Ordering::SeqCst), 1);
    *provider.ready.lock().unwrap() = Some("127.0.0.1:46102".parse().unwrap());
    provider.queue.wake(PollMask::OUT);
    assert_eq!(local(&kernel, &caller, &memory, fd).port(), 0);
    assert_eq!(
        block_on(kernel.bind(&caller, fd, GuestPtr::new(0x200), 16)),
        Ok(0)
    );
    assert_eq!(local(&kernel, &caller, &memory, fd).port(), 46102);
    assert_eq!(provider.calls.lock().unwrap().len(), 2);
}

#[test]
fn signal_interrupts_pending_bind_and_drops_uncommitted_lease() {
    let (kernel, task, memory, provider) = configured();
    let caller = Caller::new(task, &memory);
    let fd = socket(&kernel, &caller, STREAM);
    sockaddr(&memory, 0x200, 0);
    let mut bind = Box::pin(kernel.bind(&caller, fd, GuestPtr::new(0x200), 16));
    assert!(bind.as_mut().now_or_never().is_none());
    kernel.kill(task, wasixv2_abi::Signal(15)).unwrap();
    assert!(matches!(
        bind.as_mut().now_or_never(),
        Some(Err(SysErr::Restart))
    ));
    drop(bind);
    assert_eq!(provider.dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn unbound_listen_waits_for_direct_provider_listener_and_actual_port() {
    let (kernel, task, memory, provider) = configured();
    let caller = Caller::new(task, &memory);
    let fd = socket(&kernel, &caller, STREAM);
    let mut listen = Box::pin(kernel.listen(&caller, fd, 10000));
    assert!(listen.as_mut().now_or_never().is_none());
    let request = provider.calls.lock().unwrap()[0];
    assert!(!request.explicit);
    assert_eq!(
        request.purpose,
        wasixv2_vnet::endpoint::EndpointBindPurpose::Listen { backlog: 4096 }
    );
    assert_eq!(request.requested, "0.0.0.0:0".parse().unwrap());
    *provider.ready.lock().unwrap() = Some("0.0.0.0:46103".parse().unwrap());
    provider.queue.wake(PollMask::OUT);
    assert_eq!(block_on(listen), Ok(0));
    assert_eq!(local(&kernel, &caller, &memory, fd).port(), 46103);
}
