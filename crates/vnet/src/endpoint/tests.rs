//! A framed driver between two independent namespaces. The broker owns only scoped
//! publication handles and frames, never a Net. Transport methods enqueue work; drive()
//! releases every broker/transport lock before calling ingress or reporting status.
use super::*;
use crate::{
    Backend, BackendDatagram, InboundSink, Net, NetConfig, Network, Publication, SendMsg, Socket,
    SocketKind,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use wasixv2_abi::MsgFlags;

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
fn socket(n: &Net, kind: SocketKind) -> Arc<dyn Socket> {
    n.socket(Domain::Inet, kind, 0, 1).unwrap()
}
fn send(s: &dyn Socket, bytes: &[u8], to: Option<SocketAddr>) -> Result<usize, Errno> {
    s.send(SendMsg {
        data: bytes,
        to,
        flags: MsgFlags(0),
        control: &[],
        net_raw: false,
        now: Duration::ZERO,
    })
}
fn recv(s: &dyn Socket) -> (Vec<u8>, SocketAddr) {
    let mut bytes = [0; 64];
    let result = s.recv(&mut bytes, MsgFlags(0)).unwrap();
    (bytes[..result.len].to_vec(), result.from.unwrap())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Target {
    owner: usize,
    group: EndpointGroupId,
    attempt: PublicationAttemptId,
}
#[derive(Clone)]
enum Sink {
    Tcp(Arc<dyn EndpointStreamIngress>),
    Udp(Arc<dyn EndpointDatagramIngress>),
}
#[derive(Clone)]
struct Registration {
    target: Target,
    spec: EndpointGroupSpec,
    sink: Sink,
    status: PublicationReporter,
}
enum Frame {
    Withdraw(Target),
    Tcp(TcpOffer),
    Udp(Target, SocketAddr, SocketAddr, Vec<u8>),
    Configure(Arc<Tx>, UdpTxConfig),
    Bytes(usize, usize, Vec<u8>),
    Credit(usize, usize),
    Fin(usize),
}
const PENDING_TCP_LIMIT: usize = 8;
const STREAM_CAPACITY: usize = 16;
struct TcpOffer {
    target: Target,
    src: SocketAddr,
    dst: SocketAddr,
    stream: Arc<dyn BackendStream>,
    wq: WaitQueue,
    client: usize,
}
struct HeldTcp {
    offer: TcpOffer,
    wake: Arc<RoomWake>,
    _registrations: Vec<wasixv2_wait::WaitRegistration>,
}
#[derive(Default)]
struct RoomWake(AtomicBool);
impl wasixv2_wait::WaitEntry for RoomWake {
    fn wake(&self, _: PollMask) -> bool {
        self.0.store(true, Ordering::SeqCst);
        false
    }
}
#[derive(Default)]
struct Broker {
    records: Mutex<Vec<Registration>>,
    frames: Mutex<VecDeque<Frame>>,
    deliveries: Mutex<Vec<DatagramDelivery>>,
    streams: Mutex<HashMap<usize, std::sync::Weak<WireStream>>>,
    next_stream: AtomicUsize,
    pending_tcp: Mutex<Vec<HeldTcp>>,
    accepted_tcp: AtomicUsize,
}
impl Broker {
    fn queue(&self, frame: Frame) {
        self.frames.lock().unwrap().push_back(frame);
    }
    fn registration(&self, target: Target) -> Option<Registration> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.target == target)
            .cloned()
    }
    fn stream(&self, id: usize) -> Option<Arc<WireStream>> {
        self.streams
            .lock()
            .unwrap()
            .get(&id)
            .and_then(std::sync::Weak::upgrade)
    }
    fn connecting(&self, id: usize) -> bool {
        self.stream(id)
            .is_some_and(|s| s.status.load(Ordering::SeqCst) == 0)
    }
    fn complete(&self, id: usize, error: Option<Errno>) {
        if let Some(stream) = self.stream(id) {
            *stream.error.lock().unwrap() = error;
            stream
                .status
                .store(if error.is_some() { 2 } else { 1 }, Ordering::SeqCst);
            stream.wq.wake(PollMask::empty());
        }
    }
    fn offer_tcp(&self, offer: TcpOffer) {
        if !self.connecting(offer.client) {
            return;
        }
        let Some(Registration {
            sink: Sink::Tcp(sink),
            ..
        }) = self.registration(offer.target)
        else {
            self.complete(offer.client, Some(Errno::ECONNREFUSED));
            return;
        };
        let wake = Arc::new(RoomWake::default());
        let mut registrations = Vec::new();
        let mut register = |queue: &WaitQueue, _| registrations.push(queue.add(wake.clone()));
        let mut table = PollTable::new(PollMask::OUT, &mut register);
        match sink.poll_room_to(offer.src, offer.dst, Some(&mut table)) {
            Room::Ready => {
                let accepted = sink.incoming_to(offer.src, offer.dst, offer.stream, offer.wq);
                if accepted {
                    self.accepted_tcp.fetch_add(1, Ordering::SeqCst);
                }
                self.complete(offer.client, (!accepted).then_some(Errno::ECONNREFUSED));
            }
            Room::Full => {
                let mut held = self.pending_tcp.lock().unwrap();
                if held.len() < PENDING_TCP_LIMIT {
                    held.push(HeldTcp {
                        offer,
                        wake,
                        _registrations: registrations,
                    });
                } else {
                    drop(held);
                    self.complete(offer.client, Some(Errno::ECONNREFUSED));
                }
            }
            Room::Gone => self.complete(offer.client, Some(Errno::ECONNREFUSED)),
        }
    }
    fn drive(&self) {
        // PollTable wakes only mark work. Move custody out of the broker mutex before
        // querying a listener or retrying a previously unaccepted connection.
        let pending = std::mem::take(&mut *self.pending_tcp.lock().unwrap());
        for held in pending {
            if held.wake.0.swap(false, Ordering::SeqCst) || !self.connecting(held.offer.client) {
                self.offer_tcp(held.offer);
            } else {
                self.pending_tcp.lock().unwrap().push(held);
            }
        }
        loop {
            let frame = self.frames.lock().unwrap().pop_front();
            let Some(frame) = frame else { break };
            match frame {
                Frame::Withdraw(target) => {
                    self.records.lock().unwrap().retain(|r| r.target != target)
                }
                Frame::Tcp(offer) => self.offer_tcp(offer),
                Frame::Udp(target, src, dst, bytes) => {
                    let disposition = match self.registration(target) {
                        Some(Registration {
                            sink: Sink::Udp(sink),
                            ..
                        }) => sink.incoming(target.group, target.attempt, src, dst, &bytes),
                        _ => DatagramDelivery::Retired,
                    };
                    self.deliveries.lock().unwrap().push(disposition);
                }
                Frame::Configure(tx, config) => tx.apply(config),
                Frame::Bytes(from, id, bytes) => {
                    if let Some(stream) = self.stream(id) {
                        let mut input = stream.input.lock().unwrap();
                        assert!(input.len() + bytes.len() <= STREAM_CAPACITY);
                        input.extend(bytes);
                        drop(input);
                        stream.wq.wake(PollMask::IN);
                    } else {
                        self.complete(from, Some(Errno::ECONNRESET));
                    }
                }
                Frame::Credit(id, bytes) => {
                    if let Some(stream) = self.stream(id) {
                        stream.outstanding.fetch_sub(bytes, Ordering::SeqCst);
                        stream.wq.wake(PollMask::OUT);
                    }
                }
                Frame::Fin(id) => {
                    let stream = self
                        .streams
                        .lock()
                        .unwrap()
                        .get(&id)
                        .and_then(std::sync::Weak::upgrade);
                    if let Some(stream) = stream {
                        stream.eof.store(true, Ordering::SeqCst);
                        stream.wq.wake(PollMask::IN | PollMask::RDHUP);
                    }
                }
            }
        }
    }
}
/// Each side owns only its receive bytes and integer peer ID. Even TCP payload/FIN
/// crosses the driver queue; no data-plane operation calls any namespace or ingress.
struct WireStream {
    broker: std::sync::Weak<Broker>,
    id: usize,
    peer_id: usize,
    peer: SocketAddr,
    status: AtomicUsize,
    error: Mutex<Option<Errno>>,
    outstanding: AtomicUsize,
    input: Mutex<VecDeque<u8>>,
    eof: AtomicBool,
    wq: WaitQueue,
}
impl WireStream {
    fn pair(
        broker: &Arc<Broker>,
        addresses: [SocketAddr; 2],
        queues: [WaitQueue; 2],
    ) -> [Arc<Self>; 2] {
        let first = broker.next_stream.fetch_add(2, Ordering::SeqCst);
        let pair = [0, 1].map(|side| {
            Arc::new(Self {
                broker: Arc::downgrade(broker),
                id: first + side,
                peer_id: first + 1 - side,
                peer: addresses[1 - side],
                status: AtomicUsize::new(side), // client Connecting; accepted side Established
                error: Mutex::new(None),
                outstanding: AtomicUsize::new(0),
                input: Mutex::new(VecDeque::new()),
                eof: AtomicBool::new(false),
                wq: queues[side].clone(),
            })
        });
        let mut streams = broker.streams.lock().unwrap();
        for (side, stream) in pair.iter().enumerate() {
            streams.insert(first + side, Arc::downgrade(stream));
        }
        pair
    }
    fn queue(&self, frame: Frame) {
        if let Some(broker) = self.broker.upgrade() {
            broker.queue(frame);
        }
    }
}
impl Drop for WireStream {
    fn drop(&mut self) {
        self.queue(Frame::Fin(self.peer_id));
    }
}
impl Pollable for WireStream {
    fn poll(&self, _: Option<&mut PollTable<'_>>) -> PollMask {
        let mut mask = PollMask::empty();
        if self.status.load(Ordering::SeqCst) == 1
            && self.outstanding.load(Ordering::SeqCst) < STREAM_CAPACITY
        {
            mask |= PollMask::OUT;
        }
        if self.status.load(Ordering::SeqCst) == 2 {
            mask |= PollMask::ERR | PollMask::HUP | PollMask::OUT;
        }
        if !self.input.lock().unwrap().is_empty() {
            mask |= PollMask::IN;
        }
        if self.eof.load(Ordering::SeqCst) {
            mask |= PollMask::IN | PollMask::RDHUP;
        }
        mask
    }
}
impl BackendStream for WireStream {
    fn state(&self) -> crate::StreamState {
        match self.status.load(Ordering::SeqCst) {
            0 => crate::StreamState::Connecting,
            1 => crate::StreamState::Established,
            _ => crate::StreamState::Closed,
        }
    }
    fn read(&self, out: &mut [u8], peek: bool) -> Result<usize, Errno> {
        let mut input = self.input.lock().unwrap();
        if input.is_empty() && !self.eof.load(Ordering::SeqCst) {
            return Err(Errno::EAGAIN);
        }
        let len = out.len().min(input.len());
        for (dst, src) in out.iter_mut().zip(input.iter()).take(len) {
            *dst = *src;
        }
        if !peek {
            input.drain(..len);
        }
        drop(input);
        if !peek && len != 0 {
            self.queue(Frame::Credit(self.peer_id, len));
        }
        Ok(len)
    }
    fn write(&self, data: &[u8]) -> Result<usize, Errno> {
        if self.status.load(Ordering::SeqCst) != 1 {
            return Err(Errno::EAGAIN);
        }
        let mut queued = self.outstanding.load(Ordering::SeqCst);
        loop {
            let len = data.len().min(STREAM_CAPACITY - queued);
            if len == 0 && !data.is_empty() {
                return Err(Errno::EAGAIN);
            }
            match self.outstanding.compare_exchange(
                queued,
                queued + len,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    self.queue(Frame::Bytes(self.id, self.peer_id, data[..len].to_vec()));
                    return Ok(len);
                }
                Err(current) => queued = current,
            }
        }
    }
    fn write_urgent(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EOPNOTSUPP)
    }
    fn read_urgent(&self, _: bool) -> Result<u8, Errno> {
        Err(Errno::EINVAL)
    }
    fn at_mark(&self) -> bool {
        false
    }
    fn shutdown(&self, _: crate::Shutdown) -> Result<(), Errno> {
        self.queue(Frame::Fin(self.peer_id));
        Ok(())
    }
    fn take_error(&self) -> Option<Errno> {
        self.error.lock().unwrap().take()
    }
    fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    fn input_len(&self) -> usize {
        self.input.lock().unwrap().len()
    }
}

struct Lease {
    target: Target,
    broker: Arc<Broker>,
    status: PublicationReporter,
    backlog: Mutex<(u64, u32)>,
    hint_hook: Arc<Mutex<Option<Hook>>>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.broker.queue(Frame::Withdraw(self.target));
    }
}
impl Pollable for Lease {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.status.poll(table)
    }
}
impl EndpointLease for Lease {
    fn reporter(&self) -> &PublicationReporter {
        &self.status
    }
    fn set_backlog(&self, revision: u64, backlog: u32) {
        Provider::hook(&self.hint_hook);
        let mut current = self.backlog.lock().unwrap();
        if revision > current.0 {
            *current = (revision, backlog);
        }
    }
}
struct Host {
    writable: AtomicBool,
    error: Mutex<Option<Errno>>,
}
impl Default for Host {
    fn default() -> Self {
        Self {
            writable: AtomicBool::new(true),
            error: Mutex::new(None),
        }
    }
}
impl Pollable for Host {
    fn poll(&self, _: Option<&mut PollTable<'_>>) -> PollMask {
        let mut mask = PollMask::empty();
        if self.writable.load(Ordering::SeqCst) {
            mask |= PollMask::OUT;
        }
        if self.error.lock().unwrap().is_some() {
            mask |= PollMask::ERR;
        }
        mask
    }
}
impl BackendDatagram for Host {
    fn send_to(&self, data: &[u8], _: SocketAddr) -> Result<usize, Errno> {
        if self.writable.load(Ordering::SeqCst) {
            Ok(data.len())
        } else {
            Err(Errno::EAGAIN)
        }
    }
    fn connect(&self, _: Option<SocketAddr>) -> Result<(), Errno> {
        Ok(())
    }
    fn take_error(&self) -> Option<Errno> {
        self.error.lock().unwrap().take()
    }
    fn recv_from(&self, _: &mut [u8], _: bool) -> Result<(usize, usize, SocketAddr), Errno> {
        Err(Errno::EAGAIN)
    }
    fn input_len(&self) -> usize {
        0
    }
}
struct Tx {
    broker: Arc<Broker>,
    source: EndpointSourceId,
    desired: Mutex<UdpTxConfig>,
    applied: Mutex<UdpTxConfig>,
    writable: AtomicBool,
    error: Mutex<Option<Errno>>,
    sent: AtomicUsize,
    fail_after: AtomicUsize,
    wq: WaitQueue,
    deferred: AtomicBool,
    me: std::sync::Weak<Tx>,
}
impl Tx {
    fn apply(&self, config: UdpTxConfig) {
        let mut current = self.applied.lock().unwrap();
        if config.source_id == self.source && config.revision > current.revision {
            *current = config;
        }
        drop(current);
        self.wq.wake(PollMask::OUT);
    }
}
impl EndpointDatagramTx for Tx {
    fn configure(&self, config: UdpTxConfig) {
        let mut desired = self.desired.lock().unwrap();
        if config.source_id != self.source || config.revision <= desired.revision {
            return;
        }
        *desired = config;
        drop(desired);
        if self.deferred.load(Ordering::SeqCst) {
            self.broker
                .queue(Frame::Configure(self.me.upgrade().unwrap(), config));
        } else {
            self.apply(config);
        }
    }
    fn send_to(
        &self,
        revision: u64,
        target: &EndpointTarget,
        src: SocketAddr,
        dst: SocketAddr,
        bytes: &[u8],
    ) -> Result<usize, Errno> {
        if !self.poll_tx(revision).contains(PollMask::OUT) {
            return Err(Errno::EAGAIN);
        }
        let target = *target.downcast_ref::<Target>().ok_or(Errno::EINVAL)?;
        self.sent.fetch_add(1, Ordering::SeqCst);
        self.broker
            .queue(Frame::Udp(target, src, dst, bytes.to_vec()));
        Ok(bytes.len())
    }
    fn poll_tx(&self, revision: u64) -> PollMask {
        let mut mask = PollMask::empty();
        if self.writable.load(Ordering::SeqCst)
            && self.sent.load(Ordering::SeqCst) < self.fail_after.load(Ordering::SeqCst)
            && self.applied.lock().unwrap().revision >= revision
        {
            mask |= PollMask::OUT;
        }
        if self.error.lock().unwrap().is_some() {
            mask |= PollMask::ERR;
        }
        mask
    }
    fn take_error(&self) -> Option<Errno> {
        self.error.lock().unwrap().take()
    }
}
/// Control hooks intentionally reenter their own socket/Net to detect calls under WLK locks.
/// Data-plane objects never own these hooks or invoke them, including during destruction.
type Hook = Box<dyn FnOnce() + Send>;
#[derive(Default)]
struct WakeCount(AtomicUsize);
impl wasixv2_wait::WaitEntry for WakeCount {
    fn wake(&self, _: PollMask) -> bool {
        self.0.fetch_add(1, Ordering::SeqCst);
        false
    }
}
struct Provider {
    owner: usize,
    broker: Arc<Broker>,
    local_first: AtomicBool,
    refuse: AtomicBool,
    pending: AtomicBool,
    publish_error: AtomicBool,
    deferred: AtomicBool,
    select_hook: Mutex<Option<Hook>>,
    factory_hook: Mutex<Option<Hook>>,
    publication_hook: Mutex<Option<Hook>>,
    hint_hook: Arc<Mutex<Option<Hook>>>,
    provisional: Mutex<Vec<Room>>,
    wake_count: Arc<WakeCount>,
    waiters: Mutex<Vec<wasixv2_wait::WaitRegistration>>,
    queries: Mutex<Vec<EndpointQuery>>,
    txs: Mutex<Vec<Arc<Tx>>>,
    leases: Mutex<Vec<std::sync::Weak<Lease>>>,
    host: Arc<Host>,
}
impl Provider {
    fn new(owner: usize, broker: Arc<Broker>) -> Arc<Self> {
        Arc::new(Self {
            owner,
            broker,
            local_first: AtomicBool::new(false),
            refuse: AtomicBool::new(false),
            pending: AtomicBool::new(false),
            publish_error: AtomicBool::new(false),
            deferred: AtomicBool::new(false),
            select_hook: Mutex::new(None),
            factory_hook: Mutex::new(None),
            publication_hook: Mutex::new(None),
            hint_hook: Arc::new(Mutex::new(None)),
            provisional: Mutex::new(Vec::new()),
            wake_count: Arc::new(WakeCount::default()),
            waiters: Mutex::new(Vec::new()),
            queries: Mutex::new(Vec::new()),
            txs: Mutex::new(Vec::new()),
            leases: Mutex::new(Vec::new()),
            host: Arc::new(Host::default()),
        })
    }
    fn hook(slot: &Mutex<Option<Hook>>) {
        let hook = slot.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
    }
    fn publish(
        &self,
        group: EndpointGroupSpec,
        sink: Sink,
        status: PublicationReporter,
        backlog: u32,
    ) -> Result<Arc<dyn EndpointLease>, Errno> {
        Self::hook(&self.publication_hook);
        if self.publish_error.load(Ordering::SeqCst) {
            return Err(Errno::EIO);
        }
        if let Sink::Tcp(ingress) = &sink {
            let destination = if group.local.ip().is_unspecified() {
                SocketAddr::new(
                    if group.local.is_ipv4() {
                        addr("127.0.0.1:0").ip()
                    } else {
                        addr("[::1]:0").ip()
                    },
                    group.local.port(),
                )
            } else {
                group.local
            };
            let source = SocketAddr::new(destination.ip(), 40000);
            let mut waiters = Vec::new();
            let mut register = |queue: &WaitQueue, _| {
                waiters.push(queue.add(self.wake_count.clone()));
            };
            let mut table = PollTable::new(PollMask::OUT, &mut register);
            let room = ingress.poll_room_to(source, destination, Some(&mut table));
            self.provisional.lock().unwrap().push(room);
            self.waiters.lock().unwrap().extend(waiters);
        }
        let target = Target {
            owner: self.owner,
            group: group.group_id,
            attempt: group.attempt_id,
        };
        self.broker.records.lock().unwrap().push(Registration {
            target,
            spec: group.clone(),
            sink,
            status: status.clone(),
        });
        let lease = Arc::new(Lease {
            target,
            broker: self.broker.clone(),
            status: status.clone(),
            backlog: Mutex::new((group.revision, backlog)),
            hint_hook: self.hint_hook.clone(),
        });
        self.leases.lock().unwrap().push(Arc::downgrade(&lease));
        if !self.pending.load(Ordering::SeqCst) {
            status.ready();
        }
        Ok(lease)
    }
    fn records(&self) -> Vec<Registration> {
        self.broker
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.target.owner == self.owner)
            .cloned()
            .collect()
    }
    fn tx(&self) -> Arc<Tx> {
        self.txs.lock().unwrap().last().unwrap().clone()
    }
}
impl EndpointProvider for Provider {
    fn select(&self, query: &EndpointQuery) -> Result<EndpointChoice, Errno> {
        Self::hook(&self.select_hook);
        self.queries.lock().unwrap().push(query.clone());
        if self.refuse.load(Ordering::SeqCst) {
            return Err(Errno::EACCES);
        }
        if self.local_first.load(Ordering::SeqCst) && query.local_binding {
            return Ok(EndpointChoice::Namespace);
        }
        let records = self.broker.records.lock().unwrap();
        let target = records
            .iter()
            .find(|r| {
                r.target.owner != self.owner
                    && r.spec.kind == query.kind
                    && crate::net::serves(r.spec.local, r.spec.v6only, query.destination)
            })
            .map(|r| r.target);
        target
            .map(|target| EndpointChoice::Provider(EndpointTarget::new(target)))
            .ok_or(Errno::ECONNREFUSED)
    }
    fn connect(
        &self,
        target: EndpointTarget,
        _: EndpointSourceId,
        local: SocketAddr,
        remote: SocketAddr,
        wq: WaitQueue,
    ) -> Result<Arc<dyn BackendStream>, Errno> {
        Self::hook(&self.factory_hook);
        let target = *target.downcast_ref::<Target>().ok_or(Errno::EINVAL)?;
        let server_wq = WaitQueue::new();
        let [client, server] =
            WireStream::pair(&self.broker, [local, remote], [wq, server_wq.clone()]);
        self.broker.queue(Frame::Tcp(TcpOffer {
            target,
            src: local,
            dst: remote,
            stream: server,
            wq: server_wq,
            client: client.id,
        }));
        Ok(client)
    }
    fn datagram(
        &self,
        source: EndpointSource,
        initial: UdpTxConfig,
        wq: WaitQueue,
    ) -> Result<Arc<dyn EndpointDatagramTx>, Errno> {
        Self::hook(&self.factory_hook);
        let tx = Arc::new_cyclic(|me| Tx {
            broker: self.broker.clone(),
            source: source.id,
            desired: Mutex::new(initial),
            applied: Mutex::new(initial),
            writable: AtomicBool::new(true),
            error: Mutex::new(None),
            sent: AtomicUsize::new(0),
            fail_after: AtomicUsize::new(usize::MAX),
            wq,
            deferred: AtomicBool::new(self.deferred.load(Ordering::SeqCst)),
            me: me.clone(),
        });
        self.txs.lock().unwrap().push(tx.clone());
        Ok(tx)
    }
    fn publish_tcp(
        &self,
        group: EndpointGroupSpec,
        backlog: u32,
        ingress: Arc<dyn EndpointStreamIngress>,
        status: PublicationReporter,
    ) -> Result<Arc<dyn EndpointLease>, Errno> {
        self.publish(group, Sink::Tcp(ingress), status, backlog)
    }
    fn publish_udp(
        &self,
        group: EndpointGroupSpec,
        ingress: Arc<dyn EndpointDatagramIngress>,
        status: PublicationReporter,
    ) -> Result<Arc<dyn EndpointLease>, Errno> {
        self.publish(group, Sink::Udp(ingress), status, 0)
    }
}
impl Backend for Provider {
    fn endpoint_namespace(&self) -> Option<Arc<dyn EndpointProvider>> {
        unreachable!("use Adapter to capture scoped Arc")
    }
    fn connect(&self, _: SocketAddr, _: WaitQueue) -> Result<Arc<dyn BackendStream>, Errno> {
        Err(Errno::ENETUNREACH)
    }
    fn datagram(&self, _: Domain, _: WaitQueue) -> Result<Arc<dyn BackendDatagram>, Errno> {
        Ok(self.host.clone())
    }
    fn publish(
        &self,
        _: SocketAddr,
        _: u32,
        _: Arc<dyn InboundSink>,
    ) -> Result<Box<dyn Publication>, std::io::Error> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}
struct Adapter(Arc<Provider>);
impl Backend for Adapter {
    fn endpoint_namespace(&self) -> Option<Arc<dyn EndpointProvider>> {
        Some(self.0.clone())
    }
    fn connect(&self, peer: SocketAddr, wq: WaitQueue) -> Result<Arc<dyn BackendStream>, Errno> {
        Backend::connect(&*self.0, peer, wq)
    }
    fn datagram(&self, domain: Domain, wq: WaitQueue) -> Result<Arc<dyn BackendDatagram>, Errno> {
        Backend::datagram(&*self.0, domain, wq)
    }
    fn publish(
        &self,
        host: SocketAddr,
        backlog: u32,
        sink: Arc<dyn InboundSink>,
    ) -> Result<Box<dyn Publication>, std::io::Error> {
        Backend::publish(&*self.0, host, backlog, sink)
    }
}
fn pair() -> (
    Arc<Broker>,
    Arc<Net>,
    Arc<Provider>,
    Arc<Net>,
    Arc<Provider>,
) {
    let broker = Arc::new(Broker::default());
    let left = Provider::new(1, broker.clone());
    let right = Provider::new(2, broker.clone());
    let a = Net::new(
        NetConfig::host_default(),
        Some(Arc::new(Adapter(left.clone()))),
    );
    let b = Net::new(
        NetConfig::host_default(),
        Some(Arc::new(Adapter(right.clone()))),
    );
    assert!(!Arc::ptr_eq(&a, &b));
    (broker, a, left, b, right)
}

#[test]
fn independent_tcp_wildcard_source_destination_and_local_choice() {
    let (broker, left, provider, right, remote) = pair();
    let listener = socket(&right, SocketKind::Stream);
    listener.bind(addr("0.0.0.0:8080"), false).unwrap();
    listener.listen(2).unwrap();
    assert_eq!(*remote.provisional.lock().unwrap(), vec![Room::Full]);
    assert!(remote.wake_count.0.load(Ordering::SeqCst) > 0);
    let client = socket(&left, SocketKind::Stream);
    assert_eq!(
        client.connect(addr("127.0.0.2:8080")),
        Err(Errno::EINPROGRESS)
    );
    assert_eq!(listener.accept().unwrap_err(), Errno::EAGAIN);
    broker.drive();
    let accepted = listener.accept().unwrap();
    assert_eq!(
        accepted.socket.local_addr().unwrap(),
        addr("127.0.0.2:8080")
    );
    assert_eq!(accepted.peer, client.local_addr().unwrap());
    assert_eq!(send(&*client, b"hello", None), Ok(5));
    broker.drive();
    let mut bytes = [0; 5];
    assert_eq!(
        accepted.socket.recv(&mut bytes, MsgFlags(0)).unwrap().len,
        5
    );
    assert_eq!(&bytes, b"hello");
    assert_eq!(send(&*accepted.socket, b"reply", None), Ok(5));
    broker.drive();
    assert_eq!(client.recv(&mut bytes, MsgFlags(0)).unwrap().len, 5);
    assert_eq!(&bytes, b"reply");
    let local_listener = socket(&left, SocketKind::Stream);
    local_listener.bind(addr("127.0.0.1:8081"), false).unwrap();
    local_listener.listen(1).unwrap();
    provider.local_first.store(true, Ordering::SeqCst);
    let local = socket(&left, SocketKind::Stream);
    assert_eq!(local.connect(addr("127.0.0.1:8081")), Ok(()));
    assert!(local_listener.accept().is_ok());
    provider.refuse.store(true, Ordering::SeqCst);
    let denied = socket(&left, SocketKind::Stream);
    assert_eq!(denied.connect(addr("127.0.0.1:8081")), Err(Errno::EACCES));
    assert_eq!(local_listener.accept().unwrap_err(), Errno::EAGAIN);
}

#[test]
fn independent_udp_autobind_empty_datagrams_and_replies_have_one_ingress() {
    let (broker, left, provider, right, _) = pair();
    let server = socket(&right, SocketKind::Datagram);
    server.bind(addr("0.0.0.0:8090"), false).unwrap();
    let client = socket(&left, SocketKind::Datagram);
    assert_eq!(
        send(&*client, b"request", Some(addr("127.0.0.1:8090"))),
        Ok(7)
    );
    assert!(client.local_addr().unwrap().port() != 0);
    assert_eq!(server.recv(&mut [0; 8], MsgFlags(0)), Err(Errno::EAGAIN));
    broker.drive();
    let (bytes, source) = recv(&*server);
    assert_eq!(bytes, b"request");
    assert_eq!(source.port(), client.local_addr().unwrap().port());
    assert_eq!(send(&*server, b"", Some(source)), Ok(0));
    broker.drive();
    assert_eq!(recv(&*client), (Vec::new(), addr("127.0.0.1:8090")));
    assert_eq!(client.recv(&mut [0; 1], MsgFlags(0)), Err(Errno::EAGAIN));
    assert_eq!(provider.tx().sent.load(Ordering::SeqCst), 1);
    assert!(
        broker
            .deliveries
            .lock()
            .unwrap()
            .iter()
            .all(|r| *r == DatagramDelivery::Queued)
    );
}

#[test]
fn pending_failure_retry_rejects_old_callback_in_same_reuse_group() {
    let (_, _, _, right, provider) = pair();
    provider.pending.store(true, Ordering::SeqCst);
    let first = socket(&right, SocketKind::Datagram);
    let second = socket(&right, SocketKind::Datagram);
    for s in [&first, &second] {
        s.set_option(1, 15, &1i32.to_le_bytes()).unwrap();
        s.bind(addr("127.0.0.1:8100"), false).unwrap();
    }
    let old = provider.records().pop().unwrap();
    let Sink::Udp(sink) = &old.sink else {
        unreachable!()
    };
    let src = addr("127.0.0.1:40001");
    let dst = addr("127.0.0.1:8100");
    assert_eq!(
        sink.incoming(
            old.target.group,
            old.target.attempt,
            src,
            dst,
            b"provisional"
        ),
        DatagramDelivery::Dropped
    );
    old.status.failed(Errno::EIO);
    provider.pending.store(false, Ordering::SeqCst);
    right.retry_endpoint_publications();
    let current = provider.records().pop().unwrap();
    assert_eq!(current.target.group, old.target.group);
    assert_ne!(current.target.attempt, old.target.attempt);
    assert_eq!(
        sink.incoming(old.target.group, old.target.attempt, src, dst, b"late"),
        DatagramDelivery::Retired
    );
    let Sink::Udp(current_sink) = current.sink else {
        unreachable!()
    };
    drop(first);
    assert_eq!(
        current_sink.incoming(
            current.target.group,
            current.target.attempt,
            src,
            dst,
            b"live"
        ),
        DatagramDelivery::Queued
    );
    assert_eq!(recv(&*second).0, b"live");
    drop(second);
    let replacement = socket(&right, SocketKind::Datagram);
    replacement.bind(dst, false).unwrap();
    assert_eq!(
        current_sink.incoming(
            current.target.group,
            current.target.attempt,
            src,
            dst,
            b"late"
        ),
        DatagramDelivery::Retired
    );
    assert_ne!(
        provider.records().last().unwrap().target.group,
        old.target.group
    );
    assert_eq!(
        replacement.recv(&mut [0; 8], MsgFlags(0)),
        Err(Errno::EAGAIN)
    );
}

#[test]
fn group_scoped_wildcard_ingress_never_falls_back_to_specific_socket() {
    let (_, _, _, right, provider) = pair();
    let wildcard = socket(&right, SocketKind::Datagram);
    let specific = socket(&right, SocketKind::Datagram);
    for s in [&wildcard, &specific] {
        s.set_option(1, 2, &1i32.to_le_bytes()).unwrap();
    }
    wildcard.bind(addr("0.0.0.0:8110"), false).unwrap();
    let registration = provider.records().pop().unwrap();
    specific.bind(addr("127.0.0.2:8110"), false).unwrap();
    let Sink::Udp(sink) = registration.sink else {
        unreachable!()
    };
    assert_eq!(
        sink.incoming(
            registration.target.group,
            registration.target.attempt,
            addr("127.0.0.1:40000"),
            addr("127.0.0.2:8110"),
            b"scoped"
        ),
        DatagramDelivery::Queued
    );
    assert_eq!(recv(&*wildcard).0, b"scoped");
    assert_eq!(specific.recv(&mut [0; 8], MsgFlags(0)), Err(Errno::EAGAIN));
}

#[test]
fn publication_error_does_not_rollback_bind_and_retry_is_observable() {
    let (_, _, _, right, provider) = pair();
    provider.publish_error.store(true, Ordering::SeqCst);
    let listener = socket(&right, SocketKind::Stream);
    listener.bind(addr("127.0.0.1:8120"), false).unwrap();
    listener.listen(1).unwrap();
    assert_eq!(
        right.endpoint_publications()[0].state,
        PublicationState::Failed(Errno::EIO)
    );
    assert!(provider.records().is_empty());
    assert_eq!(listener.local_addr().unwrap(), addr("127.0.0.1:8120"));
    provider.publish_error.store(false, Ordering::SeqCst);
    right.retry_endpoint_publications();
    assert_eq!(
        right.endpoint_publications()[0].state,
        PublicationState::Ready
    );
    assert_eq!(provider.records().len(), 1);
}

#[test]
fn udp_write_focus_separates_host_peer_connected_and_unconnected_routes() {
    let (broker, left, provider, right, _) = pair();
    let receiver = socket(&right, SocketKind::Datagram);
    let peer = addr("127.0.0.1:8130");
    receiver.bind(peer, false).unwrap();
    let client = socket(&left, SocketKind::Datagram);
    send(&*client, b"first", Some(peer)).unwrap();
    broker.drive();
    let tx = provider.tx();
    tx.writable.store(false, Ordering::SeqCst);
    assert_eq!(send(&*client, b"blocked", Some(peer)), Err(Errno::EAGAIN));
    assert!(!client.poll(None).contains(PollMask::OUT));
    let external = addr("8.8.8.8:53");
    assert_eq!(send(&*client, b"host", Some(external)), Ok(4));
    assert!(client.poll(None).contains(PollMask::OUT));
    provider.host.writable.store(false, Ordering::SeqCst);
    tx.writable.store(true, Ordering::SeqCst);
    assert_eq!(
        send(&*client, b"blocked-host", Some(external)),
        Err(Errno::EAGAIN)
    );
    assert!(!client.poll(None).contains(PollMask::OUT));
    assert_eq!(send(&*client, b"peer", Some(peer)), Ok(4));
    assert!(client.poll(None).contains(PollMask::OUT));
    client.connect(peer).unwrap();
    send(&*client, b"new-source", None).unwrap();
    provider.tx().writable.store(false, Ordering::SeqCst);
    provider.host.writable.store(true, Ordering::SeqCst);
    assert!(!client.poll(None).contains(PollMask::OUT));
    assert_eq!(send(&*client, b"host-override", Some(external)), Ok(13));
    assert!(!client.poll(None).contains(PollMask::OUT));
    client.disconnect().unwrap();
    assert!(client.poll(None).contains(PollMask::OUT));
}

#[test]
fn udp_factory_replays_complete_configuration_and_driver_ignores_stale_updates() {
    let (broker, left, provider, right, _) = pair();
    let receiver = socket(&right, SocketKind::Datagram);
    receiver.bind(addr("127.0.0.1:8140"), false).unwrap();
    let client = socket(&left, SocketKind::Datagram);
    let during_factory = client.clone();
    *provider.factory_hook.lock().unwrap() = Some(Box::new(move || {
        during_factory
            .set_option(0, 11, &1i32.to_le_bytes())
            .unwrap();
        assert!(during_factory.local_addr().unwrap().port() != 0);
    }));
    assert_eq!(send(&*client, b"once", Some(addr("127.0.0.1:8140"))), Ok(4));
    let tx = provider.tx();
    assert!(tx.applied.lock().unwrap().recv_v4_errors);
    tx.deferred.store(true, Ordering::SeqCst);
    client.set_option(0, 11, &0i32.to_le_bytes()).unwrap();
    let off = *tx.desired.lock().unwrap();
    assert_eq!(
        send(&*client, b"unaccepted", Some(addr("127.0.0.1:8140"))),
        Err(Errno::EAGAIN)
    );
    assert!(!client.poll(None).contains(PollMask::OUT));
    let on = UdpTxConfig {
        revision: off.revision - 1,
        recv_v4_errors: true,
        ..off
    };
    tx.apply(off);
    tx.apply(on);
    assert!(!tx.applied.lock().unwrap().recv_v4_errors);
    broker.drive();
    assert!(client.poll(None).contains(PollMask::OUT));
    assert_eq!(tx.sent.load(Ordering::SeqCst), 1); // no payload replay on config progress
    assert_eq!(recv(&*receiver).0, b"once");
    assert_eq!(receiver.recv(&mut [0; 64], MsgFlags(0)), Err(Errno::EAGAIN));
    client.disconnect().unwrap();
    assert_eq!(
        send(&*client, b"replacement", Some(addr("127.0.0.1:8140"))),
        Ok(11)
    );
    assert_ne!(provider.tx().source, tx.source);
}

#[test]
fn controls_are_unlocked_and_late_factory_completion_cannot_replace_source() {
    let (_, left, provider, right, _) = pair();
    let listener = socket(&right, SocketKind::Stream);
    listener.bind(addr("127.0.0.1:8150"), false).unwrap();
    listener.listen(1).unwrap();
    let client = socket(&left, SocketKind::Stream);
    let during_select = client.clone();
    *provider.select_hook.lock().unwrap() = Some(Box::new(move || {
        during_select.local_addr().unwrap();
    }));
    let during_factory = client.clone();
    *provider.factory_hook.lock().unwrap() = Some(Box::new(move || {
        during_factory.disconnect().unwrap();
    }));
    assert_eq!(
        client.connect(addr("127.0.0.1:8150")),
        Err(Errno::ECANCELED)
    );
    assert_eq!(client.peer_addr(), Err(Errno::ENOTCONN));
    assert!(client.poll(None).contains(PollMask::HUP));
}

#[test]
fn both_udp_error_sources_remain_observable_and_retired_tx_cannot_leak() {
    let (_, left, provider, right, _) = pair();
    let server = socket(&right, SocketKind::Datagram);
    let peer = addr("127.0.0.1:8160");
    server.bind(peer, false).unwrap();
    let client = socket(&left, SocketKind::Datagram);
    send(&*client, b"host", Some(addr("8.8.8.8:53"))).unwrap();
    send(&*client, b"peer", Some(peer)).unwrap();
    let tx = provider.tx();
    *provider.host.error.lock().unwrap() = Some(Errno::EHOSTUNREACH);
    *tx.error.lock().unwrap() = Some(Errno::ECONNREFUSED);
    assert!(client.poll(None).contains(PollMask::ERR));
    assert_eq!(client.take_error(), Some(Errno::EHOSTUNREACH));
    assert!(client.poll(None).contains(PollMask::ERR));
    assert_eq!(client.take_error(), Some(Errno::ECONNREFUSED));
    assert!(!client.poll(None).contains(PollMask::ERR));
    client.disconnect().unwrap();
    *tx.error.lock().unwrap() = Some(Errno::EIO);
    assert_eq!(client.take_error(), None);
    assert!(!client.poll(None).contains(PollMask::ERR));
}

#[test]
fn queued_udp_for_retired_source_never_enters_same_address_replacement() {
    let (broker, left, _, right, _) = pair();
    let server = socket(&right, SocketKind::Datagram);
    let bound = addr("127.0.0.1:8170");
    server.bind(bound, false).unwrap();
    let client = socket(&left, SocketKind::Datagram);
    send(&*client, b"late", Some(bound)).unwrap();
    // The source frame was accepted but its target group is retired before driver ingress.
    drop(server);
    let replacement = socket(&right, SocketKind::Datagram);
    replacement.bind(bound, false).unwrap();
    broker.drive();
    assert_eq!(
        *broker.deliveries.lock().unwrap(),
        vec![DatagramDelivery::Retired]
    );
    assert_eq!(
        replacement.recv(&mut [0; 8], MsgFlags(0)),
        Err(Errno::EAGAIN)
    );
    send(&*client, b"fresh", Some(bound)).unwrap();
    broker.drive();
    assert_eq!(recv(&*replacement).0, b"fresh");
}

#[test]
fn cascade_drop_only_marks_backlog_dirty_until_explicit_unlocked_refresh() {
    let (_, _, _, right, provider) = pair();
    let first = socket(&right, SocketKind::Stream);
    let second = socket(&right, SocketKind::Stream);
    for s in [&first, &second] {
        s.set_option(1, 15, &1i32.to_le_bytes()).unwrap();
        s.bind(addr("127.0.0.1:8180"), false).unwrap();
    }
    first.listen(2).unwrap();
    second.listen(3).unwrap();
    assert_eq!(provider.records().len(), 1);
    let lease = provider.leases.lock().unwrap()[0].upgrade().unwrap();
    assert_eq!(lease.backlog.lock().unwrap().1, 5);
    let during_hint = second.clone();
    let during_namespace_hint = Arc::downgrade(&right);
    *provider.hint_hook.lock().unwrap() = Some(Box::new(move || {
        during_hint.local_addr().unwrap();
        assert_eq!(
            during_namespace_hint
                .upgrade()
                .unwrap()
                .endpoint_publications()
                .len(),
            1
        );
    }));
    drop(first);
    assert!(provider.hint_hook.lock().unwrap().is_some());
    assert_eq!(lease.backlog.lock().unwrap().1, 5);
    right.retry_endpoint_publications();
    assert!(provider.hint_hook.lock().unwrap().is_none());
    assert_eq!(lease.backlog.lock().unwrap().1, 3);
}

#[test]
fn absent_endpoint_capability_keeps_local_tcp_udp_and_no_publication() {
    let n = Net::new(NetConfig::default(), None);
    assert!(n.endpoint_namespace().is_none());
    let listener = socket(&n, SocketKind::Stream);
    listener.bind(addr("127.0.0.1:8190"), false).unwrap();
    listener.listen(1).unwrap();
    let client = socket(&n, SocketKind::Stream);
    client.connect(addr("127.0.0.1:8190")).unwrap();
    assert!(listener.accept().is_ok());
    let receiver = socket(&n, SocketKind::Datagram);
    receiver.bind(addr("127.0.0.1:8191"), false).unwrap();
    let sender = socket(&n, SocketKind::Datagram);
    send(&*sender, b"local", Some(addr("127.0.0.1:8191"))).unwrap();
    assert_eq!(recv(&*receiver).0, b"local");
    assert!(n.endpoint_publications().is_empty());
}

#[test]
fn pending_tcp_failure_and_same_socket_relisten_retire_callback_gates() {
    let (_, _, _, right, provider) = pair();
    provider.pending.store(true, Ordering::SeqCst);
    let listener = socket(&right, SocketKind::Stream);
    let dst = addr("127.0.0.1:8200");
    let src = addr("127.0.0.1:40000");
    listener.bind(dst, false).unwrap();
    listener.listen(1).unwrap();
    let old = provider.records().pop().unwrap();
    let Sink::Tcp(old_sink) = &old.sink else {
        unreachable!()
    };
    assert_eq!(old_sink.poll_room_to(src, dst, None), Room::Full);
    let before = provider.wake_count.0.load(Ordering::SeqCst);
    old.status.failed(Errno::EIO);
    assert!(provider.wake_count.0.load(Ordering::SeqCst) > before);
    assert_eq!(old_sink.poll_room_to(src, dst, None), Room::Gone);
    provider.pending.store(false, Ordering::SeqCst);
    right.retry_endpoint_publications();
    let retried = provider.records().pop().unwrap();
    assert_eq!(retried.target.group, old.target.group);
    assert_ne!(retried.target.attempt, old.target.attempt);
    let Sink::Tcp(retried_sink) = &retried.sink else {
        unreachable!()
    };
    assert_eq!(retried_sink.poll_room_to(src, dst, None), Room::Ready);
    listener.disconnect().unwrap();
    assert_eq!(listener.local_addr().unwrap(), dst);
    listener.listen(1).unwrap();
    assert_eq!(retried_sink.poll_room_to(src, dst, None), Room::Gone);
    assert_ne!(
        provider.records().last().unwrap().target.group,
        retried.target.group
    );
}

#[test]
fn dual_stack_group_filter_keeps_ipv4_arrival_in_its_selected_ipv6_group() {
    let (_, _, _, right, provider) = pair();
    let dual = right
        .socket(Domain::Inet6, SocketKind::Datagram, 0, 1)
        .unwrap();
    let v4 = socket(&right, SocketKind::Datagram);
    for s in [&dual, &v4] {
        s.set_option(1, 2, &1i32.to_le_bytes()).unwrap();
    }
    dual.bind(addr("[::]:8210"), false).unwrap();
    let record = provider.records().pop().unwrap();
    v4.bind(addr("127.0.0.1:8210"), false).unwrap();
    let Sink::Udp(sink) = record.sink else {
        unreachable!()
    };
    assert_eq!(
        sink.incoming(
            record.target.group,
            record.target.attempt,
            addr("127.0.0.1:40000"),
            addr("127.0.0.1:8210"),
            b"dual"
        ),
        DatagramDelivery::Queued
    );
    let (bytes, from) = recv(&*dual);
    assert_eq!(bytes, b"dual");
    assert_eq!(from, addr("[::ffff:127.0.0.1]:40000"));
    assert_eq!(v4.recv(&mut [0; 8], MsgFlags(0)), Err(Errno::EAGAIN));
}

#[test]
fn connected_udp_ingress_rechecks_peer_and_new_source_with_same_locked_bind() {
    let (_, _, _, right, provider) = pair();
    let server = socket(&right, SocketKind::Datagram);
    let dst = addr("127.0.0.1:8220");
    server.bind(dst, false).unwrap();
    let record = provider.records().pop().unwrap();
    let Sink::Udp(old_sink) = &record.sink else {
        unreachable!()
    };
    // Local-first selection lets us establish a connected peer without requiring a remote
    // publication. Ingress itself is still group/peer filtered after connection.
    let local_peer = socket(&right, SocketKind::Datagram);
    let src = addr("127.0.0.1:40000");
    local_peer.bind(src, false).unwrap();
    provider.local_first.store(true, Ordering::SeqCst);
    server.connect(src).unwrap();
    assert_eq!(
        old_sink.incoming(record.target.group, record.target.attempt, src, dst, b"old"),
        DatagramDelivery::Retired
    );
    let current = provider
        .records()
        .into_iter()
        .find(|r| r.spec.local == dst && r.target.group != record.target.group)
        .unwrap();
    let Sink::Udp(sink) = current.sink else {
        unreachable!()
    };
    assert_eq!(
        sink.incoming(
            current.target.group,
            current.target.attempt,
            addr("127.0.0.1:40001"),
            dst,
            b"wrong-peer"
        ),
        DatagramDelivery::Unreachable
    );
    assert_eq!(
        sink.incoming(
            current.target.group,
            current.target.attempt,
            src,
            dst,
            b"peer"
        ),
        DatagramDelivery::Queued
    );
    assert_eq!(recv(&*server).0, b"peer");
    server.disconnect().unwrap();
    assert_eq!(server.local_addr().unwrap(), dst);
    assert_eq!(
        sink.incoming(
            current.target.group,
            current.target.attempt,
            src,
            dst,
            b"late"
        ),
        DatagramDelivery::Retired
    );
}

#[test]
fn provider_refusal_preserves_udp_validation_order_without_local_fallback() {
    let (_, left, provider, _, _) = pair();
    provider.refuse.store(true, Ordering::SeqCst);
    let sender = socket(&left, SocketKind::Datagram);
    assert_eq!(
        send(&*sender, b"no-destination", None),
        Err(Errno::EDESTADDRREQ)
    );
    assert_eq!(
        send(&*sender, b"zero-port", Some(addr("127.0.0.1:0"))),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        send(&*sender, &vec![0; 65536], Some(addr("127.0.0.1:8230"))),
        Err(Errno::EMSGSIZE)
    );
    assert!(provider.queries.lock().unwrap().is_empty());
    let local = socket(&left, SocketKind::Datagram);
    local.bind(addr("127.0.0.1:8230"), false).unwrap();
    assert_eq!(
        send(&*sender, b"denied", Some(addr("127.0.0.1:8230"))),
        Err(Errno::EACCES)
    );
    assert_eq!(local.recv(&mut [0; 8], MsgFlags(0)), Err(Errno::EAGAIN));
    assert!(provider.txs.lock().unwrap().is_empty());
}

#[test]
fn provider_gso_never_replays_a_segment_accepted_before_capacity_failure() {
    let (broker, left, provider, right, _) = pair();
    let receiver = socket(&right, SocketKind::Datagram);
    let peer = addr("127.0.0.1:8240");
    receiver.bind(peer, false).unwrap();
    let sender = socket(&left, SocketKind::Datagram);
    send(&*sender, b"warm", Some(peer)).unwrap();
    broker.drive();
    recv(&*receiver);
    let tx = provider.tx();
    tx.fail_after.store(2, Ordering::SeqCst);
    let control = [crate::Control {
        level: 17,
        kind: 103,
        data: 4u16.to_le_bytes().to_vec(),
    }];
    assert_eq!(
        sender.send(SendMsg {
            data: b"abcdefghi",
            to: Some(peer),
            flags: MsgFlags(0),
            control: &control,
            net_raw: false,
            now: Duration::ZERO
        }),
        Ok(9)
    );
    broker.drive();
    assert_eq!(recv(&*receiver).0, b"abcd");
    assert_eq!(receiver.recv(&mut [0; 64], MsgFlags(0)), Err(Errno::EAGAIN));
    tx.fail_after.store(usize::MAX, Ordering::SeqCst);
    broker.drive();
    assert_eq!(tx.sent.load(Ordering::SeqCst), 2);
    assert_eq!(receiver.recv(&mut [0; 64], MsgFlags(0)), Err(Errno::EAGAIN));
}

#[test]
fn udp_retirement_wakes_registered_socket_waiter_for_every_source_reset() {
    for action in ["disconnect", "reassociate", "addrform"] {
        let (_, left, provider, right, _) = pair();
        let receiver = socket(&right, SocketKind::Datagram);
        let peer = addr("127.0.0.1:8250");
        receiver.bind(peer, false).unwrap();
        let domain = if action == "addrform" {
            Domain::Inet6
        } else {
            Domain::Inet
        };
        let sender = left.socket(domain, SocketKind::Datagram, 0, 1).unwrap();
        sender.connect(peer).unwrap();
        send(&*sender, b"start", None).unwrap();
        provider.tx().writable.store(false, Ordering::SeqCst);
        assert_eq!(send(&*sender, b"blocked", None), Err(Errno::EAGAIN));
        let wakes = Arc::new(WakeCount::default());
        let mut registrations = Vec::new();
        let mut register = |queue: &WaitQueue, _| registrations.push(queue.add(wakes.clone()));
        let mut table = PollTable::new(PollMask::OUT, &mut register);
        assert!(!sender.poll(Some(&mut table)).contains(PollMask::OUT));
        let before = wakes.0.load(Ordering::SeqCst);
        match action {
            "disconnect" => sender.disconnect().unwrap(),
            "reassociate" => sender.connect(peer).unwrap(),
            _ => sender.set_option(41, 1, &2i32.to_le_bytes()).unwrap(),
        }
        assert!(
            wakes.0.load(Ordering::SeqCst) > before,
            "no socket wake for {action}"
        );
        assert!(
            sender.poll(None).contains(PollMask::OUT),
            "stale blocked focus for {action}"
        );
    }
}

#[test]
fn udp_selection_shutdown_prevents_both_namespace_and_provider_dispatch() {
    for local in [false, true] {
        let (broker, left, provider, right, _) = pair();
        let receiver = socket(if local { &left } else { &right }, SocketKind::Datagram);
        let peer = addr("127.0.0.1:8260");
        receiver.bind(peer, false).unwrap();
        provider.local_first.store(local, Ordering::SeqCst);
        let sender = socket(&left, SocketKind::Datagram);
        let during_select = sender.clone();
        *provider.select_hook.lock().unwrap() = Some(Box::new(move || {
            assert_eq!(
                during_select.shutdown(crate::Shutdown::Write),
                Err(Errno::ENOTCONN)
            );
        }));
        assert_eq!(
            send(&*sender, b"must-not-arrive", Some(peer)),
            Err(Errno::EPIPE)
        );
        broker.drive();
        assert_eq!(receiver.recv(&mut [0; 64], MsgFlags(0)), Err(Errno::EAGAIN));
        assert!(provider.txs.lock().unwrap().is_empty());
    }
}

#[test]
fn udp_stale_selection_route_consumes_no_payload_and_never_reappends_cork() {
    let (broker, left, provider, right, _) = pair();
    let receiver = socket(&right, SocketKind::Datagram);
    let peer = addr("127.0.0.1:8270");
    receiver.bind(peer, false).unwrap();
    let sender = socket(&left, SocketKind::Datagram);
    assert_eq!(
        sender.send(SendMsg {
            data: b"first",
            to: Some(peer),
            flags: MsgFlags::MSG_MORE,
            control: &[],
            net_raw: false,
            now: Duration::ZERO
        }),
        Ok(5)
    );
    let during_select = Arc::downgrade(&left);
    *provider.select_hook.lock().unwrap() = Some(Box::new(move || {
        during_select.upgrade().unwrap().change_flags(1, 0).unwrap();
    }));
    assert_eq!(send(&*sender, b"second", None), Err(Errno::EAGAIN));
    assert!(provider.txs.lock().unwrap().is_empty());
    left.change_flags(1, 1).unwrap();
    send(&*sender, b"new", Some(peer)).unwrap();
    broker.drive();
    assert_eq!(recv(&*receiver).0, b"new");
    assert_eq!(provider.tx().sent.load(Ordering::SeqCst), 1);
    assert_eq!(receiver.recv(&mut [0; 64], MsgFlags(0)), Err(Errno::EAGAIN));
}

#[test]
fn udp_source_or_route_change_during_unlocked_factory_cannot_accept_payload() {
    for change_source in [false, true] {
        let (broker, left, provider, right, _) = pair();
        let receiver = socket(&right, SocketKind::Datagram);
        let peer = addr("127.0.0.1:8280");
        receiver.bind(peer, false).unwrap();
        let sender = socket(&left, SocketKind::Datagram);
        let socket_hook = sender.clone();
        let net_hook = Arc::downgrade(&left);
        *provider.factory_hook.lock().unwrap() = Some(Box::new(move || {
            if change_source {
                socket_hook.disconnect().unwrap();
            } else {
                net_hook.upgrade().unwrap().change_flags(1, 0).unwrap();
            }
        }));
        assert_eq!(
            send(&*sender, b"stale", Some(peer)),
            Err(if change_source {
                Errno::ECANCELED
            } else {
                Errno::EAGAIN
            })
        );
        assert_eq!(provider.tx().sent.load(Ordering::SeqCst), 0);
        broker.drive();
        assert_eq!(receiver.recv(&mut [0; 64], MsgFlags(0)), Err(Errno::EAGAIN));
    }
}

#[test]
fn queued_tcp_full_wakes_once_after_accept_and_stream_capacity_never_spins() {
    let (broker, left, _, right, _) = pair();
    let listener = socket(&right, SocketKind::Stream);
    let peer = addr("127.0.0.1:8290");
    listener.bind(peer, false).unwrap();
    listener.listen(0).unwrap(); // Linux's accept queue allows backlog + one.
    let first = socket(&left, SocketKind::Stream);
    let second = socket(&left, SocketKind::Stream);
    assert_eq!(first.connect(peer), Err(Errno::EINPROGRESS));
    assert_eq!(second.connect(peer), Err(Errno::EINPROGRESS));
    broker.drive();
    assert_eq!(broker.accepted_tcp.load(Ordering::SeqCst), 1);
    assert_eq!(broker.pending_tcp.lock().unwrap().len(), 1);
    assert!(!second.poll(None).contains(PollMask::OUT));
    let connection_wakes = Arc::new(WakeCount::default());
    let mut connection_registrations = Vec::new();
    let mut register_connection =
        |queue: &WaitQueue, _| connection_registrations.push(queue.add(connection_wakes.clone()));
    assert!(
        !second
            .poll(Some(&mut PollTable::new(
                PollMask::OUT,
                &mut register_connection
            )))
            .contains(PollMask::OUT)
    );
    let connection_before = connection_wakes.0.load(Ordering::SeqCst);
    broker.drive();
    assert_eq!(broker.pending_tcp.lock().unwrap().len(), 1);
    let accepted_first = listener.accept().unwrap().socket;
    assert!(
        broker.pending_tcp.lock().unwrap()[0]
            .wake
            .0
            .load(Ordering::SeqCst)
    );
    broker.drive();
    assert!(broker.pending_tcp.lock().unwrap().is_empty());
    assert_eq!(broker.accepted_tcp.load(Ordering::SeqCst), 2);
    assert!(connection_wakes.0.load(Ordering::SeqCst) > connection_before);
    assert!(second.poll(None).contains(PollMask::OUT));
    let accepted_second = listener.accept().unwrap().socket;
    assert_eq!(listener.accept().unwrap_err(), Errno::EAGAIN);
    assert_eq!(
        send(&*second, &[7; STREAM_CAPACITY], None),
        Ok(STREAM_CAPACITY)
    );
    assert_eq!(send(&*second, b"full", None), Err(Errno::EAGAIN));
    let wakes = Arc::new(WakeCount::default());
    let mut registrations = Vec::new();
    let mut register = |queue: &WaitQueue, _| registrations.push(queue.add(wakes.clone()));
    assert!(
        !second
            .poll(Some(&mut PollTable::new(PollMask::OUT, &mut register)))
            .contains(PollMask::OUT)
    );
    broker.drive();
    assert_eq!(accepted_second.input_len().unwrap(), STREAM_CAPACITY);
    let mut bytes = [0; STREAM_CAPACITY];
    assert_eq!(
        accepted_second.recv(&mut bytes, MsgFlags(0)).unwrap().len,
        STREAM_CAPACITY
    );
    assert_eq!(bytes, [7; STREAM_CAPACITY]);
    assert!(!second.poll(None).contains(PollMask::OUT)); // credits still on driver
    let before = wakes.0.load(Ordering::SeqCst);
    broker.drive();
    assert!(wakes.0.load(Ordering::SeqCst) > before);
    assert!(second.poll(None).contains(PollMask::OUT));
    assert_eq!(broker.accepted_tcp.load(Ordering::SeqCst), 2);
    assert_eq!(accepted_first.input_len().unwrap(), 0);
}

#[test]
fn queued_tcp_full_drops_cancelled_source_and_closed_listener_without_ghost_accept() {
    for cancel_source in [false, true] {
        let (broker, left, _, right, _) = pair();
        let listener = socket(&right, SocketKind::Stream);
        let peer = addr("127.0.0.1:8300");
        listener.bind(peer, false).unwrap();
        listener.listen(0).unwrap();
        let first = socket(&left, SocketKind::Stream);
        let blocked = socket(&left, SocketKind::Stream);
        first.connect(peer).unwrap_err();
        blocked.connect(peer).unwrap_err();
        broker.drive();
        assert_eq!(broker.pending_tcp.lock().unwrap().len(), 1);
        if cancel_source {
            blocked.disconnect().unwrap();
        } else {
            listener.disconnect().unwrap();
        }
        broker.drive();
        assert!(broker.pending_tcp.lock().unwrap().is_empty());
        assert_eq!(broker.accepted_tcp.load(Ordering::SeqCst), 1);
        if cancel_source {
            listener.accept().unwrap();
            assert_eq!(listener.accept().unwrap_err(), Errno::EAGAIN);
            assert_eq!(blocked.peer_addr(), Err(Errno::ENOTCONN));
        } else {
            assert_eq!(blocked.take_error(), Some(Errno::ECONNREFUSED));
        }
    }
}

/// Used by the runtime's private handoff test to hold admission while final owner refs drop.
pub(super) fn teardown_namespace() -> (Arc<Net>, Arc<dyn Socket>) {
    let (_, _, _, net, _) = pair();
    let listener = socket(&net, SocketKind::Stream);
    listener.bind(addr("127.0.0.1:8310"), false).unwrap();
    listener.listen(1).unwrap();
    (net, listener)
}

#[test]
fn udp_source_change_during_pure_selection_does_not_open_transport() {
    let (_, left, provider, right, _) = pair();
    let receiver = socket(&right, SocketKind::Datagram);
    let peer = addr("127.0.0.1:8320");
    receiver.bind(peer, false).unwrap();
    let sender = socket(&left, SocketKind::Datagram);
    let during_select = sender.clone();
    *provider.select_hook.lock().unwrap() = Some(Box::new(move || {
        during_select.disconnect().unwrap();
    }));
    assert_eq!(
        send(&*sender, b"stale-source", Some(peer)),
        Err(Errno::ECANCELED)
    );
    assert!(provider.txs.lock().unwrap().is_empty());
    assert_eq!(receiver.recv(&mut [0; 64], MsgFlags(0)), Err(Errno::EAGAIN));
}

#[test]
fn tcp_room_and_arrival_race_last_namespace_references_without_panic() {
    for _ in 0..16 {
        let (_, _, _, net, provider) = pair();
        let listener = socket(&net, SocketKind::Stream);
        let dst = addr("127.0.0.1:8330");
        let src = addr("127.0.0.1:40000");
        listener.bind(dst, false).unwrap();
        listener.listen(1).unwrap();
        let record = provider.records().pop().unwrap();
        let Sink::Tcp(sink) = record.sink else {
            unreachable!()
        };
        let worker_sink = sink.clone();
        let start = Arc::new(std::sync::Barrier::new(2));
        let worker_start = start.clone();
        let worker = std::thread::spawn(move || {
            worker_start.wait();
            for _ in 0..32 {
                let _ = worker_sink.poll_room_to(src, dst, None);
                let [stream, _] =
                    crate::MemoryStream::pair([dst, src], [WaitQueue::new(), WaitQueue::new()]);
                let _ = worker_sink.incoming_to(src, dst, stream, WaitQueue::new());
            }
        });
        start.wait();
        drop(listener);
        drop(net);
        worker.join().unwrap();
        assert_eq!(sink.poll_room_to(src, dst, None), Room::Gone);
        let [stream, _] =
            crate::MemoryStream::pair([dst, src], [WaitQueue::new(), WaitQueue::new()]);
        assert!(!sink.incoming_to(src, dst, stream, WaitQueue::new()));
    }
}
