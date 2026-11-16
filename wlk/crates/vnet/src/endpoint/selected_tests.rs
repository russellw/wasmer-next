//! Selected UDP resource mutation and ingress tests.
//!
//! These use the real namespace socket, bind admission, membership state, and ingress path;
//! the provider only records the bounded external operations the namespace delegates.

use super::*;
use crate::api::Network;
use crate::{
    Backend, BackendDatagram, BackendStream, Domain, Net, NetConfig, NetworkPolicy,
    PolicyDirection, Publication, SendMsg, Socket, SocketKind,
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
};
use wasixv2_abi::{Errno, IpOption, Ipv6Option, MsgFlags, SocketLevel, SocketOption};
use wasixv2_wait::{PollMask, PollTable, Pollable, WaitQueue};

#[derive(Clone, Copy)]
enum Selection {
    Namespace,
    Provider,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QueryRecord {
    source_id: EndpointSourceId,
    bound: Option<SocketAddr>,
    requested_bind: Option<SocketAddr>,
    binding_present: bool,
    destination: SocketAddr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SetCall {
    resource: usize,
    level: i32,
    name: i32,
    value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConnectCall {
    resource: usize,
    source: EndpointSourceId,
    peer: Option<SocketAddr>,
}

enum SetAction {
    Fail(Errno),
    AcceptThenFail(Errno),
}

enum ConnectAction {
    FailUnchanged(Errno),
    FailAfterPeerChange(Errno),
    FailWithUnknownPeer(Errno),
    SucceedWithLocal(SocketAddr),
}

struct SelectGate {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

#[derive(Clone)]
struct PublishedSnapshot {
    group: EndpointGroupId,
    attempt: PublicationAttemptId,
    members: Vec<EndpointSourceId>,
    ingress: Arc<dyn EndpointDatagramIngress>,
}

struct ProviderState {
    external: bool,
    select_bind: AtomicBool,
    pending_binds: AtomicBool,
    bind_addresses: Mutex<VecDeque<SocketAddr>>,
    bind_count: AtomicUsize,
    select_bind_calls: AtomicUsize,
    next_resource: AtomicUsize,
    resources: Mutex<Vec<(usize, Weak<Resource>)>>,
    choice: Mutex<Selection>,
    select_calls: Mutex<Vec<QueryRecord>>,
    next_select_gate: Mutex<Option<Arc<SelectGate>>>,
    set_actions: Mutex<HashMap<usize, VecDeque<SetAction>>>,
    set_calls: Mutex<Vec<SetCall>>,
    accepted_sets: Mutex<Vec<SetCall>>,
    connect_actions: Mutex<HashMap<usize, VecDeque<ConnectAction>>>,
    connect_calls: Mutex<Vec<ConnectCall>>,
    publications: Mutex<Vec<PublishedSnapshot>>,
    endpoint_datagram_factories: AtomicUsize,
    backend_datagram_factories: AtomicUsize,
    host_sends: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
}

impl ProviderState {
    fn new(addresses: impl IntoIterator<Item = SocketAddr>) -> Arc<Self> {
        Arc::new(Self {
            external: true,
            select_bind: AtomicBool::new(true),
            pending_binds: AtomicBool::new(false),
            bind_addresses: Mutex::new(addresses.into_iter().collect()),
            bind_count: AtomicUsize::new(0),
            select_bind_calls: AtomicUsize::new(0),
            next_resource: AtomicUsize::new(1),
            resources: Mutex::new(Vec::new()),
            choice: Mutex::new(Selection::Namespace),
            select_calls: Mutex::new(Vec::new()),
            next_select_gate: Mutex::new(None),
            set_actions: Mutex::new(HashMap::new()),
            set_calls: Mutex::new(Vec::new()),
            accepted_sets: Mutex::new(Vec::new()),
            connect_actions: Mutex::new(HashMap::new()),
            connect_calls: Mutex::new(Vec::new()),
            publications: Mutex::new(Vec::new()),
            endpoint_datagram_factories: AtomicUsize::new(0),
            backend_datagram_factories: AtomicUsize::new(0),
            host_sends: Mutex::new(Vec::new()),
        })
    }

    fn resource_ids(&self) -> Vec<usize> {
        self.resources
            .lock()
            .unwrap()
            .iter()
            .map(|(id, _)| *id)
            .collect()
    }

    fn resource_weak(&self, id: usize) -> Weak<Resource> {
        self.resources
            .lock()
            .unwrap()
            .iter()
            .find(|(candidate, _)| *candidate == id)
            .unwrap()
            .1
            .clone()
    }

    fn ready_resource(&self, id: usize) {
        let resource = self
            .resources
            .lock()
            .unwrap()
            .iter()
            .find(|(candidate, _)| *candidate == id)
            .unwrap()
            .1
            .upgrade()
            .unwrap();
        resource.ready.store(true, Ordering::Release);
        resource.wait.wake(PollMask::OUT);
    }

    fn add_set_action(&self, resource: usize, action: SetAction) {
        self.set_actions
            .lock()
            .unwrap()
            .entry(resource)
            .or_default()
            .push_back(action);
    }

    fn add_connect_action(&self, resource: usize, action: ConnectAction) {
        self.connect_actions
            .lock()
            .unwrap()
            .entry(resource)
            .or_default()
            .push_back(action);
    }

    fn latest_publication(&self) -> PublishedSnapshot {
        self.publications.lock().unwrap().last().unwrap().clone()
    }

    fn block_next_select(&self, entered: mpsc::Sender<()>, release: mpsc::Receiver<()>) {
        *self.next_select_gate.lock().unwrap() = Some(Arc::new(SelectGate {
            entered,
            release: Mutex::new(release),
        }));
    }
}

struct Provider(Arc<ProviderState>);

impl Provider {
    fn new(addresses: impl IntoIterator<Item = SocketAddr>) -> Arc<Self> {
        Arc::new(Self(ProviderState::new(addresses)))
    }

    fn select_bind(&self, selected: bool) {
        self.0.select_bind.store(selected, Ordering::SeqCst);
    }

    fn select_as(&self, selection: Selection) {
        *self.0.choice.lock().unwrap() = selection;
    }
}

struct PhysicalPeer {
    known: bool,
    peer: Option<SocketAddr>,
}

struct Resource {
    id: usize,
    local: Mutex<SocketAddr>,
    ready: AtomicBool,
    wait: WaitQueue,
    state: Arc<ProviderState>,
    peer: Mutex<PhysicalPeer>,
}

impl Pollable for Resource {
    fn poll(&self, mut table: Option<&mut PollTable<'_>>) -> PollMask {
        wasixv2_wait::poll_wait(&mut table, &self.wait);
        if self.ready.load(Ordering::Acquire) {
            PollMask::OUT
        } else {
            PollMask::empty()
        }
    }
}

impl EndpointBound for Resource {
    fn local_addr(&self) -> Result<SocketAddr, Errno> {
        if self.ready.load(Ordering::Acquire) {
            Ok(*self.local.lock().unwrap())
        } else {
            Err(Errno::EAGAIN)
        }
    }

    fn set_option(&self, level: i32, name: i32, value: &[u8]) -> Result<(), Errno> {
        let call = SetCall {
            resource: self.id,
            level,
            name,
            value: value.to_vec(),
        };
        self.state.set_calls.lock().unwrap().push(call.clone());
        let action = self
            .state
            .set_actions
            .lock()
            .unwrap()
            .get_mut(&self.id)
            .and_then(VecDeque::pop_front);
        match action {
            Some(SetAction::Fail(error)) => Err(error),
            Some(SetAction::AcceptThenFail(error)) => {
                self.state.accepted_sets.lock().unwrap().push(call);
                Err(error)
            }
            None => {
                self.state.accepted_sets.lock().unwrap().push(call);
                Ok(())
            }
        }
    }

    fn connect_datagram(
        &self,
        source: EndpointSourceId,
        peer: Option<SocketAddr>,
    ) -> Option<Result<(), Errno>> {
        self.state.connect_calls.lock().unwrap().push(ConnectCall {
            resource: self.id,
            source,
            peer,
        });
        let action = self
            .state
            .connect_actions
            .lock()
            .unwrap()
            .get_mut(&self.id)
            .and_then(VecDeque::pop_front);
        let mut state = self.peer.lock().unwrap();
        match action {
            Some(ConnectAction::FailUnchanged(error)) => Some(Err(error)),
            Some(ConnectAction::FailAfterPeerChange(error)) => {
                state.peer = peer;
                state.known = true;
                Some(Err(error))
            }
            Some(ConnectAction::FailWithUnknownPeer(error)) => {
                state.known = false;
                Some(Err(error))
            }
            Some(ConnectAction::SucceedWithLocal(local)) => {
                *self.local.lock().unwrap() = local;
                state.peer = peer;
                state.known = true;
                Some(Ok(()))
            }
            None => {
                state.peer = peer;
                state.known = true;
                Some(Ok(()))
            }
        }
    }

    fn datagram_peer_addr(&self) -> Option<Result<Option<SocketAddr>, Errno>> {
        let state = self.peer.lock().unwrap();
        state.known.then_some(Ok(state.peer))
    }
}

impl EndpointProvider for Provider {
    fn select_external(&self) -> bool {
        self.0.external
    }

    fn select_bind(&self, _: &EndpointBindRequest) -> Result<bool, Errno> {
        self.0.select_bind_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.0.select_bind.load(Ordering::SeqCst))
    }

    fn bind(
        &self,
        request: EndpointBindRequest,
        _: WaitQueue,
    ) -> Result<Option<Arc<dyn EndpointBound>>, Errno> {
        self.0.bind_count.fetch_add(1, Ordering::SeqCst);
        let id = self.0.next_resource.fetch_add(1, Ordering::SeqCst);
        let local = self
            .0
            .bind_addresses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| {
                let port = if request.requested.port() == 0 {
                    47_000 + id as u16
                } else {
                    request.requested.port()
                };
                SocketAddr::new(request.requested.ip(), port)
            });
        let resource = Arc::new(Resource {
            id,
            local: Mutex::new(local),
            ready: AtomicBool::new(!self.0.pending_binds.load(Ordering::SeqCst)),
            wait: WaitQueue::new(),
            state: self.0.clone(),
            peer: Mutex::new(PhysicalPeer {
                known: true,
                peer: None,
            }),
        });
        self.0
            .resources
            .lock()
            .unwrap()
            .push((id, Arc::downgrade(&resource)));
        let resource: Arc<dyn EndpointBound> = resource;
        Ok(Some(resource))
    }

    fn select(&self, query: &EndpointQuery) -> Result<EndpointChoice, Errno> {
        self.0.select_calls.lock().unwrap().push(QueryRecord {
            source_id: query.source_id,
            bound: query.bound,
            requested_bind: query.requested_bind,
            binding_present: query.binding.is_some(),
            destination: query.destination,
        });
        if let Some(gate) = self.0.next_select_gate.lock().unwrap().take() {
            gate.entered.send(()).unwrap();
            gate.release.lock().unwrap().recv().unwrap();
        }
        Ok(match *self.0.choice.lock().unwrap() {
            Selection::Namespace => EndpointChoice::Namespace,
            Selection::Provider => EndpointChoice::Provider(EndpointTarget::new(())),
        })
    }

    fn datagram(
        &self,
        _: EndpointSource,
        _: UdpTxConfig,
        _: WaitQueue,
    ) -> Result<Arc<dyn EndpointDatagramTx>, Errno> {
        self.0
            .endpoint_datagram_factories
            .fetch_add(1, Ordering::SeqCst);
        Err(Errno::EOPNOTSUPP)
    }

    fn publish_udp(
        &self,
        group: EndpointGroupSpec,
        ingress: Arc<dyn EndpointDatagramIngress>,
        status: PublicationReporter,
    ) -> Result<Arc<dyn EndpointLease>, Errno> {
        self.0.publications.lock().unwrap().push(PublishedSnapshot {
            group: group.group_id,
            attempt: group.attempt_id,
            members: group
                .members
                .iter()
                .map(|member| member.source_id)
                .collect(),
            ingress,
        });
        status.ready();
        Ok(Arc::new(Lease {
            state: self.0.clone(),
            group: group.group_id,
            attempt: group.attempt_id,
            status,
        }))
    }
}

struct Lease {
    state: Arc<ProviderState>,
    group: EndpointGroupId,
    attempt: PublicationAttemptId,
    status: PublicationReporter,
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

    fn update_members(&self, _: u64, members: Arc<[EndpointMember]>) {
        let mut publications = self.state.publications.lock().unwrap();
        let publication = publications
            .iter_mut()
            .rev()
            .find(|p| p.group == self.group && p.attempt == self.attempt)
            .unwrap();
        publication.members = members.iter().map(|member| member.source_id).collect();
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
        self.0
            .0
            .backend_datagram_factories
            .fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(HostDatagram(self.0.0.clone())))
    }

    fn publish(
        &self,
        _: SocketAddr,
        _: u32,
        _: Arc<dyn crate::InboundSink>,
    ) -> io::Result<Box<dyn Publication>> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

struct HostDatagram(Arc<ProviderState>);

impl Pollable for HostDatagram {
    fn poll(&self, _: Option<&mut PollTable<'_>>) -> PollMask {
        PollMask::OUT
    }
}

impl BackendDatagram for HostDatagram {
    fn send_to(&self, data: &[u8], to: SocketAddr) -> Result<usize, Errno> {
        self.0.host_sends.lock().unwrap().push((data.to_vec(), to));
        Ok(data.len())
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
}

fn network(provider: &Arc<Provider>, config: NetConfig) -> Arc<Net> {
    Net::new(config, Some(Arc::new(Adapter(provider.clone()))))
}

fn socket(net: &Arc<Net>, domain: Domain) -> Arc<dyn Socket> {
    net.socket(domain, SocketKind::Datagram, 0, 1).unwrap()
}

fn bind_selected(socket: &dyn Socket, address: SocketAddr) {
    let admission = socket.bind_admission(address, false).unwrap().unwrap();
    admission.complete().unwrap();
}

fn int(value: i32) -> [u8; 4] {
    value.to_le_bytes()
}

fn get_int(socket: &dyn Socket, level: i32, name: i32) -> i32 {
    let mut out = [0; 4];
    assert_eq!(socket.get_option(level, name, &mut out).unwrap(), out.len());
    i32::from_le_bytes(out)
}

fn mreqn(group: &str, address: &str, index: u32) -> Vec<u8> {
    let group = group.parse::<Ipv4Addr>().unwrap().octets();
    let address = address.parse::<Ipv4Addr>().unwrap().octets();
    [&group[..], &address, &index.to_le_bytes()].concat()
}

fn mreq6(group: &str, index: u32) -> Vec<u8> {
    let group = group.parse::<Ipv6Addr>().unwrap().octets();
    [&group[..], &index.to_le_bytes()].concat()
}

fn receive(socket: &dyn Socket) -> Result<(Vec<u8>, crate::RecvMsg), Errno> {
    let mut bytes = [0; 64];
    let message = socket.recv(&mut bytes, MsgFlags(0))?;
    Ok((bytes[..message.len].to_vec(), message))
}

fn inject(
    publication: &PublishedSnapshot,
    member: EndpointSourceId,
    info: DatagramInfo,
    bytes: &[u8],
) -> DatagramDelivery {
    publication.ingress.incoming_member_packet(
        publication.group,
        publication.attempt,
        member,
        info,
        bytes,
    )
}

#[test]
fn selected_provider_option_error_does_not_commit_socket_value() {
    let provider = Provider::new(["0.0.0.0:47001".parse().unwrap()]);
    let net = network(&provider, NetConfig::host_default());
    let socket = socket(&net, Domain::Inet);
    let local: SocketAddr = "0.0.0.0:47001".parse().unwrap();
    bind_selected(&*socket, local);
    let resource = provider.0.resource_ids()[0];

    assert_eq!(
        get_int(
            &*socket,
            SocketLevel::SOL_IP.0,
            IpOption::IP_MULTICAST_TTL.0
        ),
        1
    );
    provider
        .0
        .add_set_action(resource, SetAction::Fail(Errno::EIO));
    assert_eq!(
        socket.set_option(
            SocketLevel::SOL_IP.0,
            IpOption::IP_MULTICAST_TTL.0,
            &int(23),
        ),
        Err(Errno::EIO)
    );

    assert_eq!(
        get_int(
            &*socket,
            SocketLevel::SOL_IP.0,
            IpOption::IP_MULTICAST_TTL.0
        ),
        1
    );
    assert_eq!(provider.0.set_calls.lock().unwrap().len(), 1);
    assert!(provider.0.accepted_sets.lock().unwrap().is_empty());
    assert_eq!(socket.local_addr().unwrap(), local);
    assert!(provider.0.resource_weak(resource).upgrade().is_some());
}

#[test]
fn prebind_membership_replay_distinguishes_pending_from_terminal_eagain() {
    let provider = Provider::new(["127.0.0.1:47002".parse().unwrap()]);
    provider.0.pending_binds.store(true, Ordering::SeqCst);
    let net = network(&provider, NetConfig::default());
    let socket = socket(&net, Domain::Inet);
    let membership = mreqn("239.1.2.3", "127.0.0.1", 0);

    socket
        .set_option(
            SocketLevel::SOL_IP.0,
            IpOption::IP_ADD_MEMBERSHIP.0,
            &membership,
        )
        .unwrap();
    let admission = socket
        .bind_admission("127.0.0.1:0".parse().unwrap(), false)
        .unwrap()
        .unwrap();
    let resource = provider.0.resource_ids()[0];
    assert_eq!(admission.complete_result(), None);

    provider.0.ready_resource(resource);
    provider
        .0
        .add_set_action(resource, SetAction::AcceptThenFail(Errno::EAGAIN));
    assert_eq!(admission.complete_result(), Some(Err(Errno::EAGAIN)));
    assert_eq!(admission.complete_result(), Some(Err(Errno::EAGAIN)));
    assert_eq!(provider.0.set_calls.lock().unwrap().len(), 1);
    assert_eq!(provider.0.accepted_sets.lock().unwrap().len(), 1);
    assert_eq!(provider.0.bind_count.load(Ordering::SeqCst), 1);
    assert_eq!(socket.local_addr().unwrap().port(), 0);
    assert!(provider.0.publications.lock().unwrap().is_empty());

    drop(admission);
    assert!(provider.0.resource_weak(resource).upgrade().is_none());
}

#[test]
fn physical_membership_survives_namespace_interface_removal() {
    let provider = Provider::new([
        "0.0.0.0:47010".parse().unwrap(),
        "0.0.0.0:47011".parse().unwrap(),
    ]);
    let net = network(&provider, NetConfig::host_default());
    let first = socket(&net, Domain::Inet);
    let sibling = socket(&net, Domain::Inet);
    let first_local: SocketAddr = "0.0.0.0:47010".parse().unwrap();
    let sibling_local: SocketAddr = "0.0.0.0:47011".parse().unwrap();
    bind_selected(&*first, first_local);
    bind_selected(&*sibling, sibling_local);
    let ids = provider.0.resource_ids();
    // Change the namespace independently, outside the provider callback. This physical
    // membership has no synthetic namespace-interface reference to fail during commit.
    net.update_interfaces(|interfaces| interfaces.remove(crate::iface::LOOPBACK_INDEX).unwrap());
    assert!(
        net.interfaces()
            .iter()
            .all(|interface| interface.index != crate::iface::LOOPBACK_INDEX)
    );

    assert_eq!(
        first.set_option(
            SocketLevel::SOL_IP.0,
            IpOption::IP_ADD_MEMBERSHIP.0,
            &mreqn("239.2.3.4", "127.0.0.1", 0),
        ),
        Ok(())
    );
    assert_eq!(first.local_addr().unwrap(), first_local);
    assert_eq!(sibling.local_addr().unwrap(), sibling_local);
    assert!(provider.0.resource_weak(ids[0]).upgrade().is_some());
    assert!(provider.0.resource_weak(ids[1]).upgrade().is_some());
    assert_eq!(provider.0.accepted_sets.lock().unwrap().len(), 1);
    assert_eq!(
        provider.0.accepted_sets.lock().unwrap()[0].value,
        mreqn("239.2.3.4", "127.0.0.1", 0)
    );
}

#[test]
fn physical_udp_membership_targets_its_exact_reuse_member_across_replacement() {
    let local: SocketAddr = "0.0.0.0:47020".parse().unwrap();
    let provider = Provider::new([local, local, local]);
    let net = network(&provider, NetConfig::host_default());
    let reuse = int(1);
    let make_member = || {
        let socket = socket(&net, Domain::Inet);
        socket
            .set_option(
                SocketLevel::SOL_SOCKET.0,
                SocketOption::SO_REUSEPORT.0,
                &reuse,
            )
            .unwrap();
        bind_selected(&*socket, local);
        socket
    };
    let first = make_member();
    let second = make_member();
    let membership = mreqn("239.3.4.5", "0.0.0.0", 77);
    for socket in [&first, &second] {
        socket
            .set_option(
                SocketLevel::SOL_IP.0,
                IpOption::IP_ADD_MEMBERSHIP.0,
                &membership,
            )
            .unwrap();
    }

    let initial = provider.0.latest_publication();
    assert_eq!(initial.members.len(), 2);
    let first_id = initial.members[0];
    let second_id = initial.members[1];
    let info = DatagramInfo {
        source: "198.51.100.3:49000".parse().unwrap(),
        destination: "239.3.4.5:47020".parse().unwrap(),
        interface: 77,
    };
    assert_eq!(
        inject(&initial, first_id, info, b"first"),
        DatagramDelivery::Queued
    );
    assert_eq!(receive(&*first).unwrap().0, b"first");
    assert_eq!(receive(&*second), Err(Errno::EAGAIN));

    drop(first);
    assert_eq!(
        inject(&initial, first_id, info, b"stale"),
        DatagramDelivery::Retired
    );
    let replacement = make_member();
    replacement
        .set_option(
            SocketLevel::SOL_IP.0,
            IpOption::IP_ADD_MEMBERSHIP.0,
            &membership,
        )
        .unwrap();
    let current = provider.0.latest_publication();
    assert_eq!(current.group, initial.group);
    assert_eq!(current.attempt, initial.attempt);
    assert_eq!(current.members.len(), 2);
    let replacement_id = *current
        .members
        .iter()
        .find(|member| **member != second_id)
        .unwrap();
    assert_ne!(replacement_id, first_id);
    assert_eq!(
        inject(&current, replacement_id, info, b"replacement"),
        DatagramDelivery::Queued
    );
    assert_eq!(receive(&*replacement).unwrap().0, b"replacement");
    assert_eq!(receive(&*second), Err(Errno::EAGAIN));
}

#[test]
fn absent_namespace_ipv6_interface_keeps_scoped_ingress_metadata() {
    let local: SocketAddr = "[::]:47030".parse().unwrap();
    let provider = Provider::new([local]);
    let net = network(&provider, NetConfig::host_default());
    let socket = socket(&net, Domain::Inet6);
    bind_selected(&*socket, local);
    socket
        .set_option(
            SocketLevel::SOL_IPV6.0,
            Ipv6Option::IPV6_RECVPKTINFO.0,
            &int(1),
        )
        .unwrap();
    let membership = mreq6("ff02::1234", 77);
    socket
        .set_option(
            SocketLevel::SOL_IPV6.0,
            Ipv6Option::IPV6_ADD_MEMBERSHIP.0,
            &membership,
        )
        .unwrap();
    assert!(
        !net.interfaces()
            .iter()
            .any(|interface| interface.index == 77)
    );
    assert_eq!(
        provider.0.set_calls.lock().unwrap().last().unwrap().value,
        membership
    );

    let publication = provider.0.latest_publication();
    let member = publication.members[0];
    let source = SocketAddr::V6(SocketAddrV6::new(
        "fe80::abcd".parse().unwrap(),
        49000,
        0x1234,
        77,
    ));
    let destination = SocketAddr::V6(SocketAddrV6::new(
        "ff02::1234".parse().unwrap(),
        47030,
        0x5678,
        77,
    ));
    let info = DatagramInfo {
        source,
        destination,
        interface: 77,
    };
    assert_eq!(
        inject(&publication, member, info, b"scoped"),
        DatagramDelivery::Queued
    );
    let (bytes, message) = receive(&*socket).unwrap();
    assert_eq!(bytes, b"scoped");
    assert_eq!(message.from, Some(source));
    let pktinfo = message
        .control
        .iter()
        .find(|control| {
            control.level == SocketLevel::SOL_IPV6.0 && control.kind == Ipv6Option::IPV6_PKTINFO.0
        })
        .unwrap();
    assert_eq!(
        crate::cmsg::read_in6_pktinfo(&pktinfo.data).unwrap(),
        ("ff02::1234".parse().unwrap(), 77)
    );
}

#[derive(Debug)]
struct DenyInbound;

impl NetworkPolicy for DenyInbound {
    fn allows_socket(&self, _: SocketAddr, direction: PolicyDirection) -> bool {
        direction != PolicyDirection::Inbound
    }

    fn allows_domain(&self, _: &str) -> bool {
        true
    }

    fn resolved_domain(&self, _: &str, _: &[IpAddr]) {}
}

#[test]
fn policy_denial_precedes_provider_resource_creation() {
    let provider = Provider::new([]);
    let mut config = NetConfig::host_default();
    config.policy = Some(Arc::new(DenyInbound));
    let net = network(&provider, config);
    let socket = socket(&net, Domain::Inet);

    assert!(matches!(
        socket.bind_admission("192.0.2.40:47040".parse().unwrap(), false),
        Err(Errno::EPERM)
    ));
    assert_eq!(provider.0.select_bind_calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.0.bind_count.load(Ordering::SeqCst), 0);
    assert!(provider.0.resources.lock().unwrap().is_empty());
    assert!(provider.0.set_calls.lock().unwrap().is_empty());
    assert!(provider.0.publications.lock().unwrap().is_empty());
}

#[test]
fn pure_bind_decline_keeps_namespace_address_validation() {
    let provider = Provider::new([]);
    provider.select_bind(false);
    let net = network(&provider, NetConfig::host_default());
    let socket = socket(&net, Domain::Inet);
    let requested: SocketAddr = "192.0.2.41:47041".parse().unwrap();

    assert!(socket.bind_admission(requested, false).unwrap().is_none());
    assert_eq!(socket.bind(requested, false), Err(Errno::EADDRNOTAVAIL));
    assert_eq!(provider.0.select_bind_calls.load(Ordering::SeqCst), 1);
    // A declining capability must also retain ordinary address-before-port error order.
    let low_port: SocketAddr = "192.0.2.41:1".parse().unwrap();
    assert!(socket.bind_admission(low_port, false).unwrap().is_none());
    assert_eq!(socket.bind(low_port, false), Err(Errno::EADDRNOTAVAIL));
    provider.select_bind(true);
    assert!(matches!(
        socket.bind_admission(low_port, false),
        Err(Errno::EACCES)
    ));
    assert_eq!(provider.0.bind_count.load(Ordering::SeqCst), 0);
    assert!(provider.0.resources.lock().unwrap().is_empty());
}

#[test]
fn namespace_selection_keeps_payload_validation_and_uses_the_namespace_route() {
    let provider = Provider::new([]);
    provider.select_as(Selection::Namespace);
    let net = network(&provider, NetConfig::host_default());
    let socket = socket(&net, Domain::Inet);
    let destination: SocketAddr = "203.0.113.42:49042".parse().unwrap();
    let oversized = vec![0; 65_508];
    assert_eq!(
        socket.send(SendMsg {
            data: &oversized,
            to: Some(destination),
            flags: MsgFlags(0),
            control: &[],
            net_raw: false,
            now: std::time::Duration::ZERO,
        }),
        Err(Errno::EMSGSIZE)
    );
    assert!(provider.0.select_calls.lock().unwrap().is_empty());
    assert!(provider.0.host_sends.lock().unwrap().is_empty());

    assert_eq!(
        socket.send(SendMsg {
            data: b"ok",
            to: Some(destination),
            flags: MsgFlags(0),
            control: &[],
            net_raw: false,
            now: std::time::Duration::ZERO,
        }),
        Ok(2)
    );
    let queries = provider.0.select_calls.lock().unwrap();
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].destination, destination);
    drop(queries);
    assert_eq!(
        provider.0.host_sends.lock().unwrap().as_slice(),
        &[(b"ok".to_vec(), destination)]
    );
    assert_eq!(
        provider
            .0
            .endpoint_datagram_factories
            .load(Ordering::SeqCst),
        0
    );
}

#[test]
fn option_change_during_pure_selection_retires_stale_connect_witness() {
    let local: SocketAddr = "0.0.0.0:47050".parse().unwrap();
    let provider = Provider::new([local]);
    provider.select_as(Selection::Provider);
    let net = network(&provider, NetConfig::host_default());
    let socket = socket(&net, Domain::Inet);
    bind_selected(&*socket, local);
    let resource = provider.0.resource_ids()[0];
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    provider.0.block_next_select(entered_tx, release_rx);

    let connecting = socket.clone();
    let destination: SocketAddr = "203.0.113.50:49050".parse().unwrap();
    let worker = std::thread::spawn(move || connecting.connect(destination));
    entered_rx.recv().unwrap();
    socket
        .set_option(SocketLevel::SOL_IP.0, IpOption::IP_TTL.0, &int(37))
        .unwrap();
    release_tx.send(()).unwrap();

    assert_eq!(worker.join().unwrap(), Err(Errno::ECANCELED));
    assert_eq!(socket.peer_addr(), Err(Errno::ENOTCONN));
    assert_eq!(socket.local_addr().unwrap(), local);
    assert_eq!(
        get_int(&*socket, SocketLevel::SOL_IP.0, IpOption::IP_TTL.0),
        37
    );
    assert!(provider.0.connect_calls.lock().unwrap().is_empty());
    assert!(provider.0.resource_weak(resource).upgrade().is_some());
}

#[test]
fn failed_physical_connect_uses_fresh_epoch_and_retires_only_changed_or_unknown_resources() {
    let addresses = [
        "0.0.0.0:47060".parse().unwrap(),
        "0.0.0.0:47061".parse().unwrap(),
        "0.0.0.0:47062".parse().unwrap(),
    ];
    let provider = Provider::new(addresses);
    provider.select_as(Selection::Provider);
    let net = network(&provider, NetConfig::host_default());
    let first = socket(&net, Domain::Inet);
    let second = socket(&net, Domain::Inet);
    let sibling = socket(&net, Domain::Inet);
    for (socket, local) in [
        (&first, "0.0.0.0:47060".parse().unwrap()),
        (&second, "0.0.0.0:47061".parse().unwrap()),
        (&sibling, "0.0.0.0:47062".parse().unwrap()),
    ] {
        bind_selected(&**socket, local);
    }
    let ids = provider.0.resource_ids();
    let first_peer: SocketAddr = "203.0.113.60:49600".parse().unwrap();
    let second_peer: SocketAddr = "203.0.113.61:49601".parse().unwrap();
    let sibling_peer: SocketAddr = "203.0.113.62:49602".parse().unwrap();
    first.connect(first_peer).unwrap();
    second.connect(second_peer).unwrap();
    sibling.connect(sibling_peer).unwrap();

    provider
        .0
        .add_connect_action(ids[0], ConnectAction::FailUnchanged(Errno::EIO));
    let first_local = first.local_addr().unwrap();
    assert_eq!(
        first.connect("203.0.113.63:49603".parse().unwrap()),
        Err(Errno::EIO)
    );
    assert_eq!(first.peer_addr(), Ok(first_peer));
    assert_eq!(first.local_addr().unwrap(), first_local);
    let first_calls: Vec<_> = provider
        .0
        .connect_calls
        .lock()
        .unwrap()
        .iter()
        .filter(|call| call.resource == ids[0])
        .cloned()
        .collect();
    assert_eq!(first_calls.len(), 2);
    assert_ne!(first_calls[0].source, first_calls[1].source);
    assert!(provider.0.resource_weak(ids[0]).upgrade().is_some());

    provider
        .0
        .add_connect_action(ids[0], ConnectAction::FailAfterPeerChange(Errno::EIO));
    assert_eq!(
        first.connect("203.0.113.64:49604".parse().unwrap()),
        Err(Errno::EIO)
    );
    assert_eq!(first.local_addr().unwrap().port(), 0);
    assert_eq!(first.peer_addr(), Err(Errno::ENOTCONN));
    assert!(provider.0.resource_weak(ids[0]).upgrade().is_none());
    assert_eq!(second.local_addr().unwrap().port(), 47061);
    assert_eq!(second.peer_addr(), Ok(second_peer));
    assert_eq!(sibling.local_addr().unwrap().port(), 47062);
    assert_eq!(sibling.peer_addr(), Ok(sibling_peer));

    provider
        .0
        .add_connect_action(ids[1], ConnectAction::FailWithUnknownPeer(Errno::EIO));
    assert_eq!(
        second.connect("203.0.113.65:49605".parse().unwrap()),
        Err(Errno::EIO)
    );
    assert_eq!(second.local_addr().unwrap().port(), 0);
    assert_eq!(second.peer_addr(), Err(Errno::ENOTCONN));
    assert!(provider.0.resource_weak(ids[1]).upgrade().is_none());
    assert_eq!(sibling.local_addr().unwrap().port(), 47062);
    assert_eq!(sibling.peer_addr(), Ok(sibling_peer));
    assert!(provider.0.resource_weak(ids[2]).upgrade().is_some());
}

#[test]
fn successful_physical_connect_conflict_retires_only_its_captured_resource() {
    let first_local: SocketAddr = "0.0.0.0:47012".parse().unwrap();
    let sibling_local: SocketAddr = "0.0.0.0:47013".parse().unwrap();
    let provider = Provider::new([first_local, sibling_local]);
    provider.select_as(Selection::Provider);
    let net = network(&provider, NetConfig::host_default());
    let first = socket(&net, Domain::Inet);
    let sibling = socket(&net, Domain::Inet);
    // Literal port zero permits the resource's later actual-port reconciliation;
    // both distinct original reservations come from real admitted bind transactions.
    bind_selected(&*first, "0.0.0.0:0".parse().unwrap());
    bind_selected(&*sibling, "0.0.0.0:0".parse().unwrap());
    assert_eq!(first.local_addr(), Ok(first_local));
    assert_eq!(sibling.local_addr(), Ok(sibling_local));
    assert_ne!(first_local.port(), sibling_local.port());
    let ids = provider.0.resource_ids();
    provider
        .0
        .add_connect_action(ids[0], ConnectAction::SucceedWithLocal(sibling_local));
    let peer: SocketAddr = "203.0.113.12:49012".parse().unwrap();

    assert_eq!(first.connect(peer), Err(Errno::EADDRINUSE));
    assert_eq!(first.local_addr().unwrap().port(), 0);
    assert_eq!(first.peer_addr(), Err(Errno::ENOTCONN));
    assert!(provider.0.resource_weak(ids[0]).upgrade().is_none());
    assert_eq!(sibling.local_addr(), Ok(sibling_local));
    assert!(provider.0.resource_weak(ids[1]).upgrade().is_some());
    // A healthy sibling still uses its original bound resource and reservation.
    let sibling_peer: SocketAddr = "203.0.113.13:49013".parse().unwrap();
    assert_eq!(sibling.connect(sibling_peer), Ok(()));
    assert_eq!(sibling.local_addr(), Ok(sibling_local));
    assert_eq!(sibling.peer_addr(), Ok(sibling_peer));
    assert_eq!(provider.0.bind_count.load(Ordering::SeqCst), 2);
    let calls = provider.0.connect_calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!((calls[0].resource, calls[0].peer), (ids[0], Some(peer)));
    assert_eq!(
        (calls[1].resource, calls[1].peer),
        (ids[1], Some(sibling_peer))
    );
}
