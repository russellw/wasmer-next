//! Namespace-local groups and publication custody. Only explicit socket operations and
//! driver ingress call refresh; cascading destruction never invokes provider control code.
use super::*;
use crate::{Net, Socket, addr::canonical, net::serves, tcp::TcpSocket, udp::UdpSocket};
use std::{
    collections::HashMap,
    sync::{
        Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Key {
    kind: EndpointKind,
    local: SocketAddr,
    domain: Domain,
    v6only: bool,
}
#[derive(Clone)]
enum SocketRef {
    Tcp(Weak<TcpSocket>),
    Udp(Weak<UdpSocket>),
}
#[derive(Clone)]
struct Member {
    source: EndpointSourceId,
    socket: SocketRef,
    backlog: u32,
}
struct Attempt {
    id: PublicationAttemptId,
    gate: Arc<AttemptGate>,
    reporter: PublicationReporter,
    lease: Option<Arc<dyn EndpointLease>>,
}
struct Control {
    revision: u64,
    dirty: bool,
    publishing: bool,
    attempt: Option<Attempt>,
}
pub(crate) struct Group {
    id: EndpointGroupId,
    key: Key,
    live: AtomicBool,
    members: Mutex<HashMap<u64, Member>>,
    control: Mutex<Control>,
}
impl Group {
    fn spec(&self, attempt: PublicationAttemptId, revision: u64) -> EndpointGroupSpec {
        EndpointGroupSpec {
            group_id: self.id,
            attempt_id: attempt,
            kind: self.key.kind,
            local: self.key.local,
            domain: self.key.domain,
            v6only: self.key.v6only,
            revision,
        }
    }
    fn members(&self) -> Vec<Member> {
        self.members.lock().unwrap().values().cloned().collect()
    }
    fn retire(&self) {
        self.live.store(false, Ordering::Release);
        let lease = {
            let mut control = self.control.lock().unwrap();
            control.dirty = false;
            control.attempt.as_mut().and_then(|a| {
                a.gate.retire();
                a.lease.take()
            })
        };
        // This may itself be cascading destruction: ALL returned-handle Drop queues cleanup.
        drop(lease);
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        self.retire();
    }
}

/// Per-socket membership is independent of a publication attempt and never owns another Net.
pub(crate) struct SocketEndpoint {
    id: u64,
    source: AtomicU64,
    group: Mutex<Option<Arc<Group>>>,
}
impl SocketEndpoint {
    pub(crate) fn new(id: u64) -> Self {
        Self {
            id,
            source: AtomicU64::new(id),
            group: Mutex::new(None),
        }
    }
    pub(crate) fn source(&self) -> EndpointSourceId {
        EndpointSourceId(self.source.load(Ordering::Acquire))
    }
    pub(crate) fn group_id(&self) -> Option<EndpointGroupId> {
        self.group.lock().unwrap().as_ref().map(|g| g.id)
    }
    pub(crate) fn group(&self) -> Option<Arc<Group>> {
        self.group.lock().unwrap().clone()
    }
    pub(crate) fn replace_source(&self, namespace: &Namespace, source: EndpointSourceId) {
        let mut membership = self.group.lock().unwrap();
        self.source.store(source.0, Ordering::Release);
        if let Some(group) = membership.take() {
            namespace.leave(&group, self.id);
        }
    }
    /// Member epoch validation and queue commit share this local fence with retirement.
    pub(crate) fn commit<T>(
        &self,
        source: EndpointSourceId,
        enqueue: impl FnOnce() -> T,
    ) -> Option<T> {
        let membership = self.group.lock().unwrap();
        if self.source() != source || membership.is_none() {
            drop(membership);
            return None;
        }
        Some(enqueue())
    }
    pub(crate) fn renew(&self, namespace: &Namespace) {
        self.replace_source(
            namespace,
            EndpointSourceId(namespace.net.upgrade().map_or(self.id, |n| n.next_id())),
        );
    }
}

pub(crate) struct Namespace {
    net: Weak<Net>,
    pub(crate) provider: Arc<dyn EndpointProvider>,
    groups: Mutex<HashMap<Key, Arc<Group>>>,
}
impl Namespace {
    pub(crate) fn new(net: Weak<Net>, provider: Arc<dyn EndpointProvider>) -> Arc<Self> {
        Arc::new(Self {
            net,
            provider,
            groups: Mutex::new(HashMap::new()),
        })
    }
    fn next_id(&self) -> u64 {
        self.net
            .upgrade()
            .expect("live namespace operation")
            .next_id()
    }
    fn join(
        &self,
        endpoint: &SocketEndpoint,
        key: Key,
        socket: SocketRef,
        backlog: u32,
    ) -> Arc<Group> {
        let mut slot = endpoint.group.lock().unwrap();
        if slot.as_ref().is_some_and(|g| g.key != key) {
            let previous = slot.take().unwrap();
            self.leave(&previous, endpoint.id);
        }
        // Registry and membership move together: last-close cannot retire a group while a
        // reuse member is joining it. No provider code runs in this bookkeeping section.
        let mut groups = self.groups.lock().unwrap();
        let group = slot
            .get_or_insert_with(|| {
                groups
                    .entry(key)
                    .or_insert_with(|| {
                        Arc::new(Group {
                            id: EndpointGroupId(self.next_id()),
                            key,
                            live: AtomicBool::new(true),
                            members: Mutex::new(HashMap::new()),
                            control: Mutex::new(Control {
                                revision: 0,
                                dirty: true,
                                publishing: false,
                                attempt: None,
                            }),
                        })
                    })
                    .clone()
            })
            .clone();
        let mut members = group.members.lock().unwrap();
        let same = members
            .get(&endpoint.id)
            .is_some_and(|m| m.source == endpoint.source() && m.backlog == backlog);
        if !same {
            members.insert(
                endpoint.id,
                Member {
                    source: endpoint.source(),
                    socket,
                    backlog,
                },
            );
            let mut control = group.control.lock().unwrap();
            control.revision = control.revision.saturating_add(1);
            control.dirty = true;
        }
        drop(members);
        group
    }
    pub(crate) fn join_tcp(
        &self,
        endpoint: &SocketEndpoint,
        socket: Weak<TcpSocket>,
        local: SocketAddr,
        domain: Domain,
        v6only: bool,
        backlog: u32,
    ) -> Arc<Group> {
        self.join(
            endpoint,
            Key {
                kind: EndpointKind::Stream,
                local,
                domain,
                v6only,
            },
            SocketRef::Tcp(socket),
            backlog,
        )
    }
    pub(crate) fn join_udp(
        &self,
        endpoint: &SocketEndpoint,
        socket: Weak<UdpSocket>,
        local: SocketAddr,
        domain: Domain,
        v6only: bool,
    ) -> Arc<Group> {
        self.join(
            endpoint,
            Key {
                kind: EndpointKind::Datagram,
                local,
                domain,
                v6only,
            },
            SocketRef::Udp(socket),
            0,
        )
    }
    fn leave(&self, group: &Arc<Group>, id: u64) {
        let mut groups = self.groups.lock().unwrap();
        let mut members = group.members.lock().unwrap();
        members.remove(&id);
        if members.is_empty() {
            group.retire();
            if groups
                .get(&group.key)
                .is_some_and(|g| Arc::ptr_eq(g, group))
            {
                groups.remove(&group.key);
            }
        } else {
            let mut control = group.control.lock().unwrap();
            control.revision = control.revision.saturating_add(1);
            control.dirty = true;
        }
    }
    /// Explicit/driver entry ONLY. No caller holds a WLK Net/socket lock.
    pub(crate) fn refresh(self: &Arc<Self>, group: &Arc<Group>) {
        if !group.live.load(Ordering::Acquire) {
            return;
        }
        enum Work {
            Hint(Arc<dyn EndpointLease>, u64),
            Publish(
                PublicationAttemptId,
                Arc<AttemptGate>,
                PublicationReporter,
                u64,
            ),
        }
        let (backlog, work) = {
            // Membership and hint revision are one snapshot. A concurrent update cannot
            // consume dirty with a stale backlog stamped with its newer revision.
            let members = group.members.lock().unwrap();
            let backlog = members
                .values()
                .fold(0u32, |sum, m| sum.saturating_add(m.backlog));
            let mut control = group.control.lock().unwrap();
            if control.publishing {
                return;
            }
            let work = if let Some(attempt) = &control.attempt {
                if !control.dirty {
                    return;
                }
                let work = attempt
                    .lease
                    .clone()
                    .map(|lease| Work::Hint(lease, control.revision));
                control.dirty = false;
                let Some(work) = work else { return };
                work
            } else {
                let id = PublicationAttemptId(self.next_id());
                let (gate, reporter) = AttemptGate::new();
                let revision = control.revision;
                control.publishing = true;
                control.attempt = Some(Attempt {
                    id,
                    gate: gate.clone(),
                    reporter: reporter.clone(),
                    lease: None,
                });
                Work::Publish(id, gate, reporter, revision)
            };
            (backlog, work)
        };
        let (id, gate, reporter, revision) = match work {
            Work::Hint(lease, revision) => {
                lease.set_backlog(revision, backlog);
                return;
            }
            Work::Publish(id, gate, reporter, revision) => (id, gate, reporter, revision),
        };
        let ingress = Arc::new(Ingress {
            namespace: Arc::downgrade(self),
            group: Arc::downgrade(group),
            gate: gate.clone(),
            attempt: id,
        });
        let result = match group.key.kind {
            EndpointKind::Stream => self.provider.publish_tcp(
                group.spec(id, revision),
                backlog,
                ingress,
                reporter.clone(),
            ),
            EndpointKind::Datagram => {
                self.provider
                    .publish_udp(group.spec(id, revision), ingress, reporter.clone())
            }
        };
        let mut discard = None;
        {
            let mut control = group.control.lock().unwrap();
            let current = group.live.load(Ordering::Acquire)
                && control.attempt.as_ref().is_some_and(|a| a.id == id);
            if current {
                control.publishing = false;
                match result {
                    Ok(lease) => {
                        control.attempt.as_mut().unwrap().lease = Some(lease);
                        control.dirty = true;
                        gate.accept();
                    }
                    Err(error) => {
                        reporter.failed(error);
                        control.dirty = false;
                    }
                }
            } else {
                gate.retire();
                discard = result.ok();
            }
        }
        drop(discard);
        // Capture the newest hint if membership/backlog changed while the factory ran.
        self.refresh(group);
    }
    pub(crate) fn retry_all(self: &Arc<Self>) {
        let groups: Vec<_> = self.groups.lock().unwrap().values().cloned().collect();
        for group in groups {
            let retired = {
                let mut control = group.control.lock().unwrap();
                if control.publishing {
                    continue;
                }
                if control
                    .attempt
                    .as_ref()
                    .is_some_and(|a| matches!(a.reporter.state(), PublicationState::Failed(_)))
                {
                    let previous = control.attempt.take().unwrap();
                    previous.gate.retire();
                    Some(previous)
                } else {
                    None
                }
            };
            drop(retired);
            self.refresh(&group);
        }
    }
    pub(crate) fn statuses(&self) -> Vec<EndpointPublicationStatus> {
        let groups: Vec<_> = self.groups.lock().unwrap().values().cloned().collect();
        groups
            .into_iter()
            .filter_map(|g| {
                let snapshot = {
                    let c = g.control.lock().unwrap();
                    c.attempt
                        .as_ref()
                        .map(|a| (g.spec(a.id, c.revision), a.reporter.clone()))
                };
                snapshot.map(|(group, reporter)| EndpointPublicationStatus {
                    group,
                    state: reporter.state(),
                })
            })
            .collect()
    }
    pub(crate) fn hint(
        &self,
        kind: EndpointKind,
        destination: SocketAddr,
        source: SocketAddr,
    ) -> bool {
        let Some(net) = self.net.upgrade() else {
            return false;
        };
        let state = net.state();
        match kind {
            EndpointKind::Stream => !state
                .tcp
                .lookup(destination, Some(source), |w, listening| {
                    listening && w.strong_count() != 0
                })
                .is_empty(),
            EndpointKind::Datagram => state
                .udp
                .lookup_one(destination, Some(source), |w, _| w.strong_count() != 0, 0)
                .is_some(),
        }
    }
}

/// Driver ingress keeps only local weak references and an exact attempt gate.
struct Ingress {
    namespace: Weak<Namespace>,
    group: Weak<Group>,
    gate: Arc<AttemptGate>,
    attempt: PublicationAttemptId,
}
impl Ingress {
    fn tcp_members(
        &self,
        namespace: &Namespace,
        group: &Group,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Vec<(Weak<TcpSocket>, EndpointSourceId)> {
        let Some(net) = namespace.net.upgrade() else {
            return Vec::new();
        };
        let members = group.members();
        let selected = net.state().tcp.lookup(
            canonical(destination),
            Some(canonical(source)),
            |weak, listening| {
                listening
                    && members
                        .iter()
                        .any(|m| matches!(&m.socket,SocketRef::Tcp(w) if Weak::ptr_eq(w,weak)))
            },
        );
        selected
            .into_iter()
            .filter_map(|weak| {
                members
                    .iter()
                    .find(|m| matches!(&m.socket,SocketRef::Tcp(w) if Weak::ptr_eq(w,&weak)))
                    .map(|m| (weak, m.source))
            })
            .collect()
    }
    fn capture(&self, destination: SocketAddr) -> Option<(Arc<Namespace>, Arc<Group>)> {
        let namespace = self.namespace.upgrade()?;
        let group = self.group.upgrade()?;
        if !group.live.load(Ordering::Acquire)
            || !serves(group.key.local, group.key.v6only, canonical(destination))
        {
            return None;
        }
        // This is a genuinely unlocked driver entry; cascading Drop only leaves this dirty.
        namespace.refresh(&group);
        Some((namespace, group))
    }
}
impl EndpointStreamIngress for Ingress {
    fn poll_room_to(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        table: Option<&mut PollTable<'_>>,
    ) -> Room {
        let Some((namespace, group)) = self.capture(destination) else {
            return Room::Gone;
        };
        let mut table = table;
        if let Some(room) = self.gate.room(table.as_deref_mut()) {
            return room;
        }
        let mut room = Room::Gone;
        for (weak, epoch) in self.tcp_members(&namespace, &group, source, destination) {
            if let Some(socket) = weak.upgrade() {
                match socket.endpoint_room(epoch, source, destination, table.as_deref_mut()) {
                    Room::Ready => return Room::Ready,
                    Room::Full => room = Room::Full,
                    Room::Gone => {}
                }
            }
        }
        room
    }
    fn incoming_to(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        stream: Arc<dyn BackendStream>,
        wq: WaitQueue,
    ) -> bool {
        let Some((namespace, group)) = self.capture(destination) else {
            return false;
        };
        if canonical(stream.peer_addr()) != canonical(source) || self.gate.room(None).is_some() {
            return false;
        }
        let mut members = self.tcp_members(&namespace, &group, source, destination);
        if !members.is_empty() {
            let count = members.len();
            members.rotate_left(source.port() as usize % count);
        }
        let mut stream = stream;
        for (weak, epoch) in members {
            if let Some(socket) = weak.upgrade() {
                match socket.incoming_endpoint(
                    epoch,
                    &self.gate,
                    stream,
                    wq.clone(),
                    canonical(destination),
                    canonical(source),
                ) {
                    crate::tcp::Offer::Queued => return true,
                    crate::tcp::Offer::Dropped => return false,
                    crate::tcp::Offer::Declined(back) => stream = back,
                }
            }
        }
        false
    }
}
impl EndpointDatagramIngress for Ingress {
    fn incoming(
        &self,
        group_id: EndpointGroupId,
        attempt_id: PublicationAttemptId,
        source: SocketAddr,
        destination: SocketAddr,
        bytes: &[u8],
    ) -> DatagramDelivery {
        let Some((namespace, group)) = self.capture(destination) else {
            return DatagramDelivery::Retired;
        };
        if group.id != group_id || self.attempt != attempt_id {
            return DatagramDelivery::Retired;
        }
        match self.gate.room(None) {
            Some(Room::Full) => return DatagramDelivery::Dropped,
            Some(_) => return DatagramDelivery::Retired,
            None => {}
        }
        let Some(net) = namespace.net.upgrade() else {
            return DatagramDelivery::Retired;
        };
        let members = group.members();
        let from = canonical(source);
        let destination = canonical(destination);
        let selected = {
            let state = net.state();
            state.udp.lookup_one(
                destination,
                Some(from),
                |weak, _| {
                    members.iter().any(
                        |m| matches!(&m.socket,SocketRef::Udp(member) if Weak::ptr_eq(member,weak)),
                    )
                },
                from.port() as usize,
            )
        };
        let Some(weak) = selected else {
            return DatagramDelivery::Unreachable;
        };
        let member = members
            .iter()
            .find(|m| matches!(&m.socket,SocketRef::Udp(w) if Weak::ptr_eq(w,&weak)))
            .unwrap();
        weak.upgrade()
            .map_or(DatagramDelivery::Unreachable, |socket| {
                socket.deliver_endpoint(member.source, &self.gate, bytes, from, destination)
            })
    }
}

#[cfg(test)]
mod teardown_tests {
    use super::*;

    #[test]
    fn admitted_tcp_handoff_fails_closed_after_last_socket_and_net_retire() {
        let (net, listener) = super::super::tests::teardown_namespace();
        let namespace = net.endpoints().unwrap();
        let group = namespace
            .groups
            .lock()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();
        let (gate, attempt) = {
            let control = group.control.lock().unwrap();
            let attempt = control.attempt.as_ref().unwrap();
            (attempt.gate.clone(), attempt.id)
        };
        let ingress = Ingress {
            namespace: Arc::downgrade(&namespace),
            group: Arc::downgrade(&group),
            gate,
            attempt,
        };
        let src = "127.0.0.1:40000".parse().unwrap();
        let dst = "127.0.0.1:8310".parse().unwrap();
        // This is the same captured capability and admission step the public methods use.
        // Retain it across the deterministic final-reference teardown before candidate lookup.
        let (captured, captured_group) = ingress.capture(dst).unwrap();
        assert_eq!(ingress.gate.room(None), None);
        drop(listener);
        drop(net);
        drop(namespace);
        assert!(captured.net.upgrade().is_none());
        assert!(
            ingress
                .tcp_members(&captured, &captured_group, src, dst)
                .is_empty()
        );
        assert_eq!(ingress.poll_room_to(src, dst, None), Room::Gone);
        let [stream, _] =
            crate::MemoryStream::pair([dst, src], [WaitQueue::new(), WaitQueue::new()]);
        assert!(!ingress.incoming_to(src, dst, stream, WaitQueue::new()));
        drop(captured);
        assert!(ingress.namespace.upgrade().is_none());
        assert_eq!(ingress.poll_room_to(src, dst, None), Room::Gone);
    }
}
