//! Optional namespace-scoped transport for local-unicast TCP/UDP endpoints.
//!
//! This module defines the provider boundary. Capturing it does not change routing or
//! publish a socket: the socket layer must opt into selection and manage group, source and
//! publication-attempt epochs. Providers exchange scoped identities, original addresses and
//! byte streams/datagrams; they do not receive another namespace's `Net`.
//!
//! Control calls (namespace factory, selection, transport factories, publication,
//! configuration and lease methods) run without WLK Net/socket locks. ALL provider-owned
//! handle destructors (provider, lease, target and transport) are bounded/nonblocking, never
//! synchronously enter ANY WLK Net/socket/ingress, and queue real cleanup on their driver.
//! Cascading WLK destruction only retires local gates/membership and releases handles; it
//! cannot invoke reentrant state/poll/backlog callbacks merely after releasing its own lock.
//! Such dirty control refresh waits for an explicit or driver entry without WLK locks.
//! Returned transport
//! data-plane methods and destructors follow the existing nonblocking transport contract:
//! they may run under a socket lock and MUST NOT synchronously enter ANY WLK Net, socket or
//! endpoint ingress, including a peer namespace. Queue peer delivery and cleanup on the
//! owning driver; release transport locks before the driver invokes ingress. This rule also
//! applies to opaque targets owned by those transports and prevents cross-peer lock inversion.

use std::{any::Any, net::SocketAddr, sync::Arc};

use wasixv2_abi::Errno;
use wasixv2_wait::{PollMask, PollTable, Pollable, WaitQueue};

use crate::{BackendStream, Domain, QueuedError, Room};

/// A live bind/listener group. Values are fresh and never reused within one provider handle.
/// Other live reuse members keep this identity when one member leaves. Last-member removal
/// retires it, even if a later group binds the same address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EndpointGroupId(pub u64);

/// A socket binding/association epoch, not an address. Disconnect/rebind/relisten retires it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EndpointSourceId(pub u64);

/// One publication reservation. Retry of a still-live group always gets a fresh attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicationAttemptId(pub u64);

/// Only TCP streams and UDP datagrams use this optional boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EndpointKind {
    Stream,
    Datagram,
}

/// Borrowed validation context only; a provider bind admission never retains payload bytes.
pub enum EndpointAutobind<'a> {
    Connect(SocketAddr),
    Send(&'a crate::SendMsg<'a>),
    Listen(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointBindPurpose {
    Bind,
    /// Original unbound listen: call listen_tcp(any:0), never manufacture a bound TCP socket.
    Listen {
        backlog: u32,
    },
}

/// A validated local-unicast operation, before provider transport work is accepted.
#[derive(Clone)]
pub struct EndpointQuery {
    pub kind: EndpointKind,
    pub source_id: EndpointSourceId,
    /// The original guest binding; a wildcard remains a wildcard.
    pub bound: Option<SocketAddr>,
    /// Literal explicit bind request, including port zero; None means never explicitly bound.
    pub requested_bind: Option<SocketAddr>,
    /// The retained explicit bound resource, if admission used the optional provider.
    pub binding: Option<Arc<dyn EndpointBound>>,
    /// The actual source, if already selected, including an allocated nonzero source port.
    pub effective_source: Option<SocketAddr>,
    pub destination: SocketAddr,
    /// A snapshot hint only: a binding exists, not necessarily a ready/eligible recipient.
    pub local_binding: bool,
}

/// An optional provider bind is admitted before the namespace reserves its actual address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointBindRequest {
    pub source_id: EndpointSourceId,
    pub kind: EndpointKind,
    pub requested: SocketAddr,
    /// False for implicit UDP any:0 admission or direct unbound TCP listen.
    /// Unbound TCP connect does not use bind admission.
    pub explicit: bool,
    pub purpose: EndpointBindPurpose,
    pub domain: Domain,
    pub v6only: bool,
    pub reuse_addr: bool,
    pub reuse_port: bool,
}

/// The same actual bound resource subsequently used for connect, listen, or datagrams.
/// EAGAIN means Pending; Ready returns a nonzero actual port. Methods and Drop are bounded,
/// never enter WLK, and queue cancellation/cleanup on the provider driver. Pending jobs
/// retain weak publication authority so dropping the last lease closes late results.
pub trait EndpointBound: Pollable + Any {
    fn local_addr(&self) -> Result<SocketAddr, Errno>;
}

#[derive(Clone)]
pub struct EndpointMember {
    pub source_id: EndpointSourceId,
    pub requested_bind: Option<SocketAddr>,
    pub local: SocketAddr,
    pub binding: Option<Arc<dyn EndpointBound>>,
}

impl std::fmt::Debug for EndpointMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointMember")
            .field("source_id", &self.source_id)
            .field("requested_bind", &self.requested_bind)
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl PartialEq for EndpointMember {
    fn eq(&self, other: &Self) -> bool {
        self.source_id == other.source_id
            && self.requested_bind == other.requested_bind
            && self.local == other.local
            && match (&self.binding, &other.binding) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }
}
impl Eq for EndpointMember {}

/// Provider-owned identity of an exact peer/group/session for an accepted operation.
/// Retaining it must not redirect to a replacement peer after directory changes. A provider
/// validates its own payload and handle scope. This follows the opaque attachment pattern;
/// no address translation or cross-namespace `Arc<Net>` belongs in the payload contract.
#[derive(Clone)]
pub struct EndpointTarget(Arc<dyn Any + Send + Sync>);

impl EndpointTarget {
    pub fn new<T: Any + Send + Sync>(target: T) -> Self {
        Self(Arc::new(target))
    }

    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.0.downcast_ref()
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// Ordinary namespace routing, or the exact chosen provider target. A selected provider's
/// error never permits local fallback, re-resolution to a different peer or payload replay.
#[derive(Clone)]
pub enum EndpointChoice {
    Namespace,
    Provider(EndpointTarget),
}

/// One UDP source epoch. Source port 0 has already been allocated locally. The bound IP may
/// still be wildcard; each send separately supplies its actual effective source.
#[derive(Clone)]
pub struct EndpointSource {
    pub id: EndpointSourceId,
    pub group_id: EndpointGroupId,
    pub bound: SocketAddr,
    pub domain: Domain,
    pub requested_bind: Option<SocketAddr>,
    pub binding: Option<Arc<dyn EndpointBound>>,
}

impl std::fmt::Debug for EndpointQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointQuery")
            .field("source_id", &self.source_id)
            .field("requested_bind", &self.requested_bind)
            .field("bound", &self.bound)
            .field("effective_source", &self.effective_source)
            .field("destination", &self.destination)
            .field("local_binding", &self.local_binding)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for EndpointSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointSource")
            .field("id", &self.id)
            .field("group_id", &self.group_id)
            .field("bound", &self.bound)
            .field("requested_bind", &self.requested_bind)
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

/// Complete desired UDP association/error-filter state for one source epoch. Revisions are
/// strictly monotonic within that epoch, including changes made before TX construction.
/// These are the peer and RECVERR settings the existing UDP layer forwards; other socket
/// options and cork/control-message validation remain the socket layer's responsibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpTxConfig {
    pub source_id: EndpointSourceId,
    pub revision: u64,
    pub peer: Option<SocketAddr>,
    pub recv_v4_errors: bool,
    pub recv_v6_errors: bool,
}

/// Snapshot of one group and its separate registration attempt. The live member filter and
/// these identities remain authoritative through table-to-socket ingress handoff; a more
/// specific/different-family/replacement group must not receive this group's arrival.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointGroupSpec {
    pub group_id: EndpointGroupId,
    pub attempt_id: PublicationAttemptId,
    pub kind: EndpointKind,
    pub local: SocketAddr,
    pub domain: Domain,
    pub v6only: bool,
    pub revision: u64,
    /// Membership at this revision. Each explicit bind retains its own requested address
    /// and bound resource; one scalar request cannot describe a reuse group.
    pub members: Arc<[EndpointMember]>,
}

/// State of the external registration, distinct from local bind/listen success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationState {
    Pending,
    Ready,
    Failed(Errno),
}

/// A WLK-owned status/gate handle for precisely one publication attempt. The provider uses
/// it only from its control/driver path, after releasing transport locks. It is the sole
/// Pending/Ready/Failed state authority, shared with the lease and ingress gates.
///
/// Reporting Ready before local lease commit records readiness without admitting ingress.
/// Both Ready and local commit wake provisional TCP room waiters. Failed atomically retires
/// this attempt's gate before exposing failure and waking waiters. A stale reporter cannot
/// change a replacement attempt; a failed/retired attempt cannot become Ready again.
#[derive(Clone)]
pub struct PublicationReporter(Arc<dyn PublicationReport>);

// The socket layer supplies this local gate/state implementation. Providers cannot replace it.
trait PublicationReport: Pollable {
    fn state(&self) -> PublicationState;
    fn ready(&self);
    fn failed(&self, error: Errno);
}

impl PublicationReporter {
    pub fn state(&self) -> PublicationState {
        self.0.state()
    }

    pub fn ready(&self) {
        self.0.ready();
    }

    pub fn failed(&self, error: Errno) {
        self.0.failed(error);
    }
}

impl Pollable for PublicationReporter {
    /// Registers before checking status. Ready reports OUT, failure ERR; Pending reports
    /// neither. The local gate also wakes on commit/retirement independently of backlog.
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.0.poll(table)
    }
}

/// Accepted registration custody. Even Pending work has a lease; Drop withdraws exactly
/// this attempt. WLK retires its callback gate before releasing/retrying a lease. Explicit
/// backlog/state/poll methods are unlocked control calls. A final Arc may be released by
/// cascading destruction while another WLK lock remains held: Drop must be bounded,
/// nonblocking, never enter ANY WLK Net/socket/ingress, and queue withdrawal on the driver.
///
/// `Pollable::poll` and `state` delegate to the SAME reporter, never a second state cell.
/// Failed is terminal for this attempt. A provider queues driver cleanup and does not invoke
/// endpoint ingress while holding transport locks.
pub trait EndpointLease: Pollable {
    fn reporter(&self) -> &PublicationReporter;

    fn state(&self) -> PublicationState {
        self.reporter().state()
    }

    /// Saturating total capacity of current live TCP group members; actual queue admission
    /// remains the group's live member lookup. Ignore equal/older revisions. UDP may ignore it.
    fn set_backlog(&self, revision: u64, backlog: u32) {
        let _ = (revision, backlog);
    }

    /// Unlocked monotonic membership refresh, including the same bound handles as admission.
    fn update_members(&self, revision: u64, members: Arc<[EndpointMember]>) {
        let _ = (revision, members);
    }
}

/// Exact-address TCP ingress, called by the provider driver without transport locks.
/// It captures BOTH group and attempt identity. Lookup filters to current captured-group
/// members, then validates the selected member/listen epoch and attempt again at enqueue.
pub trait EndpointStreamIngress: Send + Sync {
    /// Provisional gates register on their local gate WaitQueue before returning Full;
    /// commit/Ready wakes that queue without requiring any backlog change. Retirement/Err
    /// wakes it and returns Gone. Active gates use the normal member backlog queues too.
    fn poll_room_to(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        table: Option<&mut PollTable<'_>>,
    ) -> Room;

    /// The exact destination must match the captured bind/family scope; never infer a
    /// wildcard's destination from the peer/uplink. Source must agree with stream.peer_addr.
    /// Accepted guest local/peer addresses retain these values. False accepts no stream.
    fn incoming_to(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        stream: Arc<dyn BackendStream>,
        wq: WaitQueue,
    ) -> bool;
}

/// Terminal disposition of one peer UDP arrival. None requests retry. In particular a full
/// receiver or provisional publication drops the datagram rather than queuing private RX.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramDelivery {
    /// The whole datagram was queued once in the selected guest socket's bounded queue.
    Queued,
    Dropped,
    Unreachable,
    Retired,
}

/// Sole receive authority for provider-peer datagrams and replies, including implicit
/// autobinds. The driver releases transport locks before calling this namespace ingress.
/// Its captured group/attempt and current member/source epochs gate admission AND commit.
/// Unrestricted global wildcard lookup must not retarget a different group.
pub trait EndpointDatagramIngress: Send + Sync {
    fn incoming(
        &self,
        group_id: EndpointGroupId,
        attempt_id: PublicationAttemptId,
        source: SocketAddr,
        destination: SocketAddr,
        bytes: &[u8],
    ) -> DatagramDelivery;
}

/// One source epoch's TX-only peer transport. It has NO recv/attach/input-length API;
/// namespace ingress alone receives peer bytes. Ordinary host RX remains its existing path.
/// Send/poll/error methods and Drop may run under socket locks: never synchronously enter
/// ANY WLK Net/socket/EndpointIngress. Queue delivery/cleanup on the driver, and release
/// transport locks before invoking ingress. Waking the original WaitQueue only schedules work.
pub trait EndpointDatagramTx: Send + Sync {
    /// Unlocked, infallible handoff of complete desired bookkeeping. Atomically apply only
    /// this object's captured source id and a strictly newer revision; equal/older snapshots
    /// have no side effects. Deferred driver application obeys the SAME monotonic ordering.
    ///
    /// Changes during provisional factory creation are replayed as the latest full snapshot
    /// before a send may use that revision. A retired source cannot configure its replacement.
    /// Unsupported physical effects do not invent synchronous setsockopt errors; actual
    /// transport failures use the asynchronous error methods below and wake ERR.
    fn configure(&self, config: UdpTxConfig);

    /// Success accepts the ENTIRE datagram, including empty messages. Short success is a
    /// provider contract failure. EAGAIN accepts nothing, including when the required config
    /// revision is not applied yet. Never repair a failure by replaying accepted payload.
    fn send_to(
        &self,
        required_revision: u64,
        target: &EndpointTarget,
        source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
    ) -> Result<usize, Errno>;

    /// OUT/WRNORM only when a send at this revision can proceed, and ERR for pending errors;
    /// NEVER IN. Configuration/capacity progress wakes the original socket WaitQueue.
    ///
    /// Socket POLLOUT consults only its connected route or last destination-specific blocked
    /// send's exact slot/source/config witness, not OR/AND of ordinary and peer slots. A later
    /// valid destination attempt changes that focus; source/config retirement invalidates it.
    fn poll_tx(&self, required_revision: u64) -> PollMask;

    /// Errors from both live ordinary/peer slots contribute ERR independently of OUT focus.
    fn take_error(&self) -> Option<Errno>;

    fn take_queued_error(&self) -> Option<QueuedError> {
        None
    }
}

/// The optional namespace-scoped control/factory boundary. All calls are nonblocking and
/// run without WLK Net/socket locks; generation rechecks govern resource commit/retirement.
/// Peer delivery and cleanup are queued on the owning driver, never synchronous calls into
/// another namespace. Driver invocation of ingress happens with transport locks released.
///
/// `select` is pure and may be retried after a stale snapshot. An accepted connect, payload
/// or publication is never replayed on a generation recheck. Returned data-plane objects
/// instead obey their stricter any-namespace nonreentrancy/Drop contract documented above.
pub trait EndpointProvider: Send + Sync {
    /// Also select existing backend uplink unicast routes. Captured once per namespace;
    /// DNS, veth, and another namespace's routes remain outside this optional capability.
    fn select_external(&self) -> bool {
        false
    }
    /// None accepts no work or callback custody and preserves ordinary namespace binding.
    fn bind(
        &self,
        request: EndpointBindRequest,
        wq: WaitQueue,
    ) -> Result<Option<Arc<dyn EndpointBound>>, Errno> {
        let _ = (request, wq);
        Ok(None)
    }
    fn select(&self, query: &EndpointQuery) -> Result<EndpointChoice, Errno> {
        let _ = query;
        Ok(EndpointChoice::Namespace)
    }

    fn connect(
        &self,
        target: EndpointTarget,
        source_id: EndpointSourceId,
        local: SocketAddr,
        remote: SocketAddr,
        wq: WaitQueue,
    ) -> Result<Arc<dyn BackendStream>, Errno> {
        let _ = (target, source_id, local, remote, wq);
        Err(Errno::EOPNOTSUPP)
    }

    fn datagram(
        &self,
        source: EndpointSource,
        initial: UdpTxConfig,
        wq: WaitQueue,
    ) -> Result<Arc<dyn EndpointDatagramTx>, Errno> {
        let _ = (source, initial, wq);
        Err(Errno::EOPNOTSUPP)
    }

    /// After valid local listen commit. Err means NO registration, lease or callback custody
    /// accepted; do not retain/invoke ingress later. Accepted async work returns a Pending
    /// lease, then reports Ready/Failed. Local listen success is independent of publication.
    fn publish_tcp(
        &self,
        group: EndpointGroupSpec,
        backlog: u32,
        ingress: Arc<dyn EndpointStreamIngress>,
        status: PublicationReporter,
    ) -> Result<Arc<dyn EndpointLease>, Errno> {
        let _ = (group, backlog, ingress, status);
        Err(Errno::EOPNOTSUPP)
    }

    /// After valid bind/autobind commit and nonzero port allocation; the same no-custody Err
    /// and Pending/Ready/Failed lease rules apply. This is not a second global bind authority.
    fn publish_udp(
        &self,
        group: EndpointGroupSpec,
        ingress: Arc<dyn EndpointDatagramIngress>,
        status: PublicationReporter,
    ) -> Result<Arc<dyn EndpointLease>, Errno> {
        let _ = (group, ingress, status);
        Err(Errno::EOPNOTSUPP)
    }
}

/// Local attempt state. The socket layer validates group/member identity before taking this
/// gate last at enqueue commit; gate code never enters a Net, socket or provider.
pub(crate) struct AttemptGate {
    state: std::sync::Mutex<AttemptState>,
    wait: WaitQueue,
}

#[derive(Default)]
struct AttemptState {
    accepted: bool,
    ready: bool,
    retired: bool,
    error: Option<Errno>,
}

impl AttemptGate {
    pub(crate) fn new() -> (Arc<Self>, PublicationReporter) {
        let gate = Arc::new(Self {
            state: std::sync::Mutex::new(AttemptState::default()),
            wait: WaitQueue::new(),
        });
        (gate.clone(), PublicationReporter(gate))
    }

    /// A successful factory result is committed to this still-current attempt. A provider
    /// Ready report before this point does not admit ingress.
    pub(crate) fn accept(&self) -> bool {
        let accepted = {
            let mut state = self.state.lock().unwrap();
            if state.retired {
                false
            } else {
                state.accepted = true;
                true
            }
        };
        self.wait.wake(PollMask::empty());
        accepted
    }

    /// Invalidation precedes removal of an old lease and creation of a replacement attempt.
    pub(crate) fn retire(&self) {
        {
            let mut state = self.state.lock().unwrap();
            state.retired = true;
            state.error.get_or_insert(Errno::ECANCELED);
        }
        self.wait.wake(PollMask::empty());
    }

    /// Register before inspecting state so a provisional publisher cannot miss commit or
    /// retirement. None means the caller may proceed to its group-filtered room lookup.
    pub(crate) fn room(&self, mut table: Option<&mut PollTable<'_>>) -> Option<Room> {
        wasixv2_wait::poll_wait(&mut table, &self.wait);
        let state = self.state.lock().unwrap();
        if state.retired {
            Some(Room::Gone)
        } else if state.accepted && state.ready {
            None
        } else {
            Some(Room::Full)
        }
    }

    /// Take this guard only after the member/listener queue lock, never while it could enter
    /// namespace/provider code. Retirement and enqueue thereby have one ordering point.
    pub(crate) fn commit<T>(&self, enqueue: impl FnOnce() -> T) -> Option<T> {
        let state = self.state.lock().unwrap();
        if state.retired || !state.accepted || !state.ready {
            drop(state);
            return None;
        }
        Some(enqueue())
    }
}

impl PublicationReport for AttemptGate {
    fn state(&self) -> PublicationState {
        let state = self.state.lock().unwrap();
        if let Some(error) = state.error {
            PublicationState::Failed(error)
        } else if state.accepted && state.ready {
            PublicationState::Ready
        } else {
            PublicationState::Pending
        }
    }

    fn ready(&self) {
        let changed = {
            let mut state = self.state.lock().unwrap();
            if state.retired || state.ready {
                false
            } else {
                state.ready = true;
                true
            }
        };
        if changed {
            self.wait.wake(PollMask::empty());
        }
    }

    fn failed(&self, error: Errno) {
        let changed = {
            let mut state = self.state.lock().unwrap();
            if state.retired {
                false
            } else {
                state.retired = true;
                state.error = Some(error);
                true
            }
        };
        if changed {
            self.wait.wake(PollMask::empty());
        }
    }
}

impl Pollable for AttemptGate {
    fn poll(&self, mut table: Option<&mut PollTable<'_>>) -> PollMask {
        wasixv2_wait::poll_wait(&mut table, &self.wait);
        match PublicationReport::state(self) {
            PublicationState::Pending => PollMask::empty(),
            PublicationState::Ready => PollMask::OUT | PollMask::WRNORM,
            PublicationState::Failed(_) => PollMask::ERR,
        }
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wasixv2_wait::{WaitEntry, WaitRegistration};

    struct WakeCount(AtomicUsize);
    impl WaitEntry for WakeCount {
        fn wake(&self, _: PollMask) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst);
            true
        }
    }

    #[test]
    fn provisional_waiter_wakes_on_commit_without_backlog_change() {
        let (gate, reporter) = AttemptGate::new();
        let count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let mut registrations: Vec<WaitRegistration> = Vec::new();
        let mut register = |queue: &WaitQueue, _| {
            registrations.push(queue.add(count.clone()));
        };
        let mut table = PollTable::new(PollMask::OUT, &mut register);
        assert_eq!(gate.room(Some(&mut table)), Some(Room::Full));
        reporter.ready();
        assert_eq!(reporter.state(), PublicationState::Pending);
        assert_eq!(gate.room(None), Some(Room::Full));
        let before = count.0.load(Ordering::SeqCst);
        assert!(gate.accept());
        assert!(count.0.load(Ordering::SeqCst) > before);
        assert_eq!(gate.room(None), None);
        assert_eq!(gate.commit(|| 37), Some(37));
    }

    #[test]
    fn failed_attempt_cannot_commit_into_retried_live_group() {
        let (old, reporter) = AttemptGate::new();
        assert!(old.accept());
        reporter.ready();
        reporter.failed(Errno::EIO);
        let (replacement, next_reporter) = AttemptGate::new();
        next_reporter.ready();
        assert!(replacement.accept());
        assert_eq!(
            old.commit(|| panic!("retired callback enqueued")),
            None::<()>
        );
        reporter.ready();
        assert_eq!(reporter.state(), PublicationState::Failed(Errno::EIO));
        assert_eq!(replacement.commit(|| 42), Some(42));
    }

    #[test]
    fn canceled_provisional_attempt_has_no_ingress_custody() {
        let (gate, reporter) = AttemptGate::new();
        gate.retire();
        reporter.ready();
        assert!(!gate.accept());
        assert_eq!(gate.room(None), Some(Room::Gone));
        assert_eq!(gate.commit(|| DatagramDelivery::Queued), None);
    }
}

/// Observable status of one live group's current registration attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointPublicationStatus {
    pub group: EndpointGroupSpec,
    pub state: PublicationState,
}

pub(crate) mod runtime;

pub(crate) mod bind;
pub(crate) mod pending;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bind_tests;
