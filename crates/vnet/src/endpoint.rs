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

/// A validated local-unicast operation, before provider transport work is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointQuery {
    pub kind: EndpointKind,
    pub source_id: EndpointSourceId,
    /// The original guest binding; a wildcard remains a wildcard.
    pub bound: Option<SocketAddr>,
    /// The actual source, if already selected, including an allocated nonzero source port.
    pub effective_source: Option<SocketAddr>,
    pub destination: SocketAddr,
    /// A snapshot hint only: a binding exists, not necessarily a ready/eligible recipient.
    pub local_binding: bool,
}

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointSource {
    pub id: EndpointSourceId,
    pub group_id: EndpointGroupId,
    pub bound: SocketAddr,
    pub domain: Domain,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointGroupSpec {
    pub group_id: EndpointGroupId,
    pub attempt_id: PublicationAttemptId,
    pub kind: EndpointKind,
    pub local: SocketAddr,
    pub domain: Domain,
    pub v6only: bool,
    pub revision: u64,
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
