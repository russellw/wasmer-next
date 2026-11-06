//! Native SDK network providers, using the canonical WLK transport and readiness contracts.
//!
//! Factories and close futures are `Send` and run on the client's existing services runtime.
//! Transport data-plane methods are bounded/nonblocking: they may run under a guest socket
//! lock and must never synchronously enter a WLK network, socket or ingress (including a peer).
//! Destructors only revoke local authority and queue cleanup; actual retirement belongs to
//! `close`, which the SDK retains and joins even when a public waiter is canceled.
//! Close is idempotent and joins the same actual retirement on repeated calls. An explicit
//! owner may escalate Normal to Cancel while both futures remain live on that completion.
//! Dropping a public wait subscription is not a cancellation request.
//!
//! Socket factories may wait for admission while owning no accepted independent descriptor,
//! driver job or callback. Once such work is accepted, that same poll must return its existing
//! owning handle. A returned BoundTcp, UdpSocket or root-factory TcpListener may remain pending
//! (`local_addr` returns EAGAIN until its actual binding/listening address is known); its
//! Pollable registration must wake on completion or cancellation, and its close
//! future must cancel and join all accepted work and dispose late results. A connecting
//! TcpStream similarly owns its pending connection. Cleanup hidden in a dropped factory
//! future or an untracked destructor task cannot satisfy this contract.

use async_trait::async_trait;
use std::{
    fmt::Debug,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
pub use wasixv2_abi::Errno as NetworkError;
pub use wasixv2_vnet::endpoint::{DatagramInfo, DatagramReceiver};
pub use wasixv2_vnet::provider::{
    Cidr, Completion as NetworkControlCompletion, Request as NetworkControl, Route, Security,
};
pub use wasixv2_vnet::{BackendDatagram, BackendStream};
pub use wasixv2_wait::{PollMask, PollTable, Pollable, WaitQueue};

pub type NetworkResult<T> = std::result::Result<T, NetworkError>;
pub type DynNetworkProvider = Arc<dyn NetworkProvider>;
/// Normal close honors transport draining/linger. Cancel is an explicit owner request
/// to revoke that work on the same resource, sharing its actual retirement completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkCloseMode {
    Normal,
    Cancel,
}

/// Bytes copied, full datagram length, original sender and actual per-packet destination.
pub type ReceivedDatagram = (usize, usize, DatagramInfo);

/// A live provider shared by sandbox configuration, with private per-run resource groups.
/// Unsupported factories fail authoritatively; the SDK does not retry through another provider.
#[async_trait]
pub trait NetworkProvider: Debug + Send + Sync + 'static {
    /// Factory completion may return a Connecting handle; callers own readiness and close.
    /// Original unbound connect. `local` is the address-family's unspecified address at port 0.
    /// Explicit binds use the retained `BoundTcp` instead of invoking this factory again.
    async fn connect_tcp(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpStream>> {
        let _ = (local, peer, queue);
        Err(NetworkError::EOPNOTSUPP)
    }
    async fn bind_tcp(
        &self,
        local: SocketAddr,
        v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
    ) -> NetworkResult<Arc<dyn BoundTcp>> {
        let _ = (local, v6only, reuse_port, reuse_addr);
        Err(NetworkError::EOPNOTSUPP)
    }
    /// Original unbound listen, including port zero. It is not synthesized by binding first.
    /// The returned owner may be pending: local_addr returns EAGAIN until the actual socket
    /// is listening with a known address, then Pollable wakes admission. Accept readiness is
    /// separate. The handle's close owns cancellation and actual retirement throughout.
    async fn listen_tcp(
        &self,
        local: SocketAddr,
        v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
        backlog: u32,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpListener>> {
        let _ = (local, v6only, reuse_port, reuse_addr, backlog, queue);
        Err(NetworkError::EOPNOTSUPP)
    }
    /// Returns a fresh disconnected socket with both receive-error flags disabled.
    /// The SDK skips these redundant initial defaults, then forwards requested changes.
    async fn bind_udp(
        &self,
        local: SocketAddr,
        v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn UdpSocket>> {
        let _ = (local, v6only, reuse_port, reuse_addr, queue);
        Err(NetworkError::EOPNOTSUPP)
    }
    /// Receives the caller's original UTF-8 name and low-16-bit nonzero port hint.
    async fn resolve(
        &self,
        name: &str,
        port: Option<u16>,
        dns_server: Option<IpAddr>,
    ) -> NetworkResult<Vec<IpAddr>> {
        let _ = (name, port, dns_server);
        Err(NetworkError::EOPNOTSUPP)
    }
    /// Existing canonical provider controls, including reconciliation after a remote mutation.
    async fn control(&self, request: NetworkControl) -> NetworkControlCompletion {
        let _ = request;
        NetworkControlCompletion::error(NetworkError::EOPNOTSUPP)
    }
}

/// Initialized byte buffers and canonical TCP state/readiness; no legacy InterestHandler.
#[async_trait]
pub trait TcpStream: BackendStream {
    fn local_addr(&self) -> NetworkResult<SocketAddr>;
    fn flush(&self) -> NetworkResult<()>;
    /// Explicit policy for every option passed by the canonical socket layer.
    /// Do not silently inherit `BackendStream`'s permissive default.
    fn set_socket_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()>;
    async fn close(&self, mode: NetworkCloseMode) -> NetworkResult<()>;
}

#[async_trait]
pub trait UdpSocket: BackendDatagram {
    /// Install the sole receive consumer on this SAME physical socket. Pull reads become
    /// EBUSY once accepted. The existing provider driver must observe an empty kernel queue
    /// before Ready; delivery is admitted at observation, never buffered then relabeled.
    /// Preserve actual interface/scope and this socket's original address/membership choice;
    /// packets admitted by another local socket/global multicast setting cannot leak here.
    /// Err accepts no callback custody. Callbacks run outside all transport/WLK locks.
    fn install_receiver(
        &self,
        receiver: Arc<dyn DatagramReceiver>,
    ) -> NetworkResult<Arc<dyn DatagramReceiveLease>>;
    fn peer_addr(&self) -> NetworkResult<Option<SocketAddr>>;
    /// Receive initialized bytes plus the actual destination, including wildcard-bound sockets.
    /// Preserve zero messages, full length, sender and peek without consuming on errors.
    fn recv_packet(&self, buf: &mut [u8], peek: bool) -> NetworkResult<ReceivedDatagram>;
    fn local_addr(&self) -> NetworkResult<SocketAddr>;
    fn set_socket_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()>;
    async fn close(&self, mode: NetworkCloseMode) -> NetworkResult<()>;
}

/// One receive registration, not a second owner of the socket. Dropping the lease only
/// requests bounded withdrawal; close joins withdrawal and callbacks already accepted.
/// Dropping a borrowed wait_ready subscription must not withdraw the registration.
#[async_trait]
pub trait DatagramReceiveLease: Send + Sync + 'static {
    async fn wait_ready(&self) -> NetworkResult<()>;
    async fn close(&self) -> NetworkResult<()>;
}

#[async_trait]
pub trait TcpListener: Pollable {
    fn local_addr(&self) -> NetworkResult<SocketAddr>;
    fn try_accept(&self, queue: WaitQueue) -> NetworkResult<(Arc<dyn TcpStream>, SocketAddr)>;
    fn set_backlog(&self, backlog: u32) -> NetworkResult<()>;
    fn set_socket_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()>;
    async fn close(&self, mode: NetworkCloseMode) -> NetworkResult<()>;
}

/// The same physical binding must serve the subsequent connect or listen operation.
/// Success transfers its physical socket to the returned handle. Closing this consumed
/// token must not close that child; the child has its own close/join owner.
/// Until that handoff is returned, accepted pending connect/listen work remains owned by
/// this SAME token: closing it cancels and joins the operation and any late result. Dropping
/// the operation's waiter must not detach cleanup. Listen success returns an already-listening
/// child with a known actual address, rather than a pending placeholder.
#[async_trait]
pub trait BoundTcp: Pollable + 'static {
    fn local_addr(&self) -> NetworkResult<SocketAddr>;
    fn set_socket_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()>;
    async fn connect(
        &self,
        peer: SocketAddr,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpStream>>;
    async fn listen(&self, backlog: u32, queue: WaitQueue) -> NetworkResult<Arc<dyn TcpListener>>;
    async fn close(&self, mode: NetworkCloseMode) -> NetworkResult<()>;
}

#[cfg(feature = "sys")]
mod host;
#[cfg(feature = "sys")]
pub use host::HostNetwork;
