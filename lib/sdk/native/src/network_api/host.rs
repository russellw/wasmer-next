//! The SDK Host provider delegates to the existing canonical reactor and resolver.
use super::*;
use wasixv2_vnet::{Answer, Found, LookupError, Shutdown, StreamState};
use wasixv2_vnet_host::{
    HostBackend, NativeBoundTcp, NativeDatagram, NativeListener, NativeReceiveLease, NativeStream,
};

pub struct HostNetwork {
    backend: Arc<HostBackend>,
}
impl Debug for HostNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostNetwork")
    }
}
impl HostNetwork {
    pub fn new() -> NetworkResult<Arc<Self>> {
        Ok(Arc::new(Self {
            backend: HostBackend::new()
                .map_err(|error| wasixv2_vnet_host::errno_from_io(&error))?,
        }))
    }
}
#[async_trait]
impl NetworkProvider for HostNetwork {
    async fn connect_tcp(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpStream>> {
        // Factory completion transfers the live Connecting handle. Its caller owns readiness
        // and close from this point; canceling a connection wait cannot lose its close ack.
        Ok(Arc::new(HostStream(
            self.backend.connect_tcp(local, peer, queue)?,
        )))
    }
    async fn bind_tcp(
        &self,
        local: SocketAddr,
        v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
    ) -> NetworkResult<Arc<dyn BoundTcp>> {
        Ok(Arc::new(HostBound(
            self.backend
                .bind_tcp(local, v6only, reuse_port, reuse_addr)?,
        )))
    }
    async fn listen_tcp(
        &self,
        local: SocketAddr,
        v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
        backlog: u32,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpListener>> {
        Ok(Arc::new(HostListener(self.backend.listen_tcp(
            local, v6only, reuse_port, reuse_addr, backlog, queue,
        )?)))
    }
    async fn bind_udp(
        &self,
        local: SocketAddr,
        v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn UdpSocket>> {
        Ok(Arc::new(HostDatagram(
            self.backend
                .bind_udp(local, v6only, reuse_port, reuse_addr, queue)?,
        )))
    }
    async fn resolve(
        &self,
        name: &str,
        port: Option<u16>,
        dns_server: Option<IpAddr>,
    ) -> NetworkResult<Vec<IpAddr>> {
        let (send, receive) = tokio::sync::oneshot::channel();
        self.backend.resolve_host(
            name,
            port,
            dns_server,
            Box::new(move |result| {
                let _ = send.send(result);
            }),
        );
        match receive.await.map_err(|_| NetworkError::ENETDOWN)? {
            Ok(Found {
                answer: Answer::Addrs { addrs, .. },
                ..
            }) => Ok(addrs),
            Err(LookupError::Provider(error)) => Err(error),
            Err(LookupError::NotFound { .. }) => Err(NetworkError::ENOENT),
            Ok(_) | Err(LookupError::Failed) => Err(NetworkError::EIO),
        }
    }
}
struct HostStream(Arc<NativeStream>);
impl Pollable for HostStream {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.0.poll(table)
    }
}
impl BackendStream for HostStream {
    fn provider_local_addr(&self) -> Option<NetworkResult<SocketAddr>> {
        Some(self.0.local_addr())
    }
    fn state(&self) -> StreamState {
        self.0.state()
    }
    fn tcp_established(&self) -> bool {
        self.0.tcp_established()
    }
    fn read(&self, buf: &mut [u8], peek: bool) -> NetworkResult<usize> {
        self.0.read(buf, peek)
    }
    fn write(&self, data: &[u8]) -> NetworkResult<usize> {
        self.0.write(data)
    }
    fn write_more(&self, data: &[u8], more: bool, mss: usize) -> NetworkResult<usize> {
        self.0.write_more(data, more, mss)
    }
    fn push(&self) {
        self.0.push();
    }
    fn corked_len(&self) -> usize {
        self.0.corked_len()
    }
    fn write_urgent(&self, data: &[u8]) -> NetworkResult<usize> {
        self.0.write_urgent(data)
    }
    fn read_urgent(&self, peek: bool) -> NetworkResult<u8> {
        self.0.read_urgent(peek)
    }
    fn at_mark(&self) -> bool {
        self.0.at_mark()
    }
    fn shutdown(&self, how: Shutdown) -> NetworkResult<()> {
        self.0.shutdown(how)
    }
    fn take_error(&self) -> Option<NetworkError> {
        self.0.take_error()
    }
    fn peer_addr(&self) -> SocketAddr {
        self.0.peer_addr()
    }
    fn input_len(&self) -> usize {
        self.0.input_len()
    }
    fn output_len(&self) -> usize {
        self.0.output_len()
    }
    fn set_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        self.0.set_option(level, name, value)
    }
}
#[async_trait]
impl TcpStream for HostStream {
    fn local_addr(&self) -> NetworkResult<SocketAddr> {
        self.0.local_addr()
    }
    fn flush(&self) -> NetworkResult<()> {
        self.0.flush()
    }
    fn set_socket_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        self.0.set_option(level, name, value)
    }
    async fn close(&self, mode: NetworkCloseMode) -> NetworkResult<()> {
        match mode {
            NetworkCloseMode::Normal => self.0.close().wait().await,
            NetworkCloseMode::Cancel => self.0.cancel().wait().await,
        }
    }
}
struct HostDatagram(Arc<NativeDatagram>);
impl Pollable for HostDatagram {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.0.poll(table)
    }
}
impl BackendDatagram for HostDatagram {
    fn send_to(&self, data: &[u8], to: SocketAddr) -> NetworkResult<usize> {
        self.0.send_to(data, to)
    }
    fn connect(&self, peer: Option<SocketAddr>) -> NetworkResult<()> {
        self.0.connect(peer)
    }
    fn take_error(&self) -> Option<NetworkError> {
        self.0.take_error()
    }
    fn recv_from(&self, buf: &mut [u8], peek: bool) -> NetworkResult<(usize, usize, SocketAddr)> {
        self.0.recv_from(buf, peek)
    }
    fn input_len(&self) -> usize {
        self.0.input_len()
    }
    fn set_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        self.0.set_option(level, name, value)
    }
    fn take_queued_error(&self) -> Option<wasixv2_vnet::QueuedError> {
        self.0.take_queued_error()
    }
    fn attach(&self, queue: Option<WaitQueue>) -> NetworkResult<()> {
        self.0.attach(queue)
    }
}
#[async_trait]
impl UdpSocket for HostDatagram {
    fn install_receiver(
        &self,
        receiver: Arc<dyn DatagramReceiver>,
    ) -> NetworkResult<Arc<dyn DatagramReceiveLease>> {
        Ok(Arc::new(HostReceiveLease(
            self.0.install_receiver(receiver)?,
        )))
    }
    fn peer_addr(&self) -> NetworkResult<Option<SocketAddr>> {
        self.0.peer_addr()
    }
    fn recv_packet(&self, buf: &mut [u8], peek: bool) -> NetworkResult<ReceivedDatagram> {
        self.0.recv_packet(buf, peek)
    }
    fn local_addr(&self) -> NetworkResult<SocketAddr> {
        self.0.local_addr()
    }
    fn set_socket_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        self.0.set_option(level, name, value)
    }
    async fn close(&self, _mode: NetworkCloseMode) -> NetworkResult<()> {
        self.0.close().wait().await
    }
}
struct HostListener(Arc<NativeListener>);
impl Pollable for HostListener {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.0.poll(table)
    }
}
#[async_trait]
impl TcpListener for HostListener {
    fn local_addr(&self) -> NetworkResult<SocketAddr> {
        self.0.local_addr()
    }
    fn try_accept(&self, queue: WaitQueue) -> NetworkResult<(Arc<dyn TcpStream>, SocketAddr)> {
        let stream = self.0.try_accept(queue)?;
        let peer = stream.peer_addr();
        Ok((Arc::new(HostStream(stream)), peer))
    }
    fn set_backlog(&self, backlog: u32) -> NetworkResult<()> {
        self.0.set_backlog(backlog)
    }
    fn set_socket_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        self.0.set_option(level, name, value)
    }
    async fn close(&self, _mode: NetworkCloseMode) -> NetworkResult<()> {
        self.0.close().wait().await
    }
}
struct HostBound(Arc<NativeBoundTcp>);
impl Pollable for HostBound {
    fn poll(&self, _: Option<&mut PollTable<'_>>) -> PollMask {
        match self.0.local_addr() {
            Ok(_) => PollMask::OUT,
            Err(NetworkError::EAGAIN) => PollMask::empty(),
            Err(_) => PollMask::ERR | PollMask::HUP,
        }
    }
}
#[async_trait]
impl BoundTcp for HostBound {
    fn local_addr(&self) -> NetworkResult<SocketAddr> {
        self.0.local_addr()
    }
    fn set_socket_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        self.0.set_option(level, name, value)
    }
    async fn connect(
        &self,
        peer: SocketAddr,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpStream>> {
        Ok(Arc::new(HostStream(self.0.connect(peer, queue)?)))
    }
    async fn listen(&self, backlog: u32, queue: WaitQueue) -> NetworkResult<Arc<dyn TcpListener>> {
        Ok(Arc::new(HostListener(self.0.listen(backlog, queue)?)))
    }
    async fn close(&self, _mode: NetworkCloseMode) -> NetworkResult<()> {
        self.0.close().wait().await
    }
}

struct HostReceiveLease(Arc<NativeReceiveLease>);
#[async_trait]
impl DatagramReceiveLease for HostReceiveLease {
    async fn wait_ready(&self) -> NetworkResult<()> {
        self.0.wait_ready().await
    }
    async fn close(&self) -> NetworkResult<()> {
        self.0.close().await
    }
}
