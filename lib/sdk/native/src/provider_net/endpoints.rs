//! The canonical namespace endpoint boundary over the SAME SDK provider/resource group.
use super::*;
use wasixv2_vnet::endpoint::{
    EndpointBindPurpose, EndpointBindRequest, EndpointBound, EndpointChoice,
    EndpointDatagramIngress, EndpointDatagramTx, EndpointGroupSpec, EndpointKind, EndpointLease,
    EndpointMember, EndpointProvider, EndpointQuery, EndpointSource, EndpointSourceId,
    EndpointStreamIngress, EndpointTarget, PublicationReporter, UdpTxConfig,
};

pub(super) struct NamespaceEndpoints {
    pub(super) provider: DynNetworkProvider,
    pub(super) group: Arc<Group>,
}
#[derive(Clone)]
enum Resource {
    Tcp {
        bound: Arc<dyn BoundTcp>,
        listener: Option<Arc<dyn TcpListener>>,
    },
    Listener(Arc<dyn TcpListener>),
    Udp(Arc<dyn UdpSocket>),
}
impl Resource {
    fn local_addr(&self) -> NetworkResult<SocketAddr> {
        match self {
            Self::Tcp {
                listener: Some(listener),
                ..
            } => listener.local_addr(),
            Self::Tcp {
                bound,
                listener: None,
            } => bound.local_addr(),
            Self::Listener(listener) => listener.local_addr(),
            Self::Udp(socket) => socket.local_addr(),
        }
    }
    fn set_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        match self {
            Self::Tcp {
                bound,
                listener: None,
            } => bound.set_socket_option(level, name, value),
            Self::Tcp {
                listener: Some(listener),
                ..
            }
            | Self::Listener(listener) => listener.set_socket_option(level, name, value),
            Self::Udp(socket) => socket.set_socket_option(level, name, value),
        }
    }
    async fn close(self, mode: NetworkCloseMode) -> NetworkResult<()> {
        match self {
            Self::Tcp { bound, listener } => {
                let first = if let Some(listener) = listener {
                    listener.close(mode).await
                } else {
                    Ok(())
                };
                let second = bound.close(mode).await;
                first.and(second)
            }
            Self::Listener(listener) => listener.close(mode).await,
            Self::Udp(socket) => socket.close(mode).await,
        }
    }
}
struct Physical {
    source: EndpointSourceId,
    // Acknowledged setter state belongs to this physical socket across source renewal.
    recv_errors: [Option<bool>; 2],
}
struct Binding {
    physical: Mutex<Physical>,
    group: Arc<Group>,
    service_lease: Mutex<Option<crate::service::Lease>>,
    resource_lease: Mutex<Option<Lease>>,
    cancellation: Arc<Cancellation>,
    state: Mutex<Socket<Resource>>,
    queue: WaitQueue,
    listen: tokio::sync::Mutex<()>,
    // Serializes accepted receive-lease withdrawal ACK before reinstall on this SAME FD.
    // Receiver callbacks never acquire this guard or any Binding state/physical guard.
    receive: Arc<tokio::sync::Mutex<()>>,
}
impl Binding {
    fn new(
        group: Arc<Group>,
        queue: WaitQueue,
        source: EndpointSourceId,
    ) -> NetworkResult<Arc<Self>> {
        let resource = group.resource()?;
        let lease = group
            .services
            .retain_cleanup()
            .map_err(|_| Errno::ENETDOWN)?;
        let result = Arc::new(Self {
            physical: Mutex::new(Physical {
                source,
                recv_errors: [Some(false); 2],
            }),
            group: group.clone(),
            service_lease: Mutex::new(Some(lease)),
            resource_lease: Mutex::new(Some(resource)),
            cancellation: Arc::default(),
            state: Mutex::new(Socket::Pending),
            queue,
            listen: tokio::sync::Mutex::new(()),
            receive: Arc::new(tokio::sync::Mutex::new(())),
        });
        group.register(result.clone())?;
        Ok(result)
    }
    fn ready(&self, result: NetworkResult<Resource>) {
        let mut state = self.state.lock().unwrap();
        if self.cancellation.closed() || matches!(*state, Socket::Closed) {
            drop(state);
            if let Ok(resource) = result {
                let group = self.group.clone();
                self.group.cleanup(async move {
                    group
                        .close_resource(|mode| Box::pin(resource.clone().close(mode)))
                        .await
                });
            }
            return;
        }
        *state = match result {
            Ok(resource) => Socket::Ready(resource),
            Err(error) => Socket::Failed(Some(error)),
        };
        drop(state);
        self.queue.wake(mask());
    }
    fn resource(&self) -> NetworkResult<Resource> {
        match &*self.state.lock().unwrap() {
            Socket::Ready(resource) => Ok(resource.clone()),
            Socket::Pending => Err(Errno::EAGAIN),
            Socket::Failed(error) => Err(error.unwrap_or(Errno::EIO)),
            Socket::Closed => Err(Errno::ENETDOWN),
        }
    }
    async fn listener(
        &self,
        backlog: u32,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpListener>> {
        let _serial = self.listen.lock().await;
        let bound = match self.resource()? {
            Resource::Listener(listener)
            | Resource::Tcp {
                listener: Some(listener),
                ..
            } => {
                listener.set_backlog(backlog)?;
                return Ok(listener);
            }
            Resource::Tcp {
                bound,
                listener: None,
            } => bound,
            Resource::Udp(_) => return Err(Errno::EPROTOTYPE),
        };
        let listener = bound.listen(backlog, queue).await?;
        let publish = {
            let mut state = self.state.lock().unwrap();
            if let Socket::Ready(Resource::Tcp { listener: slot, .. }) = &mut *state {
                if !self.cancellation.closed() {
                    *slot = Some(listener.clone());
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        if publish {
            Ok(listener)
        } else {
            let closed = self.group.close_resource(|mode| listener.close(mode)).await;
            self.group.record_close(closed);
            Err(Errno::ENETDOWN)
        }
    }
}
impl Endpoint for Binding {
    fn close(&self) {
        if !self.cancellation.close() {
            return;
        }
        let old = {
            let _physical = self.physical.lock().unwrap();
            std::mem::replace(&mut *self.state.lock().unwrap(), Socket::Closed)
        };
        let service = self.service_lease.lock().unwrap().take();
        let resource = self.resource_lease.lock().unwrap().take();
        let group = self.group.clone();
        self.group.cleanup(async move {
            let result = if let Socket::Ready(resource) = old {
                group
                    .close_resource(|mode| Box::pin(resource.clone().close(mode)))
                    .await
            } else {
                Ok(())
            };
            drop(service);
            drop(resource);
            result
        });
        self.queue.wake(mask());
    }
}
impl Drop for Binding {
    fn drop(&mut self) {
        self.close();
    }
}
impl Pollable for Binding {
    fn poll(&self, mut table: Option<&mut PollTable<'_>>) -> PollMask {
        if let Some(table) = &mut table {
            table.wait_on(&self.queue);
        }
        if let Ok(resource) = self.resource() {
            match resource {
                Resource::Tcp {
                    bound,
                    listener: None,
                } => {
                    let _ = bound.poll(table);
                }
                Resource::Tcp {
                    listener: Some(listener),
                    ..
                }
                | Resource::Listener(listener) => {
                    let _ = listener.poll(table);
                }
                Resource::Udp(socket) => {
                    let _ = socket.poll(table);
                }
            }
        }
        match self.local_addr() {
            Ok(_) => PollMask::OUT,
            Err(Errno::EAGAIN) => PollMask::empty(),
            Err(_) => PollMask::ERR | PollMask::HUP,
        }
    }
}
impl EndpointBound for Binding {
    fn local_addr(&self) -> NetworkResult<SocketAddr> {
        let _physical = self.physical.lock().unwrap();
        self.resource()?.local_addr()
    }
    fn set_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        let mut physical = self.physical.lock().unwrap();
        let index = match (level, name) {
            (0, 11) => Some(0),
            (41, 25) => Some(1),
            _ => None,
        };
        if let Some(index) = index {
            physical.recv_errors[index] = None;
        }
        let result = self.resource()?.set_option(level, name, value);
        if result.is_ok()
            && let Some(index) = index
        {
            physical.recv_errors[index] = value
                .get(..4)
                .map(|bytes| i32::from_le_bytes(bytes.try_into().unwrap()) != 0);
        }
        result
    }
    fn datagram_peer_addr(&self) -> Option<NetworkResult<Option<SocketAddr>>> {
        let _physical = self.physical.lock().unwrap();
        match self.resource() {
            Ok(Resource::Udp(socket)) => Some(socket.peer_addr()),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        }
    }
    fn connect_datagram(
        &self,
        source: EndpointSourceId,
        peer: Option<SocketAddr>,
    ) -> Option<NetworkResult<()>> {
        let mut physical = self.physical.lock().unwrap();
        let socket = match self.resource() {
            Ok(Resource::Udp(socket)) => socket,
            Ok(_) => return None,
            Err(error) => return Some(Err(error)),
        };
        if source.0 < physical.source.0 {
            return Some(Err(Errno::ECANCELED));
        }
        physical.source = source;
        let result = (|| {
            if socket.peer_addr()? == peer {
                Ok(())
            } else {
                socket.connect(peer)
            }
        })();
        drop(physical);
        self.queue.wake(mask());
        Some(result)
    }
}

#[derive(Clone)]
struct Target {
    group: Weak<Group>,
    binding: Option<Arc<dyn EndpointBound>>,
}
impl NamespaceEndpoints {
    fn binding<'a>(&self, binding: &'a Arc<dyn EndpointBound>) -> NetworkResult<&'a Binding> {
        let binding = (binding.as_ref() as &dyn std::any::Any)
            .downcast_ref::<Binding>()
            .ok_or(Errno::EINVAL)?;
        if !Arc::ptr_eq(&self.group, &binding.group) || self.group.closed() {
            return Err(Errno::ENETDOWN);
        }
        Ok(binding)
    }
    fn target<'a>(&self, target: &'a EndpointTarget) -> NetworkResult<&'a Target> {
        let target = target.downcast_ref::<Target>().ok_or(Errno::EINVAL)?;
        if !Weak::ptr_eq(&target.group, &Arc::downgrade(&self.group)) || self.group.closed() {
            return Err(Errno::ENETDOWN);
        }
        Ok(target)
    }
}
impl EndpointProvider for NamespaceEndpoints {
    fn select_external(&self) -> bool {
        true
    }
    fn select_bind(&self, _: &EndpointBindRequest) -> NetworkResult<bool> {
        Ok(true)
    }
    fn bind(
        &self,
        request: EndpointBindRequest,
        queue: WaitQueue,
    ) -> NetworkResult<Option<Arc<dyn EndpointBound>>> {
        let binding = Binding::new(self.group.clone(), queue.clone(), request.source_id)?;
        let output = Arc::downgrade(&binding);
        let cancel = binding.cancellation.clone();
        let group = self.group.clone();
        let provider = self.provider.clone();
        self.group.spawn(async move {
            let factory = async {
                match (request.kind, request.purpose) {
                    (EndpointKind::Stream, EndpointBindPurpose::Listen { backlog }) => provider
                        .listen_tcp(
                            request.requested,
                            request.v6only,
                            request.reuse_port,
                            request.reuse_addr,
                            backlog,
                            queue,
                        )
                        .await
                        .map(Resource::Listener),
                    (EndpointKind::Stream, EndpointBindPurpose::Bind) => provider
                        .bind_tcp(
                            request.requested,
                            request.v6only,
                            request.reuse_port,
                            request.reuse_addr,
                        )
                        .await
                        .map(|bound| Resource::Tcp {
                            bound,
                            listener: None,
                        }),
                    (EndpointKind::Datagram, _) => provider
                        .bind_udp(
                            request.requested,
                            request.v6only,
                            request.reuse_port,
                            request.reuse_addr,
                            queue,
                        )
                        .await
                        .map(Resource::Udp),
                }
            };
            if let Some(result) = group.wait_scoped(&cancel, factory).await {
                if let Some(output) = output.upgrade() {
                    output.ready(result);
                } else if let Ok(resource) = result {
                    group.record_close(
                        group
                            .close_resource(|mode| Box::pin(resource.clone().close(mode)))
                            .await,
                    );
                }
            }
        })?;
        Ok(Some(binding))
    }
    fn select(&self, query: &EndpointQuery) -> NetworkResult<EndpointChoice> {
        if self.group.closed() {
            return Err(Errno::ENETDOWN);
        }
        if let Some(binding) = &query.binding {
            self.binding(binding)?;
        }
        Ok(EndpointChoice::Provider(EndpointTarget::new(Target {
            group: Arc::downgrade(&self.group),
            binding: query.binding.clone(),
        })))
    }
    fn connect(
        &self,
        target: EndpointTarget,
        _source_id: EndpointSourceId,
        _local: SocketAddr,
        remote: SocketAddr,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn BackendStream>> {
        let target = self.target(&target)?.clone();
        let bound = if let Some(binding) = target.binding {
            match self.binding(&binding)?.resource()? {
                Resource::Tcp {
                    bound,
                    listener: None,
                } => Some(bound),
                _ => return Err(Errno::EINVAL),
            }
        } else {
            None
        };
        let stream = Stream::new(self.group.clone(), queue.clone(), remote)?;
        self.group.register(stream.clone())?;
        let output = Arc::downgrade(&stream);
        let cancel = stream.cancellation.clone();
        let group = self.group.clone();
        let provider = self.provider.clone();
        self.group.spawn(async move {
            let factory = async {
                if let Some(bound) = bound {
                    bound.connect(remote, queue).await
                } else {
                    provider
                        .connect_tcp(
                            any(if remote.is_ipv4() {
                                Domain::Inet
                            } else {
                                Domain::Inet6
                            }),
                            remote,
                            queue,
                        )
                        .await
                }
            };
            if let Some(result) = group.wait_scoped(&cancel, factory).await {
                if let Some(output) = output.upgrade() {
                    output.ready(result);
                } else if let Ok(socket) = result {
                    group.record_close(group.close_resource(|mode| socket.close(mode)).await);
                }
            }
        })?;
        Ok(stream)
    }
    fn datagram(
        &self,
        source: EndpointSource,
        initial: UdpTxConfig,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn EndpointDatagramTx>> {
        let binding = source.binding.as_ref().ok_or(Errno::EINVAL)?;
        let bound = self.binding(binding)?;
        let physical = bound.physical.lock().unwrap();
        if physical.source != source.id {
            return Err(Errno::ECANCELED);
        }
        let resource = bound.resource()?;
        let Resource::Udp(socket) = resource else {
            return Err(Errno::EPROTOTYPE);
        };
        let tx = Arc::new(Tx {
            group: Arc::downgrade(&self.group),
            binding: binding.clone(),
            socket,
            source: source.id,
            queue,
            state: Mutex::new(TxState {
                config: None,
                applied: None,
                error: None,
            }),
        });
        drop(physical);
        tx.configure(initial);
        Ok(tx)
    }
    fn publish_tcp(
        &self,
        spec: EndpointGroupSpec,
        backlog: u32,
        ingress: Arc<dyn EndpointStreamIngress>,
        reporter: PublicationReporter,
    ) -> NetworkResult<Arc<dyn EndpointLease>> {
        Publication::tcp(self.group.clone(), spec, backlog, ingress, reporter)
    }
    fn publish_udp(
        &self,
        spec: EndpointGroupSpec,
        ingress: Arc<dyn EndpointDatagramIngress>,
        reporter: PublicationReporter,
    ) -> NetworkResult<Arc<dyn EndpointLease>> {
        Publication::udp(self.group.clone(), spec, ingress, reporter)
    }
}
struct TxState {
    config: Option<UdpTxConfig>,
    applied: Option<u64>,
    error: Option<Errno>,
}
struct Tx {
    group: Weak<Group>,
    binding: Arc<dyn EndpointBound>,
    socket: Arc<dyn UdpSocket>,
    source: EndpointSourceId,
    queue: WaitQueue,
    state: Mutex<TxState>,
}
impl EndpointDatagramTx for Tx {
    fn configure(&self, config: UdpTxConfig) {
        let bound = (self.binding.as_ref() as &dyn std::any::Any)
            .downcast_ref::<Binding>()
            .expect("validated SDK binding");
        let mut physical = bound.physical.lock().unwrap();
        let mut state = self.state.lock().unwrap();
        if config.source_id != self.source
            || state
                .config
                .is_some_and(|current| config.revision <= current.revision)
        {
            return;
        }
        state.config = Some(config);
        state.applied = None;
        if physical.source != self.source || bound.cancellation.closed() {
            state.error.get_or_insert(Errno::ECANCELED);
            drop(state);
            drop(physical);
            self.queue.wake(PollMask::ERR);
            return;
        }
        let result = (|| {
            // Association belongs only to EndpointBound::connect_datagram. Config's
            // canonical peer is bookkeeping and must not replay/strip a literal scope.
            for (index, level, name, enabled) in [
                (0, 0, 11, config.recv_v4_errors),
                (1, 41, 25, config.recv_v6_errors),
            ] {
                if physical.recv_errors[index] != Some(enabled) {
                    physical.recv_errors[index] = None;
                    self.socket.set_socket_option(
                        level,
                        name,
                        &i32::from(enabled).to_le_bytes(),
                    )?;
                    physical.recv_errors[index] = Some(enabled);
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => state.applied = Some(config.revision),
            Err(error) => {
                state.error.get_or_insert(error);
            }
        }
        drop(state);
        drop(physical);
        self.queue.wake(mask());
    }
    fn send_to(
        &self,
        revision: u64,
        target: &EndpointTarget,
        _source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
    ) -> NetworkResult<usize> {
        let target = target.downcast_ref::<Target>().ok_or(Errno::EINVAL)?;
        if !Weak::ptr_eq(&target.group, &self.group)
            || self.group.upgrade().is_none_or(|group| group.closed())
        {
            return Err(Errno::ENETDOWN);
        }
        if target
            .binding
            .as_ref()
            .is_none_or(|binding| !Arc::ptr_eq(binding, &self.binding))
        {
            return Err(Errno::EINVAL);
        }
        let bound = (self.binding.as_ref() as &dyn std::any::Any)
            .downcast_ref::<Binding>()
            .ok_or(Errno::EINVAL)?;
        let physical = bound.physical.lock().unwrap();
        if physical.source != self.source || bound.cancellation.closed() {
            return Err(Errno::ECANCELED);
        }
        let state = self.state.lock().unwrap();
        if state.applied != Some(revision) {
            return Err(Errno::EAGAIN);
        }
        let count = self.socket.send_to(data, destination)?;
        if count != data.len() {
            return Err(Errno::EIO);
        }
        Ok(count)
    }
    fn poll_tx(&self, revision: u64) -> PollMask {
        let bound = (self.binding.as_ref() as &dyn std::any::Any)
            .downcast_ref::<Binding>()
            .expect("validated SDK binding");
        let physical = bound.physical.lock().unwrap();
        if physical.source != self.source || bound.cancellation.closed() {
            return PollMask::ERR | PollMask::HUP;
        }
        let state = self.state.lock().unwrap();
        let mut ready = PollMask::empty();
        if state.error.is_some() {
            ready |= PollMask::ERR;
        }
        if state.applied == Some(revision) {
            ready |= self.socket.poll(None)
                & (PollMask::OUT | PollMask::WRNORM | PollMask::ERR | PollMask::HUP);
        }
        ready
    }
    fn take_error(&self) -> Option<Errno> {
        let bound = (self.binding.as_ref() as &dyn std::any::Any)
            .downcast_ref::<Binding>()
            .expect("validated SDK binding");
        let physical = bound.physical.lock().unwrap();
        let error = self.state.lock().unwrap().error.take();
        if physical.source != self.source || bound.cancellation.closed() {
            return error.or(Some(Errno::ECANCELED));
        }
        error.or_else(|| self.socket.take_error())
    }
    fn take_queued_error(&self) -> Option<wasixv2_vnet::QueuedError> {
        let bound = (self.binding.as_ref() as &dyn std::any::Any)
            .downcast_ref::<Binding>()
            .expect("validated SDK binding");
        let physical = bound.physical.lock().unwrap();
        if physical.source != self.source || bound.cancellation.closed() {
            return None;
        }
        self.socket.take_queued_error()
    }
}

#[derive(Clone)]
struct Config {
    receives: std::collections::BTreeMap<EndpointSourceId, ReceiveState>,
    member_revision: u64,
    backlog_revision: u64,
    members: Arc<[EndpointMember]>,
    backlog: u32,
}
impl Config {
    fn version(&self) -> (u64, u64) {
        (self.member_revision, self.backlog_revision)
    }
}
struct PublicationControl {
    reporter: PublicationReporter,
    config: Mutex<Config>,
    changed: Notify,
    cancel: Cancellation,
}
struct Publication {
    reporter: PublicationReporter,
    control: Arc<PublicationControl>,
}
impl Publication {
    fn new(spec: &EndpointGroupSpec, backlog: u32, reporter: PublicationReporter) -> Arc<Self> {
        Arc::new(Self {
            reporter: reporter.clone(),
            control: Arc::new(PublicationControl {
                reporter: reporter.clone(),
                config: Mutex::new(Config {
                    receives: Default::default(),
                    member_revision: spec.revision,
                    backlog_revision: spec.revision,
                    members: spec.members.clone(),
                    backlog,
                }),
                changed: Notify::new(),
                cancel: Cancellation::default(),
            }),
        })
    }
    fn tcp(
        group: Arc<Group>,
        spec: EndpointGroupSpec,
        backlog: u32,
        ingress: Arc<dyn EndpointStreamIngress>,
        reporter: PublicationReporter,
    ) -> NetworkResult<Arc<dyn EndpointLease>> {
        let lease = Self::new(&spec, backlog, reporter.clone());
        let control = lease.control.clone();
        let jobgroup = group.clone();
        group.spawn(async move {
            let result = drive_tcp(&jobgroup, &control, &*ingress, &reporter).await;
            if let Err(error) = result {
                reporter.failed(error);
            }
        })?;
        Ok(lease)
    }
    fn udp(
        group: Arc<Group>,
        spec: EndpointGroupSpec,
        ingress: Arc<dyn EndpointDatagramIngress>,
        reporter: PublicationReporter,
    ) -> NetworkResult<Arc<dyn EndpointLease>> {
        let lease = Self::new(&spec, 0, reporter.clone());
        let control = lease.control.clone();
        let jobgroup = group.clone();
        let (group_id, attempt_id) = (spec.group_id, spec.attempt_id);
        // Only plain captured IDs outlive this call, not the original member/binding snapshot.
        drop(spec);
        group.spawn(async move {
            let result = drive_udp(&jobgroup, &control, group_id, attempt_id, ingress).await;
            if let Err(error) = result {
                reporter.failed(error);
            }
        })?;
        Ok(lease)
    }
}
impl Drop for Publication {
    fn drop(&mut self) {
        self.control.cancel.close();
        self.control.changed.notify_waiters();
    }
}
impl Pollable for Publication {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.reporter.poll(table)
    }
}
impl EndpointLease for Publication {
    fn reporter(&self) -> &PublicationReporter {
        &self.reporter
    }
    fn set_backlog(&self, revision: u64, backlog: u32) {
        let mut config = self.control.config.lock().unwrap();
        if revision <= config.backlog_revision {
            return;
        }
        config.backlog_revision = revision;
        config.backlog = backlog;
        drop(config);
        self.control.changed.notify_waiters();
    }
    fn update_members(&self, revision: u64, members: Arc<[EndpointMember]>) {
        let mut config = self.control.config.lock().unwrap();
        if revision <= config.member_revision {
            return;
        }
        config.member_revision = revision;
        let old = std::mem::replace(&mut config.members, members);
        drop(config);
        // A removed last binding may queue real close; release it outside this config lock.
        drop(old);
        self.control.changed.notify_waiters();
    }
}
enum ControlResult<T> {
    Value(T),
    Changed,
    Closed,
}
impl PublicationControl {
    async fn during<T>(
        &self,
        group: &Group,
        version: (u64, u64),
        work: impl Future<Output = T>,
    ) -> ControlResult<T> {
        let changed = self.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if self.cancel.closed() || group.closed() {
            return ControlResult::Closed;
        }
        if self.config.lock().unwrap().version() != version {
            return ControlResult::Changed;
        }
        tokio::select! {biased;_=&mut changed=>ControlResult::Changed,result=group.wait_scoped(&self.cancel,work)=>match result{Some(value)=>ControlResult::Value(value),None=>ControlResult::Closed}}
    }
    fn current(&self, version: (u64, u64)) -> bool {
        !self.cancel.closed() && self.config.lock().unwrap().version() == version
    }
}
fn member_binding(
    member: &EndpointMember,
    group: &Arc<Group>,
) -> NetworkResult<Arc<dyn EndpointBound>> {
    let binding = member.binding.clone().ok_or(Errno::EINVAL)?;
    let bound = (binding.as_ref() as &dyn std::any::Any)
        .downcast_ref::<Binding>()
        .ok_or(Errno::EINVAL)?;
    if !Arc::ptr_eq(group, &bound.group) {
        return Err(Errno::ENETDOWN);
    }
    Ok(binding)
}
async fn drive_tcp(
    group: &Arc<Group>,
    control: &PublicationControl,
    ingress: &dyn EndpointStreamIngress,
    reporter: &PublicationReporter,
) -> NetworkResult<()> {
    loop {
        if group.closed() || control.cancel.closed() {
            return Ok(());
        }
        let config = control.config.lock().unwrap().clone();
        let version = config.version();
        let queue = WaitQueue::new();
        let prepare = async {
            let mut listeners = Vec::new();
            for member in config.members.iter() {
                let binding = member_binding(member, group)?;
                let bound = (binding.as_ref() as &dyn std::any::Any)
                    .downcast_ref::<Binding>()
                    .ok_or(Errno::EINVAL)?;
                let listener = bound.listener(config.backlog, queue.clone()).await?;
                listeners.push((member.source_id, listener));
            }
            if listeners.is_empty() {
                return Err(Errno::ENETDOWN);
            }
            Ok(listeners)
        };
        let listeners = match control.during(group, version, prepare).await {
            ControlResult::Value(result) => result?,
            ControlResult::Changed => continue,
            ControlResult::Closed => return Ok(()),
        };
        if !control.current(version) {
            continue;
        }
        reporter.ready_member(config.members[0].source_id);
        let mut cursor = 0;
        loop {
            let mut registrations = Vec::new();
            let accepted = futures::future::poll_fn(|cx| {
                registrations.clear();
                let mut register = |queue: &WaitQueue, _: PollMask| {
                    registrations.push(queue.add(Arc::new(TaskWake(cx.waker().clone()))));
                };
                let mut table = PollTable::new(mask(), &mut register);
                table.wait_on(&queue);
                for step in 0..listeners.len() {
                    let index = (cursor + step) % listeners.len();
                    let (member, listener) = &listeners[index];
                    let events = listener.poll(Some(&mut table));
                    let stream_queue = WaitQueue::new();
                    match listener.try_accept(stream_queue.clone()) {
                        Ok((socket, peer)) => {
                            cursor = (index + 1) % listeners.len();
                            return Poll::Ready(Ok((socket, peer, stream_queue, *member)));
                        }
                        Err(Errno::EAGAIN) if !events.intersects(PollMask::ERR | PollMask::HUP) => {
                        }
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                }
                Poll::Pending
            });
            let (socket, peer, queue, member) = match control.during(group, version, accepted).await
            {
                ControlResult::Value(result) => result?,
                ControlResult::Changed => break,
                ControlResult::Closed => return Ok(()),
            };
            let local = match socket.local_addr() {
                Ok(local) => local,
                Err(error) => {
                    group.record_close(group.close_resource(|mode| socket.close(mode)).await);
                    return Err(error);
                }
            };
            if socket.peer_addr() != peer {
                group.record_close(group.close_resource(|mode| socket.close(mode)).await);
                return Err(Errno::EPROTO);
            }
            let mut registrations = Vec::new();
            let room = futures::future::poll_fn(|cx| {
                registrations.clear();
                let mut register = |queue: &WaitQueue, _: PollMask| {
                    registrations.push(queue.add(Arc::new(TaskWake(cx.waker().clone()))));
                };
                let mut table = PollTable::new(PollMask::OUT, &mut register);
                match ingress.poll_room_member_to(member, peer, local, Some(&mut table)) {
                    Room::Full => Poll::Pending,
                    room => Poll::Ready(room),
                }
            });
            let ready = control.during(group, version, room).await;
            match ready {
                ControlResult::Value(Room::Ready)
                    if control.current(version) && !group.closed() =>
                {
                    let stream = match Stream::new(group.clone(), queue.clone(), peer) {
                        Ok(stream) => stream,
                        Err(error) => {
                            group.record_close(
                                group.close_resource(|mode| socket.close(mode)).await,
                            );
                            return Err(error);
                        }
                    };
                    stream.ready(Ok(socket));
                    group.register(stream.clone())?;
                    let _ = ingress.incoming_member_to(member, peer, local, stream, queue);
                }
                ControlResult::Closed => {
                    group.record_close(group.close_resource(|mode| socket.close(mode)).await);
                    return Ok(());
                }
                _ => {
                    group.record_close(group.close_resource(|mode| socket.close(mode)).await);
                    break;
                }
            }
            tokio::task::yield_now().await;
        }
    }
}

#[derive(Clone)]
struct ReceiveState {
    identity: Arc<()>,
    binding: Weak<dyn EndpointBound>,
    ready: bool,
}
struct MemberReceiver {
    control: Weak<PublicationControl>,
    binding: Weak<dyn EndpointBound>,
    identity: Arc<()>,
    member: EndpointSourceId,
    group: wasixv2_vnet::endpoint::EndpointGroupId,
    attempt: wasixv2_vnet::endpoint::PublicationAttemptId,
    ingress: Arc<dyn EndpointDatagramIngress>,
}
fn current_receive(
    config: &Config,
    member: EndpointSourceId,
    identity: &Arc<()>,
    binding: &Weak<dyn EndpointBound>,
) -> bool {
    config.receives.get(&member).is_some_and(|state| {
        Arc::ptr_eq(identity, &state.identity) && Weak::ptr_eq(binding, &state.binding)
    }) && config.members.iter().any(|current| {
        current.source_id == member
            && current
                .binding
                .as_ref()
                .is_some_and(|current| Weak::ptr_eq(binding, &Arc::downgrade(current)))
    })
}
fn ready_members(config: &Config) -> bool {
    !config.members.is_empty()
        && config.members.iter().all(|member| {
            config.receives.get(&member.source_id).is_some_and(|state| {
                state.ready
                    && current_receive(config, member.source_id, &state.identity, &state.binding)
            })
        })
}
impl PublicationControl {
    fn fail_member(&self, member: EndpointSourceId, error: Errno) {
        self.reporter.failed_member(member, error);
        if matches!(
            self.reporter.state(),
            wasixv2_vnet::endpoint::PublicationState::Failed(_)
        ) {
            self.cancel.close();
            self.changed.notify_waiters();
        }
    }
    fn report_ready_members(&self) {
        let member = {
            let config = self.config.lock().unwrap();
            ready_members(&config).then(|| config.members[0].source_id)
        };
        if !self.cancel.closed()
            && let Some(member) = member
        {
            self.reporter.ready_member(member);
        }
    }
}

impl MemberReceiver {
    fn current(&self) -> bool {
        self.control.upgrade().is_some_and(|control| {
            if control.cancel.closed() {
                return false;
            }
            let config = control.config.lock().unwrap();
            current_receive(&config, self.member, &self.identity, &self.binding)
        })
    }
}
impl crate::network_api::DatagramReceiver for MemberReceiver {
    fn ready(&self) {
        let Some(control) = self.control.upgrade() else {
            return;
        };
        if control.cancel.closed() {
            return;
        }
        let ready = {
            let mut config = control.config.lock().unwrap();
            if !current_receive(&config, self.member, &self.identity, &self.binding) {
                return;
            }
            config.receives.get_mut(&self.member).unwrap().ready = true;
            ready_members(&config)
        };
        if ready && !control.cancel.closed() {
            // The witness is THIS captured member; Core atomically rejects its removal
            // between the SDK snapshot and this callback, without any SDK mutex held.
            control.reporter.ready_member(self.member);
        }
    }
    fn failed(&self, error: Errno) {
        let Some(control) = self.control.upgrade() else {
            return;
        };
        if control.cancel.closed() {
            return;
        }
        {
            let config = control.config.lock().unwrap();
            if !current_receive(&config, self.member, &self.identity, &self.binding) {
                return;
            }
        }
        // No SDK mutex or Binding guard is held across a foreign/core callback.
        control.fail_member(self.member, error);
    }
    fn received(
        &self,
        info: crate::network_api::DatagramInfo,
        bytes: &[u8],
    ) -> wasixv2_vnet::endpoint::DatagramDelivery {
        use wasixv2_vnet::endpoint::DatagramDelivery;
        let Some(control) = self.control.upgrade() else {
            return DatagramDelivery::Retired;
        };
        if control.cancel.closed() {
            return DatagramDelivery::Retired;
        }
        {
            let config = control.config.lock().unwrap();
            if !current_receive(&config, self.member, &self.identity, &self.binding) {
                return DatagramDelivery::Retired;
            }
            if !config.receives[&self.member].ready {
                return DatagramDelivery::Dropped;
            }
        }
        // The existing producer driver observes and admits NOW, with exact member affinity;
        // no private packet queue can relabel bytes after a later readiness/membership change.
        self.ingress
            .incoming_member_packet(self.group, self.attempt, self.member, info, bytes)
    }
}
struct ReceiveJob {
    identity: Arc<()>,
    binding: Weak<dyn EndpointBound>,
    cancel: Arc<Cancellation>,
}
impl Drop for ReceiveJob {
    fn drop(&mut self) {
        self.cancel.close();
    }
}
async fn drive_udp(
    group: &Arc<Group>,
    control: &Arc<PublicationControl>,
    group_id: wasixv2_vnet::endpoint::EndpointGroupId,
    attempt: wasixv2_vnet::endpoint::PublicationAttemptId,
    ingress: Arc<dyn EndpointDatagramIngress>,
) -> NetworkResult<()> {
    let mut jobs = std::collections::BTreeMap::<EndpointSourceId, ReceiveJob>::new();
    loop {
        let changed = control.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if group.closed() || control.cancel.closed() {
            break;
        }
        let members = control.config.lock().unwrap().members.clone();
        let retired: Vec<_> = jobs
            .iter()
            .filter(|(id, job)| {
                !members.iter().any(|member| {
                    member.source_id == **id
                        && member.binding.as_ref().is_some_and(|binding| {
                            Weak::ptr_eq(&job.binding, &Arc::downgrade(binding))
                        })
                })
            })
            .map(|(id, _)| *id)
            .collect();
        for member in retired {
            if let Some(job) = jobs.remove(&member) {
                job.cancel.close();
                let mut config = control.config.lock().unwrap();
                if config
                    .receives
                    .get(&member)
                    .is_some_and(|state| Arc::ptr_eq(&state.identity, &job.identity))
                {
                    config.receives.remove(&member);
                }
            }
        }
        for member in members.iter() {
            if jobs.contains_key(&member.source_id) {
                continue;
            }
            let prepared = (|| {
                let binding = member_binding(member, group)?;
                let bound = (binding.as_ref() as &dyn std::any::Any)
                    .downcast_ref::<Binding>()
                    .ok_or(Errno::EINVAL)?;
                let Resource::Udp(socket) = bound.resource()? else {
                    return Err(Errno::EPROTOTYPE);
                };
                Ok((binding.clone(), socket, bound.receive.clone()))
            })();
            let (binding, socket, serial) = match prepared {
                Ok(prepared) => prepared,
                Err(error) => {
                    control.fail_member(member.source_id, error);
                    continue;
                }
            };
            let weak_binding = Arc::downgrade(&binding);
            let identity = Arc::new(());
            let cancel = Arc::new(Cancellation::default());
            {
                let mut config = control.config.lock().unwrap();
                if !config.members.iter().any(|current| {
                    current.source_id == member.source_id
                        && current
                            .binding
                            .as_ref()
                            .is_some_and(|current| Arc::ptr_eq(current, &binding))
                }) {
                    continue;
                }
                config.receives.insert(
                    member.source_id,
                    ReceiveState {
                        identity: identity.clone(),
                        binding: weak_binding.clone(),
                        ready: false,
                    },
                );
            }
            let receiver = Arc::new(MemberReceiver {
                control: Arc::downgrade(control),
                binding: weak_binding.clone(),
                identity: identity.clone(),
                member: member.source_id,
                group: group_id,
                attempt,
                ingress: ingress.clone(),
            });
            let worker_group = group.clone();
            let stopping = cancel.clone();
            let admitted = group.spawn(async move {
                // This serial guard is ONLY an install/withdrawal lease. Receiver callbacks
                // never acquire it or any Binding guard, so synchronous callbacks can reenter.
                let Some(_serial) = worker_group.wait_scoped(&stopping, serial.lock()).await else {
                    return;
                };
                if stopping.closed() || !receiver.current() {
                    return;
                }
                let lease = match socket.install_receiver(receiver.clone()) {
                    Ok(lease) => lease,
                    Err(error) => {
                        crate::network_api::DatagramReceiver::failed(&*receiver, error);
                        return;
                    }
                };
                match worker_group
                    .wait_scoped(&stopping, lease.wait_ready())
                    .await
                {
                    Some(Ok(())) => {
                        crate::network_api::DatagramReceiver::ready(&*receiver);
                        let _ = worker_group
                            .wait_scoped(&stopping, std::future::pending::<()>())
                            .await;
                    }
                    Some(Err(error)) => {
                        crate::network_api::DatagramReceiver::failed(&*receiver, error)
                    }
                    None => {}
                }
                // Borrowed wait cancellation does not withdraw: retain the accepted lease
                // and its actual callback work until this explicit withdrawal ACK completes.
                worker_group.record_close(lease.close().await);
            });
            if let Err(error) = admitted {
                control.fail_member(member.source_id, error);
                return Ok(());
            }
            jobs.insert(
                member.source_id,
                ReceiveJob {
                    identity,
                    binding: weak_binding,
                    cancel,
                },
            );
        }
        drop(members);
        control.report_ready_members();
        if group.wait_scoped(&control.cancel, changed).await.is_none() {
            break;
        }
    }
    for (_, job) in jobs {
        job.cancel.close();
    }
    // Every accepted per-member job has its own existing Group lease through withdrawal ACK.
    Ok(())
}
