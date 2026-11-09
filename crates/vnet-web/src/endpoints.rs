//! Opt-in endpoint resources on the existing WebBackend driver and socket IDs.
//! No callback or ingress call may run with Shared::inner held.
use std::{
    any::Any,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
};
use wasixv2_abi::Errno;
use wasixv2_vnet::{
    Backend, BackendDatagram, BackendStream, Domain, InboundSink, Lookup, LookupDone, Publication,
    PublishedDatagram, Room,
    endpoint::{
        EndpointBindPurpose, EndpointBindRequest, EndpointBound, EndpointChoice, EndpointGroupSpec,
        EndpointKind, EndpointLease, EndpointMember, EndpointProvider, EndpointQuery,
        EndpointSourceId, EndpointStreamIngress, EndpointTarget, PublicationReporter,
        PublicationState,
    },
};
use wasixv2_wait::{PollMask, PollTable, Pollable, WaitQueue};

use crate::{
    WebBackend,
    backend::{Flow, Listener, Shared, Stream},
};

/// Outcome of joining the selected resources owned by this local transport.
/// The stock Classic protocol cannot attest remote physical retirement. Keep
/// that boundary separate from the guest result and from local cleanup errors.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SelectedCloseReport {
    pub remote_cleanup_unconfirmed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    Bind,
    Connect,
    Listen,
    Close,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Queued(Operation),
    Pending(Operation),
    Bound,
    Connected,
    Listening,
    Closed,
}

pub(crate) struct State {
    pub phase: Phase,
    pub actual: Option<SocketAddr>,
    pub connect_local: Option<SocketAddr>,
    pub error: Option<Errno>,
    pub transferred: bool,
    pub close: Option<Result<(), Errno>>,
    pub close_error: Option<Errno>,
    pub close_request: Option<u64>,
    pub closing: bool,
    pub close_requested: bool,
    pub remote_cleanup_unconfirmed: bool,
}

pub(crate) struct Resource {
    pub generation: u64,
    pub request: Option<EndpointBindRequest>,
    pub reserved: Option<(EndpointMember, Domain, bool)>,
    pub state: Mutex<State>,
    pub queue: WaitQueue,
}
impl Resource {
    pub fn new(
        request: Option<EndpointBindRequest>,
        operation: Operation,
        queue: WaitQueue,
        generation: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            generation,
            request,
            reserved: None,
            state: Mutex::new(State {
                phase: Phase::Queued(operation),
                actual: None,
                connect_local: None,
                error: None,
                transferred: false,
                close: None,
                close_error: None,
                close_request: None,
                closing: false,
                close_requested: false,
                remote_cleanup_unconfirmed: false,
            }),
            queue,
        })
    }
    fn reserved(
        member: EndpointMember,
        domain: Domain,
        v6only: bool,
        generation: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            generation,
            request: None,
            reserved: Some((member, domain, v6only)),
            state: Mutex::new(State {
                phase: Phase::Queued(Operation::Listen),
                actual: None,
                connect_local: None,
                error: None,
                transferred: true,
                close: None,
                close_error: None,
                close_request: None,
                closing: false,
                close_requested: false,
                remote_cleanup_unconfirmed: false,
            }),
            queue: WaitQueue::new(),
        })
    }
    pub fn address(&self) -> Result<SocketAddr, Errno> {
        let state = self.state.lock().unwrap();
        if (state.closing || state.close_requested) && state.close.is_none() {
            return Err(Errno::EAGAIN);
        }
        if let Some(error) = state.error {
            return Err(error);
        }
        if state.phase == Phase::Closed {
            return Err(Errno::ENETDOWN);
        }
        state.actual.ok_or(Errno::EAGAIN)
    }
    pub fn failed(&self, error: Errno) {
        let mut state = self.state.lock().unwrap();
        state.error.get_or_insert(error);
        state.phase = Phase::Closed;
        if state.close.is_none() {
            state.close = Some(Err(error));
            state.close_error.get_or_insert(error);
        }
    }
    pub fn local_finished_unconfirmed(&self, error: Option<Errno>) {
        let mut state = self.state.lock().unwrap();
        state.phase = Phase::Closed;
        if state.close.is_none() {
            state.close = Some(error.map_or(Ok(()), Err));
            state.remote_cleanup_unconfirmed = true;
            if let Some(error) = error {
                state.close_error.get_or_insert(error);
                state.error.get_or_insert(error);
            }
        }
    }
}
impl Pollable for Resource {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        if let Some(table) = table {
            table.wait_on(&self.queue);
        }
        let state = self.state.lock().unwrap();
        if (state.closing || state.close_requested) && state.close.is_none() {
            return PollMask::empty();
        }
        if state.error.is_some() || state.phase == Phase::Closed {
            PollMask::ERR | PollMask::HUP
        } else if matches!(
            state.phase,
            Phase::Bound | Phase::Connected | Phase::Listening
        ) {
            PollMask::OUT
        } else {
            PollMask::empty()
        }
    }
}

struct Bound {
    shared: Arc<Shared>,
    id: u64,
    resource: Arc<Resource>,
    identity: Weak<()>,
}
impl Pollable for Bound {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.resource.poll(table)
    }
}
impl EndpointBound for Bound {
    fn local_addr(&self) -> Result<SocketAddr, Errno> {
        self.resource.address()
    }
}
impl Drop for Bound {
    fn drop(&mut self) {
        // A transferred child owns physical close; the old token owns only metadata.
        let transferred = self.resource.state.lock().unwrap().transferred;
        if !transferred {
            super::backend::release(&self.shared, self.id);
        }
    }
}

struct Target {
    shared: Weak<Shared>,
    identity: Weak<()>,
    generation: u64,
    source: EndpointSourceId,
    binding: Option<Arc<dyn EndpointBound>>,
    peer: SocketAddr,
}
struct NamespaceBackend {
    backend: Arc<WebBackend>,
}
impl Backend for NamespaceBackend {
    fn endpoint_namespace(&self) -> Option<Arc<dyn EndpointProvider>> {
        Some(Arc::new(Provider {
            shared: self.backend.shared.clone(),
            identity: Arc::new(()),
        }))
    }
    fn provider(&self) -> Option<Arc<dyn wasixv2_vnet::provider::Provider>> {
        self.backend.provider()
    }
    fn connect(&self, peer: SocketAddr, queue: WaitQueue) -> Result<Arc<dyn BackendStream>, Errno> {
        self.backend.connect(peer, queue)
    }
    fn datagram(
        &self,
        domain: Domain,
        queue: WaitQueue,
    ) -> Result<Arc<dyn BackendDatagram>, Errno> {
        self.backend.datagram(domain, queue)
    }
    fn publish(
        &self,
        host: SocketAddr,
        backlog: u32,
        sink: Arc<dyn InboundSink>,
    ) -> std::io::Result<Box<dyn Publication>> {
        self.backend.publish(host, backlog, sink)
    }
    fn publish_datagram(&self, host: SocketAddr) -> std::io::Result<PublishedDatagram> {
        self.backend.publish_datagram(host)
    }
    fn lookup(&self, lookup: Lookup, done: LookupDone) {
        self.backend.lookup(lookup, done);
    }
}
impl WebBackend {
    /// Opt into canonical endpoint admission without creating another backend or driver.
    /// The transport must advertise and implement selected_endpoints explicitly.
    pub fn with_namespace_endpoints(self: Arc<Self>) -> Arc<dyn Backend> {
        Arc::new(NamespaceBackend { backend: self })
    }
    /// Revoke selected admission, then join each actual provider-close transaction.
    /// Keep polling the same Driver until this completes. Dropping a subscriber
    /// does not cancel accepted close or manufacture a success acknowledgement.
    pub async fn close_endpoints(&self) -> Result<SelectedCloseReport, Errno> {
        use futures_util::{future::poll_fn, task::AtomicWaker};
        use std::task::Poll;
        use wasixv2_wait::WaitEntry;
        struct Wake(AtomicWaker);
        impl WaitEntry for Wake {
            fn wake(&self, _: PollMask) -> bool {
                self.0.wake();
                true
            }
        }
        let resources = {
            let mut inner = self.shared.inner.lock().unwrap();
            if let Some(resources) = &inner.selected_close {
                resources.clone()
            } else {
                let generation = inner.generation;
                let mut resources = Vec::new();
                for flow in inner.flows.values_mut() {
                    if let Some(resource) = &flow.selected
                        && resource.generation == generation
                    {
                        resource.state.lock().unwrap().close_requested = true;
                        resources.push(resource.clone());
                    }
                }
                for listener in inner.listeners.values_mut() {
                    if let Some(resource) = &listener.selected
                        && resource.generation == generation
                    {
                        listener.released = true;
                        resources.push(resource.clone());
                    }
                }
                let resources: Arc<[_]> = resources.into();
                inner.selected_close = Some(resources.clone());
                resources
            }
        };
        self.shared.wake.wake();
        let wake = Arc::new(Wake(AtomicWaker::new()));
        let _registrations: Vec<_> = resources
            .iter()
            .map(|resource| resource.queue.add(wake.clone()))
            .collect();
        poll_fn(|cx| {
            wake.0.register(cx.waker());
            let mut pending = false;
            let mut failure = None;
            let mut report = SelectedCloseReport::default();
            for resource in resources.iter() {
                let state = resource.state.lock().unwrap();
                report.remote_cleanup_unconfirmed |= state.remote_cleanup_unconfirmed;
                if let Some(error) = state.close_error {
                    failure.get_or_insert(error);
                }
                match state.close {
                    None => pending = true,
                    Some(Err(error)) => {
                        failure.get_or_insert(error);
                    }
                    Some(Ok(())) => {}
                }
            }
            if pending {
                Poll::Pending
            } else {
                Poll::Ready(failure.map_or(Ok(report), Err))
            }
        })
        .await
    }
}

struct Provider {
    shared: Arc<Shared>,
    identity: Arc<()>,
}
impl Provider {
    fn bound<'a>(&self, binding: &'a Arc<dyn EndpointBound>) -> Result<&'a Bound, Errno> {
        let bound = (binding.as_ref() as &dyn Any)
            .downcast_ref::<Bound>()
            .ok_or(Errno::EINVAL)?;
        if !Arc::ptr_eq(&self.shared, &bound.shared)
            || !Weak::ptr_eq(&bound.identity, &Arc::downgrade(&self.identity))
        {
            return Err(Errno::ENETDOWN);
        }
        Ok(bound)
    }
}
impl EndpointProvider for Provider {
    fn select_external(&self) -> bool {
        true
    }
    fn select_bind(&self, request: &EndpointBindRequest) -> Result<bool, Errno> {
        let inner = self.shared.inner.lock().unwrap();
        if !inner.online || inner.selected_close.is_some() {
            return Err(Errno::ENETDOWN);
        }
        Ok(request.kind == EndpointKind::Stream && inner.capabilities.selected_bind)
    }
    fn bind(
        &self,
        request: EndpointBindRequest,
        queue: WaitQueue,
    ) -> Result<Option<Arc<dyn EndpointBound>>, Errno> {
        if request.kind != EndpointKind::Stream {
            return Ok(None);
        }
        let mut inner = self.shared.inner.lock().unwrap();
        if inner.selected_close.is_some() {
            return Err(Errno::ENETDOWN);
        }
        inner.room(self.shared.config)?;
        if !inner.capabilities.selected_endpoints || !inner.capabilities.tcp {
            return Err(Errno::EOPNOTSUPP);
        }
        super::backend::family_allowed(inner.capabilities, request.requested)?;
        if matches!(request.purpose, EndpointBindPurpose::Listen { .. })
            && !inner.capabilities.listen
        {
            return Err(Errno::EOPNOTSUPP);
        }
        let id = inner.id()?;
        let resource = Resource::new(
            Some(request),
            Operation::Bind,
            queue.clone(),
            inner.generation,
        );
        let flow = Flow::selected_stream(request.requested, queue, resource.clone());
        inner.flows.insert(id, flow);
        drop(inner);
        self.shared.wake.wake();
        Ok(Some(Arc::new(Bound {
            shared: self.shared.clone(),
            id,
            resource,
            identity: Arc::downgrade(&self.identity),
        })))
    }
    fn select(&self, query: &EndpointQuery) -> Result<EndpointChoice, Errno> {
        let (generation, external) = {
            let inner = self.shared.inner.lock().unwrap();
            if !inner.online || inner.selected_close.is_some() {
                return Err(Errno::ENETDOWN);
            }
            (inner.generation, inner.capabilities.selected_external)
        };
        if query.kind != EndpointKind::Stream {
            return Ok(EndpointChoice::Namespace);
        }
        if let Some(binding) = &query.binding {
            let bound = self.bound(binding)?;
            if bound.resource.generation != generation {
                return Err(Errno::ECANCELED);
            }
            if bound
                .resource
                .request
                .is_none_or(|request| request.source_id != query.source_id)
            {
                return Err(Errno::ECANCELED);
            }
        } else if query.requested_bind.is_some() {
            // The namespace-reserved JS Node profile never supported bound
            // connect, including loopback. Do not turn it into unbound connect.
            return Err(Errno::EOPNOTSUPP);
        } else if !query.destination.ip().is_loopback() && !external {
            // Unbound WISP/ordinary uplink stays on its existing Backend::connect path.
            return Ok(EndpointChoice::Namespace);
        }
        Ok(EndpointChoice::Provider(EndpointTarget::new(Target {
            shared: Arc::downgrade(&self.shared),
            identity: Arc::downgrade(&self.identity),
            generation,
            source: query.source_id,
            binding: query.binding.clone(),
            peer: query.destination,
        })))
    }
    fn connect(
        &self,
        target: EndpointTarget,
        source: EndpointSourceId,
        local: SocketAddr,
        peer: SocketAddr,
        queue: WaitQueue,
    ) -> Result<Arc<dyn BackendStream>, Errno> {
        let target = target.downcast_ref::<Target>().ok_or(Errno::EINVAL)?;
        if target.source != source
            || !Weak::ptr_eq(&target.shared, &Arc::downgrade(&self.shared))
            || !Weak::ptr_eq(&target.identity, &Arc::downgrade(&self.identity))
            || target.peer.port() != peer.port()
            || target.peer.ip().to_canonical() != peer.ip().to_canonical()
        {
            return Err(Errno::ECANCELED);
        }
        let mut inner = self.shared.inner.lock().unwrap();
        if !inner.online || inner.selected_close.is_some() || inner.generation != target.generation
        {
            return Err(Errno::ENETDOWN);
        }
        super::backend::family_allowed(inner.capabilities, peer)?;
        let id = if let Some(binding) = &target.binding {
            let bound = self.bound(binding)?;
            if bound.resource.generation != inner.generation {
                return Err(Errno::ECANCELED);
            }
            let flow = inner.flows.get_mut(&bound.id).ok_or(Errno::ECANCELED)?;
            let mut state = bound.resource.state.lock().unwrap();
            if state.phase != Phase::Bound || state.transferred || flow.released {
                return Err(Errno::EINVAL);
            }
            state.transferred = true;
            state.connect_local = Some(local);
            state.phase = Phase::Queued(Operation::Connect);
            flow.peer = peer;
            flow.wq = queue;
            bound.id
        } else {
            inner.room(self.shared.config)?;
            if !inner.capabilities.selected_endpoints || !inner.capabilities.tcp {
                return Err(Errno::EOPNOTSUPP);
            }
            let id = inner.id()?;
            let resource = Resource::new(None, Operation::Connect, queue.clone(), inner.generation);
            resource.state.lock().unwrap().connect_local = Some(local);
            let flow = Flow::selected_stream(peer, queue, resource);
            inner.flows.insert(id, flow);
            id
        };
        drop(inner);
        self.shared.wake.wake();
        Ok(Arc::new(Stream {
            shared: self.shared.clone(),
            id,
            peer,
        }))
    }
    fn publish_tcp(
        &self,
        spec: EndpointGroupSpec,
        backlog: u32,
        ingress: Arc<dyn EndpointStreamIngress>,
        reporter: PublicationReporter,
    ) -> Result<Arc<dyn EndpointLease>, Errno> {
        let generation = {
            let inner = self.shared.inner.lock().unwrap();
            if !inner.online || inner.selected_close.is_some() {
                return Err(Errno::ENETDOWN);
            }
            if !inner.capabilities.selected_endpoints || !inner.capabilities.listen {
                return Err(Errno::EOPNOTSUPP);
            }
            inner.generation
        };
        // Validate every member before accepting any registration work.
        for member in spec.members.iter() {
            if let Some(binding) = &member.binding {
                let bound = self.bound(binding)?;
                if bound
                    .resource
                    .request
                    .is_none_or(|request| request.source_id != member.source_id)
                {
                    return Err(Errno::ECANCELED);
                }
            } else if self.shared.inner.lock().unwrap().capabilities.selected_bind {
                return Err(Errno::EOPNOTSUPP);
            }
        }
        let publication = Arc::new(SelectedPublication {
            shared: self.shared.clone(),
            ingress,
            reporter,
            domain: spec.domain,
            v6only: spec.v6only,
            identity: Arc::downgrade(&self.identity),
            generation,
            config: Mutex::new(PublicationConfig {
                revision: spec.revision,
                backlog_revision: spec.revision,
                backlog,
                members: spec.members.clone(),
                closed: false,
            }),
        });
        {
            let inner = self.shared.inner.lock().unwrap();
            publication.validate(&inner, &spec.members)?;
        }
        publication.refresh();
        Ok(Arc::new(Lease { publication }))
    }
}

struct PublicationConfig {
    revision: u64,
    backlog_revision: u64,
    backlog: u32,
    members: Arc<[EndpointMember]>,
    closed: bool,
}
struct SelectedPublication {
    shared: Arc<Shared>,
    ingress: Arc<dyn EndpointStreamIngress>,
    reporter: PublicationReporter,
    domain: Domain,
    v6only: bool,
    identity: Weak<()>,
    generation: u64,
    config: Mutex<PublicationConfig>,
}
impl SelectedPublication {
    fn matches_member(
        member: &EndpointMember,
        source: EndpointSourceId,
        resource: &Arc<Resource>,
    ) -> bool {
        member.source_id == source
            && match &member.binding {
                Some(binding) => (binding.as_ref() as &dyn Any)
                    .downcast_ref::<Bound>()
                    .is_some_and(|bound| Arc::ptr_eq(&bound.resource, resource)),
                None => resource
                    .reserved
                    .as_ref()
                    .is_some_and(|(reserved, _, _)| reserved.source_id == source),
            }
    }
    fn validate(
        &self,
        inner: &crate::backend::Inner,
        members: &[EndpointMember],
    ) -> Result<(), Errno> {
        if !inner.online || inner.selected_close.is_some() || inner.generation != self.generation {
            return Err(Errno::ENETDOWN);
        }
        for member in members {
            if let Some(binding) = &member.binding {
                let bound = (binding.as_ref() as &dyn Any)
                    .downcast_ref::<Bound>()
                    .ok_or(Errno::EINVAL)?;
                if !Arc::ptr_eq(&bound.shared, &self.shared)
                    || !Weak::ptr_eq(&bound.identity, &self.identity)
                    || bound
                        .resource
                        .request
                        .is_none_or(|request| request.source_id != member.source_id)
                {
                    return Err(Errno::ECANCELED);
                }
                let current = inner
                    .flows
                    .get(&bound.id)
                    .and_then(|flow| flow.selected.as_ref())
                    .or_else(|| {
                        inner
                            .listeners
                            .get(&bound.id)
                            .and_then(|listener| listener.selected.as_ref())
                    });
                if !current.is_some_and(|current| Arc::ptr_eq(current, &bound.resource)) {
                    return Err(Errno::ECANCELED);
                }
                if bound.resource.state.lock().unwrap().closing {
                    return Err(Errno::ECANCELED);
                }
            } else if inner.capabilities.selected_bind {
                return Err(Errno::EINVAL);
            }
        }
        Ok(())
    }
    fn live(&self, source: EndpointSourceId, resource: &Arc<Resource>) -> bool {
        let config = self.config.lock().unwrap();
        !config.closed
            && config
                .members
                .iter()
                .any(|member| Self::matches_member(member, source, resource))
    }
    fn refresh(self: &Arc<Self>) {
        // Order is publication metadata -> backend -> resource. No foreign call
        // or destructor occurs under these locks. Hold the revision through
        // installation so an older refresh cannot recreate a removed member.
        let mut config = self.config.lock().unwrap();
        if config.closed {
            return;
        }
        let (members, backlog) = (config.members.clone(), config.backlog);
        let mut reports = Vec::new();
        let mut inner = self.shared.inner.lock().unwrap();
        if let Err(error) = self.validate(&inner, &members) {
            config.closed = true;
            for listener in inner.listeners.values_mut() {
                if listener
                    .endpoint
                    .as_ref()
                    .is_some_and(|sink| sink.belongs(self))
                {
                    listener.released = true;
                }
            }
            drop(inner);
            drop(config);
            self.reporter.failed(error);
            self.shared.wake.wake();
            return;
        }
        for member in members.iter() {
            let Some(bound) = member
                .binding
                .as_ref()
                .and_then(|binding| (binding.as_ref() as &dyn Any).downcast_ref::<Bound>())
            else {
                if member.binding.is_some() {
                    continue;
                }
                let existing = inner.listeners.iter().find_map(|(&id, listener)| {
                    listener
                        .endpoint
                        .as_ref()
                        .filter(|sink| sink.belongs(self) && sink.source == member.source_id)
                        .map(|_| id)
                });
                if let Some(id) = existing {
                    inner.listeners.get_mut(&id).unwrap().backlog = backlog;
                    continue;
                }
                let result = inner.room(self.shared.config).and_then(|()| inner.id());
                let id = match result {
                    Ok(id) => id,
                    Err(error) => {
                        reports.push((member.source_id, Err(error)));
                        continue;
                    }
                };
                let resource =
                    Resource::reserved(member.clone(), self.domain, self.v6only, inner.generation);
                let sink = Arc::new(MemberSink {
                    publication: Arc::downgrade(self),
                    resource: resource.clone(),
                    source: member.source_id,
                });
                inner.listeners.insert(
                    id,
                    Listener {
                        addr: member.local,
                        sink: sink.clone(),
                        opening: false,
                        ready: false,
                        released: false,
                        child: None,
                        binding: None,
                        selected: Some(resource),
                        endpoint: Some(sink),
                        backlog,
                    },
                );
                continue;
            };
            let resource = bound.resource.clone();
            let mut state = resource.state.lock().unwrap();
            if let Some(error) = state.error {
                reports.push((member.source_id, Err(error)));
                continue;
            }
            if matches!(state.phase, Phase::Bound | Phase::Listening) && !state.transferred {
                state.transferred = true;
                if state.phase == Phase::Bound {
                    state.phase = Phase::Queued(Operation::Listen);
                }
                if let Some(flow) = inner.flows.remove(&bound.id) {
                    let ready = state.phase == Phase::Listening;
                    let addr = state.actual.unwrap_or(member.local);
                    let sink = Arc::new(MemberSink {
                        publication: Arc::downgrade(self),
                        resource: resource.clone(),
                        source: member.source_id,
                    });
                    inner.listeners.insert(
                        bound.id,
                        Listener {
                            addr,
                            sink: sink.clone(),
                            opening: false,
                            ready,
                            released: flow.released,
                            child: None,
                            binding: None,
                            selected: Some(resource.clone()),
                            endpoint: Some(sink),
                            backlog,
                        },
                    );
                    if ready {
                        reports.push((member.source_id, Ok(())));
                    }
                }
            }
            // Backlog enforcement belongs to the canonical member queue. The provider
            // receives this value for an explicit bound-to-listen transition only.
            if let Some(listener) = inner.listeners.get_mut(&bound.id) {
                listener.backlog = backlog;
            }
        }
        drop(inner);
        drop(config);
        for (source, result) in reports {
            match result {
                Ok(()) => self.reporter.ready_member(source),
                Err(error) => self.reporter.failed_member(source, error),
            }
        }
        self.shared.wake.wake();
    }
}
impl Pollable for SelectedPublication {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.reporter.poll(table)
    }
}
struct Lease {
    publication: Arc<SelectedPublication>,
}
impl Pollable for Lease {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.publication.poll(table)
    }
}
impl EndpointLease for Lease {
    fn reporter(&self) -> &PublicationReporter {
        &self.publication.reporter
    }
    fn set_backlog(&self, revision: u64, backlog: u32) {
        let this = &self.publication;
        {
            let mut config = this.config.lock().unwrap();
            if revision <= config.backlog_revision || config.closed {
                return;
            }
            config.backlog_revision = revision;
            config.backlog = backlog;
        }
        this.refresh();
    }
    fn update_members(&self, revision: u64, members: Arc<[EndpointMember]>) {
        let this = &self.publication;
        let mut config = this.config.lock().unwrap();
        if revision <= config.revision || config.closed {
            return;
        }
        let mut inner = this.shared.inner.lock().unwrap();
        if let Err(error) = this.validate(&inner, &members) {
            config.closed = true;
            for listener in inner.listeners.values_mut() {
                if listener
                    .endpoint
                    .as_ref()
                    .is_some_and(|sink| sink.belongs(this))
                {
                    listener.released = true;
                }
            }
            drop(inner);
            drop(config);
            this.reporter.failed(error);
            this.shared.wake.wake();
            return;
        }
        config.revision = revision;
        let previous = std::mem::replace(&mut config.members, members);
        // Retire only listeners removed from this exact registration.
        {
            for listener in inner.listeners.values_mut() {
                if listener.endpoint.as_ref().is_some_and(|sink| {
                    sink.belongs(this)
                        && !config.members.iter().any(|member| {
                            SelectedPublication::matches_member(member, sink.source, &sink.resource)
                        })
                }) {
                    listener.released = true;
                }
            }
        }
        drop(inner);
        drop(config);
        drop(previous);
        this.refresh();
    }
}
impl Drop for SelectedPublication {
    fn drop(&mut self) {
        self.config.lock().unwrap().closed = true;
        {
            let mut inner = self.shared.inner.lock().unwrap();
            for listener in inner.listeners.values_mut() {
                if listener
                    .endpoint
                    .as_ref()
                    .is_some_and(|sink| sink.belongs(self))
                {
                    listener.released = true;
                }
            }
        }
        self.shared.wake.wake();
    }
}

pub(crate) struct MemberSink {
    publication: Weak<SelectedPublication>,
    resource: Arc<Resource>,
    source: EndpointSourceId,
}
impl MemberSink {
    fn belongs(&self, publication: &SelectedPublication) -> bool {
        std::ptr::eq(self.publication.as_ptr(), publication)
    }
    pub fn report(&self, result: Result<(), Errno>) {
        if let Some(publication) = self.publication.upgrade() {
            if !publication.live(self.source, &self.resource) {
                return;
            }
            match result {
                Ok(()) => publication.reporter.ready_member(self.source),
                Err(error) => publication.reporter.failed_member(self.source, error),
            }
        }
    }
    pub fn room_to(
        &self,
        peer: SocketAddr,
        local: SocketAddr,
        table: Option<&mut PollTable<'_>>,
    ) -> Room {
        let Some(publication) = self.publication.upgrade() else {
            return Room::Gone;
        };
        if !publication.live(self.source, &self.resource) {
            return Room::Gone;
        }
        publication
            .ingress
            .poll_room_member_to(self.source, peer, local, table)
    }
    pub fn incoming_to(
        &self,
        peer: SocketAddr,
        local: SocketAddr,
        stream: Arc<dyn BackendStream>,
        queue: WaitQueue,
    ) -> bool {
        let Some(publication) = self.publication.upgrade() else {
            return false;
        };
        publication.live(self.source, &self.resource)
            && publication
                .ingress
                .incoming_member_to(self.source, peer, local, stream, queue)
    }
}
impl InboundSink for MemberSink {
    fn poll_room(&self, table: Option<&mut PollTable<'_>>) -> Room {
        let Some(publication) = self.publication.upgrade() else {
            return Room::Gone;
        };
        if !publication.live(self.source, &self.resource) {
            return Room::Gone;
        }
        // This checks the canonical accepted+ready gate only. Real backlog room
        // is checked after accept, with actual peer and local addresses.
        publication.reporter.poll(table);
        match publication.reporter.state() {
            PublicationState::Pending => Room::Full,
            PublicationState::Ready => Room::Ready,
            PublicationState::Failed(_) => Room::Gone,
        }
    }
    fn incoming(&self, _stream: Arc<dyn BackendStream>, _queue: WaitQueue) -> bool {
        // Selected ingress always uses incoming_to with the actual destination.
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Capabilities, Command, Config, Driver, Event, Transport};
    use std::{
        collections::VecDeque,
        future::Future,
        task::{Context, Poll},
    };
    use wasixv2_vnet::{Net, NetConfig, Network, Socket, SocketKind};

    struct Io {
        caps: Capabilities,
        sent: Vec<Command>,
        events: VecDeque<Event>,
    }
    impl Transport for Io {
        fn capabilities(&self) -> Capabilities {
            self.caps
        }
        fn poll_send(&mut self, _: &mut Context<'_>, command: &Command) -> Poll<Result<(), Errno>> {
            self.sent.push(command.clone());
            Poll::Ready(Ok(()))
        }
        fn poll_recv(&mut self, _: &mut Context<'_>) -> Poll<Result<Event, Errno>> {
            self.events
                .pop_front()
                .map_or(Poll::Pending, |event| Poll::Ready(Ok(event)))
        }
        fn poll_closed(&mut self, _: &mut Context<'_>) -> Poll<Errno> {
            Poll::Pending
        }
        fn close(&mut self) {}
    }
    struct Setup {
        backend: Arc<WebBackend>,
        driver: Driver,
        io: Io,
        _socket: Arc<dyn Socket>,
        publication: Arc<SelectedPublication>,
    }
    impl Setup {
        fn pump(&mut self) {
            assert!(
                self.driver
                    .poll(
                        &mut Context::from_waker(futures_util::task::noop_waker_ref()),
                        &mut self.io
                    )
                    .is_pending()
            );
        }
    }
    fn setup(physical: bool) -> Setup {
        let caps = Capabilities {
            selected_endpoints: true,
            selected_bind: physical,
            ..Capabilities::classic(true)
        };
        let (backend, mut driver) = WebBackend::new(Config::default(), caps).unwrap();
        let mut io = Io {
            caps,
            sent: Vec::new(),
            events: VecDeque::new(),
        };
        let net = Net::new(
            NetConfig::host_default(),
            Some(backend.clone().with_namespace_endpoints()),
        );
        let socket = net.socket(Domain::Inet, SocketKind::Stream, 0, 1).unwrap();
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        if let Some(admission) = socket
            .bind_admission("127.0.0.1:0".parse().unwrap(), false)
            .unwrap()
        {
            assert!(driver.poll(&mut cx, &mut io).is_pending());
            let (request, socket) = match io.sent[0] {
                Command::BindStream {
                    request, socket, ..
                } => (request, socket),
                _ => unreachable!(),
            };
            io.events.push_back(Event::StreamBound {
                request,
                socket,
                result: Ok("127.0.0.1:42100".parse().unwrap()),
            });
            assert!(driver.poll(&mut cx, &mut io).is_pending());
            admission.complete().unwrap();
        } else {
            socket.bind("127.0.0.1:0".parse().unwrap(), false).unwrap();
        }
        socket.listen(1).unwrap();
        let publication = {
            let inner = backend.shared.inner.lock().unwrap();
            inner
                .listeners
                .values()
                .find_map(|listener| {
                    listener
                        .endpoint
                        .as_ref()
                        .and_then(|sink| sink.publication.upgrade())
                })
                .unwrap()
        };
        Setup {
            backend,
            driver,
            io,
            _socket: socket,
            publication,
        }
    }

    #[test]
    fn member_refresh_after_owner_close_cannot_admit_a_new_physical_listener() {
        let setup = setup(false);
        let (revision, original) = {
            let config = setup.publication.config.lock().unwrap();
            (config.revision, config.members[0].clone())
        };
        let mut replacement = original.clone();
        replacement.source_id = EndpointSourceId(original.source_id.0 + 1);
        replacement.local.set_port(original.local.port() + 1);
        let mut closing = Box::pin(setup.backend.close_endpoints());
        assert!(
            closing
                .as_mut()
                .poll(&mut Context::from_waker(
                    futures_util::task::noop_waker_ref()
                ))
                .is_pending()
        );
        let lease = Lease {
            publication: setup.publication.clone(),
        };
        lease.update_members(revision + 1, Arc::from([replacement]));
        {
            let inner = setup.backend.shared.inner.lock().unwrap();
            assert_eq!(inner.listeners.len(), 1);
            assert_eq!(inner.selected_close.as_ref().unwrap().len(), 1);
        }
        assert_eq!(
            setup.publication.config.lock().unwrap().members[0].source_id,
            original.source_id
        );
    }

    #[test]
    fn replacement_from_another_namespace_cannot_steal_its_same_backend_flow() {
        let mut setup = setup(true);
        let (revision, original) = {
            let config = setup.publication.config.lock().unwrap();
            (config.revision, config.members[0].clone())
        };
        let foreign = setup
            .backend
            .clone()
            .with_namespace_endpoints()
            .endpoint_namespace()
            .unwrap();
        let bound = foreign
            .bind(
                EndpointBindRequest {
                    source_id: original.source_id,
                    kind: EndpointKind::Stream,
                    requested: "127.0.0.1:0".parse().unwrap(),
                    explicit: true,
                    purpose: EndpointBindPurpose::Bind,
                    domain: Domain::Inet,
                    v6only: false,
                    reuse_addr: false,
                    reuse_port: false,
                },
                WaitQueue::new(),
            )
            .unwrap()
            .unwrap();
        let foreign_id = (bound.as_ref() as &dyn Any)
            .downcast_ref::<Bound>()
            .unwrap()
            .id;
        let mut replacement = original.clone();
        replacement.binding = Some(bound.clone());
        Lease {
            publication: setup.publication.clone(),
        }
        .update_members(revision + 1, Arc::from([replacement]));
        {
            let inner = setup.backend.shared.inner.lock().unwrap();
            assert!(inner.flows.contains_key(&foreign_id));
        }
        assert!(Arc::ptr_eq(
            setup.publication.config.lock().unwrap().members[0]
                .binding
                .as_ref()
                .unwrap(),
            original.binding.as_ref().unwrap()
        ));
        setup.pump();
        let request = setup
            .io
            .sent
            .iter()
            .find_map(|command| match command {
                Command::BindStream {
                    request, socket, ..
                } if *socket == foreign_id => Some(*request),
                _ => None,
            })
            .unwrap();
        setup.io.events.push_back(Event::StreamBound {
            request,
            socket: foreign_id,
            result: Ok("127.0.0.1:42101".parse().unwrap()),
        });
        setup.pump();
        assert_eq!(bound.local_addr(), Ok("127.0.0.1:42101".parse().unwrap()));
    }
}
