use crate::{
    backend::{Flow, Kind, Listener, Packet, Shared, Stream, unbound},
    endpoints::{MemberSink, Operation, Phase, Resource},
    transport::{Command, Event, Transport},
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
    task::{Context, Poll},
};
use wasixv2_abi::Errno;
use wasixv2_vnet::{Answer, Lookup, LookupError, Room, Shutdown, StreamState};
use wasixv2_wait::{PollMask, PollTable, WaitEntry, WaitQueue, WaitRegistration};

enum Pending {
    Selected(u64, Operation),
    SelectedAddress(u64, Operation),
    AcceptedAddress(u64, u64, std::net::SocketAddr),
    SelectedAccept {
        listener: u64,
        child: u64,
        resource: Arc<Resource>,
        local: std::net::SocketAddr,
        generation: u64,
        withdrawn: bool,
    },
    Open(u64),
    Address(u64, bool),
    Listen(u64),
    Send(u64, usize),
    Shutdown(u64),
}
struct SelectedAccepted {
    listener: u64,
    stream: Arc<Stream>,
    sink: Arc<MemberSink>,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    queue: WaitQueue,
}
struct DriverWake(Arc<Shared>);
impl WaitEntry for DriverWake {
    fn wake(&self, _: PollMask) -> bool {
        self.0.wake.wake();
        true
    }
}

/// One session's event pump. It contains no JS references and may be moved to the I/O worker
/// before polling. The transport itself stays local to that worker. Dropping this driver
/// cancels every pending operation of this session and wakes all affected socket waiters.
pub struct Driver {
    pub(crate) shared: Arc<Shared>,
    generation: u64,
    pending: BTreeMap<u64, Pending>,
    command: Option<Command>,
    registrations: Vec<WaitRegistration>,
    cleanup: VecDeque<Command>,
    retired: Vec<Listener>,
    cursor: u64,
    stopped: bool,
    input: Option<(u64, Vec<u8>, usize, bool)>,
    selected_wakes: Vec<Arc<Resource>>,
    accepted: BTreeMap<u64, SelectedAccepted>,
}
impl Driver {
    pub(crate) fn new(shared: Arc<Shared>, generation: u64) -> Self {
        Self {
            shared,
            generation,
            pending: BTreeMap::new(),
            command: None,
            registrations: Vec::new(),
            cleanup: VecDeque::new(),
            retired: Vec::new(),
            cursor: 0,
            stopped: false,
            input: None,
            selected_wakes: Vec::new(),
            accepted: BTreeMap::new(),
        }
    }

    /// Owns the worker-local transport so cancellation also closes its JS resources.
    pub async fn run(mut self, transport: impl Transport) -> Result<(), Errno> {
        struct Close<T: Transport>(T);
        impl<T: Transport> Drop for Close<T> {
            fn drop(&mut self) {
                self.0.close();
            }
        }
        let mut transport = Close(transport);
        futures_util::future::poll_fn(|cx| self.poll(cx, &mut transport.0)).await
    }

    /// Runs until transport failure. There is no automatic reconnection or retransmission
    /// across sessions. Bounded work per poll yields to the worker's event loop.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        transport: &mut dyn Transport,
    ) -> Poll<Result<(), Errno>> {
        if self.stopped {
            return Poll::Ready(Ok(()));
        }
        self.shared.wake.register(cx.waker());
        if self.shared.inner.lock().unwrap().capabilities != transport.capabilities() {
            return self.stop(transport, Errno::EINVAL);
        }
        for _ in 0..64 {
            let mut progress = false;
            let cutoffs = self.selected_cutoffs();
            if !cutoffs.is_empty() {
                // A held ordinary command was not accepted by poll_send. Move
                // it, with the same identity/flags/bytes, into the existing
                // cleanup queue so selected closes can reach reserved capacity.
                if self.command.as_ref().is_some_and(|command| {
                    !matches!(
                        command,
                        Command::CloseSelected { .. }
                            | Command::Close { .. }
                            | Command::Reset { .. }
                    )
                }) {
                    self.cleanup.push_front(self.command.take().unwrap());
                }
                for socket in cutoffs {
                    transport.revoke_open(socket);
                }
            }
            if let Poll::Ready(error) = transport.poll_closed(cx) {
                return self.stop(transport, error);
            }
            if self.input.is_some() {
                match transport.poll_recv_close(cx) {
                    Poll::Ready(Ok(
                        event @ (Event::ProviderCloseAck { .. }
                        | Event::LocalCloseUnconfirmed { .. }),
                    )) => {
                        if let Err(error) = self.event(event) {
                            return self.stop(transport, error);
                        }
                        progress = true;
                    }
                    Poll::Ready(Ok(_)) => return self.stop(transport, Errno::EPROTO),
                    Poll::Ready(Err(error)) => return self.stop(transport, error),
                    Poll::Pending => {}
                }
            }
            if self.input.is_none() {
                match transport.poll_recv(cx) {
                    Poll::Ready(Ok(event)) => {
                        if let Event::Data { socket, data } = event {
                            if data.len() > crate::codec::MAX_FRAME {
                                return self.stop(transport, Errno::EMSGSIZE);
                            }
                            self.input = Some((socket, data, 0, false));
                        } else if let Event::Urgent { socket, data } = event {
                            if data.is_empty() || data.len() > crate::codec::MAX_FRAME {
                                return self.stop(transport, Errno::EPROTO);
                            }
                            self.input = Some((socket, data, 0, true));
                        } else if let Err(error) = self.event(event) {
                            return self.stop(transport, error);
                        }
                        progress = true;
                    }
                    Poll::Ready(Err(error)) => return self.stop(transport, error),
                    Poll::Pending => {}
                }
            }
            match self.copy_input() {
                Ok(copied) => progress |= copied,
                Err(error) => return self.stop(transport, error),
            }
            if self.stopped {
                transport.close();
                return Poll::Ready(Ok(()));
            }
            if self.command.is_none() {
                match self.next(cx) {
                    Ok(command) => self.command = command,
                    Err(error) => return self.stop(transport, error),
                }
            }
            for resource in self.selected_wakes.drain(..) {
                resource
                    .queue
                    .wake(PollMask::READABLE | PollMask::WRITABLE | PollMask::ERR | PollMask::HUP);
            }
            // Trait-object destructors may reenter the backend, just like sink callbacks.
            self.retired.clear();
            if !self.command_valid() {
                self.discard_command();
                progress = true;
            }
            if let Some(command) = &self.command {
                match transport.poll_send(cx, command) {
                    Poll::Ready(Ok(())) => {
                        let command = self.command.take().unwrap();
                        self.sent(command);
                        progress = true;
                    }
                    Poll::Ready(Err(error)) => return self.stop(transport, error),
                    Poll::Pending => {}
                }
            }
            if !progress {
                return Poll::Pending;
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn stop(&mut self, transport: &mut dyn Transport, error: Errno) -> Poll<Result<(), Errno>> {
        transport.close();
        // Transport failure does not prove a peer RST. Linux net/ipv4/tcp.c:tcp_done's
        // asynchronous error path is represented by ECONNABORTED for lost infrastructure.
        self.disconnect(error);
        Poll::Ready(Err(error))
    }

    fn next(&mut self, cx: &mut Context<'_>) -> Result<Option<Command>, Errno> {
        self.registrations.clear();
        self.deliver_selected();
        {
            let shared = self.shared.clone();
            let mut inner = shared.inner.lock().unwrap();
            if let Some(command) = self.next_selected(&mut inner, true)? {
                return Ok(Some(command));
            }
        }
        if let Some(command) = self.cleanup.pop_front() {
            return Ok(Some(command));
        }
        let listeners: Vec<_> = {
            let inner = self.shared.inner.lock().unwrap();
            inner
                .listeners
                .iter()
                .filter(|(_, l)| l.ready && !l.released && l.child.is_none())
                .map(|(&id, l)| (id, l.sink.clone()))
                .collect()
        };
        let entry: Arc<dyn WaitEntry> = Arc::new(DriverWake(self.shared.clone()));
        let mut accepting = BTreeSet::new();
        for (id, sink) in listeners {
            let mut register = |q: &WaitQueue, _| self.registrations.push(q.add(entry.clone()));
            let room = sink.poll_room(Some(&mut PollTable::new(PollMask::empty(), &mut register)));
            // Like vnet-host's listener, accept and reset when no guest listener exists;
            // only a full accept queue leaves the connection in the relay backlog.
            let selected = self
                .shared
                .inner
                .lock()
                .unwrap()
                .listeners
                .get(&id)
                .is_some_and(|listener| listener.selected.is_some());
            if room == Room::Ready || (!selected && room != Room::Full) {
                accepting.insert(id);
            }
        }
        // Registration precedes checking the predicate. A room/guest-I/O wake before this
        // point is retained by AtomicWaker; no kernel/backend lock spans a transport call.
        self.shared.wake.register(cx.waker());
        let shared = self.shared.clone();
        let mut inner = shared.inner.lock().unwrap();
        if let Some(command) = self.next_selected(&mut inner, false)? {
            return Ok(Some(command));
        }
        if let Some(control) = inner.controls.front_mut()
            && !control.sent
        {
            control.sent = true;
            return Ok(Some(Command::Provider {
                request: control.id,
                operation: control.command.clone(),
            }));
        }
        if let Some((&request, query)) = inner.lookups.iter_mut().find(|(_, q)| !q.sent) {
            query.sent = true;
            return Ok(Some(Command::Lookup {
                request,
                lookup: query.lookup.clone(),
            }));
        }
        let listener_ids: Vec<_> = inner.listeners.keys().copied().collect();
        for id in listener_ids {
            let listener = &inner.listeners[&id];
            if listener.released {
                if listener.selected.is_some() {
                    continue;
                }
                if listener.opening {
                    continue;
                }
                let listener = inner.listeners.remove(&id).unwrap();
                if let Some(child) = listener.child
                    && let Some(flow) = inner.flows.get_mut(&child)
                {
                    flow.released = true;
                    flow.reset = true;
                    // This child was reserved, not yet delivered to a guest.
                    flow.state = StreamState::Closed;
                    flow.opening = false;
                }
                self.retired.push(listener);
                return Ok(Some(Command::Close { socket: id }));
            }
            if !listener.opening && !listener.ready {
                if listener.selected.is_some() {
                    continue;
                }
                let addr = listener.addr;
                let request = inner.id()?;
                inner.listeners.get_mut(&id).unwrap().opening = true;
                self.pending.insert(request, Pending::Listen(id));
                return Ok(Some(Command::Listen {
                    request,
                    socket: id,
                    addr,
                }));
            }
            if accepting.contains(&id)
                && listener.child.is_none()
                && inner.flows.len() + inner.listeners.len() < self.shared.config.max_sockets
            {
                let selected_listener = listener.selected.is_some();
                let child = inner.id()?;
                let mut flow = Flow::new(
                    Kind::Stream,
                    unbound(wasixv2_vnet::Domain::Inet),
                    WaitQueue::new(),
                );
                flow.opening = true;
                flow.remote = !selected_listener;
                if selected_listener {
                    let selected =
                        Resource::new(None, Operation::Connect, flow.wq.clone(), inner.generation);
                    selected.state.lock().unwrap().phase = Phase::Pending(Operation::Connect);
                    flow.selected = Some(selected);
                }
                inner.flows.insert(child, flow);
                let listener = inner.listeners.get_mut(&id).unwrap();
                listener.child = Some(child);
                return Ok(Some(Command::Accept { socket: id, child }));
            }
        }
        // Round-robin selection keeps one busy stream from starving other endpoints.
        let ids: Vec<_> = inner
            .flows
            .range((
                std::ops::Bound::Excluded(self.cursor),
                std::ops::Bound::Unbounded,
            ))
            .chain(inner.flows.range(..=self.cursor))
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            let request = inner.id()?;
            let flow = inner.flows.get_mut(&id).unwrap();
            let command = if (flow.released || flow.reset) && flow.selected.is_none() {
                if flow.reset {
                    if let Some((request, _)) = flow.inflight.take() {
                        self.pending.remove(&request);
                    }
                    flow.tx.clear();
                }
                if flow.opening || flow.inflight.is_some() {
                    continue;
                }
                if flow.reset && !flow.reset_sent && flow.remote {
                    flow.reset_sent = true;
                    Some(Command::Reset { socket: id })
                } else if flow.reset || (flow.tx.is_empty() && flow.outgoing.is_empty()) {
                    if !flow.remote {
                        if flow.released {
                            inner.flows.remove(&id);
                        }
                        continue;
                    }
                    // No wrapper still references a released endpoint. Reset endpoints with
                    // a live wrapper stay queryable after their remote socket is closed.
                    flow.remote = false;
                    let released = flow.released;
                    if released {
                        inner.flows.remove(&id);
                    }
                    Some(Command::Close { socket: id })
                } else {
                    None
                }
            } else {
                None
            };
            if command.is_some() {
                self.cursor = id;
                return Ok(command);
            }
            let Some(flow) = inner.flows.get_mut(&id) else {
                continue;
            };
            if flow.reset || flow.state == StreamState::Closed {
                continue;
            }
            if flow
                .selected
                .as_ref()
                .is_some_and(|resource| resource.state.lock().unwrap().phase != Phase::Connected)
            {
                continue;
            }
            if flow.state == StreamState::Connecting && !flow.opening && !flow.released {
                flow.opening = true;
                flow.remote = true;
                self.pending.insert(request, Pending::Open(id));
                self.cursor = id;
                return Ok(Some(match flow.kind {
                    Kind::Stream => Command::Connect {
                        request,
                        socket: id,
                        peer: flow.peer,
                    },
                    Kind::Datagram(_) => Command::Bind {
                        request,
                        socket: id,
                        addr: flow.peer,
                    },
                }));
            }
            if flow.state != StreamState::Established {
                continue;
            }
            if flow.kind != Kind::Stream {
                if let Some(packet) = flow.outgoing.front() {
                    self.cursor = id;
                    return Ok(Some(Command::SendTo {
                        socket: id,
                        data: packet.data.clone(),
                        addr: packet.addr,
                    }));
                }
                continue;
            }
            if flow.inflight.is_some() || flow.send_blocked {
                continue;
            }
            if !flow.tx.is_empty() {
                let mut size = flow.tx.len().min(self.shared.config.chunk_bytes);
                let urgent = flow
                    .tx_urgent
                    .front()
                    .is_some_and(|mark| *mark == flow.tx_head);
                if let Some(mark) = flow.tx_urgent.front() {
                    size = size.min(if urgent {
                        1
                    } else {
                        (*mark - flow.tx_head) as usize
                    });
                }
                let data = flow.tx.iter().take(size).copied().collect();
                flow.inflight = Some((request, size));
                self.pending.insert(request, Pending::Send(id, size));
                self.cursor = id;
                return Ok(Some(if urgent {
                    Command::SendUrgent {
                        request,
                        socket: id,
                        data,
                    }
                } else {
                    Command::Send {
                        request,
                        socket: id,
                        data,
                    }
                }));
            }
            let read = flow.read_shut && !flow.sent_read_shut;
            let write = flow.write_shut && !flow.sent_write_shut;
            if read || write {
                flow.sent_read_shut |= read;
                flow.sent_write_shut |= write;
                flow.inflight = Some((request, 0));
                self.pending.insert(request, Pending::Shutdown(id));
                self.cursor = id;
                return Ok(Some(Command::Shutdown {
                    request,
                    socket: id,
                    how: match (read, write) {
                        (true, true) => Shutdown::Both,
                        (true, false) => Shutdown::Read,
                        _ => Shutdown::Write,
                    },
                }));
            }
        }
        Ok(None)
    }

    fn copy_input(&mut self) -> Result<bool, Errno> {
        let Some((socket, data, offset, urgent)) = &mut self.input else {
            return Ok(false);
        };
        let mut inner = self.shared.inner.lock().unwrap();
        let Some(flow) = inner.flows.get_mut(socket) else {
            self.input = None;
            return Ok(true);
        };
        if flow.kind != Kind::Stream {
            return Err(Errno::EPROTO);
        }
        let closing = flow.selected.as_ref().is_some_and(|resource| {
            let state = resource.state.lock().unwrap();
            state.close_requested || state.closing
        });
        if flow.released || closing {
            // Linux tcp_close counts unread bytes, including bytes already received from
            // the relay but still waiting for room in the endpoint's receive queue.
            // An owner close also withdraws this frame while the stream wrapper
            // remains live, so its own CloseACK can pass a full receive queue.
            flow.reset |= *offset < data.len();
            self.input = None;
            return Ok(true);
        }
        if flow.peer_fin || flow.state == StreamState::Closed {
            self.input = None;
            return Ok(true);
        }
        let n = (data.len() - *offset).min(self.shared.config.buffer_bytes - flow.rx.len());
        let bytes = &data[*offset..*offset + n];
        let marked = *urgent && n != 0 && *offset + n == data.len();
        if marked {
            flow.rx.push_urgent(bytes, flow.oob_inline);
        } else {
            flow.rx.push(bytes);
        }
        *offset += n;
        if *offset == data.len() {
            self.input = None;
        }
        let wq = flow.wq.clone();
        drop(inner);
        if n != 0 {
            wq.wake(
                PollMask::READABLE
                    | if marked {
                        PollMask::PRI
                    } else {
                        PollMask::empty()
                    },
            );
        }
        Ok(n != 0)
    }

    fn selected_cutoffs(&self) -> Vec<u64> {
        let inner = self.shared.inner.lock().unwrap();
        inner
            .flows
            .iter()
            .filter_map(|(&id, flow)| {
                let resource = flow.selected.as_ref()?;
                if resource.generation != self.generation {
                    return None;
                }
                let state = resource.state.lock().unwrap();
                ((flow.released || flow.reset || state.close_requested || state.closing)
                    && state.close.is_none())
                .then_some(id)
            })
            .chain(inner.listeners.iter().filter_map(|(&id, listener)| {
                let resource = listener.selected.as_ref()?;
                if resource.generation != self.generation {
                    return None;
                }
                let state = resource.state.lock().unwrap();
                ((listener.released || state.closing) && state.close.is_none()).then_some(id)
            }))
            .collect()
    }

    fn selected_receipt_pending(&self, socket: u64) -> bool {
        self.pending.values().any(|pending| match pending {
            Pending::Selected(id, operation) | Pending::SelectedAddress(id, operation) => {
                *id == socket && *operation != Operation::Close
            }
            Pending::SelectedAccept { child, .. } | Pending::AcceptedAddress(_, child, _) => {
                *child == socket
            }
            _ => false,
        })
    }
    fn selected_unknown_closed(&self, socket: u64) -> bool {
        let inner = self.shared.inner.lock().unwrap();
        inner
            .flows
            .get(&socket)
            .and_then(|flow| flow.selected.as_ref())
            .or_else(|| {
                inner
                    .listeners
                    .get(&socket)
                    .and_then(|listener| listener.selected.as_ref())
            })
            .is_some_and(|resource| {
                let state = resource.state.lock().unwrap();
                state.phase == Phase::Closed
                    && state.remote_cleanup_unconfirmed
                    && state.close.is_some()
            })
    }

    /// Retire only this selected resource's commands that poll_send never
    /// accepted. In particular a removed child must not turn its cached
    /// selected Accept into an ordinary Accept after its parent disappears.
    fn retire_unaccepted_selected(&mut self, socket: u64) {
        let owned = |command: &Command| match command {
            Command::Accept { child, .. } => *child == socket,
            Command::BindStream { socket: id, .. }
            | Command::ConnectFrom { socket: id, .. }
            | Command::ListenFrom { socket: id, .. }
            | Command::ListenReserved { socket: id, .. }
            | Command::LocalAddr { socket: id, .. } => *id == socket,
            _ => false,
        };
        self.cleanup.retain(|command| !owned(command));
        if self.command.as_ref().is_some_and(owned) {
            self.command = None;
        }
        self.pending.retain(|_, pending| match pending {
            Pending::Selected(id, _) | Pending::SelectedAddress(id, _) => *id != socket,
            Pending::AcceptedAddress(_, child, _) => *child != socket,
            Pending::SelectedAccept { child, .. } => *child != socket,
            _ => true,
        });
    }

    fn next_selected(
        &mut self,
        inner: &mut crate::backend::Inner,
        closing_only: bool,
    ) -> Result<Option<Command>, Errno> {
        // A listener close does not acknowledge its separately allocated child.
        // Each reserved/accepted physical child retains its own close transaction.
        let children: Vec<_> = inner
            .listeners
            .values()
            .filter(|listener| listener.selected.is_some() && listener.released)
            .filter_map(|listener| listener.child)
            .collect();
        for child in children {
            if let Some(flow) = inner.flows.get_mut(&child) {
                flow.released = true;
                flow.reset = true;
            }
        }
        let resources: Vec<_> = inner
            .flows
            .iter()
            .filter_map(|(&id, flow)| {
                flow.selected
                    .as_ref()
                    .filter(|resource| resource.generation == self.generation)
                    .map(|resource| {
                        (
                            id,
                            resource.clone(),
                            flow.released
                                || flow.reset
                                || resource.state.lock().unwrap().close_requested,
                            flow.remote,
                            flow.peer,
                            0,
                            flow.reset || (flow.tx.is_empty() && flow.inflight.is_none()),
                        )
                    })
            })
            .chain(inner.listeners.iter().filter_map(|(&id, listener)| {
                listener
                    .selected
                    .as_ref()
                    .filter(|resource| resource.generation == self.generation)
                    .map(|resource| {
                        (
                            id,
                            resource.clone(),
                            listener.released,
                            resource.request.is_some()
                                || resource.state.lock().unwrap().phase
                                    != Phase::Queued(Operation::Listen),
                            listener.addr,
                            listener.backlog,
                            true,
                        )
                    })
            }))
            .collect();
        for (id, resource, released, remote, peer, backlog, drained) in resources {
            if closing_only && !released {
                continue;
            }
            if let Some(flow) = inner.flows.get_mut(&id)
                && flow.reset
                && flow.remote
                && !flow.reset_sent
            {
                flow.reset_sent = true;
                return Ok(Some(Command::Reset { socket: id }));
            }
            if let Some(flow) = inner.flows.get_mut(&id)
                && flow.reset
            {
                if let Some((request, _)) = flow.inflight.take() {
                    self.pending.remove(&request);
                }
                flow.tx.clear();
                flow.outgoing.clear();
                flow.outgoing_bytes = 0;
            }
            let mut state = resource.state.lock().unwrap();
            if state.phase == Phase::Closed {
                let wrapper_released = inner.flows.get(&id).is_some_and(|flow| flow.released)
                    || inner
                        .listeners
                        .get(&id)
                        .is_some_and(|listener| listener.released);
                let receipt = self.selected_receipt_pending(id);
                if wrapper_released && state.close.is_some() && !receipt {
                    inner.flows.remove(&id);
                    if let Some(listener) = inner.listeners.remove(&id) {
                        self.retired.push(listener);
                    }
                }
                continue;
            }
            if state.closing {
                continue;
            }
            let operation = if released {
                if !drained {
                    continue;
                }
                if !remote {
                    self.retire_unaccepted_selected(id);
                    state.phase = Phase::Closed;
                    state.close = Some(Ok(()));
                    self.selected_wakes.push(resource.clone());
                    let remove = inner.flows.get(&id).is_some_and(|flow| flow.released);
                    if remove {
                        inner.flows.remove(&id);
                    } else if let Some(flow) = inner.flows.get_mut(&id) {
                        // An unaccepted connect already returned a live Stream.
                        // Its queries must remain safe after owner cancellation.
                        flow.remote = false;
                        flow.fail(Errno::ECONNABORTED);
                    }
                    if let Some(listener) = inner.listeners.remove(&id) {
                        self.retired.push(listener);
                    }
                    continue;
                }
                Operation::Close
            } else if let Phase::Queued(operation) = state.phase {
                operation
            } else {
                continue;
            };
            let request = inner.id()?;
            let command = match operation {
                Operation::Bind => Command::BindStream {
                    request,
                    socket: id,
                    bind: resource.request.ok_or(Errno::EPROTO)?,
                },
                Operation::Connect => Command::ConnectFrom {
                    request,
                    socket: id,
                    peer,
                    local: state.connect_local.ok_or(Errno::EPROTO)?,
                    requested_bind: resource
                        .request
                        .filter(|bind| bind.explicit)
                        .map(|bind| bind.requested),
                    bound_addr: state.actual,
                },
                Operation::Listen => {
                    if let Some((member, domain, v6only)) = &resource.reserved {
                        Command::ListenReserved {
                            request,
                            socket: id,
                            member: member.clone(),
                            domain: *domain,
                            v6only: *v6only,
                            backlog,
                        }
                    } else {
                        Command::ListenFrom {
                            request,
                            socket: id,
                            backlog,
                        }
                    }
                }
                Operation::Close => Command::CloseSelected {
                    request,
                    socket: id,
                },
            };
            if operation == Operation::Close {
                state.closing = true;
                state.close_request = Some(request);
            } else {
                state.phase = Phase::Pending(operation);
            }
            self.pending
                .insert(request, Pending::Selected(id, operation));
            if let Some(flow) = inner.flows.get_mut(&id) {
                flow.opening = true;
            }
            if let Some(listener) = inner.listeners.get_mut(&id) {
                listener.opening = true;
            }
            return Ok(Some(command));
        }
        Ok(None)
    }

    fn deliver_selected(&mut self) {
        let entry: Arc<dyn WaitEntry> = Arc::new(DriverWake(self.shared.clone()));
        let mut finished = Vec::new();
        for (&id, accepted) in &self.accepted {
            let current = self
                .shared
                .inner
                .lock()
                .unwrap()
                .listeners
                .get(&accepted.listener)
                .is_some_and(|listener| !listener.released && listener.child == Some(id));
            let room = if current {
                let mut register =
                    |queue: &WaitQueue, _| self.registrations.push(queue.add(entry.clone()));
                accepted.sink.room_to(
                    accepted.peer,
                    accepted.local,
                    Some(&mut PollTable::new(PollMask::empty(), &mut register)),
                )
            } else {
                Room::Gone
            };
            match room {
                Room::Full => {}
                Room::Ready => {
                    accepted.sink.incoming_to(
                        accepted.peer,
                        accepted.local,
                        accepted.stream.clone(),
                        accepted.queue.clone(),
                    );
                    finished.push(id);
                }
                Room::Gone => finished.push(id),
            }
        }
        for id in finished {
            let accepted = self.accepted.remove(&id).unwrap();
            {
                let mut inner = self.shared.inner.lock().unwrap();
                if let Some(listener) = inner.listeners.get_mut(&accepted.listener)
                    && listener.child == Some(id)
                {
                    listener.child = None;
                }
            }
            // Stream Drop queues cleanup only, outside the backend mutex. A queued
            // guest owns its own Arc; a refused/retired child is released here.
            drop(accepted);
        }
    }

    fn command_valid(&self) -> bool {
        let inner = self.shared.inner.lock().unwrap();
        match &self.command {
            Some(Command::LocalAddr { request, .. }) => self.pending.contains_key(request),
            Some(Command::Accept { socket, child }) => {
                if let Some(listener) = inner.listeners.get(socket)
                    && let Some(resource) = &listener.selected
                {
                    let state = resource.state.lock().unwrap();
                    !listener.released
                        && listener.child == Some(*child)
                        && !state.closing
                        && !state.close_requested
                        && state.phase == Phase::Listening
                        && inner.flows.get(child).is_some_and(|flow| !flow.released)
                } else {
                    !inner
                        .flows
                        .get(child)
                        .is_some_and(|flow| flow.selected.is_some())
                }
            }
            Some(
                Command::ListenFrom {
                    socket, backlog, ..
                }
                | Command::ListenReserved {
                    socket, backlog, ..
                },
            ) if inner
                .listeners
                .get(socket)
                .is_none_or(|listener| listener.backlog != *backlog) =>
            {
                false
            }
            Some(
                Command::BindStream {
                    request, socket, ..
                }
                | Command::ConnectFrom {
                    request, socket, ..
                }
                | Command::ListenFrom {
                    request, socket, ..
                }
                | Command::ListenReserved {
                    request, socket, ..
                },
            ) => {
                self.pending.contains_key(request)
                    && (inner.flows.get(socket).is_some_and(|flow| !flow.released)
                        || inner
                            .listeners
                            .get(socket)
                            .is_some_and(|listener| !listener.released))
            }
            Some(
                Command::Send {
                    request, socket, ..
                }
                | Command::Shutdown {
                    request, socket, ..
                }
                | Command::SendUrgent {
                    request, socket, ..
                },
            ) => inner
                .flows
                .get(socket)
                .is_some_and(|f| f.inflight.is_some_and(|(id, _)| id == *request) && !f.reset),
            Some(Command::Connect { socket, .. } | Command::Bind { socket, .. }) => inner
                .flows
                .get(socket)
                .is_some_and(|f| f.state == StreamState::Connecting && !f.released),
            Some(Command::Listen { socket, .. }) => {
                inner.listeners.get(socket).is_some_and(|l| !l.released)
            }
            Some(Command::Lookup { request, .. }) => inner.lookups.contains_key(request),
            _ => true,
        }
    }

    fn discard_command(&mut self) {
        let command = self.command.take();
        let mut inner = self.shared.inner.lock().unwrap();
        match command {
            Some(Command::Accept { socket, child })
                if inner
                    .flows
                    .get(&child)
                    .is_some_and(|flow| flow.selected.is_some() && !flow.remote) =>
            {
                if let Some(flow) = inner.flows.remove(&child)
                    && let Some(resource) = flow.selected
                {
                    let mut state = resource.state.lock().unwrap();
                    state.phase = Phase::Closed;
                    state.close = Some(Ok(()));
                    drop(state);
                    self.selected_wakes.push(resource);
                }
                if let Some(listener) = inner.listeners.get_mut(&socket)
                    && listener.child == Some(child)
                {
                    listener.child = None;
                }
            }
            Some(
                Command::BindStream {
                    request, socket, ..
                }
                | Command::ConnectFrom {
                    request, socket, ..
                }
                | Command::ListenFrom {
                    request, socket, ..
                }
                | Command::ListenReserved {
                    request, socket, ..
                },
            ) => {
                if let Some(Pending::Selected(_, operation)) = self.pending.remove(&request) {
                    let resource = inner
                        .flows
                        .get_mut(&socket)
                        .and_then(|flow| {
                            flow.opening = false;
                            flow.selected.clone()
                        })
                        .or_else(|| {
                            inner.listeners.get_mut(&socket).and_then(|listener| {
                                listener.opening = false;
                                listener.selected.clone()
                            })
                        });
                    if let Some(resource) = resource {
                        resource.state.lock().unwrap().phase = Phase::Queued(operation);
                    }
                }
            }
            Some(
                Command::Connect {
                    request, socket, ..
                }
                | Command::Bind {
                    request, socket, ..
                },
            ) => {
                self.pending.remove(&request);
                if let Some(flow) = inner.flows.get_mut(&socket) {
                    flow.opening = false;
                    flow.remote = false;
                    if flow.released {
                        inner.flows.remove(&socket);
                    }
                }
            }
            Some(Command::Listen {
                request, socket, ..
            }) => {
                self.pending.remove(&request);
                if let Some(listener) = inner.listeners.remove(&socket) {
                    self.retired.push(listener);
                }
            }
            Some(
                Command::Send {
                    request, socket, ..
                }
                | Command::Shutdown {
                    request, socket, ..
                }
                | Command::SendUrgent {
                    request, socket, ..
                },
            ) => {
                self.pending.remove(&request);
                if let Some(flow) = inner.flows.get_mut(&socket) {
                    flow.inflight = None;
                }
            }
            _ => {}
        }
    }

    fn sent(&mut self, command: Command) {
        if let Command::Accept { socket, child } = &command {
            let resource = {
                let mut inner = self.shared.inner.lock().unwrap();
                let local = inner.listeners.get(socket).map(|listener| listener.addr);
                inner.flows.get_mut(child).and_then(|flow| {
                    flow.selected.clone().zip(local).inspect(|_| {
                        flow.remote = true;
                    })
                })
            };
            if let Some((resource, local)) = resource {
                let previous = self.pending.insert(
                    *child,
                    Pending::SelectedAccept {
                        listener: *socket,
                        child: *child,
                        resource,
                        local,
                        generation: self.generation,
                        withdrawn: false,
                    },
                );
                debug_assert!(previous.is_none());
            }
        }
        if let Command::BindStream { socket, .. }
        | Command::ConnectFrom { socket, .. }
        | Command::ListenFrom { socket, .. }
        | Command::ListenReserved { socket, .. } = &command
        {
            if let Some(flow) = self.shared.inner.lock().unwrap().flows.get_mut(socket) {
                flow.remote = true;
            }
        }
        if let Command::SendTo { socket, .. } = command {
            let wq = {
                let mut inner = self.shared.inner.lock().unwrap();
                inner.flows.get_mut(&socket).map(|flow| {
                    if let Some(packet) = flow.outgoing.pop_front() {
                        flow.outgoing_bytes -= packet.data.len().max(1);
                    }
                    flow.wq.clone()
                })
            };
            if let Some(wq) = wq {
                wq.wake(PollMask::WRITABLE);
            }
        }
    }

    fn local_close_unconfirmed(
        &mut self,
        request: u64,
        socket: u64,
        error: Option<Errno>,
    ) -> Result<(), Errno> {
        let failure = {
            let inner = self.shared.inner.lock().unwrap();
            if inner.generation != self.generation {
                return Err(Errno::ECANCELED);
            }
            let resource = inner
                .flows
                .get(&socket)
                .and_then(|flow| flow.selected.as_ref())
                .or_else(|| {
                    inner
                        .listeners
                        .get(&socket)
                        .and_then(|listener| listener.selected.as_ref())
                });
            let Some(resource) = resource else {
                // An already retired receipt cannot close a replacement. Like
                // historical close replies it may be ignored, never admitted.
                return if request != 0
                    && request < inner.next_id
                    && socket != 0
                    && socket < inner.next_id
                {
                    Ok(())
                } else {
                    Err(Errno::EPROTO)
                };
            };
            if resource.generation != self.generation {
                return Ok(());
            }
            let state = resource.state.lock().unwrap();
            if state.close_request != Some(request) || !state.closing {
                return Err(Errno::EPROTO);
            }
            match self.pending.get(&request) {
                Some(Pending::Selected(id, Operation::Close)) if *id == socket => {}
                None if state.close.is_some() => {}
                _ => return Err(Errno::EPROTO),
            }
            state.close_error.or(error)
        };
        self.pending.remove(&request);
        self.finish_selected(
            socket,
            Operation::Close,
            failure.map_or(Ok(None), Err),
            None,
            true,
        )?;
        // This event proves the whole local transport session has joined its
        // producers. Retire queued notifications/pending receipts via the SAME
        // disconnect path, without interpreting it as remote physical cleanup.
        self.disconnect_inner(Errno::ECONNABORTED, true, failure);
        failure.map_or(Ok(()), Err)
    }

    fn selected_event(&mut self, event: &Event) -> Result<bool, Errno> {
        if let Event::LocalCloseUnconfirmed {
            request,
            socket,
            error,
        } = event
        {
            return self
                .local_close_unconfirmed(*request, *socket, *error)
                .map(|()| true);
        }
        match event {
            Event::AcceptedTo {
                socket,
                child,
                peer,
                local,
            } => {
                self.selected_accept_event(*socket, *child, *peer, Some(*local))?;
                return Ok(true);
            }
            Event::Accepted {
                socket,
                child,
                peer,
            } => {
                if matches!(self.pending.get(child), Some(Pending::SelectedAccept { listener, .. }) if listener == socket)
                    || self
                        .shared
                        .inner
                        .lock()
                        .unwrap()
                        .listeners
                        .get(socket)
                        .is_some_and(|listener| listener.selected.is_some())
                {
                    self.selected_accept_event(*socket, *child, *peer, None)?;
                    return Ok(true);
                }
            }
            _ => {}
        }
        let (request, socket, operation, result, accept_pending, local_cutoff) = match event {
            Event::StreamBound {
                request,
                socket,
                result,
            } => (
                *request,
                *socket,
                Operation::Bind,
                result.map(Some),
                None,
                false,
            ),
            Event::StreamConnected {
                request,
                socket,
                result,
            } => (
                *request,
                *socket,
                Operation::Connect,
                result.map(Some),
                None,
                false,
            ),
            Event::StreamListening {
                request,
                socket,
                result,
            } => (
                *request,
                *socket,
                Operation::Listen,
                result.map(Some),
                None,
                false,
            ),
            Event::ProviderCloseAck {
                request,
                socket,
                accept_pending,
                result,
            } => (
                *request,
                *socket,
                Operation::Close,
                result.map(|()| None),
                Some(*accept_pending),
                false,
            ),
            Event::Complete { request, result } => match self.pending.get(request) {
                Some(Pending::Selected(socket, operation)) => {
                    let (socket, operation) = (*socket, *operation);
                    self.pending.remove(request);
                    if result.is_ok()
                        && operation != Operation::Close
                        && !self.selected_unknown_closed(socket)
                    {
                        let next = self.shared.inner.lock().unwrap().id()?;
                        self.pending
                            .insert(next, Pending::SelectedAddress(socket, operation));
                        self.cleanup.push_back(Command::LocalAddr {
                            request: next,
                            socket,
                        });
                        return Ok(true);
                    }
                    self.finish_selected(socket, operation, result.map(|()| None), None, false)?;
                    return Ok(true);
                }
                Some(Pending::SelectedAddress(socket, operation)) => {
                    let (socket, operation) = (*socket, *operation);
                    let error = result.err().ok_or(Errno::EPROTO)?;
                    self.pending.remove(request);
                    self.finish_selected(socket, operation, Err(error), None, false)?;
                    return Ok(true);
                }
                Some(Pending::AcceptedAddress(listener, child, peer)) => {
                    let (listener, child, peer) = (*listener, *child, *peer);
                    let error = result.err().ok_or(Errno::EPROTO)?;
                    self.pending.remove(request);
                    self.finish_selected(child, Operation::Connect, Err(error), None, false)?;
                    let mut inner = self.shared.inner.lock().unwrap();
                    if let Some(listener) = inner.listeners.get_mut(&listener)
                        && listener.child == Some(child)
                    {
                        listener.child = None;
                    }
                    let _ = peer;
                    return Ok(true);
                }
                _ => return Ok(false),
            },
            Event::LocalAddr { request, addr } => match self.pending.get(request) {
                Some(Pending::SelectedAddress(socket, operation)) => {
                    (*request, *socket, *operation, Ok(Some(*addr)), None, false)
                }
                Some(Pending::AcceptedAddress(listener, child, peer)) => {
                    let (listener, child, peer) = (*listener, *child, *peer);
                    self.pending.remove(request);
                    self.selected_accept(listener, child, peer, Some(*addr))?;
                    return Ok(true);
                }
                None => {
                    let inner = self.shared.inner.lock().unwrap();
                    return Ok(inner.capabilities.selected_endpoints
                        && *request != 0
                        && *request < inner.next_id);
                }
                _ => return Ok(false),
            },
            _ => return Ok(false),
        };
        match self.pending.remove(&request) {
            Some(Pending::Selected(id, expected) | Pending::SelectedAddress(id, expected))
                if id == socket && expected == operation => {}
            None => {
                let inner = self.shared.inner.lock().unwrap();
                let resource = inner
                    .flows
                    .get(&socket)
                    .and_then(|flow| flow.selected.as_ref())
                    .or_else(|| {
                        inner
                            .listeners
                            .get(&socket)
                            .and_then(|listener| listener.selected.as_ref())
                    });
                if request != 0
                    && request < inner.next_id
                    && socket != 0
                    && socket < inner.next_id
                    && resource
                        .is_none_or(|resource| resource.state.lock().unwrap().close.is_some())
                {
                    return Ok(true);
                }
                return Err(Errno::EPROTO);
            }
            _ => return Err(Errno::EPROTO),
        }
        self.finish_selected(socket, operation, result, accept_pending, local_cutoff)?;
        Ok(true)
    }

    fn finish_selected(
        &mut self,
        socket: u64,
        operation: Operation,
        mut result: Result<Option<std::net::SocketAddr>, Errno>,
        accept_pending: Option<bool>,
        local_cutoff: bool,
    ) -> Result<(), Errno> {
        let shared = self.shared.clone();
        let mut inner = shared.inner.lock().unwrap();
        if inner.generation != self.generation {
            return Err(Errno::ECANCELED);
        }
        let resource = inner
            .flows
            .get(&socket)
            .and_then(|flow| flow.selected.clone())
            .or_else(|| {
                inner
                    .listeners
                    .get(&socket)
                    .and_then(|listener| listener.selected.clone())
            })
            .ok_or(Errno::EPROTO)?;
        if resource.generation != self.generation {
            return Err(Errno::ECANCELED);
        }
        let io_queue = inner.flows.get(&socket).map(|flow| flow.wq.clone());
        if let Some((member, _, _)) = &resource.reserved
            && operation == Operation::Listen
            && let Ok(Some(actual)) = result
            && (actual.port() != member.local.port()
                || actual.is_ipv4() != member.local.is_ipv4()
                || (!member.local.ip().is_unspecified() && actual.ip() != member.local.ip()))
        {
            // A namespace reservation is authoritative. Do not publish a
            // different actual port/address or tear down unrelated flows.
            result = Err(Errno::EPROTO);
        }
        let mut state = resource.state.lock().unwrap();
        if operation != Operation::Close
            && state.phase == Phase::Closed
            && state.remote_cleanup_unconfirmed
            && state.close.is_some()
        {
            if state.close.is_some_and(|close| close.is_err()) && result.is_ok() {
                // A late successful result now identifies actual work which
                // was absent at the old relay's first failed Close. Clean up
                // that same resource; never replay the guest's original work.
                state.actual = result.ok().flatten().or(state.actual);
                state.phase = Phase::Bound;
                state.closing = false;
                state.close_requested = true;
                state.close = None;
                if let Some(flow) = inner.flows.get_mut(&socket) {
                    flow.remote = true;
                    flow.opening = false;
                }
            }
            drop(state);
            drop(inner);
            self.shared.wake.wake();
            return Ok(());
        }
        if (operation == Operation::Close && !state.closing)
            || (operation != Operation::Close && state.phase != Phase::Pending(operation))
        {
            return Err(Errno::EPROTO);
        }
        if state.closing && operation != Operation::Close {
            // Cancellation owns this resource until its own actual close ACK.
            // An earlier operation may finish, but cannot republish readiness.
            if let Ok(Some(actual)) = result {
                state.actual = Some(actual);
            }
            if let Err(error) = result {
                state.error.get_or_insert(error);
            }
            state.phase = Phase::Bound;
            if let Some(flow) = inner.flows.get_mut(&socket) {
                flow.opening = false;
            }
            if let Some(listener) = inner.listeners.get_mut(&socket) {
                listener.opening = false;
            }
            return Ok(());
        }
        if operation == Operation::Close {
            let was_terminal = state.close.is_some();
            state.phase = Phase::Closed;
            state.close = Some(if local_cutoff {
                state
                    .close
                    .filter(|close| close.is_err())
                    .unwrap_or(result.map(|_| ()))
            } else {
                result.map(|_| ())
            });
            if local_cutoff {
                state.remote_cleanup_unconfirmed |= !was_terminal;
            } else {
                state.remote_cleanup_unconfirmed = accept_pending.is_none();
            }
            if let Err(error) = result {
                state.error.get_or_insert(error);
                state.close_error.get_or_insert(error);
            }
            let retain_receipt = match self.pending.get_mut(&socket) {
                Some(Pending::SelectedAccept { withdrawn, .. })
                    if !local_cutoff && accept_pending != Some(false) =>
                {
                    // A stock Classic response supplies no such disposition.
                    // Do not turn that missing guarantee into `false`.
                    *withdrawn = true;
                    true
                }
                Some(Pending::SelectedAccept { .. }) => {
                    self.pending.remove(&socket);
                    false
                }
                _ => false,
            };
            let retain_open =
                !local_cutoff && accept_pending.is_none() && self.selected_receipt_pending(socket);
            if local_cutoff {
                self.retire_unaccepted_selected(socket);
            }
            let remove = inner.flows.get(&socket).is_some_and(|flow| flow.released)
                && !retain_receipt
                && !retain_open;
            if remove {
                inner.flows.remove(&socket);
            } else if let Some(flow) = inner.flows.get_mut(&socket) {
                // A reset stream may still have a guest wrapper. Its state and
                // error remain queryable after actual provider close.
                flow.remote = false;
                flow.opening = false;
                if flow.state != StreamState::Closed {
                    flow.fail(result.err().unwrap_or(Errno::ECONNABORTED));
                }
            }
            if retain_open {
                if let Some(listener) = inner.listeners.get_mut(&socket) {
                    listener.released = true;
                    listener.ready = false;
                    listener.opening = false;
                }
            } else if let Some(listener) = inner.listeners.remove(&socket) {
                self.retired.push(listener);
            }
            for listener in inner.listeners.values_mut() {
                if listener.child == Some(socket) {
                    listener.child = None;
                }
            }
            // Parent retirement withdraws publication authority, never the
            // separately owned child's cleanup or notification receipt.
            for pending in self.pending.values_mut() {
                if let Pending::SelectedAccept {
                    listener,
                    withdrawn,
                    ..
                } = pending
                    && *listener == socket
                {
                    *withdrawn = true;
                }
            }
            // This fence retires only transactions for this physical resource.
            // Any separately allocated child retains its own pending close.
            self.pending.retain(|_, pending| match pending {
                Pending::Selected(id, operation) | Pending::SelectedAddress(id, operation) => {
                    *id != socket || (retain_open && *operation != Operation::Close)
                }
                Pending::AcceptedAddress(_, child, _) => *child != socket || retain_open,
                _ => true,
            });
        } else {
            match result {
                Ok(Some(actual)) => {
                    let expected = resource.request.map(|bind| bind.requested).or_else(|| {
                        resource
                            .reserved
                            .as_ref()
                            .map(|(member, _, _)| member.local)
                    });
                    if actual.port() == 0
                        || expected.is_some_and(|requested| {
                            actual.is_ipv4() != requested.is_ipv4()
                                || (requested.port() != 0 && actual.port() != requested.port())
                                || (!requested.ip().is_unspecified()
                                    && actual.ip() != requested.ip())
                        })
                    {
                        return Err(Errno::EPROTO);
                    }
                    if operation == Operation::Connect
                        && state
                            .actual
                            .is_some_and(|bound| bound.port() != actual.port())
                    {
                        return Err(Errno::EPROTO);
                    }
                    if operation == Operation::Connect
                        && inner
                            .flows
                            .get(&socket)
                            .is_some_and(|flow| flow.peer.is_ipv4() != actual.is_ipv4())
                    {
                        return Err(Errno::EPROTO);
                    }
                    state.actual = Some(actual);
                    state.phase = match operation {
                        Operation::Bind
                            if matches!(
                                resource.request.map(|bind| bind.purpose),
                                Some(wasixv2_vnet::endpoint::EndpointBindPurpose::Listen { .. })
                            ) =>
                        {
                            Phase::Listening
                        }
                        Operation::Bind => Phase::Bound,
                        Operation::Connect => Phase::Connected,
                        Operation::Listen => Phase::Listening,
                        Operation::Close => unreachable!(),
                    };
                    if let Some(flow) = inner.flows.get_mut(&socket) {
                        flow.opening = false;
                        if operation == Operation::Connect {
                            flow.state = StreamState::Established;
                        }
                    }
                    if let Some(listener) = inner.listeners.get_mut(&socket) {
                        listener.addr = actual;
                        listener.opening = false;
                        listener.ready = true;
                    }
                }
                Ok(None) => return Err(Errno::EPROTO),
                Err(error) => {
                    state.error.get_or_insert(error);
                    state.phase = Phase::Bound;
                    if let Some(flow) = inner.flows.get_mut(&socket) {
                        flow.fail(error);
                        flow.reset = true;
                    }
                    if let Some(listener) = inner.listeners.get_mut(&socket) {
                        listener.released = true;
                        listener.opening = false;
                    }
                }
            }
        }
        let report = inner.listeners.get(&socket).and_then(|listener| {
            listener
                .endpoint
                .clone()
                .map(|endpoint| (endpoint, listener.addr))
        });
        drop(state);
        drop(inner);
        resource
            .queue
            .wake(PollMask::READABLE | PollMask::WRITABLE | PollMask::ERR | PollMask::HUP);
        if let Some(queue) = io_queue {
            queue.wake(PollMask::READABLE | PollMask::WRITABLE | PollMask::ERR | PollMask::HUP);
        }
        if let Some((report, address)) = report {
            if let Err(error) = result {
                self.publication_failure(address, error);
            }
            report.report(result.map(|_| ()));
        }
        self.shared.wake.wake();
        Ok(())
    }

    fn selected_accept_event(
        &mut self,
        socket: u64,
        child: u64,
        peer: std::net::SocketAddr,
        local: Option<std::net::SocketAddr>,
    ) -> Result<(), Errno> {
        let (resource, expected, generation, withdrawn) = match self.pending.get(&child) {
            Some(Pending::SelectedAccept {
                listener,
                child: expected,
                resource,
                local,
                generation,
                withdrawn,
            }) if *listener == socket && *expected == child => {
                (resource.clone(), *local, *generation, *withdrawn)
            }
            _ => return Err(Errno::EPROTO),
        };
        if generation != self.generation {
            return Err(Errno::EPROTO);
        }
        if local.is_some_and(|local| {
            local.port() != expected.port()
                || local.is_ipv4() != peer.is_ipv4()
                || local.ip().is_unspecified()
        }) {
            return Err(Errno::EPROTO);
        }
        let mut inner = self.shared.inner.lock().unwrap();
        if inner.generation != generation
            || inner
                .flows
                .get(&child)
                .and_then(|flow| flow.selected.as_ref())
                .is_none_or(|selected| !Arc::ptr_eq(selected, &resource))
        {
            return Err(Errno::EPROTO);
        }
        self.pending.remove(&child);
        if withdrawn {
            let mut state = resource.state.lock().unwrap();
            if state.remote_cleanup_unconfirmed && state.close.is_some_and(|close| close.is_err()) {
                // The old relay may report InvalidFd before its create result.
                // This is cleanup of that newly known late resource, not a
                // replay of the guest's bind/connect/accept operation.
                state.close = None;
                state.closing = false;
                state.close_requested = true;
                state.phase = Phase::Bound;
                let flow = inner.flows.get_mut(&child).unwrap();
                flow.remote = true;
                flow.peer = peer;
            } else if state.close.is_some() && inner.flows[&child].released {
                inner.flows.remove(&child);
            }
            drop(state);
            drop(inner);
            self.shared.wake.wake();
            return Ok(());
        }
        drop(inner);
        self.selected_accept(socket, child, peer, local)
    }

    fn selected_accept(
        &mut self,
        socket: u64,
        child: u64,
        peer: std::net::SocketAddr,
        local: Option<std::net::SocketAddr>,
    ) -> Result<(), Errno> {
        if self.accepted.contains_key(&child)
            || self.pending.values().any(
                |pending| matches!(pending, Pending::AcceptedAddress(_, id, _) if *id == child),
            )
        {
            return Err(Errno::EPROTO);
        }
        let mut inner = self.shared.inner.lock().unwrap();
        let listener = inner.listeners.get(&socket).ok_or(Errno::EPROTO)?;
        if listener.child != Some(child) {
            return Err(Errno::EPROTO);
        }
        let sink = listener.endpoint.clone().ok_or(Errno::EPROTO)?;
        if let Some(local) = local {
            if local.port() != listener.addr.port()
                || local.is_ipv4() != peer.is_ipv4()
                || local.ip().is_unspecified()
            {
                return Err(Errno::EPROTO);
            }
            let flow = inner.flows.get_mut(&child).ok_or(Errno::EPROTO)?;
            if flow
                .selected
                .as_ref()
                .is_some_and(|resource| resource.state.lock().unwrap().closing)
            {
                flow.peer = peer;
                return Ok(());
            }
            flow.peer = peer;
            flow.state = StreamState::Established;
            flow.opening = false;
            let resource = flow.selected.as_ref().ok_or(Errno::EPROTO)?;
            {
                let mut state = resource.state.lock().unwrap();
                state.actual = Some(local);
                state.phase = Phase::Connected;
            }
            let queue = flow.wq.clone();
            drop(inner);
            let stream = Arc::new(Stream {
                shared: self.shared.clone(),
                id: child,
                peer,
            });
            self.accepted.insert(
                child,
                SelectedAccepted {
                    listener: socket,
                    stream,
                    sink,
                    peer,
                    local,
                    queue,
                },
            );
            self.shared.wake.wake();
        } else {
            let request = inner.id()?;
            self.pending
                .insert(request, Pending::AcceptedAddress(socket, child, peer));
            self.cleanup.push_back(Command::LocalAddr {
                request,
                socket: child,
            });
        }
        Ok(())
    }

    fn event(&mut self, event: Event) -> Result<(), Errno> {
        if self.selected_event(&event)? {
            return Ok(());
        }
        if self.provider_event(&event)? {
            return Ok(());
        }

        let mut binding_wakes = Vec::new();
        let mut address_query = None;
        let mut wakes = Vec::new();
        let mut complete = None;
        let mut incoming = None;
        let mut inner = self.shared.inner.lock().unwrap();
        match event {
            Event::StreamBound { .. }
            | Event::StreamConnected { .. }
            | Event::StreamListening { .. }
            | Event::ProviderCloseAck { .. }
            | Event::LocalCloseUnconfirmed { .. }
            | Event::AcceptedTo { .. } => return Err(Errno::EPROTO),
            Event::Provider { .. } => return Err(Errno::EPROTO),
            Event::Complete { request, result } => {
                if let Some(query) = inner.lookups.remove(&request) {
                    complete = Some((
                        query.done,
                        Err(crate::codec::lookup_error(
                            result.err().unwrap_or(Errno::EPROTO),
                        )),
                    ));
                } else if let Some(pending) = self.pending.remove(&request) {
                    match pending {
                        Pending::Selected(..)
                        | Pending::SelectedAddress(..)
                        | Pending::AcceptedAddress(..)
                        | Pending::SelectedAccept { .. } => return Err(Errno::EPROTO),
                        Pending::Open(id) => {
                            if let Some(flow) = inner.flows.get_mut(&id) {
                                flow.opening = false;
                                match result {
                                    Ok(()) if flow.binding.is_some() => {
                                        flow.opening = true;
                                        address_query = Some((id, true));
                                    }
                                    Ok(()) => flow.state = StreamState::Established,
                                    Err(error) => {
                                        if let Some(binding) = flow.binding.take() {
                                            binding_wakes.extend(binding.complete(Err(error)));
                                        }
                                        if flow.published {
                                            self.publication_failure(flow.peer, error);
                                        }
                                        flow.fail(error)
                                    }
                                }
                                wakes.push((flow.wq.clone(), flow.mask(self.shared.config)));
                            }
                        }
                        Pending::Listen(id) => {
                            if let Some(listener) = inner.listeners.get_mut(&id) {
                                listener.opening = false;
                                listener.ready = result.is_ok();
                                if result.is_ok() && listener.binding.is_some() {
                                    listener.opening = true;
                                    listener.ready = false;
                                    address_query = Some((id, false));
                                }
                                // A failed publication never affects guest bind/listen. Keep
                                // the failure visible to the embedding driver caller.
                                if let Err(error) = result {
                                    listener.released = true;
                                    if let Some(binding) = listener.binding.take() {
                                        binding_wakes.extend(binding.complete(Err(error)));
                                    }
                                    self.publication_failure(listener.addr, error);
                                }
                            }
                        }
                        Pending::Shutdown(id) => {
                            if let Some(flow) = inner.flows.get_mut(&id) {
                                flow.inflight = None;
                                if let Err(error) = result {
                                    flow.fail(error);
                                }
                                wakes.push((flow.wq.clone(), flow.mask(self.shared.config)));
                            }
                        }
                        Pending::Address(id, udp) => {
                            let error = result.err().ok_or(Errno::EPROTO)?;
                            self.bound(&mut inner, id, udp, Err(error), &mut binding_wakes)?;
                        }
                        Pending::Send(_, _) => return Err(Errno::EPROTO),
                    }
                }
            }
            Event::LocalAddr { request, addr } => {
                if let Some(Pending::Address(id, udp)) = self.pending.remove(&request) {
                    self.bound(&mut inner, id, udp, Ok(addr), &mut binding_wakes)?;
                } else {
                    return Err(Errno::EPROTO);
                }
            }
            Event::Lookup {
                request,
                mut result,
            } => {
                if let Some(query) = inner.lookups.get(&request) {
                    if let Ok(found) = &mut result {
                        match (&query.lookup, &mut found.answer) {
                            (Lookup::Name(name), Answer::Addrs { canonical, addrs }) => {
                                if addrs.len() > 256 || canonical.len() > 253 {
                                    return Err(Errno::EPROTO);
                                }
                                if canonical.is_empty() {
                                    *canonical = name.clone();
                                }
                            }
                            (Lookup::Addr(_), Answer::Name(name)) if name.len() <= 253 => {}
                            (Lookup::Forward(_), Answer::Message(message))
                                if message.len() <= 65535 => {}
                            _ => return Err(Errno::EPROTO),
                        }
                    }
                    let query = inner.lookups.remove(&request).unwrap();
                    complete = Some((query.done, result));
                }
            }
            Event::Sent {
                request,
                socket,
                amount,
            } => {
                if let Some(Pending::Send(id, size)) = self.pending.remove(&request) {
                    if id != socket || amount == 0 || amount > size {
                        return Err(Errno::EPROTO);
                    }
                    if let Some(flow) = inner.flows.get_mut(&id) {
                        if flow.inflight != Some((request, size)) {
                            return Err(Errno::EPROTO);
                        }
                        flow.inflight = None;
                        flow.tx.drain(..amount);
                        flow.tx_head += amount as u64;
                        while flow
                            .tx_urgent
                            .front()
                            .is_some_and(|mark| *mark < flow.tx_head)
                        {
                            flow.tx_urgent.pop_front();
                        }
                        wakes.push((flow.wq.clone(), PollMask::WRITABLE));
                    }
                }
            }
            Event::SendError {
                request,
                socket,
                error,
            } => {
                if let Some(Pending::Send(id, _)) = self.pending.remove(&request) {
                    if id != socket {
                        return Err(Errno::EPROTO);
                    }
                    if let Some(flow) = inner.flows.get_mut(&id) {
                        flow.inflight = None;
                        if error == Errno::EAGAIN {
                            flow.send_blocked = true;
                        } else {
                            flow.fail(error);
                            flow.reset = true;
                        }
                        wakes.push((flow.wq.clone(), flow.mask(self.shared.config)));
                    }
                }
            }
            Event::Data { .. } | Event::Urgent { .. } => {
                unreachable!("data is copied through the bounded input slot")
            }
            Event::DatagramError { socket, error } => {
                if let Some(flow) = inner.flows.get_mut(&socket) {
                    if flow.kind == Kind::Stream {
                        return Err(Errno::EPROTO);
                    }
                    if flow.attached {
                        flow.error = Some(error);
                        wakes.push((flow.wq.clone(), PollMask::ERR));
                    }
                }
            }
            Event::DatagramRefused {
                socket,
                destination,
                offender,
                payload,
            } => {
                if !inner.capabilities.udp_icmp
                    || payload.len() > 65535
                    || offender.is_some_and(|a| a.is_ipv4() != destination.is_ipv4())
                {
                    return Err(Errno::EPROTO);
                }
                if let Some(flow) = inner.flows.get_mut(&socket) {
                    let Kind::Datagram(domain) = flow.kind else {
                        return Err(Errno::EPROTO);
                    };
                    if (domain == wasixv2_vnet::Domain::Inet) != destination.is_ipv4() {
                        return Err(Errno::EPROTO);
                    }
                    // Linux net/ipv4/udp.c:__udp4_lib_err (now udp_err) looks up the
                    // quoted tuple, then reports hard errors only to connected sockets
                    // unless RECVERR is enabled. A stale peer's error cannot hit a new peer.
                    if flow.attached
                        && !flow.released
                        && flow.connected_peer.is_none_or(|p| p == destination)
                    {
                        let changed = flow.datagram_errors.refused(
                            destination,
                            offender,
                            &payload,
                            flow.connected_peer.is_some(),
                            self.shared.config.buffer_bytes,
                        );
                        if changed {
                            wakes.push((flow.wq.clone(), PollMask::ERR));
                        }
                    }
                }
            }
            Event::Writable { socket } => {
                if let Some(flow) = inner.flows.get_mut(&socket) {
                    flow.send_blocked = false;
                    wakes.push((flow.wq.clone(), PollMask::WRITABLE));
                }
            }
            Event::Datagram { socket, data, addr } => {
                if let Some(flow) = inner.flows.get_mut(&socket) {
                    let Kind::Datagram(domain) = flow.kind else {
                        return Err(Errno::EPROTO);
                    };
                    if data.len() > 65535 {
                        return Err(Errno::EMSGSIZE);
                    }
                    // Linux net/ipv4/udp.c:__udp_enqueue_schedule_skb drops excess datagrams.
                    if (domain == wasixv2_vnet::Domain::Inet) == addr.is_ipv4()
                        && flow.connected_peer.is_none_or(|peer| peer == addr)
                        && flow.incoming_bytes + data.len().max(1)
                            <= self.shared.config.buffer_bytes
                        && flow.attached
                        && !flow.released
                        && flow.state == StreamState::Established
                    {
                        flow.incoming_bytes += data.len().max(1);
                        flow.incoming.push_back(Packet { data, addr });
                        wakes.push((flow.wq.clone(), PollMask::READABLE));
                    }
                }
            }
            Event::Eof { socket } => {
                if let Some(flow) = inner.flows.get_mut(&socket) {
                    flow.read_shut = true;
                    flow.peer_fin = true;
                    // A peer FIN is not a local SHUT_RD request.
                    flow.sent_read_shut = true;
                    wakes.push((flow.wq.clone(), flow.mask(self.shared.config)));
                }
            }
            Event::Reset { socket, error } => {
                if let Some(flow) = inner.flows.get_mut(&socket) {
                    flow.fail(error);
                    flow.reset = true;
                    self.pending.retain(|_, p| !matches!(p, Pending::Open(id) | Pending::Send(id, _) | Pending::Shutdown(id) if *id == socket));
                    wakes.push((flow.wq.clone(), flow.mask(self.shared.config)));
                }
            }
            Event::Accepted {
                socket,
                child,
                peer,
            } => {
                let sink = if let Some(listener) = inner.listeners.get_mut(&socket) {
                    if listener.child != Some(child) {
                        return Err(Errno::EPROTO);
                    }
                    listener.child = None;
                    if listener.released {
                        None
                    } else {
                        Some(listener.sink.clone())
                    }
                } else {
                    None
                };
                if let Some(flow) = inner.flows.get_mut(&child) {
                    flow.opening = false;
                    flow.peer = peer;
                    flow.state = StreamState::Established;
                    if let Some(sink) = sink {
                        incoming = Some((sink, child, peer, flow.wq.clone()));
                    } else {
                        flow.released = true;
                        flow.reset = true;
                    }
                } else {
                    if self.cleanup.len() >= self.shared.config.max_sockets * 2 {
                        return Err(Errno::ENOBUFS);
                    }
                    self.cleanup.push_back(Command::Reset { socket: child });
                    self.cleanup.push_back(Command::Close { socket: child });
                }
            }
        }
        if let Some((socket, udp)) = address_query {
            let request = inner.id()?;
            self.pending.insert(request, Pending::Address(socket, udp));
            self.cleanup
                .push_back(Command::LocalAddr { request, socket });
        }
        drop(inner);
        for waker in binding_wakes {
            waker.wake();
        }
        for (wq, mask) in wakes {
            wq.wake(mask);
        }
        if let Some((done, result)) = complete {
            done(result);
        }
        if let Some((sink, id, peer, wq)) = incoming {
            let stream = Arc::new(Stream {
                shared: self.shared.clone(),
                id,
                peer,
            });
            // Linux tcp_v4_syn_recv_sock/inet_csk_accept use current listener state.
            // Accept credit may predate listen; no callback runs under the backend mutex.
            if sink.poll_room(None) != Room::Ready || !sink.incoming(stream.clone(), wq) {
                let mut inner = self.shared.inner.lock().unwrap();
                if let Some(flow) = inner.flows.get_mut(&id) {
                    flow.reset = true;
                }
            }
        }
        Ok(())
    }

    fn bound(
        &self,
        inner: &mut crate::backend::Inner,
        id: u64,
        udp: bool,
        result: Result<std::net::SocketAddr, Errno>,
        wakes: &mut Vec<std::task::Waker>,
    ) -> Result<(), Errno> {
        let (requested, binding) = if udp {
            let Some(flow) = inner.flows.get_mut(&id) else {
                return Ok(());
            };
            (flow.peer, flow.binding.clone())
        } else {
            let Some(listener) = inner.listeners.get_mut(&id) else {
                return Ok(());
            };
            (listener.addr, listener.binding.clone())
        };
        let Some(binding) = binding else {
            return Err(Errno::EPROTO);
        };
        if let Ok(addr) = result
            && (addr.port() == 0
                || addr.is_ipv4() != requested.is_ipv4()
                || (requested.port() != 0 && requested.port() != addr.port())
                || (!requested.ip().is_unspecified() && requested.ip() != addr.ip()))
        {
            return Err(Errno::EPROTO);
        }
        if udp {
            let flow = inner.flows.get_mut(&id).unwrap();
            flow.binding = None;
            flow.opening = false;
            match result {
                Ok(addr) => {
                    flow.peer = addr;
                    flow.state = StreamState::Established;
                }
                Err(error) => flow.fail(error),
            }
        } else {
            let listener = inner.listeners.get_mut(&id).unwrap();
            listener.binding = None;
            listener.opening = false;
            match result {
                Ok(addr) => {
                    listener.addr = addr;
                    listener.ready = true;
                }
                Err(_) => listener.released = true,
            }
        }
        if let Err(error) = result {
            self.publication_failure(requested, error);
        }
        wakes.extend(binding.complete(result));
        Ok(())
    }

    fn publication_failure(&self, addr: std::net::SocketAddr, error: Errno) {
        // Returned through the driver, never as a guest socket error.
        let mut failures = self.shared.failures.lock().unwrap();
        if failures.len() == self.shared.config.max_sockets {
            failures.pop_front();
        }
        failures.push_back((addr, error));
    }

    fn disconnect(&mut self, error: Errno) {
        self.disconnect_inner(error, false, Some(error));
    }

    fn disconnect_inner(
        &mut self,
        error: Errno,
        local_unconfirmed: bool,
        cleanup_error: Option<Errno>,
    ) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        self.command = None;
        self.input = None;
        self.pending.clear();
        self.cleanup.clear();
        self.registrations.clear();
        let mut inner = self.shared.inner.lock().unwrap();
        if inner.generation != self.generation {
            return;
        }
        inner.online = false;
        let mut queues = Vec::new();
        let mut binding_wakes = Vec::new();
        let mut selected = Vec::new();
        for flow in inner.flows.values_mut() {
            if let Some(resource) = &flow.selected
                && resource.generation == self.generation
            {
                if local_unconfirmed {
                    resource.local_finished_unconfirmed(cleanup_error);
                } else {
                    resource.failed(error);
                }
                selected.push(resource.clone());
            }
            if let Some(binding) = flow.binding.take() {
                binding_wakes.extend(binding.complete(Err(Errno::ECONNABORTED)));
            }
            if flow.state != StreamState::Closed {
                flow.fail(Errno::ECONNABORTED);
                queues.push(flow.wq.clone());
            }
            flow.remote = false;
            flow.opening = false;
        }
        inner.flows.retain(|_, flow| !flow.released);
        let listeners = std::mem::take(&mut inner.listeners);
        for listener in listeners.values() {
            if let Some(resource) = &listener.selected
                && resource.generation == self.generation
            {
                if local_unconfirmed {
                    resource.local_finished_unconfirmed(cleanup_error);
                } else {
                    resource.failed(error);
                }
                selected.push(resource.clone());
            }
            if let Some(binding) = &listener.binding {
                binding_wakes.extend(binding.complete(Err(Errno::ECONNABORTED)));
            }
        }
        let queries = std::mem::take(&mut inner.lookups);
        let controls = std::mem::take(&mut inner.controls);
        drop(inner);
        self.accepted.clear();
        for listener in listeners.values() {
            if let Some(endpoint) = &listener.endpoint {
                endpoint.report(Err(error));
            }
        }
        drop(listeners);
        for resource in selected {
            resource
                .queue
                .wake(PollMask::ERR | PollMask::HUP | PollMask::READABLE | PollMask::WRITABLE);
        }
        for waker in binding_wakes {
            waker.wake();
        }
        for wq in queues {
            wq.wake(PollMask::ERR | PollMask::HUP | PollMask::READABLE | PollMask::WRITABLE);
        }
        for mut control in controls {
            control.snapshot.active_unknown = control.activity_ambiguous();
            let reconciliation = control
                .needs_reconciliation()
                .then_some(Errno::ECONNABORTED);
            (control.done)(wasixv2_vnet::provider::Completion {
                result: Err(Errno::ECONNABORTED),
                snapshot: control.snapshot,
                reconciliation,
            });
        }
        for (_, query) in queries {
            (query.done)(Err(LookupError::Failed));
        }
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.disconnect(Errno::ECONNABORTED);
    }
}
