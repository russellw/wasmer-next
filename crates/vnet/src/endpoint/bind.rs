//! Owned optional bind admission. Provider operations remain outside namespace locks.
use super::{EndpointBindRequest, EndpointBound};
use crate::{BindAdmission, PollMask, PollTable, Pollable, WaitQueue, addr::canonical};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use wasixv2_abi::Errno;

type Commit = dyn Fn(SocketAddr, Arc<dyn EndpointBound>) -> Result<(), Errno> + Send + Sync;

pub(crate) struct Admission {
    queue: WaitQueue,
    commit: Box<Commit>,
    cancel: Box<dyn Fn() + Send + Sync>,
    active: Box<dyn Fn() -> bool + Send + Sync>,
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    bound: Option<Arc<dyn EndpointBound>>,
    result: Option<Result<(), Errno>>,
}
struct Subscription(Arc<Admission>);

impl Admission {
    pub(crate) fn new(
        queue: WaitQueue,
        commit: impl Fn(SocketAddr, Arc<dyn EndpointBound>) -> Result<(), Errno> + Send + Sync + 'static,
        cancel: impl Fn() + Send + Sync + 'static,
        active: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            queue,
            commit: Box::new(commit),
            cancel: Box::new(cancel),
            active: Box::new(active),
            state: Mutex::default(),
        })
    }
    pub(crate) fn subscribe(self: &Arc<Self>) -> Box<dyn BindAdmission> {
        Box::new(Subscription(self.clone()))
    }
    pub(crate) fn install(&self, result: Result<Option<Arc<dyn EndpointBound>>, Errno>) {
        let mut state = self.state.lock().unwrap();
        match result {
            Ok(Some(bound)) => state.bound = Some(bound),
            Ok(None) => state.result = Some(Ok(())),
            Err(error) => state.result = Some(Err(error)),
        }
        drop(state);
        self.queue.wake(PollMask::empty());
    }
}

impl Pollable for Admission {
    fn poll(&self, mut table: Option<&mut PollTable<'_>>) -> PollMask {
        wasixv2_wait::poll_wait(&mut table, &self.queue);
        let state = self.state.lock().unwrap();
        match state.result {
            Some(Ok(())) => PollMask::OUT,
            Some(Err(_)) => PollMask::ERR,
            None if !(self.active)() => PollMask::ERR,
            None => state
                .bound
                .as_ref()
                .map_or(PollMask::empty(), |bound| bound.poll(table)),
        }
    }
}

impl BindAdmission for Admission {
    fn complete(&self) -> Result<(), Errno> {
        let mut state = self.state.lock().unwrap();
        if let Some(result) = state.result {
            return result;
        }
        if !(self.active)() {
            state.result = Some(Err(Errno::ECANCELED));
            return Err(Errno::ECANCELED);
        }
        let bound = state.bound.as_ref().ok_or(Errno::EAGAIN)?;
        let result_now = bound
            .local_addr()
            .and_then(|local| (self.commit)(local, bound.clone()));
        if result_now != Err(Errno::EAGAIN) {
            state.result = Some(result_now);
        }
        result_now
    }
}

impl Pollable for Subscription {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.0.poll(table)
    }
}
impl BindAdmission for Subscription {
    fn complete(&self) -> Result<(), Errno> {
        self.0.complete()
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        // The closure leaves a committed socket alone; cancellation never undoes success.
        (self.cancel)();
    }
}

pub(crate) fn validate(
    request: EndpointBindRequest,
    actual: SocketAddr,
) -> Result<SocketAddr, Errno> {
    let requested = canonical(request.requested);
    let actual = canonical(actual);
    if actual.port() == 0
        || actual.is_ipv4() != requested.is_ipv4()
        || (requested.port() != 0 && requested.port() != actual.port())
        || (!requested.ip().is_unspecified() && requested.ip() != actual.ip())
    {
        return Err(Errno::EPROTO);
    }
    Ok(actual)
}
