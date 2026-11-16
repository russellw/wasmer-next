//! A reserved TCP factory attempt. It enters ordinary Remote state before the unlocked
//! factory call, so concurrent connect/listen/disconnect retain existing socket semantics.
use crate::{BackendStream, PollMask, PollTable, Pollable, Shutdown, StreamState, WaitQueue};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use wasixv2_abi::Errno;
enum State {
    Waiting,
    Ready(Arc<dyn BackendStream>),
    Failed(Option<Errno>),
}
pub(crate) struct PendingStream {
    state: Mutex<State>,
    peer: SocketAddr,
    wq: WaitQueue,
}
impl PendingStream {
    pub(crate) fn new(peer: SocketAddr, wq: WaitQueue) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::Waiting),
            peer,
            wq,
        })
    }
    fn stream(&self) -> Result<Arc<dyn BackendStream>, Errno> {
        match &*self.state.lock().unwrap() {
            State::Waiting => Err(Errno::EAGAIN),
            State::Ready(s) => Ok(s.clone()),
            State::Failed(e) => Err(e.unwrap_or(Errno::ECONNABORTED)),
        }
    }
    pub(crate) fn complete(&self, result: Result<Arc<dyn BackendStream>, Errno>) {
        {
            let mut state = self.state.lock().unwrap();
            if matches!(*state, State::Waiting) {
                *state = match result {
                    Ok(s) => State::Ready(s),
                    Err(e) => State::Failed(Some(e)),
                };
            }
        }
        self.wq.wake(PollMask::empty());
    }
}
impl Pollable for PendingStream {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        match self.stream() {
            Ok(s) => s.poll(table),
            Err(Errno::EAGAIN) => PollMask::empty(),
            Err(_) => PollMask::ERR | PollMask::HUP | PollMask::OUT,
        }
    }
}
impl BackendStream for PendingStream {
    fn tcp_option_policy(&self) -> Option<crate::TcpOptionPolicy> {
        self.stream()
            .ok()
            .and_then(|stream| stream.tcp_option_policy())
    }
    fn async_options(&self) -> bool {
        self.stream().is_ok_and(|stream| stream.async_options())
    }
    fn start_options(
        &self,
        options: Vec<(i32, i32, Vec<u8>)>,
        done: Box<dyn FnOnce(Result<(), Errno>) + Send>,
    ) -> Result<(), Errno> {
        self.stream()?.start_options(options, done)
    }
    fn provider_local_addr(&self) -> Option<Result<SocketAddr, Errno>> {
        self.stream()
            .ok()
            .and_then(|stream| stream.provider_local_addr())
    }
    fn state(&self) -> StreamState {
        match self.stream() {
            Ok(s) => s.state(),
            Err(Errno::EAGAIN) => StreamState::Connecting,
            Err(_) => StreamState::Closed,
        }
    }
    fn tcp_established(&self) -> bool {
        self.stream().is_ok_and(|s| s.tcp_established())
    }
    fn read(&self, b: &mut [u8], peek: bool) -> Result<usize, Errno> {
        self.stream()?.read(b, peek)
    }
    fn write(&self, b: &[u8]) -> Result<usize, Errno> {
        self.stream()?.write(b)
    }
    fn write_more(&self, b: &[u8], more: bool, mss: usize) -> Result<usize, Errno> {
        self.stream()?.write_more(b, more, mss)
    }
    fn write_urgent(&self, b: &[u8]) -> Result<usize, Errno> {
        self.stream()?.write_urgent(b)
    }
    fn read_urgent(&self, peek: bool) -> Result<u8, Errno> {
        self.stream()?.read_urgent(peek)
    }
    fn at_mark(&self) -> bool {
        self.stream().is_ok_and(|s| s.at_mark())
    }
    fn shutdown(&self, how: Shutdown) -> Result<(), Errno> {
        if let Ok(s) = self.stream() {
            return s.shutdown(how);
        }
        self.complete(Err(Errno::ECONNABORTED));
        Ok(())
    }
    fn take_error(&self) -> Option<Errno> {
        let mut state = self.state.lock().unwrap();
        match &mut *state {
            State::Failed(e) => e.take(),
            State::Ready(s) => {
                let s = s.clone();
                drop(state);
                s.take_error()
            }
            State::Waiting => None,
        }
    }
    fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    fn input_len(&self) -> usize {
        self.stream().map_or(0, |s| s.input_len())
    }
    fn output_len(&self) -> usize {
        self.stream().map_or(0, |s| s.output_len())
    }
    fn corked_len(&self) -> usize {
        self.stream().map_or(0, |s| s.corked_len())
    }
    fn push(&self) {
        if let Ok(s) = self.stream() {
            s.push();
        }
    }
    fn set_option(&self, level: i32, name: i32, value: &[u8]) -> Result<(), Errno> {
        match self.stream() {
            Ok(s) => s.set_option(level, name, value),
            Err(Errno::EAGAIN) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
