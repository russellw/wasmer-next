//! One owned option batch on an existing socket flow, driven by Driver receipts.
use crate::SocketControl;
use std::time::Duration;
use wasixv2_abi::{Errno, SocketLevel, SocketOption, TcpOption};

pub(crate) type Done = Box<dyn FnOnce(Result<(), Errno>) + Send>;
#[derive(Clone)]
pub(crate) enum Step {
    Inline(bool),
    Wire(SocketControl),
}
pub(crate) struct Batch {
    pub steps: Vec<Step>,
    pub position: usize,
    pub pending: Option<u64>,
    done: Done,
}
pub(crate) enum Completion {
    Option {
        batch: Batch,
        result: Result<(), Errno>,
    },
    Readback {
        done: crate::datagram::Done,
        result: Result<wasixv2_vnet::DatagramReadbackValue, Errno>,
    },
}
impl Batch {
    pub fn prepare(options: Vec<(i32, i32, Vec<u8>)>, done: Done) -> Result<Self, Errno> {
        let mut steps = Vec::with_capacity(options.len());
        for (level, name, value) in options {
            let step = if level == SocketLevel::SOL_SOCKET.0 && name == SocketOption::SO_OOBINLINE.0
            {
                Step::Inline(wasixv2_vnet::opts::read_int(&value)? != 0)
            } else if level == SocketLevel::SOL_TCP.0 && name == TcpOption::TCP_NODELAY.0 {
                Step::Wire(SocketControl::NoDelay(
                    wasixv2_vnet::opts::read_int(&value)? != 0,
                ))
            } else if level == SocketLevel::SOL_SOCKET.0 && name == SocketOption::SO_KEEPALIVE.0 {
                Step::Wire(SocketControl::KeepAlive(
                    wasixv2_vnet::opts::read_int(&value)? != 0,
                ))
            } else if level == SocketLevel::SOL_SOCKET.0 && name == SocketOption::SO_LINGER.0 {
                let enabled = wasixv2_vnet::opts::read_int(&value)? != 0;
                let seconds = value
                    .get(4..8)
                    .and_then(|value| value.try_into().ok())
                    .map(i32::from_le_bytes)
                    .ok_or(Errno::EINVAL)?;
                let linger = if enabled {
                    Some(Duration::from_secs(
                        u64::try_from(seconds).map_err(|_| Errno::EINVAL)?,
                    ))
                } else {
                    None
                };
                Step::Wire(SocketControl::Linger(linger))
            } else {
                return Err(Errno::EOPNOTSUPP);
            };
            steps.push(step);
        }
        Ok(Self {
            steps,
            position: 0,
            pending: None,
            done,
        })
    }
    pub fn complete(self, result: Result<(), Errno>) -> Completion {
        Completion::Option {
            batch: self,
            result,
        }
    }
}
impl Completion {
    pub fn readback(
        done: crate::datagram::Done,
        result: Result<wasixv2_vnet::DatagramReadbackValue, Errno>,
    ) -> Self {
        Self::Readback { done, result }
    }

    /// Always after releasing backend/flow locks; the canonical callback may
    /// reenter the same socket synchronously.
    pub fn run(self) {
        match self {
            Self::Option { batch, result } => (batch.done)(result),
            Self::Readback { done, result } => done(result),
        }
    }
}

pub(crate) fn cancel(
    completed: &mut Vec<Completion>,
    inner: &mut crate::backend::Inner,
    id: u64,
    error: Errno,
) {
    if let Some(flow) = inner.flows.get_mut(&id) {
        let outgoing = std::mem::take(&mut flow.outgoing);
        for entry in outgoing {
            if let crate::datagram::Output::Readback { done, .. } = entry {
                completed.push(Completion::readback(done, Err(error)));
            } else {
                flow.outgoing.push_back(entry);
            }
        }
        flow.outgoing_bytes = flow
            .outgoing
            .iter()
            .map(crate::datagram::Output::charge)
            .sum();
    }
    if let Some(flow) = inner.flows.get_mut(&id)
        && let Some(batch) = flow.options.take()
    {
        if flow
            .inflight
            .is_some_and(|(request, _)| batch.pending == Some(request))
        {
            flow.inflight = None;
        }
        completed.push(batch.complete(Err(error)));
    }
}
