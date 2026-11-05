//! One serialized provider transaction, including all advertised readbacks and publication.
use crate::{Driver, Event, WebBackend};
use std::collections::VecDeque;
use wasixv2_abi::Errno;
use wasixv2_vnet::{
    Answer,
    provider::{Completion, Done, Provider, Reply, Request, Snapshot},
};

pub(crate) struct Transaction {
    pub id: u64,
    pub command: Request,
    pub sent: bool,
    operation: Request,
    reply: Option<Reply>,
    refresh: VecDeque<Request>,
    pub(crate) snapshot: Snapshot,
    pub done: Done,
}
impl Transaction {
    pub(crate) fn activity_ambiguous(&self) -> bool {
        self.reply.is_none()
            && self.sent
            && matches!(self.operation, Request::Bridge { .. } | Request::Unbridge)
    }
    pub(crate) fn needs_reconciliation(&self) -> bool {
        self.reply.is_some() || self.operation.mutates() && self.sent
    }
}
impl Provider for WebBackend {
    fn start(&self, operation: Request, done: Done) {
        let mut inner = self.shared.inner.lock().unwrap();
        let error = operation.validate().err().or_else(|| {
            if !inner.online {
                Some(Errno::ENETDOWN)
            } else if inner.capabilities.provider.is_none() {
                Some(Errno::EOPNOTSUPP)
            } else if inner.controls.len() >= self.shared.config.max_lookups {
                Some(Errno::ENOBUFS)
            } else {
                None
            }
        });
        if let Some(error) = error {
            drop(inner);
            done(Completion::error(error));
            return;
        }
        let id = match inner.id() {
            Ok(id) => id,
            Err(error) => {
                drop(inner);
                done(Completion::error(error));
                return;
            }
        };
        let readback = inner.capabilities.provider.unwrap();
        let mut refresh = VecDeque::new();
        if readback.addresses && operation != Request::Addresses {
            refresh.push_back(Request::Addresses);
        }
        if readback.mac && operation != Request::Mac {
            refresh.push_back(Request::Mac);
        }
        if readback.routes && operation != Request::Routes {
            refresh.push_back(Request::Routes);
        }
        inner.controls.push_back(Transaction {
            id,
            command: operation.clone(),
            sent: false,
            operation,
            reply: None,
            refresh,
            snapshot: Snapshot::default(),
            done,
        });
        drop(inner);
        self.shared.wake.wake();
    }
}
fn expected(operation: &Request, reply: &Reply) -> bool {
    matches!(
        (operation, reply),
        (Request::Dhcp, Reply::Acquired(_))
            | (Request::Addresses, Reply::Addresses(_))
            | (Request::Mac, Reply::Mac(_))
            | (Request::Routes, Reply::Routes(_))
    ) || operation.mutates() && !matches!(operation, Request::Dhcp) && *reply == Reply::None
}
impl Driver {
    pub(crate) fn provider_event(&mut self, event: &Event) -> Result<bool, Errno> {
        let (id, result) = match event {
            Event::Provider { request, reply } => (*request, Ok(reply.clone())),
            Event::Complete { request, result } => (*request, result.map(|()| Reply::None)),
            Event::Lookup {
                request,
                result: Ok(found),
            } => match &found.answer {
                Answer::Addrs { addrs, .. } => (*request, Ok(Reply::Acquired(addrs.clone()))),
                _ => return Ok(false),
            },
            _ => return Ok(false),
        };
        let mut inner = self.shared.inner.lock().unwrap();
        if inner
            .controls
            .front()
            .is_none_or(|control| control.id != id)
        {
            return Ok(false);
        }
        let mut control = inner.controls.pop_front().unwrap();
        let malformed = result
            .as_ref()
            .is_ok_and(|reply| !expected(&control.command, reply));
        let result = if malformed {
            Err(Errno::EPROTO)
        } else {
            result
        };
        let mut reconciliation = None;
        match result {
            Ok(reply) => {
                match &reply {
                    Reply::Addresses(addrs) => control.snapshot.addresses = Some(addrs.clone()),
                    Reply::Mac(mac) => control.snapshot.mac = Some(*mac),
                    Reply::Routes(routes) => control.snapshot.routes = Some(routes.clone()),
                    _ => {}
                }
                if control.reply.is_none() {
                    control.snapshot.active = match control.operation {
                        Request::Bridge { .. } => Some(true),
                        Request::Unbridge => Some(false),
                        _ => None,
                    };
                    control.reply = Some(reply);
                }
            }
            Err(error) => {
                // Keep definite refusals exact. A malformed sent mutation is ambiguous;
                // a failed promised readback follows a known remote completion.
                if control.reply.is_some() || malformed && control.needs_reconciliation() {
                    reconciliation = Some(error);
                    control.snapshot.active_unknown = malformed && control.activity_ambiguous();
                }
                let completion = Completion {
                    result: Err(error),
                    snapshot: control.snapshot,
                    reconciliation,
                };
                drop(inner);
                (control.done)(completion);
                self.shared.wake.wake();
                return Ok(true);
            }
        }
        if let Some(command) = control.refresh.pop_front() {
            control.id = match inner.id() {
                Ok(id) => id,
                Err(error) => {
                    drop(inner);
                    (control.done)(Completion {
                        result: Err(error),
                        snapshot: control.snapshot,
                        reconciliation: Some(error),
                    });
                    return Ok(true);
                }
            };
            control.command = command;
            control.sent = false;
            inner.controls.push_front(control);
            drop(inner);
            self.shared.wake.wake();
            return Ok(true);
        }
        // The next transaction stays queued until the callback atomically publishes Net state.
        // Driver::poll is single-owner and cannot process another control while this runs.
        drop(inner);
        (control.done)(Completion {
            result: Ok(control.reply.unwrap()),
            snapshot: control.snapshot,
            reconciliation: None,
        });
        self.shared.wake.wake();
        Ok(true)
    }
}
