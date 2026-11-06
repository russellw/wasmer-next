//! Ready bodies still run within syscall entry, including its cancellation scope.

use super::*;
use std::{
    cell::Cell,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use wasixv2_syscalls::{Layer, Layered, MaybeFuture, Syscall, SyscallRet, current_task};

struct EagerProbe {
    calls: Cell<usize>,
    pending: bool,
}
impl Layer<Kernel> for EagerProbe {
    fn call<'a>(
        &'a self,
        caller: &'a Caller<'_>,
        call: Syscall,
        next: &'a Kernel,
    ) -> MaybeFuture<'a, SysResult<SyscallRet>> {
        // Linux syscall_trace_enter ran before the selected body, with current set.
        assert_eq!(current_task(), Some(caller.task()));
        assert!(next.task_ref(caller.task(), |t| {
            t.syscall.lock_or_recover().current().is_some()
        }));
        assert!(matches!(call, Syscall::Getpid));
        self.calls.set(self.calls.get() + 1);
        if self.pending {
            MaybeFuture::Future(Box::pin(std::future::pending()))
        } else {
            MaybeFuture::Ready(Ok(SyscallRet::Getpid(42)))
        }
    }
}

#[test]
fn eager_ready_body_is_inside_entry_and_never_runs_at_construction() {
    let (kernel, task, _) = setup(b"");
    let memory = FlatMemory::default();
    let stack = Layered::new(
        SyscallEntry(EagerProbe {
            calls: Cell::new(0),
            pending: false,
        }),
        kernel,
    );
    let caller = Caller::new(task, &memory);
    let future = stack.getpid(&caller);
    assert_eq!(stack.layer.0.calls.get(), 0);
    assert_eq!(current_task(), None);
    assert_eq!(block_on(future), Ok(42));
    assert_eq!(stack.layer.0.calls.get(), 1);
    assert_eq!(current_task(), None);
    assert!(
        stack
            .inner
            .task_ref(task, |t| t.syscall.lock_or_recover().current().is_none())
    );
}

#[test]
fn cancelling_deferred_entry_clears_call_and_restores_current() {
    let (kernel, task, _) = setup(b"");
    let memory = FlatMemory::default();
    let stack = Layered::new(
        SyscallEntry(EagerProbe {
            calls: Cell::new(0),
            pending: true,
        }),
        kernel,
    );
    let caller = Caller::new(task, &memory);
    let mut future = stack.getpid(&caller);
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert_eq!(Pin::new(&mut future).poll(&mut cx), Poll::Pending);
    assert_eq!(current_task(), None);
    assert_eq!(stack.layer.0.calls.get(), 1);
    assert!(
        stack
            .inner
            .task_ref(task, |t| t.syscall.lock_or_recover().current().is_some())
    );
    drop(future);
    assert_eq!(current_task(), None);
    assert!(
        stack
            .inner
            .task_ref(task, |t| t.syscall.lock_or_recover().current().is_none())
    );
}

#[test]
fn non_lifo_same_call_records_cannot_clear_or_resurrect_a_sibling() {
    use crate::entry::{CallSlot, CurrentCall};
    let slot: CallSlot = Default::default();
    let info = crate::ptrace::CallInfo {
        nr: 172,
        args: [3; 6],
        ..Default::default()
    };
    let a = CurrentCall::new(slot.clone(), Some(info));
    a.install();
    let switch_a = CurrentCall::new(slot.clone(), None);
    switch_a.install();
    let b = CurrentCall::new(slot.clone(), Some(info));
    b.install();
    drop(switch_a);
    drop(a);
    assert_eq!(slot.lock_or_recover().current().unwrap().nr, 172);
    drop(b);
    assert!(slot.lock_or_recover().current().is_none());

    let a = CurrentCall::new(slot.clone(), Some(info));
    a.install();
    let b = CurrentCall::new(slot.clone(), Some(info));
    b.install();
    drop(a);
    assert!(
        slot.lock_or_recover().current().is_some(),
        "Info equality is not call identity"
    );
    drop(b);
    assert!(
        slot.lock_or_recover().current().is_none(),
        "dead weak parents must stay dead"
    );
}

#[derive(Default)]
struct HostProbe {
    constructed: Cell<usize>,
    polled: Cell<usize>,
    ready: Cell<bool>,
    constrain_on_poll: Cell<bool>,
}
impl Layer<Kernel> for HostProbe {
    fn call<'a>(
        &'a self,
        _: &'a Caller<'_>,
        _: Syscall,
        _: &'a Kernel,
    ) -> MaybeFuture<'a, SysResult<SyscallRet>> {
        panic!("a selected host lookup must not fall back to a guest syscall")
    }
    fn lookup_host<'a>(
        &'a self,
        caller: &'a Caller<'_>,
        _: &'a str,
        _: Option<u16>,
        next: &'a Kernel,
    ) -> Option<LocalFuture<'a, SysResult<Vec<std::net::IpAddr>>>> {
        self.constructed.set(self.constructed.get() + 1);
        Some(Box::pin(std::future::poll_fn(move |_| {
            assert_eq!(current_task(), Some(caller.task()));
            self.polled.set(self.polled.get() + 1);
            if self.constrain_on_poll.replace(false) {
                assert_eq!(
                    block_on(next.prctl(
                        caller,
                        wasixv2_abi::PrctlOption::PR_SET_SECCOMP,
                        1,
                        0,
                        0,
                        0
                    )),
                    Ok(0)
                );
            }
            if self.ready.get() {
                Poll::Ready(Ok(vec!["192.0.2.8".parse().unwrap()]))
            } else {
                Poll::Pending
            }
        })))
    }
}
fn constrain(kernel: &Kernel, caller: &Caller<'_>) {
    assert_eq!(
        block_on(kernel.prctl(caller, wasixv2_abi::PrctlOption::PR_SET_SECCOMP, 1, 0, 0, 0)),
        Ok(0)
    );
}
#[test]
fn host_lookup_entry_checks_before_construction_first_poll_and_pending_completion() {
    for when in 0..4 {
        let (kernel, task, _) = setup(b"");
        let stack = Layered::new(SyscallEntry(HostProbe::default()), kernel);
        let memory = FlatMemory::default();
        let caller = Caller::new(task, &memory);
        if when == 0 {
            constrain(&stack.inner, &caller);
            assert!(stack.lookup_host(&caller, "example.test", None).is_none());
            assert_eq!(stack.layer.0.constructed.get(), 0);
            continue;
        }
        let mut future = stack
            .lookup_host(&caller, "example.test", Some(443))
            .unwrap();
        assert_eq!(stack.layer.0.constructed.get(), 1);
        assert_eq!(
            stack.layer.0.polled.get(),
            0,
            "no provider work during construction"
        );
        let mut cx = Context::from_waker(std::task::Waker::noop());
        if when == 1 {
            constrain(&stack.inner, &caller);
        } else if when == 2 {
            assert_eq!(future.as_mut().poll(&mut cx), Poll::Pending);
            constrain(&stack.inner, &caller);
        } else {
            stack.layer.0.ready.set(true);
            stack.layer.0.constrain_on_poll.set(true);
        }
        assert_eq!(
            future.as_mut().poll(&mut cx),
            Poll::Ready(Err(SysErr::Errno(Errno::EPERM)))
        );
        assert_eq!(stack.layer.0.polled.get(), usize::from(when != 1));
        assert_eq!(current_task(), None);
    }
}
#[test]
fn host_lookup_entry_keeps_ever_traced_tasks_on_the_observable_wire_path() {
    let (kernel, task, _) = setup(b"");
    let stack = Layered::new(SyscallEntry(HostProbe::default()), kernel);
    let memory = super::proc::ForkableMemory(FlatMemory(RefCell::new(vec![0; 65536])));
    let caller = Caller::new(task, &memory);
    let mut selected = stack.lookup_host(&caller, "example.test", None).unwrap();
    let child = super::proc::fork_child(&stack.inner, &caller);
    let child_caller = Caller::new(child, &memory);
    assert_eq!(
        block_on(stack.inner.ptrace(
            &child_caller,
            wasixv2_abi::PtraceRequest::PTRACE_TRACEME,
            0,
            0,
            0
        )),
        Ok(0)
    );
    assert!(stack.inner.tracees.used());
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert_eq!(
        selected.as_mut().poll(&mut cx),
        Poll::Ready(Err(SysErr::Errno(Errno::EPERM)))
    );
    drop(selected);
    assert!(stack.lookup_host(&caller, "example.test", None).is_none());
    assert_eq!(stack.layer.0.polled.get(), 0);
}
