use crate::control::ExecutionFault;
use crate::memory::UserMemory;
use std::sync::Mutex;
use wasixv2_abi::SiCode;

/// Host-only metadata copied from the exact completion selected by `waitid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitCompletion {
    /// The selected child's pid in the waiting caller's namespace.
    pub pid: u32,
    /// The same reason written to the caller's `siginfo`.
    pub code: SiCode,
    /// The same exit status or signal written to the caller's `siginfo`.
    pub status: i32,
    /// Execution provenance, never inferred from a fatal signal number.
    pub fault: Option<ExecutionFault>,
}

#[derive(Clone, Copy, Default)]
enum WaitCompletionState {
    #[default]
    Empty,
    One(WaitCompletion),
    Ambiguous,
}

/// A fresh, borrowed output for one wait call, with no process or kernel custody.
/// Repeated publication permanently makes the optional provenance unavailable.
#[derive(Default)]
pub struct WaitCompletionSlot(Mutex<WaitCompletionState>);

impl WaitCompletionSlot {
    /// Publishes once; duplicate publication invalidates the slot without a guest error.
    pub fn publish(&self, completion: WaitCompletion) {
        let mut state = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        *state = match *state {
            WaitCompletionState::Empty => WaitCompletionState::One(completion),
            WaitCompletionState::One(_) | WaitCompletionState::Ambiguous => {
                WaitCompletionState::Ambiguous
            }
        };
    }

    /// The one unambiguous completion after the wait returns, if the provider supplied it.
    pub fn get(&self) -> Option<WaitCompletion> {
        match *self.0.lock().unwrap_or_else(|poison| poison.into_inner()) {
            WaitCompletionState::One(completion) => Some(completion),
            WaitCompletionState::Empty | WaitCompletionState::Ambiguous => None,
        }
    }
}

/// Identifies a task (a thread, in Linux terms) inside one kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TaskId(pub u32);

/// The task making a syscall and the memory its pointers refer to.
pub struct Caller<'a> {
    task: TaskId,
    memory: &'a dyn UserMemory,
    dynamic_linker: Option<&'a dyn crate::DynamicLinker>,
    descriptors: Option<crate::DescriptorSet>,
    installations: Option<crate::DescriptorInstallations>,
    functions: Option<&'a dyn crate::FunctionOperations>,
    process_fork_allowed: bool,
    wait_completion: Option<&'a WaitCompletionSlot>,
}

impl<'a> Caller<'a> {
    pub fn new(task: TaskId, memory: &'a dyn UserMemory) -> Self {
        Self {
            task,
            memory,
            dynamic_linker: None,
            descriptors: None,
            installations: None,
            functions: None,
            process_fork_allowed: true,
            wait_completion: None,
        }
    }

    /// Attaches only the current import's borrowed engine capability. The kernel never
    /// retains it; ordinary callers and custom syscall implementations need not opt in.
    pub fn with_dynamic_linker(mut self, linker: &'a dyn crate::DynamicLinker) -> Self {
        self.dynamic_linker = Some(linker);
        self
    }

    pub fn dynamic_linker(&self) -> Option<&'a dyn crate::DynamicLinker> {
        self.dynamic_linker
    }

    /// Borrows function authority for this import; dispatch cannot retain it.
    pub fn with_functions(mut self, functions: &'a dyn crate::FunctionOperations) -> Self {
        self.functions = Some(functions);
        self
    }

    pub fn functions(&self) -> Option<&'a dyn crate::FunctionOperations> {
        self.functions
    }

    /// Execution-owned eligibility, captured before the kernel can create a child.
    pub fn with_process_fork_allowed(mut self, allowed: bool) -> Self {
        self.process_fork_allowed = allowed;
        self
    }

    pub fn process_fork_allowed(&self) -> bool {
        self.process_fork_allowed
    }

    pub fn task(&self) -> TaskId {
        self.task
    }

    /// Borrows a fresh output for this exact wait invocation through ordinary dispatch.
    pub fn with_wait_completion(mut self, slot: &'a WaitCompletionSlot) -> Self {
        self.wait_completion = Some(slot);
        self
    }

    /// The optional host-only completion output; the kernel must not retain the borrow.
    pub fn wait_completion(&self) -> Option<&'a WaitCompletionSlot> {
        self.wait_completion
    }

    pub fn memory(&self) -> &'a dyn UserMemory {
        self.memory
    }

    /// Every descriptor operand must resolve within this exact acquired set. Cloning the
    /// snapshot retains its files, never its descriptor table or current slot membership.
    pub fn with_descriptors(mut self, descriptors: &crate::DescriptorSet) -> Self {
        self.descriptors = Some(descriptors.clone());
        self
    }

    pub fn descriptors(&self) -> Option<&crate::DescriptorSet> {
        self.descriptors.as_ref()
    }

    pub fn with_descriptor_installations(mut self, plan: &crate::DescriptorInstallations) -> Self {
        self.installations = Some(plan.clone());
        self
    }

    pub fn descriptor_installations(&self) -> Option<&crate::DescriptorInstallations> {
        self.installations.as_ref()
    }
}

std::thread_local! {
    static CURRENT: std::cell::Cell<Option<TaskId>> = const { std::cell::Cell::new(None) };
}

/// The task whose syscall is being polled on this thread (Linux's `current`), for what learns of
/// a change far below the syscall that made it: fanotify reports who caused an event. `None`
/// outside any task's syscall, as for work the kernel does on its own.
pub fn current_task() -> Option<TaskId> {
    CURRENT.with(std::cell::Cell::get)
}

/// `future` run as `task`'s: while it is polled, [`current_task`] is `task`. The kernel's
/// syscall entry scopes each call, including calls from a vfork child on its parent's instance.
pub fn as_task<F: std::future::Future>(task: TaskId, future: F) -> AsTask<F> {
    AsTask {
        task,
        future: Box::pin(future),
    }
}

/// See [`as_task`]. Large syscall futures stay behind a stable, compact pointer.
pub struct AsTask<F> {
    task: TaskId,
    future: std::pin::Pin<Box<F>>,
}

impl<F: std::future::Future> std::future::Future for AsTask<F> {
    type Output = F::Output;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<F::Output> {
        struct Restore(Option<TaskId>);
        impl Drop for Restore {
            fn drop(&mut self) {
                CURRENT.with(|current| current.set(self.0));
            }
        }
        // Linux include/linux/sched.h:current names the executing task. Keep
        // that scope through nesting and restore it even when a poll unwinds.
        let _restore = Restore(CURRENT.with(|current| current.replace(Some(self.task))));
        self.future.as_mut().poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_completion_is_fresh_and_any_duplicate_permanently_invalidates_it() {
        let completion = WaitCompletion {
            pid: 7,
            code: SiCode::CLD_KILLED,
            status: 4,
            fault: Some(ExecutionFault::WasmTrap),
        };
        let slot = WaitCompletionSlot::default();
        assert_eq!(slot.get(), None);
        slot.publish(completion);
        assert_eq!(slot.get(), Some(completion));
        slot.publish(completion);
        assert_eq!(
            slot.get(),
            None,
            "even an identical second publication is ambiguous"
        );
        slot.publish(WaitCompletion {
            pid: 8,
            ..completion
        });
        assert_eq!(slot.get(), None, "ambiguity cannot be overwritten");
        assert_eq!(WaitCompletionSlot::default().get(), None);
    }

    #[test]
    fn a_task_is_current_only_while_its_run_is_polled() {
        assert_eq!(current_task(), None);
        let inner = as_task(TaskId(7), async { current_task() });
        let outer = as_task(TaskId(3), async move { (current_task(), inner.await) });
        let seen = futures_executor_block_on(outer);
        assert_eq!(seen, (Some(TaskId(3)), Some(TaskId(7))));
        assert_eq!(current_task(), None);
    }

    #[test]
    fn a_panicking_task_restores_the_outer_current_task() {
        let outer = as_task(TaskId(3), async {
            let panic = std::panic::catch_unwind(|| {
                futures_executor_block_on(as_task(TaskId(7), async {
                    assert_eq!(current_task(), Some(TaskId(7)));
                    panic!("guest operation failed");
                }));
            });
            assert!(panic.is_err());
            current_task()
        });
        let seen = futures_executor_block_on(outer);
        assert_eq!(current_task(), None);
        assert_eq!(seen, Some(TaskId(3)));
    }

    /// Polls a future that never waits to its end.
    fn futures_executor_block_on<F: std::future::Future>(future: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut future = std::pin::pin!(future);
        loop {
            if let std::task::Poll::Ready(out) = future.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }
}
