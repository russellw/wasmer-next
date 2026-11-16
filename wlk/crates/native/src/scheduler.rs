//! Native TID to WLK task bookkeeping for ptrace births and exits.

use std::collections::{HashMap, VecDeque};

use wasixv2_syscalls::TaskId;

use crate::platform::BirthKind;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SpawnKind {
    Process,
    Thread,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct TaskRecord {
    pub task: TaskId,
    pub mm_id: u64,
    pub native_parent: Option<libc::pid_t>,
    pub exit_seen: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SpawnApproval {
    pub kind: SpawnKind,
    pub child_task: TaskId,
    pub returned_id: i32,
    pub child_tid: i32,
    pub native_args: [u64; 6],
    pub parent_mm: u64,
}

#[derive(Default)]
pub(super) struct Scheduler {
    tasks: HashMap<libc::pid_t, TaskRecord>,
    pending: HashMap<libc::pid_t, VecDeque<SpawnApproval>>,
    awaiting_exit: HashMap<libc::pid_t, SpawnApproval>,
}

impl Scheduler {
    pub(super) fn insert_root(&mut self, native: libc::pid_t, task: TaskId) {
        self.tasks.insert(
            native,
            TaskRecord {
                task,
                mm_id: native as u64,
                native_parent: None,
                exit_seen: false,
            },
        );
    }

    pub(super) fn task(&self, native: libc::pid_t) -> Option<TaskRecord> {
        self.tasks.get(&native).copied()
    }

    pub(super) fn approve(&mut self, parent: libc::pid_t, approval: SpawnApproval) {
        self.pending.entry(parent).or_default().push_back(approval);
    }

    pub(super) fn birth(
        &mut self,
        parent: libc::pid_t,
        child: libc::pid_t,
        event: BirthKind,
    ) -> Option<SpawnApproval> {
        let queue = self.pending.get_mut(&parent)?;
        let position = queue.iter().position(|approval| {
            matches!(
                (approval.kind, event),
                (SpawnKind::Thread, BirthKind::Clone)
                    | (SpawnKind::Process, BirthKind::Fork | BirthKind::Clone)
            )
        })?;
        let approval = queue.remove(position)?;
        if queue.is_empty() {
            self.pending.remove(&parent);
        }
        let mm_id = match approval.kind {
            SpawnKind::Thread => approval.parent_mm,
            SpawnKind::Process => child as u64,
        };
        self.tasks.insert(
            child,
            TaskRecord {
                task: approval.child_task,
                mm_id,
                native_parent: Some(parent),
                exit_seen: false,
            },
        );
        self.awaiting_exit.insert(parent, approval);
        Some(approval)
    }

    pub(super) fn syscall_exit(&mut self, native: libc::pid_t) -> Option<SpawnApproval> {
        self.awaiting_exit.remove(&native)
    }

    pub(super) fn failed_syscall(&mut self, native: libc::pid_t) -> Option<SpawnApproval> {
        let queue = self.pending.get_mut(&native)?;
        let approval = queue.pop_front()?;
        if queue.is_empty() {
            self.pending.remove(&native);
        }
        Some(approval)
    }

    pub(super) fn mark_exit(&mut self, native: libc::pid_t) -> Option<TaskRecord> {
        let task = self.tasks.get_mut(&native)?;
        task.exit_seen = true;
        Some(*task)
    }

    pub(super) fn remove(&mut self, native: libc::pid_t) -> Option<TaskRecord> {
        self.tasks.remove(&native)
    }

    pub(super) fn tasks(&self) -> impl Iterator<Item = (libc::pid_t, TaskRecord)> + '_ {
        self.tasks.iter().map(|(native, task)| (*native, *task))
    }

    pub(super) fn is_root(&self, native: libc::pid_t) -> bool {
        self.tasks
            .get(&native)
            .is_some_and(|task| task.native_parent.is_none())
    }

    pub(super) fn approval_from_request(
        kind: SpawnKind,
        child_task: TaskId,
        returned_id: i32,
        child_tid: i32,
        native_args: [u64; 6],
        parent_mm: u64,
    ) -> SpawnApproval {
        let mut args = native_args;
        args[0] &= !(libc::CLONE_PARENT_SETTID as u64
            | libc::CLONE_CHILD_SETTID as u64
            | libc::CLONE_CHILD_CLEARTID as u64);
        SpawnApproval {
            kind,
            child_task,
            returned_id,
            child_tid,
            native_args: args,
            parent_mm,
        }
    }
}
