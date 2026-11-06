//! Per-process compat state: what v1 keeps about a process that Linux does not, keyed by pid.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock, Weak},
};

use wasixv2_syscalls::{DescriptorAttachment, DescriptorSet, Fd, TaskId};

use crate::calls;

/// The compat state of one process image. A new image (`execve`) gets a new one; threads share
/// it through the pid.
#[derive(Default)]
pub struct ProcState {
    /// Loaded on the process's first v1 call; see [`calls::startup::load`].
    pub(crate) startup: OnceLock<Arc<Startup>>,
    startup_input: Mutex<StartupPolicy>,
    pub(crate) lineage: Arc<()>,
    pub(crate) inherited_root: Option<Arc<RootPresentation>>,
    pub net: calls::sock::State,
    pub proc: calls::proc::State,
    pub(crate) clocks: calls::clock::State,
}

/// Explicit startup input for a host-owned v1 environment. Paths are Machine
/// paths; names are the bytes announced by fd_prestat_dir_name. An empty list
/// requests no preopened descriptors.
#[derive(Debug, Clone, Default)]
pub struct StartupInput {
    pub args: Vec<Vec<u8>>,
    pub env: Vec<Vec<u8>>,
    pub preopens: Vec<(Vec<u8>, Vec<u8>)>,
}

/// WASI rights installed on one explicitly configured preopen descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreopenRights {
    pub base: u64,
    pub inheriting: u64,
}

impl PreopenRights {
    /// The historical mask used by the ordinary startup-input setter.
    pub const ALL: Self = Self {
        base: crate::abi::fs::Rights::ALL.0,
        inheriting: crate::abi::fs::Rights::ALL.0,
    };

    /// Metadata for a preopen installed by a trusted namespace bootstrap.
    pub fn attachment(self) -> Result<DescriptorAttachment, wasixv2_abi::Errno> {
        if !self.is_valid() {
            return Err(wasixv2_abi::Errno::EINVAL);
        }
        Ok(DescriptorAttachment::new(crate::rights::Record {
            base: crate::abi::fs::Rights(self.base),
            inheriting: crate::abi::fs::Rights(self.inheriting),
            preopen: true,
            socket: false,
            legacy: None,
            cloexec: false,
        }))
    }

    pub fn named_attachment(self, name: &[u8]) -> Result<DescriptorAttachment, wasixv2_abi::Errno> {
        if !self.is_valid() || name.contains(&0) {
            return Err(wasixv2_abi::Errno::EINVAL);
        }
        Ok(DescriptorAttachment::new(crate::rights::Record {
            legacy: Some(Arc::new(crate::rights::LegacyObject {
                name: Arc::from(name),
                stdio: false,
            })),
            preopen: true,
            ..crate::rights::Record::new(
                crate::abi::fs::Rights(self.base),
                crate::abi::fs::Rights(self.inheriting),
            )
        }))
    }

    fn is_valid(self) -> bool {
        (self.base | self.inheriting) & !crate::abi::fs::Rights::ALL.0 == 0
    }
}

/// Already installed preopens and their captured provider identities. These
/// descriptors remain process-owned, including on concurrent startup loads.
#[derive(Clone)]
pub struct StartupDescriptors {
    pub descriptors: Vec<Fd>,
    pub binding: DescriptorSet,
    pub virtual_root: Option<Fd>,
}

#[derive(Clone)]
pub(crate) struct ConfiguredStartup {
    pub(crate) input: Arc<StartupInput>,
    pub(crate) rights: Option<Arc<[PreopenRights]>>,
    pub(crate) ready: Option<Arc<StartupDescriptors>>,
}

#[derive(Default, Clone)]
struct StartupPolicy {
    configured: Option<ConfiguredStartup>,
    sealed: bool,
    preserve_preopens: bool,
}

impl ProcState {
    /// Configures a host environment once, before its first startup load begins.
    /// This controls only v1 startup buffers and preopens, not kernel procfs data.
    pub fn set_startup_input(&self, input: StartupInput) -> Result<(), wasixv2_abi::Errno> {
        self.configure_startup_input(input, None, None)
    }

    /// Configures input and one rights pair per preopen in a single transaction.
    /// Base and inheriting rights are independent masks of known WASI rights.
    pub fn set_startup_input_with_preopen_rights(
        &self,
        input: StartupInput,
        rights: Vec<PreopenRights>,
    ) -> Result<(), wasixv2_abi::Errno> {
        self.configure_startup_input(input, Some(rights), None)
    }

    /// Announces existing captured descriptors without reopening path strings.
    pub(crate) fn set_startup_input_with_descriptors(
        &self,
        input: StartupInput,
        descriptors: StartupDescriptors,
    ) -> Result<(), wasixv2_abi::Errno> {
        self.configure_startup_input(input, None, Some(descriptors))
    }

    fn configure_startup_input(
        &self,
        input: StartupInput,
        rights: Option<Vec<PreopenRights>>,
        ready: Option<StartupDescriptors>,
    ) -> Result<(), wasixv2_abi::Errno> {
        let mut policy = self.startup_input.lock().unwrap();
        if policy.sealed || policy.configured.is_some() {
            return Err(wasixv2_abi::Errno::EBUSY);
        }
        if input
            .args
            .iter()
            .chain(&input.env)
            .any(|value| value.contains(&0))
            || input
                .preopens
                .iter()
                .any(|(path, name)| path.contains(&0) || name.contains(&0))
            || rights.as_ref().is_some_and(|rights| {
                rights.len() != input.preopens.len()
                    || rights.iter().any(|rights| !rights.is_valid())
            })
            || ready.as_ref().is_some_and(|ready| {
                let mut unique = std::collections::HashSet::new();
                ready.descriptors.len() != input.preopens.len()
                    || ready
                        .virtual_root
                        .is_some_and(|root| !ready.descriptors.contains(&root))
                    || ready.descriptors.iter().enumerate().any(|(index, &fd)| {
                        !unique.insert(fd)
                            || !ready.binding.get(fd).is_some_and(|entry| {
                                entry.present
                                    && entry
                                        .attachment
                                        .as_ref()
                                        .and_then(|attachment| {
                                            attachment.downcast_ref::<crate::rights::Record>()
                                        })
                                        .is_some_and(|record| {
                                            record.preopen
                                                && record.legacy.as_ref().is_none_or(|object| {
                                                    !object.stdio
                                                        && object.name.as_ref()
                                                            == input.preopens[index].1.as_slice()
                                                })
                                                && PreopenRights {
                                                    base: record.base.0,
                                                    inheriting: record.inheriting.0,
                                                }
                                                .is_valid()
                                        })
                            })
                    })
            })
        {
            return Err(wasixv2_abi::Errno::EINVAL);
        }
        if ready.is_some() {
            policy.sealed = true;
            policy.preserve_preopens = true;
        }
        policy.configured = Some(ConfiguredStartup {
            input: Arc::new(input),
            rights: rights.map(Arc::from),
            ready: ready.map(Arc::new),
        });
        Ok(())
    }

    pub(crate) fn seal_startup_input(&self) -> Option<ConfiguredStartup> {
        let mut policy = self.startup_input.lock().unwrap();
        policy.sealed = true;
        policy.configured.clone()
    }

    pub(crate) fn finish_preparation(&self) {
        let configured = self.startup_input.lock().unwrap().configured.take();
        drop(configured);
    }

    pub(crate) fn preserves_preopens(&self) -> bool {
        self.startup_input.lock().unwrap().preserve_preopens
    }

    fn next_image(&self) -> Self {
        let policy = self.startup_input.lock().unwrap();
        Self {
            lineage: self.lineage.clone(),
            inherited_root: self
                .startup
                .get()
                .and_then(|startup| startup.root.clone())
                .or_else(|| self.inherited_root.clone()),
            startup_input: Mutex::new(StartupPolicy {
                configured: None,
                sealed: policy.sealed,
                preserve_preopens: policy.preserve_preopens,
            }),
            ..Self::default()
        }
    }

    /// The state of a child that `fork` or `vfork` makes of this process: it has the same
    /// descriptors, so it announces the same preopens and keeps what the families know about
    /// them (epoll data and socket timeouts), and the same arguments,
    /// dispositions and terminal.
    pub fn fork(&self) -> Self {
        let startup = OnceLock::new();
        if let Some(loaded) = self.startup.get() {
            let _ = startup.set(loaded.clone());
        }
        Self {
            startup,
            startup_input: Mutex::new(self.startup_input.lock().unwrap().clone()),
            lineage: Arc::new(()),
            inherited_root: self.inherited_root.clone(),
            net: self.net.fork(),
            proc: self.proc.fork(),
            clocks: self.clocks.fork(),
        }
    }
}

/// What v1 reads once per image: the argument and environment strings, and the preopened
/// directories.
#[derive(Debug, Default)]
pub struct Startup {
    pub args: Vec<Vec<u8>>,
    pub env: Vec<Vec<u8>>,
    pub preopens: Vec<Preopen>,
    pub(crate) root: Option<Arc<RootPresentation>>,
}

#[derive(Debug)]
pub(crate) struct RootPresentation {
    pub(crate) root: FileId,
    pub(crate) entries: Vec<(Vec<u8>, u64)>,
}

/// A directory v1 announces through `fd_prestat_get`.
#[derive(Debug, Clone)]
pub struct Preopen {
    pub fd: Fd,
    /// The name `fd_prestat_dir_name` reports, such as `/`.
    pub name: Vec<u8>,
}

impl Startup {
    pub fn preopen(&self, fd: Fd) -> Option<&Preopen> {
        self.preopens.iter().find(|preopen| preopen.fd == fd)
    }
}

/// The compat state of every process that runs v1 code, by pid.
#[derive(Default)]
pub struct Procs {
    procs: Mutex<HashMap<TaskId, ProcEntry>>,
}

struct ProcEntry {
    current: Arc<ProcState>,
    host_owner: Weak<HostOwner>,
    lease: Option<Arc<()>>,
}
impl Default for ProcEntry {
    fn default() -> Self {
        Self {
            current: Arc::default(),
            host_owner: Weak::new(),
            lease: None,
        }
    }
}

/// The final owning host handle retires only this explicit registration.
pub(crate) struct HostOwner {
    procs: Weak<Procs>,
    task: TaskId,
}
impl Drop for HostOwner {
    fn drop(&mut self) {
        if let Some(procs) = self.procs.upgrade() {
            let removed = {
                let mut entries = procs.procs.lock().unwrap();
                let remove = entries.get_mut(&self.task).is_some_and(|entry| {
                    if entry.host_owner.as_ptr() != self as *const Self {
                        return false;
                    }
                    entry.host_owner = Weak::new();
                    entry.lease.is_none()
                });
                if remove {
                    entries.remove(&self.task)
                } else {
                    None
                }
            };
            drop(removed);
        }
    }
}

struct ProcessTransfer {
    procs: Arc<Procs>,
    task: TaskId,
    token: Arc<()>,
}
impl wasixv2_exec::ExecProcessLease for ProcessTransfer {}
impl Drop for ProcessTransfer {
    fn drop(&mut self) {
        let (removed, owner) = {
            let mut entries = self.procs.procs.lock().unwrap();
            let mut owner = None;
            let remove = entries.get_mut(&self.task).is_some_and(|entry| {
                if !entry
                    .lease
                    .as_ref()
                    .is_some_and(|lease| Arc::ptr_eq(lease, &self.token))
                {
                    return false;
                }
                entry.lease = None;
                owner = entry.host_owner.upgrade();
                owner.is_none()
            });
            (
                if remove {
                    entries.remove(&self.task)
                } else {
                    None
                },
                owner,
            )
        };
        drop(removed);
        drop(owner);
    }
}

/// The package commands v1 programs start with their [`CommandDefaults`], by the file each
/// command is. Keyed by the file rather than by a path, so a command started through any name
/// for it (`/bin/python`, `./python` in `/bin`, a symlink to it) gets its defaults, and a file
/// that only took a command's name does not. The embedder fills it once the files exist and
/// shares it with [`crate::Wasix1`].
#[derive(Debug, Default)]
pub struct Commands(HashMap<FileId, CommandDefaults>);

/// A file, as `statx` tells it: its device and inode number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileId {
    pub dev: (u32, u32),
    pub ino: u64,
}

impl Commands {
    /// Makes `file` a command v1 programs start with `defaults`; the first registration of a
    /// file wins.
    pub fn insert(&mut self, file: FileId, defaults: CommandDefaults) {
        self.0.entry(file).or_insert(defaults);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The defaults v1 programs that start `file` pass it.
    pub fn get(&self, file: FileId) -> Option<&CommandDefaults> {
        self.0.get(&file)
    }
}

/// What WASIX v1 adds when a v1 program starts a package command, from the command's `wasi`
/// annotation: v1 registered every command at `/bin/<name>` and `/usr/bin/<name>`, and starting
/// one of those paths applied it (`WasiEnv::prepare_spawn`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandDefaults {
    /// `exec-name`: replaces `argv[0]`.
    pub argv0: Option<String>,
    /// `main-args`: inserted after `argv[0]`, before the caller's arguments.
    pub args: Vec<String>,
    /// `env`: `NAME=value` strings, each added unless the environment already names `NAME`.
    pub env: Vec<String>,
}

impl CommandDefaults {
    /// `args` and `env` as v1 hands them to the command.
    pub fn apply(&self, args: &mut Vec<Vec<u8>>, env: &mut Vec<Vec<u8>>) {
        if let Some(argv0) = &self.argv0 {
            match args.first_mut() {
                Some(first) => *first = argv0.clone().into_bytes(),
                None => args.push(argv0.clone().into_bytes()),
            }
        }
        let at = args.len().min(1);
        args.splice(at..at, self.args.iter().map(|arg| arg.clone().into_bytes()));
        let name = |entry: &[u8]| entry.split(|&b| b == b'=').next().unwrap_or(entry).to_vec();
        let mut names: std::collections::HashSet<Vec<u8>> =
            env.iter().map(|entry| name(entry)).collect();
        // v1 skips a default without `=`.
        for default in self.env.iter().filter(|default| default.contains('=')) {
            if names.insert(name(default.as_bytes())) {
                env.push(default.clone().into_bytes());
            }
        }
    }
}

impl Procs {
    pub(crate) fn host_owner(self: &Arc<Self>, task: TaskId) -> Arc<HostOwner> {
        let mut entries = self.procs.lock().unwrap();
        let entry = entries.entry(task).or_default();
        if let Some(owner) = entry.host_owner.upgrade() {
            return owner;
        }
        let owner = Arc::new(HostOwner {
            procs: Arc::downgrade(self),
            task,
        });
        entry.host_owner = Arc::downgrade(&owner);
        owner
    }

    pub(crate) fn retain_process(
        self: &Arc<Self>,
        task: TaskId,
        expected: &Arc<ProcState>,
    ) -> Result<Box<dyn wasixv2_exec::ExecProcessLease>, wasmer::RuntimeError> {
        let token = Arc::new(());
        {
            let mut entries = self.procs.lock().unwrap();
            let entry = entries
                .get_mut(&task)
                .ok_or_else(|| wasmer::RuntimeError::new("process registration is missing"))?;
            if !Arc::ptr_eq(&entry.current, expected) {
                return Err(wasmer::RuntimeError::new(
                    "process image registration was replaced",
                ));
            }
            if entry.lease.is_some() {
                return Err(wasmer::RuntimeError::new(
                    "process registration already has execution custody",
                ));
            }
            entry.lease = Some(token.clone());
        }
        Ok(Box::new(ProcessTransfer {
            procs: self.clone(),
            task,
            token,
        }))
    }

    pub(crate) fn fork_child(
        self: &Arc<Self>,
        task: TaskId,
        state: Arc<ProcState>,
    ) -> Result<Box<dyn wasixv2_exec::ExecProcessLease>, wasmer::RuntimeError> {
        let token = Arc::new(());
        {
            let mut entries = self.procs.lock().unwrap();
            if entries.contains_key(&task) {
                return Err(wasmer::RuntimeError::new(
                    "fork child process registration already exists",
                ));
            }
            entries.insert(
                task,
                ProcEntry {
                    current: state,
                    host_owner: Weak::new(),
                    lease: Some(token.clone()),
                },
            );
        }
        Ok(Box::new(ProcessTransfer {
            procs: self.clone(),
            task,
            token,
        }))
    }

    pub(crate) fn next_image(&self, task: TaskId) -> Arc<ProcState> {
        let (old, current) = {
            let mut entries = self.procs.lock().unwrap();
            let entry = entries.entry(task).or_default();
            let next = Arc::new(entry.current.next_image());
            entry.lease = None;
            (std::mem::replace(&mut entry.current, next.clone()), next)
        };
        drop(old);
        current
    }

    pub(crate) fn owned_state(
        &self,
        task: TaskId,
        owner: &Arc<HostOwner>,
    ) -> Option<Arc<ProcState>> {
        self.procs
            .lock()
            .unwrap()
            .get(&task)
            .filter(|entry| Weak::ptr_eq(&entry.host_owner, &Arc::downgrade(owner)))
            .map(|entry| entry.current.clone())
    }

    /// The current compat state of a process.
    pub fn get_or_create(&self, task: TaskId) -> Arc<ProcState> {
        self.procs
            .lock()
            .unwrap()
            .entry(task)
            .or_default()
            .current
            .clone()
    }

    /// Adopts inherited fork state while preserving the child's registration owner.
    pub(crate) fn adopt(&self, task: TaskId, inherited: &ProcState) -> Arc<ProcState> {
        let (old, current) = {
            let mut entries = self.procs.lock().unwrap();
            let entry = entries.entry(task).or_default();
            let mut state = inherited.fork();
            state.lineage = entry.current.lineage.clone();
            let current = Arc::new(state);
            (
                std::mem::replace(&mut entry.current, current.clone()),
                current,
            )
        };
        drop(old);
        current
    }

    /// Starts an independent process registration, as a fresh fork/vfork child does.
    pub fn replace(&self, task: TaskId, state: Arc<ProcState>) {
        let old = self.procs.lock().unwrap().insert(
            task,
            ProcEntry {
                current: state,
                ..ProcEntry::default()
            },
        );
        drop(old);
    }

    /// Image cleanup cannot remove a process owned by a host or an execution lease.
    pub fn remove(&self, task: TaskId, state: &Arc<ProcState>) {
        let (removed, owner) = {
            let mut entries = self.procs.lock().unwrap();
            let owner = entries
                .get(&task)
                .and_then(|entry| entry.host_owner.upgrade());
            let remove = entries.get(&task).is_some_and(|entry| {
                Arc::ptr_eq(&entry.current, state) && entry.lease.is_none() && owner.is_none()
            });
            (if remove { entries.remove(&task) } else { None }, owner)
        };
        drop(removed);
        drop(owner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_execution_custody_outlives_the_old_image_and_releases_exact_successors() {
        let procs = Arc::new(Procs::default());
        let task = TaskId(41);
        let original = procs.get_or_create(task);
        original.set_startup_input(StartupInput::default()).unwrap();
        original.seal_startup_input();
        let original_lineage = original.lineage.clone();
        let lease = procs.retain_process(task, &original).unwrap();
        assert!(
            procs.retain_process(task, &original).is_err(),
            "never overwrite custody"
        );
        let weak = Arc::downgrade(&original);
        // The real runner drops its old image BEFORE binding its replacement.
        procs.remove(task, &original);
        drop(original);
        assert!(weak.upgrade().is_some());
        let next = procs.next_image(task);
        assert!(
            weak.upgrade().is_none(),
            "a transfer must not pin the obsolete state"
        );
        assert!(Arc::ptr_eq(&next.lineage, &original_lineage));
        assert_eq!(
            next.set_startup_input(StartupInput::default()),
            Err(wasixv2_abi::Errno::EBUSY)
        );
        let successor = procs.retain_process(task, &next).unwrap();
        drop(lease);
        assert!(Arc::ptr_eq(&procs.get_or_create(task), &next));
        let third = procs.next_image(task);
        let final_lease = procs.retain_process(task, &third).unwrap();
        drop(successor);
        procs.remove(task, &third);
        assert!(Arc::ptr_eq(&procs.get_or_create(task), &third));
        drop(final_lease);
        assert!(!Arc::ptr_eq(&procs.get_or_create(task), &third));
    }

    #[test]
    fn fork_adoption_preserves_child_execution_token_without_host_ownership() {
        let procs = Arc::new(Procs::default());
        let parent = TaskId(42);
        let child = TaskId(43);
        let host_owner = procs.host_owner(parent);
        let state = procs.get_or_create(parent);
        let initial_child = procs.next_image(child);
        let child_lineage = initial_child.lineage.clone();
        let child_lease = procs.retain_process(child, &initial_child).unwrap();
        let inherited = state.fork();
        let adopted = procs.adopt(child, &inherited);
        assert!(Arc::ptr_eq(&adopted.lineage, &child_lineage));
        assert!(!Arc::ptr_eq(&adopted.lineage, &state.lineage));
        assert!(procs.owned_state(child, &host_owner).is_none());
        assert!(
            procs.retain_process(child, &adopted).is_err(),
            "adoption retains the installed token"
        );
        procs.remove(child, &initial_child);
        procs.remove(child, &adopted);
        assert!(Arc::ptr_eq(&procs.get_or_create(child), &adopted));
        drop(child_lease);
        assert!(!Arc::ptr_eq(&procs.get_or_create(child), &adopted));
        assert!(Arc::ptr_eq(&procs.get_or_create(parent), &state));
        drop(host_owner);
        assert!(!Arc::ptr_eq(&procs.get_or_create(parent), &state));
    }

    #[test]
    fn retiring_host_owner_keeps_a_pending_transfer_until_cancellation_drops_it() {
        let procs = Arc::new(Procs::default());
        let task = TaskId(44);
        let first = procs.host_owner(task);
        let second = procs.host_owner(task);
        assert!(Arc::ptr_eq(&first, &second));
        let state = procs.get_or_create(task);
        let lease = procs.retain_process(task, &state).unwrap();
        drop(first);
        drop(second);
        assert!(Arc::ptr_eq(&procs.get_or_create(task), &state));
        procs.remove(task, &state);
        drop(lease);
        assert!(!Arc::ptr_eq(&procs.get_or_create(task), &state));
    }

    #[test]
    fn prepared_policy_releases_bootstrap_binding_and_keeps_only_immutable_exec_metadata() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Captured(Arc<AtomicUsize>);
        impl Drop for Captured {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicUsize::new(0));
        let state = ProcState::default();
        state
            .set_startup_input_with_descriptors(
                StartupInput {
                    preopens: vec![],
                    ..StartupInput::default()
                },
                StartupDescriptors {
                    descriptors: vec![],
                    binding: DescriptorSet::new(Captured(dropped.clone()), vec![]),
                    virtual_root: None,
                },
            )
            .unwrap();
        let root = Arc::new(RootPresentation {
            root: FileId {
                dev: (1, 2),
                ino: 3,
            },
            entries: vec![(b"opaque//alias".to_vec(), 7)],
        });
        state
            .startup
            .set(Arc::new(Startup {
                args: vec![b"old".to_vec()],
                env: vec![b"OLD=yes".to_vec()],
                root: Some(root.clone()),
                ..Startup::default()
            }))
            .unwrap();
        state.finish_preparation();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        let next = state.next_image();
        assert!(next.startup.get().is_none());
        assert!(next.seal_startup_input().is_none());
        assert!(Arc::ptr_eq(next.inherited_root.as_ref().unwrap(), &root));
        assert!(Arc::ptr_eq(&state.lineage, &next.lineage));
        assert!(next.preserves_preopens());
        assert_eq!(
            next.set_startup_input(StartupInput::default()),
            Err(wasixv2_abi::Errno::EBUSY)
        );
        let fork = next.fork();
        assert!(!Arc::ptr_eq(&next.lineage, &fork.lineage));
        assert!(Arc::ptr_eq(fork.inherited_root.as_ref().unwrap(), &root));
        assert_eq!(
            fork.set_startup_input(StartupInput::default()),
            Err(wasixv2_abi::Errno::EBUSY)
        );
    }

    #[test]
    fn host_ready_startup_keeps_order_bindings_and_presentation_in_one_forked_policy() {
        let root = PreopenRights::ALL.attachment().unwrap();
        let directory = PreopenRights {
            base: 1,
            inheriting: 2,
        }
        .attachment()
        .unwrap();
        // This unit only checks policy custody; provider identity is exercised by
        // the trusted namespace's guest tests, not this synthetic payload.
        let binding = DescriptorSet::new(
            (),
            vec![
                wasixv2_syscalls::Descriptor {
                    fd: Fd(3),
                    present: true,
                    attachment: Some(root.clone()),
                },
                wasixv2_syscalls::Descriptor {
                    fd: Fd(4),
                    present: true,
                    attachment: Some(directory),
                },
            ],
        );
        let state = ProcState::default();
        state
            .set_startup_input_with_descriptors(
                StartupInput {
                    preopens: vec![
                        (b"unused-root".to_vec(), b"/".to_vec()),
                        (b"unused-path".to_vec(), b"opaque//alias".to_vec()),
                    ],
                    ..StartupInput::default()
                },
                StartupDescriptors {
                    descriptors: vec![Fd(3), Fd(4)],
                    binding,
                    virtual_root: Some(Fd(3)),
                },
            )
            .unwrap();
        let child = state.fork();
        let configured = state.seal_startup_input().unwrap();
        let inherited = child.seal_startup_input().unwrap();
        assert!(Arc::ptr_eq(
            configured.ready.as_ref().unwrap(),
            inherited.ready.as_ref().unwrap()
        ));
        let ready = inherited.ready.unwrap();
        assert_eq!(ready.descriptors, [Fd(3), Fd(4)]);
        assert_eq!(inherited.input.preopens[1].1, b"opaque//alias");
        assert!(
            ready
                .binding
                .get(Fd(3))
                .unwrap()
                .attachment
                .as_ref()
                .unwrap()
                .ptr_eq(&root)
        );
    }

    #[test]
    fn host_ready_startup_rejects_uncaptured_descriptors_without_consuming_configuration() {
        let state = ProcState::default();
        let input = StartupInput {
            preopens: vec![(vec![], b"/".to_vec())],
            ..StartupInput::default()
        };
        let result = state.set_startup_input_with_descriptors(
            input,
            StartupDescriptors {
                descriptors: vec![Fd(3)],
                binding: DescriptorSet::new((), vec![]),
                virtual_root: Some(Fd(3)),
            },
        );
        assert_eq!(result, Err(wasixv2_abi::Errno::EINVAL));
        state.set_startup_input(StartupInput::default()).unwrap();
        assert!(state.seal_startup_input().unwrap().ready.is_none());
    }

    #[test]
    fn host_startup_input_rights_keep_their_index_and_fork_configuration() {
        let state = ProcState::default();
        let rights = vec![
            PreopenRights {
                base: crate::abi::fs::Rights::FD_READ.0,
                inheriting: crate::abi::fs::Rights::FD_WRITE.0,
            },
            PreopenRights {
                base: crate::abi::fs::Rights::PATH_OPEN.0,
                inheriting: 0,
            },
        ];
        state
            .set_startup_input_with_preopen_rights(
                StartupInput {
                    preopens: vec![
                        (b"/first".to_vec(), b"first".to_vec()),
                        (b"/second".to_vec(), b"second".to_vec()),
                    ],
                    ..StartupInput::default()
                },
                rights.clone(),
            )
            .unwrap();
        let child = state.fork();
        let input = state.seal_startup_input().unwrap();
        let child_input = child.seal_startup_input().unwrap();
        assert_eq!(input.rights.as_deref(), Some(rights.as_slice()));
        assert_eq!(child_input.rights.as_deref(), Some(rights.as_slice()));
        assert!(Arc::ptr_eq(&input.input, &child_input.input));
        let after_seal = state.fork().seal_startup_input().unwrap();
        assert_eq!(after_seal.rights.as_deref(), Some(rights.as_slice()));
        assert_eq!(
            child.set_startup_input_with_preopen_rights(StartupInput::default(), vec![]),
            Err(wasixv2_abi::Errno::EBUSY)
        );
    }

    #[test]
    fn host_startup_input_rights_reject_invalid_input_without_partial_configuration() {
        let one = StartupInput {
            preopens: vec![(b"/first".to_vec(), b"first".to_vec())],
            ..StartupInput::default()
        };
        for rights in [
            vec![],
            vec![PreopenRights::ALL; 2],
            vec![PreopenRights {
                base: 1 << 39,
                inheriting: 0,
            }],
            vec![PreopenRights {
                base: 0,
                inheriting: 1 << 39,
            }],
        ] {
            let state = ProcState::default();
            assert_eq!(
                state.set_startup_input_with_preopen_rights(one.clone(), rights),
                Err(wasixv2_abi::Errno::EINVAL)
            );
            // A failed masks validation must not consume the one configuration.
            state.set_startup_input(one.clone()).unwrap();
            let configured = state.seal_startup_input().unwrap();
            assert_eq!(configured.input.preopens, one.preopens);
            assert!(
                configured.rights.is_none(),
                "the old setter keeps ALL rights"
            );
        }
        let state = ProcState::default();
        let invalid = StartupInput {
            args: vec![b"invalid\0".to_vec()],
            ..one.clone()
        };
        assert_eq!(
            state.set_startup_input_with_preopen_rights(invalid, vec![PreopenRights::ALL]),
            Err(wasixv2_abi::Errno::EINVAL)
        );
        state
            .set_startup_input_with_preopen_rights(one, vec![PreopenRights::ALL])
            .unwrap();
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn host_startup_input_rights_are_sealed_with_the_matching_input() {
        for _ in 0..32 {
            let state = Arc::new(ProcState::default());
            let ready = Arc::new(std::sync::Barrier::new(2));
            let rights = PreopenRights {
                base: crate::abi::fs::Rights::FD_READ.0,
                inheriting: 0,
            };
            let configure = std::thread::spawn({
                let state = state.clone();
                let ready = ready.clone();
                move || {
                    ready.wait();
                    state.set_startup_input_with_preopen_rights(
                        StartupInput {
                            preopens: vec![(b"/configured".to_vec(), b"name".to_vec())],
                            ..StartupInput::default()
                        },
                        vec![rights],
                    )
                }
            });
            ready.wait();
            let configured = state.seal_startup_input();
            match configure.join().unwrap() {
                Ok(()) => {
                    let configured = configured.unwrap();
                    assert_eq!(
                        configured.input.preopens,
                        [(b"/configured".to_vec(), b"name".to_vec())]
                    );
                    assert_eq!(configured.rights.as_deref(), Some([rights].as_slice()));
                }
                Err(error) => {
                    assert_eq!(error, wasixv2_abi::Errno::EBUSY);
                    assert!(configured.is_none());
                }
            }
        }
    }

    #[test]
    fn host_startup_input_preserves_bytes_and_fork_configuration() {
        let state = ProcState::default();
        state
            .set_startup_input(StartupInput {
                args: vec![b"program".to_vec(), vec![0xff, b'x']],
                env: vec![vec![b'K', b'=', 0xfe]],
                preopens: vec![],
            })
            .unwrap();
        let child = state.fork();
        let input = child.seal_startup_input().unwrap();
        assert_eq!(input.input.args[1], [0xff, b'x']);
        assert_eq!(input.input.env[0], [b'K', b'=', 0xfe]);
        assert!(input.input.preopens.is_empty());
        assert!(input.rights.is_none());
        assert_eq!(
            child.set_startup_input(StartupInput::default()),
            Err(wasixv2_abi::Errno::EBUSY)
        );
        assert!(Arc::ptr_eq(
            &input.input,
            &state.seal_startup_input().unwrap().input
        ));

        let default = ProcState::default();
        assert!(default.seal_startup_input().is_none());
        assert_eq!(
            default.set_startup_input(StartupInput::default()),
            Err(wasixv2_abi::Errno::EBUSY)
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn host_startup_configuration_cannot_race_past_first_load() {
        for _ in 0..32 {
            let state = Arc::new(ProcState::default());
            let ready = Arc::new(std::sync::Barrier::new(2));
            let configure = std::thread::spawn({
                let state = state.clone();
                let ready = ready.clone();
                move || {
                    ready.wait();
                    state.set_startup_input(StartupInput {
                        args: vec![b"configured".to_vec()],
                        ..StartupInput::default()
                    })
                }
            });
            ready.wait();
            let input = state.seal_startup_input();
            match configure.join().unwrap() {
                Ok(()) => assert_eq!(input.unwrap().input.args, [b"configured".to_vec()]),
                Err(error) => {
                    assert_eq!(error, wasixv2_abi::Errno::EBUSY);
                    assert!(input.is_none());
                }
            }
        }
    }

    fn strings(list: &[&str]) -> Vec<Vec<u8>> {
        list.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    /// As `WasiEnv::prepare_spawn`: `exec-name` replaces argv[0], `main-args` go after it, and
    /// `env` fills in names the environment lacks, skipping entries without `=`.
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn command_defaults_apply_as_v1() {
        let defaults = CommandDefaults {
            argv0: Some("python3".into()),
            args: vec!["-I".into(), "/app/main.py".into()],
            env: vec!["HOME=/tmp".into(), "PATH=/bin".into(), "junk".into()],
        };
        let (mut args, mut env) = (strings(&["python", "x"]), strings(&["PATH=/usr/bin"]));
        defaults.apply(&mut args, &mut env);
        assert_eq!(args, strings(&["python3", "-I", "/app/main.py", "x"]));
        assert_eq!(env, strings(&["PATH=/usr/bin", "HOME=/tmp"]));

        let (mut args, mut env) = (Vec::new(), Vec::new());
        CommandDefaults {
            argv0: None,
            ..defaults.clone()
        }
        .apply(&mut args, &mut env);
        assert_eq!(args, strings(&["-I", "/app/main.py"]));
        let (mut args, mut env) = (Vec::new(), Vec::new());
        defaults.apply(&mut args, &mut env);
        assert_eq!(args, strings(&["python3", "-I", "/app/main.py"]));
    }
}
