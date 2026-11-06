//! Per-process compat state: what v1 keeps about a process that Linux does not, keyed by pid.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use wasixv2_syscalls::{Fd, TaskId};

use crate::calls;

/// The compat state of one process image. A new image (`execve`) gets a new one; threads share
/// it through the pid.
#[derive(Default)]
pub struct ProcState {
    /// Loaded on the process's first v1 call; see [`calls::startup::load`].
    pub(crate) startup: OnceLock<Arc<Startup>>,
    startup_input: Mutex<StartupPolicy>,
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
}

#[derive(Clone)]
pub(crate) struct ConfiguredStartup {
    pub(crate) input: Arc<StartupInput>,
    pub(crate) rights: Option<Arc<[PreopenRights]>>,
}

#[derive(Default, Clone)]
struct StartupPolicy {
    configured: Option<ConfiguredStartup>,
    sealed: bool,
}

impl ProcState {
    /// Configures a host environment once, before its first startup load begins.
    /// This controls only v1 startup buffers and preopens, not kernel procfs data.
    pub fn set_startup_input(&self, input: StartupInput) -> Result<(), wasixv2_abi::Errno> {
        self.configure_startup_input(input, None)
    }

    /// Configures input and one rights pair per preopen in a single transaction.
    /// Base and inheriting rights are independent masks of known WASI rights.
    pub fn set_startup_input_with_preopen_rights(
        &self,
        input: StartupInput,
        rights: Vec<PreopenRights>,
    ) -> Result<(), wasixv2_abi::Errno> {
        self.configure_startup_input(input, Some(rights))
    }

    fn configure_startup_input(
        &self,
        input: StartupInput,
        rights: Option<Vec<PreopenRights>>,
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
                    || rights.iter().any(|rights| {
                        (rights.base | rights.inheriting) & !crate::abi::fs::Rights::ALL.0 != 0
                    })
            })
        {
            return Err(wasixv2_abi::Errno::EINVAL);
        }
        policy.configured = Some(ConfiguredStartup {
            input: Arc::new(input),
            rights: rights.map(Arc::from),
        });
        Ok(())
    }

    pub(crate) fn seal_startup_input(&self) -> Option<ConfiguredStartup> {
        let mut policy = self.startup_input.lock().unwrap();
        policy.sealed = true;
        policy.configured.clone()
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
    procs: Mutex<HashMap<TaskId, Arc<ProcState>>>,
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
    /// The state of `pid`, created empty if the process has none yet (a vfork child before its
    /// parent's state was copied, a process whose image another ABI loaded).
    pub fn get_or_create(&self, pid: TaskId) -> Arc<ProcState> {
        self.procs.lock().unwrap().entry(pid).or_default().clone()
    }

    /// Starts `pid` over with `state`, as a new process image does.
    pub fn replace(&self, pid: TaskId, state: Arc<ProcState>) {
        self.procs.lock().unwrap().insert(pid, state);
    }

    /// Drops `pid`'s state if it still is `state`, when the image that made it ends.
    pub fn remove(&self, pid: TaskId, state: &Arc<ProcState>) {
        let mut procs = self.procs.lock().unwrap();
        if procs
            .get(&pid)
            .is_some_and(|current| Arc::ptr_eq(current, state))
        {
            procs.remove(&pid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
