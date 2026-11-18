//! A package tree's commands, installed with `Machine::install_commands` and started with
//! `Machine::run_file` or `execve`, as hand-written guests.

#![recursion_limit = "256"]

use std::{
    collections::BTreeMap,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use wasixv2::{
    ByteSink, CommandDefaults, Compile, EmptySource, Engine, ExecError, Image, LoadError, Loader,
    LocalFuture, Machine, OwnedBuffer, ProcessConfig, RunError, Stdio,
};
use wasmer::Module;
use webc::v3::{
    ChecksumAlgorithm, SignatureAlgorithm, Timestamps,
    read::OwnedReader,
    write::{DirEntry, Directory, FileEntry, Writer},
};

const ENOEXEC: i32 = 8;
const ELOOP: i32 = 40;

#[derive(Default)]
struct Capture(Mutex<Vec<u8>>);

impl ByteSink for Capture {
    fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(data);
        Box::pin(async move { Ok(data.len()) })
    }
}

/// Prints its arguments, separated by spaces and ended by a newline, followed by `suffix`.
fn echo(suffix: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"
(module
  (import "wasixv2" "startup_size" (func $startup_size (result i32)))
  (import "wasixv2" "startup_get" (func $startup_get (param i32 i32) (result i32)))
  (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
  (import "wasixv2" "exit_group" (func $exit_group (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) " \n")
  (data (i32.const 16) "{suffix}")
  (func $strlen (param $p i32) (result i32) (local $n i32)
    (block $done (loop $next
      (br_if $done (i32.eqz (i32.load8_u (i32.add (local.get $p) (local.get $n)))))
      (local.set $n (i32.add (local.get $n) (i32.const 1)))
      (br $next)))
    (local.get $n))
  (func (export "_start") (local $argc i32) (local $i i32) (local $arg i32)
    (drop (call $startup_get (i32.const 1024) (call $startup_size)))
    (local.set $argc (i32.load (i32.const 1024)))
    (block $done (loop $next
      (br_if $done (i32.ge_u (local.get $i) (local.get $argc)))
      (if (local.get $i) (then (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1)))))
      (local.set $arg (i32.load (i32.add (i32.const 1028) (i32.shl (local.get $i) (i32.const 2)))))
      (drop (call $write (i32.const 1) (local.get $arg) (call $strlen (local.get $arg))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $next)))
    (drop (call $write (i32.const 1) (i32.const 1) (i32.const 1)))
    (drop (call $write (i32.const 1) (i32.const 16) (call $strlen (i32.const 16))))
    (call $exit_group (i32.const 0))
    unreachable))
"#
    ))
    .unwrap()
}

/// [`echo`] for WASI preview1, which the v1 compatibility ABI serves.
const V1_ECHO: &str = r#"
(module
  (import "wasi_snapshot_preview1" "args_sizes_get" (func $sizes (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_get" (func $args (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) " \n")
  (func $print (param $p i32) (param $len i32)
    (i32.store (i32.const 16) (local.get $p))
    (i32.store (i32.const 20) (local.get $len))
    (drop (call $fd_write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 24))))
  (func $strlen (param $p i32) (result i32) (local $n i32)
    (block $done (loop $next
      (br_if $done (i32.eqz (i32.load8_u (i32.add (local.get $p) (local.get $n)))))
      (local.set $n (i32.add (local.get $n) (i32.const 1)))
      (br $next)))
    (local.get $n))
  (func (export "_start") (local $i i32) (local $arg i32)
    (drop (call $sizes (i32.const 0) (i32.const 4)))
    (drop (call $args (i32.const 1024) (i32.const 2048)))
    (block $done (loop $next
      (br_if $done (i32.ge_u (local.get $i) (i32.load (i32.const 0))))
      (if (local.get $i) (then (call $print (i32.const 8) (i32.const 1))))
      (local.set $arg (i32.load (i32.add (i32.const 1024) (i32.shl (local.get $i) (i32.const 2)))))
      (call $print (local.get $arg) (call $strlen (local.get $arg)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $next)))
    (call $print (i32.const 9) (i32.const 1))
    (call $proc_exit (i32.const 0))))
"#;

/// Checks that `/bin/echo` is a regular `0755` file, prints the first four bytes of
/// `/usr/bin/echo`, then `execve`s `/bin/echo from-main`. Exits with the errno of a call that
/// failed, or 100 when the mode is wrong.
const MAIN: &str = r#"
(module
  (import "wasixv2" "statx" (func $statx (param i32 i32 i32 i32 i32) (result i32)))
  (import "wasixv2" "openat" (func $openat (param i32 i32 i32 i32) (result i32)))
  (import "wasixv2" "read" (func $read (param i32 i32 i32) (result i32)))
  (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
  (import "wasixv2" "execve" (func $execve (param i32 i32 i32) (result i32)))
  (import "wasixv2" "exit_group" (func $exit_group (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 16) "/bin/echo\00")
  (data (i32.const 32) "echo\00")
  (data (i32.const 48) "from-main\00")
  (data (i32.const 64) "\20\00\00\00\30\00\00\00\00\00\00\00")
  (data (i32.const 80) "/usr/bin/echo\00")
  (func $check (param $ret i32) (result i32)
    (if (i32.lt_s (local.get $ret) (i32.const 0))
      (then (call $exit_group (i32.sub (i32.const 0) (local.get $ret))) unreachable))
    (local.get $ret))
  (func (export "_start") (local $fd i32)
    ;; STATX_BASIC_STATS
    (drop (call $check (call $statx (i32.const -100) (i32.const 16) (i32.const 0) (i32.const 0x7ff) (i32.const 512))))
    ;; S_IFREG | 0755
    (if (i32.ne (i32.load16_u (i32.const 540)) (i32.const 0x81ed))
      (then (call $exit_group (i32.const 100)) unreachable))
    (local.set $fd (call $check (call $openat (i32.const -100) (i32.const 80) (i32.const 0) (i32.const 0))))
    (drop (call $write (i32.const 1) (i32.const 1024)
      (call $check (call $read (local.get $fd) (i32.const 1024) (i32.const 4)))))
    (call $exit_group (i32.sub (i32.const 0) (call $execve (i32.const 16) (i32.const 64) (i32.const 0))))
    unreachable))
"#;

fn commands(list: &[(&str, &[u8])]) -> Vec<(String, OwnedBuffer)> {
    list.iter()
        .map(|(name, image)| (name.to_string(), OwnedBuffer::from(image.to_vec())))
        .collect()
}

fn wat(source: &str) -> Vec<u8> {
    wat::parse_str(source).unwrap()
}

/// Runs `path` on `machine` with `args`, and returns its exit status and stdout.
async fn run_file(machine: &Machine, path: &str, args: &[&str]) -> (Result<i32, RunError>, String) {
    let stdout = Arc::new(Capture::default());
    let config = ProcessConfig {
        args: args.iter().map(|arg| arg.to_string()).collect(),
        env: Vec::new(),
        stdio: Stdio {
            stdin: Arc::new(EmptySource),
            stdout: stdout.clone(),
            stderr: Arc::new(Capture::default()),
        },
    };
    let status = machine.run_file(&Engine::default(), path, config).await;
    let out = String::from_utf8_lossy(&stdout.0.lock().unwrap()).into_owned();
    (status, out)
}

async fn machine_with(list: &[(&str, &[u8])]) -> Machine {
    let mut machine = Machine::new();
    machine.install_commands(commands(list)).await.unwrap();
    machine
}

fn execve_errno(status: Result<i32, RunError>) -> i32 {
    match status {
        Err(RunError::Execve { err, .. }) => err.raw_os_error().unwrap(),
        other => panic!("expected an execve failure, got {other:?}"),
    }
}

/// Runs `test` in a `LocalSet`, which the machine's host work needs.
async fn local<F: Future>(test: F) -> F::Output {
    tokio::task::LocalSet::new().run_until(test).await
}

#[tokio::test]
async fn a_command_is_an_executable_file_in_bin_and_usr_bin() {
    local(async {
        let machine = machine_with(&[("main", &wat(MAIN)), ("echo", &echo(""))]).await;
        let (status, out) = run_file(&machine, "/usr/bin/main", &["main"]).await;
        assert_eq!(out, "\0asmecho from-main\n");
        assert_eq!(status.unwrap(), 0);
    })
    .await;
}

struct HostEcho;

impl wasixv2::VirtualCommand for HostEcho {
    fn name(&self) -> &str {
        "host-echo"
    }

    fn run<'a>(
        &'a self,
        cx: wasixv2::CommandContext<'a>,
    ) -> LocalFuture<'a, wasixv2::CommandOutcome> {
        Box::pin(async move {
            let mut output = cx.args().join(&b' ');
            output.push(b'\n');
            cx.write_all(wasixv2_abi::Fd(1), &output).await.unwrap();
            wasixv2::CommandOutcome::Exit(42)
        })
    }
}

#[tokio::test]
async fn virtual_command_is_an_executable_file_and_survives_root_rebuild() {
    local(async {
        let command = Arc::new(HostEcho);
        let mut machine = Machine::builder()
            .command("/bin/echo", command.clone())
            .command("/usr/bin/echo", command.clone())
            .build();
        machine
            .install_commands(commands(&[
                ("main", &wat(MAIN)),
                ("echo", &echo("package")),
                ("script", b"#!/bin/echo -x\n"),
            ]))
            .await
            .unwrap();
        let (status, out) = run_file(&machine, "/bin/main", &["main"]).await;
        assert_eq!((status.unwrap(), out.as_str()), (42, "echo from-main\n"));
        let (status, out) = run_file(&machine, "/bin/script", &["script", "argument"]).await;
        assert_eq!(
            (status.unwrap(), out.as_str()),
            (42, "/bin/echo -x /bin/script argument\n")
        );

        // Duplicate paths fail at boot, before a kernel can start.
        let result = Machine::builder()
            .command("/bin/echo", command.clone())
            .command("/bin/echo", command)
            .try_build();
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::AlreadyExists);
    })
    .await;
}

#[tokio::test]
async fn virtual_command_copy_up_removes_dispatch() {
    local(async {
        use wasixv2_vfs::{Cred, Ctx, OpenHow};
        let machine = Machine::builder()
            .command("/bin/echo", Arc::new(HostEcho))
            .build();
        let vfs = machine.vfs();
        let root = vfs.root();
        let cx = Ctx {
            cred: &Cred::root(),
            root: &root,
            umask: 0,
            task: 0,
            leases: None,
        };
        let handle = vfs
            .open(
                &cx,
                &root,
                b"/bin/echo",
                &OpenHow {
                    flags: wasixv2_abi::OpenFlags::O_WRONLY,
                    mode: 0,
                    lookup: Default::default(),
                },
            )
            .await
            .unwrap();
        drop(handle);
        let (status, _) = run_file(&machine, "/bin/echo", &["echo"]).await;
        assert_eq!(execve_errno(status), ENOEXEC);
    })
    .await;
}

// The vfork, file actions, exec and wait sequence used by posix_spawn, with a
// directly exported vfork continuation in place of libc's longjmp wrapper.
const SPAWN_HOST_COMMAND: &str = r#"
(module
  (import "wasixv2" "openat" (func $open (param i32 i32 i32 i32) (result i32)))
  (import "wasixv2" "faccessat2" (func $access (param i32 i32 i32 i32) (result i32)))
  (import "wasixv2" "getdents64" (func $list (param i32 i32 i32) (result i32)))
  (import "wasixv2" "pipe2" (func $pipe (param i32 i32) (result i32)))
  (import "wasixv2" "dup3" (func $dup (param i32 i32 i32) (result i32)))
  (import "wasixv2" "close" (func $close (param i32) (result i32)))
  (import "wasixv2" "read" (func $read (param i32 i32 i32) (result i32)))
  (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
  (import "wasixv2" "clone" (func $clone (param i32 i32 i32 i32 i32) (result i32)))
  (import "wasixv2" "execve" (func $exec (param i32 i32 i32) (result i32)))
  (import "wasixv2" "waitid" (func $wait (param i32 i32 i32 i32 i32) (result i32)))
  (import "wasixv2" "exit_group" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 16) "/bin\00")
  (data (i32.const 32) "/bin/echo\00")
  (data (i32.const 64) "echo\00")
  (data (i32.const 80) "from-child\00")
  (data (i32.const 96) "\40\00\00\00\50\00\00\00\00\00\00\00")
  (tag $continued (param i32))
  (func (export "wasixv2_vfork_return") (param i32)
    (throw $continued (local.get 0)))
  (func $check (param $result i32) (result i32)
    (if (i32.lt_s (local.get $result) (i32.const 0))
      (then (call $exit (i32.sub (i32.const 0) (local.get $result))) unreachable))
    (local.get $result))
  (func (export "_start") (local $dir i32) (local $n i32) (local $at i32) (local $pid i32)
    (drop (call $check (call $access (i32.const -100) (i32.const 32) (i32.const 1) (i32.const 0))))
    (local.set $dir (call $check
      (call $open (i32.const -100) (i32.const 16) (i32.const 0) (i32.const 0))))
    (local.set $n (call $check (call $list (local.get $dir) (i32.const 256) (i32.const 512))))
    (local.set $at (i32.const 256))
    (block $found
      (loop $next
        (if (i32.ge_u (local.get $at) (i32.add (i32.const 256) (local.get $n)))
          (then (call $exit (i32.const 100)) unreachable))
        ;; linux_dirent64: DT_REG at 18 and the name at 19.
        (if (i32.and
          (i32.eq (i32.load8_u offset=18 (local.get $at)) (i32.const 8))
          (i32.eq (i32.load offset=19 (local.get $at)) (i32.const 0x6f686365)))
          (then (br $found)))
        (local.set $at (i32.add (local.get $at) (i32.load16_u offset=16 (local.get $at))))
        (br $next)))
    (drop (call $close (local.get $dir)))
    (drop (call $check (call $pipe (i32.const 128) (i32.const 0))))
    (block $parent (result i32)
      (try_table (catch $continued $parent)
        ;; CLONE_VM | CLONE_VFORK | SIGCHLD
        (drop (call $check (call $clone (i32.const 0x4111) (i32.const 0)
          (i32.const 0) (i32.const 0) (i32.const 0))))
        (drop (call $check (call $dup (i32.load (i32.const 132)) (i32.const 1) (i32.const 0))))
        (drop (call $close (i32.load (i32.const 128))))
        (drop (call $close (i32.load (i32.const 132))))
        (drop (call $check (call $exec (i32.const 32) (i32.const 96) (i32.const 0))))
        (call $exit (i32.const 101)))
      unreachable)
    (local.set $pid)
    (drop (call $close (i32.load (i32.const 132))))
    (local.set $n (call $check (call $read (i32.load (i32.const 128)) (i32.const 256) (i32.const 80))))
    (drop (call $write (i32.const 1) (i32.const 256) (local.get $n)))
    ;; P_PID, WEXITED, and si_status in the returned siginfo.
    (drop (call $check (call $wait (i32.const 1) (local.get $pid)
      (i32.const 512) (i32.const 4) (i32.const 0))))
    (call $exit (i32.load (i32.const 532)))
    unreachable))
"#;

#[tokio::test]
async fn virtual_command_spawn_is_listed_and_uses_the_childs_redirected_stdio() {
    local(async {
        let mut machine = Machine::builder()
            .command("/bin/echo", Arc::new(HostEcho))
            .build();
        machine
            .install_commands(commands(&[("spawn", &wat(SPAWN_HOST_COMMAND))]))
            .await
            .unwrap();
        let (status, out) = run_file(&machine, "/bin/spawn", &["spawn"]).await;
        assert_eq!((status.unwrap(), out.as_str()), (42, "echo from-child\n"));
    })
    .await;
}

/// The first command of a name wins, as the resolver orders the tree: the root package's,
/// then its dependencies'.
#[tokio::test]
async fn the_first_command_of_a_name_wins() {
    local(async {
        let machine = machine_with(&[
            ("greet", &echo("root")),
            ("other", &echo("dependency")),
            ("greet", &echo("dependency")),
        ])
        .await;
        let (status, out) = run_file(&machine, "/bin/greet", &["greet"]).await;
        assert_eq!(out, "greet\nroot");
        assert_eq!(status.unwrap(), 0);
        let (_, out) = run_file(&machine, "/usr/bin/other", &["other"]).await;
        assert_eq!(out, "other\ndependency");
    })
    .await;
}

/// A command whose program is a script runs its interpreter, here another command: the
/// interpreter, its argument, the script's path, then the arguments after argv[0].
#[tokio::test]
async fn a_script_command_runs_its_interpreter() {
    local(async {
        let machine = machine_with(&[
            ("script", b"#!/usr/bin/echo  -x \nignored\n"),
            ("echo", &echo("")),
        ])
        .await;
        let (status, out) = run_file(&machine, "/bin/script", &["anything", "a", "b"]).await;
        assert_eq!(out, "/usr/bin/echo -x /bin/script a b\n");
        assert_eq!(status.unwrap(), 0);
    })
    .await;
}

#[tokio::test]
async fn a_script_may_name_a_wasix_v1_interpreter() {
    local(async {
        let machine =
            machine_with(&[("script", b"#!/bin/v1echo\n"), ("v1echo", &wat(V1_ECHO))]).await;
        let (status, out) = run_file(&machine, "/bin/script", &["script", "a"]).await;
        assert_eq!(out, "/bin/v1echo /bin/script a\n");
        assert_eq!(status.unwrap(), 0);
    })
    .await;
}

/// Five scripts may hand over in a row, as Linux's `exec_binprm` allows; a sixth is `ELOOP`.
/// Each level passes the previous interpreter's name as the script.
#[tokio::test]
async fn interpreters_nest_five_deep() {
    local(async {
        let machine = machine_with(&[
            ("s1", b"#!/bin/s2\n"),
            ("s2", b"#!/bin/s3\n"),
            ("s3", b"#!/bin/s4\n"),
            ("s4", b"#!/bin/s5\n"),
            ("s5", b"#!/bin/s6\n"),
            ("s6", b"#!/bin/echo\n"),
            ("echo", &echo("")),
        ])
        .await;
        let (status, out) = run_file(&machine, "/bin/s2", &["s2", "a"]).await;
        assert_eq!(out, "/bin/echo /bin/s6 /bin/s5 /bin/s4 /bin/s3 /bin/s2 a\n");
        assert_eq!(status.unwrap(), 0);
        let (status, out) = run_file(&machine, "/bin/s1", &["s1"]).await;
        assert_eq!(execve_errno(status), ELOOP);
        assert_eq!(out, "");
    })
    .await;
}

#[tokio::test]
async fn a_file_that_is_neither_wasm_nor_a_script_is_enoexec() {
    local(async {
        let machine = machine_with(&[("text", b"echo hi\n"), ("script", b"#!/bin/text\n")]).await;
        let (status, _) = run_file(&machine, "/bin/text", &["text"]).await;
        assert_eq!(execve_errno(status), ENOEXEC);
        let (status, _) = run_file(&machine, "/bin/script", &["script"]).await;
        assert_eq!(execve_errno(status), ENOEXEC);
    })
    .await;
}

/// `execve(argv[1], &argv[1], NULL)`; when that fails, prints `kept` and exits with the errno,
/// which shows that the caller's image survived.
const EXEC_ARG: &str = r#"
(module
  (import "wasixv2" "startup_size" (func $startup_size (result i32)))
  (import "wasixv2" "startup_get" (func $startup_get (param i32 i32) (result i32)))
  (import "wasixv2" "execve" (func $execve (param i32 i32 i32) (result i32)))
  (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
  (import "wasixv2" "exit_group" (func $exit_group (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "kept")
  (func (export "_start") (local $ret i32)
    (drop (call $startup_get (i32.const 1024) (call $startup_size)))
    (local.set $ret (call $execve (i32.load (i32.const 1032)) (i32.const 1032) (i32.const 0)))
    (drop (call $write (i32.const 1) (i32.const 0) (i32.const 4)))
    (call $exit_group (i32.sub (i32.const 0) (local.get $ret)))
    unreachable))
"#;

/// Images in no format the machine runs, by the name they are installed under: a module without imports of any ABI, a `wasix_64v1` module, a component and a module cut
/// off inside its import section.
fn unservable() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "bare",
            wat(r#"(module (memory (export "memory") 1) (func (export "_start")))"#),
        ),
        (
            "wa64",
            wat(
                r#"(module (import "wasix_64v1" "proc_exit" (func (param i32))) (func (export "_start")))"#,
            ),
        ),
        ("comp", b"\0asm\x0d\0\x01\0".to_vec()),
        ("trnc", b"\0asm\x01\0\0\0\x02\x7f\x01".to_vec()),
    ]
}

/// `execve` refuses an image no ABI or loader serves with `ENOEXEC` before the point of no
/// return, as Linux's `search_binary_handler` does: the caller goes on with its own image.
#[tokio::test]
async fn an_image_nothing_serves_fails_execve_with_enoexec() {
    local(async {
        let images = unservable();
        let mut list: Vec<(&str, &[u8])> = images.iter().map(|(n, i)| (*n, i.as_slice())).collect();
        let exec = wat(EXEC_ARG);
        list.push(("exec", &exec));
        let machine = machine_with(&list).await;
        for (name, _) in &images {
            let path = format!("/bin/{name}");
            let (status, out) = run_file(&machine, "/bin/exec", &["exec", &path]).await;
            assert_eq!((status.unwrap(), out.as_str()), (ENOEXEC, "kept"), "{name}");
            let (status, _) = run_file(&machine, &path, &[name]).await;
            assert_eq!(execve_errno(status), ENOEXEC, "{name}");
        }
    })
    .await;
}

/// Refuses every image with `EACCES`, as a format handler may.
struct Refusing;

impl Loader for Refusing {
    fn probe(&self, _header: &[u8]) -> Result<(), LoadError> {
        Err(LoadError::Format(wasixv2_syscalls::Errno::EACCES))
    }

    fn load<'a>(
        &'a self,
        engine: &'a Engine,
        image: &'a Image,
    ) -> LocalFuture<'a, Result<(Engine, Module), LoadError>> {
        Compile.load(engine, image)
    }
}

/// The loader's probe decides which images `execve` starts, and its errno is `execve`'s.
#[tokio::test]
async fn the_loader_probe_refuses_images_before_execve_commits() {
    local(async {
        let mut machine = Machine::builder().loader(Arc::new(Refusing)).build();
        machine
            .install_commands(commands(&[("echo", &echo(""))]))
            .await
            .unwrap();
        let (status, _) = run_file(&machine, "/bin/echo", &["echo"]).await;
        // EACCES
        assert_eq!(execve_errno(status), 13);
    })
    .await;
}

fn root_volume(tool: &'static [u8]) -> OwnedReader {
    let mut bin = BTreeMap::new();
    for name in ["tool", "echo"] {
        bin.insert(
            name.parse().unwrap(),
            DirEntry::File(FileEntry::borrowed(tool, Timestamps::default())),
        );
    }
    let mut root = BTreeMap::new();
    root.insert(
        "bin".parse().unwrap(),
        DirEntry::Dir(Directory::new(bin, Timestamps::default())),
    );
    let mut writer = Writer::new(ChecksumAlgorithm::Sha256)
        .write_manifest(&Default::default())
        .unwrap()
        .write_atoms(BTreeMap::new())
        .unwrap();
    writer
        .write_volume("root", Directory::new(root, Timestamps::default()))
        .unwrap();
    OwnedReader::parse(writer.finish(SignatureAlgorithm::None).unwrap()).unwrap()
}

/// Commands join a root volume's `/bin`, and hide its files of their names.
#[tokio::test]
async fn commands_merge_with_a_root_volume() {
    local(async {
        let tool: &'static [u8] = echo("volume").leak();
        let mut machine = Machine::new();
        machine
            .mount_root_lower(&root_volume(tool), "root")
            .await
            .unwrap();
        machine
            .install_commands(commands(&[("echo", &echo("command"))]))
            .await
            .unwrap();
        let (_, out) = run_file(&machine, "/bin/tool", &["tool"]).await;
        assert_eq!(out, "tool\nvolume");
        let (_, out) = run_file(&machine, "/bin/echo", &["echo"]).await;
        assert_eq!(out, "echo\ncommand");
    })
    .await;
}

#[tokio::test]
async fn names_that_are_no_file_names_are_refused() {
    local(async {
        for name in ["", ".", "..", "a/b", "a\0b"] {
            let err = Machine::new()
                .install_commands(commands(&[(name, b"")]))
                .await
                .unwrap_err();
            // EINVAL
            assert_eq!(err.raw_os_error(), Some(22), "{name:?}");
        }
        let long = "x".repeat(256);
        let err = Machine::new()
            .install_commands(commands(&[(long.as_str(), b"")]))
            .await
            .unwrap_err();
        // ENAMETOOLONG
        assert_eq!(err.raw_os_error(), Some(36));
    })
    .await;
}

/// Counts the images it compiles, and records whether each came shared by its filesystem.
#[derive(Default)]
struct Counting(AtomicUsize, Mutex<Vec<bool>>);

impl Loader for Counting {
    fn load<'a>(
        &'a self,
        engine: &'a Engine,
        image: &'a Image,
    ) -> LocalFuture<'a, Result<(Engine, Module), LoadError>> {
        self.0.fetch_add(1, Ordering::Relaxed);
        self.1.lock().unwrap().push(image.identity().is_some());
        Compile.load(engine, image)
    }
}

/// The loader compiles the image `run_file` starts and every image `execve` loads.
#[tokio::test]
async fn the_loader_compiles_every_image() {
    local(async {
        let loader = Arc::new(Counting::default());
        let mut machine = Machine::builder().loader(loader.clone()).build();
        machine
            .install_commands(commands(&[("main", &wat(MAIN)), ("echo", &echo(""))]))
            .await
            .unwrap();
        let (status, _) = run_file(&machine, "/bin/main", &["main"]).await;
        assert_eq!(status.unwrap(), 0);
        assert_eq!(loader.0.load(Ordering::Relaxed), 2);
        // Commands are package files: `execve` shares their bytes instead of copying them, so
        // a loader can tell them apart without reading them.
        assert_eq!(*loader.1.lock().unwrap(), [true, true]);
    })
    .await;
}

/// A module the probe takes that does not compile: wasm's header, then a cut-off import
/// section.
fn cut_off() -> Vec<u8> {
    let mut cut = echo("");
    cut.truncate(cut.len() - 8);
    cut
}

/// A module that compiles but cannot instantiate: it imports a function no ABI has.
const UNKNOWN_IMPORT: &str = r#"
(module
  (import "wasixv2" "no_such_call" (func))
  (memory (export "memory") 1)
  (func (export "_start")))
"#;

/// Past `execve`'s point of no return, an image the probe took that does not compile or
/// instantiate kills the process with SIGSEGV, as a corrupt ELF does on Linux.
#[tokio::test]
async fn an_execve_image_that_does_not_start_dies_of_sigsegv() {
    local(async {
        let (cut, unknown) = (cut_off(), wat(UNKNOWN_IMPORT));
        let exec = wat(EXEC_ARG);
        let list: [(&str, &[u8]); 3] = [("cut", &cut), ("unknown", &unknown), ("exec", &exec)];
        let machine = machine_with(&list).await;
        for path in ["/bin/cut", "/bin/unknown"] {
            let (status, out) = run_file(&machine, "/bin/exec", &["exec", path]).await;
            // 128 + SIGSEGV
            assert_eq!((status.unwrap(), out.as_str()), (139, ""), "{path}");
        }
    })
    .await;
}

/// The program `run_file` starts is the embedder's: when it does not compile or instantiate,
/// the run fails with the error, as `run_module` does, instead of reporting a SIGSEGV.
#[tokio::test]
async fn run_file_of_a_program_that_does_not_start_fails() {
    local(async {
        let (cut, unknown) = (cut_off(), wat(UNKNOWN_IMPORT));
        let machine = machine_with(&[("cut", &cut), ("unknown", &unknown)]).await;
        let (status, _) = run_file(&machine, "/bin/cut", &["cut"]).await;
        assert!(
            matches!(status, Err(RunError::Exec(ExecError::Load(_)))),
            "{status:?}"
        );
        let (status, _) = run_file(&machine, "/bin/unknown", &["unknown"]).await;
        assert!(
            matches!(status, Err(RunError::Exec(ExecError::Instantiate(_)))),
            "{status:?}"
        );
    })
    .await;
}

/// Prints its arguments as [`V1_ECHO`] does, then each environment string on a line.
const V1_SHOW: &str = r#"
(module
  (import "wasi_snapshot_preview1" "args_sizes_get" (func $sizes (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_get" (func $args (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "environ_sizes_get" (func $env_sizes (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "environ_get" (func $env (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) " \n")
  (func $print (param $p i32) (param $len i32)
    (i32.store (i32.const 16) (local.get $p))
    (i32.store (i32.const 20) (local.get $len))
    (drop (call $fd_write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 24))))
  (func $strlen (param $p i32) (result i32) (local $n i32)
    (block $done (loop $next
      (br_if $done (i32.eqz (i32.load8_u (i32.add (local.get $p) (local.get $n)))))
      (local.set $n (i32.add (local.get $n) (i32.const 1)))
      (br $next)))
    (local.get $n))
  (func (export "_start") (local $i i32) (local $arg i32)
    (drop (call $sizes (i32.const 0) (i32.const 4)))
    (drop (call $args (i32.const 1024) (i32.const 2048)))
    (block $done (loop $next
      (br_if $done (i32.ge_u (local.get $i) (i32.load (i32.const 0))))
      (if (local.get $i) (then (call $print (i32.const 8) (i32.const 1))))
      (local.set $arg (i32.load (i32.add (i32.const 1024) (i32.shl (local.get $i) (i32.const 2)))))
      (call $print (local.get $arg) (call $strlen (local.get $arg)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $next)))
    (call $print (i32.const 9) (i32.const 1))
    (drop (call $env_sizes (i32.const 0) (i32.const 4)))
    (drop (call $env (i32.const 1024) (i32.const 4096)))
    (local.set $i (i32.const 0))
    (block $done (loop $next
      (br_if $done (i32.ge_u (local.get $i) (i32.load (i32.const 0))))
      (local.set $arg (i32.load (i32.add (i32.const 1024) (i32.shl (local.get $i) (i32.const 2)))))
      (call $print (local.get $arg) (call $strlen (local.get $arg)))
      (call $print (i32.const 9) (i32.const 1))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $next)))
    (call $proc_exit (i32.const 0))))
"#;

/// A WASIX v1 program that runs `show user` through `proc_exec3`, searching the default path,
/// with the environment `A=caller`. Exits with 99 when the call returns.
const V1_EXEC_SHOW: &str = r#"
(module
  (import "wasix_32v1" "proc_exec3" (func $exec (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "show")
  (data (i32.const 16) "show\nuser")
  (data (i32.const 32) "A=caller")
  (func (export "_start")
    (drop (call $exec (i32.const 0) (i32.const 4) (i32.const 16) (i32.const 9)
      (i32.const 32) (i32.const 8) (i32.const 1) (i32.const 0) (i32.const 0)))
    (call $proc_exit (i32.const 99))))
"#;

fn show_defaults() -> CommandDefaults {
    CommandDefaults {
        argv0: Some("shown".into()),
        args: vec!["--main".into()],
        env: vec!["A=default".into(), "B=default".into(), "ignored".into()],
    }
}

/// A WASIX v1 program that starts a package command passes it the command's annotation, as v1
/// did: `exec-name` for argv[0], `main-args` after it, and `env` for names not set.
#[tokio::test]
async fn v1_programs_start_commands_with_their_defaults() {
    local(async {
        let mut machine =
            machine_with(&[("main", &wat(V1_EXEC_SHOW)), ("show", &wat(V1_SHOW))]).await;
        machine
            .set_wasix1_command_defaults([("show".to_string(), show_defaults())])
            .unwrap();
        let (status, out) = run_file(&machine, "/bin/main", &["main"]).await;
        assert_eq!(out, "shown --main user\nA=caller\nB=default\n");
        assert_eq!(status.unwrap(), 0);
    })
    .await;
}

/// [`V1_EXEC_SHOW`] with `./show`, which it does not search for.
const V1_EXEC_RELATIVE: &str = r#"
(module
  (import "wasix_32v1" "proc_exec3" (func $exec (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "./show")
  (data (i32.const 16) "show\nuser")
  (data (i32.const 32) "A=caller")
  (func (export "_start")
    (drop (call $exec (i32.const 0) (i32.const 6) (i32.const 16) (i32.const 9)
      (i32.const 32) (i32.const 8) (i32.const 0) (i32.const 0) (i32.const 0)))
    (call $proc_exit (i32.const 99))))
"#;

/// The defaults belong to the command's file, not to a path string: a v1 program in `/bin`
/// that starts `./show` passes them too, and one that starts another file does not.
#[tokio::test]
async fn v1_defaults_follow_the_file_whatever_names_it() {
    local(async {
        let mut machine = machine_with(&[
            ("main", &wat(V1_EXEC_RELATIVE)),
            ("show", &wat(V1_SHOW)),
            ("other", &wat(V1_SHOW)),
        ])
        .await;
        machine
            .set_wasix1_command_defaults([("other".to_string(), show_defaults())])
            .unwrap();
        machine.set_working_dir("/usr/bin");
        let (status, out) = run_file(&machine, "/bin/main", &["main"]).await;
        assert_eq!(out, "show user\nA=caller\n");
        assert_eq!(status.unwrap(), 0);

        let mut machine =
            machine_with(&[("main", &wat(V1_EXEC_RELATIVE)), ("show", &wat(V1_SHOW))]).await;
        machine
            .set_wasix1_command_defaults([("show".to_string(), show_defaults())])
            .unwrap();
        machine.set_working_dir("/usr/bin");
        let (status, out) = run_file(&machine, "/bin/main", &["main"]).await;
        assert_eq!(out, "shown --main user\nA=caller\nB=default\n");
        assert_eq!(status.unwrap(), 0);
    })
    .await;
}

/// The defaults are v1's: a native `execve` of the same command runs it as Linux runs any
/// file.
#[tokio::test]
async fn native_execve_ignores_the_v1_defaults() {
    local(async {
        let mut machine = machine_with(&[("main", &wat(MAIN)), ("echo", &echo(""))]).await;
        machine
            .set_wasix1_command_defaults([("echo".to_string(), show_defaults())])
            .unwrap();
        let (status, out) = run_file(&machine, "/bin/main", &["main"]).await;
        assert_eq!(out, "\0asmecho from-main\n");
        assert_eq!(status.unwrap(), 0);
    })
    .await;
}

/// Writes the target of `/proc/self/exe`.
const EXE: &str = r#"
(module
  (import "wasixv2" "readlinkat" (func $readlinkat (param i32 i32 i32 i32) (result i32)))
  (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
  (import "wasixv2" "exit_group" (func $exit_group (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "/proc/self/exe\00")
  (func (export "_start") (local $len i32)
    (local.set $len (call $readlinkat (i32.const -100) (i32.const 0) (i32.const 64) (i32.const 256)))
    (if (i32.lt_s (local.get $len) (i32.const 0))
      (then (call $exit_group (i32.sub (i32.const 0) (local.get $len))) unreachable))
    (drop (call $write (i32.const 1) (i32.const 64) (local.get $len)))
    (call $exit_group (i32.const 0))
    unreachable))
"#;

/// `/proc/self/exe` names the command's file, and for a script the interpreter's.
#[tokio::test]
async fn proc_self_exe_names_the_command() {
    local(async {
        let machine = machine_with(&[("exe", &wat(EXE)), ("script", b"#!/bin/exe\n")]).await;
        let (status, out) = run_file(&machine, "/usr/bin/exe", &["exe"]).await;
        assert_eq!((status.unwrap(), out.as_str()), (0, "/usr/bin/exe"));
        let (status, out) = run_file(&machine, "/usr/bin/script", &["script"]).await;
        assert_eq!((status.unwrap(), out.as_str()), (0, "/bin/exe"));
    })
    .await;
}

/// A program whose `execve` fails is gone, and the machine runs the next one.
#[tokio::test]
async fn a_failed_start_leaves_the_machine_usable() {
    local(async {
        let machine = machine_with(&[("echo", &echo(""))]).await;
        let (status, _) = run_file(&machine, "/bin/missing", &["missing"]).await;
        // ENOENT
        assert_eq!(execve_errno(status), 2);
        let (status, out) = run_file(&machine, "/bin/echo", &["echo", "ok"]).await;
        assert_eq!((status.unwrap(), out.as_str()), (0, "echo ok\n"));
    })
    .await;
}

/// A WASIX v1 program that writes `#!/bin/echo -x` to `/tmp/script` and runs it with
/// `proc_exec3`. v1 has no `chmod`, so the file it creates must be executable already.
const V1_WRITE_AND_RUN: &str = r##"
(module
  (import "wasi_snapshot_preview1" "path_open" (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_close" (func $fd_close (param i32) (result i32)))
  (import "wasix_32v1" "proc_exec3" (func $exec (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "tmp/script")
  (data (i32.const 16) "#!/bin/echo -x\n")
  (data (i32.const 48) "/tmp/script")
  (data (i32.const 64) "script\narg")
  (func $ok (param $code i32) (param $ret i32)
    (if (local.get $ret) (then (call $proc_exit (local.get $code)))))
  (func (export "_start")
    ;; path_open(3, follow, "tmp/script", CREAT|TRUNC, write) -> fd at 128
    (call $ok (i32.const 1) (call $path_open (i32.const 3) (i32.const 1) (i32.const 0) (i32.const 10)
      (i32.const 9) (i64.const 64) (i64.const 64) (i32.const 0) (i32.const 128)))
    (i32.store (i32.const 136) (i32.const 16))
    (i32.store (i32.const 140) (i32.const 15))
    (call $ok (i32.const 2) (call $fd_write (i32.load (i32.const 128)) (i32.const 136) (i32.const 1) (i32.const 144)))
    (call $ok (i32.const 3) (call $fd_close (i32.load (i32.const 128))))
    (drop (call $exec (i32.const 48) (i32.const 11) (i32.const 64) (i32.const 10)
      (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (call $proc_exit (i32.const 99))))
"##;

#[tokio::test]
async fn a_v1_program_runs_a_script_it_wrote() {
    local(async {
        let machine = machine_with(&[("main", &wat(V1_WRITE_AND_RUN)), ("echo", &echo(""))]).await;
        let (status, out) = run_file(&machine, "/bin/main", &["main"]).await;
        assert_eq!(out, "/bin/echo -x /tmp/script arg\n");
        assert_eq!(status.unwrap(), 0);
    })
    .await;
}

/// No commands add no layer under the root: the layers' limit is not used up by empty lists.
#[tokio::test]
async fn no_commands_add_no_layer() {
    local(async {
        let mut machine = Machine::new();
        for _ in 0..300 {
            machine.install_commands(commands(&[])).await.unwrap();
        }
        machine
            .install_commands(commands(&[("echo", &echo(""))]))
            .await
            .unwrap();
        let (status, out) = run_file(&machine, "/bin/echo", &["echo", "ok"]).await;
        assert_eq!((status.unwrap(), out.as_str()), (0, "echo ok\n"));
    })
    .await;
}

/// Handing out a `Signaller` fixes the root: it signals the kernel booted now.
#[tokio::test]
async fn the_root_is_fixed_once_a_signaller_is_handed_out() {
    local(async {
        let mut machine = Machine::new();
        let _signaller = machine.signaller();
        let err = machine
            .install_commands(commands(&[("echo", &echo(""))]))
            .await
            .unwrap_err();
        // EBUSY
        assert_eq!(err.raw_os_error(), Some(16));
    })
    .await;
}

/// Opens `/proc/2` and `/proc/3` and exits with 0 when neither exists, or the number of the
/// one that does; `/proc/1`, init, and `/proc/4`, its own, must exist (else 1 or 4).
const NO_PIDS_2_3: &str = r#"
(module
  (import "wasixv2" "openat" (func $openat (param i32 i32 i32 i32) (result i32)))
  (import "wasixv2" "exit_group" (func $exit_group (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 16) "/proc/2\00")
  (data (i32.const 32) "/proc/3\00")
  (data (i32.const 48) "/proc/4\00")
  (data (i32.const 64) "/proc/1\00")
  (func (export "_start")
    (if (i32.lt_s (call $openat (i32.const -100) (i32.const 64) (i32.const 0x10000) (i32.const 0)) (i32.const 0))
      (then (call $exit_group (i32.const 1))))
    (if (i32.lt_s (call $openat (i32.const -100) (i32.const 48) (i32.const 0x10000) (i32.const 0)) (i32.const 0))
      (then (call $exit_group (i32.const 4))))
    ;; O_RDONLY | O_DIRECTORY; anything but ENOENT means the process is there.
    (if (i32.ne (call $openat (i32.const -100) (i32.const 16) (i32.const 0x10000) (i32.const 0)) (i32.const -2))
      (then (call $exit_group (i32.const 2))))
    (if (i32.ne (call $openat (i32.const -100) (i32.const 32) (i32.const 0x10000) (i32.const 0)) (i32.const -2))
      (then (call $exit_group (i32.const 3))))
    (call $exit_group (i32.const 0))
    unreachable))
"#;

/// A process `run_file` started is gone once the run returns, whether its `execve` failed
/// (pid 2) or it ran and exited (pid 3): no zombie is left in `/proc`. Init (pid 1) stays.
#[tokio::test]
async fn run_file_leaves_no_zombie() {
    local(async {
        let check = wat(NO_PIDS_2_3);
        let machine = machine_with(&[("echo", &echo("")), ("check", &check)]).await;
        let (status, _) = run_file(&machine, "/bin/missing", &["missing"]).await;
        // ENOENT
        assert_eq!(execve_errno(status), 2);
        let (status, _) = run_file(&machine, "/bin/echo", &["echo"]).await;
        assert_eq!(status.unwrap(), 0);
        let (status, _) = run_file(&machine, "/bin/check", &["check"]).await;
        assert_eq!(status.unwrap(), 0);
    })
    .await;
}

#[cfg(feature = "resolved-packages")]
mod runtime_packages {
    use super::*;
    use wasixv2::{
        ResolvedCommand, ResolvedLayout, RuntimeCommandDefaults, RuntimePackage,
        RuntimePackageResolver,
    };
    use wasmer_config::package::{PackageHash, PackageId};
    use wasmer_package::{
        loader::LoadedPackage,
        resolver::{InMemorySource, PackageInfo, resolve},
    };

    async fn layout() -> ResolvedLayout {
        use std::collections::HashMap;
        let manifest = serde_json::from_value(serde_json::json!({
            "package": { "fs": [
                { "volume_name": "assets", "mount_path": "/" },
                { "volume_name": "assets", "mount_path": "/runtime-volume" },
                { "volume_name": "assets", "mount_path": "/tmp/hidden" }
            ]}
        }))
        .unwrap();
        let mut writer = Writer::new(ChecksumAlgorithm::Sha256)
            .write_manifest(&manifest)
            .unwrap()
            .write_atoms(BTreeMap::new())
            .unwrap();
        let volume = Directory::new(
            BTreeMap::from([(
                "runtime-marker".parse().unwrap(),
                DirEntry::File(FileEntry::borrowed(b"mounted", Timestamps::default())),
            )]),
            Timestamps::default(),
        );
        writer.write_volume("assets", volume).unwrap();
        let bytes = writer.finish(SignatureAlgorithm::None).unwrap();
        let container = wasmer_package::utils::from_bytes(bytes).unwrap();
        let id = PackageId::Hash(PackageHash::from_sha256_bytes([1; 32]));
        let info =
            PackageInfo::from_manifest(id.clone(), container.manifest(), container.version())
                .unwrap();
        let resolution = resolve(&id, &info, &InMemorySource::new()).await.unwrap();
        let loaded =
            LoadedPackage::from_containers(resolution, HashMap::from([(id, container)])).unwrap();
        let mut layout = ResolvedLayout::new(&loaded, false, None).unwrap();
        layout.override_commands(vec![ResolvedCommand {
            name: "echo".to_owned(),
            atom: OwnedBuffer::from(echo("package")),
            defaults: CommandDefaults::default(),
        }]);
        layout
    }

    struct Resolver(ResolvedLayout, AtomicUsize);

    impl Resolver {
        fn package(&self, identity: u8) -> RuntimePackage {
            RuntimePackage {
                identity: [identity; 32],
                layout: self.0.clone(),
                entrypoint: "echo".into(),
                defaults: RuntimeCommandDefaults {
                    argv0: Some("package-echo".into()),
                    args: vec!["first".into()],
                    env: Vec::new(),
                },
            }
        }
    }

    impl RuntimePackageResolver for Resolver {
        fn resolve<'a>(
            &'a self,
            specifier: &'a str,
        ) -> LocalFuture<'a, io::Result<RuntimePackage>> {
            Box::pin(async move {
                self.1.fetch_add(1, Ordering::Relaxed);
                match specifier {
                    "test/a" => Ok(self.package(1)),
                    "test/b" => Ok(self.package(2)),
                    _ => Err(io::ErrorKind::NotFound.into()),
                }
            })
        }

        fn resolve_local(&self, _: webc::Container) -> LocalFuture<'_, io::Result<RuntimePackage>> {
            Box::pin(async move { Ok(self.package(1)) })
        }
    }

    const V1_WASMER_RUN: &str = r#"
(module
  (import "wasix_32v1" "proc_exec3" (func $exec (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "wasmer")
  (data (i32.const 16) "wasmer\nrun\ntest/a\n--\nsecond")
  (func (export "_start")
    (drop (call $exec (i32.const 0) (i32.const 6) (i32.const 16) (i32.const 27)
      (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 0) (i32.const 0)))
    (call $exit (i32.const 99))))
"#;

    #[tokio::test]
    async fn wasmer_imports_at_original_paths_preserving_boot_content() {
        local(async {
            let resolver = Arc::new(Resolver(layout().await, AtomicUsize::new(0)));
            let mut machine = Machine::builder()
                .runtime_package_resolver(resolver.clone())
                .runtime_package_limit(1)
                .build();
            machine
                .install_commands(commands(&[
                    ("echo", &echo("boot")),
                    ("launcher", &wat(V1_WASMER_RUN)),
                ]))
                .await
                .unwrap();

            let (status, output) = run_file(&machine, "/bin/launcher", &["launcher"]).await;
            assert_eq!(status.unwrap(), 0);
            assert_eq!(output, "package-echo first second\npackage");

            for path in ["/bin/echo", "/usr/bin/echo"] {
                let (status, output) = run_file(&machine, path, &["echo"]).await;
                assert_eq!(status.unwrap(), 0);
                assert_eq!(output, "echo\nboot");
            }

            let source = resolver.package(1);
            let (package, duplicate) = tokio::join!(
                machine.import_runtime_package(&source),
                machine.import_runtime_package(&source),
            );
            for imported in [package.unwrap(), duplicate.unwrap()] {
                assert_eq!(imported.identity, [1; 32]);
                assert_eq!(imported.entrypoint, "/bin/echo");
                assert!(!imported.entrypoint_visible);
                assert_eq!(imported.hidden, ["/tmp/hidden"]);
            }
            for path in ["/runtime-marker", "/runtime-volume/runtime-marker"] {
                let data = guest_file(machine.vfs(), path).await.unwrap();
                assert!(
                    data.shared_contents().await.is_some(),
                    "WEBC-backed file at {path}"
                );
                let mut bytes = [0; 7];
                assert_eq!(data.read_at(&mut bytes, 0).await.unwrap(), bytes.len());
                assert_eq!(&bytes, b"mounted");
            }
            assert!(
                guest_file(machine.vfs(), "/tmp/hidden/runtime-marker")
                    .await
                    .is_err()
            );
            assert!(
                guest_file(machine.vfs(), "/run/wasmer/packages")
                    .await
                    .is_err()
            );
            let (status, _) = run_file(&machine, "/bin/wasmer", &["wasmer", "run", "test/b"]).await;
            assert_eq!(status.unwrap(), 1);
            assert_eq!(
                machine
                    .import_runtime_package(&resolver.package(2))
                    .await
                    .unwrap_err()
                    .raw_os_error(),
                Some(28),
            );
            let (status, _) = run_file(&machine, "/bin/wasmer", &["wasmer", "run", "test/a"]).await;
            assert_eq!(status.unwrap(), 0);
        })
        .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_import_leaves_a_persistent_upper_untouched() {
        use std::os::unix::fs::PermissionsExt;

        local(async {
            let upper = tempfile::tempdir().unwrap();
            let persistent_command = upper.path().join("bin/echo");
            std::fs::create_dir(upper.path().join("bin")).unwrap();
            let original = echo("persistent");
            std::fs::write(&persistent_command, &original).unwrap();
            std::fs::set_permissions(&persistent_command, std::fs::Permissions::from_mode(0o755))
                .unwrap();

            let resolver = Arc::new(Resolver(layout().await, AtomicUsize::new(0)));
            {
                let mut first = Machine::builder()
                    .runtime_package_resolver(resolver.clone())
                    .build();
                first.set_root_upper_host_dir(upper.path()).await.unwrap();
                let (status, _) =
                    run_file(&first, "/bin/wasmer", &["wasmer", "run", "test/a"]).await;
                assert_eq!(status.unwrap(), 0);
                for (path, expected) in [("/bin/echo", "persistent"), ("/usr/bin/echo", "package")]
                {
                    let (status, output) = run_file(&first, path, &["echo"]).await;
                    assert_eq!(status.unwrap(), 0);
                    assert_eq!(output, format!("echo\n{expected}"));
                }
                assert_eq!(std::fs::read(&persistent_command).unwrap(), original);
                assert!(!upper.path().join("usr/bin/echo").exists());
                assert!(!upper.path().join("runtime-marker").exists());
                assert!(!upper.path().join("runtime-volume").exists());
            }
            let mut second = Machine::builder()
                .runtime_package_resolver(resolver)
                .build();
            second.set_root_upper_host_dir(upper.path()).await.unwrap();
            let (status, output) = run_file(&second, "/bin/echo", &["echo"]).await;
            assert_eq!(status.unwrap(), 0);
            assert_eq!(output, "echo\npersistent");
            let (status, _) = run_file(&second, "/usr/bin/echo", &["echo"]).await;
            assert_eq!(execve_errno(status), 2);
        })
        .await;
    }

    async fn guest_file(
        vfs: &Arc<wasixv2_vfs::Vfs>,
        path: &str,
    ) -> wasixv2_vfs::PathResult<wasixv2_vfs::File> {
        use wasixv2_vfs::{Cred, Ctx, OpenHow};
        let root = vfs.root();
        let cx = Ctx {
            cred: &Cred::root(),
            root: &root,
            umask: 0,
            task: 0,
            leases: None,
        };
        vfs.open(
            &cx,
            &root,
            path.as_bytes(),
            &OpenHow {
                flags: wasixv2_abi::OpenFlags::O_RDONLY,
                mode: 0,
                lookup: wasixv2_vfs::LookupFlags::follow(),
            },
        )
        .await
    }

    #[tokio::test]
    async fn an_earlier_import_and_its_whiteouts_win_and_images_stay_shared() {
        local(async {
            let resolver = Arc::new(Resolver(layout().await, AtomicUsize::new(0)));
            let machine = Machine::builder()
                .runtime_package_resolver(resolver.clone())
                .loader(Arc::new(SharedLoader::default()))
                .build();
            let mut first = resolver.package(1);
            let first_atom = OwnedBuffer::from(echo("package"));
            first.layout.override_commands(vec![ResolvedCommand {
                name: "echo".into(),
                atom: first_atom.clone(),
                defaults: CommandDefaults::default(),
            }]);
            let visible = machine.import_runtime_package(&first).await.unwrap();
            assert!(visible.entrypoint_visible);
            let vfs = machine.vfs();
            let root = vfs.root();
            let cx = wasixv2_vfs::Ctx {
                cred: &wasixv2_vfs::Cred::root(),
                root: &root,
                umask: 0,
                task: 0,
                leases: None,
            };
            let keep = guest_file(vfs, "/runtime-marker").await.unwrap();
            vfs.unlink(&cx, &root, b"runtime-marker").await.unwrap();
            let mut later = resolver.package(2);
            later.layout.override_commands(vec![ResolvedCommand {
                name: "echo".into(),
                atom: OwnedBuffer::from(echo("later")),
                defaults: CommandDefaults::default(),
            }]);
            let hidden = machine.import_runtime_package(&later).await.unwrap();
            assert!(!hidden.entrypoint_visible);
            assert!(guest_file(vfs, "/runtime-marker").await.is_err());
            let mut bytes = [0; 7];
            assert_eq!(keep.read_at(&mut bytes, 0).await.unwrap(), 7);
            assert_eq!(&bytes, b"mounted");

            let visible = guest_file(vfs, "/bin/echo")
                .await
                .unwrap()
                .shared_contents()
                .await
                .unwrap();
            assert!(std::ptr::eq((*visible).as_ref(), first_atom.as_ref()));
            let (status, out) = run_file(&machine, "/bin/echo", &["echo"]).await;
            assert_eq!((status.unwrap(), out.as_str()), (0, "echo\npackage"));
            let (status, out) =
                run_file(&machine, "/bin/wasmer", &["wasmer", "run", "test/a"]).await;
            assert_eq!(
                (status.unwrap(), out.as_str()),
                (0, "package-echo first\npackage")
            );
        })
        .await;
    }

    #[derive(Default)]
    struct SharedLoader(Mutex<Option<wasixv2::ImageId>>);

    impl Loader for SharedLoader {
        fn load<'a>(
            &'a self,
            engine: &'a Engine,
            image: &'a Image,
        ) -> LocalFuture<'a, Result<(Engine, Module), LoadError>> {
            let id = image
                .identity()
                .expect("package atoms retain an image cache identity");
            let previous = self.0.lock().unwrap().replace(id);
            if let Some(previous) = previous {
                assert_eq!(id, previous, "a second exec uses the same byte identity");
            }
            Compile.load(engine, image)
        }
    }

    #[tokio::test]
    async fn the_default_runtime_import_limit_is_128_distinct_layouts() {
        local(async {
            let resolver = Arc::new(Resolver(layout().await, AtomicUsize::new(0)));
            let machine = Machine::builder()
                .runtime_package_resolver(resolver.clone())
                .build();
            let mut package = resolver.package(0);
            // Only commands here, so this covers the limit without hundreds of volume paths.
            let atom = OwnedBuffer::from(echo("package"));
            package.layout = ResolvedLayout::default();
            package.layout.override_commands(vec![ResolvedCommand {
                name: "echo".into(),
                atom,
                defaults: CommandDefaults::default(),
            }]);
            for id in 0..128 {
                package.identity = [id; 32];
                machine.import_runtime_package(&package).await.unwrap();
            }
            package.identity = [128; 32];
            assert_eq!(
                machine
                    .import_runtime_package(&package)
                    .await
                    .unwrap_err()
                    .raw_os_error(),
                Some(28)
            );
            package.identity = [127; 32];
            assert!(machine.import_runtime_package(&package).await.is_ok());
        })
        .await;
    }

    struct HeldInput(Mutex<tokio::sync::oneshot::Receiver<()>>);

    impl wasixv2::ByteSource for HeldInput {
        fn poll_read(
            &self,
            cx: &mut std::task::Context<'_>,
            _: &mut [u8],
        ) -> std::task::Poll<io::Result<usize>> {
            let mut rx = self.0.lock().unwrap();
            std::pin::Pin::new(&mut *rx).poll(cx).map(|_| Ok(0))
        }
    }

    const LIVE_CWD: &str = r#"
(module
  (import "wasixv2" "openat" (func $open (param i32 i32 i32 i32) (result i32)))
  (import "wasixv2" "read" (func $read (param i32 i32 i32) (result i32)))
  (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
  (import "wasixv2" "exit_group" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 128) "runtime-marker\00")
  (func (export "_start") (local $fd i32)
    (drop (call $write (i32.const 1) (i32.const 128) (i32.const 1)))
    (drop (call $read (i32.const 0) (i32.const 256) (i32.const 1)))
    (local.set $fd (call $open (i32.const -100) (i32.const 128) (i32.const 0) (i32.const 0)))
    (if (i32.lt_s (local.get $fd) (i32.const 0))
      (then (call $exit (i32.const 10)) unreachable))
    (drop (call $write (i32.const 1) (i32.const 256)
      (call $read (local.get $fd) (i32.const 256) (i32.const 7))))
    (call $exit (i32.const 0))
    unreachable))
"#;

    #[tokio::test]
    async fn a_running_guest_sees_imports_from_its_existing_cwd() {
        local(async {
            let resolver = Arc::new(Resolver(layout().await, AtomicUsize::new(0)));
            let mut machine = Machine::builder()
                .runtime_package_resolver(resolver.clone())
                .build();
            let layer = machine
                .commands_layer([("boot".to_owned(), OwnedBuffer::from(echo("boot")))])
                .unwrap()
                .unwrap();
            machine
                .mount_layer("/runtime-volume", &layer, false)
                .await
                .unwrap();
            machine.set_working_dir("/runtime-volume");
            let (tx, rx) = tokio::sync::oneshot::channel();
            let ready = Arc::new(tokio::sync::Notify::new());
            let printed = Arc::new(Capture::default());
            let output = Arc::new(wasixv2::FnSink({
                let (ready, printed) = (ready.clone(), printed.clone());
                move |bytes: &[u8]| {
                    printed.0.lock().unwrap().extend_from_slice(bytes);
                    ready.notify_one();
                }
            }));
            let wasm = wat(LIVE_CWD);
            let run = machine.run_process(
                &wasm,
                ProcessConfig {
                    args: Vec::new(),
                    env: Vec::new(),
                    stdio: Stdio {
                        stdin: Arc::new(HeldInput(Mutex::new(rx))),
                        stdout: output,
                        stderr: Arc::new(Capture::default()),
                    },
                },
            );
            let import = async {
                ready.notified().await;
                let result = machine
                    .import_runtime_package(&resolver.package(1))
                    .await
                    .unwrap();
                assert_eq!(result.hidden, ["/tmp/hidden"]);
                tx.send(()).unwrap();
            };
            let (status, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(run, import)
            })
            .await
            .unwrap();
            assert_eq!(status.unwrap(), 0);
            assert_eq!(&*printed.0.lock().unwrap(), b"rmounted");
        })
        .await;
    }

    #[derive(Default)]
    struct PendingResolver {
        entered: tokio::sync::Notify,
        dropped: std::sync::atomic::AtomicBool,
    }

    impl RuntimePackageResolver for PendingResolver {
        fn resolve<'a>(&'a self, _: &'a str) -> LocalFuture<'a, io::Result<RuntimePackage>> {
            Box::pin(async {
                struct DropFlag<'a>(&'a std::sync::atomic::AtomicBool);
                impl Drop for DropFlag<'_> {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::Relaxed);
                    }
                }
                let _guard = DropFlag(&self.dropped);
                self.entered.notify_one();
                std::future::pending().await
            })
        }
    }

    #[tokio::test]
    async fn killed_wasmer_drops_its_active_resolver() {
        local(async {
            let resolver = Arc::new(PendingResolver::default());
            let machine = Machine::builder()
                .runtime_package_resolver(resolver.clone())
                .build();
            let run = run_file(&machine, "/bin/wasmer", &["wasmer", "run", "test/a"]);
            let kill = async {
                resolver.entered.notified().await;
                machine.signal(wasixv2_abi::Signal::SIGKILL.0).unwrap();
            };
            let ((status, _), ()) =
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    tokio::join!(run, kill)
                })
                .await
                .unwrap();
            assert_eq!(status.unwrap(), 137);
            assert!(resolver.dropped.load(Ordering::Relaxed));
        })
        .await;
    }

    #[tokio::test]
    async fn disabled_machine_has_no_runtime_command_or_install() {
        local(async {
            let machine = Machine::new();
            let resolver = Resolver(layout().await, AtomicUsize::new(0));
            let (status, _) = run_file(&machine, "/bin/wasmer", &["wasmer", "run", "test/a"]).await;
            assert_eq!(execve_errno(status), 2);
            assert_eq!(
                machine
                    .import_runtime_package(&resolver.package(1))
                    .await
                    .unwrap_err()
                    .raw_os_error(),
                Some(95),
            );
        })
        .await;
    }

    #[tokio::test]
    async fn wasmer_checks_guest_files_before_registry() {
        local(async {
            let resolver = Arc::new(Resolver(layout().await, AtomicUsize::new(0)));
            let mut machine = Machine::builder()
                .runtime_package_resolver(resolver.clone())
                .build();
            let bytes = Writer::new(ChecksumAlgorithm::Sha256)
                .write_manifest(&webc::metadata::Manifest::default())
                .unwrap()
                .write_atoms(BTreeMap::new())
                .unwrap()
                .finish(SignatureAlgorithm::None)
                .unwrap();
            machine
                .install_commands(commands(&[
                    ("local.wasm", &echo("local")),
                    ("local.webc", &bytes),
                ]))
                .await
                .unwrap();
            let (status, output) = run_file(
                &machine,
                "/bin/wasmer",
                &["wasmer", "run", "/bin/local.wasm"],
            )
            .await;
            assert_eq!(status.unwrap(), 0);
            assert_eq!(output, "/bin/local.wasm\nlocal");
            let (status, output) = run_file(
                &machine,
                "/bin/wasmer",
                &["wasmer", "run", "/bin/local.webc"],
            )
            .await;
            assert_eq!(status.unwrap(), 0);
            assert_eq!(output, "package-echo first\npackage");
            assert_eq!(resolver.1.load(Ordering::Relaxed), 0);
        })
        .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn wasmer_falls_back_for_implicit_directories_but_checks_explicit_exec_permissions() {
        use std::os::unix::fs::PermissionsExt;

        local(async {
            let upper = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(upper.path().join("test/a")).unwrap();
            let wasm = upper.path().join("x.wasm");
            std::fs::write(&wasm, echo("local")).unwrap();
            std::fs::set_permissions(&wasm, std::fs::Permissions::from_mode(0o644)).unwrap();

            let resolver = Arc::new(Resolver(layout().await, AtomicUsize::new(0)));
            let mut machine = Machine::builder()
                .runtime_package_resolver(resolver.clone())
                .build();
            machine.set_root_upper_host_dir(upper.path()).await.unwrap();
            let (status, output) =
                run_file(&machine, "/bin/wasmer", &["wasmer", "run", "test/a"]).await;
            assert_eq!(status.unwrap(), 0);
            assert_eq!(output, "package-echo first\npackage");
            let (status, _) =
                run_file(&machine, "/bin/wasmer", &["wasmer", "run", "./x.wasm"]).await;
            assert_eq!(status.unwrap(), 126);
            assert_eq!(resolver.1.load(Ordering::Relaxed), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn wasmer_custom_registration_enforces_source_policy() {
        local(async {
            let resolver = Arc::new(Resolver(layout().await, AtomicUsize::new(0)));
            let mut machine = Machine::builder()
                .wasmer_command(wasixv2::WasmerCommandConfig {
                    resolver: resolver.clone(),
                    limit: 1,
                    allow_local: false,
                    paths: vec!["/usr/bin/guest-wasmer".into()],
                })
                .build();
            machine
                .install_commands(commands(&[("local.wasm", &echo("local"))]))
                .await
                .unwrap();
            let path = "/usr/bin/guest-wasmer";
            let (status, help) = run_file(&machine, path, &["wasmer", "--help"]).await;
            assert_eq!(status.unwrap(), 0);
            assert!(help.starts_with("Usage: wasmer run"));
            let (status, version) = run_file(&machine, path, &["wasmer", "--version"]).await;
            assert_eq!(status.unwrap(), 0);
            assert_eq!(version, format!("wasmer {}\n", wasmer_types::VERSION));
            for (args, code) in [
                (&["wasmer", "run"][..], 2),
                (&["wasmer", "run", "https://example.invalid/package"][..], 2),
                (&["wasmer", "run", "/bin/local.wasm"][..], 126),
                (&["wasmer", "run", "test/missing"][..], 127),
            ] {
                let (status, _) = run_file(&machine, path, args).await;
                assert_eq!(status.unwrap(), code);
            }
            assert_eq!(resolver.1.load(Ordering::Relaxed), 1);
        })
        .await;
    }
}
