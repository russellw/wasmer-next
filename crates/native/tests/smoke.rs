#![cfg(target_os = "linux")]

use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read, Write},
    net::{TcpListener, UdpSocket},
    os::unix::ffi::OsStrExt,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const RUN_TIMEOUT: Duration = Duration::from_secs(10);
const BUILD_TIMEOUT: Duration = Duration::from_secs(45);
static BUILT: OnceLock<()> = OnceLock::new();
static GLIBC_DYNAMIC_BUILT: OnceLock<()> = OnceLock::new();
static MUSL_DYNAMIC_BUILT: OnceLock<()> = OnceLock::new();
static TEMP_ID: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    fn kill(pid: libc::pid_t, sig: libc::c_int) -> libc::c_int;
}

struct TempPath(PathBuf);

impl TempPath {
    fn new(label: &str) -> Self {
        let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("wlk-native-{label}-{}-{id}", std::process::id())))
    }

    fn as_path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("wlk-native-{label}-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).expect("create temporary directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn build_fixtures() {
    BUILT.get_or_init(|| {
        let mut command = Command::new("bash");
        command.arg(fixtures_dir().join("build.sh"));
        let output = run_bounded(command, BUILD_TIMEOUT);
        assert!(
            output.status.success(),
            "fixture compilation failed (status {}):\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    });
}

fn run_bounded(mut command: Command, timeout: Duration) -> Output {
    command
        .process_group(0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = command.spawn().expect("spawn bounded command");
    let process_group = child.id() as libc::pid_t;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });

    match receiver.recv_timeout(timeout) {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => panic!("wait for bounded command: {error}"),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // The native runner's tracee inherits its process group. Kill both if the runner
            // hangs or exits while a tracee still holds one of the captured output pipes open.
            unsafe {
                let _ = kill(-process_group, 9);
            }
            let _ = receiver.recv_timeout(Duration::from_secs(2));
            panic!("command exceeded timeout of {timeout:?}: {command:?}");
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!("bounded command waiter disconnected"),
    }
}

fn run_guest(program: &Path, args: &[&OsStr], trace: bool) -> Output {
    run_guest_with_options(program, args, trace, &[])
}

fn run_guest_with_options(
    program: &Path,
    args: &[&OsStr],
    trace: bool,
    options: &[OsString],
) -> Output {
    build_fixtures();
    let mut command = Command::new(env!("CARGO_BIN_EXE_wlk-native"));
    if trace {
        command.arg("--trace");
    }
    command.args(options);
    command.arg(program);
    command.args(args);
    run_bounded(command, RUN_TIMEOUT)
}

fn fixture(name: &str) -> PathBuf {
    fixtures_dir().join(name)
}

fn build_dynamic_fixture(variant: &str, compiler: &OsStr) -> PathBuf {
    let (built, output_name) = match variant {
        "glibc" => (&GLIBC_DYNAMIC_BUILT, "glibc"),
        "musl" => (&MUSL_DYNAMIC_BUILT, "musl"),
        _ => panic!("unknown dynamic fixture variant {variant}"),
    };
    let output_dir = fixtures_dir().join("dynamic-libs").join(output_name);
    built.get_or_init(|| {
        build_dynamic_fixture_at(variant, compiler, &output_dir);
    });
    output_dir
}

fn build_dynamic_fixture_at(variant: &str, compiler: &OsStr, output_dir: &Path) {
    let mut command = Command::new("bash");
    command
        .arg(fixtures_dir().join("build-dynamic.sh"))
        .env("DYNAMIC_VARIANT", variant)
        .env("DYNAMIC_OUT", output_dir)
        .env("DYNAMIC_CC", compiler);
    let output = run_bounded(command, BUILD_TIMEOUT);
    assert!(
        output.status.success(),
        "{variant} dynamic fixture compilation failed (status {}):\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn available_compiler(compiler: &OsStr) -> bool {
    Command::new(compiler)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn glibc_compiler() -> Option<OsString> {
    let configured = std::env::var_os("DYNAMIC_GLIBC_CC").unwrap_or_else(|| OsString::from("gcc"));
    available_compiler(&configured).then_some(configured)
}

fn musl_compiler() -> Option<OsString> {
    if let Some(compiler) = std::env::var_os("MUSL_CC") {
        return available_compiler(&compiler).then_some(compiler);
    }
    [
        "musl-gcc",
        "x86_64-linux-musl-gcc",
        "x86_64-unknown-linux-musl-gcc",
    ]
    .iter()
    .map(OsString::from)
    .find(|compiler| available_compiler(compiler))
}

fn copy_tree(source: &Path, destination: &Path) -> io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&source_path, &destination_path)?;
        } else if entry.file_type()?.is_file() {
            fs::copy(&source_path, &destination_path)?;
        }
    }
    Ok(())
}

fn copy_file_to_root(root: &Path, source: &Path) -> io::Result<()> {
    let relative = source
        .strip_prefix("/")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let destination = root.join(relative);
    if destination.is_file() {
        return Ok(());
    }
    fs::create_dir_all(destination.parent().expect("destination has parent"))?;
    fs::copy(source, destination)?;
    Ok(())
}

fn stage_dynamic_runtime(root: &Path, dynamic_dir: &Path, program: &Path) {
    let interpreter = elf_interpreter(program)
        .expect("read dynamic fixture ELF interpreter")
        .expect("dynamic fixture has PT_INTERP");
    copy_file_to_root(root, &interpreter).unwrap_or_else(|error| {
        panic!(
            "copy ELF interpreter {} into guest root: {error}",
            interpreter.display()
        )
    });

    let manifest = fs::read_to_string(dynamic_dir.join("runtime-libraries"))
        .expect("dynamic fixture runtime library manifest");
    for line in manifest.lines() {
        let Some((_, path)) = line.split_once('=') else {
            continue;
        };
        let library = Path::new(path);
        if library.is_absolute() && library.is_file() {
            copy_file_to_root(root, library).unwrap_or_else(|error| {
                panic!(
                    "copy runtime library {} into guest root: {error}",
                    library.display()
                )
            });
        }
    }
}

fn elf_interpreter(path: &Path) -> io::Result<Option<PathBuf>> {
    let bytes = fs::read(path)?;
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not ELF64"));
    }
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    for index in 0..phnum {
        let offset = phoff
            .checked_add(index.checked_mul(phentsize).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "ELF program header overflow")
            })?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ELF offset overflow"))?;
        let header = bytes
            .get(offset..offset + phentsize)
            .filter(|header| header.len() >= 56)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated ELF header"))?;
        let kind = u32::from_le_bytes(header[..4].try_into().unwrap());
        if kind != 3 {
            continue;
        }
        let file_offset = u64::from_le_bytes(header[8..16].try_into().unwrap()) as usize;
        let file_size = u64::from_le_bytes(header[32..40].try_into().unwrap()) as usize;
        let name = bytes
            .get(file_offset..file_offset + file_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated PT_INTERP"))?;
        let name = name
            .strip_suffix(&[0])
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unterminated PT_INTERP"))?;
        return Ok(Some(PathBuf::from(OsStr::from_bytes(name))));
    }
    Ok(None)
}

fn assert_dynamic_smoke(output: &Output) {
    assert_success(output);
    assert_dynamic_smoke_text(&stdout(output));
}

fn assert_dynamic_smoke_text(text: &str) {
    let lines = text.lines().collect::<Vec<_>>();
    assert!(
        lines.len() >= 5,
        "dynamic fixture output was incomplete:\n{text}"
    );
    assert_eq!(&lines[..3], &["leaf-ctor", "middle-ctor", "plugin-ctor"]);
    assert!(
        lines.contains(&"dynamic=ok chain=42 tls=43 main_tls=5 plugin=86"),
        "main did not verify dependencies, TLS, and dlopen result:\n{text}"
    );
    assert!(
        lines.contains(&"plugin-dtor"),
        "plugin destructor did not run:\n{text}"
    );
}

fn assert_dynamic_load_trace(output: &Output) {
    let trace = stderr(output);
    assert!(
        trace.contains("Openat"),
        "dynamic loader did not open images through WLK:\n{trace}"
    );
    assert!(
        trace.contains("ThreadSpawn"),
        "dynamic pthread TLS fixture did not create a WLK thread:\n{trace}"
    );
    assert!(
        trace.contains("Futex"),
        "dynamic pthread join did not use WLK futex waits:\n{trace}"
    );
}

fn dynamic_root_and_volume_roundtrip(variant: &str, compiler: &OsStr) {
    let dynamic_dir = build_dynamic_fixture(variant, compiler);

    let root = TempDir::new(&format!("{variant}-dynamic-root"));
    let guest_tree = root.path().join("opt/wlk");
    copy_tree(&dynamic_dir, &guest_tree).expect("copy dynamic program into guest root");
    let guest_program = guest_tree.join("bin/dynamic_smoke");
    stage_dynamic_runtime(root.path(), &dynamic_dir, &guest_program);
    let root_options = vec![OsString::from("--root"), root.path().as_os_str().to_owned()];
    let plugin = [OsStr::new("/opt/wlk/lib/libdynamic_plugin.so")];
    let output = run_guest_with_options(&guest_program, &plugin, true, &root_options);
    assert_dynamic_smoke(&output);
    assert_dynamic_load_trace(&output);

    let root = TempDir::new(&format!("{variant}-dynamic-volume-root"));
    let volume = TempDir::new(&format!("{variant}-dynamic-volume"));
    copy_tree(&dynamic_dir, volume.path()).expect("copy dynamic program into mounted volume");
    let volume_program = volume.path().join("bin/dynamic_smoke");
    stage_dynamic_runtime(root.path(), &dynamic_dir, &volume_program);
    let volume_spec = format!("{}:/opt/wlk:ro", volume.path().display());
    let volume_options = vec![
        OsString::from("--root"),
        root.path().as_os_str().to_owned(),
        OsString::from("--volume"),
        OsString::from(volume_spec),
    ];
    let output = run_guest_with_options(&volume_program, &plugin, true, &volume_options);
    assert_dynamic_smoke(&output);
    assert_dynamic_load_trace(&output);
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("fixture stdout is UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "runner exited {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout(output),
        stderr(output),
    );
}

#[test]
fn static_elf_receives_argv_and_guest_exit_status() {
    let args = [OsStr::new("alpha"), OsStr::new("two words")];
    let output = run_guest(&fixture("argv"), &args, false);
    assert_success(&output);
    assert_eq!(stdout(&output), "argc=3\narg=alpha\narg=two words\n");

    let output = run_guest(&fixture("exit"), &[], false);
    assert_eq!(output.status.code(), Some(23), "{}", stderr(&output));
}

#[test]
fn getpid_is_routed_through_the_virtual_kernel() {
    let output = run_guest(&fixture("getpid"), &[], true);
    assert_success(&output);
    let pid: i32 = stdout(&output)
        .trim()
        .strip_prefix("pid=")
        .expect("getpid fixture output")
        .parse()
        .expect("numeric virtual PID");
    assert!(pid > 0);
    let trace = stderr(&output);
    assert!(
        trace.contains("Getpid"),
        "getpid was not traced through WLK:\n{trace}"
    );
    assert!(
        trace.contains(&format!("Getpid -> {pid}")),
        "trace/result mismatch:\n{trace}"
    );
}

#[test]
fn process_group_ids_are_virtualized_by_wlk() {
    let output = run_guest(&fixture("process_groups"), &[], true);
    assert_success(&output);
    assert_eq!(stdout(&output), "process-groups=ok\n");
    let trace = stderr(&output);
    assert!(
        trace.contains("Getpgid"),
        "getpgid/getpgrp were not routed through WLK:\n{trace}"
    );
    assert!(
        trace.contains("Setpgid"),
        "setpgid was not routed through WLK:\n{trace}"
    );
    assert!(
        trace.contains("Getsid"),
        "getsid was not routed through WLK:\n{trace}"
    );
}

#[test]
fn terminal_ioctl_reports_enotty_and_ebadf_through_wlk() {
    let output = run_guest(&fixture("tty_ioctl"), &[], true);
    assert_success(&output);
    assert_eq!(stdout(&output), "ioctl-errors=ENOTTY,EBADF,EBADF\n");
    let trace = stderr(&output);
    assert!(
        trace.contains("Ioctl"),
        "ioctl was not routed through WLK:\n{trace}"
    );
    assert!(
        !trace.contains("unsupported native syscall 16"),
        "ioctl still fell through to ENOSYS:\n{trace}"
    );
}

#[test]
fn raw_fd_operations_preserve_duplicate_offsets_and_dup2_same_fd() {
    let path = TempPath::new("fd-ops");
    let args = [path.as_path().as_os_str()];
    let output = run_guest(&fixture("fd_ops"), &args, true);
    assert_success(&output);
    assert_eq!(stdout(&output), "fd-ops=ok\n");
    assert_eq!(fs::read(path.as_path()).unwrap(), b"ABCD");

    let trace = stderr(&output);
    for syscall in ["Fcntl64", "Dup", "Dup3"] {
        assert!(
            trace.contains(syscall),
            "{syscall} was not routed through WLK:\n{trace}"
        );
    }
    assert!(
        !trace.contains("unsupported native syscall 33"),
        "dup2 fell through instead of using WLK validation:\n{trace}"
    );
}

#[test]
fn openat_read_write_and_close_use_the_wlk_filesystem() {
    let path = TempPath::new("raw-file");
    let args = [path.as_path().as_os_str()];
    let output = run_guest(&fixture("file_io"), &args, true);
    assert_success(&output);
    assert_eq!(stdout(&output), "wlk-native-file-fixture\n");
    assert_eq!(
        fs::read_to_string(path.as_path()).unwrap(),
        "wlk-native-file-fixture\n"
    );
    let trace = stderr(&output);
    assert!(
        trace.contains("Openat"),
        "openat was not routed through WLK:\n{trace}"
    );
    assert!(
        trace.contains("Read"),
        "read was not routed through WLK:\n{trace}"
    );
    assert!(
        trace.contains("Write"),
        "write was not routed through WLK:\n{trace}"
    );
    assert!(
        trace.contains("Close"),
        "close was not routed through WLK:\n{trace}"
    );
}

#[test]
fn unsupported_syscalls_return_enosys() {
    let output = run_guest(&fixture("unsupported_syscall"), &[], false);
    assert_success(&output);
    assert_eq!(stdout(&output), "unsupported=ENOSYS\n");
}

#[test]
fn invalid_guest_pointer_returns_efault() {
    let output = run_guest(&fixture("bad_pointer"), &[], false);
    assert_success(&output);
    assert_eq!(stdout(&output), "bad-pointer=EFAULT\n");
}

#[test]
fn pthread_create_and_join_run_through_the_wlk_scheduler() {
    if !has_musl_compiler() {
        eprintln!("skipping pthread fixture: no musl compiler found (set MUSL_CC to enable)");
        return;
    }
    let output = run_guest(&fixture("pthread"), &[], true);
    assert_success(&output);
    assert_eq!(stdout(&output), "pthread=41\n");
    let trace = stderr(&output);
    assert!(
        trace.contains("ThreadSpawn"),
        "thread creation was not routed through WLK:\n{trace}"
    );
    assert!(
        trace.contains("Futex"),
        "thread join did not use WLK futex waits:\n{trace}"
    );
}

#[test]
fn fork_wait_uses_virtual_child_ids_and_inherits_open_file_offsets() {
    if !has_musl_compiler() {
        eprintln!("skipping fork fixture: no musl compiler found (set MUSL_CC to enable)");
        return;
    }
    let path = TempPath::new("fork-offset");
    let args = [path.as_path().as_os_str()];
    let output = run_guest(&fixture("fork_wait"), &args, true);
    assert_success(&output);
    let text = stdout(&output);
    let child_pid: i32 = text
        .lines()
        .find_map(|line| line.strip_prefix("child-pid="))
        .expect("forked child's virtual PID")
        .parse()
        .expect("numeric child PID");
    assert!(child_pid > 0);
    assert!(text.ends_with("fork-wait=0 file=ABC\n"), "{text}");
    let trace = stderr(&output);
    assert!(
        trace.contains(&format!("Getpid -> {child_pid}")),
        "child PID did not come from WLK:\n{trace}"
    );
    assert!(
        trace.contains("Waitid"),
        "waitpid was not routed through WLK Waitid:\n{trace}"
    );
    assert!(
        trace.contains("Clone"),
        "fork was not routed through WLK:\n{trace}"
    );
    assert_eq!(fs::read_to_string(path.as_path()).unwrap(), "ABC");
}

#[test]
fn static_exec_replaces_the_guest_image_and_propagates_child_status() {
    if !has_musl_compiler() {
        eprintln!("skipping exec fixture: no musl compiler found (set MUSL_CC to enable)");
        return;
    }
    let child = fixture("exec_child");
    let args = [child.as_os_str()];
    let output = run_guest(&fixture("exec_parent"), &args, true);
    assert_eq!(output.status.code(), Some(29), "{}", stderr(&output));
    assert_eq!(stdout(&output), "exec-child=started\n");
    assert!(
        stderr(&output).contains("Execve"),
        "exec was not routed through WLK:\n{}",
        stderr(&output)
    );
}

#[test]
fn fork_can_exec_a_static_busybox_child() {
    if !has_musl_compiler() {
        eprintln!("skipping fork/exec fixture: no musl compiler found (set MUSL_CC to enable)");
        return;
    }
    let busybox = fixture("busybox");
    if !busybox.is_file() {
        eprintln!("skipping fork/BusyBox exec: build tests/fixtures/build-busybox.sh to enable");
        return;
    }
    let args = [busybox.as_os_str()];
    let output = run_guest(&fixture("fork_exec_busybox"), &args, true);
    assert_success(&output);
    assert_eq!(stdout(&output), "fork-exec=ok\nfork-exec-status=0\n");
    let trace = stderr(&output);
    assert!(
        trace.contains("Execve"),
        "BusyBox exec was not routed through WLK:\n{trace}"
    );
    assert!(
        trace.contains("Waitid"),
        "parent wait was not routed through WLK Waitid:\n{trace}"
    );
}

#[test]
fn private_file_mmap_survives_fd_close_without_changing_the_file() {
    let path = TempPath::new("mmap");
    fs::write(path.as_path(), b"mmap fixture\n").unwrap();
    let args = [path.as_path().as_os_str()];
    let output = run_guest(&fixture("file_mmap"), &args, false);
    assert_success(&output);
    assert_eq!(
        stdout(&output),
        "file-mmap=private-ok anon=ok zero=EINVAL\n"
    );
    assert_eq!(fs::read(path.as_path()).unwrap(), b"mmap fixture\n");
}

#[test]
fn shared_file_mmap_remains_unsupported() {
    let path = TempPath::new("mmap-shared");
    fs::write(path.as_path(), b"mmap fixture\n").unwrap();
    let args = [path.as_path().as_os_str()];
    let output = run_guest(&fixture("file_mmap_shared"), &args, false);
    assert_success(&output);
    assert_eq!(stdout(&output), "file-mmap-shared=ENOSYS\n");
}

fn has_musl_compiler() -> bool {
    if let Some(compiler) = std::env::var_os("MUSL_CC") {
        return Command::new(compiler)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
    }
    [
        "musl-gcc",
        "x86_64-linux-musl-gcc",
        "x86_64-unknown-linux-musl-gcc",
    ]
    .iter()
    .any(|compiler| {
        Command::new(compiler)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    })
}

#[test]
fn static_musl_libc_program_runs_when_a_musl_compiler_is_available() {
    if !has_musl_compiler() {
        eprintln!("skipping libc_smoke: no musl compiler found (set MUSL_CC to enable)");
        return;
    }

    let path = TempPath::new("libc-file");
    let args = [OsStr::new("two words"), path.as_path().as_os_str()];
    let output = run_guest(&fixture("libc_smoke"), &args, true);
    assert_success(&output);
    let text = stdout(&output);
    assert!(text.contains("libc-argv=two words\n"), "{text}");
    assert!(text.contains("libc-pid="), "{text}");
    assert!(text.contains("libc-file=wlk-native-libc-file\n"), "{text}");
    assert_eq!(
        fs::read_to_string(path.as_path()).unwrap(),
        "wlk-native-libc-file\n"
    );
}

#[test]
fn static_bash_redirections_preserve_files_offsets_and_stdio_when_fixtures_exist() {
    let bash = fixture("bash");
    let busybox = fixture("busybox");
    if !bash.is_file() || !busybox.is_file() {
        eprintln!("skipping Bash redirection test: build optional bash and BusyBox fixtures first");
        return;
    }

    let redirected = TempPath::new("bash-redirection");
    let input_copy = TempPath::new("bash-redirection-input");
    let hidden_stdout = TempPath::new("bash-redirection-restore");
    let shared_offset = TempPath::new("bash-redirection-offset");
    let pipeline_output = TempPath::new("bash-redirection-pipeline");
    let substitution_output = TempPath::new("bash-redirection-substitution");
    let script = r#"
printf 'stale\n' > "$1"
printf 'created\n' > "$1"
printf 'appended\n' >> "$1"
"$5" cat < "$1" > "$2"
exec 3>&1
printf 'hidden\n' > "$3"
printf 'stdout-restored\n' >&3
exec 3>&-
{ printf 'stderr-through-redirection\n' >&2; } 2>&1
exec 4>"$4"
printf A >&4
exec 5>&4
printf B >&5
printf C >&4
exec 4>&-
exec 5>&-
"$5" echo pipeline | "$5" cat > "$6"
substitution=$("$5" echo command-substitution)
printf '%s\n' "$substitution" > "$7"
"#;
    let args = [
        OsStr::new("--noprofile"),
        OsStr::new("--norc"),
        OsStr::new("-c"),
        OsStr::new(script),
        OsStr::new("bash"),
        redirected.as_path().as_os_str(),
        input_copy.as_path().as_os_str(),
        hidden_stdout.as_path().as_os_str(),
        shared_offset.as_path().as_os_str(),
        busybox.as_os_str(),
        pipeline_output.as_path().as_os_str(),
        substitution_output.as_path().as_os_str(),
    ];
    let output = run_guest(&bash, &args, true);
    assert_success(&output);
    assert_eq!(
        stdout(&output),
        "stdout-restored\nstderr-through-redirection\n"
    );
    assert_eq!(
        fs::read_to_string(redirected.as_path()).unwrap(),
        "created\nappended\n"
    );
    assert_eq!(
        fs::read_to_string(input_copy.as_path()).unwrap(),
        "created\nappended\n"
    );
    assert_eq!(
        fs::read_to_string(hidden_stdout.as_path()).unwrap(),
        "hidden\n"
    );
    assert_eq!(fs::read(shared_offset.as_path()).unwrap(), b"ABC");
    assert_eq!(
        fs::read_to_string(pipeline_output.as_path()).unwrap(),
        "pipeline\n"
    );
    assert_eq!(
        fs::read_to_string(substitution_output.as_path()).unwrap(),
        "command-substitution\n"
    );

    let trace = stderr(&output);
    for syscall in ["Openat", "Fcntl64", "Dup3", "Close", "Pipe2"] {
        assert!(
            trace.contains(syscall),
            "{syscall} redirection was not routed through WLK:\n{trace}"
        );
    }
}

#[test]
fn static_busybox_echo_and_cat_run_when_the_fixture_is_built() {
    let busybox = fixture("busybox");
    if !busybox.is_file() {
        eprintln!("skipping BusyBox probes: run tests/fixtures/build-busybox.sh to enable");
        return;
    }

    let echo_args = [OsStr::new("echo"), OsStr::new("hello from BusyBox")];
    let output = run_guest(&busybox, &echo_args, false);
    assert_success(&output);
    assert_eq!(stdout(&output), "hello from BusyBox\n");

    let path = TempPath::new("busybox-cat");
    fs::write(path.as_path(), b"BusyBox cat reads through WLK\n").unwrap();
    let cat_args = [OsStr::new("cat"), path.as_path().as_os_str()];
    let output = run_guest(&busybox, &cat_args, true);
    assert_success(&output);
    assert_eq!(stdout(&output), "BusyBox cat reads through WLK\n");
    let trace = stderr(&output);
    assert!(
        trace.contains("Openat"),
        "cat openat was not routed through WLK:\n{trace}"
    );
    assert!(
        trace.contains("Read"),
        "cat read was not routed through WLK:\n{trace}"
    );
}

#[test]
fn busybox_ls_mkdir_touch_cat_rm_and_rmdir_use_a_mapped_host_volume() {
    let busybox = fixture("busybox");
    if !busybox.is_file() {
        eprintln!(
            "skipping BusyBox filesystem probes: run tests/fixtures/build-busybox.sh to enable"
        );
        return;
    }
    let root = TempDir::new("busybox-root");
    let volume = TempDir::new("busybox-volume");
    let options = volume_options(&root, &volume, false);
    fs::write(
        volume.path().join("existing.txt"),
        b"mapped-volume-content\n",
    )
    .unwrap();

    let mkdir_args = [OsStr::new("mkdir"), OsStr::new("/mnt/newdir")];
    let output = run_guest_with_options(&busybox, &mkdir_args, true, &options);
    assert_success(&output);
    assert!(volume.path().join("newdir").is_dir());
    assert!(
        stderr(&output).contains("Mkdirat"),
        "mkdir was not routed through WLK:\n{}",
        stderr(&output)
    );

    let touch_args = [OsStr::new("touch"), OsStr::new("/mnt/existing.txt")];
    let output = run_guest_with_options(&busybox, &touch_args, true, &options);
    assert_success(&output);
    assert!(
        stderr(&output).contains("UtimensatTime64"),
        "touch was not routed through WLK:\n{}",
        stderr(&output)
    );

    let ls_args = [OsStr::new("ls"), OsStr::new("-l"), OsStr::new("/mnt")];
    let output = run_guest_with_options(&busybox, &ls_args, true, &options);
    assert_success(&output);
    assert!(
        stdout(&output).contains("existing.txt"),
        "{}",
        stdout(&output)
    );
    let trace = stderr(&output);
    assert!(
        trace.contains("Getdents64"),
        "ls did not use WLK directory reads:\n{trace}"
    );
    assert!(
        trace.contains("Statx"),
        "ls metadata did not use WLK stat translation:\n{trace}"
    );

    let cat_args = [OsStr::new("cat"), OsStr::new("/mnt/existing.txt")];
    let output = run_guest_with_options(&busybox, &cat_args, true, &options);
    assert_success(&output);
    assert_eq!(stdout(&output), "mapped-volume-content\n");
    assert!(
        stderr(&output).contains("Read"),
        "cat read was not routed through WLK:\n{}",
        stderr(&output)
    );

    let rm_args = [OsStr::new("rm"), OsStr::new("/mnt/existing.txt")];
    let output = run_guest_with_options(&busybox, &rm_args, true, &options);
    assert_success(&output);
    assert!(!volume.path().join("existing.txt").exists());
    assert!(
        stderr(&output).contains("Unlinkat"),
        "rm was not routed through WLK:\n{}",
        stderr(&output)
    );

    let rmdir_args = [OsStr::new("rmdir"), OsStr::new("/mnt/newdir")];
    let output = run_guest_with_options(&busybox, &rmdir_args, true, &options);
    assert_success(&output);
    assert!(!volume.path().join("newdir").exists());
    assert!(
        stderr(&output).contains("Unlinkat"),
        "rmdir was not routed through WLK:\n{}",
        stderr(&output)
    );
}

#[test]
fn busybox_ls_lists_entries_using_wlk_stat_translation() {
    let busybox = fixture("busybox");
    if !busybox.is_file() {
        eprintln!("skipping BusyBox ls: run tests/fixtures/build-busybox.sh to enable");
        return;
    }
    let root = TempDir::new("ls-root");
    let volume = TempDir::new("ls-volume");
    let options = volume_options(&root, &volume, false);
    fs::write(volume.path().join("listed.txt"), b"listed through WLK\n").unwrap();
    let args = [OsStr::new("ls"), OsStr::new("-l"), OsStr::new("/mnt")];
    let output = run_guest_with_options(&busybox, &args, true, &options);
    assert_success(&output);
    assert!(
        stdout(&output).contains("listed.txt"),
        "{}",
        stdout(&output)
    );
    let trace = stderr(&output);
    assert!(
        trace.contains("Getdents64"),
        "ls did not use WLK getdents64:\n{trace}"
    );
    assert!(
        trace.contains("Statx"),
        "ls stat calls were not routed through WLK:\n{trace}"
    );
}

fn volume_options(root: &TempDir, host: &TempDir, read_only: bool) -> Vec<OsString> {
    fs::create_dir_all(root.path().join("mnt")).expect("create guest mount target");
    let spec = if read_only {
        format!("{}:/mnt:ro", host.path().display())
    } else {
        format!("{}:/mnt", host.path().display())
    };
    vec![
        OsString::from("--root"),
        root.path().as_os_str().to_owned(),
        OsString::from("--volume"),
        OsString::from(spec),
    ]
}

#[test]
fn static_libc_filesystem_lifecycle_uses_wlk_vfs_and_a_host_volume() {
    if !has_musl_compiler() {
        eprintln!("skipping filesystem fixture: no musl compiler found (set MUSL_CC to enable)");
        return;
    }
    let root = TempDir::new("fs-root");
    let volume = TempDir::new("fs-volume");
    let options = volume_options(&root, &volume, false);
    let args = [OsStr::new("/mnt")];
    let output = run_guest_with_options(&fixture("fs_lifecycle"), &args, true, &options);
    assert_success(&output);
    assert_eq!(stdout(&output), "filesystem-lifecycle=ok\n");
    assert!(
        !volume.path().join("dir").exists(),
        "guest left the test directory behind"
    );
    let trace = stderr(&output);
    for syscall in [
        "Mkdirat",
        "Openat",
        "Write",
        "Read",
        "Statx",
        "Getdents64",
        "Renameat2",
        "Unlinkat",
    ] {
        assert!(
            trace.contains(syscall),
            "{syscall} was not routed through WLK:\n{trace}"
        );
    }
}

#[test]
fn read_only_volume_denies_mutation() {
    if !has_musl_compiler() {
        eprintln!(
            "skipping read-only volume fixture: no musl compiler found (set MUSL_CC to enable)"
        );
        return;
    }
    let root = TempDir::new("ro-root");
    let volume = TempDir::new("ro-volume");
    let options = volume_options(&root, &volume, true);
    let args = [OsStr::new("/mnt/new-file")];
    let output = run_guest_with_options(&fixture("volume_ro"), &args, false, &options);
    assert_success(&output);
    assert_eq!(stdout(&output), "readonly=denied\n");
    assert!(!volume.path().join("new-file").exists());
}

fn tcp_echo_server() -> (u16, thread::JoinHandle<io::Result<()>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind host TCP echo server");
    listener
        .set_nonblocking(true)
        .expect("set TCP listener nonblocking");
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(7);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut request = [0u8; 11];
        stream.read_exact(&mut request)?;
        if &request != b"tcp-request" {
            return Err(io::Error::other("unexpected TCP echo request"));
        }
        stream.write_all(b"tcp-reply")
    });
    (port, server)
}

fn udp_echo_server() -> (u16, thread::JoinHandle<io::Result<()>>) {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind host UDP echo server");
    socket
        .set_read_timeout(Some(Duration::from_secs(7)))
        .expect("set UDP receive timeout");
    let port = socket.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let mut request = [0u8; 64];
        let (len, peer) = socket.recv_from(&mut request)?;
        if &request[..len] != b"udp-request" {
            return Err(io::Error::other("unexpected UDP echo request"));
        }
        socket.send_to(b"udp-reply", peer)?;
        Ok(())
    });
    (port, server)
}

#[test]
fn guest_tcp_socket_reaches_host_loopback_through_the_wlk_gateway() {
    if !has_musl_compiler() {
        eprintln!("skipping TCP fixture: no musl compiler found (set MUSL_CC to enable)");
        return;
    }
    let (port, server) = tcp_echo_server();
    let port = port.to_string();
    let args = [OsStr::new(&port)];
    let output = run_guest(&fixture("tcp_echo"), &args, true);
    let server_result = server.join().expect("TCP server thread");
    assert_success(&output);
    server_result.expect("host TCP echo");
    assert_eq!(stdout(&output), "tcp=tcp-reply\n");
    let trace = stderr(&output);
    assert!(
        trace.contains("Socket"),
        "socket was not routed through WLK:\n{trace}"
    );
    assert!(
        trace.contains("Connect"),
        "connect was not routed through WLK:\n{trace}"
    );
}

#[test]
fn guest_udp_socket_reaches_host_loopback_through_the_wlk_gateway() {
    if !has_musl_compiler() {
        eprintln!("skipping UDP fixture: no musl compiler found (set MUSL_CC to enable)");
        return;
    }
    let (port, server) = udp_echo_server();
    let port = port.to_string();
    let args = [OsStr::new(&port)];
    let output = run_guest(&fixture("udp_echo"), &args, true);
    let server_result = server.join().expect("UDP server thread");
    assert_success(&output);
    server_result.expect("host UDP echo");
    assert_eq!(stdout(&output), "udp=udp-reply\n");
    let trace = stderr(&output);
    assert!(
        trace.contains("Socket"),
        "socket was not routed through WLK:\n{trace}"
    );
    assert!(
        trace.contains("Sendto"),
        "sendto was not routed through WLK:\n{trace}"
    );
    assert!(
        trace.contains("Recvfrom"),
        "recvfrom was not routed through WLK:\n{trace}"
    );
}

#[test]
fn dynamic_glibc_runs_constructors_transitive_origin_dlopen_and_pthread_tls() {
    let Some(compiler) = glibc_compiler() else {
        eprintln!("skipping dynamic glibc fixture: no gcc found");
        return;
    };
    let dynamic_dir = build_dynamic_fixture("glibc", &compiler);
    let output = run_guest(&dynamic_dir.join("bin/dynamic_smoke"), &[], true);
    assert_dynamic_smoke(&output);
    assert_dynamic_load_trace(&output);
}

#[test]
fn dynamic_musl_runs_constructors_transitive_origin_dlopen_and_pthread_tls() {
    let Some(compiler) = musl_compiler() else {
        eprintln!("skipping dynamic musl fixture: no musl compiler found (set MUSL_CC to enable)");
        return;
    };
    let dynamic_dir = build_dynamic_fixture("musl", &compiler);
    let output = run_guest(&dynamic_dir.join("bin/dynamic_smoke"), &[], true);
    assert_dynamic_smoke(&output);
    assert_dynamic_load_trace(&output);
}

#[test]
fn dynamic_glibc_loader_and_libraries_resolve_from_guest_root_and_volume() {
    let Some(compiler) = glibc_compiler() else {
        eprintln!("skipping dynamic glibc root/volume fixture: no gcc found");
        return;
    };
    dynamic_root_and_volume_roundtrip("glibc", &compiler);
}

#[test]
fn dynamic_musl_loader_and_libraries_resolve_from_guest_root_and_volume() {
    let Some(compiler) = musl_compiler() else {
        eprintln!("skipping dynamic musl root/volume fixture: no musl compiler found");
        return;
    };
    dynamic_root_and_volume_roundtrip("musl", &compiler);
}

#[test]
fn static_guest_can_exec_dynamic_glibc_image() {
    let Some(compiler) = glibc_compiler() else {
        eprintln!("skipping dynamic exec fixture: no gcc found");
        return;
    };
    if musl_compiler().is_none() {
        eprintln!("skipping dynamic exec fixture: static musl parent requires MUSL_CC");
        return;
    }
    let dynamic_dir = build_dynamic_fixture("glibc", &compiler);
    let dynamic_program = dynamic_dir.join("bin/dynamic_smoke");
    let args = [dynamic_program.as_os_str()];
    let output = run_guest(&fixture("exec_parent"), &args, true);
    assert_dynamic_smoke(&output);
    assert!(
        stderr(&output).contains("Execve"),
        "dynamic exec was not routed through WLK:\n{}",
        stderr(&output)
    );
}

#[test]
fn forked_static_guest_can_exec_dynamic_glibc_image() {
    let Some(compiler) = glibc_compiler() else {
        eprintln!("skipping dynamic fork/exec fixture: no gcc found");
        return;
    };
    if musl_compiler().is_none() {
        eprintln!("skipping dynamic fork/exec fixture: no musl compiler found (set MUSL_CC)");
        return;
    }
    let dynamic_dir = build_dynamic_fixture("glibc", &compiler);
    let dynamic_program = dynamic_dir.join("bin/dynamic_smoke");
    let args = [dynamic_program.as_os_str()];
    let output = run_guest(&fixture("dynamic_fork_exec"), &args, true);
    assert_success(&output);
    let text = stdout(&output);
    assert_dynamic_smoke_text(&text);
    assert!(
        text.ends_with("dynamic-fork-exec=0\n"),
        "fork parent did not observe the dynamic child exit status:\n{text}"
    );
    let trace = stderr(&output);
    for syscall in ["Clone", "Waitid", "Execve"] {
        assert!(
            trace.contains(syscall),
            "{syscall} was not routed through WLK:\n{trace}"
        );
    }
}

#[test]
fn dynamic_loader_reports_a_missing_transitive_shared_library() {
    let Some(compiler) = glibc_compiler() else {
        eprintln!("skipping missing DSO regression: no gcc found");
        return;
    };
    let broken_tree = TempDir::new("dynamic-missing-library");
    build_dynamic_fixture_at("glibc", &compiler, broken_tree.path());
    fs::remove_file(broken_tree.path().join("lib/libdynamic_leaf.so"))
        .expect("remove transitive shared library");

    let output = run_guest(&broken_tree.path().join("bin/dynamic_smoke"), &[], true);
    assert!(!output.status.success(), "missing DSO unexpectedly loaded");
    assert!(
        stderr(&output).contains("libdynamic_leaf.so"),
        "loader error did not identify the missing transitive DSO:\n{}",
        stderr(&output)
    );
    assert!(
        !stdout(&output).contains("dynamic=ok"),
        "program reached main despite missing DSO:\n{}",
        stdout(&output)
    );
}

#[test]
fn dynamic_elf_fails_when_the_guest_root_hides_its_interpreter() {
    let root = TempDir::new("dynamic-hidden-interpreter-root");
    let fixtures = fixtures_dir();
    let volume_spec = format!("{}:{}:ro", fixtures.display(), fixtures.display());
    let options = vec![
        OsString::from("--root"),
        root.path().as_os_str().to_owned(),
        OsString::from("--volume"),
        OsString::from(volume_spec),
    ];
    let output = run_guest_with_options(&fixture("dynamic"), &[], true, &options);
    assert!(
        !output.status.success(),
        "dynamic ELF unexpectedly started without its interpreter in the guest root"
    );
    assert!(
        output.stdout.is_empty(),
        "program ran despite the missing guest interpreter:\n{}",
        stdout(&output)
    );
    let error = stderr(&output).to_ascii_lowercase();
    assert!(
        error.contains("interpreter")
            || error.contains("no such file")
            || error.contains("ld-linux"),
        "missing interpreter error was not reported clearly:\n{}",
        stderr(&output)
    );
}
