#![cfg(target_os = "linux")]

use std::{
    ffi::{OsStr, OsString},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{OnceLock, mpsc},
    thread,
    time::{Duration, Instant},
};

const BUILD_TIMEOUT: Duration = Duration::from_secs(45);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(7);
const RUN_TIMEOUT: Duration = Duration::from_secs(10);
static BUILT: OnceLock<()> = OnceLock::new();

unsafe extern "C" {
    fn kill(pid: libc::pid_t, sig: libc::c_int) -> libc::c_int;
}

struct ProcessGroup {
    pid: libc::pid_t,
    active: bool,
}

impl ProcessGroup {
    fn kill(&self) {
        // SAFETY: a negative PID addresses the process group started by CommandExt::process_group.
        unsafe {
            let _ = kill(-self.pid, 9);
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if self.active {
            self.kill();
        }
    }
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn fixture(name: &str) -> PathBuf {
    fixtures_dir().join(name)
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
    let mut group = ProcessGroup {
        pid: child.id() as libc::pid_t,
        active: true,
    };
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });

    match receiver.recv_timeout(timeout) {
        Ok(Ok(output)) => {
            group.disarm();
            output
        }
        Ok(Err(error)) => panic!("wait for bounded command: {error}"),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            group.kill();
            let _ = receiver.recv_timeout(Duration::from_secs(2));
            panic!("command exceeded timeout of {timeout:?}");
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!("bounded command waiter disconnected"),
    }
}

fn has_musl_compiler() -> bool {
    if let Some(compiler) = std::env::var_os("MUSL_CC") {
        return compiler_available(compiler);
    }
    [
        "musl-gcc",
        "x86_64-linux-musl-gcc",
        "x86_64-unknown-linux-musl-gcc",
    ]
    .iter()
    .any(|compiler| compiler_available(OsString::from(compiler)))
}

fn compiler_available(compiler: OsString) -> bool {
    Command::new(compiler)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("reserve an ephemeral host port")
        .local_addr()
        .expect("read ephemeral host port")
        .port()
}

fn start_guest(
    program: &Path,
    args: &[&OsStr],
) -> (mpsc::Receiver<io::Result<Output>>, ProcessGroup) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wlk-native"));
    command
        .arg("--trace")
        .arg(program)
        .args(args)
        .process_group(0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = command.spawn().expect("start native listener guest");
    let group = ProcessGroup {
        pid: child.id() as libc::pid_t,
        active: true,
    };
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    (receiver, group)
}

fn connect_until_port_is_published(port: u16) -> io::Result<TcpStream> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut last_error = None;
    while Instant::now() < deadline {
        match TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "guest TCP listener was not published",
        )
    }))
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("guest stdout is UTF-8")
}

#[test]
fn host_tcp_client_reaches_wlk_published_guest_listener() {
    if !has_musl_compiler() {
        eprintln!("skipping listener fixture: no musl compiler found (set MUSL_CC to enable)");
        return;
    }
    build_fixtures();

    let port = free_port();
    let port_arg = port.to_string();
    let args = [OsStr::new(&port_arg)];
    let (output_receiver, mut process_group) = start_guest(&fixture("tcp_listener"), &args);

    let mut stream = connect_until_port_is_published(port).expect("connect to published listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set client read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .expect("set client write timeout");
    stream
        .write_all(b"host-request")
        .expect("send request to guest");
    let mut response = [0u8; 11];
    stream
        .read_exact(&mut response)
        .expect("read guest response");
    assert_eq!(&response, b"guest-reply");

    let output = output_receiver
        .recv_timeout(RUN_TIMEOUT)
        .expect("guest runner exceeded timeout")
        .expect("collect guest output");
    process_group.disarm();
    assert!(
        output.status.success(),
        "guest failed (status {}):\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(stdout(&output), "listener=guest-reply\n");

    let trace = String::from_utf8_lossy(&output.stderr);
    for syscall in ["Bind", "Listen", "Accept"] {
        assert!(
            trace.contains(syscall),
            "guest {syscall} did not pass through WLK:\n{trace}"
        );
    }
}
