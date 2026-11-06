use crate::{
    CommandSelector, Error, Package, Process, ProcessExitError, ProcessStderr, ProcessStdin,
    ProcessStdout, Result, Sandbox,
    capture::CaptureHandle,
    compiler::NativeLoader,
    fs::validate_guest_path,
    guest_fs::GuestFs,
    stream::{PipeReader, PipeWriter, bounded_pipe},
    terminal::TerminalOptions,
};
use bytes::Bytes;
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use wasixv2::{ByteSink, ByteSource, LocalFuture, Machine, ProcessConfig};

/// Live stdio configuration for [`Command::spawn`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stdio {
    /// A bounded live pipe. The application must read it; an unread pipe
    /// intentionally backpressures the guest.
    Piped,
    /// Bounded diagnostic retention with no live stream. The guest never
    /// blocks, and the retained bytes appear in the completed [`Output`].
    Capture,
    /// Discard the stream entirely.
    Null,
}

/// Why a completed process stopped executing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExitReason {
    /// The guest exited on its own; the exit status is authoritative.
    Exited,
    /// The application terminated or killed the process through the SDK.
    Terminated,
    /// The command deadline elapsed and the SDK stopped the process.
    TimedOut,
}

impl ExitReason {
    /// The stable cross-language string for this reason.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exited => "exited",
            Self::Terminated => "terminated",
            Self::TimedOut => "timeout",
        }
    }
}

/// A subprocess-style command builder bound to a sandbox.
#[derive(Clone, Debug)]
pub struct Command {
    sandbox: Sandbox,
    selector: CommandSelector,
    args: Vec<String>,
    env: BTreeMap<String, String>,
    current_dir: PathBuf,
    input: Bytes,
    output_bytes: Option<usize>,
    timeout: Option<Duration>,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
    stream_bytes: usize,
    terminal: Option<TerminalOptions>,
}

impl Command {
    pub(crate) fn new(sandbox: Sandbox, selector: CommandSelector) -> Self {
        Self {
            sandbox,
            selector,
            args: Vec::new(),
            env: BTreeMap::new(),
            current_dir: PathBuf::from("/workspace"),
            input: Bytes::new(),
            output_bytes: None,
            timeout: None,
            stdin: Stdio::Null,
            stdout: Stdio::Piped,
            stderr: Stdio::Piped,
            stream_bytes: 64 * 1024,
            terminal: None,
        }
    }

    pub fn arg(&mut self, argument: impl Into<String>) -> &mut Self {
        self.args.push(argument.into());
        self
    }

    pub fn args<I, S>(&mut self, arguments: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(arguments.into_iter().map(Into::into));
        self
    }

    pub fn env(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn current_dir(&mut self, path: impl Into<PathBuf>) -> &mut Self {
        self.current_dir = path.into();
        self
    }

    /// Provide finite stdin. EOF is delivered after these bytes.
    pub fn input(&mut self, input: impl Into<Bytes>) -> &mut Self {
        self.input = input.into();
        self
    }

    /// Override the client-wide retention bound for each output stream.
    pub fn output_bytes(&mut self, bytes: usize) -> &mut Self {
        self.output_bytes = Some(bytes);
        self
    }

    /// Stop the process once `duration` elapses.
    ///
    /// The deadline starts when the process spawns. An expired process is
    /// killed and completes with [`ExitReason::TimedOut`]; its bounded
    /// diagnostics remain available in the [`Output`].
    pub fn timeout(&mut self, duration: Duration) -> &mut Self {
        self.timeout = Some(duration);
        self
    }

    /// Configure live stdin for [`Self::spawn`].
    pub fn stdin(&mut self, mode: Stdio) -> &mut Self {
        self.stdin = mode;
        self
    }

    /// Configure live stdout for [`Self::spawn`].
    pub fn stdout(&mut self, mode: Stdio) -> &mut Self {
        self.stdout = mode;
        self
    }

    /// Configure live stderr for [`Self::spawn`].
    pub fn stderr(&mut self, mode: Stdio) -> &mut Self {
        self.stderr = mode;
        self
    }

    /// Set each live stream's bounded queue capacity.
    pub fn stream_bytes(&mut self, bytes: usize) -> &mut Self {
        self.stream_bytes = bytes.max(1);
        self
    }

    /// Attach an interactive terminal to this command and its child process tree.
    ///
    /// Terminal mode provides piped stdin/stdout/stderr, canonical input and
    /// echo, terminal detection, and process-controlled raw/canonical mode.
    pub fn terminal(&mut self, options: TerminalOptions) -> &mut Self {
        self.terminal = Some(options);
        self
    }

    /// Run to completion, capture bounded output, and require success.
    ///
    /// Use [`Self::output`] when a non-zero exit, termination, or timeout is
    /// expected and should be inspected as an [`Output`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessExitError`] when the process does not exit normally
    /// with status zero. Resolution, startup, execution, and I/O failures are
    /// returned unchanged.
    pub async fn run(&mut self) -> Result<Output> {
        self.output().await?.check()
    }

    /// Run to completion and capture bounded stdout and stderr.
    ///
    /// Unlike [`Self::run`], this method returns unsuccessful process outcomes
    /// as data so callers can inspect their status, reason, and diagnostics.
    ///
    /// # Errors
    ///
    /// Returns an error if the sandbox is closed, command selection fails,
    /// stdin cannot be delivered, or the guest cannot be started or executed.
    pub async fn output(&mut self) -> Result<Output> {
        let mut command = self.clone();
        command.stdin = if command.input.is_empty() {
            Stdio::Null
        } else {
            Stdio::Piped
        };
        command.stdout = Stdio::Capture;
        command.stderr = Stdio::Capture;

        let input = command.input.clone();
        let mut process = Box::pin(command.spawn()).await?;
        let stdin = process.take_stdin();
        let input_owner = process.handle();

        let feed_stdin = async move {
            if let Some(mut stdin) = stdin {
                if let Err(error) = tolerate_early_exit(stdin.write_all(&input).await) {
                    input_owner.kill();
                    return Err(error);
                }
                if let Err(error) = tolerate_early_exit(stdin.shutdown().await) {
                    input_owner.kill();
                    return Err(error);
                }
            }
            Ok::<(), std::io::Error>(())
        };
        let (input_result, output) =
            Box::pin(async move { tokio::join!(feed_stdin, process.wait()) }).await;
        input_result?;
        output
    }

    /// Spawn a live process with bounded streams and diagnostic retention.
    ///
    /// Stdin defaults to [`Stdio::Null`]; stdout and stderr default to
    /// [`Stdio::Piped`]. Closing or dropping [`ProcessStdin`] delivers EOF.
    ///
    /// # Errors
    ///
    /// Returns an error if command resolution, environment construction,
    /// package mounting, compilation, or process startup fails.
    pub async fn spawn(&mut self) -> Result<Process> {
        self.sandbox.ensure_open()?;
        validate_guest_path(&self.current_dir)?;
        let admission = self.sandbox.admit()?;
        let command = self.clone();
        let services = self.sandbox.inner.client.inner.services.clone();
        services
            .run(move || {
                Box::pin(async move {
                    let result = command.spawn_owned().await;
                    drop(admission);
                    result
                })
            })
            .await
    }
    async fn spawn_owned(self) -> Result<Process> {
        let (package, command_name, mut packages) = self.resolve()?;
        packages.retain(|other| !other.same_as(&package));
        packages.insert(0, package.clone());
        let limit = self
            .output_bytes
            .unwrap_or(self.sandbox.inner.client.inner.output_bytes);
        let stdout_capture = CaptureHandle::new(limit);
        let stderr_capture = CaptureHandle::new(limit);
        let terminal = self.terminal;
        let stdin_mode = if terminal.is_some() {
            Stdio::Piped
        } else {
            self.stdin
        };
        let stdout_mode = self.stdout;
        let stderr_mode = self.stderr;
        let (input, process_stdin, stdin_closer): (Arc<dyn ByteSource>, _, _) =
            if stdin_mode == Stdio::Piped {
                let (guest, user, closer) = bounded_pipe(self.stream_bytes);
                (
                    Arc::new(Input(Mutex::new(guest))),
                    Some(ProcessStdin::new(user, closer.clone())),
                    Some(closer),
                )
            } else {
                (Arc::new(wasixv2::EmptySource), None, None)
            };
        let (stdout, process_stdout, stdout_closer) =
            guest_output(stdout_mode, &stdout_capture, self.stream_bytes);
        let (stderr, process_stderr, stderr_closer) =
            guest_output(stderr_mode, &stderr_capture, self.stream_bytes);
        let stdio = wasixv2::Stdio {
            stdin: input.clone(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
        };
        let services = self.sandbox.inner.client.inner.services.clone();
        let providers = self.sandbox.inner.provider_runtime.fork();
        #[cfg(feature = "napi-v8")]
        let napi = wasmer_napi::NapiCtx::default();
        let loader = NativeLoader::new(
            &self.sandbox.inner.client.inner,
            #[cfg(feature = "napi-v8")]
            napi.clone(),
        );
        let resolver = loader.clone();
        let capi = wasmer_c_api_imports::WasmCapiRuntimeHooks::new()
            .with_resolve_module_sync(move |bytes| resolver.compile_capi(&bytes));
        let (networking, network_scope) = self.sandbox.run_network();
        let mut builder = Machine::builder()
            .network(networking)
            .loader(loader.clone())
            .instantiation_hook(Arc::new(capi));
        #[cfg(feature = "napi-v8")]
        let mut builder =
            builder.instantiation_hook(Arc::new(wasmer_napi::NapiHook::new(napi.clone())));
        if let Some(options) = terminal {
            builder = builder
                .console_input_eof(wasixv2::ConsoleInputEof::Finite)
                .console_stdio_outputs(true)
                .console(
                    wasixv2::Console {
                        input,
                        output: stdout.clone(),
                        size: wasixv2::WindowSize {
                            cols: options.columns as u16,
                            rows: options.rows as u16,
                            ..Default::default()
                        },
                    },
                    [true; 3],
                );
        }
        let mut machine = builder.build();
        let prepare = async {
            let mut commands = Vec::with_capacity(packages.len());
            let mut roots = Vec::with_capacity(packages.len());
            for package in &packages {
                commands.push(
                    package
                        .inner
                        .binary
                        .commands
                        .iter()
                        .map(|command| (command.name().to_owned(), command.atom().clone()))
                        .collect::<Vec<_>>(),
                );
                let root = if let Some(root) = &package.inner.binary.root {
                    Some(
                        GuestFs::new(root.clone(), crate::MountMode::ReadOnly, providers.clone())
                            .await
                            .map_err(vfs_error)?
                            as Arc<dyn wasixv2::Filesystem>,
                    )
                } else {
                    None
                };
                roots.push(root);
            }
            let sources = packages
                .iter()
                .enumerate()
                .map(|(index, package)| match &package.inner.binary.layout {
                    Some(layout) => wasixv2::PackageInstallSource::Resolved(layout),
                    None => wasixv2::PackageInstallSource::Memory {
                        commands: &commands[index],
                        root: roots[index].clone(),
                    },
                })
                .collect::<Vec<_>>();
            let mut root_overlays = Vec::new();
            for package in packages.iter().rev() {
                for (guest, host) in &package.inner.binary.host_mounts {
                    if guest == "/" {
                        root_overlays.push(machine.host_dir_layer(host).map_err(execution)?);
                    }
                }
            }
            wasixv2::install_package_sources_with_root_overlays(
                &mut machine,
                &sources,
                &root_overlays,
            )
            .await
            .map_err(execution)?;
            for package in packages.iter().rev() {
                for (guest, host) in &package.inner.binary.host_mounts {
                    if guest != "/" {
                        machine
                            .mount_host_dir(guest, host, false)
                            .await
                            .map_err(execution)?;
                    }
                }
            }
            let workspace = GuestFs::new(
                self.sandbox.inner.workspace.clone(),
                crate::MountMode::ReadWrite,
                providers.clone(),
            )
            .await
            .map_err(vfs_error)?;
            machine
                .mount("/workspace", workspace, false)
                .await
                .map_err(execution)?;
            for mount in &self.sandbox.inner.mounts {
                let filesystem =
                    GuestFs::new(mount.filesystem.clone(), mount.mode, providers.clone())
                        .await
                        .map_err(vfs_error)?;
                machine
                    .mount(
                        &mount.guest_path.to_string_lossy(),
                        filesystem,
                        mount.mode == crate::MountMode::ReadOnly,
                    )
                    .await
                    .map_err(execution)?;
            }
            machine.set_working_dir(
                validate_guest_path(&self.current_dir)?
                    .to_string_lossy()
                    .into_owned(),
            );
            let command = package
                .inner
                .binary
                .get_command(&command_name)
                .ok_or_else(|| Error::CommandNotFound {
                    command: command_name.clone(),
                })?;
            let annotation = command.metadata().wasi().map_err(execution)?;
            let mut env = self.sandbox.inner.env.clone();
            env.extend(self.env.clone());
            let mut config = ProcessConfig {
                args: self.args.clone(),
                env: env
                    .into_iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect(),
                stdio,
            };
            wasixv2::command_config(&command_name, annotation.as_ref(), &mut config)
                .map_err(execution)?;
            for entry in machine.default_env() {
                let name = entry.split_once('=').map_or(entry.as_str(), |(key, _)| key);
                if !config.env.iter().any(|entry| {
                    entry.split_once('=').map_or(entry.as_str(), |(key, _)| key) == name
                }) {
                    config.env.push(entry);
                }
            }
            Ok::<_, Error>(config)
        }
        .await;
        let config = match prepare {
            Ok(config) => config,
            Err(error) => {
                machine.shutdown().await;
                drop(machine);
                if let Some(network) = &network_scope {
                    network.cancel();
                    let _ = network.close().await;
                }
                let _ = providers.close().await;
                return Err(error);
            }
        };
        let machine = Arc::new(machine);
        let run = match wasixv2::spawn_file(
            machine.clone(),
            self.sandbox.inner.client.inner.engine.clone(),
            format!("/bin/{command_name}"),
            config,
        )
        .await
        {
            Ok(run) => run,
            Err(error) => {
                machine.shutdown().await;
                drop(machine);
                if let Some(network) = &network_scope {
                    network.cancel();
                    let _ = network.close().await;
                }
                let _ = providers.close().await;
                return Err(execution(error));
            }
        };
        let control = crate::process::ProcessControl::new(
            run.id(),
            run.observer(),
            run.signaller(),
            stdin_closer,
            stdout_closer.into_iter().chain(stderr_closer).collect(),
            network_scope
                .as_ref()
                .map(|network| network.cancel_handle()),
            #[cfg(feature = "napi-v8")]
            napi,
        );
        if let Err(error) = self.sandbox.register_process(&control) {
            control.kill();
            machine.shutdown().await;
            let _ = run.wait().await;
            drop(run);
            control.release_kernel();
            drop(machine);
            if let Some(network) = &network_scope {
                network.cancel();
                let _ = network.close().await;
            }
            let _ = providers.close().await;
            return Err(error);
        }
        let supervisor = control.clone();
        services.spawn_local(Box::pin(async move {
            let mut result = run.wait().await;
            machine.shutdown().await;
            drop(run);
            supervisor.release_kernel();
            drop(machine);
            if let Some(network) = network_scope {
                if result.is_err() {
                    network.cancel();
                }
                if let Err(error) = network.close().await
                    && result.is_ok()
                {
                    result = Err(error.to_string());
                }
            }
            if let Err(error) = providers.close().await
                && result.is_ok()
            {
                result = Err(error.to_string());
            }
            drop(stdout);
            drop(stderr);
            supervisor.finish(result);
        }))?;
        let process = Process::new(
            control,
            process_stdin,
            process_stdout.map(ProcessStdout::new),
            process_stderr.map(ProcessStderr::new),
            stdout_capture,
            stderr_capture,
            terminal.is_some(),
        );
        if let Some(duration) = self.timeout {
            let handle = process.handle();
            services.spawn_local(Box::pin(async move {
                handle.kill_on_timeout(duration).await;
            }))?;
        }
        Ok(process)
    }

    fn resolve(&self) -> Result<(Package, String, Vec<Package>)> {
        let packages = self
            .sandbox
            .inner
            .packages
            .read()
            .map_err(|_| Error::InternalState {
                message: "the installed-package lock is poisoned".to_owned(),
            })?
            .clone();

        let selected = match &self.selector {
            CommandSelector::Name(name) => {
                let matches: Vec<_> = packages
                    .iter()
                    .filter(|package| package.inner.binary.get_command(name).is_some())
                    .cloned()
                    .collect();
                match matches.as_slice() {
                    [] => {
                        return Err(Error::CommandNotFound {
                            command: name.clone(),
                        });
                    }
                    [package] => (package.clone(), name.clone()),
                    many => {
                        return Err(Error::CommandAmbiguous {
                            command: name.clone(),
                            packages: many.iter().map(Package::id).collect(),
                        });
                    }
                }
            }
            CommandSelector::Ref(command) => {
                let Some(package) = packages
                    .iter()
                    .find(|package| package.same_as(command.package()))
                else {
                    return Err(Error::PackageNotInstalled {
                        package: command.package().id(),
                    });
                };
                (package.clone(), command.name().to_owned())
            }
            CommandSelector::Package(requested) => {
                let Some(package) = packages.iter().find(|package| package.same_as(requested))
                else {
                    return Err(Error::PackageNotInstalled {
                        package: requested.id(),
                    });
                };
                let entrypoint = package
                    .inner
                    .binary
                    .infer_entrypoint()
                    .map_err(|_| Error::PackageHasNoEntrypoint {
                        package: package.id(),
                    })?
                    .to_owned();
                (package.clone(), entrypoint)
            }
        };
        Ok((selected.0, selected.1, packages))
    }
}

fn deduplicate_environment(environment: &mut Vec<(String, Vec<u8>)>) {
    let mut seen = HashSet::with_capacity(environment.len());
    environment.reverse();
    environment.retain(|(key, _)| seen.insert(key.clone()));
    environment.reverse();
}

fn execution(error: impl std::fmt::Display) -> Error {
    Error::Execution {
        message: error.to_string(),
    }
}
fn vfs_error(error: wasixv2_abi::Errno) -> Error {
    execution(format!("filesystem provider: {error:?}"))
}
struct Input(Mutex<PipeReader>);
impl ByteSource for Input {
    fn poll_read(&self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<std::io::Result<usize>> {
        let mut read = ReadBuf::new(bytes);
        match Pin::new(&mut *self.0.lock().unwrap()).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read.filled().len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}
enum OutputSink {
    Pipe(Mutex<PipeWriter>, CaptureHandle),
    Capture(CaptureHandle),
    Null,
}
impl ByteSink for OutputSink {
    fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, std::io::Result<usize>> {
        Box::pin(futures::future::poll_fn(move |cx| match self {
            Self::Pipe(writer, capture) => {
                match Pin::new(&mut *writer.lock().unwrap()).poll_write(cx, data) {
                    Poll::Ready(Ok(accepted)) => {
                        capture.retain(&data[..accepted]);
                        Poll::Ready(Ok(accepted))
                    }
                    result => result,
                }
            }
            Self::Capture(capture) => {
                capture.retain(data);
                Poll::Ready(Ok(data.len()))
            }
            Self::Null => Poll::Ready(Ok(data.len())),
        }))
    }
}
fn guest_output(
    mode: Stdio,
    capture: &CaptureHandle,
    capacity: usize,
) -> (
    Arc<dyn ByteSink>,
    Option<PipeReader>,
    Option<crate::stream::PipeCloser>,
) {
    match mode {
        Stdio::Piped => {
            let (user, guest, closer) = bounded_pipe(capacity);
            (
                Arc::new(OutputSink::Pipe(Mutex::new(guest), capture.clone())),
                Some(user),
                Some(closer),
            )
        }
        Stdio::Capture => (Arc::new(OutputSink::Capture(capture.clone())), None, None),
        Stdio::Null => (Arc::new(OutputSink::Null), None, None),
    }
}

/// A guest that exits before consuming all of its stdin is not a failure:
/// `head -1`, an early crash, or a timeout all legitimately abandon input.
fn tolerate_early_exit(result: std::io::Result<()>) -> std::io::Result<()> {
    match result {
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::WriteZero
            ) =>
        {
            Ok(())
        }
        other => other,
    }
}

/// A process exit status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitStatus {
    code: i32,
}

impl ExitStatus {
    pub(crate) fn from_code(code: i32) -> Self {
        Self { code }
    }
    #[must_use]
    pub fn success(self) -> bool {
        self.code == 0
    }

    #[must_use]
    pub fn code(self) -> i32 {
        self.code
    }
}

/// Bytes captured from one completed process stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedOutput {
    bytes: Bytes,
    truncated: bool,
}

impl CapturedOutput {
    pub(crate) fn from_parts(bytes: Vec<u8>, truncated: bool) -> Self {
        Self {
            bytes: bytes.into(),
            truncated,
        }
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Decode the bytes synchronously.
    ///
    /// # Errors
    ///
    /// Returns an error when the captured bytes are not valid UTF-8.
    pub fn text(&self) -> Result<String> {
        Ok(String::from_utf8(self.bytes.to_vec())?)
    }

    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// A completed command and its captured output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Output {
    pub status: ExitStatus,
    /// Why the process stopped: its own exit, SDK termination, or a timeout.
    pub reason: ExitReason,
    pub stdout: CapturedOutput,
    pub stderr: CapturedOutput,
}

impl Output {
    /// True only when the guest exited on its own with a zero status.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.reason == ExitReason::Exited && self.status.success()
    }

    /// Convert an unsuccessful completion into a typed error.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessExitError`] when the process did not exit successfully,
    /// including termination and timeout outcomes.
    pub fn check(self) -> Result<Self> {
        if self.ok() {
            Ok(self)
        } else {
            Err(ProcessExitError::new(self).into())
        }
    }

    /// Check success and synchronously decode stdout.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessExitError`] for an unsuccessful completion or a UTF-8
    /// error when stdout is not valid UTF-8.
    pub fn text(&self) -> Result<String> {
        if !self.ok() {
            return Err(ProcessExitError::new(self.clone()).into());
        }
        self.stdout.text()
    }
}

#[cfg(test)]
mod tests {
    use super::{CapturedOutput, ExitReason, ExitStatus, Output, deduplicate_environment};

    #[tokio::test]
    async fn direct_output_sinks_retain_only_accepted_pipe_prefixes() {
        use super::guest_output;
        use crate::{Stdio, capture::CaptureHandle};
        use tokio::io::AsyncReadExt;

        let capture = CaptureHandle::new(6);
        let (sink, reader, closer) = guest_output(Stdio::Piped, &capture, 4);
        let mut reader = reader.unwrap();
        assert_eq!(sink.write(b"abcdefgh").await.unwrap(), 4);
        assert_eq!(capture.snapshot(), (b"abcd".to_vec(), false));
        let mut pending = sink.write(b"efgh");
        assert!(futures::poll!(&mut pending).is_pending());
        drop(pending);
        assert_eq!(capture.snapshot(), (b"abcd".to_vec(), false));
        let mut accepted = [0; 4];
        reader.read_exact(&mut accepted).await.unwrap();
        assert_eq!(&accepted, b"abcd");
        assert_eq!(sink.write(b"efgh").await.unwrap(), 4);
        let mut revoked = sink.write(b"ij");
        assert!(futures::poll!(&mut revoked).is_pending());
        closer.unwrap().close();
        assert_eq!(
            revoked.await.unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        assert_eq!(capture.snapshot(), (b"abcdef".to_vec(), true));
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"efgh");
        for mode in [Stdio::Capture, Stdio::Null] {
            let capture = CaptureHandle::new(2);
            let (sink, reader, closer) = guest_output(mode, &capture, 1);
            assert!(reader.is_none() && closer.is_none());
            assert_eq!(sink.write(b"full output").await.unwrap(), 11);
            assert_eq!(
                capture.snapshot(),
                if mode == Stdio::Capture {
                    (b"fu".to_vec(), true)
                } else {
                    (Vec::new(), false)
                }
            );
        }
    }

    #[test]
    fn environment_overrides_are_unique_and_last_one_wins() {
        let mut environment = vec![
            ("HOME".to_owned(), b"/package".to_vec()),
            ("PATH".to_owned(), b"/bin".to_vec()),
            ("HOME".to_owned(), b"/workspace".to_vec()),
        ];

        deduplicate_environment(&mut environment);

        assert_eq!(
            environment,
            vec![
                ("PATH".to_owned(), b"/bin".to_vec()),
                ("HOME".to_owned(), b"/workspace".to_vec()),
            ]
        );
    }

    #[test]
    fn text_is_synchronous_and_checked() {
        let output = Output {
            status: ExitStatus { code: 0 },
            reason: ExitReason::Exited,
            stdout: CapturedOutput::from_parts(b"hello".to_vec(), false),
            stderr: CapturedOutput::from_parts(Vec::new(), false),
        };
        assert_eq!(output.text().unwrap(), "hello");
    }

    #[test]
    fn checked_output_preserves_nonzero_result() {
        let output = Output {
            status: ExitStatus { code: 7 },
            reason: ExitReason::Exited,
            stdout: CapturedOutput::from_parts(b"partial".to_vec(), false),
            stderr: CapturedOutput::from_parts(b"failed".to_vec(), false),
        };
        let error = output.check().unwrap_err();
        let crate::Error::ProcessExit(error) = error else {
            panic!("expected process exit error");
        };
        assert_eq!(error.output().status.code(), 7);
        assert_eq!(error.output().stdout.bytes(), b"partial");
    }

    #[test]
    fn terminated_output_is_not_ok_even_with_zero_status() {
        let output = Output {
            status: ExitStatus { code: 0 },
            reason: ExitReason::Terminated,
            stdout: CapturedOutput::from_parts(Vec::new(), false),
            stderr: CapturedOutput::from_parts(Vec::new(), false),
        };
        assert!(!output.ok());
        assert!(output.check().is_err());
    }

    #[test]
    fn exit_error_includes_stderr_excerpt() {
        let output = Output {
            status: ExitStatus { code: 1 },
            reason: ExitReason::Exited,
            stdout: CapturedOutput::from_parts(Vec::new(), false),
            stderr: CapturedOutput::from_parts(b"boom: missing file".to_vec(), false),
        };
        let message = output.check().unwrap_err().to_string();
        assert!(message.contains("status 1"), "{message}");
        assert!(message.contains("boom: missing file"), "{message}");
    }
}
