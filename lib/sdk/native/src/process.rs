use crate::{
    CapturedOutput, Error, ExitReason, ExitStatus, Output, Result,
    capture::CaptureHandle,
    stream::{PipeCloser, PipeReader, PipeWriter},
};
use std::{
    fmt, io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
};
use wasixv2::{Signaller, WindowSize};

/// Writable live stdin for a spawned guest process.
pub struct ProcessStdin {
    inner: Option<PipeWriter>,
    closer: PipeCloser,
}
impl fmt::Debug for ProcessStdin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessStdin")
            .field("open", &self.inner.is_some())
            .finish()
    }
}
impl ProcessStdin {
    pub(crate) fn new(inner: PipeWriter, closer: PipeCloser) -> Self {
        Self {
            inner: Some(inner),
            closer,
        }
    }
    pub(crate) fn closer(&self) -> PipeCloser {
        self.closer.clone()
    }
    pub async fn close(&mut self) -> io::Result<()> {
        tokio::io::AsyncWriteExt::shutdown(self).await
    }
}
impl AsyncWrite for ProcessStdin {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut().inner.as_mut() {
            Some(stream) => Pin::new(stream).poll_write(cx, bytes),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().inner.as_mut() {
            Some(stream) => Pin::new(stream).poll_flush(cx),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(stream) = this.inner.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(stream).poll_shutdown(cx) {
            Poll::Ready(result) => {
                this.inner.take();
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
macro_rules! process_output_stream {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Debug)]
        pub struct $name {
            inner: PipeReader,
        }

        impl $name {
            pub(crate) fn new(inner: PipeReader) -> Self {
                Self { inner }
            }
        }

        impl AsyncRead for $name {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buffer: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_read(cx, buffer)
            }
        }
    };
}

process_output_stream!(
    ProcessStdout,
    "Readable live stdout from a spawned guest process."
);
process_output_stream!(
    ProcessStderr,
    "Readable live stderr from a spawned guest process."
);

/// A running guest process with single-owner live streams.
#[derive(Debug)]
pub struct Process {
    id: u32,
    control: Arc<ProcessControl>,
    stdin: Option<ProcessStdin>,
    stdout: Option<ProcessStdout>,
    stderr: Option<ProcessStderr>,
    stdout_capture: CaptureHandle,
    stderr_capture: CaptureHandle,
    terminal: bool,
    completed: Option<Output>,
}
impl Process {
    pub(crate) fn new(
        control: Arc<ProcessControl>,
        stdin: Option<ProcessStdin>,
        stdout: Option<ProcessStdout>,
        stderr: Option<ProcessStderr>,
        stdout_capture: CaptureHandle,
        stderr_capture: CaptureHandle,
        terminal: bool,
    ) -> Self {
        Self {
            id: control.id,
            control,
            stdin,
            stdout,
            stderr,
            stdout_capture,
            stderr_capture,
            terminal,
            completed: None,
        }
    }
    pub(crate) fn control(&self) -> &Arc<ProcessControl> {
        &self.control
    }
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn resize_terminal(&self, columns: u32, rows: u32) -> Result<()> {
        resize(&self.control, self.terminal, columns, rows)
    }
    #[must_use]
    pub fn handle(&self) -> ProcessHandle {
        ProcessHandle {
            control: self.control.clone(),
            terminal: self.terminal,
        }
    }
    #[must_use]
    pub fn take_stdin(&mut self) -> Option<ProcessStdin> {
        self.stdin.take()
    }
    #[must_use]
    pub fn take_stdout(&mut self) -> Option<ProcessStdout> {
        self.stdout.take()
    }
    #[must_use]
    pub fn take_stderr(&mut self) -> Option<ProcessStderr> {
        self.stderr.take()
    }
    /// Wait through guest, descendant, provider and output-owner cleanup.
    pub async fn wait(&mut self) -> Result<Output> {
        if let Some(output) = &self.completed {
            return Ok(output.clone());
        }
        let code = self
            .control
            .wait_finished()
            .await
            .map_err(|message| Error::Execution { message })?;
        let output = self.snapshot(code);
        self.completed = Some(output.clone());
        Ok(output)
    }
    pub fn try_wait(&mut self) -> Result<Option<Output>> {
        if let Some(output) = &self.completed {
            return Ok(Some(output.clone()));
        }
        let Some(result) = self.control.result() else {
            return Ok(None);
        };
        let code = result.map_err(|message| Error::Execution { message })?;
        let output = self.snapshot(code);
        self.completed = Some(output.clone());
        Ok(Some(output))
    }
    pub async fn terminate(&mut self, grace: Duration) -> Result<()> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        self.control.signal_terminate();
        let control = self.control.clone();
        tokio::select! {result=self.wait()=>{result?;},()=tokio::time::sleep(grace)=>{control.kill();self.wait().await?;}}
        Ok(())
    }
    pub fn kill(&mut self) -> Result<()> {
        self.control.kill();
        Ok(())
    }
    fn snapshot(&self, code: i32) -> Output {
        let (stdout, stdout_truncated) = self.stdout_capture.snapshot();
        let (stderr, stderr_truncated) = self.stderr_capture.snapshot();
        let (reason, status) = self.control.exit_state(code);
        Output {
            status,
            reason,
            stdout: CapturedOutput::from_parts(stdout, stdout_truncated),
            stderr: CapturedOutput::from_parts(stderr, stderr_truncated),
        }
    }
}
/// A signaling handle independent of the process's stream owner.
#[derive(Clone, Debug)]
pub struct ProcessHandle {
    control: Arc<ProcessControl>,
    terminal: bool,
}
impl ProcessHandle {
    #[must_use]
    pub fn id(&self) -> u32 {
        self.control.id
    }
    pub fn resize_terminal(&self, columns: u32, rows: u32) -> Result<()> {
        resize(&self.control, self.terminal, columns, rows)
    }
    pub fn kill(&self) {
        self.control.kill();
    }
    pub async fn terminate(&self, grace: Duration) {
        if self.control.try_join_exited() {
            return;
        }
        self.control.signal_terminate();
        tokio::select! {_=self.control.wait_finished()=>{},()=tokio::time::sleep(grace)=>self.control.kill()}
    }
    pub(crate) async fn kill_on_timeout(&self, duration: Duration) {
        tokio::select! {_=self.control.wait_finished()=>{},()=tokio::time::sleep(duration)=>self.control.kill_timed_out()}
    }
}
fn resize(control: &ProcessControl, terminal: bool, columns: u32, rows: u32) -> Result<()> {
    if !terminal {
        return Err(Error::Execution {
            message: "the process has no terminal".into(),
        });
    }
    if let Some(signaller) = control.signaller.lock().unwrap().as_ref() {
        // The canonical Linux winsize representation is u16; keep public u32 input.
        signaller.console_resize(WindowSize {
            cols: columns as u16,
            rows: rows as u16,
            xpixel: 0,
            ypixel: 0,
        });
    }
    Ok(())
}
const EXIT_NONE: u8 = 0;
const EXIT_TERMINATED_GRACEFUL: u8 = 1;
const EXIT_TERMINATED_FORCED: u8 = 2;
const EXIT_TIMED_OUT: u8 = 3;
pub(crate) struct ProcessControl {
    id: u32,
    signaller: Mutex<Option<Signaller>>,
    stdin: Option<PipeCloser>,
    outputs: Vec<PipeCloser>,
    exit: AtomicU8,
    observer: wasixv2::RunObserver,
    network_cancel: Option<crate::provider_net::NetworkCancel>,
    completed: watch::Sender<Option<std::result::Result<i32, String>>>,
    #[cfg(feature = "napi-v8")]
    napi: Mutex<Option<wasmer_napi::NapiCtx>>,
}
impl fmt::Debug for ProcessControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessControl")
            .field("id", &self.id)
            .field("exited", &self.try_join_exited())
            .finish()
    }
}
impl ProcessControl {
    pub(crate) fn new(
        id: u32,
        observer: wasixv2::RunObserver,
        signaller: Signaller,
        stdin: Option<PipeCloser>,
        outputs: Vec<PipeCloser>,
        network_cancel: Option<crate::provider_net::NetworkCancel>,
        #[cfg(feature = "napi-v8")] napi: wasmer_napi::NapiCtx,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            signaller: Mutex::new(Some(signaller)),
            stdin,
            outputs,
            exit: AtomicU8::new(EXIT_NONE),
            observer,
            network_cancel,
            completed: watch::channel(None).0,
            #[cfg(feature = "napi-v8")]
            napi: Mutex::new(Some(napi)),
        })
    }
    pub(crate) fn finish(&self, result: std::result::Result<i32, String>) {
        self.completed.send_replace(Some(result));
    }
    pub(crate) fn release_kernel(&self) {
        self.signaller.lock().unwrap().take();
        #[cfg(feature = "napi-v8")]
        self.napi.lock().unwrap().take();
    }
    fn result(&self) -> Option<std::result::Result<i32, String>> {
        self.completed.borrow().clone()
    }
    pub(crate) async fn wait_finished(&self) -> std::result::Result<i32, String> {
        let mut completed = self.completed.subscribe();
        loop {
            {
                let value = completed.borrow_and_update().clone();
                if let Some(result) = value {
                    return result;
                }
            }
            completed
                .changed()
                .await
                .map_err(|_| "the process completion owner stopped".to_owned())?;
        }
    }
    pub(crate) async fn close(&self) -> Result<()> {
        self.kill();
        self.wait_finished()
            .await
            .map(|_| ())
            .map_err(|message| Error::Execution { message })
    }
    pub(crate) fn signal_terminate(&self) {
        if self.record_exit_if_running(EXIT_TERMINATED_GRACEFUL) {
            self.signal(15);
            if let Some(stdin) = &self.stdin {
                stdin.close();
            }
        }
    }
    pub(crate) fn kill(&self) {
        let running = self.record_exit_if_running(EXIT_TERMINATED_FORCED);
        if let Some(network) = &self.network_cancel {
            network.cancel();
        }
        for output in &self.outputs {
            output.close();
        }
        if running {
            self.force_exit();
        }
    }
    fn kill_timed_out(&self) {
        let running = self.record_exit_if_running(EXIT_TIMED_OUT);
        if let Some(network) = &self.network_cancel {
            network.cancel();
        }
        for output in &self.outputs {
            output.close();
        }
        if running {
            self.force_exit();
        }
    }
    fn signal(&self, signal: i32) {
        if let Some(signaller) = self.signaller.lock().unwrap().as_ref() {
            let _ = signaller.signal(signal);
        }
    }
    fn force_exit(&self) {
        self.signal(9);
        #[cfg(feature = "napi-v8")]
        if self.observer.observed_result().is_none()
            && let Some(napi) = self.napi.lock().unwrap().as_ref()
        {
            napi.runtime_control().terminate_all();
        }
        if let Some(stdin) = &self.stdin {
            stdin.close();
        }
    }
    pub(crate) fn try_join_exited(&self) -> bool {
        self.observer.observed_result().is_some()
    }
    fn record_exit_if_running(&self, requested: u8) -> bool {
        if self.try_join_exited() {
            return false;
        }
        let _ =
            self.exit
                .compare_exchange(EXIT_NONE, requested, Ordering::AcqRel, Ordering::Acquire);
        true
    }
    fn exit_state(&self, backend_code: i32) -> (ExitReason, ExitStatus) {
        match self.exit.load(Ordering::Acquire) {
            EXIT_TERMINATED_GRACEFUL => (ExitReason::Terminated, ExitStatus::from_code(143)),
            EXIT_TERMINATED_FORCED => (ExitReason::Terminated, ExitStatus::from_code(137)),
            EXIT_TIMED_OUT => (ExitReason::TimedOut, ExitStatus::from_code(137)),
            _ => (ExitReason::Exited, ExitStatus::from_code(backend_code)),
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.completed.is_none() && !self.control.try_join_exited() {
            self.control.kill();
        }
    }
}

#[cfg(test)]
mod close_escalation {
    use crate::network_api::{BackendStream, NetworkCloseMode, PollMask, PollTable, Pollable};
    use crate::network_api::{NetworkError, NetworkProvider, NetworkResult, TcpStream, WaitQueue};
    use crate::{CacheConfig, ExitReason, PackageSource, Result, Wasmer, WasmerConfig};
    use futures::FutureExt;
    use std::sync::atomic::AtomicBool;
    use std::{
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::sync::Notify;
    use wasixv2_vnet::{Shutdown, StreamState};

    // Same connect sequence as tests/network.rs, with an explicit observed zero exit.
    const CONNECT_WAT: &str = r#"(module
      (import "wasixv2" "socket" (func $socket(param i32 i32 i32)(result i32)))
      (import "wasixv2" "connect" (func $connect(param i32 i32 i32)(result i32)))
      (import "wasixv2" "exit_group" (func $exit(param i32)))
      (memory(export "memory")1)
      (data(i32.const 16)"\02\00\01\bb\c6\33\64\50\00\00\00\00\00\00\00\00")
      (func(export "_start")
        (drop(call $connect(call $socket(i32.const 2)(i32.const 1)(i32.const 0))(i32.const 16)(i32.const 16)))
        (call $exit(i32.const 0)) unreachable))"#;

    #[derive(Debug, Default)]
    struct CloseState {
        normal: AtomicUsize,
        cancel: AtomicUsize,
        active: AtomicUsize,
        normal_started: Notify,
        cancel_started: Notify,
        acknowledged: AtomicBool,
        actual_completions: AtomicUsize,
        changed: Notify,
    }
    impl CloseState {
        fn acknowledge(&self) {
            assert!(!self.acknowledged.swap(true, Ordering::SeqCst));
            self.actual_completions.fetch_add(1, Ordering::SeqCst);
            self.changed.notify_waiters();
        }
    }
    struct Active(Arc<CloseState>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.active.fetch_sub(1, Ordering::SeqCst);
        }
    }
    struct EscalatingStream {
        state: Arc<CloseState>,
        options: std::sync::Mutex<Vec<(i32, i32, Vec<u8>)>>,
    }
    impl Pollable for EscalatingStream {
        fn poll(&self, _: Option<&mut PollTable<'_>>) -> PollMask {
            if self.state.acknowledged.load(Ordering::SeqCst) {
                PollMask::HUP | PollMask::IN
            } else {
                PollMask::OUT
            }
        }
    }
    impl BackendStream for EscalatingStream {
        fn state(&self) -> StreamState {
            if self.state.acknowledged.load(Ordering::SeqCst) {
                StreamState::Closed
            } else {
                StreamState::Established
            }
        }
        fn read(&self, _: &mut [u8], _: bool) -> NetworkResult<usize> {
            Err(NetworkError::EAGAIN)
        }
        fn write(&self, data: &[u8]) -> NetworkResult<usize> {
            Ok(data.len())
        }
        fn write_urgent(&self, _: &[u8]) -> NetworkResult<usize> {
            Err(NetworkError::EOPNOTSUPP)
        }
        fn read_urgent(&self, _: bool) -> NetworkResult<u8> {
            Err(NetworkError::EOPNOTSUPP)
        }
        fn at_mark(&self) -> bool {
            false
        }
        fn shutdown(&self, _: Shutdown) -> NetworkResult<()> {
            Ok(())
        }
        fn take_error(&self) -> Option<NetworkError> {
            None
        }
        fn peer_addr(&self) -> SocketAddr {
            "198.51.100.80:443".parse().unwrap()
        }
        fn input_len(&self) -> usize {
            0
        }
    }
    #[async_trait::async_trait]
    impl TcpStream for EscalatingStream {
        fn local_addr(&self) -> NetworkResult<SocketAddr> {
            Ok("127.0.0.1:45001".parse().unwrap())
        }
        fn flush(&self) -> NetworkResult<()> {
            Ok(())
        }
        fn set_socket_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
            match (level, name) {
                (1, 13) | (6, 1) | (1, 9) | (1, 5) | (1, 7) | (1, 8) | (0, 2) | (41, 16) => {
                    self.options
                        .lock()
                        .unwrap()
                        .push((level, name, value.to_vec()));
                    Ok(())
                }
                _ => Err(NetworkError::EOPNOTSUPP),
            }
        }
        async fn close(&self, mode: NetworkCloseMode) -> NetworkResult<()> {
            self.state.active.fetch_add(1, Ordering::SeqCst);
            let _active = Active(self.state.clone());
            match mode {
                NetworkCloseMode::Normal => {
                    self.state.normal.fetch_add(1, Ordering::SeqCst);
                    self.state.normal_started.notify_one();
                }
                NetworkCloseMode::Cancel => {
                    self.state.cancel.fetch_add(1, Ordering::SeqCst);
                    self.state.cancel_started.notify_one();
                }
            }
            loop {
                let changed = self.state.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.state.acknowledged.load(Ordering::SeqCst) {
                    return Ok(());
                }
                changed.await;
            }
        }
    }
    #[derive(Debug)]
    struct Provider {
        state: Arc<CloseState>,
        calls: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl NetworkProvider for Provider {
        async fn connect_tcp(
            &self,
            _: SocketAddr,
            _: SocketAddr,
            _: WaitQueue,
        ) -> NetworkResult<Arc<dyn TcpStream>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(EscalatingStream {
                state: self.state.clone(),
                options: std::sync::Mutex::default(),
            }))
        }
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn explicit_kill_escalates_inflight_close_and_joins_both_without_rewriting_observed_exit()
    -> Result<()> {
        tokio::time::timeout(Duration::from_secs(30), async {
            let directory = tempfile::TempDir::new()?;
            let client = Wasmer::with_config(WasmerConfig {
                cache: CacheConfig {
                    root: directory.path().join("cache"),
                },
                output_bytes: 1024,
            })?;
            let state = Arc::new(CloseState::default());
            let provider = Arc::new(Provider {
                state: state.clone(),
                calls: AtomicUsize::new(0),
            });
            let sandbox = client
                .sandboxes()
                .create()
                .package(PackageSource::bytes(wat::parse_str(CONNECT_WAT).unwrap()))
                .network_provider(provider.clone())
                .await?;
            let mut process = sandbox.command("main").spawn().await?;
            state.normal_started.notified().await;
            assert_eq!(state.normal.load(Ordering::SeqCst), 1);
            assert_eq!(state.active.load(Ordering::SeqCst), 1);
            assert!(
                process.wait().now_or_never().is_none(),
                "ordinary wait remains pending through close"
            );
            assert!(
                !process
                    .control()
                    .network_cancel
                    .as_ref()
                    .unwrap()
                    .requested(),
                "dropping the subscriber cannot even enqueue an owner-cancel request"
            );
            tokio::task::yield_now().await;
            assert_eq!(
                state.cancel.load(Ordering::SeqCst),
                0,
                "dropping a wait subscription must not request owner cancellation"
            );
            // The shared native Run observer is the actual exec/admission boundary; close
            // can start earlier during descriptor retirement, so do not infer exit from it.
            while !process.control().try_join_exited() {
                tokio::task::yield_now().await;
            }
            process.kill()?;
            assert!(
                process
                    .control()
                    .network_cancel
                    .as_ref()
                    .unwrap()
                    .requested()
            );
            state.cancel_started.notified().await;
            assert_eq!(state.cancel.load(Ordering::SeqCst), 1);
            assert_eq!(
                state.active.load(Ordering::SeqCst),
                2,
                "the Normal close future must remain owned after escalation"
            );
            assert_eq!(state.actual_completions.load(Ordering::SeqCst), 0);
            assert!(
                process.try_wait()?.is_none(),
                "Cancel is a request, not an actual retirement acknowledgement"
            );
            state.acknowledge();
            let output = process.wait().await?;
            assert_eq!(output.status.code(), 0);
            assert_eq!(
                output.reason,
                ExitReason::Exited,
                "cleanup cancellation cannot rewrite the guest's already observed exit"
            );
            assert_eq!(process.wait().await?, output);
            assert_eq!(state.active.load(Ordering::SeqCst), 0);
            assert_eq!(state.actual_completions.load(Ordering::SeqCst), 1);
            assert_eq!(
                provider.calls.load(Ordering::SeqCst),
                1,
                "escalation must not create a replacement socket"
            );
            sandbox.close().await?;
            client.shutdown().await
        })
        .await
        .expect("explicit close escalation joined the shared actual completion")
    }
}
