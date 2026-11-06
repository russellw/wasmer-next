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
        #[cfg(feature = "napi-v8")] napi: wasmer_napi::NapiCtx,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            signaller: Mutex::new(Some(signaller)),
            stdin,
            outputs,
            exit: AtomicU8::new(EXIT_NONE),
            observer,
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
        for output in &self.outputs {
            output.close();
        }
        if self.record_exit_if_running(EXIT_TERMINATED_FORCED) {
            self.force_exit();
        }
    }
    fn kill_timed_out(&self) {
        for output in &self.outputs {
            output.close();
        }
        if self.record_exit_if_running(EXIT_TIMED_OUT) {
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
        if self.observer.observed_result().is_none() {
            if let Some(napi) = self.napi.lock().unwrap().as_ref() {
                napi.terminate_all();
            }
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
