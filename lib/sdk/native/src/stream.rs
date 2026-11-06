use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use crossbeam_queue::SegQueue;
use futures::task::AtomicWaker;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};

const MAX_PIPE_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug)]
enum PipeMessage {
    Data(Vec<u8>),
    Close,
}

#[derive(Debug)]
struct PipeState {
    buffered: AtomicUsize,
    capacity: usize,
    closed: AtomicBool,
    writers: SegQueue<Arc<WriterWaiter>>,
    enqueue: Mutex<()>,
    reader: AtomicWaker,
}

#[derive(Debug, Default)]
struct WriterWaiter {
    queued: AtomicBool,
    waker: AtomicWaker,
}

impl PipeState {
    fn wake_writers(&self) {
        // Each producer (including terminal echo) needs its own registration.
        // A single AtomicWaker loses notifications when another producer waits.
        // Bound the drain so concurrently re-registering writers cannot starve
        // the reader. A writer arriving later rechecks capacity after registering.
        for _ in 0..self.writers.len() {
            if let Some(writer) = self.writers.pop() {
                writer.queued.store(false, Ordering::Release);
                writer.waker.wake();
            }
        }
    }
}

/// Create a byte-bounded asynchronous pipe without a blocking mutex.
///
/// The native pipe retains the original byte bound and mpsc storage. A short
/// enqueue lock orders data with EOF; mpsc sees only a no-op Waker, so waking
/// public readers and writers always happens after that lock is released.
pub(crate) fn bounded_pipe(capacity: usize) -> (PipeReader, PipeWriter, PipeCloser) {
    let (sender, receiver) = unbounded_channel();
    let state = Arc::new(PipeState {
        buffered: AtomicUsize::new(0),
        capacity: capacity.max(1),
        closed: AtomicBool::new(false),
        writers: SegQueue::new(),
        enqueue: Mutex::new(()),
        reader: AtomicWaker::new(),
    });
    (
        PipeReader {
            receiver,
            state: Arc::clone(&state),
            pending: None,
            offset: 0,
            eof: false,
        },
        PipeWriter {
            sender: sender.clone(),
            state: Arc::clone(&state),
            active: true,
            owns_lifetime: true,
            waiter: Arc::default(),
        },
        PipeCloser { sender, state },
    )
}

#[derive(Clone, Debug)]
pub(crate) struct PipeCloser {
    sender: UnboundedSender<PipeMessage>,
    state: Arc<PipeState>,
}

impl PipeCloser {
    pub(crate) fn close(&self) {
        let changed = {
            let _order = self.state.enqueue.lock().unwrap();
            if self.state.closed.swap(true, Ordering::AcqRel) {
                false
            } else {
                let _ = self.sender.send(PipeMessage::Close);
                true
            }
        };
        if changed {
            self.state.reader.wake();
            self.state.wake_writers();
        }
    }
}

#[derive(Debug)]
pub(crate) struct PipeReader {
    receiver: UnboundedReceiver<PipeMessage>,
    state: Arc<PipeState>,
    pending: Option<Vec<u8>>,
    offset: usize,
    eof: bool,
}

impl PipeReader {
    fn poll_read_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        self.state.reader.register(cx.waker());
        let mut queue_context = Context::from_waker(std::task::Waker::noop());
        if let Some(pending) = &self.pending {
            return Poll::Ready(Ok(pending.len().saturating_sub(self.offset)));
        }
        if self.eof {
            return Poll::Ready(Ok(0));
        }

        loop {
            match self.receiver.poll_recv(&mut queue_context) {
                Poll::Ready(Some(PipeMessage::Data(bytes))) if bytes.is_empty() => {}
                Poll::Ready(Some(PipeMessage::Data(bytes))) => {
                    let available = bytes.len();
                    self.pending = Some(bytes);
                    self.offset = 0;
                    return Poll::Ready(Ok(available));
                }
                Poll::Ready(Some(PipeMessage::Close) | None) => {
                    self.eof = true;
                    return Poll::Ready(Ok(0));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncRead for PipeReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.state.reader.register(cx.waker());
        let mut queue_context = Context::from_waker(std::task::Waker::noop());
        if buffer.remaining() == 0 || self.eof {
            return Poll::Ready(Ok(()));
        }
        let initially_filled = buffer.filled().len();

        loop {
            if let Some(pending) = self.pending.take() {
                let available = &pending[self.offset..];
                let read = available.len().min(buffer.remaining());
                buffer.put_slice(&available[..read]);
                self.offset += read;
                self.state.buffered.fetch_sub(read, Ordering::AcqRel);
                self.state.wake_writers();

                if self.offset < pending.len() {
                    self.pending = Some(pending);
                } else {
                    self.offset = 0;
                }
                if buffer.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }

            match self.receiver.poll_recv(&mut queue_context) {
                Poll::Ready(Some(PipeMessage::Data(bytes))) => {
                    self.pending = Some(bytes);
                }
                Poll::Ready(Some(PipeMessage::Close) | None) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending if buffer.filled().len() > initially_filled => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        {
            let _order = self.state.enqueue.lock().unwrap();
            self.receiver.close();
            self.state.closed.store(true, Ordering::Release);
        }
        self.state.reader.wake();
        self.state.wake_writers();
    }
}

#[derive(Debug)]
pub(crate) struct PipeWriter {
    sender: UnboundedSender<PipeMessage>,
    state: Arc<PipeState>,
    active: bool,
    owns_lifetime: bool,
    waiter: Arc<WriterWaiter>,
}

impl PipeWriter {
    /// Create a writer that can add data while this pipe remains open, without
    /// keeping the reader alive on its own. This is used for terminal echo:
    /// the guest's stdout owns the stream lifetime, while the line discipline
    /// is merely another producer.
    pub(crate) fn tap(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            state: Arc::clone(&self.state),
            active: self.active,
            owns_lifetime: false,
            waiter: Arc::default(),
        }
    }

    fn poll_capacity(&self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if !self.active || self.state.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }

        let buffered = self.state.buffered.load(Ordering::Acquire);
        if buffered < self.state.capacity {
            return Poll::Ready(Ok(self.state.capacity - buffered));
        }

        self.waiter.waker.register(cx.waker());
        if !self.waiter.queued.swap(true, Ordering::AcqRel) {
            self.state.writers.push(Arc::clone(&self.waiter));
        }
        if self.state.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let buffered = self.state.buffered.load(Ordering::Acquire);
        if buffered < self.state.capacity {
            Poll::Ready(Ok(self.state.capacity - buffered))
        } else {
            Poll::Pending
        }
    }

    fn close(&mut self) {
        if self.active && self.owns_lifetime {
            PipeCloser {
                sender: self.sender.clone(),
                state: self.state.clone(),
            }
            .close();
        }
        self.active = false;
    }
}

impl AsyncWrite for PipeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            let available = match self.poll_capacity(cx) {
                Poll::Ready(Ok(available)) => available,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            };
            let written = bytes.len().min(available).min(MAX_PIPE_CHUNK_BYTES);
            let buffered = self.state.buffered.load(Ordering::Acquire);
            if buffered >= self.state.capacity {
                continue;
            }
            let written = written.min(self.state.capacity - buffered);
            if self
                .state
                .buffered
                .compare_exchange_weak(
                    buffered,
                    buffered + written,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }

            let queued = {
                let _order = self.state.enqueue.lock().unwrap();
                !self.state.closed.load(Ordering::Acquire)
                    && self
                        .sender
                        .send(PipeMessage::Data(bytes[..written].to_vec()))
                        .is_ok()
            };
            if !queued {
                self.state.buffered.fetch_sub(written, Ordering::AcqRel);
                self.state.wake_writers();
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            self.state.reader.wake();
            return Poll::Ready(Ok(written));
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.close();
        Poll::Ready(Ok(()))
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use futures::task::noop_waker_ref;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{PipeCloser, bounded_pipe};
    use std::sync::Arc;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[tokio::test]
    async fn pipe_preserves_bytes_and_delivers_eof() {
        let (mut reader, mut writer, _closer) = bounded_pipe(4);
        let write = async {
            writer.write_all(b"abcdefgh").await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let read = async {
            let mut output = Vec::new();
            reader.read_to_end(&mut output).await.unwrap();
            output
        };

        let ((), output) = tokio::join!(write, read);
        assert_eq!(output, b"abcdefgh");
    }

    #[tokio::test]
    async fn external_close_wakes_both_ends() {
        let (mut reader, mut writer, closer) = bounded_pipe(1);
        writer.write_all(b"x").await.unwrap();
        closer.close();

        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"x");
        assert_eq!(
            writer.write_all(b"y").await.unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
    }

    #[tokio::test]
    async fn read_readiness_waits_for_data_and_reports_eof() {
        let (mut reader, mut writer, _closer) = bounded_pipe(4);
        let mut cx = Context::from_waker(noop_waker_ref());

        assert!(matches!(
            Pin::new(&mut reader).poll_read_ready(&mut cx),
            Poll::Pending
        ));

        writer.write_all(b"x").await.unwrap();
        assert!(matches!(
            Pin::new(&mut reader).poll_read_ready(&mut cx),
            Poll::Ready(Ok(1))
        ));

        let mut byte = [0];
        reader.read_exact(&mut byte).await.unwrap();
        writer.shutdown().await.unwrap();
        assert!(matches!(
            Pin::new(&mut reader).poll_read_ready(&mut cx),
            Poll::Ready(Ok(0))
        ));
    }

    #[tokio::test]
    async fn tap_writes_without_keeping_the_pipe_open() {
        let (mut reader, mut writer, _closer) = bounded_pipe(4);
        let mut tap = writer.tap();

        tap.write_all(b"x").await.unwrap();
        writer.shutdown().await.unwrap();

        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"x");
        assert_eq!(
            tap.write_all(b"y").await.unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
    }

    #[tokio::test]
    async fn draining_a_full_pipe_wakes_output_and_terminal_echo() {
        use futures::task::{ArcWake, waker};
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use tokio::io::AsyncWrite;

        #[derive(Default)]
        struct WakeFlag(AtomicBool);
        impl ArcWake for WakeFlag {
            fn wake_by_ref(flag: &Arc<Self>) {
                flag.0.store(true, Ordering::SeqCst);
            }
        }

        let (mut reader, mut output, _) = bounded_pipe(2);
        let mut echo = output.tap();
        output.write_all(b"xx").await.unwrap();
        let output_flag = Arc::new(WakeFlag::default());
        let echo_flag = Arc::new(WakeFlag::default());
        let output_waker = waker(output_flag.clone());
        let echo_waker = waker(echo_flag.clone());
        assert!(
            Pin::new(&mut output)
                .poll_write(&mut Context::from_waker(&output_waker), b"a")
                .is_pending()
        );
        assert!(
            Pin::new(&mut echo)
                .poll_write(&mut Context::from_waker(&echo_waker), b"b")
                .is_pending()
        );
        reader.read_exact(&mut [0; 2]).await.unwrap();
        assert!(
            output_flag.0.load(Ordering::SeqCst),
            "guest output lost its wake-up to terminal echo"
        );
        assert!(
            echo_flag.0.load(Ordering::SeqCst),
            "terminal echo lost its wake-up to guest output"
        );
    }
    #[test]
    fn reader_wake_can_reenter_close_without_losing_accepted_data() {
        use std::task::{Wake, Waker};
        struct CloseOnWake(PipeCloser);
        impl Wake for CloseOnWake {
            fn wake(self: Arc<Self>) {
                self.0.close();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.close();
            }
        }
        for readiness in [false, true] {
            let (mut reader, mut writer, closer) = bounded_pipe(16);
            let waker = Waker::from(Arc::new(CloseOnWake(closer)));
            let mut context = Context::from_waker(&waker);
            if readiness {
                assert!(
                    Pin::new(&mut reader)
                        .poll_read_ready(&mut context)
                        .is_pending()
                );
            } else {
                assert!(
                    Pin::new(&mut reader)
                        .poll_read(&mut context, &mut ReadBuf::new(&mut [0; 1]))
                        .is_pending()
                );
            }
            let accepted = futures::executor::block_on(writer.write(b"accepted")).unwrap();
            let mut received = Vec::new();
            futures::executor::block_on(reader.read_to_end(&mut received)).unwrap();
            assert_eq!(received, &b"accepted"[..accepted]);
            assert!(futures::executor::block_on(writer.write(b"late")).is_err());
        }
    }

    #[test]
    fn concurrent_close_drains_every_successfully_accepted_byte() {
        use std::sync::Barrier;
        for _ in 0..100 {
            let (mut reader, writer, closer) = bounded_pipe(1024);
            let mut first = writer.tap();
            let mut second = writer.tap();
            let gate = Arc::new(Barrier::new(3));
            let a = gate.clone();
            let b = gate.clone();
            let first = std::thread::spawn(move || {
                a.wait();
                futures::executor::block_on(first.write(&[b'a'; 512])).unwrap_or(0)
            });
            let second = std::thread::spawn(move || {
                b.wait();
                futures::executor::block_on(second.write(&[b'b'; 512])).unwrap_or(0)
            });
            gate.wait();
            closer.close();
            let accepted_a = first.join().unwrap();
            let accepted_b = second.join().unwrap();
            let mut received = Vec::new();
            futures::executor::block_on(reader.read_to_end(&mut received)).unwrap();
            assert_eq!(received.len(), accepted_a + accepted_b);
            assert_eq!(
                received.iter().filter(|byte| **byte == b'a').count(),
                accepted_a
            );
            assert_eq!(
                received.iter().filter(|byte| **byte == b'b').count(),
                accepted_b
            );
            drop(writer);
        }
    }
}
