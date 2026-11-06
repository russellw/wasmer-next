//! One client-owned LocalSet for facade services; the facade owns guest threads.
use std::{
    future::Future,
    sync::{Arc, Mutex},
    thread::{JoinHandle, ThreadId},
};

use tokio::{
    runtime::{Handle, RuntimeFlavor},
    sync::{mpsc, oneshot, watch},
    task::LocalSet,
};
use wasixv2_host::{LocalFuture, ThreadStart};

use crate::{Error, Result};

enum Message {
    Start(ThreadStart),
    Stop,
}
#[derive(Default)]
struct State {
    closing: bool,
    active: usize,
    stop_sent: bool,
    failure: Option<String>,
}
struct Inner {
    sender: mpsc::Sender<Message>,
    state: Mutex<State>,
    runtime: Handle,
    thread: ThreadId,
    joined: Mutex<Option<JoinHandle<()>>>,
    stopped: watch::Receiver<bool>,
}

#[derive(Clone)]
pub(crate) struct Services(Arc<Inner>);
pub(crate) struct Lease(Arc<Inner>);

impl std::fmt::Debug for Services {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Services")
            .field("thread", &self.0.thread)
            .finish_non_exhaustive()
    }
}
impl Services {
    pub(crate) fn new() -> Result<Self> {
        let current = Handle::try_current()
            .ok()
            .filter(|h| h.runtime_flavor() == RuntimeFlavor::MultiThread);
        let (sender, mut receiver) = mpsc::channel(64);
        let (ready, initialized) = std::sync::mpsc::sync_channel(1);
        let (finished, stopped) = watch::channel(false);
        let joined = std::thread::Builder::new()
            .name("wasmer-sdk-services".into())
            .spawn(move || {
                let own = match current.as_ref() {
                    Some(_) => None,
                    None => match tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .thread_name("wasmer-sdk")
                        .build()
                    {
                        Ok(runtime) => Some(runtime),
                        Err(error) => {
                            let _ = ready.send(Err(error));
                            return;
                        }
                    },
                };
                let runtime = current.unwrap_or_else(|| own.as_ref().unwrap().handle().clone());
                if ready
                    .send(Ok((runtime.clone(), std::thread::current().id())))
                    .is_err()
                {
                    return;
                }
                let local = LocalSet::new();
                runtime.block_on(local.run_until(async {
                    while let Some(message) = receiver.recv().await {
                        match message {
                            Message::Start(start) => {
                                tokio::task::spawn_local(async move {
                                    start().await;
                                });
                            }
                            Message::Stop => {
                                receiver.close();
                                break;
                            }
                        }
                    }
                }));
                // Includes detached facade cleanup spawned while an owner retired.
                runtime.block_on(local);
                drop(own);
                finished.send_replace(true);
            })
            .map_err(|error| Error::Initialization {
                message: format!("unable to create SDK services: {error}"),
            })?;
        let (runtime, thread) = initialized
            .recv()
            .map_err(|error| Error::Initialization {
                message: error.to_string(),
            })?
            .map_err(|error| Error::Initialization {
                message: error.to_string(),
            })?;
        Ok(Self(Arc::new(Inner {
            sender,
            state: Mutex::default(),
            runtime,
            thread,
            joined: Mutex::new(Some(joined)),
            stopped,
        })))
    }
    fn lease(&self, cleanup: bool) -> Result<Lease> {
        let mut state = self.0.state.lock().unwrap();
        if state.stop_sent || (state.closing && !cleanup) {
            return Err(Error::ClientClosed);
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or_else(|| Error::InternalState {
                message: "SDK operation count exhausted".into(),
            })?;
        Ok(Lease(self.0.clone()))
    }
    pub(crate) fn admit(&self) -> Result<Lease> {
        self.lease(false)
    }
    pub(crate) fn retain_cleanup(&self) -> Result<Lease> {
        self.lease(true)
    }
    pub(crate) fn handle(&self) -> Handle {
        self.0.runtime.clone()
    }
    pub(crate) fn on_service_thread(&self) -> bool {
        std::thread::current().id() == self.0.thread
    }

    /// The Send factory crosses the boundary; its local future is constructed there.
    pub(crate) async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> LocalFuture<'static, Result<T>> + Send + 'static,
    ) -> Result<T> {
        let lease = self.lease(false)?;
        let (send, result) = oneshot::channel();
        self.0
            .sender
            .send(Message::Start(Box::new(move || {
                Box::pin(async move {
                    let result = work().await;
                    let _ = send.send(result);
                    drop(lease);
                })
            })))
            .await
            .map_err(|_| Error::ClientClosed)?;
        result.await.map_err(|_| Error::Task {
            message: "SDK service operation did not complete".into(),
        })?
    }
    /// A locally constructed supervisor is driven independently of public waiters.
    pub(crate) fn spawn_local(&self, work: LocalFuture<'static, ()>) -> Result<()> {
        if !self.on_service_thread() {
            return Err(Error::InternalState {
                message: "local supervisor requires SDK services".into(),
            });
        }
        let lease = self.lease(true)?;
        tokio::task::spawn_local(async move {
            work.await;
            drop(lease);
        });
        Ok(())
    }
    pub(crate) fn request_close(&self) {
        let mut state = self.0.state.lock().unwrap();
        state.closing = true;
        stop_if_idle(&self.0, &mut state);
    }

    /// User callbacks use the existing multi-thread runtime, never this LocalSet.
    /// The detached task retains its lease through completion and abandoned-result cleanup.
    pub(crate) async fn callback<T: Send + 'static, A: Future<Output = ()> + Send + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
        abandon: impl FnOnce(T) -> A + Send + 'static,
    ) -> Result<T> {
        self.start_callback(work, abandon)?
            .await
            .map_err(|_| Error::Task {
                message: "filesystem callback did not complete".into(),
            })
    }
    fn start_callback<T: Send + 'static, A: Future<Output = ()> + Send + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
        abandon: impl FnOnce(T) -> A + Send + 'static,
    ) -> Result<oneshot::Receiver<T>> {
        let lease = self.lease(true)?;
        let (send, result) = oneshot::channel();
        self.0.runtime.spawn(async move {
            let output = work.await;
            if let Err(output) = send.send(output) {
                abandon(output).await;
            }
            drop(lease);
        });
        Ok(result)
    }
    pub(crate) fn cleanup(
        &self,
        work: impl Future<Output = Result<()>> + Send + 'static,
    ) -> Result<()> {
        let lease = self.lease(true)?;
        let state = self.0.clone();
        self.0.runtime.spawn(async move {
            if let Err(error) = work.await {
                state
                    .state
                    .lock()
                    .unwrap()
                    .failure
                    .get_or_insert_with(|| error.to_string());
            }
            drop(lease);
        });
        Ok(())
    }

    pub(crate) async fn close(&self) -> Result<()> {
        {
            let mut state = self.0.state.lock().unwrap();
            state.closing = true;
            stop_if_idle(&self.0, &mut state);
        }
        let mut stopped = self.0.stopped.clone();
        while !*stopped.borrow_and_update() {
            stopped.changed().await.map_err(|_| Error::Task {
                message: "SDK service thread stopped unexpectedly".into(),
            })?;
        }
        if let Some(thread) = self.0.joined.lock().unwrap().take() {
            thread.join().map_err(|_| Error::Task {
                message: "SDK service thread panicked".into(),
            })?;
        }
        if let Some(message) = self.0.state.lock().unwrap().failure.clone() {
            return Err(Error::Task { message });
        }
        Ok(())
    }
}
fn stop_if_idle(inner: &Inner, state: &mut State) {
    if state.closing && state.active == 0 && !state.stop_sent {
        state.stop_sent = true;
        // Every queued Start owns a lease. At zero, the bounded channel has no
        // queued Start and its independent stop notification cannot be full.
        match inner.sender.try_send(Message::Stop) {
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                unreachable!("idle SDK service channel is full")
            }
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        state.active -= 1;
        stop_if_idle(&self.0, &mut state);
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.sender.try_send(Message::Stop);
    }
}
