use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

/// Shared bounded retention for one process output stream.
#[derive(Clone, Debug)]
pub(crate) struct CaptureHandle {
    bytes: Arc<Mutex<Vec<u8>>>,
    truncated: Arc<AtomicBool>,
    limit: usize,
}

impl CaptureHandle {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            bytes: Arc::new(Mutex::new(Vec::with_capacity(limit.min(64 * 1024)))),
            truncated: Arc::new(AtomicBool::new(false)),
            limit,
        }
    }

    pub(crate) fn snapshot(&self) -> (Vec<u8>, bool) {
        (
            self.bytes.lock().expect("capture lock poisoned").clone(),
            self.truncated.load(Ordering::Acquire),
        )
    }

    pub(crate) fn retain(&self, bytes: &[u8]) {
        let mut retained = self.bytes.lock().expect("capture lock poisoned");
        let available = self.limit.saturating_sub(retained.len());
        let amount = available.min(bytes.len());
        retained.extend_from_slice(&bytes[..amount]);
        if amount < bytes.len() {
            self.truncated.store(true, Ordering::Release);
        }
    }
}
