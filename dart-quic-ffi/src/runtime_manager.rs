// Explicitly implement Send and Sync traits for RuntimeManager
unsafe impl Send for RuntimeManager {}
unsafe impl Sync for RuntimeManager {}

use tokio::runtime::{Builder, Runtime};
use std::sync::Arc;

/// Tokio Runtime Manager
/// Each instance manages its own Tokio runtime (Arc for thread safety).
/// When dropped, the runtime is destroyed.
#[derive(Clone, Debug)]
pub struct RuntimeManager {
    runtime: Arc<Runtime>,
}

impl RuntimeManager {
    /// Create a new Tokio runtime manager
    /// threads == 0: use default thread count (CPU cores)
    /// threads == 1: current-thread runtime
    /// threads > 1: multi-threaded runtime with specified thread count
    pub fn new(threads: usize) -> Self {
        let runtime = if threads == 0 {
            Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to create default multi-threaded Tokio runtime")
        } else if threads == 1 {
            Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create current-thread Tokio runtime")
        } else {
            Builder::new_multi_thread()
                .worker_threads(threads)
                .enable_all()
                .build()
                .expect("Failed to create multi-threaded Tokio runtime")
        };
        Self { runtime: Arc::new(runtime) }
    }

    /// Get an Arc reference to the inner Tokio runtime (thread safe)
    pub fn get_runtime(&self) -> Arc<Runtime> {
        self.runtime.clone()
    }

    /// Spawn a future on the runtime
    /// This can be called from any thread
    pub fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.runtime.spawn(future)
    }
}
