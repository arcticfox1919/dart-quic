/// Simplified QUIC async executor
/// 
/// Manages tokio runtime only. Provides a simple `submit_async` method for async tasks.
/// Resources (clients, connections, streams) are owned by Dart via raw pointers.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use once_cell::sync::OnceCell;

use crate::runtime_manager::RuntimeManager;

// ============================================
// Callback Types
// ============================================

/// Callback for void result
pub type VoidCallback = extern "C" fn(success: bool, error_ptr: *const u8, error_len: usize);

/// Callback for bool result  
pub type BoolCallback = extern "C" fn(success: bool, value: bool, error_ptr: *const u8, error_len: usize);

/// Callback for usize result (used for pointers/handles)
pub type UsizeCallback = extern "C" fn(success: bool, value: usize, error_ptr: *const u8, error_len: usize);

/// Callback for bytes result
pub type BytesCallback = extern "C" fn(success: bool, ptr: *mut u8, len: usize, error_ptr: *const u8, error_len: usize);

/// Callback for returning QuicFfiResult (used for async operations that return structures)
pub type ResultCallback = extern "C" fn(result: *mut crate::QuicFfiResult);

/// Wrapper to make function pointers Send + Sync
#[derive(Clone, Copy)]
pub struct SendableCallback<T>(pub T);

unsafe impl<T> Send for SendableCallback<T> {}
unsafe impl<T> Sync for SendableCallback<T> {}

// ============================================
// QUIC Executor
// ============================================

/// Simplified QUIC executor - only manages tokio runtime
pub struct QuicExecutor {
    /// Tokio runtime manager
    runtime: Arc<OnceCell<RuntimeManager>>,
    /// Running state
    running: Arc<AtomicBool>,
}

impl QuicExecutor {
    /// Create a new executor
    pub fn new() -> Self {
        Self {
            runtime: Arc::new(OnceCell::new()),
            running: Arc::new(AtomicBool::new(false)),
        }
    }
    
    /// Initialize the tokio runtime
    pub fn init_runtime(&self, threads: usize, callback: BoolCallback) {
        let running = Arc::clone(&self.running);
        let runtime = Arc::clone(&self.runtime);
        let callback = SendableCallback(callback);
        
        std::thread::spawn(move || {
            let manager = RuntimeManager::new(threads);
            let success = runtime.set(manager).is_ok();
            running.store(success, Ordering::Release);
            if success {
                (callback.0)(true, true, std::ptr::null(), 0);
            } else {
                let err = b"Failed to initialize runtime";
                (callback.0)(false, false, err.as_ptr(), err.len());
            }
        });
    }
    
    /// Check if runtime is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
    
    /// Shutdown the executor
    pub fn shutdown(&self) {
        self.running.store(false, Ordering::Release);
    }
    
    /// Submit an async task for execution
    pub fn submit_async<F>(&self, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if !self.running.load(Ordering::Acquire) {
            return false;
        }
        
        if let Some(manager) = self.runtime.get() {
            manager.spawn(future);
            true
        } else {
            false
        }
    }
}

impl Default for QuicExecutor {
    fn default() -> Self {
        Self::new()
    }
}
