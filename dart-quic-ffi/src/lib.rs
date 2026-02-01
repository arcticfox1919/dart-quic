//! dart-quic-ffi - QUIC FFI bindings for Dart
//! 
//! This library provides FFI bindings for QUIC protocol operations.
//! 
//! Module organization:
//! - lib.rs: Common types, executor, memory manager, transport config
//! - quic_ffi_client.rs: Client, Connection, Stream FFI
//! - quic_ffi_server.rs: Server FFI

pub mod runtime_manager;
pub mod memory_manager;
pub mod quic_executor;
pub mod types;
pub mod error;
pub mod quic;
pub mod quic_ffi_stream_result;
pub mod quic_ffi_endpoint;
pub mod quic_ffi_client;
pub mod quic_ffi_server;

use quic_executor::{QuicExecutor, BoolCallback};
use error::QuicError;
pub use memory_manager::{
    allocate, deallocate, memory_stats, MemoryStats,
    initialize_memory_manager, initialize_memory_manager_with_config,
    destroy_memory_manager, is_memory_manager_available, PoolConfig
};

// ============================================
// FFI Generic Result Structure
// ============================================

/// Generic FFI result structure for C API interop.
/// Used for sync operations that need to return both a handle and potential error.
#[repr(C)]
pub struct QuicFfiResult {
    pub handle: *mut std::ffi::c_void,
    pub error_msg: *mut u8,
    pub error_msg_len: usize,
}

impl QuicFfiResult {
    /// Create a success result with handle
    pub fn success<T>(handle: *mut T) -> Self {
        Self {
            handle: handle as *mut std::ffi::c_void,
            error_msg: std::ptr::null_mut(),
            error_msg_len: 0,
        }
    }
    
    /// Create a null/empty result (no error, no handle)
    pub fn null() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            error_msg: std::ptr::null_mut(),
            error_msg_len: 0,
        }
    }
    
    /// Create an error result with message
    pub fn error(err: &QuicError) -> Self {
        let mut result = Self::null();
        if let Some(msg) = err.message() {
            let msg_bytes = msg.as_bytes();
            let ptr = allocate(msg_bytes.len());
            if !ptr.is_null() {
                unsafe {
                    std::ptr::copy_nonoverlapping(msg_bytes.as_ptr(), ptr, msg_bytes.len());
                }
                result.error_msg = ptr;
                result.error_msg_len = msg_bytes.len();
            }
        }
        result
    }
    
    /// Create an error result from string
    pub fn error_str(msg: &str) -> Self {
        let mut result = Self::null();
        let msg_bytes = msg.as_bytes();
        let ptr = allocate(msg_bytes.len());
        if !ptr.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(msg_bytes.as_ptr(), ptr, msg_bytes.len());
            }
            result.error_msg = ptr;
            result.error_msg_len = msg_bytes.len();
        }
        result
    }
    
    /// Create result from Result type
    pub fn from_result<T, E: std::fmt::Display>(result: Result<*mut T, E>) -> Self {
        match result {
            Ok(ptr) => Self::success(ptr),
            Err(e) => Self::error_str(&e.to_string()),
        }
    }
    
    /// Write result from Result<T, QuicError> to self, returns error code
    /// This method boxes the value and writes the pointer to handle
    pub fn write_result<T>(&mut self, result: Result<T, QuicError>) -> i32 {
        match result {
            Ok(value) => {
                self.handle = Box::into_raw(Box::new(value)) as *mut std::ffi::c_void;
                self.error_msg = std::ptr::null_mut();
                self.error_msg_len = 0;
                types::QuicResult::Success as i32
            }
            Err(e) => {
                let code = e.code_value();
                self.handle = std::ptr::null_mut();
                if let Some(msg) = e.message() {
                    let msg_bytes = msg.as_bytes();
                    let ptr = allocate(msg_bytes.len());
                    if !ptr.is_null() {
                        unsafe {
                            std::ptr::copy_nonoverlapping(msg_bytes.as_ptr(), ptr, msg_bytes.len());
                        }
                        self.error_msg = ptr;
                        self.error_msg_len = msg_bytes.len();
                    }
                }
                code
            }
        }
    }

    /// Write error string to existing result (for parameter validation)
    /// 
    /// This method modifies the existing result in-place without allocating new QuicFfiResult,
    /// preventing memory leaks when the result pointer is passed from upper layer.
    pub fn write_error_str(&mut self, msg: &str) {
        self.handle = std::ptr::null_mut();
        let msg_bytes = msg.as_bytes();
        let ptr = allocate(msg_bytes.len());
        if !ptr.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(msg_bytes.as_ptr(), ptr, msg_bytes.len());
            }
            self.error_msg = ptr;
            self.error_msg_len = msg_bytes.len();
        } else {
            self.error_msg = std::ptr::null_mut();
            self.error_msg_len = 0;
        }
    }
}

/// Free error message allocated by QuicFfiResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_ffi_result_free_error(result: *mut QuicFfiResult) {
    if !result.is_null() {
        let r = unsafe { &mut *result };
        if !r.error_msg.is_null() && r.error_msg_len > 0 {
            deallocate(r.error_msg, r.error_msg_len);
            r.error_msg = std::ptr::null_mut();
            r.error_msg_len = 0;
        }
    }
}

// ============================================
// Error Constants (pub for submodules)
// ============================================

// ============================================
// Error Constants (pub for submodules)
// ============================================

// Error message strings - use &str as base type, convert to &[u8] when needed via .as_bytes()
#[doc(hidden)]
pub static ERR_EXECUTOR_NULL: &str = "Executor is null";
#[doc(hidden)]
pub static ERR_NOT_RUNNING: &str = "Executor not running";
#[doc(hidden)]
pub static ERR_PTR_NULL: &str = "Pointer is null";
#[doc(hidden)]
pub static ERR_SUBMIT_FAILED: &str = "Failed to submit async task";
#[doc(hidden)]
pub static ERR_CONFIG_REQUIRED: &str = "Config is required";

// ============================================
// FFI Check Macros
// ============================================

/// Check if executor is null, return early with UsizeCallback error
#[macro_export]
macro_rules! check_executor_usize {
    ($executor:expr, $callback:expr) => {
        if $executor.is_null() {
            $callback(false, 0, $crate::ERR_EXECUTOR_NULL.as_bytes().as_ptr(), $crate::ERR_EXECUTOR_NULL.len());
            return;
        }
    };
}

/// Check if pointer is null, return early with UsizeCallback error
#[macro_export]
macro_rules! check_ptr_usize {
    ($ptr:expr, $callback:expr) => {
        if $ptr.is_null() {
            $callback(false, 0, $crate::ERR_PTR_NULL.as_bytes().as_ptr(), $crate::ERR_PTR_NULL.len());
            return;
        }
    };
}

/// Check if executor is null, return early with VoidCallback error
#[macro_export]
macro_rules! check_executor_void {
    ($executor:expr, $callback:expr) => {
        if $executor.is_null() {
            $callback(false, $crate::ERR_EXECUTOR_NULL.as_bytes().as_ptr(), $crate::ERR_EXECUTOR_NULL.len());
            return;
        }
    };
}

/// Check if pointer is null, return early with VoidCallback error
#[macro_export]
macro_rules! check_ptr_void {
    ($ptr:expr, $callback:expr) => {
        if $ptr.is_null() {
            $callback(false, $crate::ERR_PTR_NULL.as_bytes().as_ptr(), $crate::ERR_PTR_NULL.len());
            return;
        }
    };
}

/// Check if executor is null, return early with BytesCallback error
#[macro_export]
macro_rules! check_executor_bytes {
    ($executor:expr, $callback:expr) => {
        if $executor.is_null() {
            $callback(false, std::ptr::null_mut(), 0, $crate::ERR_EXECUTOR_NULL.as_bytes().as_ptr(), $crate::ERR_EXECUTOR_NULL.len());
            return;
        }
    };
}

/// Check if pointer is null, return early with BytesCallback error
#[macro_export]
macro_rules! check_ptr_bytes {
    ($ptr:expr, $callback:expr) => {
        if $ptr.is_null() {
            $callback(false, std::ptr::null_mut(), 0, $crate::ERR_PTR_NULL.as_bytes().as_ptr(), $crate::ERR_PTR_NULL.len());
            return;
        }
    };
}

/// Check if executor is null, return early with ResultCallback error
#[macro_export]
macro_rules! check_executor_result {
    ($executor:expr, $callback:expr) => {
        if $executor.is_null() {
            let mut result = $crate::QuicFfiResult::error_str($crate::ERR_EXECUTOR_NULL);
            $callback(&mut result as *mut $crate::QuicFfiResult);
            return;
        }
        if !unsafe { (*$executor).is_running() } {
            let mut result = $crate::QuicFfiResult::error_str($crate::ERR_NOT_RUNNING);
            $callback(&mut result as *mut $crate::QuicFfiResult);
            return;
        }
    };
}

/// Check if pointer is null, return early with ResultCallback error
#[macro_export]
macro_rules! check_ptr_result {
    ($ptr:expr, $callback:expr) => {
        if $ptr.is_null() {
            let mut result = $crate::QuicFfiResult::error_str($crate::ERR_PTR_NULL);
            $callback(&mut result as *mut $crate::QuicFfiResult);
            return;
        }
    };
}

// ============================================
// Executor FFI
// ============================================

#[unsafe(no_mangle)]
pub extern "C" fn dart_quic_executor_new() -> *mut QuicExecutor {
    Box::into_raw(Box::new(QuicExecutor::new()))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_executor_init(
    executor: *mut QuicExecutor,
    threads: usize,
    callback: BoolCallback,
) {
    if executor.is_null() {
        callback(false, false, ERR_EXECUTOR_NULL.as_ptr(), ERR_EXECUTOR_NULL.len());
        return;
    }
    unsafe { (*executor).init_runtime(threads, callback) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_executor_is_running(executor: *mut QuicExecutor) -> bool {
    if executor.is_null() { return false }
    unsafe { (*executor).is_running() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_executor_free(executor: *mut QuicExecutor) {
    if !executor.is_null() {
        let executor_box = unsafe { Box::from_raw(executor) };
        executor_box.shutdown();
        drop(executor_box);
    }
}

// ============================================
// Memory Manager FFI
// ============================================

#[unsafe(no_mangle)]
pub extern "C" fn dart_allocate_memory(size: usize) -> *mut u8 {
    allocate(size)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_free_memory(ptr: *mut u8, size: usize) {
    deallocate(ptr, size);
}

#[unsafe(no_mangle)]
pub extern "C" fn dart_get_memory_stats() -> *const MemoryStats {
    match memory_stats() {
        Some(stats) => Box::into_raw(Box::new(stats)),
        None => std::ptr::null(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_free_memory_stats(stats: *mut MemoryStats) {
    if !stats.is_null() {
        unsafe { let _ = Box::from_raw(stats); }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dart_initialize_memory_manager() -> bool {
    initialize_memory_manager()
}

#[unsafe(no_mangle)]
pub extern "C" fn dart_initialize_memory_manager_with_config(
    tiny_pool_size: i32,
    small_pool_size: i32,
    medium_pool_size: i32,
    large_pool_size: i32,
    huge_pool_size: i32,
    xlarge_pool_size: i32,
) -> bool {
    let config = PoolConfig {
        tiny_pool_size: if tiny_pool_size >= 0 { Some(tiny_pool_size as usize) } else { None },
        small_pool_size: if small_pool_size >= 0 { Some(small_pool_size as usize) } else { None },
        medium_pool_size: if medium_pool_size >= 0 { Some(medium_pool_size as usize) } else { None },
        large_pool_size: if large_pool_size >= 0 { Some(large_pool_size as usize) } else { None },
        huge_pool_size: if huge_pool_size >= 0 { Some(huge_pool_size as usize) } else { None },
        xlarge_pool_size: if xlarge_pool_size >= 0 { Some(xlarge_pool_size as usize) } else { None },
    };
    initialize_memory_manager_with_config(config)
}

#[unsafe(no_mangle)]
pub extern "C" fn dart_destroy_memory_manager() -> bool {
    destroy_memory_manager()
}

#[unsafe(no_mangle)]
pub extern "C" fn dart_is_memory_manager_available() -> bool {
    is_memory_manager_available()
}

// ============================================
// QUIC Transport Config FFI
// ============================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_transport_config_default(result: *mut QuicFfiResult) -> i32 {
    if result.is_null() {
        return types::QuicResult::InvalidParameter as i32;
    }
    
    unsafe { (*result).write_result(Ok(quic::QuicFfiTransportConfig::default())) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_transport_config_free(config: *mut quic::QuicFfiTransportConfig) {
    if !config.is_null() {
        unsafe { let _ = Box::from_raw(config); }
    }
}
