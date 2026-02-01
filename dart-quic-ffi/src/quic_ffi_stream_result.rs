//! QUIC Stream Result Structures
//!
//! C-compatible structures for returning stream handles from async operations.

use crate::quic_executor::{QuicExecutor, SendableCallback, BytesCallback};
use crate::{allocate, ERR_NOT_RUNNING, check_executor_bytes};

// ============================================================================
// Stream Type Checking Macros
// ============================================================================

/// Check if handle is a valid recv stream (for BytesCallback)
macro_rules! check_recv_stream_bytes {
    ($handle:expr, $callback:expr) => {
        if $handle.is_null() {
            let err = b"Stream handle is null";
            $callback(false, std::ptr::null_mut(), 0, err.as_ptr(), err.len());
            return;
        }
        let stream_type = unsafe { (*$handle).stream_type };
        if stream_type != QuicStreamType::Recv as u8 {
            let err = b"Invalid stream type: expected Recv stream";
            $callback(false, std::ptr::null_mut(), 0, err.as_ptr(), err.len());
            return;
        }
    };
}

/// Check if handle is a valid send stream (for UsizeCallback)
macro_rules! check_send_stream_usize {
    ($handle:expr, $callback:expr) => {
        if $handle.is_null() {
            let err = b"Stream handle is null";
            $callback(false, 0, err.as_ptr(), err.len());
            return;
        }
        let stream_type = unsafe { (*$handle).stream_type };
        if stream_type != QuicStreamType::Send as u8 {
            let err = b"Invalid stream type: expected Send stream";
            $callback(false, 0, err.as_ptr(), err.len());
            return;
        }
    };
}

/// Check if handle is a valid send stream (for VoidCallback)
macro_rules! check_send_stream_void {
    ($handle:expr, $callback:expr) => {
        if $handle.is_null() {
            let err = b"Stream handle is null";
            $callback(false, err.as_ptr(), err.len());
            return;
        }
        let stream_type = unsafe { (*$handle).stream_type };
        if stream_type != QuicStreamType::Send as u8 {
            let err = b"Invalid stream type: expected Send stream";
            $callback(false, err.as_ptr(), err.len());
            return;
        }
    };
}

/// Check if handle is a valid send stream (for sync functions returning i32)
macro_rules! check_send_stream_sync {
    ($handle:expr) => {
        if $handle.is_null() {
            return crate::types::QuicResult::InvalidParameter as i32;
        }
        let stream_type = unsafe { (*$handle).stream_type };
        if stream_type != QuicStreamType::Send as u8 {
            return crate::types::QuicResult::InvalidParameter as i32;
        }
    };
}

// ============================================================================
// Stream Handle Structure
// ============================================================================

/// Stream type enumeration
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicStreamType {
    /// Receive stream (accept_uni, or recv side of bi stream)
    Recv = 0,
    /// Send stream (open_uni, or send side of bi stream)
    Send = 1,
}

/// Unified stream handle with metadata
///
/// FFI-friendly structure wrapping a stream pointer, its ID, and type.
/// The stream pointer can be either `SendStream*` or `RecvStream*` depending on `stream_type`.
#[repr(C)]
pub struct QuicFfiStreamHandle {
    /// Stream pointer (cast to void* for FFI, actual type depends on stream_type)
    pub stream: *mut std::ffi::c_void,
    /// Stream ID
    pub stream_id: u64,
    /// Stream type (0 = Recv, 1 = Send)
    pub stream_type: u8,
}

impl QuicFfiStreamHandle {
    /// Create a new send stream handle
    pub fn new_send(stream: quinn::SendStream) -> Self {
        let stream_id = stream.id().index();
        Self {
            stream: Box::into_raw(Box::new(stream)) as *mut std::ffi::c_void,
            stream_id,
            stream_type: QuicStreamType::Send as u8,
        }
    }

    /// Create a new recv stream handle
    pub fn new_recv(stream: quinn::RecvStream) -> Self {
        let stream_id = stream.id().index();
        Self {
            stream: Box::into_raw(Box::new(stream)) as *mut std::ffi::c_void,
            stream_id,
            stream_type: QuicStreamType::Recv as u8,
        }
    }
}

/// C-compatible structure for stream pair
/// Contains both send and recv stream handles (one or both may be null)
#[repr(C)]
pub struct QuicFfiStreamPair {
    /// Send stream handle (null if not applicable)
    pub send_handle: *mut QuicFfiStreamHandle,
    /// Recv stream handle (null if not applicable)
    pub recv_handle: *mut QuicFfiStreamHandle,
}

impl QuicFfiStreamPair {
    /// Create a bidirectional stream pair
    pub fn bi(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send_handle: Box::into_raw(Box::new(QuicFfiStreamHandle::new_send(send))),
            recv_handle: Box::into_raw(Box::new(QuicFfiStreamHandle::new_recv(recv))),
        }
    }
    
    /// Create a send-only stream pair (for open_uni)
    pub fn send_only(send: quinn::SendStream) -> Self {
        Self {
            send_handle: Box::into_raw(Box::new(QuicFfiStreamHandle::new_send(send))),
            recv_handle: std::ptr::null_mut(),
        }
    }
    
    /// Create a recv-only stream pair (for accept_uni)
    pub fn recv_only(recv: quinn::RecvStream) -> Self {
        Self {
            send_handle: std::ptr::null_mut(),
            recv_handle: Box::into_raw(Box::new(QuicFfiStreamHandle::new_recv(recv))),
        }
    }
}

/// Free stream pair structure
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_stream_pair_free(pair: *mut QuicFfiStreamPair) {
    if !pair.is_null() {
        let stream_pair = unsafe { Box::from_raw(pair) };
        // Free individual stream handles if they exist
        if !stream_pair.send_handle.is_null() {
            unsafe { dart_quic_stream_handle_free(stream_pair.send_handle); }
        }
        if !stream_pair.recv_handle.is_null() {
            unsafe { dart_quic_stream_handle_free(stream_pair.recv_handle); }
        }
    }
}

/// Free stream handle (works for both send and recv streams)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_stream_handle_free(handle: *mut QuicFfiStreamHandle) {
    if handle.is_null() {
        return;
    }
    
    let handle_ref = unsafe { Box::from_raw(handle) };
    if !handle_ref.stream.is_null() {
        // Free the stream based on its type
        match handle_ref.stream_type {
            0 => {
                // Recv stream
                unsafe {
                    let _ = Box::from_raw(handle_ref.stream as *mut quinn::RecvStream);
                }
            }
            1 => {
                // Send stream
                unsafe {
                    let _ = Box::from_raw(handle_ref.stream as *mut quinn::SendStream);
                }
            }
            _ => {
                // Invalid type, skip freeing stream (already freed handle itself)
            }
        }
    }
}

// ============================================
// RecvStream Read Operations
// ============================================

/// Read data contiguously from the stream
/// 
/// Returns the number of bytes read via callback, or None (ptr=null, len=0) if stream is finished.
/// 
/// **Memory Management Note:**
/// This function allocates `max_len` bytes upfront to avoid an extra memory copy.
/// The actual bytes read (n) may be less than `max_len`, meaning some allocated memory
/// may be unused. Callers should:
/// - Use reasonable `max_len` values (e.g., 4KB-64KB, not 1MB+)
/// - Only access the first `n` bytes returned in the callback
/// - Call `dart_free_memory(ptr, max_len)` to deallocate when done
/// 
/// This design prioritizes zero-copy performance over memory efficiency.
/// 
/// # Parameters
/// - `executor`: QuicExecutor for async execution
/// - `handle`: Stream handle (must be of type Recv)
/// - `max_len`: Maximum bytes to read (will allocate this much memory)
/// - `callback`: Called with (success, data_ptr, data_len, error_ptr, error_len)
///   - On success: callback(true, buf, bytes_read, null, 0) where bytes_read <= max_len
///   - On EOF: callback(true, null, 0, null, 0)
///   - On error: callback(false, null, 0, error_ptr, error_len)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_recv_stream_read(
    executor: *mut QuicExecutor,
    handle: *mut QuicFfiStreamHandle,
    max_len: usize,
    callback: BytesCallback,
) {
    check_executor_bytes!(executor, callback);
    check_recv_stream_bytes!(handle, callback);
    
    if max_len == 0 {
        let err = b"Invalid max length";
        callback(false, std::ptr::null_mut(), 0, err.as_ptr(), err.len());
        return;
    }
    
    let stream_ptr = unsafe { (*handle).stream } as usize;
    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };
    
    if !exec.submit_async(async move {
        let stream = unsafe { &mut *(stream_ptr as *mut quinn::RecvStream) };
        
        // Allocate max_len bytes directly for zero-copy reading
        // Trade-off: May waste (max_len - n) bytes, but avoids memory copy
        let out_ptr = allocate(max_len);
        if out_ptr.is_null() {
            let err = b"Allocation failed";
            (callback.0)(false, std::ptr::null_mut(), 0, err.as_ptr(), err.len());
            return;
        }
        
        // Convert to usize for Send safety across await
        let ptr_addr = out_ptr as usize;
        
        // Create mutable slice from allocated memory
        let buf = unsafe { std::slice::from_raw_parts_mut(ptr_addr as *mut u8, max_len) };
        
        match stream.read(buf).await {
            Ok(Some(n)) => {
                // Successfully read n bytes (n <= max_len)
                // Caller receives ptr with n valid bytes, must free max_len bytes
                (callback.0)(true, ptr_addr as *mut u8, n, std::ptr::null(), 0);
            }
            Ok(None) => {
                // EOF reached, deallocate unused memory
                crate::deallocate(ptr_addr as *mut u8, max_len);
                (callback.0)(true, std::ptr::null_mut(), 0, std::ptr::null(), 0);
            }
            Err(e) => {
                // Error occurred, deallocate unused memory
                crate::deallocate(ptr_addr as *mut u8, max_len);
                let err = format!("{}", e);
                (callback.0)(false, std::ptr::null_mut(), 0, err.as_ptr(), err.len());
            }
        }
    }) {
        callback.0(false, std::ptr::null_mut(), 0, ERR_NOT_RUNNING.as_bytes().as_ptr(), ERR_NOT_RUNNING.len());
    }
}

/// Read exact number of bytes from the stream
/// 
/// Reads exactly `exact_len` bytes or fails.
/// 
/// **Memory Management Note:**
/// This function allocates exactly `exact_len` bytes since we know the exact size needed.
/// No memory waste occurs. Caller must free exactly `exact_len` bytes.
/// 
/// # Parameters
/// - `executor`: QuicExecutor for async execution
/// - `handle`: Stream handle (must be of type Recv)
/// - `exact_len`: Exact number of bytes to read
/// - `callback`: Called with (success, data_ptr, data_len, error_ptr, error_len)
///   - On success: callback(true, buf, exact_len, null, 0)
///   - On error: callback(false, null, 0, error_ptr, error_len)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_recv_stream_read_exact(
    executor: *mut QuicExecutor,
    handle: *mut QuicFfiStreamHandle,
    exact_len: usize,
    callback: BytesCallback,
) {
    check_executor_bytes!(executor, callback);
    check_recv_stream_bytes!(handle, callback);
    
    if exact_len == 0 {
        let err = b"Invalid buffer length";
        callback(false, std::ptr::null_mut(), 0, err.as_ptr(), err.len());
        return;
    }
    
    let stream_ptr = unsafe { (*handle).stream } as usize;
    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };
    
    if !exec.submit_async(async move {
        let stream = unsafe { &mut *(stream_ptr as *mut quinn::RecvStream) };
        
        // Allocate exact size needed (no waste)
        let out_ptr = allocate(exact_len);
        if out_ptr.is_null() {
            let err = b"Allocation failed";
            (callback.0)(false, std::ptr::null_mut(), 0, err.as_ptr(), err.len());
            return;
        }
        
        // Convert to usize for Send safety across await
        let ptr_addr = out_ptr as usize;
        
        // Create mutable slice from allocated memory
        let buf = unsafe { std::slice::from_raw_parts_mut(ptr_addr as *mut u8, exact_len) };
        
        match stream.read_exact(buf).await {
            Ok(()) => {
                // Successfully read exact_len bytes
                (callback.0)(true, ptr_addr as *mut u8, exact_len, std::ptr::null(), 0);
            }
            Err(e) => {
                // Error occurred, deallocate
                crate::deallocate(ptr_addr as *mut u8, exact_len);
                let err = format!("{}", e);
                (callback.0)(false, std::ptr::null_mut(), 0, err.as_ptr(), err.len());
            }
        }
    }) {
        callback.0(false, std::ptr::null_mut(), 0, ERR_NOT_RUNNING.as_bytes().as_ptr(), ERR_NOT_RUNNING.len());
    }
}

/// Read all remaining data from the stream
/// 
/// Reads until EOF, up to `size_limit` bytes.
/// 
/// # Parameters
/// - `executor`: QuicExecutor for async execution
/// - `handle`: Stream handle (must be of type Recv)
/// - `size_limit`: Maximum bytes to read (prevents memory exhaustion)
/// - `callback`: Called with (success, data_ptr, data_len, error_ptr, error_len)
///   - On success: callback(true, buf, total_bytes, null, 0)
///   - On error: callback(false, null, 0, error_ptr, error_len)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_recv_stream_read_to_end(
    executor: *mut QuicExecutor,
    handle: *mut QuicFfiStreamHandle,
    size_limit: usize,
    callback: BytesCallback,
) {
    check_executor_bytes!(executor, callback);
    check_recv_stream_bytes!(handle, callback);
    
    let stream_ptr = unsafe { (*handle).stream } as usize;
    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };
    
    if !exec.submit_async(async move {
        let stream = unsafe { &mut *(stream_ptr as *mut quinn::RecvStream) };
        
        match stream.read_to_end(size_limit).await {
            Ok(data) => {
                if data.is_empty() {
                    (callback.0)(true, std::ptr::null_mut(), 0, std::ptr::null(), 0);
                } else {
                    let ptr = allocate(data.len());
                    if !ptr.is_null() {
                        unsafe {
                            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
                        }
                        (callback.0)(true, ptr, data.len(), std::ptr::null(), 0);
                    } else {
                        let err = b"Allocation failed";
                        (callback.0)(false, std::ptr::null_mut(), 0, err.as_ptr(), err.len());
                    }
                }
            }
            Err(e) => {
                let err = format!("{}", e);
                (callback.0)(false, std::ptr::null_mut(), 0, err.as_ptr(), err.len());
            }
        }
    }) {
        callback.0(false, std::ptr::null_mut(), 0, ERR_NOT_RUNNING.as_bytes().as_ptr(), ERR_NOT_RUNNING.len());
    }
}

// ============================================
// SendStream Write Operations
// ============================================

/// Write bytes to the send stream
/// 
/// Returns the number of bytes written. May write less than the full buffer due to
/// congestion and flow control.
/// 
/// # Parameters
/// - `executor`: QuicExecutor for async execution
/// - `handle`: Stream handle (must be of type Send)
/// - `data`: Data to write
/// - `data_len`: Data length
/// - `callback`: Called with (success, bytes_written, error_ptr, error_len)
///   - On success: callback(true, bytes_written, null, 0)
///   - On error: callback(false, 0, error_ptr, error_len)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_send_stream_write(
    executor: *mut QuicExecutor,
    handle: *mut QuicFfiStreamHandle,
    data: *const u8,
    data_len: usize,
    callback: crate::quic_executor::UsizeCallback,
) {
    use crate::check_executor_usize;
    
    check_executor_usize!(executor, callback);
    check_send_stream_usize!(handle, callback);
    
    if data.is_null() || data_len == 0 {
        let err = b"Invalid data";
        callback(false, 0, err.as_ptr(), err.len());
        return;
    }
    
    // Copy data for async use (caller's buffer may be freed)
    let data_vec = unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec();
    
    let stream_ptr = unsafe { (*handle).stream } as usize;
    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };
    
    if !exec.submit_async(async move {
        let stream = unsafe { &mut *(stream_ptr as *mut quinn::SendStream) };
        
        match stream.write(&data_vec).await {
            Ok(n) => {
                (callback.0)(true, n, std::ptr::null(), 0);
            }
            Err(e) => {
                let err = format!("{}", e);
                (callback.0)(false, 0, err.as_ptr(), err.len());
            }
        }
    }) {
        callback.0(false, 0, ERR_NOT_RUNNING.as_bytes().as_ptr(), ERR_NOT_RUNNING.len());
    }
}

/// Write all bytes to the send stream
/// 
/// Writes the entire buffer, looping internally if needed due to flow control.
/// 
/// # Parameters
/// - `executor`: QuicExecutor for async execution
/// - `handle`: Stream handle (must be of type Send)
/// - `data`: Data to write
/// - `data_len`: Data length
/// - `callback`: Called with (success, error_ptr, error_len)
///   - On success: callback(true, null, 0)
///   - On error: callback(false, error_ptr, error_len)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_send_stream_write_all(
    executor: *mut QuicExecutor,
    handle: *mut QuicFfiStreamHandle,
    data: *const u8,
    data_len: usize,
    callback: crate::quic_executor::VoidCallback,
) {
    use crate::check_executor_void;
    
    check_executor_void!(executor, callback);
    check_send_stream_void!(handle, callback);
    
    if data.is_null() || data_len == 0 {
        let err = b"Invalid data";
        callback(false, err.as_ptr(), err.len());
        return;
    }
    
    // Copy data for async use
    let data_vec = unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec();
    
    let stream_ptr = unsafe { (*handle).stream } as usize;
    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };
    
    if !exec.submit_async(async move {
        let stream = unsafe { &mut *(stream_ptr as *mut quinn::SendStream) };
        
        match stream.write_all(&data_vec).await {
            Ok(()) => {
                (callback.0)(true, std::ptr::null(), 0);
            }
            Err(e) => {
                let err = format!("{}", e);
                (callback.0)(false, err.as_ptr(), err.len());
            }
        }
    }) {
        callback.0(false, ERR_NOT_RUNNING.as_bytes().as_ptr(), ERR_NOT_RUNNING.len());
    }
}

/// Notify the peer that no more data will be written to this stream (sync)
/// 
/// It is an error to write to a stream after finishing it.
/// 
/// # Parameters
/// - `handle`: Stream handle (must be of type Send)
/// 
/// # Returns
/// - 0 (Success) on success
/// - Error code on failure
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_send_stream_finish(
    handle: *mut QuicFfiStreamHandle,
) -> i32 {
    check_send_stream_sync!(handle);
    
    let stream = unsafe { (*handle).stream } as *mut quinn::SendStream;
    if stream.is_null() {
        return crate::types::QuicResult::InvalidParameter as i32;
    }
    
    match unsafe { (*stream).finish() } {
        Ok(()) => crate::types::QuicResult::Success as i32,
        Err(_) => crate::types::QuicResult::StreamClosed as i32,
    }
}

// ============================================
// Stream ID Operations
// ============================================
// Note: Stream IDs are now directly accessible via QuicFfiStreamHandle.stream_id field
// No separate functions needed

