//! QUIC Stream Result Structures
//!
//! C-compatible structures for returning stream handles from async operations.

use crate::quic_executor::{QuicExecutor, SendableCallback, BytesCallback};
use crate::{allocate, ERR_NOT_RUNNING};
use crate::{check_executor_bytes, check_ptr_bytes};

/// C-compatible structure for stream pair
/// Contains both send and recv stream pointers (one or both may be null)
#[repr(C)]
pub struct QuicFfiStreamPair {
    /// Send stream pointer (null if not applicable)
    pub send_stream: *mut quinn::SendStream,
    /// Recv stream pointer (null if not applicable)
    pub recv_stream: *mut quinn::RecvStream,
}

impl QuicFfiStreamPair {
    /// Create a bidirectional stream pair
    pub fn bi(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send_stream: Box::into_raw(Box::new(send)),
            recv_stream: Box::into_raw(Box::new(recv)),
        }
    }
    
    /// Create a send-only stream pair (for open_uni)
    pub fn send_only(send: quinn::SendStream) -> Self {
        Self {
            send_stream: Box::into_raw(Box::new(send)),
            recv_stream: std::ptr::null_mut(),
        }
    }
    
    /// Create a recv-only stream pair (for accept_uni)
    pub fn recv_only(recv: quinn::RecvStream) -> Self {
        Self {
            send_stream: std::ptr::null_mut(),
            recv_stream: Box::into_raw(Box::new(recv)),
        }
    }
}

/// Free stream pair structure
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_stream_pair_free(pair: *mut QuicFfiStreamPair) {
    if !pair.is_null() {
        let stream_pair = unsafe { Box::from_raw(pair) };
        // Free individual streams if they exist
        if !stream_pair.send_stream.is_null() {
            unsafe { let _ = Box::from_raw(stream_pair.send_stream); }
        }
        if !stream_pair.recv_stream.is_null() {
            unsafe { let _ = Box::from_raw(stream_pair.recv_stream); }
        }
    }
}

/// Free send stream
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_send_stream_free(stream: *mut quinn::SendStream) {
    if !stream.is_null() {
        unsafe { let _ = Box::from_raw(stream); }
    }
}

/// Free recv stream
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_recv_stream_free(stream: *mut quinn::RecvStream) {
    if !stream.is_null() {
        unsafe { let _ = Box::from_raw(stream); }
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
/// - `stream`: Recv stream pointer
/// - `max_len`: Maximum bytes to read (will allocate this much memory)
/// - `callback`: Called with (success, data_ptr, data_len, error_ptr, error_len)
///   - On success: callback(true, buf, bytes_read, null, 0) where bytes_read <= max_len
///   - On EOF: callback(true, null, 0, null, 0)
///   - On error: callback(false, null, 0, error_ptr, error_len)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_recv_stream_read(
    executor: *mut QuicExecutor,
    stream: *mut quinn::RecvStream,
    max_len: usize,
    callback: BytesCallback,
) {
    check_executor_bytes!(executor, callback);
    check_ptr_bytes!(stream, callback);
    
    if max_len == 0 {
        let err = b"Invalid max length";
        callback(false, std::ptr::null_mut(), 0, err.as_ptr(), err.len());
        return;
    }
    
    let stream_ptr = stream as usize;
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
/// - `stream`: Recv stream pointer
/// - `exact_len`: Exact number of bytes to read
/// - `callback`: Called with (success, data_ptr, data_len, error_ptr, error_len)
///   - On success: callback(true, buf, exact_len, null, 0)
///   - On error: callback(false, null, 0, error_ptr, error_len)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_recv_stream_read_exact(
    executor: *mut QuicExecutor,
    stream: *mut quinn::RecvStream,
    exact_len: usize,
    callback: BytesCallback,
) {
    check_executor_bytes!(executor, callback);
    check_ptr_bytes!(stream, callback);
    
    if exact_len == 0 {
        let err = b"Invalid buffer length";
        callback(false, std::ptr::null_mut(), 0, err.as_ptr(), err.len());
        return;
    }
    
    let stream_ptr = stream as usize;
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
/// - `stream`: Recv stream pointer
/// - `size_limit`: Maximum bytes to read (prevents memory exhaustion)
/// - `callback`: Called with (success, data_ptr, data_len, error_ptr, error_len)
///   - On success: callback(true, buf, total_bytes, null, 0)
///   - On error: callback(false, null, 0, error_ptr, error_len)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_recv_stream_read_to_end(
    executor: *mut QuicExecutor,
    stream: *mut quinn::RecvStream,
    size_limit: usize,
    callback: BytesCallback,
) {
    check_executor_bytes!(executor, callback);
    check_ptr_bytes!(stream, callback);
    
    let stream_ptr = stream as usize;
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
/// - `stream`: Send stream pointer
/// - `data`: Data to write
/// - `data_len`: Data length
/// - `callback`: Called with (success, bytes_written, error_ptr, error_len)
///   - On success: callback(true, bytes_written, null, 0)
///   - On error: callback(false, 0, error_ptr, error_len)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_send_stream_write(
    executor: *mut QuicExecutor,
    stream: *mut quinn::SendStream,
    data: *const u8,
    data_len: usize,
    callback: crate::quic_executor::UsizeCallback,
) {
    use crate::{check_executor_usize, check_ptr_usize};
    
    check_executor_usize!(executor, callback);
    check_ptr_usize!(stream, callback);
    
    if data.is_null() || data_len == 0 {
        let err = b"Invalid data";
        callback(false, 0, err.as_ptr(), err.len());
        return;
    }
    
    // Copy data for async use (caller's buffer may be freed)
    let data_vec = unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec();
    
    let stream_ptr = stream as usize;
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
/// - `stream`: Send stream pointer
/// - `data`: Data to write
/// - `data_len`: Data length
/// - `callback`: Called with (success, error_ptr, error_len)
///   - On success: callback(true, null, 0)
///   - On error: callback(false, error_ptr, error_len)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_send_stream_write_all(
    executor: *mut QuicExecutor,
    stream: *mut quinn::SendStream,
    data: *const u8,
    data_len: usize,
    callback: crate::quic_executor::VoidCallback,
) {
    use crate::{check_executor_void, check_ptr_void};
    
    check_executor_void!(executor, callback);
    check_ptr_void!(stream, callback);
    
    if data.is_null() || data_len == 0 {
        let err = b"Invalid data";
        callback(false, err.as_ptr(), err.len());
        return;
    }
    
    // Copy data for async use
    let data_vec = unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec();
    
    let stream_ptr = stream as usize;
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
/// - `stream`: Send stream pointer
/// 
/// # Returns
/// - 0 (Success) on success
/// - Error code on failure
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_send_stream_finish(
    stream: *mut quinn::SendStream,
) -> i32 {
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

/// Get the identity of a send stream
/// 
/// Returns the stream ID index as a u64 value.
/// 
/// # Parameters
/// - `stream`: Send stream pointer
/// 
/// # Returns
/// - Stream ID index on success
/// - 0 if stream pointer is null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_send_stream_id(
    stream: *mut quinn::SendStream,
) -> u64 {
    if stream.is_null() {
        return 0;
    }
    
    // Use the public index() method to get the u64 value
    unsafe { (*stream).id().index() }
}

/// Get the identity of a recv stream
/// 
/// Returns the stream ID index as a u64 value.
/// 
/// # Parameters
/// - `stream`: Recv stream pointer
/// 
/// # Returns
/// - Stream ID index on success
/// - 0 if stream pointer is null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_recv_stream_id(
    stream: *mut quinn::RecvStream,
) -> u64 {
    if stream.is_null() {
        return 0;
    }
    
    // Use the public index() method to get the u64 value
    unsafe { (*stream).id().index() }
}

