//! QUIC Client FFI - Client, Connection, Stream operations

use std::ffi::CStr;
use std::os::raw::c_char;

use crate::ERR_NOT_RUNNING;
use crate::quic_executor::{
    BytesCallback, UsizeCallback, QuicExecutor, SendableCallback, VoidCallback,
};
use crate::quic_ffi_stream_result::QuicFfiStreamPair;
use crate::{allocate, deallocate, quic, types};
use crate::quic::QuicConnectionHandle;

use crate::{
    check_executor_bytes, check_executor_usize, check_executor_void,
    check_ptr_bytes, check_ptr_usize, check_ptr_void,
};

// ============================================
// QUIC Client FFI
// ============================================


/// Create QUIC client asynchronously (required when tokio runtime is managed by executor)
///
/// This function must be called after `dart_quic_executor_init` because it needs
/// to run inside the tokio runtime context.
///
/// # Safety
/// The `config` pointer and all data it references must remain valid until the callback is invoked.
///
/// Returns error code. Callback receives client pointer (as usize) on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_client_new_async(
    executor: *mut QuicExecutor,
    config: *const quic::QuicFfiClientConfig,
    callback: UsizeCallback,
) -> i32 {
    if executor.is_null() {
        return types::QuicResult::InvalidParameter as i32;
    }
    
    let executor_ref = unsafe { &*executor };
    if !executor_ref.is_running() {
        return types::QuicResult::RuntimeError as i32;
    }

    if config.is_null() {
        return types::QuicResult::InvalidParameter as i32;
    }

    let config_ptr = config as usize;
    let callback = SendableCallback(callback);
    
    executor_ref.submit_async(async move {
        let ffi_config = unsafe { &*(config_ptr as *const quic::QuicFfiClientConfig) };
        match ffi_config.build() {
            Ok(client) => {
                let ptr = Box::into_raw(Box::new(client)) as usize;
                (callback.0)(true, ptr, std::ptr::null(), 0);
            }
            Err(e) => {
                let msg = e.to_string();
                (callback.0)(false, 0, msg.as_ptr(), msg.len());
            }
        }
    });
    
    types::QuicResult::Success as i32
}

/// Free client
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_client_free(client: *mut quic::QuicClient) {
    if !client.is_null() {
        unsafe {
            let _ = Box::from_raw(client);
        }
    }
}

/// Close client (sync)
/// Returns error code
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_client_close(
    client: *mut quic::QuicClient,
    error_code: u32,
    reason: *const u8,
    reason_len: usize,
) -> i32 {
    if client.is_null() {
        return types::QuicResult::InvalidParameter as i32;
    }

    let reason_bytes = if reason.is_null() || reason_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(reason, reason_len) }
    };

    unsafe { (*client).close(error_code, reason_bytes) };
    types::QuicResult::Success as i32
}

/// Connect to server asynchronously
///
/// Callback receives QuicConnectionHandle pointer on success.
/// The handle contains:
/// - connection pointer (for subsequent operations)
/// - stable_id (connection ID)
/// - remote_addr (remote address string)
///
/// Use `dart_quic_connection_handle_free` to free the handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_client_connect(
    executor: *mut QuicExecutor,
    client: *mut quic::QuicClient,
    server_addr: *const c_char,
    server_name: *const c_char,
    callback: UsizeCallback,
) {
    check_executor_usize!(executor, callback);
    check_ptr_usize!(client, callback);

    // Parse addresses
    let addr = match unsafe { CStr::from_ptr(server_addr).to_str() } {
        Ok(s) => s.to_string(),
        Err(_) => {
            let err = b"Invalid server address";
            callback(false, 0, err.as_ptr(), err.len());
            return;
        }
    };

    let name = match unsafe { CStr::from_ptr(server_name).to_str() } {
        Ok(s) => s.to_string(),
        Err(_) => {
            let err = b"Invalid server name";
            callback(false, 0, err.as_ptr(), err.len());
            return;
        }
    };

    let client_ptr = client as usize;
    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };

    if !exec.submit_async(async move {
        let client = unsafe { &*(client_ptr as *const quic::QuicClient) };
        match client.connect(&addr, &name).await {
            Ok(conn) => {
                // Create handle with connection info
                let handle = QuicConnectionHandle::new(conn);
                let handle_ptr = Box::into_raw(Box::new(handle)) as usize;
                (callback.0)(true, handle_ptr, std::ptr::null(), 0);
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

/// Wait for client to become idle
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_client_wait_idle(
    executor: *mut QuicExecutor,
    client: *mut quic::QuicClient,
    callback: VoidCallback,
) {
    check_executor_void!(executor, callback);
    check_ptr_void!(client, callback);

    let client_ptr = client as usize;
    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };

    if !exec.submit_async(async move {
        let client = unsafe { &*(client_ptr as *const quic::QuicClient) };
        client.wait_idle().await;
        (callback.0)(true, std::ptr::null(), 0);
    }) {
        callback.0(false, ERR_NOT_RUNNING.as_bytes().as_ptr(), ERR_NOT_RUNNING.len());
    }
}

// ============================================
// QUIC Connection Handle FFI
// ============================================

/// Free connection handle and its resources
///
/// This frees:
/// - The connection itself
/// - The remote address string
/// - The handle structure
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_connection_handle_free(handle: *mut QuicConnectionHandle) {
    if handle.is_null() {
        return;
    }
    
    let handle_ref = unsafe { &mut *handle };
    
    // Free the connection
    if !handle_ref.connection.is_null() {
        unsafe {
            let _ = Box::from_raw(handle_ref.connection);
        }
    }
    
    // Free the remote address string
    if !handle_ref.remote_addr.is_null() && handle_ref.remote_addr_len > 0 {
        deallocate(handle_ref.remote_addr, handle_ref.remote_addr_len as usize);
    }
    
    // Free the handle itself
    unsafe {
        let _ = Box::from_raw(handle);
    }
}

/// Close connection (sync)
///
/// # Parameters
/// - `handle`: Connection handle
/// - `error_code`: Application error code
/// - `reason`: Close reason bytes (nullable)
/// - `reason_len`: Length of reason bytes
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_connection_close(
    handle: *mut QuicConnectionHandle,
    error_code: u32,
    reason: *const u8,
    reason_len: usize,
) {
    if handle.is_null() {
        return;
    }
    
    let handle_ref = unsafe { &*handle };
    if handle_ref.connection.is_null() {
        return;
    }

    let reason_bytes = if reason.is_null() || reason_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(reason, reason_len) }
    };

    unsafe { (*handle_ref.connection).close(error_code, reason_bytes) };
}

/// Open bidirectional stream
///
/// Returns QuicFfiStreamPair structure pointer via UsizeCallback.
///
/// # Parameters
/// - `executor`: Executor for async operations
/// - `handle`: Connection handle
/// - `callback`: Callback receiving stream pair pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_connection_open_bi(
    executor: *mut QuicExecutor,
    handle: *mut QuicConnectionHandle,
    callback: UsizeCallback,
) {
    check_executor_usize!(executor, callback);
    check_ptr_usize!(handle, callback);

    let conn_ptr = unsafe { (*handle).connection } as usize;
    if conn_ptr == 0 {
        let err = b"Invalid connection handle";
        callback(false, 0, err.as_ptr(), err.len());
        return;
    }

    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };

    if !exec.submit_async(async move {
        let conn = unsafe { &*(conn_ptr as *const quic::QuicConnection) };
        match conn.open_bi().await {
            Ok((send, recv)) => {
                let pair = Box::new(QuicFfiStreamPair::bi(send, recv));
                let pair_ptr = Box::into_raw(pair) as usize;
                (callback.0)(true, pair_ptr, std::ptr::null(), 0);
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

/// Open unidirectional stream (send only)
///
/// Returns QuicFfiStreamPair structure pointer via UsizeCallback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_connection_open_uni(
    executor: *mut QuicExecutor,
    handle: *mut QuicConnectionHandle,
    callback: UsizeCallback,
) {
    check_executor_usize!(executor, callback);
    check_ptr_usize!(handle, callback);

    let conn_ptr = unsafe { (*handle).connection } as usize;
    if conn_ptr == 0 {
        let err = b"Invalid connection handle";
        callback(false, 0, err.as_ptr(), err.len());
        return;
    }

    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };

    if !exec.submit_async(async move {
        let conn = unsafe { &*(conn_ptr as *const quic::QuicConnection) };
        match conn.open_uni().await {
            Ok(send) => {
                let pair = Box::new(QuicFfiStreamPair::send_only(send));
                let pair_ptr = Box::into_raw(pair) as usize;
                (callback.0)(true, pair_ptr, std::ptr::null(), 0);
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

/// Accept bidirectional stream
///
/// Returns QuicFfiStreamPair structure pointer via UsizeCallback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_connection_accept_bi(
    executor: *mut QuicExecutor,
    handle: *mut QuicConnectionHandle,
    callback: UsizeCallback,
) {
    check_executor_usize!(executor, callback);
    check_ptr_usize!(handle, callback);

    let conn_ptr = unsafe { (*handle).connection } as usize;
    if conn_ptr == 0 {
        let err = b"Invalid connection handle";
        callback(false, 0, err.as_ptr(), err.len());
        return;
    }

    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };

    if !exec.submit_async(async move {
        let conn = unsafe { &*(conn_ptr as *const quic::QuicConnection) };
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let pair = Box::new(QuicFfiStreamPair::bi(send, recv));
                let pair_ptr = Box::into_raw(pair) as usize;
                (callback.0)(true, pair_ptr, std::ptr::null(), 0);
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

/// Accept unidirectional stream (recv only)
///
/// Returns QuicFfiStreamPair structure pointer via UsizeCallback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_connection_accept_uni(
    executor: *mut QuicExecutor,
    handle: *mut QuicConnectionHandle,
    callback: UsizeCallback,
) {
    check_executor_usize!(executor, callback);
    check_ptr_usize!(handle, callback);

    let conn_ptr = unsafe { (*handle).connection } as usize;
    if conn_ptr == 0 {
        let err = b"Invalid connection handle";
        callback(false, 0, err.as_ptr(), err.len());
        return;
    }

    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };

    if !exec.submit_async(async move {
        let conn = unsafe { &*(conn_ptr as *const quic::QuicConnection) };
        match conn.accept_uni().await {
            Ok(recv) => {
                let pair = Box::new(QuicFfiStreamPair::recv_only(recv));
                let pair_ptr = Box::into_raw(pair) as usize;
                (callback.0)(true, pair_ptr, std::ptr::null(), 0);
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

/// Send datagram (sync, unreliable)
///
/// # Parameters
/// - `handle`: Connection handle
/// - `data`: Data to send
/// - `data_len`: Length of data
///
/// # Returns
/// - QuicResult::Success on success
/// - Error code on failure
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_connection_send_datagram(
    handle: *mut QuicConnectionHandle,
    data: *const u8,
    data_len: usize,
) -> i32 {
    if handle.is_null() || data.is_null() {
        return types::QuicResult::InvalidParameter as i32;
    }
    
    let conn = unsafe { (*handle).connection };
    if conn.is_null() {
        return types::QuicResult::InvalidParameter as i32;
    }

    let data_bytes = unsafe { std::slice::from_raw_parts(data, data_len) };

    match unsafe { (*conn).send_datagram(bytes::Bytes::copy_from_slice(data_bytes)) } {
        Ok(_) => types::QuicResult::Success as i32,
        Err(e) => e.code_value(),
    }
}

/// Read datagram (async)
///
/// # Parameters
/// - `executor`: Executor for async operations
/// - `handle`: Connection handle
/// - `callback`: Callback receiving datagram data
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_connection_read_datagram(
    executor: *mut QuicExecutor,
    handle: *mut QuicConnectionHandle,
    callback: BytesCallback,
) {
    check_executor_bytes!(executor, callback);
    check_ptr_bytes!(handle, callback);

    let conn_ptr = unsafe { (*handle).connection } as usize;
    if conn_ptr == 0 {
        let err = b"Invalid connection handle";
        callback(false, std::ptr::null_mut(), 0, err.as_ptr(), err.len());
        return;
    }

    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };

    if !exec.submit_async(async move {
        let conn = unsafe { &*(conn_ptr as *const quic::QuicConnection) };
        match conn.read_datagram().await {
            Ok(data) => {
                let len = data.len();
                let ptr = allocate(len);
                if !ptr.is_null() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, len);
                    }
                    (callback.0)(true, ptr, len, std::ptr::null(), 0);
                } else {
                    let err = b"Allocation failed";
                    (callback.0)(false, std::ptr::null_mut(), 0, err.as_ptr(), err.len());
                }
            }
            Err(e) => {
                let err = format!("{}", e);
                (callback.0)(false, std::ptr::null_mut(), 0, err.as_ptr(), err.len());
            }
        }
    }) {
        callback.0(
            false,
            std::ptr::null_mut(),
            0,
            ERR_NOT_RUNNING.as_bytes().as_ptr(),
            ERR_NOT_RUNNING.len(),
        );
    }
}
