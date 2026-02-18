//! QUIC Server FFI - Server operations

use std::ffi::CStr;
use std::os::raw::c_char;

use crate::quic_executor::{QuicExecutor, SendableCallback, UsizeCallback, VoidCallback};
use crate::error::QuicError;
use crate::{quic, types, QuicFfiResult, allocate};
use crate::quic::QuicConnectionHandle;
use crate::{check_executor_usize, check_executor_void, check_ptr_usize, check_ptr_void, ERR_NOT_RUNNING};

// ============================================
// QUIC Server FFI
// ============================================

/// Create server with self-signed certificate (testing only!)
/// Returns error code, result written to `result` parameter
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_server_new_self_signed(
    bind_addr: *const c_char,
    san_list: *const *const c_char,
    san_count: usize,
    transport_config: *const quic::QuicFfiTransportConfig,
    result: *mut QuicFfiResult,
) -> i32 {
    if result.is_null() {
        return types::QuicResult::InvalidParameter as i32;
    }

    if bind_addr.is_null() {
        unsafe { (*result).write_error_str("Bind address is required"); }
        return types::QuicResult::InvalidParameter as i32;
    }

    let server_result = (|| {
        let bind_addr_str = unsafe { CStr::from_ptr(bind_addr) }
            .to_str()
            .map_err(|_| QuicError::unknown("Invalid bind address".to_string()))?;

        let mut san_names = Vec::with_capacity(san_count);
        if !san_list.is_null() && san_count > 0 {
            for i in 0..san_count {
                let san_ptr = unsafe { *san_list.add(i) };
                if !san_ptr.is_null() {
                    if let Ok(s) = unsafe { CStr::from_ptr(san_ptr) }.to_str() {
                        san_names.push(s.to_string());
                    }
                }
            }
        }
        if san_names.is_empty() {
            san_names.push("localhost".to_string());
        }

        let san_refs: Vec<&str> = san_names.iter().map(|s| s.as_str()).collect();
        let mut builder = quic::QuicServer::builder().with_self_signed(&san_refs);

        if !transport_config.is_null() {
            let ffi_config = unsafe { &*transport_config };
            builder = builder.with_transport_config(quic::QuicTransportConfig::from(ffi_config));
        }

        builder.bind(bind_addr_str)
    })();

    unsafe { (*result).write_result(server_result) }
}

/// Create server with PEM certificate files
/// Returns error code, result written to `result` parameter
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_server_new_with_cert_files(
    bind_addr: *const c_char,
    cert_path: *const c_char,
    key_path: *const c_char,
    transport_config: *const quic::QuicFfiTransportConfig,
    result: *mut QuicFfiResult,
) -> i32 {
    if result.is_null() {
        return types::QuicResult::InvalidParameter as i32;
    }

    if bind_addr.is_null() || cert_path.is_null() || key_path.is_null() {
        unsafe { (*result).write_error_str("Bind address, cert path and key path are required"); }
        return types::QuicResult::InvalidParameter as i32;
    }

    let server_result = (|| {
        let bind_addr_str = unsafe { CStr::from_ptr(bind_addr) }
            .to_str()
            .map_err(|_| QuicError::unknown("Invalid bind address".to_string()))?;
        let cert_path_str = unsafe { CStr::from_ptr(cert_path) }
            .to_str()
            .map_err(|_| QuicError::unknown("Invalid certificate path".to_string()))?;
        let key_path_str = unsafe { CStr::from_ptr(key_path) }
            .to_str()
            .map_err(|_| QuicError::unknown("Invalid key path".to_string()))?;

        let mut builder = quic::QuicServer::builder()
            .with_cert_pem_files(cert_path_str, key_path_str)?;

        if !transport_config.is_null() {
            let ffi_config = unsafe { &*transport_config };
            builder = builder.with_transport_config(quic::QuicTransportConfig::from(ffi_config));
        }

        builder.bind(bind_addr_str)
    })();

    unsafe { (*result).write_result(server_result) }
}

/// Free server
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_server_free(server: *mut quic::QuicServer) {
    if !server.is_null() {
        unsafe { let _ = Box::from_raw(server); }
    }
}

/// Close server
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_server_close(
    server: *mut quic::QuicServer,
    error_code: u32,
    reason: *const u8,
    reason_len: usize,
) {
    if server.is_null() {
        return;
    }
    
    let reason_bytes = if reason.is_null() || reason_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(reason, reason_len) }
    };
    
    unsafe { (*server).close(error_code, reason_bytes) };
}

/// Get server local address
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_server_local_addr(
    server: *mut quic::QuicServer,
    addr_out: *mut *mut u8,
    len_out: *mut usize,
) -> bool {
    if server.is_null() || addr_out.is_null() || len_out.is_null() {
        return false;
    }
    
    let addr_str = unsafe { (*server).local_addr().to_string() };
    let addr_bytes = addr_str.as_bytes();
    
    let ptr = allocate(addr_bytes.len());
    if !ptr.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(addr_bytes.as_ptr(), ptr, addr_bytes.len());
            *addr_out = ptr;
            *len_out = addr_bytes.len();
        }
        true
    } else {
        false
    }
}

/// Accept incoming connection
///
/// Callback receives QuicConnectionHandle pointer on success.
/// The handle contains:
/// - connection pointer (for subsequent operations)
/// - stable_id (connection ID)
/// - remote_addr (remote address string)
///
/// Use `dart_quic_connection_handle_free` to free the handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_server_accept(
    executor: *mut QuicExecutor,
    server: *mut quic::QuicServer,
    callback: UsizeCallback,
) {
    check_executor_usize!(executor, callback);
    check_ptr_usize!(server, callback);

    let server_ptr = server as usize;
    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };

    if !exec.submit_async(async move {
        let server = unsafe { &*(server_ptr as *const quic::QuicServer) };
        match server.accept().await {
            Some(Ok(conn)) => {
                let handle = QuicConnectionHandle::new(conn);
                let handle_ptr = Box::into_raw(Box::new(handle)) as usize;
                (callback.0)(true, handle_ptr, std::ptr::null(), 0);
            }
            Some(Err(e)) => {
                let err = crate::FfiErrBuf::new(format!("{}", e));
                (callback.0)(false, 0, err.as_ptr(), err.len());
            }
            None => {
                // Server closed — signal completion with value=0
                (callback.0)(true, 0, std::ptr::null(), 0);
            }
        }
    }) {
        callback.0(false, 0, ERR_NOT_RUNNING.as_bytes().as_ptr(), ERR_NOT_RUNNING.len());
    }
}

/// Wait for all server connections to become idle (async)
///
/// Blocks asynchronously until all active connections are closed.
/// Should typically be called after `dart_quic_server_close` for a graceful shutdown.
///
/// # Safety
/// All pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_server_wait_idle(
    executor: *mut QuicExecutor,
    server: *mut quic::QuicServer,
    callback: VoidCallback,
) {
    check_executor_void!(executor, callback);
    check_ptr_void!(server, callback);

    let server_ptr = server as usize;
    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };

    if !exec.submit_async(async move {
        let server = unsafe { &*(server_ptr as *const quic::QuicServer) };
        server.wait_idle().await;
        (callback.0)(true, std::ptr::null(), 0);
    }) {
        let err = ERR_NOT_RUNNING.as_bytes();
        callback.0(false, err.as_ptr(), err.len());
    }
}

/// Get the number of currently open connections on the server
///
/// Returns 0 if the server pointer is null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_server_open_connections(
    server: *mut quic::QuicServer,
) -> usize {
    if server.is_null() {
        return 0;
    }
    unsafe { (*server).open_connections() }
}

/// Get server local port
///
/// Returns 0 if the server pointer is null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_server_local_port(
    server: *mut quic::QuicServer,
) -> u16 {
    if server.is_null() {
        return 0;
    }
    unsafe { (*server).local_port() }
}

/// Create a QUIC server asynchronously using unified FFI configuration
///
/// Must be called after `dart_quic_executor_init` because Quinn requires
/// an active tokio runtime context when creating the endpoint.
///
/// On success, the callback receives a `QuicServerHandle*` pointer (as usize).
/// The handle is allocated and owned by Rust; free it with `dart_quic_server_handle_free`.
///
/// # Safety
/// - `config` and all data it references must remain valid until the callback fires
///
/// # Parameters
/// - `executor`: Running QuicExecutor (must not be null)
/// - `bind_addr`: Address to bind, e.g. "0.0.0.0:4433"
/// - `config`: Pointer to FFI server configuration (must not be null)
/// - `callback`: UsizeCallback receiving QuicServerHandle* pointer on success
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_server_new_async(
    executor: *mut QuicExecutor,
    bind_addr: *const c_char,
    config: *const quic::QuicFfiServerConfig,
    callback: UsizeCallback,
) -> i32 {
    if executor.is_null() {
        return types::QuicResult::InvalidParameter as i32;
    }

    let executor_ref = unsafe { &*executor };
    if !executor_ref.is_running() {
        return types::QuicResult::RuntimeError as i32;
    }

    if bind_addr.is_null() || config.is_null() {
        return types::QuicResult::InvalidParameter as i32;
    }

    // Capture raw pointer values to send across the async boundary.
    // Safety: caller guarantees all pointers remain valid until the callback fires.
    let bind_addr_ptr = bind_addr as usize;
    let config_ptr = config as usize;
    let callback = SendableCallback(callback);

    executor_ref.submit_async(async move {
        let bind_addr_str = match unsafe { CStr::from_ptr(bind_addr_ptr as *const c_char) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                let err = b"Invalid bind address encoding";
                (callback.0)(false, 0, err.as_ptr(), err.len());
                return;
            }
        };
        let ffi_config = unsafe { &*(config_ptr as *const quic::QuicFfiServerConfig) };

        match ffi_config.build(bind_addr_str) {
            Ok(server) => {
                let handle = quic::QuicServerHandle::new(server);
                let handle_ptr = Box::into_raw(Box::new(handle)) as usize;
                (callback.0)(true, handle_ptr, std::ptr::null(), 0);
            }
            Err(e) => {
                let err = crate::FfiErrBuf::new(e.to_string());
                (callback.0)(false, 0, err.as_ptr(), err.len());
            }
        }
    });

    types::QuicResult::Success as i32
}

/// Free server handle and all its resources
///
/// This frees:
/// - The server itself
/// - The local_addr_ptr string
/// - The handle structure
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_server_handle_free(handle: *mut quic::QuicServerHandle) {
    if handle.is_null() {
        return;
    }

    let handle_ref = unsafe { &mut *handle };

    // Free the server itself
    if !handle_ref.server.is_null() {
        unsafe { let _ = Box::from_raw(handle_ref.server); }
    }

    // Free the local address string
    if !handle_ref.local_addr_ptr.is_null() && handle_ref.local_addr_len > 0 {
        crate::deallocate(handle_ref.local_addr_ptr, handle_ref.local_addr_len as usize);
    }

    // Free the handle struct itself
    unsafe { let _ = Box::from_raw(handle); }
}
