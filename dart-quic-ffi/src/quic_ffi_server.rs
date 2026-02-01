//! QUIC Server FFI - Server operations

use std::ffi::CStr;
use std::os::raw::c_char;

use crate::quic_executor::{QuicExecutor, SendableCallback, UsizeCallback};
use crate::error::QuicError;
use crate::{quic, types, QuicFfiResult, allocate};
use crate::quic::QuicConnectionHandle;
use crate::{check_executor_usize, check_ptr_usize, ERR_NOT_RUNNING};

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
        unsafe { *result = QuicFfiResult::error_str("Bind address is required"); }
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
            let config = quic::QuicTransportConfig::from(ffi_config);
            builder = builder.with_transport_config(config);
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
        unsafe { *result = QuicFfiResult::error_str("Bind address, cert path and key path are required"); }
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
            let config = quic::QuicTransportConfig::from(ffi_config);
            builder = builder.with_transport_config(config);
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
                // Create handle with connection info
                let handle = QuicConnectionHandle::new(conn);
                let handle_ptr = Box::into_raw(Box::new(handle)) as usize;
                (callback.0)(true, handle_ptr, std::ptr::null(), 0);
            }
            Some(Err(e)) => {
                let err = format!("{}", e);
                (callback.0)(false, 0, err.as_ptr(), err.len());
            }
            None => {
                let err = b"Server closed";
                (callback.0)(false, 0, err.as_ptr(), err.len());
            }
        }
    }) {
        callback.0(false, 0, ERR_NOT_RUNNING.as_bytes().as_ptr(), ERR_NOT_RUNNING.len());
    }
}
