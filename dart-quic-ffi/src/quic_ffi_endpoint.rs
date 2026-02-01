//! QUIC Endpoint FFI bindings
//!
//! Provides C API for unified QUIC endpoint management supporting:
//! - Client-only mode (outgoing connections)
//! - Server-only mode (incoming connections)
//! - Bidirectional mode (both outgoing and incoming)

use std::net::{SocketAddr, Ipv4Addr};
use std::ffi::CStr;

use crate::{
    QuicFfiResult,
    quic_executor::{QuicExecutor, UsizeCallback, VoidCallback, SendableCallback},
    quic,
    quic::QuicConnectionHandle,
    error::QuicError,
    types,
    allocate,
};

// Import check macros and error constants
use crate::{
    ERR_PTR_NULL,
    check_executor_void, check_ptr_void, check_executor_usize, check_ptr_usize,
};

// ============================================
// Endpoint Creation and Configuration
// ============================================

/// Create a QUIC endpoint with specified configuration
///
/// # Parameters
/// - `config`: Endpoint configuration (mode, bind IP, bind port)
/// - `client_config`: Client config handle (nullable based on mode)
/// - `server_config`: Server config handle (nullable based on mode)
/// - `result`: Output parameter for endpoint pointer or error
///
/// # Returns
/// - 0 on success (endpoint pointer in result)
/// - Non-zero error code on failure
///
/// # Mode Requirements
/// - ClientOnly: client_config must be provided, server_config must be null
/// - ServerOnly: server_config must be provided, client_config must be null
/// - Bidirectional: both client_config and server_config must be provided
///
/// # Safety
/// - config and result must be valid pointers
/// - client_config/server_config must be valid or null based on mode
/// Create a QUIC endpoint
///
/// # Parameters
/// - `config`: Endpoint configuration (mode and bind address)
/// - `client`: QuicClient pointer (nullable, required for Client/Bidirectional modes, will be consumed)
/// - `server`: QuicServer pointer (nullable, required for Server/Bidirectional modes, will be consumed)
/// - `result`: Result output structure
///
/// # Returns
/// - 0 on success (result.data contains endpoint pointer)
/// - Error code on failure (result.error contains error details)
///
/// # Mode Requirements
/// - ClientOnly: client required, server must be null
/// - ServerOnly: server required, client must be null
/// - Bidirectional: both client and server must be provided
///
/// # Safety
/// - config and result must be valid pointers
/// - client/server must be valid or null based on mode
/// - client/server will be consumed and must not be used after this call
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_endpoint_create(
    config: *const quic::QuicFfiEndpointConfig,
    client_config: *const quic::QuicFfiClientConfig,
    server_config: *const quic::QuicFfiServerConfig,
    result: *mut QuicFfiResult,
) -> i32 {
    if result.is_null() {
        return types::QuicResult::InvalidParameter as i32;
    }

    // Validate config
    if config.is_null() {
        unsafe {
            (*result).write_error_str("Endpoint config is null");
        }
        return types::QuicResult::InvalidParameter as i32;
    }

    let config_ref = unsafe { &*config };

    // Validate config based on mode
    let validation_error = match config_ref.mode {
        quic::QuicEndpointMode::ClientOnly => {
            if client_config.is_null() {
                Some("ClientOnly mode requires client_config")
            } else if !server_config.is_null() {
                Some("ClientOnly mode must not have server_config")
            } else {
                None
            }
        }
        quic::QuicEndpointMode::ServerOnly => {
            if server_config.is_null() {
                Some("ServerOnly mode requires server_config")
            } else if !client_config.is_null() {
                Some("ServerOnly mode must not have client_config")
            } else {
                None
            }
        }
        quic::QuicEndpointMode::Bidirectional => {
            if client_config.is_null() {
                Some("Bidirectional mode requires client_config")
            } else if server_config.is_null() {
                Some("Bidirectional mode requires server_config")
            } else {
                None
            }
        }
    };

    if let Some(error) = validation_error {
        unsafe {
            (*result).write_error_str(error);
        }
        return types::QuicResult::InvalidParameter as i32;
    }

    // Parse bind address
    let bind_ip = if config_ref.bind_ip == 0 {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::from(u32::from_be(config_ref.bind_ip))
    };
    let bind_addr = SocketAddr::from((bind_ip, config_ref.bind_port));

    // Build endpoint
    let endpoint_result = (|| -> Result<*mut quic::QuicEndpoint, QuicError> {
        let mut builder = quic::QuicEndpoint::builder();

        // Build and add client config if present
        if !client_config.is_null() {
            let client_ffi_cfg = unsafe { &*client_config };
            let quinn_client_config = client_ffi_cfg.build_quinn_config()?;
            builder = builder.with_client_config(quinn_client_config);
        }

        // Build and add server config if present  
        if !server_config.is_null() {
            let server_ffi_cfg = unsafe { &*server_config };
            let quinn_server_config = server_ffi_cfg.build_quinn_config()?;
            builder = builder.with_server_config(quinn_server_config);
        }

        // Create endpoint
        let endpoint = builder.bind_addr(bind_addr)
            .map_err(|e| QuicError::unknown(format!("Failed to bind endpoint: {}", e)))?;
        
        Ok(Box::into_raw(Box::new(endpoint)))
    })();

    unsafe {
        (*result).write_result(endpoint_result)
    }
}

/// Free an endpoint and close all connections
///
/// # Parameters
/// - `endpoint`: Endpoint pointer to free
///
/// # Safety
/// - endpoint must be a valid pointer created by dart_quic_endpoint_create
/// - Must not be used after this call
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_endpoint_free(endpoint: *mut quic::QuicEndpoint) {
    if !endpoint.is_null() {
        unsafe {
            let _ = Box::from_raw(endpoint);
        }
    }
}

// ============================================
// Endpoint Client Operations (Outgoing Connections)
// ============================================

/// Connect to a remote server (async)
///
/// # Parameters
/// - `executor`: Executor pointer for async operations
/// - `endpoint`: Endpoint pointer
/// - `server_addr`: Server address string (e.g., "127.0.0.1:4433")
/// - `server_name`: Server name for SNI (e.g., "localhost")
/// - `callback`: Callback invoked with connection pointer (or 0 on error)
///
/// # Safety
/// - All pointers must be valid
/// - Endpoint must have client capability (ClientOnly or Bidirectional mode)
/// - server_addr and server_name must be valid null-terminated C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_endpoint_connect(
    executor: *mut QuicExecutor,
    endpoint: *mut quic::QuicEndpoint,
    server_addr: *const i8,
    server_name: *const i8,
    callback: UsizeCallback,
) {
    check_executor_usize!(executor, callback);
    check_ptr_usize!(endpoint, callback);

    if server_addr.is_null() {
        let error_msg = allocate(ERR_PTR_NULL.len());
        if !error_msg.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    ERR_PTR_NULL.as_ptr(),
                    error_msg,
                    ERR_PTR_NULL.len()
                );
            }
        }
        let callback = SendableCallback(callback);
        callback.0(false, 0, error_msg, ERR_PTR_NULL.len());
        return;
    }

    if server_name.is_null() {
        let error_msg = allocate(ERR_PTR_NULL.len());
        if !error_msg.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    ERR_PTR_NULL.as_ptr(),
                    error_msg,
                    ERR_PTR_NULL.len()
                );
            }
        }
        let callback = SendableCallback(callback);
        callback.0(false, 0, error_msg, ERR_PTR_NULL.len());
        return;
    }

    let endpoint_ptr = endpoint as usize;
    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };

    // Convert C strings to Rust strings
    let addr_str = match unsafe { CStr::from_ptr(server_addr) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            let error_msg = b"Invalid server_addr encoding\0";
            let ptr = allocate(error_msg.len());
            if !ptr.is_null() {
                unsafe {
                    std::ptr::copy_nonoverlapping(error_msg.as_ptr(), ptr, error_msg.len());
                }
            }
            callback.0(false, 0, ptr, error_msg.len());
            return;
        }
    };

    let name_str = match unsafe { CStr::from_ptr(server_name) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            let error_msg = b"Invalid server_name encoding\0";
            let ptr = allocate(error_msg.len());
            if !ptr.is_null() {
                unsafe {
                    std::ptr::copy_nonoverlapping(error_msg.as_ptr(), ptr, error_msg.len());
                }
            }
            callback.0(false, 0, ptr, error_msg.len());
            return;
        }
    };

    // Submit async connect task
    exec.submit_async(async move {
        let endpoint = unsafe { &*(endpoint_ptr as *const quic::QuicEndpoint) };
        match endpoint.connect(&addr_str, &name_str).await {
            Ok(connection) => {
                // Create handle with connection info
                let handle = QuicConnectionHandle::new(connection);
                let handle_ptr = Box::into_raw(Box::new(handle)) as usize;
                callback.0(true, handle_ptr, std::ptr::null_mut(), 0);
            }
            Err(e) => {
                let error_msg = format!("Connection failed: {}\0", e);
                let error_bytes = error_msg.into_bytes();
                let ptr = allocate(error_bytes.len());
                if !ptr.is_null() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(error_bytes.as_ptr(), ptr, error_bytes.len());
                    }
                }
                callback.0(false, 0, ptr, error_bytes.len());
            }
        }
    });
}

// ============================================
// Endpoint Server Operations (Incoming Connections)
// ============================================

/// Accept an incoming connection (async)
///
/// # Parameters
/// - `executor`: Executor pointer for async operations
/// - `endpoint`: Endpoint pointer
/// - `callback`: Callback invoked with connection pointer (or 0 on error/close)
///
/// # Returns
/// - Connection pointer on success
/// - 0 if endpoint is closing or on error
///
/// # Safety
/// - All pointers must be valid
/// - Endpoint must have server capability (ServerOnly or Bidirectional mode)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_endpoint_accept(
    executor: *mut QuicExecutor,
    endpoint: *mut quic::QuicEndpoint,
    callback: UsizeCallback,
) {
    check_executor_usize!(executor, callback);
    check_ptr_usize!(endpoint, callback);

    let endpoint_ptr = endpoint as usize;
    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };

    // Submit async accept task
    exec.submit_async(async move {
        let endpoint = unsafe { &*(endpoint_ptr as *const quic::QuicEndpoint) };
        match endpoint.accept().await {
            Some(Ok(connection)) => {
                // Create handle with connection info
                let handle = QuicConnectionHandle::new(connection);
                let handle_ptr = Box::into_raw(Box::new(handle)) as usize;
                callback.0(true, handle_ptr, std::ptr::null_mut(), 0);
            }
            Some(Err(e)) => {
                let error_msg = format!("Accept failed: {}\0", e);
                let error_bytes = error_msg.into_bytes();
                let ptr = allocate(error_bytes.len());
                if !ptr.is_null() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(error_bytes.as_ptr(), ptr, error_bytes.len());
                    }
                }
                callback.0(false, 0, ptr, error_bytes.len());
            }
            None => {
                // Endpoint is closing
                let error_msg = b"Endpoint closed\0";
                let ptr = allocate(error_msg.len());
                if !ptr.is_null() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(error_msg.as_ptr(), ptr, error_msg.len());
                    }
                }
                callback.0(false, 0, ptr, error_msg.len());
            }
        }
    });
}

// ============================================
// Endpoint Information and Control
// ============================================

/// Get the local bound address of the endpoint
///
/// # Parameters
/// - `endpoint`: Endpoint pointer
/// - `out_ip`: Output buffer for IP address (network byte order)
/// - `out_port`: Output buffer for port (host byte order)
///
/// # Returns
/// - 0 on success
/// - Non-zero error code on failure
///
/// # Safety
/// - endpoint must be a valid pointer
/// - out_ip and out_port must be valid pointers
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_endpoint_local_addr(
    endpoint: *mut quic::QuicEndpoint,
    out_ip: *mut u32,
    out_port: *mut u16,
) -> i32 {
    if endpoint.is_null() || out_ip.is_null() || out_port.is_null() {
        return -1;
    }

    let endpoint_ref = unsafe { &*endpoint };
    let addr = endpoint_ref.local_addr();

    match addr {
        SocketAddr::V4(addr_v4) => {
            unsafe {
                *out_ip = u32::from_be_bytes(addr_v4.ip().octets());
                *out_port = addr_v4.port();
            }
            0
        }
        SocketAddr::V6(_) => {
            // IPv6 not supported in this simple API
            -2
        }
    }
}

/// Get the number of currently open connections
///
/// # Parameters
/// - `endpoint`: Endpoint pointer
///
/// # Returns
/// - Number of open connections
/// - 0 if endpoint is null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_endpoint_open_connections(
    endpoint: *mut quic::QuicEndpoint,
) -> usize {
    if endpoint.is_null() {
        return 0;
    }

    let endpoint_ref = unsafe { &*endpoint };
    endpoint_ref.open_connections()
}

/// Check if endpoint has client capability
///
/// # Parameters
/// - `endpoint`: Endpoint pointer
///
/// # Returns
/// - 1 if endpoint can connect to remote servers
/// - 0 otherwise
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_endpoint_can_connect(
    endpoint: *mut quic::QuicEndpoint,
) -> i32 {
    if endpoint.is_null() {
        return 0;
    }

    let endpoint_ref = unsafe { &*endpoint };
    if endpoint_ref.can_connect() { 1 } else { 0 }
}

/// Check if endpoint has server capability
///
/// # Parameters
/// - `endpoint`: Endpoint pointer
///
/// # Returns
/// - 1 if endpoint can accept incoming connections
/// - 0 otherwise
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_endpoint_can_accept(
    endpoint: *mut quic::QuicEndpoint,
) -> i32 {
    if endpoint.is_null() {
        return 0;
    }

    let endpoint_ref = unsafe { &*endpoint };
    if endpoint_ref.can_accept() { 1 } else { 0 }
}

/// Close the endpoint and all connections gracefully
///
/// # Parameters
/// - `endpoint`: Endpoint pointer
/// - `error_code`: Application error code
/// - `reason`: Reason bytes (nullable)
/// - `reason_len`: Length of reason bytes
///
/// # Safety
/// - endpoint must be a valid pointer
/// - reason must be valid for reason_len bytes if not null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_endpoint_close(
    endpoint: *mut quic::QuicEndpoint,
    error_code: u32,
    reason: *const u8,
    reason_len: usize,
) {
    if endpoint.is_null() {
        return;
    }

    let endpoint_ref = unsafe { &*endpoint };

    let reason_bytes = if reason.is_null() || reason_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(reason, reason_len) }
    };

    endpoint_ref.close(error_code, reason_bytes);
}

/// Wait for all connections to close (async)
///
/// # Parameters
/// - `executor`: Executor pointer for async operations
/// - `endpoint`: Endpoint pointer
/// - `callback`: Callback invoked when all connections are closed
///
/// # Safety
/// - All pointers must be valid
/// - Should be called after dart_quic_endpoint_close
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_endpoint_wait_idle(
    executor: *mut QuicExecutor,
    endpoint: *mut quic::QuicEndpoint,
    callback: VoidCallback,
) {
    check_executor_void!(executor, callback);
    check_ptr_void!(endpoint, callback);

    let endpoint_ptr = endpoint as usize;
    let callback = SendableCallback(callback);
    let exec = unsafe { &*executor };

    // Submit async wait_idle task
    exec.submit_async(async move {
        let endpoint = unsafe { &*(endpoint_ptr as *const quic::QuicEndpoint) };
        endpoint.wait_idle().await;
        callback.0(true, std::ptr::null_mut(), 0);
    });
}
