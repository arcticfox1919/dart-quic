//! QUIC Server Convenience Wrapper
//!
//! Provides a simpler server-specific API based on `QuicEndpoint`.
//!
//! # Relationship with QuicEndpoint
//!
//! ```text
//! QuicEndpoint (low-level unified abstraction, defined in quic_endpoint.rs)
//!       ↑
//! QuicServer (internally holds QuicEndpoint, provides simplified server API)
//! ```
//!
//! `QuicServer` internally uses `QuicEndpoint`, but:
//! - Hides client-related APIs (e.g., `connect()`)
//! - Provides simpler certificate configuration (file/memory/self-signed)
//! - Automatically builds ServerConfig
//! - Supports mutual authentication (mTLS)
//!
//! If you need to act as both client and server simultaneously, use `QuicEndpoint` directly.
//!
//! # Core Concepts
//!
//! - **One server, multiple connections**: A single server can handle multiple client connections simultaneously
//! - **Hot certificate reload**: Supports updating certificates at runtime without affecting existing connections
//!
//! # Examples
//!
//! ## Secure Server (Production Recommended)
//! ```rust
//! let server = QuicServer::builder()
//!     .with_cert_pem_files("server.crt", "server.key")?
//!     .bind("0.0.0.0:4433")?;
//!
//! while let Some(conn) = server.accept().await {
//!     let conn = conn?;
//!     tokio::spawn(async move {
//!         // Handle connection
//!     });
//! }
//! ```
//!
//! ## Self-Signed Certificate (Testing Only)
//! ```rust
//! let server = QuicServer::new_self_signed(
//!     "0.0.0.0:4433",
//!     &["localhost"],
//! )?;
//! ```

use std::net::SocketAddr;

use crate::error::QuicError;
use super::quic_config::{QuicServerConfigBuilder, QuicTransportConfig};
use super::quic_connection::QuicConnection;
use super::quic_endpoint::QuicEndpoint;

// ============================================================================
// Server Endpoint Main Class
// ============================================================================

/// QUIC Server
/// 
/// Server-specific wrapper based on `QuicEndpoint`.
/// 
/// # Internal Structure
/// ```text
/// QuicServer
///   └── inner: QuicEndpoint  // Low-level unified endpoint
/// ```
/// 
/// # Core Concepts
/// 
/// - One server can handle multiple client connections simultaneously
/// - Supports runtime certificate updates (doesn't affect existing connections)
/// - Supports mTLS mutual authentication
/// 
/// # Thread Safety
/// `QuicServer` is thread-safe and can be safely shared across multiple threads.
#[derive(Clone)]
pub struct QuicServer {
    /// Underlying QuicEndpoint
    inner: QuicEndpoint,
}

impl QuicServer {
    /// Create a builder
    /// 
    /// Returns `QuicServerConfigBuilder` for configuring certificates, mTLS, and transport parameters.
    /// 
    /// # Example
    /// ```rust
    /// let server = QuicServer::builder()
    ///     .with_cert_pem_files("server.crt", "server.key")?
    ///     .bind("0.0.0.0:4433")?;
    /// ```
    pub fn builder() -> QuicServerConfigBuilder {
        QuicServerConfigBuilder::new()
    }

    /// Create from QuicEndpoint (internal use)
    pub(crate) fn from_endpoint(endpoint: QuicEndpoint) -> Self {
        Self { inner: endpoint }
    }

    /// Create a server with self-signed certificate (testing only!)
    /// 
    /// ⚠️ **Warning**: Self-signed certificates are for development/testing environments only!
    /// Clients need to skip certificate verification or trust this certificate to connect.
    /// 
    /// # Parameters
    /// - `bind_addr`: Bind address in "host:port" format
    /// - `subject_alt_names`: Certificate subject alternative names (e.g., "localhost")
    /// 
    /// # Example
    /// ```rust
    /// // ⚠️ Testing only!
    /// let server = QuicServer::new_self_signed("0.0.0.0:4433", &["localhost"])?;
    /// ```
    pub fn new_self_signed(bind_addr: &str, subject_alt_names: &[&str]) -> Result<Self, QuicError> {
        Self::new_self_signed_with_transport(bind_addr, subject_alt_names, QuicTransportConfig::default())
    }

    /// Create a self-signed certificate server endpoint with custom transport config (testing only!)
    /// 
    /// ⚠️ **Warning**: Self-signed certificates are for development/testing environments only!
    pub fn new_self_signed_with_transport(
        bind_addr: &str,
        subject_alt_names: &[&str],
        transport_config: QuicTransportConfig,
    ) -> Result<Self, QuicError> {
        Self::builder()
            .with_self_signed(subject_alt_names)
            .with_transport_config(transport_config)
            .bind(bind_addr)
    }

    // ========== Connection Acceptance (delegated to inner) ==========

    /// Accept incoming connections
    /// 
    /// Returns `None` if the endpoint is closed.
    pub async fn accept(&self) -> Option<Result<QuicConnection, QuicError>> {
        self.inner.accept().await
    }

    // ========== Endpoint Information (delegated to inner) ==========

    /// Get local bind address
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr()
    }

    /// Get local bind port
    pub fn local_port(&self) -> u16 {
        self.inner.local_port()
    }

    /// Get current number of open connections
    pub fn open_connections(&self) -> usize {
        self.inner.open_connections()
    }

    /// Get underlying QuicEndpoint reference
    ///
    /// Used for advanced scenarios requiring access to full endpoint capabilities (e.g., getting statistics).
    pub fn as_endpoint(&self) -> &QuicEndpoint {
        &self.inner
    }

    // ========== Lifecycle Management (delegated to inner) ==========

    /// Actively close server and all connections
    ///
    /// Immediately sends CONNECTION_CLOSE frames to all connected clients, then closes the server.
    /// **This method returns immediately** without waiting for client acknowledgment.
    ///
    /// # Parameters
    /// - `error_code`: Application error code (0 means normal shutdown)
    /// - `reason`: Shutdown reason (sent to clients, can be empty)
    ///
    /// # Difference from `wait_idle()`
    /// - `close()`: Actively initiates shutdown, returns immediately
    /// - `wait_idle()`: Waits for all connections to end naturally (client disconnects or timeout)
    ///
    /// # Recommended Usage
    /// ```rust
    /// // Graceful shutdown: close first, then wait for acknowledgment
    /// server.close(0, b"server shutdown");
    /// server.wait_idle().await;  // Wait for clients to receive close notification
    /// ```
    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.inner.close(error_code, reason);
    }

    /// Wait for all connections to close (idle state)
    ///
    /// Blocks until all connections on the server are closed.
    /// Typically called after `close()` to ensure clients receive close notifications.
    ///
    /// # Use Cases
    /// 1. Ensure connections are properly closed before program exit
    /// 2. Wait for all clients to disconnect
    ///
    /// # Note
    /// If connections remain active, this method will block indefinitely.
    /// It's recommended to call `close()` first, then call this method.
    pub async fn wait_idle(&self) {
        self.inner.wait_idle().await;
    }
}

// ============================================================================
// FFI-Friendly Server Configuration
// ============================================================================

/// FFI server configuration (for C API)
///
/// # C Language Usage Example
///
/// ```c
/// QuicFfiServerConfig config = {
///     .cert_mode = 2,  // Self-signed certificate
///     // ... other fields
/// };
/// ```
#[repr(C)]
pub struct QuicFfiServerConfig {
    /// Certificate mode: 0 = file, 1 = memory, 2 = self-signed
    pub cert_mode: u32,
    /// Certificate file path (used when cert_mode = 0)
    pub cert_path_ptr: *const std::os::raw::c_char,
    /// Private key file path (used when cert_mode = 0)
    pub key_path_ptr: *const std::os::raw::c_char,
    /// Certificate DER data (used when cert_mode = 1)
    pub cert_der_ptr: *const u8,
    /// Certificate DER data length (bytes)
    pub cert_der_len: u32,
    /// Private key DER data (used when cert_mode = 1)
    pub key_der_ptr: *const u8,
    /// Private key DER data length (bytes)
    pub key_der_len: u32,
    /// Self-signed SAN list (used when cert_mode = 2)
    pub san_ptr: *const *const std::os::raw::c_char,
    /// SAN list count
    pub san_count: u32,
    /// Client authentication mode: 0 = not required, 1 = required, 2 = optional
    pub client_auth_mode: u32,
    /// Client CA certificate DER (used when client_auth_mode > 0)
    pub client_ca_ptr: *const u8,
    /// Client CA certificate DER length (bytes)
    pub client_ca_len: u32,
    /// Transport configuration
    pub transport: super::quic_config::QuicFfiTransportConfig,
}

impl Default for QuicFfiServerConfig {
    fn default() -> Self {
        Self {
            cert_mode: 2, // Default self-signed
            cert_path_ptr: std::ptr::null(),
            key_path_ptr: std::ptr::null(),
            cert_der_ptr: std::ptr::null(),
            cert_der_len: 0,
            key_der_ptr: std::ptr::null(),
            key_der_len: 0,
            san_ptr: std::ptr::null(),
            san_count: 0,
            client_auth_mode: 0,
            client_ca_ptr: std::ptr::null(),
            client_ca_len: 0,
            transport: super::quic_config::QuicFfiTransportConfig::default(),
        }
    }
}

impl QuicFfiServerConfig {
    /// Build Quinn ServerConfig from FFI configuration (without creating endpoint)
    ///
    /// This method builds only the `quinn::ServerConfig` which can be used
    /// to create a unified endpoint or for other advanced use cases.
    pub fn build_quinn_config(&self) -> Result<quinn::ServerConfig, QuicError> {
        use std::ffi::CStr;
        use super::quic_config::QuicServerConfigBuilder;
        
        let mut builder = QuicServerConfigBuilder::new();
        
        // Configure certificate based on mode
        builder = match self.cert_mode {
            0 => {
                // File mode
                if self.cert_path_ptr.is_null() || self.key_path_ptr.is_null() {
                    return Err(QuicError::unknown("Certificate and key paths are required for file mode".to_string()));
                }
                let cert_path = unsafe { CStr::from_ptr(self.cert_path_ptr) }
                    .to_str()
                    .map_err(|_| QuicError::unknown("Invalid certificate path encoding".to_string()))?;
                let key_path = unsafe { CStr::from_ptr(self.key_path_ptr) }
                    .to_str()
                    .map_err(|_| QuicError::unknown("Invalid key path encoding".to_string()))?;
                builder.with_cert_pem_files(cert_path, key_path)?
            }
            1 => {
                // Memory mode
                if self.cert_der_ptr.is_null() || self.cert_der_len == 0 ||
                   self.key_der_ptr.is_null() || self.key_der_len == 0 {
                    return Err(QuicError::unknown("Certificate and key data are required for memory mode".to_string()));
                }
                let cert_der = unsafe { std::slice::from_raw_parts(self.cert_der_ptr, self.cert_der_len as usize) }.to_vec();
                let key_der = unsafe { std::slice::from_raw_parts(self.key_der_ptr, self.key_der_len as usize) }.to_vec();
                builder.with_cert_der(cert_der, key_der)
            }
            2 => {
                // Self-signed mode
                let san_list: Vec<String> = if !self.san_ptr.is_null() && self.san_count > 0 {
                    let san_ptrs = unsafe { std::slice::from_raw_parts(self.san_ptr, self.san_count as usize) };
                    san_ptrs.iter()
                        .filter_map(|&ptr| {
                            if !ptr.is_null() {
                                unsafe { CStr::from_ptr(ptr) }.to_str().ok().map(|s| s.to_string())
                            } else {
                                None
                            }
                        })
                        .collect()
                } else {
                    vec![]
                };
                let san_refs: Vec<&str> = san_list.iter().map(|s| s.as_str()).collect();
                builder.with_self_signed(&san_refs)
            }
            _ => return Err(QuicError::unknown(format!("Invalid cert mode: {}", self.cert_mode))),
        };
        
        // Configure client authentication (mTLS)
        if self.client_auth_mode > 0 {
            if self.client_ca_ptr.is_null() || self.client_ca_len == 0 {
                return Err(QuicError::unknown("Client CA certificate data is required when client auth is enabled".to_string()));
            }
            let client_ca_der = unsafe { std::slice::from_raw_parts(self.client_ca_ptr, self.client_ca_len as usize) }.to_vec();
            builder = if self.client_auth_mode == 1 {
                // Required
                builder.require_client_cert(client_ca_der)
            } else {
                // Optional
                builder.optional_client_cert(client_ca_der)
            };
        }
        
        // Configure transport parameters
        let transport_config = super::quic_config::QuicTransportConfig::from(&self.transport);
        builder = builder.with_transport_config(transport_config);
        
        // Build Quinn config
        builder.build_config()
    }
}

