//! QUIC Client Convenience Wrapper
//!
//! Provides a simplified client-specific API based on `QuicEndpoint`.
//!
//! # Relationship with QuicEndpoint
//!
//! ```text
//! QuicEndpoint (low-level unified abstraction, defined in quic_endpoint.rs)
//!       ↑
//! QuicClient (internally holds QuicEndpoint, provides simplified client API)
//! ```
//!
//! `QuicClient` internally uses `QuicEndpoint`, but:
//! - Hides server-related APIs (such as `accept()`)
//! - Provides simpler certificate/trust configuration
//! - Automatically builds ClientConfig
//!
//! If you need to act as both client and server, use `QuicEndpoint` directly.
//!
//! # Core Concepts
//!
//! - **One client, multiple connections**: A single `QuicClient` can connect to multiple servers simultaneously
//! - **Shared local port**: All connections share the same local UDP port
//!
//! # Examples
//!
//! ## Secure Connection (Recommended for Production)
//! ```rust
//! let client = QuicClient::builder()
//!     .with_system_roots()  // Use system root certificates
//!     .bind("0.0.0.0:0")?;
//!
//! // Connect to multiple servers from the same client
//! let conn1 = client.connect("server1.com:443", "server1.com").await?;
//! let conn2 = client.connect("server2.com:443", "server2.com").await?;
//!
//! println!("Local port: {}", client.local_port());
//! ```
//!
//! ## Insecure Connection (Testing Only)
//! ```rust
//! let client = QuicClient::new_insecure("0.0.0.0:0")?;
//! let conn = client.connect("localhost:4433", "localhost").await?;
//! ```

use std::net::SocketAddr;

use crate::error::QuicError;
use super::quic_config::{QuicClientConfigBuilder, QuicTransportConfig};
use super::quic_connection::QuicConnection;
use super::quic_endpoint::QuicEndpoint;

// ============================================================================
// Client Endpoint Main Class
// ============================================================================

/// QUIC Client
///
/// A client-specific wrapper based on `QuicEndpoint`.
/// **A single client can maintain multiple connections to different servers simultaneously.**
///
/// # Internal Structure
/// ```text
/// QuicClient
///   └── inner: QuicEndpoint  // Low-level unified endpoint
/// ```
///
/// # Multiple Connections Example
/// ```rust
/// let client = QuicClient::builder()
///     .with_system_roots()
///     .bind("0.0.0.0:0")?;
///
/// // Connect to multiple servers from the same local port
/// let conn1 = client.connect("server1:443", "server1").await?;
/// let conn2 = client.connect("server2:443", "server2").await?;
/// let conn3 = client.connect("server3:443", "server3").await?;
///
/// println!("All connections share local port: {}", client.local_port());
/// ```
///
/// # Thread Safety
/// `QuicClient` is thread-safe and can be shared across multiple threads.
#[derive(Clone)]
pub struct QuicClient {
    /// Underlying QuicEndpoint
    inner: QuicEndpoint,
}

impl QuicClient {
    /// Create a builder
    ///
    /// Returns `QuicClientConfigBuilder` for configuring certificates, trust, and transport parameters.
    ///
    /// # Example
    /// ```rust
    /// let client = QuicClient::builder()
    ///     .with_system_roots()  // Use system root certificates to verify server
    ///     .bind("0.0.0.0:0")?;  // Bind and create client
    /// ```
    pub fn builder() -> QuicClientConfigBuilder {
        QuicClientConfigBuilder::new()
    }

    /// Create from QuicEndpoint (internal use)
    pub(crate) fn from_endpoint(endpoint: QuicEndpoint) -> Self {
        Self { inner: endpoint }
    }

    /// Create an endpoint that skips certificate verification (development/testing only!)
    ///
    /// ⚠️ **Security Warning**: This method skips server certificate verification and poses serious security risks!
    ///
    /// # Parameters
    /// - `bind_addr`: Local bind address (e.g., "0.0.0.0:0")
    pub fn new_insecure(bind_addr: &str) -> Result<Self, QuicError> {
        Self::builder()
            .with_skip_verification()
            .bind(bind_addr)
    }

    /// Create an insecure endpoint with custom transport configuration (development/testing only!)
    pub fn new_insecure_with_transport(
        transport_config: QuicTransportConfig,
        bind_addr: &str,
    ) -> Result<Self, QuicError> {
        Self::builder()
            .with_skip_verification()
            .with_transport_config(transport_config)
            .bind(bind_addr)
    }

    // ========== Connection Management (delegated to inner) ==========

    /// Connect to a server
    ///
    /// # Parameters
    /// - `server_addr`: Server address in "host:port" format
    /// - `server_name`: Server name (used for TLS SNI and certificate verification)
    pub async fn connect(
        &self,
        server_addr: &str,
        server_name: &str,
    ) -> Result<QuicConnection, QuicError> {
        self.inner.connect(server_addr, server_name).await
    }

    /// Connect to a server using SocketAddr
    pub async fn connect_addr(
        &self,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<QuicConnection, QuicError> {
        self.inner.connect_addr(server_addr, server_name).await
    }

    // ========== Endpoint Information (delegated to inner) ==========

    /// Get the local bind address
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr()
    }

    /// Get the local bind port
    pub fn local_port(&self) -> u16 {
        self.inner.local_port()
    }

    /// Get the number of currently open connections
    pub fn open_connections(&self) -> usize {
        self.inner.open_connections()
    }

    /// Get a reference to the underlying QuicEndpoint
    ///
    /// Used for advanced scenarios that require access to full endpoint capabilities (e.g., retrieving statistics).
    pub fn as_endpoint(&self) -> &QuicEndpoint {
        &self.inner
    }

    // ========== Lifecycle Management (delegated to inner) ==========

    /// Actively close the endpoint and all connections
    ///
    /// Immediately sends CONNECTION_CLOSE frames to all peer connections, then closes the endpoint.
    /// **This method returns immediately** without waiting for peer acknowledgment.
    ///
    /// # Parameters
    /// - `error_code`: Application-layer error code (0 indicates normal shutdown)
    /// - `reason`: Shutdown reason (sent to peer, can be empty)
    ///
    /// # Difference from `wait_idle()`
    /// - `close()`: Actively initiates shutdown, returns immediately
    /// - `wait_idle()`: Waits for all connections to end naturally (peer closes or timeout)
    ///
    /// # Recommended Usage
    /// ```rust
    /// // Graceful shutdown: close first, then wait for acknowledgment
    /// client.close(0, b"bye");
    /// client.wait_idle().await;  // Wait for peer to receive shutdown notification
    /// ```
    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.inner.close(error_code, reason);
    }

    /// Wait for all connections to close (idle state)
    ///
    /// Blocks until all connections on the endpoint have been closed.
    ///
    /// This method **does not actively close connections**, it only passively waits for the connection set to become empty.
    ///
    /// # Recommended Usage
    /// ```rust
    /// // Graceful shutdown: actively close first, then wait for handshake to complete
    /// client.close(0, b"bye");
    /// client.wait_idle().await;  // Brief blocking, wait for shutdown handshake
    /// ```
    pub async fn wait_idle(&self) {
        self.inner.wait_idle().await;
    }
}

// ============================================================================
// FFI Client Configuration Structure (Unified Configuration)
// ============================================================================

/// Trust mode
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicFfiTrustMode {
    /// Skip verification (testing only! dangerous!)
    SkipVerification = 0,
    /// Use system root certificates (recommended for production)
    SystemRoots = 1,
    /// Use custom CA (DER in memory)
    CustomCaDer = 2,
    /// Use custom CA (PEM file)
    CustomCaPemFile = 3,
    /// Use custom CA (DER file)
    CustomCaDerFile = 4,
}

/// Client certificate mode (mTLS)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicFfiClientCertMode {
    /// No client certificate
    None = 0,
    /// Load from DER memory
    Der = 1,
    /// Load from PEM file
    PemFile = 2,
    /// Load from DER file
    DerFile = 3,
}

/// FFI-friendly client configuration
///
/// Unified configuration for all client initialization options, including:
/// - Trust mode: skip verification, system root certificates, custom CA
/// - Client certificate (mTLS): none, DER memory, PEM file, DER file
/// - Transport configuration
/// - Bind address
///
/// # C Language Usage Examples
///
/// ```c
/// // Use system root certificates
/// QuicFfiClientConfig config = {
///     .trust_mode = QuicFfiTrustMode_SystemRoots,
///     .bind_addr = "0.0.0.0:0",
///     .transport_config = &transport,  // Optional
/// };
///
/// // Skip verification (testing)
/// QuicFfiClientConfig config = {
///     .trust_mode = QuicFfiTrustMode_SkipVerification,
/// };
///
/// // Use custom CA (DER in memory)
/// QuicFfiClientConfig config = {
///     .trust_mode = QuicFfiTrustMode_CustomCaDer,
///     .ca_cert_data = ca_der_bytes,
///     .ca_cert_len = ca_der_len,
/// };
///
/// // Use custom CA (PEM file)
/// QuicFfiClientConfig config = {
///     .trust_mode = QuicFfiTrustMode_CustomCaPemFile,
///     .ca_cert_path = "/path/to/ca.pem",
/// };
///
/// // With client certificate (mTLS, PEM file)
/// QuicFfiClientConfig config = {
///     .trust_mode = QuicFfiTrustMode_SystemRoots,
///     .client_cert_mode = QuicFfiClientCertMode_PemFile,
///     .client_cert_path = "/path/to/client.pem",
///     .client_key_path = "/path/to/client.key",
/// };
/// ```
#[repr(C)]
pub struct QuicFfiClientConfig {
    // ===== Trust Configuration =====
    /// Trust mode
    pub trust_mode: QuicFfiTrustMode,
    
    /// CA certificate data (for CustomCaDer mode)
    pub ca_cert_data: *const u8,
    /// CA certificate data length (bytes)
    pub ca_cert_len: u32,
    
    /// CA certificate/file path (for CustomCaPemFile/CustomCaDerFile modes)
    /// UTF-8 encoded C string
    pub ca_cert_path: *const std::os::raw::c_char,
    
    // ===== Client Certificate Configuration (mTLS) =====
    /// Client certificate mode
    pub client_cert_mode: QuicFfiClientCertMode,
    
    /// Client certificate data (for Der mode)
    pub client_cert_data: *const u8,
    /// Client certificate data length (bytes)
    pub client_cert_len: u32,
    
    /// Client private key data (for Der mode)
    pub client_key_data: *const u8,
    /// Client private key data length (bytes)
    pub client_key_len: u32,
    
    /// Client certificate file path (for PemFile/DerFile modes)
    pub client_cert_path: *const std::os::raw::c_char,
    /// Client private key file path (for PemFile/DerFile modes)
    pub client_key_path: *const std::os::raw::c_char,
    
    // ===== Transport Configuration =====
    /// Transport configuration (optional, NULL uses default)
    pub transport_config: *const super::quic_config::QuicFfiTransportConfig,
    
    // ===== Bind Address =====
    /// Local bind address (optional, NULL or empty string uses "0.0.0.0:0")
    pub bind_addr: *const std::os::raw::c_char,
}

impl QuicFfiClientConfig {
    /// Build QuicClient from FFI configuration
    pub fn build(&self) -> Result<QuicClient, QuicError> {
        use std::ffi::CStr;
        
        // Build base builder
        let mut builder = QuicClientConfigBuilder::new();
        
        // Configure trust mode
        builder = match self.trust_mode {
            QuicFfiTrustMode::SkipVerification => {
                builder.with_skip_verification()
            }
            QuicFfiTrustMode::SystemRoots => {
                builder.with_system_roots()
            }
            QuicFfiTrustMode::CustomCaDer => {
                if self.ca_cert_data.is_null() || self.ca_cert_len == 0 {
                    return Err(QuicError::unknown("CA certificate data is required for CustomCaDer mode".to_string()));
                }
                let ca_der = unsafe { std::slice::from_raw_parts(self.ca_cert_data, self.ca_cert_len as usize) }.to_vec();
                builder.with_custom_ca(ca_der)
            }
            QuicFfiTrustMode::CustomCaPemFile => {
                if self.ca_cert_path.is_null() {
                    return Err(QuicError::unknown("CA certificate path is required for CustomCaPemFile mode".to_string()));
                }
                let path = unsafe { CStr::from_ptr(self.ca_cert_path) }
                    .to_str()
                    .map_err(|_| QuicError::unknown("Invalid CA certificate path encoding".to_string()))?;
                builder.with_custom_ca_pem_file(path)?
            }
            QuicFfiTrustMode::CustomCaDerFile => {
                if self.ca_cert_path.is_null() {
                    return Err(QuicError::unknown("CA certificate path is required for CustomCaDerFile mode".to_string()));
                }
                let path = unsafe { CStr::from_ptr(self.ca_cert_path) }
                    .to_str()
                    .map_err(|_| QuicError::unknown("Invalid CA certificate path encoding".to_string()))?;
                builder.with_custom_ca_der_file(path)?
            }
        };
        
        // Configure client certificate (mTLS)
        builder = match self.client_cert_mode {
            QuicFfiClientCertMode::None => builder,
            QuicFfiClientCertMode::Der => {
                if self.client_cert_data.is_null() || self.client_cert_len == 0 {
                    return Err(QuicError::unknown("Client certificate data is required for Der mode".to_string()));
                }
                if self.client_key_data.is_null() || self.client_key_len == 0 {
                    return Err(QuicError::unknown("Client key data is required for Der mode".to_string()));
                }
                let cert_der = unsafe { std::slice::from_raw_parts(self.client_cert_data, self.client_cert_len as usize) }.to_vec();
                let key_der = unsafe { std::slice::from_raw_parts(self.client_key_data, self.client_key_len as usize) }.to_vec();
                builder.with_client_cert(cert_der, key_der)
            }
            QuicFfiClientCertMode::PemFile => {
                if self.client_cert_path.is_null() || self.client_key_path.is_null() {
                    return Err(QuicError::unknown("Client certificate and key paths are required for PemFile mode".to_string()));
                }
                let cert_path = unsafe { CStr::from_ptr(self.client_cert_path) }
                    .to_str()
                    .map_err(|_| QuicError::unknown("Invalid client certificate path encoding".to_string()))?;
                let key_path = unsafe { CStr::from_ptr(self.client_key_path) }
                    .to_str()
                    .map_err(|_| QuicError::unknown("Invalid client key path encoding".to_string()))?;
                builder.with_client_cert_pem_files(cert_path, key_path)?
            }
            QuicFfiClientCertMode::DerFile => {
                if self.client_cert_path.is_null() || self.client_key_path.is_null() {
                    return Err(QuicError::unknown("Client certificate and key paths are required for DerFile mode".to_string()));
                }
                let cert_path = unsafe { CStr::from_ptr(self.client_cert_path) }
                    .to_str()
                    .map_err(|_| QuicError::unknown("Invalid client certificate path encoding".to_string()))?;
                let key_path = unsafe { CStr::from_ptr(self.client_key_path) }
                    .to_str()
                    .map_err(|_| QuicError::unknown("Invalid client key path encoding".to_string()))?;
                builder.with_client_cert_der_files(cert_path, key_path)?
            }
        };
        
        // Configure transport parameters
        if !self.transport_config.is_null() {
            let ffi_config = unsafe { &*self.transport_config };
            let config = QuicTransportConfig::from(ffi_config);
            builder = builder.with_transport_config(config);
        }
        
        // Get bind address
        let bind_addr = if self.bind_addr.is_null() {
            "0.0.0.0:0"
        } else {
            let addr_str = unsafe { CStr::from_ptr(self.bind_addr) }
                .to_str()
                .map_err(|_| QuicError::unknown("Invalid bind address encoding".to_string()))?;
            if addr_str.is_empty() { "0.0.0.0:0" } else { addr_str }
        };
        
        builder.bind(bind_addr)
    }
}

impl Default for QuicFfiClientConfig {
    fn default() -> Self {
        Self {
            trust_mode: QuicFfiTrustMode::SystemRoots,
            ca_cert_data: std::ptr::null(),
            ca_cert_len: 0,
            ca_cert_path: std::ptr::null(),
            client_cert_mode: QuicFfiClientCertMode::None,
            client_cert_data: std::ptr::null(),
            client_cert_len: 0,
            client_key_data: std::ptr::null(),
            client_key_len: 0,
            client_cert_path: std::ptr::null(),
            client_key_path: std::ptr::null(),
            transport_config: std::ptr::null(),
            bind_addr: std::ptr::null(),
        }
    }
}
