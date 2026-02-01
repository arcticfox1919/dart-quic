//! QUIC Unified Endpoint Wrapper
//!
//! In the QUIC protocol, an Endpoint is a core concept representing a network entity bound to a local UDP port.
//! **The same endpoint can simultaneously act as both client and server**—this is an important distinction from traditional TCP.
//!
//! # Core Concepts
//!
//! - **Endpoint**: Bound to a local UDP port, the foundation for all connections
//! - **ClientConfig**: Used to initiate outgoing connections (connect)
//! - **ServerConfig**: Used to accept incoming connections (accept)
//!
//! # Two Usage Patterns
//!
//! ## Simple Pattern: Use `QuicClient` / `QuicServer` (Recommended for Most Scenarios)
//!
//! If you only need pure client or pure server functionality, use the simpler wrappers:
//!
//! ```rust
//! // Pure client
//! let client = QuicClient::builder()
//!     .with_system_roots()
//!     .bind("0.0.0.0:0")?;
//! let conn = client.connect("server:443", "server").await?;
//!
//! // Pure server
//! let server = QuicServer::builder()
//!     .with_self_signed(&["localhost"])
//!     .bind("0.0.0.0:4433")?;
//! let conn = server.accept().await?;
//! ```
//!
//! ## Advanced Pattern: Use `QuicEndpoint` (Supports Simultaneous Client + Server)
//!
//! When you need to **initiate and accept connections on the same port**, use `QuicEndpoint`:
//!
//! ```rust
//! use dart_quic_native::{QuicClientConfigBuilder, QuicServerConfigBuilder};
//!
//! // Step 1: Create configurations using config builders
//! let client_config = QuicClientConfigBuilder::new()
//!     .with_system_roots()  // or .with_custom_ca(ca_der) or .with_skip_verification()
//!     .build()?;
//!
//! let server_config = QuicServerConfigBuilder::new()
//!     .with_self_signed(&["localhost"])  // or .with_cert_pem_files("cert.pem", "key.pem")?
//!     .build()?;
//!
//! // Step 2: Create endpoint
//! let endpoint = QuicEndpoint::builder()
//!     .with_client_config(client_config)
//!     .with_server_config(server_config)
//!     .bind("0.0.0.0:4433")?;
//!
//! // Now can simultaneously initiate and accept connections
//! let outgoing = endpoint.connect("peer:4433", "peer").await?;
//! let incoming = endpoint.accept().await;
//! ```
//!
//! # Config Builders
//!
//! Config builders (`QuicClientConfigBuilder` / `QuicServerConfigBuilder`) provide
//! convenient ways to create Quinn's `ClientConfig` and `ServerConfig`:
//!
//! ```rust
//! // Client config: three trust modes
//! let config = QuicClientConfigBuilder::new()
//!     .with_system_roots()           // Use system CA (production recommended)
//!     // .with_custom_ca(ca_der)     // Trust private CA
//!     // .with_skip_verification()   // Skip verification (testing only!)
//!     .with_client_cert(cert, key)   // Optional: client certificate (mTLS)
//!     .with_transport_config(config) // Optional: transport config
//!     .build()?;
//!
//! // Server config: three certificate sources
//! let config = QuicServerConfigBuilder::new()
//!     .with_self_signed(&["localhost"])           // Self-signed (for testing)
//!     // .with_cert_pem_files("cert.pem", "key.pem")?  // PEM files
//!     // .with_cert_der(cert_der, key_der)        // DER bytes
//!     .with_transport_config(config)              // Optional: transport config
//!     .build()?;
//! ```

use std::net::SocketAddr;

use quinn::{ClientConfig, Endpoint, ServerConfig};

use crate::error::QuicError;
use super::quic_connection::QuicConnection;

// ============================================================================
// Endpoint Builder
// ============================================================================

/// QUIC Endpoint Builder
///
/// Uses the Builder pattern to configure endpoints, supporting flexible combination of client/server capabilities.
pub struct QuicEndpointBuilder {
    client_config: Option<ClientConfig>,
    server_config: Option<ServerConfig>,
}

impl QuicEndpointBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            client_config: None,
            server_config: None,
        }
    }

    /// Configure client capability
    ///
    /// After setting, the endpoint can use `connect()` to initiate outgoing connections.
    pub fn with_client_config(mut self, config: ClientConfig) -> Self {
        self.client_config = Some(config);
        self
    }

    /// Configure server capability
    ///
    /// After setting, the endpoint can use `accept()` to accept incoming connections.
    pub fn with_server_config(mut self, config: ServerConfig) -> Self {
        self.server_config = Some(config);
        self
    }

    /// Bind to the specified address and create endpoint
    ///
    /// # Parameters
    /// - `bind_addr`: Local bind address in "ip:port" format
    ///   - Clients typically use "0.0.0.0:0" (system-assigned port)
    ///   - Servers typically use "0.0.0.0:4433" (fixed port)
    pub fn bind(self, bind_addr: &str) -> Result<QuicEndpoint, QuicError> {
        let addr: SocketAddr = bind_addr.parse().map_err(|e| {
            QuicError::unknown(format!("Invalid bind address '{}': {}", bind_addr, e))
        })?;

        self.bind_addr(addr)
    }

    /// Bind to the specified SocketAddr and create endpoint
    pub fn bind_addr(self, addr: SocketAddr) -> Result<QuicEndpoint, QuicError> {
        // Determine creation method based on configuration
        let has_client = self.client_config.is_some();
        let has_server = self.server_config.is_some();

        if !has_client && !has_server {
            return Err(QuicError::unknown(
                "At least one of client_config or server_config must be provided".to_string(),
            ));
        }

        let endpoint = if let Some(server_config) = self.server_config {
            // Use server() when server config is present
            let mut ep = Endpoint::server(server_config, addr).map_err(|e| {
                QuicError::unknown(format!("Failed to create server endpoint on {}: {}", addr, e))
            })?;

            // If client config is also present, set it
            if let Some(client_config) = self.client_config {
                ep.set_default_client_config(client_config);
            }
            ep
        } else if let Some(client_config) = self.client_config {
            // Client-only configuration
            let mut ep = Endpoint::client(addr).map_err(|e| {
                QuicError::unknown(format!("Failed to create client endpoint on {}: {}", addr, e))
            })?;
            ep.set_default_client_config(client_config);
            ep
        } else {
            unreachable!()
        };

        let local_addr = endpoint.local_addr().map_err(|e| {
            QuicError::unknown(format!("Failed to get local address: {}", e))
        })?;

        Ok(QuicEndpoint {
            inner: endpoint,
            local_addr,
            has_client_config: has_client,
            has_server_config: has_server,
        })
    }
}

impl Default for QuicEndpointBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unified Endpoint
// ============================================================================

/// QUIC Unified Endpoint
///
/// Represents a QUIC endpoint bound to a local UDP port.
/// Depending on configuration, it can have client/server capabilities simultaneously or individually.
///
/// # Capability Overview
///
/// | Capability | Required Config | Corresponding Method |
/// |-----------|----------------|---------------------|
/// | Initiate connections | ClientConfig | `connect()` |
/// | Accept connections | ServerConfig | `accept()` |
///
/// # Thread Safety
/// `QuicEndpoint` is thread-safe and can be safely shared across multiple threads.
pub struct QuicEndpoint {
    inner: Endpoint,
    local_addr: SocketAddr,
    has_client_config: bool,
    has_server_config: bool,
}

impl QuicEndpoint {
    /// Create an endpoint builder
    pub fn builder() -> QuicEndpointBuilder {
        QuicEndpointBuilder::new()
    }

    // ========== Client Capabilities ==========

    /// Connect to a remote server
    ///
    /// Requires `ClientConfig` to be provided during construction.
    ///
    /// # Parameters
    /// - `server_addr`: Server address in "host:port" format
    /// - `server_name`: Server name (for TLS SNI and certificate verification)
    ///
    /// # Errors
    /// - Returns error if endpoint has no ClientConfig configured
    /// - Returns error if connection fails
    pub async fn connect(
        &self,
        server_addr: &str,
        server_name: &str,
    ) -> Result<QuicConnection, QuicError> {
        if !self.has_client_config {
            return Err(QuicError::unknown(
                "Endpoint has no client configuration. Use builder().with_client_config() to enable outgoing connections.".to_string(),
            ));
        }

        let addr: SocketAddr = server_addr.parse().map_err(|e| {
            QuicError::unknown(format!("Invalid server address '{}': {}", server_addr, e))
        })?;

        self.connect_addr(addr, server_name).await
    }

    /// Connect to a remote server using SocketAddr
    pub async fn connect_addr(
        &self,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<QuicConnection, QuicError> {
        if !self.has_client_config {
            return Err(QuicError::unknown(
                "Endpoint has no client configuration".to_string(),
            ));
        }

        let connecting = self.inner.connect(server_addr, server_name).map_err(|e| {
            QuicError::unknown(format!("Failed to initiate connection to {}: {}", server_addr, e))
        })?;

        let connection = connecting.await.map_err(|e| {
            QuicError::unknown(format!("Connection to {} failed: {}", server_addr, e))
        })?;

        Ok(QuicConnection::new(connection))
    }

    /// Connect using a custom ClientConfig
    ///
    /// Allows using a different client configuration for a specific connection.
    pub async fn connect_with(
        &self,
        config: ClientConfig,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<QuicConnection, QuicError> {
        let connecting = self
            .inner
            .connect_with(config, server_addr, server_name)
            .map_err(|e| {
                QuicError::unknown(format!("Failed to initiate connection: {}", e))
            })?;

        let connection = connecting.await.map_err(|e| {
            QuicError::unknown(format!("Connection failed: {}", e))
        })?;

        Ok(QuicConnection::new(connection))
    }

    // ========== Server Capabilities ==========

    /// Accept incoming connections
    ///
    /// Requires `ServerConfig` to be provided during construction.
    /// Returns `None` if the endpoint is closed.
    ///
    /// # Errors
    /// - Returns error if endpoint has no ServerConfig configured
    pub async fn accept(&self) -> Option<Result<QuicConnection, QuicError>> {
        if !self.has_server_config {
            return Some(Err(QuicError::unknown(
                "Endpoint has no server configuration. Use builder().with_server_config() to enable incoming connections.".to_string(),
            )));
        }

        let incoming = self.inner.accept().await?;
        Some(
            incoming
                .await
                .map(QuicConnection::new)
                .map_err(|e| QuicError::unknown(format!("Accept failed: {}", e))),
        )
    }

    /// Update server configuration
    ///
    /// Used for hot-reloading certificates and similar scenarios. Only affects new connections.
    pub fn set_server_config(&self, config: Option<ServerConfig>) {
        self.inner.set_server_config(config);
    }

    // ========== Endpoint Information ==========

    /// Get local bind address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get local bind port
    pub fn local_port(&self) -> u16 {
        self.local_addr.port()
    }

    /// Get current number of open connections
    pub fn open_connections(&self) -> usize {
        self.inner.open_connections()
    }

    /// Whether the endpoint has client capability
    pub fn can_connect(&self) -> bool {
        self.has_client_config
    }

    /// Whether the endpoint has server capability
    pub fn can_accept(&self) -> bool {
        self.has_server_config
    }

    /// Get internal Quinn Endpoint reference
    pub fn inner(&self) -> &Endpoint {
        &self.inner
    }

    /// Get endpoint statistics
    pub fn stats(&self) -> quinn::EndpointStats {
        self.inner.stats()
    }

    // ========== Lifecycle Management ==========

    /// Close endpoint and all connections
    ///
    /// # Parameters
    /// - `error_code`: Application error code
    /// - `reason`: Close reason
    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.inner.close(error_code.into(), reason);
    }

    /// Wait for all connections to close
    ///
    /// Call this method before exit to ensure peers receive connection close notifications.
    pub async fn wait_idle(&self) {
        self.inner.wait_idle().await;
    }
}

// Allow cloning endpoint handles (sharing underlying endpoint)
impl Clone for QuicEndpoint {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            local_addr: self.local_addr,
            has_client_config: self.has_client_config,
            has_server_config: self.has_server_config,
        }
    }
}

// ============================================================================
// FFI-Friendly Endpoint Configuration
// ============================================================================

/// Endpoint operation mode (for C API)
///
/// The QUIC protocol allows the same UDP port to act as both client and server simultaneously,
/// which is an important distinction from traditional TCP.
/// This enum is used to specify the endpoint's operation mode at the FFI layer.
///
/// # Usage Example
///
/// ```c
/// // C API example
/// FfiEndpointConfig config = {
///     .mode = QuicEndpointMode_ClientOnly,  // Client-only
///     .bind_ip = 0,      // INADDR_ANY
///     .bind_port = 0,    // System-assigned port
/// };
/// ```
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicEndpointMode {
    /// Client-only mode
    ///
    /// - Can only use `connect()` to initiate outgoing connections
    /// - Cannot use `accept()` to accept incoming connections
    /// - Suitable for: regular client applications, crawlers, API callers
    /// - Bind address typically `0.0.0.0:0` (system auto-assigned port)
    ClientOnly = 0,

    /// Server-only mode
    ///
    /// - Can only use `accept()` to accept incoming connections
    /// - Cannot use `connect()` to initiate outgoing connections
    /// - Suitable for: web servers, API services, game servers
    /// - Bind address typically `0.0.0.0:4433` (fixed port)
    ServerOnly = 1,

    /// Bidirectional mode (simultaneously client and server)
    ///
    /// - Supports both `connect()` and `accept()`
    /// - The same UDP port can both initiate and accept connections
    /// - Suitable for:
    ///   - P2P networks (BitTorrent, IPFS)
    ///   - Game server clusters (accept players and connect to other servers)
    ///   - Microservices (bidirectional inter-service communication)
    ///   - NAT traversal scenarios
    Bidirectional = 2,
}

/// FFI endpoint configuration (for C API)
///
/// # Field Descriptions
///
/// - `mode`: Endpoint operation mode, determines what operations the endpoint can perform
/// - `bind_ip`: Local IP address (network byte order), 0 means bind to all interfaces
/// - `bind_port`: Local port number (host byte order), 0 means system auto-assign
///
/// # C Language Usage Example
///
/// ```c
/// QuicFfiEndpointConfig config = {
///     .mode = QuicEndpointMode_ClientOnly,
///     .bind_ip = 0,      // INADDR_ANY
///     .bind_port = 0,    // System-assigned port
/// };
///
/// QuicEndpoint* endpoint = quic_endpoint_create(&config);
/// ```
#[repr(C)]
pub struct QuicFfiEndpointConfig {
    /// Endpoint operation mode
    pub mode: QuicEndpointMode,
    /// Local bind IP (network byte order, 0 means INADDR_ANY)
    pub bind_ip: u32,
    /// Local bind port (host byte order, 0 means system-assigned)
    pub bind_port: u16,
}

impl Default for QuicFfiEndpointConfig {
    fn default() -> Self {
        Self {
            mode: QuicEndpointMode::ClientOnly,
            bind_ip: 0,   // INADDR_ANY
            bind_port: 0, // System-assigned
        }
    }
}

