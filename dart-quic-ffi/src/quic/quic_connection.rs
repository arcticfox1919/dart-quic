//! QUIC Connection Wrapper
//!
//! Standalone connection module, used by both client and server.

use std::net::SocketAddr;

use quinn::{Connection, RecvStream, SendStream};
use rustls::pki_types::CertificateDer;

use crate::error::QuicError;
use crate::types::QuicResult;

// ============================================================================
// QUIC Connection
// ============================================================================

/// QUIC Connection
///
/// Wraps a single QUIC connection, providing stream operation APIs.
/// This type is used by both `QuicClient` and `QuicServer`.
///
/// # Thread Safety
/// `QuicConnection` is thread-safe and can be safely used across multiple threads.
pub struct QuicConnection {
    inner: Connection,
}

impl QuicConnection {
    /// Create from quinn::Connection
    pub(crate) fn new(connection: Connection) -> Self {
        Self { inner: connection }
    }

    /// Get remote address
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    /// Get local address
    pub fn local_ip(&self) -> Option<std::net::IpAddr> {
        self.inner.local_ip()
    }

    /// Get stable ID of the connection
    pub fn stable_id(&self) -> usize {
        self.inner.stable_id()
    }

    /// Create bidirectional stream
    ///
    /// Returns a (send stream, receive stream) tuple.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), QuicError> {
        self.inner
            .open_bi()
            .await
            .map_err(|e| QuicError::from(e))
    }

    /// Create unidirectional stream (send only)
    pub async fn open_uni(&self) -> Result<SendStream, QuicError> {
        self.inner
            .open_uni()
            .await
            .map_err(|e| QuicError::from(e))
    }

    /// Accept bidirectional stream created by peer
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), QuicError> {
        self.inner
            .accept_bi()
            .await
            .map_err(|e| QuicError::from(e))
    }

    /// Accept unidirectional stream created by peer (receive only)
    pub async fn accept_uni(&self) -> Result<RecvStream, QuicError> {
        self.inner
            .accept_uni()
            .await
            .map_err(|e| QuicError::from(e))
    }

    /// Send unreliable datagram
    ///
    /// QUIC Datagrams are unreliable and don't guarantee delivery, suitable for real-time data.
    pub fn send_datagram(&self, data: bytes::Bytes) -> Result<(), QuicError> {
        self.inner
            .send_datagram(data)
            .map_err(|e| QuicError::from(e))
    }

    /// Receive unreliable datagram
    pub async fn read_datagram(&self) -> Result<bytes::Bytes, QuicError> {
        self.inner
            .read_datagram()
            .await
            .map_err(|_| QuicError::from_code(QuicResult::StreamError))
    }

    /// Get maximum datagram size
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }

    /// Get current round-trip time (RTT) estimate
    pub fn rtt(&self) -> std::time::Duration {
        self.inner.rtt()
    }

    /// Get peer certificate (if available)
    ///
    /// In mutual authentication (mTLS) scenarios, servers can obtain client certificates.
    pub fn peer_identity(&self) -> Option<Vec<CertificateDer<'static>>> {
        self.inner
            .peer_identity()
            .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok())
            .map(|certs| (*certs).clone())
    }

    /// Close connection
    ///
    /// # Parameters
    /// - `error_code`: Application error code
    /// - `reason`: Close reason (UTF-8 string)
    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.inner.close(error_code.into(), reason);
    }

    /// Wait for connection to fully close
    pub async fn closed(&self) -> quinn::ConnectionError {
        self.inner.closed().await
    }

    /// Get internal quinn::Connection reference
    pub fn inner(&self) -> &Connection {
        &self.inner
    }

    /// Consume and return internal quinn::Connection
    pub fn into_inner(self) -> Connection {
        self.inner
    }
}

// ============================================================================
// FFI-Friendly Connection Handle
// ============================================================================

/// Connection handle (for C API)
///
/// FFI-friendly structure that wraps a QuicConnection pointer along with
/// commonly used connection information. This allows the Dart layer to
/// directly access connection info without additional FFI calls.
///
/// # Memory Management
/// - `connection`: Owned pointer, must be freed via `dart_quic_connection_handle_free`
/// - `remote_addr`: Owned string pointer, freed together with handle
///
/// # C API Usage
/// ```c
/// QuicConnectionHandle* handle = ...;
/// printf("Connected to: %.*s\n", (int)handle->remote_addr_len, handle->remote_addr);
/// // Use handle->connection for stream operations
/// dart_quic_connection_handle_free(handle);
/// ```
#[repr(C)]
pub struct QuicConnectionHandle {
    /// Connection pointer (for subsequent operations)
    pub connection: *mut QuicConnection,
    /// Connection stable ID (unique identifier)
    pub stable_id: u64,
    /// Remote address string (IP:Port format, allocated memory)
    pub remote_addr: *mut u8,
    /// Remote address string length
    pub remote_addr_len: u32,
}

impl QuicConnectionHandle {
    /// Create a new connection handle from QuicConnection
    ///
    /// Takes ownership of the connection and allocates remote address string.
    pub fn new(connection: QuicConnection) -> Self {
        let remote_addr_str = connection.remote_address().to_string();
        let stable_id = connection.stable_id() as u64;
        
        // Allocate and copy remote address string
        let remote_addr_bytes = remote_addr_str.as_bytes();
        let remote_addr = crate::allocate(remote_addr_bytes.len());
        let remote_addr_len = if !remote_addr.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    remote_addr_bytes.as_ptr(),
                    remote_addr,
                    remote_addr_bytes.len()
                );
            }
            remote_addr_bytes.len() as u32
        } else {
            0
        };
        
        // Box the connection and get raw pointer
        let connection_ptr = Box::into_raw(Box::new(connection));
        
        Self {
            connection: connection_ptr,
            stable_id,
            remote_addr,
            remote_addr_len,
        }
    }
    
    /// Create a null/invalid handle
    pub fn null() -> Self {
        Self {
            connection: std::ptr::null_mut(),
            stable_id: 0,
            remote_addr: std::ptr::null_mut(),
            remote_addr_len: 0,
        }
    }
    
    /// Check if handle is valid
    pub fn is_valid(&self) -> bool {
        !self.connection.is_null()
    }
}
