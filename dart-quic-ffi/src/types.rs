//! QUIC Type Definition Module
//!
//! Defines FFI-friendly result codes and common types.

// ============================================================================
// QuicResult Error Code
// ============================================================================

/// QUIC Operation Result Code
///
/// FFI-friendly error code enumeration for passing operation results across language boundaries.
/// Value design:
/// - 0: Success
/// - 1-99: Generic errors
/// - 100-199: Connection-related errors
/// - 200-299: Stream-related errors
/// - 300-399: Datagram-related errors
/// - 400-499: Configuration and parameter errors
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicResult {
    // ===== Success =====
    /// Operation succeeded
    Success = 0,

    // ===== Generic errors (1-99) =====
    /// Unknown error
    UnknownError = 1,
    /// Runtime error
    RuntimeError = 2,
    /// IO error
    IoError = 3,
    /// Timeout
    Timeout = 4,
    /// Resource exhausted
    ResourceExhausted = 5,
    /// Invalid operation
    InvalidOperation = 6,
    /// Internal error
    InternalError = 7,
    /// Operation cancelled
    Cancelled = 8,

    // ===== Connection-related errors (100-199) =====
    /// Connection failed
    ConnectionFailed = 100,
    /// Connection closed
    ConnectionClosed = 101,
    /// Connection lost
    ConnectionLost = 102,
    /// Connection reset
    ConnectionReset = 103,
    /// Version mismatch
    VersionMismatch = 104,
    /// Transport layer error
    TransportError = 105,
    /// Application layer closed
    ApplicationClosed = 106,
    /// Endpoint closed
    EndpointClosed = 107,
    /// Handshake failed
    HandshakeFailed = 108,
    /// TLS error
    TlsError = 109,
    /// Certificate error
    CertificateError = 110,

    // ===== Stream-related errors (200-299) =====
    /// Stream operation error
    StreamError = 200,
    /// Stream closed
    StreamClosed = 201,
    /// Stream reset
    StreamReset = 202,
    /// Stream stopped
    StreamStopped = 203,
    /// 0-RTT rejected
    ZeroRttRejected = 204,
    /// Buffer too small
    BufferTooSmall = 205,
    /// No more data
    NoMoreData = 206,

    // ===== Datagram-related errors (300-399) =====
    /// Datagram feature disabled
    DatagramDisabled = 300,
    /// Datagram too large
    DatagramTooLarge = 301,
    /// Unsupported by peer
    UnsupportedByPeer = 302,

    // ===== Configuration and parameter errors (400-499) =====
    /// Invalid parameter
    InvalidParameter = 400,
    /// Configuration error
    ConfigError = 401,
    /// Address parse error
    AddressParseError = 402,
    /// File not found
    FileNotFound = 403,
    /// Format error
    FormatError = 404,
}

impl QuicResult {
    /// Check if successful
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    /// Check if connection-related error
    pub fn is_connection_error(&self) -> bool {
        let code = *self as i32;
        (100..200).contains(&code)
    }

    /// Check if stream-related error
    pub fn is_stream_error(&self) -> bool {
        let code = *self as i32;
        (200..300).contains(&code)
    }

    /// Convert from integer value
    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => Self::Success,
            1 => Self::UnknownError,
            2 => Self::RuntimeError,
            3 => Self::IoError,
            4 => Self::Timeout,
            5 => Self::ResourceExhausted,
            6 => Self::InvalidOperation,
            7 => Self::InternalError,
            8 => Self::Cancelled,

            100 => Self::ConnectionFailed,
            101 => Self::ConnectionClosed,
            102 => Self::ConnectionLost,
            103 => Self::ConnectionReset,
            104 => Self::VersionMismatch,
            105 => Self::TransportError,
            106 => Self::ApplicationClosed,
            107 => Self::EndpointClosed,
            108 => Self::HandshakeFailed,
            109 => Self::TlsError,
            110 => Self::CertificateError,

            200 => Self::StreamError,
            201 => Self::StreamClosed,
            202 => Self::StreamReset,
            203 => Self::StreamStopped,
            204 => Self::ZeroRttRejected,
            205 => Self::BufferTooSmall,
            206 => Self::NoMoreData,

            300 => Self::DatagramDisabled,
            301 => Self::DatagramTooLarge,
            302 => Self::UnsupportedByPeer,

            400 => Self::InvalidParameter,
            401 => Self::ConfigError,
            402 => Self::AddressParseError,
            403 => Self::FileNotFound,
            404 => Self::FormatError,

            _ => Self::UnknownError,
        }
    }
}

impl Default for QuicResult {
    fn default() -> Self {
        Self::Success
    }
}
