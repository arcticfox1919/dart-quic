//! QUIC Error Types Module
//!
//! Provides unified error handling mechanism with error codes and detailed error messages.
//! Error messages are provided by the Dart layer based on error codes; only unknown error types require custom messages.

use std::fmt;
use std::error::Error;

use crate::types::QuicResult;

// ============================================================================
// QuicError Definition
// ============================================================================

/// QUIC Error Type
///
/// Contains error code and optional detailed error information.
/// - Known error types: contain only error code; message is provided by the Dart layer based on error code
/// - Unknown error types: contain custom message for passing underlying error details
#[derive(Clone)]
pub struct QuicError {
    /// Error code
    code: QuicResult,
    /// Detailed error message (only used for unknown error types)
    message: Option<String>,
}

impl QuicError {
    /// Create from error code (known error type, no custom message needed)
    pub fn from_code(code: QuicResult) -> Self {
        Self {
            code,
            message: None,
        }
    }

    /// Create an unknown error (requires custom message)
    pub fn unknown(message: impl Into<String>) -> Self {
        Self {
            code: QuicResult::UnknownError,
            message: Some(message.into()),
        }
    }

    /// Get error code
    pub fn code(&self) -> QuicResult {
        self.code
    }

    /// Get integer value of error code
    pub fn code_value(&self) -> i32 {
        self.code as i32
    }

    /// Get error message (only has value for unknown error types)
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Check if successful (not a true error)
    pub fn is_success(&self) -> bool {
        matches!(self.code, QuicResult::Success)
    }
}

impl fmt::Debug for QuicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("QuicError");
        d.field("code", &self.code);
        if let Some(msg) = &self.message {
            d.field("message", msg);
        }
        d.finish()
    }
}

impl fmt::Display for QuicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            Some(msg) => write!(f, "[{:?}] {}", self.code, msg),
            None => write!(f, "[{:?}]", self.code),
        }
    }
}

impl Error for QuicError {}

// ============================================================================
// Error Type Conversion
// ============================================================================

impl From<std::io::Error> for QuicError {
    fn from(err: std::io::Error) -> Self {
        // IO errors are diverse, preserve the original message
        Self {
            code: QuicResult::IoError,
            message: Some(err.to_string()),
        }
    }
}

impl From<quinn::ConnectionError> for QuicError {
    fn from(err: quinn::ConnectionError) -> Self {
        let code = match &err {
            quinn::ConnectionError::VersionMismatch => QuicResult::VersionMismatch,
            quinn::ConnectionError::TransportError(_) => QuicResult::TransportError,
            quinn::ConnectionError::ConnectionClosed(_) => QuicResult::ConnectionClosed,
            quinn::ConnectionError::ApplicationClosed(_) => QuicResult::ApplicationClosed,
            quinn::ConnectionError::Reset => QuicResult::ConnectionReset,
            quinn::ConnectionError::TimedOut => QuicResult::Timeout,
            quinn::ConnectionError::LocallyClosed => QuicResult::ConnectionClosed,
            quinn::ConnectionError::CidsExhausted => QuicResult::ResourceExhausted,
        };
        Self::from_code(code)
    }
}

impl From<quinn::ConnectError> for QuicError {
    fn from(err: quinn::ConnectError) -> Self {
        let code = match &err {
            quinn::ConnectError::EndpointStopping => QuicResult::EndpointClosed,
            quinn::ConnectError::InvalidServerName(_) => QuicResult::InvalidParameter,
            quinn::ConnectError::InvalidRemoteAddress(_) => QuicResult::InvalidParameter,
            quinn::ConnectError::NoDefaultClientConfig => QuicResult::ConfigError,
            quinn::ConnectError::UnsupportedVersion => QuicResult::VersionMismatch,
            quinn::ConnectError::CidsExhausted => QuicResult::ResourceExhausted,
        };
        Self::from_code(code)
    }
}

impl From<quinn::WriteError> for QuicError {
    fn from(err: quinn::WriteError) -> Self {
        let code = match &err {
            quinn::WriteError::Stopped(_) => QuicResult::StreamStopped,
            quinn::WriteError::ConnectionLost(_) => QuicResult::ConnectionLost,
            quinn::WriteError::ClosedStream => QuicResult::StreamClosed,
            quinn::WriteError::ZeroRttRejected => QuicResult::ZeroRttRejected,
        };
        Self::from_code(code)
    }
}

impl From<quinn::ReadError> for QuicError {
    fn from(err: quinn::ReadError) -> Self {
        let code = match &err {
            quinn::ReadError::Reset(_) => QuicResult::StreamReset,
            quinn::ReadError::ConnectionLost(_) => QuicResult::ConnectionLost,
            quinn::ReadError::ClosedStream => QuicResult::StreamClosed,
            quinn::ReadError::IllegalOrderedRead => QuicResult::InvalidOperation,
            quinn::ReadError::ZeroRttRejected => QuicResult::ZeroRttRejected,
        };
        Self::from_code(code)
    }
}

impl From<quinn::ReadToEndError> for QuicError {
    fn from(err: quinn::ReadToEndError) -> Self {
        match err {
            quinn::ReadToEndError::Read(e) => e.into(),
            quinn::ReadToEndError::TooLong => Self::from_code(QuicResult::BufferTooSmall),
        }
    }
}

impl From<quinn::SendDatagramError> for QuicError {
    fn from(err: quinn::SendDatagramError) -> Self {
        let code = match &err {
            quinn::SendDatagramError::UnsupportedByPeer => QuicResult::UnsupportedByPeer,
            quinn::SendDatagramError::Disabled => QuicResult::DatagramDisabled,
            quinn::SendDatagramError::TooLarge => QuicResult::DatagramTooLarge,
            quinn::SendDatagramError::ConnectionLost(_) => QuicResult::ConnectionLost,
        };
        Self::from_code(code)
    }
}

impl From<quinn::ClosedStream> for QuicError {
    fn from(_err: quinn::ClosedStream) -> Self {
        Self::from_code(QuicResult::StreamClosed)
    }
}
