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
abstract final class QuicResultCode {
  // ===== Success =====
  /// Operation succeeded
  static const int success = 0;

  // ===== Generic errors (1-99) =====
  /// Unknown error
  static const int unknownError = 1;

  /// Runtime error
  static const int runtimeError = 2;

  /// I/O error
  static const int ioError = 3;

  /// Timeout
  static const int timeout = 4;

  /// Resource exhausted
  static const int resourceExhausted = 5;

  /// Invalid operation
  static const int invalidOperation = 6;

  /// Internal error
  static const int internalError = 7;

  /// Operation cancelled
  static const int cancelled = 8;

  // ===== Connection-related errors (100-199) =====
  /// Connection failed
  static const int connectionFailed = 100;

  /// Connection closed
  static const int connectionClosed = 101;

  /// Connection lost
  static const int connectionLost = 102;

  /// Connection reset
  static const int connectionReset = 103;

  /// Version mismatch
  static const int versionMismatch = 104;

  /// Transport layer error
  static const int transportError = 105;

  /// Application closed connection
  static const int applicationClosed = 106;

  /// Endpoint closed
  static const int endpointClosed = 107;

  /// Handshake failed
  static const int handshakeFailed = 108;

  /// TLS error
  static const int tlsError = 109;

  /// Certificate error
  static const int certificateError = 110;

  // ===== Stream-related errors (200-299) =====
  /// Stream operation error
  static const int streamError = 200;

  /// Stream closed
  static const int streamClosed = 201;

  /// Stream reset by peer
  static const int streamReset = 202;

  /// Stream stopped
  static const int streamStopped = 203;

  /// 0-RTT data rejected
  static const int zeroRttRejected = 204;

  /// Buffer too small
  static const int bufferTooSmall = 205;

  /// No more data available
  static const int noMoreData = 206;

  // ===== Datagram-related errors (300-399) =====
  /// Datagram feature disabled
  static const int datagramDisabled = 300;

  /// Datagram too large
  static const int datagramTooLarge = 301;

  /// Feature not supported by peer
  static const int unsupportedByPeer = 302;

  // ===== Configuration and parameter errors (400-499) =====
  /// Invalid parameter
  static const int invalidParameter = 400;

  /// Configuration error
  static const int configError = 401;

  /// Address parse error
  static const int addressParseError = 402;

  /// File not found
  static const int fileNotFound = 403;

  /// Format error
  static const int formatError = 404;

  // ===== Static Methods =====

  /// Get the default error message for a result code
  static String getMessage(int code) {
    return _messages[code] ?? 'Unknown error (code: $code)';
  }

  /// Check if operation succeeded
  static bool isSuccess(int code) => code == success;

  /// Check if error is connection-related
  static bool isConnectionError(int code) => code >= 100 && code < 200;

  /// Check if error is stream-related
  static bool isStreamError(int code) => code >= 200 && code < 300;

  /// Check if error is datagram-related
  static bool isDatagramError(int code) => code >= 300 && code < 400;

  /// Check if error is configuration/parameter related
  static bool isConfigError(int code) => code >= 400 && code < 500;

  /// Default error messages for result codes
  static const _messages = <int, String>{
    // Success
    success: 'Operation successful',

    // Generic errors
    unknownError: 'Unknown error',
    runtimeError: 'Runtime error',
    ioError: 'I/O error',
    timeout: 'Operation timed out',
    resourceExhausted: 'Resource exhausted',
    invalidOperation: 'Invalid operation',
    internalError: 'Internal error',
    cancelled: 'Operation cancelled',

    // Connection-related
    connectionFailed: 'Connection failed',
    connectionClosed: 'Connection closed',
    connectionLost: 'Connection lost',
    connectionReset: 'Connection reset',
    versionMismatch: 'QUIC version mismatch',
    transportError: 'Transport error',
    applicationClosed: 'Application closed connection',
    endpointClosed: 'Endpoint closed',
    handshakeFailed: 'Handshake failed',
    tlsError: 'TLS error',
    certificateError: 'Certificate error',

    // Stream-related
    streamError: 'Stream operation error',
    streamClosed: 'Stream closed',
    streamReset: 'Stream reset by peer',
    streamStopped: 'Stream stopped',
    zeroRttRejected: '0-RTT data rejected',
    bufferTooSmall: 'Buffer too small',
    noMoreData: 'No more data available',

    // Datagram-related
    datagramDisabled: 'Datagram feature disabled',
    datagramTooLarge: 'Datagram too large',
    unsupportedByPeer: 'Feature not supported by peer',

    // Configuration and parameters
    invalidParameter: 'Invalid parameter',
    configError: 'Configuration error',
    addressParseError: 'Address parse error',
    fileNotFound: 'File not found',
    formatError: 'Format error',
  };
}
