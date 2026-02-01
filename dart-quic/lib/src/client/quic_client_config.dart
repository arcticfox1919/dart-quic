import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:dart_quic/src/bindings/quic_ffi_bindings.dart';
import 'package:dart_quic/src/common/quic_transport_config.dart';
import 'package:ffi/ffi.dart';

/// QUIC client configuration
///
/// Provides fluent API for configuring client-side QUIC connections.
/// Supports various trust modes and client certificate configurations (mTLS).
///
/// Example:
/// ```dart
/// // Use system root certificates
/// final config = QuicClientConfig.withSystemRoots();
///
/// // Skip verification (testing only!)
/// final config = QuicClientConfig.withSkipVerification();
///
/// // Custom CA from file
/// final config = QuicClientConfig.withCustomCaPemFile('/path/to/ca.pem');
///
/// // With client certificate (mTLS)
/// final config = QuicClientConfig.withSystemRoots()
///   ..setClientCertFromPemFiles('/path/to/cert.pem', '/path/to/key.pem');
/// ```
class QuicClientConfig {
  static final Finalizer<Arena> _arenaFinalizer = Finalizer<Arena>((
    Arena arena,
  ) {
    try {
      arena.releaseAll();
    } catch (_) {
      // swallow errors in finalizer
    }
  });

  late final ffi.Pointer<QuicFfiClientConfig> _config;

  // Use Arena for automatic memory management
  final _arena = Arena();

  // Private constructor
  QuicClientConfig._internal(QuicFfiTrustMode trustMode) {
    // Allocate config struct using arena
    _config = _arena<QuicFfiClientConfig>();
    _initializeDefaults(trustMode);
    // Attach finalizer as a safety net in case dispose() is not called.
    _arenaFinalizer.attach(this, _arena, detach: _arena);
  }

  // ========== Factory Constructors ==========

  /// Create config with system root certificates (recommended for production)
  factory QuicClientConfig.withSystemRoots() {
    return QuicClientConfig._internal(QuicFfiTrustMode.SystemRoots);
  }

  /// Create config that skips certificate verification (testing only! dangerous!)
  factory QuicClientConfig.withSkipVerification() {
    return QuicClientConfig._internal(QuicFfiTrustMode.SkipVerification);
  }

  /// Create config with custom CA certificate from DER-encoded bytes
  factory QuicClientConfig.withCustomCaDer(Uint8List caDer) {
    final config = QuicClientConfig._internal(QuicFfiTrustMode.CustomCaDer);
    config._setCustomCaDer(caDer);
    return config;
  }

  /// Create config with custom CA certificate from PEM file
  factory QuicClientConfig.withCustomCaPemFile(String caPath) {
    final config = QuicClientConfig._internal(QuicFfiTrustMode.CustomCaPemFile);
    config._setCustomCaPath(caPath);
    return config;
  }

  /// Create config with custom CA certificate from DER file
  factory QuicClientConfig.withCustomCaDerFile(String caPath) {
    final config = QuicClientConfig._internal(QuicFfiTrustMode.CustomCaDerFile);
    config._setCustomCaPath(caPath);
    return config;
  }

  // ========== Initialization ==========

  void _initializeDefaults(QuicFfiTrustMode trustMode) {
    _config.ref.trust_mode = trustMode.value;
    _config.ref.ca_cert_data = ffi.nullptr;
    _config.ref.ca_cert_len = 0;
    _config.ref.ca_cert_path = ffi.nullptr;
    _config.ref.client_cert_mode = QuicFfiClientCertMode.None.value;
    _config.ref.client_cert_data = ffi.nullptr;
    _config.ref.client_cert_len = 0;
    _config.ref.client_key_data = ffi.nullptr;
    _config.ref.client_key_len = 0;
    _config.ref.client_cert_path = ffi.nullptr;
    _config.ref.client_key_path = ffi.nullptr;
    _config.ref.transport_config = ffi.nullptr;
    _config.ref.bind_addr = ffi.nullptr;
  }

  // ========== CA Certificate Configuration ==========

  void _setCustomCaDer(Uint8List caDer) {
    final ptr = _arena<ffi.Uint8>(caDer.length);
    // Use setRange for explicit range specification
    ptr.asTypedList(caDer.length).setRange(0, caDer.length, caDer);

    _config.ref.ca_cert_data = ptr;
    _config.ref.ca_cert_len = caDer.length;
  }

  void _setCustomCaPath(String caPath) {
    final ptr = caPath.toNativeUtf8(allocator: _arena);
    _config.ref.ca_cert_path = ptr.cast<ffi.Char>();
  }

  // ========== Client Certificate Configuration (mTLS) ==========

  /// Set client certificate from DER-encoded bytes (mTLS)
  ///
  /// Parameters:
  /// - [certDer]: Client certificate in DER format
  /// - [keyDer]: Private key in DER format
  QuicClientConfig setClientCertFromDer(Uint8List certDer, Uint8List keyDer) {
    _config.ref.client_cert_mode = QuicFfiClientCertMode.Der.value;

    // Allocate and copy certificate
    final certPtr = _arena<ffi.Uint8>(certDer.length);
    certPtr.asTypedList(certDer.length).setRange(0, certDer.length, certDer);
    _config.ref.client_cert_data = certPtr;
    _config.ref.client_cert_len = certDer.length;

    // Allocate and copy key
    final keyPtr = _arena<ffi.Uint8>(keyDer.length);
    keyPtr.asTypedList(keyDer.length).setRange(0, keyDer.length, keyDer);
    _config.ref.client_key_data = keyPtr;
    _config.ref.client_key_len = keyDer.length;

    return this;
  }

  /// Set client certificate from PEM files (mTLS)
  ///
  /// Parameters:
  /// - [certPath]: Path to client certificate PEM file
  /// - [keyPath]: Path to private key PEM file
  QuicClientConfig setClientCertFromPemFiles(String certPath, String keyPath) {
    _config.ref.client_cert_mode = QuicFfiClientCertMode.PemFile.value;

    _config.ref.client_cert_path = certPath
        .toNativeUtf8(allocator: _arena)
        .cast<ffi.Char>();
    _config.ref.client_key_path = keyPath
        .toNativeUtf8(allocator: _arena)
        .cast<ffi.Char>();

    return this;
  }

  /// Set client certificate from DER files (mTLS)
  ///
  /// Parameters:
  /// - [certPath]: Path to client certificate DER file
  /// - [keyPath]: Path to private key DER file
  QuicClientConfig setClientCertFromDerFiles(String certPath, String keyPath) {
    _config.ref.client_cert_mode = QuicFfiClientCertMode.DerFile.value;

    _config.ref.client_cert_path = certPath
        .toNativeUtf8(allocator: _arena)
        .cast<ffi.Char>();
    _config.ref.client_key_path = keyPath
        .toNativeUtf8(allocator: _arena)
        .cast<ffi.Char>();

    return this;
  }

  // ========== Transport Configuration ==========

  /// Set custom transport configuration
  ///
  /// Parameters:
  /// - [transportConfig]: QuicTransportConfig instance
  QuicClientConfig setTransportConfig(QuicTransportConfig transportConfig) {
    _config.ref.transport_config = transportConfig.ffiConfig;
    return this;
  }

  // ========== Bind Address ==========

  /// Set local bind address
  ///
  /// Parameters:
  /// - [bindAddr]: Local bind address (e.g., "0.0.0.0:0" for system-assigned port)
  QuicClientConfig setBindAddress(String bindAddr) {
    _config.ref.bind_addr = bindAddr
        .toNativeUtf8(allocator: _arena)
        .cast<ffi.Char>();
    return this;
  }

  // ========== Getters ==========

  /// Get the underlying FFI config pointer
  ffi.Pointer<QuicFfiClientConfig> get ffiConfig => _config;

  /// Get trust mode
  QuicFfiTrustMode get trustMode =>
      QuicFfiTrustMode.fromValue(_config.ref.trust_mode);

  /// Get client certificate mode
  QuicFfiClientCertMode get clientCertMode =>
      QuicFfiClientCertMode.fromValue(_config.ref.client_cert_mode);

  /// Check if client certificate is configured
  bool get hasClientCert =>
      _config.ref.client_cert_mode != QuicFfiClientCertMode.None.value;

  // ========== Cleanup ==========

  /// Free all allocated resources
  ///
  /// IMPORTANT: Must be called when the config is no longer needed.
  /// Arena automatically frees all allocated memory.
  void dispose() {
    // Prevent finalizer from running after explicit dispose to avoid double-free
    _arenaFinalizer.detach(_arena);
    _arena.releaseAll();
  }

  @override
  String toString() {
    return 'QuicClientConfig('
        'trustMode: $trustMode, '
        'clientCertMode: $clientCertMode'
        ')';
  }
}
