import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:dart_quic/src/bindings/quic_ffi_bindings.dart';
import 'package:dart_quic/src/common/quic_transport_config.dart';
import 'package:ffi/ffi.dart';

/// Certificate mode for QUIC server configuration
enum QuicServerCertMode {
  /// Load certificate from PEM/DER files
  file(0),

  /// Load certificate from DER memory
  memory(1),

  /// Generate self-signed certificate (testing only!)
  selfSigned(2);

  const QuicServerCertMode(this.value);
  final int value;
}

/// Client authentication mode for mTLS
enum QuicClientAuthMode {
  /// Client authentication not required (default)
  notRequired(0),

  /// Client authentication required
  required(1),

  /// Client authentication optional
  optional(2);

  const QuicClientAuthMode(this.value);
  final int value;
}

/// QUIC server configuration
///
/// Provides fluent API for configuring server-side QUIC connections.
/// Supports self-signed certificates (for testing), PEM files, and DER memory.
///
/// Example:
/// ```dart
/// // Self-signed certificate (testing only!)
/// final config = QuicServerConfig.selfSigned(
///   bindAddr: '0.0.0.0:4433',
///   sanList: ['localhost', '127.0.0.1'],
/// );
///
/// // PEM certificate files
/// final config = QuicServerConfig.withCertFiles(
///   bindAddr: '0.0.0.0:4433',
///   certPath: '/path/to/cert.pem',
///   keyPath: '/path/to/key.pem',
/// );
///
/// // DER certificate in memory
/// final config = QuicServerConfig.withCertDer(
///   bindAddr: '0.0.0.0:4433',
///   certDer: certBytes,
///   keyDer: keyBytes,
/// );
/// ```
class QuicServerConfig {
  static final Finalizer<Arena> _arenaFinalizer = Finalizer<Arena>((arena) {
    try {
      arena.releaseAll();
    } catch (_) {
      // swallow errors in finalizer
    }
  });

  final Arena _arena = Arena();
  late final ffi.Pointer<QuicFfiServerConfig> _config;
  final String _bindAddr;

  // For self-signed: list of SANs (Subject Alternative Names)
  final List<String> _sanList;

  // For cert files
  final String? _certPath;
  final String? _keyPath;

  // For convenience when calling the correct FFI function
  final QuicServerCertMode _certMode;

  QuicServerConfig._internal({
    required String bindAddr,
    required QuicServerCertMode certMode,
    List<String> sanList = const [],
    String? certPath,
    String? keyPath,
    Uint8List? certDer,
    Uint8List? keyDer,
    QuicClientAuthMode clientAuthMode = QuicClientAuthMode.notRequired,
    Uint8List? clientCaDer,
  }) : _bindAddr = bindAddr,
       _certMode = certMode,
       _sanList = sanList,
       _certPath = certPath,
       _keyPath = keyPath {
    _config = _arena<QuicFfiServerConfig>();
    _initializeDefaults();
    _applyConfig(
      certMode: certMode,
      sanList: sanList,
      certPath: certPath,
      keyPath: keyPath,
      certDer: certDer,
      keyDer: keyDer,
      clientAuthMode: clientAuthMode,
      clientCaDer: clientCaDer,
    );
    _arenaFinalizer.attach(this, _arena, detach: _arena);
  }

  // ========== Factory Constructors ==========

  /// Create config with self-signed certificate (testing only!)
  ///
  /// Parameters:
  /// - [bindAddr]: Local bind address (e.g., "0.0.0.0:4433")
  /// - [sanList]: List of Subject Alternative Names (e.g., ['localhost', '127.0.0.1'])
  ///   If empty, defaults to ['localhost']
  /// - [transportConfig]: Optional transport configuration
  factory QuicServerConfig.selfSigned({
    required String bindAddr,
    List<String> sanList = const ['localhost'],
    QuicTransportConfig? transportConfig,
  }) {
    final config = QuicServerConfig._internal(
      bindAddr: bindAddr,
      certMode: QuicServerCertMode.selfSigned,
      sanList: sanList.isEmpty ? const ['localhost'] : sanList,
    );
    if (transportConfig != null) {
      config._config.ref.transport = transportConfig.ffiConfig;
    }
    return config;
  }

  /// Create config with PEM certificate files
  ///
  /// Parameters:
  /// - [bindAddr]: Local bind address (e.g., "0.0.0.0:4433")
  /// - [certPath]: Path to PEM certificate file
  /// - [keyPath]: Path to PEM private key file
  /// - [transportConfig]: Optional transport configuration
  /// - [clientAuthMode]: Client authentication mode (default: notRequired)
  /// - [clientCaDer]: Client CA certificate DER data (required when clientAuthMode != notRequired)
  factory QuicServerConfig.withCertFiles({
    required String bindAddr,
    required String certPath,
    required String keyPath,
    QuicTransportConfig? transportConfig,
    QuicClientAuthMode clientAuthMode = QuicClientAuthMode.notRequired,
    Uint8List? clientCaDer,
  }) {
    final config = QuicServerConfig._internal(
      bindAddr: bindAddr,
      certMode: QuicServerCertMode.file,
      certPath: certPath,
      keyPath: keyPath,
      clientAuthMode: clientAuthMode,
      clientCaDer: clientCaDer,
    );
    if (transportConfig != null) {
      config._config.ref.transport = transportConfig.ffiConfig;
    }
    return config;
  }

  /// Create config with DER certificate from memory
  ///
  /// Parameters:
  /// - [bindAddr]: Local bind address (e.g., "0.0.0.0:4433")
  /// - [certDer]: Certificate in DER format
  /// - [keyDer]: Private key in DER format
  /// - [transportConfig]: Optional transport configuration
  /// - [clientAuthMode]: Client authentication mode (default: notRequired)
  /// - [clientCaDer]: Client CA certificate DER data (required when clientAuthMode != notRequired)
  factory QuicServerConfig.withCertDer({
    required String bindAddr,
    required Uint8List certDer,
    required Uint8List keyDer,
    QuicTransportConfig? transportConfig,
    QuicClientAuthMode clientAuthMode = QuicClientAuthMode.notRequired,
    Uint8List? clientCaDer,
  }) {
    final config = QuicServerConfig._internal(
      bindAddr: bindAddr,
      certMode: QuicServerCertMode.memory,
      certDer: certDer,
      keyDer: keyDer,
      clientAuthMode: clientAuthMode,
      clientCaDer: clientCaDer,
    );
    if (transportConfig != null) {
      config._config.ref.transport = transportConfig.ffiConfig;
    }
    return config;
  }

  // ========== Initialization ==========

  void _initializeDefaults() {
    _config.ref.cert_mode = 0;
    _config.ref.cert_path_ptr = ffi.nullptr;
    _config.ref.key_path_ptr = ffi.nullptr;
    _config.ref.cert_der_ptr = ffi.nullptr;
    _config.ref.cert_der_len = 0;
    _config.ref.key_der_ptr = ffi.nullptr;
    _config.ref.key_der_len = 0;
    _config.ref.san_ptr = ffi.nullptr;
    _config.ref.san_count = 0;
    _config.ref.client_auth_mode = 0;
    _config.ref.client_ca_ptr = ffi.nullptr;
    _config.ref.client_ca_len = 0;
    _config.ref.transport = ffi.nullptr;
  }

  void _applyConfig({
    required QuicServerCertMode certMode,
    required List<String> sanList,
    String? certPath,
    String? keyPath,
    Uint8List? certDer,
    Uint8List? keyDer,
    required QuicClientAuthMode clientAuthMode,
    Uint8List? clientCaDer,
  }) {
    _config.ref.cert_mode = certMode.value;

    // San list (for self-signed)
    if (sanList.isNotEmpty) {
      final sanPtrs = _arena<ffi.Pointer<ffi.Char>>(sanList.length);
      for (var i = 0; i < sanList.length; i++) {
        sanPtrs[i] = sanList[i]
            .toNativeUtf8(allocator: _arena)
            .cast<ffi.Char>();
      }
      _config.ref.san_ptr = sanPtrs;
      _config.ref.san_count = sanList.length;
    }

    // Certificate file paths
    if (certPath != null) {
      _config.ref.cert_path_ptr = certPath
          .toNativeUtf8(allocator: _arena)
          .cast<ffi.Char>();
    }
    if (keyPath != null) {
      _config.ref.key_path_ptr = keyPath
          .toNativeUtf8(allocator: _arena)
          .cast<ffi.Char>();
    }

    // Certificate DER data
    if (certDer != null) {
      final ptr = _arena<ffi.Uint8>(certDer.length);
      ptr.asTypedList(certDer.length).setRange(0, certDer.length, certDer);
      _config.ref.cert_der_ptr = ptr;
      _config.ref.cert_der_len = certDer.length;
    }
    if (keyDer != null) {
      final ptr = _arena<ffi.Uint8>(keyDer.length);
      ptr.asTypedList(keyDer.length).setRange(0, keyDer.length, keyDer);
      _config.ref.key_der_ptr = ptr;
      _config.ref.key_der_len = keyDer.length;
    }

    // Client authentication
    _config.ref.client_auth_mode = clientAuthMode.value;
    if (clientCaDer != null) {
      final ptr = _arena<ffi.Uint8>(clientCaDer.length);
      ptr
          .asTypedList(clientCaDer.length)
          .setRange(0, clientCaDer.length, clientCaDer);
      _config.ref.client_ca_ptr = ptr;
      _config.ref.client_ca_len = clientCaDer.length;
    }
  }

  // ========== Getters ==========

  /// Local bind address
  String get bindAddr => _bindAddr;

  /// Certificate mode
  QuicServerCertMode get certMode => _certMode;

  /// SAN list (for self-signed certificates)
  List<String> get sanList => List.unmodifiable(_sanList);

  /// Certificate file path (for file mode)
  String? get certPath => _certPath;

  /// Key file path (for file mode)
  String? get keyPath => _keyPath;

  /// Underlying FFI config pointer (internal use)
  ffi.Pointer<QuicFfiServerConfig> get ffiConfig => _config;

  /// Bind address as native C string (internal use)
  ffi.Pointer<ffi.Char> get nativeBindAddr =>
      _bindAddr.toNativeUtf8(allocator: _arena).cast<ffi.Char>();

  /// SAN list as native C string array (internal use, for self-signed only)
  ffi.Pointer<ffi.Pointer<ffi.Char>> get nativeSanList {
    if (_sanList.isEmpty) return ffi.nullptr;
    final ptrs = _arena<ffi.Pointer<ffi.Char>>(_sanList.length);
    for (var i = 0; i < _sanList.length; i++) {
      ptrs[i] = _sanList[i].toNativeUtf8(allocator: _arena).cast<ffi.Char>();
    }
    return ptrs;
  }

  /// Certificate path as native C string (internal use)
  ffi.Pointer<ffi.Char> get nativeCertPath =>
      (_certPath ?? '').toNativeUtf8(allocator: _arena).cast<ffi.Char>();

  /// Key path as native C string (internal use)
  ffi.Pointer<ffi.Char> get nativeKeyPath =>
      (_keyPath ?? '').toNativeUtf8(allocator: _arena).cast<ffi.Char>();

  /// Transport config pointer (internal use, null pointer if not set)
  ffi.Pointer<QuicFfiTransportConfig> get nativeTransportConfig =>
      _config.ref.transport;

  // ========== Cleanup ==========

  /// Free all allocated resources
  void dispose() {
    _arenaFinalizer.detach(_arena);
    _arena.releaseAll();
  }

  @override
  String toString() {
    return 'QuicServerConfig('
        'bindAddr: $_bindAddr, '
        'certMode: $_certMode'
        ')';
  }
}
