import 'dart:async';
import 'dart:ffi';

import 'package:dart_quic/src/bindings/quic_ffi_bindings.dart';
import 'package:dart_quic/src/common/quic_connection.dart';
import 'package:dart_quic/src/common/quic_result.dart';
import 'package:dart_quic/src/server/quic_server_config.dart';
import 'package:dart_quic/src/utils/quic_initializer.dart';
import 'package:ffi/ffi.dart' as ffi;

/// QUIC server for accepting incoming connections.
///
/// Manages the lifecycle of a QUIC server and provides methods for
/// accepting connections and managing the server state.
///
/// Example:
/// ```dart
/// // Self-signed certificate (testing)
/// final config = QuicServerConfig.selfSigned(
///   bindAddr: '0.0.0.0:4433',
///   sanList: ['localhost'],
/// );
/// final server = await QuicServerEndpoint.bind(config);
/// print('Server listening on: ${server.localAddr}');
///
/// try {
///   while (true) {
///     final connection = await server.accept();
///     if (connection == null) break; // server closed
///     handleConnection(connection);
///   }
/// } finally {
///   server.close();
///   server.dispose();
/// }
/// ```
class QuicServerEndpoint {
  static final Finalizer<_QuicServerResources> _finalizer =
      Finalizer<_QuicServerResources>((resources) {
        try {
          resources.cleanup();
        } catch (_) {
          // swallow errors in finalizer
        }
      });

  final QuicFFIBindings _bindings;
  Pointer<QuicServerHandle>? _handlePtr;
  Pointer<QuicServer>? _serverPtr;
  Pointer<QuicExecutor>? _executorPtr;
  final String _localAddr;
  final int _localPort;
  bool _isDisposed = false;
  bool _isClosed = false;

  QuicServerEndpoint._internal(
    this._bindings,
    this._executorPtr,
    this._handlePtr,
    this._serverPtr,
    this._localAddr,
    this._localPort,
  ) {
    final resources = _QuicServerResources(_bindings, _handlePtr, _executorPtr);
    _finalizer.attach(this, resources, detach: this);
  }

  /// Bind and start a QUIC server with the given configuration.
  ///
  /// This initializes the tokio runtime, creates the server asynchronously
  /// inside the runtime context, and starts listening for incoming connections.
  ///
  /// The [config] will be disposed automatically after server creation.
  /// Throws [StateError] if binding fails.
  static Future<QuicServerEndpoint> bind(QuicServerConfig config) async {
    final bindings = QuicInitializer.ffiBindings;
    Pointer<QuicExecutor>? executorPtr;

    try {
      // Step 1: Create and initialize executor
      executorPtr = bindings.dart_quic_executor_new();
      await _initializeRuntime(bindings, executorPtr);

      // Step 2: Create server asynchronously inside the tokio runtime
      final (handlePtr, serverPtr, localAddr, localPort) =
          await _createServerAsync(bindings, executorPtr, config);

      return QuicServerEndpoint._internal(
        bindings,
        executorPtr,
        handlePtr,
        serverPtr,
        localAddr,
        localPort,
      );
    } catch (e) {
      if (executorPtr != null) {
        bindings.dart_quic_executor_free(executorPtr);
      }
      rethrow;
    } finally {
      config.dispose();
    }
  }

  static Future<void> _initializeRuntime(
    QuicFFIBindings bindings,
    Pointer<QuicExecutor> executorPtr,
  ) async {
    final completer = Completer<bool>();
    late final NativeCallable<BoolCallbackFunction> callback;

    void onResult(
      bool success,
      bool value,
      Pointer<Uint8> errorPtr,
      int errorLen,
    ) {
      if (success) {
        completer.complete(value);
      } else {
        final errorMsg = errorLen > 0
            ? errorPtr.cast<ffi.Utf8>().toDartString(length: errorLen)
            : 'Unknown error';
        completer.completeError(StateError('Runtime init failed: $errorMsg'));
      }
      callback.close();
    }

    callback = NativeCallable<BoolCallbackFunction>.listener(onResult);
    bindings.dart_quic_executor_init(
      executorPtr,
      QuicInitializer.numberOfThreads,
      callback.nativeFunction,
    );

    final success = await completer.future;
    if (!success) {
      throw StateError('Failed to initialize runtime');
    }
  }

  /// Creates the server asynchronously via [dart_quic_server_new_async].
  ///
  /// Supports all certificate modes
  /// (self-signed, PEM files, DER memory) uniformly through [QuicFfiServerConfig].
  /// Returns (handlePtr, serverPtr, localAddr, localPort).
  ///
  /// NOTE: The handle is NOT freed here. It is kept alive for the lifetime of
  /// [QuicServerEndpoint] and freed together with the server in [dispose()].
  static Future<(Pointer<QuicServerHandle>, Pointer<QuicServer>, String, int)>
  _createServerAsync(
    QuicFFIBindings bindings,
    Pointer<QuicExecutor> executorPtr,
    QuicServerConfig config,
  ) async {
    final completer = Completer<Pointer<QuicServerHandle>>();
    late final NativeCallable<UsizeCallbackFunction> nativeCallback;

    void onResult(
      bool success,
      int value,
      Pointer<Uint8> errorPtr,
      int errorLen,
    ) {
      if (success && value != 0) {
        completer.complete(Pointer<QuicServerHandle>.fromAddress(value));
      } else {
        final msg = errorLen > 0
            ? errorPtr.cast<ffi.Utf8>().toDartString(length: errorLen)
            : 'Unknown error';
        completer.completeError(StateError('Failed to create server: $msg'));
      }
      nativeCallback.close();
    }

    nativeCallback = NativeCallable<UsizeCallbackFunction>.listener(onResult);

    final resultCode = bindings.dart_quic_server_new_async(
      executorPtr,
      config.nativeBindAddr,
      config.ffiConfig,
      nativeCallback.nativeFunction,
    );

    if (resultCode.isFailure) {
      nativeCallback.close();
      throw StateError(
        'Failed to submit server creation: ${resultCode.errorMessage}',
      );
    }

    final handlePtr = await completer.future;

    // Extract server pointer, local address and port from handle for caching.
    // The handle (and server) remain alive until dispose().
    final serverPtr = handlePtr.ref.server;
    final localPort = handlePtr.ref.local_port;
    final addrLen = handlePtr.ref.local_addr_len;
    final String localAddr;
    if (addrLen > 0 && handlePtr.ref.local_addr_ptr != nullptr) {
      localAddr = handlePtr.ref.local_addr_ptr.cast<ffi.Utf8>().toDartString(
        length: addrLen,
      );
    } else {
      localAddr = config.bindAddr;
    }

    return (handlePtr, serverPtr, localAddr, localPort);
  }

  /// Accept an incoming connection.
  ///
  /// Returns a [Future] that completes with a [QuicConn] when a client connects,
  /// or `null` if the server has been closed.
  ///
  /// Typically called in a loop to continuously accept connections:
  /// ```dart
  /// while (true) {
  ///   final conn = await server.accept();
  ///   if (conn == null) break;
  ///   handleConnection(conn);
  /// }
  /// ```
  ///
  /// Throws [StateError] if the server is disposed.
  Future<QuicConn?> accept() async {
    _checkDisposed();

    final completer = Completer<QuicConn?>();
    late final NativeCallable<UsizeCallbackFunction> nativeCallback;

    void onResult(
      bool success,
      int value,
      Pointer<Uint8> errorPtr,
      int errorLen,
    ) {
      if (success && value != 0) {
        final handlePtr = Pointer<QuicConnectionHandle>.fromAddress(value);
        try {
          final connection = QuicConn.fromHandle(
            _bindings,
            handlePtr,
            _executorPtr!,
          );
          completer.complete(connection);
        } catch (e) {
          completer.completeError(
            StateError('Failed to create connection from handle: $e'),
          );
        }
      } else if (!success) {
        // Server closed or error
        final msg = errorLen > 0
            ? errorPtr.cast<ffi.Utf8>().toDartString(length: errorLen)
            : 'Server closed';
        if (msg == 'Server closed' || _isClosed) {
          completer.complete(null);
        } else {
          completer.completeError(StateError('Accept failed: $msg'));
        }
      } else {
        // value == 0 means server closed
        completer.complete(null);
      }
      nativeCallback.close();
    }

    nativeCallback = NativeCallable<UsizeCallbackFunction>.listener(onResult);

    _bindings.dart_quic_server_accept(
      _executorPtr!,
      _serverPtr!,
      nativeCallback.nativeFunction,
    );

    return completer.future;
  }

  /// Wait for all active connections to close (idle state).
  ///
  /// Typically called after [close] for a graceful shutdown sequence:
  /// ```dart
  /// server.close();
  /// await server.waitIdle();
  /// server.dispose();
  /// ```
  ///
  /// Throws [StateError] if the server is disposed.
  Future<void> waitIdle() async {
    _checkDisposed();

    final completer = Completer<void>();
    late final NativeCallable<VoidCallbackFunction> nativeCallback;

    void onResult(bool success, Pointer<Uint8> errorPtr, int errorLen) {
      if (success) {
        completer.complete();
      } else {
        final msg = errorLen > 0
            ? errorPtr.cast<ffi.Utf8>().toDartString(length: errorLen)
            : 'Unknown error';
        completer.completeError(StateError('waitIdle failed: $msg'));
      }
      nativeCallback.close();
    }

    nativeCallback = NativeCallable<VoidCallbackFunction>.listener(onResult);

    _bindings.dart_quic_server_wait_idle(
      _executorPtr!,
      _serverPtr!,
      nativeCallback.nativeFunction,
    );

    return completer.future;
  }

  /// Close the server gracefully.
  ///
  /// Parameters:
  /// - [errorCode]: Application error code (default: 0)
  /// - [reason]: Close reason string (optional)
  ///
  /// After closing, [accept] will return `null`.
  void close({int errorCode = 0, String? reason}) {
    if (_isDisposed || _serverPtr == null || _isClosed) return;
    _isClosed = true;

    Pointer<Uint8> reasonPtr = nullptr;
    int reasonLen = 0;

    if (reason != null && reason.isNotEmpty) {
      final arena = ffi.Arena();
      try {
        final utf8Ptr = reason.toNativeUtf8(allocator: arena);
        // Copy to FFI-allocated memory since arena will be released
        final len = utf8Ptr.length;
        final ptr = _bindings.dart_allocate_memory(len);
        ptr
            .asTypedList(len)
            .setRange(0, len, utf8Ptr.cast<Uint8>().asTypedList(len));
        reasonPtr = ptr;
        reasonLen = len;
      } finally {
        arena.releaseAll();
      }
    }

    _bindings.dart_quic_server_close(
      _serverPtr!,
      errorCode,
      reasonPtr,
      reasonLen,
    );

    if (reasonLen > 0 && reasonPtr != nullptr) {
      _bindings.dart_free_memory(reasonPtr, reasonLen);
    }
  }

  /// Free all allocated resources.
  ///
  /// IMPORTANT: Must be called when the server is no longer needed.
  /// Should be called after [close()].
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;

    _finalizer.detach(this);

    // Free server + handle together — dart_quic_server_handle_free owns both.
    if (_handlePtr != null) {
      _bindings.dart_quic_server_handle_free(_handlePtr!);
      _handlePtr = null;
      _serverPtr = null;
    }

    if (_executorPtr != null) {
      _bindings.dart_quic_executor_free(_executorPtr!);
      _executorPtr = null;
    }
  }

  void _checkDisposed() {
    if (_isDisposed) {
      throw StateError('QuicServer has been disposed');
    }
  }

  /// The local address the server is bound to (e.g., "0.0.0.0:4433")
  String get localAddr => _localAddr;

  /// The local port the server is bound to
  int get localPort => _localPort;

  /// The number of currently open connections
  int get openConnections {
    if (_isDisposed || _serverPtr == null) return 0;
    return _bindings.dart_quic_server_open_connections(_serverPtr!);
  }

  /// Whether the server has been closed
  bool get isClosed => _isClosed;

  /// Whether the server has been disposed
  bool get isDisposed => _isDisposed;

  @override
  String toString() => 'QuicServerEndpoint(localAddr: $_localAddr)';
}

/// Internal resources holder for finalizer.
class _QuicServerResources {
  final QuicFFIBindings _bindings;
  final Pointer<QuicServerHandle>? _handlePtr;
  final Pointer<QuicExecutor>? _executorPtr;

  _QuicServerResources(this._bindings, this._handlePtr, this._executorPtr);

  void cleanup() {
    if (_handlePtr != null) {
      _bindings.dart_quic_server_handle_free(_handlePtr!);
    }
    if (_executorPtr != null) {
      _bindings.dart_quic_executor_free(_executorPtr!);
    }
  }
}
