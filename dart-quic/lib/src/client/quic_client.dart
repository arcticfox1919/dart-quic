import 'dart:async';
import 'dart:ffi';

import 'package:dart_quic/src/bindings/quic_ffi_bindings.dart';
import 'package:dart_quic/src/client/quic_client_config.dart';
import 'package:dart_quic/src/common/quic_connection.dart';
import 'package:dart_quic/src/common/quic_result.dart';
import 'package:dart_quic/src/common/socket_address.dart';
import 'package:dart_quic/src/utils/quic_initializer.dart';
import 'package:ffi/ffi.dart' as ffi;

/// QUIC client for establishing connections to QUIC servers.
///
/// Manages the lifecycle of QUIC client instances and provides
/// methods for connecting to servers and managing connections.
///
/// Example:
/// ```dart
/// final client = await QuicClientEndpoint.create(QuicClientConfig.withSystemRoots());
/// try {
///   // Using SocketAddress:
///   final conn = await client.connect(serverAddr: SocketAddress.parse('127.0.0.1:4433'), serverName: 'localhost');
///   // Or using a plain string:
///   final conn = await client.connectTo(serverAddr: '127.0.0.1:4433', serverName: 'localhost');
/// } finally {
///   await client.close();
///   client.dispose();
/// }
/// ```
class QuicClientEndpoint {
  static final Finalizer<_QuicClientResources> _finalizer =
      Finalizer<_QuicClientResources>((resources) {
        try {
          resources.cleanup();
        } catch (_) {
          // swallow errors in finalizer
        }
      });

  final QuicFFIBindings _bindings;
  final _arena = ffi.Arena();
  Pointer<Void>? _clientPtr;
  Pointer<QuicExecutor>? _executorPtr;
  bool _isDisposed = false;

  /// Private constructor - use [create] factory method instead.
  QuicClientEndpoint._internal(
    this._bindings,
    this._executorPtr,
    this._clientPtr,
  ) {
    // Attach finalizer as safety net
    final resources = _QuicClientResources(
      _bindings,
      _clientPtr,
      _executorPtr,
      _arena,
    );
    _finalizer.attach(this, resources, detach: this);
  }

  /// Create a new QUIC client endpoint with the given configuration.
  ///
  /// This is an async factory method that initializes the tokio runtime
  /// and creates the QUIC client.
  ///
  /// The [config] will be disposed automatically after client creation.
  /// Throws [StateError] if initialization fails.
  static Future<QuicClientEndpoint> create(QuicClientConfig config) async {
    final bindings = QuicInitializer.ffiBindings;
    Pointer<QuicExecutor>? executorPtr;

    try {
      // Create executor for async operations
      executorPtr = bindings.dart_quic_executor_new();

      // Step 1: Initialize the tokio runtime
      await _initializeRuntime(bindings, executorPtr);

      // Step 2: Create the QUIC client asynchronously
      final clientPtr = await _createClientAsync(bindings, executorPtr, config);

      return QuicClientEndpoint._internal(bindings, executorPtr, clientPtr);
    } catch (e) {
      // Cleanup on failure
      if (executorPtr != null) {
        bindings.dart_quic_executor_free(executorPtr);
      }
      rethrow;
    } finally {
      // Always dispose config after creation attempt
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

  static Future<Pointer<Void>> _createClientAsync(
    QuicFFIBindings bindings,
    Pointer<QuicExecutor> executorPtr,
    QuicClientConfig config,
  ) async {
    final completer = Completer<Pointer<Void>>();
    late final NativeCallable<UsizeCallbackFunction> callback;

    void onResult(
      bool success,
      int value,
      Pointer<Uint8> errorPtr,
      int errorLen,
    ) {
      if (success) {
        completer.complete(Pointer<Void>.fromAddress(value));
      } else {
        final errorMsg = errorLen > 0
            ? errorPtr.cast<ffi.Utf8>().toDartString(length: errorLen)
            : 'Unknown error';
        completer.completeError(
          StateError('Failed to create QUIC client: $errorMsg'),
        );
      }
      callback.close();
    }

    callback = NativeCallable<UsizeCallbackFunction>.listener(onResult);

    final resultCode = bindings.dart_quic_client_new_async(
      executorPtr,
      config.ffiConfig,
      callback.nativeFunction,
    );

    if (resultCode.isFailure) {
      callback.close();
      throw StateError(
        'Failed to submit client creation: ${resultCode.errorMessage}',
      );
    }

    return completer.future;
  }

  /// Connect to a QUIC server.
  ///
  /// Parameters:
  /// - [serverAddr]: Server address as a [SocketAddress].
  /// - [serverName]: Server name for SNI (TLS Server Name Indication).
  ///
  /// Returns a [Future] that completes with a [QuicConn] on success.
  /// Throws [StateError] if the client is disposed or connection fails.
  ///
  /// See also [connectTo] for a convenience overload that accepts a plain string.
  Future<QuicConn> connect({
    required SocketAddress serverAddr,
    required String serverName,
  }) async {
    _checkDisposed();

    final completer = Completer<QuicConn>();
    late final NativeCallable<UsizeCallbackFunction> nativeCallback;

    void onConnectionResult(
      bool success,
      int value,
      Pointer<Uint8> errorPtr,
      int errorLen,
    ) {
      if (success) {
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
            StateError('Failed to create connection: $e'),
          );
        }
      } else {
        completer.completeError(
          StateError(
            'Connection failed: ${errorPtr.cast<ffi.Utf8>().toDartString(length: errorLen)}',
          ),
        );
      }
      nativeCallback.close();
    }

    nativeCallback = NativeCallable<UsizeCallbackFunction>.listener(
      onConnectionResult,
    );

    final serverAddrStr = serverAddr.addr
        .toNativeUtf8(allocator: _arena)
        .cast<Char>();
    final serverNameStr = serverName
        .toNativeUtf8(allocator: _arena)
        .cast<Char>();

    _bindings.dart_quic_client_connect(
      _executorPtr!,
      _clientPtr!.cast(),
      serverAddrStr,
      serverNameStr,
      nativeCallback.nativeFunction,
    );

    return completer.future;
  }

  /// Convenience overload of [connect] that accepts the server address as a
  /// plain [String] (e.g. `'127.0.0.1:4433'`).
  ///
  /// The string is validated and parsed into a [SocketAddress] before
  /// connecting. Throws [ArgumentError] on invalid format.
  Future<QuicConn> connectTo({
    required String serverAddr,
    required String serverName,
  }) => connect(
    serverAddr: SocketAddress.parse(serverAddr),
    serverName: serverName,
  );

  /// Close the client and all its connections.
  ///
  /// Parameters:
  /// - [errorCode]: Application error code (default: 0)
  /// - [reason]: Close reason string (optional)
  ///
  /// Returns a [Future] that completes when the client is closed.
  Future<void> close({int errorCode = 0, String? reason}) async {
    if (_isDisposed || _clientPtr == null) return;

    final completer = Completer<void>();
    late final NativeCallable<VoidCallbackFunction> nativeCallback;

    void onIdleComplete(bool success, Pointer<Uint8> errorPtr, int errorLen) {
      completer.complete();
      nativeCallback.close();
    }

    nativeCallback = NativeCallable<VoidCallbackFunction>.listener(
      onIdleComplete,
    );

    final Pointer<Uint8> reasonPtr;
    final int reasonLen;
    if (reason != null && reason.isNotEmpty) {
      final utf8Ptr = reason.toNativeUtf8(allocator: _arena);
      reasonPtr = utf8Ptr.cast<Uint8>();
      reasonLen = utf8Ptr.length;
    } else {
      reasonPtr = nullptr;
      reasonLen = 0;
    }

    final resultCode = _bindings.dart_quic_client_close(
      _clientPtr!.cast(),
      errorCode,
      reasonPtr,
      reasonLen,
    );
    if (resultCode.isFailure) {
      throw StateError('Failed to close client: ${resultCode.errorMessage}');
    }

    // Wait for client to become idle
    _bindings.dart_quic_client_wait_idle(
      _executorPtr!,
      _clientPtr!.cast(),
      nativeCallback.nativeFunction,
    );

    return completer.future;
  }

  /// Free all allocated resources.
  ///
  /// IMPORTANT: Must be called when the client is no longer needed.
  /// Should be called after [close()].
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;

    // Prevent finalizer from running after explicit dispose
    _finalizer.detach(this);

    // Free client pointer
    if (_clientPtr != null) {
      _bindings.dart_quic_client_free(_clientPtr!.cast());
      _clientPtr = null;
    }

    // Free executor
    if (_executorPtr != null) {
      _bindings.dart_quic_executor_free(_executorPtr!);
      _executorPtr = null;
    }

    // Release arena
    _arena.releaseAll();
  }

  void _checkDisposed() {
    if (_isDisposed) {
      throw StateError('QuicClientEndpoint has been disposed');
    }
  }

  /// Check if the client is disposed.
  bool get isDisposed => _isDisposed;
}

/// Internal class to hold resources for finalizer.
class _QuicClientResources {
  final QuicFFIBindings _bindings;
  final Pointer<Void>? _clientPtr;
  final Pointer<QuicExecutor>? _executorPtr;
  final ffi.Arena _arena;

  _QuicClientResources(
    this._bindings,
    this._clientPtr,
    this._executorPtr,
    this._arena,
  );

  void cleanup() {
    if (_clientPtr != null) {
      _bindings.dart_quic_client_free(_clientPtr!.cast());
    }
    if (_executorPtr != null) {
      _bindings.dart_quic_executor_free(_executorPtr!);
    }
    _arena.releaseAll();
  }
}
