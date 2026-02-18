import 'dart:async';
import 'dart:ffi' as ffi;

import 'package:dart_quic/src/bindings/quic_ffi_bindings.dart';
import 'package:dart_quic/src/common/quic_stream.dart';
import 'package:ffi/ffi.dart';

/// QUIC connection for bidirectional and unidirectional streams.
///
/// Represents an established QUIC connection and provides methods
/// for opening streams and managing the connection lifecycle.
///
/// IMPORTANT: Connections are created by [QuicClientEndpoint.connect] or server accept.
/// Do not construct directly.
///
///
/// Example:
/// ```dart
/// final connection = await client.connect(
///   SocketAddress.parse('127.0.0.1:4433'),
///   serverName: 'localhost',
/// );
/// try {
///   // Open bidirectional stream
///   final stream = await connection.openBiStream();
///   // Use stream...
/// } finally {
///   await connection.close();
///   connection.dispose();
/// }
/// ```
class QuicConn {
  static final Finalizer<_QuicConnectionResources> _finalizer =
      Finalizer<_QuicConnectionResources>((resources) {
        try {
          resources.cleanup();
        } catch (_) {
          // swallow errors in finalizer
        }
      });

  final QuicFFIBindings _bindings;
  final Arena _arena = Arena();
  ffi.Pointer<QuicConnectionHandle>? _handlePtr;
  ffi.Pointer<QuicExecutor>? _executorPtr;
  late final int _stableId;
  late final String _remoteAddr;
  bool _isDisposed = false;

  /// Internal constructor. Use [QuicClientEndpoint.connect] to create connections.
  ///
  /// The [executor] is shared from the parent endpoint and should not be freed by this class.
  QuicConn.fromHandle(
    this._bindings,
    ffi.Pointer<QuicConnectionHandle> handle,
    ffi.Pointer<QuicExecutor> executor,
  ) {
    _handlePtr = handle;
    _executorPtr = executor;
    _stableId = handle.ref.stable_id;

    // Copy remote address string
    final remoteAddrPtr = handle.ref.remote_addr;
    final remoteAddrLen = handle.ref.remote_addr_len;
    _remoteAddr = remoteAddrPtr.cast<Utf8>().toDartString(
      length: remoteAddrLen,
    );

    // Attach finalizer as safety net (only for connection handle, not executor)
    final resources = _QuicConnectionResources(_bindings, _handlePtr, _arena);
    _finalizer.attach(this, resources, detach: this);
  }

  /// Get the stable connection ID.
  int get stableId => _stableId;

  /// Get the remote address.
  String get remoteAddr => _remoteAddr;

  /// Open a bidirectional stream.
  ///
  /// Returns a [Future] that completes with a [QuicStream] on success.
  /// The stream supports both reading and writing ([canRead] and [canWrite] are true).
  ///
  /// Throws [StateError] if the connection is disposed or opening fails.
  Future<QuicStream> openBiStream() async {
    _checkDisposed();

    final completer = Completer<QuicStream>();
    late final ffi.NativeCallable<UsizeCallbackFunction> nativeCallback;

    void onResult(
      bool success,
      int value,
      ffi.Pointer<ffi.Uint8> errorPtr,
      int errorLen,
    ) {
      if (success) {
        final pairPtr = ffi.Pointer<QuicFfiStreamPair>.fromAddress(value);
        try {
          final stream = QuicStream.fromPair(_bindings, _executorPtr!, pairPtr);
          completer.complete(stream);
        } catch (e) {
          completer.completeError(
            StateError('Failed to create bidirectional stream: $e'),
          );
        }
      } else {
        completer.completeError(
          StateError(
            'Failed to open bidirectional stream: ${errorPtr.cast<Utf8>().toDartString(length: errorLen)}',
          ),
        );
      }
      nativeCallback.close();
    }

    nativeCallback = ffi.NativeCallable<UsizeCallbackFunction>.listener(
      onResult,
    );

    _bindings.dart_quic_connection_open_bi(
      _executorPtr!,
      _handlePtr!,
      nativeCallback.nativeFunction,
    );

    return completer.future;
  }

  /// Open a unidirectional stream (send only).
  ///
  /// Returns a [Future] that completes with a [QuicStream] on success.
  /// The stream only supports writing ([canWrite] is true, [canRead] is false).
  ///
  /// Throws [StateError] if the connection is disposed or opening fails.
  Future<QuicStream> openUniStream() async {
    _checkDisposed();

    final completer = Completer<QuicStream>();
    late final ffi.NativeCallable<UsizeCallbackFunction> nativeCallback;

    void onResult(
      bool success,
      int value,
      ffi.Pointer<ffi.Uint8> errorPtr,
      int errorLen,
    ) {
      if (success) {
        final pairPtr = ffi.Pointer<QuicFfiStreamPair>.fromAddress(value);
        try {
          final stream = QuicStream.fromPair(_bindings, _executorPtr!, pairPtr);
          completer.complete(stream);
        } catch (e) {
          completer.completeError(
            StateError('Failed to create unidirectional stream: $e'),
          );
        }
      } else {
        completer.completeError(
          StateError(
            'Failed to open unidirectional stream: ${errorPtr.cast<Utf8>().toDartString(length: errorLen)}',
          ),
        );
      }
      nativeCallback.close();
    }

    nativeCallback = ffi.NativeCallable<UsizeCallbackFunction>.listener(
      onResult,
    );

    _bindings.dart_quic_connection_open_uni(
      _executorPtr!,
      _handlePtr!,
      nativeCallback.nativeFunction,
    );

    return completer.future;
  }

  /// Close the connection.
  ///
  /// Parameters:
  /// - [errorCode]: Application error code (default: 0)
  /// - [reason]: Close reason string (optional)
  void close({int errorCode = 0, String? reason}) {
    if (_isDisposed || _handlePtr == null) return;

    final ffi.Pointer<ffi.Uint8> reasonPtr;
    final int reasonLen;
    if (reason != null && reason.isNotEmpty) {
      final utf8Ptr = reason.toNativeUtf8(allocator: _arena);
      reasonPtr = utf8Ptr.cast<ffi.Uint8>();
      reasonLen = utf8Ptr.length;
    } else {
      reasonPtr = ffi.nullptr;
      reasonLen = 0;
    }

    _bindings.dart_quic_connection_close(
      _handlePtr!,
      errorCode,
      reasonPtr,
      reasonLen,
    );
  }

  /// Free all allocated resources.
  ///
  /// IMPORTANT: Must be called when the connection is no longer needed.
  /// Should be called after [close()].
  ///
  /// Note: The executor is shared and will not be freed here.
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;

    // Prevent finalizer from running after explicit dispose
    _finalizer.detach(this);

    // Free connection handle
    if (_handlePtr != null) {
      _bindings.dart_quic_connection_handle_free(_handlePtr!);
      _handlePtr = null;
    }

    // Note: _executorPtr is shared from parent endpoint, do not free it here
    _executorPtr = null;

    // Release arena
    _arena.releaseAll();
  }

  void _checkDisposed() {
    if (_isDisposed) {
      throw StateError('QuicConn has been disposed');
    }
  }

  /// Check if the connection is disposed.
  bool get isDisposed => _isDisposed;

  @override
  String toString() {
    return 'QuicConn(stableId: $_stableId, remoteAddr: $_remoteAddr)';
  }
}

/// Internal class to hold resources for finalizer.
///
/// Note: The executor is shared from parent endpoint and is not managed here.
class _QuicConnectionResources {
  final QuicFFIBindings _bindings;
  final ffi.Pointer<QuicConnectionHandle>? _handlePtr;
  final Arena _arena;

  _QuicConnectionResources(this._bindings, this._handlePtr, this._arena);

  void cleanup() {
    if (_handlePtr != null) {
      _bindings.dart_quic_connection_handle_free(_handlePtr!);
    }
    // Note: executor is shared from parent, do not free it here
    _arena.releaseAll();
  }
}
