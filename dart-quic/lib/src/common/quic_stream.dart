import 'dart:async';
import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:dart_quic/src/bindings/quic_ffi_bindings.dart';
import 'package:dart_quic/src/utils/quic_allocator.dart';
import 'package:dart_quic/src/utils/str_utf8_ptr.dart';
import 'package:ffi/ffi.dart';

/// QUIC stream for reading and writing data.
///
/// A unified stream class that supports both bidirectional and unidirectional streams.
/// Use [canRead] and [canWrite] to check stream capabilities.
///
/// Example:
/// ```dart
/// final stream = await connection.openBidirectionalStream();
/// try {
///   await stream.writeAll(Uint8List.fromList([1, 2, 3]));
///   final response = await stream.read(1024);
///   stream.finish();
/// } finally {
///   stream.dispose();
/// }
/// ```
class QuicStream {
  final QuicFFIBindings _bindings;
  final ffi.Pointer<QuicExecutor> _executorPtr;
  final ffi.Pointer<QuicFfiStreamPair> _pairPtr;
  final ffi.Pointer<QuicFfiStreamHandle>? _sendHandle;
  final ffi.Pointer<QuicFfiStreamHandle>? _recvHandle;
  final QuicAllocator _allocator;

  bool _isDisposed = false;
  bool _isFinished = false;

  /// Stream ID.
  final int streamId;

  QuicStream._({
    required QuicFFIBindings bindings,
    required ffi.Pointer<QuicExecutor> executor,
    required ffi.Pointer<QuicFfiStreamPair> pairPtr,
    required ffi.Pointer<QuicFfiStreamHandle>? sendHandle,
    required ffi.Pointer<QuicFfiStreamHandle>? recvHandle,
    required this.streamId,
    required QuicAllocator allocator,
  }) : _bindings = bindings,
       _executorPtr = executor,
       _pairPtr = pairPtr,
       _sendHandle = sendHandle,
       _recvHandle = recvHandle,
       _allocator = allocator;

  /// Create a stream from a stream pair pointer.
  ///
  /// The [executor] is shared from the parent connection.
  factory QuicStream.fromPair(
    QuicFFIBindings bindings,
    ffi.Pointer<QuicExecutor> executor,
    ffi.Pointer<QuicFfiStreamPair> pairPtr,
  ) {
    final sendHandle = pairPtr.ref.send_handle;
    final recvHandle = pairPtr.ref.recv_handle;

    final hasSend = sendHandle != ffi.nullptr;
    final hasRecv = recvHandle != ffi.nullptr;

    if (!hasSend && !hasRecv) {
      throw StateError('Invalid stream pair: no handles');
    }

    // Get stream ID from whichever handle is available
    final streamId = hasSend
        ? sendHandle.ref.stream_id
        : recvHandle.ref.stream_id;

    return QuicStream._(
      bindings: bindings,
      executor: executor,
      pairPtr: pairPtr,
      sendHandle: hasSend ? sendHandle : null,
      recvHandle: hasRecv ? recvHandle : null,
      streamId: streamId,
      allocator: QuicAllocator(bindings),
    );
  }

  /// Whether this stream supports writing.
  bool get canWrite => _sendHandle != null;

  /// Whether this stream supports reading.
  bool get canRead => _recvHandle != null;

  /// Whether this is a bidirectional stream.
  bool get isBidirectional => canRead && canWrite;

  /// Whether this stream has been disposed.
  bool get isDisposed => _isDisposed;

  /// Whether the send side has been finished.
  bool get isFinished => _isFinished;

  // ============================================
  // Write Operations
  // ============================================

  /// Write data to the stream.
  ///
  /// Returns the number of bytes written.
  /// May write fewer bytes than requested due to flow control.
  ///
  /// Throws [StateError] if stream does not support writing.
  Future<int> write(Uint8List data) async {
    _checkWritable();

    final completer = Completer<int>();
    late final ffi.NativeCallable<UsizeCallbackFunction> nativeCallback;

    void onResult(
      bool success,
      int value,
      ffi.Pointer<ffi.Uint8> errorPtr,
      int errorLen,
    ) {
      if (success) {
        completer.complete(value);
      } else {
        completer.completeError(
          StateError(
            'Write failed: ${errorPtr.cast<Utf8>().toDartString(length: errorLen)}',
          ),
        );
      }
      nativeCallback.close();
    }

    nativeCallback = ffi.NativeCallable<UsizeCallbackFunction>.listener(
      onResult,
    );

    return _allocator.using<ffi.Uint8, Future<int>>(data.length, (dataPtr) {
      dataPtr.asTypedList(data.length).setAll(0, data);

      _bindings.dart_quic_send_stream_write(
        _executorPtr,
        _sendHandle!,
        dataPtr,
        data.length,
        nativeCallback.nativeFunction,
      );

      return completer.future;
    });
  }

  /// Write all data to the stream.
  ///
  /// Loops internally until all data is written.
  ///
  /// Throws [StateError] if stream does not support writing.
  Future<void> writeAll(Uint8List data) async {
    _checkWritable();

    final completer = Completer<void>();
    late final ffi.NativeCallable<VoidCallbackFunction> nativeCallback;

    void onResult(bool success, ffi.Pointer<ffi.Uint8> errorPtr, int errorLen) {
      if (success) {
        completer.complete();
      } else {
        completer.completeError(
          StateError(
            'Write all failed: ${errorPtr.cast<Utf8>().toDartString(length: errorLen)}',
          ),
        );
      }
      nativeCallback.close();
    }

    nativeCallback = ffi.NativeCallable<VoidCallbackFunction>.listener(
      onResult,
    );

    return _allocator.using<ffi.Uint8, Future<void>>(data.length, (dataPtr) {
      dataPtr.asTypedList(data.length).setAll(0, data);

      _bindings.dart_quic_send_stream_write_all(
        _executorPtr,
        _sendHandle!,
        dataPtr,
        data.length,
        nativeCallback.nativeFunction,
      );

      return completer.future;
    });
  }

  /// Write a string to the stream.
  ///
  /// The string is encoded as UTF-8 bytes.
  /// Loops internally until all data is written.
  ///
  /// Throws [StateError] if stream does not support writing.
  Future<void> writeString(String str) async {
    _checkWritable();

    final completer = Completer<void>();
    late final ffi.NativeCallable<VoidCallbackFunction> nativeCallback;

    void onResult(bool success, ffi.Pointer<ffi.Uint8> errorPtr, int errorLen) {
      if (success) {
        completer.complete();
      } else {
        completer.completeError(
          StateError(
            'Write string failed: ${errorPtr.cast<Utf8>().toDartString(length: errorLen)}',
          ),
        );
      }
      nativeCallback.close();
    }

    nativeCallback = ffi.NativeCallable<VoidCallbackFunction>.listener(
      onResult,
    );

    final byteLen = str.bytesSize;
    final dataPtr = str.toBytes(allocator: _allocator);

    _bindings.dart_quic_send_stream_write_all(
      _executorPtr,
      _sendHandle!,
      dataPtr.cast<ffi.Uint8>(),
      byteLen,
      nativeCallback.nativeFunction,
    );

    return completer.future.whenComplete(() => _allocator.free(dataPtr));
  }

  /// Finish the stream (no more data will be written).
  ///
  /// After calling this, no more writes are allowed.
  ///
  /// Throws [StateError] if stream does not support writing.
  void finish() {
    if (_isDisposed || _isFinished) return;
    if (!canWrite) {
      throw StateError('Stream does not support writing');
    }

    _isFinished = true;
    final result = _bindings.dart_quic_send_stream_finish(_sendHandle!);
    if (result != 0) {
      throw StateError('Failed to finish stream: error code $result');
    }
  }

  // ============================================
  // Read Operations
  // ============================================

  /// Read up to [maxLen] bytes from the stream.
  ///
  /// Returns the data read. May return fewer bytes than requested.
  /// Returns empty Uint8List if stream is finished.
  ///
  /// Throws [StateError] if stream does not support reading.
  Future<Uint8List> read(int maxLen) async {
    _checkReadable();

    final completer = Completer<Uint8List>();
    late final ffi.NativeCallable<BytesCallbackFunction> nativeCallback;

    void onResult(
      bool success,
      ffi.Pointer<ffi.Uint8> ptr,
      int len,
      ffi.Pointer<ffi.Uint8> errorPtr,
      int errorLen,
    ) {
      if (success) {
        if (len > 0 && ptr != ffi.nullptr) {
          final data = Uint8List.fromList(ptr.asTypedList(len));
          _bindings.dart_free_memory(ptr, maxLen);
          completer.complete(data);
        } else {
          completer.complete(Uint8List(0));
        }
      } else {
        completer.completeError(
          StateError(
            'Read failed: ${errorPtr.cast<Utf8>().toDartString(length: errorLen)}',
          ),
        );
      }
      nativeCallback.close();
    }

    nativeCallback = ffi.NativeCallable<BytesCallbackFunction>.listener(
      onResult,
    );

    _bindings.dart_quic_recv_stream_read(
      _executorPtr,
      _recvHandle!,
      maxLen,
      nativeCallback.nativeFunction,
    );

    return completer.future;
  }

  /// Read exactly [len] bytes from the stream.
  ///
  /// Throws if the stream ends before [len] bytes are read.
  ///
  /// Throws [StateError] if stream does not support reading.
  Future<Uint8List> readExact(int len) async {
    _checkReadable();

    final completer = Completer<Uint8List>();
    late final ffi.NativeCallable<BytesCallbackFunction> nativeCallback;

    void onResult(
      bool success,
      ffi.Pointer<ffi.Uint8> ptr,
      int dataLen,
      ffi.Pointer<ffi.Uint8> errorPtr,
      int errorLen,
    ) {
      if (success) {
        if (dataLen > 0 && ptr != ffi.nullptr) {
          final data = Uint8List.fromList(ptr.asTypedList(dataLen));
          _bindings.dart_free_memory(ptr, len);
          completer.complete(data);
        } else {
          completer.complete(Uint8List(0));
        }
      } else {
        completer.completeError(
          StateError(
            'Read exact failed: ${errorPtr.cast<Utf8>().toDartString(length: errorLen)}',
          ),
        );
      }
      nativeCallback.close();
    }

    nativeCallback = ffi.NativeCallable<BytesCallbackFunction>.listener(
      onResult,
    );

    _bindings.dart_quic_recv_stream_read_exact(
      _executorPtr,
      _recvHandle!,
      len,
      nativeCallback.nativeFunction,
    );

    return completer.future;
  }

  /// Read all remaining data from the stream until it ends.
  ///
  /// Use [maxSize] to limit the maximum amount of data read.
  ///
  /// Throws [StateError] if stream does not support reading.
  Future<Uint8List> readToEnd({int maxSize = 10 * 1024 * 1024}) async {
    _checkReadable();

    final completer = Completer<Uint8List>();
    late final ffi.NativeCallable<BytesCallbackFunction> nativeCallback;

    void onResult(
      bool success,
      ffi.Pointer<ffi.Uint8> ptr,
      int len,
      ffi.Pointer<ffi.Uint8> errorPtr,
      int errorLen,
    ) {
      if (success) {
        if (len > 0 && ptr != ffi.nullptr) {
          final data = Uint8List.fromList(ptr.asTypedList(len));
          _bindings.dart_free_memory(ptr, len);
          completer.complete(data);
        } else {
          completer.complete(Uint8List(0));
        }
      } else {
        completer.completeError(
          StateError(
            'Read to end failed: ${errorPtr.cast<Utf8>().toDartString(length: errorLen)}',
          ),
        );
      }
      nativeCallback.close();
    }

    nativeCallback = ffi.NativeCallable<BytesCallbackFunction>.listener(
      onResult,
    );

    _bindings.dart_quic_recv_stream_read_to_end(
      _executorPtr,
      _recvHandle!,
      maxSize,
      nativeCallback.nativeFunction,
    );

    return completer.future;
  }

  // ============================================
  // Lifecycle
  // ============================================

  /// Free all resources.
  ///
  /// Should be called when the stream is no longer needed.
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;

    // Free the stream pair (this also frees the handles)
    _bindings.dart_quic_stream_pair_free(_pairPtr);
    // Free any remaining allocations (shouldn't have any in normal usage)
    _allocator.freeAll();
  }

  void _checkWritable() {
    if (_isDisposed) {
      throw StateError('QuicStream has been disposed');
    }
    if (!canWrite) {
      throw StateError('Stream does not support writing');
    }
    if (_isFinished) {
      throw StateError('Stream has been finished');
    }
  }

  void _checkReadable() {
    if (_isDisposed) {
      throw StateError('QuicStream has been disposed');
    }
    if (!canRead) {
      throw StateError('Stream does not support reading');
    }
  }

  @override
  String toString() {
    final type = isBidirectional
        ? 'bidirectional'
        : (canWrite ? 'send-only' : 'recv-only');
    return 'QuicStream(id: $streamId, type: $type)';
  }
}
