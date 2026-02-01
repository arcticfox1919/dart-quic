/// Simplified callback-based QUIC processor using NativeCallable.listener
///
/// This implementation leverages Dart's NativeCallable.listener for direct
/// callback invocation from native code, eliminating the need for:
/// 1. Task IDs for message matching
/// 2. Complex binary protocol serialization
/// 3. Single message dispatcher pattern
library;

import 'dart:async';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/quic_ffi_bindings.dart';
import '../core/quic_buffer.dart';
import '../core/quic_initializer.dart';

/// QUIC command types
enum QuicCommand {
  ping(0x01),
  echo(0x02),
  sendData(0x10);

  const QuicCommand(this.value);
  final int value;
}

/// Native callback function types
typedef NativeVoidCallback = Void Function();
typedef NativeBoolCallback = Void Function(Bool success, Bool value);
typedef NativeI64Callback = Void Function(Bool success, Int64 value);
typedef NativeF64Callback = Void Function(Bool success, Double value);
typedef NativeBytesCallback =
    Void Function(Bool success, Pointer<Uint8> ptr, IntPtr len);

/// Callback-based QUIC processor
///
/// Each method call creates its own NativeCallable.listener and returns a Future.
/// The callback is automatically closed after receiving the response.
class QuicCallbackProcessor {
  late final QuicFFIBindings _bindings;
  late final Pointer<QuicCallbackExecutor> _executor;
  final _initialized = Completer<bool>();

  QuicCallbackProcessor() {
    _bindings = QuicInitializer.ffiBindings;
    final executor = _bindings.quic_callback_executor_new();
    if (executor == nullptr) {
      throw Exception('Failed to create QUIC callback executor');
    }
    _executor = executor;
  }

  /// Initialize the runtime
  Future<bool> initialize() {
    late final NativeCallable<NativeBoolCallback> callback;

    void onInit(bool success, bool value) {
      _initialized.complete(success && value);
      callback.close();
    }

    callback = NativeCallable<NativeBoolCallback>.listener(onInit);
    _bindings.quic_callback_executor_init(
      _executor,
      QuicInitializer.numberOfThreads,
      callback.nativeFunction,
    );

    return _initialized.future;
  }

  /// Check if runtime is running
  bool get isRunning => _bindings.quic_callback_executor_is_running(_executor);

  /// Send a void command (fire and forget with completion notification)
  Future<void> sendVoid(
    QuicCommand command, {
    Pointer<Uint8>? data,
    int dataLen = 0,
  }) {
    final completer = Completer<void>();
    late final NativeCallable<NativeVoidCallback> callback;

    void onComplete() {
      completer.complete();
      callback.close();
    }

    callback = NativeCallable<NativeVoidCallback>.listener(onComplete);
    _bindings.quic_callback_submit_void(
      _executor,
      command.value,
      data ?? nullptr,
      dataLen,
      nullptr,
      0,
      callback.nativeFunction,
    );

    return completer.future;
  }

  /// Send a command expecting bool result
  Future<bool> sendBool(
    QuicCommand command, {
    Pointer<Uint8>? data,
    int dataLen = 0,
  }) {
    final completer = Completer<bool>();
    late final NativeCallable<NativeBoolCallback> callback;

    void onResult(bool success, bool value) {
      if (success) {
        completer.complete(value);
      } else {
        completer.completeError(Exception('Command failed'));
      }
      callback.close();
    }

    callback = NativeCallable<NativeBoolCallback>.listener(onResult);
    _bindings.quic_callback_submit_bool(
      _executor,
      command.value,
      data ?? nullptr,
      dataLen,
      nullptr,
      0,
      callback.nativeFunction,
    );

    return completer.future;
  }

  /// Send a command expecting int result
  Future<int> sendInt(
    QuicCommand command, {
    Pointer<Uint8>? data,
    int dataLen = 0,
  }) {
    final completer = Completer<int>();
    late final NativeCallable<NativeI64Callback> callback;

    void onResult(bool success, int value) {
      if (success) {
        completer.complete(value);
      } else {
        completer.completeError(Exception('Command failed'));
      }
      callback.close();
    }

    callback = NativeCallable<NativeI64Callback>.listener(onResult);
    _bindings.quic_callback_submit_i64(
      _executor,
      command.value,
      data ?? nullptr,
      dataLen,
      nullptr,
      0,
      callback.nativeFunction,
    );

    return completer.future;
  }

  /// Send a command expecting double result
  Future<double> sendDouble(
    QuicCommand command, {
    Pointer<Uint8>? data,
    int dataLen = 0,
  }) {
    final completer = Completer<double>();
    late final NativeCallable<NativeF64Callback> callback;

    void onResult(bool success, double value) {
      if (success) {
        completer.complete(value);
      } else {
        completer.completeError(Exception('Command failed'));
      }
      callback.close();
    }

    callback = NativeCallable<NativeF64Callback>.listener(onResult);
    _bindings.quic_callback_submit_f64(
      _executor,
      command.value,
      data ?? nullptr,
      dataLen,
      nullptr,
      0,
      callback.nativeFunction,
    );

    return completer.future;
  }

  /// Send a command expecting bytes result
  Future<QuicBuffer> sendBytes(
    QuicCommand command, {
    Pointer<Uint8>? data,
    int dataLen = 0,
  }) {
    final completer = Completer<QuicBuffer>();
    late final NativeCallable<NativeBytesCallback> callback;

    void onResult(bool success, Pointer<Uint8> ptr, int len) {
      if (success) {
        completer.complete(_CallbackQuicBuffer(_bindings, ptr, len));
      } else {
        completer.completeError(Exception('Command failed'));
      }
      callback.close();
    }

    callback = NativeCallable<NativeBytesCallback>.listener(onResult);
    _bindings.quic_callback_submit_bytes(
      _executor,
      command.value,
      data ?? nullptr,
      dataLen,
      nullptr,
      0,
      callback.nativeFunction,
    );

    return completer.future;
  }

  // === Convenience methods ===

  /// Ping test
  Future<bool> ping() => sendBool(QuicCommand.ping);

  /// Echo test
  Future<QuicBuffer> echo(Uint8List data) async {
    final ptr = calloc<Uint8>(data.length);
    ptr.asTypedList(data.length).setAll(0, data);
    try {
      return await sendBytes(QuicCommand.echo, data: ptr, dataLen: data.length);
    } finally {
      calloc.free(ptr);
    }
  }

  /// Send data test
  Future<int> sendData(Uint8List data) async {
    final ptr = calloc<Uint8>(data.length);
    ptr.asTypedList(data.length).setAll(0, data);
    try {
      return await sendInt(
        QuicCommand.sendData,
        data: ptr,
        dataLen: data.length,
      );
    } finally {
      calloc.free(ptr);
    }
  }

  /// Dispose resources
  void dispose() {
    _bindings.quic_callback_executor_free(_executor);
  }

  /// Dispose resources synchronously
  void disposeSync() {
    _bindings.quic_callback_executor_free_sync(_executor);
  }
}

/// QuicBuffer implementation for callback results
class _CallbackQuicBuffer implements QuicBuffer {
  final QuicFFIBindings _bindings;
  final Pointer<Uint8> _ptr;
  final int _size;

  _CallbackQuicBuffer(this._bindings, this._ptr, this._size);

  @override
  Uint8List get data => _ptr.asTypedList(_size);

  @override
  int get size => _size;

  @override
  void destroy() {
    if (_ptr != nullptr) {
      _bindings.dart_free_memory(_ptr.cast(), _size);
    }
  }
}
