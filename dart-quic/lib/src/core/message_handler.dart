/// Simplified message handler for QUIC FFI validation testing
///
/// This provides basic command submission and response handling
/// matching the simplified Rust QuicCommandHandler
library;

import 'dart:async';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:dart_quic/src/core/quic_buffer.dart';
import 'package:dart_quic/src/core/quic_initializer.dart';

import '../bindings/quic_ffi_bindings.dart';
import '../protocol/binary_protocol.dart';

/// Simple QUIC command types for validation testing
enum QuicCommandType {
  ping(0x01), // Connection test
  echo(0x02), // Echo test
  sendData(0x10); // Send data test

  const QuicCommandType(this.value);

  final int value;
}

class QuicTaskResponse {
  final DataType dataType;
  final TaskStatus status;
  final int taskId;
  dynamic value;
  QuicBuffer? buffer;

  QuicTaskResponse._({
    required this.dataType,
    required this.status,
    required this.taskId,
    this.value,
    this.buffer,
  });
}

typedef QuicTaskHandler = void Function(QuicTaskResponse);

class QuicMessageHandler {
  late final QuicFFIBindings _bindings;
  late final Pointer<QuicTaskExecutor> _executor;
  late final ReceivePort _receivePort;
  StreamSubscription? subscription;
  final _initialized = Completer<bool>();
  var _initId = 0;

  QuicMessageHandler() {
    _bindings = QuicInitializer.ffiBindings;

    _receivePort = ReceivePort();
    final executor = _bindings.dart_quic_executor_new(
      _receivePort.sendPort.nativePort,
    );

    if (executor == nullptr) {
      _receivePort.close();
      throw Exception('Failed to create QUIC executor');
    }
    _executor = executor;
  }

  Future<bool> initialize() {
    _initId = _bindings.dart_quic_executor_init_runtime(
      _executor,
      QuicInitializer.numberOfThreads,
    );
    return _initialized.future;
  }

  /// Setup Event Handler
  void setTaskHandler(QuicTaskHandler handler) {
    subscription = _receivePort.listen((data) {
      if (data is Uint8List) {
        final message = MessageSerializer.deserialize(data);
        if (message != null && message.isValid) {
          if (message.header.taskId == _initId) {
            _initialized.complete((message.payload as BoolDataPayload).value);
          } else {
            handler.call(_buildResponse(message));
          }
        }
      }
    });
  }

  QuicTaskResponse _buildResponse(QuicTaskMessage msg) =>
      switch (msg.header.dataType) {
        DataType.none => QuicTaskResponse._(
          dataType: msg.header.dataType,
          status: msg.header.status,
          taskId: msg.header.taskId,
        ),
        DataType.bool => QuicTaskResponse._(
          dataType: msg.header.dataType,
          status: msg.header.status,
          taskId: msg.header.taskId,
          value: (msg.payload as BoolDataPayload).value,
        ),
        DataType.u64 => QuicTaskResponse._(
          dataType: msg.header.dataType,
          status: msg.header.status,
          taskId: msg.header.taskId,
          value: (msg.payload as U64DataPayload).value,
        ),
        DataType.bytes => QuicTaskResponse._(
          dataType: msg.header.dataType,
          status: msg.header.status,
          taskId: msg.header.taskId,
          buffer: _QuicBuffer(
            _bindings,
            (msg.payload as BytesDataPayload).ptr,
            (msg.payload as BytesDataPayload).length,
          ),
        ),
        DataType.string => QuicTaskResponse._(
          dataType: msg.header.dataType,
          status: msg.header.status,
          taskId: msg.header.taskId,
          value: (msg.payload as StringDataPayload).getString(),
        ),
      };

  /// Internal helper to submit command with data
  int sendCommand(
    QuicCommandType command, {
    Pointer<Uint8>? dataPtr,
    int dataLen = 0,
    Pointer<Uint64>? paramsPtr,
    int paramsCount = 0,
  }) {
    return _bindings.dart_quic_executor_submit_params(
      _executor,
      command.value,
      dataPtr ?? nullptr,
      dataLen,
      paramsPtr ?? nullptr,
      paramsCount,
    );
  }

  /// Check if runtime is running
  bool get isRunning => _bindings.dart_quic_executor_is_running(_executor);

  /// Dispose resources
  Future<void> dispose() async{
    await subscription?.cancel();
    _receivePort.close();
    _bindings.dart_quic_executor_free(_executor);
  }
}

class _QuicBuffer implements QuicBuffer {
  final QuicFFIBindings _bindings;
  final Pointer<Uint8> _ptr;
  final int _size;

  _QuicBuffer(this._bindings, this._ptr, this._size);

  @override
  Uint8List get data => _ptr.asTypedList(size);

  @override
  void destroy() {
    _bindings.dart_free_memory(_ptr.cast(), size);
  }

  @override
  int get size => _size;
}
