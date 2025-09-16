/// Simplified message handler for QUIC FFI validation testing
///
/// This provides basic command submission and response handling
/// matching the simplified Rust QuicCommandHandler
library;

import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import '../quic_ffi_bindings.dart';
import 'binary_protocol.dart';

/// Simple QUIC command types for validation testing
enum QuicCommandType {
  ping(0x01), // Connection test
  echo(0x02), // Echo test
  sendData(0x10); // Send data test

  const QuicCommandType(this.value);
  final int value;
}

/// Simplified QUIC message handler for validation testing
class QuicMessageHandler {
  final QuicFFIBindings _bindings;
  final Pointer<QuicTaskExecutor> _executor;
  final ReceivePort _receivePort;

  QuicMessageHandler._(this._bindings, this._executor, this._receivePort);

  /// Create a new message handler
  static Future<QuicMessageHandler> create(QuicFFIBindings bindings) async {
    final receivePort = ReceivePort();
    final executor = bindings.dart_quic_executor_new(
      receivePort.sendPort.nativePort,
    );

    if (executor == nullptr) {
      receivePort.close();
      throw Exception('Failed to create QUIC executor');
    }

    final handler = QuicMessageHandler._(bindings, executor, receivePort);
    handler._setupListener();

    return handler;
  }

  /// Setup simple message listener
  void _setupListener() {
    _receivePort.listen((data) {
      if (data is Uint8List) {
        final message = TaskEventMessage.fromBytes(data);
        if (message != null && message.isValid) {
          print(
            '📥 Response: Task ${message.header.taskId}, Status: ${message.header.status}',
          );

          // Simple response handling
          if (message.isSuccess && message.payload is U64DataPayload) {
            final value = (message.payload as U64DataPayload).value;
            print('   → Result: $value');
          } else if (message.isSuccess && message.payload is BoolDataPayload) {
            final value = (message.payload as BoolDataPayload).value;
            print('   → Result: $value');
          }
        }
      }
    });
  }

  /// Submit ping command - simple connection test
  int ping() {
    return _bindings.dart_quic_executor_submit_params(
      _executor,
      QuicCommandType.ping.value,
      nullptr,
      0,
      nullptr,
      0,
    );
  }

  /// Submit echo command - returns data length
  int echo(Uint8List data) {
    return _submitWithData(QuicCommandType.echo, data);
  }

  /// Submit send data command - simulation of sending data
  int sendData(Uint8List data) {
    return _submitWithData(QuicCommandType.sendData, data);
  }

  /// Internal helper to submit command with data
  int _submitWithData(QuicCommandType command, Uint8List data) {
    if (data.isEmpty) {
      return _bindings.dart_quic_executor_submit_params(
        _executor,
        command.value,
        nullptr,
        0,
        nullptr,
        0,
      );
    }

    final dataPtr = _bindings.dart_allocate_memory(data.length);
    if (dataPtr == nullptr) {
      throw Exception('Failed to allocate memory');
    }

    try {
      dataPtr.asTypedList(data.length).setAll(0, data);
      return _bindings.dart_quic_executor_submit_params(
        _executor,
        command.value,
        dataPtr,
        data.length,
        nullptr,
        0,
      );
    } finally {
      _bindings.dart_free_memory(dataPtr, data.length);
    }
  }

  /// Check if executor is running
  bool get isRunning => _bindings.dart_quic_executor_is_running(_executor);

  /// Dispose resources
  void dispose() {
    _receivePort.close();
    _bindings.dart_quic_executor_free(_executor);
  }
}

/// Simple memory manager wrapper
class QuicMemoryManager {
  final QuicFFIBindings _bindings;

  QuicMemoryManager(this._bindings);

  /// Initialize with default settings
  bool initialize() => _bindings.dart_initialize_memory_manager();

  /// Check availability
  bool get isAvailable => _bindings.dart_is_memory_manager_available();

  /// Cleanup
  bool destroy() => _bindings.dart_destroy_memory_manager();
}
