/// High-efficiency binary protocol for Rust-Dart FFI communication
///
/// This is the Dart counterpart of the Rust binary_protocol.rs
/// Provides zero-copy message handling and efficient serialization/deserialization
library;

import 'dart:ffi';
import 'dart:typed_data';
import 'dart:convert';

/// Protocol version - for backward compatibility
const int protocolVersion = 1;

/// Protocol magic number
const int protocolMagic = 0xDABCFE01;

/// Task status enumeration
/// Corresponds to the Rust TaskStatus enum
enum TaskStatus {
  // === 0x0000 - 0x00FF ===
  success(0x0000), // Task completed successfully, no return data
  successWithData(0x0001), // Task completed successfully, has return data

  // === 0x0100 - 0x01FF ===
  workerShutdown(0x0100), // Worker thread shutdown normally

  // === 0x9000 - 0x9FFF ===
  unknownError(0x9001), // Unknown error

  // === 0xF000 - 0xFFFF ===
  protocolError(0xF001), // Protocol error
  versionMismatch(0xF002), // Version mismatch
  corruptedData(0xF003); // Data corrupted

  const TaskStatus(this.value);

  final int value;

  /// Create TaskStatus from integer value using factory constructor
  factory TaskStatus.fromValue(int value) {
    switch (value) {
      case 0x0000:
        return TaskStatus.success;
      case 0x0001:
        return TaskStatus.successWithData;
      case 0x0100:
        return TaskStatus.workerShutdown;
      case 0x9001:
        return TaskStatus.unknownError;
      case 0xF001:
        return TaskStatus.protocolError;
      case 0xF002:
        return TaskStatus.versionMismatch;
      case 0xF003:
        return TaskStatus.corruptedData;
      default:
        throw ArgumentError('Unknown TaskStatus value: $value');
    }
  }

  /// Check if this is a success status
  bool get isSuccess =>
      this == TaskStatus.success || this == TaskStatus.successWithData;

  /// Check if this is an error status
  bool get isError => !isSuccess && this != TaskStatus.workerShutdown;
}

/// Data type enumeration
/// Corresponds to the Rust DataType enum
enum DataType {
  none(0), // No data
  bool(1), // Boolean value
  u64(2), // 64-bit unsigned integer
  bytes(3), // Byte array (zero-copy pointer)
  string(4); // String (error messages, etc.)

  const DataType(this.value);

  final int value;

  /// Create DataType from integer value using factory constructor
  factory DataType.fromValue(int value) {
    switch (value) {
      case 0:
        return DataType.none;
      case 1:
        return DataType.bool;
      case 2:
        return DataType.u64;
      case 3:
        return DataType.bytes;
      case 4:
        return DataType.string;
      default:
        throw ArgumentError('Unknown DataType value: $value');
    }
  }
}

/// Message header structure (16 bytes)
/// Corresponds to the Rust MessageHeader struct
class MessageHeader {
  final int magic;
  final int version;
  final DataType dataType;
  final TaskStatus status;
  final int taskId;

  const MessageHeader({
    required this.magic,
    required this.version,
    required this.dataType,
    required this.status,
    required this.taskId,
  });

  /// Check if header is valid
  bool get isValid => magic == protocolMagic && version == protocolVersion;

  /// Serialize header to bytes (16 bytes)
  Uint8List toBytes() {
    final buffer = ByteData(16);
    int offset = 0;

    buffer.setUint32(offset, magic, Endian.little);
    offset += 4;
    buffer.setUint8(offset, version);
    offset += 1;
    buffer.setUint8(offset, dataType.value);
    offset += 1;
    buffer.setUint16(offset, status.value, Endian.little);
    offset += 2;
    buffer.setUint64(offset, taskId, Endian.little);
    offset += 8;

    return buffer.buffer.asUint8List();
  }

  /// Deserialize header from bytes
  static MessageHeader? fromBytes(Uint8List bytes) {
    if (bytes.length < 16) return null;

    final buffer = ByteData.sublistView(bytes);
    int offset = 0;

    final magic = buffer.getUint32(offset, Endian.little);
    offset += 4;
    final version = buffer.getUint8(offset);
    offset += 1;
    final dataTypeValue = buffer.getUint8(offset);
    offset += 1;
    final statusValue = buffer.getUint16(offset, Endian.little);
    offset += 2;
    final taskId = buffer.getUint64(offset, Endian.little);
    offset += 8;

    try {
      final dataType = DataType.fromValue(dataTypeValue);
      final status = TaskStatus.fromValue(statusValue);

      return MessageHeader(
        magic: magic,
        version: version,
        dataType: dataType,
        status: status,
        taskId: taskId,
      );
    } catch (e) {
      // Invalid enum values
      return null;
    }
  }

  @override
  String toString() {
    return 'MessageHeader(magic: 0x${magic.toRadixString(16)}, '
        'version: $version, dataType: $dataType, '
        'status: $status, taskId: $taskId)';
  }
}

/// Data payload for different types
/// Corresponds to the Rust DataPayload union
abstract class DataPayload {
  const DataPayload();

  /// Serialize payload to bytes (16 bytes)
  Uint8List toBytes();
}

/// No data payload
class NoDataPayload extends DataPayload {
  const NoDataPayload();

  @override
  Uint8List toBytes() {
    return Uint8List(16); // All zeros
  }
}

/// Boolean data payload
class BoolDataPayload extends DataPayload {
  final bool value;

  const BoolDataPayload(this.value);

  @override
  Uint8List toBytes() {
    final buffer = ByteData(16);
    buffer.setUint8(0, value ? 1 : 0);
    return buffer.buffer.asUint8List();
  }
}

/// U64 data payload
class U64DataPayload extends DataPayload {
  final int value;

  const U64DataPayload(this.value);

  @override
  Uint8List toBytes() {
    final buffer = ByteData(16);
    buffer.setUint64(0, value, Endian.little);
    return buffer.buffer.asUint8List();
  }
}

/// Bytes data payload (pointer + length)
class BytesDataPayload extends DataPayload {
  final Pointer<Uint8> ptr;
  final int length;

  const BytesDataPayload(this.ptr, this.length);

  @override
  Uint8List toBytes() {
    final buffer = ByteData(16);
    buffer.setUint64(0, ptr.address, Endian.little); // Pointer as address
    buffer.setUint64(8, length, Endian.little); // Length
    return buffer.buffer.asUint8List();
  }

  /// Get the actual byte data (zero-copy if possible)
  Uint8List getData() {
    if (ptr == nullptr || length == 0) {
      return Uint8List(0);
    }
    return ptr.asTypedList(length);
  }
}

/// String data payload (pointer + length)
class StringDataPayload extends DataPayload {
  final Pointer<Uint8> ptr;
  final int length;

  const StringDataPayload(this.ptr, this.length);

  @override
  Uint8List toBytes() {
    final buffer = ByteData(16);
    buffer.setUint64(0, ptr.address, Endian.little); // Pointer as address
    buffer.setUint64(8, length, Endian.little); // Length
    return buffer.buffer.asUint8List();
  }

  /// Get the actual string data
  String getString() {
    if (ptr == nullptr || length == 0) {
      return '';
    }
    final bytes = ptr.asTypedList(length);
    return utf8.decode(bytes);
  }
}

/// Complete task event message structure
/// Corresponds to the Rust TaskEventMessage struct (32 bytes total)
class QuicTaskMessage {
  final MessageHeader header;
  final DataPayload payload;

  const QuicTaskMessage({required this.header, required this.payload});

  /// Create no-data success message
  factory QuicTaskMessage.noData(int taskId) {
    return QuicTaskMessage(
      header: MessageHeader(
        magic: protocolMagic,
        version: protocolVersion,
        dataType: DataType.none,
        status: TaskStatus.success,
        taskId: taskId,
      ),
      payload: const NoDataPayload(),
    );
  }

  /// Create boolean data message
  factory QuicTaskMessage.boolData(int taskId, bool value) {
    return QuicTaskMessage(
      header: MessageHeader(
        magic: protocolMagic,
        version: protocolVersion,
        dataType: DataType.bool,
        status: TaskStatus.successWithData,
        taskId: taskId,
      ),
      payload: BoolDataPayload(value),
    );
  }

  /// Create U64 data message
  factory QuicTaskMessage.u64Data(int taskId, int value) {
    return QuicTaskMessage(
      header: MessageHeader(
        magic: protocolMagic,
        version: protocolVersion,
        dataType: DataType.u64,
        status: TaskStatus.successWithData,
        taskId: taskId,
      ),
      payload: U64DataPayload(value),
    );
  }

  /// Create bytes data message
  factory QuicTaskMessage.bytesData(
    int taskId,
    Pointer<Uint8> ptr,
    int length,
  ) {
    return QuicTaskMessage(
      header: MessageHeader(
        magic: protocolMagic,
        version: protocolVersion,
        dataType: DataType.bytes,
        status: TaskStatus.successWithData,
        taskId: taskId,
      ),
      payload: BytesDataPayload(ptr, length),
    );
  }

  /// Create string data message
  factory QuicTaskMessage.stringData(
    int taskId,
    TaskStatus status,
    String text,
  ) {
    // For simplicity, we'll use a different approach for string messages
    // In practice, you might want to allocate memory and create a pointer
    final bytes = utf8.encode(text);
    // This is a simplified version - in real implementation you'd need proper pointer management
    return QuicTaskMessage(
      header: MessageHeader(
        magic: protocolMagic,
        version: protocolVersion,
        dataType: DataType.string,
        status: status,
        taskId: taskId,
      ),
      payload: StringDataPayload(nullptr, bytes.length), // Simplified
    );
  }

  /// Create error message
  factory QuicTaskMessage.errorMessage(
    int taskId,
    TaskStatus errorType,
    String errorMsg,
  ) {
    return QuicTaskMessage.stringData(taskId, errorType, errorMsg);
  }

  /// Create worker shutdown message
  factory QuicTaskMessage.shutdownMessage() {
    return QuicTaskMessage(
      header: MessageHeader(
        magic: protocolMagic,
        version: protocolVersion,
        dataType: DataType.none,
        status: TaskStatus.workerShutdown,
        taskId: 0,
      ),
      payload: const NoDataPayload(),
    );
  }

  /// Check if the message is valid
  bool get isValid => header.isValid;

  /// Check if the message indicates success
  bool get isSuccess => header.status.isSuccess;

  /// Check if the message indicates an error
  bool get isError => header.status.isError;

  /// Get total message size (always 32 bytes)
  int get totalSize => 32;

  /// Serialize message to bytes (32 bytes)
  Uint8List toBytes() {
    final headerBytes = header.toBytes();
    final payloadBytes = payload.toBytes();

    final result = Uint8List(32);
    result.setRange(0, 16, headerBytes);
    result.setRange(16, 32, payloadBytes);

    return result;
  }

  /// Deserialize message from bytes
  static QuicTaskMessage? fromBytes(Uint8List bytes) {
    if (bytes.length < 32) return null;

    // Parse header
    final header = MessageHeader.fromBytes(bytes.sublist(0, 16));
    if (header == null || !header.isValid) return null;

    // Parse payload based on data type
    final payloadBytes = bytes.sublist(16, 32);
    final payloadBuffer = ByteData.sublistView(payloadBytes);

    DataPayload payload;

    switch (header.dataType) {
      case DataType.none:
        payload = const NoDataPayload();
        break;

      case DataType.bool:
        final boolValue = payloadBuffer.getUint8(0) != 0;
        payload = BoolDataPayload(boolValue);
        break;

      case DataType.u64:
        final u64Value = payloadBuffer.getUint64(0, Endian.little);
        payload = U64DataPayload(u64Value);
        break;

      case DataType.bytes:
        final ptrAddress = payloadBuffer.getUint64(0, Endian.little);
        final length = payloadBuffer.getUint64(8, Endian.little);
        final ptr = Pointer<Uint8>.fromAddress(ptrAddress);
        payload = BytesDataPayload(ptr, length);
        break;

      case DataType.string:
        final ptrAddress = payloadBuffer.getUint64(0, Endian.little);
        final length = payloadBuffer.getUint64(8, Endian.little);
        final ptr = Pointer<Uint8>.fromAddress(ptrAddress);
        payload = StringDataPayload(ptr, length);
        break;
    }

    return QuicTaskMessage(header: header, payload: payload);
  }

  @override
  String toString() {
    return 'QuicTaskMessage(header: $header, payload: ${payload.runtimeType})';
  }
}

/// High-performance message serializer
/// Corresponds to the Rust MessageSerializer
class MessageSerializer {
  const MessageSerializer._();

  /// Serialize message to binary data (fixed 32 bytes)
  static Uint8List serialize(QuicTaskMessage message) {
    return message.toBytes();
  }

  /// Deserialize binary data to message
  static QuicTaskMessage? deserialize(Uint8List data) {
    return QuicTaskMessage.fromBytes(data);
  }

  /// Get data pointed to by pointer (zero-copy access)
  /// Returns null if no pointer data is available
  static Uint8List? getDataPointer(QuicTaskMessage message) {
    switch (message.payload) {
      case BytesDataPayload(:final ptr, :final length):
        if (ptr != nullptr && length > 0) {
          return ptr.asTypedList(length);
        }
        break;
      case StringDataPayload(:final ptr, :final length):
        if (ptr != nullptr && length > 0) {
          return ptr.asTypedList(length);
        }
        break;
      default:
        break;
    }
    return null;
  }

  /// Get string data from pointer
  static String? getStringData(QuicTaskMessage message) {
    if (message.payload is StringDataPayload) {
      final stringPayload = message.payload as StringDataPayload;
      return stringPayload.getString();
    }
    return null;
  }
}

/// Protocol exception for error handling
class ProtocolException implements Exception {
  final String message;
  final TaskStatus? status;

  const ProtocolException(this.message, [this.status]);

  @override
  String toString() =>
      'ProtocolException: $message${status != null ? ' (status: $status)' : ''}';
}

/// Protocol utilities
class ProtocolUtils {
  const ProtocolUtils._();

  /// Validate protocol version compatibility
  static bool isVersionCompatible(int version) {
    return version == protocolVersion;
  }

  /// Create protocol error message
  static QuicTaskMessage createProtocolError(int taskId, String error) {
    return QuicTaskMessage.errorMessage(
      taskId,
      TaskStatus.protocolError,
      error,
    );
  }

  /// Create version mismatch error
  static QuicTaskMessage createVersionMismatchError(
    int taskId,
    int receivedVersion,
  ) {
    return QuicTaskMessage.errorMessage(
      taskId,
      TaskStatus.versionMismatch,
      'Version mismatch: expected $protocolVersion, got $receivedVersion',
    );
  }

  /// Create corrupted data error
  static QuicTaskMessage createCorruptedDataError(int taskId) {
    return QuicTaskMessage.errorMessage(
      taskId,
      TaskStatus.corruptedData,
      'Data corrupted',
    );
  }
}
