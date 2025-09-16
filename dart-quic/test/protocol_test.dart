/// Tests for the binary protocol implementation
///
/// Validates the Dart protocol classes against the Rust specification
library;

import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dart_quic/dart_quic.dart';

void main() {
  group('Binary Protocol Tests', () {
    test('Protocol constants', () {
      expect(protocolVersion, equals(1));
      expect(protocolMagic, equals(0xDABCFE01));
    });

    test('TaskStatus enum values', () {
      expect(TaskStatus.success.value, equals(0x0000));
      expect(TaskStatus.successWithData.value, equals(0x0001));
      expect(TaskStatus.workerShutdown.value, equals(0x0100));
      expect(TaskStatus.unknownError.value, equals(0x9001));
      expect(TaskStatus.protocolError.value, equals(0xF001));
      expect(TaskStatus.versionMismatch.value, equals(0xF002));
      expect(TaskStatus.corruptedData.value, equals(0xF003));
    });

    test('TaskStatus fromValue', () {
      expect(TaskStatus.fromValue(0x0000), equals(TaskStatus.success));
      expect(TaskStatus.fromValue(0x0001), equals(TaskStatus.successWithData));
      expect(TaskStatus.fromValue(0x0100), equals(TaskStatus.workerShutdown));
      expect(TaskStatus.fromValue(0x9001), equals(TaskStatus.unknownError));
      expect(TaskStatus.fromValue(0xF001), equals(TaskStatus.protocolError));
      expect(TaskStatus.fromValue(0xF002), equals(TaskStatus.versionMismatch));
      expect(TaskStatus.fromValue(0xF003), equals(TaskStatus.corruptedData));
      expect(() => TaskStatus.fromValue(0xFFFF), throwsArgumentError);
    });

    test('TaskStatus properties', () {
      expect(TaskStatus.success.isSuccess, isTrue);
      expect(TaskStatus.successWithData.isSuccess, isTrue);
      expect(TaskStatus.unknownError.isSuccess, isFalse);
      expect(TaskStatus.unknownError.isError, isTrue);
      expect(TaskStatus.workerShutdown.isError, isFalse);
    });

    test('DataType enum values', () {
      expect(DataType.none.value, equals(0));
      expect(DataType.bool.value, equals(1));
      expect(DataType.u64.value, equals(2));
      expect(DataType.bytes.value, equals(3));
      expect(DataType.string.value, equals(4));
    });

    test('DataType fromValue', () {
      expect(DataType.fromValue(0), equals(DataType.none));
      expect(DataType.fromValue(1), equals(DataType.bool));
      expect(DataType.fromValue(2), equals(DataType.u64));
      expect(DataType.fromValue(3), equals(DataType.bytes));
      expect(DataType.fromValue(4), equals(DataType.string));
      expect(() => DataType.fromValue(99), throwsArgumentError);
    });
  });

  group('MessageHeader Tests', () {
    test('Header creation', () {
      final header = MessageHeader(
        magic: protocolMagic,
        version: protocolVersion,
        dataType: DataType.bool,
        status: TaskStatus.successWithData,
        taskId: 12345,
      );

      expect(header.magic, equals(protocolMagic));
      expect(header.version, equals(protocolVersion));
      expect(header.dataType, equals(DataType.bool));
      expect(header.status, equals(TaskStatus.successWithData));
      expect(header.taskId, equals(12345));
      expect(header.isValid, isTrue);
    });

    test('Header serialization/deserialization', () {
      final original = MessageHeader(
        magic: protocolMagic,
        version: protocolVersion,
        dataType: DataType.u64,
        status: TaskStatus.success,
        taskId: 0xDEADBEEF12345678,
      );

      final serialized = original.toBytes();
      expect(serialized.length, equals(16));

      final deserialized = MessageHeader.fromBytes(serialized);
      expect(deserialized, isNotNull);
      expect(deserialized!.magic, equals(original.magic));
      expect(deserialized.version, equals(original.version));
      expect(deserialized.dataType, equals(original.dataType));
      expect(deserialized.status, equals(original.status));
      expect(deserialized.taskId, equals(original.taskId));
    });

    test('Invalid header detection', () {
      final header = MessageHeader(
        magic: 0x12345678, // Wrong magic
        version: protocolVersion,
        dataType: DataType.none,
        status: TaskStatus.success,
        taskId: 0,
      );

      expect(header.isValid, isFalse);
    });
  });

  group('DataPayload Tests', () {
    test('NoDataPayload', () {
      const payload = NoDataPayload();
      expect(payload.dataType, equals(DataType.none));

      final bytes = payload.toBytes();
      expect(bytes.length, equals(16));
      expect(bytes.every((b) => b == 0), isTrue);
    });

    test('BoolDataPayload', () {
      const truePayload = BoolDataPayload(true);
      const falsePayload = BoolDataPayload(false);

      expect(truePayload.dataType, equals(DataType.bool));
      expect(falsePayload.dataType, equals(DataType.bool));

      final trueBytes = truePayload.toBytes();
      final falseBytes = falsePayload.toBytes();

      expect(trueBytes.length, equals(16));
      expect(falseBytes.length, equals(16));
      expect(trueBytes[0], equals(1));
      expect(falseBytes[0], equals(0));
    });

    test('U64DataPayload', () {
      const payload = U64DataPayload(0xDEADBEEF12345678);
      expect(payload.dataType, equals(DataType.u64));

      final bytes = payload.toBytes();
      expect(bytes.length, equals(16));

      // Check that the value is correctly stored in little-endian
      final buffer = ByteData.sublistView(bytes);
      final value = buffer.getUint64(0, Endian.little);
      expect(value, equals(0xDEADBEEF12345678));
    });

    test('DataPayload serialization consistency', () {
      // Test multiple U64 values to ensure consistent little-endian serialization
      final testValues = [
        0x0000000000000000,
        0x1111111111111111,
        0xAAAAAAAAAAAAAAAA,
        0xFFFFFFFFFFFFFFFF,
        0x123456789ABCDEF0,
      ];

      for (final value in testValues) {
        final payload = U64DataPayload(value);
        final bytes = payload.toBytes();

        // Verify serialization
        expect(bytes.length, equals(16));

        // Verify little-endian format
        final buffer = ByteData.sublistView(bytes);
        final deserializedValue = buffer.getUint64(0, Endian.little);
        expect(
          deserializedValue,
          equals(value),
          reason:
              'Value 0x${value.toRadixString(16)} should roundtrip correctly',
        );
      }
    });
  });

  group('TaskEventMessage Tests', () {
    test('No data message', () {
      final message = TaskEventMessage.noData(123);

      expect(message.header.taskId, equals(123));
      expect(message.header.status, equals(TaskStatus.success));
      expect(message.header.dataType, equals(DataType.none));
      expect(message.isValid, isTrue);
      expect(message.isSuccess, isTrue);
      expect(message.isError, isFalse);
      expect(message.totalSize, equals(32));
    });

    test('Bool data message', () {
      final message = TaskEventMessage.boolData(456, true);

      expect(message.header.taskId, equals(456));
      expect(message.header.status, equals(TaskStatus.successWithData));
      expect(message.header.dataType, equals(DataType.bool));
      expect(message.payload, isA<BoolDataPayload>());
      expect((message.payload as BoolDataPayload).value, isTrue);
    });

    test('U64 data message', () {
      final message = TaskEventMessage.u64Data(789, 0xABCDEF0123456789);

      expect(message.header.taskId, equals(789));
      expect(message.header.status, equals(TaskStatus.successWithData));
      expect(message.header.dataType, equals(DataType.u64));
      expect(message.payload, isA<U64DataPayload>());
      expect(
        (message.payload as U64DataPayload).value,
        equals(0xABCDEF0123456789),
      );
    });

    test('Error message', () {
      final message = TaskEventMessage.errorMessage(
        999,
        TaskStatus.unknownError,
        'Something went wrong',
      );

      expect(message.header.taskId, equals(999));
      expect(message.header.status, equals(TaskStatus.unknownError));
      expect(message.header.dataType, equals(DataType.string));
      expect(message.isError, isTrue);
      expect(message.isSuccess, isFalse);
    });

    test('Shutdown message', () {
      final message = TaskEventMessage.shutdownMessage();

      expect(message.header.taskId, equals(0));
      expect(message.header.status, equals(TaskStatus.workerShutdown));
      expect(message.header.dataType, equals(DataType.none));
    });
  });

  group('MessageSerializer Tests', () {
    test('Message serialization/deserialization roundtrip', () {
      final original = TaskEventMessage.u64Data(12345, 0xFEEDFACECAFEBABE);

      final serialized = MessageSerializer.serialize(original);
      expect(serialized.length, equals(32));

      final deserialized = MessageSerializer.deserialize(serialized);
      expect(deserialized, isNotNull);
      expect(deserialized!.isValid, isTrue);
      expect(deserialized.header.taskId, equals(original.header.taskId));
      expect(deserialized.header.status, equals(original.header.status));
      expect(deserialized.header.dataType, equals(original.header.dataType));

      final originalPayload = original.payload as U64DataPayload;
      final deserializedPayload = deserialized.payload as U64DataPayload;
      expect(deserializedPayload.value, equals(originalPayload.value));
    });

    test('Invalid data handling', () {
      final invalidData = Uint8List(10); // Too short
      final result = MessageSerializer.deserialize(invalidData);
      expect(result, isNull);
    });

    test('Bool message serialization consistency', () {
      final trueMessage = TaskEventMessage.boolData(1, true);
      final falseMessage = TaskEventMessage.boolData(2, false);

      final trueSerialized = MessageSerializer.serialize(trueMessage);
      final falseSerialized = MessageSerializer.serialize(falseMessage);

      expect(trueSerialized.length, equals(32));
      expect(falseSerialized.length, equals(32));

      final trueDeserialized = MessageSerializer.deserialize(trueSerialized)!;
      final falseDeserialized = MessageSerializer.deserialize(falseSerialized)!;

      expect((trueDeserialized.payload as BoolDataPayload).value, isTrue);
      expect((falseDeserialized.payload as BoolDataPayload).value, isFalse);
    });

    test('Message serialization with various data types', () {
      final messages = [
        TaskEventMessage.noData(1),
        TaskEventMessage.boolData(2, true),
        TaskEventMessage.boolData(3, false),
        TaskEventMessage.u64Data(4, 0),
        TaskEventMessage.u64Data(5, 0xFFFFFFFFFFFFFFFF),
        TaskEventMessage.u64Data(6, 0x123456789ABCDEF0),
      ];

      for (final original in messages) {
        final serialized = MessageSerializer.serialize(original);
        expect(
          serialized.length,
          equals(32),
          reason: 'All messages should be 32 bytes',
        );

        final deserialized = MessageSerializer.deserialize(serialized);
        expect(
          deserialized,
          isNotNull,
          reason: 'Deserialization should succeed',
        );
        expect(
          deserialized!.isValid,
          isTrue,
          reason: 'Deserialized message should be valid',
        );
        expect(
          deserialized.header.taskId,
          equals(original.header.taskId),
          reason: 'Task ID should be preserved',
        );
        expect(
          deserialized.header.dataType,
          equals(original.header.dataType),
          reason: 'Data type should be preserved',
        );
      }
    });

    test('MessageSerializer edge cases', () {
      // Test with null data
      final nullData = Uint8List(0);
      final nullResult = MessageSerializer.deserialize(nullData);
      expect(nullResult, isNull);

      // Test with wrong size data
      final wrongSizeData = Uint8List(16); // Should be 32
      final wrongSizeResult = MessageSerializer.deserialize(wrongSizeData);
      expect(wrongSizeResult, isNull);

      // Test with corrupted magic number
      final validMessage = TaskEventMessage.noData(123);
      final serialized = MessageSerializer.serialize(validMessage);

      // Corrupt the magic number
      final buffer = ByteData.sublistView(serialized);
      buffer.setUint32(0, 0x12345678, Endian.little); // Wrong magic

      final corruptedResult = MessageSerializer.deserialize(serialized);
      // The deserializer might return null for invalid magic, or return an invalid message
      if (corruptedResult != null) {
        expect(
          corruptedResult.isValid,
          isFalse,
          reason: 'Message with corrupted magic should be marked as invalid',
        );
      }
      // Either behavior (null or invalid message) is acceptable for corrupted data
    });
  });

  group('ProtocolUtils Tests', () {
    test('Version compatibility', () {
      expect(ProtocolUtils.isVersionCompatible(1), isTrue);
      expect(ProtocolUtils.isVersionCompatible(0), isFalse);
      expect(ProtocolUtils.isVersionCompatible(2), isFalse);
    });

    test('Error message creation', () {
      final protocolError = ProtocolUtils.createProtocolError(
        123,
        'Invalid data',
      );
      expect(protocolError.header.taskId, equals(123));
      expect(protocolError.header.status, equals(TaskStatus.protocolError));
      expect(protocolError.header.dataType, equals(DataType.string));

      final versionError = ProtocolUtils.createVersionMismatchError(456, 2);
      expect(versionError.header.status, equals(TaskStatus.versionMismatch));
      expect(versionError.header.taskId, equals(456));

      final corruptedError = ProtocolUtils.createCorruptedDataError(789);
      expect(corruptedError.header.status, equals(TaskStatus.corruptedData));
      expect(corruptedError.header.taskId, equals(789));
    });
  });

  group('Protocol Exception Tests', () {
    test('Exception creation', () {
      const exception = ProtocolException(
        'Test error',
        TaskStatus.unknownError,
      );
      expect(exception.message, equals('Test error'));
      expect(exception.status, equals(TaskStatus.unknownError));
      expect(exception.toString(), contains('Test error'));
      expect(exception.toString(), contains('unknownError'));
    });

    test('Exception without status', () {
      const exception = ProtocolException('Simple error');
      expect(exception.message, equals('Simple error'));
      expect(exception.status, isNull);
      expect(exception.toString(), contains('Simple error'));
    });
  });

  group('Endianness and Binary Consistency Tests', () {
    test('MessageHeader little-endian serialization consistency', () {
      final header = MessageHeader(
        magic: 0xDABCFE01,
        version: 1,
        dataType: DataType.u64,
        status: TaskStatus.successWithData,
        taskId: 0xDEADBEEF12345678,
      );

      final serialized = header.toBytes();
      expect(serialized.length, equals(16));

      // Verify little-endian byte order manually
      final buffer = ByteData.sublistView(serialized);
      expect(buffer.getUint32(0, Endian.little), equals(0xDABCFE01)); // magic
      expect(buffer.getUint8(4), equals(1)); // version (single byte)
      expect(
        buffer.getUint8(5),
        equals(DataType.u64.value),
      ); // dataType (single byte)
      expect(
        buffer.getUint16(6, Endian.little),
        equals(TaskStatus.successWithData.value),
      ); // status
      expect(
        buffer.getUint64(8, Endian.little),
        equals(0xDEADBEEF12345678),
      ); // taskId
    });

    test('U64DataPayload little-endian serialization', () {
      const payload = U64DataPayload(0xFEEDFACECAFEBABE);
      final bytes = payload.toBytes();
      expect(bytes.length, equals(16));

      // Verify little-endian storage
      final buffer = ByteData.sublistView(bytes);
      final value = buffer.getUint64(0, Endian.little);
      expect(value, equals(0xFEEDFACECAFEBABE));
    });

    test('Complete message serialization roundtrip with endianness', () {
      final original = TaskEventMessage.u64Data(
        0x123456789ABC,
        0xFEEDFACECAFEBABE,
      ); // Use 6-byte taskId

      final serialized = MessageSerializer.serialize(original);
      expect(serialized.length, equals(32));

      // Verify the serialized data maintains little-endian format
      final buffer = ByteData.sublistView(serialized);
      expect(buffer.getUint32(0, Endian.little), equals(0xDABCFE01)); // magic
      expect(
        buffer.getUint64(16, Endian.little),
        equals(0xFEEDFACECAFEBABE),
      ); // payload

      final deserialized = MessageSerializer.deserialize(serialized);
      expect(deserialized, isNotNull);
      expect(deserialized!.header.taskId, equals(original.header.taskId));
      expect(
        (deserialized.payload as U64DataPayload).value,
        equals((original.payload as U64DataPayload).value),
      );
    });

    test('Cross-platform endianness consistency verification', () {
      // Test that our protocol produces the same byte sequence regardless of platform
      final testCases = [
        (0x12345678, [0x78, 0x56, 0x34, 0x12]), // 32-bit little-endian
        (0xDEADBEEF, [0xEF, 0xBE, 0xAD, 0xDE]), // 32-bit little-endian
      ];

      for (final (value, expectedBytes) in testCases) {
        final buffer = ByteData(4);
        buffer.setUint32(0, value, Endian.little);
        final actualBytes = buffer.buffer.asUint8List();

        expect(
          actualBytes,
          equals(expectedBytes),
          reason:
              'Value 0x${value.toRadixString(16)} should serialize to little-endian bytes',
        );
      }
    });

    test('TaskStatus and DataType fromValue error handling', () {
      // Test that invalid enum values throw appropriate errors
      expect(() => TaskStatus.fromValue(0xFFFF), throwsArgumentError);
      expect(() => DataType.fromValue(99), throwsArgumentError);

      // Test that the error messages are informative
      try {
        TaskStatus.fromValue(0xDEAD);
        fail('Should have thrown ArgumentError');
      } catch (e) {
        expect(e.toString(), contains('Unknown TaskStatus value'));
        expect(e.toString(), contains('57005')); // 0xDEAD in decimal
      }
    });

    test('Boundary value testing for enums', () {
      // Test boundary values for TaskStatus
      final validTaskStatusValues = [
        0x0000,
        0x0001,
        0x0100,
        0x9001,
        0xF001,
        0xF002,
        0xF003,
      ];
      for (final value in validTaskStatusValues) {
        expect(
          () => TaskStatus.fromValue(value),
          isNot(throwsException),
          reason: 'Valid TaskStatus value $value should not throw',
        );
      }

      // Test boundary values for DataType
      final validDataTypeValues = [0, 1, 2, 3, 4];
      for (final value in validDataTypeValues) {
        expect(
          () => DataType.fromValue(value),
          isNot(throwsException),
          reason: 'Valid DataType value $value should not throw',
        );
      }

      // Test invalid boundary values
      final invalidTaskStatusValues = [0x0002, 0x0101, 0x9000, 0xF000, 0xF004];
      for (final value in invalidTaskStatusValues) {
        expect(
          () => TaskStatus.fromValue(value),
          throwsArgumentError,
          reason: 'Invalid TaskStatus value $value should throw',
        );
      }

      final invalidDataTypeValues = [-1, 5, 10, 100];
      for (final value in invalidDataTypeValues) {
        expect(
          () => DataType.fromValue(value),
          throwsArgumentError,
          reason: 'Invalid DataType value $value should throw',
        );
      }
    });

    test('Protocol message size and alignment verification', () {
      // Verify that all protocol components have expected sizes
      final testMessages = [
        TaskEventMessage.noData(1),
        TaskEventMessage.boolData(2, true),
        TaskEventMessage.u64Data(3, 0x123456789ABCDEF0),
      ];

      for (final message in testMessages) {
        // Header should be 16 bytes
        final headerBytes = message.header.toBytes();
        expect(
          headerBytes.length,
          equals(16),
          reason: 'Message header should be exactly 16 bytes',
        );

        // Payload should be 16 bytes
        final payloadBytes = message.payload.toBytes();
        expect(
          payloadBytes.length,
          equals(16),
          reason: 'Message payload should be exactly 16 bytes',
        );

        // Total serialized message should be 32 bytes
        final serialized = MessageSerializer.serialize(message);
        expect(
          serialized.length,
          equals(32),
          reason: 'Complete message should be exactly 32 bytes',
        );

        // Verify byte alignment (should be 4-byte aligned for efficiency)
        expect(
          serialized.length % 4,
          equals(0),
          reason: 'Message size should be 4-byte aligned',
        );
      }
    });
  });
}
