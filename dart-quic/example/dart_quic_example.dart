/// Simplified QUIC FFI Example
///
/// This example demonstrates the basic usage of the simplified QUIC FFI system
/// with memory manager, message handler, and protocol validation
library;

import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'package:dart_quic/src/core/quic_message_processor.dart';
import 'package:dart_quic/src/core/quic_buffer.dart';
import 'package:dart_quic/src/core/quic_initializer.dart';
import 'package:dart_quic/src/utils/library_loader.dart';
import 'package:dart_quic/src/utils/quic_arena.dart';
import 'package:dart_quic/src/utils/str_utf8_ptr.dart';

final response = <int, Completer<QuicBuffer>>{};

Future<void> main() async {
  print('Dart QUIC FFI Example');
  print('=' * 40);

  try {
    LibraryLoader.setCustomLoader(
      () => DynamicLibrary.open(
        '../dist/windows-x86_64/release/dart_quic_ffi.dll',
      ),
    );
    QuicInitializer.initialize();
    var handler = QuicMessageProcessor();
    handler.setTaskHandler((resp) {
      if (response.containsKey(resp.taskId)) {
        response[resp.taskId]?.complete(resp.buffer);
      }
    });
    final r = await handler.initialize();
    print('initialize $r');
    final result = await echo(handler, 'hello world!!!');
    print(result);
    handler.dispose();
  } catch (e) {
    print('❌ Example failed: $e');
  }
}

Future<String> echo(QuicMessageProcessor handler, String content) async {
  return autoRelease((arena) async {
    final id = handler.sendCommand(
      QuicCommandType.echo,
      dataPtr: content.toBytes(allocator: arena).cast(),
      dataLen: content.bytesSize,
    );
    final task = Completer<QuicBuffer>();
    response[id] = task;

    final buf = await task.future;
    arena.using<QuicBuffer>(buf, (buf) => buf.destroy());
    return utf8.decode(buf.data);
  });
}
