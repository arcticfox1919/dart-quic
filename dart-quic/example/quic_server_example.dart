/// QUIC Echo Server Example
///
/// Demonstrates how to use the dart_quic library as a bidirectional echo server:
/// 1. Initialize the library with a custom DLL path
/// 2. Create a server endpoint with a self-signed certificate
/// 3. Accept incoming connections in a loop
/// 4. For each connection, accept bidirectional streams and echo data back
/// 5. Gracefully shut down on Ctrl+C
///
/// Prerequisites:
/// - dart_quic_ffi.dll built and placed at the path below
/// - A client connecting and opening a bidirectional stream (e.g. quic_client_example.dart)
///
/// Usage:
///   dart run example/quic_server_example.dart
library;

import 'dart:async';
import 'dart:ffi';
import 'dart:io';

import 'package:dart_quic/dart_quic.dart';

const _bindAddr = '0.0.0.0:4433';
const _dllPath =
    '../dist/windows-x86_64/release/dart_quic_ffi.dll';

Future<void> main() async {
  _banner('QUIC Echo Server Example');

  LibraryLoader.setCustomLoader(() => DynamicLibrary.open(_dllPath));

  QuicInitializer.initialize();
  print('[OK] Library initialized');

  QuicServerEndpoint? server;

  try {
    // Create server with a self-signed certificate (testing only).
    // Use QuicServerConfig.withCertFiles() or withCertDer() in production.
    print('[..] Starting server on $_bindAddr...');
    server = await QuicServerEndpoint.bind(
      QuicServerConfig.selfSigned(bindAddr: _bindAddr, sanList: ['localhost']),
    );
    print(
      '[OK] Server listening on ${server.localAddr} (port ${server.localPort})',
    );
    print('     Press Ctrl+C to stop\n');

    // Handle Ctrl+C: close the server so accept() returns null
    ProcessSignal.sigint.watch().listen((_) {
      print('\n[..] Shutting down...');
      server?.close(errorCode: 0, reason: 'server shutdown');
    });

    // Accept connections until the server is closed
    while (true) {
      final conn = await server.accept();
      if (conn == null) break; // server closed

      print(
        '[>>] New connection from ${conn.remoteAddr} (ID: ${conn.stableId})',
      );
      _handleConnection(conn); // fire-and-forget
    }

    // Wait for all in-flight connections to finish
    await server.waitIdle();
    _banner('Server stopped');
  } catch (e, st) {
    print('[ERROR] $e');
    print(st);
  } finally {
    server?.dispose();
  }
}

/// Handle a single connection:
/// - Loop accepting bidirectional streams from the client
/// - Echo all received data back on the same stream
void _handleConnection(QuicConn conn) {
  Future(() async {
    try {
      print('     [conn ${conn.stableId}] waiting for streams...');

      while (!conn.isDisposed) {
        // Accept the next bidirectional stream opened by the client
        final QuicStream stream;
        try {
          stream = await conn.acceptBiStream();
        } catch (_) {
          // acceptBiStream fails when the connection is closed
          break;
        }

        print(
          '     [conn ${conn.stableId}] accepted bi-stream ${stream.streamId}',
        );

        // Echo loop: read chunks until the client signals EOF, write them back
        _echoStream(conn.stableId, stream); // fire-and-forget per stream
      }
    } catch (e) {
      print('     [conn ${conn.stableId}] error: $e');
    } finally {
      if (!conn.isDisposed) {
        conn.close();
        conn.dispose();
      }
      print('[<<] Connection ${conn.stableId} closed');
    }
  });
}

/// Read all data from [stream] and write it back (echo).
void _echoStream(int connId, QuicStream stream) {
  Future(() async {
    final sid = stream.streamId;
    try {
      while (true) {
        // Read up to 64 KiB at a time; returns empty list on EOF
        final chunk = await stream.read(65536);
        if (chunk.isEmpty) break; // EOF

        final text = String.fromCharCodes(chunk);
        print(
          '     [conn $connId / stream $sid] recv ${chunk.length} bytes: $text',
        );

        // Echo the same bytes back
        await stream.write(chunk);
        print('     [conn $connId / stream $sid] echoed ${chunk.length} bytes');
      }

      // Signal end of write side
      stream.finish();
      print('     [conn $connId / stream $sid] echo complete');
    } catch (e) {
      print('     [conn $connId / stream $sid] error: $e');
    } finally {
      stream.dispose();
    }
  });
}

void _banner(String title) {
  final bar = '='.padRight(50, '=');
  print(bar);
  print('  $title');
  print(bar);
}
