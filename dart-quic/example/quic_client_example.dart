/// QUIC Client Example
///
/// This example demonstrates how to use the dart_quic library to:
/// 1. Initialize the QUIC library with a custom DLL loader
/// 2. Configure a QUIC client with certificate verification options
/// 3. Connect to a QUIC server
/// 4. Open a bidirectional stream
/// 5. Send and receive data over the stream
/// 6. Properly close and dispose resources
///
/// Prerequisites:
/// - A running QUIC server at the specified address
/// - The dart_quic_ffi.dll built and placed in the correct location
///
/// Usage:
///   dart run dart_quic_example.dart
library;

import 'dart:ffi';

import 'package:dart_quic/dart_quic.dart';

Future<void> main() async {
  print('='.padRight(50, '='));
  print('  QUIC Client Example');
  print('='.padRight(50, '='));

  // Step 1: Configure custom library loader (optional)
  // This is useful when the DLL is not in the default location
  LibraryLoader.setCustomLoader(
    () =>
        DynamicLibrary.open('../dist/windows-x86_64/release/dart_quic_ffi.dll'),
  );

  // Step 2: Initialize the QUIC library
  QuicInitializer.initialize();
  print('[OK] QUIC library initialized');

  // Configuration
  const serverAddress = '127.0.0.1:4433';
  const serverName = 'localhost';

  QuicClientEndpoint? client;
  QuicConn? connection;
  QuicStream? stream;

  try {
    // Step 3: Create QUIC client configuration
    // Use skipVerification for testing only! Use withSystemRoots() for production.
    // Step 4: Create and initialize QUIC client endpoint
    print('[..] Creating client endpoint...');
    client = await QuicClientEndpoint.create(
      QuicClientConfig.withSkipVerification(),
    );
    print('[OK] Client endpoint created and initialized');

    // Step 5: Connect to the QUIC server
    print('[..] Connecting to $serverAddress...');
    connection = await client.connect(
      serverAddr: SocketAddress.parse(serverAddress),
      serverName: serverName,
    );
    print('[OK] Connected to server');
    print('    Remote address: ${connection.remoteAddr}');
    print('    Connection ID: ${connection.stableId}');

    // Step 6: Open a bidirectional stream
    stream = await connection.openBiStream();
    print('[OK] Bidirectional stream opened (ID: ${stream.streamId})');

    // Step 7: Send data to the server
    final requestData = 'Hello, QUIC Server!';
    await stream.writeString(requestData);
    print('[OK] Sent: $requestData');

    // Signal end of write (FIN)
    stream.finish();
    print('[OK] Stream write finished');

    // Step 8: Read response from the server
    print('[..] Waiting for response...');
    final responseData = await stream.read(4096);
    if (responseData.isNotEmpty) {
      final responseStr = String.fromCharCodes(responseData);
      print('[OK] Received: $responseStr');
    } else {
      print('[OK] Received empty response (stream ended)');
    }

    print('');
    print('='.padRight(50, '='));
    print('  Example completed successfully!');
    print('='.padRight(50, '='));
  } catch (e, stackTrace) {
    print('[ERROR] $e');
    print('Stack trace: $stackTrace');
  } finally {
    // Step 9: Clean up resources (in reverse order)
    print('');
    print('[..] Cleaning up resources...');

    // Dispose stream
    if (stream != null && !stream.isDisposed) {
      stream.dispose();
      print('[OK] Stream disposed');
    }

    // Close and dispose connection
    if (connection != null && !connection.isDisposed) {
      connection.close();
      connection.dispose();
      print('[OK] Connection closed and disposed');
    }

    // Close and dispose client
    if (client != null && !client.isDisposed) {
      await client.close();
      client.dispose();
      print('[OK] Client closed and disposed');
    }

    print('[OK] Cleanup complete');
  }
}

/// Example: Using system root certificates (production)
///
/// ```dart
/// final config = QuicClientConfig.withSystemRoots();
/// ```
///
/// Example: Using custom CA certificate file
///
/// ```dart
/// final config = QuicClientConfig.withCustomCaPemFile('/path/to/ca.pem');
/// ```
///
/// Example: Using transport configuration
///
/// ```dart
/// final transportConfig = QuicTransportConfig()
///   ..setMaxIdleTimeout(60000)      // 60 seconds
///   ..setKeepAliveInterval(15000)   // 15 seconds
///   ..setMaxConcurrentBiStreams(200);
///
/// final config = QuicClientConfig.withSystemRoots()
///   ..setTransportConfig(transportConfig);
/// ```
