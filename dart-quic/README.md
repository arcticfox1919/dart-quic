# dart-quic

A Dart library for QUIC protocol communication, built on top of [quinn](https://github.com/quinn-rs/quinn) via FFI.

## Structure

```
dart-quic/        # Dart package (pub)
dart-quic-ffi/    # Rust FFI crate (quinn wrapper, compiled to a native shared library)
build_scripts/    # Helper scripts for building and regenerating FFI bindings
```

## Features

- QUIC client and server endpoints
- Bidirectional and unidirectional streams
- Datagram support
- Self-signed certificate generation for testing
- Async/await API built on a Tokio runtime managed internally

## Quick start

**Server**

```dart
// Load native library and initialize
LibraryLoader.setCustomLoader(() => DynamicLibrary.open('path/dart_quic_ffi.so'));
QuicInitializer.initialize();

// Bind with a self-signed certificate (testing only)
final server = await QuicServerEndpoint.bind(
  QuicServerConfig.selfSigned(bindAddr: '0.0.0.0:4433', sanList: ['localhost']),
);

while (true) {
  final conn = await server.accept();
  if (conn == null) break; // server closed
  final stream = await conn.acceptBiStream();
  final data = await stream.read(4096);
  await stream.write(data); // echo back
  stream.finish();
}

server.dispose();
```

**Client**

```dart
LibraryLoader.setCustomLoader(() => DynamicLibrary.open('path/dart_quic_ffi.so'));
QuicInitializer.initialize();

final client = await QuicClientEndpoint.create(
  QuicClientConfig.withSkipVerification(), // testing only; use withSystemRoots() in production
);
// Using SocketAddress:
final conn = await client.connect(
  serverAddr: SocketAddress.parse('127.0.0.1:4433'),
  serverName: 'localhost',
);
// Or using a plain string:
// final conn = await client.connectTo(serverAddr: '127.0.0.1:4433', serverName: 'localhost');
final stream = await conn.openBiStream();
await stream.writeString('Hello, QUIC!');
stream.finish();
final response = await stream.read(4096);
print(String.fromCharCodes(response));

client.dispose();
```

See `dart-quic/example/` for full examples.
