/// Simplified QUIC FFI Example
///
/// This example demonstrates the basic usage of the simplified QUIC FFI system
/// with memory manager, message handler, and protocol validation
library;

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_quic/src/quic_ffi_bindings.dart';
import 'package:dart_quic/src/protocol/message_handler.dart';
import 'package:dart_quic/src/protocol/binary_protocol.dart';

typedef dartPostCObject =
    Pointer Function(
      Pointer<NativeFunction<Int8 Function(Int64, Pointer<Dart_CObject>)>>,
    );

// Global variables to avoid duplicate initialization
late final DynamicLibrary _library;
late final QuicFFIBindings _bindings;

/// Get the path to the native library based on current platform and script location
String _getNativeLibraryPath() {
  // Get current script directory (dart-quic/example/)
  final scriptFile = Platform.script.toFilePath();
  final scriptDir = Directory(scriptFile).parent;

  // Navigate to project root (dart-quic/../)
  final projectRoot = scriptDir.parent.parent;

  // Determine platform-specific library path
  String platformDir;
  String libName;

  if (Platform.isWindows) {
    platformDir = 'windows-x86_64';
    libName = 'dart_quic_ffi.dll';
  } else if (Platform.isLinux) {
    platformDir = 'linux-x86_64';
    libName = 'libdart_quic_ffi.so';
  } else if (Platform.isMacOS) {
    platformDir = 'macos-aarch64';
    libName = 'libdart_quic_ffi.dylib';
  } else {
    throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
  }

  // Build path to distribution directory
  final distPath = '${projectRoot.path}/dist/$platformDir/release/$libName';

  if (!File(distPath).existsSync()) {
    throw FileSystemException(
      'Native library not found at: $distPath\n'
      'Please run the build script first: dart run builder.dart ${platformDir.split('-')[0]}X64',
    );
  }

  return distPath;
}

Future<void> main() async {
  print('🚀 Dart QUIC FFI Example');
  print('=' * 40);

  try {
    // Step 1: Initialize FFI once
    await initializeFFI();

    // Step 2: Test commands
    await commandExample();

    print('\n✅ All examples completed successfully!');
  } catch (e) {
    print('❌ Example failed: $e');
  }
}

/// Initialize FFI library once (called only once)
Future<void> initializeFFI() async {
  print('\n🔧 Initializing FFI');
  print('-' * 25);

  try {
    // Load the native library once
    final libraryPath = _getNativeLibraryPath();
    _library = DynamicLibrary.open(libraryPath);
    print('✅ Native library loaded from: $libraryPath');

    // Setup Dart post object function for communication (ONLY ONCE)
    final storeDartPostCObject = _library
        .lookupFunction<dartPostCObject, dartPostCObject>(
          'store_dart_post_cobject',
        );
    storeDartPostCObject(NativeApi.postCObject);
    print('✅ Dart post object configured');

    // Initialize FFI bindings once
    _bindings = QuicFFIBindings(_library);
    print('✅ FFI bindings created');

    // Test memory manager
    final memManager = QuicMemoryManager(_bindings);
    final initialized = memManager.initialize();
    print('✅ Memory manager initialized: $initialized');

    if (initialized) {
      print('� Memory manager available: ${memManager.isAvailable}');
    }
  } catch (e) {
    print('❌ FFI setup failed: $e');
    rethrow;
  }
}

/// Command execution example (uses global initialized bindings)
Future<void> commandExample() async {
  print('\n🎯 Command Example');
  print('-' * 25);

  try {
    // Use the already initialized global bindings
    final handler = await QuicMessageHandler.create(_bindings);
    print('✅ Message handler created');
    print('📋 Executor running: ${handler.isRunning}');

    // Test ping command
    print('\n🏓 Testing ping command...');
    final pingTask = handler.ping();
    print('📤 Ping submitted with task ID: $pingTask');

    // Test echo command with small data
    print('\n🔄 Testing echo command...');
    final echoData = Uint8List.fromList('Hello!'.codeUnits);
    final echoTask = handler.echo(echoData);
    print('📤 Echo submitted with task ID: $echoTask');
    print(
      '   Data: "${String.fromCharCodes(echoData)}" (${echoData.length} bytes)',
    );

    // Test send data command with larger data
    print('\n📤 Testing send data command...');
    final sendData = Uint8List(100);
    for (int i = 0; i < sendData.length; i++) {
      sendData[i] = i % 256;
    }
    final sendTask = handler.sendData(sendData);
    print('📤 Send data submitted with task ID: $sendTask');
    print('   Data: ${sendData.length} bytes of test pattern');

    // Wait for responses
    print('\n⏳ Waiting for responses...');
    await Future.delayed(Duration(milliseconds: 800));

    // Show protocol information
    print('\n📊 Protocol Information:');
    print('   Version: $protocolVersion');
    print('   Magic: 0x${protocolMagic.toRadixString(16)}');
    print('   Message size: 32 bytes (fixed)');
    print('   Endianness: Little-endian');

    // Show supported commands
    print('\n🎯 Supported Commands:');
    for (final cmd in QuicCommandType.values) {
      print('   ${cmd.name}: 0x${cmd.value.toRadixString(16).padLeft(2, '0')}');
    }

    // Cleanup
    handler.dispose();
    print('\n✅ Message handler disposed');
  } catch (e) {
    print('❌ Command example failed: $e');
  }
}
