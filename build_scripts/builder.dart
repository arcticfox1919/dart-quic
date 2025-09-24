#!/usr/bin/env dart

/// Unified cross-platform native library build script for dart-quic-ffi
///
/// Features:
/// - Single platform builds
/// - Batch builds with presets
/// - Automatic library type selection (static for iOS, dynamic for others)
/// - Smart Rust target management
/// - Configurable build modes and output directories

import 'dart:io';
import 'dart:async';
import 'package:args/args.dart';

// ============================================================================
// Core Data Models
// ============================================================================

/// Supported target platforms with their Rust configurations
enum TargetPlatform {
  androidArm64('android', 'aarch64-linux-android'),
  androidArm('android', 'armv7-linux-androideabi'),
  androidX64('android', 'x86_64-linux-android'),
  iosArm64('ios', 'aarch64-apple-ios'),
  iosX64('ios', 'x86_64-apple-ios'),
  macosArm64('macos', 'aarch64-apple-darwin'),
  macosX64('macos', 'x86_64-apple-darwin'),
  windowsX64('windows', 'x86_64-pc-windows-msvc'),
  windowsX86('windows', 'i686-pc-windows-msvc'),
  linuxX64('linux', 'x86_64-unknown-linux-gnu'),
  linuxArm64('linux', 'aarch64-unknown-linux-gnu');

  const TargetPlatform(this.os, this.rustTarget);

  final String os;
  final String rustTarget;

  bool get requiresStaticLib => os == 'ios';

  String get libExtension {
    if (requiresStaticLib) return 'a';
    switch (os) {
      case 'windows':
        return 'dll';
      case 'macos':
      case 'ios':
        return 'dylib';
      default:
        return 'so';
    }
  }

  String get libFileName {
    final prefix = os == 'windows' ? '' : 'lib';
    return '${prefix}dart_quic_ffi.$libExtension';
  }
}

/// Build presets for batch operations
enum BuildPreset {
  all('all platforms'),
  mobile('mobile platforms (Android + iOS)'),
  desktop('desktop platforms (Windows + macOS + Linux)'),
  ios('iOS platforms only'),
  android('Android platforms only'),
  current('current platform only');

  const BuildPreset(this.description);
  final String description;

  List<TargetPlatform> get platforms {
    switch (this) {
      case BuildPreset.all:
        return TargetPlatform.values;
      case BuildPreset.mobile:
        return [
          TargetPlatform.androidArm64,
          TargetPlatform.androidArm,
          TargetPlatform.androidX64,
          TargetPlatform.iosArm64,
          TargetPlatform.iosX64,
        ];
      case BuildPreset.desktop:
        return [
          TargetPlatform.macosArm64,
          TargetPlatform.macosX64,
          TargetPlatform.windowsX64,
          TargetPlatform.windowsX86,
          TargetPlatform.linuxX64,
          TargetPlatform.linuxArm64,
        ];
      case BuildPreset.ios:
        return [TargetPlatform.iosArm64, TargetPlatform.iosX64];
      case BuildPreset.android:
        return [
          TargetPlatform.androidArm64,
          TargetPlatform.androidArm,
          TargetPlatform.androidX64,
        ];
      case BuildPreset.current:
        return [_getCurrentPlatform()];
    }
  }
}

/// Build configuration container
class BuildConfig {
  final TargetPlatform platform;
  final bool release;
  final bool verbose;
  final String? outputDir;
  final bool skipExisting;

  const BuildConfig({
    required this.platform,
    this.release = true,
    this.verbose = false,
    this.outputDir,
    this.skipExisting = false,
  });

  String get buildMode => release ? 'release' : 'debug';
  String get cargoProfile => release ? '--release' : '';

  BuildConfig copyWith({
    TargetPlatform? platform,
    bool? release,
    bool? verbose,
    String? outputDir,
    bool? skipExisting,
  }) {
    return BuildConfig(
      platform: platform ?? this.platform,
      release: release ?? this.release,
      verbose: verbose ?? this.verbose,
      outputDir: outputDir ?? this.outputDir,
      skipExisting: skipExisting ?? this.skipExisting,
    );
  }
}

/// Build result container
class BuildResult {
  final TargetPlatform platform;
  final bool success;
  final Duration duration;
  final String? error;
  final int? libSize;

  const BuildResult({
    required this.platform,
    required this.success,
    required this.duration,
    this.error,
    this.libSize,
  });
}

// ============================================================================
// Core Builder Class
// ============================================================================

/// Cross-platform native library builder with caching and optimization
class NativeLibraryBuilder {
  final BuildConfig config;
  final String ffiProjectDir;

  NativeLibraryBuilder(this.config, this.ffiProjectDir);

  /// Build the native library for a single platform
  Future<BuildResult> build() async {
    final startTime = DateTime.now();

    _log('🚀 Building ${config.platform.name} (${config.platform.rustTarget})');
    _log(
      '📦 Library type: ${config.platform.requiresStaticLib ? 'Static' : 'Dynamic'}',
    );
    _log('🔧 Build mode: ${config.buildMode}');

    try {
      await _ensureRustTarget();
      await _configureCargo();
      await _buildWithCargo();
      final libSize = await _copyOutput();

      _log('✅ Build completed successfully!');

      return BuildResult(
        platform: config.platform,
        success: true,
        duration: DateTime.now().difference(startTime),
        libSize: libSize,
      );
    } catch (e) {
      _log('❌ Build failed: $e');
      return BuildResult(
        platform: config.platform,
        success: false,
        duration: DateTime.now().difference(startTime),
        error: e.toString(),
      );
    }
  }

  Future<void> _ensureRustTarget() async {
    _log('🔍 Checking Rust target: ${config.platform.rustTarget}');

    final result = await Process.run('rustup', [
      'target',
      'list',
      '--installed',
    ], workingDirectory: ffiProjectDir);

    if (!result.stdout.toString().contains(config.platform.rustTarget)) {
      _log('📥 Installing Rust target: ${config.platform.rustTarget}');
      final installResult = await Process.run('rustup', [
        'target',
        'add',
        config.platform.rustTarget,
      ], workingDirectory: ffiProjectDir);

      if (installResult.exitCode != 0) {
        throw Exception(
          'Failed to install Rust target: ${installResult.stderr}',
        );
      }
    }
  }

  Future<void> _configureCargo() async {
    final cargoTomlPath = '$ffiProjectDir/Cargo.toml';
    final cargoFile = File(cargoTomlPath);

    if (!await cargoFile.exists()) {
      throw Exception('Cargo.toml not found at $cargoTomlPath');
    }

    String content = await cargoFile.readAsString();
    final crateType = config.platform.requiresStaticLib
        ? 'staticlib'
        : 'cdylib';
    final crateTypeRegex = RegExp(r'crate-type\s*=\s*\[.*?\]', multiLine: true);

    if (crateTypeRegex.hasMatch(content)) {
      content = content.replaceAll(
        crateTypeRegex,
        'crate-type = ["$crateType"]',
      );
    } else {
      content = content.replaceFirst(
        RegExp(r'\[lib\]'),
        '[lib]\ncrate-type = ["$crateType"]',
      );
    }

    await cargoFile.writeAsString(content);
    _log('🔧 Configured Cargo.toml for $crateType');
  }

  Future<void> _buildWithCargo() async {
    _log('🔨 Building with Cargo...');

    final args = [
      'build',
      '--target',
      config.platform.rustTarget,
      if (config.release) '--release',
      if (config.verbose) '--verbose',
    ];

    final result = await Process.run(
      'cargo',
      args,
      workingDirectory: ffiProjectDir,
    );

    if (result.exitCode != 0) {
      throw Exception('Cargo build failed:\n${result.stderr}');
    }

    if (config.verbose) {
      _log('📄 Cargo output:\n${result.stdout}');
    }
  }

  Future<int> _copyOutput() async {
    final targetDir =
        '$ffiProjectDir/target/${config.platform.rustTarget}/${config.buildMode}';
    final sourceLib = File('$targetDir/${config.platform.libFileName}');

    if (!await sourceLib.exists()) {
      throw Exception('Built library not found: ${sourceLib.path}');
    }

    final distOutputPath = await _getDistOutputPath();
    final distDestLib = File(distOutputPath);
    await distDestLib.parent.create(recursive: true);

    if (await distDestLib.exists()) {
      await distDestLib.delete();
    }
    await sourceLib.copy(distDestLib.path);

    // Copy header file to dart-quic/include
    await _copyHeaderFile();

    final libSize = await sourceLib.length();
    _log(' Distribution copy: ${distDestLib.path}');
    _log('📊 Library size: ${_formatFileSize(libSize)}');

    return libSize;
  }

  Future<String> _getDistOutputPath() async {
    // Standard binary distribution directory structure
    final rootDir = '$ffiProjectDir/..';
    final distDir = '$rootDir/dist';
    final platformDir =
        '${config.platform.os}-${config.platform.rustTarget.split('-')[0]}';
    final modeDir = config.release ? 'release' : 'debug';
    return '$distDir/$platformDir/$modeDir/${config.platform.libFileName}';
  }

  Future<void> _copyHeaderFile() async {
    final sourceHeader = File('$ffiProjectDir/include/dart_quic_ffi.h');
    final destHeader = File(
      '$ffiProjectDir/../dart-quic/include/dart_quic_ffi.h',
    );

    if (!await sourceHeader.exists()) {
      _log('⚠️  Header file not found: ${sourceHeader.path}');
      return;
    }

    // Ensure destination directory exists
    await destHeader.parent.create(recursive: true);
    await sourceHeader.copy(destHeader.path);
    _log('📄 Header copied to: ${destHeader.path}');
  }

  void _log(String message) {
    print(message);
  }
}

// ============================================================================
// Batch Builder
// ============================================================================

/// Batch builder for multiple platforms
class BatchBuilder {
  final BuildConfig baseConfig;
  final String ffiProjectDir;

  BatchBuilder(this.baseConfig, this.ffiProjectDir);

  /// Build multiple platforms according to preset
  Future<List<BuildResult>> buildPreset(BuildPreset preset) async {
    final platforms = preset.platforms;

    print('🚀 Starting batch build: ${preset.description}');
    print('📋 Platforms: ${platforms.map((p) => p.name).join(', ')}');

    final results = <BuildResult>[];
    final startTime = DateTime.now();

    for (final platform in platforms) {
      print('\n${'=' * 60}');
      print('🔨 Building ${platform.name}...');
      print('=' * 60);

      final platformConfig = baseConfig.copyWith(platform: platform);
      final builder = NativeLibraryBuilder(platformConfig, ffiProjectDir);
      final result = await builder.build();

      results.add(result);

      final icon = result.success ? '✅' : '❌';
      final duration = '${result.duration.inSeconds}s';
      print('$icon ${platform.name} completed in $duration');
    }

    _printBatchSummary(results, DateTime.now().difference(startTime));
    return results;
  }

  void _printBatchSummary(List<BuildResult> results, Duration totalDuration) {
    print('\n${'=' * 60}');
    print('📊 BUILD SUMMARY');
    print('=' * 60);

    final successful = results.where((r) => r.success).length;
    final failed = results.length - successful;

    print(
      'Total time: ${totalDuration.inMinutes}m ${totalDuration.inSeconds % 60}s',
    );
    print('✅ Successful: $successful');
    print('❌ Failed: $failed');

    if (failed > 0) {
      print('\n❌ Failed builds:');
      for (final result in results.where((r) => !r.success)) {
        print('   ${result.platform.name}: ${result.error}');
      }
    }

    print('\n📦 Successful builds:');
    for (final result in results.where((r) => r.success)) {
      final size = result.libSize != null
          ? ' (${_formatFileSize(result.libSize!)})'
          : '';
      print('   ✅ ${result.platform.name}$size');
    }

    if (failed == 0) {
      print('\n🎉 All builds completed successfully!');
    }
  }
}

// ============================================================================
// Utilities
// ============================================================================

TargetPlatform _getCurrentPlatform() {
  if (Platform.isWindows) {
    return Platform.version.contains('x64')
        ? TargetPlatform.windowsX64
        : TargetPlatform.windowsX86;
  }
  if (Platform.isMacOS) {
    // Detect Apple Silicon vs Intel
    return TargetPlatform.macosArm64; // Default to ARM64, could be improved
  }
  if (Platform.isLinux) {
    return TargetPlatform.linuxX64; // Default to x64
  }
  throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
}

String _formatFileSize(int bytes) {
  if (bytes < 1024) return '${bytes}B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)}KB';
  return '${(bytes / (1024 * 1024)).toStringAsFixed(1)}MB';
}

String _findProjectDir() {
  final currentDir = Directory.current.path;
  final candidates = [
    '$currentDir/../dart-quic-ffi',
    '$currentDir/dart-quic-ffi',
    './dart-quic-ffi',
  ];

  for (final candidate in candidates) {
    if (Directory(candidate).existsSync()) {
      return candidate;
    }
  }

  throw Exception(
    'FFI project directory not found. Searched: ${candidates.join(', ')}',
  );
}

// ============================================================================
// Command Line Interface
// ============================================================================

/// Create argument parser
ArgParser _createArgParser() {
  final parser = ArgParser()
    ..addOption(
      'platform',
      abbr: 'p',
      help: 'Target platform (see -l for list)',
    )
    ..addFlag(
      'debug',
      abbr: 'd',
      help: 'Build in debug mode (default: release)',
      negatable: false,
    )
    ..addFlag(
      'verbose',
      abbr: 'v',
      help: 'Enable verbose output',
      negatable: false,
    )
    ..addFlag(
      'skip-existing',
      abbr: 's',
      help: 'Skip builds if output is up to date',
      negatable: false,
    )
    ..addOption('output', abbr: 'o', help: 'Custom output directory')
    ..addFlag(
      'list-platforms',
      abbr: 'l',
      help: 'List all supported platforms',
      negatable: false,
    )
    ..addFlag('list-presets', help: 'List all build presets', negatable: false)
    ..addFlag(
      'presets',
      abbr: 'P',
      help: 'List all build presets (short form)',
      negatable: false,
      hide: true,
    )
    ..addFlag('help', abbr: 'h', help: 'Show this help', negatable: false);

  return parser;
}

Future<void> main(List<String> arguments) async {
  final parser = _createArgParser();

  try {
    final results = parser.parse(arguments);

    // Handle help
    if (results['help'] || arguments.isEmpty) {
      _printUsage(parser);
      exit(0);
    }

    // Handle list commands
    if (results['list-platforms']) {
      _listPlatforms();
      exit(0);
    }

    if (results['list-presets'] || results['presets']) {
      _listPresets();
      exit(0);
    }

    final ffiProjectDir = _findProjectDir();

    // Parse configuration from arguments
    final config = _buildConfigFromArgs(results);

    // Determine if this is a preset build or single platform build
    final remainingArgs = results.rest;
    if (remainingArgs.isNotEmpty) {
      final firstArg = remainingArgs.first;

      // Try to parse as preset first
      try {
        final preset = BuildPreset.values.firstWhere((p) => p.name == firstArg);
        // Batch build
        final batchBuilder = BatchBuilder(config, ffiProjectDir);
        final batchResults = await batchBuilder.buildPreset(preset);

        final failed = batchResults.where((r) => !r.success).length;
        exit(failed > 0 ? 1 : 0);
      } catch (e) {
        // Not a preset, check if it's a platform name
        try {
          final platform = TargetPlatform.values.firstWhere(
            (p) => p.name == firstArg || p.os == firstArg,
          );
          final platformConfig = config.copyWith(platform: platform);
          final builder = NativeLibraryBuilder(platformConfig, ffiProjectDir);
          final result = await builder.build();
          exit(result.success ? 0 : 1);
        } catch (e) {
          print('❌ Unknown preset or platform: $firstArg');
          _printUsage(parser);
          exit(1);
        }
      }
    } else if (results.wasParsed('platform')) {
      // Single platform build specified with --platform
      final builder = NativeLibraryBuilder(config, ffiProjectDir);
      final result = await builder.build();
      exit(result.success ? 0 : 1);
    } else {
      // No preset or platform specified
      print('❌ Please specify a preset or platform');
      _printUsage(parser);
      exit(1);
    }
  } catch (e) {
    print('❌ Error: $e');
    _printUsage(parser);
    exit(1);
  }
}

BuildConfig _buildConfigFromArgs(ArgResults results) {
  TargetPlatform platform = _getCurrentPlatform();

  // Parse platform if specified
  if (results.wasParsed('platform')) {
    final platformName = results['platform'] as String;
    platform = TargetPlatform.values.firstWhere(
      (p) => p.name == platformName || p.os == platformName,
      orElse: () => throw ArgumentError('Unknown platform: $platformName'),
    );
  }

  return BuildConfig(
    platform: platform,
    release: !results['debug'],
    verbose: results['verbose'],
    outputDir: results['output'] as String?,
    skipExisting: results['skip-existing'],
  );
}

void _printUsage(ArgParser parser) {
  print('''
Unified Native Library Builder for dart-quic-ffi

Usage: 
  dart run builder.dart <preset>                    # Batch build
  dart run builder.dart -p <platform>               # Single platform build
  dart run builder.dart <platform>                  # Single platform build (shorthand)

Presets:
  all       Build for all platforms
  mobile    Build for mobile platforms (Android + iOS) 
  desktop   Build for desktop platforms (Windows + macOS + Linux)
  ios       Build for iOS platforms only
  android   Build for Android platforms only
  current   Build for current platform only

Options:
${parser.usage}

Examples:
  dart run builder.dart mobile                      # Build all mobile platforms
  dart run builder.dart androidArm64                # Build single platform (shorthand)
  dart run builder.dart -p androidArm64             # Build single platform
  dart run builder.dart ios -d -v                   # Build iOS in debug mode
  dart run builder.dart all -s                      # Skip up-to-date builds
  dart run builder.dart -l                          # List platforms
  dart run builder.dart -P                          # List presets
''');
}

void _listPlatforms() {
  print('Supported platforms:');
  for (final platform in TargetPlatform.values) {
    final libType = platform.requiresStaticLib ? 'static' : 'dynamic';
    print(
      '  ${platform.name.padRight(15)} -> ${platform.os} (${platform.rustTarget}) [$libType]',
    );
  }
}

void _listPresets() {
  print('Available build presets:');
  for (final preset in BuildPreset.values) {
    final platformCount = preset.platforms.length;
    print(
      '  ${preset.name.padRight(8)} -> ${preset.description} ($platformCount platforms)',
    );
  }
}
