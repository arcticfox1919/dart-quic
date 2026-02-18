import 'dart:io';

/// Generate FFI bindings for dart-quic-ffi library.
///
/// Usage:
///   dart run ffigen.dart
void main() async {
  final scriptDir = Directory.fromUri(Platform.script.resolve('./'));
  final dartQuicDir = Directory.fromUri(scriptDir.uri.resolve('../dart-quic/'));

  print('Generating FFI bindings...');
  print('  Working directory: ${dartQuicDir.path}');

  final result = await Process.run(
    'dart',
    ['run', 'ffigen', '--config', 'ffigen.yaml'],
    workingDirectory: dartQuicDir.path,
    runInShell: true,
  );

  stdout.write(result.stdout);
  stderr.write(result.stderr);

  if (result.exitCode != 0) {
    print('FFI generation failed with exit code: ${result.exitCode}');
    exit(result.exitCode);
  }

  print('Done!');
}
