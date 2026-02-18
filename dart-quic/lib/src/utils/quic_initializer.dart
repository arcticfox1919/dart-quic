import '../bindings/quic_ffi_bindings.dart';
import 'library_loader.dart';

class QuicInitializer {
  static var _initialized = false;
  static QuicFFIBindings? _bindings;
  static int _numberOfThreads = 0;

  static void initialize() {
    if (!_initialized) {
      _initialized = true;
      final dl = LibraryLoader.load();
      _bindings = QuicFFIBindings(dl);
    }
  }

  static void configure({
    int? numberOfThreads,
    int? tinyPoolSize,
    int? smallPoolSize,
    int? mediumPoolSize,
    int? largePoolSize,
    int? hugePoolSize,
    int? xLargePoolSize,
  }) {
    if (_check()) {
      _numberOfThreads = numberOfThreads ?? _numberOfThreads;
      _bindings!.dart_initialize_memory_manager_with_config(
        tinyPoolSize ?? 20,
        smallPoolSize ?? 20,
        mediumPoolSize ?? 20,
        largePoolSize ?? 10,
        hugePoolSize ?? 10,
        xLargePoolSize ?? 0,
      );
    }
  }

  static int get numberOfThreads => _numberOfThreads;

  static QuicFFIBindings get ffiBindings {
    _check();
    return _bindings!;
  }

  static bool _check() {
    if (_bindings == null) {
      throw StateError(
        'QuicInitializer not initialized. Call QuicInitializer.initialize() first.',
      );
    }
    return true;
  }
}
