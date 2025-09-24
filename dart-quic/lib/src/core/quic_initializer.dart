import 'dart:ffi';

import '../bindings/quic_ffi_bindings.dart';
import '../utils/library_loader.dart';

typedef _DartPostCObject =
    Pointer Function(
      Pointer<NativeFunction<Int8 Function(Int64, Pointer<Dart_CObject>)>>,
    );

class QuicInitializer {
  static var _initialized = false;
  static QuicFFIBindings? _bindings;
  static int _numberOfThreads = 0;

  static void initialize() {
    if (!_initialized) {
      _initialized = true;
      final dl = LibraryLoader.load();
      _bindings = QuicFFIBindings(dl);
      // Setup Dart post object function for communication
      final storeDartPostCObject = dl
          .lookupFunction<_DartPostCObject, _DartPostCObject>(
            'store_dart_post_cobject',
          );
      storeDartPostCObject(NativeApi.postCObject);
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
      throw StateError('');
    }
    return true;
  }
}
