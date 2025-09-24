import 'dart:async';
import 'dart:ffi';

import 'package:dart_quic/src/bindings/quic_ffi_bindings.dart';

import '../core/quic_initializer.dart';

class QuicArena implements Allocator {
  /// Native memory under management by this [QuicArena].
  final List<(Pointer<NativeType>, int)> _managedMemoryPointers = [];

  final List<void Function()> _managedResourceReleaseCallbacks = [];

  bool _inUse = true;
  final QuicFFIBindings _bindings;

  QuicArena(this._bindings);

  @override
  Pointer<T> allocate<T extends NativeType>(int byteCount, {int? alignment}) {
    _ensureInUse();
    final p = _bindings.dart_allocate_memory(byteCount);
    _managedMemoryPointers.add((p, byteCount));
    return p.cast();
  }

  T using<T>(T resource, void Function(T) releaseCallback) {
    _ensureInUse();
    releaseCallback = Zone.current.bindUnaryCallback(releaseCallback);
    _managedResourceReleaseCallbacks.add(() => releaseCallback(resource));
    return resource;
  }

  /// Registers [releaseResourceCallback] to be executed on [releaseAll].
  void onReleaseAll(void Function() releaseResourceCallback) {
    _managedResourceReleaseCallbacks.add(releaseResourceCallback);
  }

  void releaseAll({bool reuse = false}) {
    if (!reuse) {
      _inUse = false;
    }
    while (_managedResourceReleaseCallbacks.isNotEmpty) {
      _managedResourceReleaseCallbacks.removeLast()();
    }
    for (final (p, size) in _managedMemoryPointers) {
      _bindings.dart_free_memory(p.cast(), size);
    }
    _managedMemoryPointers.clear();
  }

  /// Does nothing, invoke [releaseAll] instead.
  @override
  void free(Pointer<NativeType> pointer) {}

  void _ensureInUse() {
    if (!_inUse) {
      throw StateError(
        'QuicArena no longer in use, `releaseAll(reuse: false)` was called.',
      );
    }
  }
}

R autoRelease<R>(R Function(QuicArena) computation) {
  final arena = QuicArena(QuicInitializer.ffiBindings);
  var isAsync = false;
  try {
    final result = computation(arena);
    if (result is Future) {
      isAsync = true;
      return result.whenComplete(arena.releaseAll) as R;
    }
    return result;
  } finally {
    if (!isAsync) {
      arena.releaseAll();
    }
  }
}
