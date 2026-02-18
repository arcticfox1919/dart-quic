import 'dart:ffi';

import 'package:dart_quic/src/bindings/quic_ffi_bindings.dart';
import 'package:dart_quic/src/utils/quic_initializer.dart';

/// A custom memory allocator that uses the QUIC FFI memory pool.
///
/// This allocator uses `dart_allocate_memory` and `dart_free_memory`
/// from the Rust FFI layer, which provides efficient pooled memory allocation.
///
/// Example:
/// ```dart
/// final allocator = QuicAllocator();
/// final ptr = allocator.allocate<Uint8>(1024);
/// try {
///   // Use ptr...
/// } finally {
///   allocator.free(ptr);
/// }
/// ```
///
/// Or use the [using] method for automatic cleanup:
/// ```dart
/// final result = allocator.using<Uint8, int>(1024, (ptr) {
///   // Use ptr, it will be automatically freed
///   return someComputation(ptr);
/// });
/// ```
class QuicAllocator implements Allocator {
  /// Track allocated memory sizes for proper deallocation.
  final Map<int, int> _allocations = {};

  final QuicFFIBindings _bindings;

  /// Create a new QuicAllocator.
  ///
  /// If [bindings] is not provided, uses the global bindings from [QuicInitializer].
  QuicAllocator([QuicFFIBindings? bindings])
    : _bindings = bindings ?? QuicInitializer.ffiBindings;

  /// Global shared instance for convenience.
  static QuicAllocator? _instance;

  /// Get the global shared QuicAllocator instance.
  static QuicAllocator get instance => _instance ??= QuicAllocator();

  @override
  Pointer<T> allocate<T extends NativeType>(int byteCount, {int? alignment}) {
    if (byteCount <= 0) {
      throw ArgumentError.value(byteCount, 'byteCount', 'Must be positive');
    }

    final ptr = _bindings.dart_allocate_memory(byteCount);
    if (ptr == nullptr) {
      throw StateError('Failed to allocate $byteCount bytes');
    }

    _allocations[ptr.address] = byteCount;
    return ptr.cast<T>();
  }

  @override
  void free(Pointer<NativeType> pointer) {
    if (pointer == nullptr) return;

    final size = _allocations.remove(pointer.address);
    if (size == null) {
      // Not tracked by this allocator, skip
      return;
    }

    _bindings.dart_free_memory(pointer.cast<Uint8>(), size);
  }

  /// Free all tracked allocations.
  ///
  /// Useful for cleanup in error scenarios.
  void freeAll() {
    for (final entry in _allocations.entries) {
      final ptr = Pointer<Uint8>.fromAddress(entry.key);
      _bindings.dart_free_memory(ptr, entry.value);
    }
    _allocations.clear();
  }

  /// Number of currently tracked allocations.
  int get allocationCount => _allocations.length;

  /// Total bytes currently allocated.
  int get totalAllocatedBytes =>
      _allocations.values.fold(0, (sum, size) => sum + size);

  /// Allocate memory, execute [computation], then automatically free the memory.
  ///
  /// Supports both sync and async computations.
  ///
  /// Example:
  /// ```dart
  /// final result = allocator.using<Uint8, int>(1024, (ptr) {
  ///   // Use ptr...
  ///   return someValue;
  /// });
  /// ```
  R using<T extends NativeType, R>(
    int byteCount,
    R Function(Pointer<T> ptr) computation,
  ) {
    final ptr = allocate<T>(byteCount);
    bool isAsync = false;

    try {
      final result = computation(ptr);
      if (result is Future) {
        isAsync = true;
        return (result.whenComplete(() => free(ptr))) as R;
      }
      return result;
    } finally {
      if (!isAsync) {
        free(ptr);
      }
    }
  }
}
