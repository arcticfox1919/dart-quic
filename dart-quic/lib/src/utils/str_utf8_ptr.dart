
import 'dart:convert';
import 'dart:ffi';

import 'package:ffi/ffi.dart';

/// Extension method for converting a [String]
extension StrUtf8Ptr on String {

  int get bytesSize {
    final units = utf8.encode(this);
    return units.length;
  }

  Pointer<Utf8> toBytes({Allocator allocator = malloc}) {
    final units = utf8.encode(this);
    final result = allocator<Uint8>(units.length);
    final nativeString = result.asTypedList(units.length);
    nativeString.setAll(0, units);
    return result.cast();
  }
}