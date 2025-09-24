import 'dart:typed_data';

abstract interface class QuicBuffer {
  int get size;

  Uint8List get data;

  void destroy();
}
