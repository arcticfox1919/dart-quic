import 'dart:async';
import 'dart:ffi';

import 'package:dart_quic/src/bindings/quic_ffi_bindings.dart';
import 'package:dart_quic/src/client/quic_client_config.dart';
import 'package:dart_quic/src/common/quic_result.dart';
import 'package:dart_quic/src/core/quic_initializer.dart';
import 'package:ffi/ffi.dart' as ffi;


class QuicClient {
  final QuicFFIBindings _bindings;
  final _arena = ffi.Arena();
  Pointer<Void>? clientPtr;

  QuicClient(QuicClientConfig config)
    : _bindings = QuicInitializer.ffiBindings {
    final resultPtr = ffi.calloc<QuicFfiResult>();
    try {
      final resultCode = _bindings.dart_quic_client_new(
        config.ffiConfig,
        resultPtr,
      );
      if (QuicResultCode.isSuccess(resultCode)) {
        clientPtr = resultPtr.ref.handle;
      } else {
        print(QuicResultCode.getMessage(resultCode));
      }
    } finally {
      config.dispose();
      ffi.calloc.free(resultPtr);
    }
  }
}
