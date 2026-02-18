import 'package:dart_quic/src/common/quic_connection.dart';

final class QuicEndpoint {
  Future<QuicConn> connect() async {
    throw UnimplementedError('QuicEndpoint.connect is not implemented');
  }

  void close() {}
}
