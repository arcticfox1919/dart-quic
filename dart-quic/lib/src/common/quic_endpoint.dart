import 'package:dart_quic/src/common/quic_connection.dart';

final class QuicEndpoint {
  Future<QuicConnection> connect() async {
    return QuicConnection();
  }

  void close() {}
}
