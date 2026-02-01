import 'dart:async';

import 'package:dart_quic/src/common/quic_endpoint.dart';

import '../common/socket_address.dart';
import '../core/quic_message_processor.dart';

final class ClientConfig {
  final SocketAddress clientAddr;
  final SocketAddress serverAddr;
  final String serverName;
  final bool skipServerVerification;

  ClientConfig({
    required this.clientAddr,
    required this.serverAddr,
    required this.serverName,
    this.skipServerVerification = false,
  });
}

class QuicClient {
  final QuicMessageProcessor _processor;
  final _response = <int, Completer>{};

  QuicClient._() : _processor = QuicMessageProcessor() {
    _processor.setTaskHandler(_handleResponse);
  }

  Future<void> _setup() => _processor.initialize();

  QuicEndpoint newEndpoint({required ClientConfig config}) {
    return QuicEndpoint();
  }

  void _handleResponse(QuicTaskResponse resp) {
    final task = _response.remove(resp.taskId);
    if (task != null) {
      task.complete(resp.buffer);
    }
  }

  Future<void> close() => _processor.dispose();

  static Future<QuicClient> create() async {
    final client = QuicClient._();
    await client._setup();
    return client;
  }
}
