final class SocketAddress {
  final String addr; // e.g. "127.0.0.1:8080" or "[::1]:8080"

  SocketAddress.v4(String ip, int port) : addr = '$ip:$port';

  SocketAddress.v6(String ip, int port) : addr = '[$ip]:$port';

  /// Parse socket address from string format.
  ///
  /// Supported formats:
  /// - IPv4: "127.0.0.1:8080", "192.168.1.1:80"
  /// - IPv6: "[::1]:8080", "[2001:db8::1]:443"
  ///
  /// Throws [ArgumentError] if the format is invalid.
  SocketAddress.parse(String addr) : addr = _validateAndNormalize(addr);

  static String _validateAndNormalize(String addr) {
    if (addr.isEmpty) {
      throw ArgumentError('Address string cannot be empty');
    }

    // IPv6 format: [ipv6]:port
    if (addr.startsWith('[')) {
      final closeIndex = addr.indexOf(']');
      if (closeIndex == -1 ||
          closeIndex == addr.length - 1 ||
          addr[closeIndex + 1] != ':') {
        throw ArgumentError('Invalid IPv6 format. Expected: [ipv6]:port');
      }
      final portStr = addr.substring(closeIndex + 2);
      final port = int.tryParse(portStr);
      if (port == null || port < 1 || port > 65535) {
        throw ArgumentError('Invalid port: $portStr');
      }
      return addr;
    }

    // IPv4 format: ip:port
    final colonIndex = addr.lastIndexOf(':');
    if (colonIndex == -1 || colonIndex == 0 || colonIndex == addr.length - 1) {
      throw ArgumentError('Invalid format. Expected: ip:port or [ipv6]:port');
    }

    final portStr = addr.substring(colonIndex + 1);
    final port = int.tryParse(portStr);
    if (port == null || port < 1 || port > 65535) {
      throw ArgumentError('Invalid port: $portStr');
    }

    return addr;
  }

  @override
  String toString() => addr;
}
