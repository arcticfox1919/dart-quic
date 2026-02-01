import 'dart:ffi' as ffi;
import 'package:dart_quic/src/bindings/quic_ffi_bindings.dart';
import 'package:ffi/ffi.dart';

/// QUIC transport layer configuration
///
/// Configures various transport parameters for QUIC connections including
/// timeouts, stream limits, MTU discovery, and congestion control.
class QuicTransportConfig {
  // Use Arena for automatic memory management
  final Arena _arena = Arena();
  late final ffi.Pointer<QuicFfiTransportConfig> _config;

  /// Create a new transport configuration with default values
  QuicTransportConfig() {
    _config = _arena<QuicFfiTransportConfig>();
    _initializeDefaults();
  }

  void _initializeDefaults() {
    _config.ref.max_idle_timeout_ms = 30000; // 30 seconds
    _config.ref.keep_alive_interval_ms = 0; // Disabled by default
    _config.ref.max_concurrent_bi_streams = 100;
    _config.ref.max_concurrent_uni_streams = 100;
    _config.ref.stream_receive_window = 6291456; // 6 MB
    _config.ref.send_window = 12582912; // 12 MB
    _config.ref.initial_rtt_ms = 333; // 333 ms
    _config.ref.initial_mtu = 1200;
    _config.ref.min_mtu = 1200;
    _config.ref.enable_mtu_discovery = true;
    _config.ref.datagram_receive_buffer_size = 65536; // 64 KB
    _config.ref.datagram_send_buffer_size = 65536; // 64 KB
    _config.ref.congestion_controller = 0; // Cubic (default)
    _config.ref.allow_spin = false;
    _config.ref.enable_gso = false;
  }

  // ========== Timeout Configuration ==========

  /// Set maximum idle timeout in milliseconds
  ///
  /// Connection will be closed if no packets are received for this duration.
  QuicTransportConfig setMaxIdleTimeout(int milliseconds) {
    _config.ref.max_idle_timeout_ms = milliseconds;
    return this;
  }

  /// Set keep-alive interval in milliseconds
  ///
  /// If set to non-zero, keep-alive packets will be sent at this interval.
  QuicTransportConfig setKeepAliveInterval(int milliseconds) {
    _config.ref.keep_alive_interval_ms = milliseconds;
    return this;
  }

  // ========== Stream Limits ==========

  /// Set maximum concurrent bidirectional streams
  QuicTransportConfig setMaxConcurrentBiStreams(int max) {
    _config.ref.max_concurrent_bi_streams = max;
    return this;
  }

  /// Set maximum concurrent unidirectional streams
  QuicTransportConfig setMaxConcurrentUniStreams(int max) {
    _config.ref.max_concurrent_uni_streams = max;
    return this;
  }

  // ========== Window Configuration ==========

  /// Set stream receive window size in bytes
  QuicTransportConfig setStreamReceiveWindow(int bytes) {
    _config.ref.stream_receive_window = bytes;
    return this;
  }

  /// Set connection send window size in bytes
  QuicTransportConfig setSendWindow(int bytes) {
    _config.ref.send_window = bytes;
    return this;
  }

  // ========== RTT Configuration ==========

  /// Set initial round-trip time estimate in milliseconds
  QuicTransportConfig setInitialRtt(int milliseconds) {
    _config.ref.initial_rtt_ms = milliseconds;
    return this;
  }

  // ========== MTU Configuration ==========

  /// Set initial MTU (Maximum Transmission Unit) in bytes
  QuicTransportConfig setInitialMtu(int bytes) {
    _config.ref.initial_mtu = bytes;
    return this;
  }

  /// Set minimum MTU in bytes
  QuicTransportConfig setMinMtu(int bytes) {
    _config.ref.min_mtu = bytes;
    return this;
  }

  /// Enable or disable MTU discovery
  QuicTransportConfig setEnableMtuDiscovery(bool enable) {
    _config.ref.enable_mtu_discovery = enable;
    return this;
  }

  // ========== Datagram Configuration ==========

  /// Set datagram receive buffer size in bytes
  QuicTransportConfig setDatagramReceiveBufferSize(int bytes) {
    _config.ref.datagram_receive_buffer_size = bytes;
    return this;
  }

  /// Set datagram send buffer size in bytes
  QuicTransportConfig setDatagramSendBufferSize(int bytes) {
    _config.ref.datagram_send_buffer_size = bytes;
    return this;
  }

  // ========== Congestion Control ==========

  /// Set congestion controller algorithm
  ///
  /// - 0: Cubic (default, recommended)
  /// - 1: NewReno
  /// - 2: BBR
  QuicTransportConfig setCongestionController(int algorithm) {
    _config.ref.congestion_controller = algorithm;
    return this;
  }

  // ========== Advanced Options ==========

  /// Allow spin bit for RTT measurement
  QuicTransportConfig setAllowSpin(bool allow) {
    _config.ref.allow_spin = allow;
    return this;
  }

  /// Enable GSO (Generic Segmentation Offload)
  QuicTransportConfig setEnableGso(bool enable) {
    _config.ref.enable_gso = enable;
    return this;
  }

  // ========== Getters ==========

  /// Get the underlying FFI config pointer (internal use)
  ffi.Pointer<QuicFfiTransportConfig> get ffiConfig => _config;

  /// Get max idle timeout in milliseconds
  int get maxIdleTimeout => _config.ref.max_idle_timeout_ms;

  /// Get keep-alive interval in milliseconds
  int get keepAliveInterval => _config.ref.keep_alive_interval_ms;

  /// Get max concurrent bidirectional streams
  int get maxConcurrentBiStreams => _config.ref.max_concurrent_bi_streams;

  /// Get max concurrent unidirectional streams
  int get maxConcurrentUniStreams => _config.ref.max_concurrent_uni_streams;

  // ========== Cleanup ==========

  /// Free all allocated resources
  ///
  /// IMPORTANT: Must be called when the config is no longer needed.
  void dispose() {
    _arena.releaseAll();
  }

  @override
  String toString() {
    return 'QuicTransportConfig('
        'maxIdleTimeout: ${_config.ref.max_idle_timeout_ms}ms, '
        'maxBiStreams: ${_config.ref.max_concurrent_bi_streams}, '
        'maxUniStreams: ${_config.ref.max_concurrent_uni_streams}'
        ')';
  }
}
