//! QUIC Configuration Module
//!
//! Provides unified certificate and connection configuration for both clients and servers.
//! Design goals: simple, secure, and easy FFI binding.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;

use crate::error::QuicError;
use crate::types::QuicResult;

// ============================================================================
// Certificate Source (Internal Use)
// ============================================================================

/// Certificate source
#[derive(Clone)]
pub(crate) enum CertificateSource {
    /// Self-signed certificate (for development/testing)
    SelfSigned { subject_alt_names: Vec<String> },
    /// Load from file (for production)
    FromFile { cert_path: String, key_path: String },
    /// Load from memory
    FromMemory { cert_der: Vec<u8>, key_der: Vec<u8> },
}

/// Trust source (for clients)
#[derive(Clone)]
pub(crate) enum TrustSource {
    /// Use system root certificates (production recommended)
    SystemRoots,
    /// Trust specified CA certificate
    CustomCa(Vec<u8>),
    /// Skip verification (testing only! dangerous!)
    SkipVerification,
}

// ============================================================================
// MTU Discovery Configuration
// ============================================================================

/// MTU Discovery Configuration
///
/// Controls QUIC path MTU discovery behavior for optimizing transmission efficiency.
#[derive(Clone, Debug)]
pub struct MtuDiscoveryConfig {
    /// MTU discovery interval (default 600 seconds)
    pub interval: Duration,
    /// MTU upper bound (default 1452, Ethernet MTU minus IP/UDP headers)
    pub upper_bound: u16,
    /// Black hole detection cooldown period (default 60 seconds)
    pub black_hole_cooldown: Duration,
    /// Minimum change threshold (default 20)
    pub minimum_change: u16,
}

impl Default for MtuDiscoveryConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(600),
            upper_bound: 1452,
            black_hole_cooldown: Duration::from_secs(60),
            minimum_change: 20,
        }
    }
}

impl MtuDiscoveryConfig {
    /// Create default configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set MTU discovery interval
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Set MTU upper bound
    pub fn with_upper_bound(mut self, upper_bound: u16) -> Self {
        self.upper_bound = upper_bound.min(65527);
        self
    }

    /// Set black hole detection cooldown period
    pub fn with_black_hole_cooldown(mut self, cooldown: Duration) -> Self {
        self.black_hole_cooldown = cooldown;
        self
    }
}

// ============================================================================
// ACK Frequency Configuration
// ============================================================================

/// ACK Frequency Configuration
///
/// Controls the frequency at which peers send ACKs, can reduce ACK count to improve efficiency.
/// Requires peer support for QUIC ACK Frequency extension.
#[derive(Clone, Debug)]
pub struct AckFrequencyConfig {
    /// ACK trigger threshold (number of ack-eliciting packets received before sending ACK)
    pub ack_eliciting_threshold: u32,
    /// Maximum ACK delay
    pub max_ack_delay: Option<Duration>,
    /// Reordering threshold (number of out-of-order packets received before immediately sending ACK)
    pub reordering_threshold: u32,
}

impl Default for AckFrequencyConfig {
    fn default() -> Self {
        Self {
            ack_eliciting_threshold: 1,
            max_ack_delay: None,
            reordering_threshold: 2,
        }
    }
}

// ============================================================================
// Congestion Control Algorithm
// ============================================================================

/// Congestion control algorithm
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CongestionControllerType {
    /// Cubic algorithm (default, suitable for most scenarios)
    Cubic,
    /// NewReno algorithm (classic algorithm)
    NewReno,
    /// BBR algorithm (suitable for high bandwidth, high latency networks)
    Bbr,
}

impl Default for CongestionControllerType {
    fn default() -> Self {
        Self::Cubic
    }
}

// ============================================================================
// Transport Configuration (General)
// ============================================================================

/// QUIC Transport Layer Configuration
///
/// Can be used for both clients and servers, controlling connection timeout, flow control, MTU, congestion control, and other parameters.
/// Includes all major configuration items supported by quinn::TransportConfig.
///
/// # Example
/// ```rust
/// let config = QuicTransportConfig::default()
///     .with_max_idle_timeout(Duration::from_secs(30))
///     .with_keep_alive_interval(Some(Duration::from_secs(10)))
///     .with_congestion_controller(CongestionControllerType::Bbr);
/// ```
#[derive(Clone)]
pub struct QuicTransportConfig {
    // ===== Connection Management =====
    /// Idle timeout (default 30 seconds)
    pub max_idle_timeout: Duration,
    /// Keep-alive interval (default None, disabled)
    pub keep_alive_interval: Option<Duration>,

    // ===== Flow Control =====
    /// Maximum concurrent bidirectional streams (default 100)
    pub max_concurrent_bi_streams: u32,
    /// Maximum concurrent unidirectional streams (default 100)
    pub max_concurrent_uni_streams: u32,
    /// Per-stream receive window size (bytes, default 1MB)
    pub stream_receive_window: u32,
    /// Connection-level receive window size (bytes, default maximum)
    pub receive_window: u64,
    /// Send window size (bytes, default 8MB)
    pub send_window: u64,
    /// Whether to enable fair scheduling (default true)
    pub send_fairness: bool,

    // ===== RTT and Loss Detection =====
    /// Initial RTT estimate (default 333ms)
    pub initial_rtt: Duration,
    /// Packet threshold for loss detection (default 3)
    pub packet_threshold: u32,
    /// Time threshold factor for loss detection (default 9/8)
    pub time_threshold: f32,
    /// Persistent congestion threshold (default 3 PTOs)
    pub persistent_congestion_threshold: u32,

    // ===== MTU Configuration =====
    /// Initial MTU (default 1200)
    pub initial_mtu: u16,
    /// Minimum MTU (default 1200)
    pub min_mtu: u16,
    /// MTU discovery configuration (None disables)
    pub mtu_discovery: Option<MtuDiscoveryConfig>,

    // ===== Datagram Configuration =====
    /// Datagram receive buffer size (None disables Datagram)
    pub datagram_receive_buffer_size: Option<usize>,
    /// Datagram send buffer size (default 1MB)
    pub datagram_send_buffer_size: usize,

    // ===== Encryption and Protocol =====
    /// ALPN protocol list
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Crypto buffer size (default 16KB)
    pub crypto_buffer_size: usize,

    // ===== Congestion Control =====
    /// Congestion control algorithm
    pub congestion_controller: CongestionControllerType,

    // ===== Privacy and Debugging =====
    /// Whether to allow spin bit (default true)
    pub allow_spin: bool,
    /// Whether to enable GSO (default true)
    pub enable_segmentation_offload: bool,

    // ===== ACK Frequency (Optional) =====
    /// ACK frequency configuration (requires peer support for extension)
    pub ack_frequency: Option<AckFrequencyConfig>,
}

impl Default for QuicTransportConfig {
    fn default() -> Self {
        // Keep consistent with quinn defaults
        const EXPECTED_RTT: u32 = 100; // ms
        const MAX_STREAM_BANDWIDTH: u32 = 12500 * 1000; // 12.5 MB/s
        const STREAM_RWND: u32 = MAX_STREAM_BANDWIDTH / 1000 * EXPECTED_RTT; // ~1.25 MB

        Self {
            // Connection management
            max_idle_timeout: Duration::from_secs(30),
            keep_alive_interval: None, // quinn default disabled

            // Flow control
            max_concurrent_bi_streams: 100,
            max_concurrent_uni_streams: 100,
            stream_receive_window: STREAM_RWND,
            receive_window: u64::MAX, // VarInt::MAX
            send_window: (8 * STREAM_RWND) as u64,
            send_fairness: true,

            // RTT and loss detection
            initial_rtt: Duration::from_millis(333),
            packet_threshold: 3,
            time_threshold: 9.0 / 8.0,
            persistent_congestion_threshold: 3,

            // MTU
            initial_mtu: 1200,
            min_mtu: 1200,
            mtu_discovery: Some(MtuDiscoveryConfig::default()),

            // Datagram
            datagram_receive_buffer_size: Some(STREAM_RWND as usize),
            datagram_send_buffer_size: 1024 * 1024,

            // Encryption and protocol
            alpn_protocols: vec![b"h3".to_vec(), b"hq-29".to_vec()],
            crypto_buffer_size: 16 * 1024,

            // Congestion control
            congestion_controller: CongestionControllerType::Cubic,

            // Privacy and debugging
            allow_spin: true,
            enable_segmentation_offload: true,

            // ACK frequency
            ack_frequency: None,
        }
    }
}

impl QuicTransportConfig {
    /// Create default configuration
    pub fn new() -> Self {
        Self::default()
    }

    // ===== Connection Management =====

    /// Set idle timeout
    pub fn with_max_idle_timeout(mut self, timeout: Duration) -> Self {
        self.max_idle_timeout = timeout;
        self
    }

    /// Set keep-alive interval (None disables keep-alive)
    pub fn with_keep_alive_interval(mut self, interval: Option<Duration>) -> Self {
        self.keep_alive_interval = interval;
        self
    }

    // ===== Flow Control =====

    /// Set maximum concurrent bidirectional streams
    pub fn with_max_concurrent_bi_streams(mut self, count: u32) -> Self {
        self.max_concurrent_bi_streams = count;
        self
    }

    /// Set maximum concurrent unidirectional streams
    pub fn with_max_concurrent_uni_streams(mut self, count: u32) -> Self {
        self.max_concurrent_uni_streams = count;
        self
    }

    /// Set per-stream receive window size (bytes)
    pub fn with_stream_receive_window(mut self, size: u32) -> Self {
        self.stream_receive_window = size;
        self
    }

    /// Set connection-level receive window size (bytes)
    pub fn with_receive_window(mut self, size: u64) -> Self {
        self.receive_window = size;
        self
    }

    /// Set send window size (bytes)
    pub fn with_send_window(mut self, size: u64) -> Self {
        self.send_window = size;
        self
    }

    /// Set whether to enable fair scheduling
    pub fn with_send_fairness(mut self, enabled: bool) -> Self {
        self.send_fairness = enabled;
        self
    }

    // ===== RTT and Loss Detection =====

    /// Set initial RTT estimate
    pub fn with_initial_rtt(mut self, rtt: Duration) -> Self {
        self.initial_rtt = rtt;
        self
    }

    /// Set packet threshold for loss detection
    pub fn with_packet_threshold(mut self, threshold: u32) -> Self {
        self.packet_threshold = threshold;
        self
    }

    /// Set time threshold factor for loss detection
    pub fn with_time_threshold(mut self, threshold: f32) -> Self {
        self.time_threshold = threshold;
        self
    }

    // ===== MTU Configuration =====

    /// Set initial MTU
    pub fn with_initial_mtu(mut self, mtu: u16) -> Self {
        self.initial_mtu = mtu.max(1200);
        self
    }

    /// Set minimum MTU
    pub fn with_min_mtu(mut self, mtu: u16) -> Self {
        self.min_mtu = mtu.max(1200);
        self
    }

    /// Set MTU discovery configuration (None disables MTU discovery)
    pub fn with_mtu_discovery(mut self, config: Option<MtuDiscoveryConfig>) -> Self {
        self.mtu_discovery = config;
        self
    }

    // ===== Datagram Configuration =====

    /// Set Datagram receive buffer size (None disables Datagram)
    pub fn with_datagram_receive_buffer_size(mut self, size: Option<usize>) -> Self {
        self.datagram_receive_buffer_size = size;
        self
    }

    /// Set Datagram send buffer size
    pub fn with_datagram_send_buffer_size(mut self, size: usize) -> Self {
        self.datagram_send_buffer_size = size;
        self
    }

    // ===== Protocol Configuration =====

    /// Set ALPN protocol list
    pub fn with_alpn_protocols(mut self, protocols: Vec<&str>) -> Self {
        self.alpn_protocols = protocols.into_iter().map(|s| s.as_bytes().to_vec()).collect();
        self
    }

    // ===== Congestion Control =====

    /// Set congestion control algorithm
    pub fn with_congestion_controller(mut self, controller: CongestionControllerType) -> Self {
        self.congestion_controller = controller;
        self
    }

    // ===== Privacy and Debugging =====

    /// Set whether to allow spin bit
    pub fn with_allow_spin(mut self, allow: bool) -> Self {
        self.allow_spin = allow;
        self
    }

    /// Set whether to enable GSO
    pub fn with_enable_segmentation_offload(mut self, enabled: bool) -> Self {
        self.enable_segmentation_offload = enabled;
        self
    }

    // ===== ACK Frequency =====

    /// Set ACK frequency configuration
    pub fn with_ack_frequency(mut self, config: Option<AckFrequencyConfig>) -> Self {
        self.ack_frequency = config;
        self
    }

    /// Apply to Quinn transport configuration
    pub(crate) fn apply_to_transport(&self, transport: &mut quinn::TransportConfig) {
        use quinn::VarInt;

        // Connection management
        if let Ok(timeout) = self.max_idle_timeout.try_into() {
            transport.max_idle_timeout(Some(timeout));
        }
        transport.keep_alive_interval(self.keep_alive_interval);

        // Flow control
        transport.max_concurrent_bidi_streams(VarInt::from_u32(self.max_concurrent_bi_streams));
        transport.max_concurrent_uni_streams(VarInt::from_u32(self.max_concurrent_uni_streams));
        transport.stream_receive_window(VarInt::from_u32(self.stream_receive_window));
        if let Ok(window) = VarInt::try_from(self.receive_window) {
            transport.receive_window(window);
        }
        transport.send_window(self.send_window);
        transport.send_fairness(self.send_fairness);

        // RTT and loss detection
        transport.initial_rtt(self.initial_rtt);
        transport.packet_threshold(self.packet_threshold);
        transport.time_threshold(self.time_threshold);
        transport.persistent_congestion_threshold(self.persistent_congestion_threshold);

        // MTU
        transport.initial_mtu(self.initial_mtu);
        transport.min_mtu(self.min_mtu);
        if let Some(ref mtu_config) = self.mtu_discovery {
            let mut quinn_mtu = quinn::MtuDiscoveryConfig::default();
            quinn_mtu.interval(mtu_config.interval);
            quinn_mtu.upper_bound(mtu_config.upper_bound);
            quinn_mtu.black_hole_cooldown(mtu_config.black_hole_cooldown);
            quinn_mtu.minimum_change(mtu_config.minimum_change);
            transport.mtu_discovery_config(Some(quinn_mtu));
        } else {
            transport.mtu_discovery_config(None);
        }

        // Datagram
        transport.datagram_receive_buffer_size(self.datagram_receive_buffer_size);
        transport.datagram_send_buffer_size(self.datagram_send_buffer_size);

        // Encryption
        transport.crypto_buffer_size(self.crypto_buffer_size);

        // Congestion control
        let cc_factory: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
            match self.congestion_controller {
                CongestionControllerType::Cubic => {
                    Arc::new(quinn::congestion::CubicConfig::default())
                }
                CongestionControllerType::NewReno => {
                    Arc::new(quinn::congestion::NewRenoConfig::default())
                }
                CongestionControllerType::Bbr => {
                    Arc::new(quinn::congestion::BbrConfig::default())
                }
            };
        transport.congestion_controller_factory(cc_factory);

        // Privacy
        transport.allow_spin(self.allow_spin);
        transport.enable_segmentation_offload(self.enable_segmentation_offload);

        // ACK frequency
        if let Some(ref ack_config) = self.ack_frequency {
            let mut quinn_ack = quinn::AckFrequencyConfig::default();
            quinn_ack.ack_eliciting_threshold(VarInt::from_u32(ack_config.ack_eliciting_threshold));
            quinn_ack.max_ack_delay(ack_config.max_ack_delay);
            quinn_ack.reordering_threshold(VarInt::from_u32(ack_config.reordering_threshold));
            transport.ack_frequency_config(Some(quinn_ack));
        }
    }
}

// ============================================================================
// Certificate Utility Functions
// ============================================================================

/// Generate self-signed certificate
pub(crate) fn generate_self_signed(
    subject_alt_names: Vec<String>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), QuicError> {
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|e| QuicError::unknown(format!("Failed to generate cert: {}", e)))?;

    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    Ok((vec![cert_der], key_der))
}

/// Load certificates from PEM file
pub(crate) fn load_certs_from_pem(path: &Path) -> Result<Vec<CertificateDer<'static>>, QuicError> {
    let cert_data = fs::read(path)
        .map_err(|e| QuicError::unknown(format!("Failed to read cert file: {}", e)))?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_data.as_slice())
        .filter_map(|r| r.ok())
        .collect();

    if certs.is_empty() {
        return Err(QuicError::from_code(QuicResult::InvalidParameter));
    }

    Ok(certs)
}

/// Load private key from PEM file
pub(crate) fn load_key_from_pem(path: &Path) -> Result<PrivateKeyDer<'static>, QuicError> {
    let key_data = fs::read(path)
        .map_err(|e| QuicError::unknown(format!("Failed to read key file: {}", e)))?;

    // Try various private key formats
    let mut reader = key_data.as_slice();

    // Try PKCS#8
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .filter_map(|r| r.ok())
        .next()
    {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }

    // Try RSA
    reader = key_data.as_slice();
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)
        .filter_map(|r| r.ok())
        .next()
    {
        return Ok(PrivateKeyDer::Pkcs1(key));
    }

    // Try EC
    reader = key_data.as_slice();
    if let Some(key) = rustls_pemfile::ec_private_keys(&mut reader)
        .filter_map(|r| r.ok())
        .next()
    {
        return Ok(PrivateKeyDer::Sec1(key));
    }

    Err(QuicError::from_code(QuicResult::InvalidParameter))
}

/// Load certificate from DER bytes
pub(crate) fn load_cert_from_der(der: Vec<u8>) -> CertificateDer<'static> {
    CertificateDer::from(der)
}

/// Load private key from DER bytes (PKCS#8 format)
pub(crate) fn load_key_from_der(der: Vec<u8>) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))
}

/// Load certificate from DER file
pub(crate) fn load_cert_der_from_file(path: &Path) -> Result<Vec<u8>, QuicError> {
    fs::read(path).map_err(|e| {
        QuicError::unknown(format!("Failed to read DER certificate file '{}': {}", path.display(), e))
    })
}

/// Load private key from DER file
pub(crate) fn load_key_der_from_file(path: &Path) -> Result<Vec<u8>, QuicError> {
    fs::read(path).map_err(|e| {
        QuicError::unknown(format!("Failed to read DER key file '{}': {}", path.display(), e))
    })
}

/// Create root certificate store
pub(crate) fn create_root_store(ca_cert: &CertificateDer<'static>) -> Result<RootCertStore, QuicError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(ca_cert.clone())
        .map_err(|e| QuicError::unknown(format!("Invalid CA certificate: {}", e)))?;
    Ok(roots)
}

// ============================================================================
// Skip Verification Implementation (Testing Only)
// ============================================================================

/// Verifier that skips server certificate verification
///
/// ⚠️ **Warning**: This implementation is for development/testing only, never use in production!
#[derive(Debug)]
pub(crate) struct SkipServerVerification(pub(crate) Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // ⚠️ Dangerous: unconditionally trust any certificate
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

// ============================================================================
// Quinn Client Config Builder
// ============================================================================

/// QUIC Client Configuration Builder
///
/// Used to build `quinn::ClientConfig`, can be reused by `QuicClient` and `QuicEndpoint`.
///
/// # Example
///
/// ```rust
/// use dart_quic_native::{QuicClient, QuicClientConfigBuilder};
///
/// // Use system root certificates (production recommended)
/// let client = QuicClient::builder()
///     .with_system_roots()
///     .bind("0.0.0.0:0")?;
///
/// // Use custom CA
/// let client = QuicClient::builder()
///     .with_custom_ca(ca_der_bytes)
///     .bind("0.0.0.0:0")?;
///
/// // Skip verification (testing only)
/// let client = QuicClient::builder()
///     .with_skip_verification()
///     .bind("0.0.0.0:0")?;
///
/// // If only ClientConfig is needed (for QuicEndpoint)
/// let config = QuicClient::builder()
///     .with_system_roots()
///     .build_config()?;
/// ```
pub struct QuicClientConfigBuilder {
    trust_source: TrustSource,
    transport_config: QuicTransportConfig,
    client_cert: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    bind_addr: std::net::SocketAddr,
}

impl QuicClientConfigBuilder {
    /// Create a new builder (default uses system root certificates)
    pub fn new() -> Self {
        Self {
            trust_source: TrustSource::SystemRoots,
            transport_config: QuicTransportConfig::default(),
            client_cert: None,
            bind_addr: "0.0.0.0:0".parse().unwrap(),
        }
    }

    // ========== Trust Configuration ==========

    /// Use system root certificates to verify server (production recommended)
    ///
    /// Used for **verifying server identity** (one-way authentication).
    pub fn with_system_roots(mut self) -> Self {
        self.trust_source = TrustSource::SystemRoots;
        self
    }

    /// Trust specified CA certificate (DER-encoded memory data)
    ///
    /// Used for **verifying server identity** (one-way authentication).
    /// Client uses this CA to verify whether the server certificate is trusted.
    ///
    /// # Parameters
    /// - `ca_cert_der`: DER-encoded bytes of CA certificate
    ///
    /// # Note
    /// This is a trust configuration, not a client certificate. For mTLS mutual authentication,
    /// also use the `with_client_cert*` series of methods.
    pub fn with_custom_ca(mut self, ca_cert_der: Vec<u8>) -> Self {
        self.trust_source = TrustSource::CustomCa(ca_cert_der);
        self
    }

    /// Load and trust CA certificate from PEM file
    ///
    /// Used for **verifying server identity** (one-way authentication).
    /// Client uses this CA to verify whether the server certificate is trusted.
    ///
    /// # Parameters
    /// - `ca_path`: CA certificate PEM file path
    ///
    /// # Note
    /// This is a trust configuration, not a client certificate. For mTLS mutual authentication,
    /// also use the `with_client_cert*` series of methods.
    pub fn with_custom_ca_pem_file(mut self, ca_path: &str) -> Result<Self, QuicError> {
        let certs = load_certs_from_pem(std::path::Path::new(ca_path))?;
        if let Some(cert) = certs.into_iter().next() {
            self.trust_source = TrustSource::CustomCa(cert.to_vec());
        }
        Ok(self)
    }

    /// Load and trust CA certificate from DER file
    ///
    /// Used for **verifying server identity** (one-way authentication).
    /// Client uses this CA to verify whether the server certificate is trusted.
    ///
    /// # Parameters
    /// - `ca_path`: CA certificate DER file path
    ///
    /// # Note
    /// This is a trust configuration, not a client certificate. For mTLS mutual authentication,
    /// also use the `with_client_cert*` series of methods.
    pub fn with_custom_ca_der_file(mut self, ca_path: &str) -> Result<Self, QuicError> {
        let der_bytes = load_cert_der_from_file(std::path::Path::new(ca_path))?;
        self.trust_source = TrustSource::CustomCa(der_bytes);
        Ok(self)
    }

    /// Skip server certificate verification (⚠️ testing only!)
    pub fn with_skip_verification(mut self) -> Self {
        self.trust_source = TrustSource::SkipVerification;
        self
    }

    // ========== Client Certificate (mTLS) ==========

    /// Set client certificate (DER-encoded memory data)
    ///
    /// Used for **proving client identity to server** (mTLS mutual authentication).
    /// Server will verify this certificate to confirm client identity.
    ///
    /// # Parameters
    /// - `cert_der`: DER-encoded bytes of client certificate
    /// - `key_der`: DER-encoded bytes of client private key (PKCS#8 format)
    ///
    /// # Note
    /// This is the client's identity certificate, not a trust configuration.
    /// To verify server, use `with_custom_ca*` or `with_system_roots`.
    pub fn with_client_cert(mut self, cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
        let cert = load_cert_from_der(cert_der);
        let key = load_key_from_der(key_der);
        self.client_cert = Some((vec![cert], key));
        self
    }

    /// Load client certificate from PEM file
    ///
    /// Used for **proving client identity to server** (mTLS mutual authentication).
    /// Server will verify this certificate to confirm client identity.
    ///
    /// # Parameters
    /// - `cert_path`: Client certificate PEM file path
    /// - `key_path`: Client private key PEM file path
    ///
    /// # Note
    /// This is the client's identity certificate, not a trust configuration.
    /// To verify server, use `with_custom_ca*` or `with_system_roots`.
    pub fn with_client_cert_pem_files(
        mut self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self, QuicError> {
        let certs = load_certs_from_pem(std::path::Path::new(cert_path))?;
        let key = load_key_from_pem(std::path::Path::new(key_path))?;
        self.client_cert = Some((certs, key));
        Ok(self)
    }

    /// Load client certificate from DER file
    ///
    /// Used for **proving client identity to server** (mTLS mutual authentication).
    /// Server will verify this certificate to confirm client identity.
    ///
    /// # Parameters
    /// - `cert_path`: Client certificate DER file path
    /// - `key_path`: Client private key DER file path (PKCS#8 format)
    ///
    /// # Note
    /// This is the client's identity certificate, not a trust configuration.
    /// To verify server, use `with_custom_ca*` or `with_system_roots`.
    pub fn with_client_cert_der_files(
        mut self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self, QuicError> {
        let cert_der = load_cert_der_from_file(std::path::Path::new(cert_path))?;
        let key_der = load_key_der_from_file(std::path::Path::new(key_path))?;
        let cert = load_cert_from_der(cert_der);
        let key = load_key_from_der(key_der);
        self.client_cert = Some((vec![cert], key));
        Ok(self)
    }

    // ========== Transport Configuration ==========

    /// Set transport layer configuration
    pub fn with_transport_config(mut self, config: QuicTransportConfig) -> Self {
        self.transport_config = config;
        self
    }

    // ========== Bind Address ==========

    /// Set local bind address
    ///
    /// Defaults to `0.0.0.0:0` (system auto-assigned port).
    pub fn with_bind_addr(mut self, addr: std::net::SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Set local bind port (bind to all interfaces)
    pub fn with_bind_port(mut self, port: u16) -> Self {
        self.bind_addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
        self
    }

    // ========== Build ==========

    /// Build Quinn ClientConfig (configuration only, does not create endpoint)
    ///
    /// Use this method if you need to directly obtain `quinn::ClientConfig` for `QuicEndpoint`.
    pub fn build_config(&self) -> Result<quinn::ClientConfig, QuicError> {
        let crypto_config = match &self.trust_source {
            TrustSource::SystemRoots => {
                use rustls_platform_verifier::BuilderVerifierExt;
                
                let builder = rustls::ClientConfig::builder()
                    .with_platform_verifier()
                    .map_err(|e| QuicError::unknown(format!("Platform verifier error: {}", e)))?;
                
                match &self.client_cert {
                    Some((certs, key)) => builder.with_client_auth_cert(certs.clone(), key.clone_key())
                        .map_err(|e| QuicError::unknown(format!("Invalid client cert: {}", e)))?,
                    None => builder.with_no_client_auth(),
                }
            }
            TrustSource::CustomCa(ca_der) => {
                let ca_cert = load_cert_from_der(ca_der.clone());
                let roots = create_root_store(&ca_cert)?;
                
                let builder = rustls::ClientConfig::builder()
                    .with_root_certificates(roots);
                
                match &self.client_cert {
                    Some((certs, key)) => builder.with_client_auth_cert(certs.clone(), key.clone_key())
                        .map_err(|e| QuicError::unknown(format!("Invalid client cert: {}", e)))?,
                    None => builder.with_no_client_auth(),
                }
            }
            TrustSource::SkipVerification => {
                let builder = rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(SkipServerVerification::new());
                
                match &self.client_cert {
                    Some((certs, key)) => builder.with_client_auth_cert(certs.clone(), key.clone_key())
                        .map_err(|e| QuicError::unknown(format!("Invalid client cert: {}", e)))?,
                    None => builder.with_no_client_auth(),
                }
            }
        };

        let mut crypto_config = crypto_config;
        crypto_config.alpn_protocols = self.transport_config.alpn_protocols.clone();

        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(crypto_config)
            .map_err(|e| QuicError::unknown(format!("QUIC config error: {}", e)))?;

        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
        
        // Apply transport configuration
        let mut transport = quinn::TransportConfig::default();
        self.transport_config.apply_to_transport(&mut transport);
        client_config.transport_config(Arc::new(transport));

        Ok(client_config)
    }

    /// Bind to specified address and build QuicClient
    ///
    /// # Parameters
    /// - `addr`: Local bind address string, e.g., "0.0.0.0:0"
    ///
    /// # Example
    /// ```rust
    /// let client = QuicClient::builder()
    ///     .with_system_roots()
    ///     .bind("0.0.0.0:0")?;
    /// ```
    pub fn bind(self, addr: &str) -> Result<super::quic_client::QuicClient, QuicError> {
        let socket_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
            QuicError::unknown(format!("Invalid bind address '{}': {}", addr, e))
        })?;
        self.bind_socket_addr(socket_addr)
    }

    /// Bind to default address (address set in builder) and build QuicClient
    pub fn build(self) -> Result<super::quic_client::QuicClient, QuicError> {
        let addr = self.bind_addr;
        self.bind_socket_addr(addr)
    }

    /// Bind to specified SocketAddr and build QuicClient
    pub fn bind_socket_addr(self, addr: std::net::SocketAddr) -> Result<super::quic_client::QuicClient, QuicError> {
        use super::quic_endpoint::QuicEndpoint;
        
        let client_config = self.build_config()?;
        
        let inner = QuicEndpoint::builder()
            .with_client_config(client_config)
            .bind_addr(addr)?;

        Ok(super::quic_client::QuicClient::from_endpoint(inner))
    }
}

impl Default for QuicClientConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Quinn Server Config Builder
// ============================================================================

/// QUIC Server Configuration Builder
///
/// Used to build `quinn::ServerConfig`, can be reused by `QuicServer` and `QuicEndpoint`.
///
/// # Example
///
/// ```rust
/// use dart_quic_native::{QuicServer, QuicServerConfigBuilder};
///
/// // Use self-signed certificate (for testing)
/// let server = QuicServer::builder()
///     .with_self_signed(&["localhost"])
///     .bind("0.0.0.0:4433")?;
///
/// // Use PEM file certificate (for production)
/// let server = QuicServer::builder()
///     .with_cert_pem_files("cert.pem", "key.pem")?
///     .bind("0.0.0.0:4433")?;
///
/// // If only ServerConfig is needed (for QuicEndpoint)
/// let config = QuicServer::builder()
///     .with_self_signed(&["localhost"])
///     .build_config()?;
/// ```
pub struct QuicServerConfigBuilder {
    cert_source: CertificateSource,
    transport_config: QuicTransportConfig,
    client_cert_mode: ClientCertMode,
    /// Whether certificate is configured (server must configure certificate)
    cert_configured: bool,
}

/// Client certificate verification mode
#[derive(Clone)]
enum ClientCertMode {
    /// Do not require client certificate
    NoClientAuth,
    /// Require client certificate (mTLS)
    Required { trusted_ca_der: Vec<u8> },
    /// Optional client certificate
    Optional { trusted_ca_der: Vec<u8> },
}

impl QuicServerConfigBuilder {
    /// Create a new builder (default uses localhost self-signed certificate)
    pub fn new() -> Self {
        Self {
            cert_source: CertificateSource::SelfSigned {
                subject_alt_names: vec!["localhost".to_string()],
            },
            transport_config: QuicTransportConfig::default(),
            client_cert_mode: ClientCertMode::NoClientAuth,
            cert_configured: true, // Default self-signed certificate
        }
    }

    // ========== Certificate Configuration ==========

    /// Use self-signed certificate (testing only)
    pub fn with_self_signed(mut self, subject_alt_names: &[&str]) -> Self {
        self.cert_source = CertificateSource::SelfSigned {
            subject_alt_names: subject_alt_names.iter().map(|s| s.to_string()).collect(),
        };
        self.cert_configured = true;
        self
    }

    /// Load certificate from PEM file
    pub fn with_cert_pem_files(mut self, cert_path: &str, key_path: &str) -> Result<Self, QuicError> {
        // Verify file exists
        if !std::path::Path::new(cert_path).exists() {
            return Err(QuicError::unknown(format!("Certificate file not found: {}", cert_path)));
        }
        if !std::path::Path::new(key_path).exists() {
            return Err(QuicError::unknown(format!("Key file not found: {}", key_path)));
        }
        self.cert_source = CertificateSource::FromFile {
            cert_path: cert_path.to_string(),
            key_path: key_path.to_string(),
        };
        self.cert_configured = true;
        Ok(self)
    }

    /// Load certificate from DER bytes
    pub fn with_cert_der(mut self, cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
        self.cert_source = CertificateSource::FromMemory { cert_der, key_der };
        self.cert_configured = true;
        self
    }

    // ========== Client Certificate Verification (mTLS) ==========

    /// Require client to provide certificate (enable mTLS)
    pub fn require_client_cert(mut self, trusted_ca_der: Vec<u8>) -> Self {
        self.client_cert_mode = ClientCertMode::Required { trusted_ca_der };
        self
    }

    /// Load CA from PEM file and require client certificate
    pub fn require_client_cert_pem_file(mut self, ca_path: &str) -> Result<Self, QuicError> {
        let certs = load_certs_from_pem(std::path::Path::new(ca_path))?;
        if let Some(cert) = certs.into_iter().next() {
            self.client_cert_mode = ClientCertMode::Required { trusted_ca_der: cert.to_vec() };
        }
        Ok(self)
    }

    /// Optional client certificate (verify if provided)
    pub fn optional_client_cert(mut self, trusted_ca_der: Vec<u8>) -> Self {
        self.client_cert_mode = ClientCertMode::Optional { trusted_ca_der };
        self
    }

    // ========== Transport Configuration ==========

    /// Set transport layer configuration
    pub fn with_transport_config(mut self, config: QuicTransportConfig) -> Self {
        self.transport_config = config;
        self
    }

    // ========== Build ==========

    /// Build Quinn ServerConfig (configuration only, does not create endpoint)
    ///
    /// Use this method if you need to directly obtain `quinn::ServerConfig` for `QuicEndpoint`.
    pub fn build_config(&self) -> Result<quinn::ServerConfig, QuicError> {
        // Load or generate certificate
        let (certs, key) = match &self.cert_source {
            CertificateSource::SelfSigned { subject_alt_names } => {
                generate_self_signed(subject_alt_names.clone())?
            }
            CertificateSource::FromFile { cert_path, key_path } => {
                let certs = load_certs_from_pem(std::path::Path::new(cert_path))?;
                let key = load_key_from_pem(std::path::Path::new(key_path))?;
                (certs, key)
            }
            CertificateSource::FromMemory { cert_der, key_der } => {
                let cert = load_cert_from_der(cert_der.clone());
                let key = load_key_from_der(key_der.clone());
                (vec![cert], key)
            }
        };

        // Build rustls ServerConfig (based on client certificate verification mode)
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        
        let crypto_config = match &self.client_cert_mode {
            ClientCertMode::NoClientAuth => {
                rustls::ServerConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .map_err(|e| QuicError::unknown(format!("TLS config error: {}", e)))?
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .map_err(|e| QuicError::unknown(format!("Invalid certificate: {}", e)))?
            }
            ClientCertMode::Required { trusted_ca_der } => {
                let ca_cert = load_cert_from_der(trusted_ca_der.clone());
                let roots = create_root_store(&ca_cert)?;
                let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots), provider.clone()
                )
                    .build()
                    .map_err(|e| QuicError::unknown(format!("Client verifier error: {}", e)))?;
                
                rustls::ServerConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .map_err(|e| QuicError::unknown(format!("TLS config error: {}", e)))?
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(certs, key)
                    .map_err(|e| QuicError::unknown(format!("Invalid certificate: {}", e)))?
            }
            ClientCertMode::Optional { trusted_ca_der } => {
                let ca_cert = load_cert_from_der(trusted_ca_der.clone());
                let roots = create_root_store(&ca_cert)?;
                let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots), provider.clone()
                )
                    .allow_unauthenticated()
                    .build()
                    .map_err(|e| QuicError::unknown(format!("Client verifier error: {}", e)))?;
                
                rustls::ServerConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .map_err(|e| QuicError::unknown(format!("TLS config error: {}", e)))?
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(certs, key)
                    .map_err(|e| QuicError::unknown(format!("Invalid certificate: {}", e)))?
            }
        };

        let mut crypto_config = crypto_config;
        crypto_config.alpn_protocols = self.transport_config.alpn_protocols.clone();

        let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(crypto_config)
            .map_err(|e| QuicError::unknown(format!("QUIC config error: {}", e)))?;

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
        
        // Apply transport configuration
        let mut transport = quinn::TransportConfig::default();
        self.transport_config.apply_to_transport(&mut transport);
        server_config.transport_config(Arc::new(transport));

        Ok(server_config)
    }

    /// Bind to specified address and build QuicServer
    ///
    /// # Parameters
    /// - `addr`: Local bind address string, e.g., "0.0.0.0:4433"
    ///
    /// # Example
    /// ```rust
    /// let server = QuicServer::builder()
    ///     .with_self_signed(&["localhost"])
    ///     .bind("0.0.0.0:4433")?;
    /// ```
    pub fn bind(self, addr: &str) -> Result<super::quic_server::QuicServer, QuicError> {
        let socket_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
            QuicError::unknown(format!("Invalid bind address '{}': {}", addr, e))
        })?;
        self.bind_socket_addr(socket_addr)
    }

    /// Bind to specified SocketAddr and build QuicServer
    pub fn bind_socket_addr(self, addr: std::net::SocketAddr) -> Result<super::quic_server::QuicServer, QuicError> {
        use super::quic_endpoint::QuicEndpoint;
        
        if !self.cert_configured {
            return Err(QuicError::unknown(
                "No certificate configured. Use with_self_signed() or with_cert_pem_files()".to_string(),
            ));
        }

        let server_config = self.build_config()?;
        
        let inner = QuicEndpoint::builder()
            .with_server_config(server_config)
            .bind_addr(addr)?;

        Ok(super::quic_server::QuicServer::from_endpoint(inner))
    }
}

impl Default for QuicServerConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// FFI-Friendly Configuration Structures (for C API)
// ============================================================================

/// FFI-friendly transport configuration
///
/// # C Language Usage Example
///
/// ```c
/// QuicFfiTransportConfig transport = {
///     .max_idle_timeout_ms = 30000,
///     .keep_alive_interval_ms = 15000,
///     // ...
/// };
/// ```
#[repr(C)]
#[derive(Clone)]
pub struct QuicFfiTransportConfig {
    // Connection management
    pub max_idle_timeout_ms: u64,
    pub keep_alive_interval_ms: u64, // 0 = disabled

    // Flow control
    pub max_concurrent_bi_streams: u32,
    pub max_concurrent_uni_streams: u32,
    pub stream_receive_window: u32,
    pub send_window: u64,

    // RTT
    pub initial_rtt_ms: u64,

    // MTU
    pub initial_mtu: u16,
    pub min_mtu: u16,
    pub enable_mtu_discovery: bool,

    // Datagram
    pub datagram_receive_buffer_size: u32, // 0 = disabled
    pub datagram_send_buffer_size: u32,

    // Congestion control: 0 = Cubic, 1 = NewReno, 2 = BBR
    pub congestion_controller: u8,

    // Privacy
    pub allow_spin: bool,
    pub enable_gso: bool,
}

impl Default for QuicFfiTransportConfig {
    fn default() -> Self {
        let config = QuicTransportConfig::default();
        Self::from(&config)
    }
}

impl From<&QuicTransportConfig> for QuicFfiTransportConfig {
    fn from(config: &QuicTransportConfig) -> Self {
        Self {
            max_idle_timeout_ms: config.max_idle_timeout.as_millis() as u64,
            keep_alive_interval_ms: config.keep_alive_interval.map(|d| d.as_millis() as u64).unwrap_or(0),
            max_concurrent_bi_streams: config.max_concurrent_bi_streams,
            max_concurrent_uni_streams: config.max_concurrent_uni_streams,
            stream_receive_window: config.stream_receive_window,
            send_window: config.send_window,
            initial_rtt_ms: config.initial_rtt.as_millis() as u64,
            initial_mtu: config.initial_mtu,
            min_mtu: config.min_mtu,
            enable_mtu_discovery: config.mtu_discovery.is_some(),
            datagram_receive_buffer_size: config.datagram_receive_buffer_size.unwrap_or(0) as u32,
            datagram_send_buffer_size: config.datagram_send_buffer_size as u32,
            congestion_controller: match config.congestion_controller {
                CongestionControllerType::Cubic => 0,
                CongestionControllerType::NewReno => 1,
                CongestionControllerType::Bbr => 2,
            },
            allow_spin: config.allow_spin,
            enable_gso: config.enable_segmentation_offload,
        }
    }
}

impl From<&QuicFfiTransportConfig> for QuicTransportConfig {
    fn from(ffi: &QuicFfiTransportConfig) -> Self {
        Self {
            max_idle_timeout: Duration::from_millis(ffi.max_idle_timeout_ms),
            keep_alive_interval: if ffi.keep_alive_interval_ms > 0 {
                Some(Duration::from_millis(ffi.keep_alive_interval_ms))
            } else {
                None
            },
            max_concurrent_bi_streams: ffi.max_concurrent_bi_streams,
            max_concurrent_uni_streams: ffi.max_concurrent_uni_streams,
            stream_receive_window: ffi.stream_receive_window,
            receive_window: u64::MAX,
            send_window: ffi.send_window,
            send_fairness: true,
            initial_rtt: Duration::from_millis(ffi.initial_rtt_ms),
            packet_threshold: 3,
            time_threshold: 9.0 / 8.0,
            persistent_congestion_threshold: 3,
            initial_mtu: ffi.initial_mtu,
            min_mtu: ffi.min_mtu,
            mtu_discovery: if ffi.enable_mtu_discovery {
                Some(MtuDiscoveryConfig::default())
            } else {
                None
            },
            datagram_receive_buffer_size: if ffi.datagram_receive_buffer_size > 0 {
                Some(ffi.datagram_receive_buffer_size as usize)
            } else {
                None
            },
            datagram_send_buffer_size: ffi.datagram_send_buffer_size as usize,
            alpn_protocols: vec![b"h3".to_vec(), b"hq-29".to_vec()],
            crypto_buffer_size: 16 * 1024,
            congestion_controller: match ffi.congestion_controller {
                0 => CongestionControllerType::Cubic,
                1 => CongestionControllerType::NewReno,
                2 => CongestionControllerType::Bbr,
                _ => CongestionControllerType::Cubic,
            },
            allow_spin: ffi.allow_spin,
            enable_segmentation_offload: ffi.enable_gso,
            ack_frequency: None,
        }
    }
}

