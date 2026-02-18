//! QUIC Protocol Module
//!
//! Provides core functionality for QUIC clients, servers, and configurations.

mod quic_config;
mod quic_client;
mod quic_server;
mod quic_connection;
mod quic_endpoint;

pub use quic_config::{
    QuicTransportConfig, MtuDiscoveryConfig, AckFrequencyConfig,
    CongestionControllerType, QuicFfiTransportConfig,
    QuicClientConfigBuilder, QuicServerConfigBuilder,
};
pub use quic_client::{
    QuicClient, QuicFfiClientConfig, QuicFfiTrustMode, QuicFfiClientCertMode,
};
pub use quic_server::{QuicServer, QuicServerHandle, QuicFfiServerConfig};
pub use quic_connection::{QuicConnection, QuicConnectionHandle};
pub use quic_endpoint::{QuicEndpoint, QuicEndpointBuilder, QuicEndpointMode, QuicFfiEndpointConfig};
