//! Error types for `sh-transport`.

use thiserror::Error;

/// All errors that can be returned by `sh-transport` operations.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Failed to bind the local socket or create the QUIC endpoint.
    #[error("endpoint bind error: {0}")]
    Bind(#[from] std::io::Error),

    /// Connection attempt failed.
    #[error("connect error: {0}")]
    Connect(#[from] quinn::ConnectError),

    /// Connection-level error (e.g., closed, reset).
    #[error("connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),

    /// Datagram send failed.
    #[error("send datagram error: {0}")]
    SendDatagram(#[from] quinn::SendDatagramError),

    /// The remote peer does not support datagrams.
    #[error("datagrams are not supported by the remote peer")]
    DatagramsNotSupported,

    /// No incoming connection was available (server endpoint closed).
    #[error("server endpoint closed before a connection arrived")]
    EndpointClosed,

    /// Certificate generation failed (insecure-lan feature only).
    #[cfg(feature = "insecure-lan")]
    #[error("certificate generation error: {0}")]
    CertGeneration(#[from] rcgen::Error),

    /// TLS/QUIC configuration assembly failed (insecure-lan feature only).
    ///
    /// Aggregates several heterogeneous config-time error sources (the rustls config builder,
    /// private-key parsing, and quinn's `QuicServerConfig`/`QuicClientConfig` conversion) that can
    /// only occur at lab startup. Structured variants will replace this when the production crypto
    /// path lands (P3/P4).
    #[cfg(feature = "insecure-lan")]
    #[error("TLS config error: {0}")]
    TlsConfig(String),
}
