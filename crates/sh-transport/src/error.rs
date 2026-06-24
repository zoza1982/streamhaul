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

    /// The QUIC stream was closed cleanly by the peer before a complete framed message
    /// could be read (partial header or payload received).
    #[error("stream closed by peer mid-message")]
    StreamClosed,

    /// A framed message header declared a payload length that exceeds the configured
    /// safety limit.
    #[error("framed message too large: declared length {len} bytes")]
    MessageTooLarge {
        /// The declared payload length in bytes.
        len: u32,
    },

    /// An I/O error occurred while writing to a QUIC stream.
    #[error("stream write error: {0}")]
    Io(#[from] quinn::WriteError),

    /// The stream was already closed when a priority or other operation was attempted.
    #[error("stream already closed")]
    StreamAlreadyClosed,

    /// An I/O error occurred while reading from a QUIC stream.
    #[error("stream read error: {0}")]
    StreamRead(#[from] quinn::ReadExactError),

    /// The channel header bytes received during stream negotiation were invalid.
    #[error("invalid channel header: {reason}")]
    InvalidChannelHeader {
        /// A description of what was wrong.
        reason: &'static str,
    },

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

    /// Failed to export Noise session-binding context from a QUIC connection's TLS layer.
    ///
    /// Returned by [`sh_transport::quic_binding::export_noise_session_context`] when the
    /// QUIC connection's TLS exporter is unavailable (e.g. connection not yet established).
    #[error("failed to export Noise session-binding context from QUIC TLS layer")]
    NoiseContextExport,

    /// A str0m WebRTC engine error.
    ///
    /// Wraps errors from the [`str0m`] WebRTC sans-IO engine, including DTLS, ICE, SCTP,
    /// and data-channel errors.
    #[error("webrtc: {0}")]
    Webrtc(String),

    /// An ICE candidate string could not be parsed.
    ///
    /// Returned by [`PinnedWebRtcTransport::add_remote_candidate`] and
    /// [`PinnedWebRtcTransport::add_local_host_candidate`] when the supplied candidate
    /// string is rejected by str0m's ICE implementation. Callers outside `sh-transport`
    /// do not need to import [`crate::webrtc::SdpBridgeError`] to handle these errors.
    #[error("ICE candidate parse error: {0}")]
    CandidateParseError(String),
}
