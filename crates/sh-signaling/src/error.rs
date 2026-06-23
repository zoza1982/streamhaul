//! Error types for `sh-signaling`.

use thiserror::Error;

use crate::envelope::{SessionId, ENVELOPE_HEADER_LEN, MAX_PAYLOAD_LEN};

/// All errors that can be returned by `sh-signaling` operations.
#[derive(Debug, Error)]
pub enum SignalingError {
    /// The input buffer is shorter than the minimum envelope header length.
    #[error("envelope too short: need at least {ENVELOPE_HEADER_LEN} bytes, got {actual}")]
    EnvelopeTooShort {
        /// Actual number of bytes in the buffer.
        actual: usize,
    },

    /// The kind byte in the envelope header is not a known [`crate::MessageKind`] discriminant.
    #[error("unknown message kind byte: {byte:#04x}")]
    UnknownMessageKind {
        /// The unrecognised byte value.
        byte: u8,
    },

    /// The declared payload length exceeds [`MAX_PAYLOAD_LEN`].
    ///
    /// Payload sizes above this limit are rejected unconditionally to prevent memory
    /// amplification attacks from hostile peers.
    #[error("payload too large: {len} bytes (max {MAX_PAYLOAD_LEN})")]
    PayloadTooLarge {
        /// Declared payload length in bytes.
        len: u64,
    },

    /// The buffer ends before `payload_len` bytes of payload are available.
    #[error("truncated payload: declared {declared} bytes but only {available} bytes remain")]
    TruncatedPayload {
        /// The payload length declared in the header.
        declared: u32,
        /// How many bytes are actually available after the header.
        available: usize,
    },

    /// A fingerprint field in the envelope header is not valid 64-character ASCII hex.
    #[error("invalid fingerprint: must be 64 ASCII hex characters")]
    InvalidFingerprint,

    /// An underlying WebSocket protocol error.
    ///
    /// Boxed to keep the enum size small — `tungstenite::Error` is large.
    #[error("WebSocket error: {0}")]
    WebSocket(Box<tokio_tungstenite::tungstenite::Error>),

    /// An underlying I/O error (e.g., bind/accept failure).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The routing table has no record for the given session.
    #[error("session not found: {session_id:?}")]
    SessionNotFound {
        /// The session ID that was looked up.
        session_id: SessionId,
    },

    /// A peer with the given fingerprint is not registered in the session.
    #[error("peer not found in session: {fp}")]
    PeerNotFound {
        /// The fingerprint that was looked up.
        fp: String,
    },

    /// A client sent an envelope whose `from_fp` does not match its registered fingerprint.
    ///
    /// This is a spoof-rejection: the server assigns each connection a single `from_fp` on
    /// `Hello` and rejects any subsequent message with a different `from_fp`.
    #[error("fingerprint mismatch: registered {registered}, attempted {attempted}")]
    FingerprintSpoofAttempt {
        /// The fingerprint the server recorded when the client sent `Hello`.
        registered: String,
        /// The `from_fp` field in the offending envelope.
        attempted: String,
    },

    /// The server's session table has reached its capacity limit.
    #[error("session table full (max {max} sessions)")]
    SessionTableFull {
        /// Maximum number of concurrent sessions supported.
        max: usize,
    },

    /// A send or receive was attempted on a client that is not currently connected.
    #[error("client not connected")]
    NotConnected,

    /// The server sent an `Error` envelope; the payload is the reason string.
    #[error("connection refused by server: {reason}")]
    ServerError {
        /// The error reason from the server's `Error` envelope payload.
        reason: String,
    },

    /// A WebSocket message arrived with an unexpected type (e.g., Text when Binary expected).
    #[error("unexpected WebSocket message type")]
    UnexpectedMessageType,
}

impl From<tokio_tungstenite::tungstenite::Error> for SignalingError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::WebSocket(Box::new(e))
    }
}
