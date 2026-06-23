//! `sh-signaling` — WebSocket signaling server and client for Streamhaul session establishment.
//!
//! This crate implements the signaling layer (Phase 4, P4-1). It handles SDP/ICE exchange
//! between two peers via a zero-knowledge relay: the server routes opaque envelopes based
//! solely on `(session_id, to_fp)` and never inspects the payload.
//!
//! # Architecture
//!
//! ## Wire format
//!
//! All messages use a hand-rolled binary [`SignalingEnvelope`] (see [`envelope`] module).
//! The 149-byte header is big-endian throughout. The payload is bounded at [`MAX_PAYLOAD_LEN`]
//! to prevent memory amplification from hostile peers.
//!
//! ## Server
//!
//! [`SignalingServer`] binds plain WebSocket (no in-process TLS). Production deployments
//! terminate TLS at a reverse proxy (nginx, Caddy). Tests use plain `ws://` on loopback.
//!
//! Authentication is delegated to [`PeerAuthenticator`]. The default [`AcceptAll`] (available
//! with the `insecure-lan` feature) admits every peer; production code must supply a real
//! implementation.
//!
//! ## Client
//!
//! [`SignalingClient`] connects over plain WS, sends a `Hello` envelope on connection, and
//! then drives a send/recv loop. Reconnection uses an injectable [`BackoffStrategy`].
//!
//! ## Zero-knowledge invariant
//!
//! The server MUST NOT parse `payload`. It routes using only `session_id` and `to_fp`.
//! Any change that violates this invariant is a security regression (LLD §6.3).
//!
//! # Features
//!
//! - **`insecure-lan`** — enables [`InsecureLanLab`] witness type and [`AcceptAll`]
//!   authenticator for loopback/integration tests. MUST NOT be enabled in release builds.

#![deny(missing_docs)]

pub mod auth;
pub mod backoff;
pub mod client;
pub mod envelope;
pub mod error;
pub mod server;

pub use auth::PeerAuthenticator;
pub use backoff::{BackoffStrategy, ExponentialBackoff};
pub use client::SignalingClient;
pub use envelope::{
    MessageKind, SessionId, SignalingEnvelope, ENVELOPE_HEADER_LEN, MAX_PAYLOAD_LEN,
};
pub use error::SignalingError;
pub use server::SignalingServer;

#[cfg(feature = "insecure-lan")]
pub use auth::{AcceptAll, InsecureLanLab};
