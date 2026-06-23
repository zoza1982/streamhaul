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
//! Authentication is delegated to [`PeerAuthenticator`] (R-SIG-AUTH, ADR-0016). The server issues
//! a fresh challenge on connect; the production [`IdentityProofAuthenticator`] verifies an Ed25519
//! possession-of-identity-key proof carried in the opaque `Hello` payload, binding `from_fp` to a
//! key the peer controls. The test-only [`AcceptAll`] (available with the `insecure-lan` feature)
//! admits every peer. Server-side auth proves *ownership*, not end-to-end *trust* (which the peers
//! establish via Noise/BindCert/TOFU, P3).
//!
//! ## Client
//!
//! [`SignalingClient`] connects over plain WS. On connect it receives the server `Challenge`,
//! signs it with its [`Keystore`](sh_crypto::Keystore) (via
//! [`connect_authenticated`](SignalingClient::connect_authenticated)), and sends a `Hello` carrying
//! the proof, then drives a send/recv loop. Reconnection uses an injectable [`BackoffStrategy`].
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
pub mod challenge;
pub mod client;
pub mod envelope;
pub mod error;
pub mod server;

pub use auth::{AuthContext, AuthError, IdentityProofAuthenticator, PeerAuthenticator};
pub use backoff::{BackoffStrategy, ExponentialBackoff};
pub use challenge::{ChallengeSource, OsChallengeSource};
pub use client::SignalingClient;
pub use envelope::{
    MessageKind, SessionId, SignalingEnvelope, ENVELOPE_HEADER_LEN, MAX_PAYLOAD_LEN,
};
pub use error::SignalingError;
pub use server::SignalingServer;

#[cfg(feature = "insecure-lan")]
pub use auth::{AcceptAll, InsecureLanLab};
