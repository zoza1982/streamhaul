//! Session orchestration seam: transport capability negotiation and session establishment (P4-6).
//!
//! This module provides [`SessionEstablisher`], which drives the full capability-negotiation
//! and transport-construction flow between two Streamhaul peers. It is intentionally **generic
//! over injected seams** so that every path can be tested deterministically without live sockets:
//!
//! - [`SignalingChannel`] — injects the signaling send/receive I/O.
//! - [`TransportFactory`] — injects the transport constructor (QUIC or WebRTC).
//!
//! # Orchestration flow
//!
//! Both initiator and responder follow the same four-phase flow:
//!
//! ```text
//! 1. Cap-exchange:   each side sends its TransportCaps in a Candidate envelope and reads
//!                    the peer's Candidate envelope.
//! 2. Negotiate:      select the preferred common transport via a fixed global order [QUIC, WebRTC].
//! 3. Security gate:  for WebRTC, extract the verified DTLS pin from the Noise outcome and pass
//!                    it to the factory. For QUIC, pass None. The factory applies the pin when
//!                    constructing the WebRtcTransport. This gate is non-bypassable in the
//!                    production code path.
//! 4. Build:          call the factory to obtain the concrete Transport.
//! ```
//!
//! # Security
//!
//! The DTLS pin gate (step 3) ensures that every WebRTC transport is constructed with the
//! cryptographically verified peer DTLS fingerprint committed inside the Noise BindCert. An
//! attacker who swaps the DTLS certificate presented in the DTLS handshake will be rejected by
//! str0m because the pin won't match. The gate is enforced structurally: a `SessionEstablisher`
//! cannot call `factory.build(Webrtc, ...)` without first calling
//! [`HandshakeOutcome::require_webrtc_dtls_pin`].
//!
//! A QUIC peer whose `BindCert` includes a DTLS commitment is rejected
//! ([`SessionError::UnexpectedDtlsCommitment`]); this anomaly indicates a protocol violation
//! (a WebRTC-capable peer that erroneously negotiated QUIC) and is treated as a security
//! concern rather than a soft warning.
//!
//! See ADR-0014 (DTLS fingerprint binding) and ADR-0015 (transport negotiation).
//!
//! # Identity fields
//!
//! The [`SessionEstablisher`] carries the local and peer device fingerprints and session ID so
//! that caps-exchange envelopes are routed correctly through the zero-knowledge relay.
//!
//! # Examples
//!
//! ```no_run
//! # use sh_core::session::{SessionEstablisher, SessionError, IcePathOutcome, SignalingChannel, TransportFactory};
//! # use sh_protocol::transport_caps::TransportCaps;
//! # use sh_types::TransportKind;
//! # use sh_signaling::{MessageKind, SessionId, SignalingEnvelope};
//! # use sh_transport::channel::Transport;
//! # use sh_crypto::noise::HandshakeOutcome;
//! # use bytes::Bytes;
//! # use std::net::{SocketAddr, Ipv4Addr};
//! # struct NoopSignaling;
//! # #[async_trait::async_trait]
//! # impl SignalingChannel for NoopSignaling {
//! #     async fn send(&mut self, _e: SignalingEnvelope) -> Result<(), SessionError> { unimplemented!() }
//! #     async fn recv(&mut self) -> Result<SignalingEnvelope, SessionError> { unimplemented!() }
//! # }
//! # struct NoopFactory;
//! # impl TransportFactory for NoopFactory {
//! #     fn build(&self, _k: TransportKind, _p: &IcePathOutcome, _pin: Option<[u8;32]>) -> Result<Box<dyn Transport>, SessionError> { unimplemented!() }
//! # }
//! # async fn example(outcome: HandshakeOutcome) -> Result<(), SessionError> {
//! let caps = TransportCaps { supports_quic: true, supports_webrtc: true };
//! let ice_path = IcePathOutcome {
//!     local_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
//!     remote_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
//!     is_relay: false,
//! };
//! let local_fp = "a".repeat(64);
//! let peer_fp = "b".repeat(64);
//! let session_id = sh_signaling::SessionId([0u8; 16]);
//! let establisher = SessionEstablisher::new(caps, NoopSignaling, NoopFactory, local_fp, peer_fp, session_id);
//! let (_kind, _transport) = establisher.establish_as_initiator(&outcome, &ice_path).await?;
//! # Ok(()) }
//! ```

use async_trait::async_trait;
use sh_crypto::noise::HandshakeOutcome;
use sh_protocol::transport_caps::{
    decode_transport_caps, encode_transport_caps, negotiate, NegotiationError, TransportCaps,
    TRANSPORT_CAPS_LEN,
};
use sh_protocol::ProtocolError;
use sh_signaling::{MessageKind, SessionId, SignalingEnvelope};
use sh_transport::channel::Transport;
use sh_types::TransportKind;
use std::net::SocketAddr;

// ─── Public types ─────────────────────────────────────────────────────────────

/// Outcome of ICE path selection: the pair of addresses and whether a relay was used.
///
/// The factory receives this to know where to point the transport. The `is_relay` flag
/// informs downstream decisions (e.g., billing, metrics, and GCC congestion estimation).
#[derive(Debug, Clone)]
pub struct IcePathOutcome {
    /// The local socket address (ICE-selected local candidate).
    pub local_addr: SocketAddr,
    /// The remote socket address (ICE-selected remote candidate, or TURN relay address).
    pub remote_addr: SocketAddr,
    /// `true` if this path goes through a TURN relay; `false` for a direct P2P path.
    pub is_relay: bool,
}

/// Errors from session establishment.
///
/// Each variant corresponds to a distinct failure mode in the four-phase orchestration flow.
/// The variants are stable API — callers may pattern-match on them.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The signaling channel failed to send or receive an envelope.
    #[error("signaling error: {0}")]
    Signaling(String),

    /// A malformed peer payload was received (e.g., wrong version byte, truncated caps).
    ///
    /// Distinct from [`SessionError::Signaling`] (I/O drop) so callers can distinguish
    /// a hostile/malformed peer from a channel failure.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// A cryptographic operation failed (e.g., DTLS pin extraction).
    #[error("crypto error: {0}")]
    Crypto(#[from] sh_crypto::CryptoError),

    /// Transport capability negotiation failed (no common transport).
    #[error("negotiation failed: {0}")]
    Negotiation(#[from] NegotiationError),

    /// The factory could not construct the requested transport.
    #[error("transport error: {0}")]
    Transport(#[from] sh_transport::TransportError),

    /// The WebRTC security gate: the Noise `HandshakeOutcome` carries no valid DTLS pin.
    ///
    /// This is returned when negotiation selects WebRTC but the peer's `BindCert` committed
    /// `ALG=NONE` (a stripped DTLS binding), indicating a downgrade attempt.
    #[error("DTLS binding missing — WebRTC peer must commit its DTLS fingerprint")]
    DtlsBindingMissing,

    /// A QUIC peer sent an unexpected DTLS commitment in its `BindCert`.
    ///
    /// This is a protocol violation: a peer advertising QUIC-only caps (negotiated as QUIC)
    /// must not commit a DTLS fingerprint. This is treated as a security anomaly and the
    /// session is aborted. See ADR-0015 §Security for the policy rationale.
    #[error("unexpected DTLS commitment on QUIC-negotiated session")]
    UnexpectedDtlsCommitment,

    /// An incoming signaling envelope had a kind that did not match what the protocol expected.
    ///
    /// The expected and received kinds are included for diagnostics.
    #[error("envelope kind mismatch: expected {expected}, got {got}")]
    EnvelopeKindMismatch {
        /// The `MessageKind` name expected at this step.
        expected: String,
        /// The `MessageKind` name actually received.
        got: String,
    },

    /// An incoming caps envelope payload had an unexpected length.
    ///
    /// The signaling protocol requires exactly [`TRANSPORT_CAPS_LEN`] bytes for a caps payload.
    /// Extra bytes could indicate a piggybacked blob or a spoofed/corrupted envelope.
    #[error("caps payload wrong length: expected {expected}, got {got}")]
    CapsPayloadWrongLength {
        /// The expected exact byte count.
        expected: usize,
        /// The actual byte count received.
        got: usize,
    },

    /// ICE did not produce a nominated path (internal consistency check; should not occur after a
    /// successful ICE convergence).
    #[error("no nominated ICE path")]
    NoNominatedPath,
}

// ─── Injected seam traits ─────────────────────────────────────────────────────

/// Injected signaling channel abstraction.
///
/// Both `send` and `recv` are async so they can be driven from a tokio task without blocking
/// worker threads. Implementors must be [`Send`] so the [`SessionEstablisher`] can be moved
/// across task boundaries, and `'static` so it can be held across `.await` points.
///
/// # Examples
///
/// In tests, an in-memory channel is the most natural implementation:
/// use two `tokio::sync::mpsc` channels and forward envelopes to each other.
#[async_trait]
pub trait SignalingChannel: Send + 'static {
    /// Send an envelope to the peer.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Signaling`] on any I/O failure.
    async fn send(&mut self, env: SignalingEnvelope) -> Result<(), SessionError>;

    /// Receive the next envelope from the peer.
    ///
    /// Yields to the executor while waiting; does not block a worker thread.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Signaling`] if the channel is closed or an I/O error occurs.
    async fn recv(&mut self) -> Result<SignalingEnvelope, SessionError>;
}

/// Factory that constructs a [`Transport`] from the negotiated transport kind and ICE path.
///
/// The factory is **responsible for applying the WebRTC DTLS pin** when `kind == Webrtc` and
/// `webrtc_peer_pin == Some(_)`. If it does not apply the pin before starting the DTLS
/// handshake, the WebRTC session will be vulnerable to DTLS certificate swaps (MITM).
///
/// The factory must be [`Send`] and `'static` for the same reasons as [`SignalingChannel`].
///
/// # Security
///
/// The `webrtc_peer_pin` value is derived from the cryptographically verified Noise
/// `HandshakeOutcome` (via [`HandshakeOutcome::require_webrtc_dtls_pin`]). It is the
/// peer's DTLS fingerprint committed inside its identity-signed `BindCert`. The factory
/// must pass it to `WebRtcTransport::set_remote_dtls_fingerprint` before DTLS begins.
///
/// A production follow-up (`PinnedWebRtcTransport` builder, tracked in R-WEBRTC-LIVE) will
/// enforce pin application structurally so the factory cannot silently skip it.
pub trait TransportFactory: Send + 'static {
    /// Build a [`Transport`] for the given negotiated kind and ICE path.
    ///
    /// `webrtc_peer_pin` is `Some([u8; 32])` **only** when `kind == Webrtc`; it is `None` when
    /// `kind == Quic`. Implementors must apply the pin (e.g., via
    /// `WebRtcTransport::set_remote_dtls_fingerprint`) before returning.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Transport`] if construction fails.
    fn build(
        &self,
        kind: TransportKind,
        path: &IcePathOutcome,
        webrtc_peer_pin: Option<[u8; 32]>,
    ) -> Result<Box<dyn Transport>, SessionError>;
}

// ─── SessionEstablisher ───────────────────────────────────────────────────────

/// Drives the four-phase transport capability negotiation and session establishment flow.
///
/// Generic over [`SignalingChannel`] and [`TransportFactory`] seams so the flow can be tested
/// deterministically without live sockets. Both seams are consumed by the `establish_*` methods;
/// the established transport is returned to the caller.
///
/// The `SessionEstablisher` is **not object-safe** (it has generic type parameters); if you need
/// dynamic dispatch over a session type, wrap the result in a `Box<dyn Transport>` instead.
///
/// # Usage
///
/// Create one per session establishment attempt (not reusable after `establish_*` returns). The
/// `local_caps` field declares what this endpoint supports; the peer's caps are received during
/// the exchange.
///
/// # Ordering
///
/// The QUIC > WebRTC preference order is global and fixed. Neither side can influence it beyond
/// advertising which transports they support. [`negotiate`] implements the symmetric selection.
///
/// # Identity fields
///
/// The `local_fp`, `peer_fp`, and `session_id` parameters are threaded into every
/// [`SignalingEnvelope`] sent during caps exchange so the zero-knowledge relay can route the
/// envelope correctly. These must match the values established during device pairing.
pub struct SessionEstablisher<S: SignalingChannel, F: TransportFactory> {
    /// The transports this local endpoint supports.
    local_caps: TransportCaps,
    /// The injected signaling channel for cap-exchange.
    signaling: S,
    /// The injected transport factory.
    factory: F,
    /// The local device fingerprint (64 lowercase hex chars).
    local_fp: String,
    /// The intended peer device fingerprint (64 lowercase hex chars).
    peer_fp: String,
    /// The session identifier for this establishment attempt.
    session_id: SessionId,
}

impl<S: SignalingChannel, F: TransportFactory> SessionEstablisher<S, F> {
    /// Create a new [`SessionEstablisher`].
    ///
    /// # Parameters
    ///
    /// - `local_caps`: which transports this endpoint supports (used in the caps exchange).
    /// - `signaling`: the channel over which [`SignalingEnvelope`]s are exchanged with the peer.
    /// - `factory`: constructs the concrete transport after negotiation.
    /// - `local_fp`: the local device fingerprint (64 lowercase hex chars, from the keystore).
    /// - `peer_fp`: the intended peer device fingerprint (64 lowercase hex chars).
    /// - `session_id`: the session identifier for this establishment attempt.
    pub fn new(
        local_caps: TransportCaps,
        signaling: S,
        factory: F,
        local_fp: String,
        peer_fp: String,
        session_id: SessionId,
    ) -> Self {
        Self {
            local_caps,
            signaling,
            factory,
            local_fp,
            peer_fp,
            session_id,
        }
    }

    /// Establish as the **initiator**: send caps first, then receive the peer's caps.
    ///
    /// # Protocol
    ///
    /// 1. Encode `local_caps` and send it in a `MessageKind::Candidate` envelope.
    /// 2. Receive the peer's `MessageKind::Candidate` envelope and decode their caps.
    /// 3. Call [`negotiate`] to select the transport.
    /// 4. Apply the DTLS security gate (WebRTC only; QUIC with unexpected DTLS pin → error).
    /// 5. Call the factory and return the transport.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] on any step failure.
    pub async fn establish_as_initiator(
        mut self,
        noise_outcome: &HandshakeOutcome,
        ice_path: &IcePathOutcome,
    ) -> Result<(TransportKind, Box<dyn Transport>), SessionError> {
        // ── Step 1: Send our caps ─────────────────────────────────────────────
        let local_wire = encode_transport_caps(&self.local_caps);
        self.signaling
            .send(self.make_caps_envelope(MessageKind::Candidate, &local_wire))
            .await?;

        // ── Step 2: Receive peer caps ─────────────────────────────────────────
        let peer_caps = self.recv_peer_caps(MessageKind::Candidate).await?;

        // ── Steps 3–5: Negotiate + gate + build ───────────────────────────────
        self.negotiate_and_build(noise_outcome, ice_path, peer_caps)
    }

    /// Establish as the **responder**: receive the peer's caps first, then send ours.
    ///
    /// # Protocol
    ///
    /// 1. Receive the peer's `MessageKind::Candidate` envelope and decode their caps.
    /// 2. Encode `local_caps` and send it in a `MessageKind::Candidate` envelope.
    /// 3. Call [`negotiate`] to select the transport.
    /// 4. Apply the DTLS security gate (WebRTC only; QUIC with unexpected DTLS pin → error).
    /// 5. Call the factory and return the transport.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] on any step failure.
    pub async fn establish_as_responder(
        mut self,
        noise_outcome: &HandshakeOutcome,
        ice_path: &IcePathOutcome,
    ) -> Result<(TransportKind, Box<dyn Transport>), SessionError> {
        // ── Step 1: Receive peer caps ─────────────────────────────────────────
        let peer_caps = self.recv_peer_caps(MessageKind::Candidate).await?;

        // ── Step 2: Send our caps ─────────────────────────────────────────────
        let local_wire = encode_transport_caps(&self.local_caps);
        self.signaling
            .send(self.make_caps_envelope(MessageKind::Candidate, &local_wire))
            .await?;

        // ── Steps 3–5: Negotiate + gate + build ───────────────────────────────
        self.negotiate_and_build(noise_outcome, ice_path, peer_caps)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Receive the next envelope and parse it as a `TransportCaps` payload.
    ///
    /// The envelope kind must be `expected_kind`; a mismatch returns
    /// [`SessionError::EnvelopeKindMismatch`]. The payload must be **exactly**
    /// [`TRANSPORT_CAPS_LEN`] bytes; extra bytes are rejected with
    /// [`SessionError::CapsPayloadWrongLength`] (hostile-input defense: piggybacked blobs or
    /// ICE candidates whose first 2 bytes happen to be 0x01,0x03 are caught by this check).
    /// The payload is decoded as a [`TransportCaps`] via [`decode_transport_caps`]; a protocol
    /// error is surfaced as [`SessionError::Protocol`].
    async fn recv_peer_caps(
        &mut self,
        expected_kind: MessageKind,
    ) -> Result<TransportCaps, SessionError> {
        let env = self.signaling.recv().await?;
        if env.kind != expected_kind {
            return Err(SessionError::EnvelopeKindMismatch {
                expected: format!("{expected_kind:?}"),
                got: format!("{:?}", env.kind),
            });
        }

        // Require EXACT length: piggybacked blobs or oversized payloads are hostile input.
        if env.payload.len() != TRANSPORT_CAPS_LEN {
            return Err(SessionError::CapsPayloadWrongLength {
                expected: TRANSPORT_CAPS_LEN,
                got: env.payload.len(),
            });
        }

        // These indexing operations are safe: we verified payload.len() == TRANSPORT_CAPS_LEN.
        #[allow(clippy::indexing_slicing)]
        let caps_bytes = &env.payload[..TRANSPORT_CAPS_LEN];
        decode_transport_caps(caps_bytes).map_err(SessionError::Protocol)
    }

    /// Negotiate the transport, apply the security gate, and call the factory.
    ///
    /// This is the shared tail of both `establish_as_initiator` and `establish_as_responder`.
    fn negotiate_and_build(
        self,
        noise_outcome: &HandshakeOutcome,
        ice_path: &IcePathOutcome,
        peer_caps: TransportCaps,
    ) -> Result<(TransportKind, Box<dyn Transport>), SessionError> {
        // ── Step 3: Negotiate ─────────────────────────────────────────────────
        let kind = negotiate(self.local_caps, peer_caps)?;

        // ── Step 4: Security gate ─────────────────────────────────────────────
        let webrtc_peer_pin: Option<[u8; 32]> = match kind {
            TransportKind::Webrtc => {
                // MANDATORY: extract the verified DTLS pin from the Noise outcome.
                // If the peer committed ALG=NONE (no DTLS fingerprint), this returns
                // DtlsBindingMissing — the session is aborted. This is the non-bypassable
                // anti-downgrade gate for WebRTC sessions.
                let pin = noise_outcome
                    .require_webrtc_dtls_pin()
                    .map_err(|_| SessionError::DtlsBindingMissing)?;
                Some(pin)
            }
            TransportKind::Quic => {
                // For QUIC we must NOT have a DTLS commitment from the peer.
                // A peer that negotiated QUIC but whose BindCert includes a DTLS fingerprint
                // is behaving anomalously — this is a protocol violation and we reject it
                // defensively. See ADR-0015 §Security for policy rationale.
                if noise_outcome.peer_dtls_pin().is_some() {
                    return Err(SessionError::UnexpectedDtlsCommitment);
                }
                None
            }
        };

        // ── Step 5: Build ─────────────────────────────────────────────────────
        let transport = self.factory.build(kind, ice_path, webrtc_peer_pin)?;
        Ok((kind, transport))
    }

    /// Build a [`SignalingEnvelope`] carrying the local `TransportCaps` wire bytes.
    ///
    /// The `from_fp`, `to_fp`, and `session_id` fields are taken from the `SessionEstablisher`'s
    /// identity context so the zero-knowledge relay routes the envelope to the correct peer.
    fn make_caps_envelope(
        &self,
        kind: MessageKind,
        wire: &[u8; TRANSPORT_CAPS_LEN],
    ) -> SignalingEnvelope {
        SignalingEnvelope {
            kind,
            session_id: self.session_id,
            from_fp: self.local_fp.clone(),
            to_fp: self.peer_fp.clone(),
            payload: bytes::Bytes::copy_from_slice(wire),
        }
    }
}
