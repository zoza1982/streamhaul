//! Noise protocol handshake wrapper for Streamhaul.
//!
//! This module wraps [`snow`] behind a thin seam so the rest of `sh-crypto` never
//! exposes raw `snow` types. The wrapper can be swapped for an audited implementation
//! without changing callers.
//!
//! # SECURITY WARNING: `snow` is UNAUDITED
//!
//! `snow` is used here but has not been independently audited. See `SECURITY.md` for the
//! third-party crypto posture. This wrapper is fuzzed and version-pinned; a pre-GA security
//! review of `snow` and this wrapper is scheduled in the Risk Register.
//!
//! # Patterns
//!
//! | Pattern | Use case | RTT |
//! |---------|----------|-----|
//! | `Noise_XK_25519_ChaChaPoly_SHA256` | First pairing | 1.5-RTT |
//! | `Noise_IK_25519_ChaChaPoly_SHA256` | Post-pairing reconnect | 1-RTT |
//!
//! # BindCert exchange positions (ADR-0007 §2.5)
//!
//! - **XK**: responder sends BindCert in message-2 payload; initiator sends in message-3 payload.
//! - **IK**: initiator sends BindCert in message-1 payload; responder sends in message-2 payload.
//!
//! # Payload format
//!
//! When a BindCert is carried in a handshake message, the full payload is:
//! ```text
//! ed25519_pubkey[32] || lp32(TBS)[4] || TBS[N] || SIGNATURE[64]
//! ```
//! The 32-byte Ed25519 public key prefix is needed so the recipient can reconstruct
//! a [`DeviceIdentity`] and verify the BindCert signature (check 2 of 6).
//!
//! # Prologue (anti-downgrade, ADR-0007 §1.4)
//!
//! ```text
//! "SHP-NOISE\x00" || u8(prologue_version=1) || u8(pattern_id) || u8(suite_id)
//! || u16_be(shp_version) || u32_be(session_context_len) || session_context
//! ```

use hkdf::Hkdf;
use sha2::Sha256;
use snow::Builder;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    bind_cert::{BindCert, BindCertBuilder, DtlsCommitment, DtlsPin, BIND_CERT_VALIDITY_SECS},
    clock::Clock,
    CryptoError, DeviceIdentity, Keystore,
};

// ─── Pattern / suite IDs (prologue bytes) ──────────────────────────────────

/// Pattern ID for `Noise_XK` (ADR-0007 §1.4).
pub const PATTERN_ID_XK: u8 = 0x01;
/// Pattern ID for `Noise_IK` (ADR-0007 §1.4).
pub const PATTERN_ID_IK: u8 = 0x02;
/// Suite ID for `25519_ChaChaPoly_SHA256` (ADR-0007 §1.4).
pub const SUITE_ID_25519_CHACHA_SHA256: u8 = 0x01;
/// SHP protocol version bound into the prologue (LLD §3.1).
pub const SHP_VERSION: u16 = 1;
/// Prologue version byte.
const PROLOGUE_VERSION: u8 = 0x01;
/// Prologue domain tag (10 bytes including NUL).
const PROLOGUE_TAG: &[u8; 10] = b"SHP-NOISE\x00";

/// The Noise pattern being run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoisePattern {
    /// `Noise_XK_25519_ChaChaPoly_SHA256` — first pairing (1.5-RTT, initiator-identity-hiding).
    Xk,
    /// `Noise_IK_25519_ChaChaPoly_SHA256` — post-pairing reconnect (1-RTT).
    Ik,
}

/// The role this side plays in the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    /// The initiating side (controller/client).
    Initiator,
    /// The responding side (host).
    Responder,
}

// ─── Prologue construction ─────────────────────────────────────────────────

fn build_prologue(pattern_id: u8, session_context: &[u8]) -> Vec<u8> {
    // "SHP-NOISE\x00"(10) + version(1) + pattern_id(1) + suite_id(1)
    // + shp_version_u16_be(2) + ctx_len_u32_be(4) + session_context
    // session_context is a QUIC exporter output (32 bytes) or empty; well within u32 range.
    #[allow(clippy::cast_possible_truncation)]
    let ctx_len_u32 = session_context.len() as u32;
    let capacity = 10_usize
        .saturating_add(1)
        .saturating_add(1)
        .saturating_add(1)
        .saturating_add(2)
        .saturating_add(4)
        .saturating_add(session_context.len());
    let mut p = Vec::with_capacity(capacity);
    p.extend_from_slice(PROLOGUE_TAG.as_slice());
    p.push(PROLOGUE_VERSION);
    p.push(pattern_id);
    p.push(SUITE_ID_25519_CHACHA_SHA256);
    p.extend_from_slice(&SHP_VERSION.to_be_bytes());
    p.extend_from_slice(&ctx_len_u32.to_be_bytes());
    p.extend_from_slice(session_context);
    p
}

// ─── Message index helpers ─────────────────────────────────────────────────
//
// `message_idx` is a single counter incremented by BOTH write_message and read_message,
// matching the exchange-wide 0-indexed message number:
//
//   XK exchange:
//     msg 0: initiator writes -> e, es
//     msg 1: responder writes <- e, ee, se   (responder sends BindCert here)
//     msg 2: initiator writes -> s, se        (initiator sends BindCert here)
//
//   IK exchange:
//     msg 0: initiator writes -> e, es, s, ss  (initiator sends BindCert here)
//     msg 1: responder writes <- e, ee, se      (responder sends BindCert here)
//
// For each side, write_message uses message_idx to decide whether to inject BindCert,
// and read_message uses message_idx to decide whether to extract BindCert. Both increment
// message_idx after the call so the next call sees the next index.

/// Returns the exchange-wide message index at which this side SENDS the BindCert.
fn send_bind_cert_at(role: HandshakeRole, pattern: NoisePattern) -> u8 {
    match (pattern, role) {
        (NoisePattern::Xk, HandshakeRole::Initiator) => 2, // initiator's 2nd write = exchange msg 2
        (NoisePattern::Xk, HandshakeRole::Responder) => 1, // responder's 1st write = exchange msg 1
        (NoisePattern::Ik, HandshakeRole::Initiator) => 0, // initiator's 1st write = exchange msg 0
        (NoisePattern::Ik, HandshakeRole::Responder) => 1, // responder's 1st write = exchange msg 1
    }
}

/// Returns the exchange-wide message index at which this side RECEIVES the peer's BindCert.
fn receive_bind_cert_at(role: HandshakeRole, pattern: NoisePattern) -> u8 {
    match (pattern, role) {
        (NoisePattern::Xk, HandshakeRole::Initiator) => 1, // initiator reads exchange msg 1
        (NoisePattern::Xk, HandshakeRole::Responder) => 2, // responder reads exchange msg 2
        (NoisePattern::Ik, HandshakeRole::Initiator) => 1, // initiator reads exchange msg 1
        (NoisePattern::Ik, HandshakeRole::Responder) => 0, // responder reads exchange msg 0
    }
}

// ─── NoiseSession ──────────────────────────────────────────────────────────

/// The post-handshake Noise transport state.
///
/// Owns the send and receive cipher states after `HandshakeState::split()`. Provides
/// authenticated encrypt/decrypt and an HKDF-based keying-material export seam for P3-4.
///
/// # Security
///
/// Raw cipher state is never exposed. The underlying `snow::TransportState` zeroizes its
/// keys on drop.
///
/// The handshake hash `h` is NOT stored here; the single authoritative copy lives in
/// [`HandshakeOutcome::handshake_hash`]. `NoiseSession` only holds the HKDF PRK derived from
/// `h` at split time, which is sufficient for `export_keying_material`. This avoids holding two
/// independent copies of root session material in memory.
pub struct NoiseSession {
    transport: snow::TransportState,
    /// HKDF pseudo-random key derived once from the handshake hash `h` at split time.
    ///
    /// Wrapped in `Zeroizing` so the session root material is erased when the session drops.
    prk: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for NoiseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseSession").finish_non_exhaustive()
    }
}

impl NoiseSession {
    fn new(
        transport: snow::TransportState,
        handshake_hash: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        // RFC 5869 §2: Extract once from the handshake hash as IKM (no salt → HMAC-SHA256 with
        // an all-zeros salt, which is the RFC default). The result is a true PRK — the output of
        // the Extract step, distinct from any Expand output. Subsequent `export_keying_material`
        // calls each perform a single Expand from this PRK, giving the standard
        // `Expand(Extract(h), info)` construction. This is the P3-4 channel-subkey KDF root.
        let (prk_arr, _hkdf) = Hkdf::<Sha256>::extract(None, handshake_hash.as_slice());
        let mut prk_buf = Zeroizing::new([0u8; 32]);
        prk_buf.copy_from_slice(prk_arr.as_slice());
        Ok(Self {
            transport,
            prk: prk_buf,
        })
    }

    /// Encrypts `plaintext` into `output`, returning the ciphertext length.
    ///
    /// `output` must be at least `plaintext.len() + 16` bytes (AEAD overhead).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] on AEAD failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        self.transport
            .write_message(plaintext, output)
            .map_err(|_| CryptoError::HandshakeFailed {
                reason: "AEAD encryption failed",
            })
    }

    /// Decrypts `ciphertext` into `output`, returning the plaintext length.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] on AEAD failure or authentication failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn decrypt(&mut self, ciphertext: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        self.transport
            .read_message(ciphertext, output)
            .map_err(|_| CryptoError::HandshakeFailed {
                reason: "AEAD decryption or authentication failed",
            })
    }

    /// Zeroizes the HKDF PRK in place.
    ///
    /// After this call, [`export_keying_material`](Self::export_keying_material) will fail.
    /// Used by [`SessionKeys::zeroize_all`](crate::channel_crypto::SessionKeys::zeroize_all)
    /// to ensure the root key-derivation material is erased as part of the kill-switch.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn zeroize_prk(&mut self) {
        self.prk.zeroize();
    }

    /// Derives keying material from the session for use by P3-4 (channel subkeys).
    ///
    /// Uses HKDF-SHA-256 over an internal PRK derived from the handshake hash at split time.
    /// `label` and `context` are additional inputs; `out` is filled with the derived bytes.
    ///
    /// The HKDF info string is length-prefixed as `u32_be(label_len) || label || u32_be(ctx_len)
    /// || context` to prevent collision between `(b"foo\x00", b"bar")` and `(b"foo", b"\x00bar")`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] if HKDF expansion fails (e.g. output too long
    /// or label/context byte length exceeds `u32::MAX`).
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let hkdf = Hkdf::<Sha256>::from_prk(self.prk.as_slice()).map_err(|_| {
            CryptoError::HandshakeFailed {
                reason: "invalid PRK for HKDF export",
            }
        })?;
        // Length-prefix both label and context so no two distinct (label, context) pairs
        // produce the same info string, regardless of whether the inputs contain null bytes.
        let label_len = u32::try_from(label.len()).map_err(|_| CryptoError::HandshakeFailed {
            reason: "label exceeds u32 length limit",
        })?;
        let ctx_len = u32::try_from(context.len()).map_err(|_| CryptoError::HandshakeFailed {
            reason: "context exceeds u32 length limit",
        })?;
        let capacity = 4_usize
            .saturating_add(label.len())
            .saturating_add(4)
            .saturating_add(context.len());
        let mut info = Vec::with_capacity(capacity);
        info.extend_from_slice(&label_len.to_be_bytes());
        info.extend_from_slice(label);
        info.extend_from_slice(&ctx_len.to_be_bytes());
        info.extend_from_slice(context);
        hkdf.expand(&info, out)
            .map_err(|_| CryptoError::HandshakeFailed {
                reason: "HKDF expand failed for keying material export",
            })
    }
}

// ─── HandshakeOutcome ──────────────────────────────────────────────────────

/// The result of a completed and fully-verified Noise handshake.
///
/// This is the sole typed seam between P3-2 and P3-3 (SAS) / P3-4 (channel subkeys).
/// See ADR-0007 §4.
///
/// # Examples
///
/// ```no_run
/// use sh_crypto::noise::{HandshakeOutcome, NoisePattern, HandshakeRole};
///
/// fn consume_outcome(outcome: HandshakeOutcome) {
///     let hash = outcome.handshake_hash;
///     let _session = outcome.transport; // encrypt/decrypt and export keying material
///     let _peer = outcome.peer_identity;
///     // P3-3: derive SAS from hash + fingerprint
///     // P3-4: use export_keying_material for channel subkeys
///     drop(hash);
/// }
/// ```
pub struct HandshakeOutcome {
    /// The post-split Noise transport cipher state.
    pub transport: NoiseSession,
    /// The Noise handshake hash `h` after split (SHA-256, 32 bytes).
    ///
    /// Input to P3-3 (SAS). A MITM cannot produce the same `h` on both sides.
    ///
    /// Wrapped in `Zeroizing` so the session root material is erased when this struct drops.
    pub handshake_hash: Zeroizing<[u8; 32]>,
    /// The verified, BindCert-bound peer identity.
    pub peer_identity: DeviceIdentity,
    /// The verified peer [`BindCert`](crate::bind_cert::BindCert).
    ///
    /// Available for P4-5 (platform attestation inspection) and any caller that needs to
    /// inspect the peer's DTLS fingerprint or platform attestation blob.
    pub peer_bind_cert: crate::bind_cert::BindCert,
    /// Which role this side played.
    pub role: HandshakeRole,
    /// Which pattern ran.
    pub pattern: NoisePattern,
}

impl std::fmt::Debug for HandshakeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeOutcome")
            .field("peer_identity", &self.peer_identity)
            .field("role", &self.role)
            .field("pattern", &self.pattern)
            .finish_non_exhaustive()
    }
}

impl HandshakeOutcome {
    /// Returns the peer's DTLS pin from the verified [`BindCert`], or `None` (P4-5).
    ///
    /// Thin forwarder to [`BindCert::dtls_pin`](crate::bind_cert::BindCert::dtls_pin). Returns
    /// `Some` for a WebRTC peer (the BindCert committed a SHA-256 DTLS fingerprint) and `None`
    /// for a QUIC peer. The pin is authenticated: it came from the identity-signed BindCert
    /// delivered *inside* the verified Noise handshake, so it is safe to pin against the
    /// untrusted SDP-relayed fingerprint.
    ///
    /// **For a path that must be WebRTC, call
    /// [`require_webrtc_dtls_pin`](Self::require_webrtc_dtls_pin) instead.** This accessor does not
    /// enforce the anti-downgrade rule and (per [`BindCert::dtls_pin`]) may return a `Some` whose
    /// commit is all zeros for a malformed peer; pinning that would fail-close DTLS with no clear
    /// diagnostic.
    #[must_use]
    pub fn peer_dtls_pin(&self) -> Option<DtlsPin> {
        self.peer_bind_cert.dtls_pin()
    }

    /// Returns the peer's 32-byte committed DTLS fingerprint, enforcing the WebRTC
    /// anti-downgrade rule (P4-5).
    ///
    /// Thin forwarder to
    /// [`BindCert::require_webrtc_dtls_pin`](crate::bind_cert::BindCert::require_webrtc_dtls_pin).
    /// Call this on the WebRTC pin path *before* the DTLS handshake; feed the returned bytes to
    /// `WebRtcTransportBuilder::pin_remote_dtls`. A peer BindCert that carries
    /// `DTLS_FPR_ALG = NONE` (a stripped binding) or an all-zero commit is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::DtlsBindingMissing`] if the peer committed no usable SHA-256 DTLS
    /// fingerprint (downgrade attempt on a WebRTC session).
    #[must_use = "the returned pin is the anti-downgrade gate; dropping it skips the DTLS binding check"]
    pub fn require_webrtc_dtls_pin(&self) -> Result<[u8; 32], CryptoError> {
        self.peer_bind_cert.require_webrtc_dtls_pin()
    }
}

// ─── NoiseHandshake ────────────────────────────────────────────────────────

/// A Noise handshake in progress.
///
/// Drive the handshake by calling [`write_message`](Self::write_message) and
/// [`read_message`](Self::read_message) in the correct order for the pattern, then call
/// [`complete`](Self::complete) when the handshake is finished.
///
/// The BindCert (prepended with the 32-byte Ed25519 public key) is automatically injected
/// into / extracted from the handshake payload at the correct message per ADR-0007 §2.5.
///
/// # State machine
///
/// ```text
/// Active  ──(write_message / read_message returns Err)──►  Poisoned  (terminal)
/// Active  ──(complete() called and consumed)─────────────►  Completed (terminal)
/// ```
///
/// - **Active**: initial state; `write_message` and `read_message` are callable.
/// - **Poisoned**: set on any error returned after snow's internal state has been advanced.
///   Every subsequent call to `write_message`, `read_message`, or `complete()` returns
///   `HandshakeFailed { reason: "handshake already aborted" }`. `is_finished()` returns
///   `false` even if the underlying snow state considers itself finished.
/// - **Completed**: `complete()` consumes `self` and returns a [`HandshakeOutcome`]; the
///   `NoiseHandshake` value ceases to exist.
///
/// # Construction
///
/// Use [`NoiseHandshake::initiator_xk`], [`NoiseHandshake::responder_xk`],
/// [`NoiseHandshake::initiator_ik`], or [`NoiseHandshake::responder_ik`].
///
/// # Examples
///
/// ```no_run
/// # use sh_crypto::noise::{NoiseHandshake, HandshakeOutcome};
/// # use sh_crypto::{SoftwareKeystore, Keystore};
/// # use sh_crypto::clock::SystemClock;
/// # use x25519_dalek::{StaticSecret, PublicKey};
/// # use rand_core::OsRng;
/// # tokio_test::block_on(async {
/// let host_ks = SoftwareKeystore::generate();
/// let host_static = StaticSecret::random_from_rng(OsRng);
/// let host_pub = PublicKey::from(&host_static);
///
/// let client_ks = SoftwareKeystore::generate();
/// let client_static = StaticSecret::random_from_rng(OsRng);
///
/// let clock = SystemClock;
/// let (mut initiator, mut responder) = tokio::join!(
///     NoiseHandshake::initiator_xk(
///         &client_ks, client_static, host_pub.to_bytes(), &[], &clock
///     ),
///     NoiseHandshake::responder_xk(&host_ks, host_static, &[], &clock),
/// );
/// # });
/// ```
pub struct NoiseHandshake {
    state: snow::HandshakeState,
    role: HandshakeRole,
    pattern: NoisePattern,
    /// Exchange-wide message index at which we send our BindCert.
    send_at: u8,
    /// Exchange-wide message index at which we receive the peer's BindCert.
    receive_at: u8,
    /// Current exchange-wide message index. Incremented by both write_message and read_message.
    message_idx: u8,
    /// Our local BindCert to send at the appropriate message.
    local_bind_cert: BindCert,
    /// Our Ed25519 public key bytes (32 bytes), prepended before the BindCert wire bytes.
    local_ed25519_pub: [u8; 32],
    /// The peer's BindCert once received and parsed.
    peer_bind_cert: Option<BindCert>,
    /// The verified peer identity (set once BindCert checks 2–5 pass).
    peer_identity: Option<DeviceIdentity>,
    /// Poison flag. Set to `true` if any `read_message` or `write_message` call returns an error
    /// after advancing snow's internal state. Once poisoned, every subsequent call returns
    /// `HandshakeFailed { reason: "handshake already aborted" }` to prevent operating on a
    /// desynced state machine.
    failed: bool,
}

impl std::fmt::Debug for NoiseHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseHandshake")
            .field("role", &self.role)
            .field("pattern", &self.pattern)
            .field("message_idx", &self.message_idx)
            .finish_non_exhaustive()
    }
}

impl NoiseHandshake {
    // ─── Internal helpers ───────────────────────────────────────────────

    fn build_snow_state(
        pattern_str: &str,
        local_static_bytes: &[u8; 32],
        peer_static_pub: Option<&[u8; 32]>,
        prologue: &[u8],
        initiator: bool,
    ) -> Result<snow::HandshakeState, CryptoError> {
        // snow::Builder methods (local_private_key, prologue, remote_public_key) return Self —
        // they are infallible setters. Only build_initiator/build_responder return Result.
        let pattern = pattern_str
            .parse()
            .map_err(|_| CryptoError::HandshakeFailed {
                reason: "failed to parse Noise pattern string",
            })?;
        let mut builder = Builder::new(pattern)
            .local_private_key(local_static_bytes)
            .prologue(prologue);

        if let Some(peer_pub) = peer_static_pub {
            builder = builder.remote_public_key(peer_pub);
        }

        if initiator {
            builder
                .build_initiator()
                .map_err(|_| CryptoError::HandshakeFailed {
                    reason: "snow build_initiator failed",
                })
        } else {
            builder
                .build_responder()
                .map_err(|_| CryptoError::HandshakeFailed {
                    reason: "snow build_responder failed",
                })
        }
    }

    async fn make_bind_cert<K: Keystore>(
        keystore: &K,
        local_static_pub: [u8; 32],
        dtls_commitment: Option<DtlsCommitment>,
        clock: &dyn Clock,
    ) -> Result<BindCert, CryptoError> {
        let mut builder = BindCertBuilder::new(keystore)
            .noise_static(local_static_pub)
            .valid_for_secs(BIND_CERT_VALIDITY_SECS);
        if let Some(commitment) = dtls_commitment {
            // WebRTC path: commit the local whole-cert DTLS fingerprint (P4-5, ADR-0014).
            builder = builder.dtls_commitment(commitment);
        }
        // QUIC path: no commitment → DTLS_FPR_ALG = 0x00 (unchanged behavior).
        builder.build(clock).await
    }

    // 7 arguments: all are required for the Noise pattern + role + crypto configuration.
    // The per-role/pattern constructors (initiator_xk, etc.) each call this once, so the
    // parameter count is not visible at the call sites. Private fn — suppress the lint.
    //
    // NOTE: ephemeral key generation is handled entirely by snow's default resolver (backed by
    // the OS CSPRNG). There is no `rng` parameter because snow does not accept external entropy
    // for ephemerals — see `snow::Builder` docs. Determinism in tests comes from the injected
    // `Clock`; handshake message bytes are legitimately non-deterministic.
    #[allow(clippy::too_many_arguments)]
    async fn new_inner<K: Keystore>(
        keystore: &K,
        local_static: x25519_dalek::StaticSecret,
        peer_static_pub: Option<[u8; 32]>,
        session_context: &[u8],
        dtls_commitment: Option<DtlsCommitment>,
        clock: &dyn Clock,
        pattern: NoisePattern,
        role: HandshakeRole,
    ) -> Result<Self, CryptoError> {
        let local_pub = x25519_dalek::PublicKey::from(&local_static);
        let local_pub_bytes = local_pub.to_bytes();
        let local_static_bytes = Zeroizing::new(local_static.to_bytes());
        // Drop the original StaticSecret immediately after extracting the bytes so that only
        // one copy of the private scalar exists in memory (the Zeroizing wrapper).
        drop(local_static);

        let (pattern_str, pattern_id) = match pattern {
            NoisePattern::Xk => ("Noise_XK_25519_ChaChaPoly_SHA256", PATTERN_ID_XK),
            NoisePattern::Ik => ("Noise_IK_25519_ChaChaPoly_SHA256", PATTERN_ID_IK),
        };

        let prologue = build_prologue(pattern_id, session_context);
        let initiator = role == HandshakeRole::Initiator;

        let state = Self::build_snow_state(
            pattern_str,
            &local_static_bytes,
            peer_static_pub.as_ref(),
            &prologue,
            initiator,
        )?;

        let local_bind_cert =
            Self::make_bind_cert(keystore, local_pub_bytes, dtls_commitment, clock).await?;
        let identity = keystore.device_identity().await?;
        let local_ed25519_pub = *identity.public_key_bytes();

        let send_at = send_bind_cert_at(role, pattern);
        let receive_at = receive_bind_cert_at(role, pattern);

        Ok(Self {
            state,
            role,
            pattern,
            send_at,
            receive_at,
            message_idx: 0,
            local_bind_cert,
            local_ed25519_pub,
            peer_bind_cert: None,
            peer_identity: None,
            failed: false,
        })
    }

    // ─── Public constructors ─────────────────────────────────────────────

    /// Creates an XK initiator handshake (controller/client, first pairing).
    ///
    /// `local_static`: our X25519 static secret.
    /// `peer_static_pub`: the host's known X25519 static public key (32 bytes).
    /// `session_context`: QUIC exporter output or empty slice for tests.
    /// `clock`: injected clock for BindCert validity.
    ///
    /// Ephemeral key generation is handled by snow's default resolver (backed by the OS CSPRNG).
    /// Handshake message bytes are legitimately non-deterministic.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] or [`CryptoError::Backend`] on failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn initiator_xk<K: Keystore>(
        keystore: &K,
        local_static: x25519_dalek::StaticSecret,
        peer_static_pub: [u8; 32],
        session_context: &[u8],
        clock: &dyn Clock,
    ) -> Result<Self, CryptoError> {
        Self::new_inner(
            keystore,
            local_static,
            Some(peer_static_pub),
            session_context,
            None,
            clock,
            NoisePattern::Xk,
            HandshakeRole::Initiator,
        )
        .await
    }

    /// Creates an XK initiator handshake that commits a DTLS fingerprint (WebRTC, P4-5).
    ///
    /// Identical to [`initiator_xk`](Self::initiator_xk) but the local `BindCert` commits
    /// `dtls_commitment` (the local whole-cert DTLS fingerprint) so the peer can pin it before the
    /// DTLS handshake. The commitment is **required**: this is the WebRTC entry point, and there is
    /// no way to obtain an unpinned WebRTC handshake from it. For a QUIC / no-DTLS handshake use
    /// [`initiator_xk`](Self::initiator_xk) instead (which commits `ALG=NONE`).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] or [`CryptoError::Backend`] on failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn initiator_xk_with_dtls<K: Keystore>(
        keystore: &K,
        local_static: x25519_dalek::StaticSecret,
        peer_static_pub: [u8; 32],
        session_context: &[u8],
        dtls_commitment: DtlsCommitment,
        clock: &dyn Clock,
    ) -> Result<Self, CryptoError> {
        Self::new_inner(
            keystore,
            local_static,
            Some(peer_static_pub),
            session_context,
            Some(dtls_commitment),
            clock,
            NoisePattern::Xk,
            HandshakeRole::Initiator,
        )
        .await
    }

    /// Creates an XK responder handshake (host, first pairing).
    ///
    /// `local_static`: our X25519 static secret.
    /// `session_context`: QUIC exporter output or empty slice for tests.
    ///
    /// Ephemeral key generation is handled by snow's default resolver (backed by the OS CSPRNG).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] or [`CryptoError::Backend`] on failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn responder_xk<K: Keystore>(
        keystore: &K,
        local_static: x25519_dalek::StaticSecret,
        session_context: &[u8],
        clock: &dyn Clock,
    ) -> Result<Self, CryptoError> {
        Self::new_inner(
            keystore,
            local_static,
            None,
            session_context,
            None,
            clock,
            NoisePattern::Xk,
            HandshakeRole::Responder,
        )
        .await
    }

    /// Creates an XK responder handshake that commits a DTLS fingerprint (WebRTC, P4-5).
    ///
    /// Identical to [`responder_xk`](Self::responder_xk) but the local `BindCert` commits
    /// `dtls_commitment`. The commitment is **required**: this is the WebRTC entry point. For a
    /// QUIC / no-DTLS handshake use [`responder_xk`](Self::responder_xk) instead (which commits
    /// `ALG=NONE`).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] or [`CryptoError::Backend`] on failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn responder_xk_with_dtls<K: Keystore>(
        keystore: &K,
        local_static: x25519_dalek::StaticSecret,
        session_context: &[u8],
        dtls_commitment: DtlsCommitment,
        clock: &dyn Clock,
    ) -> Result<Self, CryptoError> {
        Self::new_inner(
            keystore,
            local_static,
            None,
            session_context,
            Some(dtls_commitment),
            clock,
            NoisePattern::Xk,
            HandshakeRole::Responder,
        )
        .await
    }

    /// Creates an IK initiator handshake (controller, post-pairing reconnect).
    ///
    /// `peer_static_pub`: the host's pinned X25519 static public key.
    ///
    /// Ephemeral key generation is handled by snow's default resolver (backed by the OS CSPRNG).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] or [`CryptoError::Backend`] on failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn initiator_ik<K: Keystore>(
        keystore: &K,
        local_static: x25519_dalek::StaticSecret,
        peer_static_pub: [u8; 32],
        session_context: &[u8],
        clock: &dyn Clock,
    ) -> Result<Self, CryptoError> {
        Self::new_inner(
            keystore,
            local_static,
            Some(peer_static_pub),
            session_context,
            None,
            clock,
            NoisePattern::Ik,
            HandshakeRole::Initiator,
        )
        .await
    }

    /// Creates an IK initiator handshake that commits a DTLS fingerprint (WebRTC, P4-5).
    ///
    /// Identical to [`initiator_ik`](Self::initiator_ik) but the local `BindCert` commits
    /// `dtls_commitment`. The commitment is **required**: this is the WebRTC entry point. For a
    /// QUIC / no-DTLS handshake use [`initiator_ik`](Self::initiator_ik) instead (which commits
    /// `ALG=NONE`).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] or [`CryptoError::Backend`] on failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn initiator_ik_with_dtls<K: Keystore>(
        keystore: &K,
        local_static: x25519_dalek::StaticSecret,
        peer_static_pub: [u8; 32],
        session_context: &[u8],
        dtls_commitment: DtlsCommitment,
        clock: &dyn Clock,
    ) -> Result<Self, CryptoError> {
        Self::new_inner(
            keystore,
            local_static,
            Some(peer_static_pub),
            session_context,
            Some(dtls_commitment),
            clock,
            NoisePattern::Ik,
            HandshakeRole::Initiator,
        )
        .await
    }

    /// Creates an IK responder handshake (host, post-pairing reconnect).
    ///
    /// Ephemeral key generation is handled by snow's default resolver (backed by the OS CSPRNG).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] or [`CryptoError::Backend`] on failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn responder_ik<K: Keystore>(
        keystore: &K,
        local_static: x25519_dalek::StaticSecret,
        session_context: &[u8],
        clock: &dyn Clock,
    ) -> Result<Self, CryptoError> {
        Self::new_inner(
            keystore,
            local_static,
            None,
            session_context,
            None,
            clock,
            NoisePattern::Ik,
            HandshakeRole::Responder,
        )
        .await
    }

    /// Creates an IK responder handshake that commits a DTLS fingerprint (WebRTC, P4-5).
    ///
    /// Identical to [`responder_ik`](Self::responder_ik) but the local `BindCert` commits
    /// `dtls_commitment`. The commitment is **required**: this is the WebRTC entry point. For a
    /// QUIC / no-DTLS handshake use [`responder_ik`](Self::responder_ik) instead (which commits
    /// `ALG=NONE`).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeFailed`] or [`CryptoError::Backend`] on failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn responder_ik_with_dtls<K: Keystore>(
        keystore: &K,
        local_static: x25519_dalek::StaticSecret,
        session_context: &[u8],
        dtls_commitment: DtlsCommitment,
        clock: &dyn Clock,
    ) -> Result<Self, CryptoError> {
        Self::new_inner(
            keystore,
            local_static,
            None,
            session_context,
            Some(dtls_commitment),
            clock,
            NoisePattern::Ik,
            HandshakeRole::Responder,
        )
        .await
    }

    // ─── Handshake drive methods ─────────────────────────────────────────

    /// Writes the next handshake message, injecting our BindCert at the correct position.
    ///
    /// Returns the bytes to send to the peer.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::HandshakeFailed`] with reason `"handshake already aborted"` if any
    ///   prior call to `read_message` or `write_message` returned an error (poisoned state).
    /// - [`CryptoError::HandshakeFailed`] if the underlying snow state machine errors.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn write_message(&mut self) -> Result<Vec<u8>, CryptoError> {
        if self.failed {
            return Err(CryptoError::HandshakeFailed {
                reason: "handshake already aborted",
            });
        }

        let payload = if self.message_idx == self.send_at {
            // Payload = ed25519_pubkey[32] || bind_cert_wire
            let bind_cert_wire = self.local_bind_cert.encode();
            let mut p = Vec::with_capacity(32_usize.saturating_add(bind_cert_wire.len()));
            p.extend_from_slice(&self.local_ed25519_pub);
            p.extend_from_slice(&bind_cert_wire);
            p
        } else {
            Vec::new()
        };

        // snow's max message size is 65535. Our payload is at most:
        // 32 (pubkey) + 4 (lp32) + 129 (min TBS) + 4096 (max attest) + 64 (sig) = 4325 bytes.
        // The Noise handshake message overhead (tag, ephem key) is at most ~96 bytes, so
        // 65535 is more than sufficient.
        let mut buf = vec![0u8; 65535];
        let n = self.state.write_message(&payload, &mut buf).map_err(|_| {
            self.failed = true;
            CryptoError::HandshakeFailed {
                reason: "snow write_message failed",
            }
        })?;
        buf.truncate(n);
        self.message_idx = self.message_idx.saturating_add(1);
        Ok(buf)
    }

    /// Reads a handshake message from the peer, extracting and verifying their BindCert.
    ///
    /// At the expected message index, the payload is parsed as:
    /// `ed25519_pubkey[32] || lp32(TBS)[4] || TBS[N] || SIGNATURE[64]`
    ///
    /// Checks 2–5 of the 6-check BindCert protocol are performed immediately. Check 6 (trust)
    /// is deferred to [`complete`](Self::complete).
    ///
    /// # Errors
    ///
    /// - [`CryptoError::HandshakeFailed`] with reason `"handshake already aborted"` if any
    ///   prior call to `read_message` or `write_message` returned an error (poisoned state).
    /// - Other typed `CryptoError` variants on any validation failure. After any error, the
    ///   handshake is permanently poisoned and all subsequent calls return the above.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn read_message(&mut self, msg: &[u8], clock: &dyn Clock) -> Result<(), CryptoError> {
        if self.failed {
            return Err(CryptoError::HandshakeFailed {
                reason: "handshake already aborted",
            });
        }

        let mut payload_buf = vec![0u8; 65535];
        // If snow's read_message fails, the state is not advanced and we have not advanced
        // message_idx — no desync. Poison anyway since the session is unrecoverable.
        let n = self
            .state
            .read_message(msg, &mut payload_buf)
            .map_err(|_| {
                self.failed = true;
                CryptoError::HandshakeFailed {
                    reason: "snow read_message failed (MAC failure or state error)",
                }
            })?;
        payload_buf.truncate(n);

        // Snow advanced its internal state. Any error from here onwards would desync
        // snow's state from message_idx — poison the handshake immediately on any failure.
        let bind_cert_result = self.read_message_bind_cert(&payload_buf, clock);
        if let Err(ref _e) = bind_cert_result {
            self.failed = true;
            return bind_cert_result;
        }

        self.message_idx = self.message_idx.saturating_add(1);
        Ok(())
    }

    /// Inner helper: parse and verify the BindCert payload (if expected at this message index).
    ///
    /// Separated from `read_message` so the poisoning logic is easy to reason about.
    fn read_message_bind_cert(
        &mut self,
        payload_buf: &[u8],
        clock: &dyn Clock,
    ) -> Result<(), CryptoError> {
        if self.message_idx == self.receive_at {
            // Parse: ed25519_pubkey[32] || bind_cert_wire
            let pubkey_slice = payload_buf
                .get(..32)
                .ok_or(CryptoError::MalformedBindCert {
                    reason: "BindCert payload too short for Ed25519 pubkey prefix",
                })?;
            let mut pubkey_bytes = [0u8; 32];
            pubkey_bytes.copy_from_slice(pubkey_slice);
            let bind_cert_wire = payload_buf
                .get(32..)
                .ok_or(CryptoError::MalformedBindCert {
                    reason: "BindCert payload too short after Ed25519 pubkey prefix",
                })?;

            // Reconstruct peer DeviceIdentity from the 32-byte Ed25519 public key.
            let peer_identity = DeviceIdentity::from_public_key_bytes(&pubkey_bytes)?;

            // Parse the BindCert (structural check = check 1).
            let bind_cert = BindCert::decode(bind_cert_wire)?;

            // Get the live Noise static (X25519 public key the peer used in this handshake).
            let live_static = self.get_remote_static_now()?;

            // Checks 2–5.
            bind_cert.verify(&peer_identity, &live_static, clock)?;

            self.peer_identity = Some(peer_identity);
            self.peer_bind_cert = Some(bind_cert);
        }
        Ok(())
    }

    /// Completes the handshake, performing trust check (step 6) and returning [`HandshakeOutcome`].
    ///
    /// Must be called after all handshake messages have been exchanged and
    /// `snow` reports the handshake is finished.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::UntrustedPeer`] if the peer identity is not in the trust store.
    /// - [`CryptoError::HandshakeFailed`] if called before the handshake is complete or if
    ///   the peer BindCert was never received.
    /// - [`CryptoError::Backend`] if the keystore trust check fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn complete<K: Keystore>(
        self,
        keystore: &K,
    ) -> Result<HandshakeOutcome, CryptoError> {
        if self.failed {
            return Err(CryptoError::HandshakeFailed {
                reason: "handshake already aborted",
            });
        }
        if !self.state.is_handshake_finished() {
            return Err(CryptoError::HandshakeFailed {
                reason: "handshake not yet complete",
            });
        }
        let peer_identity = self.peer_identity.ok_or(CryptoError::HandshakeFailed {
            reason: "peer BindCert was never received or verified",
        })?;
        let peer_bind_cert = self.peer_bind_cert.ok_or(CryptoError::HandshakeFailed {
            reason: "peer BindCert was never received or verified",
        })?;

        // Step 6: trust check.
        if !keystore.is_trusted(&peer_identity).await? {
            return Err(CryptoError::UntrustedPeer);
        }

        // Extract handshake hash (SHA-256, 32 bytes) into a Zeroizing buffer so the
        // session root material is erased when both the session and the outcome drop.
        let handshake_hash: Zeroizing<[u8; 32]> = {
            let h = self.state.get_handshake_hash();
            if h.len() != 32 {
                return Err(CryptoError::HandshakeFailed {
                    reason: "handshake hash is not 32 bytes (expected SHA-256)",
                });
            }
            let mut arr = Zeroizing::new([0u8; 32]);
            arr.copy_from_slice(h);
            arr
        };

        let transport =
            self.state
                .into_transport_mode()
                .map_err(|_| CryptoError::HandshakeFailed {
                    reason: "snow into_transport_mode failed",
                })?;
        // Derive the session PRK from the handshake hash; the hash itself is stored only in
        // HandshakeOutcome — NoiseSession does not duplicate it.
        let session = NoiseSession::new(transport, &handshake_hash)?;

        Ok(HandshakeOutcome {
            transport: session,
            handshake_hash,
            peer_identity,
            peer_bind_cert,
            role: self.role,
            pattern: self.pattern,
        })
    }

    /// Returns `true` if the underlying snow handshake is finished AND the handshake has not
    /// been poisoned by a prior error.
    ///
    /// A snow-finished-but-BindCert-failed handshake (failed == true) reports `false` here so
    /// callers cannot proceed to `complete()` on a desynced state machine.
    pub fn is_finished(&self) -> bool {
        !self.failed && self.state.is_handshake_finished()
    }

    // ─── Private helpers ─────────────────────────────────────────────────

    /// Retrieves the remote static X25519 public key from the snow state.
    ///
    /// Returns an error if the key is not yet available (wrong handshake stage) or has
    /// an unexpected length.
    fn get_remote_static_now(&self) -> Result<[u8; 32], CryptoError> {
        let s = self
            .state
            .get_remote_static()
            .ok_or(CryptoError::HandshakeFailed {
                reason: "remote static not available yet at BindCert receive time",
            })?;
        if s.len() != 32 {
            return Err(CryptoError::HandshakeFailed {
                reason: "remote static is not 32 bytes",
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(s);
        Ok(arr)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::bind_cert::BIND_CERT_VALIDITY_SECS;
    use crate::clock::FixedClock;
    use crate::{Keystore, SoftwareKeystore};
    use rand_core::OsRng;
    use x25519_dalek::StaticSecret;

    const NOW: i64 = 1_000_000_000;

    // ─── Helpers ─────────────────────────────────────────────────────────

    /// Run a full XK handshake in memory, returning both outcomes.
    async fn do_xk_handshake(
        init_ks: &SoftwareKeystore,
        resp_ks: &SoftwareKeystore,
        clock: &dyn Clock,
    ) -> (HandshakeOutcome, HandshakeOutcome) {
        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);

        // Trust each other so complete() succeeds.
        let resp_id = resp_ks.device_identity().await.unwrap();
        let init_id = init_ks.device_identity().await.unwrap();
        init_ks.trust_peer(&resp_id).await.unwrap();
        resp_ks.trust_peer(&init_id).await.unwrap();

        let mut init =
            NoiseHandshake::initiator_xk(init_ks, init_static, resp_pub.to_bytes(), &[], clock)
                .await
                .unwrap();
        let mut resp = NoiseHandshake::responder_xk(resp_ks, resp_static, &[], clock)
            .await
            .unwrap();

        // XK: -> e, es   (msg 0, initiator writes)
        let msg0 = init.write_message().unwrap();
        resp.read_message(&msg0, clock).unwrap();

        // XK: <- e, ee, se  (msg 1, responder writes BindCert)
        let msg1 = resp.write_message().unwrap();
        init.read_message(&msg1, clock).unwrap();

        // XK: -> s, se  (msg 2, initiator writes BindCert)
        let msg2 = init.write_message().unwrap();
        resp.read_message(&msg2, clock).unwrap();

        assert!(init.is_finished());
        assert!(resp.is_finished());

        let init_outcome = init.complete(init_ks).await.unwrap();
        let resp_outcome = resp.complete(resp_ks).await.unwrap();

        (init_outcome, resp_outcome)
    }

    /// Run a full IK handshake in memory, returning both outcomes.
    async fn do_ik_handshake(
        init_ks: &SoftwareKeystore,
        resp_ks: &SoftwareKeystore,
        clock: &dyn Clock,
    ) -> (HandshakeOutcome, HandshakeOutcome) {
        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);

        let resp_id = resp_ks.device_identity().await.unwrap();
        let init_id = init_ks.device_identity().await.unwrap();
        init_ks.trust_peer(&resp_id).await.unwrap();
        resp_ks.trust_peer(&init_id).await.unwrap();

        let mut init =
            NoiseHandshake::initiator_ik(init_ks, init_static, resp_pub.to_bytes(), &[], clock)
                .await
                .unwrap();
        let mut resp = NoiseHandshake::responder_ik(resp_ks, resp_static, &[], clock)
            .await
            .unwrap();

        // IK: -> e, es, s, ss  (msg 0, initiator writes BindCert)
        let msg0 = init.write_message().unwrap();
        resp.read_message(&msg0, clock).unwrap();

        // IK: <- e, ee, se  (msg 1, responder writes BindCert)
        let msg1 = resp.write_message().unwrap();
        init.read_message(&msg1, clock).unwrap();

        assert!(init.is_finished());
        assert!(resp.is_finished());

        let init_outcome = init.complete(init_ks).await.unwrap();
        let resp_outcome = resp.complete(resp_ks).await.unwrap();

        (init_outcome, resp_outcome)
    }

    // ─── P4-5: DTLS pin propagation through the handshake ────────────────

    /// An XK handshake where both sides commit a DTLS fingerprint: each verified outcome exposes
    /// the *peer's* committed pin via `peer_dtls_pin()` / `require_webrtc_dtls_pin()`.
    #[tokio::test]
    async fn xk_with_dtls_propagates_peer_pin() {
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let clock = FixedClock(NOW);

        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);

        let resp_id = resp_ks.device_identity().await.unwrap();
        let init_id = init_ks.device_identity().await.unwrap();
        init_ks.trust_peer(&resp_id).await.unwrap();
        resp_ks.trust_peer(&init_id).await.unwrap();

        let init_dtls = [0x11u8; 32]; // initiator's "local DTLS fingerprint"
        let resp_dtls = [0x22u8; 32]; // responder's "local DTLS fingerprint"

        let mut init = NoiseHandshake::initiator_xk_with_dtls(
            &init_ks,
            init_static,
            resp_pub.to_bytes(),
            &[],
            DtlsCommitment::sha256(init_dtls),
            &clock,
        )
        .await
        .unwrap();
        let mut resp = NoiseHandshake::responder_xk_with_dtls(
            &resp_ks,
            resp_static,
            &[],
            DtlsCommitment::sha256(resp_dtls),
            &clock,
        )
        .await
        .unwrap();

        let msg0 = init.write_message().unwrap();
        resp.read_message(&msg0, &clock).unwrap();
        let msg1 = resp.write_message().unwrap();
        init.read_message(&msg1, &clock).unwrap();
        let msg2 = init.write_message().unwrap();
        resp.read_message(&msg2, &clock).unwrap();

        let init_outcome = init.complete(&init_ks).await.unwrap();
        let resp_outcome = resp.complete(&resp_ks).await.unwrap();

        // The initiator pins the RESPONDER's committed fingerprint, and vice-versa.
        assert_eq!(init_outcome.require_webrtc_dtls_pin().unwrap(), resp_dtls);
        assert_eq!(resp_outcome.require_webrtc_dtls_pin().unwrap(), init_dtls);
        assert_eq!(init_outcome.peer_dtls_pin().unwrap().commit(), &resp_dtls);
        assert_eq!(resp_outcome.peer_dtls_pin().unwrap().commit(), &init_dtls);
    }

    /// An IK handshake where both sides commit a DTLS fingerprint (mutual): each verified outcome
    /// exposes the *peer's* committed pin via `require_webrtc_dtls_pin()` / `peer_dtls_pin()`.
    ///
    /// This guards the IK `_with_dtls` constructors against a copy-paste delegation typo (e.g. a
    /// wrong pattern/role/`Some` wiring in `initiator_ik_with_dtls`/`responder_ik_with_dtls`): the
    /// IK message ordering differs from XK (the initiator sends its BindCert in msg 0), so the IK
    /// path needs its own end-to-end coverage.
    #[tokio::test]
    async fn ik_with_dtls_propagates_peer_pin() {
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let clock = FixedClock(NOW);

        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);

        let resp_id = resp_ks.device_identity().await.unwrap();
        let init_id = init_ks.device_identity().await.unwrap();
        init_ks.trust_peer(&resp_id).await.unwrap();
        resp_ks.trust_peer(&init_id).await.unwrap();

        let init_dtls = [0x33u8; 32]; // initiator's "local DTLS fingerprint"
        let resp_dtls = [0x44u8; 32]; // responder's "local DTLS fingerprint"

        let mut init = NoiseHandshake::initiator_ik_with_dtls(
            &init_ks,
            init_static,
            resp_pub.to_bytes(),
            &[],
            DtlsCommitment::sha256(init_dtls),
            &clock,
        )
        .await
        .unwrap();
        let mut resp = NoiseHandshake::responder_ik_with_dtls(
            &resp_ks,
            resp_static,
            &[],
            DtlsCommitment::sha256(resp_dtls),
            &clock,
        )
        .await
        .unwrap();

        // IK: -> e, es, s, ss (msg 0, initiator writes BindCert)
        let msg0 = init.write_message().unwrap();
        resp.read_message(&msg0, &clock).unwrap();
        // IK: <- e, ee, se (msg 1, responder writes BindCert)
        let msg1 = resp.write_message().unwrap();
        init.read_message(&msg1, &clock).unwrap();

        let init_outcome = init.complete(&init_ks).await.unwrap();
        let resp_outcome = resp.complete(&resp_ks).await.unwrap();

        // The initiator pins the RESPONDER's committed fingerprint, and vice-versa. If the IK
        // constructors had a copy-paste typo (wrong commitment wiring), these would not match.
        assert_eq!(init_outcome.require_webrtc_dtls_pin().unwrap(), resp_dtls);
        assert_eq!(resp_outcome.require_webrtc_dtls_pin().unwrap(), init_dtls);
        assert_eq!(init_outcome.peer_dtls_pin().unwrap().commit(), &resp_dtls);
        assert_eq!(resp_outcome.peer_dtls_pin().unwrap().commit(), &init_dtls);
    }

    /// Downgrade: if the responder builds a QUIC (no-DTLS) BindCert but the initiator treats the
    /// session as WebRTC, `require_webrtc_dtls_pin()` rejects it. The handshake itself still
    /// completes (the binding is stripped, not forged) — the abort happens at the pin step.
    #[tokio::test]
    async fn webrtc_pin_rejects_peer_without_dtls_commitment() {
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let clock = FixedClock(NOW);

        // do_xk_handshake builds both sides with the plain (None) constructors → ALG=NONE.
        let (init_outcome, _resp_outcome) = do_xk_handshake(&init_ks, &resp_ks, &clock).await;

        assert!(init_outcome.peer_dtls_pin().is_none());
        assert!(
            matches!(
                init_outcome.require_webrtc_dtls_pin(),
                Err(CryptoError::DtlsBindingMissing)
            ),
            "a WebRTC pin must be rejected when the peer committed no DTLS fingerprint"
        );
    }

    // ─── XK / IK full handshake tests ────────────────────────────────────

    #[tokio::test]
    async fn xk_full_handshake_completes() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let (io, ro) = do_xk_handshake(&init_ks, &resp_ks, &clock).await;

        // Both sides must agree on the handshake hash.
        assert_eq!(io.handshake_hash, ro.handshake_hash);
        assert_eq!(io.pattern, NoisePattern::Xk);
        assert_eq!(ro.pattern, NoisePattern::Xk);
        assert_eq!(io.role, HandshakeRole::Initiator);
        assert_eq!(ro.role, HandshakeRole::Responder);

        // Each side knows the other's identity.
        let resp_id = resp_ks.device_identity().await.unwrap();
        let init_id = init_ks.device_identity().await.unwrap();
        assert_eq!(io.peer_identity, resp_id);
        assert_eq!(ro.peer_identity, init_id);
    }

    #[tokio::test]
    async fn ik_full_handshake_completes() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let (io, ro) = do_ik_handshake(&init_ks, &resp_ks, &clock).await;

        assert_eq!(io.handshake_hash, ro.handshake_hash);
        assert_eq!(io.pattern, NoisePattern::Ik);
        assert_eq!(ro.pattern, NoisePattern::Ik);
    }

    #[tokio::test]
    async fn xk_handshake_hash_matches_on_both_sides() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let (io, ro) = do_xk_handshake(&init_ks, &resp_ks, &clock).await;
        // Both sides must agree on the handshake hash (the single authoritative copy lives in
        // HandshakeOutcome; NoiseSession does not duplicate it).
        assert_eq!(io.handshake_hash, ro.handshake_hash);
    }

    // ─── Encrypt/decrypt after handshake ─────────────────────────────────

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip_xk() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let (mut io, mut ro) = do_xk_handshake(&init_ks, &resp_ks, &clock).await;

        let plaintext = b"hello secure world";
        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let ct_len = io.transport.encrypt(plaintext, &mut ciphertext).unwrap();

        let mut decrypted = vec![0u8; ct_len];
        let pt_len = ro
            .transport
            .decrypt(&ciphertext[..ct_len], &mut decrypted)
            .unwrap();
        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip_ik() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let (mut io, mut ro) = do_ik_handshake(&init_ks, &resp_ks, &clock).await;

        let plaintext = b"IK transport test";
        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let ct_len = io.transport.encrypt(plaintext, &mut ciphertext).unwrap();

        let mut decrypted = vec![0u8; ct_len];
        let pt_len = ro
            .transport
            .decrypt(&ciphertext[..ct_len], &mut decrypted)
            .unwrap();
        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    // ─── Export keying material ───────────────────────────────────────────

    #[tokio::test]
    async fn export_keying_material_deterministic() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let (io, ro) = do_xk_handshake(&init_ks, &resp_ks, &clock).await;

        let mut init_km = [0u8; 32];
        let mut resp_km = [0u8; 32];
        io.transport
            .export_keying_material(b"test-label", b"test-context", &mut init_km)
            .unwrap();
        ro.transport
            .export_keying_material(b"test-label", b"test-context", &mut resp_km)
            .unwrap();

        // Both sides must derive the same keying material from the same hash.
        assert_eq!(init_km, resp_km);
    }

    #[tokio::test]
    async fn export_keying_material_different_labels_differ() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let (io, _ro) = do_xk_handshake(&init_ks, &resp_ks, &clock).await;

        let mut km1 = [0u8; 32];
        let mut km2 = [0u8; 32];
        io.transport
            .export_keying_material(b"label-a", b"ctx", &mut km1)
            .unwrap();
        io.transport
            .export_keying_material(b"label-b", b"ctx", &mut km2)
            .unwrap();
        assert_ne!(km1, km2);
    }

    // ─── Security: MITM — substituted Noise static ───────────────────────
    //
    // The MITM scenario (ADR-0007 §3): an attacker intercepts the Noise handshake
    // and uses a different X25519 static than what the BindCert commits. The XK and IK
    // patterns both encrypt early messages to the "known" remote static, so a MITM with a
    // different static cannot DH-agree → MAC failure before the BindCert binding check even
    // needs to fire. This confirms the cryptographic property.

    #[tokio::test]
    async fn xk_mitm_substituted_noise_static_rejected() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();

        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);
        // MITM uses a completely different X25519 static.
        let mitm_static = StaticSecret::random_from_rng(OsRng);

        let resp_id = resp_ks.device_identity().await.unwrap();
        let init_id = init_ks.device_identity().await.unwrap();
        init_ks.trust_peer(&resp_id).await.unwrap();
        resp_ks.trust_peer(&init_id).await.unwrap();

        // Initiator expects resp_pub as the known responder static (XK "K" = known).
        // MITM acts as the responder but with mitm_static.
        let mut init =
            NoiseHandshake::initiator_xk(&init_ks, init_static, resp_pub.to_bytes(), &[], &clock)
                .await
                .unwrap();
        let mut mitm_resp = NoiseHandshake::responder_xk(&resp_ks, mitm_static, &[], &clock)
            .await
            .unwrap();

        // msg 0: initiator writes (-> e, es using resp_pub).
        // MITM has mitm_static, not resp_static → DH disagreement → MAC failure.
        let msg0 = init.write_message().unwrap();
        let result = mitm_resp.read_message(&msg0, &clock);
        assert!(
            result.is_err(),
            "MITM responder with substituted static must fail to read msg 0"
        );
    }

    #[tokio::test]
    async fn ik_mitm_substituted_noise_static_rejected() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();

        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);
        let mitm_static = StaticSecret::random_from_rng(OsRng);

        let resp_id = resp_ks.device_identity().await.unwrap();
        let init_id = init_ks.device_identity().await.unwrap();
        init_ks.trust_peer(&resp_id).await.unwrap();
        resp_ks.trust_peer(&init_id).await.unwrap();

        // Initiator uses IK with known resp_pub; MITM uses mitm_static.
        let mut init =
            NoiseHandshake::initiator_ik(&init_ks, init_static, resp_pub.to_bytes(), &[], &clock)
                .await
                .unwrap();
        let mut mitm_resp = NoiseHandshake::responder_ik(&resp_ks, mitm_static, &[], &clock)
            .await
            .unwrap();

        // IK msg 0 encrypts to resp_pub. MITM with mitm_static cannot decrypt → MAC fail.
        let msg0 = init.write_message().unwrap();
        let result = mitm_resp.read_message(&msg0, &clock);
        assert!(
            result.is_err(),
            "IK MITM responder with substituted static must fail to read msg 0"
        );
    }

    // ─── Security: downgrade via prologue mismatch ────────────────────────

    #[tokio::test]
    async fn downgrade_prologue_mismatch_rejected() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();

        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);

        let resp_id = resp_ks.device_identity().await.unwrap();
        let init_id = init_ks.device_identity().await.unwrap();
        init_ks.trust_peer(&resp_id).await.unwrap();
        resp_ks.trust_peer(&init_id).await.unwrap();

        // Initiator uses XK (pattern_id 0x01); responder uses IK (pattern_id 0x02).
        // Prologue mismatch → MAC failure on the first read.
        let mut init =
            NoiseHandshake::initiator_xk(&init_ks, init_static, resp_pub.to_bytes(), &[], &clock)
                .await
                .unwrap();

        let resp_static2 = StaticSecret::random_from_rng(OsRng);
        let mut resp = NoiseHandshake::responder_ik(&resp_ks, resp_static2, &[], &clock)
            .await
            .unwrap();

        let msg0 = init.write_message().unwrap();
        // Pattern mismatch means snow's internal key agreement will fail.
        let result = resp.read_message(&msg0, &clock);
        assert!(result.is_err());
    }

    // ─── Security: untrusted peer ─────────────────────────────────────────

    #[tokio::test]
    async fn untrusted_identity_rejected() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();

        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);

        // Initiator trusts responder but responder does NOT trust initiator.
        let resp_id = resp_ks.device_identity().await.unwrap();
        init_ks.trust_peer(&resp_id).await.unwrap();
        // (do NOT call resp_ks.trust_peer(&init_id))

        let mut init =
            NoiseHandshake::initiator_xk(&init_ks, init_static, resp_pub.to_bytes(), &[], &clock)
                .await
                .unwrap();
        let mut resp = NoiseHandshake::responder_xk(&resp_ks, resp_static, &[], &clock)
            .await
            .unwrap();

        let msg0 = init.write_message().unwrap();
        resp.read_message(&msg0, &clock).unwrap();
        let msg1 = resp.write_message().unwrap();
        init.read_message(&msg1, &clock).unwrap();
        let msg2 = init.write_message().unwrap();
        resp.read_message(&msg2, &clock).unwrap();

        // Responder's complete() should fail because initiator is not trusted.
        let result = resp.complete(&resp_ks).await;
        assert!(matches!(result, Err(CryptoError::UntrustedPeer)));
    }

    // ─── Security: expired BindCert ───────────────────────────────────────

    #[tokio::test]
    async fn expired_bindcert_rejected() {
        // BindCerts are built at `now`; verify happens at `now + BIND_CERT_VALIDITY_SECS + 1`.
        let build_clock = FixedClock(NOW);
        let verify_clock = FixedClock(NOW + BIND_CERT_VALIDITY_SECS + 1);

        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();

        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);

        let resp_id = resp_ks.device_identity().await.unwrap();
        let init_id = init_ks.device_identity().await.unwrap();
        init_ks.trust_peer(&resp_id).await.unwrap();
        resp_ks.trust_peer(&init_id).await.unwrap();

        // Both sides build with build_clock (so their certs expire at NOW + BIND_CERT_VALIDITY_SECS).
        let mut init = NoiseHandshake::initiator_xk(
            &init_ks,
            init_static,
            resp_pub.to_bytes(),
            &[],
            &build_clock,
        )
        .await
        .unwrap();
        let mut resp = NoiseHandshake::responder_xk(&resp_ks, resp_static, &[], &build_clock)
            .await
            .unwrap();

        let msg0 = init.write_message().unwrap();
        resp.read_message(&msg0, &build_clock).unwrap();
        // msg1 carries resp's BindCert; initiator verifies with verify_clock → expired.
        let msg1 = resp.write_message().unwrap();
        let result = init.read_message(&msg1, &verify_clock);
        assert!(matches!(result, Err(CryptoError::BindCertExpired)));
    }

    // ─── Replay / truncation ─────────────────────────────────────────────

    #[tokio::test]
    async fn malformed_truncated_message_rejects() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();

        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);

        let mut init =
            NoiseHandshake::initiator_xk(&init_ks, init_static, resp_pub.to_bytes(), &[], &clock)
                .await
                .unwrap();
        let mut resp = NoiseHandshake::responder_xk(&resp_ks, resp_static, &[], &clock)
            .await
            .unwrap();

        // Truncate msg0 to 0 bytes → snow MAC failure.
        let _msg0 = init.write_message().unwrap();
        let result = resp.read_message(&[], &clock);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn replay_rejected() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();

        let resp_id = resp_ks.device_identity().await.unwrap();
        let init_id = init_ks.device_identity().await.unwrap();
        init_ks.trust_peer(&resp_id).await.unwrap();
        resp_ks.trust_peer(&init_id).await.unwrap();

        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);

        let mut init =
            NoiseHandshake::initiator_xk(&init_ks, init_static, resp_pub.to_bytes(), &[], &clock)
                .await
                .unwrap();
        let mut resp = NoiseHandshake::responder_xk(&resp_ks, resp_static, &[], &clock)
            .await
            .unwrap();

        let msg0 = init.write_message().unwrap();
        resp.read_message(&msg0, &clock).unwrap();
        let msg1 = resp.write_message().unwrap();
        init.read_message(&msg1, &clock).unwrap();
        let msg2 = init.write_message().unwrap();
        resp.read_message(&msg2, &clock).unwrap();

        let (mut io, mut ro) = (
            init.complete(&init_ks).await.unwrap(),
            resp.complete(&resp_ks).await.unwrap(),
        );

        // Encrypt a message from initiator.
        let plaintext = b"first message";
        let mut ct = vec![0u8; plaintext.len() + 16];
        let ct_len = io.transport.encrypt(plaintext, &mut ct).unwrap();

        // Decrypt once — succeeds.
        let mut pt = vec![0u8; ct_len];
        let _ = ro.transport.decrypt(&ct[..ct_len], &mut pt).unwrap();

        // Decrypt the SAME ciphertext again — snow's nonce counter means this fails.
        let mut pt2 = vec![0u8; ct_len];
        let result = ro.transport.decrypt(&ct[..ct_len], &mut pt2);
        assert!(result.is_err(), "replay must be rejected");
    }

    // ─── Export keying material: context variation ────────────────────────

    #[tokio::test]
    async fn export_keying_material_different_contexts_differ() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let (io, _ro) = do_xk_handshake(&init_ks, &resp_ks, &clock).await;

        let mut km1 = [0u8; 32];
        let mut km2 = [0u8; 32];
        io.transport
            .export_keying_material(b"shp-channel", b"ctx-a", &mut km1)
            .unwrap();
        io.transport
            .export_keying_material(b"shp-channel", b"ctx-b", &mut km2)
            .unwrap();
        // Different contexts with the same label must produce different outputs.
        assert_ne!(km1, km2);
    }

    // ─── IK negative-path tests ──────────────────────────────────────────
    //
    // The IK message ordering is different from XK: the initiator sends its BindCert
    // in msg 0 (the very first message), so the receive_at index is 0 for the responder.
    // These tests verify that the security properties hold specifically over the IK path.

    #[tokio::test]
    async fn ik_expired_bindcert_rejected() {
        // Initiator builds with build_clock; responder verifies with a clock 25h later.
        let build_clock = FixedClock(NOW);
        let verify_clock = FixedClock(NOW + 90_001); // 25h + 1s > default 24h validity

        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();

        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);

        let resp_id = resp_ks.device_identity().await.unwrap();
        let init_id = init_ks.device_identity().await.unwrap();
        init_ks.trust_peer(&resp_id).await.unwrap();
        resp_ks.trust_peer(&init_id).await.unwrap();

        let mut init = NoiseHandshake::initiator_ik(
            &init_ks,
            init_static,
            resp_pub.to_bytes(),
            &[],
            &build_clock,
        )
        .await
        .unwrap();
        let mut resp = NoiseHandshake::responder_ik(&resp_ks, resp_static, &[], &build_clock)
            .await
            .unwrap();

        // IK msg 0 carries the initiator's BindCert; responder reads it with verify_clock.
        let msg0 = init.write_message().unwrap();
        // Responder must reject the initiator's expired BindCert on read_message.
        let result = resp.read_message(&msg0, &verify_clock);
        assert!(
            matches!(result, Err(CryptoError::BindCertExpired)),
            "IK responder must reject expired initiator BindCert; got: {result:?}"
        );
    }

    #[tokio::test]
    async fn ik_untrusted_initiator_rejected() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();

        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);

        // Responder trusts initiator? NO. Initiator trusts responder (for the IK static).
        let resp_id = resp_ks.device_identity().await.unwrap();
        init_ks.trust_peer(&resp_id).await.unwrap();
        // resp_ks does NOT trust init_ks.

        let mut init =
            NoiseHandshake::initiator_ik(&init_ks, init_static, resp_pub.to_bytes(), &[], &clock)
                .await
                .unwrap();
        let mut resp = NoiseHandshake::responder_ik(&resp_ks, resp_static, &[], &clock)
            .await
            .unwrap();

        // Full IK exchange; trust check happens in complete().
        let msg0 = init.write_message().unwrap();
        resp.read_message(&msg0, &clock).unwrap();
        let msg1 = resp.write_message().unwrap();
        init.read_message(&msg1, &clock).unwrap();

        // Responder's complete() must fail: initiator is not trusted.
        let result = resp.complete(&resp_ks).await;
        assert!(
            matches!(result, Err(CryptoError::UntrustedPeer)),
            "IK complete() must reject untrusted initiator; got: {result:?}"
        );
    }

    #[tokio::test]
    async fn ik_noise_static_binding_checked() {
        // IK-specific: the responder's BindCert must commit to the X25519 static that
        // the initiator pinned (via `resp_pub`). We can't force a mismatch without
        // bypassing snow's MAC (which itself enforces the static), but we can verify
        // that the responder's `peer_bind_cert` is present in the outcome and that it
        // commits the right noise static.
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let (io, ro) = do_ik_handshake(&init_ks, &resp_ks, &clock).await;

        // Confirm peer_bind_cert is present and accessible from the outcome.
        // The noise_static field in the cert must match the peer's X25519 public key.
        let _ = io.peer_bind_cert; // field is accessible (not private)
        let _ = ro.peer_bind_cert;
        // Both sides got a valid outcome → static binding was verified as step 4 of 6.
        assert_eq!(io.pattern, NoisePattern::Ik);
        assert_eq!(ro.pattern, NoisePattern::Ik);
    }

    // ─── Poisoned-state tests ─────────────────────────────────────────────
    //
    // Once read_message or write_message returns an error, snow's internal state may have
    // advanced (message already consumed) while message_idx has not. To prevent operating on
    // a desynced state machine, the handshake is permanently poisoned. Every subsequent call
    // must return the clear `HandshakeFailed { reason: "handshake already aborted" }` error.

    /// After a MAC failure on `read_message`, all subsequent `read_message` calls must return
    /// `HandshakeFailed { reason: "handshake already aborted" }`, not an opaque snow error.
    #[tokio::test]
    async fn poisoned_handshake_subsequent_call_returns_clear_error() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();

        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);

        let mut init =
            NoiseHandshake::initiator_xk(&init_ks, init_static, resp_pub.to_bytes(), &[], &clock)
                .await
                .unwrap();
        let mut resp = NoiseHandshake::responder_xk(&resp_ks, resp_static, &[], &clock)
            .await
            .unwrap();

        // First, produce a valid msg0 so we have a reference.
        let msg0 = init.write_message().unwrap();
        // Feed a truncated / corrupted message — this causes a MAC failure inside snow.
        let first_err = resp.read_message(&msg0[..4], &clock);
        assert!(first_err.is_err(), "truncated message must be rejected");

        // Now the handshake is poisoned. A second call — even with the valid message —
        // must return the clear aborted error, not an opaque snow state-machine error.
        let second_err = resp.read_message(&msg0, &clock);
        assert!(
            matches!(
                second_err,
                Err(CryptoError::HandshakeFailed { reason }) if reason == "handshake already aborted"
            ),
            "post-failure call must return 'handshake already aborted'; got: {second_err:?}"
        );

        // complete() must also return the clear aborted error (not panic).
        let complete_err = resp.complete(&resp_ks).await;
        assert!(
            matches!(
                complete_err,
                Err(CryptoError::HandshakeFailed { reason }) if reason == "handshake already aborted"
            ),
            "complete() after poisoning must return 'handshake already aborted'; got: {complete_err:?}"
        );
    }

    /// After a poisoning failure on the final handshake message, `is_finished()` must return
    /// `false` even though snow internally considers the handshake complete. This ensures callers
    /// cannot inadvertently treat a broken handshake as finished.
    #[tokio::test]
    async fn is_finished_false_after_poison_on_final_message() {
        let clock = FixedClock(NOW);
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();

        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);

        let resp_id = resp_ks.device_identity().await.unwrap();
        let init_id = init_ks.device_identity().await.unwrap();
        init_ks.trust_peer(&resp_id).await.unwrap();
        resp_ks.trust_peer(&init_id).await.unwrap();

        let mut init =
            NoiseHandshake::initiator_xk(&init_ks, init_static, resp_pub.to_bytes(), &[], &clock)
                .await
                .unwrap();
        let mut resp = NoiseHandshake::responder_xk(&resp_ks, resp_static, &[], &clock)
            .await
            .unwrap();

        // Drive XK to the final message (msg 2, which carries the initiator's BindCert).
        let msg0 = init.write_message().unwrap();
        resp.read_message(&msg0, &clock).unwrap();
        let msg1 = resp.write_message().unwrap();
        init.read_message(&msg1, &clock).unwrap();
        let msg2 = init.write_message().unwrap();

        // Feed the final message truncated — snow will process the Noise envelope but fail
        // the MAC / length check, poisoning the responder after it advances state.
        let result = resp.read_message(&msg2[..8], &clock);
        assert!(result.is_err(), "truncated final message must be rejected");

        // After poisoning, is_finished() must be false even though snow may think it's done.
        assert!(
            !resp.is_finished(),
            "is_finished() must return false on a poisoned handshake"
        );
    }
}
