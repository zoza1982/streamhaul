//! Typed error enum for `sh-crypto`.

use thiserror::Error;

/// All errors that can be returned by `sh-crypto` operations.
///
/// # Examples
///
/// ```
/// use sh_crypto::CryptoError;
///
/// let e = CryptoError::MalformedSignature { reason: "wrong length" };
/// assert!(e.to_string().contains("wrong length"));
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// A signature verification failed (bad signature or mismatched key/data).
    ///
    /// Treat this as an authentication failure — do not log the raw bytes involved.
    #[error("signature verification failed")]
    Signature,

    /// The peer's [`crate::DeviceIdentity`] is not in the local trust store.
    ///
    /// Callers should reject the connection and prompt the user to perform TOFU pairing.
    #[error("peer identity is not trusted")]
    UntrustedPeer,

    /// The supplied public-key bytes are not a valid Ed25519 verifying key.
    #[error("malformed key: {reason}")]
    MalformedKey {
        /// A human-readable description of the validation failure.
        reason: &'static str,
    },

    /// The supplied signature bytes cannot be decoded as a 64-byte Ed25519 signature.
    #[error("malformed signature: {reason}")]
    MalformedSignature {
        /// A human-readable description of the decode failure.
        reason: &'static str,
    },

    /// An underlying keystore backend operation failed.
    ///
    /// This variant wraps OS-level or hardware-security-module errors. The payload string is
    /// suitable for logging but must not contain key material.
    #[error("keystore backend error: {0}")]
    Backend(String),

    /// A received `BindCert` is malformed or fails structural validation.
    #[error("malformed BindCert: {reason}")]
    MalformedBindCert {
        /// A human-readable description (no secret bytes).
        reason: &'static str,
    },

    /// The live Noise static key does not match the Noise static committed in the `BindCert`.
    ///
    /// This indicates a key-substitution MITM attempt.
    #[error("Noise static key does not match BindCert commitment")]
    NoiseStaticMismatch,

    /// The `BindCert`'s `NOT_AFTER` timestamp has passed.
    #[error("BindCert has expired")]
    BindCertExpired,

    /// The `BindCert`'s `ISSUED_AT` timestamp is in the future (beyond clock skew tolerance).
    #[error("BindCert is not yet valid")]
    BindCertNotYetValid,

    /// The Noise handshake failed (MAC or state machine error).
    #[error("handshake failed: {reason}")]
    HandshakeFailed {
        /// Description of the failure (no secret bytes).
        reason: &'static str,
    },

    /// Protocol downgrade detected (prologue mismatch).
    ///
    /// Reserved for explicit downgrade-detection logic that distinguishes a prologue
    /// mismatch from other handshake failures. Currently, prologue mismatches surface as
    /// [`HandshakeFailed`](Self::HandshakeFailed) (snow returns a MAC error indistinguishably).
    /// A future pass will inspect snow's error type and promote prologue-mismatch errors
    /// to this variant so callers can count/log active downgrade attempts separately.
    ///
    /// Do not match on this variant expecting to receive it from the current implementation.
    #[error("protocol downgrade detected")]
    Downgrade,

    // ── P3-3: pairing ───────────────────────────────────────────────────────
    /// The Short Authentication String (SAS) values shown to the human did not match.
    ///
    /// This variant is used when an automated SAS comparison detects a mismatch. In the
    /// attended pairing flow, the human is the comparator and this is signalled via
    /// [`PairingOutcome::Aborted`](crate::pairing::PairingOutcome::Aborted) instead.
    #[error("SAS mismatch — possible MITM; pairing aborted")]
    SasMismatch,

    /// The PAKE key-confirmation MAC did not match.
    ///
    /// This indicates either a wrong pairing code or an active attack (relay / relay-substitute
    /// attack). One online guess has been consumed; the pairing code should be invalidated.
    ///
    /// **Security:** do not log the attempted code or any keying material. Only log this event
    /// and the peer fingerprint for rate-limiting purposes.
    #[error("PAKE key-confirmation failed — wrong code or active attack")]
    PakeConfirmationFailed,

    /// The pairing code's `not_after` timestamp has passed.
    ///
    /// The code is expired and must not be used for a PAKE exchange. A new code should be
    /// generated.
    #[error("pairing code has expired")]
    PairingCodeExpired,

    /// A PAKE message is structurally invalid (wrong length, bad encoding, etc.).
    ///
    /// `reason` is a human-readable description suitable for logging. It MUST NOT contain
    /// any secret material (codes, keys, or keying material).
    #[error("malformed PAKE message: {reason}")]
    MalformedPakeMessage {
        /// A human-readable description of the validation failure (no secrets).
        reason: &'static str,
    },

    /// A previously revoked peer attempted re-pairing; explicit operator confirmation required.
    ///
    /// The pairing layer detected that the peer identity was previously revoked (R-HW-KS).
    /// Re-pinning has been blocked. The operator must perform an explicit separate confirmation
    /// action before `Keystore::trust_peer` is called for this identity.
    ///
    /// This is NOT returned by `pair_attended` / `pair_unattended` — those return
    /// [`PairingOutcome::ReTrustAfterRevokeRequiresConfirmation`](crate::pairing::PairingOutcome::ReTrustAfterRevokeRequiresConfirmation)
    /// instead. This variant exists for contexts where a `CryptoError` is the only
    /// available return channel.
    #[error("peer was previously revoked; explicit operator re-trust confirmation required")]
    ReTrustAfterRevoke,

    // ── P3-4: channel crypto ────────────────────────────────────────────────
    /// AEAD seal or open failed (authentication tag did not verify, or encryption failed).
    ///
    /// This covers both encryption and decryption AEAD failures. No key material in the message.
    #[error("AEAD operation failed")]
    AeadFailure,

    /// A received frame's sequence number has already been seen (replay attack or duplicate).
    #[error("replayed frame: seq already accepted")]
    ReplayedFrame,

    /// The received frame's epoch is more than 1 ahead of the current epoch.
    ///
    /// A well-behaved peer advances at most one epoch at a time. Drop the frame and log at warn
    /// level; no teardown is required. A single occurrence may indicate packet reordering during a
    /// rekey; repeated occurrences from the same peer are a sign of a misbehaving or malicious
    /// peer and should be rate-limited.
    #[error("epoch too far ahead")]
    EpochTooFarAhead,

    /// The sequence or generation counter would exceed its hard limit.
    ///
    /// This prevents nonce reuse. The caller must trigger a rekey before sealing more frames.
    #[error("nonce counter exhausted: rekey required")]
    NonceExhausted,

    /// A channel frame header is structurally invalid.
    #[error("malformed channel frame: {reason}")]
    MalformedChannelFrame {
        /// Description of the parse failure. No secret bytes.
        reason: &'static str,
    },

    // ── P3-5: authorization / UGC ──────────────────────────────────────────────
    /// A received UGC is structurally invalid (bad domain tag, bad length, trailing garbage, etc.).
    #[error("malformed UGC: {reason}")]
    MalformedUgc {
        /// Human-readable description (no secret bytes).
        reason: &'static str,
    },

    /// The UGC signature did not verify against the pinned host identity.
    ///
    /// Treat as a forgery attempt. Do not log the UGC payload.
    #[error("UGC signature verification failed")]
    UgcBadSignature,

    /// The UGC's GRANTEE_DEVICE_ID does not match the authenticated peer identity.
    ///
    /// This blocks stolen-UGC replay: a valid UGC for device A is useless to device B
    /// because it cannot become the authenticated Noise peer_identity without A's key.
    #[error("UGC grantee does not match authenticated peer identity")]
    UgcWrongGrantee,

    /// The UGC has expired or its ISSUED_AT is in the future.
    #[error("UGC is expired or not yet valid")]
    UgcExpired,

    /// The UGC's epoch is below the host's minimum-epoch floor (revoked).
    ///
    /// The host operator has bumped `min_epoch` above this UGC's epoch. A re-issued UGC
    /// with a higher epoch is required for unattended access.
    #[error("UGC epoch is below the minimum-epoch floor (revoked)")]
    UgcRevoked,
}
