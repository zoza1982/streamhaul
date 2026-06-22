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
}
