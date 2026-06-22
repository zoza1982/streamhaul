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
}
