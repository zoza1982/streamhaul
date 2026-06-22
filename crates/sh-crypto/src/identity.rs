//! [`DeviceIdentity`] and [`Fingerprint`] — the public-facing device identity type.
//!
//! # Design rationale
//!
//! `DeviceIdentity` carries only **public** information — the Ed25519 verifying key and its
//! fingerprint. No secret material is ever stored here or accessible through any accessor.
//!
//! ## Fingerprint format
//!
//! The fingerprint is the **SHA-256 digest of the 32-byte compressed Ed25519 public key**,
//! encoded as **lowercase hex** (64 characters). We chose SHA-256/hex because:
//!
//! - SHA-256 is well-understood, hardware-accelerated on all target platforms, and already in
//!   the dependency tree via `sha2`.
//! - Hex is unambiguous, copy-pasteable, and widely understood. Base32/Base58 would shorten
//!   display strings but add a dependency and a decoding layer.
//! - A 256-bit fingerprint is ample collision resistance for the peer-pinning use case.
//!
//! A **short form** (first 16 hex chars = 64 bits of the digest) is exposed via
//! [`Fingerprint::short`] for SAS-style attended display. 64 bits provides ~4 billion pairs
//! before a collision, which is sufficient for human comparison but NOT for automated identity
//! checks — always use the full fingerprint for programmatic comparison.
//!
//! ## Equality semantics
//!
//! Two `DeviceIdentity` values are considered equal when their **full fingerprints** are equal.
//! Because the fingerprint is derived deterministically from the public key bytes, this is
//! equivalent to byte-equality of the public keys. The public key is not secret, so we use
//! standard (non-constant-time) equality. If constant-time comparison is ever needed (e.g., for
//! equality used in a MAC comparison), callers must use `subtle::ConstantTimeEq` directly on
//! the underlying key bytes — that is not the case for identity comparison.

use std::fmt;

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

/// A stable, human-comparable fingerprint derived from an Ed25519 public key.
///
/// The fingerprint is the SHA-256 hash of the 32-byte compressed public key, encoded as
/// lowercase hexadecimal (64 characters). It is the **public `device_id`** that the relay
/// routing layer uses to identify peers and that users compare out-of-band to detect MITM.
///
/// # Examples
///
/// ```
/// use sh_crypto::{SoftwareKeystore, Keystore};
///
/// # tokio_test::block_on(async {
/// let ks = SoftwareKeystore::generate();
/// let id = ks.device_identity().await.unwrap();
/// let fp = id.fingerprint();
/// assert_eq!(fp.as_str().len(), 64, "full fingerprint is 64 hex chars");
/// assert_eq!(fp.short().len(), 16, "short form is 16 hex chars");
/// # });
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint(
    /// 64-character lowercase hex string.
    String,
);

impl Fingerprint {
    /// Computes a fingerprint from the given verifying key.
    pub(crate) fn from_verifying_key(key: &VerifyingKey) -> Self {
        let digest = Sha256::digest(key.as_bytes());
        // Build the hex string in one allocation.
        let mut hex = String::with_capacity(64);
        for b in digest.iter() {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
        }
        Self(hex)
    }

    /// Returns the full fingerprint as a 64-character lowercase hex string.
    ///
    /// This is the canonical form for programmatic identity comparison and storage.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the first 16 hex characters of the fingerprint (64 bits of entropy).
    ///
    /// Suitable for SAS-style attended display. **Do not use for automated identity checks**;
    /// use [`as_str`](Self::as_str) for the full fingerprint.
    ///
    /// # Panics
    ///
    /// Never panics. The inner string is always exactly 64 ASCII hex characters (invariant
    /// maintained by the sole constructor [`Fingerprint::from_verifying_key`]), so the
    /// `[..16]` slice is always in-bounds.
    pub fn short(&self) -> &str {
        // Invariant: the string is always exactly 64 ASCII hex characters; 16 is in-bounds.
        &self.0[..16]
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", &self.0[..16])
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The public Ed25519 identity of a Streamhaul device.
///
/// A `DeviceIdentity` carries only public data: the Ed25519 **verifying key** and its
/// **fingerprint**. No secret material is stored here. This value is freely shareable —
/// it is exchanged in-band during the Noise handshake (P3-2) and committed in the
/// `BindCert` (P4-5).
///
/// # Equality
///
/// Two identities are equal iff their fingerprints are equal (which is equivalent to their
/// verifying keys being equal, since the fingerprint is a deterministic hash of the key bytes).
/// Equality uses standard (non-constant-time) comparison because the public key is not secret.
///
/// # Examples
///
/// ```
/// use sh_crypto::{SoftwareKeystore, Keystore};
///
/// # tokio_test::block_on(async {
/// let ks = SoftwareKeystore::generate();
/// let id1 = ks.device_identity().await.unwrap();
/// let id2 = ks.device_identity().await.unwrap();
/// // The fingerprint is stable across calls.
/// assert_eq!(id1.fingerprint(), id2.fingerprint());
/// # });
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DeviceIdentity {
    verifying_key: VerifyingKey,
    fingerprint: Fingerprint,
}

impl DeviceIdentity {
    /// Constructs a `DeviceIdentity` from an Ed25519 verifying key.
    ///
    /// The fingerprint is derived deterministically from `key` and cached.
    pub(crate) fn from_verifying_key(key: VerifyingKey) -> Self {
        let fingerprint = Fingerprint::from_verifying_key(&key);
        Self {
            verifying_key: key,
            fingerprint,
        }
    }

    /// Returns the fingerprint of this identity.
    ///
    /// The fingerprint is the SHA-256 of the 32-byte compressed public key, hex-encoded (64
    /// characters). It is stable: the same key always produces the same fingerprint.
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Returns the raw 32-byte compressed Ed25519 public key.
    ///
    /// This is useful for embedding the key in a `BindCert` or for wire serialization. The
    /// bytes are public and safe to log or transmit.
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        self.verifying_key.as_bytes()
    }

    /// Constructs a `DeviceIdentity` from a 32-byte compressed public key slice.
    ///
    /// # Errors
    ///
    /// Returns [`crate::CryptoError::MalformedKey`] if:
    /// - The bytes do not decompress to a valid Ed25519 curve point, or
    /// - The key is a small-order (weak) point in a torsion subgroup. Small-order keys are
    ///   rejected as a defense-in-depth measure: they can never be pinned in the trust store,
    ///   appear in a `BindCert`, or be used in signature verification — even though
    ///   [`Signature::verify`] already uses `verify_strict` which would also reject them.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_crypto::{DeviceIdentity, SoftwareKeystore, Keystore};
    ///
    /// # tokio_test::block_on(async {
    /// let ks = SoftwareKeystore::generate();
    /// let id = ks.device_identity().await.unwrap();
    /// let bytes = *id.public_key_bytes();
    /// let roundtrip = DeviceIdentity::from_public_key_bytes(&bytes).unwrap();
    /// assert_eq!(id, roundtrip);
    /// # });
    /// ```
    pub fn from_public_key_bytes(bytes: &[u8; 32]) -> Result<Self, crate::CryptoError> {
        let key =
            VerifyingKey::from_bytes(bytes).map_err(|_| crate::CryptoError::MalformedKey {
                reason: "bytes do not form a valid Ed25519 compressed point",
            })?;
        // Defense-in-depth: reject small-order (weak) public keys before they can be pinned
        // in the trust store. A small-order key lies in a torsion subgroup, not the prime-order
        // subgroup, and allows an attacker to forge signatures that verify under `verify()`
        // (cofactored). Even with `verify_strict`, we want to prevent weak keys from ever
        // entering the identity/trust machinery so they cannot appear in BindCert or audit logs.
        if key.is_weak() {
            return Err(crate::CryptoError::MalformedKey {
                reason: "public key is a small-order (weak) point and cannot be trusted",
            });
        }
        Ok(Self::from_verifying_key(key))
    }

    /// Returns the inner [`ed25519_dalek::VerifyingKey`].
    ///
    /// This is `pub(crate)` only — callers outside the crate must use
    /// [`public_key_bytes`](Self::public_key_bytes) for wire serialization.
    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show only the short fingerprint — never the key bytes, which could be confused
        // with the signing key in logs. The full fingerprint is available via Display.
        f.debug_struct("DeviceIdentity")
            .field("fingerprint", &self.fingerprint.short())
            .finish()
    }
}

impl fmt::Display for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceIdentity({})", self.fingerprint)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn make_key() -> VerifyingKey {
        SigningKey::generate(&mut OsRng).verifying_key()
    }

    #[test]
    fn fingerprint_is_64_hex_chars() {
        let id = DeviceIdentity::from_verifying_key(make_key());
        assert_eq!(id.fingerprint().as_str().len(), 64);
        assert!(id
            .fingerprint()
            .as_str()
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn short_fingerprint_is_16_chars() {
        let id = DeviceIdentity::from_verifying_key(make_key());
        assert_eq!(id.fingerprint().short().len(), 16);
    }

    #[test]
    fn fingerprint_stable_across_calls() {
        let key = make_key();
        let id1 = DeviceIdentity::from_verifying_key(key);
        let id2 = DeviceIdentity::from_verifying_key(key);
        assert_eq!(id1.fingerprint(), id2.fingerprint());
    }

    #[test]
    fn distinct_keys_distinct_fingerprints() {
        let id1 = DeviceIdentity::from_verifying_key(make_key());
        let id2 = DeviceIdentity::from_verifying_key(make_key());
        // Collision probability is 1/2^256 — this test would fail less often than the sun burns out.
        assert_ne!(id1.fingerprint(), id2.fingerprint());
    }

    #[test]
    fn from_public_key_bytes_roundtrip() {
        let key = make_key();
        let id = DeviceIdentity::from_verifying_key(key);
        let bytes = *id.public_key_bytes();
        let id2 = DeviceIdentity::from_public_key_bytes(&bytes).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn from_public_key_bytes_invalid_point_is_error() {
        // y = 2 (first byte 0x02, rest zeros) does not decompress to a point on the
        // Ed25519 curve, so `from_bytes` rejects it. Verified by inspection of the
        // curve25519-dalek decompression path.
        let mut bytes = [0u8; 32];
        bytes[0] = 0x02;
        let result = DeviceIdentity::from_public_key_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn debug_does_not_contain_full_key_bytes() {
        // Use a fixed signing key so we can derive the exact public key hex and assert
        // it is absent from the Debug output.
        let signing_key = SigningKey::generate(&mut OsRng);
        let vk = signing_key.verifying_key();
        let pubkey_hex: String = vk.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let id = DeviceIdentity::from_verifying_key(vk);
        let debug_str = format!("{id:?}");
        // The raw 32-byte public key hex must not appear in Debug output.
        assert!(
            !debug_str.contains(&pubkey_hex),
            "Debug must not expose the raw public key bytes, got: {debug_str}"
        );
        // The full 64-char fingerprint must not appear (we only show the 16-char short form).
        assert!(
            !debug_str.contains(id.fingerprint().as_str()),
            "Debug should show short fingerprint only, got: {debug_str}"
        );
        assert!(debug_str.contains(id.fingerprint().short()));
    }

    /// Defense-in-depth: `from_public_key_bytes` must reject small-order (weak) keys
    /// so they can never be pinned in the trust store or appear in a BindCert.
    ///
    /// The Ed25519 curve has a cofactor of 8. The eight small-order points (the torsion
    /// subgroup) are known constants. We test three of them here; the others follow by
    /// symmetry. If this test fails, someone removed the `is_weak()` check.
    #[test]
    fn small_order_public_key_rejected() {
        // Known small-order points on the Ed25519 curve (from RFC 8032 / libsodium tests).
        // Each is a valid compressed y-coordinate that decompresses to a torsion point.
        let small_order_keys: &[[u8; 32]] = &[
            // The identity element: (0, 1) → y = 1, sign bit 0.
            {
                let mut b = [0u8; 32];
                b[0] = 0x01;
                b
            },
            // Point of order 2: (0, -1) → y = p-1 in compressed form.
            // In Ed25519, p = 2^255 - 19, so -1 mod p = p-1.
            // Compressed: bytes of (p-1), low bit = sign of x = 0 → 0xec, 0xff * 30, 0x7f.
            [
                0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
            // A well-known order-4 torsion point used in libsodium's test vectors.
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
        ];

        for key_bytes in small_order_keys {
            let result = DeviceIdentity::from_public_key_bytes(key_bytes);
            // Either the bytes don't decompress at all (MalformedKey from from_bytes),
            // or they decompress but is_weak() triggers. Either way: must be Err.
            assert!(
                result.is_err(),
                "from_public_key_bytes must reject small-order key: {key_bytes:02x?}"
            );
        }
    }

    #[test]
    fn display_shows_full_fingerprint() {
        let key = make_key();
        let id = DeviceIdentity::from_verifying_key(key);
        let display_str = format!("{id}");
        assert!(display_str.contains(id.fingerprint().as_str()));
    }

    #[test]
    fn fingerprint_derives_only_from_public_key() {
        // The same public key, constructed independently, must yield the same fingerprint.
        let signing_key = SigningKey::generate(&mut OsRng);
        let vk = signing_key.verifying_key();
        let id1 = DeviceIdentity::from_verifying_key(vk);
        let id2 = DeviceIdentity::from_public_key_bytes(vk.as_bytes()).unwrap();
        assert_eq!(id1.fingerprint(), id2.fingerprint());
    }
}
