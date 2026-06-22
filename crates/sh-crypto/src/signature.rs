//! The [`Signature`] newtype — a 64-byte Ed25519 signature for wire exchange.
//!
//! # Wire format
//!
//! An Ed25519 signature is always exactly **64 bytes**: a 32-byte compressed `R` point followed
//! by a 32-byte scalar `S`. [`Signature::encode`] returns these 64 bytes; [`Signature::decode`]
//! validates the input length and constructs the type — it never panics on malformed input.
//!
//! # Security notes
//!
//! `decode` accepts untrusted network bytes and is therefore fuzzed (see
//! `crates/sh-crypto/fuzz/fuzz_targets/sig_decode.rs`). The decoder performs a bounds check
//! before any construction; no unsafe code is used.
//!
//! `Signature` does **not** implement `Debug` in a way that exposes the raw bytes in logs —
//! `Debug` renders only a placeholder. The 64 bytes are not secret (they are sent on the wire)
//! but including them in debug logs creates large, unreadable noise.

use ed25519_dalek::Signature as DalekSignature;

use crate::{CryptoError, DeviceIdentity};

/// The length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// A 64-byte Ed25519 signature.
///
/// This is the wire-facing signature type. It wraps [`ed25519_dalek::Signature`] and adds
/// panic-free wire encode/decode and a convenience [`verify`](Self::verify) method.
///
/// # Examples
///
/// ```
/// use sh_crypto::{SoftwareKeystore, Keystore};
///
/// # tokio_test::block_on(async {
/// let ks = SoftwareKeystore::generate();
/// let id = ks.device_identity().await.unwrap();
/// let sig = ks.sign(b"hello world").await.unwrap();
///
/// // Roundtrip through wire bytes.
/// let wire = sig.encode();
/// let sig2 = sh_crypto::Signature::decode(&wire).unwrap();
/// assert!(sig2.verify(&id, b"hello world").is_ok());
/// # });
/// ```
#[derive(Clone)]
pub struct Signature(DalekSignature);

impl Signature {
    /// Constructs a `Signature` from the raw `ed25519-dalek` type.
    pub(crate) fn from_dalek(inner: DalekSignature) -> Self {
        Self(inner)
    }

    /// Encodes this signature to its 64-byte wire representation.
    ///
    /// The encoding is always exactly [`SIGNATURE_LEN`] bytes: 32 bytes for the `R` point
    /// followed by 32 bytes for the `S` scalar, as specified in RFC 8032 §5.1.6.
    pub fn encode(&self) -> [u8; SIGNATURE_LEN] {
        self.0.to_bytes()
    }

    /// Decodes a `Signature` from untrusted wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MalformedSignature`] if `bytes` is not exactly
    /// [`SIGNATURE_LEN`] (64) bytes long. Note that **structural validity** of the `R` and `S`
    /// components is checked lazily by `ed25519-dalek` at verification time, not here — this
    /// keeps the decoder panic-free even on arbitrary garbage input.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_crypto::Signature;
    ///
    /// // Wrong length → typed error, no panic.
    /// assert!(Signature::decode(&[0u8; 32]).is_err());
    /// assert!(Signature::decode(&[]).is_err());
    ///
    /// // Exact length → Ok (structural check happens at verify time).
    /// assert!(Signature::decode(&[0u8; 64]).is_ok());
    /// ```
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: &[u8; SIGNATURE_LEN] =
            bytes
                .try_into()
                .map_err(|_| CryptoError::MalformedSignature {
                    reason: "expected exactly 64 bytes",
                })?;
        Ok(Self(DalekSignature::from_bytes(arr)))
    }

    /// Verifies this signature against `data` using `identity`'s public key.
    ///
    /// Returns `Ok(())` if the signature is valid, or [`CryptoError::Signature`] if it is
    /// not. A failed verification should be treated as an authentication failure.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Signature`] if the signature does not verify under `identity`.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_crypto::{SoftwareKeystore, Keystore};
    ///
    /// # tokio_test::block_on(async {
    /// let ks = SoftwareKeystore::generate();
    /// let id = ks.device_identity().await.unwrap();
    /// let sig = ks.sign(b"test data").await.unwrap();
    ///
    /// // Valid signature.
    /// assert!(sig.verify(&id, b"test data").is_ok());
    ///
    /// // Tampered data.
    /// assert!(sig.verify(&id, b"tampered").is_err());
    /// # });
    /// ```
    pub fn verify(&self, identity: &DeviceIdentity, data: &[u8]) -> Result<(), CryptoError> {
        // Use `verify_strict` rather than `verify` to reject:
        // - small-order public keys (e.g. the identity/torsion-subgroup points), and
        // - non-canonical ("malleable") `R` components in the signature itself.
        // This is mandatory for a device-identity TRUST ROOT: accepting small-order keys
        // would break the signature-uniqueness assumptions relied on by BindCert, anti-replay
        // logic, and audit receipts downstream.
        identity
            .verifying_key()
            .verify_strict(data, &self.0)
            .map_err(|_| CryptoError::Signature)
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not log the raw bytes — they are not secret but produce large, unreadable noise.
        f.write_str("Signature(<64 bytes>)")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{Keystore, SoftwareKeystore};
    use proptest::prelude::*;

    // Helper: create a keystore with a deterministic seed.
    fn make_ks_seeded(seed: u64) -> SoftwareKeystore {
        use rand_core::SeedableRng;
        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
        SoftwareKeystore::generate_with_rng(rng)
    }

    #[tokio::test]
    async fn decode_wrong_length_is_err() {
        assert!(Signature::decode(&[]).is_err());
        assert!(Signature::decode(&[0u8; 32]).is_err());
        assert!(Signature::decode(&[0u8; 63]).is_err());
        assert!(Signature::decode(&[0u8; 65]).is_err());
    }

    #[tokio::test]
    async fn decode_exact_length_ok() {
        // Any 64 bytes decode without panic; structural validity is only checked at verify.
        assert!(Signature::decode(&[0u8; 64]).is_ok());
        assert!(Signature::decode(&[0xff; 64]).is_ok());
    }

    #[tokio::test]
    async fn garbage_signature_fails_verify() {
        let ks = make_ks_seeded(1);
        let id = ks.device_identity().await.unwrap();
        let garbage = Signature::decode(&[0u8; 64]).unwrap();
        assert!(garbage.verify(&id, b"data").is_err());
    }

    #[tokio::test]
    async fn encode_decode_roundtrip() {
        let ks = make_ks_seeded(2);
        let id = ks.device_identity().await.unwrap();
        let sig = ks.sign(b"roundtrip").await.unwrap();
        let wire = sig.encode();
        let sig2 = Signature::decode(&wire).unwrap();
        assert!(sig2.verify(&id, b"roundtrip").is_ok());
    }

    #[tokio::test]
    async fn tampered_data_fails_verify() {
        let ks = make_ks_seeded(3);
        let id = ks.device_identity().await.unwrap();
        let sig = ks.sign(b"original").await.unwrap();
        assert!(sig.verify(&id, b"tampered").is_err());
    }

    #[tokio::test]
    async fn tampered_signature_fails_verify() {
        let ks = make_ks_seeded(4);
        let id = ks.device_identity().await.unwrap();
        let sig = ks.sign(b"data").await.unwrap();
        let mut wire = sig.encode();
        // Flip a bit in the R component.
        wire[0] ^= 0x01;
        let bad_sig = Signature::decode(&wire).unwrap();
        assert!(bad_sig.verify(&id, b"data").is_err());
    }

    #[tokio::test]
    async fn cross_key_rejection() {
        let ks_a = make_ks_seeded(10);
        let ks_b = make_ks_seeded(20);
        let id_b = ks_b.device_identity().await.unwrap();
        let sig_a = ks_a.sign(b"data").await.unwrap();
        // Signature from A must not verify under B's identity.
        assert!(sig_a.verify(&id_b, b"data").is_err());
    }

    #[tokio::test]
    async fn debug_does_not_expose_bytes() {
        // Use a KNOWN key so we can assert the actual secret scalar hex is absent.
        use rand_core::SeedableRng;
        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(5);
        let ks = SoftwareKeystore::generate_with_rng(rng);
        let sig = ks.sign(b"secret").await.unwrap();
        let raw_bytes = sig.encode();
        let raw_hex: String = raw_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let debug = format!("{sig:?}");
        // The actual 64 raw bytes (128 hex chars) must not appear in Debug output.
        assert!(
            !debug.contains(&raw_hex[..16]),
            "Debug must not expose raw signature bytes"
        );
        assert!(debug.contains("Signature"));
    }

    /// Regression test for the `verify_strict` requirement.
    ///
    /// A small-order `R` point (the Ed25519/ristretto255 identity element encoded as 32 zero
    /// bytes followed by a 1) is a canonical representation of a torsion point. A signature
    /// with R = identity and S = 0 trivially satisfies the non-strict batch equation
    /// `[8][S]B = [8]R + [8][H]A` when A is also small-order, but `verify_strict` rejects it.
    ///
    /// This test MUST fail if someone reverts to `verify()`. The all-zeros 64-byte signature
    /// used by `garbage_signature_fails_verify` does NOT cover this because dalek parses it
    /// as R = compressed identity (valid small-order point) and S = 0, which the non-strict
    /// verifier may accept under a small-order public key.
    #[test]
    fn small_order_r_signature_rejected_by_verify_strict() {
        // Use a normal (non-small-order) verifying key — verify_strict must reject this
        // signature because its R component encodes a small-order point.
        use rand_core::SeedableRng;
        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(99);
        let ks = SoftwareKeystore::generate_with_rng(rng);
        // Build the identity synchronously using block_on since Keystore is async.
        let id = tokio_test::block_on(ks.device_identity()).unwrap();

        // A signature whose R component is the compressed identity point on Ed25519:
        // RFC 8032 encodes the neutral element as y = 1 (bit pattern: 0x01 in byte 0,
        // rest zero). S = 0.  `verify_strict` rejects signatures where R is small-order.
        let mut small_order_sig_bytes = [0u8; 64];
        small_order_sig_bytes[0] = 0x01; // y-coordinate = 1 → identity/neutral point

        let sig = Signature::decode(&small_order_sig_bytes).unwrap();
        let result = sig.verify(&id, b"any data");
        assert!(
            result.is_err(),
            "verify_strict must reject a signature with a small-order R point; \
             if this assertion fails, verify() was used instead of verify_strict()"
        );
    }

    proptest! {
        #[test]
        fn decode_arbitrary_bytes_never_panics(data in proptest::collection::vec(any::<u8>(), 0..=128)) {
            let _ = Signature::decode(&data);
        }

        #[test]
        fn sign_verify_roundtrip_arbitrary_message(
            seed in any::<u64>(),
            msg in proptest::collection::vec(any::<u8>(), 0..=1024)
        ) {
            use rand_core::SeedableRng;
            let rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            let ks = SoftwareKeystore::generate_with_rng(rng);
            // Use tokio_test::block_on instead of spinning up a fresh runtime per iteration.
            let id = tokio_test::block_on(ks.device_identity()).unwrap();
            let sig = tokio_test::block_on(ks.sign(&msg)).unwrap();
            prop_assert!(sig.verify(&id, &msg).is_ok());
        }
    }
}
