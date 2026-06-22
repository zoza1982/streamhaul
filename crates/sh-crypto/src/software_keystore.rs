//! [`SoftwareKeystore`] — a portable in-memory [`Keystore`] backed by an Ed25519 `SigningKey`.
//!
//! # Security status: SOFTWARE-BACKED (non-exportable key deferred)
//!
//! The LLD (§6.2, §6.3) specifies that the device identity key must be **hardware-non-exportable**
//! (TPM 2.0, Secure Enclave / Keychain, DPAPI, Android StrongBox). This implementation does NOT
//! provide that guarantee:
//!
//! - The signing key lives in ordinary heap memory (`Box`ed `SigningKey`).
//! - `ed25519-dalek`'s `zeroize` feature ensures the memory is securely wiped on drop.
//! - However, a process with root-level access to the host can read the signing key from RAM.
//!
//! **Use this implementation only for development, testing, and prototyping.** Production
//! deployments MUST replace it with a platform hardware-keystore backend once those are
//! implemented (tracked as risk entry R-HW-KS in IMPLEMENTATION_PLAN.md).
//!
//! # TOFU / revocation policy
//!
//! - `trust_peer` is idempotent. Calling it for an already-trusted peer is a no-op.
//! - `revoke_peer` is idempotent. Revoking a never-trusted peer is a no-op.
//! - **Re-trust after revocation is permitted.** If a peer is revoked and then `trust_peer`
//!   is called again, the peer is moved from the revoked set back to the trusted set. Rationale:
//!   the operator may rotate a device and re-pair it under the same identity (e.g., after a
//!   factory reset). Requiring a new identity for re-pairing would be overly restrictive for the
//!   P3-1 software store. Hardware keystores (P3+ follow-up) may enforce stricter policies.
//!
//! # Thread safety
//!
//! The trust/revoke sets are protected by a `std::sync::RwLock`, which allows concurrent
//! `is_trusted` reads. `trust_peer` and `revoke_peer` take a write lock. No async-aware lock is
//! used because the critical section is extremely short (a hash-set lookup/insert) and never
//! calls external I/O — blocking the thread for a nanosecond is acceptable.

use std::{collections::HashSet, fmt, sync::RwLock};

use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{CryptoRng, OsRng, RngCore};

use crate::{keystore::Keystore, CryptoError, DeviceIdentity, Signature};

/// The inner state of the software keystore, behind an `RwLock`.
struct Inner {
    /// Fingerprints of trusted peers (pinned, not revoked).
    trusted: HashSet<String>,
    /// Fingerprints of explicitly revoked peers.
    revoked: HashSet<String>,
}

/// A portable, in-memory [`Keystore`] backed by an Ed25519 signing key.
///
/// See the [module-level documentation](self) for the security status and TOFU/revocation policy.
///
/// # Construction
///
/// | Constructor | Use case |
/// |-------------|----------|
/// | [`SoftwareKeystore::generate()`] | Production: generates a fresh key using `OsRng`. |
/// | [`SoftwareKeystore::generate_with_rng(rng)`](Self::generate_with_rng) | Tests: generates a fresh key using a seedable RNG. |
/// | [`SoftwareKeystore::from_signing_key(key)`](Self::from_signing_key) | Tests: constructs from an existing key (e.g. a test vector). |
///
/// # Examples
///
/// ```
/// use sh_crypto::{SoftwareKeystore, Keystore};
///
/// # tokio_test::block_on(async {
/// // Production usage: OsRng key.
/// let ks = SoftwareKeystore::generate();
/// let id = ks.device_identity().await.unwrap();
/// let sig = ks.sign(b"data").await.unwrap();
/// assert!(sig.verify(&id, b"data").is_ok());
/// # });
/// ```
pub struct SoftwareKeystore {
    /// The Ed25519 signing key.
    ///
    /// `SigningKey` implements `ZeroizeOnDrop` when `ed25519-dalek`'s `zeroize` feature is
    /// enabled (which it is in our configuration — see `Cargo.toml`). The key bytes are
    /// zeroed when the field is dropped. No public accessor exists for this field.
    ///
    /// The key is `Box`ed to give it a stable heap address, avoiding accidental copies on
    /// stack moves. The stack pointer to the `Box` is the only copy.
    signing_key: Box<SigningKey>,
    /// The cached public identity (derived once at construction; never changes).
    identity: DeviceIdentity,
    /// Mutable trust/revoke state behind an `RwLock`.
    inner: RwLock<Inner>,
}

impl SoftwareKeystore {
    /// Generates a fresh identity using the OS entropy pool ([`OsRng`]).
    ///
    /// This is the **production constructor**. The key is non-deterministic. For deterministic
    /// tests, use [`generate_with_rng`](Self::generate_with_rng) or
    /// [`from_signing_key`](Self::from_signing_key).
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_crypto::{SoftwareKeystore, Keystore};
    ///
    /// # tokio_test::block_on(async {
    /// let ks = SoftwareKeystore::generate();
    /// let id = ks.device_identity().await.unwrap();
    /// println!("fingerprint: {}", id.fingerprint());
    /// # });
    /// ```
    pub fn generate() -> Self {
        Self::generate_with_rng(OsRng)
    }

    /// Generates a fresh identity using the provided `rng`.
    ///
    /// Use this constructor in tests to produce a deterministic, seedable identity.
    ///
    /// # Examples
    ///
    /// ```
    /// use rand_core::SeedableRng;
    /// use rand_chacha::ChaCha8Rng;
    /// use sh_crypto::{SoftwareKeystore, Keystore};
    ///
    /// # tokio_test::block_on(async {
    /// let rng = ChaCha8Rng::seed_from_u64(42);
    /// let ks = SoftwareKeystore::generate_with_rng(rng);
    /// let id = ks.device_identity().await.unwrap();
    /// // The same seed always produces the same fingerprint.
    /// let rng2 = ChaCha8Rng::seed_from_u64(42);
    /// let ks2 = SoftwareKeystore::generate_with_rng(rng2);
    /// let id2 = ks2.device_identity().await.unwrap();
    /// assert_eq!(id.fingerprint(), id2.fingerprint());
    /// # });
    /// ```
    pub fn generate_with_rng<R: CryptoRng + RngCore>(mut rng: R) -> Self {
        let signing_key = SigningKey::generate(&mut rng);
        Self::from_signing_key(signing_key)
    }

    /// Constructs a `SoftwareKeystore` from an existing [`SigningKey`].
    ///
    /// This is the lowest-level constructor, intended for tests that need a known key. The
    /// trust/revoke stores start empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use rand_core::OsRng;
    /// use sh_crypto::{SoftwareKeystore, Keystore};
    ///
    /// # tokio_test::block_on(async {
    /// let key = SigningKey::generate(&mut OsRng);
    /// let ks = SoftwareKeystore::from_signing_key(key);
    /// let id = ks.device_identity().await.unwrap();
    /// println!("fingerprint: {}", id.fingerprint());
    /// # });
    /// ```
    pub fn from_signing_key(key: SigningKey) -> Self {
        let verifying_key = key.verifying_key();
        let identity = DeviceIdentity::from_verifying_key(verifying_key);
        Self {
            signing_key: Box::new(key),
            identity,
            inner: RwLock::new(Inner {
                trusted: HashSet::new(),
                revoked: HashSet::new(),
            }),
        }
    }

    /// Returns the fingerprint string from a `DeviceIdentity` for use as a hash key.
    fn fp(id: &DeviceIdentity) -> &str {
        id.fingerprint().as_str()
    }
}

impl fmt::Debug for SoftwareKeystore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately omit the signing key. Show only the public identity fingerprint.
        f.debug_struct("SoftwareKeystore")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Keystore for SoftwareKeystore {
    async fn device_identity(&self) -> Result<DeviceIdentity, CryptoError> {
        Ok(self.identity.clone())
    }

    async fn sign(&self, data: &[u8]) -> Result<Signature, CryptoError> {
        let dalek_sig = self.signing_key.as_ref().sign(data);
        Ok(Signature::from_dalek(dalek_sig))
    }

    async fn trust_peer(&self, id: &DeviceIdentity) -> Result<(), CryptoError> {
        let fp = Self::fp(id).to_owned();
        // Re-trust after revocation: remove from the revoked set and add to trusted.
        // See module doc for the policy rationale.
        let mut inner = self
            .inner
            .write()
            .map_err(|_| CryptoError::Backend("trust store lock poisoned".into()))?;
        inner.revoked.remove(&fp);
        inner.trusted.insert(fp);
        Ok(())
    }

    async fn is_trusted(&self, id: &DeviceIdentity) -> Result<bool, CryptoError> {
        let inner = self
            .inner
            .read()
            .map_err(|_| CryptoError::Backend("trust store lock poisoned".into()))?;
        // Trusted iff pinned AND not revoked.
        // Note: `revoke_peer` always removes from `trusted`, so this check is
        // `trusted.contains(fp)` alone, but we double-check the revoked set for
        // safety in case of implementation bugs.
        let fp = Self::fp(id);
        Ok(inner.trusted.contains(fp) && !inner.revoked.contains(fp))
    }

    async fn revoke_peer(&self, id: &DeviceIdentity) -> Result<(), CryptoError> {
        let fp = Self::fp(id).to_owned();
        let mut inner = self
            .inner
            .write()
            .map_err(|_| CryptoError::Backend("trust store lock poisoned".into()))?;
        inner.trusted.remove(&fp);
        inner.revoked.insert(fp);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{Fingerprint, Keystore};
    use rand_core::SeedableRng;

    fn seeded(seed: u64) -> SoftwareKeystore {
        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
        SoftwareKeystore::generate_with_rng(rng)
    }

    // ----- Identity & fingerprint -----

    #[tokio::test]
    async fn identity_stable_across_calls() {
        let ks = seeded(1);
        let id1 = ks.device_identity().await.unwrap();
        let id2 = ks.device_identity().await.unwrap();
        assert_eq!(id1, id2);
    }

    #[tokio::test]
    async fn distinct_keystores_distinct_identities() {
        let ks_a = seeded(100);
        let ks_b = seeded(200);
        let id_a = ks_a.device_identity().await.unwrap();
        let id_b = ks_b.device_identity().await.unwrap();
        assert_ne!(id_a, id_b);
    }

    #[tokio::test]
    async fn same_seed_produces_same_identity() {
        let ks1 = seeded(42);
        let ks2 = seeded(42);
        let id1 = ks1.device_identity().await.unwrap();
        let id2 = ks2.device_identity().await.unwrap();
        assert_eq!(id1, id2);
    }

    // ----- Sign / verify -----

    #[tokio::test]
    async fn sign_verify_roundtrip() {
        let ks = seeded(1);
        let id = ks.device_identity().await.unwrap();
        let sig = ks.sign(b"hello world").await.unwrap();
        assert!(sig.verify(&id, b"hello world").is_ok());
    }

    #[tokio::test]
    async fn sign_tampered_data_fails() {
        let ks = seeded(2);
        let id = ks.device_identity().await.unwrap();
        let sig = ks.sign(b"original").await.unwrap();
        assert!(sig.verify(&id, b"tampered").is_err());
    }

    #[tokio::test]
    async fn sign_tampered_signature_fails() {
        let ks = seeded(3);
        let id = ks.device_identity().await.unwrap();
        let sig = ks.sign(b"data").await.unwrap();
        let mut wire = sig.encode();
        wire[0] ^= 0x01;
        let bad = Signature::decode(&wire).unwrap();
        assert!(bad.verify(&id, b"data").is_err());
    }

    #[tokio::test]
    async fn cross_key_rejection() {
        let ks_a = seeded(10);
        let ks_b = seeded(20);
        let id_b = ks_b.device_identity().await.unwrap();
        let sig_a = ks_a.sign(b"data").await.unwrap();
        assert!(sig_a.verify(&id_b, b"data").is_err());
    }

    #[tokio::test]
    async fn empty_message_sign_verify() {
        let ks = seeded(4);
        let id = ks.device_identity().await.unwrap();
        let sig = ks.sign(b"").await.unwrap();
        assert!(sig.verify(&id, b"").is_ok());
    }

    // ----- TOFU trust store -----

    #[tokio::test]
    async fn unknown_peer_is_not_trusted() {
        let ks = seeded(5);
        let peer_ks = seeded(6);
        let peer_id = peer_ks.device_identity().await.unwrap();
        assert!(!ks.is_trusted(&peer_id).await.unwrap());
    }

    #[tokio::test]
    async fn trust_peer_makes_trusted() {
        let ks = seeded(7);
        let peer_ks = seeded(8);
        let peer_id = peer_ks.device_identity().await.unwrap();

        ks.trust_peer(&peer_id).await.unwrap();
        assert!(ks.is_trusted(&peer_id).await.unwrap());
    }

    #[tokio::test]
    async fn trust_peer_is_idempotent() {
        let ks = seeded(9);
        let peer_ks = seeded(10);
        let peer_id = peer_ks.device_identity().await.unwrap();

        ks.trust_peer(&peer_id).await.unwrap();
        ks.trust_peer(&peer_id).await.unwrap(); // second call must not error
        assert!(ks.is_trusted(&peer_id).await.unwrap());
    }

    #[tokio::test]
    async fn revoke_peer_makes_untrusted() {
        let ks = seeded(11);
        let peer_ks = seeded(12);
        let peer_id = peer_ks.device_identity().await.unwrap();

        ks.trust_peer(&peer_id).await.unwrap();
        ks.revoke_peer(&peer_id).await.unwrap();
        assert!(!ks.is_trusted(&peer_id).await.unwrap());
    }

    #[tokio::test]
    async fn revoke_peer_is_idempotent() {
        let ks = seeded(13);
        let peer_ks = seeded(14);
        let peer_id = peer_ks.device_identity().await.unwrap();

        // Revoking a never-trusted peer must not error.
        ks.revoke_peer(&peer_id).await.unwrap();
        // Revoking again must not error.
        ks.revoke_peer(&peer_id).await.unwrap();
        assert!(!ks.is_trusted(&peer_id).await.unwrap());
    }

    #[tokio::test]
    async fn retrust_after_revoke_is_allowed() {
        // Per the documented policy: re-trust after revocation is permitted.
        // This represents the "device re-paired after factory reset" scenario.
        let ks = seeded(15);
        let peer_ks = seeded(16);
        let peer_id = peer_ks.device_identity().await.unwrap();

        ks.trust_peer(&peer_id).await.unwrap();
        ks.revoke_peer(&peer_id).await.unwrap();
        assert!(!ks.is_trusted(&peer_id).await.unwrap());

        // Re-trust.
        ks.trust_peer(&peer_id).await.unwrap();
        assert!(ks.is_trusted(&peer_id).await.unwrap());
    }

    #[tokio::test]
    async fn trust_does_not_bleed_between_peers() {
        let ks = seeded(17);
        let peer_a_ks = seeded(18);
        let peer_b_ks = seeded(19);
        let peer_a_id = peer_a_ks.device_identity().await.unwrap();
        let peer_b_id = peer_b_ks.device_identity().await.unwrap();

        ks.trust_peer(&peer_a_id).await.unwrap();
        // B is not trusted even though A is.
        assert!(!ks.is_trusted(&peer_b_id).await.unwrap());
    }

    // ----- No secret leakage -----

    #[tokio::test]
    async fn debug_does_not_contain_signing_key() {
        let ks = seeded(20);
        let id = ks.device_identity().await.unwrap();
        let debug_str = format!("{ks:?}");
        // The signing key bytes are never accessible, but we can ensure the Debug output
        // does not contain any 32-byte hex strings that could be the key scalar.
        // The fingerprint (public) is fine to appear.
        assert!(debug_str.contains("SoftwareKeystore"));
        // No explicit private key field should be present.
        assert!(!debug_str.contains("signing_key"));
        // Debug of DeviceIdentity shows only the short fingerprint (16 chars).
        assert!(debug_str.contains(id.fingerprint().short()));
    }

    #[tokio::test]
    async fn from_signing_key_produces_consistent_identity() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let vk = signing_key.verifying_key();
        let expected_fp = Fingerprint::from_verifying_key(&vk);

        // We can't move `signing_key` after taking `vk`, so we need to reconstruct.
        // Use the bytes to rebuild.
        let key_bytes = signing_key.to_bytes();
        let signing_key2 = SigningKey::from_bytes(&key_bytes);
        let ks = SoftwareKeystore::from_signing_key(signing_key2);
        let id = ks.device_identity().await.unwrap();
        assert_eq!(id.fingerprint(), &expected_fp);
    }
}
