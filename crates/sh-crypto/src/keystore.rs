//! The [`Keystore`] trait — the async seam for device identity and key management.
//!
//! # Design
//!
//! `Keystore` is deliberately **async and object-safe** (`Send + Sync + 'static`) so it can be
//! held behind a `Box<dyn Keystore>` or `Arc<dyn Keystore + 'static>` and called from async tasks without
//! concern for which thread supplies the key material. On platforms with a hardware security
//! module (TPM 2.0, Secure Enclave, DPAPI, StrongBox), the async boundary lets HSM calls block
//! without stalling the QUIC I/O executor.
//!
//! # Trust store semantics
//!
//! The trust store is a TOFU (Trust On First Use) pin store. The expected lifecycle is:
//!
//! 1. Controller generates its identity and presents it to the host.
//! 2. The host calls [`Keystore::trust_peer`] to pin the controller's identity (after the user
//!    performs an attended pairing step or a PAKE exchange — P3-3).
//! 3. On subsequent connections the host calls [`Keystore::is_trusted`] to verify that the
//!    connecting controller's identity matches a previously pinned one.
//! 4. If a device is compromised, the host calls [`Keystore::revoke_peer`].

use async_trait::async_trait;

use crate::{pairing::TrustOutcome, CryptoError, DeviceIdentity, Signature};

/// Async interface for Ed25519 device identity and TOFU trust management.
///
/// Implementors provide:
/// - The device's own Ed25519 identity (public key + fingerprint).
/// - The ability to sign arbitrary data with the device's signing key.
/// - A trust store for pinning peer identities (TOFU) and revoking them.
///
/// # Object safety
///
/// This trait is object-safe. It can be used as `Box<dyn Keystore>` or `Arc<dyn Keystore>` to
/// allow runtime selection of keystore backends (software vs. hardware). The `'static` bound is
/// required for `Arc<dyn Keystore>` to be safely sent across thread or task boundaries.
///
/// # Security contract
///
/// - Implementations MUST NOT expose the signing key material through any method or field.
/// - Implementations MUST NOT log key material.
/// - The signing key MUST be zeroed on drop (either via hardware destruction or `zeroize`).
/// - `trust_peer` and `revoke_peer` MUST be consistent: once revoked, [`is_trusted`](Self::is_trusted)
///   MUST return `false` until [`trust_peer`](Self::trust_peer) is explicitly called again
///   (re-trust-after-revoke policy is documented per implementation).
///
/// # Examples
///
/// ```
/// use sh_crypto::{SoftwareKeystore, Keystore};
///
/// # tokio_test::block_on(async {
/// let ks = SoftwareKeystore::generate();
/// let id = ks.device_identity().await.unwrap();
/// let sig = ks.sign(b"example payload").await.unwrap();
/// assert!(sig.verify(&id, b"example payload").is_ok());
/// # });
/// ```
#[async_trait]
pub trait Keystore: Send + Sync + 'static {
    /// Returns this device's Ed25519 public identity (verifying key + fingerprint).
    ///
    /// The returned value contains **only public data** — no signing key material is ever
    /// exposed through this method.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Backend`] if the hardware or software keystore cannot be accessed.
    async fn device_identity(&self) -> Result<DeviceIdentity, CryptoError>;

    /// Signs `data` with this device's Ed25519 signing key.
    ///
    /// The signature is computed over the raw bytes of `data` without any additional framing.
    /// Callers are responsible for constructing a well-defined signing payload (e.g. a
    /// `BindCert` or audit receipt) before calling this method.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Backend`] if the signing operation fails (e.g. HSM communication
    ///   error).
    ///
    /// # Security
    ///
    /// Do not log `data` if it contains session-identifying content. The returned [`Signature`]
    /// is safe to transmit on the wire.
    async fn sign(&self, data: &[u8]) -> Result<Signature, CryptoError>;

    /// Pins `id` as a trusted peer (TOFU).
    ///
    /// After a successful call, [`is_trusted(id)`](Self::is_trusted) returns `true` (unless
    /// `id` is subsequently revoked).
    ///
    /// This operation is **idempotent**: calling `trust_peer` for an already-trusted identity
    /// is not an error and has no observable effect.
    ///
    /// # Re-trust after revocation
    ///
    /// Re-trust policy after revocation is **implementation-defined**:
    ///
    /// - [`SoftwareKeystore`][crate::SoftwareKeystore] **permits** re-trust. Calling
    ///   `trust_peer` on a previously revoked identity moves it back to the trusted state.
    ///   This supports the "factory reset and re-pair" scenario without requiring a new key.
    ///
    /// - Production / hardware keystores **should** make revocation sticky: once revoked,
    ///   an identity should require a distinct, explicitly operator-confirmed action to be
    ///   re-trusted — not the ordinary first-pairing `trust_peer` path. See the module
    ///   documentation on [`SoftwareKeystore`][crate::SoftwareKeystore] and
    ///   `IMPLEMENTATION_PLAN.md` entry `R-HW-KS`.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Backend`] if the trust store cannot be persisted.
    async fn trust_peer(&self, id: &DeviceIdentity) -> Result<(), CryptoError>;

    /// Returns `true` if `id` is currently trusted (pinned and not revoked).
    ///
    /// An identity is trusted iff it has been pinned via [`trust_peer`](Self::trust_peer) and
    /// has not subsequently been revoked via [`revoke_peer`](Self::revoke_peer).
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Backend`] if the trust store cannot be read.
    async fn is_trusted(&self, id: &DeviceIdentity) -> Result<bool, CryptoError>;

    /// Revokes a previously trusted peer identity.
    ///
    /// After revocation, [`is_trusted(id)`](Self::is_trusted) returns `false`. The identity
    /// is added to a revocation set so that future `trust_peer` calls can check it.
    ///
    /// This operation is **idempotent**: revoking an already-revoked (or never-trusted)
    /// identity is not an error.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Backend`] if the revocation state cannot be persisted.
    async fn revoke_peer(&self, id: &DeviceIdentity) -> Result<(), CryptoError>;

    /// Returns `true` if `id` was explicitly revoked (and has not been re-trusted since).
    ///
    /// This distinguishes "never seen" from "revoked" peers — both return `false` from
    /// [`is_trusted`](Self::is_trusted), but the pairing layer needs to know if a peer was
    /// revoked in order to gate re-trust behind an explicit operator confirmation (R-HW-KS,
    /// ADR-0008 §3). A "never seen" peer may be silently pinned on first pairing; a revoked
    /// peer requires a distinct explicit confirmation before re-pinning.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Backend`] if the trust store cannot be read.
    async fn was_peer_revoked(&self, id: &DeviceIdentity) -> Result<bool, CryptoError>;

    /// Atomically checks whether `id` is revoked and, if not, pins it as trusted.
    ///
    /// This operation performs both the revocation check **and** the pin under a single
    /// write-lock acquisition, eliminating the TOCTOU race that would exist between a
    /// separate `was_peer_revoked` read and a `trust_peer` write.
    ///
    /// # Returns
    ///
    /// - [`TrustOutcome::Pinned`] if the peer was not revoked and has been pinned (or was
    ///   already pinned). The peer is trusted after this call.
    /// - [`TrustOutcome::WasRevoked`] if the peer was previously revoked. The pin is
    ///   **refused**; `is_trusted` still returns `false`. The caller must surface
    ///   [`PairingOutcome::ReTrustAfterRevokeRequiresConfirmation`](crate::pairing::PairingOutcome::ReTrustAfterRevokeRequiresConfirmation)
    ///   to the operator and require an explicit separate confirmation before calling
    ///   [`trust_peer`](Self::trust_peer) directly.
    ///
    /// # Atomicity requirement
    ///
    /// Implementations MUST perform the revocation check and the pin under the same
    /// exclusive lock (or an equivalent single critical section). A two-step
    /// read-then-write is NOT acceptable — a concurrent `revoke_peer` between the check
    /// and the pin would silently re-trust the revoked peer.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Backend`] if the trust store cannot be read or written.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn trust_peer_if_not_revoked(
        &self,
        id: &DeviceIdentity,
    ) -> Result<TrustOutcome, CryptoError>;
}
