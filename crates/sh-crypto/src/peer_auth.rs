//! [`IdentityProof`] — a possession-of-identity-key proof for signaling peer authentication
//! (R-SIG-AUTH, ADR-0016).
//!
//! A connecting signaling peer must PROVE it controls the Ed25519 device key behind the
//! `from_fp` it claims, so that a malicious or unauthenticated peer cannot register an arbitrary
//! fingerprint and hijack routing, impersonate another device, or DoS a session at the relay.
//!
//! The proof is a fresh Ed25519 signature over a canonical, domain-separated, server-challenged
//! message. The signaling server issues a random 32-byte challenge on connect; the peer signs
//! `DOMAIN || VERSION || session_id || device_pubkey || challenge` and presents
//! `device_pubkey || challenge || signature`. The verifier checks:
//!
//! 1. `Fingerprint::from(device_pubkey) == claimed_fp` (constant-time over the hex bytes) — binds
//!    the claimed routing fingerprint to the presented key.
//! 2. The echoed `session_id` and `challenge` match what the verifier expects (constant-time) —
//!    binds the proof to THIS connection and defeats replay across sessions/connections.
//! 3. The signature verifies under the presented key via [`Signature::verify`] (which uses
//!    `verify_strict`, rejecting small-order keys and non-canonical/malleable signatures).
//!
//! # Replay resistance
//!
//! Replay is defeated by the **server-issued challenge nonce**: every proof is bound to a fresh,
//! server-chosen 32-byte value, so a recorded proof is useless on any other connection (and a
//! malicious relay cannot replay a captured proof to impersonate the peer). See ADR-0016 for the
//! tradeoff (one extra round-trip vs. the replay window of a self-signed time-boxed token).
//!
//! # Authentication is NOT peer trust
//!
//! A valid [`IdentityProof`] proves only that the connecting peer **owns** the claimed fingerprint
//! — it stops fingerprint spoofing/impersonation/DoS at the relay. It does **not** establish
//! peer-to-peer trust between the two endpoints; that remains the peers' job via the Noise
//! handshake + [`BindCert`](crate::BindCert) + TOFU pairing (P3). Do not read a passing
//! server-side proof as end-to-end identity verification.
//!
//! # Self-hostable, no external issuer
//!
//! The proof is self-contained against the peer's OWN identity key. There is no token-issuing
//! service and no pre-shared server secret — a self-hosted relay needs only the random challenge.
//! A deployment MAY still layer an allow-list policy on top at the signaling layer.
//!
//! # Wire format
//!
//! ```text
//! IdentityProof (wire, fixed 128 bytes):
//!   offset  size  field
//!    0      32    DEVICE_PUBKEY      (Ed25519 compressed public key)
//!   32      32    CHALLENGE          (echo of the server-issued challenge)
//!   64      64    SIGNATURE          (Ed25519 signature over the TBS below)
//! ```
//!
//! The to-be-signed (TBS) message is canonical and fixed-width, mirroring the `BindCert` TBS
//! style (a domain tag first prevents cross-structure signature confusion):
//!
//! ```text
//!   offset  size  field
//!    0      16    DOMAIN_TAG = b"SHP-SIG-PEERAUTH"
//!   16       1    TBS_VERSION = 0x01
//!   17      16    SESSION_ID         (16-byte signaling session id)
//!   33      32    DEVICE_PUBKEY      (Ed25519 compressed public key)
//!   65      32    CHALLENGE          (server-issued 32-byte nonce)
//!                 total = 97 bytes
//! ```

use subtle::ConstantTimeEq as _;

use crate::{CryptoError, DeviceIdentity, Keystore, Signature};

/// Domain-separation tag for the peer-auth TBS (prevents cross-structure signature confusion).
const AUTH_DOMAIN_TAG: &[u8; 16] = b"SHP-SIG-PEERAUTH";
/// Version byte for the peer-auth TBS encoding.
const AUTH_TBS_VERSION: u8 = 0x01;

/// Length of an Ed25519 compressed public key in bytes.
const PUBKEY_LEN: usize = 32;
/// Length of the signaling session id in bytes.
const SESSION_ID_LEN: usize = 16;

/// Length of the server-issued challenge nonce, in bytes.
///
/// 32 bytes (256 bits) makes accidental collision and any pre-image / guessing attack
/// negligible; a unique challenge per connection is what defeats proof replay.
pub const PEER_AUTH_CHALLENGE_LEN: usize = 32;

/// Total fixed length of an encoded [`IdentityProof`] on the wire (128 bytes).
///
/// `DEVICE_PUBKEY(32) + CHALLENGE(32) + SIGNATURE(64)`.
pub const IDENTITY_PROOF_LEN: usize =
    PUBKEY_LEN + PEER_AUTH_CHALLENGE_LEN + crate::signature::SIGNATURE_LEN;

/// Length of the canonical to-be-signed (TBS) message.
///
/// `DOMAIN_TAG(16) + VERSION(1) + SESSION_ID(16) + DEVICE_PUBKEY(32) + CHALLENGE(32) = 97`.
const TBS_LEN: usize = 16 + 1 + SESSION_ID_LEN + PUBKEY_LEN + PEER_AUTH_CHALLENGE_LEN;

/// Appends `src` to `out` at the running `cursor`, advancing it. Panic-free: a slice that does not
/// fit is simply not written (the fixed-capacity callers below always size `out` exactly, so this
/// never silently drops in practice; the bounds-checked form just satisfies `indexing_slicing`).
fn write_field(out: &mut [u8], cursor: &mut usize, src: &[u8]) {
    let start = *cursor;
    let end = start.saturating_add(src.len());
    if let Some(dst) = out.get_mut(start..end) {
        dst.copy_from_slice(src);
        *cursor = end;
    }
}

/// Builds the canonical TBS byte string for a peer-auth proof.
///
/// The layout is fixed-width and domain-separated; there is exactly one valid encoding for a
/// given `(session_id, device_pubkey, challenge)`.
fn build_tbs(
    session_id: &[u8; SESSION_ID_LEN],
    device_pubkey: &[u8; PUBKEY_LEN],
    challenge: &[u8; PEER_AUTH_CHALLENGE_LEN],
) -> [u8; TBS_LEN] {
    let mut tbs = [0u8; TBS_LEN];
    let mut cursor = 0usize;
    write_field(&mut tbs, &mut cursor, AUTH_DOMAIN_TAG.as_slice()); // 0..16
    write_field(&mut tbs, &mut cursor, &[AUTH_TBS_VERSION]); // 16
    write_field(&mut tbs, &mut cursor, session_id.as_slice()); // 17..33
    write_field(&mut tbs, &mut cursor, device_pubkey.as_slice()); // 33..65
    write_field(&mut tbs, &mut cursor, challenge.as_slice()); // 65..97
    debug_assert_eq!(cursor, TBS_LEN);
    tbs
}

/// A possession-of-identity-key proof presented by a connecting signaling peer.
///
/// Construct one with [`IdentityProof::create`] (signs with the local [`Keystore`]) and verify a
/// received one with [`IdentityProof::decode`] followed by [`IdentityProof::verify`].
///
/// # Examples
///
/// ```
/// # use sh_crypto::{SoftwareKeystore, Keystore};
/// # use sh_crypto::peer_auth::IdentityProof;
/// # tokio_test::block_on(async {
/// let ks = SoftwareKeystore::generate();
/// let id = ks.device_identity().await.unwrap();
/// let session_id = [7u8; 16];
/// let challenge = [9u8; 32];
///
/// // Peer side: build and serialize the proof.
/// let proof = IdentityProof::create(&ks, &session_id, &challenge).await.unwrap();
/// let wire = proof.encode();
///
/// // Server side: decode and verify against the claimed fingerprint + the challenge it issued.
/// let received = IdentityProof::decode(&wire).unwrap();
/// received
///     .verify(id.fingerprint().as_str(), &session_id, &challenge)
///     .unwrap();
/// # });
/// ```
#[derive(Clone)]
pub struct IdentityProof {
    /// The presented Ed25519 compressed public key.
    device_pubkey: [u8; PUBKEY_LEN],
    /// The echoed server challenge.
    challenge: [u8; PEER_AUTH_CHALLENGE_LEN],
    /// The Ed25519 signature over the canonical TBS.
    signature: Signature,
}

impl std::fmt::Debug for IdentityProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Public bytes, but keep logs terse and avoid dumping key/sig material.
        f.write_str("IdentityProof(<128 bytes>)")
    }
}

impl IdentityProof {
    /// Creates a signed [`IdentityProof`] for `session_id` over the server-issued `challenge`.
    ///
    /// Signs the canonical, domain-separated TBS with the local device key via `keystore`.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Backend`] if the keystore signing operation fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn create<K: Keystore + ?Sized>(
        keystore: &K,
        session_id: &[u8; SESSION_ID_LEN],
        challenge: &[u8; PEER_AUTH_CHALLENGE_LEN],
    ) -> Result<Self, CryptoError> {
        let identity = keystore.device_identity().await?;
        let device_pubkey = *identity.public_key_bytes();
        let tbs = build_tbs(session_id, &device_pubkey, challenge);
        let signature = keystore.sign(&tbs).await?;
        Ok(Self {
            device_pubkey,
            challenge: *challenge,
            signature,
        })
    }

    /// Decodes an [`IdentityProof`] from untrusted wire bytes.
    ///
    /// Treats the input as hostile: the only structural requirement is an exact length of
    /// [`IDENTITY_PROOF_LEN`] (128) bytes. The validity of the public key (curve point /
    /// small-order) and of the signature is deferred to [`verify`](Self::verify), which uses
    /// `verify_strict`. This keeps the decoder panic-free on arbitrary garbage.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::MalformedSignature`] if `bytes.len() != IDENTITY_PROOF_LEN`.
    ///
    /// # Panics
    ///
    /// Never panics. All slicing is bounds-checked.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_crypto::peer_auth::{IdentityProof, IDENTITY_PROOF_LEN};
    ///
    /// // Wrong length → typed error, no panic.
    /// assert!(IdentityProof::decode(&[]).is_err());
    /// assert!(IdentityProof::decode(&[0u8; 10]).is_err());
    /// assert!(IdentityProof::decode(&[0u8; IDENTITY_PROOF_LEN + 1]).is_err());
    /// // Exact length decodes (validity checked at verify time).
    /// assert!(IdentityProof::decode(&[0u8; IDENTITY_PROOF_LEN]).is_ok());
    /// ```
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != IDENTITY_PROOF_LEN {
            return Err(CryptoError::MalformedSignature {
                reason: "identity proof must be exactly 128 bytes",
            });
        }

        let mut device_pubkey = [0u8; PUBKEY_LEN];
        device_pubkey.copy_from_slice(bytes.get(0..PUBKEY_LEN).ok_or(
            CryptoError::MalformedSignature {
                reason: "identity proof too short for device pubkey",
            },
        )?);

        let challenge_end = PUBKEY_LEN + PEER_AUTH_CHALLENGE_LEN;
        let mut challenge = [0u8; PEER_AUTH_CHALLENGE_LEN];
        challenge.copy_from_slice(bytes.get(PUBKEY_LEN..challenge_end).ok_or(
            CryptoError::MalformedSignature {
                reason: "identity proof too short for challenge",
            },
        )?);

        let sig_slice = bytes.get(challenge_end..IDENTITY_PROOF_LEN).ok_or(
            CryptoError::MalformedSignature {
                reason: "identity proof too short for signature",
            },
        )?;
        let signature = Signature::decode(sig_slice)?;

        Ok(Self {
            device_pubkey,
            challenge,
            signature,
        })
    }

    /// Encodes this proof to its fixed 128-byte wire form (`pubkey || challenge || signature`).
    #[must_use]
    pub fn encode(&self) -> [u8; IDENTITY_PROOF_LEN] {
        let mut out = [0u8; IDENTITY_PROOF_LEN];
        let mut cursor = 0usize;
        write_field(&mut out, &mut cursor, &self.device_pubkey); // 0..32
        write_field(&mut out, &mut cursor, &self.challenge); // 32..64
        write_field(&mut out, &mut cursor, &self.signature.encode()); // 64..128
        debug_assert_eq!(cursor, IDENTITY_PROOF_LEN);
        out
    }

    /// Verifies this proof binds the presented key to `expected_fp` for `(expected_session_id,
    /// expected_challenge)`.
    ///
    /// # Checks performed (in order)
    ///
    /// 1. **Challenge binding** — the proof's echoed challenge must equal `expected_challenge`
    ///    (constant-time). This is the anti-replay check: a proof captured on another connection
    ///    carries a different challenge.
    /// 2. **Key validity** — the presented public-key bytes must decode to a valid, non-weak
    ///    Ed25519 key ([`DeviceIdentity::from_public_key_bytes`] rejects small-order points).
    /// 3. **Fingerprint binding** — `Fingerprint::from(device_pubkey)` must equal `expected_fp`
    ///    (constant-time over the 64 hex bytes). This ties the claimed routing fingerprint to the
    ///    key whose possession is being proven.
    /// 4. **Signature** — the Ed25519 signature must verify (via `verify_strict`) over the
    ///    canonical TBS recomputed from `expected_session_id`, the presented key, and the
    ///    challenge.
    ///
    /// On success, the connecting peer has proven possession of the key behind `expected_fp` for
    /// this challenged connection. This does **not** imply the peer is *trusted* (see the module
    /// docs): trust is established separately by the endpoints via Noise/BindCert/TOFU.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Signature`] if the challenge does not match, the fingerprint does not
    ///   match, or the signature does not verify. The error is intentionally **uniform** across
    ///   these cases so a probing peer cannot learn *which* check failed (no enumeration oracle).
    /// - [`CryptoError::MalformedKey`] if the presented public-key bytes are not a valid,
    ///   non-weak Ed25519 key.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn verify(
        &self,
        expected_fp: &str,
        expected_session_id: &[u8; SESSION_ID_LEN],
        expected_challenge: &[u8; PEER_AUTH_CHALLENGE_LEN],
    ) -> Result<(), CryptoError> {
        // Check 1: challenge binding (constant-time). Reject replayed/foreign proofs.
        if self
            .challenge
            .ct_eq(expected_challenge.as_slice())
            .unwrap_u8()
            == 0
        {
            return Err(CryptoError::Signature);
        }

        // Check 2: key validity. `from_public_key_bytes` rejects non-points and small-order keys.
        let identity = DeviceIdentity::from_public_key_bytes(&self.device_pubkey)?;

        // Check 3: fingerprint binding (constant-time over the canonical lowercase-hex bytes).
        let actual_fp = identity.fingerprint();
        if actual_fp
            .as_str()
            .as_bytes()
            .ct_eq(expected_fp.as_bytes())
            .unwrap_u8()
            == 0
        {
            // Uniform error: do not reveal that the fingerprint (vs. signature) was the mismatch.
            return Err(CryptoError::Signature);
        }

        // Check 4: signature over the canonical TBS (verify_strict via Signature::verify).
        let tbs = build_tbs(expected_session_id, &self.device_pubkey, &self.challenge);
        self.signature.verify(&identity, &tbs)
    }

    /// Returns the presented Ed25519 compressed public-key bytes (public; safe to log/transmit).
    #[must_use]
    pub fn device_pubkey(&self) -> &[u8; PUBKEY_LEN] {
        &self.device_pubkey
    }

    /// Returns the echoed challenge bytes.
    #[must_use]
    pub fn challenge(&self) -> &[u8; PEER_AUTH_CHALLENGE_LEN] {
        &self.challenge
    }
}

/// Fuzz seam: pure decode of a raw byte slice, for cargo-fuzz.
///
/// Calls [`IdentityProof::decode`] and discards the result. Its sole purpose is a stable
/// entry-point for the fuzz target; it must never panic regardless of input.
///
/// # Errors
///
/// Propagates any [`CryptoError`] from [`IdentityProof::decode`]; the fuzz target ignores it.
pub fn fuzz_decode_identity_proof(data: &[u8]) -> Result<IdentityProof, CryptoError> {
    IdentityProof::decode(data)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::{Keystore, SoftwareKeystore};
    use ed25519_dalek::VerifyingKey;

    const SESSION: [u8; 16] = [0x11; 16];
    const CHALLENGE: [u8; 32] = [0x22; 32];

    async fn make_proof(ks: &SoftwareKeystore) -> (IdentityProof, String) {
        let id = ks.device_identity().await.unwrap();
        let proof = IdentityProof::create(ks, &SESSION, &CHALLENGE)
            .await
            .unwrap();
        (proof, id.fingerprint().as_str().to_owned())
    }

    #[tokio::test]
    async fn valid_proof_verifies() {
        let ks = SoftwareKeystore::generate();
        let (proof, fp) = make_proof(&ks).await;
        proof.verify(&fp, &SESSION, &CHALLENGE).unwrap();
    }

    #[tokio::test]
    async fn encode_decode_roundtrip() {
        let ks = SoftwareKeystore::generate();
        let (proof, fp) = make_proof(&ks).await;
        let wire = proof.encode();
        assert_eq!(wire.len(), IDENTITY_PROOF_LEN);
        let decoded = IdentityProof::decode(&wire).unwrap();
        decoded.verify(&fp, &SESSION, &CHALLENGE).unwrap();
    }

    #[tokio::test]
    async fn wrong_fingerprint_rejected() {
        let ks = SoftwareKeystore::generate();
        let (proof, _fp) = make_proof(&ks).await;
        // A different device's fingerprint must not be admitted by this proof.
        let other = SoftwareKeystore::generate();
        let other_fp = other.device_identity().await.unwrap();
        let result = proof.verify(other_fp.fingerprint().as_str(), &SESSION, &CHALLENGE);
        assert!(matches!(result, Err(CryptoError::Signature)));
    }

    #[tokio::test]
    async fn fingerprint_pubkey_mismatch_rejected() {
        // Hand-craft a proof where the claimed fingerprint belongs to key A but the presented
        // pubkey is key B's. The fp-binding check (constant-time) must reject it.
        let ks_a = SoftwareKeystore::generate();
        let ks_b = SoftwareKeystore::generate();
        let id_a = ks_a.device_identity().await.unwrap();
        // Proof is built and signed by B (so the signature is valid for B's key), but we will
        // verify against A's fingerprint.
        let proof = IdentityProof::create(&ks_b, &SESSION, &CHALLENGE)
            .await
            .unwrap();
        let result = proof.verify(id_a.fingerprint().as_str(), &SESSION, &CHALLENGE);
        assert!(matches!(result, Err(CryptoError::Signature)));
    }

    #[tokio::test]
    async fn tampered_signature_rejected() {
        let ks = SoftwareKeystore::generate();
        let (proof, fp) = make_proof(&ks).await;
        let mut wire = proof.encode();
        // Flip a byte in the signature region (last 64 bytes).
        let sig_start = PUBKEY_LEN + PEER_AUTH_CHALLENGE_LEN;
        wire[sig_start] ^= 0xff;
        let decoded = IdentityProof::decode(&wire).unwrap();
        let result = decoded.verify(&fp, &SESSION, &CHALLENGE);
        assert!(matches!(result, Err(CryptoError::Signature)));
    }

    #[tokio::test]
    async fn replayed_challenge_rejected() {
        // A proof issued for one challenge must not verify under a different (fresh) challenge.
        let ks = SoftwareKeystore::generate();
        let (proof, fp) = make_proof(&ks).await;
        let fresh_challenge = [0x99u8; 32];
        let result = proof.verify(&fp, &SESSION, &fresh_challenge);
        assert!(matches!(result, Err(CryptoError::Signature)));
    }

    #[tokio::test]
    async fn wrong_session_id_rejected() {
        // A proof bound to session A must not verify for session B (cross-session replay).
        let ks = SoftwareKeystore::generate();
        let (proof, fp) = make_proof(&ks).await;
        let other_session = [0x44u8; 16];
        let result = proof.verify(&fp, &other_session, &CHALLENGE);
        assert!(matches!(result, Err(CryptoError::Signature)));
    }

    #[tokio::test]
    async fn tampered_pubkey_rejected() {
        // Tampering the pubkey bytes changes the derived fingerprint (and breaks the signature).
        let ks = SoftwareKeystore::generate();
        let (proof, fp) = make_proof(&ks).await;
        let mut wire = proof.encode();
        wire[0] ^= 0x01; // perturb the first pubkey byte
                         // decode may still succeed (validity checked at verify); verify must reject.
        if let Ok(decoded) = IdentityProof::decode(&wire) {
            let result = decoded.verify(&fp, &SESSION, &CHALLENGE);
            assert!(result.is_err());
        }
    }

    #[test]
    fn small_order_pubkey_rejected_by_verify() {
        // A proof presenting a small-order public key must be rejected (verify_strict +
        // from_public_key_bytes weak-key guard). Build the wire bytes directly.
        let mut weak_pub = [0u8; 32];
        weak_pub[0] = 0x01; // Ed25519 identity element (small-order point)
        let vk = VerifyingKey::from_bytes(&weak_pub).expect("identity point decompresses");
        assert!(vk.is_weak());
        let fp = DeviceIdentity::from_verifying_key(vk)
            .fingerprint()
            .as_str()
            .to_owned();

        let mut wire = [0u8; IDENTITY_PROOF_LEN];
        wire[0..32].copy_from_slice(&weak_pub);
        wire[32..64].copy_from_slice(&CHALLENGE);
        // signature bytes left as zeros — irrelevant; the weak key must be rejected first.
        let decoded = IdentityProof::decode(&wire).unwrap();
        let result = decoded.verify(&fp, &SESSION, &CHALLENGE);
        assert!(result.is_err());
    }

    #[test]
    fn decode_wrong_length_is_err() {
        assert!(IdentityProof::decode(&[]).is_err());
        assert!(IdentityProof::decode(&[0u8; 64]).is_err());
        assert!(IdentityProof::decode(&[0u8; IDENTITY_PROOF_LEN - 1]).is_err());
        assert!(IdentityProof::decode(&[0u8; IDENTITY_PROOF_LEN + 1]).is_err());
    }

    #[test]
    fn decode_exact_length_ok() {
        // All-zero bytes decode without panic; validity is only checked at verify.
        assert!(IdentityProof::decode(&[0u8; IDENTITY_PROOF_LEN]).is_ok());
    }

    #[test]
    fn fuzz_seam_no_panic_on_garbage() {
        let _ = fuzz_decode_identity_proof(&[]);
        let _ = fuzz_decode_identity_proof(&[0xff; 200]);
        let _ = fuzz_decode_identity_proof(&[0u8; IDENTITY_PROOF_LEN]);
        // Exhaustively walk a range of lengths around the boundary: never panics.
        for len in 0..=(IDENTITY_PROOF_LEN + 4) {
            let buf = vec![0xABu8; len];
            let _ = fuzz_decode_identity_proof(&buf);
        }
    }

    #[tokio::test]
    async fn tbs_is_domain_separated() {
        // The TBS must begin with the domain tag and version — guards against cross-structure
        // signature confusion (e.g. a BindCert TBS being accepted here).
        let tbs = build_tbs(&SESSION, &[7u8; 32], &CHALLENGE);
        assert_eq!(&tbs[0..16], AUTH_DOMAIN_TAG.as_slice());
        assert_eq!(tbs[16], AUTH_TBS_VERSION);
        assert_eq!(tbs.len(), TBS_LEN);
    }
}
