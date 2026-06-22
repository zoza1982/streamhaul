//! [`BindCert`] — identity-bound certificate binding an X25519 Noise static key to an
//! Ed25519 device identity.
//!
//! A `BindCert` is the signed artifact that proves the peer presenting a Noise static in a
//! handshake is the same device that holds a trusted Ed25519 identity (ADR-0007 §2). It is
//! created by the device that owns the identity, transmitted inside the encrypted Noise
//! handshake (never in cleartext), and verified by the other side.
//!
//! # Structure
//!
//! ```text
//! BindCert (wire):
//!   lp32(TBS)   — 4-byte BE length prefix + the to-be-signed bytes
//!   SIGNATURE   — 64-byte Ed25519 signature over exactly the TBS bytes
//! ```
//!
//! The to-be-signed (TBS) layout is canonical and length-prefixed (ADR-0007 §2.1):
//!
//! ```text
//!   offset  size  field
//!    0      12    DOMAIN_TAG = b"SHP-BINDCERT"
//!   12       1    TBS_VERSION = 0x01
//!   13       1    FIELD_COUNT = 0x06
//!   14      32    DEVICE_ID (SHA-256 digest of Ed25519 pubkey, raw 32 bytes)
//!   46      32    NOISE_STATIC_X25519 (X25519 static public key, 32 bytes)
//!   78       1    DTLS_FPR_ALG (0x01=SHA-256, 0x00=none)
//!   79      32    DTLS_FPR_COMMIT (32 bytes, zeros if ALG=0x00)
//!  111       2    PLATFORM_ATTEST_LEN (u16 BE, 0..=4096)
//!  113       L    PLATFORM_ATTEST (opaque, NOT verified in P3-2)
//!  113+L     8    NOT_AFTER (i64 BE, Unix epoch)
//!  121+L     8    ISSUED_AT (i64 BE, Unix epoch)
//! ```
//!
//! # Security
//!
//! All fields in the TBS are **fixed-width or explicitly length-prefixed** in a fixed order.
//! There is exactly one valid encoding. A domain tag as the first bytes prevents cross-structure
//! signature confusion.
//!
//! ## PLATFORM_ATTEST is NOT verified in P3-2
//!
//! The `PLATFORM_ATTEST` field is signed (cannot be tampered post-issuance) but its contents
//! are opaque in P3-2. Verification of TPM 2.0 / App Attest / Play Integrity attestation
//! blobs is deferred to a later task. See ADR-0007 §2.4.
//!
//! ## `snow` dependency posture
//!
//! `snow` is unaudited. See `SECURITY.md` for the third-party crypto posture and the Risk
//! Register entry for the pre-GA review.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

use crate::{
    clock::Clock, signature::SIGNATURE_LEN, CryptoError, DeviceIdentity, Keystore, Signature,
};

// ─── TBS constants ─────────────────────────────────────────────────────────

const DOMAIN_TAG: &[u8; 12] = b"SHP-BINDCERT";
const TBS_VERSION: u8 = 0x01;
const FIELD_COUNT: u8 = 0x06;

/// Maximum allowed `PLATFORM_ATTEST_LEN` (DoS guard, ADR-0007 §2.1).
pub const MAX_PLATFORM_ATTEST_LEN: usize = 4096;

/// Minimum TBS length (no attestation data: 129 bytes).
const TBS_MIN_LEN: usize = 129;

// Field offsets (fixed part only)
const OFF_DOMAIN_TAG: usize = 0;
const OFF_TBS_VERSION: usize = 12;
const OFF_FIELD_COUNT: usize = 13;
const OFF_DEVICE_ID: usize = 14;
const OFF_NOISE_STATIC: usize = 46;
const OFF_DTLS_FPR_ALG: usize = 78;
const OFF_DTLS_FPR_COMMIT: usize = 79;
const OFF_PLATFORM_ATTEST_LEN: usize = 111;
const OFF_PLATFORM_ATTEST_DATA: usize = 113;

/// DTLS fingerprint algorithm: none (native QUIC, no DTLS).
pub const DTLS_FPR_ALG_NONE: u8 = 0x00;
/// DTLS fingerprint algorithm: SHA-256.
pub const DTLS_FPR_ALG_SHA256: u8 = 0x01;

/// A clock skew tolerance (5 minutes) applied to `ISSUED_AT` validation.
///
/// A peer's clock may be slightly behind ours; we permit their `ISSUED_AT` to be up to
/// this many seconds in the future relative to our clock without rejecting the cert.
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 300;

// ─── Parsed representation ──────────────────────────────────────────────────

/// A parsed `BindCert`.
///
/// Constructed by [`BindCert::decode`] followed by [`BindCert::verify`]. Do not construct
/// directly — always go through decode+verify to ensure the 6 ordered checks pass.
///
/// # Examples
///
/// ```
/// # use sh_crypto::{SoftwareKeystore, Keystore};
/// # use sh_crypto::bind_cert::{BindCert, BindCertBuilder};
/// # use sh_crypto::clock::FixedClock;
/// # tokio_test::block_on(async {
/// let ks = SoftwareKeystore::generate();
/// let id = ks.device_identity().await.unwrap();
/// let noise_static = [0u8; 32];
/// let clock = FixedClock(1_000_000);
///
/// let cert = BindCertBuilder::new(&ks)
///     .noise_static(noise_static)
///     .valid_for_secs(3600)
///     .build(&clock)
///     .await
///     .unwrap();
///
/// let wire = cert.encode();
/// let decoded = BindCert::decode(&wire).unwrap();
/// // verify() checks steps 1-5; trust check (step 6) is caller's responsibility
/// decoded.verify(&id, &noise_static, &clock).unwrap();
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct BindCert {
    /// The raw TBS bytes as received (NOT re-encoded). Used for signature verification.
    tbs_bytes: Vec<u8>,
    /// The Ed25519 signature over `tbs_bytes`.
    signature: Signature,
    /// Parsed fields (extracted from `tbs_bytes` for convenience).
    fields: TbsFields,
}

/// Parsed TBS fields extracted from a `BindCert`.
#[derive(Debug, Clone)]
struct TbsFields {
    device_id_digest: [u8; 32],
    noise_static: [u8; 32],
    dtls_fpr_alg: u8,
    dtls_fpr_commit: [u8; 32],
    platform_attest: Vec<u8>,
    not_after: i64,
    issued_at: i64,
}

impl BindCert {
    /// Decodes a `BindCert` from untrusted wire bytes.
    ///
    /// This performs structural validation only (step 1 of the 6-check process). Call
    /// [`verify`](Self::verify) afterward to complete checks 2–5. Step 6 (trust) is the
    /// caller's responsibility via [`Keystore::is_trusted`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MalformedBindCert`] for any structural problem including:
    /// - Input too short to contain the `lp32` length prefix and minimum TBS
    /// - `lp32` length overflows the input
    /// - `DOMAIN_TAG` mismatch
    /// - `TBS_VERSION` or `FIELD_COUNT` mismatch
    /// - `PLATFORM_ATTEST_LEN > 4096`
    /// - Total length mismatch (trailing garbage)
    /// - Signature bytes of wrong length
    ///
    /// # Panics
    ///
    /// Never panics. All arithmetic is bounds-checked.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_crypto::bind_cert::BindCert;
    ///
    /// // Truncated input → typed error, no panic.
    /// assert!(BindCert::decode(&[]).is_err());
    /// assert!(BindCert::decode(&[0u8; 10]).is_err());
    /// ```
    pub fn decode(wire: &[u8]) -> Result<Self, CryptoError> {
        // Need at least 4 bytes for the lp32 prefix.
        if wire.len() < 4 {
            return Err(CryptoError::MalformedBindCert {
                reason: "input too short for lp32 prefix",
            });
        }
        let prefix: [u8; 4] = wire
            .get(..4)
            .ok_or(CryptoError::MalformedBindCert {
                reason: "input too short for lp32 prefix",
            })?
            .try_into()
            .map_err(|_| CryptoError::MalformedBindCert {
                reason: "lp32 prefix slice conversion failed",
            })?;
        let tbs_len = u32::from_be_bytes(prefix) as usize;

        let wire_after_prefix = wire.get(4..).ok_or(CryptoError::MalformedBindCert {
            reason: "input too short after lp32 prefix",
        })?;
        if tbs_len > wire_after_prefix.len() {
            return Err(CryptoError::MalformedBindCert {
                reason: "lp32 length exceeds available input",
            });
        }
        let tbs_bytes = wire_after_prefix
            .get(..tbs_len)
            .ok_or(CryptoError::MalformedBindCert {
                reason: "TBS slice out of bounds",
            })?;
        let remaining = wire_after_prefix
            .get(tbs_len..)
            .ok_or(CryptoError::MalformedBindCert {
                reason: "signature slice out of bounds",
            })?;

        // The signature must be exactly SIGNATURE_LEN bytes after the TBS.
        if remaining.len() != SIGNATURE_LEN {
            return Err(CryptoError::MalformedBindCert {
                reason: "expected exactly 64 signature bytes after TBS",
            });
        }
        let signature = Signature::decode(remaining)?;

        // Validate TBS minimum length.
        if tbs_bytes.len() < TBS_MIN_LEN {
            return Err(CryptoError::MalformedBindCert {
                reason: "TBS too short for fixed fields",
            });
        }

        // Check domain tag (bytes 0..12).
        let tag = tbs_bytes
            .get(OFF_DOMAIN_TAG..OFF_DOMAIN_TAG.saturating_add(12))
            .ok_or(CryptoError::MalformedBindCert {
                reason: "TBS too short for domain tag",
            })?;
        if tag != DOMAIN_TAG.as_slice() {
            return Err(CryptoError::MalformedBindCert {
                reason: "domain tag mismatch",
            });
        }

        // Check TBS_VERSION.
        let version =
            tbs_bytes
                .get(OFF_TBS_VERSION)
                .copied()
                .ok_or(CryptoError::MalformedBindCert {
                    reason: "TBS too short for version byte",
                })?;
        if version != TBS_VERSION {
            return Err(CryptoError::MalformedBindCert {
                reason: "unsupported TBS version",
            });
        }

        // Check FIELD_COUNT.
        let field_count =
            tbs_bytes
                .get(OFF_FIELD_COUNT)
                .copied()
                .ok_or(CryptoError::MalformedBindCert {
                    reason: "TBS too short for field count",
                })?;
        if field_count != FIELD_COUNT {
            return Err(CryptoError::MalformedBindCert {
                reason: "field count mismatch",
            });
        }

        // Extract DEVICE_ID (32 bytes at offset 14).
        let mut device_id_digest = [0u8; 32];
        let device_id_slice = tbs_bytes
            .get(OFF_DEVICE_ID..OFF_DEVICE_ID.saturating_add(32))
            .ok_or(CryptoError::MalformedBindCert {
                reason: "TBS too short for DEVICE_ID",
            })?;
        device_id_digest.copy_from_slice(device_id_slice);

        // Extract NOISE_STATIC_X25519 (32 bytes at offset 46).
        let mut noise_static = [0u8; 32];
        let ns_slice = tbs_bytes
            .get(OFF_NOISE_STATIC..OFF_NOISE_STATIC.saturating_add(32))
            .ok_or(CryptoError::MalformedBindCert {
                reason: "TBS too short for NOISE_STATIC_X25519",
            })?;
        noise_static.copy_from_slice(ns_slice);

        // Extract DTLS_FPR_ALG (1 byte at offset 78).
        let dtls_fpr_alg =
            tbs_bytes
                .get(OFF_DTLS_FPR_ALG)
                .copied()
                .ok_or(CryptoError::MalformedBindCert {
                    reason: "TBS too short for DTLS_FPR_ALG",
                })?;

        // Extract DTLS_FPR_COMMIT (32 bytes at offset 79).
        let mut dtls_fpr_commit = [0u8; 32];
        let fpr_slice = tbs_bytes
            .get(OFF_DTLS_FPR_COMMIT..OFF_DTLS_FPR_COMMIT.saturating_add(32))
            .ok_or(CryptoError::MalformedBindCert {
                reason: "TBS too short for DTLS_FPR_COMMIT",
            })?;
        dtls_fpr_commit.copy_from_slice(fpr_slice);

        // Extract PLATFORM_ATTEST_LEN (u16 BE at offset 111).
        let pa_len_arr: [u8; 2] = tbs_bytes
            .get(OFF_PLATFORM_ATTEST_LEN..OFF_PLATFORM_ATTEST_LEN.saturating_add(2))
            .ok_or(CryptoError::MalformedBindCert {
                reason: "TBS too short for PLATFORM_ATTEST_LEN",
            })?
            .try_into()
            .map_err(|_| CryptoError::MalformedBindCert {
                reason: "PLATFORM_ATTEST_LEN slice conversion failed",
            })?;
        let pa_len = u16::from_be_bytes(pa_len_arr) as usize;

        // DoS guard: reject oversized attestation blobs.
        if pa_len > MAX_PLATFORM_ATTEST_LEN {
            return Err(CryptoError::MalformedBindCert {
                reason: "PLATFORM_ATTEST_LEN exceeds 4096",
            });
        }

        // Compute expected total TBS length and validate — no trailing garbage.
        let expected_tbs_len = TBS_MIN_LEN.saturating_add(pa_len);
        if tbs_bytes.len() != expected_tbs_len {
            return Err(CryptoError::MalformedBindCert {
                reason: "TBS length does not match computed expected length",
            });
        }

        // Extract PLATFORM_ATTEST blob.
        let pa_end = OFF_PLATFORM_ATTEST_DATA.saturating_add(pa_len);
        let platform_attest = tbs_bytes
            .get(OFF_PLATFORM_ATTEST_DATA..pa_end)
            .ok_or(CryptoError::MalformedBindCert {
                reason: "TBS too short for PLATFORM_ATTEST data",
            })?
            .to_vec();

        // Extract NOT_AFTER (i64 BE at 113+L).
        let not_after_off = OFF_PLATFORM_ATTEST_DATA.saturating_add(pa_len);
        let not_after_arr: [u8; 8] = tbs_bytes
            .get(not_after_off..not_after_off.saturating_add(8))
            .ok_or(CryptoError::MalformedBindCert {
                reason: "TBS too short for NOT_AFTER",
            })?
            .try_into()
            .map_err(|_| CryptoError::MalformedBindCert {
                reason: "NOT_AFTER slice conversion failed",
            })?;
        let not_after = i64::from_be_bytes(not_after_arr);

        // Extract ISSUED_AT (i64 BE at 121+L).
        let issued_at_off = not_after_off.saturating_add(8);
        let issued_at_arr: [u8; 8] = tbs_bytes
            .get(issued_at_off..issued_at_off.saturating_add(8))
            .ok_or(CryptoError::MalformedBindCert {
                reason: "TBS too short for ISSUED_AT",
            })?
            .try_into()
            .map_err(|_| CryptoError::MalformedBindCert {
                reason: "ISSUED_AT slice conversion failed",
            })?;
        let issued_at = i64::from_be_bytes(issued_at_arr);

        // Structural check: NOT_AFTER must be > ISSUED_AT.
        if not_after <= issued_at {
            return Err(CryptoError::MalformedBindCert {
                reason: "NOT_AFTER must be strictly greater than ISSUED_AT",
            });
        }

        Ok(Self {
            tbs_bytes: tbs_bytes.to_vec(),
            signature,
            fields: TbsFields {
                device_id_digest,
                noise_static,
                dtls_fpr_alg,
                dtls_fpr_commit,
                platform_attest,
                not_after,
                issued_at,
            },
        })
    }

    /// Verifies this `BindCert` (checks 2–5 of the 6-check protocol, ADR-0007 §2.6).
    ///
    /// # Checks performed (in order)
    ///
    /// 2. **Signature**: `peer_identity` must have signed the exact received TBS bytes.
    /// 3. **Identity self-consistency**: `DEVICE_ID` digest must equal `SHA-256(peer pubkey)`.
    /// 4. **Noise-static binding**: `NOISE_STATIC_X25519` must byte-equal `live_noise_static`
    ///    in constant time.
    /// 5. **Expiry**: `NOT_AFTER > now` and `ISSUED_AT ≤ now + skew_tolerance`.
    ///
    /// Check 6 (trust store) is the **caller's responsibility** via [`Keystore::is_trusted`]
    /// because it is async. Call this method first, then check trust.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Signature`] — signature invalid
    /// - [`CryptoError::MalformedBindCert`] — identity self-consistency failure
    /// - [`CryptoError::NoiseStaticMismatch`] — live static ≠ committed static (MITM)
    /// - [`CryptoError::BindCertExpired`] — `NOT_AFTER` in the past
    /// - [`CryptoError::BindCertNotYetValid`] — `ISSUED_AT` too far in the future
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sh_crypto::{SoftwareKeystore, Keystore};
    /// # use sh_crypto::bind_cert::{BindCert, BindCertBuilder};
    /// # use sh_crypto::clock::FixedClock;
    /// # tokio_test::block_on(async {
    /// let ks = SoftwareKeystore::generate();
    /// let id = ks.device_identity().await.unwrap();
    /// let noise_static = [1u8; 32];
    /// let clock = FixedClock(1_000_000);
    /// let cert = BindCertBuilder::new(&ks)
    ///     .noise_static(noise_static)
    ///     .valid_for_secs(3600)
    ///     .build(&clock)
    ///     .await
    ///     .unwrap();
    /// let wire = cert.encode();
    /// let decoded = BindCert::decode(&wire).unwrap();
    /// assert!(decoded.verify(&id, &noise_static, &clock).is_ok());
    /// # });
    /// ```
    pub fn verify(
        &self,
        peer_identity: &DeviceIdentity,
        live_noise_static: &[u8; 32],
        clock: &dyn Clock,
    ) -> Result<(), CryptoError> {
        // Check 2: Verify signature over the RECEIVED tbs bytes (never a re-encode).
        self.signature.verify(peer_identity, &self.tbs_bytes)?;

        // Check 3: Identity self-consistency — DEVICE_ID == SHA-256(peer Ed25519 pubkey).
        let expected_digest = Sha256::digest(peer_identity.public_key_bytes());
        if expected_digest.as_slice() != self.fields.device_id_digest.as_slice() {
            return Err(CryptoError::MalformedBindCert {
                reason: "DEVICE_ID does not match SHA-256 of peer's Ed25519 public key",
            });
        }

        // Check 4: Noise-static binding — constant-time comparison.
        // subtle::Choice does not implement Into<u8>; use unwrap_u8() instead.
        if self
            .fields
            .noise_static
            .ct_eq(live_noise_static)
            .unwrap_u8()
            == 0
        {
            return Err(CryptoError::NoiseStaticMismatch);
        }

        // Check 5: Clock validity.
        let now = clock.now_unix_secs();
        if self.fields.not_after <= now {
            return Err(CryptoError::BindCertExpired);
        }
        let skew_adjusted_now = now.saturating_add(CLOCK_SKEW_TOLERANCE_SECS);
        if self.fields.issued_at > skew_adjusted_now {
            return Err(CryptoError::BindCertNotYetValid);
        }

        Ok(())
    }

    /// Encodes this `BindCert` to its wire form (`lp32(TBS) || SIGNATURE`).
    ///
    /// # Examples
    ///
    /// ```
    /// # use sh_crypto::{SoftwareKeystore, Keystore};
    /// # use sh_crypto::bind_cert::{BindCert, BindCertBuilder};
    /// # use sh_crypto::clock::FixedClock;
    /// # tokio_test::block_on(async {
    /// let ks = SoftwareKeystore::generate();
    /// let clock = FixedClock(1_000_000);
    /// let cert = BindCertBuilder::new(&ks)
    ///     .noise_static([2u8; 32])
    ///     .valid_for_secs(3600)
    ///     .build(&clock)
    ///     .await
    ///     .unwrap();
    /// let wire = cert.encode();
    /// // 4-byte lp32 + 129-byte TBS (no attestation) + 64-byte sig = 197 bytes
    /// assert_eq!(wire.len(), 4 + 129 + 64);
    /// # });
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let tbs_len = self.tbs_bytes.len();
        let total = 4_usize
            .saturating_add(tbs_len)
            .saturating_add(SIGNATURE_LEN);
        let mut out = Vec::with_capacity(total);
        // TBS length is bounded by TBS_MIN_LEN + MAX_PLATFORM_ATTEST_LEN = 4225, which is always
        // within u32 range. Use saturating cast; a value that large would be caught at decode time.
        #[allow(clippy::cast_possible_truncation)]
        let len_u32 = tbs_len as u32;
        out.extend_from_slice(&len_u32.to_be_bytes());
        out.extend_from_slice(&self.tbs_bytes);
        out.extend_from_slice(&self.signature.encode());
        out
    }

    /// Returns the `DEVICE_ID` field (SHA-256 digest of the signer's Ed25519 public key).
    pub fn device_id_digest(&self) -> &[u8; 32] {
        &self.fields.device_id_digest
    }

    /// Returns the committed X25519 Noise static public key.
    pub fn noise_static(&self) -> &[u8; 32] {
        &self.fields.noise_static
    }

    /// Returns the DTLS fingerprint algorithm byte.
    pub fn dtls_fpr_alg(&self) -> u8 {
        self.fields.dtls_fpr_alg
    }

    /// Returns the DTLS fingerprint commitment (32 bytes; zeros if `dtls_fpr_alg() == 0x00`).
    pub fn dtls_fpr_commit(&self) -> &[u8; 32] {
        &self.fields.dtls_fpr_commit
    }

    /// Returns the opaque platform attestation blob (NOT verified in P3-2).
    ///
    /// See ADR-0007 §2.4 for the deferred schema.
    pub fn platform_attest(&self) -> &[u8] {
        &self.fields.platform_attest
    }

    /// Returns the `NOT_AFTER` Unix epoch timestamp (UTC, seconds).
    pub fn not_after(&self) -> i64 {
        self.fields.not_after
    }

    /// Returns the `ISSUED_AT` Unix epoch timestamp (UTC, seconds).
    pub fn issued_at(&self) -> i64 {
        self.fields.issued_at
    }
}

// ─── BindCertBuilder ────────────────────────────────────────────────────────

/// Builder for a signed [`BindCert`].
///
/// # Examples
///
/// ```
/// # use sh_crypto::{SoftwareKeystore, Keystore};
/// # use sh_crypto::bind_cert::BindCertBuilder;
/// # use sh_crypto::clock::FixedClock;
/// # tokio_test::block_on(async {
/// let ks = SoftwareKeystore::generate();
/// let clock = FixedClock(1_000_000);
/// let cert = BindCertBuilder::new(&ks)
///     .noise_static([3u8; 32])
///     .valid_for_secs(3600)
///     .build(&clock)
///     .await
///     .unwrap();
/// # });
/// ```
pub struct BindCertBuilder<'a, K: Keystore> {
    keystore: &'a K,
    noise_static: Option<[u8; 32]>,
    valid_for_secs: Option<i64>,
    dtls_fpr_alg: u8,
    dtls_fpr_commit: [u8; 32],
    platform_attest: Vec<u8>,
}

impl<'a, K: Keystore> BindCertBuilder<'a, K> {
    /// Creates a new builder using the given `keystore` as the signer.
    pub fn new(keystore: &'a K) -> Self {
        Self {
            keystore,
            noise_static: None,
            valid_for_secs: None,
            dtls_fpr_alg: DTLS_FPR_ALG_NONE,
            dtls_fpr_commit: [0u8; 32],
            platform_attest: Vec::new(),
        }
    }

    /// Sets the X25519 Noise static public key to bind.
    #[must_use]
    pub fn noise_static(mut self, key: [u8; 32]) -> Self {
        self.noise_static = Some(key);
        self
    }

    /// Sets the validity duration in seconds from the build time.
    #[must_use]
    pub fn valid_for_secs(mut self, secs: i64) -> Self {
        self.valid_for_secs = Some(secs);
        self
    }

    /// Sets a DTLS fingerprint commitment (for WebRTC / P4-5).
    ///
    /// `alg` must be [`DTLS_FPR_ALG_SHA256`] and `commit` the SHA-256 of the DTLS SPKI.
    #[must_use]
    pub fn dtls_fpr(mut self, alg: u8, commit: [u8; 32]) -> Self {
        self.dtls_fpr_alg = alg;
        self.dtls_fpr_commit = commit;
        self
    }

    /// Sets the opaque platform attestation blob.
    ///
    /// [`BindCertBuilder::build`] will return an error if the blob exceeds 4096 bytes.
    #[must_use]
    pub fn platform_attest(mut self, blob: Vec<u8>) -> Self {
        self.platform_attest = blob;
        self
    }

    /// Builds and signs the [`BindCert`].
    ///
    /// # Errors
    ///
    /// - [`CryptoError::MalformedBindCert`] if `noise_static` was not set, `valid_for_secs`
    ///   was not set, or the platform attestation blob exceeds 4096 bytes.
    /// - [`CryptoError::Backend`] if the keystore signing operation fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn build(self, clock: &dyn Clock) -> Result<BindCert, CryptoError> {
        let noise_static = self.noise_static.ok_or(CryptoError::MalformedBindCert {
            reason: "noise_static not set on BindCertBuilder",
        })?;
        let valid_for_secs = self.valid_for_secs.ok_or(CryptoError::MalformedBindCert {
            reason: "valid_for_secs not set on BindCertBuilder",
        })?;
        if self.platform_attest.len() > MAX_PLATFORM_ATTEST_LEN {
            return Err(CryptoError::MalformedBindCert {
                reason: "platform_attest blob exceeds 4096 bytes",
            });
        }

        let identity = self.keystore.device_identity().await?;
        let mut device_id_digest = [0u8; 32];
        device_id_digest.copy_from_slice(Sha256::digest(identity.public_key_bytes()).as_slice());

        let issued_at = clock.now_unix_secs();
        let not_after = issued_at.saturating_add(valid_for_secs);

        // Structural check: not_after must be > issued_at.
        if not_after <= issued_at {
            return Err(CryptoError::MalformedBindCert {
                reason: "valid_for_secs must be positive (not_after must exceed issued_at)",
            });
        }

        let tbs_bytes = build_tbs(
            &device_id_digest,
            &noise_static,
            self.dtls_fpr_alg,
            &self.dtls_fpr_commit,
            &self.platform_attest,
            not_after,
            issued_at,
        );

        let signature = self.keystore.sign(&tbs_bytes).await?;

        Ok(BindCert {
            tbs_bytes,
            signature,
            fields: TbsFields {
                device_id_digest,
                noise_static,
                dtls_fpr_alg: self.dtls_fpr_alg,
                dtls_fpr_commit: self.dtls_fpr_commit,
                platform_attest: self.platform_attest,
                not_after,
                issued_at,
            },
        })
    }
}

/// Builds the canonical TBS byte string.
fn build_tbs(
    device_id_digest: &[u8; 32],
    noise_static: &[u8; 32],
    dtls_fpr_alg: u8,
    dtls_fpr_commit: &[u8; 32],
    platform_attest: &[u8],
    not_after: i64,
    issued_at: i64,
) -> Vec<u8> {
    let pa_len = platform_attest.len();
    let capacity = TBS_MIN_LEN.saturating_add(pa_len);
    let mut tbs = Vec::with_capacity(capacity);

    tbs.extend_from_slice(DOMAIN_TAG.as_slice()); // 12 bytes
    tbs.push(TBS_VERSION); // 1 byte
    tbs.push(FIELD_COUNT); // 1 byte
    tbs.extend_from_slice(device_id_digest.as_slice()); // 32 bytes (offset 14)
    tbs.extend_from_slice(noise_static.as_slice()); // 32 bytes (offset 46)
    tbs.push(dtls_fpr_alg); // 1 byte  (offset 78)
    tbs.extend_from_slice(dtls_fpr_commit.as_slice()); // 32 bytes (offset 79)
                                                       // pa_len ≤ MAX_PLATFORM_ATTEST_LEN (4096), always fits in u16.
    #[allow(clippy::cast_possible_truncation)]
    let pa_len_u16 = pa_len as u16;
    tbs.extend_from_slice(&pa_len_u16.to_be_bytes()); // 2 bytes (offset 111)
    tbs.extend_from_slice(platform_attest); // L bytes (offset 113)
    tbs.extend_from_slice(&not_after.to_be_bytes()); // 8 bytes
    tbs.extend_from_slice(&issued_at.to_be_bytes()); // 8 bytes

    tbs
}

/// Builds a TBS for test use (no DTLS, no attestation).
///
/// Used by the fuzz harness and unit tests that need direct TBS construction.
// Fuzz crates are excluded from the workspace, so this appears unused to the workspace compiler.
#[allow(dead_code)]
pub(crate) fn build_tbs_for_test(
    device_id_digest: &[u8; 32],
    noise_static: &[u8; 32],
    not_after: i64,
    issued_at: i64,
) -> Vec<u8> {
    build_tbs(
        device_id_digest,
        noise_static,
        DTLS_FPR_ALG_NONE,
        &[0u8; 32],
        &[],
        not_after,
        issued_at,
    )
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
    use crate::clock::FixedClock;
    use crate::{Keystore, SoftwareKeystore};
    use proptest::prelude::*;

    const NOW: i64 = 1_000_000_000;
    const VALID_FOR: i64 = 3600;

    async fn make_cert(ks: &SoftwareKeystore, noise_static: [u8; 32], now: i64) -> BindCert {
        BindCertBuilder::new(ks)
            .noise_static(noise_static)
            .valid_for_secs(VALID_FOR)
            .build(&FixedClock(now))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn encode_decode_roundtrip() {
        let ks = SoftwareKeystore::generate();
        let ns = [0x42u8; 32];
        let cert = make_cert(&ks, ns, NOW).await;
        let wire = cert.encode();
        let decoded = BindCert::decode(&wire).unwrap();
        assert_eq!(decoded.noise_static(), &ns);
        assert_eq!(decoded.not_after(), cert.not_after());
        assert_eq!(decoded.issued_at(), cert.issued_at());
        assert_eq!(decoded.device_id_digest(), cert.device_id_digest());
    }

    #[tokio::test]
    async fn wire_length_no_attestation() {
        let ks = SoftwareKeystore::generate();
        let cert = make_cert(&ks, [0u8; 32], NOW).await;
        let wire = cert.encode();
        assert_eq!(wire.len(), 4 + TBS_MIN_LEN + SIGNATURE_LEN);
    }

    #[tokio::test]
    async fn verify_valid_cert() {
        let ks = SoftwareKeystore::generate();
        let id = ks.device_identity().await.unwrap();
        let ns = [0x11u8; 32];
        let clock = FixedClock(NOW);
        let cert = make_cert(&ks, ns, NOW).await;
        let wire = cert.encode();
        let decoded = BindCert::decode(&wire).unwrap();
        decoded.verify(&id, &ns, &clock).unwrap();
    }

    #[tokio::test]
    async fn tampered_tbs_byte_rejected() {
        let ks = SoftwareKeystore::generate();
        let id = ks.device_identity().await.unwrap();
        let ns = [0x22u8; 32];
        let clock = FixedClock(NOW);
        let cert = make_cert(&ks, ns, NOW).await;
        let mut wire = cert.encode();
        // Flip a byte inside the TBS (offset 14 = first byte of DEVICE_ID).
        wire[4 + 14] ^= 0xff;
        let decoded = BindCert::decode(&wire).unwrap();
        assert!(decoded.verify(&id, &ns, &clock).is_err());
    }

    #[tokio::test]
    async fn tampered_sig_byte_rejected() {
        let ks = SoftwareKeystore::generate();
        let id = ks.device_identity().await.unwrap();
        let ns = [0x33u8; 32];
        let clock = FixedClock(NOW);
        let cert = make_cert(&ks, ns, NOW).await;
        let mut wire = cert.encode();
        // Flip a byte in the signature (last 64 bytes).
        let sig_start = wire.len() - SIGNATURE_LEN;
        wire[sig_start] ^= 0xff;
        let decoded = BindCert::decode(&wire).unwrap();
        let result = decoded.verify(&id, &ns, &clock);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn expired_cert_rejected() {
        let ks = SoftwareKeystore::generate();
        let id = ks.device_identity().await.unwrap();
        let ns = [0x44u8; 32];
        // Cert valid from NOW to NOW+VALID_FOR; clock is AFTER not_after.
        let cert = make_cert(&ks, ns, NOW).await;
        let wire = cert.encode();
        let decoded = BindCert::decode(&wire).unwrap();
        let future_clock = FixedClock(NOW + VALID_FOR + 1);
        let result = decoded.verify(&id, &ns, &future_clock);
        assert!(matches!(result, Err(CryptoError::BindCertExpired)));
    }

    #[tokio::test]
    async fn not_yet_valid_rejected() {
        let ks = SoftwareKeystore::generate();
        let id = ks.device_identity().await.unwrap();
        let ns = [0x55u8; 32];
        // Cert issued_at = NOW; check at NOW - CLOCK_SKEW_TOLERANCE_SECS - 1.
        let cert = make_cert(&ks, ns, NOW).await;
        let wire = cert.encode();
        let decoded = BindCert::decode(&wire).unwrap();
        // Clock is far enough in the past that even with skew tolerance, issued_at is in the future.
        let past_clock = FixedClock(NOW - CLOCK_SKEW_TOLERANCE_SECS - 1);
        let result = decoded.verify(&id, &ns, &past_clock);
        assert!(matches!(result, Err(CryptoError::BindCertNotYetValid)));
    }

    #[tokio::test]
    async fn noise_static_mismatch_rejected() {
        let ks = SoftwareKeystore::generate();
        let id = ks.device_identity().await.unwrap();
        let ns = [0x66u8; 32];
        let wrong_ns = [0x77u8; 32];
        let clock = FixedClock(NOW);
        let cert = make_cert(&ks, ns, NOW).await;
        let wire = cert.encode();
        let decoded = BindCert::decode(&wire).unwrap();
        let result = decoded.verify(&id, &wrong_ns, &clock);
        assert!(matches!(result, Err(CryptoError::NoiseStaticMismatch)));
    }

    #[tokio::test]
    async fn identity_self_consistency_fail() {
        let ks = SoftwareKeystore::generate();
        let other_ks = SoftwareKeystore::generate();
        let other_id = other_ks.device_identity().await.unwrap();
        let ns = [0x88u8; 32];
        let clock = FixedClock(NOW);
        // Cert signed by `ks`; try to verify with `other_id` → sig fails (check 2).
        let cert = make_cert(&ks, ns, NOW).await;
        let wire = cert.encode();
        let decoded = BindCert::decode(&wire).unwrap();
        let result = decoded.verify(&other_id, &ns, &clock);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn truncated_decode_never_panics() {
        let ks = SoftwareKeystore::generate();
        let cert = make_cert(&ks, [0u8; 32], NOW).await;
        let wire = cert.encode();
        for len in 0..wire.len() {
            let _ = BindCert::decode(&wire[..len]);
        }
    }

    #[tokio::test]
    async fn oversized_platform_attest_rejected() {
        let ks = SoftwareKeystore::generate();
        let clock = FixedClock(NOW);
        let blob = vec![0u8; MAX_PLATFORM_ATTEST_LEN + 1];
        let result = BindCertBuilder::new(&ks)
            .noise_static([0u8; 32])
            .valid_for_secs(3600)
            .platform_attest(blob)
            .build(&clock)
            .await;
        assert!(matches!(result, Err(CryptoError::MalformedBindCert { .. })));
    }

    #[tokio::test]
    async fn wrong_domain_tag_rejected() {
        let ks = SoftwareKeystore::generate();
        let cert = make_cert(&ks, [0u8; 32], NOW).await;
        let mut wire = cert.encode();
        // Corrupt the first byte of the domain tag (inside TBS, after 4-byte lp32).
        wire[4] ^= 0xff;
        let result = BindCert::decode(&wire);
        assert!(matches!(result, Err(CryptoError::MalformedBindCert { .. })));
    }

    #[tokio::test]
    async fn trailing_garbage_rejected() {
        let ks = SoftwareKeystore::generate();
        let cert = make_cert(&ks, [0u8; 32], NOW).await;
        let mut wire = cert.encode();
        // Append a garbage byte — total wire length is wrong.
        wire.push(0xff);
        let result = BindCert::decode(&wire);
        assert!(matches!(result, Err(CryptoError::MalformedBindCert { .. })));
    }

    #[tokio::test]
    async fn not_after_equal_issued_at_rejected() {
        // Build a TBS manually with not_after == issued_at.
        let ks = SoftwareKeystore::generate();
        let id = ks.device_identity().await.unwrap();
        let mut device_id_digest = [0u8; 32];
        device_id_digest.copy_from_slice(Sha256::digest(id.public_key_bytes()).as_slice());
        let ns = [0u8; 32];
        let t = NOW;
        let tbs = build_tbs(
            &device_id_digest,
            &ns,
            DTLS_FPR_ALG_NONE,
            &[0u8; 32],
            &[],
            t,
            t,
        );
        let sig = ks.sign(&tbs).await.unwrap();
        let mut wire = Vec::new();
        wire.extend_from_slice(&(tbs.len() as u32).to_be_bytes());
        wire.extend_from_slice(&tbs);
        wire.extend_from_slice(&sig.encode());
        let result = BindCert::decode(&wire);
        assert!(matches!(result, Err(CryptoError::MalformedBindCert { .. })));
    }

    #[tokio::test]
    async fn platform_attest_roundtrip() {
        let ks = SoftwareKeystore::generate();
        let id = ks.device_identity().await.unwrap();
        let ns = [0xaau8; 32];
        let clock = FixedClock(NOW);
        let blob = vec![0x01, 0x02, 0x03, 0x04];
        let cert = BindCertBuilder::new(&ks)
            .noise_static(ns)
            .valid_for_secs(3600)
            .platform_attest(blob.clone())
            .build(&clock)
            .await
            .unwrap();
        let wire = cert.encode();
        // Expected wire length: 4 + (129 + 4) + 64 = 201
        assert_eq!(wire.len(), 4 + TBS_MIN_LEN + blob.len() + SIGNATURE_LEN);
        let decoded = BindCert::decode(&wire).unwrap();
        assert_eq!(decoded.platform_attest(), blob.as_slice());
        decoded.verify(&id, &ns, &clock).unwrap();
    }

    /// Golden conformance vector for the TBS byte layout.
    ///
    /// This test ensures that the canonical encoding of a `BindCert` TBS does not change
    /// silently between refactors. If this test fails, the encoding has changed in a
    /// backwards-incompatible way (ADR-0007 §2.1 requires exactly one valid encoding).
    #[test]
    fn golden_tbs_conformance_vector() {
        // Fixed, known inputs for deterministic output.
        let device_id_digest = [0x01u8; 32]; // DEVICE_ID
        let noise_static = [0x02u8; 32]; // NOISE_STATIC_X25519
        let dtls_fpr_alg = DTLS_FPR_ALG_NONE; // 0x00
        let dtls_fpr_commit = [0x00u8; 32]; // zeros (ALG=0x00)
        let platform_attest: &[u8] = &[]; // empty
        let not_after: i64 = 0x0000_0000_3B9A_CA00_i64; // 1_000_000_000
        let issued_at: i64 = 0x0000_0000_3B9A_C9FC_i64; // 999_999_996

        let tbs = build_tbs(
            &device_id_digest,
            &noise_static,
            dtls_fpr_alg,
            &dtls_fpr_commit,
            platform_attest,
            not_after,
            issued_at,
        );

        // Verify length: 129 bytes (no attestation).
        assert_eq!(tbs.len(), TBS_MIN_LEN, "TBS must be exactly 129 bytes");

        // Verify domain tag at offset 0..12.
        assert_eq!(&tbs[0..12], b"SHP-BINDCERT", "domain tag mismatch");
        // Verify TBS_VERSION at offset 12.
        assert_eq!(tbs[12], 0x01, "TBS_VERSION must be 0x01");
        // Verify FIELD_COUNT at offset 13.
        assert_eq!(tbs[13], 0x06, "FIELD_COUNT must be 0x06");
        // Verify DEVICE_ID at offset 14..46.
        assert_eq!(&tbs[14..46], &[0x01u8; 32], "DEVICE_ID mismatch");
        // Verify NOISE_STATIC_X25519 at offset 46..78.
        assert_eq!(&tbs[46..78], &[0x02u8; 32], "NOISE_STATIC_X25519 mismatch");
        // Verify DTLS_FPR_ALG at offset 78.
        assert_eq!(tbs[78], 0x00, "DTLS_FPR_ALG must be 0x00 (none)");
        // Verify DTLS_FPR_COMMIT at offset 79..111 (all zeros for ALG=0x00).
        assert_eq!(&tbs[79..111], &[0x00u8; 32], "DTLS_FPR_COMMIT must be zero");
        // Verify PLATFORM_ATTEST_LEN at offset 111..113 (u16 BE = 0).
        assert_eq!(
            &tbs[111..113],
            &[0x00, 0x00],
            "PLATFORM_ATTEST_LEN must be 0"
        );
        // Verify NOT_AFTER at offset 113..121.
        assert_eq!(
            &tbs[113..121],
            &not_after.to_be_bytes(),
            "NOT_AFTER bytes mismatch"
        );
        // Verify ISSUED_AT at offset 121..129.
        assert_eq!(
            &tbs[121..129],
            &issued_at.to_be_bytes(),
            "ISSUED_AT bytes mismatch"
        );
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = BindCert::decode(&data);
        }

        #[test]
        fn encode_decode_roundtrip_prop(seed in any::<u64>(), noise_bytes in any::<[u8; 32]>()) {
            use rand_core::SeedableRng;
            let rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            let ks = SoftwareKeystore::generate_with_rng(rng);
            let id = tokio_test::block_on(ks.device_identity()).unwrap();
            let clock = FixedClock(NOW);
            let cert = tokio_test::block_on(make_cert(&ks, noise_bytes, NOW));
            let wire = cert.encode();
            let decoded = BindCert::decode(&wire).unwrap();
            prop_assert!(decoded.verify(&id, &noise_bytes, &clock).is_ok());
        }
    }
}
