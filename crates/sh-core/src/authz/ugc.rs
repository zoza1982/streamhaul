//! [`Ugc`] — Unattended Grant Certificate (ADR-0010 §2).
//!
//! A `Ugc` is a host-signed, grantee-bound, time-limited, epoch-versioned bearer token
//! that authorises unattended access for a specific controller device. It mirrors the
//! `BindCert` discipline: canonical, fixed-order, fixed-width, domain-separated,
//! single-valid-encoding.
//!
//! # Wire format
//!
//! ```text
//! UGC wire bytes (141 bytes total):
//!   lp32(UGC_TBS)   — 4-byte BE length prefix + the 73-byte TBS
//!   || SIGNATURE[64] — Ed25519 signature over exactly the TBS bytes (host identity)
//! ```
//!
//! # TBS layout (73 bytes, all fixed-width, big-endian)
//!
//! ```text
//! offset  size  field
//!      0    11  DOMAIN_TAG = b"SHP-UGC\x00\x00\x00\x00"
//!     11     1  TBS_VERSION = 0x01
//!     12     1  FIELD_COUNT = 0x05
//!     13    32  GRANTEE_DEVICE_ID (SHA-256 of grantee Ed25519 pubkey)
//!     45     4  CAPS (u32 BE)
//!     49     8  EPOCH (u64 BE)
//!     57     8  NOT_AFTER (i64 BE, Unix seconds)
//!     65     8  ISSUED_AT (i64 BE, Unix seconds)
//! ```
//!
//! # Domain-tag distinctness
//!
//! | Structure | Domain tag | Length |
//! |-----------|-----------|--------|
//! | BindCert  | `b"SHP-BINDCERT"` | 12 |
//! | UGC       | `b"SHP-UGC\x00\x00\x00\x00"` | 11 |
//!
//! Different length AND different bytes: no signed blob can be confused for another.
//!
//! # Security
//!
//! The verifier verifies over the **received TBS slice**, never a re-encode. Unknown
//! `CAPS` bits are dropped by [`Capabilities::from_bits_truncate`] (reserved bits grant nothing).

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

use sh_crypto::{clock::Clock, CryptoError, DeviceIdentity, Keystore, Signature};

use crate::authz::Capabilities;

// ─── TBS constants ─────────────────────────────────────────────────────────

const DOMAIN_TAG: &[u8; 11] = b"SHP-UGC\x00\x00\x00\x00";
const TBS_VERSION: u8 = 0x01;
const FIELD_COUNT: u8 = 0x05;

/// Length of the UGC TBS in bytes (fixed, all fields are fixed-width).
pub const UGC_TBS_LEN: usize = 73;

/// `UGC_TBS_LEN` as a `u32` for lp32 serialisation (safe: 73 < u32::MAX).
// clippy allow: UGC_TBS_LEN = 73, well within u32::MAX; this cast never truncates.
#[allow(clippy::cast_possible_truncation)]
const UGC_TBS_LEN_U32: u32 = UGC_TBS_LEN as u32;

/// Total wire length of a serialised UGC: 4 (lp32) + 73 (TBS) + 64 (sig).
pub const UGC_WIRE_LEN: usize = 4 + UGC_TBS_LEN + 64;

/// Clock skew tolerance applied to `ISSUED_AT` validation (5 minutes, same as BindCert).
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 300;

// Field offsets within the TBS
const OFF_DOMAIN_TAG: usize = 0;
const OFF_TBS_VERSION: usize = 11;
const OFF_FIELD_COUNT: usize = 12;
const OFF_GRANTEE_DEVICE_ID: usize = 13;
const OFF_CAPS: usize = 45;
const OFF_EPOCH: usize = 49;
const OFF_NOT_AFTER: usize = 57;
const OFF_ISSUED_AT: usize = 65;

/// A parsed Unattended Grant Certificate (ADR-0010 §2).
///
/// Constructed by [`Ugc::encode`] (host-side issuance) or by decoding wire bytes with
/// [`Ugc::decode`] followed by [`Ugc::verify`]. Do not construct directly — always go
/// through `decode` + `verify` to ensure all five ordered checks pass.
///
/// # Examples
///
/// See [`Ugc::encode`] and [`Ugc::verify`].
#[derive(Debug, Clone)]
pub struct Ugc {
    /// The raw TBS bytes as received (NOT re-encoded). Used for signature verification.
    tbs_bytes: [u8; UGC_TBS_LEN],
    /// The Ed25519 signature over `tbs_bytes`.
    signature: Signature,
    /// Parsed fields extracted from `tbs_bytes`.
    fields: UgcFields,
}

/// Parsed fields extracted from the UGC TBS.
#[derive(Debug, Clone)]
struct UgcFields {
    grantee_device_id: [u8; 32],
    caps_raw: u32,
    epoch: u64,
    not_after: i64,
    issued_at: i64,
}

impl Ugc {
    /// Encodes and signs a new UGC using the host keystore.
    ///
    /// The TBS is constructed canonically per ADR-0010 §2.1 and signed via
    /// `keystore.sign()` (Ed25519, `verify_strict`-compatible).
    ///
    /// The `GRANTEE_DEVICE_ID` field in the TBS is computed as `SHA-256(grantee.public_key_bytes())`
    /// internally, matching exactly what [`Ugc::verify`] recomputes. Callers supply the
    /// [`DeviceIdentity`] directly so it is impossible to pass a raw public key where the
    /// digest is expected (which would always produce `UgcWrongGrantee` on verify with no
    /// issuance-time diagnostic).
    ///
    /// # Arguments
    ///
    /// - `keystore` — the **host** keystore that will sign the UGC.
    /// - `grantee` — the grantee's [`DeviceIdentity`]; the SHA-256 digest of its Ed25519
    ///   public key bytes is computed here and embedded in the TBS.
    /// - `caps` — the capabilities to grant.
    /// - `epoch` — the revocation epoch for this UGC.
    /// - `not_after` — Unix-epoch-seconds expiry (must be > `issued_at`).
    /// - `clock` — injected clock; `issued_at` is `clock.now_unix_secs()`.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::MalformedUgc`] if `not_after <= issued_at`.
    /// - [`CryptoError::Backend`] if the keystore signing operation fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn encode<K: Keystore>(
        keystore: &K,
        grantee: &DeviceIdentity,
        caps: Capabilities,
        epoch: u64,
        not_after: i64,
        clock: &dyn Clock,
    ) -> Result<Self, CryptoError> {
        let issued_at = clock.now_unix_secs();
        if not_after <= issued_at {
            return Err(CryptoError::MalformedUgc {
                reason: "not_after must be strictly greater than issued_at",
            });
        }

        // Compute the grantee device ID the same way verify() does, so
        // encode/verify are always consistent and the wrong-bytes mistake is impossible.
        let grantee_device_id: [u8; 32] = Sha256::digest(grantee.public_key_bytes()).into();

        let tbs_bytes = build_tbs(&grantee_device_id, caps.bits(), epoch, not_after, issued_at);
        let signature = keystore.sign(&tbs_bytes).await?;

        Ok(Self {
            tbs_bytes,
            signature,
            fields: UgcFields {
                grantee_device_id,
                caps_raw: caps.bits(),
                epoch,
                not_after,
                issued_at,
            },
        })
    }

    /// Decodes a UGC from untrusted wire bytes (check 1 of 5).
    ///
    /// Performs structural validation only. Call [`verify`](Self::verify) afterward to
    /// complete checks 2–5.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MalformedUgc`] for any structural problem:
    /// - Input length ≠ [`UGC_WIRE_LEN`] (141 bytes)
    /// - `lp32` ≠ [`UGC_TBS_LEN`] (73)
    /// - `DOMAIN_TAG` mismatch
    /// - `TBS_VERSION` ≠ 0x01
    /// - `FIELD_COUNT` ≠ 0x05
    /// - `NOT_AFTER <= ISSUED_AT`
    /// - Signature bytes wrong length
    ///
    /// # Panics
    ///
    /// Never panics. All arithmetic is bounds-checked.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_core::authz::Ugc;
    ///
    /// // Truncated input → typed error, no panic.
    /// assert!(Ugc::decode(&[]).is_err());
    /// assert!(Ugc::decode(&[0u8; 10]).is_err());
    /// ```
    pub fn decode(wire: &[u8]) -> Result<Self, CryptoError> {
        // The UGC wire format is fixed-size: 4 + 73 + 64 = 141 bytes exactly.
        if wire.len() != UGC_WIRE_LEN {
            return Err(CryptoError::MalformedUgc {
                reason: "UGC wire length must be exactly 141 bytes (4+73+64)",
            });
        }

        // Parse the lp32 prefix.
        let tbs_len_prefix: [u8; 4] =
            wire.get(..4)
                .and_then(|s| s.try_into().ok())
                .ok_or(CryptoError::MalformedUgc {
                    reason: "lp32 prefix conversion failed",
                })?;
        let tbs_len = u32::from_be_bytes(tbs_len_prefix) as usize;
        if tbs_len != UGC_TBS_LEN {
            return Err(CryptoError::MalformedUgc {
                reason: "lp32 length must be exactly 73 (UGC_TBS_LEN)",
            });
        }

        // Extract TBS bytes.
        let tbs_slice = wire
            .get(4..4 + UGC_TBS_LEN)
            .ok_or(CryptoError::MalformedUgc {
                reason: "wire too short for TBS",
            })?;
        let tbs_bytes: [u8; UGC_TBS_LEN] =
            tbs_slice
                .try_into()
                .map_err(|_| CryptoError::MalformedUgc {
                    reason: "TBS slice conversion failed",
                })?;

        // Extract signature bytes (last 64 bytes).
        let sig_bytes = wire
            .get(4 + UGC_TBS_LEN..)
            .ok_or(CryptoError::MalformedUgc {
                reason: "wire too short for signature",
            })?;
        let signature = Signature::decode(sig_bytes).map_err(|_| CryptoError::MalformedUgc {
            reason: "signature bytes must be exactly 64 bytes",
        })?;

        // Validate DOMAIN_TAG (bytes 0..11).
        let tag = tbs_bytes.get(OFF_DOMAIN_TAG..OFF_DOMAIN_TAG + 11).ok_or(
            CryptoError::MalformedUgc {
                reason: "TBS too short for domain tag",
            },
        )?;
        if tag != DOMAIN_TAG.as_slice() {
            return Err(CryptoError::MalformedUgc {
                reason: "domain tag mismatch",
            });
        }

        // Validate TBS_VERSION.
        let version = tbs_bytes
            .get(OFF_TBS_VERSION)
            .copied()
            .ok_or(CryptoError::MalformedUgc {
                reason: "TBS too short for version byte",
            })?;
        if version != TBS_VERSION {
            return Err(CryptoError::MalformedUgc {
                reason: "unsupported TBS version",
            });
        }

        // Validate FIELD_COUNT.
        let field_count =
            tbs_bytes
                .get(OFF_FIELD_COUNT)
                .copied()
                .ok_or(CryptoError::MalformedUgc {
                    reason: "TBS too short for field count",
                })?;
        if field_count != FIELD_COUNT {
            return Err(CryptoError::MalformedUgc {
                reason: "field count mismatch",
            });
        }

        // Extract GRANTEE_DEVICE_ID (32 bytes at offset 13).
        let mut grantee_device_id = [0u8; 32];
        let gdi_slice = tbs_bytes
            .get(OFF_GRANTEE_DEVICE_ID..OFF_GRANTEE_DEVICE_ID + 32)
            .ok_or(CryptoError::MalformedUgc {
                reason: "TBS too short for GRANTEE_DEVICE_ID",
            })?;
        grantee_device_id.copy_from_slice(gdi_slice);

        // Extract CAPS (u32 BE at offset 45).
        let caps_arr: [u8; 4] = tbs_bytes
            .get(OFF_CAPS..OFF_CAPS + 4)
            .ok_or(CryptoError::MalformedUgc {
                reason: "TBS too short for CAPS",
            })?
            .try_into()
            .map_err(|_| CryptoError::MalformedUgc {
                reason: "CAPS slice conversion failed",
            })?;
        let caps_raw = u32::from_be_bytes(caps_arr);

        // Extract EPOCH (u64 BE at offset 49).
        let epoch_arr: [u8; 8] = tbs_bytes
            .get(OFF_EPOCH..OFF_EPOCH + 8)
            .ok_or(CryptoError::MalformedUgc {
                reason: "TBS too short for EPOCH",
            })?
            .try_into()
            .map_err(|_| CryptoError::MalformedUgc {
                reason: "EPOCH slice conversion failed",
            })?;
        let epoch = u64::from_be_bytes(epoch_arr);

        // Extract NOT_AFTER (i64 BE at offset 57).
        let na_arr: [u8; 8] = tbs_bytes
            .get(OFF_NOT_AFTER..OFF_NOT_AFTER + 8)
            .ok_or(CryptoError::MalformedUgc {
                reason: "TBS too short for NOT_AFTER",
            })?
            .try_into()
            .map_err(|_| CryptoError::MalformedUgc {
                reason: "NOT_AFTER slice conversion failed",
            })?;
        let not_after = i64::from_be_bytes(na_arr);

        // Extract ISSUED_AT (i64 BE at offset 65).
        let ia_arr: [u8; 8] = tbs_bytes
            .get(OFF_ISSUED_AT..OFF_ISSUED_AT + 8)
            .ok_or(CryptoError::MalformedUgc {
                reason: "TBS too short for ISSUED_AT",
            })?
            .try_into()
            .map_err(|_| CryptoError::MalformedUgc {
                reason: "ISSUED_AT slice conversion failed",
            })?;
        let issued_at = i64::from_be_bytes(ia_arr);

        // Structural check: NOT_AFTER must be > ISSUED_AT.
        if not_after <= issued_at {
            return Err(CryptoError::MalformedUgc {
                reason: "NOT_AFTER must be strictly greater than ISSUED_AT",
            });
        }

        Ok(Self {
            tbs_bytes,
            signature,
            fields: UgcFields {
                grantee_device_id,
                caps_raw,
                epoch,
                not_after,
                issued_at,
            },
        })
    }

    /// Encodes this UGC to its wire form (`lp32(TBS) || SIGNATURE`, 141 bytes).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // See Ugc::encode for a full example.
    /// ```
    pub fn wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(UGC_WIRE_LEN);
        out.extend_from_slice(&UGC_TBS_LEN_U32.to_be_bytes());
        out.extend_from_slice(&self.tbs_bytes);
        out.extend_from_slice(&self.signature.encode());
        out
    }

    /// Verifies this UGC against the host identity, authenticated peer identity, epoch floor,
    /// and clock (checks 2–5 of the 5-check process, ADR-0010 §2.4).
    ///
    /// # Checks performed (in order)
    ///
    /// 2. **Signature** — Ed25519 `verify_strict` over the exact received TBS bytes against
    ///    the pinned `host_identity`. Fails → [`CryptoError::UgcBadSignature`].
    /// 3. **Grantee binding (constant-time)** — `GRANTEE_DEVICE_ID` must byte-equal the
    ///    SHA-256 fingerprint digest of `grantee_peer_identity`. Mismatch →
    ///    [`CryptoError::UgcWrongGrantee`]. This defeats stolen-UGC replay.
    /// 4. **Expiry** — `NOT_AFTER > now` and `ISSUED_AT ≤ now + skew_tolerance`. Fails →
    ///    [`CryptoError::UgcExpired`].
    /// 5. **Epoch floor** — `EPOCH >= min_epoch`. Fails → [`CryptoError::UgcRevoked`].
    ///
    /// On success returns the masked [`Capabilities`] (`from_bits_truncate(CAPS)`).
    ///
    /// # Arguments
    ///
    /// - `host_identity` — the pinned host [`DeviceIdentity`] (the trust root).
    /// - `grantee_peer_identity` — the **authenticated Noise `peer_identity`** from
    ///   `HandshakeOutcome`, ADR-0007. MUST NOT be a peer-asserted identity.
    /// - `min_epoch` — the current epoch floor from [`MinEpochStore::current`].
    /// - `clock` — injected clock for expiry checks.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::UgcBadSignature`] — signature invalid
    /// - [`CryptoError::UgcWrongGrantee`] — grantee mismatch
    /// - [`CryptoError::UgcExpired`] — expired or not yet valid
    /// - [`CryptoError::UgcRevoked`] — epoch < min_epoch
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn verify(
        &self,
        host_identity: &DeviceIdentity,
        grantee_peer_identity: &DeviceIdentity,
        min_epoch: u64,
        clock: &dyn Clock,
    ) -> Result<Capabilities, CryptoError> {
        // Check 2: Signature over the RECEIVED TBS bytes (never re-encode).
        self.signature
            .verify(host_identity, &self.tbs_bytes)
            .map_err(|_| CryptoError::UgcBadSignature)?;

        // Check 3: Grantee binding — constant-time comparison against SHA-256 of peer pubkey.
        // We compare the 32-byte raw digest stored in the TBS against the SHA-256 of
        // the grantee's Ed25519 public key bytes. This is the crux of stolen-UGC defense.
        let grantee_pubkey_digest: [u8; 32] =
            Sha256::digest(grantee_peer_identity.public_key_bytes()).into();
        // Constant-time comparison via subtle — avoids timing side-channel on the comparison.
        if self
            .fields
            .grantee_device_id
            .ct_eq(&grantee_pubkey_digest)
            .unwrap_u8()
            == 0
        {
            return Err(CryptoError::UgcWrongGrantee);
        }

        // Check 4: Expiry — against the injected clock (NO SystemTime::now).
        //
        // The same CLOCK_SKEW_TOLERANCE_SECS is applied symmetrically to both edges:
        //   - not_after: a verifier whose clock runs fast is given CLOCK_SKEW_TOLERANCE_SECS
        //     of grace before declaring the UGC expired, matching the tolerance on issued_at.
        //   - issued_at: a verifier whose clock runs slow accepts a UGC issued up to
        //     CLOCK_SKEW_TOLERANCE_SECS in the "future" (normal pre-issuance skew).
        let now = clock.now_unix_secs();
        // not_after check: expired if even the skew-adjusted not_after is in the past.
        if self
            .fields
            .not_after
            .saturating_add(CLOCK_SKEW_TOLERANCE_SECS)
            <= now
        {
            return Err(CryptoError::UgcExpired);
        }
        // issued_at check: reject UGCs with an issued_at too far in the future.
        let skew_adjusted_now = now.saturating_add(CLOCK_SKEW_TOLERANCE_SECS);
        if self.fields.issued_at > skew_adjusted_now {
            return Err(CryptoError::UgcExpired);
        }

        // Check 5: Epoch floor (offline revocation).
        if self.fields.epoch < min_epoch {
            return Err(CryptoError::UgcRevoked);
        }

        // All checks passed. Mask unknown bits before returning.
        Ok(Capabilities::from_bits_truncate(self.fields.caps_raw))
    }

    /// Returns the raw `GRANTEE_DEVICE_ID` field (32-byte SHA-256 digest).
    pub fn grantee_device_id(&self) -> &[u8; 32] {
        &self.fields.grantee_device_id
    }

    /// Returns the `EPOCH` field.
    pub fn epoch(&self) -> u64 {
        self.fields.epoch
    }

    /// Returns the `NOT_AFTER` Unix timestamp.
    pub fn not_after(&self) -> i64 {
        self.fields.not_after
    }

    /// Returns the `ISSUED_AT` Unix timestamp.
    pub fn issued_at(&self) -> i64 {
        self.fields.issued_at
    }

    /// Returns the raw `CAPS` u32 field (before masking unknown bits).
    pub fn caps_raw(&self) -> u32 {
        self.fields.caps_raw
    }
}

/// Builds the canonical 73-byte UGC TBS.
fn build_tbs(
    grantee_device_id: &[u8; 32],
    caps_raw: u32,
    epoch: u64,
    not_after: i64,
    issued_at: i64,
) -> [u8; UGC_TBS_LEN] {
    let mut tbs = [0u8; UGC_TBS_LEN];
    tbs[OFF_DOMAIN_TAG..OFF_DOMAIN_TAG + 11].copy_from_slice(DOMAIN_TAG.as_slice());
    tbs[OFF_TBS_VERSION] = TBS_VERSION;
    tbs[OFF_FIELD_COUNT] = FIELD_COUNT;
    tbs[OFF_GRANTEE_DEVICE_ID..OFF_GRANTEE_DEVICE_ID + 32]
        .copy_from_slice(grantee_device_id.as_slice());
    tbs[OFF_CAPS..OFF_CAPS + 4].copy_from_slice(&caps_raw.to_be_bytes());
    tbs[OFF_EPOCH..OFF_EPOCH + 8].copy_from_slice(&epoch.to_be_bytes());
    tbs[OFF_NOT_AFTER..OFF_NOT_AFTER + 8].copy_from_slice(&not_after.to_be_bytes());
    tbs[OFF_ISSUED_AT..OFF_ISSUED_AT + 8].copy_from_slice(&issued_at.to_be_bytes());
    tbs
}

/// Exposed for conformance tests only.
///
/// Gated `#[cfg(test)]` to prevent downstream production callers from constructing
/// TBS bytes that bypass the `not_after > issued_at` guard enforced by [`Ugc::encode`].
#[cfg(test)]
pub fn build_tbs_for_test(
    grantee_device_id: &[u8; 32],
    caps_raw: u32,
    epoch: u64,
    not_after: i64,
    issued_at: i64,
) -> [u8; UGC_TBS_LEN] {
    build_tbs(grantee_device_id, caps_raw, epoch, not_after, issued_at)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use sh_crypto::{Keystore, SoftwareKeystore};
    use sh_types::FixedClock;

    /// Creates a test keystore from a seed.
    fn make_ks(seed: u64) -> SoftwareKeystore {
        use rand_core::SeedableRng;
        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
        SoftwareKeystore::generate_with_rng(rng)
    }

    /// Makes a valid UGC with default parameters.
    async fn make_valid_ugc(host_ks: &SoftwareKeystore, grantee: &DeviceIdentity, now: i64) -> Ugc {
        let clock = FixedClock(now);
        Ugc::encode(
            host_ks,
            grantee,
            Capabilities::VIEW | Capabilities::CONTROL,
            /*epoch=*/ 1,
            /*not_after=*/ now + 3600,
            &clock,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn ugc_roundtrip() {
        let host_ks = make_ks(1);
        let grantee_ks = make_ks(2);
        let host_id = host_ks.device_identity().await.unwrap();
        let grantee_id_pub = grantee_ks.device_identity().await.unwrap();
        let now = 1_700_000_000_i64;
        let clock = FixedClock(now);

        let ugc = Ugc::encode(
            &host_ks,
            &grantee_id_pub,
            Capabilities::VIEW | Capabilities::CONTROL,
            1,
            now + 3600,
            &clock,
        )
        .await
        .unwrap();

        let wire = ugc.wire_bytes();
        assert_eq!(wire.len(), UGC_WIRE_LEN);

        let decoded = Ugc::decode(&wire).unwrap();
        let verify_clock = FixedClock(now + 10);
        let caps = decoded
            .verify(
                &host_id,
                &grantee_id_pub,
                /*min_epoch=*/ 0,
                &verify_clock,
            )
            .unwrap();
        assert_eq!(caps, Capabilities::VIEW | Capabilities::CONTROL);
    }

    #[tokio::test]
    async fn forged_ugc_wrong_signer_rejected() {
        let host_ks = make_ks(1);
        let attacker_ks = make_ks(99);
        let grantee_ks = make_ks(2);
        let host_id = host_ks.device_identity().await.unwrap();
        let grantee_id_pub = grantee_ks.device_identity().await.unwrap();
        let now = 1_700_000_000_i64;
        let clock = FixedClock(now);

        // Sign with attacker key, but verify against host
        let ugc = Ugc::encode(
            &attacker_ks,
            &grantee_id_pub,
            Capabilities::VIEW,
            1,
            now + 3600,
            &clock,
        )
        .await
        .unwrap();

        let wire = ugc.wire_bytes();
        let decoded = Ugc::decode(&wire).unwrap();
        let verify_clock = FixedClock(now + 10);
        let result = decoded.verify(&host_id, &grantee_id_pub, 0, &verify_clock);
        assert!(
            matches!(result, Err(CryptoError::UgcBadSignature)),
            "expected UgcBadSignature, got {result:?}"
        );
    }

    #[tokio::test]
    async fn tampered_ugc_flip_caps_rejected() {
        let host_ks = make_ks(1);
        let grantee_ks = make_ks(2);
        let host_id = host_ks.device_identity().await.unwrap();
        let grantee_id_pub = grantee_ks.device_identity().await.unwrap();
        let now = 1_700_000_000_i64;

        let ugc = make_valid_ugc(&host_ks, &grantee_id_pub, now).await;
        let mut wire = ugc.wire_bytes();
        // Flip a byte in CAPS field (offset 4 + 45 = 49 in wire)
        wire[4 + OFF_CAPS] ^= 0xFF;

        // After tampering, it may not even decode (NOT_AFTER <= ISSUED_AT could be hit),
        // but if it decodes, verify must fail signature.
        match Ugc::decode(&wire) {
            Err(_) => { /* structural rejection is also acceptable */ }
            Ok(decoded) => {
                let verify_clock = FixedClock(now + 10);
                let result = decoded.verify(&host_id, &grantee_id_pub, 0, &verify_clock);
                assert!(
                    matches!(result, Err(CryptoError::UgcBadSignature)),
                    "tampered caps must fail signature: {result:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn tampered_ugc_flip_epoch_rejected() {
        let host_ks = make_ks(1);
        let grantee_ks = make_ks(2);
        let host_id = host_ks.device_identity().await.unwrap();
        let grantee_id_pub = grantee_ks.device_identity().await.unwrap();
        let now = 1_700_000_000_i64;

        let ugc = make_valid_ugc(&host_ks, &grantee_id_pub, now).await;
        let mut wire = ugc.wire_bytes();
        // Flip a byte in EPOCH field (offset 4 + 49)
        wire[4 + OFF_EPOCH] ^= 0x01;

        let decoded = Ugc::decode(&wire).unwrap();
        let verify_clock = FixedClock(now + 10);
        let result = decoded.verify(&host_id, &grantee_id_pub, 0, &verify_clock);
        assert!(
            matches!(result, Err(CryptoError::UgcBadSignature)),
            "tampered epoch must fail signature: {result:?}"
        );
    }

    #[tokio::test]
    async fn tampered_ugc_flip_grantee_id_rejected() {
        let host_ks = make_ks(1);
        let grantee_ks = make_ks(2);
        let host_id = host_ks.device_identity().await.unwrap();
        let grantee_id_pub = grantee_ks.device_identity().await.unwrap();
        let now = 1_700_000_000_i64;

        let ugc = make_valid_ugc(&host_ks, &grantee_id_pub, now).await;
        let mut wire = ugc.wire_bytes();
        // Flip a byte in GRANTEE_DEVICE_ID (offset 4 + 13)
        wire[4 + OFF_GRANTEE_DEVICE_ID] ^= 0xFF;

        let decoded = Ugc::decode(&wire).unwrap();
        let verify_clock = FixedClock(now + 10);
        let result = decoded.verify(&host_id, &grantee_id_pub, 0, &verify_clock);
        assert!(
            matches!(result, Err(CryptoError::UgcBadSignature)),
            "tampered grantee_id must fail signature: {result:?}"
        );
    }

    #[tokio::test]
    async fn wrong_grantee_rejected() {
        let host_ks = make_ks(1);
        let grantee_ks = make_ks(2);
        let wrong_grantee_ks = make_ks(3);
        let host_id = host_ks.device_identity().await.unwrap();
        let grantee_id_pub = grantee_ks.device_identity().await.unwrap();
        let wrong_grantee_id_pub = wrong_grantee_ks.device_identity().await.unwrap();
        let now = 1_700_000_000_i64;

        let ugc = make_valid_ugc(&host_ks, &grantee_id_pub, now).await;
        let wire = ugc.wire_bytes();
        let decoded = Ugc::decode(&wire).unwrap();

        // Verify with wrong peer identity
        let verify_clock = FixedClock(now + 10);
        let result = decoded.verify(&host_id, &wrong_grantee_id_pub, 0, &verify_clock);
        assert!(
            matches!(result, Err(CryptoError::UgcWrongGrantee)),
            "wrong grantee must be rejected: {result:?}"
        );
    }

    #[tokio::test]
    async fn expired_ugc_rejected() {
        let host_ks = make_ks(1);
        let grantee_ks = make_ks(2);
        let host_id = host_ks.device_identity().await.unwrap();
        let grantee_id_pub = grantee_ks.device_identity().await.unwrap();
        let issued_at = 1_700_000_000_i64;
        let not_after = issued_at + 3600;

        let ugc = make_valid_ugc(&host_ks, &grantee_id_pub, issued_at).await;
        let wire = ugc.wire_bytes();
        let decoded = Ugc::decode(&wire).unwrap();

        // With symmetric skew tolerance, the UGC is considered expired when:
        //   not_after + CLOCK_SKEW_TOLERANCE_SECS <= now
        // i.e., at now == not_after + CLOCK_SKEW_TOLERANCE_SECS.

        // One second before the tolerance boundary → still valid (fast-clock grace).
        let just_before_clock = FixedClock(not_after + CLOCK_SKEW_TOLERANCE_SECS - 1);
        let result_before = decoded.verify(&host_id, &grantee_id_pub, 0, &just_before_clock);
        assert!(
            result_before.is_ok(),
            "UGC within skew tolerance of not_after must still be valid: {result_before:?}"
        );

        // At the tolerance boundary (not_after + CLOCK_SKEW_TOLERANCE_SECS) → expired.
        // Guards the `<=` in `not_after.saturating_add(skew) <= now`.
        let at_boundary_clock = FixedClock(not_after + CLOCK_SKEW_TOLERANCE_SECS);
        let result_boundary = decoded.verify(&host_id, &grantee_id_pub, 0, &at_boundary_clock);
        assert!(
            matches!(result_boundary, Err(CryptoError::UgcExpired)),
            "UGC at not_after + skew boundary must be expired: {result_boundary:?}"
        );

        // Well past not_after → also expired.
        let verify_clock = FixedClock(not_after + CLOCK_SKEW_TOLERANCE_SECS + 3600);
        let result = decoded.verify(&host_id, &grantee_id_pub, 0, &verify_clock);
        assert!(
            matches!(result, Err(CryptoError::UgcExpired)),
            "expired UGC must be rejected: {result:?}"
        );
    }

    #[tokio::test]
    async fn backdated_ugc_rejected() {
        let host_ks = make_ks(1);
        let grantee_ks = make_ks(2);
        let host_id = host_ks.device_identity().await.unwrap();
        let grantee_id_pub = grantee_ks.device_identity().await.unwrap();
        // issued_at is far in the future relative to our "now"
        let future_time = 2_000_000_000_i64;

        let ugc = make_valid_ugc(&host_ks, &grantee_id_pub, future_time).await;
        let wire = ugc.wire_bytes();
        let decoded = Ugc::decode(&wire).unwrap();

        // Verify at a time that makes issued_at > now + CLOCK_SKEW_TOLERANCE_SECS
        let verify_clock = FixedClock(future_time - CLOCK_SKEW_TOLERANCE_SECS - 1);
        let result = decoded.verify(&host_id, &grantee_id_pub, 0, &verify_clock);
        assert!(
            matches!(result, Err(CryptoError::UgcExpired)),
            "backdated UGC must be rejected: {result:?}"
        );
    }

    #[tokio::test]
    async fn epoch_below_min_floor_revoked() {
        let host_ks = make_ks(1);
        let grantee_ks = make_ks(2);
        let host_id = host_ks.device_identity().await.unwrap();
        let grantee_id_pub = grantee_ks.device_identity().await.unwrap();
        let now = 1_700_000_000_i64;
        let clock = FixedClock(now);

        let ugc = Ugc::encode(
            &host_ks,
            &grantee_id_pub,
            Capabilities::VIEW,
            /*epoch=*/ 5,
            now + 3600,
            &clock,
        )
        .await
        .unwrap();

        let wire = ugc.wire_bytes();
        let decoded = Ugc::decode(&wire).unwrap();
        let verify_clock = FixedClock(now + 10);

        // min_epoch = 6 > epoch = 5 → revoked
        let result = decoded.verify(
            &host_id,
            &grantee_id_pub,
            /*min_epoch=*/ 6,
            &verify_clock,
        );
        assert!(
            matches!(result, Err(CryptoError::UgcRevoked)),
            "epoch below floor must be revoked: {result:?}"
        );

        // min_epoch = 5 == epoch = 5 → valid
        let result_ok = decoded.verify(
            &host_id,
            &grantee_id_pub,
            /*min_epoch=*/ 5,
            &verify_clock,
        );
        assert!(
            result_ok.is_ok(),
            "epoch == floor must be accepted: {result_ok:?}"
        );
    }

    #[tokio::test]
    async fn reserved_caps_bits_truncated() {
        let host_ks = make_ks(1);
        let grantee_ks = make_ks(2);
        let host_id = host_ks.device_identity().await.unwrap();
        let grantee_id_pub = grantee_ks.device_identity().await.unwrap();
        let now = 1_700_000_000_i64;

        // Build TBS with all-bits-set caps (u32::MAX); compute grantee_device_id the same
        // way encode() does so verify() matches.
        let grantee_device_id: [u8; 32] = Sha256::digest(grantee_id_pub.public_key_bytes()).into();
        let tbs = build_tbs_for_test(&grantee_device_id, u32::MAX, 1, now + 3600, now);
        let sig = host_ks.sign(&tbs).await.unwrap();
        let mut wire = Vec::with_capacity(UGC_WIRE_LEN);
        wire.extend_from_slice(&UGC_TBS_LEN_U32.to_be_bytes());
        wire.extend_from_slice(&tbs);
        wire.extend_from_slice(&sig.encode());

        let decoded = Ugc::decode(&wire).unwrap();
        assert_eq!(decoded.caps_raw(), u32::MAX);

        let verify_clock = FixedClock(now + 10);
        let caps = decoded
            .verify(&host_id, &grantee_id_pub, 0, &verify_clock)
            .unwrap();
        // Unknown bits must be dropped; only the 6 known bits survive
        assert_eq!(caps, Capabilities::all());
        assert!(!caps.is_empty());
        // Bits 6+ must not appear
        let known_mask = Capabilities::all().bits();
        assert_eq!(caps.bits() & !known_mask, 0);
    }

    #[test]
    fn domain_tag_not_confusable_with_bindcert() {
        // BindCert domain tag from bind_cert.rs: b"SHP-BINDCERT" (12 bytes)
        let bindcert_tag = b"SHP-BINDCERT";
        let ugc_tag = DOMAIN_TAG;
        // Different length
        assert_ne!(bindcert_tag.len(), ugc_tag.len());
        // Different bytes (first 7 are same "SHP-UGC" vs "SHP-BIND")
        // UGC tag is 11 bytes, BindCert is 12 — no prefix confusion possible at different lengths
        assert_ne!(bindcert_tag.as_slice(), ugc_tag.as_slice());
    }

    #[test]
    fn golden_tbs_vector() {
        // Verifies the exact byte layout of the TBS encoding.
        let grantee_id = [0xAB_u8; 32];
        let caps_raw: u32 = 0x0000_0003; // VIEW | CONTROL
        let epoch: u64 = 42;
        let not_after: i64 = 1_700_003_600;
        let issued_at: i64 = 1_700_000_000;

        let tbs = build_tbs_for_test(&grantee_id, caps_raw, epoch, not_after, issued_at);
        assert_eq!(tbs.len(), UGC_TBS_LEN);

        // DOMAIN_TAG (bytes 0..11)
        assert_eq!(&tbs[0..11], DOMAIN_TAG.as_slice());
        // TBS_VERSION (byte 11)
        assert_eq!(tbs[11], 0x01);
        // FIELD_COUNT (byte 12)
        assert_eq!(tbs[12], 0x05);
        // GRANTEE_DEVICE_ID (bytes 13..45)
        assert_eq!(&tbs[13..45], &[0xABu8; 32]);
        // CAPS (bytes 45..49, u32 BE)
        assert_eq!(&tbs[45..49], &[0x00, 0x00, 0x00, 0x03]);
        // EPOCH (bytes 49..57, u64 BE)
        assert_eq!(&tbs[49..57], &42_u64.to_be_bytes());
        // NOT_AFTER (bytes 57..65, i64 BE)
        assert_eq!(&tbs[57..65], &1_700_003_600_i64.to_be_bytes());
        // ISSUED_AT (bytes 65..73, i64 BE)
        assert_eq!(&tbs[65..73], &1_700_000_000_i64.to_be_bytes());
    }

    #[test]
    fn truncated_decode_never_panics() {
        // Any prefix of a valid-looking wire buffer must not panic.
        let base = [0u8; UGC_WIRE_LEN];
        for len in 0..=UGC_WIRE_LEN + 10 {
            let slice = if len <= UGC_WIRE_LEN {
                &base[..len]
            } else {
                base.as_slice()
            };
            let _ = Ugc::decode(slice);
        }
    }

    #[tokio::test]
    async fn bump_min_epoch_revokes_previously_valid_ugc() {
        use crate::authz::{InMemoryMinEpochStore, MinEpochStore};

        let host_ks = make_ks(1);
        let grantee_ks = make_ks(2);
        let host_id = host_ks.device_identity().await.unwrap();
        let grantee_id_pub = grantee_ks.device_identity().await.unwrap();
        let now = 1_700_000_000_i64;
        let clock = FixedClock(now);

        let store = InMemoryMinEpochStore::new(0);
        let ugc = Ugc::encode(
            &host_ks,
            &grantee_id_pub,
            Capabilities::VIEW,
            /*epoch=*/ 1,
            now + 3600,
            &clock,
        )
        .await
        .unwrap();

        let wire = ugc.wire_bytes();
        let decoded = Ugc::decode(&wire).unwrap();
        let verify_clock = FixedClock(now + 10);

        // Initially valid
        let result = decoded.verify(&host_id, &grantee_id_pub, store.current(), &verify_clock);
        assert!(result.is_ok(), "should be valid initially: {result:?}");

        // Bump past epoch 1
        store.bump(2);
        let result_revoked =
            decoded.verify(&host_id, &grantee_id_pub, store.current(), &verify_clock);
        assert!(
            matches!(result_revoked, Err(CryptoError::UgcRevoked)),
            "should be revoked after bump: {result_revoked:?}"
        );
    }
}
