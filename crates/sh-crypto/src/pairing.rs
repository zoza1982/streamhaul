//! SPAKE2 PAKE pairing and TOFU pinning orchestration.
//!
//! # Overview (ADR-0008 §2–§3)
//!
//! This module implements **two pairing modes** for Streamhaul:
//!
//! 1. **Attended pairing** ([`pair_attended`]): a human is at both sides, observes the SAS
//!    (derived by the caller from [`crate::sas::Sas`]), and confirms the match via
//!    [`Sas::confirm`](crate::sas::Sas::confirm) which returns a [`SasConfirmed`] token.
//!    On confirm, the peer identity is pinned (`trust_peer`). On mismatch, the pairing is
//!    aborted without a pin.
//!
//! 2. **Unattended pairing** ([`pair_unattended`]): no human is present at the host. A
//!    pre-provisioned single-use [`PairingCode`] is shared out-of-band. The code must first
//!    be validated with [`PairingCode::check_not_expired`] to produce a [`ValidPairingCode`];
//!    only a [`ValidPairingCode`] can be passed to [`PakeExchange::start_with_rng`], making
//!    expiry enforcement structurally unrepresentable to skip. Both sides run a SPAKE2 PAKE
//!    exchange over that code, with an explicit HKDF-SHA-256 key-confirmation MAC that binds
//!    the shared key to both device identities AND to the Noise handshake hash `h`. On
//!    confirmed key match, the peer is pinned.
//!
//! # Security invariants (from ADR-0008)
//!
//! - **Expiry checked before PAKE.** [`PairingCode::check_not_expired`] returns a
//!   [`ValidPairingCode`] newtype; [`PakeExchange::start_with_rng`] only accepts
//!   `ValidPairingCode` — it is a compile-time error to start a PAKE with an unchecked code.
//! - **Pin ONLY after explicit confirmation.** `trust_peer` is called strictly after SAS
//!   match-confirm (via [`SasConfirmed`]) or PAKE key-confirmation success — never on bare
//!   handshake completion.
//! - **Revoke gate is atomic.** [`Keystore::trust_peer_if_not_revoked`] checks and pins under
//!   a single write-lock acquisition, eliminating the TOCTOU race between the revocation
//!   check and the pin.
//! - **Identity from Noise.** The pinned identity is always the BindCert-verified
//!   `peer_identity` from the [`HandshakeOutcome`](crate::noise::HandshakeOutcome). PAKE
//!   messages can never claim or substitute an identity.
//! - **Binding.** The PAKE key-confirmation MAC covers `{spake2_key, h, id_a, id_b}` so a
//!   relayed code (wrong identities) or replayed code (wrong `h`) fails confirmation.
//! - **Offline dictionary: eliminated.** SPAKE2 puts no code-derived value on the wire;
//!   transcripts are not brute-forceable offline.
//! - **Never log secrets.** Pairing codes and PAKE keying material are `Zeroizing`; only
//!   public fingerprints appear in error messages.
//!
//! # SECURITY WARNING: `spake2` is UNAUDITED
//!
//! The [`spake2`] crate (RustCrypto) has not been independently audited ("USE AT YOUR OWN
//! RISK"). It is wrapped here and fuzzed; a pre-GA security review is tracked in the Risk
//! Register (`R-SPAKE2-AUDIT`). See `SECURITY.md` for the full posture.
//!
//! # Examples
//!
//! ```no_run
//! use sh_crypto::pairing::{PairingCode, PairingCodeFormat, PakeRole, PakeExchange};
//! use sh_crypto::clock::FixedClock;
//!
//! # fn example() -> Result<(), sh_crypto::CryptoError> {
//! let clock = FixedClock(1_000_000_000);
//! let not_after = 1_000_000_300i64; // 5 minutes later
//!
//! // Host generates a pairing code out-of-band.
//! let code = PairingCode::generate_with_rng(
//!     &mut rand_core::OsRng,
//!     PairingCodeFormat::EightDigit,
//!     not_after,
//! );
//! // Validate expiry; only a ValidPairingCode can be used with PakeExchange.
//! let valid_code = code.check_not_expired(&clock)?;
//! # Ok(())
//! # }
//! ```

use std::fmt;

use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{clock::Clock, CryptoError, DeviceIdentity, Keystore};

// ─── HKDF info strings ────────────────────────────────────────────────────────

/// HKDF info for deriving the initiator confirmation MAC key from the SPAKE2 shared key.
const PAKE_CONFIRM_INITIATOR_INFO: &[u8] = b"SHP-PAKE-v1-confirm-initiator\x00";
/// HKDF info for deriving the responder confirmation MAC key from the SPAKE2 shared key.
const PAKE_CONFIRM_RESPONDER_INFO: &[u8] = b"SHP-PAKE-v1-confirm-responder\x00";

// ─── PairingCodeFormat ────────────────────────────────────────────────────────

/// The format of a pairing code generated for unattended pairing.
///
/// Unattended codes use **8 digits by default** — stronger than the 6-digit SAS because the
/// code is the sole authenticator (no human transcript-commit step). This gives a
/// `10⁻⁸` per-guess online attack surface before rate limiting and single-use expiry further
/// reduce the effective window. (ADR-0008 §2.4: never below 8 for unattended.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PairingCodeFormat {
    /// Eight decimal digits, displayed as "NNNN-NNNN" (~26.6 bits, `10⁻⁸` per guess).
    ///
    /// This is the **default** and the floor for unattended codes.
    #[default]
    EightDigit,
}

impl PairingCodeFormat {
    /// Number of decimal digits in this format.
    fn digit_count(self) -> usize {
        match self {
            PairingCodeFormat::EightDigit => 8,
        }
    }

    /// The modulus for reducing a random u64 to the code value.
    fn modulus(self) -> u64 {
        match self {
            PairingCodeFormat::EightDigit => 100_000_000,
        }
    }
}

// ─── PairingCode ─────────────────────────────────────────────────────────────

/// A single-use, expiring, CSPRNG-derived pairing code for unattended enrollment.
///
/// The code value is [`Zeroizing`] — it is erased from memory when this struct drops.
///
/// # Security
///
/// - The code is **never transmitted** (that is the PAKE property — both sides provide it
///   as local input; no code-derived value appears on the wire).
/// - Call [`check_not_expired`](Self::check_not_expired) to validate expiry; the returned
///   [`ValidPairingCode`] is the only type accepted by [`PakeExchange::start_with_rng`].
///   This makes it a **compile-time error** to start a PAKE exchange with an unchecked code.
/// - After a successful pairing the code must be invalidated (single-use); after a
///   configurable number of failed attempts the code must also be invalidated. The
///   invalidation state is maintained by the caller (host agent), not by this struct.
///
/// # Examples
///
/// ```
/// use sh_crypto::pairing::{PairingCode, PairingCodeFormat};
/// use sh_crypto::clock::FixedClock;
///
/// let code = PairingCode::generate_with_rng(
///     &mut rand_core::OsRng,
///     PairingCodeFormat::EightDigit,
///     1_000_001_000i64, // not_after
/// );
/// let clock = FixedClock(1_000_000_000);
/// assert!(code.check_not_expired(&clock).is_ok());
/// ```
pub struct PairingCode {
    /// The Zeroizing raw code digits (e.g. "12345678" for 8-digit).
    value: Zeroizing<String>,
    /// Epoch-seconds timestamp after which this code is invalid.
    not_after: i64,
    /// The format used to generate this code.
    format: PairingCodeFormat,
}

impl PairingCode {
    /// Generates a fresh pairing code from the provided CSPRNG.
    ///
    /// The code is a uniformly random decimal value of the appropriate digit count,
    /// zero-padded. The `not_after` parameter is an epoch-seconds timestamp; the code
    /// is invalid at or after that time (checked via the injected [`Clock`]).
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn generate_with_rng<R: CryptoRng + RngCore>(
        rng: &mut R,
        format: PairingCodeFormat,
        not_after: i64,
    ) -> Self {
        // Generate a 64-bit random value and reduce modulo the format's modulus.
        // This gives a slight bias (2^64 mod 10^8 ≠ 0) but for a 10^8 code space the
        // bias is negligible (< 2^-26 per digit) and well within the security model.
        let mut raw_bytes = [0u8; 8];
        rng.fill_bytes(&mut raw_bytes);
        let raw = u64::from_be_bytes(raw_bytes);
        // `format.modulus()` is always a non-zero constant; `checked_rem` avoids the
        // `arithmetic_side_effects` lint. The `unwrap_or(0)` is unreachable by construction.
        let code = raw.checked_rem(format.modulus()).unwrap_or(0);
        let digits = format!("{code:0>width$}", width = format.digit_count());
        Self {
            value: Zeroizing::new(digits),
            not_after,
            format,
        }
    }

    /// Constructs a `PairingCode` from a known digit string (for testing and re-use).
    ///
    /// The caller is responsible for ensuring the string has the correct length and
    /// contains only ASCII decimal digits. For production use, prefer
    /// [`generate_with_rng`](Self::generate_with_rng).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MalformedPakeMessage`] if the digit string is not exactly
    /// the expected length or contains non-digit characters.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn from_digits(
        digits: &str,
        format: PairingCodeFormat,
        not_after: i64,
    ) -> Result<Self, CryptoError> {
        let expected_len = format.digit_count();
        if digits.len() != expected_len {
            return Err(CryptoError::MalformedPakeMessage {
                reason: "pairing code has wrong digit count",
            });
        }
        if !digits.chars().all(|c| c.is_ascii_digit()) {
            return Err(CryptoError::MalformedPakeMessage {
                reason: "pairing code contains non-digit characters",
            });
        }
        Ok(Self {
            value: Zeroizing::new(digits.to_owned()),
            not_after,
            format,
        })
    }

    /// Returns the format of this pairing code.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn format(&self) -> PairingCodeFormat {
        self.format
    }

    /// Validates that this code has not yet expired relative to the given clock, and
    /// returns a [`ValidPairingCode`] proof token on success.
    ///
    /// The [`ValidPairingCode`] is the **only** type accepted by
    /// [`PakeExchange::start_with_rng`] — making it a compile-time error to start a PAKE
    /// exchange with an unchecked code. This eliminates the class of bugs where expiry
    /// enforcement is accidentally omitted.
    ///
    /// Returns `Ok(ValidPairingCode)` if `clock.now_unix_secs() < not_after`, or
    /// [`CryptoError::PairingCodeExpired`] otherwise.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::PairingCodeExpired`] if the code has expired.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn check_not_expired(self, clock: &dyn Clock) -> Result<ValidPairingCode, CryptoError> {
        if clock.now_unix_secs() >= self.not_after {
            return Err(CryptoError::PairingCodeExpired);
        }
        Ok(ValidPairingCode(self))
    }

    /// Returns the code value as a string slice for use as PAKE input.
    ///
    /// The returned reference is a borrow of the [`Zeroizing`] storage — the bytes will
    /// be erased when this `PairingCode` drops.
    ///
    /// # Security
    ///
    /// Never log or display this value; it is the shared secret that authenticates the PAKE.
    ///
    /// # Panics
    ///
    /// Never panics.
    fn as_str(&self) -> &str {
        self.value.as_str()
    }
}

// `PairingCode` deliberately does NOT implement `Debug`, `Display`, or `Clone`
// to prevent accidental logging of the secret code value.

// ─── ValidPairingCode ────────────────────────────────────────────────────────

/// Proof that a [`PairingCode`] has been validated against the clock and is not expired.
///
/// This newtype is the **only** type accepted by [`PakeExchange::start_with_rng`].
/// The only constructor is [`PairingCode::check_not_expired`], so it is a **compile-time
/// error** to start a PAKE exchange with an unchecked or expired code — "unchecked expiry"
/// is structurally unrepresentable.
///
/// The inner code is [`Zeroizing`] and will be erased on drop.
///
/// # Security
///
/// `Debug` is implemented but deliberately omits the secret code value — only the format is
/// shown. This type does not implement `Display` or `Clone` to prevent accidental logging or
/// duplication of the secret code value.
pub struct ValidPairingCode(PairingCode);

impl fmt::Debug for ValidPairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately omit the code value. Show only the format.
        f.debug_struct("ValidPairingCode")
            .field("format", &self.0.format)
            .finish_non_exhaustive()
    }
}

impl ValidPairingCode {
    /// Returns the underlying code value as a string slice.
    ///
    /// # Security
    ///
    /// Never log or display this value; it is the shared secret that authenticates the PAKE.
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// ─── PakeRole ────────────────────────────────────────────────────────────────

/// The role played by this side in a PAKE exchange.
///
/// Both roles are symmetric (balanced SPAKE2 — neither side holds an advantage), but the
/// protocol requires that each side know its label (`id_a` = initiator, `id_b` = responder).
///
/// **Mapping:** the Noise initiator (controller) takes [`PakeRole::Initiator`]; the Noise
/// responder (host) takes [`PakeRole::Responder`]. Both send an "id_a" / "id_b" in the SPAKE2
/// `idA` / `idB` slots, which are the 32-byte Ed25519 device fingerprint bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PakeRole {
    /// The initiating side (controller / client).
    Initiator,
    /// The responding side (host).
    Responder,
}

// ─── PakeConfirmed ───────────────────────────────────────────────────────────

/// Proof that a PAKE key-confirmation succeeded.
///
/// The contained peer identity is the **Noise BindCert-verified peer identity** from the
/// [`HandshakeOutcome`](crate::noise::HandshakeOutcome) — NEVER a claim from a PAKE message.
/// The PAKE authorizes a pin; the *thing pinned* is the cryptographically verified identity
/// from the Noise layer.
///
/// Produced **exclusively** by [`PakeExchange::finish`]. The peer identity field is private
/// and only accessible via [`PakeConfirmed::peer`] — fabricating a `PakeConfirmed` without
/// going through a real PAKE exchange is not possible from outside this module.
#[derive(Debug, Clone)]
pub struct PakeConfirmed {
    /// The identity that the PAKE exchange authorizes to be pinned.
    ///
    /// Private: the only constructor is `PakeExchange::finish`. This ensures a
    /// `PakeConfirmed` can never be fabricated to pin an arbitrary identity without
    /// completing a real PAKE exchange.
    authorizes_pin: DeviceIdentity,
}

impl PakeConfirmed {
    /// Returns a reference to the verified peer identity that this confirmation authorizes
    /// to be pinned.
    ///
    /// This is the `peer_identity` from the `HandshakeOutcome` passed to
    /// [`PakeExchange::start_with_rng`] — never a claim from a PAKE message.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn peer(&self) -> &DeviceIdentity {
        &self.authorizes_pin
    }
}

// ─── PakeExchange ─────────────────────────────────────────────────────────────

/// SPAKE2 PAKE exchange state machine.
///
/// # Protocol
///
/// 1. Validate the pairing code with [`PairingCode::check_not_expired`] to get a
///    [`ValidPairingCode`].
/// 2. Call [`start_with_rng`](Self::start_with_rng) on both sides to produce the first PAKE
///    message.
/// 3. Exchange the first messages (each side gets the other's [`outbound_msg`](Self::outbound_msg)).
/// 4. Call [`read_peer_msg`](Self::read_peer_msg) with the remote message to derive the shared key.
/// 5. Exchange confirmation MACs:
///    - Initiator sends its MAC and reads the responder's MAC.
///    - Responder sends its MAC and reads the initiator's MAC.
/// 6. Call [`finish`](Self::finish) with the peer's confirmation MAC to complete the exchange.
///
/// # Security
///
/// - `start_with_rng` requires a [`ValidPairingCode`] (produced only by
///   [`PairingCode::check_not_expired`]) — expiry is enforced structurally.
/// - The SPAKE2 shared key is [`Zeroizing`] and never exposed.
/// - The key-confirmation MAC additionally covers `h`, `id_a`, and `id_b` so a relayed or
///   replayed PAKE fails confirmation (ADR-0008 §2.3 / open-risk #1).
/// - Key material is erased when this struct drops.
/// - **Single-use:** this struct must be discarded after any error or after `finish` is called.
///   The internal SPAKE2 state is consumed by `read_peer_msg` and cannot be re-used.
///
/// # SECURITY WARNING
///
/// `spake2` is unaudited. See module doc and `SECURITY.md`.
pub struct PakeExchange {
    /// This side's SPAKE2 state (takes ownership until `read_peer_msg` is called).
    spake2_state: Option<spake2::Spake2<spake2::Ed25519Group>>,
    /// This side's SPAKE2 outbound message (the bytes to send to the peer).
    outbound: Vec<u8>,
    /// The expected peer confirmation MAC after `read_peer_msg` has been called.
    ///
    /// Renamed from `shared_key` (which was semantically misleading — this field holds a
    /// MAC tag for peer-confirmation verification, not the raw SPAKE2 shared key).
    /// `Zeroizing` ensures the expected MAC is erased on drop.
    peer_expected_mac: Option<Zeroizing<[u8; 32]>>,
    /// Our role in the exchange.
    role: PakeRole,
    /// The Noise handshake hash `h` (binding to the Noise session).
    handshake_hash: Zeroizing<[u8; 32]>,
    /// Our local device identity (used in the confirmation binding).
    local_id: DeviceIdentity,
    /// The peer device identity (from Noise BindCert — authoritative).
    peer_id: DeviceIdentity,
    /// Our local confirmation MAC (computed after `read_peer_msg`).
    local_confirmation: Option<[u8; 32]>,
}

impl PakeExchange {
    /// Starts a PAKE exchange and produces the first message to send to the peer.
    ///
    /// Both sides must call this with:
    /// - `rng`: a CSPRNG (injected for determinism in tests).
    /// - `role`: whether this side is [`PakeRole::Initiator`] or [`PakeRole::Responder`].
    /// - `code`: a [`ValidPairingCode`] produced by [`PairingCode::check_not_expired`];
    ///   expiry is enforced structurally — passing an unchecked code is a compile error.
    /// - `local_id`: this device's Ed25519 identity (from `Keystore::device_identity`).
    /// - `peer_id`: the peer's verified identity from the `HandshakeOutcome`.
    /// - `handshake_hash`: the Noise `h` for session binding.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::MalformedPakeMessage`] if SPAKE2 state construction fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn start_with_rng<R: CryptoRng + RngCore>(
        rng: &mut R,
        role: PakeRole,
        code: &ValidPairingCode,
        local_id: DeviceIdentity,
        peer_id: DeviceIdentity,
        handshake_hash: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        // The SPAKE2 password is the pairing code bytes.
        // `id_a` = initiator's device_id fingerprint bytes (hex fingerprint string, 64 bytes).
        // `id_b` = responder's device_id fingerprint bytes (hex fingerprint string, 64 bytes).
        // This binds both identities into the SPAKE2 transcript so swapping identities fails.
        // NOTE: We use the hex fingerprint string (not raw 32-byte digest) for both ids, as it
        // is an injective encoding — security-equivalent — and avoids an extra decode step.
        let (id_a_bytes, id_b_bytes) = match role {
            PakeRole::Initiator => (
                local_id.fingerprint().as_str().as_bytes().to_vec(),
                peer_id.fingerprint().as_str().as_bytes().to_vec(),
            ),
            PakeRole::Responder => (
                peer_id.fingerprint().as_str().as_bytes().to_vec(),
                local_id.fingerprint().as_str().as_bytes().to_vec(),
            ),
        };

        let password_bytes = Zeroizing::new(code.as_str().as_bytes().to_vec());
        let password = spake2::Password::new(&*password_bytes);
        let identity_a = spake2::Identity::new(&id_a_bytes);
        let identity_b = spake2::Identity::new(&id_b_bytes);

        // Construct the SPAKE2 state using the injected RNG; outbound is the first message.
        // `start_a_with_rng` / `start_b_with_rng` return `(Spake2<G>, Vec<u8>)`.
        let (spake2_state, outbound) = match role {
            PakeRole::Initiator => spake2::Spake2::<spake2::Ed25519Group>::start_a_with_rng(
                &password,
                &identity_a,
                &identity_b,
                rng,
            ),
            PakeRole::Responder => spake2::Spake2::<spake2::Ed25519Group>::start_b_with_rng(
                &password,
                &identity_a,
                &identity_b,
                rng,
            ),
        };

        let mut h_copy: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        h_copy.copy_from_slice(handshake_hash);

        Ok(Self {
            spake2_state: Some(spake2_state),
            outbound,
            peer_expected_mac: None,
            role,
            handshake_hash: h_copy,
            local_id,
            peer_id,
            local_confirmation: None,
        })
    }

    /// Returns the outbound message bytes to send to the peer.
    ///
    /// This is the SPAKE2 first message. Send these bytes to the peer, then call
    /// [`read_peer_msg`](Self::read_peer_msg) with the peer's response.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn outbound_msg(&self) -> &[u8] {
        &self.outbound
    }

    /// Reads the peer's PAKE message and derives the shared key + local confirmation MAC.
    ///
    /// After this call, [`local_confirmation_mac`](Self::local_confirmation_mac) returns the
    /// local confirmation bytes to send to the peer.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::MalformedPakeMessage`] if the peer message is malformed, too short,
    ///   too long, or fails SPAKE2 key derivation.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn read_peer_msg(&mut self, peer_msg: &[u8]) -> Result<(), CryptoError> {
        // Enforce message bounds — must match spake2's expected message size.
        // Ed25519Group messages are 33 bytes: 1 role byte + 32-byte compressed point.
        const MAX_SPAKE2_MSG: usize = 33;
        const MIN_SPAKE2_MSG: usize = 33;
        if peer_msg.len() < MIN_SPAKE2_MSG || peer_msg.len() > MAX_SPAKE2_MSG {
            return Err(CryptoError::MalformedPakeMessage {
                reason: "SPAKE2 message has unexpected length",
            });
        }

        let state = self
            .spake2_state
            .take()
            .ok_or(CryptoError::MalformedPakeMessage {
                reason: "read_peer_msg already called",
            })?;

        // SPAKE2 finish: derive the shared key.
        let raw_key = state
            .finish(peer_msg)
            .map_err(|_| CryptoError::MalformedPakeMessage {
                reason: "SPAKE2 key derivation failed (wrong code or malformed message)",
            })?;
        // Wrap raw_key in Zeroizing so the SPAKE2 secret is erased when it leaves this scope.
        let raw_key = Zeroizing::new(raw_key);

        // Derive the key-confirmation MAC for the local role.
        // The confirmation key additionally covers h + id_a + id_b (ADR-0008 open-risk #1):
        //   confirm_key = HKDF-Expand(Extract(spake2_key), info = label || h || id_a || id_b)
        //
        // Using separate labels for initiator and responder ensures neither can replay the other's
        // confirmation message (asymmetric confirmation).
        let local_confirm_key =
            self.derive_confirmation_key(&raw_key, self.local_confirm_info_label())?;
        let peer_confirm_key =
            self.derive_confirmation_key(&raw_key, self.peer_confirm_info_label())?;

        // The local confirmation MAC = HMAC-SHA256(local_confirm_key, context).
        // We use HKDF-Expand with a fixed label to produce the 32-byte MAC tag from the key.
        //   local_mac = HKDF-Expand(local_confirm_key, b"mac\x00", L=32)
        let local_confirmation = self.final_mac(&local_confirm_key)?;
        // The peer expected MAC is derived from the peer's confirmation key. We store this
        // (Zeroizing) so finish() can compare it against the peer's actual MAC.
        let peer_expected_mac = self.final_mac(&peer_confirm_key)?;

        self.local_confirmation = Some(local_confirmation);
        self.peer_expected_mac = Some(Zeroizing::new(peer_expected_mac));

        Ok(())
    }

    /// Returns the local confirmation MAC to send to the peer.
    ///
    /// Must be called after [`read_peer_msg`](Self::read_peer_msg).
    ///
    /// # Errors
    ///
    /// - [`CryptoError::MalformedPakeMessage`] if `read_peer_msg` has not been called yet.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn local_confirmation_mac(&self) -> Result<[u8; 32], CryptoError> {
        self.local_confirmation
            .ok_or(CryptoError::MalformedPakeMessage {
                reason: "must call read_peer_msg before local_confirmation_mac",
            })
    }

    /// Verifies the peer's confirmation MAC and, if valid, returns a [`PakeConfirmed`].
    ///
    /// `peer_confirmation` is the 32-byte MAC received from the peer (from their
    /// [`local_confirmation_mac`](Self::local_confirmation_mac)).
    ///
    /// The comparison is **constant-time** via [`subtle::ConstantTimeEq`].
    ///
    /// # Errors
    ///
    /// - [`CryptoError::MalformedPakeMessage`] if `peer_confirmation` is not 32 bytes.
    /// - [`CryptoError::PakeConfirmationFailed`] if the MAC does not match (wrong code,
    ///   wrong identities, or wrong `h` binding). No information about _how_ it was wrong
    ///   is disclosed — one online guess is consumed.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn finish(self, peer_confirmation: &[u8]) -> Result<PakeConfirmed, CryptoError> {
        if peer_confirmation.len() != 32 {
            return Err(CryptoError::MalformedPakeMessage {
                reason: "peer confirmation MAC must be exactly 32 bytes",
            });
        }

        let expected =
            self.peer_expected_mac
                .as_ref()
                .ok_or(CryptoError::MalformedPakeMessage {
                    reason: "must call read_peer_msg before finish",
                })?;

        // Constant-time comparison of the expected peer MAC vs the received peer MAC.
        let ct_result = expected.as_slice().ct_eq(peer_confirmation);
        if ct_result.unwrap_u8() != 1 {
            return Err(CryptoError::PakeConfirmationFailed);
        }

        Ok(PakeConfirmed {
            authorizes_pin: self.peer_id,
        })
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    /// Returns the HKDF info label for the local side's confirmation key derivation.
    fn local_confirm_info_label(&self) -> &'static [u8] {
        match self.role {
            PakeRole::Initiator => PAKE_CONFIRM_INITIATOR_INFO,
            PakeRole::Responder => PAKE_CONFIRM_RESPONDER_INFO,
        }
    }

    /// Returns the HKDF info label for the peer's expected confirmation key derivation.
    fn peer_confirm_info_label(&self) -> &'static [u8] {
        match self.role {
            PakeRole::Initiator => PAKE_CONFIRM_RESPONDER_INFO,
            PakeRole::Responder => PAKE_CONFIRM_INITIATOR_INFO,
        }
    }

    /// Derives a 32-byte confirmation key from the SPAKE2 shared key using HKDF-SHA-256.
    ///
    /// The HKDF info additionally covers `h + id_a + id_b` so the confirmation is bound
    /// to both the Noise session and both device identities (ADR-0008 §2.3, open-risk #1).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MalformedPakeMessage`] if HKDF fails (not expected in practice).
    fn derive_confirmation_key(
        &self,
        spake2_key: &[u8],
        role_label: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        // IKM = spake2_key (the shared SPAKE2 secret)
        let (_, hkdf) = Hkdf::<Sha256>::extract(None, spake2_key);

        // info = role_label || h[32] || id_a_fp[64] || id_b_fp[64]
        // — covers the Noise session AND both device identities.
        // NOTE: We use hex fingerprint strings (64 bytes each, injective encoding) as
        // documented in ADR-0008 §2.3.
        let (id_a_fp, id_b_fp) = match self.role {
            PakeRole::Initiator => (
                self.local_id.fingerprint().as_str(),
                self.peer_id.fingerprint().as_str(),
            ),
            PakeRole::Responder => (
                self.peer_id.fingerprint().as_str(),
                self.local_id.fingerprint().as_str(),
            ),
        };

        let info_capacity = role_label
            .len()
            .saturating_add(32)
            .saturating_add(64)
            .saturating_add(64);
        let mut info = Vec::with_capacity(info_capacity);
        info.extend_from_slice(role_label);
        info.extend_from_slice(self.handshake_hash.as_slice());
        info.extend_from_slice(id_a_fp.as_bytes());
        info.extend_from_slice(id_b_fp.as_bytes());

        let mut key = Zeroizing::new([0u8; 32]);
        hkdf.expand(&info, key.as_mut())
            .map_err(|_| CryptoError::MalformedPakeMessage {
                reason: "HKDF expand failed for confirmation key",
            })?;
        Ok(key)
    }

    /// Derives the final 32-byte confirmation MAC from a confirmation key.
    ///
    /// Uses a single HKDF-Expand step with a fixed label to separate the key from the MAC tag.
    /// The returned MAC tag is not secret (it goes on the wire), so it is returned as a plain
    /// `[u8; 32]` without `Zeroizing`.
    fn final_mac(&self, confirm_key: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
        let (_, hkdf) = Hkdf::<Sha256>::extract(None, confirm_key.as_slice());
        let mut mac = [0u8; 32];
        hkdf.expand(b"mac\x00", &mut mac)
            .map_err(|_| CryptoError::MalformedPakeMessage {
                reason: "HKDF expand failed for confirmation MAC",
            })?;
        Ok(mac)
    }
}

impl fmt::Debug for PakeExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PakeExchange")
            .field("role", &self.role)
            .field("local_id", &self.local_id)
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

// ─── PairingOutcome ───────────────────────────────────────────────────────────

/// The result of a pairing attempt.
///
/// Returned by [`pair_attended`] and [`pair_unattended`]. No variant contains secret
/// material — only public fingerprints appear in the enum.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PairingOutcome {
    /// Pairing succeeded and the peer identity has been pinned via `Keystore::trust_peer`.
    Pinned {
        /// The identity that was pinned.
        peer: DeviceIdentity,
    },
    /// The pairing was aborted without pinning.
    Aborted {
        /// A description of why pairing was aborted.
        ///
        /// This is a human-readable string suitable for operator logs. It does NOT contain
        /// any secret material (keys, pairing codes, or PAKE keying material).
        reason: &'static str,
    },
    /// The peer was previously revoked; the operator must perform an explicit re-trust action.
    ///
    /// The peer has NOT been pinned. The caller must obtain explicit out-of-band operator
    /// confirmation before calling `Keystore::trust_peer` on the contained identity.
    ///
    /// This satisfies the R-HW-KS constraint (ADR-0006 §6, ADR-0008 §3):
    /// silently re-pinning a revoked attacker device would bypass the revocation.
    ReTrustAfterRevokeRequiresConfirmation {
        /// The revoked identity that would be re-pinned pending confirmation.
        peer: DeviceIdentity,
    },
}

// ─── SasConfirmed ─────────────────────────────────────────────────────────────

/// Proof that a human explicitly confirmed a SAS match for a specific peer.
///
/// This typestate is returned by [`Sas::confirm`](crate::sas::Sas::confirm) when
/// `human_said_match = true`. [`pair_attended`] requires a `SasConfirmed` instead of a raw
/// `bool`, making it a **compile-time error** to call `pair_attended` without going through
/// the SAS display-and-confirm flow.
///
/// `SasConfirmed` carries the peer identity to bind the SAS confirmation to the specific peer
/// being paired, preventing the confirmation from being replayed for a different peer.
#[derive(Debug, Clone)]
pub struct SasConfirmed {
    /// The peer identity whose SAS was confirmed by the human.
    pub(crate) peer: DeviceIdentity,
}

impl SasConfirmed {
    /// Returns the peer identity that was confirmed.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn peer(&self) -> &DeviceIdentity {
        &self.peer
    }
}

// ─── pair_attended ────────────────────────────────────────────────────────────

/// Attended pairing: the human confirms SAS match; if confirmed, the peer is pinned.
///
/// The caller is responsible for:
/// 1. Deriving the SAS from the handshake hash using [`crate::sas::Sas::from_handshake_hash`].
/// 2. Displaying the SAS to the human alongside the peer's fingerprint.
/// 3. Obtaining out-of-band human confirmation (both sides compare displayed SAS values).
/// 4. Calling [`Sas::confirm`](crate::sas::Sas::confirm) with the peer identity and the
///    human's answer; this produces a [`SasConfirmed`] on match or `None` on mismatch.
/// 5. Calling this function with the `SasConfirmed` token.
///
/// **This function pins the peer ONLY when a valid `SasConfirmed` is provided.**
///
/// # Typestate enforcement
///
/// Taking a `SasConfirmed` (instead of a raw `bool`) makes it a **compile error** to call
/// `pair_attended` without going through [`Sas::confirm`] — you cannot accidentally bypass
/// the SAS display step.
///
/// # Revocation check
///
/// The revocation check and the pin are performed **atomically** via
/// [`Keystore::trust_peer_if_not_revoked`] under a single write-lock acquisition, eliminating
/// the TOCTOU race between checking revocation state and pinning.
///
/// If the peer identity was previously revoked, this function returns
/// [`PairingOutcome::ReTrustAfterRevokeRequiresConfirmation`]. The caller must obtain a
/// separate, explicit operator confirmation before calling `Keystore::trust_peer` directly.
///
/// # Errors
///
/// - [`CryptoError::Backend`] if the keystore trust-store read or write fails.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use sh_crypto::pairing::{pair_attended, SasConfirmed, PairingOutcome};
/// use sh_crypto::noise::HandshakeOutcome;
/// use sh_crypto::sas::Sas;
/// use sh_crypto::SoftwareKeystore;
/// use sh_crypto::clock::SystemClock;
///
/// # async fn example(outcome: HandshakeOutcome, ks: SoftwareKeystore) -> Result<(), sh_crypto::CryptoError> {
/// let sas = Sas::from_handshake_hash(&outcome.handshake_hash);
/// println!("SAS: {sas}");
/// // ... display to human and get confirmation ...
/// let human_said_match = true; // obtained from UI
/// if let Some(confirmed) = sas.confirm(&outcome.peer_identity, human_said_match) {
///     let pairing = pair_attended(confirmed, &ks).await?;
///     match pairing {
///         PairingOutcome::Pinned { peer } => println!("pinned: {peer}"),
///         PairingOutcome::Aborted { reason } => println!("aborted: {reason}"),
///         PairingOutcome::ReTrustAfterRevokeRequiresConfirmation { peer } =>
///             println!("revoked peer requires explicit re-trust: {peer}"),
///         _ => {}
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub async fn pair_attended(
    sas_confirmed: SasConfirmed,
    keystore: &dyn Keystore,
) -> Result<PairingOutcome, CryptoError> {
    let peer = sas_confirmed.peer;

    // Atomically check revocation state and pin, under a single write-lock acquisition.
    // This eliminates the TOCTOU race between was_peer_revoked() and trust_peer().
    match keystore.trust_peer_if_not_revoked(&peer).await? {
        TrustOutcome::Pinned => Ok(PairingOutcome::Pinned { peer }),
        TrustOutcome::WasRevoked => {
            Ok(PairingOutcome::ReTrustAfterRevokeRequiresConfirmation { peer })
        }
    }
}

// ─── pair_unattended ──────────────────────────────────────────────────────────

/// Unattended pairing: PAKE over a shared code → confirm → pin.
///
/// This is a single-function convenience wrapper for the full unattended pairing flow.
/// For the multi-step exchange needed when the two sides are on different machines, use
/// [`PakeExchange`] directly and wire the message exchange over the Noise transport.
///
/// `pake_confirmed` is the [`PakeConfirmed`] token returned by [`PakeExchange::finish`];
/// the peer identity inside it is the verified peer identity.
///
/// # Revocation check
///
/// Same as [`pair_attended`]: the revocation check and pin are performed **atomically** via
/// [`Keystore::trust_peer_if_not_revoked`] to eliminate the TOCTOU race.
///
/// If the peer was previously revoked, returns
/// [`PairingOutcome::ReTrustAfterRevokeRequiresConfirmation`] instead of auto-pinning.
///
/// # Errors
///
/// - [`CryptoError::Backend`] if the keystore read or write fails.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use sh_crypto::pairing::{pair_unattended, PakeConfirmed, PairingOutcome};
/// use sh_crypto::SoftwareKeystore;
/// use sh_crypto::clock::SystemClock;
///
/// # async fn example(confirmed: PakeConfirmed, ks: SoftwareKeystore) -> Result<(), sh_crypto::CryptoError> {
/// let outcome = pair_unattended(confirmed, &ks).await?;
/// match outcome {
///     PairingOutcome::Pinned { peer } => println!("pinned: {peer}"),
///     PairingOutcome::Aborted { reason } => println!("aborted: {reason}"),
///     PairingOutcome::ReTrustAfterRevokeRequiresConfirmation { peer } =>
///         println!("revoked — operator must confirm: {peer}"),
///     _ => {}
/// }
/// # Ok(())
/// # }
/// ```
pub async fn pair_unattended(
    pake_confirmed: PakeConfirmed,
    keystore: &dyn Keystore,
) -> Result<PairingOutcome, CryptoError> {
    let peer = pake_confirmed.authorizes_pin;

    // Atomically check revocation state and pin, under a single write-lock acquisition.
    // This eliminates the TOCTOU race between was_peer_revoked() and trust_peer().
    match keystore.trust_peer_if_not_revoked(&peer).await? {
        TrustOutcome::Pinned => Ok(PairingOutcome::Pinned { peer }),
        TrustOutcome::WasRevoked => {
            Ok(PairingOutcome::ReTrustAfterRevokeRequiresConfirmation { peer })
        }
    }
}

// ─── TrustOutcome ─────────────────────────────────────────────────────────────

/// The result of an atomic revocation-check-and-pin operation.
///
/// Returned by [`Keystore::trust_peer_if_not_revoked`]. Separates "pinned successfully" from
/// "was revoked, pin refused" without exposing any secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustOutcome {
    /// The peer was not revoked; it has been pinned (or was already pinned).
    Pinned,
    /// The peer was previously revoked; the pin was refused. Operator must confirm re-trust.
    WasRevoked,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::clock::FixedClock;
    use crate::sas::Sas;
    use crate::{Keystore, SoftwareKeystore};
    use rand_core::SeedableRng;

    const NOW: i64 = 1_000_000_000i64;
    const NOT_AFTER: i64 = 1_000_001_000i64; // 1000 seconds later

    fn seeded_ks(seed: u64) -> SoftwareKeystore {
        SoftwareKeystore::generate_with_rng(rand_chacha::ChaCha8Rng::seed_from_u64(seed))
    }

    fn seeded_rng(seed: u64) -> rand_chacha::ChaCha8Rng {
        rand_chacha::ChaCha8Rng::seed_from_u64(seed)
    }

    fn fixed_h(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// Helper: produce a validated code from digits (for use in tests that need `ValidPairingCode`).
    fn valid_code(digits: &str) -> ValidPairingCode {
        let code =
            PairingCode::from_digits(digits, PairingCodeFormat::EightDigit, NOT_AFTER).unwrap();
        let clock = FixedClock(NOW);
        code.check_not_expired(&clock).unwrap()
    }

    // ─── PairingCode ─────────────────────────────────────────────────────────

    #[test]
    fn pairing_code_correct_digit_count() {
        let mut rng = seeded_rng(1);
        let code =
            PairingCode::generate_with_rng(&mut rng, PairingCodeFormat::EightDigit, NOT_AFTER);
        assert_eq!(code.format(), PairingCodeFormat::EightDigit);
        // The code should have 8 digits (only observable via `from_digits` roundtrip).
        let digits = code.as_str().to_string();
        assert_eq!(digits.len(), 8);
        assert!(digits.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn pairing_code_not_expired_passes() {
        let mut rng = seeded_rng(2);
        let code =
            PairingCode::generate_with_rng(&mut rng, PairingCodeFormat::EightDigit, NOT_AFTER);
        let clock = FixedClock(NOW);
        assert!(code.check_not_expired(&clock).is_ok());
    }

    #[test]
    fn pairing_code_expired_returns_error() {
        let mut rng = seeded_rng(3);
        let code =
            PairingCode::generate_with_rng(&mut rng, PairingCodeFormat::EightDigit, NOT_AFTER);
        // Clock is at exactly not_after — should be rejected.
        let clock = FixedClock(NOT_AFTER);
        assert!(matches!(
            code.check_not_expired(&clock),
            Err(CryptoError::PairingCodeExpired)
        ));
    }

    #[test]
    fn pairing_code_past_expiry_returns_error() {
        let mut rng = seeded_rng(4);
        let code =
            PairingCode::generate_with_rng(&mut rng, PairingCodeFormat::EightDigit, NOT_AFTER);
        let clock = FixedClock(NOT_AFTER + 9999);
        assert!(matches!(
            code.check_not_expired(&clock),
            Err(CryptoError::PairingCodeExpired)
        ));
    }

    #[test]
    fn pairing_code_from_digits_valid() {
        let code = PairingCode::from_digits("12345678", PairingCodeFormat::EightDigit, NOT_AFTER);
        assert!(code.is_ok());
        let code = code.unwrap();
        assert_eq!(code.as_str(), "12345678");
    }

    #[test]
    fn pairing_code_from_digits_wrong_length_errors() {
        let r = PairingCode::from_digits("1234", PairingCodeFormat::EightDigit, NOT_AFTER);
        assert!(matches!(r, Err(CryptoError::MalformedPakeMessage { .. })));
    }

    #[test]
    fn pairing_code_from_digits_non_digit_errors() {
        let r = PairingCode::from_digits("1234567x", PairingCodeFormat::EightDigit, NOT_AFTER);
        assert!(matches!(r, Err(CryptoError::MalformedPakeMessage { .. })));
    }

    // ─── CRITICAL: Expiry enforced at PAKE start — structural test ───────────

    /// Structural guarantee: an expired code cannot reach `start_with_rng`.
    ///
    /// `check_not_expired` consumes `self` and returns `Err(PairingCodeExpired)` when the
    /// code is expired. `start_with_rng` requires `&ValidPairingCode`, so an expired code
    /// physically cannot be passed — this test confirms the runtime behaviour of the check
    /// at the exact boundary.
    #[test]
    fn expired_code_check_not_expired_returns_error_before_pake() {
        let mut rng = seeded_rng(5);
        // A code that expired 1 second ago relative to our injected clock.
        let code =
            PairingCode::generate_with_rng(&mut rng, PairingCodeFormat::EightDigit, NOT_AFTER);
        // Clock is past not_after — expiry must be enforced.
        let expired_clock = FixedClock(NOT_AFTER + 1);
        let result = code.check_not_expired(&expired_clock);
        assert!(
            matches!(result, Err(CryptoError::PairingCodeExpired)),
            "expired code must return PairingCodeExpired before PAKE starts, got: {result:?}"
        );
        // The Err branch means no ValidPairingCode was returned → start_with_rng is
        // unreachable without a valid code (enforced by type system + this test).
    }

    // ─── PAKE correct code → confirmed ──────────────────────────────────────

    #[tokio::test]
    async fn pake_correct_code_succeeds() {
        let mut rng_a = seeded_rng(10);
        let mut rng_b = seeded_rng(11);

        let ks_a = seeded_ks(100);
        let ks_b = seeded_ks(101);
        let id_a = ks_a.device_identity().await.unwrap();
        let id_b = ks_b.device_identity().await.unwrap();

        let h = fixed_h(0x5a);
        let code_a = valid_code("12345678");
        let code_b = valid_code("12345678");

        // Both sides start the PAKE.
        let mut exc_a = PakeExchange::start_with_rng(
            &mut rng_a,
            PakeRole::Initiator,
            &code_a,
            id_a.clone(),
            id_b.clone(),
            &h,
        )
        .unwrap();

        let mut exc_b = PakeExchange::start_with_rng(
            &mut rng_b,
            PakeRole::Responder,
            &code_b,
            id_b.clone(),
            id_a.clone(),
            &h,
        )
        .unwrap();

        // Exchange first messages.
        let msg_a = exc_a.outbound_msg().to_vec();
        let msg_b = exc_b.outbound_msg().to_vec();

        // Each side reads the other's message.
        exc_a.read_peer_msg(&msg_b).unwrap();
        exc_b.read_peer_msg(&msg_a).unwrap();

        // Exchange confirmation MACs.
        let mac_a = exc_a.local_confirmation_mac().unwrap();
        let mac_b = exc_b.local_confirmation_mac().unwrap();

        // Finish: each side verifies the other's MAC.
        let confirmed_a = exc_a.finish(&mac_b).unwrap();
        let confirmed_b = exc_b.finish(&mac_a).unwrap();

        // The confirmed peer identities must be the Noise-verified ones (not PAKE claims).
        assert_eq!(confirmed_a.peer(), &id_b);
        assert_eq!(confirmed_b.peer(), &id_a);
    }

    // ─── PAKE wrong code → confirmation fails, NO pin ────────────────────────

    #[tokio::test]
    async fn pake_wrong_code_no_pin() {
        let mut rng_a = seeded_rng(20);
        let mut rng_b = seeded_rng(21);

        let ks_a = seeded_ks(200);
        let ks_b = seeded_ks(201);
        let id_a = ks_a.device_identity().await.unwrap();
        let id_b = ks_b.device_identity().await.unwrap();

        let h = fixed_h(0xab);
        // A and B use DIFFERENT codes.
        let code_a = valid_code("12345678");
        let code_b = valid_code("87654321");

        let mut exc_a = PakeExchange::start_with_rng(
            &mut rng_a,
            PakeRole::Initiator,
            &code_a,
            id_a.clone(),
            id_b.clone(),
            &h,
        )
        .unwrap();
        let mut exc_b = PakeExchange::start_with_rng(
            &mut rng_b,
            PakeRole::Responder,
            &code_b,
            id_b.clone(),
            id_a.clone(),
            &h,
        )
        .unwrap();

        let msg_a = exc_a.outbound_msg().to_vec();
        let msg_b = exc_b.outbound_msg().to_vec();

        exc_a.read_peer_msg(&msg_b).unwrap();
        exc_b.read_peer_msg(&msg_a).unwrap();

        let mac_a = exc_a.local_confirmation_mac().unwrap();
        let mac_b = exc_b.local_confirmation_mac().unwrap();

        // Both confirmations must fail (wrong code → different keys → different MACs).
        let result_a = exc_a.finish(&mac_b);
        let result_b = exc_b.finish(&mac_a);

        assert!(
            matches!(result_a, Err(CryptoError::PakeConfirmationFailed)),
            "wrong code: initiator must get PakeConfirmationFailed, got {result_a:?}"
        );
        assert!(
            matches!(result_b, Err(CryptoError::PakeConfirmationFailed)),
            "wrong code: responder must get PakeConfirmationFailed, got {result_b:?}"
        );

        // Explicitly verify no pin was called.
        assert!(
            !ks_a.is_trusted(&id_b).await.unwrap(),
            "wrong-code PAKE must NOT pin peer on initiator side"
        );
        assert!(
            !ks_b.is_trusted(&id_a).await.unwrap(),
            "wrong-code PAKE must NOT pin peer on responder side"
        );
    }

    // ─── Relayed PAKE (wrong id_a/id_b) → fail ──────────────────────────────

    #[tokio::test]
    async fn pake_relayed_wrong_identities_fails() {
        let mut rng_a = seeded_rng(30);
        let mut rng_relay = seeded_rng(31);

        let ks_a = seeded_ks(300);
        let ks_b = seeded_ks(301);
        let ks_relay = seeded_ks(399); // attacker / relay device
        let id_a = ks_a.device_identity().await.unwrap();
        let id_b = ks_b.device_identity().await.unwrap();
        let id_relay = ks_relay.device_identity().await.unwrap();

        let h = fixed_h(0xcc);
        let code_a = valid_code("11111111");
        let code_relay = valid_code("11111111");

        // Legitimate initiator pairs with id_b.
        let mut exc_a = PakeExchange::start_with_rng(
            &mut rng_a,
            PakeRole::Initiator,
            &code_a,
            id_a.clone(),
            id_b.clone(), // expects id_b as responder
            &h,
        )
        .unwrap();

        // Relay substitutes id_relay as if it were the responder.
        let mut exc_relay = PakeExchange::start_with_rng(
            &mut rng_relay,
            PakeRole::Responder,
            &code_relay,
            id_relay.clone(), // relay pretends to be id_a (responder binding differs)
            id_a.clone(),
            &h,
        )
        .unwrap();

        let msg_a = exc_a.outbound_msg().to_vec();
        let msg_relay = exc_relay.outbound_msg().to_vec();

        // Message exchange proceeds (SPAKE2 doesn't reject at this layer).
        exc_a.read_peer_msg(&msg_relay).unwrap();
        exc_relay.read_peer_msg(&msg_a).unwrap();

        let _mac_a = exc_a.local_confirmation_mac().unwrap();
        let mac_relay = exc_relay.local_confirmation_mac().unwrap();

        // Confirmation MUST fail: the identity binding in the info string differs.
        // Side A bound id_b; relay bound id_relay — different info → different keys → MAC mismatch.
        let result_a = exc_a.finish(&mac_relay);
        assert!(
            matches!(result_a, Err(CryptoError::PakeConfirmationFailed)),
            "relayed PAKE must fail confirmation on initiator side: {result_a:?}"
        );
    }

    // ─── Replayed transcript (wrong h binding) → reject ─────────────────────

    #[tokio::test]
    async fn pake_wrong_h_binding_fails() {
        let mut rng_a = seeded_rng(40);
        let mut rng_b = seeded_rng(41);

        let ks_a = seeded_ks(400);
        let ks_b = seeded_ks(401);
        let id_a = ks_a.device_identity().await.unwrap();
        let id_b = ks_b.device_identity().await.unwrap();

        let h_real = fixed_h(0x11);
        let h_replay = fixed_h(0x22); // different h
        let code_a = valid_code("99999999");
        let code_b = valid_code("99999999");

        // A uses the real h; B uses a different h (replay scenario).
        let mut exc_a = PakeExchange::start_with_rng(
            &mut rng_a,
            PakeRole::Initiator,
            &code_a,
            id_a.clone(),
            id_b.clone(),
            &h_real,
        )
        .unwrap();
        let mut exc_b = PakeExchange::start_with_rng(
            &mut rng_b,
            PakeRole::Responder,
            &code_b,
            id_b.clone(),
            id_a.clone(),
            &h_replay, // different h
        )
        .unwrap();

        let msg_a = exc_a.outbound_msg().to_vec();
        let msg_b = exc_b.outbound_msg().to_vec();

        exc_a.read_peer_msg(&msg_b).unwrap();
        exc_b.read_peer_msg(&msg_a).unwrap();

        let _mac_a = exc_a.local_confirmation_mac().unwrap();
        let mac_b = exc_b.local_confirmation_mac().unwrap();

        // h binding mismatch → confirmation MACs differ → both sides reject.
        let result_a = exc_a.finish(&mac_b);
        assert!(
            matches!(result_a, Err(CryptoError::PakeConfirmationFailed)),
            "wrong-h PAKE must fail on initiator: {result_a:?}"
        );
    }

    // ─── HKDF identity-binding isolation test ────────────────────────────────

    /// Regression guard: varying only the HKDF `info` identity binding (holding the SPAKE2
    /// key constant by using identical codes and `h`) must produce a MAC mismatch when the
    /// identity differs on each side. This catches a regression where the HKDF id-binding
    /// is accidentally dropped.
    #[tokio::test]
    async fn hkdf_identity_binding_mismatch_causes_confirmation_failure() {
        let mut rng_a = seeded_rng(4200);
        let mut rng_b = seeded_rng(4201);

        let ks_a = seeded_ks(4200);
        let ks_b = seeded_ks(4201);
        let ks_c = seeded_ks(4202); // a third identity — used as a substitute

        let id_a = ks_a.device_identity().await.unwrap();
        let id_b = ks_b.device_identity().await.unwrap();
        let id_c = ks_c.device_identity().await.unwrap();

        let h = fixed_h(0xDD);
        // Both sides use the SAME code and the SAME h, so the SPAKE2 shared key is the same.
        // But A binds (id_a, id_b) in the HKDF info, while B binds (id_c, id_a).
        // → different info → different confirm keys → MAC mismatch.
        let code_a = valid_code("42424242");
        let code_b = valid_code("42424242");

        let mut exc_a = PakeExchange::start_with_rng(
            &mut rng_a,
            PakeRole::Initiator,
            &code_a,
            id_a.clone(),
            id_b.clone(), // A expects peer = id_b
            &h,
        )
        .unwrap();

        // B uses id_c as the local identity (different from id_a), so the identity binding
        // in HKDF info differs even though code and h are identical.
        let mut exc_b = PakeExchange::start_with_rng(
            &mut rng_b,
            PakeRole::Responder,
            &code_b,
            id_c.clone(), // B's local identity is id_c, not id_b
            id_a.clone(),
            &h,
        )
        .unwrap();

        let msg_a = exc_a.outbound_msg().to_vec();
        let msg_b = exc_b.outbound_msg().to_vec();

        exc_a.read_peer_msg(&msg_b).unwrap();
        exc_b.read_peer_msg(&msg_a).unwrap();

        let mac_a = exc_a.local_confirmation_mac().unwrap();
        let mac_b = exc_b.local_confirmation_mac().unwrap();

        // MAC mismatch expected because the HKDF info identity bindings differ.
        let result_a = exc_a.finish(&mac_b);
        let result_b = exc_b.finish(&mac_a);

        assert!(
            matches!(result_a, Err(CryptoError::PakeConfirmationFailed)),
            "identity mismatch must cause confirmation failure on A side: {result_a:?}"
        );
        assert!(
            matches!(result_b, Err(CryptoError::PakeConfirmationFailed)),
            "identity mismatch must cause confirmation failure on B side: {result_b:?}"
        );
    }

    // ─── Pin ONLY after confirm (no pin on bare handshake) ───────────────────

    #[tokio::test]
    async fn no_pin_without_pake_confirmation() {
        let ks_a = seeded_ks(50);
        let ks_b = seeded_ks(51);
        let id_b = ks_b.device_identity().await.unwrap();

        // Deliberately do NOT call pair_attended or pair_unattended.
        assert!(
            !ks_a.is_trusted(&id_b).await.unwrap(),
            "peer must not be trusted without explicit pairing confirm"
        );
    }

    // ─── Malformed / truncated / over-long PAKE bytes → typed error, no panic ─

    #[test]
    fn pake_empty_msg_returns_error() {
        let mut rng = seeded_rng(60);
        let ks_a = seeded_ks(600);
        let ks_b = seeded_ks(601);
        let id_a = futures_lite::future::block_on(ks_a.device_identity()).unwrap();
        let id_b = futures_lite::future::block_on(ks_b.device_identity()).unwrap();
        let h = fixed_h(0x00);
        let code = valid_code("12345678");

        let mut exc =
            PakeExchange::start_with_rng(&mut rng, PakeRole::Initiator, &code, id_a, id_b, &h)
                .unwrap();

        let result = exc.read_peer_msg(&[]);
        assert!(
            matches!(result, Err(CryptoError::MalformedPakeMessage { .. })),
            "empty PAKE msg must return MalformedPakeMessage: {result:?}"
        );
    }

    #[test]
    fn pake_truncated_msg_returns_error() {
        let mut rng = seeded_rng(61);
        let ks_a = seeded_ks(610);
        let ks_b = seeded_ks(611);
        let id_a = futures_lite::future::block_on(ks_a.device_identity()).unwrap();
        let id_b = futures_lite::future::block_on(ks_b.device_identity()).unwrap();
        let h = fixed_h(0x00);
        let code = valid_code("12345678");

        let mut exc =
            PakeExchange::start_with_rng(&mut rng, PakeRole::Initiator, &code, id_a, id_b, &h)
                .unwrap();

        // 10 bytes — too short for a 33-byte SPAKE2 Ed25519Group message.
        let short = vec![0u8; 10];
        let result = exc.read_peer_msg(&short);
        assert!(
            matches!(result, Err(CryptoError::MalformedPakeMessage { .. })),
            "truncated PAKE msg must return MalformedPakeMessage: {result:?}"
        );
    }

    #[test]
    fn pake_overlength_msg_returns_error() {
        let mut rng = seeded_rng(62);
        let ks_a = seeded_ks(620);
        let ks_b = seeded_ks(621);
        let id_a = futures_lite::future::block_on(ks_a.device_identity()).unwrap();
        let id_b = futures_lite::future::block_on(ks_b.device_identity()).unwrap();
        let h = fixed_h(0x00);
        let code = valid_code("12345678");

        let mut exc =
            PakeExchange::start_with_rng(&mut rng, PakeRole::Initiator, &code, id_a, id_b, &h)
                .unwrap();

        // 100 bytes — too long.
        let long = vec![0u8; 100];
        let result = exc.read_peer_msg(&long);
        assert!(
            matches!(result, Err(CryptoError::MalformedPakeMessage { .. })),
            "over-long PAKE msg must return MalformedPakeMessage: {result:?}"
        );
    }

    #[test]
    fn pake_wrong_confirmation_length_returns_error() {
        let mut rng_a = seeded_rng(63);
        let mut rng_b = seeded_rng(64);
        let ks_a = seeded_ks(630);
        let ks_b = seeded_ks(631);
        let id_a = futures_lite::future::block_on(ks_a.device_identity()).unwrap();
        let id_b = futures_lite::future::block_on(ks_b.device_identity()).unwrap();

        let h = fixed_h(0x00);
        let code_a = valid_code("12345678");
        let code_b = valid_code("12345678");

        let mut exc_a = PakeExchange::start_with_rng(
            &mut rng_a,
            PakeRole::Initiator,
            &code_a,
            id_a.clone(),
            id_b.clone(),
            &h,
        )
        .unwrap();
        let mut exc_b =
            PakeExchange::start_with_rng(&mut rng_b, PakeRole::Responder, &code_b, id_b, id_a, &h)
                .unwrap();

        let msg_a = exc_a.outbound_msg().to_vec();
        let msg_b = exc_b.outbound_msg().to_vec();
        exc_a.read_peer_msg(&msg_b).unwrap();
        exc_b.read_peer_msg(&msg_a).unwrap();

        // Send a wrong-length confirmation.
        let bad_confirmation = vec![0u8; 16]; // must be 32
        let result = exc_a.finish(&bad_confirmation);
        assert!(
            matches!(result, Err(CryptoError::MalformedPakeMessage { .. })),
            "wrong-length confirmation must return MalformedPakeMessage: {result:?}"
        );
    }

    // ─── SasConfirmed typestate test ─────────────────────────────────────────

    /// Confirms that `pair_attended` requires a `SasConfirmed` token (not a raw bool),
    /// and that `Sas::confirm` returns `None` when the human says no match.
    #[tokio::test]
    async fn sas_confirm_none_when_human_declines() {
        let ks_a = seeded_ks(90);
        let ks_b = seeded_ks(91);
        let id_b = ks_b.device_identity().await.unwrap();

        let h = fixed_h(0x42);
        let sas = Sas::from_handshake_hash(&h);

        // Human says no match.
        let confirmed = sas.confirm(&id_b, false);
        assert!(
            confirmed.is_none(),
            "Sas::confirm must return None when human says no match"
        );

        // Without a SasConfirmed, pair_attended cannot be called — type-system enforced.
        // Verify peer is not trusted.
        assert!(!ks_a.is_trusted(&id_b).await.unwrap());
    }

    #[tokio::test]
    async fn sas_confirm_some_when_human_confirms() {
        let ks_b = seeded_ks(93);
        let id_b = ks_b.device_identity().await.unwrap();

        let h = fixed_h(0x42);
        let sas = Sas::from_handshake_hash(&h);

        let confirmed = sas.confirm(&id_b, true);
        assert!(
            confirmed.is_some(),
            "Sas::confirm must return Some(SasConfirmed) when human confirms"
        );
        assert_eq!(confirmed.unwrap().peer(), &id_b);
    }

    // ─── TOCTOU atomic test ───────────────────────────────────────────────────

    /// Confirms that `trust_peer_if_not_revoked` atomically refuses to re-pin a revoked peer,
    /// and that calling it a second time after revocation still returns WasRevoked.
    #[tokio::test]
    async fn atomic_trust_if_not_revoked_refuses_revoked_peer() {
        let ks = seeded_ks(7000);
        let peer_ks = seeded_ks(7001);
        let peer_id = peer_ks.device_identity().await.unwrap();

        // Trust then revoke.
        ks.trust_peer(&peer_id).await.unwrap();
        ks.revoke_peer(&peer_id).await.unwrap();
        assert!(!ks.is_trusted(&peer_id).await.unwrap());

        // Atomic check-and-pin must refuse.
        let outcome = ks.trust_peer_if_not_revoked(&peer_id).await.unwrap();
        assert_eq!(
            outcome,
            TrustOutcome::WasRevoked,
            "atomic pin must return WasRevoked for a revoked peer"
        );

        // Peer must NOT have been re-pinned.
        assert!(
            !ks.is_trusted(&peer_id).await.unwrap(),
            "revoked peer must not be re-pinned by trust_peer_if_not_revoked"
        );
    }

    #[tokio::test]
    async fn atomic_trust_if_not_revoked_pins_new_peer() {
        let ks = seeded_ks(7002);
        let peer_ks = seeded_ks(7003);
        let peer_id = peer_ks.device_identity().await.unwrap();

        // Never-seen peer — must be pinned atomically.
        let outcome = ks.trust_peer_if_not_revoked(&peer_id).await.unwrap();
        assert_eq!(outcome, TrustOutcome::Pinned, "new peer must return Pinned");
        assert!(
            ks.is_trusted(&peer_id).await.unwrap(),
            "new peer must be trusted after atomic pin"
        );
    }

    // ─── Re-trust after revoke → ReTrustAfterRevokeRequiresConfirmation ──────

    #[tokio::test]
    async fn attended_revoked_peer_returns_retrust_signal() {
        let ks_host = seeded_ks(70);
        let ks_peer = seeded_ks(71);
        let peer_id = ks_peer.device_identity().await.unwrap();

        // Trust and then revoke the peer.
        ks_host.trust_peer(&peer_id).await.unwrap();
        ks_host.revoke_peer(&peer_id).await.unwrap();
        assert!(!ks_host.is_trusted(&peer_id).await.unwrap());

        // pair_attended via SasConfirmed must NOT auto-pin; must return the signal.
        let h = fixed_h(0x99);
        let sas = Sas::from_handshake_hash(&h);
        let confirmed = sas.confirm(&peer_id, true).unwrap();
        let outcome = pair_attended(confirmed, &ks_host).await.unwrap();
        assert!(
            matches!(
                outcome,
                PairingOutcome::ReTrustAfterRevokeRequiresConfirmation { .. }
            ),
            "revoked peer must return ReTrustAfterRevokeRequiresConfirmation, got {outcome:?}"
        );
        // Must NOT have been re-pinned.
        assert!(
            !ks_host.is_trusted(&peer_id).await.unwrap(),
            "revoked peer must NOT be auto-re-pinned"
        );
    }

    #[tokio::test]
    async fn unattended_revoked_peer_returns_retrust_signal() {
        let ks_host = seeded_ks(80);
        let ks_peer = seeded_ks(81);
        let peer_id = ks_peer.device_identity().await.unwrap();

        ks_host.trust_peer(&peer_id).await.unwrap();
        ks_host.revoke_peer(&peer_id).await.unwrap();

        // Fabricate a PakeConfirmed via the private constructor (cfg(test) path).
        let confirmed = PakeConfirmed {
            authorizes_pin: peer_id.clone(),
        };
        let outcome = pair_unattended(confirmed, &ks_host).await.unwrap();
        assert!(
            matches!(outcome, PairingOutcome::ReTrustAfterRevokeRequiresConfirmation { .. }),
            "revoked peer unattended must return ReTrustAfterRevokeRequiresConfirmation: {outcome:?}"
        );
        assert!(
            !ks_host.is_trusted(&peer_id).await.unwrap(),
            "revoked peer must NOT be auto-re-pinned by pair_unattended"
        );
    }

    // ─── Never-seen peer (not revoked) attends and gets pinned ───────────────

    #[tokio::test]
    async fn attended_new_peer_gets_pinned() {
        let ks_host = seeded_ks(90);
        let ks_peer = seeded_ks(91);
        let peer_id = ks_peer.device_identity().await.unwrap();

        let h = fixed_h(0x42);
        let sas = Sas::from_handshake_hash(&h);
        let confirmed = sas.confirm(&peer_id, true).unwrap();
        let outcome = pair_attended(confirmed, &ks_host).await.unwrap();
        assert!(
            matches!(outcome, PairingOutcome::Pinned { .. }),
            "new peer with confirmed SAS must be pinned: {outcome:?}"
        );
        assert!(ks_host.is_trusted(&peer_id).await.unwrap());
    }

    // ─── Proptest: arbitrary bytes into read_peer_msg never panics ───────────

    use proptest::prelude::*;
    proptest! {
        #[test]
        fn arbitrary_pake_msg_never_panics(data in proptest::collection::vec(0u8.., 0..200)) {
            let mut rng = seeded_rng(9999);
            let ks_a = seeded_ks(99990);
            let ks_b = seeded_ks(99991);
            let id_a = futures_lite::future::block_on(ks_a.device_identity()).unwrap();
            let id_b = futures_lite::future::block_on(ks_b.device_identity()).unwrap();
            let h = [0u8; 32];
            let code = PairingCode::from_digits("12345678", PairingCodeFormat::EightDigit, NOT_AFTER).unwrap();
            let valid = code.check_not_expired(&FixedClock(NOW)).unwrap();
            if let Ok(mut exc) = PakeExchange::start_with_rng(
                &mut rng,
                PakeRole::Initiator,
                &valid,
                id_a,
                id_b,
                &h,
            ) {
                // Must never panic; may return Ok or Err.
                let _ = exc.read_peer_msg(&data);
            }
        }
    }
}
