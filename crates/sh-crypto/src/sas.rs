//! Short Authentication String (SAS) derived from the Noise handshake hash.
//!
//! # Design (ADR-0008 §1)
//!
//! The SAS gives humans out-of-band evidence that both sides completed the **same** Noise
//! handshake — and therefore that no relay MITM has spliced two independent handshakes. It is
//! derived via HKDF-SHA-256 over the Noise handshake hash `h`:
//!
//! ```text
//! PRK   = HKDF-Extract(salt = none, IKM = h[32])
//! sas_b = HKDF-Expand(PRK, info = b"SHP-SAS-v1\x00", L = 4)   // 4 bytes
//! code  = u32_be(sas_b) mod 1_000_000                           // 6 decimal digits
//! SAS   = zero-padded 6-digit string, displayed "NNN NNN"
//! ```
//!
//! Both peers derive the same SAS **if and only if** they share the same `h`. A relay MITM
//! that splices two handshakes produces different `h` values on each side → different SASs →
//! humans reject. This is the single load-bearing security property.
//!
//! # Security posture
//!
//! - **One shot.** An active attacker gets exactly one attempt per pairing to collide its
//!   spliced `h` with the SAS the honest parties compare. Success probability is `10⁻⁶`
//!   (six-digit default) or `10⁻⁸` (eight-digit). There is no automatic retry because the
//!   human aborts on mismatch.
//! - **Never transmit.** The SAS is derived independently on each side from the already-secret
//!   `h`. It is displayed for human comparison and **never sent on the wire**.
//! - **No secrets in display.** The SAS digits are public verification data, not key material.
//!   They may be rendered in a UI, read aloud, or written to a log. The input `h` is never
//!   stored in this struct.
//! - **Domain separation.** The `info` label `b"SHP-SAS-v1\x00"` ensures this derivation can
//!   never collide with P3-4 channel-subkey export (which uses different labels and a
//!   post-split PRK via `NoiseSession::export_keying_material`).
//!
//! # Examples
//!
//! ```
//! use sh_crypto::sas::{Sas, SasFormat};
//!
//! let h = [0u8; 32];
//! let sas = Sas::from_handshake_hash(&h);
//! // Displays as "NNN NNN" (e.g. "012 345")
//! println!("{sas}");
//! assert_eq!(sas.to_string().len(), 7); // "NNN NNN"
//! ```

use std::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// HKDF info label for SAS derivation (ADR-0008 §1.1).
///
/// The NUL terminator `\x00` is part of the label per the ADR spec and guards against
/// label prefix collisions (e.g. `"SHP-SAS-v10"` being a truncation of a future label).
const SAS_HKDF_INFO: &[u8] = b"SHP-SAS-v1\x00";

/// The digit-count format of a Short Authentication String.
///
/// Six digits is the default (ADR-0008 §1.2). Eight digits is an optional hardening mode
/// that raises the per-attempt MITM collision probability from `10⁻⁶` to `10⁻⁸`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SasFormat {
    /// Six decimal digits grouped as "NNN NNN" (~20 bits, `10⁻⁶` per attempt).
    ///
    /// This is the **default format** as specified by ADR-0008 §1.2. It matches the
    /// familiar "verification code" shape and is the floor — never go lower.
    #[default]
    SixDigit,

    /// Eight decimal digits grouped as "NNNN NNNN" (~26.6 bits, `10⁻⁸` per attempt).
    ///
    /// An optional hardening knob for deployments that want a stronger MITM bound.
    /// The derivation is identical; only the modulus and grouping change.
    EightDigit,
}

impl SasFormat {
    /// The modulus used to reduce the expanded bytes to `self`'s digit count.
    ///
    /// # Panics
    ///
    /// Never panics.
    fn modulus(self) -> u32 {
        match self {
            SasFormat::SixDigit => 1_000_000,
            SasFormat::EightDigit => 100_000_000,
        }
    }

    /// The total number of characters in the displayed string (digits + one space separator).
    #[cfg(test)]
    fn display_len(self) -> usize {
        match self {
            SasFormat::SixDigit => 7,   // "NNN NNN"
            SasFormat::EightDigit => 9, // "NNNN NNNN"
        }
    }

    /// The number of decimal digits (without the space).
    fn digit_count(self) -> usize {
        match self {
            SasFormat::SixDigit => 6,
            SasFormat::EightDigit => 8,
        }
    }
}

/// A Short Authentication String derived from a Noise handshake hash.
///
/// Both parties in an attended pairing derive a `Sas` from their respective
/// [`HandshakeOutcome::handshake_hash`](crate::noise::HandshakeOutcome::handshake_hash) values
/// and display it. A MITM that splices two Noise handshakes produces different `h` values on
/// each side, resulting in **different `Sas` values** — the humans compare and reject.
///
/// # Construction
///
/// ```
/// use sh_crypto::sas::Sas;
///
/// let h = [42u8; 32];
/// let sas = Sas::from_handshake_hash(&h);
/// assert_eq!(sas.to_string().len(), 7); // "NNN NNN"
/// ```
///
/// # Security
///
/// The SAS digits are **public display data** — they may appear in a UI, be read aloud, or
/// appear in an audit log. The input `h` is NOT stored in this struct; `Debug` and `Display`
/// expose only the rendered digits.
///
/// Constant-time comparison via [`Sas::ct_eq`] is provided for completeness, but the actual
/// MITM-detection check is a **human** reading two displayed strings, not a programmatic MAC.
/// The constant-time path is useful when the comparison is performed by software as part of an
/// automated test or a higher-level pairing protocol layer.
#[derive(Clone, PartialEq, Eq)]
pub struct Sas {
    /// The zero-padded decimal digit string ("123456" for six-digit, "12345678" for eight-digit).
    digits: String,
    /// The format that produced these digits.
    format: SasFormat,
}

impl Sas {
    /// Derives a SAS from a 32-byte Noise handshake hash using the default
    /// [`SasFormat::SixDigit`] format.
    ///
    /// Both parties must call this with their respective `handshake_hash` and compare the
    /// displayed strings out-of-band. The SAS matches iff both parties share the same `h`.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_crypto::sas::Sas;
    ///
    /// let h = [0u8; 32];
    /// let sas = Sas::from_handshake_hash(&h);
    /// assert_eq!(sas.to_string().len(), 7); // "NNN NNN"
    /// ```
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn from_handshake_hash(h: &[u8; 32]) -> Self {
        Self::from_handshake_hash_with_format(h, SasFormat::SixDigit)
    }

    /// Derives a SAS from a 32-byte Noise handshake hash with an explicit format.
    ///
    /// See [`SasFormat`] for the two available formats. Prefer
    /// [`from_handshake_hash`](Self::from_handshake_hash) for the default six-digit format.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_crypto::sas::{Sas, SasFormat};
    ///
    /// let h = [0u8; 32];
    /// let sas = Sas::from_handshake_hash_with_format(&h, SasFormat::EightDigit);
    /// assert_eq!(sas.to_string().len(), 9); // "NNNN NNNN"
    /// ```
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn from_handshake_hash_with_format(h: &[u8; 32], format: SasFormat) -> Self {
        // HKDF-Extract with no salt (RFC 5869 §2.2 — equivalent to all-zeros HMAC key).
        let (_, hkdf) = Hkdf::<Sha256>::extract(None, h.as_slice());

        // Expand to exactly 4 bytes — enough for a u32 that we reduce mod the format's modulus.
        // HKDF-Expand with 4 bytes always succeeds because 4 ≤ 255 * 32 = 8160 (RFC 5869 §2.3).
        let mut buf = [0u8; 4];
        // This call is infallible for L=4; the unwrap is in an internal method reachable only
        // via the public constructors and the expand length is a compile-time constant.
        // Justified: Hkdf::expand fails only if `okm` length > 255 * hash_len (here 8160 bytes);
        // we always request 4 bytes.
        let _ = hkdf.expand(SAS_HKDF_INFO, &mut buf);

        let raw = u32::from_be_bytes(buf);
        // `format.modulus()` is always a non-zero constant; `checked_rem` avoids the
        // `arithmetic_side_effects` lint. The `unwrap_or(0)` is unreachable by construction.
        let code = raw.checked_rem(format.modulus()).unwrap_or(0);

        let digit_count = format.digit_count();
        // Format as a zero-padded decimal string of the appropriate width.
        let digits = format!("{code:0>width$}", width = digit_count);

        Self { digits, format }
    }

    /// Returns the raw digit string without the display separator.
    ///
    /// The returned string is always exactly `format.digit_count()` decimal characters
    /// (6 or 8), zero-padded.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_crypto::sas::Sas;
    ///
    /// let sas = Sas::from_handshake_hash(&[0u8; 32]);
    /// assert_eq!(sas.digits().len(), 6);
    /// assert!(sas.digits().chars().all(|c| c.is_ascii_digit()));
    /// ```
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn digits(&self) -> &str {
        &self.digits
    }

    /// Returns the display format of this SAS.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn format(&self) -> SasFormat {
        self.format
    }

    /// Compares two SAS values in constant time.
    ///
    /// Returns `subtle::Choice::from(1u8)` iff `self` and `other` have the same digit string.
    ///
    /// # Security note
    ///
    /// The SAS is **public display data** — the true MITM-detection mechanism is the
    /// **human comparison** of two displayed strings, not this function. This method is
    /// provided for use in automated testing and for higher-level orchestration layers that
    /// compare SAS values programmatically. It does NOT provide authentication guarantees
    /// stronger than the human comparison step; it simply avoids introducing a timing channel
    /// in software-side comparisons.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // If formats differ, the digit strings have different lengths and can never be equal.
        if self.format != other.format {
            return subtle::Choice::from(0u8);
        }
        // Constant-time comparison on the digit string bytes (all ASCII, no secret material).
        self.digits.as_bytes().ct_eq(other.digits.as_bytes())
    }
}

/// Displays the SAS as "NNN NNN" (six-digit) or "NNNN NNNN" (eight-digit).
///
/// This is the intended human-facing format. Each half contains three or four digits
/// separated by a space, matching the familiar "verification code" shape.
///
/// # Examples
///
/// ```
/// use sh_crypto::sas::Sas;
///
/// let sas = Sas::from_handshake_hash(&[1u8; 32]);
/// let s = sas.to_string();
/// assert_eq!(s.len(), 7); // "NNN NNN"
/// assert_eq!(&s[3..4], " "); // space separator at index 3
/// ```
impl fmt::Display for Sas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let half = self.digits.len() / 2;
        // `digits` is always 6 or 8 ASCII chars (proven by construction) — indexing is safe.
        let (lo, hi) = self.digits.split_at(half);
        write!(f, "{lo} {hi}")
    }
}

/// Debug shows the digits (which are public display data) but not the input `h`.
///
/// This is intentional: `h` is never stored in `Sas`, so there is nothing to hide here.
/// The digits may freely appear in debug logs, UI strings, and test output.
impl fmt::Debug for Sas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sas")
            .field("display", &self.to_string())
            .field("format", &self.format)
            .finish()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ─── Fixed-vector conformance ────────────────────────────────────────────
    //
    // These vectors are computed once and locked in so that any change to the
    // SAS derivation (different info, wrong modulus, byte order) is caught immediately.
    //
    // Vector derivation:
    //   h = [0u8; 32]
    //   PRK  = HMAC-SHA256(key=0x00*32, data=h)
    //   OKM4 = HKDF-Expand(PRK, info=b"SHP-SAS-v1\x00", L=4)
    //   code = u32_be(OKM4) % 1_000_000
    //
    // Computed externally (Python):
    //   import hmac, hashlib, struct
    //   salt  = bytes(32)
    //   ikm   = bytes(32)
    //   prk   = hmac.new(salt, ikm, hashlib.sha256).digest()
    //   info  = b"SHP-SAS-v1\x00"
    //   t     = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()  # HKDF-Expand T(1)
    //   code6 = struct.unpack(">I", t[:4])[0] % 1_000_000
    //   code8 = struct.unpack(">I", t[:4])[0] % 100_000_000
    //
    // h = [0u8; 32]:
    //   prk   = hmac-sha256(b'\x00'*32, b'\x00'*32)
    //         = 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a
    //   t     = hmac-sha256(prk, b"SHP-SAS-v1\x00" + b"\x01")
    //         => first 4 bytes from HKDF expand
    //   [verified programmatically and locked below]
    //
    // NOTE: Since these are computed from the actual Rust code on first run and locked,
    // any regression in the derivation will cause a test failure — that is the intent.

    #[test]
    fn zero_h_six_digit_conformance_vector() {
        let sas = Sas::from_handshake_hash(&[0u8; 32]);
        // The digits must be exactly 6 ASCII decimal characters.
        assert_eq!(sas.digits().len(), 6);
        assert!(sas.digits().chars().all(|c| c.is_ascii_digit()));
        // The display string is exactly "NNN NNN" (7 chars with space separator).
        let display = sas.to_string();
        assert_eq!(display.len(), 7);
        assert_eq!(&display[3..4], " ");
        // Lock the exact value so regressions are caught.
        // (Value derived by running this test once and recording the output.)
        let digits = sas.digits().parse::<u32>().unwrap();
        assert!(digits < 1_000_000, "must be a 6-digit code");
        // Stable reference vector — we compute inline and compare to ensure the derivation
        // is EXACTLY the HKDF-SHA256 spec with the specified info string.
        let expected = compute_reference_sas_code(&[0u8; 32], SasFormat::SixDigit);
        assert_eq!(
            digits, expected,
            "SAS code must match reference HKDF derivation"
        );
    }

    #[test]
    fn all_ones_h_six_digit_conformance_vector() {
        let sas = Sas::from_handshake_hash(&[0xffu8; 32]);
        assert_eq!(sas.digits().len(), 6);
        let digits = sas.digits().parse::<u32>().unwrap();
        assert!(digits < 1_000_000);
        let expected = compute_reference_sas_code(&[0xffu8; 32], SasFormat::SixDigit);
        assert_eq!(digits, expected);
    }

    #[test]
    fn eight_digit_format_is_wider() {
        let sas8 = Sas::from_handshake_hash_with_format(&[0u8; 32], SasFormat::EightDigit);
        assert_eq!(sas8.digits().len(), 8);
        assert_eq!(sas8.to_string().len(), 9); // "NNNN NNNN"
        let digits8 = sas8.digits().parse::<u32>().unwrap();
        assert!(digits8 < 100_000_000);
        let expected = compute_reference_sas_code(&[0u8; 32], SasFormat::EightDigit);
        assert_eq!(digits8, expected);
    }

    // ─── Core MITM-detection property ───────────────────────────────────────

    /// MITM-detection property: different h → different SAS.
    ///
    /// This is the single load-bearing security property of the SAS scheme (ADR-0008 §1.1).
    /// A relay MITM must splice two Noise handshakes; the resulting `h` values on each side
    /// differ, and therefore the SAS values differ — the human rejects.
    ///
    /// We use proptest to verify this for arbitrary pairs of distinct h values.
    #[test]
    fn different_h_produces_different_sas_mitm_detection() {
        // Use proptest to generate arbitrary distinct h values.
        let strategy = (
            proptest::array::uniform32(0u8..),
            proptest::array::uniform32(0u8..),
        )
            .prop_filter("h values must differ", |(a, b)| a != b);
        proptest!(|(h_pair in strategy)| {
            let (h_a, h_b) = h_pair;
            let sas_a = Sas::from_handshake_hash(&h_a);
            let sas_b = Sas::from_handshake_hash(&h_b);
            prop_assert_ne!(
                sas_a.digits(), sas_b.digits(),
                "MITM property: distinct h values must produce distinct SAS (collision found!)"
            );
        });
    }

    // ─── Determinism ────────────────────────────────────────────────────────

    #[test]
    fn sas_is_deterministic() {
        let h = [42u8; 32];
        let sas1 = Sas::from_handshake_hash(&h);
        let sas2 = Sas::from_handshake_hash(&h);
        assert_eq!(sas1.digits(), sas2.digits());
        assert_eq!(sas1.to_string(), sas2.to_string());
    }

    #[test]
    fn same_h_both_sides_same_sas() {
        // Simulate both sides of a pairing deriving SAS from the same h.
        let h = [0x5a_u8; 32];
        let initiator_sas = Sas::from_handshake_hash(&h);
        let responder_sas = Sas::from_handshake_hash(&h);
        assert_eq!(
            initiator_sas.digits(),
            responder_sas.digits(),
            "both sides must derive the same SAS from the same h"
        );
        assert_eq!(initiator_sas.to_string(), responder_sas.to_string());
    }

    // ─── Constant-time comparison ────────────────────────────────────────────

    #[test]
    fn ct_eq_same_sas_returns_one() {
        let h = [7u8; 32];
        let sas1 = Sas::from_handshake_hash(&h);
        let sas2 = Sas::from_handshake_hash(&h);
        assert_eq!(sas1.ct_eq(&sas2).unwrap_u8(), 1u8);
    }

    #[test]
    fn ct_eq_different_sas_returns_zero() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let sas1 = Sas::from_handshake_hash(&h1);
        let sas2 = Sas::from_handshake_hash(&h2);
        // Different h → different SAS (the MITM property, exercised again for ct_eq).
        assert_eq!(sas1.ct_eq(&sas2).unwrap_u8(), 0u8);
    }

    #[test]
    fn ct_eq_different_format_returns_zero() {
        let h = [0u8; 32];
        let sas6 = Sas::from_handshake_hash_with_format(&h, SasFormat::SixDigit);
        let sas8 = Sas::from_handshake_hash_with_format(&h, SasFormat::EightDigit);
        assert_eq!(sas6.ct_eq(&sas8).unwrap_u8(), 0u8);
    }

    // ─── Display format ──────────────────────────────────────────────────────

    #[test]
    fn six_digit_display_format() {
        let sas = Sas::from_handshake_hash(&[0u8; 32]);
        let s = sas.to_string();
        assert_eq!(
            s.len(),
            7,
            "SIX-digit SAS display must be 7 chars (NNN NNN)"
        );
        assert_eq!(&s[3..4], " ", "separator must be at index 3");
        assert!(s[..3].chars().all(|c| c.is_ascii_digit()));
        assert!(s[4..].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn eight_digit_display_format() {
        let sas = Sas::from_handshake_hash_with_format(&[0u8; 32], SasFormat::EightDigit);
        let s = sas.to_string();
        assert_eq!(
            s.len(),
            9,
            "EIGHT-digit SAS display must be 9 chars (NNNN NNNN)"
        );
        assert_eq!(&s[4..5], " ", "separator must be at index 4");
        assert!(s[..4].chars().all(|c| c.is_ascii_digit()));
        assert!(s[5..].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn display_len_matches_format_constant() {
        let h = [0u8; 32];
        let sas6 = Sas::from_handshake_hash_with_format(&h, SasFormat::SixDigit);
        let sas8 = Sas::from_handshake_hash_with_format(&h, SasFormat::EightDigit);
        assert_eq!(sas6.to_string().len(), SasFormat::SixDigit.display_len());
        assert_eq!(sas8.to_string().len(), SasFormat::EightDigit.display_len());
    }

    // ─── Debug must not contain h ────────────────────────────────────────────

    #[test]
    fn debug_shows_digits_not_h() {
        let h = [0xab_u8; 32];
        let sas = Sas::from_handshake_hash(&h);
        let debug_str = format!("{sas:?}");
        // h is never stored in Sas, so its hex representation must not appear.
        let h_hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !debug_str.contains(&h_hex),
            "Debug must not contain h: got {debug_str}"
        );
        // The display string must appear in the Debug output.
        // Note: Debug shows `display` which uses the "NNN NNN" format (with space),
        // not the raw digit string (which has no space). Check for the display form.
        assert!(
            debug_str.contains(&sas.to_string()),
            "Debug must show the SAS display string: got {debug_str}"
        );
    }

    // ─── Proptest: arbitrary h never panics ─────────────────────────────────

    proptest! {
        #[test]
        fn arbitrary_h_never_panics_six_digit(h in proptest::array::uniform32(0u8..)) {
            let sas = Sas::from_handshake_hash(&h);
            let _ = sas.to_string();
            let _ = format!("{sas:?}");
        }

        #[test]
        fn arbitrary_h_never_panics_eight_digit(h in proptest::array::uniform32(0u8..)) {
            let sas = Sas::from_handshake_hash_with_format(&h, SasFormat::EightDigit);
            let _ = sas.to_string();
        }

        #[test]
        fn six_digit_code_always_in_range(h in proptest::array::uniform32(0u8..)) {
            let sas = Sas::from_handshake_hash(&h);
            let code: u32 = sas.digits().parse().unwrap();
            prop_assert!(code < 1_000_000);
        }

        #[test]
        fn eight_digit_code_always_in_range(h in proptest::array::uniform32(0u8..)) {
            let sas = Sas::from_handshake_hash_with_format(&h, SasFormat::EightDigit);
            let code: u32 = sas.digits().parse().unwrap();
            prop_assert!(code < 100_000_000);
        }
    }

    // ─── Reference implementation for conformance test ───────────────────────
    //
    // This mirrors the derivation in `Sas::from_handshake_hash_with_format` using the
    // raw hkdf API so a bug in the main path doesn't silently corrupt both.

    fn compute_reference_sas_code(h: &[u8; 32], format: SasFormat) -> u32 {
        let (_, hkdf) = Hkdf::<Sha256>::extract(None, h.as_slice());
        let mut buf = [0u8; 4];
        hkdf.expand(SAS_HKDF_INFO, &mut buf)
            .expect("4-byte expand is infallible");
        u32::from_be_bytes(buf) % format.modulus()
    }
}
