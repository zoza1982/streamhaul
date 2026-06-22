//! Codec capability offer/answer wire framing (LLD §3.1 capability handshake / §3.2 wire layout,
//! P2-5).
//!
//! This module provides a compact binary format for advertising which codecs each endpoint can
//! hardware-encode, hardware-decode, and whether software H.264 encoding is available.  The frames
//! are carried as the payload of a [`ControlFrame`](crate::ControlFrame) with
//! [`KIND_CODEC_CAPS_OFFER`] or [`KIND_CODEC_CAPS_ANSWER`].
//!
//! ## Wire format — `CodecCapsPayload` (4 bytes, fixed)
//!
//! ```text
//! BYTE 0:  HW_ENCODE_MASK   (u8 bitmask of Codec discriminants the encoder supports in HW)
//!                            bits 0–2 are valid codec bits (H264=0, H265=1, AV1=2).
//!                            bits 3–7 are RESERVED and MUST be 0; rejected on decode.
//! BYTE 1:  HW_DECODE_MASK   (u8 bitmask of Codec discriminants the decoder supports in HW)
//!                            Same bit layout and reserved-bit rules as HW_ENCODE_MASK.
//! BYTE 2:  FLAGS             bit 0 = sw_h264_encode_available
//!                            bit 1 = is_apple   (VideoToolbox host — no AV1 encode)
//!                            bit 2 = is_browser  (always offers H.264 decode)
//!                            bits 3–7 = RESERVED (must be 0; rejected on decode)
//! BYTE 3:  SELECTED_CODEC   (Codec discriminant of the negotiated codec; 0xFF = none/offer)
//!                            Valid values: 0 (H264), 1 (H265/HEVC), 2 (AV1), 0xFF (none).
//!                            Any other value is rejected on decode.
//! ```
//!
//! Total: **4 bytes** ([`CODEC_CAPS_LEN`]).  All fields are mandatory; truncated input is
//! rejected.
//!
//! ## Codec discriminants
//!
//! Matching [`crate::Codec`] wire encoding in [`VideoHeader`](crate::VideoHeader):
//! - `0` ([`CODEC_DISC_H264`]) = H264
//! - `1` ([`CODEC_DISC_H265`]) = H265 (HEVC) — only set in `hw_encode_mask` by commercial builds
//!   with the `hevc` Cargo feature; OSS builds may receive it in a peer's offer/answer (decode only)
//! - `2` ([`CODEC_DISC_AV1`])  = AV1
//! - `3` = Raw (NOT a negotiable codec; bit 3 in HW_ENCODE_MASK / HW_DECODE_MASK must be 0)
//! - `4–254` = reserved; rejected on decode
//!
//! ## Reserved bits in codec masks
//!
//! HW_ENCODE_MASK and HW_DECODE_MASK bits 3–7 are reserved and must be zero.  [`decode_caps`]
//! rejects any mask with `mask & 0b1111_1000 != 0` with [`ProtocolError::ReservedBitsSet`], which
//! also covers the Raw-codec bit (bit 3).
//!
//! ## BuildFlavor ↔ `hevc` feature mapping
//!
//! The `hevc` Cargo feature (in `sh-codec-hw`) is the single compile-time gate for HEVC.  When
//! the feature is **OFF** (OSS / Apache-2.0 build), `BuildFlavor::from_compile_time()` returns
//! `BuildFlavor::Oss` and the negotiation ladder never contains `Codec::H265`, regardless of what
//! the remote peer advertises.  When the feature is **ON** (commercial build), `BuildFlavor::
//! Commercial` is used and H265 appears at the top of the candidate ladder.
//!
//! Importantly, [`decode_caps`] deliberately does **not** reject `CODEC_DISC_H265` in the
//! `selected_codec` field regardless of build flavor.  This preserves OSS ↔ commercial
//! interoperability parsing: an OSS peer must be able to parse a commercial peer's answer that
//! selects H265.  The encode-side gate is purely local and enforced by `BuildFlavor`.
//!
//! **INVARIANT for session handlers:** After calling [`decode_caps`] and obtaining
//! `selected_codec == Some(CODEC_DISC_H265)`, a session handler MUST check `BuildFlavor::
//! from_compile_time()` and reject the session with an appropriate error if it returns `Oss`.
//! The local H265 encoder does not exist in an OSS build.  (Do not add a `#[cfg]` rejection
//! inside `decode_caps` itself — that would break parsing of commercial peers' answers.)
//!
//! ## Security note
//!
//! The decoder treats all input as hostile: it bounds-checks every field and never panics.  The
//! `shp_decode` cargo-fuzz target exercises this decoder (and the whole `sh-protocol` decode
//! surface) on arbitrary bytes.
//!
//! ## Usage
//!
//! Build an offer on the initiating side:
//!
//! ```
//! use sh_protocol::capability::{CodecCapsPayload, encode_caps, KIND_CODEC_CAPS_OFFER};
//! use sh_protocol::encode_control;
//!
//! let payload = CodecCapsPayload {
//!     hw_encode_mask: 0b0100,  // AV1 HW encode
//!     hw_decode_mask: 0b0101,  // H264 + AV1 HW decode
//!     sw_h264_encode_available: true,
//!     is_apple: false,
//!     is_browser: false,
//!     selected_codec: None,
//! };
//! let bytes = encode_caps(&payload).unwrap();
//! let frame = encode_control(KIND_CODEC_CAPS_OFFER, &bytes).unwrap();
//! ```

use crate::error::ProtocolError;

// ── Control frame kind bytes ──────────────────────────────────────────────────

/// `ControlFrame::kind` byte for a codec capability **offer** (initiator → responder).
pub const KIND_CODEC_CAPS_OFFER: u8 = 0x10;

/// `ControlFrame::kind` byte for a codec capability **answer** (responder → initiator).
///
/// The answer carries the same fields as the offer but with `selected_codec` set to the
/// negotiated codec (or `None` / `0xFF` when no intersection exists).
pub const KIND_CODEC_CAPS_ANSWER: u8 = 0x11;

// ── Wire constants ────────────────────────────────────────────────────────────

/// Wire length of a serialized [`CodecCapsPayload`] (bytes).
pub const CODEC_CAPS_LEN: usize = 4;

/// Sentinel value for `SELECTED_CODEC` meaning "no codec selected / this is an offer".
const NO_CODEC_SENTINEL: u8 = 0xFF;

// Bitmask positions within BYTE 2 (FLAGS).
const FLAG_SW_H264: u8 = 0b0000_0001;
const FLAG_IS_APPLE: u8 = 0b0000_0010;
const FLAG_IS_BROWSER: u8 = 0b0000_0100;
const FLAGS_RESERVED_MASK: u8 = 0b1111_1000;

// Bits 3–7 of the codec HW encode/decode masks are reserved and must be zero.
// Bit 3 corresponds to Codec::Raw (discriminant 3), which is not a negotiable codec.
// Bits 4–7 are undefined; rejecting them keeps the format unambiguous for future use.
const CODEC_MASK_RESERVED: u8 = 0b1111_1000;

// ── Codec discriminant helpers ────────────────────────────────────────────────

/// H.264 discriminant (matches `Codec::H264` wire encoding).
pub const CODEC_DISC_H264: u8 = 0;
/// H.265 / HEVC discriminant (matches `Codec::H265` wire encoding).
///
/// Only set in codec masks when the `hevc` Cargo feature is enabled in `sh-codec-hw`.
/// This crate exposes the constant unconditionally so the decoder can validate/round-trip it
/// regardless of build flavor; the `sh-codec-hw` negotiator gates whether it enters a *ladder*.
pub const CODEC_DISC_H265: u8 = 1;
/// AV1 discriminant (matches `Codec::Av1` wire encoding).
pub const CODEC_DISC_AV1: u8 = 2;

// ── Data model ────────────────────────────────────────────────────────────────

/// A decoded codec capability payload, exchanged during the capability handshake.
///
/// Each field mirrors a wire byte or flag; see the [module-level docs](self) for the exact layout.
///
/// # Examples
///
/// ```
/// use sh_protocol::capability::{CodecCapsPayload, encode_caps, decode_caps};
///
/// let payload = CodecCapsPayload {
///     hw_encode_mask: 0b0100,   // AV1
///     hw_decode_mask: 0b0101,   // H264 + AV1
///     sw_h264_encode_available: true,
///     is_apple: false,
///     is_browser: false,
///     selected_codec: None,
/// };
/// let bytes = encode_caps(&payload).unwrap();
/// assert_eq!(decode_caps(&bytes), Ok(payload));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecCapsPayload {
    /// Bitmask of codec discriminants this endpoint can **hardware-encode**.
    ///
    /// Bit `n` = 1 means codec with discriminant `n` is HW-encode capable.
    /// Bit 3 (Raw) must always be 0 — Raw is not a negotiable codec.
    pub hw_encode_mask: u8,

    /// Bitmask of codec discriminants this endpoint can **hardware-decode**.
    ///
    /// Bit `n` = 1 means codec with discriminant `n` is HW-decode capable.
    /// Bit 3 (Raw) must always be 0.
    pub hw_decode_mask: u8,

    /// Whether this endpoint can encode H.264 in software (CPU, last resort).
    ///
    /// Software H.264 encode is the final rung of the OSS Game-mode ladder.
    /// Work mode never sets this — Work never software-encodes.
    pub sw_h264_encode_available: bool,

    /// Whether this host is an Apple device (VideoToolbox).
    ///
    /// Apple VideoToolbox has no AV1 *encode*, so AV1 is excluded from the encode ladder when
    /// this flag is set, regardless of `hw_encode_mask`.  The negotiator in `sh-codec-hw` uses
    /// this flag rather than hard-coding a platform check, keeping the logic data-driven.
    pub is_apple: bool,

    /// Whether this peer is a browser.
    ///
    /// Browsers always support H.264 decode via their native WebRTC stack.  When this flag is
    /// set the negotiator guarantees H.264 remains reachable in the ladder even if
    /// `hw_decode_mask` does not explicitly advertise it.
    pub is_browser: bool,

    /// The negotiated codec chosen by the responder, or `None` for an offer / empty intersection.
    ///
    /// `Some(disc)` in an answer means the responder selected the codec with that discriminant.
    /// `None` on an offer (use [`encode_caps`] which writes `0xFF`).
    /// `None` on an answer means no mutually supported codec was found.
    pub selected_codec: Option<u8>,
}

// ── Encode / decode ───────────────────────────────────────────────────────────

/// Serialize a [`CodecCapsPayload`] to its 4-byte wire form.
///
/// Returns `Ok([u8; CODEC_CAPS_LEN])` on success.
///
/// # Errors
///
/// - [`ProtocolError::ReservedBitsSet`] — `hw_encode_mask` or `hw_decode_mask` have reserved bits
///   set (bits 3–7).
/// - [`ProtocolError::InvalidCodec`] — `selected_codec` is `Some(disc)` where `disc` is not a
///   recognized, non-Raw codec discriminant (`0`=H264, `1`=H265, `2`=AV1).  Raw (3) and unknown
///   values are rejected so that `encode_caps` and `decode_caps` accept exactly the same value set.
///
/// # Examples
///
/// ```
/// use sh_protocol::capability::{encode_caps, CodecCapsPayload, CODEC_CAPS_LEN};
///
/// let payload = CodecCapsPayload {
///     hw_encode_mask: 0x04,
///     hw_decode_mask: 0x05,
///     sw_h264_encode_available: false,
///     is_apple: true,
///     is_browser: false,
///     selected_codec: None,
/// };
/// let bytes = encode_caps(&payload).unwrap();
/// assert_eq!(bytes.len(), CODEC_CAPS_LEN);
/// ```
pub fn encode_caps(payload: &CodecCapsPayload) -> Result<[u8; CODEC_CAPS_LEN], ProtocolError> {
    // Reject reserved bits in codec masks (bits 3–7).  This mirrors the decode-side check and
    // ensures encode and decode accept exactly the same value set.
    if (payload.hw_encode_mask & CODEC_MASK_RESERVED) != 0 {
        return Err(ProtocolError::ReservedBitsSet);
    }
    if (payload.hw_decode_mask & CODEC_MASK_RESERVED) != 0 {
        return Err(ProtocolError::ReservedBitsSet);
    }

    // Validate selected_codec: only H264 (0), H265 (1), AV1 (2), or None (→ 0xFF) are valid.
    // Raw (3) and any unknown value are rejected so that callers cannot accidentally emit a value
    // that decode_caps would reject, ensuring encode/decode symmetry.
    let selected = match payload.selected_codec {
        None => NO_CODEC_SENTINEL,
        Some(n @ (CODEC_DISC_H264 | CODEC_DISC_H265 | CODEC_DISC_AV1)) => n,
        Some(other) => return Err(ProtocolError::InvalidCodec(other)),
    };

    let mut flags: u8 = 0;
    if payload.sw_h264_encode_available {
        flags |= FLAG_SW_H264;
    }
    if payload.is_apple {
        flags |= FLAG_IS_APPLE;
    }
    if payload.is_browser {
        flags |= FLAG_IS_BROWSER;
    }

    Ok([
        payload.hw_encode_mask,
        payload.hw_decode_mask,
        flags,
        selected,
    ])
}

/// Parse a [`CodecCapsPayload`] from a 4-byte wire buffer.
///
/// Never panics.  Rejects:
/// - Truncated input (fewer than [`CODEC_CAPS_LEN`] bytes).
/// - Reserved bits set in the FLAGS byte (bits 3–7 must be 0).
/// - Reserved bits set in `hw_encode_mask` or `hw_decode_mask` (bits 3–7 must be 0).
///   This covers the Raw-codec bit (bit 3 = discriminant 3) as well as bits 4–7 which are
///   currently undefined.  Consistent strict rejection keeps the format unambiguous and hostile
///   input from smuggling unknown values that would be silently re-emitted.
/// - `selected_codec` discriminants that are not a recognized, non-Raw codec
///   (values other than 0=H264, 1=H265, 2=AV1, and 0xFF=none/offer are rejected).
///
/// **Note on H265 acceptance:** `decode_caps` accepts `CODEC_DISC_H265` (1) as a valid
/// `selected_codec` value regardless of build flavor (OSS or commercial).  This is intentional:
/// an OSS peer must be able to parse a commercial peer's answer without error to implement proper
/// OSS↔commercial interoperability.  The encode-side gate is enforced locally by `BuildFlavor` in
/// `sh-codec-hw`; see the module-level `INVARIANT` note for how session handlers must handle this.
///
/// # Errors
///
/// - [`ProtocolError::Truncated`] — fewer than 4 bytes.
/// - [`ProtocolError::ReservedBitsSet`] — reserved bits are non-zero in FLAGS or codec masks.
/// - [`ProtocolError::InvalidCodec`] — `selected_codec` holds an unrecognized discriminant.
///
/// # Examples
///
/// ```
/// use sh_protocol::capability::{decode_caps, CodecCapsPayload};
/// use sh_protocol::ProtocolError;
///
/// // Truncated input.
/// assert_eq!(decode_caps(&[0, 0, 0]), Err(ProtocolError::Truncated { needed: 4, have: 3 }));
///
/// // Reserved bits set in FLAGS byte.
/// assert_eq!(
///     decode_caps(&[0, 0, 0b1000_0000, 0xFF]),
///     Err(ProtocolError::ReservedBitsSet),
/// );
///
/// // Reserved bits set in hw_encode_mask (bits 3–7).
/// assert_eq!(
///     decode_caps(&[0b1111_0000, 0, 0, 0xFF]),
///     Err(ProtocolError::ReservedBitsSet),
/// );
///
/// // Unknown selected_codec (not H264=0, H265=1, AV1=2, or sentinel=0xFF).
/// assert_eq!(
///     decode_caps(&[0, 0, 0, 0x05]),
///     Err(ProtocolError::InvalidCodec(5)),
/// );
/// ```
pub fn decode_caps(data: &[u8]) -> Result<CodecCapsPayload, ProtocolError> {
    use crate::bits::take_array;
    let [hw_encode_mask, hw_decode_mask, flags, selected_raw] = take_array::<CODEC_CAPS_LEN>(data)?;

    // Reserved flag bits (bits 3–7) must be zero.
    if (flags & FLAGS_RESERVED_MASK) != 0 {
        return Err(ProtocolError::ReservedBitsSet);
    }

    // Reserved bits in codec masks (bits 3–7) must be zero.  Bit 3 corresponds to Codec::Raw
    // (discriminant 3), which is not a negotiable codec.  Bits 4–7 are undefined.  Rejecting all
    // of them together is consistent with the FLAGS handling and prevents hostile input from
    // carrying bits that `encode_caps` would silently re-emit.
    if (hw_encode_mask & CODEC_MASK_RESERVED) != 0 || (hw_decode_mask & CODEC_MASK_RESERVED) != 0 {
        return Err(ProtocolError::ReservedBitsSet);
    }

    // Validate selected_codec.  H265 (1) is accepted unconditionally so that an OSS build can
    // parse a commercial peer's answer; the session handler is responsible for rejecting H265 as
    // a local encode target in an OSS build (see module-level INVARIANT note).
    let selected_codec = match selected_raw {
        NO_CODEC_SENTINEL => None,
        // H264 (0), H265 (1), AV1 (2) are valid codec discriminants.
        n @ (CODEC_DISC_H264 | CODEC_DISC_H265 | CODEC_DISC_AV1) => Some(n),
        other => return Err(ProtocolError::InvalidCodec(other)),
    };

    Ok(CodecCapsPayload {
        hw_encode_mask,
        hw_decode_mask,
        sw_h264_encode_available: (flags & FLAG_SW_H264) != 0,
        is_apple: (flags & FLAG_IS_APPLE) != 0,
        is_browser: (flags & FLAG_IS_BROWSER) != 0,
        selected_codec,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn all_flags_payload() -> CodecCapsPayload {
        CodecCapsPayload {
            hw_encode_mask: 0b0000_0110, // AV1 + H265 (bits 2 + 1)
            hw_decode_mask: 0b0000_0111, // H264 + H265 + AV1 (bits 0..2)
            sw_h264_encode_available: true,
            is_apple: true,
            is_browser: false,
            selected_codec: Some(CODEC_DISC_AV1),
        }
    }

    #[test]
    fn roundtrip_all_flags() {
        let p = all_flags_payload();
        assert_eq!(decode_caps(&encode_caps(&p).unwrap()), Ok(p));
    }

    #[test]
    fn roundtrip_no_selected_codec() {
        let p = CodecCapsPayload {
            hw_encode_mask: 0b0000_0100, // AV1
            hw_decode_mask: 0b0000_0001, // H264
            sw_h264_encode_available: false,
            is_apple: false,
            is_browser: true,
            selected_codec: None,
        };
        assert_eq!(decode_caps(&encode_caps(&p).unwrap()), Ok(p));
    }

    #[test]
    fn roundtrip_selected_h264() {
        let p = CodecCapsPayload {
            hw_encode_mask: 0,
            hw_decode_mask: 0b0000_0001,
            sw_h264_encode_available: true,
            is_apple: false,
            is_browser: true,
            selected_codec: Some(CODEC_DISC_H264),
        };
        assert_eq!(decode_caps(&encode_caps(&p).unwrap()), Ok(p));
    }

    #[test]
    fn decode_rejects_truncated() {
        assert_eq!(
            decode_caps(&[0, 0, 0]),
            Err(ProtocolError::Truncated { needed: 4, have: 3 })
        );
        assert_eq!(
            decode_caps(&[]),
            Err(ProtocolError::Truncated { needed: 4, have: 0 })
        );
    }

    #[test]
    fn decode_rejects_reserved_flag_bits() {
        // Each reserved flag bit (3..7) independently rejected.
        for bit in 3u8..=7 {
            let flags = 1u8 << bit;
            assert_eq!(
                decode_caps(&[0, 0, flags, 0xFF]),
                Err(ProtocolError::ReservedBitsSet),
                "flag bit {bit} should be rejected"
            );
        }
    }

    #[test]
    fn decode_rejects_reserved_bits_in_codec_masks() {
        // Bits 3–7 in hw_encode_mask must all be rejected (covers Raw at bit 3 plus bits 4–7).
        for bit in 3u8..=7 {
            let mask = 1u8 << bit;
            assert_eq!(
                decode_caps(&[mask, 0, 0, 0xFF]),
                Err(ProtocolError::ReservedBitsSet),
                "hw_encode_mask bit {bit} should be rejected"
            );
            assert_eq!(
                decode_caps(&[0, mask, 0, 0xFF]),
                Err(ProtocolError::ReservedBitsSet),
                "hw_decode_mask bit {bit} should be rejected"
            );
        }
        // Hostile input: upper nibble set (all reserved bits 4–7 simultaneously).
        assert_eq!(
            decode_caps(&[0b1111_0000, 0, 0, 0xFF]),
            Err(ProtocolError::ReservedBitsSet),
            "hw_encode_mask 0b1111_0000 should be rejected"
        );
    }

    #[test]
    fn decode_rejects_unknown_selected_codec() {
        // Include discriminant 3 (Raw) which encode_caps would also reject, plus other unknowns.
        for bad in [3u8, 4, 5, 10, 127, 254] {
            assert_eq!(
                decode_caps(&[0, 0, 0, bad]),
                Err(ProtocolError::InvalidCodec(bad)),
                "codec discriminant {bad} should be rejected"
            );
        }
    }

    #[test]
    fn encode_rejects_raw_as_selected_codec() {
        // encode_caps must reject selected_codec = Some(3) (Raw) just as decode_caps does.
        let p = CodecCapsPayload {
            hw_encode_mask: 0,
            hw_decode_mask: 0,
            sw_h264_encode_available: false,
            is_apple: false,
            is_browser: false,
            selected_codec: Some(3), // Raw
        };
        assert_eq!(encode_caps(&p), Err(ProtocolError::InvalidCodec(3)));
    }

    #[test]
    fn encode_rejects_unknown_selected_codec() {
        for bad in [4u8, 5, 10, 127, 254] {
            let p = CodecCapsPayload {
                hw_encode_mask: 0,
                hw_decode_mask: 0,
                sw_h264_encode_available: false,
                is_apple: false,
                is_browser: false,
                selected_codec: Some(bad),
            };
            assert_eq!(
                encode_caps(&p),
                Err(ProtocolError::InvalidCodec(bad)),
                "encode_caps should reject unknown selected_codec {bad}"
            );
        }
    }

    #[test]
    fn encode_rejects_reserved_bits_in_masks() {
        // encode_caps must reject masks with bits 3–7 set (symmetric with decode_caps).
        let p = CodecCapsPayload {
            hw_encode_mask: 0b1111_0000, // bits 4–7 set
            hw_decode_mask: 0,
            sw_h264_encode_available: false,
            is_apple: false,
            is_browser: false,
            selected_codec: None,
        };
        assert_eq!(encode_caps(&p), Err(ProtocolError::ReservedBitsSet));

        let p2 = CodecCapsPayload {
            hw_encode_mask: 0,
            hw_decode_mask: 0b0000_1000, // bit 3 (Raw) set
            ..p
        };
        assert_eq!(encode_caps(&p2), Err(ProtocolError::ReservedBitsSet));
    }

    #[test]
    fn sentinel_0xff_decodes_to_none() {
        let bytes = encode_caps(&CodecCapsPayload {
            hw_encode_mask: 0,
            hw_decode_mask: 0,
            sw_h264_encode_available: false,
            is_apple: false,
            is_browser: false,
            selected_codec: None,
        })
        .unwrap();
        assert_eq!(bytes[3], 0xFF);
        let decoded = decode_caps(&bytes).unwrap();
        assert_eq!(decoded.selected_codec, None);
    }

    #[test]
    fn encode_flags_are_independent() {
        let sw_only = CodecCapsPayload {
            hw_encode_mask: 0,
            hw_decode_mask: 0,
            sw_h264_encode_available: true,
            is_apple: false,
            is_browser: false,
            selected_codec: None,
        };
        let apple_only = CodecCapsPayload {
            sw_h264_encode_available: false,
            is_apple: true,
            is_browser: false,
            ..sw_only
        };
        let browser_only = CodecCapsPayload {
            sw_h264_encode_available: false,
            is_apple: false,
            is_browser: true,
            ..sw_only
        };
        assert_eq!(encode_caps(&sw_only).unwrap()[2], FLAG_SW_H264);
        assert_eq!(encode_caps(&apple_only).unwrap()[2], FLAG_IS_APPLE);
        assert_eq!(encode_caps(&browser_only).unwrap()[2], FLAG_IS_BROWSER);
    }

    #[test]
    fn kind_bytes_are_distinct() {
        assert_ne!(KIND_CODEC_CAPS_OFFER, KIND_CODEC_CAPS_ANSWER);
    }

    #[test]
    fn codec_caps_len_is_four() {
        assert_eq!(CODEC_CAPS_LEN, 4);
    }

    proptest! {
        /// Round-trip: for any *valid* payload, encode then decode is identity.
        #[test]
        fn roundtrip_valid_payloads(
            hw_encode in 0u8..8u8,      // bits 0..2 only (avoid bit 3 = Raw and bits 4–7)
            hw_decode in 0u8..8u8,      // bits 0..2 only
            sw_h264 in any::<bool>(),
            is_apple in any::<bool>(),
            is_browser in any::<bool>(),
            selected in proptest::option::of(0u8..3u8),  // 0=H264 1=H265 2=AV1
        ) {
            let p = CodecCapsPayload {
                hw_encode_mask: hw_encode,
                hw_decode_mask: hw_decode,
                sw_h264_encode_available: sw_h264,
                is_apple,
                is_browser,
                selected_codec: selected,
            };
            let bytes = encode_caps(&p).unwrap();
            prop_assert_eq!(decode_caps(&bytes), Ok(p));
        }

        /// Decoder never panics on arbitrary bytes.
        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..16)) {
            let _ = decode_caps(&data);
        }
    }
}
