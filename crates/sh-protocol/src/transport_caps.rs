//! Transport capability offer/answer wire framing (P4-6).
//!
//! This module encodes and decodes the 2-byte `TransportCaps` wire message, and implements
//! the symmetric, preference-ordered [`negotiate`] function that selects a [`TransportKind`]
//! from the intersection of two capability sets.
//!
//! ## Wire format — `TransportCaps` (2 bytes, fixed)
//!
//! ```text
//! BYTE 0:  VERSION          Must be 0x01 on encode; rejected if != 0x01 on decode.
//! BYTE 1:  TRANSPORT_MASK   Bitmask of supported transport protocols.
//!                            bit 0 = QUIC  (sh_types::TransportKind::Quic)
//!                            bit 1 = WebRTC (sh_types::TransportKind::Webrtc)
//!                            bits 2-7 = RESERVED; MUST be 0 on encode; IGNORED on decode
//!                            (forward-compatibility: a future version may define them).
//! ```
//!
//! Total: **2 bytes** ([`TRANSPORT_CAPS_LEN`]).  All fields are mandatory; truncated input is
//! rejected with [`ProtocolError::Truncated`].
//!
//! ## Negotiation
//!
//! [`negotiate`] iterates the global preference order `[QUIC, WebRTC]` and returns the first
//! transport present in **both** capability sets. This ordering guarantees symmetry:
//! `negotiate(a, b) == negotiate(b, a)` for all inputs — neither side can force a downgrade by
//! supplying its caps in a different order.
//!
//! ## Security note
//!
//! The decoder treats all input as hostile: it bounds-checks, validates the version byte, and
//! never panics. Reserved bits in TRANSPORT_MASK are **ignored on decode** (forward-compat),
//! which differs from the codec caps module where reserved bits are rejected. This is by design:
//! future versions can define new transport bits without breaking current decoders.
//!
//! ## Message kind constants
//!
//! Two payload-type discriminants are defined for use with the signaling channel:
//! - [`KIND_TRANSPORT_CAPS_OFFER`] (`0x20`) — initiator announces its caps
//! - [`KIND_TRANSPORT_CAPS_ANSWER`] (`0x21`) — responder announces its caps
//!
//! In the P4-6 session orchestrator both sides send their caps in a `MessageKind::Candidate`
//! signaling envelope; the VERSION byte (0x01) distinguishes these 2-byte payloads from ICE
//! candidate blobs in the same envelope type.
//!
//! ## Usage
//!
//! ```
//! use sh_protocol::transport_caps::{
//!     TransportCaps, encode_transport_caps, decode_transport_caps,
//!     negotiate, TRANSPORT_CAPS_LEN,
//! };
//! use sh_types::TransportKind;
//!
//! // Encode
//! let caps = TransportCaps { supports_quic: true, supports_webrtc: true };
//! let wire = encode_transport_caps(&caps);
//! assert_eq!(wire.len(), TRANSPORT_CAPS_LEN);
//!
//! // Decode
//! let decoded = decode_transport_caps(&wire).unwrap();
//! assert!(decoded.supports_quic);
//! assert!(decoded.supports_webrtc);
//!
//! // Negotiate: QUIC is preferred
//! let peer = TransportCaps { supports_quic: false, supports_webrtc: true };
//! let kind = negotiate(caps, peer).unwrap();
//! assert_eq!(kind, TransportKind::Webrtc);
//! ```

use sh_types::TransportKind;
use thiserror::Error;

use crate::error::ProtocolError;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Wire length of a [`TransportCaps`] payload, in bytes.
pub const TRANSPORT_CAPS_LEN: usize = 2;

/// Version byte that must appear in byte 0 of every `TransportCaps` wire encoding.
const TRANSPORT_CAPS_VERSION: u8 = 0x01;

/// Bitmask bit for QUIC in byte 1 of the wire format.
const MASK_QUIC: u8 = 0b0000_0001;

/// Bitmask bit for WebRTC in byte 1 of the wire format.
const MASK_WEBRTC: u8 = 0b0000_0010;

/// Payload-type discriminant: initiator transport-caps announcement.
///
/// Carried as the first byte of a control-frame payload when the initiator
/// sends its [`TransportCaps`] to the responder.
pub const KIND_TRANSPORT_CAPS_OFFER: u8 = 0x20;

/// Payload-type discriminant: responder transport-caps announcement.
///
/// Carried as the first byte of a control-frame payload when the responder
/// sends its [`TransportCaps`] back to the initiator.
pub const KIND_TRANSPORT_CAPS_ANSWER: u8 = 0x21;

// ─── Data types ───────────────────────────────────────────────────────────────

/// The set of transport protocols an endpoint supports.
///
/// Encoded as a 2-byte wire message (see module docs). Both fields default to `false`;
/// a peer that supports no transports at all cannot complete negotiation.
///
/// # Examples
///
/// ```
/// use sh_protocol::transport_caps::TransportCaps;
///
/// let quic_only = TransportCaps { supports_quic: true, supports_webrtc: false };
/// let webrtc_only = TransportCaps { supports_quic: false, supports_webrtc: true };
/// assert!(quic_only.supports_quic);
/// assert!(!quic_only.supports_webrtc);
/// assert!(!webrtc_only.supports_quic);
/// assert!(webrtc_only.supports_webrtc);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportCaps {
    /// Whether this endpoint supports QUIC (RFC 9000 / quinn).
    pub supports_quic: bool,
    /// Whether this endpoint supports WebRTC (str0m / DTLS-SRTP + ICE).
    pub supports_webrtc: bool,
}

/// Errors that can occur during transport negotiation.
///
/// Returned by [`negotiate`] when the two capability sets have no transport in common.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NegotiationError {
    /// No common transport was found between the local and peer capability sets.
    ///
    /// The session cannot proceed: both sides must support at least one common protocol.
    #[error("no common transport: local={local:?} peer={peer:?}")]
    NoCommonTransport {
        /// The local endpoint's capability set.
        local: TransportCaps,
        /// The peer's capability set.
        peer: TransportCaps,
    },
}

// ─── Encode ───────────────────────────────────────────────────────────────────

/// Encodes a [`TransportCaps`] into its 2-byte wire representation.
///
/// This function is infallible. The returned array always starts with [`VERSION = 0x01`].
/// Reserved bits 2–7 of byte 1 are always written as zero.
///
/// # Examples
///
/// ```
/// use sh_protocol::transport_caps::{TransportCaps, encode_transport_caps, TRANSPORT_CAPS_LEN};
///
/// let caps = TransportCaps { supports_quic: true, supports_webrtc: true };
/// let wire = encode_transport_caps(&caps);
/// assert_eq!(wire.len(), TRANSPORT_CAPS_LEN);
/// assert_eq!(wire[0], 0x01); // VERSION
/// assert_eq!(wire[1] & 0b0000_0001, 1); // QUIC bit
/// assert_eq!(wire[1] & 0b0000_0010, 2); // WebRTC bit
/// ```
#[must_use]
pub fn encode_transport_caps(caps: &TransportCaps) -> [u8; TRANSPORT_CAPS_LEN] {
    let mut mask = 0u8;
    if caps.supports_quic {
        mask |= MASK_QUIC;
    }
    if caps.supports_webrtc {
        mask |= MASK_WEBRTC;
    }
    [TRANSPORT_CAPS_VERSION, mask]
}

// ─── Decode ───────────────────────────────────────────────────────────────────

/// Decodes a [`TransportCaps`] from a byte slice.
///
/// Treats the input as hostile — all bounds checks happen before any field access.
///
/// # Errors
///
/// - [`ProtocolError::Truncated`] — `data.len() < 2`
/// - [`ProtocolError::UnknownVersion`] — byte 0 is not `0x01`
///
/// Reserved bits 2–7 in byte 1 (TRANSPORT_MASK) are **silently ignored** for forward
/// compatibility: a future version may define them without breaking this decoder.
///
/// # Examples
///
/// ```
/// use sh_protocol::transport_caps::{decode_transport_caps, TRANSPORT_CAPS_LEN};
///
/// // Valid 2-byte wire value: version=0x01, mask=0x03 (QUIC + WebRTC)
/// let wire = [0x01u8, 0x03];
/// let caps = decode_transport_caps(&wire).unwrap();
/// assert!(caps.supports_quic);
/// assert!(caps.supports_webrtc);
///
/// // Truncated
/// assert!(decode_transport_caps(&[0x01]).is_err());
///
/// // Unknown version
/// assert!(decode_transport_caps(&[0x02, 0x01]).is_err());
/// ```
pub fn decode_transport_caps(data: &[u8]) -> Result<TransportCaps, ProtocolError> {
    if data.len() < TRANSPORT_CAPS_LEN {
        return Err(ProtocolError::Truncated {
            needed: TRANSPORT_CAPS_LEN,
            have: data.len(),
        });
    }

    // These indexing operations are safe: we verified data.len() >= 2 above.
    #[allow(clippy::indexing_slicing)]
    let version = data[0];
    #[allow(clippy::indexing_slicing)]
    let mask = data[1];

    if version != TRANSPORT_CAPS_VERSION {
        return Err(ProtocolError::UnknownVersion(version));
    }

    // Reserved bits 2-7 are ignored for forward compatibility (not rejected).
    let supports_quic = (mask & MASK_QUIC) != 0;
    let supports_webrtc = (mask & MASK_WEBRTC) != 0;

    Ok(TransportCaps {
        supports_quic,
        supports_webrtc,
    })
}

// ─── Negotiate ────────────────────────────────────────────────────────────────

/// The global transport preference order.
///
/// QUIC is preferred over WebRTC for native↔native because it has lower overhead
/// (no DTLS+SRTP stack), native multiplexing, and purpose-built congestion control.
/// WebRTC is the browser-compatible fallback.
///
/// This slice is iterated in order by [`negotiate`]; the first entry present in both
/// capability sets is selected. The fixed global order is what guarantees symmetry.
const PREFERENCE_ORDER: &[TransportKind] = &[TransportKind::Quic, TransportKind::Webrtc];

/// Negotiates a transport protocol from two capability sets using a fixed global preference order.
///
/// The preference order is always `[QUIC, WebRTC]` regardless of which side is `local`
/// and which is `peer`. This means the result is **symmetric**:
/// `negotiate(a, b) == negotiate(b, a)` for all inputs where the intersection is non-empty.
/// Neither side can influence the outcome beyond indicating which transports it supports.
///
/// # Errors
///
/// Returns [`NegotiationError::NoCommonTransport`] if the intersection of the two capability
/// sets is empty (neither transport appears in both sets).
///
/// # Examples
///
/// ```
/// use sh_protocol::transport_caps::{TransportCaps, negotiate};
/// use sh_types::TransportKind;
///
/// // Both support everything: QUIC wins (preferred)
/// let both = TransportCaps { supports_quic: true, supports_webrtc: true };
/// assert_eq!(negotiate(both, both).unwrap(), TransportKind::Quic);
///
/// // Local QUIC+WebRTC, peer WebRTC-only: WebRTC is the fallback
/// let local = TransportCaps { supports_quic: true, supports_webrtc: true };
/// let peer = TransportCaps { supports_quic: false, supports_webrtc: true };
/// assert_eq!(negotiate(local, peer).unwrap(), TransportKind::Webrtc);
///
/// // No overlap: error
/// let quic_only = TransportCaps { supports_quic: true, supports_webrtc: false };
/// let webrtc_only = TransportCaps { supports_quic: false, supports_webrtc: true };
/// assert!(negotiate(quic_only, webrtc_only).is_err());
/// ```
pub fn negotiate(
    local: TransportCaps,
    peer: TransportCaps,
) -> Result<TransportKind, NegotiationError> {
    for &kind in PREFERENCE_ORDER {
        let local_has = match kind {
            TransportKind::Quic => local.supports_quic,
            TransportKind::Webrtc => local.supports_webrtc,
        };
        let peer_has = match kind {
            TransportKind::Quic => peer.supports_quic,
            TransportKind::Webrtc => peer.supports_webrtc,
        };
        if local_has && peer_has {
            return Ok(kind);
        }
    }
    Err(NegotiationError::NoCommonTransport { local, peer })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn arbitrary_caps() -> impl Strategy<Value = TransportCaps> {
        (any::<bool>(), any::<bool>()).prop_map(|(q, w)| TransportCaps {
            supports_quic: q,
            supports_webrtc: w,
        })
    }

    // ── Encode / decode round-trips ──────────────────────────────────────────

    #[test]
    fn round_trip_both_transports() {
        let caps = TransportCaps {
            supports_quic: true,
            supports_webrtc: true,
        };
        let wire = encode_transport_caps(&caps);
        assert_eq!(wire.len(), TRANSPORT_CAPS_LEN);
        let decoded = decode_transport_caps(&wire).unwrap();
        assert_eq!(decoded, caps);
    }

    #[test]
    fn round_trip_quic_only() {
        let caps = TransportCaps {
            supports_quic: true,
            supports_webrtc: false,
        };
        let wire = encode_transport_caps(&caps);
        let decoded = decode_transport_caps(&wire).unwrap();
        assert_eq!(decoded, caps);
    }

    #[test]
    fn round_trip_webrtc_only() {
        let caps = TransportCaps {
            supports_quic: false,
            supports_webrtc: true,
        };
        let wire = encode_transport_caps(&caps);
        let decoded = decode_transport_caps(&wire).unwrap();
        assert_eq!(decoded, caps);
    }

    #[test]
    fn round_trip_neither() {
        let caps = TransportCaps {
            supports_quic: false,
            supports_webrtc: false,
        };
        let wire = encode_transport_caps(&caps);
        let decoded = decode_transport_caps(&wire).unwrap();
        assert_eq!(decoded, caps);
    }

    #[test]
    fn encoded_version_byte_is_0x01() {
        let caps = TransportCaps {
            supports_quic: true,
            supports_webrtc: false,
        };
        let wire = encode_transport_caps(&caps);
        assert_eq!(wire[0], 0x01, "version byte must be 0x01");
    }

    #[test]
    fn encoded_reserved_bits_are_zero() {
        // Encoding must never set reserved bits 2-7.
        let caps = TransportCaps {
            supports_quic: true,
            supports_webrtc: true,
        };
        let wire = encode_transport_caps(&caps);
        assert_eq!(
            wire[1] & 0b1111_1100,
            0,
            "reserved bits 2-7 must be zero on encode"
        );
    }

    // ── Decode error cases ────────────────────────────────────────────────────

    #[test]
    fn decode_truncated_returns_error() {
        // Empty
        let err = decode_transport_caps(&[]).unwrap_err();
        assert!(
            matches!(err, ProtocolError::Truncated { needed: 2, have: 0 }),
            "expected Truncated, got {err:?}"
        );
        // One byte only
        let err = decode_transport_caps(&[0x01]).unwrap_err();
        assert!(
            matches!(err, ProtocolError::Truncated { needed: 2, have: 1 }),
            "expected Truncated, got {err:?}"
        );
    }

    #[test]
    fn decode_wrong_version_returns_error() {
        // Version 0x00
        let err = decode_transport_caps(&[0x00, 0x01]).unwrap_err();
        assert!(
            matches!(err, ProtocolError::UnknownVersion(0x00)),
            "expected UnknownVersion(0x00), got {err:?}"
        );
        // Version 0x02
        let err = decode_transport_caps(&[0x02, 0x03]).unwrap_err();
        assert!(
            matches!(err, ProtocolError::UnknownVersion(0x02)),
            "expected UnknownVersion(0x02), got {err:?}"
        );
    }

    #[test]
    fn decode_reserved_bits_ignored() {
        // Set all reserved bits (2-7) in TRANSPORT_MASK — must still decode successfully
        let wire = [0x01u8, 0b1111_1100]; // no QUIC or WebRTC bits set
        let caps = decode_transport_caps(&wire).unwrap();
        assert!(!caps.supports_quic, "QUIC bit should be 0");
        assert!(!caps.supports_webrtc, "WebRTC bit should be 0");

        // Reserved bits set alongside real transport bits
        let wire2 = [0x01u8, 0b1111_1111]; // all bits set
        let caps2 = decode_transport_caps(&wire2).unwrap();
        assert!(caps2.supports_quic);
        assert!(caps2.supports_webrtc);
    }

    // ── Negotiation ───────────────────────────────────────────────────────────

    #[test]
    fn negotiate_both_prefer_quic() {
        let both = TransportCaps {
            supports_quic: true,
            supports_webrtc: true,
        };
        let result = negotiate(both, both).unwrap();
        assert_eq!(
            result,
            TransportKind::Quic,
            "QUIC must be preferred over WebRTC"
        );
    }

    #[test]
    fn negotiate_quic_only_vs_webrtc_only_is_error() {
        let quic_only = TransportCaps {
            supports_quic: true,
            supports_webrtc: false,
        };
        let webrtc_only = TransportCaps {
            supports_quic: false,
            supports_webrtc: true,
        };
        let err = negotiate(quic_only, webrtc_only).unwrap_err();
        assert!(
            matches!(err, NegotiationError::NoCommonTransport { .. }),
            "expected NoCommonTransport, got {err:?}"
        );
    }

    #[test]
    fn negotiate_webrtc_fallback() {
        // Local has both; peer only WebRTC → WebRTC is selected
        let local = TransportCaps {
            supports_quic: true,
            supports_webrtc: true,
        };
        let peer = TransportCaps {
            supports_quic: false,
            supports_webrtc: true,
        };
        let result = negotiate(local, peer).unwrap();
        assert_eq!(result, TransportKind::Webrtc);
    }

    #[test]
    fn negotiate_no_common_transport() {
        let quic_only = TransportCaps {
            supports_quic: true,
            supports_webrtc: false,
        };
        let webrtc_only = TransportCaps {
            supports_quic: false,
            supports_webrtc: true,
        };
        let neither = TransportCaps {
            supports_quic: false,
            supports_webrtc: false,
        };
        // All pairings without a common transport
        assert!(negotiate(quic_only, webrtc_only).is_err());
        assert!(negotiate(webrtc_only, quic_only).is_err());
        assert!(negotiate(neither, quic_only).is_err());
        assert!(negotiate(neither, webrtc_only).is_err());
        assert!(negotiate(neither, neither).is_err());
    }

    // ── Symmetry property test ────────────────────────────────────────────────

    proptest! {
        #[test]
        fn negotiate_symmetry(
            a in arbitrary_caps(),
            b in arbitrary_caps(),
        ) {
            let ab = negotiate(a, b);
            let ba = negotiate(b, a);
            // If the intersection is non-empty, both calls must return the same result.
            // If empty, both calls must return an error.
            match (ab, ba) {
                (Ok(ka), Ok(kb)) => prop_assert_eq!(ka, kb, "negotiate must be symmetric"),
                (Err(_), Err(_)) => {}, // both failed → symmetric failure
                (Ok(k), Err(e)) => {
                    return Err(proptest::test_runner::TestCaseError::fail(
                        format!("negotiate({a:?},{b:?})=Ok({k:?}) but negotiate({b:?},{a:?})=Err({e:?})")
                    ));
                }
                (Err(e), Ok(k)) => {
                    return Err(proptest::test_runner::TestCaseError::fail(
                        format!("negotiate({a:?},{b:?})=Err({e:?}) but negotiate({b:?},{a:?})=Ok({k:?})")
                    ));
                }
            }
        }
    }

    // ── Decode no-panic sanity (mirrors the fuzz target) ─────────────────────

    #[test]
    fn decode_no_panic_on_garbage() {
        let _ = decode_transport_caps(&[]);
        let _ = decode_transport_caps(&[0xFF; 64]);
        let _ = decode_transport_caps(b"garbage");
        let _ = decode_transport_caps(&[0x01, 0xFF]);
    }
}
