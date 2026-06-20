//! Framing for the reliable, ordered **control / RPC channel** (`LLD.md` §3.2).
//!
//! The control channel is a byte stream, so messages are length-delimited: `KIND(1) | LEN(2 BE) |
//! PAYLOAD`. [`decode_control`] is incremental — it returns `Ok(None)` when the buffer does not yet
//! hold a complete frame — so a reader can append stream bytes and drain whole frames as they arrive.
//! The payload bytes are opaque here; higher layers (e.g. prost-encoded RPC) interpret them.

use crate::error::ProtocolError;

/// Length of the control frame header: `KIND(1) | LEN(2)`.
pub const CONTROL_HEADER_LEN: usize = 3;

/// A control frame parsed out of a stream buffer (payload borrows the input).
///
/// `kind` is deliberately a raw `u8`: this framing layer is application-agnostic. The mapping from
/// `kind` to a typed message enum lives at the RPC/dispatch layer (P1-1+), not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlFrame<'a> {
    /// Application-defined message kind.
    pub kind: u8,
    /// Opaque message payload.
    pub payload: &'a [u8],
}

impl ControlFrame<'_> {
    /// Total bytes this frame occupied in the source buffer (header + payload). Advance the stream
    /// reader's cursor by this to reach the next frame.
    #[must_use]
    pub fn consumed(&self) -> usize {
        CONTROL_HEADER_LEN.saturating_add(self.payload.len())
    }
}

/// Encode a control frame (`KIND | LEN | PAYLOAD`) into a freshly allocated buffer.
///
/// # Errors
/// Returns [`ProtocolError::ControlPayloadTooLarge`] if `payload` exceeds the 16-bit length field.
pub fn encode_control(kind: u8, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let len = u16::try_from(payload.len())
        .map_err(|_| ProtocolError::ControlPayloadTooLarge(payload.len()))?;
    let mut buf = Vec::with_capacity(CONTROL_HEADER_LEN.saturating_add(payload.len()));
    buf.push(kind);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    Ok(buf)
}

/// Try to parse one control frame from the start of `data`.
///
/// Returns `Ok(None)` if `data` does not yet contain a full frame (the caller should read more bytes
/// and retry). Never panics.
///
/// # Errors
/// Currently infallible; the `Result` is reserved for future framing checks (e.g. CRC validation).
// `Result` is intentional for forward compatibility, so callers' `?`-handling stays stable when
// fallible framing checks are added.
#[allow(clippy::unnecessary_wraps)]
pub fn decode_control(data: &[u8]) -> Result<Option<ControlFrame<'_>>, ProtocolError> {
    let header: [u8; CONTROL_HEADER_LEN] = match data
        .get(..CONTROL_HEADER_LEN)
        .and_then(|s| s.try_into().ok())
    {
        Some(h) => h,
        None => return Ok(None),
    };
    let [kind, l0, l1] = header;
    let len = usize::from(u16::from_be_bytes([l0, l1]));
    let total = CONTROL_HEADER_LEN.saturating_add(len);
    let Some(payload) = data.get(CONTROL_HEADER_LEN..total) else {
        return Ok(None);
    };
    Ok(Some(ControlFrame { kind, payload }))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn roundtrip_single_frame() {
        let buf = encode_control(7, b"hello").unwrap();
        assert_eq!(buf, vec![7, 0, 5, b'h', b'e', b'l', b'l', b'o']);
        let frame = decode_control(&buf).unwrap().unwrap();
        assert_eq!(frame.kind, 7);
        assert_eq!(frame.payload, b"hello");
        assert_eq!(frame.consumed(), 8);
    }

    #[test]
    fn empty_payload() {
        let buf = encode_control(1, b"").unwrap();
        let frame = decode_control(&buf).unwrap().unwrap();
        assert_eq!(frame.payload, b"");
        assert_eq!(frame.consumed(), 3);
    }

    #[test]
    fn incremental_needs_more() {
        // Header says 5 payload bytes but only 2 present → None (need more).
        assert_eq!(decode_control(&[9, 0, 5, 1, 2]).unwrap(), None);
        // A large declared length with a tiny buffer must also be None, never a panic/mis-slice.
        assert_eq!(decode_control(&[9, 0xFF, 0xFF, 1, 2, 3]).unwrap(), None);
        // Not even a full header.
        assert_eq!(decode_control(&[9, 0]).unwrap(), None);
        assert_eq!(decode_control(&[]).unwrap(), None);
    }

    #[test]
    fn trailing_garbage_is_ignored() {
        // One valid 8-byte frame followed by junk decodes to exactly the first frame.
        let frame = decode_control(&[7, 0, 5, 1, 2, 3, 4, 5, 0xFF, 0xAA])
            .unwrap()
            .unwrap();
        assert_eq!(frame.kind, 7);
        assert_eq!(frame.payload, &[1, 2, 3, 4, 5]);
        assert_eq!(frame.consumed(), 8);
    }

    #[test]
    fn drains_consecutive_frames() {
        let mut buf = encode_control(1, b"ab").unwrap();
        buf.extend(encode_control(2, b"xyz").unwrap());
        let f1 = decode_control(&buf).unwrap().unwrap();
        assert_eq!((f1.kind, f1.payload), (1, b"ab".as_ref()));
        let f2 = decode_control(&buf[f1.consumed()..]).unwrap().unwrap();
        assert_eq!((f2.kind, f2.payload), (2, b"xyz".as_ref()));
    }

    #[test]
    fn rejects_oversized_payload() {
        let big = vec![0u8; usize::from(u16::MAX) + 1];
        assert!(matches!(
            encode_control(0, &big),
            Err(ProtocolError::ControlPayloadTooLarge(_))
        ));
    }

    proptest! {
        #[test]
        fn encode_decode_roundtrip(kind in any::<u8>(), payload in proptest::collection::vec(any::<u8>(), 0..600)) {
            let buf = encode_control(kind, &payload).unwrap();
            let frame = decode_control(&buf).unwrap().unwrap();
            prop_assert_eq!(frame.kind, kind);
            prop_assert_eq!(frame.payload, payload.as_slice());
            prop_assert_eq!(frame.consumed(), buf.len());
        }

        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = decode_control(&data);
        }
    }
}
