//! The 12-byte video payload header that follows the common header on the video channel (`LLD.md` §3.1).

use sh_types::{FrameId, TimestampUs};

use crate::bits::{bitpack, take_array};
use crate::error::ProtocolError;
use crate::{MAX_FRAME_ID, MAX_MONITOR_ID, VIDEO_HEADER_LEN};

/// Video codec identifying the bitstream in a video payload (`CODEC_ID`, 4 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// H.264 / AVC.
    H264,
    /// H.265 / HEVC.
    H265,
    /// AV1.
    Av1,
    /// Uncompressed/raw frames — used by the Phase-0 LAN-lab software pipeline (`sh-codec-hw`).
    Raw,
}

/// Frame coding type (`FRAME_TYPE`, 2 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// Inter-coded delta (P) frame.
    Predicted,
    /// Instantaneous decoder refresh (keyframe).
    Idr,
    /// A rolling intra-refresh slice.
    IntraRefresh,
}

/// Drop/scheduling priority of a video packet (`PRIORITY`, 2 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// May be dropped first under congestion.
    DropEligible,
    /// Normal priority.
    Normal,
    /// High priority (e.g. an IDR).
    High,
}

/// The 12-byte video payload header.
///
/// Layout (big-endian): bytes 0–2 `FRAME_ID` (24-bit); byte 3 `FRAG_INDEX`; byte 4 `TOTAL_FRAGS`;
/// byte 5 = `CODEC_ID(4) | FRAME_TYPE(2) | PRIORITY(2)`; byte 6 = `MONITOR_ID(4) | MARKER(1) |
/// RESERVED(3)`; byte 7 `RESERVED`; bytes 8–11 `ENCODE_TS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoHeader {
    /// Monotonic frame counter. The wire field is 24-bit, so the value must be `<= `[`MAX_FRAME_ID`].
    pub frame_id: FrameId,
    /// Index of this fragment within the frame (0-based).
    pub frag_index: u8,
    /// Total number of fragments composing the frame.
    pub total_frags: u8,
    /// Codec of the carried bitstream.
    pub codec: Codec,
    /// Frame coding type.
    pub frame_type: FrameType,
    /// Packet priority.
    pub priority: Priority,
    /// Source monitor. The wire field is 4-bit, so the value must be `<= `[`MAX_MONITOR_ID`].
    pub monitor_id: u8,
    /// Set on the last fragment of a frame (RTP-marker analogue).
    pub marker: bool,
    /// Encoder capture timestamp in microseconds (for end-to-end latency). Only the low 32 bits travel
    /// on the wire and wrap at 2^32 µs; higher bits are dropped by [`VideoHeader::encode`].
    pub encode_ts_us: TimestampUs,
}

impl VideoHeader {
    /// Serialize to the fixed 12-byte big-endian wire form.
    ///
    /// # Errors
    /// - [`ProtocolError::FrameIdTooLarge`] if `frame_id` exceeds [`MAX_FRAME_ID`].
    /// - [`ProtocolError::MonitorIdTooLarge`] if `monitor_id` exceeds [`MAX_MONITOR_ID`].
    ///
    /// # Examples
    /// ```
    /// use sh_protocol::{Codec, FrameType, Priority, VideoHeader};
    /// use sh_types::{FrameId, TimestampUs};
    /// # fn main() -> Result<(), sh_protocol::ProtocolError> {
    /// let h = VideoHeader {
    ///     frame_id: FrameId(0x00AB_CDEF),
    ///     frag_index: 3,
    ///     total_frags: 7,
    ///     codec: Codec::H265,
    ///     frame_type: FrameType::Idr,
    ///     priority: Priority::High,
    ///     monitor_id: 0x0A,
    ///     marker: true,
    ///     encode_ts_us: TimestampUs(0xDEAD_BEEF),
    /// };
    /// let bytes = h.encode()?;
    /// assert_eq!(VideoHeader::decode(&bytes), Ok(h));
    /// # Ok(()) }
    /// ```
    pub fn encode(&self) -> Result<[u8; VIDEO_HEADER_LEN], ProtocolError> {
        if self.frame_id.0 > u64::from(MAX_FRAME_ID) {
            return Err(ProtocolError::FrameIdTooLarge(self.frame_id.0));
        }
        if self.monitor_id > MAX_MONITOR_ID {
            return Err(ProtocolError::MonitorIdTooLarge(self.monitor_id));
        }
        // frame_id is validated <= 0xFF_FFFF, so only the low 3 bytes are significant.
        let [_, _, _, _, _, f0, f1, f2] = self.frame_id.0.to_be_bytes();
        // byte 5: CODEC_ID(4) | FRAME_TYPE(2) | PRIORITY(2)
        let byte5 = bitpack(&[
            (codec_to_bits(self.codec), 4),
            (frame_type_to_bits(self.frame_type), 2),
            (priority_to_bits(self.priority), 0),
        ]);
        // byte 6: MONITOR_ID(4) | MARKER(1) | RESERVED(3)=0
        let byte6 = bitpack(&[(self.monitor_id, 4), (u8::from(self.marker), 3)]);
        // Keep only the low 32 bits of the encode timestamp (wire field is 32-bit).
        let [_, _, _, _, e0, e1, e2, e3] = self.encode_ts_us.0.to_be_bytes();
        Ok([
            f0,
            f1,
            f2,
            self.frag_index,
            self.total_frags,
            byte5,
            byte6,
            0u8,
            e0,
            e1,
            e2,
            e3,
        ])
    }

    /// Parse a video header from the start of `data`. Never panics; rejects malformed input.
    ///
    /// # Errors
    /// - [`ProtocolError::Truncated`] if `data` is shorter than [`VIDEO_HEADER_LEN`].
    /// - [`ProtocolError::ReservedBitsSet`] if any reserved bit (byte 7, or the low 3 bits of byte 6) is set.
    /// - [`ProtocolError::InvalidCodec`] / [`ProtocolError::InvalidFrameType`] /
    ///   [`ProtocolError::InvalidPriority`] if those fields hold an unassigned bit pattern.
    ///
    /// # Examples
    /// ```
    /// use sh_protocol::{ProtocolError, VideoHeader};
    /// // byte 5 codec nibble = 0xF (15) is unassigned and rejected.
    /// let mut bytes = [0u8; 12];
    /// bytes[5] = 0xF0;
    /// assert_eq!(VideoHeader::decode(&bytes), Err(ProtocolError::InvalidCodec(15)));
    /// ```
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        let [f0, f1, f2, frag_index, total_frags, byte5, byte6, reserved, e0, e1, e2, e3] =
            take_array::<VIDEO_HEADER_LEN>(data)?;
        if reserved != 0 || (byte6 & 0x07) != 0 {
            return Err(ProtocolError::ReservedBitsSet);
        }
        Ok(Self {
            frame_id: FrameId(u64::from(u32::from_be_bytes([0, f0, f1, f2]))),
            frag_index,
            total_frags,
            codec: codec_from_bits(byte5 >> 4)?,
            frame_type: frame_type_from_bits((byte5 >> 2) & 0x03)?,
            priority: priority_from_bits(byte5 & 0x03)?,
            monitor_id: byte6 >> 4,
            marker: (byte6 & 0x08) != 0,
            encode_ts_us: TimestampUs(u64::from(u32::from_be_bytes([e0, e1, e2, e3]))),
        })
    }
}

fn codec_to_bits(codec: Codec) -> u8 {
    match codec {
        Codec::H264 => 0,
        Codec::H265 => 1,
        Codec::Av1 => 2,
        Codec::Raw => 3,
    }
}

fn codec_from_bits(bits: u8) -> Result<Codec, ProtocolError> {
    match bits {
        0 => Ok(Codec::H264),
        1 => Ok(Codec::H265),
        2 => Ok(Codec::Av1),
        3 => Ok(Codec::Raw),
        other => Err(ProtocolError::InvalidCodec(other)),
    }
}

fn frame_type_to_bits(frame_type: FrameType) -> u8 {
    match frame_type {
        FrameType::Predicted => 0,
        FrameType::Idr => 1,
        FrameType::IntraRefresh => 2,
    }
}

fn frame_type_from_bits(bits: u8) -> Result<FrameType, ProtocolError> {
    match bits {
        0 => Ok(FrameType::Predicted),
        1 => Ok(FrameType::Idr),
        2 => Ok(FrameType::IntraRefresh),
        other => Err(ProtocolError::InvalidFrameType(other)),
    }
}

fn priority_to_bits(priority: Priority) -> u8 {
    match priority {
        Priority::DropEligible => 0,
        Priority::Normal => 1,
        Priority::High => 2,
    }
}

fn priority_from_bits(bits: u8) -> Result<Priority, ProtocolError> {
    match bits {
        0 => Ok(Priority::DropEligible),
        1 => Ok(Priority::Normal),
        2 => Ok(Priority::High),
        other => Err(ProtocolError::InvalidPriority(other)),
    }
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

    fn sample() -> VideoHeader {
        VideoHeader {
            frame_id: FrameId(0x00AB_CDEF),
            frag_index: 3,
            total_frags: 7,
            codec: Codec::H265,
            frame_type: FrameType::Idr,
            priority: Priority::High,
            monitor_id: 0x0A,
            marker: true,
            encode_ts_us: TimestampUs(0xDEAD_BEEF),
        }
    }

    #[test]
    fn known_layout_roundtrips() {
        let h = sample();
        let bytes = h.encode().unwrap();
        assert_eq!([bytes[0], bytes[1], bytes[2]], [0xAB, 0xCD, 0xEF]); // FRAME_ID
        assert_eq!(bytes[5], 0x16); // CODEC=0001 FRAME_TYPE=01 PRIORITY=10
        assert_eq!(bytes[6], 0xA8); // MONITOR=1010 MARKER=1 RESERVED=000
        assert_eq!(
            [bytes[8], bytes[9], bytes[10], bytes[11]],
            [0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert_eq!(VideoHeader::decode(&bytes), Ok(h));
    }

    #[test]
    fn encode_rejects_oversized_frame_id() {
        let mut h = sample();
        h.frame_id = FrameId(u64::from(MAX_FRAME_ID) + 1);
        assert_eq!(
            h.encode(),
            Err(ProtocolError::FrameIdTooLarge(u64::from(MAX_FRAME_ID) + 1))
        );
    }

    #[test]
    fn encode_rejects_oversized_monitor_id() {
        let mut h = sample();
        h.monitor_id = MAX_MONITOR_ID + 1;
        assert_eq!(
            h.encode(),
            Err(ProtocolError::MonitorIdTooLarge(MAX_MONITOR_ID + 1))
        );
    }

    #[test]
    fn decode_rejects_truncation() {
        assert_eq!(
            VideoHeader::decode(&[0u8; 11]),
            Err(ProtocolError::Truncated {
                needed: 12,
                have: 11
            })
        );
    }

    #[test]
    fn decode_rejects_invalid_codec() {
        let mut bytes = [0u8; VIDEO_HEADER_LEN];
        bytes[5] = 0xF0; // codec nibble = 15
        assert_eq!(
            VideoHeader::decode(&bytes),
            Err(ProtocolError::InvalidCodec(15))
        );
    }

    #[test]
    fn decode_rejects_invalid_frame_type() {
        let mut bytes = [0u8; VIDEO_HEADER_LEN];
        bytes[5] = 0x0C; // codec=0, frame_type=3, priority=0
        assert_eq!(
            VideoHeader::decode(&bytes),
            Err(ProtocolError::InvalidFrameType(3))
        );
    }

    #[test]
    fn decode_rejects_invalid_priority() {
        let mut bytes = [0u8; VIDEO_HEADER_LEN];
        bytes[5] = 0x03; // priority = 3
        assert_eq!(
            VideoHeader::decode(&bytes),
            Err(ProtocolError::InvalidPriority(3))
        );
    }

    #[test]
    fn decode_rejects_reserved_bits() {
        let mut byte7 = [0u8; VIDEO_HEADER_LEN];
        byte7[7] = 1; // byte-7 reserved must be zero
        assert_eq!(
            VideoHeader::decode(&byte7),
            Err(ProtocolError::ReservedBitsSet)
        );

        let mut byte6 = [0u8; VIDEO_HEADER_LEN];
        byte6[6] = 0x01; // low 3 bits of byte 6 are reserved
        assert_eq!(
            VideoHeader::decode(&byte6),
            Err(ProtocolError::ReservedBitsSet)
        );
    }

    proptest! {
        #[test]
        fn roundtrips(
            frame_id in 0u32..=MAX_FRAME_ID,
            frag_index in any::<u8>(),
            total_frags in any::<u8>(),
            codec_bits in 0u8..=3,
            frame_type_bits in 0u8..=2,
            priority_bits in 0u8..=2,
            monitor_id in 0u8..=MAX_MONITOR_ID,
            marker in any::<bool>(),
            encode_ts in any::<u32>(),
        ) {
            let h = VideoHeader {
                frame_id: FrameId(u64::from(frame_id)),
                frag_index,
                total_frags,
                codec: codec_from_bits(codec_bits).unwrap(),
                frame_type: frame_type_from_bits(frame_type_bits).unwrap(),
                priority: priority_from_bits(priority_bits).unwrap(),
                monitor_id,
                marker,
                encode_ts_us: TimestampUs(u64::from(encode_ts)),
            };
            let bytes = h.encode().unwrap();
            prop_assert_eq!(VideoHeader::decode(&bytes), Ok(h));
        }

        #[test]
        fn encode_rejects_out_of_range_frame_id(extra in 1u64..=0xFFFF_FFFF) {
            let mut h = sample();
            h.frame_id = FrameId(u64::from(MAX_FRAME_ID) + extra);
            prop_assert!(matches!(h.encode(), Err(ProtocolError::FrameIdTooLarge(_))));
        }

        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..32)) {
            let _ = VideoHeader::decode(&data);
        }
    }
}
