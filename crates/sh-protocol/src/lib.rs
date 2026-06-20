//! Streamhaul Protocol (SHP) wire format.
//!
//! This crate is pure, allocation-light, and does **no I/O**: it turns header structs into byte arrays
//! and parses byte slices back into structs. All multi-byte fields are **big-endian** (network byte
//! order). Decoding treats every input as hostile — it never panics and never indexes out of bounds;
//! malformed input returns [`ProtocolError`]. See `LLD.md` §3.1 for the field layouts.
//!
//! This first cut (task P0-3) covers the **common header** and the **video payload header**. Audio,
//! input, and feedback message types land with their phases.

use sh_types::ChannelId;
use thiserror::Error;

/// Current SHP protocol version, carried in the top two bits of byte 0 of every packet.
pub const SHP_VERSION: u8 = 0b01;

/// Wire length of the common SHP header, in bytes.
pub const COMMON_HEADER_LEN: usize = 9;

/// Wire length of the video payload header (follows the common header for video packets), in bytes.
pub const VIDEO_HEADER_LEN: usize = 12;

/// The largest value a 24-bit on-wire `FRAME_ID` can hold.
pub const MAX_FRAME_ID: u32 = 0x00FF_FFFF;

/// The largest value a 4-bit on-wire `MONITOR_ID` can hold.
pub const MAX_MONITOR_ID: u8 = 0x0F;

/// Errors produced while decoding (or validating before encoding) SHP wire data.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    /// The input slice is shorter than the header it should contain.
    #[error("truncated: need {needed} bytes, have {have}")]
    Truncated {
        /// Bytes required to parse the header.
        needed: usize,
        /// Bytes actually available.
        have: usize,
    },
    /// The version bits do not match [`SHP_VERSION`].
    #[error("unsupported SHP version: {0:#04b}")]
    UnsupportedVersion(u8),
    /// The channel bits do not map to a known [`ChannelId`].
    #[error("invalid channel id: {0}")]
    InvalidChannel(u8),
    /// The codec bits do not map to a known [`Codec`].
    #[error("invalid codec id: {0}")]
    InvalidCodec(u8),
    /// The frame-type bits do not map to a known [`FrameType`].
    #[error("invalid frame type: {0}")]
    InvalidFrameType(u8),
    /// The priority bits do not map to a known [`Priority`].
    #[error("invalid priority: {0}")]
    InvalidPriority(u8),
    /// A reserved field was non-zero (must be zero; rejected to keep the format unambiguous).
    #[error("reserved bits must be zero")]
    ReservedBitsSet,
    /// `frame_id` exceeds [`MAX_FRAME_ID`] (does not fit the 24-bit wire field).
    #[error("frame_id {0} exceeds 24-bit maximum")]
    FrameIdTooLarge(u32),
    /// `monitor_id` exceeds [`MAX_MONITOR_ID`] (does not fit the 4-bit wire field).
    #[error("monitor_id {0} exceeds 4-bit maximum")]
    MonitorIdTooLarge(u8),
}

/// The two SHP flag bits in byte 0 of the common header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags {
    /// Set when this packet is a fragment of a larger payload.
    pub fragment: bool,
    /// Set on the final fragment of a fragmented payload.
    pub last_fragment: bool,
}

/// The 9-byte common header that prefixes every SHP packet on every channel (`LLD.md` §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonHeader {
    /// Which logical channel this packet belongs to.
    pub channel: ChannelId,
    /// Fragmentation flags.
    pub flags: Flags,
    /// Per-channel sequence number (wraps at 2^16).
    pub sequence: u16,
    /// Microseconds since the session epoch (monotonic).
    pub timestamp_us: u32,
    /// Length in bytes of the payload following this header.
    pub payload_len: u16,
}

impl CommonHeader {
    /// Serialize the header to its fixed 9-byte big-endian wire form.
    #[must_use]
    pub fn encode(&self) -> [u8; COMMON_HEADER_LEN] {
        let flags_bits = pack2(
            u8::from(self.flags.fragment),
            u8::from(self.flags.last_fragment),
        );
        // byte 0: VER(2) | CHANNEL(4) | FLAGS(2)
        let byte0 = bitpack(&[
            (SHP_VERSION, 6),
            (channel_to_bits(self.channel), 2),
            (flags_bits, 0),
        ]);
        let [s0, s1] = self.sequence.to_be_bytes();
        let [t0, t1, t2, t3] = self.timestamp_us.to_be_bytes();
        let [l0, l1] = self.payload_len.to_be_bytes();
        [byte0, s0, s1, t0, t1, t2, t3, l0, l1]
    }

    /// Parse a common header from the start of `data`. Never panics; rejects malformed input.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        let [byte0, s0, s1, t0, t1, t2, t3, l0, l1] = take_array::<COMMON_HEADER_LEN>(data)?;
        let version = byte0 >> 6;
        if version != SHP_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let channel = channel_from_bits((byte0 >> 2) & 0x0F)?;
        let flags = Flags {
            fragment: (byte0 & 0b10) != 0,
            last_fragment: (byte0 & 0b01) != 0,
        };
        Ok(Self {
            channel,
            flags,
            sequence: u16::from_be_bytes([s0, s1]),
            timestamp_us: u32::from_be_bytes([t0, t1, t2, t3]),
            payload_len: u16::from_be_bytes([l0, l1]),
        })
    }
}

/// Video codec identifying the bitstream in a video payload (`CODEC_ID`, 4 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// H.264 / AVC.
    H264,
    /// H.265 / HEVC.
    H265,
    /// AV1.
    Av1,
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

/// The 12-byte video payload header that follows the common header on the video channel (`LLD.md` §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoHeader {
    /// Monotonic frame counter (24-bit on the wire; must be `<= `[`MAX_FRAME_ID`]).
    pub frame_id: u32,
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
    /// Source monitor (4-bit; must be `<= `[`MAX_MONITOR_ID`]).
    pub monitor_id: u8,
    /// Set on the last fragment of a frame (RTP-marker analogue).
    pub marker: bool,
    /// Encoder capture timestamp in microseconds (for end-to-end latency measurement).
    pub encode_ts_us: u32,
}

impl VideoHeader {
    /// Serialize to the fixed 12-byte big-endian wire form.
    ///
    /// # Errors
    /// Returns [`ProtocolError::FrameIdTooLarge`] or [`ProtocolError::MonitorIdTooLarge`] if a field
    /// does not fit its narrowed wire width.
    pub fn encode(&self) -> Result<[u8; VIDEO_HEADER_LEN], ProtocolError> {
        if self.frame_id > MAX_FRAME_ID {
            return Err(ProtocolError::FrameIdTooLarge(self.frame_id));
        }
        if self.monitor_id > MAX_MONITOR_ID {
            return Err(ProtocolError::MonitorIdTooLarge(self.monitor_id));
        }
        // frame_id is validated <= 0xFF_FFFF, so the top byte is zero and the low 3 carry the value.
        let [_, f0, f1, f2] = self.frame_id.to_be_bytes();
        // byte 5: CODEC_ID(4) | FRAME_TYPE(2) | PRIORITY(2)
        let byte5 = bitpack(&[
            (codec_to_bits(self.codec), 4),
            (frame_type_to_bits(self.frame_type), 2),
            (priority_to_bits(self.priority), 0),
        ]);
        // byte 6: MONITOR_ID(4) | MARKER(1) | RESERVED(3)=0
        let byte6 = bitpack(&[(self.monitor_id, 4), (u8::from(self.marker), 3)]);
        let [e0, e1, e2, e3] = self.encode_ts_us.to_be_bytes();
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
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        let [f0, f1, f2, frag_index, total_frags, byte5, byte6, reserved, e0, e1, e2, e3] =
            take_array::<VIDEO_HEADER_LEN>(data)?;
        if reserved != 0 || (byte6 & 0x07) != 0 {
            return Err(ProtocolError::ReservedBitsSet);
        }
        Ok(Self {
            frame_id: u32::from_be_bytes([0, f0, f1, f2]),
            frag_index,
            total_frags,
            codec: codec_from_bits(byte5 >> 4)?,
            frame_type: frame_type_from_bits((byte5 >> 2) & 0x03)?,
            priority: priority_from_bits(byte5 & 0x03)?,
            monitor_id: byte6 >> 4,
            marker: (byte6 & 0x08) != 0,
            encode_ts_us: u32::from_be_bytes([e0, e1, e2, e3]),
        })
    }
}

// --- internal helpers -------------------------------------------------------------------------

/// Copy the first `N` bytes of `data` into a fixed array, or report truncation. No panics, no
/// indexing: `get(..N)` bounds-checks and `try_into` cannot fail once the length is known.
fn take_array<const N: usize>(data: &[u8]) -> Result<[u8; N], ProtocolError> {
    let slice = data.get(..N).ok_or(ProtocolError::Truncated {
        needed: N,
        have: data.len(),
    })?;
    <[u8; N]>::try_from(slice).map_err(|_| ProtocolError::Truncated {
        needed: N,
        have: data.len(),
    })
}

/// Pack `(value, left_shift)` pairs into a single byte by OR-ing each value shifted left.
///
/// Every caller passes constant shifts `<= 6` and pre-masked small values, so no shift overflows and
/// no bits collide; the loop uses wrapping shifts to stay clear of the `arithmetic_side_effects` lint
/// while remaining exactly equivalent for these in-range shifts.
fn bitpack(parts: &[(u8, u32)]) -> u8 {
    let mut out = 0u8;
    for &(value, shift) in parts {
        out |= value.wrapping_shl(shift);
    }
    out
}

/// Pack two single-bit values into the low two bits: `hi` at bit 1, `lo` at bit 0.
fn pack2(hi: u8, lo: u8) -> u8 {
    hi.wrapping_shl(1) | lo
}

fn channel_to_bits(channel: ChannelId) -> u8 {
    match channel {
        ChannelId::Video => 0,
        ChannelId::Audio => 1,
        ChannelId::Input => 2,
        ChannelId::Clipboard => 3,
        ChannelId::File => 4,
        ChannelId::Control => 5,
    }
}

fn channel_from_bits(bits: u8) -> Result<ChannelId, ProtocolError> {
    match bits {
        0 => Ok(ChannelId::Video),
        1 => Ok(ChannelId::Audio),
        2 => Ok(ChannelId::Input),
        3 => Ok(ChannelId::Clipboard),
        4 => Ok(ChannelId::File),
        5 => Ok(ChannelId::Control),
        other => Err(ProtocolError::InvalidChannel(other)),
    }
}

fn codec_to_bits(codec: Codec) -> u8 {
    match codec {
        Codec::H264 => 0,
        Codec::H265 => 1,
        Codec::Av1 => 2,
    }
}

fn codec_from_bits(bits: u8) -> Result<Codec, ProtocolError> {
    match bits {
        0 => Ok(Codec::H264),
        1 => Ok(Codec::H265),
        2 => Ok(Codec::Av1),
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
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn common_header_known_layout() {
        let h = CommonHeader {
            channel: ChannelId::Input,
            flags: Flags {
                fragment: true,
                last_fragment: false,
            },
            sequence: 0x0102,
            timestamp_us: 0x0304_0506,
            payload_len: 0x0708,
        };
        let bytes = h.encode();
        // VER=01, CHANNEL=0010 (Input=2), FLAGS=10 (fragment, !last) => 0b01_0010_10 = 0x4A
        assert_eq!(
            bytes,
            [0x4A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(CommonHeader::decode(&bytes), Ok(h));
    }

    #[test]
    fn video_header_known_layout() {
        let h = VideoHeader {
            frame_id: 0x00AB_CDEF & MAX_FRAME_ID,
            frag_index: 3,
            total_frags: 7,
            codec: Codec::H265,
            frame_type: FrameType::Idr,
            priority: Priority::High,
            monitor_id: 0x0A,
            marker: true,
            encode_ts_us: 0xDEAD_BEEF,
        };
        let bytes = h.encode().expect("valid header encodes");
        // byte5: CODEC=0001 FRAME_TYPE=01 PRIORITY=10 => 0b0001_01_10 = 0x16
        // byte6: MONITOR=1010 MARKER=1 RESERVED=000 => 0b1010_1_000 = 0xA8
        assert_eq!(bytes[5], 0x16);
        assert_eq!(bytes[6], 0xA8);
        assert_eq!(VideoHeader::decode(&bytes), Ok(h));
    }

    #[test]
    fn decode_rejects_truncation() {
        assert!(matches!(
            CommonHeader::decode(&[0u8; 8]),
            Err(ProtocolError::Truncated { needed: 9, have: 8 })
        ));
        assert!(matches!(
            VideoHeader::decode(&[0u8; 11]),
            Err(ProtocolError::Truncated {
                needed: 12,
                have: 11
            })
        ));
    }

    #[test]
    fn decode_rejects_bad_version() {
        // version bits 11 (0xC0) is not SHP_VERSION (01)
        let bytes = [0xC0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            CommonHeader::decode(&bytes),
            Err(ProtocolError::UnsupportedVersion(0b11))
        );
    }

    #[test]
    fn decode_rejects_unknown_channel() {
        // VER=01, CHANNEL=1111 (15, invalid), FLAGS=00 => 0b01_1111_00 = 0x7C
        let bytes = [0x7C, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            CommonHeader::decode(&bytes),
            Err(ProtocolError::InvalidChannel(15))
        );
    }

    #[test]
    fn encode_rejects_oversized_fields() {
        let mut h = VideoHeader {
            frame_id: MAX_FRAME_ID + 1,
            frag_index: 0,
            total_frags: 1,
            codec: Codec::H264,
            frame_type: FrameType::Predicted,
            priority: Priority::Normal,
            monitor_id: 0,
            marker: false,
            encode_ts_us: 0,
        };
        assert_eq!(
            h.encode(),
            Err(ProtocolError::FrameIdTooLarge(MAX_FRAME_ID + 1))
        );
        h.frame_id = 0;
        h.monitor_id = MAX_MONITOR_ID + 1;
        assert_eq!(
            h.encode(),
            Err(ProtocolError::MonitorIdTooLarge(MAX_MONITOR_ID + 1))
        );
    }

    fn arb_channel() -> impl Strategy<Value = ChannelId> {
        prop_oneof![
            Just(ChannelId::Video),
            Just(ChannelId::Audio),
            Just(ChannelId::Input),
            Just(ChannelId::Clipboard),
            Just(ChannelId::File),
            Just(ChannelId::Control),
        ]
    }

    proptest! {
        #[test]
        fn common_header_roundtrips(
            channel in arb_channel(),
            fragment in any::<bool>(),
            last_fragment in any::<bool>(),
            sequence in any::<u16>(),
            timestamp_us in any::<u32>(),
            payload_len in any::<u16>(),
        ) {
            let h = CommonHeader {
                channel,
                flags: Flags { fragment, last_fragment },
                sequence,
                timestamp_us,
                payload_len,
            };
            prop_assert_eq!(CommonHeader::decode(&h.encode()), Ok(h));
        }

        #[test]
        fn video_header_roundtrips(
            frame_id in 0u32..=MAX_FRAME_ID,
            frag_index in any::<u8>(),
            total_frags in any::<u8>(),
            codec_bits in 0u8..=2,
            frame_type_bits in 0u8..=2,
            priority_bits in 0u8..=2,
            monitor_id in 0u8..=MAX_MONITOR_ID,
            marker in any::<bool>(),
            encode_ts_us in any::<u32>(),
        ) {
            let h = VideoHeader {
                frame_id,
                frag_index,
                total_frags,
                codec: codec_from_bits(codec_bits).unwrap(),
                frame_type: frame_type_from_bits(frame_type_bits).unwrap(),
                priority: priority_from_bits(priority_bits).unwrap(),
                monitor_id,
                marker,
                encode_ts_us,
            };
            let bytes = h.encode().unwrap();
            prop_assert_eq!(VideoHeader::decode(&bytes), Ok(h));
        }

        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            // The contract: decoding arbitrary bytes returns Ok/Err but never panics or hangs.
            let _ = CommonHeader::decode(&data);
            let _ = VideoHeader::decode(&data);
        }
    }
}
