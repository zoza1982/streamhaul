//! The [`EncodedPacket`] produced by a [`VideoEncoder`](crate::VideoEncoder).

use bytes::Bytes;
use sh_protocol::{Codec, FrameType};
use sh_types::{FrameId, TimestampUs};

/// One encoded frame (or frame fragment set) ready to be packetized onto the SHP video channel.
///
/// The fields map directly onto `sh_protocol::VideoHeader`: `frame_id` → `frame_id`,
/// `capture_ts_us` → `VideoHeader::encode_ts_us`, plus `codec` and `frame_type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedPacket {
    /// The encoded bitstream for this frame.
    pub data: Bytes,
    /// Codec that produced `data`.
    pub codec: Codec,
    /// Frame identifier this packet encodes (matches the source [`VideoFrame`](crate::VideoFrame)).
    pub frame_id: FrameId,
    /// Capture timestamp carried through for end-to-end latency measurement
    /// (maps to `sh_protocol::VideoHeader::encode_ts_us`).
    pub capture_ts_us: TimestampUs,
    /// Coding type of this frame (delta / IDR / intra-refresh) — the full protocol vocabulary, not a
    /// keyframe boolean, so an intra-refresh frame is representable.
    pub frame_type: FrameType,
}
