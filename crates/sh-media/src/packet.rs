//! The [`EncodedPacket`] produced by a [`VideoEncoder`](crate::VideoEncoder).

use bytes::Bytes;
use sh_protocol::Codec;
use sh_types::{FrameId, TimestampUs};

/// One encoded frame (or frame fragment set) ready to be packetized onto the SHP video channel.
///
/// The fields map directly onto the SHP video payload header (`sh_protocol::VideoHeader`): `frame_id`,
/// `capture_ts_us` (→ `ENCODE_TS`), `codec`, and keyframe status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedPacket {
    /// The encoded bitstream for this frame.
    pub data: Bytes,
    /// Codec that produced `data`.
    pub codec: Codec,
    /// Frame identifier this packet encodes (matches the source [`VideoFrame`](crate::VideoFrame)).
    pub frame_id: FrameId,
    /// Capture timestamp carried through for end-to-end latency measurement.
    pub capture_ts_us: TimestampUs,
    /// Whether this packet is independently decodable (a keyframe / IDR).
    pub is_keyframe: bool,
}
