//! The [`AudioEncodedPacket`] produced by an [`AudioEncoder`](crate::AudioEncoder).

use bytes::Bytes;
use sh_protocol::Codec;
use sh_types::TimestampUs;

/// One encoded audio frame ready to be packetized onto the SHP audio channel.
///
/// The buffer format depends on the [`Codec`]: for [`Codec::Raw`] it is a
/// self-describing header followed by interleaved i16 LE PCM samples (see
/// `sh-codec-hw::RawAudioEncoder`). Future Opus frames will carry the raw Opus
/// packet bytes directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioEncodedPacket {
    /// The encoded audio bitstream.
    pub data: Bytes,
    /// Capture timestamp in microseconds since the session epoch.
    pub capture_ts_us: TimestampUs,
    /// Monotonic sequence number matching the source [`AudioFrame`](crate::AudioFrame).
    pub seq: u64,
    /// Codec that produced `data`.
    pub codec: Codec,
}
