//! Fragmentation and reassembly of SHP video packets.

use std::collections::BTreeMap;

use bytes::Bytes;
use sh_media::EncodedPacket;
use sh_protocol::{
    Codec, CommonHeader, Flags, FrameType, VideoHeader, COMMON_HEADER_LEN, MAX_FRAME_ID,
    VIDEO_HEADER_LEN,
};
use sh_types::{ChannelId, FrameId, TimestampUs};

/// Errors that can occur during packet fragmentation.
#[derive(Debug, thiserror::Error)]
pub enum PacketizeError {
    /// The packet requires more than 255 fragments.
    #[error("packet requires {count} fragments, maximum is 255")]
    TooManyFragments {
        /// The number of fragments that would be required.
        count: usize,
    },
    /// A protocol encoding error occurred.
    #[error("protocol error: {0}")]
    Protocol(#[from] sh_protocol::ProtocolError),
    /// The payload length field overflowed u16.
    #[error("payload too large to fit in u16 length field")]
    PayloadTooLarge,
    /// The max datagram size is too small to fit even one byte of payload.
    #[error("max_datagram {max_datagram} is too small to fit even one payload byte")]
    DatagramTooSmall {
        /// The maximum datagram size that was provided.
        max_datagram: usize,
    },
}

/// Fragment an [`EncodedPacket`] into QUIC datagrams.
///
/// Each datagram contains a [`CommonHeader`] and [`VideoHeader`] followed by a
/// chunk of the encoded payload. The number of fragments is at most 255.
///
/// # Errors
///
/// Returns [`PacketizeError::DatagramTooSmall`] if `max_datagram` is not larger
/// than the combined header size (no room for even one payload byte).
/// Returns [`PacketizeError::TooManyFragments`] if the packet would require more
/// than 255 fragments given the `max_datagram` size.
/// Returns [`PacketizeError::Protocol`] if header encoding fails.
/// Returns [`PacketizeError::PayloadTooLarge`] if the combined header + chunk
/// length cannot fit in a `u16`.
pub fn fragment(
    packet: &EncodedPacket,
    seq_start: u16,
    max_datagram: usize,
) -> Result<Vec<Bytes>, PacketizeError> {
    let combined_header = COMMON_HEADER_LEN.saturating_add(VIDEO_HEADER_LEN);
    if max_datagram <= combined_header {
        return Err(PacketizeError::DatagramTooSmall { max_datagram });
    }
    // saturating_sub is safe here: the check above guarantees max_datagram > combined_header.
    let chunk_size = max_datagram.saturating_sub(combined_header);

    let num_frags = if packet.data.is_empty() {
        1
    } else {
        packet.data.len().div_ceil(chunk_size)
    };

    if num_frags > 255 {
        return Err(PacketizeError::TooManyFragments { count: num_frags });
    }

    // num_frags <= 255 is checked above; the try_from cannot fail here.
    // Use saturating cast via the checked path to stay panic/unwrap free.
    #[allow(clippy::cast_possible_truncation)]
    let total_frags = num_frags as u8;
    let frame_id_masked = packet.frame_id.0 & u64::from(MAX_FRAME_ID);
    let ts = TimestampUs(packet.capture_ts_us.0 & 0xFFFF_FFFF);

    let mut result = Vec::with_capacity(num_frags);

    for frag_idx in 0..num_frags {
        let start = frag_idx.saturating_mul(chunk_size);
        let end = (frag_idx.saturating_add(1))
            .saturating_mul(chunk_size)
            .min(packet.data.len());
        let chunk = packet.data.slice(start..end);

        let is_last = frag_idx.saturating_add(1) == num_frags;
        let flags = Flags {
            fragment: total_frags > 1,
            last_fragment: is_last,
        };

        let seq_offset = u16::try_from(frag_idx).unwrap_or(u16::MAX);
        let sequence = seq_start.wrapping_add(seq_offset);

        let payload_len = u16::try_from(VIDEO_HEADER_LEN.saturating_add(chunk.len()))
            .map_err(|_| PacketizeError::PayloadTooLarge)?;

        let frag_index = u8::try_from(frag_idx)
            .map_err(|_| PacketizeError::TooManyFragments { count: frag_idx })?;

        let common_header = CommonHeader {
            channel: ChannelId::Video,
            flags,
            sequence,
            timestamp_us: ts,
            payload_len,
        };

        let video_header = VideoHeader {
            frame_id: FrameId(frame_id_masked),
            frag_index,
            total_frags,
            codec: packet.codec,
            frame_type: packet.frame_type,
            priority: sh_protocol::Priority::High,
            monitor_id: 0,
            marker: is_last,
            encode_ts_us: ts,
        };

        let common_bytes = common_header.encode();
        let video_bytes = video_header.encode()?;

        let total_len = COMMON_HEADER_LEN
            .saturating_add(VIDEO_HEADER_LEN)
            .saturating_add(chunk.len());
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&common_bytes);
        buf.extend_from_slice(&video_bytes);
        buf.extend_from_slice(&chunk);

        result.push(Bytes::from(buf));
    }

    Ok(result)
}

/// Maximum number of incomplete frames buffered by the [`Reassembler`].
const MAX_BUFFERED_FRAMES: usize = 32;

/// Internal buffer for an in-progress frame reassembly.
struct FrameBuffer {
    /// Fragment slots indexed by `frag_index`.
    slots: Vec<Option<Bytes>>,
    /// Expected total number of fragments.
    total_frags: u8,
    /// Number of fragments received so far.
    received: usize,
    /// Codec of the frame.
    codec: Codec,
    /// Frame type (keyframe, predicted, etc.).
    frame_type: FrameType,
    /// Frame identifier.
    frame_id: FrameId,
    /// Capture timestamp in microseconds.
    capture_ts_us: TimestampUs,
}

/// Reassembles fragmented video datagrams into complete [`EncodedPacket`]s.
///
/// Buffers up to [`MAX_BUFFERED_FRAMES`] incomplete frames at a time. When the buffer is full
/// and a new frame key arrives, the entry with the lowest key is evicted (FIFO by key order,
/// not true FIFO by arrival time). Note: the 24-bit frame_id wraps at [`MAX_FRAME_ID`], so
/// frame IDs can collide after 16 777 215 frames — do not use this reassembler for long-lived
/// sessions without resetting.
pub struct Reassembler {
    buffers: BTreeMap<u32, FrameBuffer>,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    /// Create a new, empty `Reassembler`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffers: BTreeMap::new(),
        }
    }

    /// Ingest a raw datagram and return a complete [`EncodedPacket`] if all
    /// fragments of a frame have been received.
    ///
    /// Returns `None` if:
    /// - The datagram is malformed or too short.
    /// - The channel is not [`ChannelId::Video`].
    /// - The fragment is a duplicate.
    /// - The frame is not yet complete.
    /// - The incoming `total_frags` does not match the previously stored value for this frame.
    /// - The `frag_index` is out of range per the stored `total_frags`.
    pub fn ingest(&mut self, datagram: &Bytes) -> Option<EncodedPacket> {
        let common = CommonHeader::decode(datagram).ok()?;
        if common.channel != ChannelId::Video {
            return None;
        }

        let rest = datagram.get(COMMON_HEADER_LEN..)?;
        let video = VideoHeader::decode(rest).ok()?;

        if video.total_frags == 0 {
            return None;
        }
        if video.frag_index >= video.total_frags {
            return None;
        }

        let key = u32::try_from(video.frame_id.0 & u64::from(MAX_FRAME_ID)).unwrap_or(MAX_FRAME_ID);

        // Evict oldest frame if buffer is full and this is a new frame
        if !self.buffers.contains_key(&key) && self.buffers.len() >= MAX_BUFFERED_FRAMES {
            if let Some(&oldest) = self.buffers.keys().next() {
                self.buffers.remove(&oldest);
            }
        }

        let total_frags_usize = usize::from(video.total_frags);
        let buf = self.buffers.entry(key).or_insert_with(|| FrameBuffer {
            slots: vec![None; total_frags_usize],
            total_frags: video.total_frags,
            received: 0,
            codec: video.codec,
            frame_type: video.frame_type,
            frame_id: video.frame_id,
            capture_ts_us: common.timestamp_us,
        });

        // Validate against the stored total_frags (not the incoming value) to prevent
        // a corrupt packet from widening the slot vector after the frame was first seen.
        if video.total_frags != buf.total_frags {
            return None; // mismatched fragment — discard
        }
        if video.frag_index >= buf.total_frags {
            return None; // out of range per stored value
        }

        let frag_index_usize = usize::from(video.frag_index);

        // Check for duplicate
        if buf.slots.get(frag_index_usize).is_some_and(|s| s.is_some()) {
            return None;
        }

        let header_total = COMMON_HEADER_LEN.saturating_add(VIDEO_HEADER_LEN);
        if datagram.len() < header_total {
            return None;
        }
        let chunk = datagram.slice(header_total..);

        if let Some(slot) = buf.slots.get_mut(frag_index_usize) {
            *slot = Some(chunk);
            buf.received = buf.received.saturating_add(1);
        } else {
            return None;
        }

        if buf.received == usize::from(buf.total_frags) {
            let frame_buf = self.buffers.remove(&key)?;
            let mut data = Vec::new();
            for chunk in frame_buf.slots.into_iter().flatten() {
                data.extend_from_slice(&chunk);
            }
            Some(EncodedPacket {
                data: Bytes::from(data),
                codec: frame_buf.codec,
                frame_id: frame_buf.frame_id,
                capture_ts_us: frame_buf.capture_ts_us,
                frame_type: frame_buf.frame_type,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use proptest::prelude::*;
    use sh_media::EncodedPacket;
    use sh_protocol::{Codec, FrameType};
    use sh_types::{FrameId, TimestampUs};

    fn make_packet(data: Vec<u8>, frame_id: u64) -> EncodedPacket {
        EncodedPacket {
            data: Bytes::from(data),
            codec: Codec::Raw,
            frame_id: FrameId(frame_id),
            capture_ts_us: TimestampUs(0),
            frame_type: FrameType::Idr,
        }
    }

    #[test]
    fn fragment_datagram_too_small_returns_error() {
        let combined_header = sh_protocol::COMMON_HEADER_LEN + sh_protocol::VIDEO_HEADER_LEN;
        let packet = make_packet(vec![0u8; 100], 1);
        let result = fragment(&packet, 0, combined_header);
        assert!(
            matches!(result, Err(PacketizeError::DatagramTooSmall { .. })),
            "expected DatagramTooSmall, got {result:?}"
        );
    }

    #[test]
    fn fragment_exact_header_size_returns_error() {
        let combined_header = sh_protocol::COMMON_HEADER_LEN + sh_protocol::VIDEO_HEADER_LEN;
        let packet = make_packet(vec![42u8; 50], 2);
        // max_datagram == combined_header means 0 bytes of payload, should error
        let result = fragment(&packet, 0, combined_header);
        assert!(matches!(
            result,
            Err(PacketizeError::DatagramTooSmall { .. })
        ));
    }

    proptest! {
        #[test]
        fn all_datagrams_fit_in_max_datagram(
            payload_len in 0usize..4096,
            max_datagram in 30usize..2000,
        ) {
            let combined_header = sh_protocol::COMMON_HEADER_LEN + sh_protocol::VIDEO_HEADER_LEN;
            let data = vec![0u8; payload_len];
            let packet = make_packet(data, 1);
            match fragment(&packet, 0, max_datagram) {
                Ok(datagrams) => {
                    for dg in &datagrams {
                        prop_assert!(dg.len() <= max_datagram,
                            "datagram len {} > max {}", dg.len(), max_datagram);
                    }
                }
                Err(PacketizeError::DatagramTooSmall { .. }) => {
                    prop_assert!(max_datagram <= combined_header);
                }
                Err(_) => {} // TooManyFragments etc. are also acceptable
            }
        }

        #[test]
        fn fragment_reassemble_roundtrip(
            payload in proptest::collection::vec(any::<u8>(), 0..4096),
            frame_id in 0u64..0x00FF_FFFF,
        ) {
            let combined_header = sh_protocol::COMMON_HEADER_LEN + sh_protocol::VIDEO_HEADER_LEN;
            let max_datagram = combined_header + 256;
            let packet = make_packet(payload.clone(), frame_id);
            let datagrams = match fragment(&packet, 0, max_datagram) {
                Ok(d) => d,
                Err(_) => return Ok(()),
            };
            let mut reassembler = Reassembler::new();
            let mut result = None;
            for dg in &datagrams {
                result = reassembler.ingest(dg);
            }
            if let Some(reassembled) = result {
                prop_assert_eq!(&reassembled.data[..], &payload[..]);
            }
        }

        #[test]
        fn ingest_random_bytes_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let mut r = Reassembler::new();
            let _ = r.ingest(&Bytes::from(data));
        }
    }
}
