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
}

/// Fragment an [`EncodedPacket`] into QUIC datagrams.
///
/// Each datagram contains a [`CommonHeader`] and [`VideoHeader`] followed by a
/// chunk of the encoded payload. The number of fragments is at most 255.
///
/// # Errors
///
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
    let chunk_size = max_datagram.saturating_sub(combined_header).max(1);

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
/// Buffers up to [`MAX_BUFFERED_FRAMES`] incomplete frames at a time, evicting
/// the oldest frame when the buffer is full.
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
