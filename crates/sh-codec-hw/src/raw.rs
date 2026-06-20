//! A portable, lossless **raw** codec: the "encoded" bitstream is the pixel buffer prefixed with a
//! small self-describing header. It exists so the Phase-0 pipeline has a real, testable encode/decode
//! path with no hardware or C dependencies. Decoding treats the bitstream as untrusted and never panics.

use bytes::Bytes;
use sh_media::{
    DecoderCaps, EncodedPacket, EncoderCaps, MediaError, PixelFormat, Resolution, VideoDecoder,
    VideoEncoder, VideoFrame,
};
use sh_protocol::{Codec, FrameType};

/// Length of the raw bitstream header: `version(1) | format(1) | width(4) | height(4)`.
pub const RAW_HEADER_LEN: usize = 10;

/// Bitstream format version, bumped on any incompatible header change.
const RAW_VERSION: u8 = 1;

// `format_to_u8` is exhaustive (adding a `PixelFormat` variant breaks compilation here, forcing the
// developer to this file); keep `format_from_u8` directly below it in sync.
fn format_to_u8(format: PixelFormat) -> u8 {
    match format {
        PixelFormat::Bgra8 => 0,
        PixelFormat::I420 => 1,
        PixelFormat::Nv12 => 2,
    }
}

fn format_from_u8(byte: u8) -> Option<PixelFormat> {
    match byte {
        0 => Some(PixelFormat::Bgra8),
        1 => Some(PixelFormat::I420),
        2 => Some(PixelFormat::Nv12),
        _ => None,
    }
}

/// Lossless raw encoder: emits the frame's pixels verbatim behind a [`RAW_HEADER_LEN`]-byte header.
#[derive(Debug, Default, Clone)]
pub struct RawEncoder;

impl RawEncoder {
    /// Create a raw encoder.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl VideoEncoder for RawEncoder {
    /// # Errors
    /// Returns [`MediaError::FrameSize`] if `frame.data` is inconsistent with its format/resolution.
    // TODO(perf): this copies the whole pixel buffer behind the header every frame (~8 MB at 1080p).
    // A scatter-gather `EncodedPacket` (header `Bytes` chained with the frame's `Bytes`) would make
    // raw encode zero-copy; deferred until the pipeline justifies the API change.
    fn encode(&mut self, frame: &VideoFrame) -> Result<Option<EncodedPacket>, MediaError> {
        frame.validate_len()?;
        let [w0, w1, w2, w3] = frame.resolution.width.to_be_bytes();
        let [h0, h1, h2, h3] = frame.resolution.height.to_be_bytes();
        let mut buf = Vec::with_capacity(RAW_HEADER_LEN.saturating_add(frame.data.len()));
        buf.extend_from_slice(&[
            RAW_VERSION,
            format_to_u8(frame.format),
            w0,
            w1,
            w2,
            w3,
            h0,
            h1,
            h2,
            h3,
        ]);
        buf.extend_from_slice(&frame.data);
        Ok(Some(EncodedPacket {
            data: Bytes::from(buf),
            codec: Codec::Raw,
            frame_id: frame.frame_id,
            capture_ts_us: frame.capture_ts_us,
            // Every raw frame is independently decodable.
            frame_type: FrameType::Idr,
        }))
    }

    fn request_keyframe(&mut self) {
        // Raw frames are always keyframes; nothing to do.
    }

    fn caps(&self) -> EncoderCaps {
        EncoderCaps {
            codec: Codec::Raw,
            hardware: false,
            max_resolution: Resolution::new(u32::MAX, u32::MAX),
            // Raw is format-agnostic: it records the frame's format in the header and passes pixels
            // through verbatim, so the pipeline never needs to convert (empty = accepts any).
            accepted_input_formats: &[],
        }
    }
}

/// Decoder for [`RawEncoder`] bitstreams. Reconstructs the [`VideoFrame`], carrying the frame id and
/// capture timestamp from the [`EncodedPacket`].
#[derive(Debug, Default, Clone)]
pub struct RawDecoder;

impl RawDecoder {
    /// Create a raw decoder.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl VideoDecoder for RawDecoder {
    /// # Errors
    /// Returns [`MediaError::Decode`] if `packet.codec` is not [`Codec::Raw`], or the bitstream is
    /// truncated, carries an unknown version or format byte, declares a zero dimension, or its pixel
    /// length does not match the declared format and resolution.
    fn decode(&mut self, packet: &EncodedPacket) -> Result<Option<VideoFrame>, MediaError> {
        if packet.codec != Codec::Raw {
            return Err(MediaError::Decode(format!(
                "raw: unexpected codec {:?}",
                packet.codec
            )));
        }
        let header: [u8; RAW_HEADER_LEN] = packet
            .data
            .get(..RAW_HEADER_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| MediaError::Decode("raw: truncated header".to_owned()))?;
        let [version, fmt, w0, w1, w2, w3, h0, h1, h2, h3] = header;
        if version != RAW_VERSION {
            return Err(MediaError::Decode(format!(
                "raw: unknown version {version}"
            )));
        }
        let format = format_from_u8(fmt)
            .ok_or_else(|| MediaError::Decode(format!("raw: bad format {fmt}")))?;
        let resolution = Resolution::new(
            u32::from_be_bytes([w0, w1, w2, w3]),
            u32::from_be_bytes([h0, h1, h2, h3]),
        );
        if resolution.width == 0 || resolution.height == 0 {
            return Err(MediaError::Decode("raw: zero-dimension frame".to_owned()));
        }
        // Pixels follow the header; the slice range is in bounds because the header parsed.
        let pixels = packet.data.slice(RAW_HEADER_LEN..);
        let expected = format.frame_len(resolution);
        if pixels.len() != expected {
            return Err(MediaError::Decode(format!(
                "raw: pixel length {} != expected {expected}",
                pixels.len()
            )));
        }
        Ok(Some(VideoFrame {
            data: pixels,
            format,
            resolution,
            frame_id: packet.frame_id,
            capture_ts_us: packet.capture_ts_us,
        }))
    }

    fn caps(&self) -> DecoderCaps {
        DecoderCaps {
            codec: Codec::Raw,
            hardware: false,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use sh_media::{ScreenCapturer, SyntheticCapturer};
    use sh_types::{FrameId, TimestampUs};
    use std::time::Duration;

    #[test]
    fn roundtrips_all_formats_at_odd_dims() {
        // Odd dimensions exercise 4:2:0 chroma rounding in frame_len; the codec must be lossless and
        // must carry frame_id / capture_ts from the source frame through the packet.
        for format in [PixelFormat::Bgra8, PixelFormat::I420, PixelFormat::Nv12] {
            let resolution = Resolution::new(3, 5);
            let len = format.frame_len(resolution);
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let frame = VideoFrame {
                data: Bytes::from(data),
                format,
                resolution,
                frame_id: FrameId(42),
                capture_ts_us: TimestampUs(7),
            };
            let packet = RawEncoder::new().encode(&frame).unwrap().unwrap();
            let decoded = RawDecoder::new().decode(&packet).unwrap().unwrap();
            assert_eq!(decoded, frame, "lossless roundtrip for {format:?}");
            assert_eq!(decoded.frame_id, FrameId(42));
            assert_eq!(decoded.capture_ts_us, TimestampUs(7));
        }
    }

    #[test]
    fn roundtrips_a_synthetic_frame() {
        let mut cap = SyntheticCapturer::new(Resolution::new(32, 24), 60);
        let mut enc = RawEncoder::new();
        let mut dec = RawDecoder::new();

        let frame = cap.next_frame(Duration::ZERO).unwrap().unwrap();
        let packet = enc.encode(&frame).unwrap().unwrap();
        assert_eq!(packet.codec, Codec::Raw);
        assert_eq!(packet.frame_type, FrameType::Idr);
        assert_eq!(packet.frame_id, frame.frame_id);

        let decoded = dec.decode(&packet).unwrap().unwrap();
        assert_eq!(decoded, frame, "raw codec must be lossless");
    }

    #[test]
    fn encode_rejects_inconsistent_frame() {
        let mut enc = RawEncoder::new();
        let bad = VideoFrame {
            data: Bytes::from_static(&[0u8; 4]),
            format: PixelFormat::Bgra8,
            resolution: Resolution::new(4, 4), // needs 64 bytes
            frame_id: FrameId(0),
            capture_ts_us: TimestampUs(0),
        };
        assert!(matches!(
            enc.encode(&bad),
            Err(MediaError::FrameSize { .. })
        ));
    }

    #[test]
    fn decode_rejects_malformed_without_panicking() {
        let mut dec = RawDecoder::new();
        let pkt = |data: &'static [u8]| EncodedPacket {
            data: Bytes::from_static(data),
            codec: Codec::Raw,
            frame_id: FrameId(0),
            capture_ts_us: TimestampUs(0),
            frame_type: FrameType::Idr,
        };
        // Truncated header.
        assert!(matches!(
            dec.decode(&pkt(&[1, 0, 0])),
            Err(MediaError::Decode(_))
        ));
        // Bad version (99) with a full 10-byte header.
        assert!(matches!(
            dec.decode(&pkt(&[99, 0, 0, 0, 0, 1, 0, 0, 0, 1])),
            Err(MediaError::Decode(_))
        ));
        // Valid header (1×1 Bgra8 needs 4 pixel bytes) but zero pixels.
        assert!(matches!(
            dec.decode(&pkt(&[1, 0, 0, 0, 0, 1, 0, 0, 0, 1])),
            Err(MediaError::Decode(_))
        ));
        // Unknown format byte (7).
        assert!(matches!(
            dec.decode(&pkt(&[1, 7, 0, 0, 0, 1, 0, 0, 0, 1])),
            Err(MediaError::Decode(_))
        ));
        // Zero-dimension frame (width = 0) is rejected before the length check.
        assert!(matches!(
            dec.decode(&pkt(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 1])),
            Err(MediaError::Decode(_))
        ));
    }

    #[test]
    fn decode_rejects_wrong_codec() {
        let mut dec = RawDecoder::new();
        let not_raw = EncodedPacket {
            data: Bytes::from_static(&[1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0]),
            codec: Codec::H264,
            frame_id: FrameId(0),
            capture_ts_us: TimestampUs(0),
            frame_type: FrameType::Idr,
        };
        assert!(matches!(dec.decode(&not_raw), Err(MediaError::Decode(_))));
    }

    #[test]
    fn caps_report_software_raw() {
        assert_eq!(RawEncoder::new().caps().codec, Codec::Raw);
        assert!(!RawEncoder::new().caps().hardware);
        assert_eq!(RawDecoder::new().caps().codec, Codec::Raw);
    }
}
