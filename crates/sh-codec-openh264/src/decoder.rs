//! [`OpenH264Decoder`] — the native software H.264 decoder (Annex-B → [`VideoFrame`]).
//!
//! The **production** decoder for the browser path is the browser's own WebCodecs `VideoDecoder`;
//! this native decoder exists for non-browser clients and for the round-trip pipeline test (ADR-0029).

use bytes::Bytes;
use openh264::decoder::{Decoder, DecoderConfig};
use openh264::formats::YUVSource;
use openh264::OpenH264API;

use sh_media::{
    DecoderCaps, EncodedPacket, MediaError, PixelFormat, Resolution, VideoDecoder, VideoFrame,
};
use sh_protocol::Codec;

/// A software H.264 decoder backed by OpenH264. Decodes **Annex-B** packets into BGRA [`VideoFrame`]s.
pub struct OpenH264Decoder {
    decoder: Decoder,
    /// Reusable RGBA scratch buffer (avoids a per-frame allocation; reused across decodes).
    rgba: Vec<u8>,
}

impl OpenH264Decoder {
    /// Create a software H.264 decoder.
    ///
    /// # Errors
    /// Returns [`MediaError::Decode`] if the OpenH264 decoder cannot be initialized.
    pub fn new() -> Result<Self, MediaError> {
        let api = OpenH264API::from_source();
        let config = DecoderConfig::new();
        let decoder = Decoder::with_api_config(api, config)
            .map_err(|e| MediaError::Decode(format!("OpenH264 decoder init failed: {e}")))?;
        Ok(Self {
            decoder,
            rgba: Vec::new(),
        })
    }
}

impl VideoDecoder for OpenH264Decoder {
    fn decode(&mut self, packet: &EncodedPacket) -> Result<Option<VideoFrame>, MediaError> {
        if packet.codec != Codec::H264 {
            return Err(MediaError::Decode(format!(
                "OpenH264Decoder expects H264, got {:?}",
                packet.codec
            )));
        }

        // OpenH264 buffers internally; a packet carrying only SPS/PPS (or a partial AU) yields None
        // until a full picture is available — surface that as "need more input".
        let Some(img) = self
            .decoder
            .decode(&packet.data)
            .map_err(|e| MediaError::Decode(format!("OpenH264 decode failed: {e}")))?
        else {
            return Ok(None);
        };

        let (w, h) = img.dimensions();
        if w == 0 || h == 0 {
            // A decoded picture with no luma plane is not displayable — treat as no frame.
            return Ok(None);
        }

        // OpenH264 emits RGBA; size the buffer EXACTLY w*h*4 (write_rgba8 panics on a size mismatch
        // — avoided here by sizing from the same img.dimensions() — and also asserts the decoded
        // image is I420, which is always true for OpenH264 decode output), then swap R<->B in place
        // to produce BGRA (PixelFormat::Bgra8).
        let rgba_len = w
            .checked_mul(h)
            .and_then(|n| n.checked_mul(4))
            .ok_or_else(|| MediaError::Decode("decoded dimensions overflow".to_string()))?;
        self.rgba.clear();
        self.rgba.resize(rgba_len, 0);
        img.write_rgba8(&mut self.rgba);
        for px in self.rgba.chunks_exact_mut(4) {
            px.swap(0, 2); // RGBA -> BGRA
        }

        let width = u32::try_from(w)
            .map_err(|_| MediaError::Decode("decoded width exceeds u32".to_string()))?;
        let height = u32::try_from(h)
            .map_err(|_| MediaError::Decode("decoded height exceeds u32".to_string()))?;

        Ok(Some(VideoFrame {
            data: Bytes::copy_from_slice(&self.rgba),
            format: PixelFormat::Bgra8,
            resolution: Resolution::new(width, height),
            frame_id: packet.frame_id,
            capture_ts_us: packet.capture_ts_us,
        }))
    }

    fn caps(&self) -> DecoderCaps {
        DecoderCaps {
            codec: Codec::H264,
            hardware: false,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::test_support::synthetic_bgra_seq;
    use crate::OpenH264Encoder;
    use sh_media::VideoEncoder;
    use sh_types::{FrameId, TimestampUs};

    #[test]
    fn decodes_encoder_keyframe_to_bgra_frame() {
        let mut enc = OpenH264Encoder::new().unwrap();
        enc.request_keyframe();
        let pkt = enc
            .encode(&synthetic_bgra_seq(64, 48, 3))
            .unwrap()
            .expect("keyframe packet");

        let mut dec = OpenH264Decoder::new().unwrap();
        let frame = dec
            .decode(&pkt)
            .unwrap()
            .expect("a keyframe must decode to a frame");
        assert_eq!(frame.format, PixelFormat::Bgra8);
        assert_eq!(frame.resolution, Resolution::new(64, 48));
        assert_eq!(frame.data.len(), 64 * 48 * 4);
        // Frame id + capture timestamp propagate through the codec.
        assert_eq!(frame.frame_id, FrameId(3));
        assert_eq!(frame.capture_ts_us, TimestampUs(3000));
        frame
            .validate_len()
            .expect("decoded frame length must be self-consistent");
    }

    #[test]
    fn round_trip_preserves_channel_order() {
        // The whole risk of this codec is the BGRA↔RGBA channel handling. Encode a SOLID known
        // color and assert the decoded pixels are that color within YUV 4:2:0 round-trip tolerance.
        // A swapped R/B would land ~170 off (30 vs 200), far outside tolerance — so this pins order.
        const B: u8 = 30;
        const G: u8 = 150;
        const R: u8 = 200;
        let (w, h) = (64u32, 48u32);
        let mut data = vec![0u8; (w as usize) * (h as usize) * 4];
        for px in data.chunks_exact_mut(4) {
            px[0] = B;
            px[1] = G;
            px[2] = R;
            px[3] = 255;
        }
        let frame = VideoFrame {
            data: Bytes::from(data),
            format: PixelFormat::Bgra8,
            resolution: Resolution::new(w, h),
            frame_id: FrameId(1),
            capture_ts_us: TimestampUs(0),
        };

        let mut enc = OpenH264Encoder::new().unwrap();
        enc.request_keyframe();
        let pkt = enc.encode(&frame).unwrap().expect("keyframe packet");
        let mut dec = OpenH264Decoder::new().unwrap();
        let out = dec.decode(&pkt).unwrap().expect("decoded frame");

        // Sample an interior pixel (avoid edges where chroma interpolation differs most).
        let stride = w as usize * 4;
        let idx = (h as usize / 2) * stride + (w as usize / 2) * 4;
        let (db, dg, dr) = (out.data[idx], out.data[idx + 1], out.data[idx + 2]);
        let tol = 12i32;
        assert!(
            (i32::from(db) - i32::from(B)).abs() <= tol,
            "B channel: got {db}, want ~{B}"
        );
        assert!(
            (i32::from(dg) - i32::from(G)).abs() <= tol,
            "G channel: got {dg}, want ~{G}"
        );
        assert!(
            (i32::from(dr) - i32::from(R)).abs() <= tol,
            "R channel: got {dr}, want ~{R}"
        );
    }

    #[test]
    fn rejects_non_h264_packet() {
        let mut dec = OpenH264Decoder::new().unwrap();
        let pkt = EncodedPacket {
            data: Bytes::from_static(&[0, 0, 0, 1, 0x65]),
            codec: Codec::Raw,
            frame_id: FrameId(0),
            capture_ts_us: TimestampUs(0),
            frame_type: sh_protocol::FrameType::Idr,
        };
        assert!(matches!(dec.decode(&pkt), Err(MediaError::Decode(_))));
    }

    #[test]
    fn decoder_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<OpenH264Decoder>();
    }
}
