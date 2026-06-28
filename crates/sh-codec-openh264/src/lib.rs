#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Software H.264 encoder via OpenH264 — Streamhaul (ADR-0028).
//!
//! This crate is **excluded from the workspace** (see the root `Cargo.toml` `exclude` list), so the
//! default `cargo build/clippy/test --workspace --all-features` never compiles the vendored OpenH264
//! C source. It is built only by its dedicated `codec-openh264` CI job and by a build that explicitly
//! depends on it. This enforces the licensing posture below and keeps the heavy C build off every
//! cross-OS CI run (the same reason the wasm crates are excluded).
//!
//! [`OpenH264Encoder`] implements [`sh_media::VideoEncoder`], producing **Annex-B** H.264 a browser's
//! WebCodecs `VideoDecoder` can decode. Input frames must be [`sh_media::PixelFormat::Bgra8`] with
//! **even** dimensions (4:2:0 chroma); each frame is converted BGRA→RGB into a reusable scratch
//! buffer, then RGB→YUV by OpenH264.
//!
//! # Licensing / scope (read this)
//!
//! A **preview / non-distribution** encoder. H.264 is covered by the MPEG-LA AVC patent pool; Cisco's
//! royalty-free grant applies only to **Cisco's pre-built OpenH264 binary**, NOT to OpenH264 **built
//! from source** (which `OpenH264API::from_source()` does). So linking this crate is licensing-gated,
//! the same posture as the `hevc` feature (`docs/adr/0004-oss-codec-and-licensing.md`, ADR-0028). The
//! real low-latency path remains hardware encode (NVENC / VA-API / VideoToolbox / Media Foundation),
//! tracked as R-CODEC.

use bytes::Bytes;
use openh264::encoder::{Encoder, EncoderConfig, FrameType as OhFrameType};
use openh264::formats::{RgbSliceU8, YUVBuffer};
use openh264::OpenH264API;

use sh_media::{
    EncodedPacket, EncoderCaps, MediaError, PixelFormat, Resolution, VideoEncoder, VideoFrame,
};
use sh_protocol::{Codec, FrameType};

/// A software H.264 encoder backed by OpenH264. See the [module docs](self) for the licensing scope.
pub struct OpenH264Encoder {
    encoder: Encoder,
    /// Reusable BGRA→RGB scratch buffer (avoids a per-frame allocation on the hot path).
    rgb: Vec<u8>,
    /// Set by [`request_keyframe`](VideoEncoder::request_keyframe); forces the next frame to IDR.
    force_keyframe: bool,
}

impl OpenH264Encoder {
    /// Create a software H.264 encoder with OpenH264's default rate-control config.
    ///
    /// Bitrate/fps tuning from a [`sh_media::EncoderConfig`] is a follow-up (the host wires the
    /// allocator's target in); v1 uses OpenH264's defaults.
    ///
    /// # Errors
    /// Returns [`MediaError::Encode`] if the OpenH264 encoder cannot be initialized.
    pub fn new() -> Result<Self, MediaError> {
        let api = OpenH264API::from_source();
        let config = EncoderConfig::new();
        let encoder = Encoder::with_api_config(api, config)
            .map_err(|e| MediaError::Encode(format!("OpenH264 encoder init failed: {e}")))?;
        Ok(Self {
            encoder,
            rgb: Vec::new(),
            force_keyframe: false,
        })
    }
}

impl VideoEncoder for OpenH264Encoder {
    // Indices below are all bounded by `chunks_exact(4)` / `chunks_exact_mut(3)` (exact-length
    // slices) and the up-front even/non-zero dimension check; none can be out of bounds.
    #[allow(clippy::indexing_slicing)]
    fn encode(&mut self, frame: &VideoFrame) -> Result<Option<EncodedPacket>, MediaError> {
        if frame.format != PixelFormat::Bgra8 {
            return Err(MediaError::Encode(format!(
                "OpenH264Encoder requires Bgra8 input, got {:?}",
                frame.format
            )));
        }
        frame.validate_len()?;

        let w = frame.resolution.width as usize;
        let h = frame.resolution.height as usize;
        // OpenH264 4:2:0 requires non-zero, even dimensions.
        if w == 0 || h == 0 || (w & 1) != 0 || (h & 1) != 0 {
            return Err(MediaError::Encode(format!(
                "OpenH264 requires non-zero even dimensions, got {w}x{h}"
            )));
        }

        // BGRA → RGB into the reusable scratch buffer.
        let rgb_len = w
            .checked_mul(h)
            .and_then(|n| n.checked_mul(3))
            .ok_or_else(|| MediaError::Encode("frame dimensions overflow".to_string()))?;
        self.rgb.clear();
        self.rgb.resize(rgb_len, 0);
        for (src, dst) in frame.data.chunks_exact(4).zip(self.rgb.chunks_exact_mut(3)) {
            dst[0] = src[2]; // R
            dst[1] = src[1]; // G
            dst[2] = src[0]; // B
        }

        // RGB → YUV (owned by `yuv`; the borrow of `self.rgb` ends with this statement).
        let yuv = YUVBuffer::from_rgb_source(RgbSliceU8::new(&self.rgb, (w, h)));

        if self.force_keyframe {
            self.encoder.force_intra_frame();
            self.force_keyframe = false;
        }

        let bitstream = self
            .encoder
            .encode(&yuv)
            .map_err(|e| MediaError::Encode(format!("OpenH264 encode failed: {e}")))?;

        let frame_type = match bitstream.frame_type() {
            // The encoder skipped this frame (rate control) or isn't ready — no packet.
            OhFrameType::Skip | OhFrameType::Invalid => return Ok(None),
            // IDR and plain-I are full intra frames — valid stream join / seek points.
            OhFrameType::IDR | OhFrameType::I => FrameType::Idr,
            // IPMixed mixes I and P slices: it carries an intra refresh but still depends on prior
            // frames, so it is NOT a full keyframe and must not be advertised as a seek point.
            OhFrameType::IPMixed => FrameType::IntraRefresh,
            OhFrameType::P => FrameType::Predicted,
        };

        let data = bitstream.to_vec();
        if data.is_empty() {
            return Ok(None);
        }

        Ok(Some(EncodedPacket {
            data: Bytes::from(data),
            codec: Codec::H264,
            frame_id: frame.frame_id,
            capture_ts_us: frame.capture_ts_us,
            frame_type,
        }))
    }

    fn request_keyframe(&mut self) {
        self.force_keyframe = true;
    }

    // `flush()` is intentionally NOT overridden: OpenH264 is synchronous — each `encode()` either
    // produces or skips a packet immediately, with no inter-call buffering (the returned
    // `EncodedBitStream` borrows `self`, so it cannot retain frames). The trait's default no-op is
    // correct for a non-buffering encoder.

    fn caps(&self) -> EncoderCaps {
        EncoderCaps {
            codec: Codec::H264,
            hardware: false,
            // OpenH264 supports up to 4K+; bound conservatively to a common ceiling.
            max_resolution: Resolution::new(3840, 2160),
            accepted_input_formats: &[PixelFormat::Bgra8],
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
    use openh264::decoder::{Decoder, DecoderConfig};
    use sh_types::{FrameId, TimestampUs};

    fn synthetic_bgra(w: u32, h: u32) -> VideoFrame {
        // seq=7 → FrameId(7); the round-trip test asserts this id propagates to the packet.
        synthetic_bgra_seq(w, h, 7)
    }

    /// Like [`synthetic_bgra`] but the pattern shifts with `seq`, so successive frames differ —
    /// this lets the encoder emit inter-predicted (P) frames instead of repeatedly skipping.
    fn synthetic_bgra_seq(w: u32, h: u32, seq: usize) -> VideoFrame {
        let mut data = vec![0u8; (w as usize) * (h as usize) * 4];
        for (i, px) in data.chunks_exact_mut(4).enumerate() {
            px[0] = ((i + seq * 17) % 251) as u8; // B
            px[1] = ((i / 3 + seq * 7) % 251) as u8; // G
            px[2] = (200 - (seq % 50)) as u8; // R
            px[3] = 255; // A
        }
        VideoFrame {
            data: Bytes::from(data),
            format: PixelFormat::Bgra8,
            resolution: Resolution::new(w, h),
            frame_id: FrameId(seq as u64),
            capture_ts_us: TimestampUs(seq as u64 * 1000),
        }
    }

    #[test]
    fn encodes_decodable_h264_annexb() {
        let mut enc = OpenH264Encoder::new().unwrap();
        enc.request_keyframe();
        let pkt = enc
            .encode(&synthetic_bgra(64, 48))
            .unwrap()
            .expect("first frame should produce a packet");
        assert_eq!(pkt.codec, Codec::H264);
        assert_eq!(pkt.frame_type, FrameType::Idr);
        assert_eq!(pkt.frame_id, FrameId(7));
        // Annex-B 4-byte start code.
        assert_eq!(&pkt.data[..4], &[0, 0, 0, 1]);

        // Decode it back with OpenH264 to prove the bytes are valid, decodable H.264.
        let mut dec =
            Decoder::with_api_config(OpenH264API::from_source(), DecoderConfig::new()).unwrap();
        let img = dec
            .decode(&pkt.data)
            .unwrap()
            .expect("a keyframe must decode to an image");
        // dimensions_uv is the chroma plane size = luma/2 → (32, 24) for a 64x48 frame.
        assert_eq!(img.dimensions_uv(), (32, 24));
    }

    #[test]
    fn rejects_odd_dimensions() {
        let mut enc = OpenH264Encoder::new().unwrap();
        // Odd width.
        assert!(matches!(
            enc.encode(&synthetic_bgra(63, 48)),
            Err(MediaError::Encode(_))
        ));
        // Odd height (the other branch of the even-dimension check).
        assert!(matches!(
            enc.encode(&synthetic_bgra(64, 47)),
            Err(MediaError::Encode(_))
        ));
    }

    #[test]
    fn rejects_zero_dimensions() {
        // A 0x0 frame passes validate_len() (0 bytes == 0 expected), so the dimension guard is the
        // only thing rejecting it — cover the `w == 0 || h == 0` branch explicitly.
        let mut enc = OpenH264Encoder::new().unwrap();
        let frame = VideoFrame {
            data: Bytes::new(),
            format: PixelFormat::Bgra8,
            resolution: Resolution::new(0, 0),
            frame_id: FrameId(0),
            capture_ts_us: TimestampUs(0),
        };
        assert!(matches!(enc.encode(&frame), Err(MediaError::Encode(_))));
    }

    #[test]
    fn emits_predicted_frame_then_forces_keyframe_midstream() {
        let mut enc = OpenH264Encoder::new().unwrap();

        // Drive several differing frames so the encoder produces at least one P frame after the
        // initial IDR — this exercises the OhFrameType::P -> FrameType::Predicted branch, which the
        // single-frame round-trip test cannot reach.
        let mut saw_predicted = false;
        for seq in 0..8 {
            if let Some(pkt) = enc.encode(&synthetic_bgra_seq(64, 48, seq)).unwrap() {
                if pkt.frame_type == FrameType::Predicted {
                    saw_predicted = true;
                    break;
                }
            }
        }
        assert!(
            saw_predicted,
            "encoder should emit at least one predicted (P) frame across differing inputs"
        );

        // Now force a keyframe mid-stream and confirm the next emitted packet is an IDR — a
        // NON-vacuous check (we are already past the always-IDR first frame).
        enc.request_keyframe();
        let mut forced_idr = false;
        for seq in 8..12 {
            if let Some(pkt) = enc.encode(&synthetic_bgra_seq(64, 48, seq)).unwrap() {
                assert_eq!(
                    pkt.frame_type,
                    FrameType::Idr,
                    "the frame after request_keyframe() must be an IDR keyframe"
                );
                forced_idr = true;
                break;
            }
        }
        assert!(forced_idr, "forced keyframe must produce a packet");
    }

    #[test]
    fn encoder_is_send() {
        // The host pipeline moves the encoder across threads; `VideoEncoder: Send` must hold.
        fn assert_send<T: Send>() {}
        assert_send::<OpenH264Encoder>();
    }

    #[test]
    fn rejects_non_bgra_input() {
        let mut enc = OpenH264Encoder::new().unwrap();
        let frame = VideoFrame {
            data: Bytes::from(vec![0u8; 64 * 48 * 3 / 2]), // size is immaterial; format check fires first
            format: PixelFormat::I420,
            resolution: Resolution::new(64, 48),
            frame_id: FrameId(0),
            capture_ts_us: TimestampUs(0),
        };
        assert!(matches!(enc.encode(&frame), Err(MediaError::Encode(_))));
    }

    #[test]
    fn caps_report_software_h264() {
        let enc = OpenH264Encoder::new().unwrap();
        let caps = enc.caps();
        assert_eq!(caps.codec, Codec::H264);
        assert!(!caps.hardware);
        assert_eq!(caps.accepted_input_formats, &[PixelFormat::Bgra8]);
    }
}
