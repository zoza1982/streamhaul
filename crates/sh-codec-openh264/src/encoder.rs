//! [`OpenH264Encoder`] — the software H.264 encoder. See the [crate docs](crate) for licensing scope.

use bytes::Bytes;
use openh264::encoder::{
    BitRate, Encoder, EncoderConfig as OhEncoderConfig, FrameRate, FrameType as OhFrameType,
    IntraFramePeriod, RateControlMode, UsageType,
};
use openh264::formats::{RgbSliceU8, YUVBuffer};
use openh264::OpenH264API;

use sh_media::{
    EncodedPacket, EncoderCaps, EncoderConfig, MediaError, PixelFormat, Resolution, VideoEncoder,
    VideoFrame,
};
use sh_protocol::{Codec, FrameType};

/// Periodic-keyframe (GOP) interval in seconds for bitrate-mode streaming, so a receiver joining
/// mid-stream or recovering from loss gets an IDR within this window (ADR-0035).
const KEYFRAME_INTERVAL_SECS: u32 = 2;

/// A software H.264 encoder backed by OpenH264. See the [crate docs](crate) for the licensing scope.
pub struct OpenH264Encoder {
    encoder: Encoder,
    /// Reusable BGRA→RGB scratch buffer (avoids a per-frame allocation on the hot path).
    rgb: Vec<u8>,
    /// Set by [`request_keyframe`](VideoEncoder::request_keyframe); forces the next frame to IDR.
    force_keyframe: bool,
}

impl OpenH264Encoder {
    /// Create a software H.264 encoder with OpenH264's default rate control (constant-quality),
    /// tuned for **screen content** (remote desktop) rather than camera video.
    ///
    /// Use [`with_config`](Self::with_config) to drive the target bitrate/fps from the negotiated
    /// [`EncoderConfig`] (e.g. the `RateAllocator`'s video budget).
    ///
    /// # Errors
    /// Returns [`MediaError::Encode`] if the OpenH264 encoder cannot be initialized.
    pub fn new() -> Result<Self, MediaError> {
        // No bitrate target ⇒ constant-quality, skip off (the pipeline is the sole drop authority).
        Self::from_oh_config(
            OhEncoderConfig::new()
                .usage_type(UsageType::ScreenContentRealTime)
                .skip_frames(false),
        )
    }

    /// Create a software H.264 encoder configured from a [`sh_media::EncoderConfig`].
    ///
    /// Mapping onto OpenH264 (ADR-0029):
    /// - `codec` must be [`Codec::H264`] (else [`MediaError::Unsupported`]).
    /// - `target_bitrate_kbps`: `Some(k)` → bitrate rate-control at `k` kbps; `None` → OpenH264's
    ///   default constant-quality mode.
    /// - `target_fps` (when non-zero) → sets OpenH264's maximum frame rate (a rate-control hint)
    ///   **and** the periodic-IDR interval to `target_fps × KEYFRAME_INTERVAL_SECS` encoded frames
    ///   (~2 s at full frame rate; ADR-0035). `target_fps == 0` disables BOTH (no periodic keyframe);
    ///   `request_keyframe()` still forces an IDR on demand regardless of this setting.
    /// - `resolution` is **not** passed here: OpenH264 adapts to each frame's actual dimensions, so
    ///   the field is informational at construction time and the real size comes from the frame.
    /// - Usage is always [`UsageType::ScreenContentRealTime`] (remote desktop).
    ///
    /// # Errors
    /// Returns [`MediaError::Unsupported`] if `config.codec` is not [`Codec::H264`], or
    /// [`MediaError::Encode`] if the OpenH264 encoder cannot be initialized.
    pub fn with_config(config: &EncoderConfig) -> Result<Self, MediaError> {
        if config.codec != Codec::H264 {
            return Err(MediaError::Unsupported(format!(
                "OpenH264Encoder only produces H264, got {:?}",
                config.codec
            )));
        }

        let oh = OhEncoderConfig::new().usage_type(UsageType::ScreenContentRealTime);
        // Rate control + frame skip are TWO complementary drop layers (ADR-0029):
        //   * pipeline backpressure drops whole frames at the input (coarse), and
        //   * OpenH264's RC skip caps the size of a SINGLE encoded frame when QP alone can't fit the
        //     per-frame bit budget (fine) — without it, RC_BITRATE_MODE literally cannot honor the
        //     congestion-controlled bitrate, and one high-change screen frame can blow the congestion
        //     window (queueing/loss). So enable skip ONLY when a bitrate target is set; in
        //     constant-quality mode there is no budget and the pipeline is the sole drop authority.
        // The keyframe-durability fix (re-arm force_keyframe until a real IDR emits) makes skip safe
        // for forced keyframes. NOTE: this is OpenH264-specific — HW encoders (NVENC/VA-API/
        // VideoToolbox) honor a bitrate via VBV+QP and must NOT copy this skip logic.
        let oh = match config.target_bitrate_kbps {
            // kbps → bps; saturate so a pathological config can never overflow the u32 bps field.
            Some(kbps) => oh
                .bitrate(BitRate::from_bps(kbps.saturating_mul(1000)))
                .rate_control_mode(RateControlMode::Bitrate)
                .skip_frames(true),
            // Constant-quality: no network budget; pipeline backpressure is the only drop mechanism.
            None => oh.skip_frames(false),
        };
        let oh = if config.target_fps > 0 {
            // Emit a periodic IDR every `2 × fps` ENCODED frames (~2 s at full frame rate; longer if
            // backpressure drops frames) so a receiver that joins mid-stream or recovers from loss
            // gets a keyframe to decode from, instead of only the single IDR at stream start.
            // `request_keyframe()` still forces an extra IDR on demand between these.
            let gop = config.target_fps.saturating_mul(KEYFRAME_INTERVAL_SECS);
            oh.max_frame_rate(FrameRate::from_hz(config.target_fps as f32)) // u32→f32: lossless for realistic fps
                .intra_frame_period(IntraFramePeriod::from_num_frames(gop))
        } else {
            oh
        };

        Self::from_oh_config(oh)
    }

    fn from_oh_config(config: OhEncoderConfig) -> Result<Self, MediaError> {
        let api = OpenH264API::from_source();
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
        // Indices are bounded by `chunks_exact(4)` / `chunks_exact_mut(3)` (exact-length slices);
        // none can be out of bounds.
        #[allow(clippy::indexing_slicing)]
        for (src, dst) in frame.data.chunks_exact(4).zip(self.rgb.chunks_exact_mut(3)) {
            dst[0] = src[2]; // R
            dst[1] = src[1]; // G
            dst[2] = src[0]; // B
        }

        // RGB → YUV (owned by `yuv`; the borrow of `self.rgb` ends with this statement).
        let yuv = YUVBuffer::from_rgb_source(RgbSliceU8::new(&self.rgb, (w, h)));

        // Arm a forced IDR if requested. We do NOT clear the flag yet: only clear it once a real IDR
        // packet actually leaves (below), so a request is never lost to a skipped/empty/errored
        // encode — the worst time to lose it is exactly the loss-recovery path that asks for it.
        if self.force_keyframe {
            self.encoder.force_intra_frame();
        }

        let bitstream = self
            .encoder
            .encode(&yuv)
            .map_err(|e| MediaError::Encode(format!("OpenH264 encode failed: {e}")))?;

        let frame_type = match bitstream.frame_type() {
            // The encoder skipped this frame or isn't ready — no packet (keyframe request stays armed).
            OhFrameType::Skip | OhFrameType::Invalid => return Ok(None),
            // A true IDR flushes the decoder's reference buffers — the ONLY valid mid-stream join /
            // seek / loss-recovery point.
            OhFrameType::IDR => FrameType::Idr,
            // Plain-I and IPMixed are intra-coded but NOT IDRs: they do not flush reference buffers,
            // so the receiver must not treat them as seek points. (force_intra_frame() emits a true
            // IDR, so a keyframe request is satisfied by the IDR arm, never here.)
            OhFrameType::I | OhFrameType::IPMixed => FrameType::IntraRefresh,
            OhFrameType::P => FrameType::Predicted,
        };

        let data = bitstream.to_vec();
        if data.is_empty() {
            return Ok(None); // no packet — keep any keyframe request armed
        }

        // A real packet is going out: a true IDR satisfies (and clears) any pending keyframe request.
        if frame_type == FrameType::Idr {
            self.force_keyframe = false;
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
    use crate::test_support::synthetic_bgra_seq;
    use openh264::decoder::{Decoder, DecoderConfig};
    use sh_types::{FrameId, TimestampUs};

    fn synthetic_bgra(w: u32, h: u32) -> VideoFrame {
        // seq=7 → FrameId(7); the round-trip test asserts this id propagates to the packet.
        synthetic_bgra_seq(w, h, 7)
    }

    fn h264_config(bitrate_kbps: Option<u32>) -> EncoderConfig {
        EncoderConfig {
            codec: Codec::H264,
            resolution: Resolution::new(64, 48),
            target_fps: 30,
            target_bitrate_kbps: bitrate_kbps,
        }
    }

    #[test]
    fn emits_periodic_keyframes_at_the_gop_interval() {
        // fps = 4 → GOP = 2 s × 4 = 8 frames, so an IDR should recur roughly every 8 frames (not
        // just the single one at stream start). Encode 20 differing frames and require ≥ 2 IDRs.
        // The bitrate (2000 kbps) is deliberately oversized for a 64×48 frame so rate control never
        // SKIPs the periodic IDR — keep it generous if this fixture's resolution/fps changes.
        let cfg = EncoderConfig {
            codec: Codec::H264,
            resolution: Resolution::new(64, 48),
            target_fps: 4,
            target_bitrate_kbps: Some(2_000),
        };
        let mut enc = OpenH264Encoder::with_config(&cfg).unwrap();
        let mut idr_count = 0;
        for seq in 0..20 {
            if let Some(pkt) = enc.encode(&synthetic_bgra_seq(64, 48, seq)).unwrap() {
                if pkt.frame_type == FrameType::Idr {
                    idr_count += 1;
                }
            }
        }
        assert!(
            idr_count >= 2,
            "expected periodic IDRs from the GOP, got only {idr_count}"
        );
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
    fn with_config_builds_h264_encoder_and_encodes() {
        // A bitrate-controlled config must construct and produce a decodable keyframe.
        let mut enc = OpenH264Encoder::with_config(&h264_config(Some(2_000))).unwrap();
        enc.request_keyframe();
        let pkt = enc
            .encode(&synthetic_bgra(64, 48))
            .unwrap()
            .expect("first frame should produce a packet");
        assert_eq!(pkt.codec, Codec::H264);
        assert_eq!(pkt.frame_type, FrameType::Idr);

        // A None-bitrate (constant-quality) config must also work.
        let mut enc_q = OpenH264Encoder::with_config(&h264_config(None)).unwrap();
        enc_q.request_keyframe();
        assert!(enc_q.encode(&synthetic_bgra(64, 48)).unwrap().is_some());
    }

    #[test]
    fn with_config_rejects_non_h264_codec() {
        let cfg = EncoderConfig {
            codec: Codec::Av1,
            resolution: Resolution::new(64, 48),
            target_fps: 30,
            target_bitrate_kbps: Some(1_000),
        };
        assert!(matches!(
            OpenH264Encoder::with_config(&cfg),
            Err(MediaError::Unsupported(_))
        ));
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
    fn handles_midstream_resolution_change() {
        // OpenH264 re-initializes internally when frame dimensions change; verify a mid-stream change
        // still yields a valid forced IDR at the new size (rather than erroring or wedging).
        let mut enc = OpenH264Encoder::new().unwrap();
        enc.request_keyframe();
        let p1 = enc
            .encode(&synthetic_bgra_seq(64, 48, 0))
            .unwrap()
            .expect("first frame packet");
        assert_eq!(p1.frame_type, FrameType::Idr);

        // Switch resolution and force another keyframe.
        enc.request_keyframe();
        let p2 = enc
            .encode(&synthetic_bgra_seq(80, 60, 1))
            .unwrap()
            .expect("post-resize frame packet");
        assert_eq!(p2.frame_type, FrameType::Idr);
        assert_eq!(&p2.data[..4], &[0, 0, 0, 1]); // valid Annex-B at the new size
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
