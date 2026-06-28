#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Software H.264 codec via OpenH264 — Streamhaul (ADR-0028, ADR-0029).
//!
//! This crate is **excluded from the workspace** (see the root `Cargo.toml` `exclude` list), so the
//! default `cargo build/clippy/test --workspace --all-features` never compiles the vendored OpenH264
//! C source. It is built only by its dedicated `codec-openh264` CI job and by a build that explicitly
//! depends on it. This enforces the licensing posture below and keeps the heavy C build off every
//! cross-OS CI run (the same reason the wasm crates are excluded).
//!
//! - [`OpenH264Encoder`] implements [`sh_media::VideoEncoder`], producing **Annex-B** H.264 a
//!   browser's WebCodecs `VideoDecoder` can decode. Input frames must be
//!   [`sh_media::PixelFormat::Bgra8`] with **even** dimensions (4:2:0 chroma).
//! - [`OpenH264Decoder`] implements [`sh_media::VideoDecoder`] (Annex-B → BGRA), for native clients
//!   and round-trip testing. The production browser path decodes via WebCodecs, not this.
//! - [`openh264_encoder_factory`] returns an [`EncoderFactory`](sh_codec_hw::mode_switch::EncoderFactory)
//!   so OpenH264 slots into the existing `DoubleBufferedEncoder` seam exactly where NVENC will.
//!
//! # Licensing / scope (read this)
//!
//! A **preview / non-distribution** codec. H.264 is covered by the MPEG-LA AVC patent pool; Cisco's
//! royalty-free grant applies only to **Cisco's pre-built OpenH264 binary**, NOT to OpenH264 **built
//! from source** (which `OpenH264API::from_source()` does). So linking this crate is licensing-gated,
//! the same posture as the `hevc` feature (`docs/adr/0004-oss-codec-and-licensing.md`, ADR-0028). The
//! real low-latency path remains hardware encode (NVENC / VA-API / VideoToolbox / Media Foundation),
//! tracked as R-CODEC.

mod decoder;
mod encoder;

pub use decoder::OpenH264Decoder;
pub use encoder::OpenH264Encoder;

use sh_codec_hw::mode_switch::EncoderFactory;
use sh_media::{EncoderConfig, MediaError, VideoEncoder};

/// Build an [`EncoderFactory`] that constructs [`OpenH264Encoder`]s from the negotiated config.
///
/// This is the seam the existing
/// [`DoubleBufferedEncoder`](sh_codec_hw::mode_switch::DoubleBufferedEncoder) drives for glitch-free
/// mid-stream codec/bitrate switches — OpenH264 slots in exactly where the NVENC backend will, with
/// no pipeline changes. The `config.target_bitrate_kbps` carried in is how the `RateAllocator`'s
/// video budget reaches the encoder (see [`OpenH264Encoder::with_config`]).
#[must_use]
pub fn openh264_encoder_factory() -> EncoderFactory {
    Box::new(
        |config: &EncoderConfig| -> Result<Box<dyn VideoEncoder>, MediaError> {
            Ok(Box::new(OpenH264Encoder::with_config(config)?))
        },
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sh_media::Resolution;
    use sh_protocol::Codec;

    #[test]
    fn factory_produces_working_h264_encoder() {
        // Exercise the actual factory closure (the host/DoubleBufferedEncoder entry point) end to end.
        let mut factory = openh264_encoder_factory();
        let cfg = EncoderConfig {
            codec: Codec::H264,
            resolution: Resolution::new(64, 48),
            target_fps: 30,
            target_bitrate_kbps: Some(1_000),
        };
        let mut enc = factory(&cfg).expect("factory must build an encoder for an H264 config");
        enc.request_keyframe();
        let pkt = enc
            .encode(&test_support::synthetic_bgra_seq(64, 48, 0))
            .expect("encode must not error")
            .expect("first frame must produce a packet");
        assert_eq!(pkt.codec, Codec::H264);
    }

    #[test]
    fn factory_rejects_non_h264_config() {
        let mut factory = openh264_encoder_factory();
        let cfg = EncoderConfig {
            codec: Codec::Av1,
            resolution: Resolution::new(64, 48),
            target_fps: 30,
            target_bitrate_kbps: Some(1_000),
        };
        assert!(matches!(factory(&cfg), Err(MediaError::Unsupported(_))));
    }
}

/// Shared synthetic-frame helpers for the unit tests in `encoder` and `decoder`.
#[cfg(test)]
#[allow(clippy::cast_possible_truncation, clippy::arithmetic_side_effects)]
pub(crate) mod test_support {
    use bytes::Bytes;
    use sh_media::{PixelFormat, Resolution, VideoFrame};
    use sh_types::{FrameId, TimestampUs};

    /// A synthetic BGRA frame whose pattern shifts with `seq`, so successive frames differ (which
    /// lets the encoder emit inter-predicted frames). `frame_id == seq`, `capture_ts_us == seq*1000`.
    pub(crate) fn synthetic_bgra_seq(w: u32, h: u32, seq: usize) -> VideoFrame {
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
}
