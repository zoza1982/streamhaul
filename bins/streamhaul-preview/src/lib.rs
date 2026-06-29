#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Shared logic for the Streamhaul **preview** host/client (ADR-0030).
//!
//! These binaries stream the **real screen** as **OpenH264** video over QUIC and decode it back —
//! the first end-to-end real-capture → compress → transport → decode slice. They live in a
//! workspace-EXCLUDED crate because they pull in `sh-codec-openh264` (vendored OpenH264 C); see
//! ADR-0028/0029 for why that must stay out of the default build. **Preview / non-distribution:**
//! linking an H.264 encoder is licensing-gated (the OSS build links none).
//!
//! The host capture→encode→send and client receive→decode→sink loops are the same
//! [`sh_core::run_host_pipeline`] / [`sh_core::run_client_pipeline`] the synthetic bins use — only the
//! capturer (real X11) and codec (OpenH264) differ. [`EvenDimCapturer`] crops to even dimensions
//! because OpenH264's 4:2:0 chroma requires them and real displays are not guaranteed even.

use std::time::{Duration, Instant};

use bytes::Bytes;
use sh_codec_openh264::{OpenH264Decoder, OpenH264Encoder};
use sh_core::{run_client_pipeline, run_host_pipeline, HostPipelineParams};
use sh_media::{
    CollectingSink, EncoderConfig, MediaError, PixelFormat, Resolution, ScreenCapturer, VideoFrame,
};
use sh_protocol::Codec;
use sh_transport::Connection;
use sh_types::FrameId;

/// A [`ScreenCapturer`] adapter that crops every frame to **even** width/height.
///
/// OpenH264's 4:2:0 chroma sampling requires even dimensions, but a real display (or X11 root window)
/// can report odd ones. This wraps any BGRA capturer and trims the last row/column when needed; even
/// frames pass through untouched (no copy).
pub struct EvenDimCapturer<C> {
    inner: C,
}

impl<C: ScreenCapturer> EvenDimCapturer<C> {
    /// Wrap `inner`, cropping its frames to even dimensions.
    pub fn new(inner: C) -> Self {
        Self { inner }
    }

    fn even(v: u32) -> u32 {
        v & !1
    }
}

impl<C: ScreenCapturer> ScreenCapturer for EvenDimCapturer<C> {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<VideoFrame>, MediaError> {
        let Some(frame) = self.inner.next_frame(timeout)? else {
            return Ok(None);
        };
        let (w, h) = (frame.resolution.width, frame.resolution.height);
        let (ew, eh) = (Self::even(w), Self::even(h));
        if ew == w && eh == h {
            return Ok(Some(frame)); // already even — no copy
        }
        if frame.format != PixelFormat::Bgra8 {
            return Err(MediaError::Unsupported(format!(
                "EvenDimCapturer can only crop Bgra8, got {:?}",
                frame.format
            )));
        }
        if ew == 0 || eh == 0 {
            return Err(MediaError::Capture(format!(
                "display too small to crop to even dimensions: {w}x{h}"
            )));
        }

        // Copy the top-left ew×eh region, row by row (source stride = w*4 bytes).
        let src_stride = (w as usize).saturating_mul(4);
        let dst_stride = (ew as usize).saturating_mul(4);
        let mut out = vec![0u8; dst_stride.saturating_mul(eh as usize)];
        for y in 0..(eh as usize) {
            let s = y.saturating_mul(src_stride);
            let d = y.saturating_mul(dst_stride);
            // Bounds hold: src has h*src_stride bytes (h >= eh) and dst has eh*dst_stride bytes.
            let (Some(src_row), Some(dst_row)) = (
                frame.data.get(s..s.saturating_add(dst_stride)),
                out.get_mut(d..d.saturating_add(dst_stride)),
            ) else {
                return Err(MediaError::Capture("crop row out of bounds".to_owned()));
            };
            dst_row.copy_from_slice(src_row);
        }

        Ok(Some(VideoFrame {
            data: Bytes::from(out),
            format: PixelFormat::Bgra8,
            resolution: Resolution::new(ew, eh),
            frame_id: frame.frame_id,
            capture_ts_us: frame.capture_ts_us,
        }))
    }

    fn resolution(&self) -> Resolution {
        let r = self.inner.resolution();
        Resolution::new(Self::even(r.width), Self::even(r.height))
    }

    /// The wrapped capturer's pixel format, unchanged. Note: cropping is only supported for
    /// [`PixelFormat::Bgra8`] — a non-BGRA capturer with **odd** dimensions errors in
    /// [`next_frame`](Self::next_frame) (even-dimension non-BGRA frames pass through untouched).
    fn pixel_format(&self) -> PixelFormat {
        self.inner.pixel_format()
    }
}

/// Host side: capture `frames` frames from `capturer`, OpenH264-encode them at `bitrate_kbps`, and
/// stream them over `conn`. Returns the per-frame `(FrameId, send_instant)` list.
///
/// # Errors
/// Returns an error if the encoder cannot be created or the host pipeline fails.
pub async fn serve(
    conn: &Connection,
    capturer: &mut dyn ScreenCapturer,
    bitrate_kbps: u32,
    frames: usize,
    fps: u32,
    pace_frames: bool,
) -> anyhow::Result<Vec<(FrameId, Instant)>> {
    let res = capturer.resolution();
    let cfg = EncoderConfig {
        codec: Codec::H264,
        resolution: res,
        target_fps: fps,
        target_bitrate_kbps: Some(bitrate_kbps),
    };
    let mut encoder = OpenH264Encoder::with_config(&cfg)?;
    let params = HostPipelineParams {
        frame_count: frames,
        fps,
        pace_frames,
    };
    Ok(run_host_pipeline(conn, capturer, &mut encoder, &params).await?)
}

/// Client side: receive up to `frames` frames from `conn`, OpenH264-decode them, and collect them.
/// Returns the per-frame `(FrameId, recv_instant)` list and the decoded frames.
///
/// # Errors
/// Returns an error if the decoder cannot be created or the client pipeline fails.
pub async fn receive(
    conn: &Connection,
    frames: usize,
    recv_timeout: Duration,
) -> anyhow::Result<(Vec<(FrameId, Instant)>, Vec<VideoFrame>)> {
    let mut decoder = OpenH264Decoder::new()?;
    let mut sink = CollectingSink::new(frames);
    let recv_times =
        run_client_pipeline(conn, &mut decoder, &mut sink, frames, recv_timeout).await?;
    Ok((recv_times, sink.frames().to_vec()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use sh_media::{SyntheticCapturer, VideoEncoder};
    use sh_types::{FrameId, TimestampUs};

    /// A one-shot capturer that emits a single caller-specified frame (for exercising the format /
    /// dimension branches of [`EvenDimCapturer`] that `SyntheticCapturer` can't reach).
    struct OneFrame(Option<VideoFrame>, Resolution, PixelFormat);
    impl ScreenCapturer for OneFrame {
        fn next_frame(&mut self, _t: Duration) -> Result<Option<VideoFrame>, MediaError> {
            Ok(self.0.take())
        }
        fn resolution(&self) -> Resolution {
            self.1
        }
        fn pixel_format(&self) -> PixelFormat {
            self.2
        }
    }

    #[test]
    fn even_dim_capturer_passes_even_frames_through() {
        let cap = SyntheticCapturer::new(Resolution::new(64, 48), 30);
        let mut even = EvenDimCapturer::new(cap);
        assert_eq!(even.resolution(), Resolution::new(64, 48));
        let f = even.next_frame(Duration::ZERO).unwrap().unwrap();
        assert_eq!(f.resolution, Resolution::new(64, 48));
        assert_eq!(f.data.len(), 64 * 48 * 4);
    }

    #[test]
    fn even_dim_capturer_crops_asymmetric_dimensions() {
        // Odd width only, then odd height only — the trickiest stride cases (one axis cropped, the
        // other not). Both must land on the even floor with a self-consistent BGRA buffer.
        for (in_w, in_h) in [(65u32, 48u32), (64, 49)] {
            let cap = SyntheticCapturer::new(Resolution::new(in_w, in_h), 30);
            let mut even = EvenDimCapturer::new(cap);
            let f = even.next_frame(Duration::ZERO).unwrap().unwrap();
            assert_eq!(
                f.resolution,
                Resolution::new(64, 48),
                "for input {in_w}x{in_h}"
            );
            assert_eq!(f.data.len(), 64 * 48 * 4);
        }
    }

    #[test]
    fn even_dim_capturer_rejects_too_small_display() {
        // 1x1 → even floor 0x0 → cannot crop to a non-empty even region.
        let cap = SyntheticCapturer::new(Resolution::new(1, 1), 30);
        let mut even = EvenDimCapturer::new(cap);
        assert!(matches!(
            even.next_frame(Duration::ZERO),
            Err(MediaError::Capture(_))
        ));
    }

    #[test]
    fn even_dim_capturer_rejects_non_bgra_with_odd_dims() {
        // A non-BGRA frame with odd dims can't be cropped generically → Unsupported.
        let frame = VideoFrame {
            data: Bytes::from(vec![0u8; 65 * 48 * 3 / 2]), // I420-ish size; irrelevant to the guard
            format: PixelFormat::I420,
            resolution: Resolution::new(65, 48),
            frame_id: FrameId(0),
            capture_ts_us: TimestampUs(0),
        };
        let mut even = EvenDimCapturer::new(OneFrame(
            Some(frame),
            Resolution::new(65, 48),
            PixelFormat::I420,
        ));
        assert!(matches!(
            even.next_frame(Duration::ZERO),
            Err(MediaError::Unsupported(_))
        ));
    }

    #[test]
    fn even_dim_capturer_crops_odd_frames() {
        // SyntheticCapturer emits the size it's told; feed it odd dims and verify the crop.
        let cap = SyntheticCapturer::new(Resolution::new(65, 49), 30);
        let mut even = EvenDimCapturer::new(cap);
        assert_eq!(even.resolution(), Resolution::new(64, 48));
        let f = even.next_frame(Duration::ZERO).unwrap().unwrap();
        assert_eq!(f.resolution, Resolution::new(64, 48));
        assert_eq!(f.data.len(), 64 * 48 * 4);
        // The cropped frame must encode cleanly (even dims) — the whole point of the adapter.
        let cfg = EncoderConfig {
            codec: Codec::H264,
            resolution: Resolution::new(64, 48),
            target_fps: 30,
            target_bitrate_kbps: Some(1_000),
        };
        let mut enc = OpenH264Encoder::with_config(&cfg).unwrap();
        enc.request_keyframe();
        assert!(enc.encode(&f).unwrap().is_some());
    }
}
