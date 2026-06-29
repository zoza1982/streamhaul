#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Live X11→OpenH264→WebRTC frame source for the browser-interop preview (ADR-0032).
//!
//! This crate is **workspace-EXCLUDED** (see ADR-0028/0032): it depends on `sh-codec-openh264`
//! which builds the vendored OpenH264 C from source. The default `--workspace --all-features`
//! build never compiles this crate. It is built only by its dedicated CI job and on explicit
//! local invocation.
//!
//! # Types
//!
//! - [`DownscaleCapturer`] — integer nearest-neighbor BGRA downscale adapter that keeps encoded
//!   frames under the SHP 16-bit `payload_len` cap (64 KiB). Fragmentation (the real fix) is a
//!   deferred follow-up; see ADR-0032.
//! - [`LiveFrameSource`] — [`VideoFrameSource`](streamhaul_webrtc_host::VideoFrameSource)
//!   implementation that captures frames with any [`ScreenCapturer`] and encodes them with
//!   [`OpenH264Encoder`](sh_codec_openh264::OpenH264Encoder).
//!
//! # Wrap order for the binary
//!
//! ```text
//! X11ScreenCapturer → DownscaleCapturer → EvenDimCapturer → LiveFrameSource
//! ```
//!
//! `DownscaleCapturer` ensures encoded IDRs stay under 64 KiB.
//! `EvenDimCapturer` (re-used from `streamhaul_preview`) satisfies OpenH264's 4:2:0 even-dimension
//! requirement.

use std::time::Duration;

use anyhow::Context as _;
use bytes::Bytes;
use sh_codec_openh264::OpenH264Encoder;
use sh_media::{
    EncoderConfig, MediaError, PixelFormat, Resolution, ScreenCapturer, VideoEncoder, VideoFrame,
};
use sh_protocol::{Codec, FrameType};
use streamhaul_webrtc_host::VideoFrameSource;

// ── DownscaleCapturer ───────────────────────────────────────────────────────────────────────────

/// Integer nearest-neighbor BGRA downscale adapter (ADR-0032).
///
/// Reduces each captured frame so its **width ≤ `max_width`**, using the smallest integer scale
/// factor `f = ceil(width / max_width)`. The output resolution is `(width/f, height/f)`. Frames
/// that already satisfy `width ≤ max_width` pass through untouched (no copy, factor = 1).
///
/// This keeps encoded keyframes under the SHP 16-bit `payload_len` cap. SHP fragmentation (the
/// correct long-term fix) is deferred; see ADR-0032.
///
/// Only [`sh_media::PixelFormat::Bgra8`] frames can be downscaled. A non-BGRA frame whose width
/// already satisfies `max_width` passes through unchanged; one that needs downscaling returns
/// [`MediaError::Unsupported`].
///
/// # Wrap order
///
/// `X11ScreenCapturer → DownscaleCapturer → EvenDimCapturer → LiveFrameSource`
///
/// # Assumptions
///
/// The inner capturer's [`resolution`](ScreenCapturer::resolution) must be **cheap** (it is read
/// more than once per frame to derive the downscale factor) and **stable** for the adapter's
/// lifetime (the factor is computed from it while the per-frame copy uses the actual frame's
/// dimensions). A mid-stream resolution change is defended against — the packed-stride check in
/// [`next_frame`](Self::next_frame) rejects a frame whose size doesn't match its declared
/// dimensions — but a stable source (e.g. `X11ScreenCapturer` on a fixed display) is expected.
pub struct DownscaleCapturer<C> {
    inner: C,
    max_width: u32,
}

impl<C: ScreenCapturer> DownscaleCapturer<C> {
    /// Wrap `inner`, downscaling its frames so their width is ≤ `max_width`.
    ///
    /// `max_width = 0` is treated as 1 to avoid division by zero.
    pub fn new(inner: C, max_width: u32) -> Self {
        Self { inner, max_width }
    }

    /// Smallest integer factor such that `inner.width / factor ≤ max_width`.
    ///
    /// Returns 1 when the inner width already satisfies the constraint.
    fn factor(&self) -> u32 {
        let w = self.inner.resolution().width;
        let max_w = self.max_width.max(1);
        if w <= max_w {
            return 1;
        }
        // ceil(w / max_w) ensures output width <= max_w.
        // saturating_add prevents overflow when w and max_w are both u32::MAX.
        let numer = w.saturating_add(max_w.saturating_sub(1));
        numer.checked_div(max_w).unwrap_or(1).max(1)
    }
}

impl<C: ScreenCapturer> ScreenCapturer for DownscaleCapturer<C> {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<VideoFrame>, MediaError> {
        let Some(frame) = self.inner.next_frame(timeout)? else {
            return Ok(None);
        };
        let factor = self.factor();
        if factor <= 1 {
            return Ok(Some(frame)); // already small enough — no copy
        }
        if frame.format != PixelFormat::Bgra8 {
            return Err(MediaError::Unsupported(format!(
                "DownscaleCapturer can only downscale Bgra8, got {:?}",
                frame.format
            )));
        }

        let src_w = usize::try_from(frame.resolution.width)
            .map_err(|e| MediaError::Capture(format!("frame width overflow: {e}")))?;
        let src_h = usize::try_from(frame.resolution.height)
            .map_err(|e| MediaError::Capture(format!("frame height overflow: {e}")))?;
        let factor_us = usize::try_from(factor)
            .map_err(|e| MediaError::Capture(format!("scale factor overflow: {e}")))?;

        let dst_w = src_w.checked_div(factor_us).unwrap_or(0);
        let dst_h = src_h.checked_div(factor_us).unwrap_or(0);
        if dst_w == 0 || dst_h == 0 {
            return Err(MediaError::Capture(format!(
                "downscale factor {factor} too large for {src_w}x{src_h} frame"
            )));
        }

        // DownscaleCapturer assumes packed BGRA (stride = width × 4). Verify the invariant so
        // a capturer that pads rows produces a clear error rather than silently corrupt output.
        let src_stride = src_w.saturating_mul(4);
        let expected_len = src_stride.saturating_mul(src_h);
        if frame.data.len() != expected_len {
            return Err(MediaError::Capture(format!(
                "DownscaleCapturer: packed stride assumed (width×4={src_stride}×{src_h}={expected_len} bytes) \
                 but frame.data.len()={} — row-padded frames are unsupported",
                frame.data.len()
            )));
        }
        // Nearest-neighbor BGRA downscale: for each output pixel (dx, dy), sample input (dx*f, dy*f).
        let dst_stride = dst_w.saturating_mul(4);
        let mut out = vec![0u8; dst_stride.saturating_mul(dst_h)];

        for dy in 0..dst_h {
            let sy = dy.saturating_mul(factor_us);
            for dx in 0..dst_w {
                let sx = dx.saturating_mul(factor_us);
                let src_off = sy
                    .saturating_mul(src_stride)
                    .saturating_add(sx.saturating_mul(4));
                let dst_off = dy
                    .saturating_mul(dst_stride)
                    .saturating_add(dx.saturating_mul(4));
                let src_px = frame
                    .data
                    .get(src_off..src_off.saturating_add(4))
                    .ok_or_else(|| {
                        MediaError::Capture(format!("src pixel out of bounds at ({sx},{sy})"))
                    })?;
                let dst_px = out
                    .get_mut(dst_off..dst_off.saturating_add(4))
                    .ok_or_else(|| {
                        MediaError::Capture(format!("dst pixel out of bounds at ({dx},{dy})"))
                    })?;
                dst_px.copy_from_slice(src_px);
            }
        }

        let dst_w_u32 = u32::try_from(dst_w)
            .map_err(|e| MediaError::Capture(format!("dst width u32 overflow: {e}")))?;
        let dst_h_u32 = u32::try_from(dst_h)
            .map_err(|e| MediaError::Capture(format!("dst height u32 overflow: {e}")))?;

        Ok(Some(VideoFrame {
            data: Bytes::from(out),
            format: PixelFormat::Bgra8,
            resolution: Resolution::new(dst_w_u32, dst_h_u32),
            frame_id: frame.frame_id,
            capture_ts_us: frame.capture_ts_us,
        }))
    }

    fn resolution(&self) -> Resolution {
        let r = self.inner.resolution();
        let factor = self.factor();
        let w = r.width.checked_div(factor).unwrap_or(0);
        let h = r.height.checked_div(factor).unwrap_or(0);
        Resolution::new(w, h)
    }

    /// The wrapped capturer's pixel format, unchanged.
    ///
    /// Note: non-BGRA frames whose width already satisfies `max_width` pass through; a non-BGRA
    /// frame that needs downscaling will error in [`Self::next_frame`].
    fn pixel_format(&self) -> PixelFormat {
        self.inner.pixel_format()
    }
}

// ── LiveFrameSource ─────────────────────────────────────────────────────────────────────────────

/// A [`VideoFrameSource`] that captures and OpenH264-encodes frames from any [`ScreenCapturer`].
///
/// The intended capturer stack is:
/// ```text
/// X11ScreenCapturer → DownscaleCapturer → EvenDimCapturer → LiveFrameSource
/// ```
///
/// The encoder is created with a target bitrate so encoded frames stay small enough for the SHP
/// 16-bit `payload_len` cap. The first frame is forced to IDR so the browser can initialise its
/// decoder. If the encoder skips a frame (`Ok(None)` — RC budget or warm-up), the next frame is
/// captured and retried until a packet is produced.
///
/// # Blocking note
///
/// [`VideoFrameSource::next_frame`] calls [`ScreenCapturer::next_frame`] and
/// [`VideoEncoder::encode`] synchronously. These are quick on a local X11 display + software
/// encoder (typically ≤ 5 ms), so inline blocking in the async streaming loop is acceptable for
/// this development tool. A production path would use `tokio::task::spawn_blocking`.
pub struct LiveFrameSource<C: ScreenCapturer> {
    capturer: C,
    encoder: OpenH264Encoder,
}

impl<C: ScreenCapturer> LiveFrameSource<C> {
    /// Create a live frame source wrapping `capturer`, encoding at `bitrate_kbps` kbps and `fps` fps.
    ///
    /// Forces a keyframe on the first encode so the browser can configure its decoder (ADR-0031).
    ///
    /// # Errors
    ///
    /// Returns an error if `fps == 0`, `bitrate_kbps == 0`, or if [`OpenH264Encoder::with_config`]
    /// cannot be initialised.
    pub fn new(capturer: C, bitrate_kbps: u32, fps: u32) -> anyhow::Result<Self> {
        anyhow::ensure!(fps > 0, "fps must be > 0");
        anyhow::ensure!(bitrate_kbps > 0, "bitrate_kbps must be > 0");
        let res = capturer.resolution();
        let cfg = EncoderConfig {
            codec: Codec::H264,
            resolution: res,
            target_fps: fps,
            target_bitrate_kbps: Some(bitrate_kbps),
        };
        let mut encoder = OpenH264Encoder::with_config(&cfg)
            .context("failed to initialise OpenH264 encoder for live source")?;
        // Force the first frame to IDR so the browser can configure its WebCodecs VideoDecoder.
        encoder.request_keyframe();
        Ok(Self { capturer, encoder })
    }
}

/// Maximum consecutive `Ok(None)` responses from the capturer before `next_frame` gives up.
///
/// 100 × 100 ms = 10 s of idle screen. Avoids hanging the async streaming task indefinitely if
/// the underlying capturer never produces a new frame (e.g. a damage-based capturer on an
/// unmoving display, or encoder misconfiguration that causes every frame to be skipped).
const MAX_CAPTURE_SKIPS: u32 = 100;

/// Maximum consecutive encoder skips (`Ok(None)`) before `next_frame` gives up.
///
/// Protects against `--bitrate-kbps` values so small that the rate-control budget is never met.
const MAX_ENCODER_SKIPS: u32 = 60;

impl<C: ScreenCapturer> VideoFrameSource for LiveFrameSource<C> {
    fn next_frame(&mut self) -> anyhow::Result<(FrameType, Vec<u8>)> {
        let capture_timeout = Duration::from_millis(100);
        let mut encoder_skips: u32 = 0;
        loop {
            // Capture: retry on `Ok(None)` (no new frame within the deadline) up to the cap.
            let frame = {
                let mut capture_skips: u32 = 0;
                loop {
                    match self.capturer.next_frame(capture_timeout) {
                        Ok(Some(f)) => break f,
                        Ok(None) => {
                            capture_skips = capture_skips.saturating_add(1);
                            anyhow::ensure!(
                                capture_skips < MAX_CAPTURE_SKIPS,
                                "capture produced no frame after {MAX_CAPTURE_SKIPS} retries \
                                 ({} ms); display may be frozen or capturer misconfigured",
                                u64::from(MAX_CAPTURE_SKIPS).saturating_mul(100)
                            );
                        }
                        Err(e) => return Err(anyhow::anyhow!("capture failed: {e}")),
                    }
                }
            };

            // Encode: if the encoder skips the frame (RC warm-up / budget), capture the next one.
            match self.encoder.encode(&frame) {
                Ok(Some(pkt)) => return Ok((pkt.frame_type, pkt.data.to_vec())),
                Ok(None) => {
                    encoder_skips = encoder_skips.saturating_add(1);
                    anyhow::ensure!(
                        encoder_skips < MAX_ENCODER_SKIPS,
                        "encoder skipped {MAX_ENCODER_SKIPS} consecutive frames; \
                         check --bitrate-kbps (too low?) or frame dimensions"
                    );
                }
                Err(e) => return Err(anyhow::anyhow!("encode failed: {e}")),
            }
        }
    }

    fn request_keyframe(&mut self) {
        // Force the next encoded frame back to an IDR — the streamer calls this after dropping an
        // oversize frame so the stream recovers a decodable keyframe (see `VideoFrameSource`).
        self.encoder.request_keyframe();
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use sh_media::{Resolution, SyntheticCapturer};
    use streamhaul_preview::EvenDimCapturer;

    #[test]
    fn downscale_factor_is_correct() {
        // 1920 / 960 = exactly 2; ceil(1920/960) = 2.
        let cap = SyntheticCapturer::new(Resolution::new(1920, 1080), 30);
        let dc = DownscaleCapturer::new(cap, 960);
        assert_eq!(dc.factor(), 2);
        assert_eq!(dc.resolution(), Resolution::new(960, 540));
    }

    #[test]
    fn downscale_factor_rounds_up() {
        // 1921 / 960 = 2.00104...; ceil = 3.  output = (1921/3, 1080/3) = (640, 360).
        let cap = SyntheticCapturer::new(Resolution::new(1921, 1080), 30);
        let dc = DownscaleCapturer::new(cap, 960);
        assert_eq!(dc.factor(), 3);
        assert_eq!(dc.resolution(), Resolution::new(640, 360));
    }

    #[test]
    fn no_downscale_when_width_fits() {
        // 800 ≤ 960 → factor 1, no copy.
        let cap = SyntheticCapturer::new(Resolution::new(800, 600), 30);
        let mut dc = DownscaleCapturer::new(cap, 960);
        assert_eq!(dc.factor(), 1);
        let frame = dc.next_frame(Duration::ZERO).unwrap().unwrap();
        assert_eq!(frame.resolution, Resolution::new(800, 600));
    }

    #[test]
    fn live_frame_source_via_synthetic_produces_idr() {
        // SyntheticCapturer at 160×120 → DownscaleCapturer (no-op) → EvenDimCapturer → LiveFrameSource.
        // 160×120 is already small and even so both adapters are no-ops here; the test exercises
        // the full encode path without a display.
        let cap = SyntheticCapturer::new(Resolution::new(160, 120), 30);
        let dc = DownscaleCapturer::new(cap, 960);
        let even = EvenDimCapturer::new(dc);
        let mut src =
            LiveFrameSource::new(even, 2_000, 30).expect("LiveFrameSource must init at 160x120");

        let (frame_type, payload) = src.next_frame().expect("first frame must succeed");
        assert_eq!(frame_type, FrameType::Idr, "first frame must be IDR");
        assert!(
            payload.starts_with(&[0, 0, 0, 1]) || payload.starts_with(&[0, 0, 1]),
            "payload must be Annex-B (start code not found)"
        );
        assert!(
            payload.len() <= usize::from(u16::MAX),
            "frame must fit in SHP 64 KB cap: {} bytes",
            payload.len()
        );
    }

    #[test]
    fn downscaled_oversize_frame_encodes_within_shp_cap() {
        // Exercise the REAL downscale copy path (factor > 1) through the encoder + size cap: a large
        // 1920×1440 source at --max-width 480 → factor 4 → 480×360, then encode. Asserts the encoded
        // frame is a valid Annex-B IDR that fits the SHP 64 KiB cap (the whole point of downscaling).
        let cap = SyntheticCapturer::new(Resolution::new(1920, 1440), 30);
        let dc = DownscaleCapturer::new(cap, 480);
        assert_eq!(dc.factor(), 4);
        assert_eq!(dc.resolution(), Resolution::new(480, 360));
        let even = EvenDimCapturer::new(dc);
        let mut src = LiveFrameSource::new(even, 2_000, 30).expect("LiveFrameSource init");

        let (frame_type, payload) = src.next_frame().expect("first frame must succeed");
        assert_eq!(frame_type, FrameType::Idr);
        assert!(
            payload.starts_with(&[0, 0, 0, 1]) || payload.starts_with(&[0, 0, 1]),
            "payload must be Annex-B"
        );
        assert!(
            payload.len() <= usize::from(u16::MAX),
            "downscaled frame must fit the SHP 64 KiB cap: {} bytes",
            payload.len()
        );
    }
}
