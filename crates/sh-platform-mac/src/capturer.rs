//! CoreGraphics screen capturer (macOS).
//!
//! Grabs the main display via `CGDisplay::image()` (`CGDisplayCreateImage`) and repacks it into a
//! tightly-packed [`PixelFormat::Bgra8`] [`VideoFrame`], dropping the `bytes_per_row` stride padding.
//!
//! `CGDisplay::image()` returns `None` without the **Screen Recording** TCC permission; the capturer
//! surfaces that as a typed [`MediaError::Capture`] (fail-closed, never a panic). Live capture is a
//! hardware follow-up (R-MAC-TCC); the modern ScreenCaptureKit path is R-MAC-SCK.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use core_graphics::display::CGDisplay;
use sh_media::{MediaError, PixelFormat, Resolution, ScreenCapturer, VideoFrame};
use sh_types::{FrameId, TimestampUs};
use tracing::debug;

/// Process-global monotonic frame counter (unique [`FrameId`]s across capturer instances).
static FRAME_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A [`ScreenCapturer`] that reads the macOS main display via CoreGraphics `CGDisplay::image()`.
///
/// Each [`next_frame`](CgDisplayCapturer::next_frame) call grabs the whole main display and repacks
/// it to tightly-packed BGRA. There is no change-detection in v1 (a frame is always returned on a
/// permitted display). `CGDisplayCreateImage` is deprecated in macOS 14+ but still functional;
/// ScreenCaptureKit is the modern follow-up (R-MAC-SCK).
pub struct CgDisplayCapturer {
    display: CGDisplay,
    epoch: Instant,
}

impl CgDisplayCapturer {
    /// Create a capturer for the main display.
    ///
    /// # Errors
    /// Always succeeds in the current CoreGraphics implementation (the main-display handle is just a
    /// display id); the `Result` is retained for trait consistency with a future backend (e.g.
    /// ScreenCaptureKit, R-MAC-SCK) that may fail at construction.
    pub fn new() -> Result<Self, MediaError> {
        Ok(Self {
            display: CGDisplay::main(),
            epoch: Instant::now(),
        })
    }

    fn elapsed_us(&self) -> TimestampUs {
        let us = self
            .epoch
            .elapsed()
            .as_micros()
            .try_into()
            .unwrap_or(u64::MAX);
        TimestampUs(us)
    }
}

impl ScreenCapturer for CgDisplayCapturer {
    /// Capture one frame from the main display.
    ///
    /// The `timeout` is accepted for trait compatibility but unused: this v1 has no change-detection,
    /// so it captures and returns a frame unconditionally and **never returns `Ok(None)`**.
    ///
    /// # Errors
    /// Returns [`MediaError::Capture`] if `CGDisplay::image()` returns `None` (no Screen Recording
    /// permission, or no displayable surface), the pixel format is not 32-bit, or the returned buffer
    /// is too short for the reported geometry.
    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<VideoFrame>, MediaError> {
        let image = self.display.image().ok_or_else(|| {
            MediaError::Capture(
                "CGDisplay::image() returned None (Screen Recording permission required?)"
                    .to_string(),
            )
        })?;

        let width = image.width();
        let height = image.height();
        let bytes_per_row = image.bytes_per_row();
        let bits_per_pixel = image.bits_per_pixel();
        if bits_per_pixel != 32 {
            return Err(MediaError::Capture(format!(
                "unexpected macOS capture format: {bits_per_pixel} bpp (expected 32)"
            )));
        }

        let row_bytes = width
            .checked_mul(4)
            .ok_or_else(|| MediaError::Capture("capture width overflow".to_string()))?;
        if bytes_per_row < row_bytes {
            return Err(MediaError::Capture(format!(
                "bytes_per_row {bytes_per_row} < {row_bytes} for width {width}"
            )));
        }

        let cf_data = image.data();
        let src = cf_data.bytes();
        let needed = bytes_per_row
            .checked_mul(height)
            .ok_or_else(|| MediaError::Capture("capture buffer size overflow".to_string()))?;
        if src.len() < needed {
            return Err(MediaError::Capture(format!(
                "CGImage data {} bytes < {needed} for {width}×{height} stride {bytes_per_row}",
                src.len()
            )));
        }

        // Repack row-by-row into a tight `width*4` buffer (drop the stride padding) and force the
        // alpha byte to 0xFF (the screen is opaque). CGDisplayCreateImage yields BGRA (32-bit).
        // Invariant: `row_bytes ≤ bytes_per_row` and `bytes_per_row*height` did not overflow (checked
        // above), so `row_bytes*height` cannot overflow either — the `saturating_mul`s below (used to
        // satisfy the arithmetic-side-effects lint) therefore never actually saturate.
        debug_assert!(
            row_bytes.checked_mul(height).is_some(),
            "stride*height overflow"
        );
        let mut out = vec![0u8; row_bytes.saturating_mul(height)];
        for y in 0..height {
            let src_start = y.saturating_mul(bytes_per_row);
            let dst_start = y.saturating_mul(row_bytes);
            // Both ranges are within bounds by the length checks above.
            if let (Some(src_row), Some(dst_row)) = (
                src.get(src_start..src_start.saturating_add(row_bytes)),
                out.get_mut(dst_start..dst_start.saturating_add(row_bytes)),
            ) {
                dst_row.copy_from_slice(src_row);
                for px in dst_row.chunks_exact_mut(4) {
                    if let Some(a) = px.get_mut(3) {
                        *a = 0xFF;
                    }
                }
            }
        }

        let w = u32::try_from(width)
            .map_err(|_| MediaError::Capture(format!("capture width {width} exceeds u32")))?;
        let h = u32::try_from(height)
            .map_err(|_| MediaError::Capture(format!("capture height {height} exceeds u32")))?;

        let frame = VideoFrame {
            data: Bytes::from(out),
            format: PixelFormat::Bgra8,
            resolution: Resolution::new(w, h),
            frame_id: FrameId(FRAME_COUNTER.fetch_add(1, Ordering::Relaxed)),
            capture_ts_us: self.elapsed_us(),
        };
        debug!(w, h, "CgDisplayCapturer: captured frame");
        frame.validate_len()?;
        Ok(Some(frame))
    }

    fn resolution(&self) -> Resolution {
        // Pixel dimensions of the main display (independent of any capture permission). The trait
        // method is infallible, so on a physically-impossible >u32::MAX dimension we fall back to 0
        // (a degenerate-but-valid resolution) rather than erroring.
        let w = u32::try_from(self.display.pixels_wide()).unwrap_or(0);
        let h = u32::try_from(self.display.pixels_high()).unwrap_or(0);
        Resolution::new(w, h)
    }

    fn pixel_format(&self) -> PixelFormat {
        PixelFormat::Bgra8
    }
}

// macOS runtime smoke test (runs on macos-latest CI). Constructs the capturer and calls next_frame;
// without Screen Recording permission `CGDisplay::image()` returns None → a typed Capture error, so
// we only assert it returns a Result WITHOUT PANICKING (and, if a frame is returned, that it is
// internally consistent). Real pixel capture is TCC-gated and verified on hardware (R-MAC-TCC).
#[cfg(all(test, target_os = "macos"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod mac_tests {
    use super::*;

    #[test]
    fn constructs_and_next_frame_is_panic_free() {
        let mut cap = CgDisplayCapturer::new().expect("construct capturer");
        assert_eq!(cap.pixel_format(), PixelFormat::Bgra8);
        let _ = cap.resolution(); // must not panic
                                  // With Screen Recording permission: a valid, length-consistent frame. Headless CI (no
                                  // permission) returns a typed Err — this impl never returns Ok(None); both are accepted
                                  // no-ops (we only assert next_frame is panic-free).
        if let Ok(Some(frame)) = cap.next_frame(Duration::from_millis(0)) {
            frame.validate_len().unwrap();
        }
    }
}
