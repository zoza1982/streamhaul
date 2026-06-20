//! A portable, deterministic [`ScreenCapturer`] for tests, demos, and the Phase-0 latency harness.

use std::time::Duration;

use bytes::Bytes;
use sh_types::{FrameId, TimestampUs};

use crate::error::MediaError;
use crate::frame::{PixelFormat, Resolution, VideoFrame};
use crate::ScreenCapturer;

/// Generates deterministic BGRA test frames without any capture hardware.
///
/// Each frame carries an incrementing [`FrameId`] and a content pattern that depends on the frame id,
/// so a decoded frame can be byte-compared against the original to verify end-to-end integrity. The
/// capture timestamp is a deterministic function of the frame id (`frame_id × frame_interval`), which
/// keeps the generator reproducible; wall-clock latency is measured separately by the harness.
///
/// `next_frame` returns immediately (it ignores `timeout`): pacing to the target frame rate is the
/// caller's responsibility, which keeps tests deterministic.
#[derive(Debug, Clone)]
pub struct SyntheticCapturer {
    resolution: Resolution,
    frame_interval_us: u64,
    next_frame_id: u64,
}

impl SyntheticCapturer {
    /// Create a capturer producing `resolution` BGRA frames whose timestamps advance as if captured
    /// at `fps` frames per second. `fps` is clamped to at least 1.
    #[must_use]
    pub fn new(resolution: Resolution, fps: u32) -> Self {
        let fps = fps.max(1);
        let frame_interval_us = 1_000_000u64.checked_div(u64::from(fps)).unwrap_or(0);
        Self {
            resolution,
            frame_interval_us,
            next_frame_id: 0,
        }
    }

    /// Render the deterministic BGRA pattern for `frame_id`.
    ///
    /// The arithmetic here is bounded test-pattern generation (values are masked to a byte), so the
    /// overflow/cast lints are locally allowed rather than littering the hot loop with conversions.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
    fn render_pattern(&self, frame_id: u64) -> Bytes {
        let width = u64::from(self.resolution.width);
        let len = PixelFormat::Bgra8.frame_len(self.resolution);
        let mut buf = vec![0u8; len];
        for (i, px) in buf.chunks_exact_mut(4).enumerate() {
            let idx = i as u64;
            let x = idx.checked_rem(width).unwrap_or(0);
            let y = idx.checked_div(width).unwrap_or(0);
            if let [b, g, r, a] = px {
                *b = ((x + frame_id) & 0xFF) as u8;
                *g = ((y + frame_id) & 0xFF) as u8;
                *r = (frame_id & 0xFF) as u8;
                *a = 0xFF;
            }
        }
        Bytes::from(buf)
    }
}

impl ScreenCapturer for SyntheticCapturer {
    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<VideoFrame>, MediaError> {
        let frame_id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.wrapping_add(1);
        let capture_ts_us = frame_id.wrapping_mul(self.frame_interval_us);
        Ok(Some(VideoFrame {
            data: self.render_pattern(frame_id),
            format: PixelFormat::Bgra8,
            resolution: self.resolution,
            frame_id: FrameId(frame_id),
            capture_ts_us: TimestampUs(capture_ts_us),
        }))
    }

    fn resolution(&self) -> Resolution {
        self.resolution
    }

    fn pixel_format(&self) -> PixelFormat {
        PixelFormat::Bgra8
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn res() -> Resolution {
        Resolution::new(16, 8)
    }

    #[test]
    fn produces_well_formed_frames() {
        let mut cap = SyntheticCapturer::new(res(), 60);
        assert_eq!(cap.resolution(), res());
        assert_eq!(cap.pixel_format(), PixelFormat::Bgra8);

        let frame = cap.next_frame(Duration::ZERO).unwrap().unwrap();
        assert_eq!(frame.frame_id, FrameId(0));
        assert_eq!(frame.format, PixelFormat::Bgra8);
        frame.validate_len().unwrap();
        assert_eq!(frame.data.len(), 16 * 8 * 4);
    }

    #[test]
    fn frame_ids_increment_and_content_changes() {
        let mut cap = SyntheticCapturer::new(res(), 30);
        let f0 = cap.next_frame(Duration::ZERO).unwrap().unwrap();
        let f1 = cap.next_frame(Duration::ZERO).unwrap().unwrap();
        assert_eq!(f0.frame_id, FrameId(0));
        assert_eq!(f1.frame_id, FrameId(1));
        assert_ne!(f0.data, f1.data, "successive frames must differ");
        // Capture timestamps advance by one 30fps interval (33_333 µs).
        assert_eq!(f0.capture_ts_us, TimestampUs(0));
        assert_eq!(f1.capture_ts_us, TimestampUs(33_333));
    }

    #[test]
    fn output_is_deterministic() {
        let mut a = SyntheticCapturer::new(res(), 60);
        let mut b = SyntheticCapturer::new(res(), 60);
        for _ in 0..4 {
            assert_eq!(
                a.next_frame(Duration::ZERO).unwrap(),
                b.next_frame(Duration::ZERO).unwrap()
            );
        }
    }
}
