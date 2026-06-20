//! Raw/decoded frame and pixel-format types.

use bytes::Bytes;
use sh_types::{FrameId, TimestampUs};

use crate::error::MediaError;

/// Pixel format of a [`VideoFrame`]'s buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// 32-bit BGRA, 8 bits per channel. Capture/display friendly, tightly packed (stride = width·4).
    Bgra8,
    /// Planar Y′CbCr 4:2:0 (I420) — 12 bits per pixel, encoder-friendly.
    I420,
    /// Bi-planar Y′CbCr 4:2:0 (NV12) — 12 bits per pixel, hardware-encoder-friendly.
    Nv12,
}

impl PixelFormat {
    /// Average bits per pixel for this format.
    #[must_use]
    pub fn bits_per_pixel(self) -> u32 {
        match self {
            PixelFormat::Bgra8 => 32,
            PixelFormat::I420 | PixelFormat::Nv12 => 12,
        }
    }

    /// Number of bytes a tightly-packed frame of `resolution` occupies in this format.
    ///
    /// Saturates rather than overflowing on absurd resolutions.
    #[must_use]
    pub fn frame_len(self, resolution: Resolution) -> usize {
        let bits = u64::from(resolution.width)
            .saturating_mul(u64::from(resolution.height))
            .saturating_mul(u64::from(self.bits_per_pixel()));
        let bytes = bits.checked_div(8).unwrap_or(0);
        usize::try_from(bytes).unwrap_or(usize::MAX)
    }
}

/// A frame resolution in pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolution {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl Resolution {
    /// Create a resolution.
    #[must_use]
    pub fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }
}

/// A single raw or decoded video frame, with its pixel buffer and capture metadata.
///
/// The buffer is tightly packed for [`PixelFormat::Bgra8`] (stride = `width·4`). Planar formats pack
/// their planes contiguously. Zero-copy GPU-surface frames are a later concern (P0-6/P0-7); this
/// Phase-0 type is CPU-buffer-backed via [`Bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoFrame {
    /// The pixel buffer.
    pub data: Bytes,
    /// Pixel format of `data`.
    pub format: PixelFormat,
    /// Frame resolution.
    pub resolution: Resolution,
    /// Monotonic frame identifier.
    pub frame_id: FrameId,
    /// Capture timestamp in microseconds since the session epoch.
    pub capture_ts_us: TimestampUs,
}

impl VideoFrame {
    /// Validate that `data` is the exact length implied by `format` and `resolution`.
    ///
    /// # Errors
    /// Returns [`MediaError::FrameSize`] if the buffer length does not match.
    pub fn validate_len(&self) -> Result<(), MediaError> {
        let expected = self.format.frame_len(self.resolution);
        if self.data.len() == expected {
            Ok(())
        } else {
            Err(MediaError::FrameSize {
                expected,
                got: self.data.len(),
            })
        }
    }
}
