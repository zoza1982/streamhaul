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
    /// Number of bytes a tightly-packed frame of `resolution` occupies in this format.
    ///
    /// For the 4:2:0 planar formats the chroma planes round each dimension **up** to even
    /// (`Y + 2·⌈w/2⌉·⌈h/2⌉`), so the count is exact even at odd resolutions. Saturates rather than
    /// overflowing on absurd resolutions.
    #[must_use]
    pub fn frame_len(self, resolution: Resolution) -> usize {
        let w = u64::from(resolution.width);
        let h = u64::from(resolution.height);
        let bytes = match self {
            PixelFormat::Bgra8 => w.saturating_mul(h).saturating_mul(4),
            PixelFormat::I420 => {
                let luma = w.saturating_mul(h);
                let chroma = w.div_ceil(2).saturating_mul(h.div_ceil(2));
                luma.saturating_add(chroma).saturating_add(chroma) // Y + Cb + Cr
            }
            PixelFormat::Nv12 => {
                let luma = w.saturating_mul(h);
                let chroma = w
                    .div_ceil(2)
                    .saturating_mul(h.div_ceil(2))
                    .saturating_mul(2); // interleaved UV
                luma.saturating_add(chroma)
            }
        };
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bgra8_frame_len() {
        assert_eq!(
            PixelFormat::Bgra8.frame_len(Resolution::new(640, 480)),
            640 * 480 * 4
        );
        assert_eq!(PixelFormat::Bgra8.frame_len(Resolution::new(0, 0)), 0);
    }

    #[test]
    fn planar_frame_len_even_and_odd() {
        // Even: 640×480 → Y=307200, +2 chroma planes of 320×240=76800 each → 460800 (I420 == NV12).
        assert_eq!(
            PixelFormat::I420.frame_len(Resolution::new(640, 480)),
            460_800
        );
        assert_eq!(
            PixelFormat::Nv12.frame_len(Resolution::new(640, 480)),
            460_800
        );
        // Odd: 3×3 → Y=9, chroma planes ceil(3/2)=2 → 2×2=4 each → I420 9+4+4=17, NV12 9+8=17.
        assert_eq!(PixelFormat::I420.frame_len(Resolution::new(3, 3)), 17);
        assert_eq!(PixelFormat::Nv12.frame_len(Resolution::new(3, 3)), 17);
        // 1×1 → Y=1, chroma 1×1=1 → I420 1+1+1=3, NV12 1+2=3.
        assert_eq!(PixelFormat::I420.frame_len(Resolution::new(1, 1)), 3);
        assert_eq!(PixelFormat::Nv12.frame_len(Resolution::new(1, 1)), 3);
    }

    #[test]
    fn validate_len_catches_mismatch() {
        let frame = VideoFrame {
            data: Bytes::from_static(&[0u8; 10]),
            format: PixelFormat::Bgra8,
            resolution: Resolution::new(2, 2), // needs 2*2*4 = 16 bytes
            frame_id: FrameId(0),
            capture_ts_us: TimestampUs(0),
        };
        assert_eq!(
            frame.validate_len(),
            Err(MediaError::FrameSize {
                expected: 16,
                got: 10
            })
        );
    }
}
