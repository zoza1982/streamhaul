//! Raw/decoded audio frame type.

use bytes::Bytes;
use sh_types::TimestampUs;

use crate::error::MediaError;

/// A single raw, decoded audio frame carrying interleaved i16 little-endian PCM samples.
///
/// Samples are interleaved: for stereo (channels = 2), the layout is
/// `[L0, R0, L1, R1, …]`. The byte representation of each i16 sample is
/// **little-endian** (least-significant byte first), matching the standard
/// convention for PCM on both Linux (ALSA) and Windows (WASAPI).
///
/// The frame owns its buffer via [`Bytes`] for cheap cloning across pipeline stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFrame {
    /// Interleaved i16 LE PCM samples for all channels.
    ///
    /// The field is named `samples` (not `data`) to distinguish it from
    /// [`VideoFrame::data`], which is an opaque pixel buffer. The naming
    /// reflects the semantic: audio is addressable as typed i16 samples,
    /// not as an arbitrary byte blob.
    ///
    /// Length must be even (`len % 2 == 0`), since each sample is 2 bytes.
    /// For multi-channel audio `samples.len() / 2` must be divisible by `channels`.
    pub samples: Bytes,
    /// Sample rate in Hz (e.g. 48000).
    pub sample_rate: u32,
    /// Number of interleaved channels (e.g. 1 for mono, 2 for stereo).
    pub channels: u8,
    /// Capture timestamp in microseconds since the session epoch.
    pub capture_ts_us: TimestampUs,
    /// Monotonic sequence number, incremented by the source per frame.
    pub seq: u64,
}

impl AudioFrame {
    /// Validate the frame's buffer length is consistent with its format.
    ///
    /// Checks:
    /// - `channels > 0`
    /// - `sample_rate > 0`
    /// - `samples.len() % 2 == 0` (each i16 is 2 bytes)
    /// - For multi-channel audio: `(samples.len() / 2) % channels == 0`
    ///   (the total sample count must be divisible by the channel count)
    ///
    /// # Errors
    /// Returns [`MediaError::Unsupported`] if `channels == 0` or `sample_rate == 0`.
    /// Returns [`MediaError::FrameSize`] if the byte length is odd or the sample
    /// count is not divisible by the channel count.
    pub fn validate_len(&self) -> Result<(), MediaError> {
        if self.channels == 0 {
            return Err(MediaError::Unsupported(
                "audio frame has zero channels".to_owned(),
            ));
        }
        if self.sample_rate == 0 {
            return Err(MediaError::Unsupported(
                "audio frame has zero sample rate".to_owned(),
            ));
        }
        if self.samples.len() % 2 != 0 {
            return Err(MediaError::FrameSize {
                expected: self.samples.len().saturating_sub(1),
                got: self.samples.len(),
            });
        }
        // For multi-channel frames: each channel must have a whole number of samples.
        let total_samples = self.samples.len() / 2;
        let ch = usize::from(self.channels);
        if ch > 1 {
            // checked_rem avoids the clippy::arithmetic_side_effects lint on `%` (variable divisor).
            // ch is non-zero (channels > 0 checked above) so this is always Some; the unwrap_or(1)
            // fallback is fail-safe — a zero divisor would yield a non-zero remainder and reject the
            // frame rather than silently accepting it, should the guard above ever be removed.
            let rem = total_samples.checked_rem(ch).unwrap_or(1);
            if rem != 0 {
                return Err(MediaError::FrameSize {
                    expected: total_samples.saturating_sub(rem).saturating_mul(2),
                    got: self.samples.len(),
                });
            }
        }
        Ok(())
    }

    /// Returns the number of i16 samples in the buffer (i.e., `samples.len() / 2`).
    ///
    /// For a multi-channel frame, this counts all channel samples combined.
    /// Divide by `channels` to get the number of per-channel sample points.
    #[must_use]
    pub fn sample_count(&self) -> usize {
        // Integer division: samples are always 2 bytes each.
        self.samples.len() / 2
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn make_frame(len: usize, channels: u8, sample_rate: u32) -> AudioFrame {
        AudioFrame {
            samples: Bytes::from(vec![0u8; len]),
            sample_rate,
            channels,
            capture_ts_us: TimestampUs(0),
            seq: 0,
        }
    }

    #[test]
    fn validate_rejects_zero_channels() {
        let f = make_frame(4, 0, 48_000);
        assert!(
            matches!(f.validate_len(), Err(MediaError::Unsupported(_))),
            "zero channels must be rejected with Unsupported"
        );
    }

    #[test]
    fn validate_rejects_zero_sample_rate() {
        let f = make_frame(4, 1, 0);
        assert!(
            matches!(f.validate_len(), Err(MediaError::Unsupported(_))),
            "zero sample_rate must be rejected with Unsupported"
        );
    }

    #[test]
    fn validate_rejects_odd_byte_count() {
        let f = make_frame(3, 1, 48_000);
        assert!(
            matches!(f.validate_len(), Err(MediaError::FrameSize { .. })),
            "odd byte count must be rejected"
        );
    }

    #[test]
    fn validate_rejects_stereo_frame_with_odd_sample_count() {
        // 6 bytes = 3 i16 samples, channels=2 → 3 % 2 != 0 → invalid
        let f = make_frame(6, 2, 48_000);
        assert!(
            matches!(f.validate_len(), Err(MediaError::FrameSize { .. })),
            "stereo frame with 3 samples (not divisible by 2 channels) must be rejected"
        );
    }

    #[test]
    fn validate_accepts_valid_stereo_frame() {
        // 8 bytes = 4 i16 samples, channels=2 → 4 % 2 == 0 → valid
        let f = make_frame(8, 2, 48_000);
        assert!(f.validate_len().is_ok());
    }

    #[test]
    fn validate_accepts_valid_frame() {
        let f = make_frame(960 * 2, 1, 48_000);
        assert!(f.validate_len().is_ok());
    }

    #[test]
    fn sample_count_is_half_byte_len() {
        let f = make_frame(8, 2, 48_000);
        assert_eq!(f.sample_count(), 4);
    }
}
