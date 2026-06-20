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
    ///
    /// # Errors
    /// Returns [`MediaError::FrameSize`] if any invariant is violated.
    pub fn validate_len(&self) -> Result<(), MediaError> {
        if self.channels == 0 {
            return Err(MediaError::FrameSize {
                expected: 0,
                got: self.samples.len(),
            });
        }
        if self.sample_rate == 0 {
            return Err(MediaError::FrameSize {
                expected: 0,
                got: self.samples.len(),
            });
        }
        if self.samples.len() % 2 != 0 {
            return Err(MediaError::FrameSize {
                expected: self.samples.len().saturating_sub(1),
                got: self.samples.len(),
            });
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
            matches!(f.validate_len(), Err(MediaError::FrameSize { .. })),
            "zero channels must be rejected"
        );
    }

    #[test]
    fn validate_rejects_zero_sample_rate() {
        let f = make_frame(4, 1, 0);
        assert!(
            matches!(f.validate_len(), Err(MediaError::FrameSize { .. })),
            "zero sample_rate must be rejected"
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
