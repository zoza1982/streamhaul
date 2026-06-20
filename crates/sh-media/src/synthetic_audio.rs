//! A portable, deterministic [`SyntheticAudioSource`] for tests and the Phase-0 pipeline.

use bytes::Bytes;
use sh_types::TimestampUs;

use crate::audio_frame::AudioFrame;

/// Default sample rate: 48 kHz, the standard for VoIP and web audio.
pub const DEFAULT_SAMPLE_RATE: u32 = 48_000;

/// Default channel count: mono.
pub const DEFAULT_CHANNELS: u8 = 1;

/// Default frame duration: 20 ms (960 samples at 48 kHz), the standard Opus frame size.
pub const DEFAULT_FRAME_DURATION_US: u64 = 20_000;

/// Generates deterministic PCM audio frames without any capture hardware.
///
/// Each call to [`next_frame`](SyntheticAudioSource::next_frame) produces a
/// frame whose samples follow a simple linear ramp pattern seeded by the
/// sequence number, making the output reproducible and verifiable without
/// needing a reference sine table.
///
/// The capture timestamp is `seq * frame_duration_us`, so successive frames
/// advance monotonically at the configured frame rate. This makes the source
/// useful as an injection point for A/V sync tests.
///
/// # Example
/// ```
/// use sh_media::SyntheticAudioSource;
///
/// let mut src = SyntheticAudioSource::new(48_000, 1, 20_000);
/// let f0 = src.next_frame();
/// let f1 = src.next_frame();
/// assert_eq!(f0.seq, 0);
/// assert_eq!(f1.seq, 1);
/// assert!(f1.capture_ts_us.0 > f0.capture_ts_us.0);
/// ```
#[derive(Debug, Clone)]
pub struct SyntheticAudioSource {
    /// Sample rate in Hz.
    sample_rate: u32,
    /// Number of interleaved channels.
    channels: u8,
    /// Duration of each frame in microseconds.
    frame_duration_us: u64,
    /// The next sequence number to emit.
    next_seq: u64,
}

impl SyntheticAudioSource {
    /// Create a new source with the given parameters.
    ///
    /// `sample_rate` is clamped to at least 1 and `channels` to at least 1 to
    /// prevent zero-size frames. `frame_duration_us` is clamped to at least 1
    /// to prevent zero-length timestamps.
    #[must_use]
    pub fn new(sample_rate: u32, channels: u8, frame_duration_us: u64) -> Self {
        Self {
            sample_rate: sample_rate.max(1),
            channels: channels.max(1),
            frame_duration_us: frame_duration_us.max(1),
            next_seq: 0,
        }
    }

    /// Create a source with default parameters (48 kHz, mono, 20 ms frames).
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(
            DEFAULT_SAMPLE_RATE,
            DEFAULT_CHANNELS,
            DEFAULT_FRAME_DURATION_US,
        )
    }

    /// Produce the next audio frame.
    ///
    /// The capture timestamp is `seq * frame_duration_us`. Samples are a deterministic ramp:
    /// each i16 value is `(seq.wrapping_mul(1000).wrapping_add(sample_index)) as i16`, where
    /// `sample_index` counts every interleaved sample in the frame (not per-channel). The ramp
    /// wraps naturally via i16 arithmetic, which is fine for test data.
    ///
    /// The sequence number is incremented after each call.
    pub fn next_frame(&mut self) -> AudioFrame {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        let capture_ts_us = TimestampUs(seq.saturating_mul(self.frame_duration_us));

        let samples = self.render_samples(seq);

        AudioFrame {
            samples,
            sample_rate: self.sample_rate,
            channels: self.channels,
            capture_ts_us,
            seq,
        }
    }

    /// Render deterministic i16 LE samples for `seq`.
    ///
    /// Samples per frame = sample_rate * frame_duration_us / 1_000_000 * channels.
    /// We use integer math with saturation to avoid panics.
    ///
    /// The ramp pattern ensures different sequences produce different buffers without
    /// needing a floating-point sine table (no `std::f64` dependency).
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
    fn render_samples(&self, seq: u64) -> Bytes {
        // samples_per_channel = sample_rate * frame_duration_us / 1_000_000
        // Use u64 arithmetic then cast to usize safely.
        let rate = u64::from(self.sample_rate);
        let chans = u64::from(self.channels);
        let samples_per_channel = rate
            .saturating_mul(self.frame_duration_us)
            .saturating_div(1_000_000);
        let total_samples = samples_per_channel.saturating_mul(chans);
        // Each i16 is 2 bytes.
        let byte_len = total_samples.saturating_mul(2);
        let byte_len = usize::try_from(byte_len).unwrap_or(usize::MAX);

        let mut buf = vec![0u8; byte_len];
        for (i, chunk) in buf.chunks_exact_mut(2).enumerate() {
            // Ramp: value = (seq * 1000 + i) as i16, naturally wrapping.
            let val = seq.wrapping_mul(1000).wrapping_add(i as u64) as i16;
            let le = val.to_le_bytes();
            if let [lo, hi] = chunk {
                *lo = le[0];
                *hi = le[1];
            }
        }
        Bytes::from(buf)
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

    #[test]
    fn produces_valid_frames_with_default_config() {
        let mut src = SyntheticAudioSource::default_config();
        let f = src.next_frame();
        assert_eq!(f.seq, 0);
        assert_eq!(f.capture_ts_us.0, 0);
        assert_eq!(f.sample_rate, DEFAULT_SAMPLE_RATE);
        assert_eq!(f.channels, DEFAULT_CHANNELS);
        f.validate_len().unwrap();
        // 48000 * 20000 / 1_000_000 = 960 samples × 1 channel × 2 bytes = 1920 bytes
        assert_eq!(f.samples.len(), 1920);
    }

    #[test]
    fn timestamps_advance_monotonically() {
        let mut src = SyntheticAudioSource::default_config();
        let f0 = src.next_frame();
        let f1 = src.next_frame();
        let f2 = src.next_frame();
        assert_eq!(f0.capture_ts_us.0, 0);
        assert_eq!(f1.capture_ts_us.0, DEFAULT_FRAME_DURATION_US);
        assert_eq!(f2.capture_ts_us.0, DEFAULT_FRAME_DURATION_US * 2);
    }

    #[test]
    fn successive_frames_differ() {
        let mut src = SyntheticAudioSource::default_config();
        let f0 = src.next_frame();
        let f1 = src.next_frame();
        assert_ne!(f0.samples, f1.samples, "successive frames must differ");
    }

    #[test]
    fn output_is_deterministic() {
        let mut a = SyntheticAudioSource::default_config();
        let mut b = SyntheticAudioSource::default_config();
        for _ in 0..5 {
            assert_eq!(a.next_frame(), b.next_frame());
        }
    }

    #[test]
    fn stereo_frame_has_correct_size() {
        let mut src = SyntheticAudioSource::new(48_000, 2, 20_000);
        let f = src.next_frame();
        // 960 samples/ch × 2 ch × 2 bytes = 3840 bytes
        assert_eq!(f.samples.len(), 3840);
        f.validate_len().unwrap();
    }

    #[test]
    fn seq_increments_correctly() {
        let mut src = SyntheticAudioSource::new(48_000, 1, 20_000);
        let f0 = src.next_frame();
        let f1 = src.next_frame();
        assert_eq!(f0.seq, 0);
        assert_eq!(f1.seq, 1);
    }
}
