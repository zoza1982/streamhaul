//! A/V synchronisation controller.
//!
//! Both audio and video frames carry a `capture_ts_us` drawn from the same
//! monotonic capture clock on the host. The [`AvSync`] controller uses these
//! timestamps to:
//!
//! 1. Establish a **local playout epoch** from the first frame (either stream)
//!    presented to the controller.
//! 2. Map each frame's `capture_ts_us` to a **local playout time** by
//!    preserving the relative offset from the capture epoch:
//!    `playout = local_epoch + (capture_ts - capture_epoch)`.
//! 3. Measure **skew** as `last_video_capture_ts - last_audio_capture_ts`
//!    (positive = video is ahead of audio) and emit correction hints.
//!
//! The controller is **clock-injected** via [`MonotonicClock`] so that tests
//! are fully deterministic with no real `Instant::now()` calls.

use sh_types::TimestampUs;

/// A monotonic clock whose time is measured in microseconds.
///
/// Implementations must be monotone (successive calls must return non-decreasing
/// values). A real implementation wraps `std::time::Instant`; tests inject a
/// manual counter.
pub trait MonotonicClock: Send {
    /// Returns the current time in microseconds since an arbitrary epoch.
    fn now_us(&self) -> TimestampUs;
}

/// A/V sync controller.
///
/// Establishes a common playout epoch from the first presented frame.
///
/// ```text
/// playout_instant(capture_ts) = local_epoch + (capture_ts - capture_epoch)
/// ```
///
/// Both audio and video share the capture clock, so scheduling by `capture_ts`
/// preserves relative timing exactly. Skew is measured as the signed difference
/// between the most recently presented video and audio capture timestamps:
/// positive skew means video is ahead of audio.
pub struct AvSync<C: MonotonicClock> {
    clock: C,
    /// Capture timestamp of the very first frame (either stream).
    capture_epoch: Option<TimestampUs>,
    /// Local time when the first frame arrived.
    local_epoch: Option<TimestampUs>,
    /// Capture timestamp of the most recent video frame.
    last_video_capture_ts: Option<TimestampUs>,
    /// Capture timestamp of the most recent audio frame.
    last_audio_capture_ts: Option<TimestampUs>,
}

impl<C: MonotonicClock> AvSync<C> {
    /// Creates a new [`AvSync`] controller using the given clock.
    pub fn new(clock: C) -> Self {
        Self {
            clock,
            capture_epoch: None,
            local_epoch: None,
            last_video_capture_ts: None,
            last_audio_capture_ts: None,
        }
    }

    /// Present a video frame capture timestamp to the sync controller.
    ///
    /// Returns the recommended playout time in microseconds (local clock).
    pub fn present_video(&mut self, capture_ts_us: TimestampUs) -> TimestampUs {
        self.last_video_capture_ts = Some(capture_ts_us);
        self.playout_time(capture_ts_us)
    }

    /// Present an audio packet capture timestamp to the sync controller.
    ///
    /// Returns the recommended playout time in microseconds (local clock).
    pub fn present_audio(&mut self, capture_ts_us: TimestampUs) -> TimestampUs {
        self.last_audio_capture_ts = Some(capture_ts_us);
        self.playout_time(capture_ts_us)
    }

    /// Returns the signed skew in microseconds: `video_ts − audio_ts`.
    ///
    /// Positive = video is ahead of audio.
    /// Returns `None` if either stream has not presented a frame yet.
    pub fn skew_us(&self) -> Option<i64> {
        let v = self.last_video_capture_ts?;
        let a = self.last_audio_capture_ts?;
        // Both timestamps are u64; convert to i64 for signed subtraction.
        // At realistic session lengths (hours) both values fit in i64 (max ~9.2e18 µs).
        let v_i64 = i64::try_from(v.0).unwrap_or(i64::MAX);
        let a_i64 = i64::try_from(a.0).unwrap_or(i64::MAX);
        Some(v_i64.saturating_sub(a_i64))
    }

    /// Returns `true` if `|skew| <= tolerance_us`.
    ///
    /// Returns `false` if either stream has not presented a frame yet.
    pub fn in_sync(&self, tolerance_us: u64) -> bool {
        match self.skew_us() {
            None => false,
            Some(skew) => {
                let abs_skew = skew.unsigned_abs();
                abs_skew <= tolerance_us
            }
        }
    }

    /// Returns a correction hint for audio playout.
    ///
    /// - Positive hint: advance audio playout (audio is behind video).
    /// - Negative hint: hold audio playout (audio is ahead of video).
    ///
    /// The hint is a proportional nudge: `hint = skew / 2`, clamped to
    /// ±500 ms to prevent runaway corrections.
    ///
    /// Returns `None` if either stream has not presented a frame yet.
    pub fn audio_correction_hint_us(&self) -> Option<i64> {
        const MAX_HINT_US: i64 = 500_000; // 500 ms
        let skew = self.skew_us()?;
        // Positive skew = video ahead = audio behind → positive hint = advance audio.
        let hint = skew.saturating_div(2);
        Some(hint.clamp(-MAX_HINT_US, MAX_HINT_US))
    }

    /// Compute the playout time for a given capture timestamp.
    ///
    /// Epoch is established on the first call (either audio or video).
    /// Subsequent calls use the same epoch pair.
    fn playout_time(&mut self, capture_ts_us: TimestampUs) -> TimestampUs {
        let now = self.clock.now_us();
        match (self.capture_epoch, self.local_epoch) {
            (None, _) | (_, None) => {
                // First frame: establish epoch.
                self.capture_epoch = Some(capture_ts_us);
                self.local_epoch = Some(now);
                now
            }
            (Some(cap_epoch), Some(local_epoch)) => {
                // offset = capture_ts - capture_epoch (signed, so video arriving
                // before audio's first frame is represented correctly).
                let offset = i64::try_from(capture_ts_us.0)
                    .unwrap_or(i64::MAX)
                    .saturating_sub(i64::try_from(cap_epoch.0).unwrap_or(i64::MAX));
                // playout = local_epoch + offset (clamp to 0 if negative, i.e. a
                // frame that arrived before the first frame is played immediately).
                let playout = if offset >= 0 {
                    local_epoch
                        .0
                        .saturating_add(u64::try_from(offset).unwrap_or(0))
                } else {
                    // Frame is from before the epoch; schedule it for immediate playout.
                    local_epoch.0
                };
                TimestampUs(playout)
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
mod tests {
    use super::*;

    /// A manual, deterministic clock for tests.
    struct ManualClock {
        now: u64,
    }

    impl ManualClock {
        fn new(start: u64) -> Self {
            Self { now: start }
        }

        fn advance(&mut self, delta_us: u64) {
            self.now = self.now.saturating_add(delta_us);
        }
    }

    impl MonotonicClock for ManualClock {
        fn now_us(&self) -> TimestampUs {
            TimestampUs(self.now)
        }
    }

    /// Gate test: A/V skew stays within ±20ms across a simulated run.
    ///
    /// Setup:
    /// - Audio: 48 kHz, 20 ms frames → capture_ts 0, 20000, 40000, …
    /// - Video: 60 fps → capture_ts 0, 16667, 33333, …
    /// - Audio is artificially started 5 ms behind video to test that we can
    ///   measure non-zero skew (and that it stays within the 20 ms tolerance).
    ///
    /// The clock advances deterministically between each present call.
    /// After initial setup, |skew| must be ≤ 20000 µs for all frames.
    #[test]
    fn av_sync_skew_within_20ms() {
        // Audio: 20 ms frame interval
        const AUDIO_INTERVAL_US: u64 = 20_000;
        // Video: ~16.667 ms at 60 fps
        const VIDEO_INTERVAL_US: u64 = 16_667;
        const TOLERANCE_US: u64 = 20_000;
        // Simulate 200 audio frames and 240 video frames (about 4 seconds).
        const AUDIO_FRAMES: u64 = 200;
        const VIDEO_FRAMES: u64 = 240;

        // Audio starts 5 ms "behind" video in capture time.
        const AUDIO_OFFSET_US: u64 = 5_000;

        let clock = ManualClock::new(1_000_000); // arbitrary local epoch start
        let mut sync = AvSync::new(clock);

        let mut max_skew_us: i64 = 0;

        // Interleave frames in chronological order of capture_ts.
        let mut audio_seq: u64 = 0;
        let mut video_seq: u64 = 0;

        loop {
            let audio_done = audio_seq >= AUDIO_FRAMES;
            let video_done = video_seq >= VIDEO_FRAMES;
            if audio_done && video_done {
                break;
            }

            let audio_ts =
                AUDIO_OFFSET_US.saturating_add(audio_seq.saturating_mul(AUDIO_INTERVAL_US));
            let video_ts = video_seq.saturating_mul(VIDEO_INTERVAL_US);

            // Advance whichever stream is earlier in capture time.
            let present_audio = !audio_done && (video_done || audio_ts <= video_ts);

            if present_audio {
                sync.clock.advance(1_000); // 1 ms local clock advance per audio frame
                sync.present_audio(TimestampUs(audio_ts));
                audio_seq = audio_seq.saturating_add(1);
            } else {
                sync.clock.advance(800); // 0.8 ms local clock advance per video frame
                sync.present_video(TimestampUs(video_ts));
                video_seq = video_seq.saturating_add(1);
            }

            // Once both streams have at least one frame, check skew.
            if let Some(skew) = sync.skew_us() {
                let abs_skew = skew.abs();
                if abs_skew > max_skew_us {
                    max_skew_us = abs_skew;
                }
            }
        }

        println!(
            "A/V sync gate test: max |skew| = {} µs ({} ms)",
            max_skew_us,
            max_skew_us / 1000
        );

        // The skew is purely the difference between the capture timestamps at the
        // point of measurement. With audio 5 ms behind video and frame intervals of
        // 20 ms (audio) vs 16.667 ms (video), the skew oscillates but stays well
        // within 20 ms.
        assert!(
            max_skew_us <= i64::try_from(TOLERANCE_US).unwrap_or(i64::MAX),
            "A/V skew exceeded ±20 ms tolerance: max observed = {} µs",
            max_skew_us
        );

        // Also verify skew is not zero for all frames (would hide a bug where we
        // always return the same timestamp and skew calculation is trivially zero).
        // The initial 5 ms audio offset means we MUST observe non-zero skew at some
        // point.
        assert!(
            max_skew_us > 0,
            "max skew must be non-zero (test would be trivially passing if always zero)"
        );
    }

    #[test]
    fn skew_none_before_both_streams_presented() {
        let clock = ManualClock::new(0);
        let mut sync = AvSync::new(clock);
        assert_eq!(sync.skew_us(), None);
        sync.present_video(TimestampUs(1000));
        assert_eq!(sync.skew_us(), None); // audio not presented yet
        sync.present_audio(TimestampUs(0));
        assert!(sync.skew_us().is_some());
    }

    #[test]
    fn skew_positive_when_video_ahead() {
        let clock = ManualClock::new(0);
        let mut sync = AvSync::new(clock);
        sync.present_video(TimestampUs(5_000));
        sync.present_audio(TimestampUs(0));
        let skew = sync.skew_us().unwrap();
        assert_eq!(skew, 5_000, "video 5 ms ahead → skew = +5000");
    }

    #[test]
    fn skew_negative_when_audio_ahead() {
        let clock = ManualClock::new(0);
        let mut sync = AvSync::new(clock);
        sync.present_video(TimestampUs(0));
        sync.present_audio(TimestampUs(5_000));
        let skew = sync.skew_us().unwrap();
        assert_eq!(skew, -5_000, "audio 5 ms ahead → skew = −5000");
    }

    #[test]
    fn in_sync_within_tolerance() {
        let clock = ManualClock::new(0);
        let mut sync = AvSync::new(clock);
        sync.present_video(TimestampUs(3_000));
        sync.present_audio(TimestampUs(0));
        assert!(
            sync.in_sync(5_000),
            "3 ms skew should be in sync at 5 ms tolerance"
        );
        assert!(
            !sync.in_sync(2_000),
            "3 ms skew must not be in sync at 2 ms tolerance"
        );
    }

    #[test]
    fn correction_hint_advances_audio_when_video_ahead() {
        let clock = ManualClock::new(0);
        let mut sync = AvSync::new(clock);
        sync.present_video(TimestampUs(10_000));
        sync.present_audio(TimestampUs(0));
        let hint = sync.audio_correction_hint_us().unwrap();
        assert_eq!(hint, 5_000, "hint = skew / 2 = 10000 / 2");
    }

    #[test]
    fn correction_hint_holds_audio_when_audio_ahead() {
        let clock = ManualClock::new(0);
        let mut sync = AvSync::new(clock);
        sync.present_video(TimestampUs(0));
        sync.present_audio(TimestampUs(10_000));
        let hint = sync.audio_correction_hint_us().unwrap();
        assert_eq!(hint, -5_000, "hint = skew / 2 = −10000 / 2");
    }

    #[test]
    fn playout_epoch_established_on_first_frame() {
        let clock = ManualClock::new(1_000);
        let mut sync = AvSync::new(clock);
        // First video frame: capture_ts=500, local clock at 1000.
        let t0 = sync.present_video(TimestampUs(500));
        assert_eq!(t0.0, 1_000, "first frame plays out at local_epoch");
        // Second video frame: capture_ts=1500 (1 ms later in capture time).
        sync.clock.advance(1_000);
        let t1 = sync.present_video(TimestampUs(1_500));
        // playout = local_epoch(1000) + (1500 - 500) = 1000 + 1000 = 2000
        assert_eq!(t1.0, 2_000);
    }
}
