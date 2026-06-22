//! Cross-channel rate allocator for Streamhaul.
//!
//! This module splits the total send budget produced by [`CongestionController::target_bitrate`]
//! across the six logical [`ChannelId`] channels, enforcing the product invariants from `LLD.md`
//! §1 and §3.2:
//!
//! # Priority order
//!
//! Allocation proceeds in strict priority order, top to bottom:
//!
//! 1. **Input** (reserve, non-starvable) — input events are tiny and reliable;
//!    they get a small fixed floor **first**, even at near-zero total budgets.
//! 2. **Control** (reserve) — RPC and session control messages take the next fixed floor.
//! 3. **Clipboard** (reserve) — clipboard sync takes a small fixed floor.
//! 4. **Audio** (configurable floor, default 96 kbps) — voice intelligibility is more important
//!    than video quality; audio gets its floor before video takes the bulk. If the total is below
//!    the sum of the above reserves plus the audio floor, audio still wins over video and file.
//! 5. **Video** (bulk, between `video_min` and `video_max`) — consumes the bulk of what remains
//!    after the floors, clamped to `[video_min, video_max]`.
//! 6. **File** (leftover) — file transfer is last in line. It receives only what is left after
//!    all other channels are satisfied. This is the "congestion-isolated" policy described in
//!    `LLD.md` §3.2: file transfer never starves video. True per-flow QUIC isolation (a separate
//!    QUIC stream not competing at the packet level) is transport-level and tracked separately;
//!    here we express the *budget* isolation — file may only spend the leftover.
//!
//! # Degenerate / hostile totals
//!
//! When `total` is less than the sum of all configured floors, budgets are dispensed in the
//! priority order above until the budget is exhausted. Channels that cannot be served get
//! [`Bitrate::ZERO`]. The sum of allocations is always `<= total`; it is never negative or NaN.
//! `total == 0` produces all-zero allocations. `total == u64::MAX` saturates arithmetic safely.
//!
//! # Caller integration
//!
//! The typical control-loop integration is:
//!
//! ```rust
//! # use sh_adaptive::{ScreamConfig, ScreamController, CongestionController, allocator::{AllocatorConfig, RateAllocator}};
//! # use sh_adaptive::stats::TransportStats;
//! # use std::time::Instant;
//! # let config = AllocatorConfig::default();
//! let allocator = RateAllocator::new(config);
//! # let mut controller = ScreamController::new(ScreamConfig::default());
//! // In the control-tick callback:
//! // (controller has already received feedback via on_feedback)
//! let allocation = allocator.allocate(controller.target_bitrate());
//! // Hand allocations to the encoder / pacer:
//! // encoder.set_bitrate(allocation.video);
//! // audio_encoder.set_bitrate(allocation.audio);
//! // file_pacer.set_budget(allocation.file);
//! ```

use sh_types::{Bitrate, ChannelId};

// ── Public config ─────────────────────────────────────────────────────────────

/// Per-channel bitrate floors, reserves, and video min/max for [`RateAllocator`].
///
/// All fields are inclusive bounds. Defaults are chosen to reflect practical Streamhaul
/// requirements: tiny reserves for control channels, a comfortable audio floor, and a wide video
/// operating range.
#[derive(Debug, Clone)]
pub struct AllocatorConfig {
    /// Fixed floor reserved for the Input channel (highest priority).
    ///
    /// Input events are tiny (< 200 bytes per event, hundreds per second at most → well under
    /// 1 Mbps in practice). The reserve is deliberately small so it never meaningfully reduces
    /// the video budget, yet it guarantees input is served even at near-zero total.
    ///
    /// Default: 32 kbps.
    pub input_reserve: Bitrate,

    /// Fixed floor reserved for the Control channel (session RPC, keepalives).
    ///
    /// Default: 32 kbps.
    pub control_reserve: Bitrate,

    /// Fixed floor reserved for the Clipboard channel.
    ///
    /// Default: 32 kbps.
    pub clipboard_reserve: Bitrate,

    /// Minimum bitrate guaranteed to the Audio channel before video receives anything beyond its
    /// own floor.
    ///
    /// Voice intelligibility takes precedence over video quality. When the network budget is
    /// tight, the audio floor is preserved at the expense of video. Setting this to
    /// [`Bitrate::ZERO`] disables the audio priority guarantee.
    ///
    /// Default: 96 kbps (comfortable Opus stereo; 64 kbps is the practical minimum for Opus).
    pub audio_min: Bitrate,

    /// Minimum bitrate that video receives when the budget allows anything beyond the floors.
    ///
    /// If the budget is not sufficient to provide `video_min` after the floors are served,
    /// video gets whatever is left (which may be zero).
    ///
    /// Default: 200 kbps (minimum acceptable H.264/HEVC quality for a remote desktop stream).
    pub video_min: Bitrate,

    /// Maximum bitrate that video may consume. Video never receives more than this, regardless
    /// of how much total budget remains. Surplus above `video_max` (after the audio floor is
    /// already served) flows to the File channel as leftover.
    ///
    /// Default: 20 Mbps (high-quality 4K remote desktop stream with HEVC).
    pub video_max: Bitrate,
}

impl Default for AllocatorConfig {
    fn default() -> Self {
        Self {
            input_reserve: Bitrate::from_kbps(32),
            control_reserve: Bitrate::from_kbps(32),
            clipboard_reserve: Bitrate::from_kbps(32),
            audio_min: Bitrate::from_kbps(96),
            video_min: Bitrate::from_kbps(200),
            video_max: Bitrate::from_mbps(20),
        }
    }
}

// ── Allocation result ─────────────────────────────────────────────────────────

/// Per-channel bitrate allocations produced by [`RateAllocator::allocate`].
///
/// Fields are named after the [`ChannelId`] variants they correspond to. The struct uses named
/// fields rather than a `HashMap` to avoid hash-map non-determinism and allocation overhead in the
/// control-tick hot path.
///
/// The sum of all fields is always `<= total` (the argument passed to [`RateAllocator::allocate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelAllocation {
    /// Allocation for [`ChannelId::Input`].
    pub input: Bitrate,
    /// Allocation for [`ChannelId::Control`].
    pub control: Bitrate,
    /// Allocation for [`ChannelId::Clipboard`].
    pub clipboard: Bitrate,
    /// Allocation for [`ChannelId::Audio`].
    pub audio: Bitrate,
    /// Allocation for [`ChannelId::Video`].
    pub video: Bitrate,
    /// Allocation for [`ChannelId::File`].
    pub file: Bitrate,
    /// Total budget that was passed to [`RateAllocator::allocate`].
    ///
    /// Stored for convenience so callers can verify that the sum of fields equals this or can
    /// present the total alongside the per-channel breakdown in diagnostics.
    pub total: Bitrate,
}

impl ChannelAllocation {
    /// Look up the allocation for an arbitrary [`ChannelId`].
    ///
    /// Useful when callers iterate over channels generically rather than accessing named fields.
    #[must_use]
    pub fn get(&self, channel: ChannelId) -> Bitrate {
        match channel {
            ChannelId::Input => self.input,
            ChannelId::Control => self.control,
            ChannelId::Clipboard => self.clipboard,
            ChannelId::Audio => self.audio,
            ChannelId::Video => self.video,
            ChannelId::File => self.file,
        }
    }

    /// The sum of all per-channel allocations.
    ///
    /// Guaranteed to be `<= self.total`. Uses saturating addition internally (overflow is
    /// impossible given each field is `<= total`, but we saturate defensively).
    #[must_use]
    pub fn sum(&self) -> Bitrate {
        self.input
            .saturating_add(self.control)
            .saturating_add(self.clipboard)
            .saturating_add(self.audio)
            .saturating_add(self.video)
            .saturating_add(self.file)
    }
}

// ── Allocator ─────────────────────────────────────────────────────────────────

/// Cross-channel rate allocator.
///
/// Takes the total send budget from the congestion controller and distributes it across the six
/// Streamhaul channels according to the documented priority order and configurable floors/caps.
///
/// `RateAllocator` is a **pure function** of `(total, config)`: it holds no mutable state beyond
/// the configuration. Calling [`allocate`] with the same `total` always returns the same result.
/// There are no interior locks, async state, or platform dependencies.
///
/// # Usage
///
/// Construct once at session start, then call [`allocate`] on every control tick:
///
/// ```rust
/// use sh_adaptive::allocator::{AllocatorConfig, RateAllocator};
/// use sh_types::Bitrate;
///
/// let allocator = RateAllocator::new(AllocatorConfig::default());
/// let alloc = allocator.allocate(Bitrate::from_mbps(2));
/// assert!(alloc.sum() <= Bitrate::from_mbps(2));
/// // Video gets the bulk; audio gets its floor; file gets leftover (may be zero).
/// assert!(alloc.video >= alloc.file);
/// ```
///
/// [`allocate`]: RateAllocator::allocate
#[derive(Debug, Clone)]
pub struct RateAllocator {
    config: AllocatorConfig,
}

impl RateAllocator {
    /// Construct a new `RateAllocator` with the given configuration.
    #[must_use]
    pub fn new(config: AllocatorConfig) -> Self {
        Self { config }
    }

    /// Allocate `total` across all channels according to the configured priority order.
    ///
    /// The returned [`ChannelAllocation`] satisfies:
    /// - `sum() <= total` (never over-commits)
    /// - All per-channel values are `>= Bitrate::ZERO` (no negative rates)
    /// - Priority order is strictly respected (see module-level doc for details)
    #[must_use]
    pub fn allocate(&self, total: Bitrate) -> ChannelAllocation {
        let c = &self.config;
        let mut remaining = total;

        // 1. Input reserve (highest priority — must never be starved).
        let input = c.input_reserve.clamp(Bitrate::ZERO, remaining);
        remaining = remaining.saturating_sub(input);

        // 2. Control reserve.
        let control = c.control_reserve.clamp(Bitrate::ZERO, remaining);
        remaining = remaining.saturating_sub(control);

        // 3. Clipboard reserve.
        let clipboard = c.clipboard_reserve.clamp(Bitrate::ZERO, remaining);
        remaining = remaining.saturating_sub(clipboard);

        // 4. Audio floor (served before video).
        let audio = c.audio_min.clamp(Bitrate::ZERO, remaining);
        remaining = remaining.saturating_sub(audio);

        // 5. Video: bulk of what remains, clamped to [video_min, video_max].
        //    - If remaining < video_min: video gets all of remaining (may be 0).
        //    - If remaining > video_max: video is capped at video_max; the cap ensures video
        //      never grabs more than it can usefully encode, leaving surplus for file.
        let video = remaining.clamp(Bitrate::ZERO, c.video_max);
        remaining = remaining.saturating_sub(video);

        // 6. File: pure leftover after video. File never starves video.
        let file = remaining;

        ChannelAllocation {
            input,
            control,
            clipboard,
            audio,
            video,
            file,
            total,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Build a default allocator for convenience in multiple tests.
    fn default_alloc() -> RateAllocator {
        RateAllocator::new(AllocatorConfig::default())
    }

    // ── Sum invariant (proptest) ───────────────────────────────────────────────

    proptest! {
        /// For any total bitrate, the sum of channel allocations must never exceed the total.
        #[test]
        fn prop_sum_never_exceeds_total(total_bps in 0u64..=u64::MAX) {
            let alloc = default_alloc();
            let result = alloc.allocate(Bitrate::from_bps(total_bps));
            prop_assert!(result.sum() <= result.total,
                "sum {} > total {}", result.sum().as_bps(), result.total.as_bps());
        }

        /// sum() == get(Input) + get(Control) + get(Clipboard) + get(Audio) + get(Video) + get(File).
        #[test]
        fn prop_get_matches_named_fields(total_bps in 0u64..=u64::MAX) {
            let alloc = default_alloc();
            let result = alloc.allocate(Bitrate::from_bps(total_bps));
            let via_get = result.get(ChannelId::Input)
                .saturating_add(result.get(ChannelId::Control))
                .saturating_add(result.get(ChannelId::Clipboard))
                .saturating_add(result.get(ChannelId::Audio))
                .saturating_add(result.get(ChannelId::Video))
                .saturating_add(result.get(ChannelId::File));
            prop_assert_eq!(result.sum(), via_get);
        }

        /// No channel allocation ever exceeds the total.
        #[test]
        fn prop_no_channel_exceeds_total(total_bps in 0u64..=u64::MAX) {
            let alloc = default_alloc();
            let result = alloc.allocate(Bitrate::from_bps(total_bps));
            let total = Bitrate::from_bps(total_bps);
            prop_assert!(result.input    <= total);
            prop_assert!(result.control  <= total);
            prop_assert!(result.clipboard<= total);
            prop_assert!(result.audio    <= total);
            prop_assert!(result.video    <= total);
            prop_assert!(result.file     <= total);
        }

        /// Video never exceeds video_max regardless of total.
        #[test]
        fn prop_video_never_exceeds_video_max(total_bps in 0u64..=u64::MAX) {
            let config = AllocatorConfig::default();
            let video_max = config.video_max;
            let alloc = RateAllocator::new(config);
            let result = alloc.allocate(Bitrate::from_bps(total_bps));
            prop_assert!(result.video <= video_max,
                "video {} > video_max {}", result.video.as_bps(), video_max.as_bps());
        }

        /// When total >= floors sum, file is non-negative (it may still be zero if video fills the budget).
        #[test]
        fn prop_file_is_non_negative(total_bps in 0u64..=u64::MAX) {
            let alloc = default_alloc();
            let result = alloc.allocate(Bitrate::from_bps(total_bps));
            // file is Bitrate (u64 newtype), so always >= 0; this tests the type invariant.
            prop_assert!(result.file >= Bitrate::ZERO);
        }
    }

    // ── Priority order ─────────────────────────────────────────────────────────

    /// At zero total, all allocations are zero.
    #[test]
    fn zero_total_produces_zero_allocations() {
        let result = default_alloc().allocate(Bitrate::ZERO);
        assert_eq!(result.input, Bitrate::ZERO);
        assert_eq!(result.control, Bitrate::ZERO);
        assert_eq!(result.clipboard, Bitrate::ZERO);
        assert_eq!(result.audio, Bitrate::ZERO);
        assert_eq!(result.video, Bitrate::ZERO);
        assert_eq!(result.file, Bitrate::ZERO);
        assert_eq!(result.sum(), Bitrate::ZERO);
    }

    /// At 1 bps total, only Input gets anything (it has the highest priority).
    #[test]
    fn one_bps_goes_to_input_only() {
        let result = default_alloc().allocate(Bitrate::from_bps(1));
        assert_eq!(
            result.input,
            Bitrate::from_bps(1),
            "input should win at 1 bps"
        );
        assert_eq!(result.control, Bitrate::ZERO);
        assert_eq!(result.clipboard, Bitrate::ZERO);
        assert_eq!(result.audio, Bitrate::ZERO);
        assert_eq!(result.video, Bitrate::ZERO);
        assert_eq!(result.file, Bitrate::ZERO);
    }

    /// Just above the input reserve: input fills, control gets a little, rest zero.
    #[test]
    fn just_above_input_reserve_fills_input_then_control() {
        let config = AllocatorConfig::default();
        // Total = input_reserve + 1 bps
        let total = config.input_reserve.saturating_add(Bitrate::from_bps(1));
        let result = RateAllocator::new(config.clone()).allocate(total);
        assert_eq!(result.input, config.input_reserve);
        assert_eq!(result.control, Bitrate::from_bps(1));
        assert_eq!(result.clipboard, Bitrate::ZERO);
        assert_eq!(result.audio, Bitrate::ZERO);
        assert_eq!(result.video, Bitrate::ZERO);
        assert_eq!(result.file, Bitrate::ZERO);
        assert_eq!(result.sum(), total);
    }

    /// At total == input_reserve + control_reserve + clipboard_reserve: all three reserves filled,
    /// audio and video and file get zero.
    #[test]
    fn exactly_three_reserves_no_audio_no_video_no_file() {
        let config = AllocatorConfig::default();
        let total = config
            .input_reserve
            .saturating_add(config.control_reserve)
            .saturating_add(config.clipboard_reserve);
        let result = RateAllocator::new(config.clone()).allocate(total);
        assert_eq!(result.input, config.input_reserve);
        assert_eq!(result.control, config.control_reserve);
        assert_eq!(result.clipboard, config.clipboard_reserve);
        assert_eq!(result.audio, Bitrate::ZERO);
        assert_eq!(result.video, Bitrate::ZERO);
        assert_eq!(result.file, Bitrate::ZERO);
        assert_eq!(result.sum(), total);
    }

    // ── Audio floor ────────────────────────────────────────────────────────────

    /// Audio gets its full floor when the budget allows it.
    #[test]
    fn audio_floor_respected_when_budget_allows() {
        let config = AllocatorConfig::default();
        // total = all three reserves + audio_min exactly
        let total = config
            .input_reserve
            .saturating_add(config.control_reserve)
            .saturating_add(config.clipboard_reserve)
            .saturating_add(config.audio_min);
        let result = RateAllocator::new(config.clone()).allocate(total);
        assert_eq!(
            result.audio, config.audio_min,
            "audio should get its full floor"
        );
        assert_eq!(result.video, Bitrate::ZERO);
        assert_eq!(result.file, Bitrate::ZERO);
        assert_eq!(result.sum(), total);
    }

    /// When total is between the three reserves and reserves+audio_min, audio gets less than
    /// its floor but video and file still get zero (audio wins over video even below its floor).
    #[test]
    fn audio_wins_over_video_when_below_audio_floor() {
        let config = AllocatorConfig::default();
        // Put 1 bps above the three reserves — not enough for the full audio floor.
        let total = config
            .input_reserve
            .saturating_add(config.control_reserve)
            .saturating_add(config.clipboard_reserve)
            .saturating_add(Bitrate::from_bps(1));
        let result = RateAllocator::new(config).allocate(total);
        assert_eq!(
            result.audio,
            Bitrate::from_bps(1),
            "audio should win over video even when below its floor"
        );
        assert_eq!(result.video, Bitrate::ZERO);
        assert_eq!(result.file, Bitrate::ZERO);
    }

    // ── Video bulk ─────────────────────────────────────────────────────────────

    /// At a comfortable total (2 Mbps), video gets the bulk and file may get zero.
    #[test]
    fn video_gets_bulk_at_2mbps() {
        let result = default_alloc().allocate(Bitrate::from_mbps(2));
        // floors: 32+32+32+96 = 192 kbps
        // remaining for video: 2000 - 192 = 1808 kbps
        let expected_video = Bitrate::from_kbps(1808);
        assert_eq!(
            result.video, expected_video,
            "video should take the remaining budget at 2 Mbps; got {}",
            result.video
        );
        // file gets zero because video_max (20 Mbps) is not reached
        assert_eq!(result.file, Bitrate::ZERO);
        assert_eq!(result.sum(), Bitrate::from_mbps(2));
    }

    /// At 20 Mbps total, video hits video_max; file gets any leftover.
    #[test]
    fn video_capped_at_video_max_leaving_file_surplus() {
        let config = AllocatorConfig::default();
        // total well above video_max (20 Mbps) — use 25 Mbps
        let total = Bitrate::from_mbps(25);
        let result = RateAllocator::new(config.clone()).allocate(total);
        // Video must be capped at video_max.
        assert_eq!(
            result.video, config.video_max,
            "video should be capped at video_max"
        );
        // File must be non-zero.
        assert!(
            result.file > Bitrate::ZERO,
            "file should get the surplus above video_max; got {}",
            result.file
        );
        assert_eq!(result.sum(), total);
    }

    /// As total grows from video_max + floors, video reaches video_max before file gets a
    /// large share. Verify the crossover point.
    #[test]
    fn file_gets_large_share_only_after_video_reaches_max() {
        let config = AllocatorConfig::default();
        let alloc = RateAllocator::new(config.clone());

        // Floors consumed before video: input + control + clipboard + audio
        let floor_sum = config
            .input_reserve
            .saturating_add(config.control_reserve)
            .saturating_add(config.clipboard_reserve)
            .saturating_add(config.audio_min);

        // total = floors + video_max − 1 bps: video just below video_max, file = 0.
        let total_just_below = floor_sum
            .saturating_add(config.video_max)
            .saturating_sub(Bitrate::from_bps(1));
        let result_below = alloc.allocate(total_just_below);
        assert_eq!(
            result_below.file,
            Bitrate::ZERO,
            "file must be zero when total is just below the video_max crossover"
        );

        // total = floors + video_max + 1 bps: video exactly at video_max, file = 1 bps.
        let total_above = floor_sum
            .saturating_add(config.video_max)
            .saturating_add(Bitrate::from_bps(1));
        let result_above = alloc.allocate(total_above);
        assert_eq!(
            result_above.video, config.video_max,
            "video must be exactly video_max at crossover"
        );
        assert_eq!(
            result_above.file,
            Bitrate::from_bps(1),
            "file must be 1 bps immediately above the video_max crossover"
        );
    }

    // ── File never starves video ────────────────────────────────────────────────

    /// File never exceeds video at any total. Once video reaches video_max, file gets the
    /// remainder — but below video_max the video allocation always dominates file.
    #[test]
    fn file_never_starves_video_below_video_max() {
        let alloc = default_alloc();
        // Sweep across the range where video is below video_max (0 to floors + video_max).
        for kbps in [0u64, 100, 192, 300, 500, 1000, 2000, 5000, 10_000, 20_000] {
            let result = alloc.allocate(Bitrate::from_kbps(kbps));
            assert!(
                result.video >= result.file,
                "at {}kbps total: video {} < file {}",
                kbps,
                result.video.as_kbps(),
                result.file.as_kbps()
            );
        }
    }

    // ── Degenerate / hostile totals ────────────────────────────────────────────

    /// u64::MAX total does not panic and produces a valid (finite) allocation.
    #[test]
    fn u64_max_total_no_panic_no_overflow() {
        let alloc = default_alloc();
        let result = alloc.allocate(Bitrate::from_bps(u64::MAX));
        // sum() must not overflow and must be <= u64::MAX.
        assert!(result.sum() <= Bitrate::from_bps(u64::MAX));
        // video must be capped at video_max.
        assert_eq!(result.video, AllocatorConfig::default().video_max);
    }

    /// Allocation is deterministic: same input always produces same output.
    #[test]
    fn allocation_is_deterministic() {
        let alloc = default_alloc();
        let total = Bitrate::from_mbps(10);
        let a = alloc.allocate(total);
        let b = alloc.allocate(total);
        assert_eq!(a, b);
    }

    // ── Allocation table (printed when running with --nocapture) ───────────────

    /// Pretty-print allocations at several representative totals.
    ///
    /// Run with `cargo test -- --nocapture print_allocation_table` to see the table.
    #[test]
    fn print_allocation_table() {
        let alloc = default_alloc();
        println!();
        println!(
            "{:<14} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
            "Total", "Input", "Control", "Clipboard", "Audio", "Video", "File", "Sum"
        );
        println!("{}", "-".repeat(92));
        for &kbps in &[
            0u64, 1, 32, 96, 192, 200, 300, 500, 1_000, 2_000, 5_000, 10_000, 20_000, 25_000,
        ] {
            let total = Bitrate::from_kbps(kbps);
            let r = alloc.allocate(total);
            println!(
                "{:<14} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
                format!("{} kbps", kbps),
                r.input.as_kbps(),
                r.control.as_kbps(),
                r.clipboard.as_kbps(),
                r.audio.as_kbps(),
                r.video.as_kbps(),
                r.file.as_kbps(),
                r.sum().as_kbps(),
            );
        }
        println!();

        // Assert the three spot-check rows used in the task spec.
        let r200 = alloc.allocate(Bitrate::from_kbps(200));
        assert_eq!(r200.sum(), Bitrate::from_kbps(200));

        let r2m = alloc.allocate(Bitrate::from_mbps(2));
        assert_eq!(r2m.sum(), Bitrate::from_mbps(2));

        let r20m = alloc.allocate(Bitrate::from_mbps(20));
        assert_eq!(r20m.sum(), Bitrate::from_mbps(20));
    }
}
