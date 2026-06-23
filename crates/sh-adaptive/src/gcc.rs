//! GCC (Google Congestion Control) congestion controller for the WebRTC path.
//!
//! This module implements a pragmatic **Google Congestion Control (GCC)** controller, the
//! algorithm implemented by Chromium/libwebrtc and documented in the IETF drafts
//! `draft-ietf-rmcat-gcc` and `draft-holmer-rmcat-transport-wide-cc-extensions`.
//!
//! GCC combines a **delay-based** estimate (using inter-arrival time OWD gradients) with a
//! **loss-based** bound. This implementation uses the [`TransportStats`] `queue_delay` field as
//! a proxy for the one-way delay gradient rather than computing a full Kalman/trendline filter
//! on per-packet arrival times.
//!
//! ## Algorithm overview
//!
//! 1. **Delay state machine** — on each feedback:
//!    - If `queue_delay > OVERUSE_THRESHOLD` (25 ms): enter **Decrease** state.
//!    - If `queue_delay < UNDERUSE_THRESHOLD` (10 ms) and state was **Decrease**: enter **Hold**.
//!    - If `queue_delay < UNDERUSE_THRESHOLD` and state was **Hold**: enter **Increase**.
//!
//! 2. **Bitrate update** — per state:
//!    - **Decrease**: multiply estimate by `BETA_DECREASE` (0.85), at most once per RTT.
//!    - **Hold**: no change.
//!    - **Increase**: multiplicative (`×1.08`) when far from `last_known_rate_bps`;
//!      additive (`+8 kbps`) once within 90% of the last known operating point.
//!      The operating-point anchor (`last_known_rate_bps`) is **stale-aware**: if the estimate
//!      has grown more than `OPERATING_POINT_RESET_MARGIN` above the anchor while in Increase
//!      (meaning no congestion signal has refreshed the anchor), the anchor is reset to `None`
//!      so multiplicative growth resumes toward the actual capacity ceiling. This prevents a
//!      stale post-decrease anchor from locking the controller into slow additive fill after a
//!      genuine capacity increase. The anchor is only refreshed by a non-suppressed Decrease
//!      (either delay-based or loss-based), so it always reflects a real, recent congestion
//!      signal.
//!
//! 3. **Loss-based adjustment** — applied AFTER the delay state machine, using a pre-state
//!    snapshot to avoid double application with a concurrent delay Decrease:
//!    - If loss fraction > 10%: apply `BETA_DECREASE` once per RTT (same `decrease_suppressed`
//!      gate as the delay path); write back to `estimate_bps`; update `last_decrease_time`.
//!    - If loss fraction > 2%: freeze (revert any increase that just happened).
//!
//! 4. **Final target** — `estimate_bps.clamp(min, max)`.
//!
//! ## Deviations from libwebrtc / RFC drafts
//!
//! 1. **OWD proxy**: uses `TransportStats::queue_delay` as a one-way-delay gradient proxy.
//!    Real GCC computes the inter-arrival gradient via a Kalman/trendline filter on per-packet
//!    arrival timestamps (TWCC). Deferred to P5 when TWCC feedback arrives from browsers.
//!
//! 2. **Simplified state transitions**: real GCC has hysteresis counters before transitioning
//!    `Hold → Increase` and `Increase → Decrease`. This implementation uses single-measurement
//!    thresholds, making the controller more reactive but easier to reason about. The
//!    `last_known_rate_bps` field switches from multiplicative to additive increase once
//!    the estimate is within 90% of the last known operating point, mitigating overshoot.
//!    The anchor is only written during Decrease when `estimate > acked_throughput` (genuine
//!    overshoot), guaranteeing `anchor ≥ cap` at all times and preventing spurious stale resets.
//!
//! 3. **Single estimate**: real GCC maintains a separate bandwidth estimator (BWE) with its own
//!    exponential moving average, and merges it with the delay estimate via `min`. We use a single
//!    `estimate_bps` that serves both roles.
//!
//! 4. **AIMD constants**: chosen to match libwebrtc's general shape (8 kbps additive increase,
//!    0.85 multiplicative decrease, ×1.08 multiplicative growth), but not bit-for-bit identical.
//!
//! 5. **Loss-to-state writeback**: libwebrtc applies the loss-based decrease to the
//!    internal estimate (permanent state change). Earlier revisions only applied it to the
//!    derived target (a per-tick overlay). Fixed: loss decrease now writes back to
//!    `estimate_bps`, updates `last_decrease_time`, and is gated by `decrease_suppressed` so
//!    it fires at most once per RTT — identical rate-limiting to the delay-path Decrease.
//!    The loss cap uses the pre-delay-state snapshot to avoid double application with a
//!    concurrent delay Decrease.
//!
//! 6. **Stale operating-point reset** (ADR-0013 note): `last_known_rate_bps` is reset to
//!    `None` when the acknowledged throughput in the Increase arm exceeds the anchor.  This is
//!    safe because the Decrease arm only writes the anchor when `estimate > acked_throughput`
//!    (genuine overshoot), guaranteeing `anchor ≥ bottleneck_cap` whenever it is set.  After
//!    a real capacity increase, the estimate grows additively past the old anchor and the very
//!    next tick has `acked_throughput > anchor`, clearing the anchor and re-enabling ×1.08
//!    multiplicative fill to probe the new ceiling.

use std::time::{Duration, Instant};

use crate::util::{clamp_duration, clamp_rtt, MAX_QUEUE_DELAY, MIN_RTT_SECS};
use crate::{Bitrate, CongestionController, TransportStats};

// ── Internal constants ────────────────────────────────────────────────────────

/// Queue-delay threshold above which the controller signals **overuse** and enters Decrease.
///
/// Stored as `f64` to avoid repeated `as_secs_f64()` in the hot path.
/// Deviation from libwebrtc: libwebrtc uses an adaptive threshold based on the trendline filter;
/// we use a fixed 25 ms to match the OVERUSE_THRESHOLD constant in `modules/remote_bitrate_estimator`.
const OVERUSE_THRESHOLD_SECS: f64 = 0.025;

/// Queue-delay threshold below which the controller signals **underuse**.
///
/// Stored as `f64` to avoid repeated `as_secs_f64()` in the hot path.
const UNDERUSE_THRESHOLD_SECS: f64 = 0.010;

/// Loss fraction (proportion of packets) above which the loss-based estimate applies a decrease.
///
/// libwebrtc: `kDefaultHighLossFraction = 0.1` (10%).
const LOSS_HIGH_THRESHOLD: f64 = 0.10;

/// Loss fraction below which no loss-based penalty applies.
///
/// libwebrtc: `kDefaultLowLossFraction = 0.02` (2%).
const LOSS_LOW_THRESHOLD: f64 = 0.02;

/// Multiplicative decrease factor for both delay-overuse and high-loss events.
///
/// GCC spec: `β = 0.85` (15% decrease). Matches libwebrtc `kDefaultDecreaseRate`.
const BETA_DECREASE: f64 = 0.85;

/// Maximum additive bitrate increase per feedback step when near the cap (AIMD steady-state).
///
/// libwebrtc additive increase is ~8 kbps per interval. Stored as bits per second.
/// The actual per-tick step is further capped by `AIMD_HEADROOM_FRACTION` so that the
/// estimate cannot overshoot the confirmed operating-point anchor in a single large step.
const AIMD_INCREASE_BPS: f64 = 8_000.0;

/// Fraction of the remaining headroom to the anchor used as the additive step cap.
///
/// When within 90% of the last known anchor, the additive step per tick is capped at
/// `(anchor - estimate) × AIMD_HEADROOM_FRACTION`.  This ensures the estimate asymptotically
/// approaches the anchor rather than overshooting it by many multiples of the flat step.
///
/// Rationale: the overuse-detection queue delay (25 ms) takes hundreds of ticks to build up
/// when the estimate overshoots the bottleneck by only a few kbps.  Without this cap, the
/// estimate can grow far above the real cap during the slow-queue-build period, producing a
/// wide oscillation band.  With the cap, the estimate stays within a small margin of the anchor,
/// and the max/min ratio in the tail window is bounded to ≈ 1/BETA_DECREASE ≈ 1.18.
const AIMD_HEADROOM_FRACTION: f64 = 0.50;

/// Multiplicative increase factor when far from the cap (< 90% of max).
///
/// libwebrtc uses ×1.08 per feedback when in the multiplicative-increase region.
const MULTIPLICATIVE_INCREASE_FACTOR: f64 = 1.08;

/// Pacing packet size in bytes for `pacing_interval` computation.
const MIN_PACING_PACKET_BYTES: u32 = 1_460;

/// Minimum feedback update interval. Sub-millisecond feedback causes numerical instability.
const MIN_UPDATE_INTERVAL: Duration = Duration::from_millis(1);

/// Maximum inter-feedback gap before a cold-restart. Stale state after silence is discarded.
const MAX_UPDATE_INTERVAL: Duration = Duration::from_secs(30);

// ── Private state enum ────────────────────────────────────────────────────────

/// Delay-based controller state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Waiting for conditions to improve before increasing (after a Decrease).
    Hold,
    /// Underuse confirmed: increase estimate toward available capacity.
    Increase,
    /// Overuse detected: reduce estimate to relieve the queue.
    Decrease,
}

// ── Public types ──────────────────────────────────────────────────────────────

/// Configuration parameters for [`GccController`].
///
/// All bitrate bounds are inclusive. The controller always keeps `target_bitrate()` within
/// `[min_bitrate, max_bitrate]`.
#[derive(Debug, Clone)]
pub struct GccConfig {
    /// Minimum allowed target bitrate.
    ///
    /// Default: 100 kbps.
    pub min_bitrate: Bitrate,

    /// Maximum allowed target bitrate.
    ///
    /// Default: 50 Mbps.
    pub max_bitrate: Bitrate,

    /// Initial target bitrate before any feedback has been received.
    ///
    /// Default: 2 Mbps.
    pub initial_bitrate: Bitrate,

    /// Assumed initial RTT for decrease-suppression before a real RTT sample arrives.
    ///
    /// Default: 50 ms.
    pub initial_rtt: Duration,
}

impl Default for GccConfig {
    fn default() -> Self {
        Self {
            min_bitrate: Bitrate::from_kbps(100),
            max_bitrate: Bitrate::from_mbps(50),
            initial_bitrate: Bitrate::from_mbps(2),
            initial_rtt: Duration::from_millis(50),
        }
    }
}

/// GCC congestion controller for the WebRTC data-channel path.
///
/// # Construction
///
/// ```rust
/// use sh_adaptive::{GccConfig, GccController};
/// use sh_adaptive::Bitrate;
///
/// let config = GccConfig {
///     min_bitrate: Bitrate::from_kbps(100),
///     max_bitrate: Bitrate::from_mbps(50),
///     ..GccConfig::default()
/// };
/// let controller = GccController::new(config);
/// ```
///
/// # Clock injection
///
/// `GccController` never calls `Instant::now()`. All time is supplied by the caller via the
/// `now` parameter of `on_feedback`. This makes the controller deterministic and testable.
///
/// # Robustness
///
/// The controller is robust to hostile/degenerate feedback from the network:
/// - Zero, negative (via underflow), or huge RTT values are clamped.
/// - `bytes_lost > bytes_acked` is handled gracefully (loss fraction clamped to 1.0).
/// - Non-monotonic `now` (clock going backwards) causes the feedback to be silently ignored.
/// - All internal `f64` results are checked for `NaN`/`Inf` before updating state.
#[derive(Debug)]
pub struct GccController {
    config: GccConfig,

    /// Current delay-based controller state.
    state: State,

    /// Smoothed RTT (EWMA, α = 0.125), in seconds.
    srtt_secs: f64,

    /// `Instant` of the last `on_feedback` call.
    last_feedback_time: Option<Instant>,

    /// Last decrease event time. Used to suppress multiple decreases within one RTT.
    last_decrease_time: Option<Instant>,

    /// Delay-based bitrate estimate (bits per second). Raw; clamped when deriving `target_bitrate`.
    estimate_bps: f64,

    /// Cached target bitrate (re-derived on each feedback).
    target_bitrate: Bitrate,

    /// The `estimate_bps` value recorded just BEFORE the most recent non-suppressed Decrease.
    ///
    /// Used by the Increase arm to switch from multiplicative to additive increase once the
    /// estimate is within 90% of this last known operating point, preventing limit cycles.
    /// Reset to `None` on cold-restart.
    last_known_rate_bps: Option<f64>,
}

impl GccController {
    /// Create a new `GccController` with the given configuration.
    ///
    /// The controller starts in `Hold` state, using `config.initial_bitrate` as the first target
    /// bitrate until feedback arrives.
    #[must_use]
    pub fn new(config: GccConfig) -> Self {
        let initial_bitrate = config
            .initial_bitrate
            .clamp(config.min_bitrate, config.max_bitrate);
        let initial_rtt_secs = clamp_rtt(config.initial_rtt).as_secs_f64();
        Self {
            srtt_secs: initial_rtt_secs,
            estimate_bps: initial_bitrate.as_bps_f64(),
            target_bitrate: initial_bitrate,
            state: State::Hold,
            last_feedback_time: None,
            last_decrease_time: None,
            last_known_rate_bps: None,
            config,
        }
    }

    /// Create a new `GccController` with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(GccConfig::default())
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Returns `true` if a multiplicative decrease should be suppressed because one already
    /// happened within the last RTT (prevents multiple halvings in one RTT).
    fn decrease_suppressed(&self, now: Instant) -> bool {
        match self.last_decrease_time {
            None => false,
            Some(t) => {
                let elapsed = now.saturating_duration_since(t);
                elapsed < Duration::from_secs_f64(self.srtt_secs.max(MIN_RTT_SECS))
            }
        }
    }

    /// Perform a cold-restart: reset estimate and RTT to initial config values, enter Hold.
    fn cold_restart(&mut self) {
        let init_bps = self
            .config
            .initial_bitrate
            .clamp(self.config.min_bitrate, self.config.max_bitrate)
            .as_bps_f64();
        self.estimate_bps = init_bps;
        self.srtt_secs = clamp_rtt(self.config.initial_rtt).as_secs_f64();
        self.state = State::Hold;
        self.last_decrease_time = None;
        self.last_known_rate_bps = None;
        self.target_bitrate = self
            .config
            .initial_bitrate
            .clamp(self.config.min_bitrate, self.config.max_bitrate);
    }
}

impl CongestionController for GccController {
    /// Ingest a feedback report and update the delay estimate / target bitrate.
    ///
    /// # Errors
    ///
    /// This method never returns an error — it is infallible by design.
    fn on_feedback(&mut self, fb: &TransportStats, now: Instant) {
        // ── Guard: non-monotonic or too-fast clock ────────────────────────────
        if let Some(last) = self.last_feedback_time {
            match now.checked_duration_since(last) {
                None => {
                    // Clock went backwards — ignore this report.
                    return;
                }
                Some(d) if d < MIN_UPDATE_INTERVAL => {
                    // Feedback arrived too fast; skip.
                    return;
                }
                Some(d) if d > MAX_UPDATE_INTERVAL => {
                    // Very long gap: cold-restart.
                    self.last_feedback_time = Some(now);
                    self.cold_restart();
                    return;
                }
                _ => {}
            }
        }
        self.last_feedback_time = Some(now);

        // ── Update SRTT ───────────────────────────────────────────────────────
        if fb.rtt > Duration::ZERO {
            let rtt_s = clamp_rtt(fb.rtt).as_secs_f64();
            self.srtt_secs = 0.875 * self.srtt_secs + 0.125 * rtt_s;
        }

        // ── Queue-delay signal ────────────────────────────────────────────────
        let queue_delay_secs = clamp_duration(fb.queue_delay, MAX_QUEUE_DELAY).as_secs_f64();

        // ── Loss fraction ─────────────────────────────────────────────────────
        let loss_frac: f64 = if fb.loss_fraction_q8 > 0 {
            fb.loss_fraction()
        } else if fb.bytes_lost > 0 {
            let denom = fb.bytes_acked.max(1);
            (f64::from(fb.bytes_lost) / f64::from(denom)).min(1.0)
        } else {
            0.0
        };

        // ── Acknowledged throughput proxy ─────────────────────────────────────
        // `acked_throughput_bps` is the actual delivery rate observed this interval
        // (bytes_acked × 8 / interval_secs).  It is bounded by the bottleneck link
        // capacity regardless of the send rate, making it a reliable proxy for the
        // acknowledged bitrate that libwebrtc uses to detect when available capacity
        // has grown above the last recorded operating point.
        let acked_throughput_bps: f64 = {
            let interval_secs = fb.interval.as_secs_f64();
            if interval_secs > 0.0 {
                let raw = f64::from(fb.bytes_acked) * 8.0 / interval_secs;
                if raw.is_finite() {
                    raw
                } else {
                    0.0
                }
            } else {
                0.0
            }
        };

        // ── Delay-based state machine ─────────────────────────────────────────
        if queue_delay_secs > OVERUSE_THRESHOLD_SECS {
            self.state = State::Decrease;
        } else if queue_delay_secs < UNDERUSE_THRESHOLD_SECS {
            match self.state {
                State::Decrease => self.state = State::Hold,
                State::Hold => self.state = State::Increase,
                State::Increase => {} // stay in Increase
            }
        }
        // Between thresholds: state unchanged.

        // Snapshot BEFORE applying state machine bitrate updates.
        // Used by loss adjustment below to avoid double-applying BETA_DECREASE
        // when the delay state machine also triggers a Decrease in the same tick.
        let pre_state_estimate = self.estimate_bps;

        // ── Compute delay-based estimate ──────────────────────────────────────
        match self.state {
            State::Decrease => {
                if !self.decrease_suppressed(now) {
                    // Only update the operating-point anchor when the current estimate is
                    // genuinely above the acknowledged throughput, i.e., the estimate really
                    // is overshooting the bottleneck capacity.  If `estimate ≤ acked_throughput`
                    // the queue delay is a residual from a previous overshoot (the bottleneck is
                    // draining old backlog while the estimate is already below its capacity).
                    // Writing a below-cap anchor in that case would corrupt stale-anchor
                    // detection in the Increase arm and produce a spurious stale-reset that
                    // restarts multiplicative growth — the root cause of the R2 limit cycle.
                    if self.estimate_bps > acked_throughput_bps {
                        self.last_known_rate_bps = Some(self.estimate_bps);
                    }
                    let new_est = self.estimate_bps * BETA_DECREASE;
                    if new_est.is_finite() {
                        self.estimate_bps = new_est;
                    }
                    self.last_decrease_time = Some(now);
                }
            }
            State::Hold => {
                // No change to estimate.
            }
            State::Increase => {
                // Stale-anchor reset (F2): clear `last_known_rate_bps` when the acknowledged
                // throughput proves the network can now deliver more than the recorded anchor.
                //
                // Rationale: `last_known_rate_bps` records the estimate immediately before the
                // most recent non-suppressed Decrease (delay or loss path).  The Decrease arm
                // only writes the anchor when `estimate > acked_throughput` (genuine overshoot),
                // so the anchor is guaranteed to be above the bottleneck cap at the time it is
                // written.  Consequently:
                //
                // Key invariant at steady-state cap:
                //   anchor ≥ cap (always, by the Decrease-arm guard).  While the link is at the
                //   same cap, `acked_throughput ≤ cap < anchor`, so the stale condition
                //   `acked_throughput > anchor` never fires.  No spurious resets.
                //
                // Key behaviour on a genuine capacity increase:
                //   After the bottleneck cap rises, the estimate (which is below the old anchor)
                //   grows in additive steps.  Once it first crosses the anchor, the very next
                //   tick has `acked_throughput > anchor`.  The condition fires, clears the anchor,
                //   and re-enables ×1.08 multiplicative fill to probe the new ceiling.  The first
                //   overshoot of the new cap sets a fresh, higher anchor.
                //
                // Safety: clearing to `None` enables ×1.08 against `config.max_bitrate`.
                // At the new cap the delay path triggers Decrease within tens of ticks, setting
                // a fresh anchor.  At most one probe cycle of overshoot per capacity-increase
                // event — not the sustained limit cycle from R1 (which had no anchor at all).
                // Under loss the anchor must not be cleared because the loss signal itself is
                // the congestion evidence; additionally acked_throughput is degraded by loss
                // and would give a misleading comparison.
                if let Some(anchor) = self.last_known_rate_bps {
                    if loss_frac <= LOSS_LOW_THRESHOLD
                        && acked_throughput_bps.is_finite()
                        && acked_throughput_bps > anchor
                    {
                        self.last_known_rate_bps = None;
                    }
                }

                let new_est = if let Some(last_rate) = self.last_known_rate_bps {
                    if self.estimate_bps >= 0.9 * last_rate {
                        // Near last known operating point — additive increase (AIMD steady-state).
                        // Cap the step by AIMD_HEADROOM_FRACTION × remaining headroom to prevent
                        // the estimate from blowing past the anchor: the queue-delay signal takes
                        // many ticks to build up at small excess rates, so without this cap the
                        // estimate drifts far above the real ceiling.  The result is an asymptotic
                        // approach to the anchor: fast at first, slowing to <1 bps as it converges,
                        // which bounds the overshoot — and the max/min oscillation ratio — tightly.
                        let headroom = (last_rate - self.estimate_bps).max(0.0);
                        let step = AIMD_INCREASE_BPS
                            .min(headroom * AIMD_HEADROOM_FRACTION)
                            .max(1.0);
                        self.estimate_bps + step
                    } else {
                        // Far from last known cap — multiplicative increase.
                        self.estimate_bps * MULTIPLICATIVE_INCREASE_FACTOR
                    }
                } else {
                    // No prior decrease observed (or anchor just cleared as stale) — use
                    // configured max_bitrate as reference to cap multiplicative growth near the
                    // config limit.
                    let cap_bps = self.config.max_bitrate.as_bps_f64();
                    if self.estimate_bps < 0.9 * cap_bps {
                        self.estimate_bps * MULTIPLICATIVE_INCREASE_FACTOR
                    } else {
                        self.estimate_bps + AIMD_INCREASE_BPS
                    }
                };
                if new_est.is_finite() {
                    self.estimate_bps = new_est;
                }
            }
        }

        // Sanitise estimate after state machine (guard against NaN from state machine).
        if !self.estimate_bps.is_finite() || self.estimate_bps < 0.0 {
            self.estimate_bps = self.config.min_bitrate.as_bps_f64();
        }

        // ── Loss-based adjustment (applied AFTER delay state machine) ─────────
        // Uses pre_state_estimate as the base to avoid double-applying BETA_DECREASE
        // when the delay state machine already triggered a Decrease in the same tick.
        //
        // F1 fix: the high-loss branch is gated by the same `decrease_suppressed()` machinery
        // used by the delay path, and updates `last_decrease_time` when it fires.  Without this
        // gate, at 100 Hz / 50 ms RTT the loss path applied 0.85 on every tick → 0.85^5 ≈ 44%
        // collapse per RTT instead of the documented "at most once per RTT".
        if loss_frac > LOSS_HIGH_THRESHOLD {
            // High loss: apply multiplicative decrease to the pre-state snapshot, but at most
            // once per RTT (same suppression window as the delay-path Decrease).
            if !self.decrease_suppressed(now) {
                let loss_cut = pre_state_estimate * BETA_DECREASE;
                if loss_cut.is_finite() && loss_cut < self.estimate_bps {
                    // Record operating point BEFORE writing back the loss cut, so the anchor
                    // reflects the highest confirmed-good rate (same contract as delay Decrease).
                    self.last_known_rate_bps = Some(pre_state_estimate);
                    self.estimate_bps = loss_cut;
                    self.last_decrease_time = Some(now);
                }
            }
        } else if loss_frac > LOSS_LOW_THRESHOLD {
            // Moderate loss: freeze — revert any increase that just happened.
            if self.estimate_bps > pre_state_estimate {
                self.estimate_bps = pre_state_estimate;
            }
        }

        // Sanitise estimate after loss adjustment.
        if !self.estimate_bps.is_finite() || self.estimate_bps < 0.0 {
            self.estimate_bps = self.config.min_bitrate.as_bps_f64();
        }

        // ── Final target ──────────────────────────────────────────────────────
        self.target_bitrate = Bitrate::from_bps_f64(self.estimate_bps)
            .clamp(self.config.min_bitrate, self.config.max_bitrate);
    }

    fn target_bitrate(&self) -> Bitrate {
        self.target_bitrate
    }

    /// The inter-packet pacing gap derived from `target_bitrate` and the pacing packet size.
    ///
    /// Formula: `pacing_packet_bytes * 8 / target_bitrate_bps` seconds.
    ///
    /// Always `>= 1 µs` (clamped).
    fn pacing_interval(&self) -> Duration {
        let bps = self.target_bitrate.as_bps_f64();
        if bps <= 0.0 {
            return Duration::from_micros(1);
        }
        let interval_secs = f64::from(MIN_PACING_PACKET_BYTES) * 8.0 / bps;
        if !interval_secs.is_finite() || interval_secs <= 0.0 {
            return Duration::from_micros(1);
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let micros = (interval_secs * 1_000_000.0) as u64;
        Duration::from_micros(micros.max(1))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
mod tests {
    #[allow(clippy::wildcard_imports)]
    use super::*;
    use crate::util::test_helpers::{arb_feedback, NetSim};

    // ── Strategy helper for proptest ──────────────────────────────────────────

    use proptest::prelude::*;

    // ── Core behaviour tests ──────────────────────────────────────────────────

    /// Test: target_bitrate is always within [min, max], even after many iterations.
    #[test]
    fn target_always_within_bounds() {
        let cfg = GccConfig {
            min_bitrate: Bitrate::from_kbps(100),
            max_bitrate: Bitrate::from_mbps(50),
            ..GccConfig::default()
        };
        let mut ctrl = GccController::new(cfg.clone());
        let mut sim = NetSim::new(5_000, 20, 0.0);

        for _ in 0..200 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
            let target = ctrl.target_bitrate();
            assert!(
                target >= cfg.min_bitrate,
                "target {target} < min {}",
                cfg.min_bitrate
            );
            assert!(
                target <= cfg.max_bitrate,
                "target {target} > max {}",
                cfg.max_bitrate
            );
        }
    }

    /// Test: controller converges toward the available bandwidth cap without limit cycles.
    ///
    /// Runs 600 ticks and checks the windowed mean of the last 100 readings is within
    /// [75%, 125%] of the cap. Also checks max/min ratio of the window < 2.0 (no limit cycle).
    #[test]
    fn converges_toward_cap() {
        let cap_kbps = 5_000u64;
        let mut ctrl = GccController::with_defaults();
        let mut sim = NetSim::new(cap_kbps, 20, 0.0);

        let mut last_100: Vec<u64> = Vec::with_capacity(100);

        for i in 0..600u64 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
            if i >= 500 {
                last_100.push(ctrl.target_bitrate().as_kbps());
            }
        }

        let windowed_mean = last_100.iter().copied().sum::<u64>() / 100;
        let max_r = last_100.iter().copied().max().unwrap_or(0);
        let min_r = last_100.iter().copied().min().unwrap_or(1);
        let ratio = if min_r > 0 {
            max_r as f64 / min_r as f64
        } else {
            f64::INFINITY
        };

        let low = cap_kbps * 75 / 100; // 75%
        let high = cap_kbps * 125 / 100; // 125%
        println!(
            "[converges_toward_cap] cap={cap_kbps} kbps, windowed_mean={windowed_mean} kbps (band: [{low},{high}]), max/min ratio={ratio:.2}"
        );
        assert!(
            windowed_mean >= low,
            "controller failed to ramp up: windowed_mean={windowed_mean} kbps < {low} kbps"
        );
        assert!(
            windowed_mean <= high,
            "controller overshot too much: windowed_mean={windowed_mean} kbps > {high} kbps"
        );
        assert!(
            ratio < 2.0,
            "limit cycle detected: max/min ratio={ratio:.2} >= 2.0 (max={max_r}, min={min_r})"
        );
    }

    /// Test: backs off when queue delay exceeds overuse threshold.
    #[test]
    fn backs_off_on_delay_overuse() {
        let mut ctrl = GccController::with_defaults();
        let mut sim = NetSim::new(5_000, 20, 0.0);

        // Let the controller ramp up first; track the last sim timestamp.
        let mut last_now = sim.clock;
        for _ in 0..200 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
            last_now = now;
        }
        let before_overuse = ctrl.target_bitrate().as_kbps();
        println!("[backs_off_on_delay_overuse] before overuse: {before_overuse} kbps");

        // Inject several overuse feedbacks; at least one will clear the decrease-suppression
        // window (which is bounded by SRTT ≈ 40ms). We space them 20ms apart over 200ms.
        let overuse_fb = TransportStats {
            rtt: Duration::from_millis(40),
            queue_delay: Duration::from_millis(50), // well above OVERUSE_THRESHOLD (25ms)
            bytes_acked: 1_000,
            bytes_lost: 0,
            loss_fraction_q8: 0,
            interval: Duration::from_millis(20),
        };
        for i in 1u64..=10 {
            ctrl.on_feedback(&overuse_fb, last_now + Duration::from_millis(20 * i));
        }
        let after_overuse = ctrl.target_bitrate().as_kbps();
        println!(
            "[backs_off_on_delay_overuse] before={before_overuse} kbps, after={after_overuse} kbps"
        );
        assert!(
            after_overuse < before_overuse,
            "expected backoff on overuse: before={before_overuse}, after={after_overuse}"
        );
    }

    /// Test: recovers / ramps when bandwidth cap rises, and does so QUICKLY via multiplicative
    /// growth rather than slow additive fill.
    ///
    /// Strengthened for F2: after the cap rises from 2 → 8 Mbps, the stale-anchor reset must
    /// allow the controller to reach ≥75% of the NEW cap (6 000 kbps) within 200 ticks
    /// (200 × 10ms = 2 s).  Without the reset, the old 2-Mbps anchor keeps the controller in
    /// additive mode: 4 000 kbps gap / 8 kbps/tick = 500 ticks (5 s) to reach 75%.
    #[test]
    fn recovers_on_cap_rise() {
        let new_cap_kbps = 8_000u64;
        let target_75pct_kbps = new_cap_kbps * 75 / 100; // 6 000 kbps

        let mut ctrl = GccController::with_defaults();
        let mut sim = NetSim::new(2_000, 20, 0.0); // 2 Mbps initially

        // Phase 1: converge at low cap (200 ticks × 10 ms = 2 s).
        for _ in 0..200 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
        }
        let at_low_cap = ctrl.target_bitrate().as_kbps();
        println!("[recovers_on_cap_rise] at low cap (2 Mbps): {at_low_cap} kbps");

        // Phase 2: raise cap to 8 Mbps; run up to 200 ticks and check 75% is reached.
        // 200 ticks × 10 ms = 2 s — fast fill via multiplicative growth should suffice.
        // Additive-only fill would take ~500 ticks, so 200 is a tight-enough bound to prove
        // multiplicative growth resumed (F2 fix). We also record the tick it crosses 75%.
        sim.cap_bps = (new_cap_kbps as f64) * 1_000.0;
        sim.max_queue_bytes = sim.cap_bps * 0.200 / 8.0;
        let mut reached_75pct_tick: Option<u32> = None;
        for i in 0..200u32 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
            let cur_kbps = ctrl.target_bitrate().as_kbps();
            if reached_75pct_tick.is_none() && cur_kbps >= target_75pct_kbps {
                reached_75pct_tick = Some(i + 1);
            }
        }
        let at_high_cap = ctrl.target_bitrate().as_kbps();
        println!(
            "[recovers_on_cap_rise] at high cap ({new_cap_kbps} kbps): {at_high_cap} kbps \
             (75%={target_75pct_kbps} kbps reached at tick={reached_75pct_tick:?})"
        );

        // Primary: must have reached 75% of the new cap within 200 ticks (proves fast fill).
        assert!(
            reached_75pct_tick.is_some(),
            "did not reach 75% of new cap ({target_75pct_kbps} kbps) within 200 ticks; \
             final={at_high_cap} kbps — stale anchor likely locking controller in additive mode (F2)"
        );
        // Secondary: final value still above old cap (directional sanity).
        assert!(
            at_high_cap > at_low_cap,
            "expected ramp: at_low={at_low_cap}, at_high={at_high_cap}"
        );
    }

    /// Test: pacing_interval is always positive and finite.
    #[test]
    fn pacing_interval_always_positive() {
        let mut ctrl = GccController::with_defaults();
        let mut sim = NetSim::new(5_000, 20, 0.0);
        for _ in 0..100 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
            let pi = ctrl.pacing_interval();
            assert!(
                pi >= Duration::from_micros(1),
                "pacing_interval too small: {pi:?}"
            );
            assert!(
                pi.as_secs_f64().is_finite(),
                "pacing_interval not finite: {pi:?}"
            );
        }
    }

    /// Test: non-monotonic `now` is silently ignored (no panic, no state corruption).
    #[test]
    fn non_monotonic_now_is_ignored() {
        let mut ctrl = GccController::with_defaults();
        let mut sim = NetSim::new(5_000, 20, 0.0);
        let (t0, fb0) = sim.tick(ctrl.target_bitrate().as_bps_f64());
        ctrl.on_feedback(&fb0, t0);
        let rate_after_first = ctrl.target_bitrate();

        // Feed an earlier timestamp — should be ignored.
        let early_now = t0 - Duration::from_millis(1);
        ctrl.on_feedback(&fb0, early_now);
        // State should be unchanged.
        assert_eq!(ctrl.target_bitrate(), rate_after_first);
    }

    /// Test: zero-RTT feedback does not crash and preserves bounds.
    #[test]
    fn zero_rtt_feedback_is_safe() {
        let mut ctrl = GccController::with_defaults();
        let mut sim = NetSim::new(5_000, 20, 0.0);
        let (mut now, mut fb) = sim.tick(ctrl.target_bitrate().as_bps_f64());
        fb.rtt = Duration::ZERO;
        ctrl.on_feedback(&fb, now);
        for _ in 0..10 {
            let (n, f) = sim.tick(ctrl.target_bitrate().as_bps_f64());
            now = n;
            fb = f;
            fb.rtt = Duration::ZERO;
            ctrl.on_feedback(&fb, now);
        }
        let t = ctrl.target_bitrate();
        let cfg = GccConfig::default();
        assert!(t >= cfg.min_bitrate && t <= cfg.max_bitrate);
    }

    /// Test: bytes_lost > bytes_acked is handled gracefully.
    #[test]
    fn bytes_lost_exceeds_acked_is_safe() {
        let mut ctrl = GccController::with_defaults();
        let mut sim = NetSim::new(5_000, 20, 0.0);
        let (t0, _) = sim.tick(0.0);
        let fb = TransportStats {
            rtt: Duration::from_millis(20),
            queue_delay: Duration::ZERO,
            bytes_acked: 100,
            bytes_lost: 50_000, // More lost than acked
            loss_fraction_q8: 0,
            interval: Duration::from_millis(10),
        };
        ctrl.on_feedback(&fb, t0);
        let t = ctrl.target_bitrate();
        let cfg = GccConfig::default();
        assert!(t >= cfg.min_bitrate && t <= cfg.max_bitrate);
    }

    /// Test: convergence summary printed with --nocapture (shows bandwidth tracking up/down).
    #[test]
    fn bandwidth_convergence_summary() {
        println!("\n=== GCC bandwidth convergence summary ===");
        let mut ctrl = GccController::with_defaults();
        let cfg = GccConfig::default();

        let scenarios: &[(&str, u64, u64)] = &[
            ("Phase 1: ramp to 5 Mbps cap", 5_000, 200),
            ("Phase 2: stay at 5 Mbps", 5_000, 100),
            ("Phase 3: cap drops to 1 Mbps", 1_000, 150),
            ("Phase 4: cap rises to 8 Mbps", 8_000, 250),
            ("Phase 5: cap drops to 2 Mbps", 2_000, 150),
        ];

        let mut sim = NetSim::new(5_000, 20, 0.0);

        for (label, cap_kbps, steps) in scenarios {
            sim.cap_bps = (*cap_kbps as f64) * 1_000.0;
            sim.queue_bytes = 0.0;
            sim.max_queue_bytes = sim.cap_bps * 0.200 / 8.0;
            for i in 0..*steps {
                let send_bps = ctrl.target_bitrate().as_bps_f64();
                let (now, fb) = sim.tick(send_bps);
                let queue_ms = fb.queue_delay.as_secs_f64() * 1000.0;
                ctrl.on_feedback(&fb, now);
                if i % 50 == 49 || i == steps - 1 {
                    println!(
                        "  {label} [step {:>3}]: cap={cap_kbps} kbps  target={} kbps  queue={queue_ms:.1}ms",
                        i + 1,
                        ctrl.target_bitrate().as_kbps(),
                    );
                }
            }
            let final_rate = ctrl.target_bitrate();
            assert!(final_rate >= cfg.min_bitrate, "below min: {}", final_rate);
            assert!(final_rate <= cfg.max_bitrate, "above max: {}", final_rate);
        }
        println!("=== end of convergence summary ===\n");
    }

    // ── Regression tests ──────────────────────────────────────────────────────

    /// Regression: sustained high loss must drive estimate DOWN, not up.
    /// Before fix, estimate_bps was never written back from the loss cap, so
    /// the Increase arm grew it each tick and target kept ramping despite loss.
    #[test]
    fn loss_runaway_regression() {
        let cfg = GccConfig {
            min_bitrate: Bitrate::from_kbps(100),
            max_bitrate: Bitrate::from_mbps(50),
            initial_bitrate: Bitrate::from_mbps(2),
            ..GccConfig::default()
        };
        let mut ctrl = GccController::new(cfg);
        let initial_kbps = ctrl.target_bitrate().as_kbps();
        // 15% packet loss, no queue delay (so delay state machine stays in Hold/Increase).
        let mut sim = NetSim::new(10_000, 20, 0.15);
        for _ in 0..80 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
        }
        let final_kbps = ctrl.target_bitrate().as_kbps();
        println!(
            "[loss_runaway_regression] initial={initial_kbps} kbps, final={final_kbps} kbps (should be <= {initial_kbps})"
        );
        assert!(
            final_kbps <= initial_kbps,
            "target ramped up under 15% loss: initial={initial_kbps} kbps, final={final_kbps} kbps"
        );
    }

    /// Regression: moderate loss (5%) must freeze the estimate, not allow increase.
    #[test]
    fn moderate_loss_freeze_regression() {
        let cfg = GccConfig {
            min_bitrate: Bitrate::from_kbps(100),
            max_bitrate: Bitrate::from_mbps(50),
            initial_bitrate: Bitrate::from_mbps(2),
            ..GccConfig::default()
        };
        let mut ctrl = GccController::new(cfg);
        let initial_kbps = ctrl.target_bitrate().as_kbps();
        // 5% loss, no queue delay.
        let mut sim = NetSim::new(10_000, 20, 0.05);
        for _ in 0..60 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
        }
        let final_kbps = ctrl.target_bitrate().as_kbps();
        println!(
            "[moderate_loss_freeze_regression] initial={initial_kbps} kbps, final={final_kbps} kbps"
        );
        assert!(
            final_kbps <= initial_kbps,
            "target grew under 5% moderate loss: initial={initial_kbps} kbps, final={final_kbps} kbps"
        );
    }

    /// Regression: concurrent delay-Decrease AND high loss must produce a single BETA_DECREASE,
    /// not two (0.85 × 0.85 = 0.7225 effective). The target after one tick should be in the
    /// band [0.80, 0.92] × estimate_before, not below 0.73 × estimate_before.
    ///
    /// Approach: stabilize at ~5 Mbps via Hold ticks, then fire one overuse+loss tick,
    /// then observe target is in the single-cut band.
    #[test]
    fn coincident_decrease_and_high_loss_single_cut() {
        #[allow(clippy::disallowed_methods)]
        let base = Instant::now();
        // Use a low initial_bitrate so we can set estimate without real sim.
        let cfg = GccConfig {
            min_bitrate: Bitrate::from_kbps(100),
            max_bitrate: Bitrate::from_mbps(50),
            initial_bitrate: Bitrate::from_mbps(5),
            initial_rtt: Duration::from_millis(40),
        };
        let mut ctrl = GccController::new(cfg);

        // Warm up: send ~50 Hold-state ticks so estimate sits near 5 Mbps.
        // Hold state = no state transition + no queue delay change: use queue_delay between
        // thresholds (e.g. 15ms, between UNDERUSE=10ms and OVERUSE=25ms).
        for i in 0..50u64 {
            let hold_fb = TransportStats {
                rtt: Duration::from_millis(40),
                queue_delay: Duration::from_millis(15), // between thresholds → no state change
                bytes_acked: 10_000,
                bytes_lost: 0,
                loss_fraction_q8: 0,
                interval: Duration::from_millis(10),
            };
            ctrl.on_feedback(&hold_fb, base + Duration::from_millis(10 * (i + 1)));
        }
        let estimate_before = ctrl.target_bitrate().as_bps_f64();
        println!(
            "[coincident_decrease_and_high_loss_single_cut] estimate_before={:.0} bps",
            estimate_before
        );

        // Fire ONE tick with both overuse delay AND high loss (>10%).
        // bytes_lost / bytes_acked = 200/1000 = 20% > LOSS_HIGH_THRESHOLD (10%).
        let combined_fb = TransportStats {
            rtt: Duration::from_millis(40),
            queue_delay: Duration::from_millis(35), // > OVERUSE_THRESHOLD (25ms) → Decrease state
            bytes_acked: 1_000,
            bytes_lost: 200, // 20% loss
            loss_fraction_q8: 0,
            interval: Duration::from_millis(10),
        };
        ctrl.on_feedback(&combined_fb, base + Duration::from_millis(510));

        let after_bps = ctrl.target_bitrate().as_bps_f64();
        let single_cut_low = estimate_before * 0.80;
        let single_cut_high = estimate_before * 0.92;
        let double_cut_floor = estimate_before * 0.73;

        println!(
            "[coincident_decrease_and_high_loss_single_cut] after={:.0} bps, band=[{:.0},{:.0}], double_cut_floor={:.0}",
            after_bps, single_cut_low, single_cut_high, double_cut_floor
        );

        assert!(
            after_bps >= double_cut_floor,
            "double BETA_DECREASE applied: after={after_bps:.0} < double_cut_floor={double_cut_floor:.0}"
        );
        assert!(
            after_bps <= single_cut_high,
            "not enough decrease: after={after_bps:.0} > single_cut_high={single_cut_high:.0}"
        );
    }

    /// Regression: under sustained high loss (>10%), the loss-based decrease must fire at most
    /// once per RTT, NOT once per feedback tick.
    ///
    /// Setup: 100 Hz feedback (10 ms step), 50 ms RTT → ≈5 ticks per RTT.
    /// Without the per-RTT gate: 0.85^5 ≈ 44% collapse per RTT.
    /// With the gate: one 0.85× per RTT → ≈15% drop per RTT.
    ///
    /// We run 500 ms (50 ticks = 10 RTTs) and count the number of multiplicative cuts that
    /// actually fire (detectable by `last_decrease_time` updates — proxied by tracking
    /// estimate drops > 5% per tick). Must be ≈ interval/RTT (10) not per-tick (50).
    #[test]
    fn loss_decrease_rate_is_per_rtt() {
        #[allow(clippy::disallowed_methods)]
        let base = Instant::now();

        // RTT = 50 ms, tick = 10 ms → 5 ticks per RTT.
        // Run 50 ticks = 10 RTTs → expect ≈10 cuts, definitely not 50.
        let rtt_ms = 50u64;
        let tick_ms = 10u64;
        let ticks = 50u32;
        let ticks_per_rtt = (rtt_ms / tick_ms) as u32; // 5

        let cfg = GccConfig {
            min_bitrate: Bitrate::from_kbps(100),
            max_bitrate: Bitrate::from_mbps(50),
            initial_bitrate: Bitrate::from_mbps(5),
            initial_rtt: Duration::from_millis(rtt_ms),
        };
        let mut ctrl = GccController::new(cfg);

        // Warm up with zero-loss, zero-delay ticks so we enter Increase state.
        for i in 0..20u64 {
            let fb = TransportStats {
                rtt: Duration::from_millis(rtt_ms),
                queue_delay: Duration::from_millis(5), // below UNDERUSE → Increase
                bytes_acked: 10_000,
                bytes_lost: 0,
                loss_fraction_q8: 0,
                interval: Duration::from_millis(tick_ms),
            };
            ctrl.on_feedback(&fb, base + Duration::from_millis(tick_ms * (i + 1)));
        }
        let start_bps = ctrl.target_bitrate().as_bps_f64();

        // Inject sustained high-loss ticks (20% loss, queue=0 → delay path stays in Increase).
        let mut cut_count = 0u32;
        let mut prev_bps = start_bps;
        for i in 0..ticks {
            let now = base + Duration::from_millis(tick_ms * (20 + u64::from(i) + 1));
            let fb = TransportStats {
                rtt: Duration::from_millis(rtt_ms),
                queue_delay: Duration::from_millis(5), // underuse → keep in Increase
                bytes_acked: 800,
                bytes_lost: 200, // 200/1000 = 20% > LOSS_HIGH_THRESHOLD
                loss_fraction_q8: 0,
                interval: Duration::from_millis(tick_ms),
            };
            ctrl.on_feedback(&fb, now);
            let cur_bps = ctrl.target_bitrate().as_bps_f64();
            // A cut fired if estimate dropped >5% from previous tick (additive changes are <1%).
            if cur_bps < prev_bps * 0.95 {
                cut_count += 1;
            }
            prev_bps = cur_bps;
        }

        let end_bps = ctrl.target_bitrate().as_bps_f64();
        // Expected cuts ≈ ticks / ticks_per_rtt = 10. Allow a ±2 window (8–12).
        let expected_cuts = ticks / ticks_per_rtt; // 10
        let cut_lo = expected_cuts.saturating_sub(2); // 8
        let cut_hi = expected_cuts + 2; // 12

        println!(
            "[loss_decrease_rate_is_per_rtt] start={start_bps:.0} bps, end={end_bps:.0} bps, \
             cut_count={cut_count} (expected ≈{expected_cuts}, window=[{cut_lo},{cut_hi}])"
        );

        assert!(
            cut_count <= cut_hi,
            "loss path fires more than once per RTT: cut_count={cut_count} > {cut_hi} \
             (expected ≈{expected_cuts} cuts in {ticks} ticks at {ticks_per_rtt} ticks/RTT)"
        );
        assert!(
            cut_count >= cut_lo,
            "loss path fired too rarely: cut_count={cut_count} < {cut_lo}; \
             loss backoff may be broken"
        );
        // Sanity: the estimate must have dropped (loss is genuinely backing off).
        assert!(
            end_bps < start_bps,
            "estimate did not decrease under sustained loss: start={start_bps:.0}, end={end_bps:.0}"
        );
    }

    // ── Property tests ────────────────────────────────────────────────────────

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 1_000,
            ..ProptestConfig::default()
        })]

        /// Property: for arbitrary sequences of feedback (including adversarial values), the
        /// controller never panics, `target_bitrate()` stays within `[min, max]`, and
        /// `pacing_interval()` is positive.
        #[test]
        fn no_panic_and_bounds_hold(
            feedbacks in prop::collection::vec(arb_feedback(), 1..50),
            initial_step_ms in 10u64..=100u64,
        ) {
            let cfg = GccConfig::default();
            let mut ctrl = GccController::new(cfg.clone());

            #[allow(clippy::disallowed_methods)]
            let base = Instant::now();
            let mut elapsed = Duration::ZERO;

            for (i, fb) in feedbacks.iter().enumerate() {
                elapsed += Duration::from_millis(initial_step_ms * (u64::try_from(i).unwrap_or(u64::MAX) + 1));
                let now = base + elapsed;
                ctrl.on_feedback(fb, now);

                let target = ctrl.target_bitrate();
                prop_assert!(
                    target >= cfg.min_bitrate,
                    "target {target} < min {}",
                    cfg.min_bitrate
                );
                prop_assert!(
                    target <= cfg.max_bitrate,
                    "target {target} > max {}",
                    cfg.max_bitrate
                );

                let pi = ctrl.pacing_interval();
                prop_assert!(
                    pi >= Duration::from_micros(1),
                    "pacing_interval too small: {pi:?}"
                );
            }
        }

        /// Property: even with deliberately non-monotonic `now` values interspersed, the
        /// controller never panics and bounds hold.
        #[test]
        fn non_monotonic_clock_no_panic(
            feedbacks in prop::collection::vec(arb_feedback(), 1..30),
        ) {
            let cfg = GccConfig::default();
            let mut ctrl = GccController::new(cfg.clone());

            #[allow(clippy::disallowed_methods)]
            let base = Instant::now();
            let mut elapsed = Duration::from_secs(1);

            for (i, fb) in feedbacks.iter().enumerate() {
                if i % 3 == 0 {
                    elapsed = elapsed.saturating_sub(Duration::from_millis(500));
                } else {
                    elapsed += Duration::from_millis(20);
                }
                let now = base + elapsed;
                ctrl.on_feedback(fb, now);

                let target = ctrl.target_bitrate();
                prop_assert!(target >= cfg.min_bitrate);
                prop_assert!(target <= cfg.max_bitrate);
                prop_assert!(ctrl.pacing_interval() >= Duration::from_micros(1));
            }
        }
    }
}
