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
//!    - **Increase**: multiplicative (`×1.08`) when far from cap; additive (`+8 kbps`) near cap.
//!
//! 3. **Loss-based cap** — if loss fraction > 10%: apply `BETA_DECREASE`; else no extra cap.
//!
//! 4. **Final target** — `min(delay_estimate, loss_cap).clamp(min, max)`.
//!
//! ## Deviations from libwebrtc / RFC drafts
//!
//! 1. **OWD proxy**: uses `TransportStats::queue_delay` as a one-way-delay gradient proxy.
//!    Real GCC computes the inter-arrival gradient via a Kalman/trendline filter on per-packet
//!    arrival timestamps (TWCC). Deferred to P5 when TWCC feedback arrives from browsers.
//!
//! 2. **Simplified state transitions**: real GCC has hysteresis counters before transitioning
//!    `Hold → Increase` and `Increase → Decrease`. This implementation uses single-measurement
//!    thresholds, making the controller more reactive but easier to reason about.
//!
//! 3. **Single estimate**: real GCC maintains a separate bandwidth estimator (BWE) with its own
//!    exponential moving average, and merges it with the delay estimate via `min`. We use a single
//!    `estimate_bps` that serves both roles.
//!
//! 4. **AIMD constants**: chosen to match libwebrtc's general shape (8 kbps additive increase,
//!    0.85 multiplicative decrease, ×1.08 multiplicative growth), but not bit-for-bit identical.

use std::time::{Duration, Instant};

use crate::{Bitrate, CongestionController, TransportStats};

// ── Internal constants ────────────────────────────────────────────────────────

/// Minimum plausible RTT. Sub-100 µs RTT is a measurement artefact; clamp up to this.
const MIN_RTT: Duration = Duration::from_micros(100);

/// Maximum RTT we trust. Above this the link is either very congested or the measurement is wrong.
const MAX_RTT: Duration = Duration::from_secs(10);

/// Maximum queue delay we trust from the transport layer.
const MAX_QUEUE_DELAY: Duration = Duration::from_secs(2);

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

/// Minimum RTT in seconds. Used as floor for the decrease-suppression window.
const MIN_RTT_SECS: f64 = 0.000_100;

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

/// Additive bitrate increase per feedback step when near the cap (AIMD steady-state).
///
/// libwebrtc additive increase is ~8 kbps per interval. Stored as bits per second.
const AIMD_INCREASE_BPS: f64 = 8_000.0;

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

        // ── Compute delay-based estimate ──────────────────────────────────────
        match self.state {
            State::Decrease => {
                if !self.decrease_suppressed(now) {
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
                let cap_bps = self.config.max_bitrate.as_bps_f64();
                let new_est = if self.estimate_bps < 0.9 * cap_bps {
                    // Multiplicative increase: far from cap.
                    self.estimate_bps * MULTIPLICATIVE_INCREASE_FACTOR
                } else {
                    // Additive increase: near cap.
                    self.estimate_bps + AIMD_INCREASE_BPS
                };
                if new_est.is_finite() {
                    self.estimate_bps = new_est;
                }
            }
        }

        // Sanitise estimate.
        if !self.estimate_bps.is_finite() || self.estimate_bps < 0.0 {
            self.estimate_bps = self.config.min_bitrate.as_bps_f64();
        }

        // ── Loss-based cap ────────────────────────────────────────────────────
        // High loss only caps (multiplies); it does not independently increase.
        let loss_est_bps = if loss_frac > LOSS_HIGH_THRESHOLD {
            self.estimate_bps * BETA_DECREASE
        } else if loss_frac > LOSS_LOW_THRESHOLD {
            // Loss is non-trivial but below high threshold: freeze (no increase).
            // We represent this as equal to the current estimate (no growth).
            self.estimate_bps
        } else {
            self.estimate_bps
        };

        // ── Final target ──────────────────────────────────────────────────────
        let raw_bps = if loss_frac > LOSS_HIGH_THRESHOLD {
            self.estimate_bps.min(loss_est_bps)
        } else {
            self.estimate_bps
        };

        let clamped_bps = if raw_bps.is_finite() && raw_bps >= 0.0 {
            raw_bps
        } else {
            self.config.min_bitrate.as_bps_f64()
        };

        self.target_bitrate = Bitrate::from_bps_f64(clamped_bps)
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

// ── Free helpers ──────────────────────────────────────────────────────────────

/// Clamp an RTT to `[MIN_RTT, MAX_RTT]`.
#[inline]
fn clamp_rtt(rtt: Duration) -> Duration {
    if rtt < MIN_RTT {
        MIN_RTT
    } else if rtt > MAX_RTT {
        MAX_RTT
    } else {
        rtt
    }
}

/// Clamp a `Duration` to `[Duration::ZERO, max]`.
#[inline]
fn clamp_duration(d: Duration, max: Duration) -> Duration {
    if d > max {
        max
    } else {
        d
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

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// A network simulator with an accumulating bottleneck queue model.
    ///
    /// Tracks a virtual queue in bytes that fills when send rate exceeds the link capacity and
    /// drains at line rate. Queue delay is computed as queue_bytes / drain_rate. Tail-drop
    /// occurs when the queue exceeds `max_queue_bytes` (≈200 ms of buffering at cap).
    struct NetSim {
        /// Available bandwidth (bits per second).
        cap_bps: f64,
        /// Fixed propagation delay (one-way); RTT = 2 × prop_delay.
        prop_delay: Duration,
        /// Fractional packet loss rate (0.0 = no loss, 1.0 = 100% loss).
        loss_rate: f64,
        /// Synthetic clock: monotonically incremented.
        clock: Instant,
        /// Clock step per simulated feedback interval.
        step: Duration,
        /// Accumulated bottleneck queue in bytes.
        queue_bytes: f64,
        /// Maximum buffer before tail-drop (bytes). At cap, ≈200 ms of buffering.
        max_queue_bytes: f64,
    }

    impl NetSim {
        fn new(cap_kbps: u64, prop_delay_ms: u64, loss_rate: f64) -> Self {
            // Instant::now() is allowed in tests; the controller itself never calls it.
            #[allow(clippy::disallowed_methods)]
            let clock = Instant::now();
            let cap_bps = f64::from(u32::try_from(cap_kbps).unwrap_or(u32::MAX)) * 1_000.0;
            let max_queue_bytes = cap_bps * 0.200 / 8.0;
            Self {
                cap_bps,
                prop_delay: Duration::from_millis(prop_delay_ms),
                loss_rate: loss_rate.clamp(0.0, 1.0),
                clock,
                step: Duration::from_millis(10),
                queue_bytes: 0.0,
                max_queue_bytes,
            }
        }

        /// Advance time by one step and return a `TransportStats` for the current state.
        fn tick(&mut self, send_rate_bps: f64) -> (Instant, TransportStats) {
            self.clock += self.step;
            let step_secs = self.step.as_secs_f64();
            let rtt = self.prop_delay.saturating_mul(2);

            let ingress = (send_rate_bps * step_secs / 8.0).max(0.0);
            let egress = (self.cap_bps * step_secs / 8.0).max(0.0);

            self.queue_bytes = (self.queue_bytes + ingress - egress).max(0.0);
            self.queue_bytes = self.queue_bytes.min(self.max_queue_bytes);

            let queue_delay_secs = if self.cap_bps > 0.0 {
                (self.queue_bytes * 8.0 / self.cap_bps).min(MAX_QUEUE_DELAY.as_secs_f64())
            } else {
                MAX_QUEUE_DELAY.as_secs_f64()
            };

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let bytes_acked = (egress * (1.0 - self.loss_rate)) as u32;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let bytes_lost = (egress * self.loss_rate) as u32;

            let fb = TransportStats {
                rtt,
                queue_delay: Duration::from_secs_f64(queue_delay_secs),
                bytes_acked,
                bytes_lost,
                loss_fraction_q8: 0,
                interval: self.step,
            };
            (self.clock, fb)
        }
    }

    // ── Strategy helper for proptest ──────────────────────────────────────────

    use proptest::prelude::*;

    /// Strategy: generate arbitrary (bounded) `TransportStats` values, including adversarial ones.
    fn arb_feedback() -> impl Strategy<Value = TransportStats> {
        (
            0u64..=10_000_000u64, // rtt_us: 0 to 10 s in µs
            0u64..=2_000_000u64,  // queue_delay_us: 0 to 2 s in µs
            0u32..=1_000_000u32,  // bytes_acked
            0u32..=2_000_000u32,  // bytes_lost (may exceed bytes_acked)
            0u8..=255u8,          // loss_fraction_q8
            1u64..=100u64,        // interval_ms
        )
            .prop_map(
                |(rtt_us, queue_us, bytes_acked, bytes_lost, loss_q8, interval_ms)| {
                    TransportStats {
                        rtt: Duration::from_micros(rtt_us),
                        queue_delay: Duration::from_micros(queue_us),
                        bytes_acked,
                        bytes_lost,
                        loss_fraction_q8: loss_q8,
                        interval: Duration::from_millis(interval_ms),
                    }
                },
            )
    }

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

    /// Test: controller converges toward the available bandwidth cap.
    ///
    /// After enough steps, target_bitrate should be within [80%, 120%] of the cap.
    /// GCC warms up differently from SCReAM (no slow-start), so we use a wider band.
    #[test]
    fn converges_toward_cap() {
        let cap_kbps = 5_000u64;
        let mut ctrl = GccController::with_defaults();
        let mut sim = NetSim::new(cap_kbps, 20, 0.0);

        for _ in 0..500 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
        }

        let final_kbps = ctrl.target_bitrate().as_kbps();
        let low = cap_kbps * 80 / 100; // 80%
        let high = cap_kbps * 120 / 100; // 120%
        println!(
            "[converges_toward_cap] cap={cap_kbps} kbps, final={final_kbps} kbps  (band: [{low},{high}])"
        );
        assert!(
            final_kbps >= low,
            "controller failed to ramp up: {final_kbps} kbps < {low} kbps"
        );
        assert!(
            final_kbps <= high,
            "controller overshot too much: {final_kbps} kbps > {high} kbps"
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

    /// Test: recovers / ramps when bandwidth cap rises.
    #[test]
    fn recovers_on_cap_rise() {
        let mut ctrl = GccController::with_defaults();
        let mut sim = NetSim::new(2_000, 20, 0.0); // 2 Mbps initially

        // Phase 1: converge at low cap.
        for _ in 0..200 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
        }
        let at_low_cap = ctrl.target_bitrate().as_kbps();
        println!("[recovers_on_cap_rise] at low cap (2 Mbps): {at_low_cap} kbps");

        // Phase 2: raise cap to 8 Mbps and run 300 more steps.
        sim.cap_bps = 8_000.0 * 1_000.0;
        sim.max_queue_bytes = sim.cap_bps * 0.200 / 8.0;
        for _ in 0..300 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
        }
        let at_high_cap = ctrl.target_bitrate().as_kbps();
        println!("[recovers_on_cap_rise] at high cap (8 Mbps): {at_high_cap} kbps");
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
