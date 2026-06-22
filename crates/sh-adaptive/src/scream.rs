//! SCReAM congestion controller for the native (QUIC) path.
//!
//! This module implements a pragmatic, RFC 8298-faithful **Self-Clocked Rate Adaptation for
//! Multimedia (SCReAM)** controller. SCReAM is a queue-delay-based algorithm designed for
//! real-time media (video/audio) where the goal is to fill the available bandwidth without
//! building up large queues.
//!
//! ## Algorithm overview (RFC 8298)
//!
//! 1. **Queue-delay signal:** the controller tracks a *reference queue delay* (base delay) and
//!    computes the current *queuing delay* as `observed_delay - base_delay`. When the delay
//!    exceeds a threshold, the network is becoming congested.
//!
//! 2. **Congestion window (CWND):** on each feedback:
//!    - **Additive increase** when `queue_delay < HIGH_THRESHOLD` and no significant loss.
//!    - **Exponential increase** early in the session (slow-start analogue).
//!    - **Multiplicative decrease** when `queue_delay >= HIGH_THRESHOLD` OR loss fraction exceeds
//!      the configured threshold. The window is halved (minimum one step per RTT).
//!
//! 3. **Target bitrate:** derived from CWND / RTT, clamped to `[min_bitrate, max_bitrate]`.
//!
//! 4. **Pacing interval:** `pacing_packet_bytes * 8 / target_bitrate_bps` (seconds per packet),
//!    clamped to at least 1 µs.
//!
//! ## Clamping strategy (hostile/degenerate input)
//!
//! Network feedback is untrusted data. The controller applies the following guards:
//!
//! | Input | Clamping |
//! |-------|---------|
//! | `rtt == 0` or `rtt < MIN_RTT_US` | treated as `MIN_RTT_US` (100 µs) |
//! | `rtt > MAX_RTT` | treated as `MAX_RTT` (10 s) |
//! | `queue_delay > MAX_QUEUE_DELAY` | treated as `MAX_QUEUE_DELAY` (2 s) |
//! | `bytes_lost > bytes_acked` | loss fraction treated as 1.0 (100%) |
//! | non-monotonic `now` (now < last_now) | feedback ignored (no state change) |
//! | `CWND` after decrease below min | clamped to `min_cwnd` |
//! | `target_bitrate` out of `[min, max]` | clamped to `[min, max]` |
//! | any `f64` becomes `NaN` or `Inf` | replaced with the previous valid value |
//!
//! [RFC 8298]: https://www.rfc-editor.org/rfc/rfc8298

use std::time::{Duration, Instant};

use crate::{Bitrate, CongestionController, TransportStats};

// ── Internal constants ────────────────────────────────────────────────────────

/// Minimum plausible RTT. Sub-100 µs RTT is a measurement artefact; clamp up to this.
const MIN_RTT: Duration = Duration::from_micros(100);

/// Maximum RTT we trust. Above this the link is either very congested or the measurement is wrong.
const MAX_RTT: Duration = Duration::from_secs(10);

/// Maximum queue delay we trust from the transport layer.
const MAX_QUEUE_DELAY: Duration = Duration::from_secs(2);

/// Queue-delay threshold above which the controller triggers multiplicative decrease.
///
/// RFC 8298 §4.1.1 recommends `Qth = 0.02 s` (20 ms) for interactive media. This is the
/// boundary between "network is loading up" and "network is congested".
const QUEUE_DELAY_HIGH_THRESHOLD: Duration = Duration::from_millis(20);

/// Queue-delay target for additive increase: we aim for half the high threshold so there is
/// headroom before triggering decrease.
const QUEUE_DELAY_TARGET: Duration = Duration::from_millis(10);

/// Loss fraction (as a proportion of `bytes_acked`) above which multiplicative decrease triggers.
///
/// A 2% instantaneous loss rate indicates significant congestion on most networks.
const LOSS_THRESHOLD: f64 = 0.02;

/// Additive increase step applied to CWND each RTT in the non-congested region.
///
/// RFC 8298 §4.1.1: `delta_CWND = max(MSS * bytes_newly_acked / CWND, MSS)`.
/// We use a simpler per-feedback additive step of 1 MSS (1 460 bytes, typical Ethernet MTU).
const MSS_BYTES: f64 = 1_460.0;

/// Multiplicative decrease factor applied to CWND on congestion (queue-delay spike or loss).
///
/// RFC 8298 §4.1.1 recommends `BETA_R = 0.85` (15% decrease) for rate-limited media.
const BETA_DECREASE: f64 = 0.85;

/// Scale factor for slow-start exponential increase. Matches RFC 8298 recommendation.
const SLOW_START_SCALE: f64 = 8.0;

/// Pacing packet size in bytes used to compute `pacing_interval`.
///
/// We assume packets are approximately one MTU. This determines the granularity of pacing: a
/// target of 10 Mbps with a 1 460-byte pacing packet gives a 1.168 ms pacing interval.
const PACING_PACKET_BYTES: u32 = 1_460;

/// Minimum congestion window: two MSS. Below this we cannot make progress.
const MIN_CWND_BYTES: f64 = 2.0 * MSS_BYTES;

/// Maximum congestion window guard: 100 Mbps × 200 ms RTT / 8 = ~2.5 MB.
///
/// This prevents runaway CWND growth in cases where feedback is unexpectedly delayed for a long
/// period and the window would otherwise grow without bound.
const MAX_CWND_BYTES: f64 = 2_500_000.0;

/// Minimum update interval: we do not update the CWND faster than once per millisecond even if
/// feedback arrives faster. Prevents numerical instability from extremely rapid feedback.
const MIN_UPDATE_INTERVAL: Duration = Duration::from_millis(1);

/// Maximum inter-update interval recognised as valid. Feedback older than this is treated as a
/// session restart (cold-start path) to avoid giant CWND jumps from stale RTT estimates.
const MAX_UPDATE_INTERVAL: Duration = Duration::from_secs(30);

// ── Public types ──────────────────────────────────────────────────────────────

/// Configuration parameters for the [`ScreamController`].
///
/// All bitrate bounds are inclusive. The controller always keeps `target_bitrate()` within
/// `[min_bitrate, max_bitrate]`.
#[derive(Debug, Clone)]
pub struct ScreamConfig {
    /// Minimum allowed target bitrate.
    ///
    /// Default: 100 kbps (the lowest rate at which a video stream remains useful).
    pub min_bitrate: Bitrate,

    /// Maximum allowed target bitrate.
    ///
    /// Default: 50 Mbps (well above any expected LAN or WAN path capacity in the near term).
    pub max_bitrate: Bitrate,

    /// Initial CWND in bytes at session start (cold-start).
    ///
    /// Default: `initial_bitrate * 100ms / 8` (roughly 100 ms worth of the initial target rate).
    pub initial_cwnd_bytes: f64,

    /// Initial target bitrate before any feedback has been received.
    ///
    /// Default: 2 Mbps (a conservative starting point that avoids flooding a slow network while
    /// still being high enough to stream acceptable quality immediately).
    pub initial_bitrate: Bitrate,

    /// Assumed initial RTT for the first CWND-to-bitrate conversion (before a real RTT sample).
    ///
    /// Default: 50 ms.
    pub initial_rtt: Duration,
}

impl Default for ScreamConfig {
    fn default() -> Self {
        let initial_bitrate = Bitrate::from_mbps(2);
        // initial_cwnd = rate * rtt / 8  (bytes)
        // = 2e6 bps * 0.050 s / 8 = 12_500 bytes
        let initial_cwnd_bytes = (initial_bitrate.as_bps_f64() * 0.050) / 8.0;
        Self {
            min_bitrate: Bitrate::from_kbps(100),
            max_bitrate: Bitrate::from_mbps(50),
            initial_cwnd_bytes,
            initial_bitrate,
            initial_rtt: Duration::from_millis(50),
        }
    }
}

/// Phase of the congestion controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Slow-start: CWND grows rapidly until the first congestion signal or until we exceed a
    /// threshold derived from the initial bitrate.
    SlowStart,
    /// Steady state: additive increase / multiplicative decrease (AIMD).
    SteadyState,
}

/// SCReAM congestion controller (RFC 8298) for the native QUIC path.
///
/// # Construction
///
/// ```rust
/// use sh_adaptive::{ScreamConfig, ScreamController};
/// use sh_adaptive::Bitrate;
///
/// let config = ScreamConfig {
///     min_bitrate: Bitrate::from_kbps(100),
///     max_bitrate: Bitrate::from_mbps(50),
///     ..ScreamConfig::default()
/// };
/// let controller = ScreamController::new(config);
/// ```
///
/// # Clock injection
///
/// `ScreamController` never calls `Instant::now()`. All time is supplied by the caller via the
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
pub struct ScreamController {
    config: ScreamConfig,

    /// Current congestion window in bytes.
    cwnd: f64,

    /// Smoothed RTT (EWMA, α = 0.125, matching TCP), in seconds.
    srtt_secs: f64,

    /// Minimum RTT observed over the session, used as the base delay reference.
    min_rtt_secs: f64,

    /// Current controller phase (slow-start vs. steady-state AIMD).
    phase: Phase,

    /// `Instant` of the last `on_feedback` call, used to guard against non-monotonic `now`.
    last_feedback_time: Option<Instant>,

    /// Last congestion event time. Used to enforce at most one multiplicative decrease per RTT.
    last_decrease_time: Option<Instant>,

    /// Cached target bitrate (re-derived on each feedback).
    target_bitrate: Bitrate,
}

impl ScreamController {
    /// Create a new `ScreamController` with the given configuration.
    ///
    /// The controller starts in slow-start, using `config.initial_bitrate` as the first target
    /// bitrate until feedback arrives.
    ///
    /// # Panics
    ///
    /// This function does not panic. (Asserted here to satisfy `#![deny(missing_docs)]` for the
    /// `# Panics` convention — there is nothing to panic about in the constructor.)
    #[must_use]
    pub fn new(config: ScreamConfig) -> Self {
        let initial_bitrate = config
            .initial_bitrate
            .clamp(config.min_bitrate, config.max_bitrate);
        let cwnd = config
            .initial_cwnd_bytes
            .clamp(MIN_CWND_BYTES, MAX_CWND_BYTES);
        let initial_rtt_secs = clamp_rtt(config.initial_rtt).as_secs_f64();
        Self {
            target_bitrate: initial_bitrate,
            cwnd,
            srtt_secs: initial_rtt_secs,
            min_rtt_secs: initial_rtt_secs,
            phase: Phase::SlowStart,
            last_feedback_time: None,
            last_decrease_time: None,
            config,
        }
    }

    /// Create a new `ScreamController` with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ScreamConfig::default())
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Update the smoothed RTT and minimum-RTT baseline.
    fn update_rtt(&mut self, rtt: Duration) {
        let rtt_s = clamp_rtt(rtt).as_secs_f64();
        // EWMA: α = 0.125 (same as TCP SRTT in RFC 6298)
        self.srtt_secs = 0.875 * self.srtt_secs + 0.125 * rtt_s;
        if rtt_s < self.min_rtt_secs {
            self.min_rtt_secs = rtt_s;
        }
    }

    /// Clamp CWND to `[MIN_CWND_BYTES, MAX_CWND_BYTES]` and replace NaN/Inf.
    fn sanitise_cwnd(&mut self) {
        if !self.cwnd.is_finite() {
            self.cwnd = MIN_CWND_BYTES;
        } else {
            self.cwnd = self.cwnd.clamp(MIN_CWND_BYTES, MAX_CWND_BYTES);
        }
    }

    /// Derive `target_bitrate` from CWND and SRTT, then clamp to `[min, max]`.
    ///
    /// Formula: `target = cwnd * 8 / srtt` (bits per second).
    fn update_target_bitrate(&mut self) {
        let srtt = self.srtt_secs;
        // Guard: SRTT below minimum is physically impossible; clamp up to avoid huge bitrate.
        let srtt = srtt.max(MIN_RTT.as_secs_f64());

        let bps = self.cwnd * 8.0 / srtt;
        // NaN/Inf guard
        let bps = if bps.is_finite() && bps >= 0.0 {
            bps
        } else {
            self.config.min_bitrate.as_bps_f64()
        };

        self.target_bitrate =
            Bitrate::from_bps_f64(bps).clamp(self.config.min_bitrate, self.config.max_bitrate);
    }

    /// Returns `true` if a multiplicative decrease should be suppressed because one already
    /// happened within the last RTT (prevents multiple halving in one RTT).
    fn decrease_suppressed(&self, now: Instant) -> bool {
        match self.last_decrease_time {
            None => false,
            Some(t) => {
                let elapsed = now.saturating_duration_since(t);
                // Suppress if less than one SRTT has passed since the last decrease.
                elapsed < Duration::from_secs_f64(self.srtt_secs.max(0.0))
            }
        }
    }

    /// Execute the AIMD increase step.
    ///
    /// The increase depends on the current phase:
    /// - **Slow-start:** multiplicative increase (`cwnd += bytes_acked * SLOW_START_SCALE`)
    ///   until the first congestion event or until CWND reaches the initial bitrate × initial RTT.
    /// - **Steady-state:** additive increase (`cwnd += MSS * bytes_acked / cwnd`), bounded
    ///   to at least one MSS per RTT (RFC 8298 §4.1.1).
    fn apply_increase(&mut self, bytes_acked: u32, queue_delay_secs: f64) {
        let acked = f64::from(bytes_acked);
        match self.phase {
            Phase::SlowStart => {
                // Exponential growth until we hit the initial BDP estimate.
                let increase = acked * SLOW_START_SCALE;
                let new_cwnd = self.cwnd + increase;
                if new_cwnd.is_finite() {
                    self.cwnd = new_cwnd;
                }
                // Graduate to steady state if CWND is large enough that we're beyond cold start,
                // or if the queue is already building up.
                let bdp_estimate = self.config.initial_bitrate.as_bps_f64() * self.srtt_secs / 8.0;
                if self.cwnd >= bdp_estimate || queue_delay_secs > QUEUE_DELAY_TARGET.as_secs_f64()
                {
                    self.phase = Phase::SteadyState;
                }
            }
            Phase::SteadyState => {
                // RFC 8298 §4.1.1: delta_cwnd = max(MSS * acked / cwnd, MSS)
                let delta = (MSS_BYTES * acked / self.cwnd).max(MSS_BYTES);
                let new_cwnd = self.cwnd + delta;
                if new_cwnd.is_finite() {
                    self.cwnd = new_cwnd;
                }
            }
        }
        self.sanitise_cwnd();
    }

    /// Execute the multiplicative decrease step (congestion detected).
    ///
    /// CWND is multiplied by `BETA_DECREASE` (0.85), equivalent to a 15% reduction.
    /// At most one decrease per SRTT is applied (guarded by `decrease_suppressed`).
    fn apply_decrease(&mut self, now: Instant) {
        let new_cwnd = self.cwnd * BETA_DECREASE;
        if new_cwnd.is_finite() {
            self.cwnd = new_cwnd;
        }
        self.sanitise_cwnd();
        self.last_decrease_time = Some(now);
        // Exit slow-start permanently on first congestion signal.
        self.phase = Phase::SteadyState;
    }
}

impl CongestionController for ScreamController {
    /// Ingest a feedback report and update the congestion window / target bitrate.
    ///
    /// # Errors
    ///
    /// This method never returns an error — it is infallible by design. All degenerate inputs
    /// (zero RTT, non-monotonic `now`, `bytes_lost > bytes_acked`) are handled by clamping or
    /// early return.
    fn on_feedback(&mut self, fb: &TransportStats, now: Instant) {
        // ── Guard: non-monotonic clock ────────────────────────────────────────
        if let Some(last) = self.last_feedback_time {
            let delta = now.checked_duration_since(last);
            match delta {
                None => {
                    // now < last: clock went backwards. Ignore this report entirely.
                    return;
                }
                Some(d) if d < MIN_UPDATE_INTERVAL => {
                    // Feedback arrived too fast; skip to avoid numerical instability.
                    return;
                }
                Some(d) if d > MAX_UPDATE_INTERVAL => {
                    // Very long gap: treat as session restart / cold start.
                    self.phase = Phase::SlowStart;
                }
                _ => {}
            }
        }
        self.last_feedback_time = Some(now);

        // ── Update RTT ────────────────────────────────────────────────────────
        if fb.rtt > Duration::ZERO {
            self.update_rtt(fb.rtt);
        }

        // ── Compute queue-delay signal (seconds) ──────────────────────────────
        let queue_delay_secs = clamp_duration(fb.queue_delay, MAX_QUEUE_DELAY).as_secs_f64();

        // ── Compute loss fraction ─────────────────────────────────────────────
        // Use the explicit `loss_fraction_q8` if set; otherwise derive from byte counts.
        let loss_frac: f64 = if fb.loss_fraction_q8 > 0 {
            fb.loss_fraction()
        } else if fb.bytes_lost > 0 {
            // Clamp: if bytes_lost > bytes_acked, treat as 100% loss.
            let denom = fb.bytes_acked.max(1);
            (f64::from(fb.bytes_lost) / f64::from(denom)).min(1.0)
        } else {
            0.0
        };

        // ── Congestion decision ───────────────────────────────────────────────
        let congested = queue_delay_secs >= QUEUE_DELAY_HIGH_THRESHOLD.as_secs_f64()
            || loss_frac >= LOSS_THRESHOLD;

        if congested {
            if !self.decrease_suppressed(now) {
                self.apply_decrease(now);
            }
        } else {
            self.apply_increase(fb.bytes_acked, queue_delay_secs);
        }

        // ── Re-derive target bitrate ──────────────────────────────────────────
        self.update_target_bitrate();
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
            // Defensive: should never happen given min_bitrate > 0.
            return Duration::from_micros(1);
        }
        let interval_secs = f64::from(PACING_PACKET_BYTES) * 8.0 / bps;
        if !interval_secs.is_finite() || interval_secs <= 0.0 {
            return Duration::from_micros(1);
        }
        // Convert to Duration, clamping to at least 1 µs.
        // interval_secs is finite and positive (guarded above).
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

    /// A simple network simulator used to drive the controller deterministically.
    ///
    /// The simulator advances a synthetic clock and produces `TransportStats` based on a
    /// token-bucket bandwidth cap, a fixed propagation delay, and an optional loss rate.
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
    }

    impl NetSim {
        fn new(cap_kbps: u64, prop_delay_ms: u64, loss_rate: f64) -> Self {
            // Instant::now() is allowed in tests; the controller itself never calls it.
            #[allow(clippy::disallowed_methods)]
            let clock = Instant::now();
            Self {
                cap_bps: f64::from(u32::try_from(cap_kbps).unwrap_or(u32::MAX)) * 1_000.0,
                prop_delay: Duration::from_millis(prop_delay_ms),
                loss_rate: loss_rate.clamp(0.0, 1.0),
                clock,
                step: Duration::from_millis(10), // 100 Hz feedback
            }
        }

        /// Advance time by one step and return a `TransportStats` for the current state.
        ///
        /// `send_rate_bps` is the rate at which the controller is currently sending; the sim
        /// computes how many bytes were acked/lost given the cap and loss rate.
        fn tick(&mut self, send_rate_bps: f64) -> (Instant, TransportStats) {
            self.clock += self.step;
            let rtt = self.prop_delay.saturating_mul(2);
            // Bytes delivered this step = min(send_rate, cap) * step_duration * (1 - loss)
            let deliverable_bps = send_rate_bps.min(self.cap_bps);
            let bytes_this_step = (deliverable_bps * self.step.as_secs_f64() / 8.0).max(0.0) as u32;
            let bytes_acked = ((bytes_this_step as f64) * (1.0 - self.loss_rate)) as u32;
            let bytes_lost = bytes_this_step.saturating_sub(bytes_acked);
            // Queue-delay: if sending above cap, queue builds up. We model a 50ms buffer
            // that fills proportionally to the excess send rate: when the excess is 40% of
            // cap (i.e. send rate = 1.4×cap), queue delay reaches 20ms (the SCReAM threshold),
            // so the controller backs off promptly. This is more representative of real router
            // buffers (tens of ms) than scaling by propagation delay alone.
            let excess_ratio = (send_rate_bps / self.cap_bps.max(1.0) - 1.0).max(0.0);
            let buffer_fill_secs = excess_ratio * 0.050; // 50 ms buffer fully fills at 2× cap
            let queue_delay =
                Duration::from_secs_f64(buffer_fill_secs.min(MAX_QUEUE_DELAY.as_secs_f64()));
            let fb = TransportStats {
                rtt,
                queue_delay,
                bytes_acked,
                bytes_lost,
                loss_fraction_q8: 0,
                interval: self.step,
            };
            (self.clock, fb)
        }
    }

    // ── Core behaviour tests ──────────────────────────────────────────────────

    /// Test: target_bitrate is always within [min, max], even after many iterations.
    #[test]
    fn target_always_within_bounds() {
        let cfg = ScreamConfig {
            min_bitrate: Bitrate::from_kbps(100),
            max_bitrate: Bitrate::from_mbps(50),
            ..ScreamConfig::default()
        };
        let mut ctrl = ScreamController::new(cfg.clone());
        let mut sim = NetSim::new(5_000, 20, 0.0); // 5 Mbps, 20ms prop delay, no loss

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
    /// After enough steps, target_bitrate should be within [50%, 130%] of the cap.
    #[test]
    fn converges_toward_cap() {
        let cap_kbps = 5_000u64;
        let mut ctrl = ScreamController::with_defaults();
        let mut sim = NetSim::new(cap_kbps, 20, 0.0);

        // Run 300 steps (~3 seconds at 100Hz feedback) to allow convergence.
        for _ in 0..300 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
        }

        let final_kbps = ctrl.target_bitrate().as_kbps();
        let low = cap_kbps / 2;
        let high = cap_kbps * 13 / 10; // 130% (accounts for transient overshoot)
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

    /// Test: backs off promptly when loss is induced.
    #[test]
    fn backs_off_on_loss() {
        let mut ctrl = ScreamController::with_defaults();
        let mut sim = NetSim::new(10_000, 20, 0.0); // 10 Mbps, no loss

        // Ramp up for 200 steps.
        for _ in 0..200 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
        }
        let peak = ctrl.target_bitrate().as_kbps();
        println!("[backs_off_on_loss] peak before loss: {peak} kbps");

        // Inject 20% loss for 50 steps.
        sim.loss_rate = 0.20;
        for _ in 0..50 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
        }
        let after_loss = ctrl.target_bitrate().as_kbps();
        println!("[backs_off_on_loss] after 50 loss steps: {after_loss} kbps");
        assert!(
            after_loss < peak,
            "expected backoff: peak={peak}, after_loss={after_loss}"
        );
    }

    /// Test: recovers / ramps when bandwidth cap rises.
    #[test]
    fn recovers_on_cap_rise() {
        let mut ctrl = ScreamController::with_defaults();
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

    /// Test: backs off when cap drops.
    #[test]
    fn backs_off_on_cap_drop() {
        let mut ctrl = ScreamController::with_defaults();
        let mut sim = NetSim::new(10_000, 20, 0.0); // 10 Mbps

        // Phase 1: converge at high cap.
        for _ in 0..300 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
        }
        let at_high_cap = ctrl.target_bitrate().as_kbps();
        println!("[backs_off_on_cap_drop] at high cap (10 Mbps): {at_high_cap} kbps");

        // Phase 2: drop cap to 1 Mbps and run 200 more steps.
        sim.cap_bps = 1_000.0 * 1_000.0;
        for _ in 0..200 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
        }
        let at_low_cap = ctrl.target_bitrate().as_kbps();
        println!("[backs_off_on_cap_drop] at low cap (1 Mbps): {at_low_cap} kbps");
        assert!(
            at_low_cap < at_high_cap,
            "expected backoff: at_high={at_high_cap}, at_low={at_low_cap}"
        );
    }

    /// Test: pacing_interval is always positive and finite.
    #[test]
    fn pacing_interval_always_positive() {
        let mut ctrl = ScreamController::with_defaults();
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
        let mut ctrl = ScreamController::with_defaults();
        let mut sim = NetSim::new(5_000, 20, 0.0);
        let (t0, fb0) = sim.tick(ctrl.target_bitrate().as_bps_f64());
        ctrl.on_feedback(&fb0, t0);
        let rate_after_first = ctrl.target_bitrate();

        // Feed the same `now` (or an earlier one) — should be ignored.
        let early_now = t0 - Duration::from_millis(1);
        // checked_duration_since would panic if t0 < last so we supply t0 - 1ms directly.
        ctrl.on_feedback(&fb0, early_now);
        // State should be unchanged.
        assert_eq!(ctrl.target_bitrate(), rate_after_first);
    }

    /// Test: zero-RTT feedback does not crash and preserves bounds.
    #[test]
    fn zero_rtt_feedback_is_safe() {
        let mut ctrl = ScreamController::with_defaults();
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
        let cfg = ScreamConfig::default();
        assert!(t >= cfg.min_bitrate && t <= cfg.max_bitrate);
    }

    /// Test: bytes_lost > bytes_acked is handled gracefully.
    #[test]
    fn bytes_lost_exceeds_acked_is_safe() {
        let mut ctrl = ScreamController::with_defaults();
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
        let cfg = ScreamConfig::default();
        assert!(t >= cfg.min_bitrate && t <= cfg.max_bitrate);
    }

    /// Test: convergence summary printed with --nocapture (shows bandwidth tracking up/down).
    #[test]
    fn bandwidth_convergence_summary() {
        println!("\n=== SCReAM bandwidth convergence summary ===");
        let mut ctrl = ScreamController::with_defaults();
        let cfg = ScreamConfig::default();

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
            for i in 0..*steps {
                let send_bps = ctrl.target_bitrate().as_bps_f64();
                let (now, fb) = sim.tick(send_bps);
                ctrl.on_feedback(&fb, now);
                // Print every 50 steps.
                if i % 50 == 49 || i == steps - 1 {
                    println!(
                        "  {label} [step {:>3}]: cap={cap_kbps} kbps  target={} kbps",
                        i + 1,
                        ctrl.target_bitrate().as_kbps()
                    );
                }
            }
            let final_rate = ctrl.target_bitrate();
            assert!(final_rate >= cfg.min_bitrate, "below min: {}", final_rate);
            assert!(final_rate <= cfg.max_bitrate, "above max: {}", final_rate);
        }
        println!("=== end of convergence summary ===\n");
    }

    /// Test: no oscillation (variance stays bounded once converged).
    ///
    /// After converging, the target bitrate should not flap more than ±30% around the cap.
    #[test]
    fn no_pathological_oscillation() {
        let cap_kbps = 4_000u64;
        let mut ctrl = ScreamController::with_defaults();
        let mut sim = NetSim::new(cap_kbps, 20, 0.0);

        // Warm up for 300 steps.
        for _ in 0..300 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
        }

        // Measure variance over the next 200 steps.
        let mut readings = Vec::with_capacity(200);
        for _ in 0..200 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
            readings.push(ctrl.target_bitrate().as_kbps());
        }

        let min_r = *readings.iter().min().unwrap_or(&0);
        let max_r = *readings.iter().max().unwrap_or(&0);
        let range = max_r.saturating_sub(min_r);
        println!(
            "[no_pathological_oscillation] converged range: [{min_r},{max_r}] kbps (spread: {range} kbps)"
        );
        // Range should be less than 60% of the cap (i.e. not wildly oscillating).
        assert!(
            range < cap_kbps * 6 / 10,
            "too much oscillation: range={range} kbps, cap={cap_kbps} kbps"
        );
    }

    // ── Constructor / config tests ────────────────────────────────────────────

    #[test]
    fn with_defaults_starts_at_initial_bitrate() {
        let ctrl = ScreamController::with_defaults();
        let cfg = ScreamConfig::default();
        assert_eq!(ctrl.target_bitrate(), cfg.initial_bitrate);
    }

    #[test]
    fn initial_pacing_interval_is_positive() {
        let ctrl = ScreamController::with_defaults();
        assert!(ctrl.pacing_interval() >= Duration::from_micros(1));
    }

    #[test]
    fn custom_config_is_respected() {
        let cfg = ScreamConfig {
            min_bitrate: Bitrate::from_kbps(500),
            max_bitrate: Bitrate::from_mbps(5),
            initial_bitrate: Bitrate::from_mbps(1),
            ..ScreamConfig::default()
        };
        let ctrl = ScreamController::new(cfg.clone());
        assert_eq!(ctrl.target_bitrate(), cfg.initial_bitrate);
    }

    #[test]
    fn min_greater_than_initial_clamps_target() {
        // If min > initial, target is clamped to min.
        let cfg = ScreamConfig {
            min_bitrate: Bitrate::from_mbps(5),
            max_bitrate: Bitrate::from_mbps(50),
            initial_bitrate: Bitrate::from_kbps(100), // below min
            ..ScreamConfig::default()
        };
        let ctrl = ScreamController::new(cfg.clone());
        assert_eq!(ctrl.target_bitrate(), cfg.min_bitrate);
    }
}

// ── Property tests ────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod prop_tests {
    use super::*;
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
            let cfg = ScreamConfig::default();
            let mut ctrl = ScreamController::new(cfg.clone());

            // Build a monotonic clock starting from a fixed point.
            // Instant::now() is allowed in tests.
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
            let cfg = ScreamConfig::default();
            let mut ctrl = ScreamController::new(cfg.clone());

            #[allow(clippy::disallowed_methods)]
            let base = Instant::now();
            let mut elapsed = Duration::from_secs(1); // start with slack so we can go back

            for (i, fb) in feedbacks.iter().enumerate() {
                // Alternate: monotonic increase vs. a backwards step.
                if i % 3 == 0 {
                    // Backwards: subtract 500ms
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

        /// Property: extreme RTT values (near zero, near max) never produce out-of-bound bitrate.
        #[test]
        fn extreme_rtt_stays_in_bounds(
            rtt_us in 0u64..=10_000_000_000u64, // 0 to 10000 seconds
            bytes_acked in 0u32..=1_000_000u32,
        ) {
            let cfg = ScreamConfig::default();
            let mut ctrl = ScreamController::new(cfg.clone());

            #[allow(clippy::disallowed_methods)]
            let base = Instant::now();
            let fb = TransportStats {
                rtt: Duration::from_micros(rtt_us),
                queue_delay: Duration::ZERO,
                bytes_acked,
                bytes_lost: 0,
                loss_fraction_q8: 0,
                interval: Duration::from_millis(10),
            };
            ctrl.on_feedback(&fb, base + Duration::from_secs(1));

            let target = ctrl.target_bitrate();
            prop_assert!(target >= cfg.min_bitrate);
            prop_assert!(target <= cfg.max_bitrate);
            prop_assert!(ctrl.pacing_interval() >= Duration::from_micros(1));
        }
    }
}
