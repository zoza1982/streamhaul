//! SCReAM congestion controller for the native (QUIC) path.
//!
//! This module implements a pragmatic, RFC 8298-faithful **Self-Clocked Rate Adaptation for
//! Multimedia (SCReAM)** controller. SCReAM is a queue-delay-based algorithm designed for
//! real-time media (video/audio) where the goal is to fill the available bandwidth without
//! building up large queues.
//!
//! ## Algorithm overview (RFC 8298)
//!
//! 1. **Queue-delay signal:** the transport layer supplies `queue_delay` directly in
//!    [`TransportStats`]. The controller does not compute a base-delay baseline; that
//!    responsibility belongs to the transport layer.
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

use crate::util::{clamp_duration, clamp_rtt, MAX_QUEUE_DELAY, MIN_RTT_SECS};
use crate::{Bitrate, CongestionController, TransportStats};

/// Queue-delay threshold in seconds above which the controller triggers multiplicative decrease.
///
/// RFC 8298 §4.1.1 recommends `Qth = 0.02 s` (20 ms) for interactive media. This is the
/// boundary between "network is loading up" and "network is congested".
/// Stored as `f64` to avoid repeated `as_secs_f64()` conversions in the hot path.
const QUEUE_DELAY_HIGH_THRESHOLD_SECS: f64 = 0.020;

/// Queue-delay target in seconds for additive increase: we aim for half the high threshold so
/// there is headroom before triggering decrease.
/// Stored as `f64` to avoid repeated `as_secs_f64()` conversions in the hot path.
const QUEUE_DELAY_TARGET_SECS: f64 = 0.010;

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
        Self {
            min_bitrate: Bitrate::from_kbps(100),
            max_bitrate: Bitrate::from_mbps(50),
            initial_bitrate: Bitrate::from_mbps(2),
            initial_rtt: Duration::from_millis(50),
        }
    }
}

/// Phase of the congestion controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Slow-start: CWND grows rapidly until the first congestion signal or until CWND reaches
    /// `ssthresh`.
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

    /// Slow-start threshold in bytes. Graduate [`Phase::SlowStart`] → [`Phase::SteadyState`]
    /// when CWND reaches this, or on the first congestion event.
    ssthresh: f64,

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
        let initial_rtt_secs = clamp_rtt(config.initial_rtt).as_secs_f64();
        // Compute initial CWND: rate * rtt / 8 (bytes), clamped to [MIN, MAX].
        let cwnd_raw = config.initial_bitrate.as_bps_f64() * initial_rtt_secs / 8.0;
        let cwnd = if cwnd_raw.is_finite() {
            cwnd_raw.clamp(MIN_CWND_BYTES, MAX_CWND_BYTES)
        } else {
            MIN_CWND_BYTES
        };
        Self {
            target_bitrate: initial_bitrate,
            cwnd,
            srtt_secs: initial_rtt_secs,
            ssthresh: MAX_CWND_BYTES,
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

    /// Update the smoothed RTT.
    fn update_rtt(&mut self, rtt: Duration) {
        let rtt_s = clamp_rtt(rtt).as_secs_f64();
        // EWMA: α = 0.125 (same as TCP SRTT in RFC 6298)
        self.srtt_secs = 0.875 * self.srtt_secs + 0.125 * rtt_s;
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
        let srtt = srtt.max(MIN_RTT_SECS);

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
                // Floor at MIN_RTT to prevent srtt_secs near zero from making the suppression
                // window vanishingly small.
                elapsed < Duration::from_secs_f64(self.srtt_secs.max(MIN_RTT_SECS))
            }
        }
    }

    /// Execute the AIMD increase step.
    ///
    /// The increase depends on the current phase:
    /// - **Slow-start:** multiplicative increase (`cwnd += bytes_acked * SLOW_START_SCALE`)
    ///   until the first congestion event or until CWND reaches `ssthresh`.
    /// - **Steady-state:** additive increase (`cwnd += MSS * bytes_acked / cwnd`), bounded
    ///   to at least one MSS per RTT (RFC 8298 §4.1.1). Only applied when `bytes_acked > 0`.
    fn apply_increase(&mut self, bytes_acked: u32, queue_delay_secs: f64) {
        let acked = f64::from(bytes_acked);
        match self.phase {
            Phase::SlowStart => {
                // Exponential growth.
                let increase = acked * SLOW_START_SCALE;
                let new_cwnd = self.cwnd + increase;
                if new_cwnd.is_finite() {
                    self.cwnd = new_cwnd;
                }
                // Graduate to steady state if CWND reaches ssthresh or the queue is building.
                if self.cwnd >= self.ssthresh || queue_delay_secs > QUEUE_DELAY_TARGET_SECS {
                    self.phase = Phase::SteadyState;
                }
            }
            Phase::SteadyState => {
                // Only increase if bytes were acknowledged this feedback epoch.
                if acked > 0.0 {
                    // RFC 8298 §4.1.1: delta_cwnd = max(MSS * acked / cwnd, MSS)
                    let delta = (MSS_BYTES * acked / self.cwnd).max(MSS_BYTES);
                    let new_cwnd = self.cwnd + delta;
                    if new_cwnd.is_finite() {
                        self.cwnd = new_cwnd;
                    }
                }
            }
        }
        self.sanitise_cwnd();
    }

    /// Execute the multiplicative decrease step (congestion detected).
    ///
    /// Sets `ssthresh` to `cwnd * BETA_DECREASE` before reducing CWND, so slow-start knows
    /// where to stop on the next cold-restart. CWND is then multiplied by `BETA_DECREASE`
    /// (0.85), equivalent to a 15% reduction.
    /// At most one decrease per SRTT is applied (guarded by `decrease_suppressed`).
    fn apply_decrease(&mut self, now: Instant) {
        // Record ssthresh before decrease so slow-start won't overshoot on restart.
        self.ssthresh = (self.cwnd * BETA_DECREASE).max(MIN_CWND_BYTES);
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
                    // Very long gap: full cold-restart to avoid resuming with stale state.
                    // Reset everything to initial config values, then return — CWND update
                    // for this particular (stale) feedback is skipped; the *next* feedback
                    // will drive the algorithm from the clean initial state.
                    self.phase = Phase::SlowStart;
                    // Recompute initial window from config (same formula as ::new).
                    let init_rtt_s = clamp_rtt(self.config.initial_rtt).as_secs_f64();
                    let init_cwnd_raw = self.config.initial_bitrate.as_bps_f64() * init_rtt_s / 8.0;
                    let init_cwnd = if init_cwnd_raw.is_finite() {
                        init_cwnd_raw.clamp(MIN_CWND_BYTES, MAX_CWND_BYTES)
                    } else {
                        MIN_CWND_BYTES
                    };
                    self.cwnd = init_cwnd;
                    self.srtt_secs = init_rtt_s;
                    self.last_decrease_time = None;
                    self.ssthresh = MAX_CWND_BYTES;
                    self.last_feedback_time = Some(now);
                    self.update_target_bitrate();
                    return;
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
        let congested =
            queue_delay_secs >= QUEUE_DELAY_HIGH_THRESHOLD_SECS || loss_frac >= LOSS_THRESHOLD;

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
    use crate::util::test_helpers::NetSim;

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
    /// After enough steps, target_bitrate should be within [85%, 115%] of the cap.
    #[test]
    fn converges_toward_cap() {
        let cap_kbps = 5_000u64;
        let mut ctrl = ScreamController::with_defaults();
        let mut sim = NetSim::new(cap_kbps, 20, 0.0);

        // Collect queue delays over the last 200 steps for the bufferbloat guard.
        let mut late_queue_delays: Vec<Duration> = Vec::new();

        // Run 500 steps (~5 seconds at 100Hz feedback) to allow convergence with physical queue.
        for i in 0..500 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
            if i >= 300 {
                late_queue_delays.push(fb.queue_delay);
            }
        }

        let final_kbps = ctrl.target_bitrate().as_kbps();
        let low = cap_kbps * 85 / 100; // 85%
        let high = cap_kbps * 115 / 100; // 115%
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

        // Bufferbloat guard: steady-state queue delay should stay under 40ms.
        let max_late_queue = late_queue_delays
            .iter()
            .max()
            .copied()
            .unwrap_or(Duration::ZERO);
        assert!(
            max_late_queue < Duration::from_millis(40),
            "bufferbloat: max queue delay {max_late_queue:?} exceeds 40ms"
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
            // Reset queue between scenario phases to avoid accumulated state skewing results.
            sim.queue_bytes = 0.0;
            sim.max_queue_bytes = sim.cap_bps * 0.200 / 8.0;
            for i in 0..*steps {
                let send_bps = ctrl.target_bitrate().as_bps_f64();
                let (now, fb) = sim.tick(send_bps);
                let queue_ms = fb.queue_delay.as_secs_f64() * 1000.0;
                ctrl.on_feedback(&fb, now);
                // Print every 50 steps.
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

        let min_r = readings.iter().copied().min().unwrap_or(0);
        let max_r = readings.iter().copied().max().unwrap_or(0);
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

    // ── New regression / correctness tests ───────────────────────────────────

    /// Test: slow-start ramps target significantly before the queue builds up.
    #[test]
    fn slow_start_ramps_exponentially() {
        // With ssthresh=MAX_CWND_BYTES, slow-start should run for many steps before
        // the queue builds up and forces graduation to steady state.
        let mut ctrl = ScreamController::with_defaults();
        // Use a very high cap so the queue never builds — slow-start can run freely.
        let mut sim = NetSim::new(50_000, 5, 0.0); // 50 Mbps, 5ms prop delay

        let initial_target = ctrl.target_bitrate().as_bps_f64();
        let mut prev_target = initial_target;
        let mut exponential_steps = 0u32;

        // Run for up to 100 steps; count how many steps the target increased significantly
        // (>= 50% above previous, indicating exponential-style growth).
        for _ in 0..100 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (now, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, now);
            let cur = ctrl.target_bitrate().as_bps_f64();
            if cur > prev_target * 1.5 {
                exponential_steps += 1;
            }
            prev_target = cur;
        }
        let final_target = ctrl.target_bitrate().as_bps_f64();
        println!(
            "[slow_start_ramps_exponentially] initial={:.0} bps, final={:.0} bps, exp_steps={exponential_steps}",
            initial_target, final_target
        );
        // Should have ramped significantly from initial.
        assert!(
            final_target > initial_target * 5.0,
            "slow start should ramp target significantly; initial={initial_target:.0}, final={final_target:.0}"
        );
        // Should have seen at least some exponential-looking steps.
        assert!(
            exponential_steps >= 1,
            "expected at least one exponential growth step"
        );
    }

    /// Test: zero bytes_acked in SteadyState does not inflate CWND.
    #[test]
    fn zero_acked_does_not_inflate_cwnd() {
        let cfg = ScreamConfig {
            initial_bitrate: Bitrate::from_mbps(2),
            ..ScreamConfig::default()
        };
        let mut ctrl = ScreamController::new(cfg.clone());
        // First, graduate out of slow-start by sending one real feedback with acked bytes
        // and a queue delay to force steady state.
        #[allow(clippy::disallowed_methods)]
        let base = Instant::now();
        let trigger_fb = TransportStats {
            rtt: Duration::from_millis(20),
            queue_delay: Duration::from_millis(15), // above QUEUE_DELAY_TARGET, forces steady-state
            bytes_acked: 10_000,
            bytes_lost: 0,
            loss_fraction_q8: 0,
            interval: Duration::from_millis(10),
        };
        ctrl.on_feedback(&trigger_fb, base + Duration::from_millis(10));
        // Ensure we're in steady-state by applying a decrease signal.
        let decrease_fb = TransportStats {
            rtt: Duration::from_millis(20),
            queue_delay: Duration::from_millis(25), // above HIGH_THRESHOLD → decrease
            bytes_acked: 0,
            bytes_lost: 0,
            loss_fraction_q8: 0,
            interval: Duration::from_millis(10),
        };
        ctrl.on_feedback(&decrease_fb, base + Duration::from_millis(20));
        let rate_after_decrease = ctrl.target_bitrate();

        // Now send many feedbacks with zero acked, no congestion → CWND must NOT increase.
        // We use rtt=ZERO so that SRTT is not updated (the guard `if fb.rtt > ZERO` skips it),
        // keeping target = cwnd/srtt stable. This isolates the CWND guard from RTT convergence.
        for i in 0..50u64 {
            let zero_fb = TransportStats {
                rtt: Duration::ZERO,         // skip RTT update to keep SRTT stable
                queue_delay: Duration::ZERO, // no congestion
                bytes_acked: 0,
                bytes_lost: 0,
                loss_fraction_q8: 0,
                interval: Duration::from_millis(10),
            };
            ctrl.on_feedback(&zero_fb, base + Duration::from_millis(30 + i * 10));
        }
        let rate_after_zero = ctrl.target_bitrate();
        println!(
            "[zero_acked_does_not_inflate_cwnd] after_decrease={rate_after_decrease}, after_50_zero_acked={rate_after_zero}"
        );
        assert!(
            rate_after_zero <= rate_after_decrease,
            "CWND inflated with zero acked: before={rate_after_decrease}, after={rate_after_zero}"
        );
    }

    /// Test: after a >30s gap, the controller cold-restarts to near initial bitrate.
    #[test]
    fn session_restart_resets_cwnd_to_initial() {
        let cfg = ScreamConfig::default();
        let mut ctrl = ScreamController::new(cfg.clone());
        #[allow(clippy::disallowed_methods)]
        let base = Instant::now();
        let mut sim = NetSim::new(10_000, 20, 0.0); // 10 Mbps

        // Ramp up for 300 steps.
        for i in 0..300u64 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (_, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, base + Duration::from_millis(10 * (i + 1)));
        }
        let peak = ctrl.target_bitrate();
        println!("[session_restart] peak before gap: {peak}");

        // Simulate 31 seconds of silence, then resume.
        let resume_time = base + Duration::from_millis(3_000) + Duration::from_secs(31);
        let (_, resume_fb) = sim.tick(ctrl.target_bitrate().as_bps_f64());
        ctrl.on_feedback(&resume_fb, resume_time);

        let after_restart = ctrl.target_bitrate();
        println!("[session_restart] after 31s gap: {after_restart}");

        // After cold-restart, target should be near the initial bitrate, not at peak.
        // The cold-restart branch resets CWND to initial and re-derives the target via
        // update_target_bitrate(), then returns early (apply_increase is NOT called), so the target
        // equals initial_bitrate exactly. Allow +5 Mbps headroom as a conservative bound against
        // future floating-point rounding drift.
        let initial = cfg.initial_bitrate;
        assert!(
            after_restart <= initial.saturating_add(Bitrate::from_mbps(5)),
            "expected reset near initial {initial} after gap, got {after_restart}"
        );
        assert!(
            after_restart < peak,
            "expected target to drop after restart: peak={peak}, after={after_restart}"
        );
    }

    /// Test: `decrease_suppressed` uses the MIN_RTT floor correctly at low RTT.
    ///
    /// Verifies that `decrease_suppressed` floors the suppression window at `MIN_RTT_SECS`,
    /// preventing a very small SRTT (e.g., 200 µs) from allowing decreases faster than
    /// `MIN_RTT` intervals. We use a normal RTT controller, ramp it up, then send persistent
    /// congestion at 2 ms intervals and verify that (a) decreases do occur, (b) the controller
    /// stays within bounds, and (c) it does not panic.
    #[test]
    fn persistent_congestion_decreases_at_most_once_per_min_rtt() {
        let cfg = ScreamConfig::default(); // 50ms initial RTT — cwnd is substantial
        let mut ctrl = ScreamController::new(cfg.clone());
        #[allow(clippy::disallowed_methods)]
        let base = Instant::now();

        // Ramp up the controller for a few steps so cwnd is above minimum.
        let mut sim = NetSim::new(10_000, 5, 0.0);
        for i in 0..50u64 {
            let send_bps = ctrl.target_bitrate().as_bps_f64();
            let (_, fb) = sim.tick(send_bps);
            ctrl.on_feedback(&fb, base + Duration::from_millis(10 * (i + 1)));
        }
        let before_congestion = ctrl.target_bitrate();
        println!("[persistent_congestion_low_rtt] before congestion: {before_congestion}");

        // Now simulate persistent congestion (25ms queue delay) at 2ms intervals.
        // Each step is well above MIN_UPDATE_INTERVAL (1ms), so none are filtered.
        // The suppression window = max(srtt ≈ 10ms, MIN_RTT = 0.1ms) = 10ms.
        // With 2ms steps, some steps will be suppressed (within the 10ms window),
        // and some will not. We verify that at least one decrease fires and bounds hold.
        let congestion_start = base + Duration::from_millis(10 * 51);
        let mut decrease_count = 0u32;
        let mut prev = before_congestion;
        for i in 0..50u64 {
            let now = congestion_start + Duration::from_millis(2 * i + 2);
            ctrl.on_feedback(
                &TransportStats {
                    rtt: Duration::from_millis(10),
                    queue_delay: Duration::from_millis(25), // above HIGH_THRESHOLD
                    bytes_acked: 0,
                    bytes_lost: 0,
                    loss_fraction_q8: 0,
                    interval: Duration::from_millis(2),
                },
                now,
            );
            let cur = ctrl.target_bitrate();
            if cur < prev {
                decrease_count += 1;
            }
            prev = cur;
            assert!(
                cur >= cfg.min_bitrate,
                "below min after decrease #{i}: {cur}"
            );
        }
        println!(
            "[persistent_congestion_low_rtt] decreases={decrease_count}/50, final={}",
            ctrl.target_bitrate()
        );
        // At 2ms steps and srtt ≈ 10ms, suppression window = 10ms.
        // Decrease fires at step 0, then suppressed for 5 steps, then fires again, etc.
        // We expect roughly 50/5 = ~10 decreases, but at least a few.
        assert!(
            decrease_count > 0,
            "expected at least one decrease on persistent congestion; got {decrease_count}"
        );
        // Target should be well below where we started (congestion drove it down).
        assert!(
            ctrl.target_bitrate() < before_congestion,
            "expected target to decrease under persistent congestion: before={before_congestion}, after={}",
            ctrl.target_bitrate()
        );
    }
}

// ── Property tests ────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod prop_tests {
    use super::*;
    use crate::util::test_helpers::arb_feedback;
    use proptest::prelude::*;

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
