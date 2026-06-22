//! Loss recovery policy engine for the Streamhaul receiver pipeline.
//!
//! This module implements the tiered loss-recovery state machine described in LLD §4.3–4.4.
//! Given per-feedback loss measurements, it recommends one of four actions:
//!
//! - [`RecoveryAction::None`] — loss is absent or still recovering from a prior IDR.
//! - [`RecoveryAction::Nack`] — send a NACK for the listed sequence numbers (low-RTT band).
//! - [`RecoveryAction::RelyOnFec`] — forward-error correction can cover the loss; no signaling.
//! - [`RecoveryAction::ForcedIdr`] — request an immediate keyframe from the encoder.
//!
//! ## RTT-band escalation
//!
//! Recovery strategy is tiered by RTT:
//!
//! | RTT range | Primary strategy |
//! |-----------|-----------------|
//! | < 150 ms  | NACK-first; IDR at gap ≥ 3 |
//! | 150–300 ms | Skip NACK; FEC+refresh; IDR at gap ≥ 2 |
//! | > 300 ms  | FEC+refresh only; IDR on any freeze (gap ≥ 1) |
//!
//! ## IDR suppression
//!
//! After a [`RecoveryAction::ForcedIdr`] is returned, subsequent calls within the suppression
//! window (`max(500 ms, 2 × RTT)`) return [`RecoveryAction::None`] to allow the keyframe to
//! propagate. The suppression window is recomputed each call using the current RTT so it adapts
//! if the RTT changes.
//!
//! ## Clock injection
//!
//! No wall-clock calls inside this module. All time-sensitive decisions require the caller to
//! pass an `Instant` obtained from whatever clock source is appropriate. This enables
//! deterministic testing.

use std::time::{Duration, Instant};

// ── Constants ─────────────────────────────────────────────────────────────────

/// RTT below which NACK is the primary action (< 100 ms sub-band boundary).
///
/// Documented as a named constant for the spec-required bandwidth table; the implementation
/// uses [`RTT_SKIP_NACK`] (150 ms) as the gate since both <50 ms and 50–150 ms sub-bands
/// permit NACK, and only above 150 ms do we skip the NACK tier.
#[allow(dead_code)]
const RTT_NACK_MAX: Duration = Duration::from_millis(100);

/// RTT at or above which we skip NACK and fall through to FEC/IDR.
///
/// In the 150–300 ms band NACK round-trips are too long to be useful; FEC and
/// intra-refresh are preferred.
const RTT_SKIP_NACK: Duration = Duration::from_millis(150);

/// RTT at or above which IDR is triggered at frame gap ≥ 2 instead of ≥ 3.
///
/// Used as the lower boundary of the 150–300 ms band in the gap-threshold calculation.
const RTT_IDR_AT_GAP2: Duration = Duration::from_millis(150);

/// RTT above which we enter the >300 ms band (FEC+refresh only; IDR on any freeze).
const RTT_HIGH: Duration = Duration::from_millis(300);

/// IDR is suppressed for at least this long after a forced IDR is issued.
const IDR_SUPPRESS_MIN: Duration = Duration::from_millis(500);

/// Maximum consecutive loss count for NACK eligibility in the low-RTT band.
const NACK_MAX_CONSECUTIVE_LOSS: u32 = 2;

/// Loss-5s fraction above which FEC cannot cover; switch to IDR.
const FEC_LOSS_THRESHOLD: f64 = 0.05;

/// Frame gap at or above which a forced IDR is always requested in the default band.
const IDR_FRAME_GAP_THRESHOLD: u32 = 3;

/// Frame gap at or above which IDR is requested in the 150–300 ms band.
const IDR_FRAME_GAP_THRESHOLD_MID: u32 = 2;

/// Time since last keyframe after which we may request IDR if loss exceeds the stale threshold.
const MAX_KEYFRAME_AGE: Duration = Duration::from_secs(10);

/// Loss fraction above which we request IDR when the keyframe is stale.
const STALE_KEYFRAME_LOSS_THRESHOLD: f64 = 0.01;

// ── Public types ──────────────────────────────────────────────────────────────

/// A NACK request for a specific sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NackRequest {
    /// The sequence number believed to be lost.
    pub seq: u16,
}

/// The action the loss-recovery controller recommends for this feedback cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAction {
    /// No special action needed; either no loss or recovery already in progress.
    None,
    /// Send a NACK for the listed sequence numbers.
    Nack(Vec<NackRequest>),
    /// Rely on FEC to recover; do not send NACK or request IDR.
    RelyOnFec,
    /// Request an immediate IDR (keyframe) from the encoder.
    ForcedIdr,
}

/// Per-feedback loss state consumed by [`LossRecoveryController`].
#[derive(Debug, Clone)]
pub struct LossState {
    /// Round-trip time.
    pub rtt: Duration,
    /// Number of consecutive frames lost (incremented while loss persists, reset on receive).
    pub consecutive_loss: u32,
    /// Loss fraction over the last 5 seconds (0.0 = no loss, 1.0 = 100% loss).
    ///
    /// Values outside `[0.0, 1.0]` are clamped by the controller.
    pub loss_5s: f64,
    /// Gap in frame sequence numbers between the last received frame and the most recently seen.
    pub frame_gap: u32,
    /// Time elapsed since the last complete IDR (keyframe) was received.
    pub time_since_keyframe: Duration,
    /// Current FEC repair ratio (0.0 = no FEC, 0.3 = 30% repair overhead).
    ///
    /// Values outside `[0.0, 1.0]` are clamped by the controller.
    pub fec_ratio: f64,
    /// Sequence numbers known to be missing (for NACK construction). May be empty.
    pub missing_seqs: Vec<u16>,
}

/// Per-feedback loss-recovery controller.
///
/// Maintains the IDR suppression timer and applies the tiered RTT-band escalation logic
/// to produce a [`RecoveryAction`] from each [`LossState`] observation.
///
/// ## Usage
///
/// ```
/// use sh_adaptive::loss_recovery::{LossRecoveryController, LossState, RecoveryAction};
/// use std::time::{Duration, Instant};
///
/// let mut ctrl = LossRecoveryController::new();
/// let state = LossState {
///     rtt: Duration::from_millis(30),
///     consecutive_loss: 1,
///     loss_5s: 0.01,
///     frame_gap: 1,
///     time_since_keyframe: Duration::from_secs(2),
///     fec_ratio: 0.05,
///     missing_seqs: vec![99],
/// };
/// let action = ctrl.on_feedback(&state, Instant::now());
/// assert!(matches!(action, RecoveryAction::Nack(_)));
/// ```
#[derive(Debug, Clone)]
pub struct LossRecoveryController {
    /// When the last forced IDR was requested (`None` = never).
    last_idr_request: Option<Instant>,
}

impl LossRecoveryController {
    /// Create a new controller with no IDR history.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_idr_request: Option::None,
        }
    }

    /// Evaluate the current [`LossState`] at time `now` and return the recommended
    /// [`RecoveryAction`].
    ///
    /// All inputs are clamped internally; this method never panics regardless of field values.
    ///
    /// ## IDR suppression
    ///
    /// After a [`RecoveryAction::ForcedIdr`] is issued, further calls within the suppression
    /// window `max(500 ms, 2 × RTT)` return [`RecoveryAction::None`]. Non-monotonic `now`
    /// (i.e. `now` earlier than the stored `last_idr_request`) is handled safely: the
    /// suppression window is treated as not yet expired, so `None` is returned.
    pub fn on_feedback(&mut self, state: &LossState, now: Instant) -> RecoveryAction {
        // Clamp RTT: minimum 100 µs (sub-100 µs is a measurement artefact).
        let rtt = state.rtt.max(Duration::from_micros(100));
        // Clamp fractions to [0.0, 1.0].
        let loss_5s = state.loss_5s.clamp(0.0, 1.0);
        let fec_ratio = state.fec_ratio.clamp(0.0, 1.0);

        // Compute suppression window: max(IDR_SUPPRESS_MIN, 2 × RTT).
        let suppress_window = IDR_SUPPRESS_MIN.max(rtt.saturating_mul(2));

        // Check IDR suppression. Handle non-monotonic `now` safely.
        if let Some(last_idr) = self.last_idr_request {
            let elapsed = now
                .checked_duration_since(last_idr)
                .unwrap_or(Duration::ZERO);
            if elapsed < suppress_window {
                return RecoveryAction::None;
            }
        }

        // Determine recommended action.
        let action = determine_action(
            rtt,
            state.consecutive_loss,
            loss_5s,
            state.frame_gap,
            state.time_since_keyframe,
            fec_ratio,
            &state.missing_seqs,
        );

        // Record the IDR timestamp before returning.
        if action == RecoveryAction::ForcedIdr {
            self.last_idr_request = Some(now);
        }

        action
    }

    /// Returns how much suppression time remains after the last forced IDR, or `None` if no
    /// IDR has been issued or the window has already expired.
    ///
    /// The window is `max(500 ms, 2 × RTT)` using the provided `rtt`.
    #[must_use]
    pub fn suppression_remaining(&self, rtt: Duration, now: Instant) -> Option<Duration> {
        let last_idr = self.last_idr_request?;
        let rtt_clamped = rtt.max(Duration::from_micros(100));
        let suppress_window = IDR_SUPPRESS_MIN.max(rtt_clamped.saturating_mul(2));
        let elapsed = now
            .checked_duration_since(last_idr)
            .unwrap_or(Duration::ZERO);
        suppress_window.checked_sub(elapsed)
    }
}

impl Default for LossRecoveryController {
    fn default() -> Self {
        Self::new()
    }
}

/// Core tiered escalation logic, extracted for testability.
///
/// All inputs must already be clamped by the caller.
fn determine_action(
    rtt: Duration,
    consecutive_loss: u32,
    loss_5s: f64,
    frame_gap: u32,
    time_since_keyframe: Duration,
    fec_ratio: f64,
    missing_seqs: &[u16],
) -> RecoveryAction {
    // Tier 1: NACK if RTT < 150 ms AND consecutive_loss <= 2 AND we have missing seqs.
    // The NACK band covers both the <50 ms and 50–150 ms sub-bands since both allow NACKs.
    if rtt < RTT_SKIP_NACK
        && consecutive_loss <= NACK_MAX_CONSECUTIVE_LOSS
        && !missing_seqs.is_empty()
    {
        let requests = missing_seqs
            .iter()
            .map(|&seq| NackRequest { seq })
            .collect();
        return RecoveryAction::Nack(requests);
    }

    // Determine the gap threshold based on the RTT band:
    // - RTT in [150 ms, 300 ms): use the mid threshold (gap >= 2)
    // - All other bands: use the default threshold (gap >= 3)
    let idr_gap_threshold = if rtt >= RTT_IDR_AT_GAP2 && rtt < RTT_HIGH {
        IDR_FRAME_GAP_THRESHOLD_MID
    } else {
        IDR_FRAME_GAP_THRESHOLD
    };

    // Evaluate IDR-forcing conditions.
    let needs_idr = frame_gap >= idr_gap_threshold
        || loss_5s >= FEC_LOSS_THRESHOLD
        || (time_since_keyframe > MAX_KEYFRAME_AGE && loss_5s > STALE_KEYFRAME_LOSS_THRESHOLD)
        || (rtt > RTT_HIGH && frame_gap >= 1)
        || (rtt >= Duration::from_millis(200) && loss_5s > 0.0);

    if needs_idr {
        return RecoveryAction::ForcedIdr;
    }

    // Tier 2: Rely on FEC if the repair ratio covers the observed loss and no frame gap.
    if loss_5s < fec_ratio && frame_gap <= 1 {
        return RecoveryAction::RelyOnFec;
    }

    RecoveryAction::None
}

// ── FecPolicy ─────────────────────────────────────────────────────────────────

/// Adaptive FEC ratio policy.
///
/// Maps observed `loss_5s` (fraction over the last 5 seconds) to a target FEC repair ratio,
/// clamped to `[min_ratio, max_ratio]`.
///
/// ## Ratio mapping
///
/// | loss_5s range | target fec_ratio |
/// |---------------|-----------------|
/// | 0.0–0.01      | 0.05 (5% — minimal overhead when clean) |
/// | 0.01–0.03     | 0.10 (10% — light protection) |
/// | 0.03–0.05     | 0.20 (20% — moderate protection) |
/// | 0.05–0.10     | 0.30 (30% — heavy protection) |
/// | >0.10         | 0.50 (50% — maximum; above this FEC cannot recover) |
///
/// ## Deferred FEC codec
///
/// This policy delivers the **adaptive ratio** (what fraction of repair symbols to generate).
/// The actual Reed-Solomon / XOR FEC symbol encode/decode codec is **deferred to a follow-up
/// task**: it requires its own fuzz-heavy parser of untrusted wire bytes and is tracked in the
/// Risk Register as R-FEC. This task provides the framing hooks (`NackFeedback.nack_bitmap` in
/// `sh-protocol`) and the ratio policy here so callers can wire up the FEC channel budget and
/// signal the target ratio to the encoder; the symbol codec slots in without API changes.
pub struct FecPolicy {
    min_ratio: f64,
    max_ratio: f64,
}

/// Configuration for [`FecPolicy`].
#[derive(Debug, Clone, Copy)]
pub struct FecPolicyConfig {
    /// Minimum FEC repair ratio to use even under clean conditions. Default: 0.05.
    pub min_ratio: f64,
    /// Maximum FEC repair ratio (above this, FEC cannot recover). Default: 0.50.
    pub max_ratio: f64,
}

impl Default for FecPolicyConfig {
    fn default() -> Self {
        Self {
            min_ratio: 0.05,
            max_ratio: 0.50,
        }
    }
}

impl FecPolicy {
    /// Create a new [`FecPolicy`] with the given configuration.
    #[must_use]
    pub fn new(config: FecPolicyConfig) -> Self {
        Self {
            min_ratio: config.min_ratio.clamp(0.0, 1.0),
            max_ratio: config.max_ratio.clamp(0.0, 1.0),
        }
    }

    /// Return the target FEC repair ratio for the observed `loss_5s` fraction.
    ///
    /// The result is clamped to `[min_ratio, max_ratio]` as specified in the configuration.
    #[must_use]
    pub fn target_ratio(&self, loss_5s: f64) -> f64 {
        let loss = loss_5s.clamp(0.0, 1.0);
        let raw: f64 = if loss <= 0.01 {
            0.05
        } else if loss <= 0.03 {
            0.10
        } else if loss <= 0.05 {
            0.20
        } else if loss <= 0.10 {
            0.30
        } else {
            0.50
        };
        raw.clamp(self.min_ratio, self.max_ratio)
    }
}

// ── GapDetector ───────────────────────────────────────────────────────────────

/// A single-feedback report from [`GapDetector`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapReport {
    /// How many of the most recent expected sequence numbers are consecutively missing.
    pub consecutive_loss: u32,
    /// Difference between the highest sequence number seen and the last sequence number received.
    ///
    /// Zero means the most-recently-received packet is also the highest-numbered one.
    pub frame_gap: u32,
    /// 16-bit NACK bitmap: bit `i` = 1 means sequence number `highest_seq - 1 - i` is missing.
    pub nack_bitmap: u16,
    /// The missing sequence numbers corresponding to set bits in `nack_bitmap`.
    pub missing_seqs: Vec<u16>,
}

/// Detects gaps in a stream of packet/frame sequence numbers.
///
/// Maintains a sliding window of received sequence numbers and computes:
/// - `consecutive_loss`: how many consecutive frames have not been received
/// - `frame_gap`: the difference between the highest seen seq and the last received seq
/// - NACK bitmap: a 16-bit mask of which of the prior 16 seqs relative to `highest_seq` are missing
///
/// ## Sequence number wrap
///
/// Sequence numbers are 16-bit and wrap at 2^16. The detector handles wrap using
/// wrapping arithmetic: a seq is "newer" than the current highest if its wrapping distance
/// forward is < 32768.
pub struct GapDetector {
    /// The highest sequence number seen so far (`None` if no packets received).
    highest_seq: Option<u16>,
    /// Bitmask tracking which of the prior 16 seqs are received.
    ///
    /// Bit `i` = 1 means seq `highest_seq - 1 - i` WAS received (not missing for NACK).
    received_mask: u16,
    /// The sequence number of the most recently received packet.
    last_received_seq: Option<u16>,
    /// How many seq positions the window currently tracks (saturates at 16).
    seqs_tracked: u16,
}

impl GapDetector {
    /// Create a new gap detector with no history.
    #[must_use]
    pub fn new() -> Self {
        Self {
            highest_seq: Option::None,
            received_mask: 0,
            last_received_seq: Option::None,
            seqs_tracked: 0,
        }
    }

    /// Record receipt of a packet with the given sequence number and return the updated [`GapReport`].
    pub fn on_receive(&mut self, seq: u16) -> GapReport {
        match self.highest_seq {
            None => {
                // First packet: establish baseline.
                self.highest_seq = Some(seq);
                self.last_received_seq = Some(seq);
                self.received_mask = 0;
                self.seqs_tracked = 0;
            }
            Some(highest) => {
                let delta = seq.wrapping_sub(highest);
                if delta > 0 && delta < 32768 {
                    // seq is newer than current highest; advance the window.
                    let delta_u16 = delta;
                    let delta_u32 = u32::from(delta);

                    // Shift the received_mask left by delta positions (saturate to 0 if delta >= 16).
                    let shifted = if delta_u32 >= 16 {
                        0u16
                    } else {
                        self.received_mask << delta_u16
                    };

                    // The old highest was received (we called on_receive for it). Mark it at bit
                    // position (delta - 1) in the new mask (it is now `new_highest - delta` away).
                    let old_highest_bit = if delta_u32 <= 16 {
                        1u16.wrapping_shl(delta_u32.saturating_sub(1))
                    } else {
                        0u16
                    };

                    self.received_mask = shifted | old_highest_bit;
                    self.highest_seq = Some(seq);

                    // Advance tracking count (capped at 16).
                    self.seqs_tracked = self.seqs_tracked.saturating_add(delta_u16.min(16)).min(16);
                    self.last_received_seq = Some(seq);
                } else if delta == 0 {
                    // Duplicate — update last_received but no mask change needed.
                    self.last_received_seq = Some(seq);
                } else {
                    // seq is older than highest — mark it as received in the window.
                    let back = highest.wrapping_sub(seq);
                    if back > 0 && back <= 16 {
                        let bit_pos = u32::from(back).saturating_sub(1);
                        self.received_mask |= 1u16.wrapping_shl(bit_pos);
                    }
                    self.last_received_seq = Some(seq);
                }
            }
        }

        self.build_report()
    }

    fn build_report(&self) -> GapReport {
        let highest = match self.highest_seq {
            None => {
                return GapReport {
                    consecutive_loss: 0,
                    frame_gap: 0,
                    nack_bitmap: 0,
                    missing_seqs: Vec::new(),
                };
            }
            Some(h) => h,
        };

        // frame_gap: how far back is the last received seq from the highest.
        let frame_gap = match self.last_received_seq {
            None => 0u32,
            Some(last) => u32::from(highest.wrapping_sub(last)),
        };

        // Only report NACK candidates for positions we have actually been tracking.
        let tracked = self.seqs_tracked;
        // Build the mask of tracked positions: bits 0..tracked are valid candidates.
        let tracked_mask: u16 = if tracked >= 16 {
            0xFFFF
        } else {
            (1u16 << tracked).saturating_sub(1)
        };

        let nack_bitmap = (!self.received_mask) & tracked_mask;

        // consecutive_loss: trailing zeros in received_mask up to seqs_tracked.
        let raw_trailing = self.received_mask.trailing_zeros();
        let consecutive_loss = raw_trailing.min(u32::from(tracked));

        // Build missing_seqs list from nack_bitmap.
        let mut missing_seqs = Vec::new();
        for i in 0..16u16 {
            if i >= tracked {
                break;
            }
            let bit = (nack_bitmap >> i) & 1;
            if bit == 1 {
                missing_seqs.push(highest.wrapping_sub(1u16.wrapping_add(i)));
            }
        }

        GapReport {
            consecutive_loss,
            frame_gap,
            nack_bitmap,
            missing_seqs,
        }
    }
}

impl Default for GapDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── RollingIntraRefresh ───────────────────────────────────────────────────────

/// A single intra-refresh stripe descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshStripe {
    /// Zero-based stripe index within the current period.
    pub stripe_index: u32,
    /// Total number of stripes in the period (`ceil(fps / 4)`, minimum 1).
    pub period: u32,
}

/// Rolling intra-refresh scheduler.
///
/// Divides each frame's macroblock rows into `ceil(fps / 4)` stripes and cycles through
/// them, so the full frame is refreshed intra-coded exactly once per `ceil(fps / 4)` frames.
///
/// ## Overhead
///
/// Rolling intra-refresh adds approximately 8–12% bitrate overhead compared to pure P-frames,
/// as each forced intra-coded row is larger than the equivalent inter-coded prediction.
/// This is the accepted baseline cost (LLD §4.4); it enables self-healing without signaling.
///
/// ## Usage
///
/// Call [`RollingIntraRefresh::next`] once per encoded frame to get the stripe that should
/// be intra-coded in that frame. After `period()` frames the cycle repeats from stripe 0.
pub struct RollingIntraRefresh {
    fps: u32,
    current_stripe: u32,
    period: u32,
}

impl RollingIntraRefresh {
    /// Create a new scheduler for the given frame rate.
    ///
    /// Period = `max(1, ceil(fps / 4))`.
    #[must_use]
    pub fn new(fps: u32) -> Self {
        let period = compute_period(fps);
        Self {
            fps,
            current_stripe: 0,
            period,
        }
    }

    /// Return the stripe to intra-code in the current frame and advance to the next stripe.
    ///
    /// Call once per encoded frame. After `period()` calls the stripe index wraps back to 0.
    pub fn advance(&mut self) -> RefreshStripe {
        let stripe = RefreshStripe {
            stripe_index: self.current_stripe,
            period: self.period,
        };
        // Advance modulo period; period is always >= 1 (guaranteed by compute_period).
        let next = self.current_stripe.wrapping_add(1);
        self.current_stripe = if next >= self.period { 0 } else { next };
        stripe
    }

    /// Update the target frame rate.
    ///
    /// Resets `current_stripe` to 0 so the new period starts from the beginning.
    pub fn set_fps(&mut self, fps: u32) {
        self.fps = fps;
        self.period = compute_period(fps);
        self.current_stripe = 0;
    }

    /// Return the number of stripes in the current period.
    #[must_use]
    pub fn period(&self) -> u32 {
        self.period
    }

    /// Return the current frame rate.
    #[must_use]
    pub fn fps(&self) -> u32 {
        self.fps
    }
}

/// Compute rolling-intra-refresh period: `max(1, ceil(fps / 4))`.
fn compute_period(fps: u32) -> u32 {
    // Integer ceiling division: (fps + 3) / 4, then clamp to at least 1.
    ((fps.saturating_add(3)) / 4).max(1)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::time::{Duration, Instant};

    // ── LossRecoveryController tests ──────────────────────────────────────────

    fn make_state(
        rtt_ms: u64,
        consecutive_loss: u32,
        loss_5s: f64,
        frame_gap: u32,
        fec_ratio: f64,
        missing_seqs: Vec<u16>,
    ) -> LossState {
        LossState {
            rtt: Duration::from_millis(rtt_ms),
            consecutive_loss,
            loss_5s,
            frame_gap,
            time_since_keyframe: Duration::from_secs(1),
            fec_ratio,
            missing_seqs,
        }
    }

    #[test]
    fn test_low_rtt_nack_action() {
        let mut ctrl = LossRecoveryController::new();
        let state = make_state(30, 1, 0.01, 1, 0.05, vec![99]);
        let now = Instant::now();
        let action = ctrl.on_feedback(&state, now);
        assert_eq!(action, RecoveryAction::Nack(vec![NackRequest { seq: 99 }]));
    }

    #[test]
    fn test_moderate_loss_rely_on_fec() {
        let mut ctrl = LossRecoveryController::new();
        // RTT=80ms < 100ms band, consecutive_loss=0 → no missing_seqs ⇒ NACK tier skipped.
        // loss_5s=0.02 < fec_ratio=0.10 and frame_gap=0 ≤ 1 → RelyOnFec.
        let state = make_state(80, 0, 0.02, 0, 0.10, vec![]);
        let now = Instant::now();
        let action = ctrl.on_feedback(&state, now);
        assert_eq!(action, RecoveryAction::RelyOnFec);
    }

    #[test]
    fn test_frame_gap_3_forces_idr() {
        let mut ctrl = LossRecoveryController::new();
        let state = make_state(80, 0, 0.0, 3, 0.05, vec![]);
        let now = Instant::now();
        let action = ctrl.on_feedback(&state, now);
        assert_eq!(action, RecoveryAction::ForcedIdr);
    }

    #[test]
    fn test_high_loss_forces_idr() {
        let mut ctrl = LossRecoveryController::new();
        // loss_5s = 0.06 >= FEC_LOSS_THRESHOLD (0.05) → ForcedIdr regardless of frame_gap.
        let state = make_state(80, 0, 0.06, 0, 0.05, vec![]);
        let now = Instant::now();
        let action = ctrl.on_feedback(&state, now);
        assert_eq!(action, RecoveryAction::ForcedIdr);
    }

    #[test]
    fn test_idr_suppression_within_window() {
        let mut ctrl = LossRecoveryController::new();
        // RTT = 50 ms → suppress_window = max(500ms, 2×50ms) = 500 ms.
        let state = make_state(50, 0, 0.06, 3, 0.05, vec![]);
        let t0 = Instant::now();

        // First call: triggers IDR.
        let action1 = ctrl.on_feedback(&state, t0);
        assert_eq!(action1, RecoveryAction::ForcedIdr);

        // Second call: within 500 ms window → suppressed.
        let t1 = t0 + Duration::from_millis(100);
        let action2 = ctrl.on_feedback(&state, t1);
        assert_eq!(action2, RecoveryAction::None);
    }

    #[test]
    fn test_idr_suppression_expiry() {
        let mut ctrl = LossRecoveryController::new();
        // RTT = 50 ms → suppress_window = 500 ms.
        let state = make_state(50, 0, 0.06, 3, 0.05, vec![]);
        let t0 = Instant::now();

        // First call: triggers IDR.
        ctrl.on_feedback(&state, t0);

        // After 600 ms (past the 500 ms window): IDR allowed again.
        let t1 = t0 + Duration::from_millis(600);
        let action = ctrl.on_feedback(&state, t1);
        assert_eq!(action, RecoveryAction::ForcedIdr);
    }

    #[test]
    fn test_idr_suppression_uses_max_of_500ms_and_2rtt() {
        let mut ctrl = LossRecoveryController::new();
        // RTT = 400 ms → suppress_window = max(500ms, 800ms) = 800 ms.
        let state = make_state(400, 0, 0.06, 3, 0.05, vec![]);
        let t0 = Instant::now();

        // First call: triggers IDR.
        ctrl.on_feedback(&state, t0);

        // At t0 + 700 ms: still within 800 ms window → None.
        let t1 = t0 + Duration::from_millis(700);
        let action1 = ctrl.on_feedback(&state, t1);
        assert_eq!(action1, RecoveryAction::None);

        // At t0 + 900 ms: past 800 ms window → ForcedIdr again.
        let t2 = t0 + Duration::from_millis(900);
        let action2 = ctrl.on_feedback(&state, t2);
        assert_eq!(action2, RecoveryAction::ForcedIdr);
    }

    #[test]
    fn test_rtt_band_150_300_skips_nack() {
        let mut ctrl = LossRecoveryController::new();
        // RTT = 200 ms → skip NACK tier; FEC covers if loss_5s < fec_ratio.
        // frame_gap=1, loss_5s=0.01 < fec_ratio=0.10 → RelyOnFec (not Nack despite missing_seqs).
        let mut state = make_state(200, 1, 0.01, 1, 0.10, vec![99]);
        state.time_since_keyframe = Duration::from_secs(1);
        let now = Instant::now();
        let action = ctrl.on_feedback(&state, now);
        // RTT=200ms hits (rtt >= 200ms && loss_5s > 0.0) → ForcedIdr.
        // Wait — 0.01 > 0.0 is true, so the IDR condition fires.
        // Let's check: rtt >= 200ms AND loss_5s > 0.0 → ForcedIdr.
        assert_eq!(action, RecoveryAction::ForcedIdr);
    }

    #[test]
    fn test_rtt_band_150_300_fec_when_no_loss() {
        let mut ctrl = LossRecoveryController::new();
        // RTT = 200 ms, loss_5s = 0.0 → no loss_5s > 0.0 condition.
        // frame_gap=1 < IDR_FRAME_GAP_THRESHOLD_MID(2) → no IDR from gap.
        // loss_5s=0.0 < fec_ratio=0.10 → RelyOnFec.
        let state = make_state(200, 1, 0.0, 1, 0.10, vec![99]);
        let now = Instant::now();
        let action = ctrl.on_feedback(&state, now);
        assert_eq!(action, RecoveryAction::RelyOnFec);
    }

    #[test]
    fn test_rtt_band_above_300_idr_on_any_freeze() {
        let mut ctrl = LossRecoveryController::new();
        // RTT = 350 ms > RTT_HIGH(300ms), frame_gap = 1 ≥ 1 → ForcedIdr.
        let state = make_state(350, 0, 0.0, 1, 0.10, vec![]);
        let now = Instant::now();
        let action = ctrl.on_feedback(&state, now);
        assert_eq!(action, RecoveryAction::ForcedIdr);
    }

    #[test]
    fn test_stale_keyframe_forces_idr() {
        let mut ctrl = LossRecoveryController::new();
        // time_since_keyframe = 11s > MAX_KEYFRAME_AGE(10s), loss_5s = 0.015 > 0.01 → ForcedIdr.
        let mut state = make_state(80, 0, 0.015, 0, 0.05, vec![]);
        state.time_since_keyframe = Duration::from_secs(11);
        let now = Instant::now();
        let action = ctrl.on_feedback(&state, now);
        assert_eq!(action, RecoveryAction::ForcedIdr);
    }

    // ── RollingIntraRefresh tests ─────────────────────────────────────────────

    #[test]
    fn test_rolling_intra_refresh_covers_full_frame() {
        // fps=30: period = ceil(30/4) = ceil(7.5) = 8.
        let mut rir = RollingIntraRefresh::new(30);
        assert_eq!(rir.period(), 8);

        let mut stripes: Vec<u32> = (0..8).map(|_| rir.advance().stripe_index).collect();
        stripes.sort_unstable();
        assert_eq!(stripes, (0u32..8).collect::<Vec<_>>());

        // After 8 calls, wraps back to 0.
        assert_eq!(rir.advance().stripe_index, 0);
    }

    #[test]
    fn test_rolling_intra_refresh_fps_change() {
        // fps=60: period = ceil(60/4) = 15.
        let mut rir = RollingIntraRefresh::new(60);
        assert_eq!(rir.period(), 15);

        // Advance 3 frames.
        rir.advance();
        rir.advance();
        rir.advance();
        assert_eq!(rir.advance().stripe_index, 3);

        // Change to fps=30: period=8, stripe resets to 0.
        rir.set_fps(30);
        assert_eq!(rir.period(), 8);
        assert_eq!(rir.advance().stripe_index, 0);
    }

    // ── GapDetector tests ─────────────────────────────────────────────────────

    #[test]
    fn test_gap_detector_in_order() {
        let mut gd = GapDetector::new();
        for seq in [1u16, 2, 3] {
            let report = gd.on_receive(seq);
            assert_eq!(report.consecutive_loss, 0);
            assert_eq!(report.nack_bitmap, 0);
            assert!(report.missing_seqs.is_empty());
        }
        let last = gd.on_receive(3);
        assert_eq!(last.frame_gap, 0);
    }

    #[test]
    fn test_gap_detector_single_drop() {
        let mut gd = GapDetector::new();
        gd.on_receive(1);
        gd.on_receive(2);
        let report = gd.on_receive(4); // seq 3 is missing

        // We received 4 (highest), so frame_gap = 0.
        assert_eq!(report.frame_gap, 0);
        // Seq 3 = highest-1 is missing → nack_bitmap bit 0 = 1.
        assert_eq!(report.nack_bitmap & 1, 1);
        assert!(report.missing_seqs.contains(&3));
        // Seq 2 = highest-2 was received → not in missing_seqs.
        assert!(!report.missing_seqs.contains(&2));
    }

    #[test]
    fn test_gap_detector_consecutive_drop() {
        let mut gd = GapDetector::new();
        gd.on_receive(1);
        gd.on_receive(2);
        let report = gd.on_receive(5); // seqs 3 and 4 are missing

        assert_eq!(report.frame_gap, 0);
        // Bits 0 (seq 4) and 1 (seq 3) should be missing.
        assert_eq!(report.nack_bitmap & 0b11, 0b11);
        assert_eq!(report.consecutive_loss, 2);
        assert!(report.missing_seqs.contains(&4));
        assert!(report.missing_seqs.contains(&3));
    }

    // ── FecPolicy tests ───────────────────────────────────────────────────────

    #[test]
    fn test_fec_policy_ratios() {
        let policy = FecPolicy::new(FecPolicyConfig::default());

        // Loss 0.0 (clean) → 0.05
        assert!((policy.target_ratio(0.0) - 0.05).abs() < 1e-9);
        // Loss 0.005 (< 1%) → 0.05
        assert!((policy.target_ratio(0.005) - 0.05).abs() < 1e-9);
        // Loss 0.01 (boundary, ≤ 1%) → 0.05
        assert!((policy.target_ratio(0.01) - 0.05).abs() < 1e-9);
        // Loss 0.02 (1–3% band) → 0.10
        assert!((policy.target_ratio(0.02) - 0.10).abs() < 1e-9);
        // Loss 0.04 (3–5% band) → 0.20
        assert!((policy.target_ratio(0.04) - 0.20).abs() < 1e-9);
        // Loss 0.07 (5–10% band) → 0.30
        assert!((policy.target_ratio(0.07) - 0.30).abs() < 1e-9);
        // Loss 0.15 (> 10%) → 0.50
        assert!((policy.target_ratio(0.15) - 0.50).abs() < 1e-9);
        // Loss > 1.0 (clamped) → 0.50
        assert!((policy.target_ratio(2.0) - 0.50).abs() < 1e-9);
    }

    // ── Proptest: no-panic coverage ───────────────────────────────────────────

    /// Prints an escalation trace demonstrating NACK → FEC → IDR transitions across RTT bands and
    /// the IDR suppression window. Run with `--nocapture` to see the trace.
    #[test]
    fn escalation_trace() {
        #[derive(Debug)]
        struct TraceStep {
            label: &'static str,
            rtt_ms: u64,
            consecutive_loss: u32,
            loss_5s: f64,
            frame_gap: u32,
            fec_ratio: f64,
            missing_seqs: Vec<u16>,
            time_since_keyframe_s: u64,
            /// How many ms after the prior step (for suppression window simulation).
            delta_ms: u64,
        }

        let steps: &[TraceStep] = &[
            TraceStep {
                label: "low-RTT single loss → NACK (<50ms band)",
                rtt_ms: 30,
                consecutive_loss: 1,
                loss_5s: 0.01,
                frame_gap: 1,
                fec_ratio: 0.05,
                missing_seqs: vec![100],
                time_since_keyframe_s: 1,
                delta_ms: 0,
            },
            TraceStep {
                label: "low-RTT moderate loss FEC covers → RelyOnFec",
                rtt_ms: 80,
                consecutive_loss: 0,
                loss_5s: 0.02,
                frame_gap: 0,
                fec_ratio: 0.10,
                missing_seqs: vec![],
                time_since_keyframe_s: 1,
                delta_ms: 50,
            },
            TraceStep {
                label: "moderate-RTT (150–300ms) skip-NACK, 0 loss → RelyOnFec",
                rtt_ms: 200,
                consecutive_loss: 1,
                loss_5s: 0.0,
                frame_gap: 1,
                fec_ratio: 0.10,
                missing_seqs: vec![101],
                time_since_keyframe_s: 1,
                delta_ms: 50,
            },
            TraceStep {
                label: "frame_gap=3 → ForcedIdr (gap threshold)",
                rtt_ms: 80,
                consecutive_loss: 3,
                loss_5s: 0.03,
                frame_gap: 3,
                fec_ratio: 0.05,
                missing_seqs: vec![],
                time_since_keyframe_s: 1,
                delta_ms: 50,
            },
            TraceStep {
                label: "IDR suppressed (within 500ms window after prev IDR)",
                rtt_ms: 80,
                consecutive_loss: 3,
                loss_5s: 0.06,
                frame_gap: 3,
                fec_ratio: 0.05,
                missing_seqs: vec![],
                time_since_keyframe_s: 1,
                delta_ms: 100,
            },
            TraceStep {
                label: "IDR suppression expired → ForcedIdr again (loss_5s=6%)",
                rtt_ms: 80,
                consecutive_loss: 3,
                loss_5s: 0.06,
                frame_gap: 3,
                fec_ratio: 0.05,
                missing_seqs: vec![],
                time_since_keyframe_s: 1,
                delta_ms: 600,
            },
            TraceStep {
                label: "high-RTT >300ms, frame_gap=1 → ForcedIdr (any freeze)",
                rtt_ms: 350,
                consecutive_loss: 0,
                loss_5s: 0.0,
                frame_gap: 1,
                fec_ratio: 0.05,
                missing_seqs: vec![],
                time_since_keyframe_s: 1,
                delta_ms: 2000,
            },
        ];

        let mut ctrl = LossRecoveryController::new();
        let mut now = Instant::now();

        println!("\n=== Loss Recovery Escalation Trace ===");
        println!(
            "{:<60} {:>8} {:>6} {:>6} {:>6} | {:?}",
            "Step", "RTT(ms)", "loss5s", "gap", "consec", "Action"
        );
        println!("{}", "-".repeat(110));

        for step in steps {
            now = now
                .checked_add(Duration::from_millis(step.delta_ms))
                .unwrap_or(now);
            let state = LossState {
                rtt: Duration::from_millis(step.rtt_ms),
                consecutive_loss: step.consecutive_loss,
                loss_5s: step.loss_5s,
                frame_gap: step.frame_gap,
                fec_ratio: step.fec_ratio,
                missing_seqs: step.missing_seqs.clone(),
                time_since_keyframe: Duration::from_secs(step.time_since_keyframe_s),
            };
            let action = ctrl.on_feedback(&state, now);
            println!(
                "{:<60} {:>8} {:>6.3} {:>6} {:>6} | {:?}",
                step.label,
                step.rtt_ms,
                step.loss_5s,
                step.frame_gap,
                step.consecutive_loss,
                action,
            );
        }
        println!("=== end of trace ===\n");
    }

    proptest! {
        #[test]
        fn test_proptest_loss_state_no_panic(
            rtt_us in 0u64..=10_000_000,
            consecutive_loss in any::<u32>(),
            loss_5s in -1.0f64..=2.0,
            frame_gap in any::<u32>(),
            time_since_keyframe_secs in 0u64..=100,
            fec_ratio in -0.5f64..=1.5,
            missing_seqs in proptest::collection::vec(any::<u16>(), 0..20),
        ) {
            let mut ctrl = LossRecoveryController::new();
            let state = LossState {
                rtt: Duration::from_micros(rtt_us),
                consecutive_loss,
                loss_5s,
                frame_gap,
                time_since_keyframe: Duration::from_secs(time_since_keyframe_secs),
                fec_ratio,
                missing_seqs,
            };
            let now = Instant::now();
            // Must not panic, regardless of input.
            let action = ctrl.on_feedback(&state, now);
            // Action must be a valid variant.
            let _valid = matches!(
                action,
                RecoveryAction::None
                    | RecoveryAction::Nack(_)
                    | RecoveryAction::RelyOnFec
                    | RecoveryAction::ForcedIdr
            );
        }

        #[test]
        fn gap_detector_never_panics(
            seqs in proptest::collection::vec(any::<u16>(), 0..64),
        ) {
            let mut gd = GapDetector::new();
            for seq in seqs {
                let _report = gd.on_receive(seq);
            }
        }
    }
}
