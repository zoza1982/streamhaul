//! Shared utility constants, clamping helpers, and test infrastructure for
//! congestion controllers.

use std::time::Duration;

// ── Shared timing constants ────────────────────────────────────────────────────

/// Minimum plausible RTT. Sub-100 µs RTT is a measurement artefact; clamp up to this.
pub(crate) const MIN_RTT: Duration = Duration::from_micros(100);

/// Maximum RTT we trust. Above this the link is either very congested or the measurement is wrong.
pub(crate) const MAX_RTT: Duration = Duration::from_secs(10);

/// Maximum queue delay we trust from the transport layer.
pub(crate) const MAX_QUEUE_DELAY: Duration = Duration::from_secs(2);

/// Minimum RTT in seconds. Used as floor for the decrease-suppression window.
pub(crate) const MIN_RTT_SECS: f64 = 0.000_100;

// ── Shared clamping helpers ───────────────────────────────────────────────────

/// Clamp an RTT to `[MIN_RTT, MAX_RTT]`.
#[inline]
pub(crate) fn clamp_rtt(rtt: Duration) -> Duration {
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
pub(crate) fn clamp_duration(d: Duration, max: Duration) -> Duration {
    if d > max {
        max
    } else {
        d
    }
}

// ── Shared test helpers ───────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
pub(crate) mod test_helpers {
    use super::MAX_QUEUE_DELAY;
    use crate::TransportStats;
    use proptest::prelude::*;
    use std::time::{Duration, Instant};

    /// A network simulator with an accumulating bottleneck queue model.
    ///
    /// Tracks a virtual queue in bytes that fills when send rate exceeds the link capacity and
    /// drains at line rate. Queue delay is computed as queue_bytes / drain_rate. Tail-drop
    /// occurs when the queue exceeds `max_queue_bytes` (≈200 ms of buffering at cap).
    pub(crate) struct NetSim {
        /// Available bandwidth (bits per second).
        pub(crate) cap_bps: f64,
        /// Fixed propagation delay (one-way); RTT = 2 × prop_delay.
        pub(crate) prop_delay: Duration,
        /// Fractional packet loss rate (0.0 = no loss, 1.0 = 100% loss).
        pub(crate) loss_rate: f64,
        /// Synthetic clock: monotonically incremented.
        pub(crate) clock: Instant,
        /// Clock step per simulated feedback interval.
        pub(crate) step: Duration,
        /// Accumulated bottleneck queue in bytes.
        pub(crate) queue_bytes: f64,
        /// Maximum buffer before tail-drop (bytes). At cap, ≈200 ms of buffering.
        pub(crate) max_queue_bytes: f64,
    }

    impl NetSim {
        pub(crate) fn new(cap_kbps: u64, prop_delay_ms: u64, loss_rate: f64) -> Self {
            // Instant::now() is allowed in tests; the controller itself never calls it.
            #[allow(clippy::disallowed_methods)]
            let clock = Instant::now();
            let cap_bps = f64::from(u32::try_from(cap_kbps).unwrap_or(u32::MAX)) * 1_000.0;
            // 200 ms buffer at cap
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
        pub(crate) fn tick(&mut self, send_rate_bps: f64) -> (Instant, TransportStats) {
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

    /// Strategy: generate arbitrary (bounded) `TransportStats` values, including adversarial ones.
    pub(crate) fn arb_feedback() -> impl Strategy<Value = TransportStats> {
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
}
