//! [`TransportStats`] — the per-feedback input consumed by a [`CongestionController`].
//!
//! This struct is the shared feedback seam between `sh-transport` (which measures the network)
//! and `sh-adaptive` (which reacts to it). It is designed so both **SCReAM** (native/QUIC path)
//! and **GCC** (WebRTC path, Phase 4) can consume the same structure.
//!
//! [`CongestionController`]: crate::CongestionController

use std::time::Duration;

/// Per-feedback statistics delivered from the transport layer to a [`CongestionController`].
///
/// A feedback report is generated periodically (typically every 5–50 ms) by the transport layer
/// based on receiver reports, ACKs, or RTCP packets. The controller uses these measurements to
/// adjust its congestion window and target bitrate.
///
/// ## Units
///
/// All `Duration` fields use `std::time::Duration`. Zero-duration values are valid inputs; the
/// controller must handle them without panicking (see [`ScreamController`] clamping guarantees).
///
/// ## Degenerate inputs
///
/// The controller clamps / ignores invalid combinations (e.g. `bytes_lost > bytes_acked`). Callers
/// should fill only the fields that their transport can actually measure; leaving a field at its
/// `Default` value is safe.
///
/// [`ScreamController`]: crate::ScreamController
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportStats {
    /// Round-trip time (RTT) sample for this feedback epoch.
    ///
    /// **Source:** in-path ACK timestamps or RTCP SR/RR round-trip measurement (RFC 3550 §6.4).
    ///
    /// **Clamping:** values below 100 µs are treated as 100 µs by the controller (sub-100 µs RTT
    /// is physically implausible on a LAN and most likely a measurement artefact); values above
    /// 10 s are treated as 10 s to prevent runaway state.
    pub rtt: Duration,

    /// One-way queuing delay measured at the receiver relative to the reference (minimum) delay.
    ///
    /// **Source:** the difference between the current one-way path delay and the historical minimum
    /// one-way delay (i.e. the *base delay* observed during the session). When only RTT is
    /// available (symmetric network assumption), callers may set this to `rtt / 2 - base_rtt / 2`.
    ///
    /// **Clamping:** negative durations would indicate clock drift and are treated as zero. Values
    /// above 2 s are treated as 2 s.
    pub queue_delay: Duration,

    /// Number of **payload bytes** newly acknowledged (confirmed received) in this feedback epoch.
    ///
    /// Headers and retransmissions should not be included; only application-level payload bytes.
    /// Zero is valid (e.g. the first feedback report before any ACKs have arrived).
    pub bytes_acked: u32,

    /// Number of **payload bytes** inferred as lost in this feedback epoch.
    ///
    /// If `bytes_lost > bytes_acked`, the controller treats the loss fraction as 1.0 (100% loss)
    /// rather than panicking or producing a negative number.
    pub bytes_lost: u32,

    /// Fraction of packets lost in this feedback epoch, expressed as a value in `[0, 256]`.
    ///
    /// `0` = no loss; `256` = 100% loss (matches the RTCP Fraction Lost encoding, RFC 3550
    /// §6.4.1, where the 8-bit field is `floor(lost/expected * 256)`).
    ///
    /// Controllers may use this _instead of_ or _in addition to_ `bytes_lost`/`bytes_acked`.
    /// If the transport provides the fraction directly (e.g. from an RTCP RR), set this field;
    /// if the fraction is derived from byte counts, either approach is acceptable.
    pub loss_fraction_q8: u8,

    /// Wall-clock duration of the feedback epoch (time since the previous feedback report).
    ///
    /// Used to compute per-second byte counts. If zero (first report), the controller skips
    /// rate-of-change calculations that would require division.
    pub interval: Duration,
}

impl Default for TransportStats {
    /// Returns a zero-valued feedback report suitable as a "no data yet" placeholder.
    ///
    /// Controllers treat this as cold-start and skip RTT/queue-delay-sensitive calculations.
    fn default() -> Self {
        Self {
            rtt: Duration::ZERO,
            queue_delay: Duration::ZERO,
            bytes_acked: 0,
            bytes_lost: 0,
            loss_fraction_q8: 0,
            interval: Duration::ZERO,
        }
    }
}

impl TransportStats {
    /// Compute the loss fraction as `f64` in `[0.0, 1.0]` from the `loss_fraction_q8` field.
    ///
    /// Returns `0.0` when there is no loss.
    #[inline]
    #[must_use]
    pub fn loss_fraction(&self) -> f64 {
        f64::from(self.loss_fraction_q8) / 256.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_zeroed() {
        let s = TransportStats::default();
        assert_eq!(s.rtt, Duration::ZERO);
        assert_eq!(s.bytes_acked, 0);
        assert_eq!(s.loss_fraction_q8, 0);
    }

    #[test]
    fn loss_fraction_no_loss() {
        let s = TransportStats {
            loss_fraction_q8: 0,
            ..Default::default()
        };
        assert_eq!(s.loss_fraction(), 0.0);
    }

    #[test]
    fn loss_fraction_half() {
        let s = TransportStats {
            loss_fraction_q8: 128,
            ..Default::default()
        };
        let frac = s.loss_fraction();
        assert!((frac - 0.5).abs() < 0.01, "expected ~0.5, got {frac}");
    }

    #[test]
    fn loss_fraction_full() {
        let s = TransportStats {
            loss_fraction_q8: 255,
            ..Default::default()
        };
        let frac = s.loss_fraction();
        assert!((frac - (255.0 / 256.0)).abs() < 1e-9);
    }
}
