//! Token-bucket bandwidth pacer for the file-transfer channel (P7 — ADR-0024).
//!
//! The cross-channel [`RateAllocator`](crate::RateAllocator) hands the File channel **leftover**
//! bandwidth — whatever remains after the interactive reserves, the audio floor, and video. A
//! [`TokenBucket`] turns that leftover *budget* into an actual send *rate*: the file sender awaits
//! tokens before transmitting each chunk, so a bulk copy physically cannot offer bytes faster than
//! its spare-bandwidth allocation. Combined with the per-transfer QUIC stream's own flow-control
//! window (the *structural* isolation in `sh-transport`), file traffic is isolated twice over.
//!
//! The bucket is **time-agnostic and deterministic**: the caller advances it with an explicit
//! elapsed [`Duration`] ([`TokenBucket::advance`]) rather than reading a clock. This keeps it
//! trivially testable (simulated time, no wall-clock flakiness) and lets production code drive it
//! from a monotonic clock. Tokens are tracked in **bytes**; the fill rate is derived from a
//! [`Bitrate`] (bits/sec ÷ 8).

use std::time::Duration;

use crate::bitrate::Bitrate;

/// Comparison slack when matching a byte request against the token balance, in bytes.
///
/// Tokens accrue as `f64`, so advancing by exactly `time_until(n)` leaves the balance a rounding
/// error below `n` (the error is on the order of an ULP at byte magnitudes — far larger than
/// [`f64::EPSILON`], which is meaningless here). Half a byte absorbs that drift so an "advance the
/// reported deficit, then consume" caller succeeds in one step, while never letting a consume exceed
/// the budget by a meaningful amount (≤ 0.5 B per call).
const TOKEN_SLACK: f64 = 0.5;

/// A byte-denominated token bucket that fills at a configurable [`Bitrate`].
///
/// Tokens accrue at `rate / 8` bytes per second up to a burst capacity, and are consumed by
/// [`try_consume`](TokenBucket::try_consume). A `rate` of zero means the bucket never fills (file
/// transfer is fully throttled — e.g. when video has consumed the entire budget).
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use sh_adaptive::{Bitrate, TokenBucket};
///
/// // 8 Mbps = 1 MB/s, 10 ms burst → 10 KB capacity, starts full.
/// let mut tb = TokenBucket::new(Bitrate::from_mbps(8), Duration::from_millis(10));
/// assert!(tb.try_consume(10_000)); // spend the full burst
/// assert!(!tb.try_consume(1_000)); // empty now
///
/// // Wait the reported deficit, then the consume succeeds.
/// let wait = tb.time_until(1_000).expect("rate is positive and within capacity");
/// tb.advance(wait);
/// assert!(tb.try_consume(1_000));
/// ```
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Fill rate in **bytes per second** (derived from the configured [`Bitrate`]).
    fill_bytes_per_sec: f64,
    /// Maximum tokens the bucket may hold, in bytes (burst allowance).
    capacity_bytes: f64,
    /// Current token balance, in bytes. Always in `0.0..=capacity_bytes`.
    tokens_bytes: f64,
}

impl TokenBucket {
    /// Create a bucket filling at `rate`, allowing a burst of up to `burst` worth of bytes.
    ///
    /// The burst capacity is `rate` sustained for `burst` time (so a `burst` of 100 ms at 8 Mbps
    /// allows a 100 KB burst). The bucket starts **full** so the first chunk is not delayed.
    ///
    /// `burst` must be large enough to hold at least one chunk's worth of bytes
    /// (`burst ≥ chunk_size / rate`); a zero/too-small burst yields a capacity below one chunk, so
    /// `try_consume` of a full chunk can never succeed (the bucket clamps accrual to capacity).
    /// Callers pace whole chunks, so size the burst to at least one max-chunk worth of time.
    #[must_use]
    pub fn new(rate: Bitrate, burst: Duration) -> Self {
        let fill_bytes_per_sec = bytes_per_sec(rate);
        let capacity_bytes = (fill_bytes_per_sec * burst.as_secs_f64()).max(0.0);
        Self {
            fill_bytes_per_sec,
            capacity_bytes,
            tokens_bytes: capacity_bytes,
        }
    }

    /// Update the fill rate (e.g. when the allocator re-runs after a congestion-control update).
    ///
    /// The current token balance is preserved but re-clamped to the new capacity, which scales with
    /// the rate so the burst window stays constant.
    pub fn set_rate(&mut self, rate: Bitrate, burst: Duration) {
        self.fill_bytes_per_sec = bytes_per_sec(rate);
        self.capacity_bytes = (self.fill_bytes_per_sec * burst.as_secs_f64()).max(0.0);
        if self.tokens_bytes > self.capacity_bytes {
            self.tokens_bytes = self.capacity_bytes;
        }
    }

    /// Accrue tokens for `elapsed` time, clamped to the burst capacity.
    pub fn advance(&mut self, elapsed: Duration) {
        let added = self.fill_bytes_per_sec * elapsed.as_secs_f64();
        self.tokens_bytes = (self.tokens_bytes + added).min(self.capacity_bytes);
    }

    /// Try to consume `bytes` tokens. Returns `true` and deducts them if available, else `false`
    /// (the caller should wait — see [`time_until`](TokenBucket::time_until)).
    #[must_use]
    pub fn try_consume(&mut self, bytes: usize) -> bool {
        let want = bytes as f64;
        if self.tokens_bytes + TOKEN_SLACK >= want {
            self.tokens_bytes -= want;
            if self.tokens_bytes < 0.0 {
                self.tokens_bytes = 0.0;
            }
            true
        } else {
            false
        }
    }

    /// How long until `bytes` tokens would be available, given the current fill rate.
    ///
    /// Returns [`Duration::ZERO`] if already available. Returns [`None`] when the request can **never**
    /// be satisfied — the rate is zero (tokens never accrue) **or** `bytes` exceeds the burst
    /// capacity (accrual is clamped to capacity in [`advance`](Self::advance), so a request larger
    /// than capacity would wait forever). Callers must treat [`None`] as "reconfigure / fatal", not
    /// "retry later", to avoid a busy-loop. The returned wait is saturated to [`Duration::MAX`] rather
    /// than panicking on an extreme (tiny-rate) deficit.
    #[must_use]
    pub fn time_until(&self, bytes: usize) -> Option<Duration> {
        let want = bytes as f64;
        if self.tokens_bytes + TOKEN_SLACK >= want {
            return Some(Duration::ZERO);
        }
        // Never satisfiable: no fill, or the request exceeds what the bucket can ever hold.
        if self.fill_bytes_per_sec <= 0.0 || want > self.capacity_bytes + TOKEN_SLACK {
            return None;
        }
        let deficit = want - self.tokens_bytes;
        // `try_from_secs_f64` returns Err on overflow/NaN; saturate instead of panicking (§6).
        Some(
            Duration::try_from_secs_f64(deficit / self.fill_bytes_per_sec).unwrap_or(Duration::MAX),
        )
    }

    /// Current token balance in bytes (for diagnostics/tests).
    #[must_use]
    pub fn tokens(&self) -> f64 {
        self.tokens_bytes
    }

    /// The configured fill rate in bytes per second.
    #[must_use]
    pub fn fill_bytes_per_sec(&self) -> f64 {
        self.fill_bytes_per_sec
    }
}

/// Convert a [`Bitrate`] (bits/sec) to bytes/sec as `f64`.
fn bytes_per_sec(rate: Bitrate) -> f64 {
    (rate.0 as f64) / 8.0
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    #[test]
    fn starts_full_and_consumes() {
        // 8 Mbps = 1 MB/s. Burst 100 ms → capacity 100 KB. Starts full.
        let mut tb = TokenBucket::new(Bitrate::from_mbps(8), Duration::from_millis(100));
        assert!((tb.tokens() - 100_000.0).abs() < 1.0);
        assert!(tb.try_consume(100_000));
        assert!(tb.tokens() < 1.0);
        // Now empty: a further consume fails.
        assert!(!tb.try_consume(1));
    }

    #[test]
    fn refills_at_rate() {
        // 1 MB/s, 10 ms burst → 10 KB capacity. Drain it, then refill by advancing time.
        let mut tb = TokenBucket::new(Bitrate::from_mbps(8), Duration::from_millis(10));
        assert!(tb.try_consume(10_000)); // drain the full bucket
        assert!(tb.tokens() < 1.0);
        assert!(!tb.try_consume(1000));
        // Advance 1 ms → 1 MB/s * 1 ms = 1000 bytes.
        tb.advance(Duration::from_millis(1));
        assert!((tb.tokens() - 1000.0).abs() < 1.0);
        assert!(tb.try_consume(1000));
    }

    #[test]
    fn refill_clamped_to_capacity() {
        let mut tb = TokenBucket::new(Bitrate::from_mbps(8), Duration::from_millis(10));
        let _ = tb.try_consume(100_000); // drain whatever's there
                                         // Advance a full second — would add 1 MB, but capacity is 10 ms * 1 MB/s = 10 KB.
        tb.advance(Duration::from_secs(1));
        assert!((tb.tokens() - 10_000.0).abs() < 1.0);
    }

    #[test]
    fn time_until_computes_deficit() {
        // 1 MB/s, 10 ms burst (10 KB cap). Drain, then 2000 bytes need 2 ms to accrue.
        let mut tb = TokenBucket::new(Bitrate::from_mbps(8), Duration::from_millis(10));
        assert!(tb.try_consume(10_000)); // empty the bucket
        let wait = tb.time_until(2000).unwrap();
        assert!((wait.as_secs_f64() - 0.002).abs() < 1e-6);
        tb.advance(wait);
        assert!(tb.try_consume(2000));
    }

    #[test]
    fn time_until_does_not_panic_on_tiny_rate_huge_want() {
        // Regression: deficit/rate overflowed Duration::from_secs_f64 → panic. Must saturate.
        let tb = TokenBucket::new(Bitrate(1), Duration::from_secs(1));
        let got = tb.time_until(usize::MAX);
        // Either None (want > capacity) or a saturated Duration — never a panic.
        assert!(matches!(got, None | Some(_)));
    }

    #[test]
    fn time_until_none_when_want_exceeds_capacity() {
        // Regression (livelock): burst smaller than the request can never be satisfied because
        // `advance` clamps accrual to capacity. `time_until` must report None, not a finite wait.
        let tb = TokenBucket::new(Bitrate::from_mbps(8), Duration::from_millis(1)); // cap 1000 B
        assert_eq!(tb.time_until(16_384), None);
    }

    #[test]
    fn advance_exact_deficit_then_consume_succeeds_at_chunk_scale() {
        // Regression: the old f64::EPSILON slack was inert at byte magnitudes, so a single
        // advance(time_until(n)) + consume(n) spuriously failed for a real 16 KiB chunk.
        let mut tb = TokenBucket::new(Bitrate::from_mbps(8), Duration::from_millis(50)); // cap 50 KB
        assert!(tb.try_consume(50_000)); // drain
        let wait = tb.time_until(16_384).unwrap();
        tb.advance(wait);
        assert!(
            tb.try_consume(16_384),
            "advancing the reported deficit must make exactly one chunk available"
        );
    }

    #[test]
    fn zero_rate_never_fills() {
        let mut tb = TokenBucket::new(Bitrate(0), Duration::from_millis(100));
        assert_eq!(tb.tokens(), 0.0);
        tb.advance(Duration::from_secs(10));
        assert_eq!(tb.tokens(), 0.0);
        // Never available → None, so callers don't busy-wait.
        assert_eq!(tb.time_until(1), None);
    }

    #[test]
    fn set_rate_preserves_balance_reclamped() {
        let mut tb = TokenBucket::new(Bitrate::from_mbps(8), Duration::from_millis(100));
        assert!((tb.tokens() - 100_000.0).abs() < 1.0);
        // Drop to 4 Mbps (0.5 MB/s); capacity now 50 KB → balance re-clamped down.
        tb.set_rate(Bitrate::from_mbps(4), Duration::from_millis(100));
        assert!((tb.tokens() - 50_000.0).abs() < 1.0);
        assert!((tb.fill_bytes_per_sec() - 500_000.0).abs() < 1.0);
    }
}
