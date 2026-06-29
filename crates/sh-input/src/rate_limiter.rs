//! A monotonic-clock token-bucket rate limiter for the input back-channel.
//!
//! Streamhaul is a remote-control product: the host decodes and injects input that arrives over
//! the network, so it must treat that stream as **hostile** (CLAUDE.md §7). The bounded injection
//! queue caps memory under a flood, but nothing caps the *rate* at which synthesized events hit
//! the host OS — a malicious or buggy client can dispatch pointer-move events far faster than any
//! human, hammering the OS injection API. [`RateLimiter`] is the rate cap.
//!
//! # Which events may be gated (the caller's responsibility)
//!
//! This struct is a generic token bucket; it knows nothing about event types. The **caller** must
//! apply it only to events that are safe to drop. Dropping a `Button`/`Key` *release* would leave
//! the controlled machine with a button or key **stuck down** — exactly the failure
//! [`crate::InputInjector::release_all`] exists to prevent — so those state-transition events must
//! bypass the limiter entirely. The drop-safe, high-rate vectors are `PointerMove` (absolute
//! position, so the next move supersedes a dropped one) and `Wheel` (a self-contained scroll notch
//! with no held state). Gating those *before* the bounded injection queue also lightens queue
//! pressure on the state-transition events, making it *less* likely a button/key transition is
//! dropped by queue overflow. See `admit_input` in the host for the exact classification.
//!
//! # Determinism
//!
//! [`RateLimiter::allow`] takes the current [`Instant`] as a parameter rather than reading the
//! clock itself, so tests drive time explicitly (CLAUDE.md §5 — inject the clock, no wall-clock
//! flakiness).

use std::time::Instant;

/// A token-bucket rate limiter over a monotonic [`Instant`] clock.
///
/// The bucket holds up to `burst` tokens and refills at `refill_per_sec` tokens per second. Each
/// [`allow`](Self::allow) call refills based on elapsed time (capped at `burst`), then consumes one
/// token if available. A steady stream is admitted at up to `refill_per_sec`; a quiet period banks
/// up to `burst` tokens so a short burst passes unthrottled.
///
/// Token math uses `f64`, which never panics on overflow (unlike the integer arithmetic the
/// workspace lints forbid) and saturates cleanly to `±inf` at extreme inputs.
///
/// # Example
///
/// ```
/// use std::time::{Duration, Instant};
/// use sh_input::RateLimiter;
///
/// // 100 events/sec sustained, burst of 2.
/// let mut rl = RateLimiter::new(100, 2);
/// let t0 = Instant::now();
///
/// // The initial burst is admitted...
/// assert!(rl.allow(t0));
/// assert!(rl.allow(t0));
/// // ...then the bucket is empty at the same instant.
/// assert!(!rl.allow(t0));
///
/// // After 10 ms one token (100/sec × 0.01 s) has refilled.
/// assert!(rl.allow(t0 + Duration::from_millis(10)));
/// ```
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Maximum tokens the bucket can hold (burst allowance). Always ≥ 1.0.
    capacity: f64,
    /// Steady-state refill rate in tokens per second. Always ≥ 0.0.
    refill_per_sec: f64,
    /// Current token count, in `[0.0, capacity]`.
    tokens: f64,
    /// Instant of the previous `allow` call; `None` until the first call.
    last: Option<Instant>,
}

impl RateLimiter {
    /// Create a limiter admitting `refill_per_sec` events/second sustained, with a `burst`
    /// allowance. The bucket starts **full** (`burst` tokens) so an immediate short burst passes.
    ///
    /// `burst` is clamped to a minimum of 1 (a zero-capacity bucket would drop everything,
    /// silently disabling input — never the intent). `refill_per_sec` of 0 is permitted and yields
    /// a fixed budget of exactly `burst` events total (no refill) — useful only in tests.
    #[must_use]
    pub fn new(refill_per_sec: u32, burst: u32) -> Self {
        let capacity = f64::from(burst.max(1));
        Self {
            capacity,
            refill_per_sec: f64::from(refill_per_sec),
            tokens: capacity,
            last: None,
        }
    }

    /// Refill for the time elapsed since the previous call, then consume one token.
    ///
    /// Returns `true` if a token was available (the event is admitted) or `false` if the bucket is
    /// empty (the caller should drop the event). `now` must be monotonically non-decreasing across
    /// calls; a `now` earlier than the previous call contributes no refill (it is clamped via
    /// [`Instant::saturating_duration_since`], never negative).
    pub fn allow(&mut self, now: Instant) -> bool {
        match self.last {
            Some(last) => {
                let elapsed = now.saturating_duration_since(last).as_secs_f64();
                // refill = elapsed × rate, capped at capacity. f64 ops don't panic on overflow.
                let refilled = self.tokens + elapsed * self.refill_per_sec;
                self.tokens = refilled.min(self.capacity);
                // Never rewind the base: a backwards `now` (only reachable in tests — production
                // uses monotonic `Instant::now()`) contributes zero refill AND must not move `last`
                // back, or a later call between the two would accrue spurious tokens.
                self.last = Some(last.max(now));
            }
            None => self.last = Some(now),
        }

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn admits_initial_burst_then_blocks() {
        let mut rl = RateLimiter::new(100, 3);
        let t0 = Instant::now();
        // Bucket starts full with `burst` tokens.
        assert!(rl.allow(t0));
        assert!(rl.allow(t0));
        assert!(rl.allow(t0));
        // Fourth event at the same instant: no tokens left.
        assert!(!rl.allow(t0));
    }

    #[test]
    fn refills_at_the_configured_rate() {
        let mut rl = RateLimiter::new(100, 1); // 100/sec, burst 1
        let t0 = Instant::now();
        assert!(rl.allow(t0)); // consume the single token
        assert!(!rl.allow(t0)); // empty

        // 100/sec → one token per 10 ms. Well under one interval: still short. (5 ms ≈ 0.5 token;
        // we stay clear of the exact 10 ms boundary, which f64 token math can land just shy of.)
        assert!(!rl.allow(t0 + Duration::from_millis(5)));
        // Well past one interval: a token has refilled (capped at burst=1, so still admit-able).
        assert!(rl.allow(t0 + Duration::from_millis(50)));
    }

    #[test]
    fn refill_is_capped_at_burst() {
        let mut rl = RateLimiter::new(100, 2); // burst 2
        let t0 = Instant::now();
        // Idle for a long time — refill must NOT exceed the burst capacity.
        let later = t0 + Duration::from_secs(10); // would be 1000 tokens uncapped
        assert!(rl.allow(later));
        assert!(rl.allow(later));
        // Only `burst` (2) tokens were available despite the long idle.
        assert!(!rl.allow(later));
    }

    #[test]
    fn sustained_rate_throttles_a_flood_to_the_configured_rate() {
        // 50/sec, burst 1. Offer a *flood* — one event every 5 ms for 1 second (200 offers, i.e.
        // 200/sec, 4× the cap). The limiter must throttle the admitted rate to ~50/sec.
        let mut rl = RateLimiter::new(50, 1);
        let t0 = Instant::now();
        let mut admitted = 0u32;
        for i in 0..200u32 {
            if rl.allow(t0 + Duration::from_millis(u64::from(i) * 5)) {
                admitted = admitted.saturating_add(1);
            }
        }
        // Over ~1 s at 50/sec we expect ≈50 admitted (plus the initial burst token). Assert a
        // tolerance band rather than an exact count — f64 token accounting lands within a hair of
        // the boundary, and the point is that the flood was throttled near the configured rate.
        assert!(
            (48..=53).contains(&admitted),
            "expected ~50 admitted under a 200/sec flood, got {admitted}"
        );
    }

    #[test]
    fn backwards_time_does_not_refill_or_panic() {
        let mut rl = RateLimiter::new(100, 1);
        let t0 = Instant::now() + Duration::from_secs(1);
        assert!(rl.allow(t0));
        assert!(!rl.allow(t0));
        // A `now` earlier than the previous call: saturating_duration_since → 0, no refill, no panic.
        let earlier = t0 - Duration::from_millis(500);
        assert!(!rl.allow(earlier));
        // The backwards call must NOT have rewound the base: a later call *between* `earlier` and
        // `t0` must still accrue zero refill (regression guard for the clock-rewind bug).
        let between = t0 - Duration::from_millis(200);
        assert!(
            !rl.allow(between),
            "a call between the backwards time and t0 must not refill (base must not rewind)"
        );
    }

    #[test]
    fn extreme_rate_and_idle_never_misjudge() {
        // A pathological config (max rate, max burst) plus a long idle must still yield a sane,
        // saturating verdict — no NaN/inf admitting infinitely or starving wrongly.
        let mut rl = RateLimiter::new(u32::MAX, u32::MAX);
        let t0 = Instant::now();
        // Full bucket: first event admitted.
        assert!(rl.allow(t0));
        // Even a huge elapsed time caps tokens at `burst` (finite), so the bucket never overflows
        // to inf and the verdict stays correct.
        let later = t0 + Duration::from_secs(86_400); // 1 day
        assert!(rl.allow(later));
    }

    #[test]
    fn zero_burst_is_clamped_to_one() {
        // burst 0 would drop everything; it must clamp to 1 so at least one event passes.
        let mut rl = RateLimiter::new(10, 0);
        let t0 = Instant::now();
        assert!(rl.allow(t0));
        assert!(!rl.allow(t0));
    }
}
