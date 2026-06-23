//! Reconnect backoff strategies for the signaling client.
//!
//! [`BackoffStrategy`] is the injection point for delay policy in the client's reconnect loop.
//! A production client uses [`ExponentialBackoff`]; tests can inject a zero-delay strategy.

use std::time::Duration;

/// Controls the delay between reconnect attempts in [`crate::SignalingClient`].
///
/// The client calls [`next_delay`](BackoffStrategy::next_delay) before each reconnect attempt.
/// `None` means "give up". [`reset`](BackoffStrategy::reset) is called after a successful
/// connection to restart the sequence from the beginning.
pub trait BackoffStrategy: Send + 'static {
    /// Returns the duration to wait before the next reconnect attempt, or `None` to give up.
    fn next_delay(&mut self) -> Option<Duration>;

    /// Resets the strategy to its initial state after a successful connection.
    fn reset(&mut self);
}

/// Exponential backoff with a configurable base, cap, and maximum attempt count.
///
/// The delay sequence is: `base_ms`, `base_ms * 2`, `base_ms * 4`, …, up to `max_ms`.
/// After `max_attempts` calls to [`next_delay`](BackoffStrategy::next_delay) that returned
/// `Some(…)`, the next call returns `None`.
///
/// # Examples
///
/// ```
/// use sh_signaling::backoff::{BackoffStrategy, ExponentialBackoff};
///
/// let mut b = ExponentialBackoff::default();
/// let d0 = b.next_delay().unwrap();
/// let d1 = b.next_delay().unwrap();
/// assert!(d1 >= d0, "delay should be non-decreasing");
/// b.reset();
/// assert_eq!(b.next_delay(), Some(d0), "reset restores initial delay");
/// ```
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    /// Initial delay in milliseconds.
    pub base_ms: u64,
    /// Maximum delay in milliseconds (cap).
    pub max_ms: u64,
    /// Maximum number of attempts before giving up.
    pub max_attempts: u32,
    current_ms: u64,
    attempts: u32,
}

impl ExponentialBackoff {
    /// Creates a new `ExponentialBackoff` with the given parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_signaling::backoff::ExponentialBackoff;
    ///
    /// let b = ExponentialBackoff::new(100, 30_000, 8);
    /// assert_eq!(b.base_ms, 100);
    /// ```
    #[must_use]
    pub fn new(base_ms: u64, max_ms: u64, max_attempts: u32) -> Self {
        Self {
            base_ms,
            max_ms,
            max_attempts,
            current_ms: base_ms,
            attempts: 0,
        }
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::new(100, 30_000, 8)
    }
}

impl BackoffStrategy for ExponentialBackoff {
    fn next_delay(&mut self) -> Option<Duration> {
        if self.attempts >= self.max_attempts {
            return None;
        }
        let delay = Duration::from_millis(self.current_ms);
        self.attempts = self.attempts.saturating_add(1);
        // Double, capped at max_ms.
        self.current_ms = self.current_ms.saturating_mul(2).min(self.max_ms);
        Some(delay)
    }

    fn reset(&mut self) {
        self.current_ms = self.base_ms;
        self.attempts = 0;
    }
}

/// A zero-delay backoff for tests — always returns `Some(Duration::ZERO)`, never gives up.
///
/// This is useful in integration tests where you want the reconnect to happen immediately
/// without waiting.
#[derive(Debug, Clone, Default)]
pub struct ImmediateBackoff;

impl BackoffStrategy for ImmediateBackoff {
    fn next_delay(&mut self) -> Option<Duration> {
        Some(Duration::ZERO)
    }

    fn reset(&mut self) {}
}

/// A backoff that refuses all reconnects — always returns `None`.
///
/// Useful for tests that want to assert the client does not reconnect.
#[derive(Debug, Clone, Default)]
pub struct NoReconnect;

impl BackoffStrategy for NoReconnect {
    fn next_delay(&mut self) -> Option<Duration> {
        None
    }

    fn reset(&mut self) {}
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn exponential_doubles_delay() {
        let mut b = ExponentialBackoff::new(100, 10_000, 8);
        let d0 = b.next_delay().unwrap();
        let d1 = b.next_delay().unwrap();
        let d2 = b.next_delay().unwrap();
        assert_eq!(d0, Duration::from_millis(100));
        assert_eq!(d1, Duration::from_millis(200));
        assert_eq!(d2, Duration::from_millis(400));
    }

    #[test]
    fn exponential_caps_at_max() {
        let mut b = ExponentialBackoff::new(100, 150, 10);
        let _ = b.next_delay().unwrap(); // 100
        let d = b.next_delay().unwrap(); // 150 (capped from 200)
        assert_eq!(d, Duration::from_millis(150));
        let d2 = b.next_delay().unwrap(); // still 150
        assert_eq!(d2, Duration::from_millis(150));
    }

    #[test]
    fn exponential_gives_up_after_max_attempts() {
        let mut b = ExponentialBackoff::new(10, 1_000, 3);
        assert!(b.next_delay().is_some());
        assert!(b.next_delay().is_some());
        assert!(b.next_delay().is_some());
        assert!(b.next_delay().is_none());
    }

    #[test]
    fn exponential_reset_restarts() {
        let mut b = ExponentialBackoff::new(100, 10_000, 3);
        let d0 = b.next_delay().unwrap();
        b.reset();
        let d_reset = b.next_delay().unwrap();
        assert_eq!(d0, d_reset);
    }

    #[test]
    fn immediate_backoff_never_gives_up() {
        let mut b = ImmediateBackoff;
        for _ in 0..100 {
            assert_eq!(b.next_delay(), Some(Duration::ZERO));
        }
    }

    #[test]
    fn no_reconnect_always_gives_up() {
        let mut b = NoReconnect;
        assert!(b.next_delay().is_none());
    }
}
