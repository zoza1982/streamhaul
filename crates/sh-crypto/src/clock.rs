//! Injected clock abstraction for deterministic testing.
//!
//! All time-sensitive code in `sh-crypto` (BindCert validity, handshake timeouts) must
//! call [`Clock::now_unix_secs`] rather than [`std::time::SystemTime::now`]. This
//! allows tests to use a fixed or advancing mock clock without OS calls.

/// An injected wall-clock abstraction.
///
/// Implementations must return a monotonically non-decreasing value of Unix epoch
/// seconds (UTC). The system implementation calls [`std::time::SystemTime::now`];
/// test implementations use a fixed or advancing value.
///
/// # Fallback semantics
///
/// If the system clock is unavailable, implementations must return `i64::MAX`. This is
/// the conservative choice: a [`BindCert`](crate::bind_cert::BindCert) validated against
/// `i64::MAX` will always fail the `NOT_AFTER` check (the cert appears perpetually
/// expired), preventing acceptance of potentially-valid credentials during a clock failure.
///
/// # Examples
///
/// ```
/// use sh_crypto::clock::{Clock, SystemClock};
///
/// let clock = SystemClock;
/// let now = clock.now_unix_secs();
/// assert!(now > 0, "system clock must return a positive epoch");
/// ```
pub trait Clock: Send + Sync + 'static {
    /// Returns the current time as a Unix epoch timestamp (seconds since 1970-01-01T00:00:00Z).
    ///
    /// # Panics
    ///
    /// Implementations must not panic on a clock read. If the system clock is unavailable,
    /// return `i64::MAX` (conservative: treats all certs as perpetually expired).
    fn now_unix_secs(&self) -> i64;
}

/// The production [`Clock`] backed by [`std::time::SystemTime`].
///
/// # Examples
///
/// ```
/// use sh_crypto::clock::{Clock, SystemClock};
/// let clock = SystemClock;
/// let now = clock.now_unix_secs();
/// assert!(now > 0);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> i64 {
        // If the system clock is before the Unix epoch or the duration overflows i64,
        // return i64::MAX (conservative: all certs appear expired, nothing is accepted).
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(i64::MAX)
    }
}

/// A fixed-time [`Clock`] for use in tests.
///
/// Returns a constant value for every call to [`Clock::now_unix_secs`].
///
/// # Examples
///
/// ```
/// use sh_crypto::clock::{Clock, FixedClock};
/// let clock = FixedClock(1_000_000);
/// assert_eq!(clock.now_unix_secs(), 1_000_000);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub i64);

impl Clock for FixedClock {
    fn now_unix_secs(&self) -> i64 {
        self.0
    }
}
