//! [`Bitrate`] — a strongly-typed bits-per-second newtype.
//!
//! All internal values are stored as **unsigned bits per second** (`u64`). No floating-point
//! values appear on the public API surface; internal SCReAM arithmetic that requires `f64` must
//! convert via [`Bitrate::as_bps`] and convert back via [`Bitrate::from_bps`], clamping any
//! non-finite or out-of-range result before re-entering the type.

use std::fmt;
use std::ops::{Add, Sub};

/// A network bitrate measured in **bits per second** (bps).
///
/// The inner value is the number of bits per second as a `u64`. Helper constructors and
/// accessors convert to/from kilobits per second (kbps) and megabits per second (Mbps).
///
/// ## Units
///
/// | Unit | Relationship |
/// |------|--------------|
/// | bps  | 1 bit per second (inner representation) |
/// | kbps | 1 000 bps (decimal, not 1 024) |
/// | Mbps | 1 000 000 bps (decimal) |
///
/// ## Integer API
///
/// The public boundary is intentionally integer-only.  Internal algorithms that must work in
/// floating-point (SCReAM's window-based arithmetic) should call [`Bitrate::as_bps`], do their
/// maths in `f64`, guard against `NaN`/`Inf` via [`f64::is_finite`], and then reconstruct with
/// [`Bitrate::from_bps`] which saturates at [`u64::MAX`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Bitrate(pub u64);

impl Bitrate {
    /// Zero bits per second (link completely idle / not yet estimated).
    pub const ZERO: Self = Self(0);

    /// Construct from a raw bits-per-second value.
    #[inline]
    #[must_use]
    pub const fn from_bps(bps: u64) -> Self {
        Self(bps)
    }

    /// Construct from kilobits per second (kbps = 1 000 bps).
    ///
    /// Saturates at [`u64::MAX`] on overflow (a 18 Pbps bitrate is not a practical concern).
    #[inline]
    #[must_use]
    pub fn from_kbps(kbps: u64) -> Self {
        Self(kbps.saturating_mul(1_000))
    }

    /// Construct from megabits per second (Mbps = 1 000 000 bps).
    ///
    /// Saturates at [`u64::MAX`] on overflow.
    #[inline]
    #[must_use]
    pub fn from_mbps(mbps: u64) -> Self {
        Self(mbps.saturating_mul(1_000_000))
    }

    /// Construct from a floating-point bits-per-second value.
    ///
    /// Returns [`Bitrate::ZERO`] if `bps` is negative, `NaN`, or `-Inf`.
    /// Saturates at [`u64::MAX`] if `bps` is `+Inf` or exceeds `u64::MAX`.
    #[inline]
    #[must_use]
    pub fn from_bps_f64(bps: f64) -> Self {
        // NaN, -Inf, and any negative finite value → zero.
        if bps.is_nan() || bps < 0.0 {
            return Self::ZERO;
        }
        // +Inf or any value larger than u64::MAX as f64 → saturate at u64::MAX.
        // Note: u64::MAX as f64 rounds up in IEEE 754 (to 2^64), so comparing against
        // u64::MAX as f64 would incorrectly saturate values that still fit in u64.
        // We use `!bps.is_finite()` to catch +Inf, and the large-value cast saturates naturally.
        if !bps.is_finite() {
            return Self(u64::MAX);
        }
        // Finite, non-negative. Values beyond 1.844e19 exceed u64::MAX but f64 rounds
        // u64::MAX up; clamp any value >= 2^64 to u64::MAX.
        if bps >= 1.844_674_407_370_955_2e19_f64 {
            return Self(u64::MAX);
        }
        // SAFETY: value is finite, in [0, u64::MAX) (guarded above).
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Self(bps as u64)
    }

    /// The raw bits-per-second value.
    #[inline]
    #[must_use]
    pub const fn as_bps(self) -> u64 {
        self.0
    }

    /// The value in kilobits per second (1 kbps = 1 000 bps), rounded down.
    #[inline]
    #[must_use]
    pub const fn as_kbps(self) -> u64 {
        self.0 / 1_000
    }

    /// The value in megabits per second (1 Mbps = 1 000 000 bps), rounded down.
    #[inline]
    #[must_use]
    pub const fn as_mbps(self) -> u64 {
        self.0 / 1_000_000
    }

    /// The raw bits-per-second value as `f64`.
    ///
    /// This is the recommended bridge for floating-point internal arithmetic. The result is
    /// always finite and non-negative.
    #[inline]
    #[must_use]
    pub fn as_bps_f64(self) -> f64 {
        self.0 as f64
    }

    /// Clamp `self` to the range `[min, max]`.
    ///
    /// If `min > max` this returns `min`.
    #[inline]
    #[must_use]
    pub fn clamp(self, min: Self, max: Self) -> Self {
        if self < min {
            min
        } else if self > max {
            max
        } else {
            self
        }
    }

    /// Saturating addition.
    #[inline]
    #[must_use]
    pub fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    /// Saturating subtraction (floors at zero).
    #[inline]
    #[must_use]
    pub fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl fmt::Display for Bitrate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bps = self.0;
        if bps >= 1_000_000 {
            write!(f, "{} Mbps", bps / 1_000_000)
        } else if bps >= 1_000 {
            write!(f, "{} kbps", bps / 1_000)
        } else {
            write!(f, "{bps} bps")
        }
    }
}

impl Add for Bitrate {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        self.saturating_add(rhs)
    }
}

impl Sub for Bitrate {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self.saturating_sub(rhs)
    }
}

#[cfg(test)]
mod tests {
    #[allow(clippy::wildcard_imports)]
    use super::*;

    #[test]
    fn from_bps_roundtrips() {
        let b = Bitrate::from_bps(1_234_567);
        assert_eq!(b.as_bps(), 1_234_567);
    }

    #[test]
    fn kbps_conversion() {
        let b = Bitrate::from_kbps(5_000);
        assert_eq!(b.as_bps(), 5_000_000);
        assert_eq!(b.as_kbps(), 5_000);
    }

    #[test]
    fn mbps_conversion() {
        let b = Bitrate::from_mbps(10);
        assert_eq!(b.as_bps(), 10_000_000);
        assert_eq!(b.as_mbps(), 10);
    }

    #[test]
    fn from_bps_f64_finite() {
        let b = Bitrate::from_bps_f64(2_000_000.0);
        assert_eq!(b.as_bps(), 2_000_000);
    }

    #[test]
    fn from_bps_f64_nan_gives_zero() {
        assert_eq!(Bitrate::from_bps_f64(f64::NAN), Bitrate::ZERO);
    }

    #[test]
    fn from_bps_f64_neg_gives_zero() {
        assert_eq!(Bitrate::from_bps_f64(-1.0), Bitrate::ZERO);
    }

    #[test]
    fn from_bps_f64_pos_inf_saturates() {
        assert_eq!(Bitrate::from_bps_f64(f64::INFINITY), Bitrate(u64::MAX));
    }

    #[test]
    fn from_bps_f64_neg_inf_gives_zero() {
        assert_eq!(Bitrate::from_bps_f64(f64::NEG_INFINITY), Bitrate::ZERO);
    }

    #[test]
    fn clamp_within() {
        let b = Bitrate::from_kbps(500);
        assert_eq!(
            b.clamp(Bitrate::from_kbps(100), Bitrate::from_kbps(1_000)),
            b
        );
    }

    #[test]
    fn clamp_below_min() {
        let b = Bitrate::from_kbps(50);
        let min = Bitrate::from_kbps(100);
        assert_eq!(b.clamp(min, Bitrate::from_kbps(1_000)), min);
    }

    #[test]
    fn clamp_above_max() {
        let b = Bitrate::from_kbps(2_000);
        let max = Bitrate::from_kbps(1_000);
        assert_eq!(b.clamp(Bitrate::from_kbps(100), max), max);
    }

    #[test]
    fn display_bps() {
        assert_eq!(format!("{}", Bitrate::from_bps(500)), "500 bps");
    }

    #[test]
    fn display_kbps() {
        assert_eq!(format!("{}", Bitrate::from_kbps(250)), "250 kbps");
    }

    #[test]
    fn display_mbps() {
        assert_eq!(format!("{}", Bitrate::from_mbps(8)), "8 Mbps");
    }

    #[test]
    fn saturating_add() {
        let a = Bitrate(u64::MAX - 10);
        let b = Bitrate(20);
        assert_eq!(a.saturating_add(b), Bitrate(u64::MAX));
    }

    #[test]
    fn saturating_sub_floors_at_zero() {
        let a = Bitrate::from_kbps(100);
        let b = Bitrate::from_kbps(200);
        assert_eq!(a.saturating_sub(b), Bitrate::ZERO);
    }

    #[test]
    fn ordering() {
        assert!(Bitrate::from_kbps(100) < Bitrate::from_kbps(200));
        assert!(Bitrate::from_mbps(1) > Bitrate::from_kbps(999));
    }

    #[test]
    fn kbps_saturates_on_overflow() {
        // u64::MAX / 1_000 + 1 overflows
        let huge = u64::MAX / 1_000 + 1;
        let b = Bitrate::from_kbps(huge);
        assert_eq!(b, Bitrate(u64::MAX));
    }
}
