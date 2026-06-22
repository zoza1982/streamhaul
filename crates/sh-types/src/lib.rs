//! Core shared types for Streamhaul.
//!
//! This is the workspace **leaf crate**: it depends on no other Streamhaul crate, so every other
//! crate may depend on it without creating cycles. It holds stable identifiers, time units, and the
//! shared error type. See [`LLD.md`](https://github.com/zoza1982/streamhaul/blob/main/LLD.md) §1–§3.

use std::fmt;
use std::ops::{Add, Sub};
use thiserror::Error;

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
        // Finite, non-negative. `u64::MAX as f64` rounds UP to the next representable double
        // (2^64), so any finite bps at or above that value would truncate unsafely; saturate it.
        const U64_MAX_AS_F64: f64 = u64::MAX as f64;
        if bps >= U64_MAX_AS_F64 {
            return Self(u64::MAX);
        }
        // Invariant: bps is finite and in [0.0, 2^64), so the truncating cast is exact and in range.
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
    /// For well-formed ranges (`min <= max`) this matches [`Ord::clamp`] semantics. If `min > max`
    /// the result is unspecified (it returns `min` or `max` depending on `self`), but unlike
    /// [`Ord::clamp`] this method never panics.
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

/// A monotonic, per-session encoded-frame identifier.
///
/// On the wire (SHP video header) the field is 24 bits and wraps at 2^24; in memory it is widened to
/// [`u64`] so accumulation logic never has to reason about wrap-around. The inner field is public on
/// purpose — these are deliberately thin typed-integer wrappers, not invariant-bearing types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameId(pub u64);

/// A monotonic timestamp in microseconds since the session epoch (not wall-clock time).
///
/// On the wire (SHP common header) the TIMESTAMP field is 32 bits and wraps at 2^32 µs (~71 min); in
/// memory it is widened to [`u64`] so session-level accounting never has to handle wrap-around. The
/// inner field is public on purpose (a thin typed wrapper).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimestampUs(pub u64);

/// A logical channel within a session. Each maps to a distinct transport carrier with its own
/// reliability and priority profile (see `LLD.md` §3.2).
///
/// The single-byte discriminant is **wire-stable** and shared by every crate that encodes a channel
/// (SHP common header in `sh-protocol`, the stream-open header in `sh-transport`). Use
/// [`u8::from`]`(ChannelId)` and [`ChannelId::try_from`]`(u8)` as the *only* mapping; do not
/// hand-roll a second copy, or the wire formats can silently desync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelId {
    /// Host → client encoded video (unreliable, drop-stale). Wire discriminant `0`.
    Video,
    /// Host → client audio (unreliable + FEC). Wire discriminant `1`.
    Audio,
    /// Client → host input events (reliable, ordered, highest priority). Wire discriminant `2`.
    Input,
    /// Bidirectional clipboard sync (reliable). Wire discriminant `3`.
    Clipboard,
    /// Bidirectional bulk file transfer (reliable, congestion-isolated). Wire discriminant `4`.
    File,
    /// Bidirectional control / RPC (reliable). Wire discriminant `5`.
    Control,
}

/// Error returned by [`ChannelId::try_from`] when a byte does not map to a known [`ChannelId`].
///
/// Carries the offending byte so callers can surface it in their own structured errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidChannelId(pub u8);

impl core::fmt::Display for InvalidChannelId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid channel id: {}", self.0)
    }
}

impl std::error::Error for InvalidChannelId {}

impl From<ChannelId> for u8 {
    /// Maps a [`ChannelId`] to its wire-stable single-byte discriminant.
    fn from(channel: ChannelId) -> Self {
        match channel {
            ChannelId::Video => 0,
            ChannelId::Audio => 1,
            ChannelId::Input => 2,
            ChannelId::Clipboard => 3,
            ChannelId::File => 4,
            ChannelId::Control => 5,
        }
    }
}

impl TryFrom<u8> for ChannelId {
    type Error = InvalidChannelId;

    /// Maps a wire-stable single-byte discriminant back to a [`ChannelId`].
    ///
    /// # Errors
    ///
    /// Returns [`InvalidChannelId`] (carrying the offending byte) if the byte is not one of the
    /// six known discriminants (`0..=5`).
    fn try_from(byte: u8) -> core::result::Result<Self, Self::Error> {
        match byte {
            0 => Ok(ChannelId::Video),
            1 => Ok(ChannelId::Audio),
            2 => Ok(ChannelId::Input),
            3 => Ok(ChannelId::Clipboard),
            4 => Ok(ChannelId::File),
            5 => Ok(ChannelId::Control),
            other => Err(InvalidChannelId(other)),
        }
    }
}

/// Errors shared across Streamhaul crates. Crate-specific errors wrap or convert into this where they
/// cross a public boundary.
///
/// The `String` payloads are **scaffolding placeholders**: concrete crates (`sh-protocol`,
/// `sh-transport`, …) define richer, matchable error types and will replace these with structured
/// variants as those crates land. Downstream callers should not match on the message text.
#[derive(Debug, Error)]
pub enum Error {
    /// A wire-format or protocol violation (malformed header, unexpected message, version mismatch).
    #[error("protocol error: {0}")]
    Protocol(String),
    /// A transport-layer failure (connection lost, channel closed, handshake failure).
    #[error("transport error: {0}")]
    Transport(String),
}

/// Convenience alias for results carrying the shared [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_ids_are_distinct() {
        assert_ne!(ChannelId::Video, ChannelId::Input);
        assert_eq!(ChannelId::Control, ChannelId::Control);
    }

    #[test]
    fn channel_id_u8_roundtrips_all_variants() {
        for (channel, byte) in [
            (ChannelId::Video, 0u8),
            (ChannelId::Audio, 1),
            (ChannelId::Input, 2),
            (ChannelId::Clipboard, 3),
            (ChannelId::File, 4),
            (ChannelId::Control, 5),
        ] {
            assert_eq!(u8::from(channel), byte);
            assert_eq!(ChannelId::try_from(byte), Ok(channel));
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn channel_id_try_from_rejects_invalid_byte() {
        assert_eq!(ChannelId::try_from(6), Err(InvalidChannelId(6)));
        assert_eq!(ChannelId::try_from(0xFF), Err(InvalidChannelId(0xFF)));
        // The error renders the offending byte and is a std::error::Error.
        let err = ChannelId::try_from(42).unwrap_err();
        assert!(format!("{err}").contains("42"));
        let _as_dyn: &dyn std::error::Error = &err;
    }

    #[test]
    fn frame_ids_order_monotonically() {
        assert!(FrameId(1) < FrameId(2));
        assert!(TimestampUs(10) < TimestampUs(20));
    }

    #[test]
    fn error_display_includes_context() {
        let e = Error::Protocol("bad header".into());
        assert!(format!("{e}").contains("bad header"));
        let t = Error::Transport("channel closed".into());
        assert!(format!("{t}").contains("channel closed"));
    }
}
