//! Core shared types for Streamhaul.
//!
//! This is the workspace **leaf crate**: it depends on no other Streamhaul crate, so every other
//! crate may depend on it without creating cycles. It holds stable identifiers, time units, and the
//! shared error type. See [`LLD.md`](https://github.com/zoza1982/streamhaul/blob/main/LLD.md) §1–§3.

use thiserror::Error;

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
