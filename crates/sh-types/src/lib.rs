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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelId {
    /// Host → client encoded video (unreliable, drop-stale).
    Video,
    /// Host → client audio (unreliable + FEC).
    Audio,
    /// Client → host input events (reliable, ordered, highest priority).
    Input,
    /// Bidirectional clipboard sync (reliable).
    Clipboard,
    /// Bidirectional bulk file transfer (reliable, congestion-isolated).
    File,
    /// Bidirectional control / RPC (reliable).
    Control,
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
