//! Error type for input injection failures.

use thiserror::Error;

/// Errors that can occur during input injection or coordinate mapping.
///
/// All variants are designed to be matchable so callers can distinguish recoverable
/// backend hiccups (`Backend`) from permanent configuration issues (`ZeroSizeAxis`,
/// `Unsupported`).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum InputError {
    /// The target display axis has zero extent.
    ///
    /// A [`crate::TargetRect`] with `width = 0` or `height = 0` has no valid pixels to map to.
    /// Reject the rect at construction time; do not silently clamp or guess.
    #[error("target rect has zero-size axis: width={width} height={height}")]
    ZeroSizeAxis {
        /// Width of the rejected rect.
        width: u32,
        /// Height of the rejected rect.
        height: u32,
    },

    /// The event type or event fields are not supported by this injector.
    ///
    /// For example, a mock injector may accept only pointer and key events; returning
    /// `Unsupported` lets callers decide whether to skip or escalate.
    #[error("unsupported event: {reason}")]
    Unsupported {
        /// Human-readable description of why the event is unsupported.
        reason: &'static str,
    },

    /// An OS-level or backend-specific injection failure.
    ///
    /// The string payload carries the backend's error message so it can be logged.
    /// Do not match on the message text — use this variant only for logging / telemetry.
    #[error("injection backend error: {0}")]
    Backend(String),
}
