//! Error type for clipboard-access failures.

use thiserror::Error;

/// Errors that can occur while reading from or writing to an OS clipboard.
///
/// Variants are matchable so callers can distinguish a permanent capability gap
/// ([`Unsupported`](ClipboardError::Unsupported)) from a transient backend hiccup
/// ([`Backend`](ClipboardError::Backend)).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClipboardError {
    /// This backend does not support the requested clipboard operation.
    ///
    /// For example, a read-only or write-only backend, or a headless environment with no
    /// selection owner. Callers decide whether to skip or escalate.
    #[error("unsupported clipboard operation: {reason}")]
    Unsupported {
        /// Human-readable description of why the operation is unsupported.
        reason: &'static str,
    },

    /// An OS-level or backend-specific clipboard failure.
    ///
    /// The string payload carries the backend's error message so it can be logged. Do not match on
    /// the message text — use this variant only for logging / telemetry.
    ///
    /// **§7 (load-bearing for backend authors):** this string is a log/telemetry surface, so it MUST
    /// describe the *failure* and MUST NEVER embed the clipboard *content* (or its length, or any
    /// substring). Clipboard text is session data — arbitrary user text (passwords, PII),
    /// categorically more sensitive than an input keycode. Do not `{:?}`/`{}`-format the text being
    /// read or written into this message, even while debugging.
    #[error("clipboard backend error: {0}")]
    Backend(String),
}
