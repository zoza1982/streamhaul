//! No-op clipboard access -- reads empty, discards writes.

use crate::{ClipboardAccess, ClipboardError};

/// A [`ClipboardAccess`] that owns no real clipboard: reads return "empty", writes are discarded.
///
/// Useful as a placeholder when the real platform backend is not yet available (headless CI, or
/// the default before a `sh-platform-*` clipboard backend is linked in) and as a **fail-closed
/// stub** when the `CLIPBOARD` capability is denied -- a denied session gets a `NoopClipboard`, so
/// even a wiring bug cannot read or write the real OS clipboard.
///
/// [`get_text`](NoopClipboard::get_text) always returns `Ok(None)` (empty) and
/// [`set_text`](NoopClipboard::set_text) always returns `Ok(())`, both without allocating or
/// touching the OS.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopClipboard;

impl NoopClipboard {
    /// Create a new `NoopClipboard`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl ClipboardAccess for NoopClipboard {
    /// Always returns `Ok(None)` -- the no-op clipboard is always empty.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    fn get_text(&mut self) -> Result<Option<String>, ClipboardError> {
        Ok(None)
    }

    /// Accepts `text` and returns `Ok(())` without side effects.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    fn set_text(&mut self, _text: &str) -> Result<(), ClipboardError> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn get_text_is_always_empty() {
        let mut cb = NoopClipboard::new();
        assert_eq!(cb.get_text(), Ok(None));
    }

    #[test]
    fn set_text_always_ok_and_does_not_persist() {
        let mut cb = NoopClipboard::new();
        assert_eq!(cb.set_text("hello"), Ok(()));
        // A write is discarded: a subsequent read is still empty (fail-closed stub behavior).
        assert_eq!(cb.get_text(), Ok(None));
    }

    #[test]
    fn noop_clipboard_is_dyn_compatible() {
        let _boxed: Box<dyn ClipboardAccess> = Box::new(NoopClipboard::new());
    }
}
