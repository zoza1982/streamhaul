//! Recording clipboard access -- captures writes and serves a preset read value, for tests.

use crate::{ClipboardAccess, ClipboardError};

/// A [`ClipboardAccess`] **test double**: it records every [`set_text`](RecordingClipboard::set_text)
/// write in order and serves a preset value from [`get_text`](RecordingClipboard::get_text).
///
/// Feed writes in and assert on [`writes`](RecordingClipboard::writes) to verify the host paste path
/// (browser->host) delivered the right text in the right order; preset a read value with
/// [`set_read_value`](RecordingClipboard::set_read_value) to drive the read path (host->browser).
///
/// The internal write log **grows unbounded** -- every write is retained. That is fine for tests;
/// call [`clear`](RecordingClipboard::clear) between assertion phases. It is a test double, not a
/// production backend (a real backend performs no such retention -- and §7 forbids retaining
/// session content in production).
///
/// # Example
///
/// ```rust
/// use sh_clipboard::{ClipboardAccess, RecordingClipboard};
///
/// let mut cb = RecordingClipboard::new();
///
/// // Read path: serve a preset value.
/// cb.set_read_value(Some("copied on the peer".to_owned()));
/// assert_eq!(cb.get_text(), Ok(Some("copied on the peer".to_owned())));
///
/// // Write path: record what the peer pasted.
/// cb.set_text("pasted from the peer").unwrap();
/// assert_eq!(cb.writes(), &["pasted from the peer".to_owned()]);
/// ```
#[derive(Debug, Default)]
pub struct RecordingClipboard {
    writes: Vec<String>,
    read_value: Option<String>,
}

impl RecordingClipboard {
    /// Create a new, empty `RecordingClipboard` whose read value is empty (`None`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            writes: Vec::new(),
            read_value: None,
        }
    }

    /// Set the value that [`get_text`](RecordingClipboard::get_text) will return.
    ///
    /// `Some(text)` makes reads return that text; `None` makes reads return "empty".
    pub fn set_read_value(&mut self, value: Option<String>) {
        self.read_value = value;
    }

    /// Return, in order, the text of every [`set_text`](RecordingClipboard::set_text) call.
    #[must_use]
    pub fn writes(&self) -> &[String] {
        &self.writes
    }

    /// Return the number of writes recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// Return `true` if no writes have been recorded yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// Clear the recorded writes (leaves the preset read value untouched).
    pub fn clear(&mut self) {
        self.writes.clear();
    }
}

impl ClipboardAccess for RecordingClipboard {
    /// Return a clone of the preset read value (see
    /// [`set_read_value`](RecordingClipboard::set_read_value)).
    ///
    /// # Errors
    ///
    /// Never returns an error; the recording read always succeeds.
    fn get_text(&mut self) -> Result<Option<String>, ClipboardError> {
        Ok(self.read_value.clone())
    }

    /// Record `text` and return `Ok(())`.
    ///
    /// # Errors
    ///
    /// Never returns an error; the recording write always succeeds.
    fn set_text(&mut self, text: &str) -> Result<(), ClipboardError> {
        self.writes.push(text.to_owned());
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn starts_empty() {
        let cb = RecordingClipboard::new();
        assert!(cb.is_empty());
        assert_eq!(cb.len(), 0);
        assert_eq!(cb.writes(), &[] as &[String]);
    }

    #[test]
    fn get_text_defaults_to_none() {
        let mut cb = RecordingClipboard::new();
        assert_eq!(cb.get_text(), Ok(None));
    }

    #[test]
    fn get_text_serves_preset_value() {
        let mut cb = RecordingClipboard::new();
        cb.set_read_value(Some("hello, 世界 🌍".to_owned()));
        assert_eq!(cb.get_text(), Ok(Some("hello, 世界 🌍".to_owned())));
        // Reading does not consume the value: a second read returns it again.
        assert_eq!(cb.get_text(), Ok(Some("hello, 世界 🌍".to_owned())));
    }

    #[test]
    fn set_read_value_overwrites_rather_than_accumulates() {
        let mut cb = RecordingClipboard::new();
        cb.set_read_value(Some("first".to_owned()));
        cb.set_read_value(Some("second".to_owned()));
        // The latest preset replaces the previous one; reads never see a stale value.
        assert_eq!(cb.get_text(), Ok(Some("second".to_owned())));
    }

    #[test]
    fn set_read_value_none_returns_empty() {
        let mut cb = RecordingClipboard::new();
        cb.set_read_value(Some("x".to_owned()));
        cb.set_read_value(None);
        assert_eq!(cb.get_text(), Ok(None));
    }

    #[test]
    fn records_single_write() {
        let mut cb = RecordingClipboard::new();
        cb.set_text("one").unwrap();
        assert_eq!(cb.len(), 1);
        assert!(!cb.is_empty());
        assert_eq!(cb.writes(), &["one".to_owned()]);
    }

    #[test]
    fn preserves_write_order() {
        let mut cb = RecordingClipboard::new();
        for s in ["a", "b", "c"] {
            cb.set_text(s).unwrap();
        }
        assert_eq!(
            cb.writes(),
            &["a".to_owned(), "b".to_owned(), "c".to_owned()]
        );
    }

    #[test]
    fn clear_resets_writes_but_not_read_value() {
        let mut cb = RecordingClipboard::new();
        cb.set_read_value(Some("keep".to_owned()));
        cb.set_text("gone").unwrap();
        cb.clear();
        assert!(cb.is_empty());
        assert_eq!(cb.writes(), &[] as &[String]);
        // The preset read value survives a `clear`.
        assert_eq!(cb.get_text(), Ok(Some("keep".to_owned())));
    }

    #[test]
    fn recording_clipboard_is_dyn_compatible() {
        let _boxed: Box<dyn ClipboardAccess> = Box::new(RecordingClipboard::new());
    }

    #[test]
    fn empty_string_write_is_recorded_distinct_from_no_write() {
        let mut cb = RecordingClipboard::new();
        cb.set_text("").unwrap();
        // An empty-string write is a real write, distinct from never having written.
        assert_eq!(cb.len(), 1);
        assert_eq!(cb.writes(), &[String::new()]);
    }
}
