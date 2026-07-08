//! The clipboard-update wire message carried on the Clipboard channel (`ChannelId::Clipboard`).
//!
//! Clipboard content flows in **both** directions (browser→host paste, host→browser paste) over the
//! reliable+ordered Clipboard channel. Like the bare [`InputEvent`](crate::InputEvent) on the input
//! channel, a [`ClipboardUpdate`] carries no [`CommonHeader`](crate::CommonHeader): the channel
//! identifies it and the DataChannel message boundary delimits it. See ADR-0037.
//!
//! The content is **untrusted** — a hostile peer can send arbitrary bytes claiming to be clipboard
//! text — so [`ClipboardUpdate::decode`] is total (never panics), bounds the size, and rejects
//! non-UTF-8 text; it is a `cargo-fuzz` target (CLAUDE.md §5). The content is **session data**: it is
//! never logged (§7).

use crate::error::ProtocolError;

/// Maximum clipboard payload accepted from the wire, a hostile-input DoS bound (256 KiB).
///
/// Comfortably covers real text clipboards; a peer cannot make the receiver buffer an unbounded
/// clipboard. Larger or binary formats are a future `format` id, not this version.
pub const MAX_CLIPBOARD_BYTES: usize = 256 * 1024;

/// Clipboard content format — the first wire byte of a [`ClipboardUpdate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardFormat {
    /// UTF-8 `text/plain`. Wire discriminant `0`.
    Text,
}

/// A clipboard update: `[format: u8][content …]` on the reliable+ordered Clipboard channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardUpdate {
    /// The content format.
    pub format: ClipboardFormat,
    /// The content bytes. For a [`ClipboardFormat::Text`] value produced by [`text`](Self::text) or
    /// [`decode`](Self::decode) this is valid UTF-8, but the field is public so a hand-built value
    /// need not be — consumers should read text via [`as_text`](Self::as_text) (which re-validates)
    /// rather than assume this is UTF-8.
    pub content: Vec<u8>,
}

impl ClipboardUpdate {
    /// Build a UTF-8 text clipboard update, bounded to [`MAX_CLIPBOARD_BYTES`].
    ///
    /// This enforces the **same** size bound as [`decode`](Self::decode), so a value built here
    /// always re-decodes (`decode(encode(x)) == Ok(x)`). Oversized content is rejected at
    /// construction rather than being silently dropped by the peer's `decode` — a send-side sink
    /// (e.g. the clipboard wiring reading a large OS clipboard) gets an explicit error to truncate
    /// or drop on.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::ClipboardTooLarge`] if `s` exceeds [`MAX_CLIPBOARD_BYTES`].
    ///
    /// # Examples
    /// ```
    /// use sh_protocol::ClipboardUpdate;
    /// let u = ClipboardUpdate::text("hello").unwrap();
    /// assert_eq!(ClipboardUpdate::decode(&u.encode()), Ok(u));
    /// ```
    pub fn text(s: &str) -> Result<Self, ProtocolError> {
        if s.len() > MAX_CLIPBOARD_BYTES {
            return Err(ProtocolError::ClipboardTooLarge(s.len()));
        }
        Ok(Self {
            format: ClipboardFormat::Text,
            content: s.as_bytes().to_vec(),
        })
    }

    /// The content as `&str`, or `None` for a non-text format.
    ///
    /// Always `Some` for a [`ClipboardFormat::Text`] value produced by [`text`](Self::text) or
    /// [`decode`](Self::decode) (both guarantee valid UTF-8).
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self.format {
            ClipboardFormat::Text => core::str::from_utf8(&self.content).ok(),
        }
    }

    /// Serialize to the wire form `[format][content]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.content.len().saturating_add(1));
        out.push(format_to_u8(self.format));
        out.extend_from_slice(&self.content);
        out
    }

    /// Parse a [`ClipboardUpdate`] from the wire. **Total** — never panics on any input.
    ///
    /// # Errors
    ///
    /// - [`ProtocolError::Truncated`] if `bytes` is empty (no format byte).
    /// - [`ProtocolError::InvalidClipboardFormat`] for an unknown format byte.
    /// - [`ProtocolError::ClipboardTooLarge`] if the content exceeds [`MAX_CLIPBOARD_BYTES`].
    /// - [`ProtocolError::InvalidClipboardText`] if a [`ClipboardFormat::Text`] payload is not valid
    ///   UTF-8 (never hand malformed text to an OS clipboard).
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let (&fmt, content) = bytes
            .split_first()
            .ok_or(ProtocolError::Truncated { needed: 1, have: 0 })?;
        let format = format_from_u8(fmt)?;
        if content.len() > MAX_CLIPBOARD_BYTES {
            return Err(ProtocolError::ClipboardTooLarge(content.len()));
        }
        match format {
            ClipboardFormat::Text => {
                if core::str::from_utf8(content).is_err() {
                    return Err(ProtocolError::InvalidClipboardText);
                }
            }
        }
        Ok(Self {
            format,
            content: content.to_vec(),
        })
    }
}

const FORMAT_TEXT: u8 = 0;

fn format_to_u8(f: ClipboardFormat) -> u8 {
    match f {
        ClipboardFormat::Text => FORMAT_TEXT,
    }
}

fn format_from_u8(b: u8) -> Result<ClipboardFormat, ProtocolError> {
    match b {
        FORMAT_TEXT => Ok(ClipboardFormat::Text),
        other => Err(ProtocolError::InvalidClipboardFormat(other)),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn round_trips_text() {
        let u = ClipboardUpdate::text("hello, 世界 🌍").unwrap();
        let decoded = ClipboardUpdate::decode(&u.encode()).unwrap();
        assert_eq!(decoded, u);
        assert_eq!(decoded.as_text(), Some("hello, 世界 🌍"));
    }

    #[test]
    fn round_trips_empty_text() {
        let u = ClipboardUpdate::text("").unwrap();
        assert_eq!(ClipboardUpdate::decode(&u.encode()), Ok(u));
    }

    #[test]
    fn text_rejects_oversize_at_construction() {
        // Symmetric with `decode`'s bound: a > MAX string can't be built (so it can't be encoded
        // into a message the peer would reject).
        let big = "a".repeat(MAX_CLIPBOARD_BYTES + 1);
        assert!(matches!(
            ClipboardUpdate::text(&big),
            Err(ProtocolError::ClipboardTooLarge(n)) if n == MAX_CLIPBOARD_BYTES + 1
        ));
    }

    #[test]
    fn format_wire_values_are_stable() {
        // Cross-version wire contract: `Text` MUST stay 0 so a future format id can't shift it.
        assert_eq!(format_to_u8(ClipboardFormat::Text), 0);
    }

    #[test]
    fn decode_checks_format_before_size() {
        // An unknown format with oversize content must fail as InvalidClipboardFormat (format is
        // validated first) — and no large copy is made.
        let mut bytes = vec![0xFF];
        bytes.extend(std::iter::repeat_n(b'a', MAX_CLIPBOARD_BYTES + 1));
        assert!(matches!(
            ClipboardUpdate::decode(&bytes),
            Err(ProtocolError::InvalidClipboardFormat(0xFF))
        ));
    }

    #[test]
    fn decode_rejects_empty_input() {
        assert!(matches!(
            ClipboardUpdate::decode(&[]),
            Err(ProtocolError::Truncated { needed: 1, have: 0 })
        ));
    }

    #[test]
    fn decode_rejects_unknown_format() {
        assert!(matches!(
            ClipboardUpdate::decode(&[0xFF, b'x']),
            Err(ProtocolError::InvalidClipboardFormat(0xFF))
        ));
    }

    #[test]
    fn decode_rejects_invalid_utf8_text() {
        // format Text (0) + an invalid UTF-8 byte sequence.
        assert!(matches!(
            ClipboardUpdate::decode(&[FORMAT_TEXT, 0xFF, 0xFE]),
            Err(ProtocolError::InvalidClipboardText)
        ));
    }

    #[test]
    fn decode_rejects_oversize() {
        let mut bytes = vec![FORMAT_TEXT];
        bytes.extend(std::iter::repeat_n(b'a', MAX_CLIPBOARD_BYTES + 1));
        assert!(matches!(
            ClipboardUpdate::decode(&bytes),
            Err(ProtocolError::ClipboardTooLarge(n)) if n == MAX_CLIPBOARD_BYTES + 1
        ));
    }

    #[test]
    fn decode_accepts_exactly_max() {
        let mut bytes = vec![FORMAT_TEXT];
        bytes.extend(std::iter::repeat_n(b'a', MAX_CLIPBOARD_BYTES));
        assert!(ClipboardUpdate::decode(&bytes).is_ok());
    }

    proptest! {
        /// Any valid string (within the size bound; `.*` yields short strings) round-trips.
        #[test]
        fn text_round_trips(s in ".*") {
            let u = ClipboardUpdate::text(&s).unwrap();
            prop_assert_eq!(ClipboardUpdate::decode(&u.encode()).unwrap(), u);
        }

        /// decode never panics on arbitrary bytes, and any Ok is a valid, bounded, UTF-8 text update.
        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            if let Ok(u) = ClipboardUpdate::decode(&data) {
                prop_assert!(u.content.len() <= MAX_CLIPBOARD_BYTES);
                prop_assert!(u.as_text().is_some(), "a decoded Text update must be valid UTF-8");
            }
        }
    }
}
