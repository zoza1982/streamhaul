#![no_main]
//! Fuzz target: the clipboard paste-injection sanitizer must be total and hold its safety
//! invariants on any input (it takes already-UTF-8-validated text, exactly like the wiring does
//! after `ClipboardUpdate::decode`). See ADR-0037 §6.

use libfuzzer_sys::fuzz_target;
use sh_clipboard::{is_forbidden_in_paste_output, sanitize_clipboard_text, sanitize_for_paste};

fuzz_target!(|data: &[u8]| {
    // The sanitizer operates on valid UTF-8 (the wire codec guarantees it upstream); only feed it
    // valid UTF-8, mirroring the real call site.
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let out = sanitize_clipboard_text(input);

    // (2) no forbidden scalar survives. Uses the crate's own policy predicate (the single source of
    // truth the sanitizer strips against) — so this checks the LOOP faithfully removes everything
    // the policy forbids, with no hand-maintained duplicate set to drift.
    assert!(
        out.chars().all(|c| !is_forbidden_in_paste_output(c)),
        "forbidden scalar survived sanitization"
    );
    // (3) non-growth: output never longer than input (preserves the 256 KiB wire bound).
    assert!(out.len() <= input.len(), "sanitizer grew the input");
    // (4) idempotent: a second pass changes nothing.
    assert_eq!(
        sanitize_clipboard_text(&out),
        out,
        "sanitizer is not idempotent"
    );
    // `sanitize_for_paste` agrees with the raw sanitizer and never yields `Some("")`.
    match sanitize_for_paste(input) {
        Some(t) => assert!(!t.is_empty() && t == out, "sanitize_for_paste disagreed"),
        None => assert!(out.is_empty(), "sanitize_for_paste skipped non-empty safe text"),
    }
});
