# sh-clipboard

Portable clipboard-access seam for the Streamhaul host and browser wiring.

## What this crate provides

| Item | Description |
|------|-------------|
| `ClipboardAccess` | Object-safe trait: `get_text(&mut self) -> Result<Option<String>, _>` and `set_text(&mut self, &str) -> Result<(), _>` |
| `sanitize_clipboard_text` | Paste-injection hardening: strips control/bidi/invisible scalars + normalizes line endings before a paste sink |
| `NoopClipboard` | Reads empty, discards writes; placeholder **and** fail-closed stub for a capability-denied session |
| `RecordingClipboard` | Records writes and serves a preset read value; a test double |
| `ClipboardError` | `thiserror`-derived error type for clipboard-access failures |

## Architecture

```
Transport Clipboard channel
      │ ClipboardUpdate (bare [format][content], sh_protocol)
      ▼
 decode() → as_text()      ← validates format, bounds size (256 KiB), rejects non-UTF-8
      │ &str (valid UTF-8)
      ▼
 ClipboardAccess::set_text()   ← writes text to the OS clipboard (host→browser paste)
 ClipboardAccess::get_text()   ← reads text from the OS clipboard (browser→host paste)
      │
      ▼
 OS (X11 selections / NSPasteboard / Windows clipboard …)
```

Real platform backends (`sh-platform-linux`, `sh-platform-mac`, `sh-platform-win`) implement
`ClipboardAccess` and drop in without touching callers — the same trait-seam pattern as
`sh-input` (`InputInjector`) / `sh-media` (traits) / `sh-codec-hw` (impls).

## Text only (v1)

The trait deals in `String`/`&str` — valid UTF-8 by construction. The wire format
(`ClipboardUpdate`) is `text/plain` only in v1 and its `decode` rejects non-UTF-8, so nothing
malformed reaches this trait. A future non-text format (HTML/image) is a new wire `format` id with
its own sanitizer and threat model (ADR-0037), not a widening of this trait.

## Security

Clipboard content is untrusted and is session data (never logged, §7). The wire codec
(`sh_protocol::ClipboardUpdate`) owns hostile-input parsing (bounded, UTF-8-validated, fuzzed). The
*wiring* that drives this trait owns the rest (ADR-0037):

- a **fail-closed** `CLIPBOARD` capability gate on the *receive* path in **both** directions;
- **never** logging content (`ClipboardError` payloads describe the failure, never the content);
- running **`sanitize_clipboard_text`** before every paste sink (control/bidi/invisible stripping +
  line-ending normalization — the paste-injection hardening from ADR-0037 §6), skipping the write
  when it returns empty for a non-empty input.

`NoopClipboard` is the fail-closed default: a capability-denied session is handed a `NoopClipboard`,
so even a wiring bug cannot read or write the real OS clipboard.

## Status

Portable slice (ADR-0037 PR 2). Host + browser wiring and real OS backends (X11
`PRIMARY`/`CLIPBOARD`, macOS `NSPasteboard`, Windows clipboard) are deferred to follow-up PRs and
`sh-platform-*`, exactly like the input injectors.
