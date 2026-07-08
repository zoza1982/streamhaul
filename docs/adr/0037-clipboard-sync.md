# ADR 0037: Clipboard sync (browser ↔ host)

- **Status:** Accepted (wire format = PR 1; portable crate, host + browser wiring, OS backends staged)
- **Date:** 2026-07-06
- **Deciders:** software-architect (design), security-engineer (consulted)
- **Builds on:** ADR-0034 (input back-channel — the pattern this mirrors), P1-1 (multi-channel
  `Transport`/`Channel`, `ChannelId::Clipboard`), P3-5 (the `CLIPBOARD` capability bit)

## Context

A remote desktop must sync the clipboard so the user can copy on one side and paste on the other.
The scaffolding already exists — `ChannelId::Clipboard` (wire discriminant 3),
`ChannelSpec::clipboard()` (reliable + ordered, urgency 2), and the `CLIPBOARD` authorization
capability — but nothing carries clipboard content yet. Clipboard content is **untrusted** in both
directions (a hostile peer can send arbitrary bytes claiming to be clipboard text) and is **session
content** (§7: never logged).

## Decision

Sync clipboard **text** over the reliable+ordered `ChannelId::Clipboard` channel, mirroring the
input back-channel (ADR-0034): a small fuzzable wire message + a portable OS-access trait with
mocks + thin host/browser wiring, OS backends deferred like the injectors.

### Wire format (this PR)

A **`ClipboardUpdate`** carried as a bare message on the Clipboard channel (the channel identifies
it; the DataChannel message boundary delimits it — no `CommonHeader`, exactly like the bare
`InputEvent` on the Input channel):

```
[ format: u8 ][ content: bytes … ]
```

- `format`: `0` = `Text` (UTF-8 `text/plain`). Unknown format → decode error (never guessed).
- `content`: the clipboard bytes. For `Text`, **validated as UTF-8 on decode** — malformed text is
  rejected, never handed to an OS clipboard.
- **Bound:** `content.len() > MAX_CLIPBOARD_BYTES` (256 KiB) → decode error. A hostile peer cannot
  make the host buffer/allocate an unbounded clipboard. (256 KiB comfortably covers real text
  clipboards; larger/binary formats are a future format id, not this PR.)

`decode` is **total** (never panics/allocates unboundedly on any input) and is a **`cargo-fuzz`
target** (§5 — a parser of untrusted network bytes).

### Portable access trait (follow-up PR)

A `sh-clipboard` crate with a `ClipboardAccess` trait (`get_text`/`set_text`) + portable mocks
(`NoopClipboard`, `RecordingClipboard`), mirroring `sh-input`'s `InputInjector` + `Noop`/`Recording`.
Real OS backends (X11 `PRIMARY`/`CLIPBOARD` selections, macOS `NSPasteboard`, Windows clipboard) are
deferred to `sh-platform-*` and gated on hardware, exactly like the injectors.

### Host + browser wiring (follow-up PRs)

The host routes the Clipboard channel to a `Box<dyn ClipboardAccess>`; the browser bridges
`navigator.clipboard` to the Clipboard channel. Both directions (host→browser paste, browser→host
paste) gated by the `CLIPBOARD` capability. A CI logger mock (like `StdoutInputLogger`) proves
receipt+decode without touching the OS.

## Security

- **Untrusted content:** `decode` validates the format, bounds the size (256 KiB), and rejects
  non-UTF-8 text — a hostile peer cannot panic the parser, exhaust memory, or inject invalid text.
  The parser is fuzzed (§5).
- **§7:** clipboard content is session data and is **never logged** (the CI mock logs only a byte
  count + format, never the text).
- **Authorization:** clipboard flows only when the session's `CLIPBOARD` capability is granted
  (P3-5) — enforced at the host wiring layer (follow-up PR), not the wire layer.

### Requirements for the wiring PRs (security-engineer review — **MUST**)

The wire codec is a pure (de)serializer; the following are the wiring layer's responsibility and
MUST hold before clipboard content touches any OS or the peer:

1. **Capability gate: fail-closed, checked on the *receive* path in BOTH directions** (host→browser
   *and* browser→host) before any OS clipboard call — either direction is an exfiltration/injection
   primitive.
2. **Consent for reads:** reading the browser clipboard requires an explicit user gesture /
   permission (browsers enforce this) — the wiring MUST NOT try to defeat the prompt. A granted
   capability at pairing time is not standing consent to harvest whatever the user later copies.
3. **Never log content:** never `{:?}`-log a `ClipboardUpdate` (its `Debug` renders `content`); the
   CI logger mock logs only `content.len()` + the format discriminant, never `as_text()`.
4. **Consume only via `as_text()`:** never trust the public `content: Vec<u8>` to be UTF-8.
5. **Bound the transport max-message-size** on the Clipboard channel to ~`MAX_CLIPBOARD_BYTES` — the
   256 KiB bound protects *post-receive* allocation, but the DataChannel buffers the whole message
   *before* `decode` sees it (reliable channels are length-delimited by a `u32` prefix under
   `sh-transport`), so a peer could otherwise make the transport buffer a large message that `decode`
   then rejects, defeating the DoS bound at the buffer.
6. **Paste-injection hardening** at the host paste/inject sink: even `text/plain` can carry C0
   control chars / bracketed-paste-bypass sequences (`curl | sh` drops, homoglyph/hidden-newline
   payloads) — threat-model this and consider stripping/normalizing control characters before a
   paste sink.
7. **Any future non-text format id** (HTML/image) gets its own threat model, sanitizer, and fuzz
   target before it ships — UTF-8-only in v1 is a deliberate injection-surface minimization.

## Consequences

- **Positive:** a real clipboard-sync capability on the existing Clipboard channel; the wire format
  is minimal, bounded, fuzzed, and format-extensible (a new `format` id adds HTML/image later).
- **Negative / follow-ups:** the `sh-clipboard` trait/mocks, host + browser wiring, and OS backends
  are separate PRs; only `text/plain` in v1 (binary/HTML formats are future format ids); large-format
  fragmentation (if a format ever exceeds one DataChannel message) is deferred. `ClipboardFormat` is
  intentionally NOT `#[non_exhaustive]`: adding a format id is a *deliberate* breaking change — the
  exhaustive `match` forces every call site (`decode`/`as_text`/the format converters, and any
  out-of-workspace consumer) to handle the new variant rather than silently ignore it.
