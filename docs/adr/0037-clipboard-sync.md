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

### Paste-injection hardening (this PR)

`sh_clipboard::sanitize_clipboard_text(&str) -> String` — a **total, infallible** receive-path
filter the wiring MUST run before `ClipboardAccess::set_text` on both peers (Security item 6). It is
a single pass: line-ending normalization (`CRLF`, lone `CR`, `U+2028`, `U+2029` → a single `LF`) plus
a strip of the control/bidi/invisible-smuggling class, keeping only `TAB` + `LF` among controls and
all printable text (every script + emoji):

| Removed | Why |
|---------|-----|
| C0 controls except `TAB`/`LF` (incl. **`ESC` `U+001B`**), `DEL` | ANSI/CSI/OSC sequences, cursor tricks, and the bracketed-paste terminator `ESC[201~` — stripping `ESC` means a payload can neither emit an escape sequence nor break out of bracketed paste |
| C1 controls `U+0080`–`U+009F` (incl. 8-bit `CSI` `U+009B`, `NEL` `U+0085`) | raw-byte path around the `ESC` defense |
| bidi controls `U+202A`–`U+202E`, `U+2066`–`U+2069`, `U+200E`/`U+200F`, `U+061C` | **Trojan Source (CVE-2021-42574)** — display order ≠ logical order (natural RTL still renders without them) |
| zero-width / invisible format `U+200B`–`U+200D`, `U+00AD`, `U+180E`, `U+2060`–`U+2064`, `U+206A`–`U+206F`, `U+FEFF`, `U+FFF9`–`U+FFFB`, `U+1D173`–`U+1D17A` | hidden payload / homoglyph concealment |
| Tag block `U+E0000`–`U+E007F` | ASCII-smuggling / hidden-command steganography |
| Unicode noncharacters `U+FDD0`–`U+FDEF`, every plane's `*FFFE`/`*FFFF` | never valid for interchange |

It **never rejects** (rejection would be a DoS/annoyance primitive — a hostile peer could kill the
victim's clipboard sync with one control char; the user gets the safe substring instead). It only
removes/normalizes, so output is valid UTF-8 and never longer than input — the 256 KiB bound holds
without re-checking. The strip policy has a single source of truth, the exported predicate
`is_forbidden_in_paste_output`, which the filter, the proptests, and the fuzz target all consume (no
duplicated set to drift). **Caller obligation, made un-forgettable:** the wiring calls
`sanitize_for_paste(&str) -> Option<String>`, which returns `None` when nothing safe remains (empty
or all-control input) so the caller **skips** `set_text` rather than clobbering the local clipboard
with an attacker-forced empty value. Proptest invariants (total, no-forbidden-survives, non-growth,
idempotent, identity-on-safe-subset) run every PR; a `clipboard_sanitize` `cargo-fuzz` target runs
nightly (§5). `U+200C`/`U+200D` (ZWNJ/ZWJ) are stripped in v1 (security-first; degrades some emoji-ZWJ
and ZWNJ-dependent orthography — a future whitelist-inside-grapheme-cluster refinement candidate);
variation selectors `U+FE00`–`U+FE0F` are kept for emoji/CJK fidelity.

**Residual risks the sanitizer does NOT close** (honest scope): social engineering (a user pasting
*visible* `curl … | sh` and pressing Enter); embedded `LF` into a sink without bracketed paste (kept
by design — we guarantee the payload can't *disable* bracketed paste, not that the sink supports it);
homoglyph/confusable spoofing (no confusable folding — would break legitimate non-Latin text);
spreadsheet/CSV formula injection (leading `=`/`+`/`-`/`@` — a paste-target-app concern);
variation-selector steganography; and any fully-valid-printable malicious content (not a content
scanner). Reading-side exfiltration is a capability-gate/consent concern (items 1–2), not the
sanitizer's.

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
   payloads). **Done (this PR):** `sh_clipboard::sanitize_clipboard_text` — see "Paste-injection
   hardening" under Decision for the concrete policy, invariants, and residual risks. The wiring
   MUST call `sanitize_for_paste` before every `set_text` and skip the write on `None` (nothing safe
   to write).
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
