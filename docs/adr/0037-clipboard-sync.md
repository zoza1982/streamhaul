# ADR 0037: Clipboard sync (browser ↔ host)

- **Status:** Accepted (wire format, portable crate, paste hardening, and **both directions** of
  browser↔host clipboard sync done through PR 6; real OS clipboard backends, the `navigator.clipboard`
  user-gesture read, and the UGC capability gate staged)
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

### Host receive wiring (this PR)

The host session accepts an optional dedicated Clipboard channel alongside video/input (one shared
bounded accept window for both optional channels; classified order-independently by parsed
`ChannelSpec`). A dedicated `run_clipboard_recv` task owns the channel and applies every browser→host
paste in arrival order: `ClipboardUpdate::decode` → `sanitize_for_paste` → `ClipboardAccess::set_text`
(skip on empty). It is **not** a session driver — its close is a non-fatal event; video/input remain
the drivers — and it is always aborted+awaited on session end. `set_text` runs on `spawn_blocking`
(the trait's contract allows an OS/IPC-blocking backend), awaited before the next message so writes
apply in wire order. The workspace host uses `StdoutClipboardLogger` (a CI mock logging **only** a
byte count + sequence, never content — §7), proving receipt+decode+sanitize without an OS clipboard;
the fail-closed default sink is `NoopClipboard` (the live preview uses it until an OS backend lands).

**Transport message-size bound (item 5) — still deferred.** The receive path enforces the 256 KiB
bound *after* `decode`, but `sh-transport` has no per-channel max-message-size cap today — only the
blanket 16 MiB `MAX_FRAME_LEN` on every reliable channel. So a hostile peer can still make the
transport buffer up to ~16 MiB per bogus Clipboard message before `decode`'s 256 KiB check runs. This
is a pre-existing transport-layer gap (it applies to every reliable channel, not just clipboard), not
fixable in the host wiring; it remains a tracked follow-up (item 5), called out here rather than left
silent.

**Capability gate — deferred, tracked, consistent with input.** ADR item 1 requires a fail-closed
`CLIPBOARD` capability gate on the receive path. The `streamhaul-webrtc-host` session has **no**
authorization plumbing today — the dedicated Input channel (remote control) is likewise not
`CONTROL`-gated; this is the `insecure-lan` dev/preview harness (`TrustAllKeystore`). Rather than
invent a clipboard-only gate the rest of the host lacks, the fail-closed posture here is the **inert
default sink** (`NoopClipboard` can neither read nor write a real OS clipboard), and a UGC-driven
`SessionAuthorizer` gate for *all* privileged channels (input + clipboard) is a tracked follow-up.
This is called out honestly rather than silently skipped (CLAUDE.md §11).

### Browser send wiring (this PR)

`sh-web-client`'s `create_offer` now opens a third DataChannel — clipboard, label `"3:2:1"`
(`ChannelId::Clipboard` = 3, priority 2, ordered), which round-trips to `ChannelSpec::clipboard()`
via the host's `parse_channel_label` (pinned by `dedicated_input_channel_labels_route_correctly`).
The new `WebClient::send_clipboard` sends a `ClipboardUpdate` on it; `sh_wasm::encode_clipboard_text`
builds the wire bytes (the TS never serializes the wire — browser and host share one codec).
End-to-end: the `browser-native` e2e sends a CRLF-containing paste via `send_clipboard` and asserts
the host's `CLIPBOARD_PASTED` log, proving browser→host clipboard sync over a real DTLS DataChannel
in headless Firefox (the host applies the sanitized, line-ending-normalized text).

### Host→browser direction (this PR)

Both directions now flow over the one bidirectional Clipboard channel. On session start the host's
`run_clipboard` task reads its clipboard (`get_text`, off the runtime via `spawn_blocking`) and, if
non-empty, sends it once as a `ClipboardUpdate` (host→browser); it then loops applying browser→host
pastes. The browser's `WebClient::on_clipboard` delivers the raw wire bytes; the app decodes **and
sanitizes** them with `sh_wasm::decode_and_sanitize_clipboard` (host content is untrusted — the SAME
`sanitize_for_paste` hardening runs browser-side) before a best-effort `navigator.clipboard.writeText`.
The workspace host offers via a `--offer-clipboard <text>` flag (a real host reads the OS clipboard
here); the `browser-native` e2e drives it and asserts the browser received the exact sanitized text,
proving host→browser sync end to end in headless Firefox.

### OS backends + capability gate (follow-up PRs)

Real OS clipboard backends (X11 selections, `NSPasteboard`, Windows clipboard) — so the host offers
its *actual* clipboard and the browser reads the *real* browser clipboard on a user gesture — and the
UGC capability gate are follow-up PRs, deferred like the input injectors' OS backends.

## Security

- **Untrusted content:** `decode` validates the format, bounds the size (256 KiB), and rejects
  non-UTF-8 text — a hostile peer cannot panic the parser, exhaust memory, or inject invalid text.
  The parser is fuzzed (§5).
- **§7:** clipboard content is session data and is **never logged** (the CI mock logs only a byte
  count + format, never the text).
- **Authorization:** clipboard flows only when the session's `CLIPBOARD` capability is granted
  (P3-5) — enforced at the host wiring layer, not the wire layer. In the current dev/preview host
  the fail-closed posture is the inert `NoopClipboard` default sink; a UGC-driven `SessionAuthorizer`
  gate for all privileged channels (input + clipboard) is a tracked follow-up (see "Host receive
  wiring").

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
