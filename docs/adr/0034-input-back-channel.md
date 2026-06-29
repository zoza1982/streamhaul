# ADR 0034: Input back-channel — browser drives the host (remote control)

- **Status:** Accepted
- **Date:** 2026-06-29
- **Deciders:** rust-staff-engineer, realtime-systems-engineer (consulted), security-engineer (consulted)
- **Builds on:** ADR-0031/0032/0033 (browser↔host video), P1-2/P1-3 (`sh-input` InputInjector + SHP InputEvent)

## Context

The browser↔host path was view-only: the host streams video, but the browser's keyboard/mouse
went nowhere — so it was a *viewer*, not a *remote desktop*. The pieces to close the loop already
existed: the browser encodes DOM input to the 16-byte SHP `InputEvent` wire form
(`encode_input_event`, proven by the loopback e2e), and `sh-input` defines `InputInjector` with OS
backends (`XTestInjector` on Linux). What was missing was the **host receiving** input off the
DataChannel and injecting it.

## Decision

Add a browser→host input back-channel on the **same** "shp" DataChannel.

- **Wire:** the browser sends bare 16-byte `InputEvent`s (no extra framing). The host only ever
  *sends* video on this channel, so on the host's *receive* side every inbound message is
  browser→host input. The host ignores any non-16-byte message (e.g. the channel-open HELLO frame).
- **Host (lib):** `run_video_stream` drains inbound messages between video frames with a
  **non-blocking** `tokio::time::timeout(ZERO, channel.recv())` poll. `recv` is cancel-safe: it only
  consumes a message after popping it from the channel's queue under the mutex, so cancelling the
  ZERO-timeout future at its internal `notified().await` leaves the queue untouched (the message is
  delivered on the next poll). Each 16-byte message is `InputEvent::decode`d (`decode_input`) and
  pushed onto a **bounded** channel feeding a **dedicated `spawn_blocking` injection thread** that
  owns the `Box<dyn InputInjector>` (carried in `StreamMode::Video`). This honors the
  `InputInjector` contract — inject() runs off the async executor, so a synchronous XTEST/X11 call
  can't stall the video loop — and the bounded queue (`try_send`, drop-on-full) is the natural
  backpressure/flood point. The per-frame drain is also capped (`MAX_INPUT_PER_FRAME`) so a flood
  can't starve video. Input latency is ≤ one frame interval (~33 ms at 30 fps). Malformed events and
  injection errors are logged, never fatal (hostile input cannot crash the host).
- **Injector is supplied by the binary:** the live `streamhaul-webrtc-preview` host injects into the
  real X11 session via `XTestInjector` — **actual remote control**. The workspace
  `streamhaul-webrtc-host` (which runs in CI with no display) uses a `StdoutInputLogger` that prints
  `INPUT_INJECTED ...` per event, proving receipt+decode without touching the OS.

## Verification

- **Host unit tests:** `decode_and_inject` round-trips a browser-encoded `InputEvent` into a
  `RecordingInjector`, and ignores non-16-byte / malformed messages (never injects garbage).
- **Browser→host e2e (CI):** the `browser-native` video test's browser sends synthetic
  `PointerMove` events via `viewer.send_frame(encode_input_event(...))`; the test asserts the host's
  stdout shows `INPUT_INJECTED` — proving the **full** browser→host control path in headless Firefox.
- The browser input *encode* path is already covered by the loopback e2e + input-map unit tests.

## Consequences

- **Positive:** the browser↔host session is now a real **remote desktop** — full-resolution video
  out (ADR-0033) and keyboard/mouse control in. The live preview host drives the actual desktop. No
  transport-trait change; no security-surface change (input only flows after the pinned DTLS channel
  is up — same as video).
- **Negative / trade-offs:** input latency is bounded by the frame interval (the sequential
  drain-between-frames); a dedicated low-latency input path (a separate Input channel + task) is a
  follow-up if needed. The bounded injection queue **drops events under a sustained flood** — and a
  dropped button-up could leave a mouse button *stuck*. **Mitigated:** the injection thread calls
  `InputInjector::release_all()` on session end, so a disconnect can't leave a button held. This is
  implemented on **all three OS backends** — `XTestInjector` (Linux), `CgEventInjector` (macOS), and
  `SendInputInjector` (Windows) each release any button still set in their `prev_button_mask`. On
  every backend keys/modifiers are emitted as **atomic press+release pairs** so they never latch —
  the latched mouse-button state is the only stuck-state surface, and it is now released everywhere.
  (The Linux path is verified end-to-end against the X server via `QueryPointer`; the macOS/Windows
  overrides assert the tracked-state bookkeeping on their CI runners, with live OS-effect validation
  deferred to hardware per R-MAC-TCC / R-WIN-INTERACTIVE.) Still deferred: *mid-session* gap
  detection (a button-up dropped mid-stream stays stuck until session end; needs input sequence
  numbers). No explicit rate-limiting beyond the queue depth yet.
  Coordinates are normalized (0..=65535); per-monitor mapping is the injector's responsibility
  (`CoordMapper`).
- **Follow-ups:** a dedicated Input channel/task for lower latency; input rate-limiting; clipboard;
  multi-monitor coordinate mapping; macOS/Windows injectors on the preview host.
