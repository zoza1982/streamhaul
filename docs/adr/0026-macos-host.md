# ADR 0026: macOS host platform — CoreGraphics capture + CGEvent injection (compile-verified)

- **Status:** Accepted
- **Date:** 2026-06-25
- **Deciders:** mobile-engineer, realtime-systems-engineer, security-engineer (consulted)

## Context

Phase 6 (P6-1) adds the macOS host. Unlike the Linux X11 slice (P6-2), which we verified at
**runtime** in CI via Xvfb, macOS capture and input injection are gated behind **TCC** (Transparency,
Consent & Control): `ScreenCaptureKit`/`CGDisplayCreateImage` require **Screen Recording** permission,
and `CGEventPost` to other apps requires **Accessibility** permission. Neither can be granted on a
headless GitHub Actions `macos-latest` runner (there is no logged-in GUI session to approve the TCC
prompt). So a macOS host cannot be *runtime*-verified in CI.

However — per the request — CI **can** still do a great deal: GitHub Actions has real macOS runners,
so it compiles the crate against the **actual macOS SDK + frameworks**, builds the binary, runs
clippy, and executes the **pure-logic unit tests**. The build itself is a strong gate (the macOS
framework calls must type-check and link), and the security-critical pure logic (HID→keycode mapping,
coordinate mapping, pixel repacking) is fully tested. The TCC-gated *runtime* is deferred to real
hardware.

The host abstractions already exist as traits (`sh_media::ScreenCapturer`, `sh_input::InputInjector`)
— the same seam the Linux and (future) Windows hosts implement.

## Decision

New crate **`crates/sh-platform-mac`** (workspace member; macOS-specific code is `#[cfg(target_os =
"macos")]`-gated, and the `core-graphics`/`core-foundation` deps are **target-gated** so the crate
compiles to an essentially empty crate on Linux/Windows and does not perturb their builds):

- **`CgDisplayCapturer`** implements `ScreenCapturer` via CoreGraphics `CGDisplay::image()`: grab the
  main display → a tightly-packed `PixelFormat::Bgra8` `VideoFrame` (repacking row-by-row to drop the
  `bytes_per_row` stride padding). CoreGraphics is chosen over a blind first cut at the newer
  **ScreenCaptureKit** (async `SCStream`, harder to bring up compile-only) — SCK is the documented
  modern follow-up (R-MAC-SCK). `CGDisplayCreateImage` returns `None` without Screen Recording
  permission, which the capturer surfaces as a typed error (fail-closed, never a crash).
- **`CgEventInjector`** implements `InputInjector` via CoreGraphics `CGEvent`: pointer move
  (`CoordMapper` → `CGPoint`, `MouseMoved`), button press/release (`{Left,Right,Other}Mouse{Down,Up}`
  at the tracked cursor position), and key (USB-HID → macOS virtual keycode via `keymap`, with
  `CGEventFlags` for modifiers). Scroll wheel, Touch, and Pen → `InputError::Unsupported` (documented
  follow-ups; the safe scroll-event binding lands with R-MAC-SCROLL). `CGEventPost` silently no-ops
  without Accessibility permission — correct fail-soft for the off-hardware build.
- **`keymap`** (`hid_to_cgkeycode`) is **pure and OS-independent** (a `u16 → u16` table), so it builds
  and is unit-tested on every platform — the security-relevant "no arbitrary keystroke" property is
  covered in CI everywhere, not only on macOS.

### Dependencies

`core-graphics` + `core-foundation` (pinned), **target-gated to macOS**. Both are the long-standing,
widely-used Servo-project bindings. Any `unsafe` lives inside those vetted crates, not ours.

### Verification

- **Build + clippy on `macos-latest`** (a new `platform-mac` CI job + the existing `test
  (macos-latest)` workspace job): the crate must compile against the real frameworks with
  `-D warnings` and link — this is the primary CI gate. **This is "CI as the compiler."**
- **Pure-logic unit tests** run everywhere (HID→keycode subset incl. unknown→`None`, coord mapping,
  BGRA stride repacking).
- **Runtime construction tests** on macOS CI assert the capturer/injector *construct* and that
  `inject`/`next_frame` return a `Result` without panicking (they no-op / fail-closed without TCC) —
  but do **not** assert real pixels/keystrokes (impossible headlessly).
- **Live capture + injection on real hardware is deferred → R-MAC-TCC.**

### Security

Identical posture to the Linux host (ADR-0025): every network-delivered `InputEvent` field is treated
as hostile (bounded, no `unwrap/expect/panic`, no `unsafe` in our code); unknown key / wheel / touch /
pen → `Unsupported`, never an arbitrary action. Capture reads the whole display; authorization
(`Capabilities::VIEW`/`CONTROL`) is enforced by the host-pipeline caller, and — on macOS specifically —
the OS itself enforces a second, non-bypassable gate via TCC (the user must grant Screen Recording /
Accessibility). No screen pixels, keystroke values, or pointer coordinates are logged (§7).

## Consequences

- **Positive:** a real macOS host crate, **compile-verified against the macOS SDK in CI** and binary-
  buildable, with the security-critical pure logic unit-tested everywhere. Reuses the existing trait
  seams; the host pipeline gains macOS support with no call-site changes. No `unsafe` in our code.
- **Negative / trade-offs:** runtime is **not** CI-verified (TCC) — live capture/inject is a hardware
  follow-up. CoreGraphics `CGDisplayCreateImage` is deprecated in macOS 14+ (still functional);
  ScreenCaptureKit is the modern replacement (R-MAC-SCK). Scroll/Touch/Pen are `Unsupported` for now.
- **Follow-ups (deferred):** R-MAC-TCC (live capture/inject + TCC permission flow on hardware),
  R-MAC-SCK (ScreenCaptureKit + VideoToolbox HW encode), R-MAC-SCROLL (scroll-wheel events),
  R-MAC-AUDIO (Core Audio capture), the full HID keymap.

## Alternatives considered

- **Mark P6-1 fully deferred ("needs a Mac")** — rejected: CI *can* compile-verify + unit-test +
  build the binary on `macos-latest`; only the TCC-gated runtime needs hardware. Deferring everything
  would understate what CI can prove.
- **ScreenCaptureKit first** — rejected for the first slice: the async `SCStream` API is materially
  harder to bring up compile-only (blind, no local macOS toolchain); CoreGraphics capture is the
  pragmatic first cut, with SCK as the tracked modern follow-up.
- **Raw `objc2` framework FFI** — rejected: introduces `unsafe`/`objc` surface for no benefit over the
  vetted `core-graphics` bindings for this scope.
