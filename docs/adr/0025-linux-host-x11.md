# ADR 0025: Linux host platform — X11-first (capture + input injection)

- **Status:** Accepted
- **Date:** 2026-06-24
- **Deciders:** realtime-systems-engineer, rust-staff-engineer, security-engineer (consulted)

## Context

Phase 6 (P6-2) adds the Linux host: turning a real Linux machine into a Streamhaul host that
captures its screen, encodes it, and injects remote input. The plan names "PipeWire/DRM capture +
VA-API + `uinput` inject + PipeWire audio; Wayland+X11" — a large surface spanning two display
servers, hardware encode, and audio.

The host abstractions already exist as traits (the same seam every platform plugs into):
- `sh_media::ScreenCapturer` — `next_frame(timeout) -> Option<VideoFrame>`, `resolution()`,
  `pixel_format()`.
- `sh_input::InputInjector` — `inject(&InputEvent) -> Result<(), InputError>`, with `CoordMapper`
  for normalized-`0..=65535` → absolute-pixel mapping.

**What the target environment supports** (assessed on the dev/CI Linux): an **X11** session
(`$DISPLAY` reachable), `libX11`/`libXtst`/`libXext`/`libva` present, a GPU at `/dev/dri/renderD128`,
a PipeWire socket — but **no Wayland session**, `/dev/uinput` is root-only, and no VA-API driver is
confirmed (`vainfo` absent). GitHub Actions Linux runners are headless (no `$DISPLAY`).

## Decision

**Ship the X11 half first, as a real and CI-verified implementation; defer the rest behind documented
risk entries** (the same posture every prior phase took with hardware it could not exercise).

New crate **`crates/sh-platform-linux`** (workspace member, native-only):

- **`X11ScreenCapturer`** implements `ScreenCapturer` via **x11rb** (pure-Rust, safe XCB bindings):
  connect to `$DISPLAY`, `GetImage(ZPixmap)` the root window → a tightly-packed `PixelFormat::Bgra8`
  `VideoFrame`. (The `MIT-SHM` shared-memory fast path is a follow-up; correctness first.)
- **`XTestInjector`** implements `InputInjector` via the **XTEST** extension (x11rb): pointer move
  (`CoordMapper` → fake motion), button press/release (mask-diff against the previous state), wheel
  (X buttons 4/5 vertical, 6/7 horizontal), and key (USB-HID-usage → X keysym → keycode, for a
  documented subset; unknown keys → `InputError::Unsupported`, never a wild injection).

  **Why XTEST, not `/dev/uinput`** (which the `InputInjector` doc suggests for Linux): XTEST is the
  correct path for an **X11** session — it injects through the X server, needs no elevated device
  permission, and lands in the right session. `/dev/uinput` is the path for **Wayland / headless**
  hosts and requires write access to a root-only device here → deferred (R-LINUX-UINPUT).

- **Dependency:** `x11rb` (pinned). Justified per CLAUDE.md §7: it is the standard, vetted, **pure-
  Rust** X11 binding, avoiding `unsafe` FFI to `libX11`/`libXtst`. No other new third-party dep.

### Verification — real, and headless-CI-verified via Xvfb

Tests connect to `$DISPLAY` and exercise capture + injection **for real**. CI runs them under
**Xvfb** (a real in-memory X server), so the X11 capture and XTEST injection are verified headlessly
in CI — the same approach the project uses for headless-Firefox WebRTC. The strongest assertion is a
**pointer round-trip**: `inject(PointerMove)` then `QueryPointer` confirms the cursor landed at the
mapped pixel. Tests **skip cleanly** when no display is available (a truly displayless dev machine),
gated on `$DISPLAY` — never a false pass.

### Security (input injection + screen capture are a critical surface)

- Injection synthesizes **OS-level input from network-delivered events**. The injector treats every
  `InputEvent` field as hostile: it bounds/validates and **never panics**; an unmappable key/button
  is a typed `Unsupported`, not an arbitrary action. Authorization (`Capabilities::CONTROL`) is
  enforced by the host pipeline at the call site, not re-litigated here, but this crate must be safe
  to call with any decoded event.
- Capture reads the **entire display** — gated by `Capabilities::VIEW` upstream.
- **Fail-closed:** no `$DISPLAY` / failed connection / missing XTEST or SHM extension → a construction
  error, never a silent no-op that looks like success.
- No secrets/keys/screen content logged (§7); `tracing` carries only geometry/counters.

## Consequences

- **Positive:** a Linux X11 host that captures and accepts remote control, verified headlessly in CI
  (Xvfb) — not a stub. Reuses the existing `ScreenCapturer`/`InputInjector` seams, so the host
  pipeline gains Linux support with no call-site changes. No `unsafe`, one vetted pure-Rust dep.
- **Negative / trade-offs:** X11 only; `GetImage` (no SHM yet) copies the framebuffer each grab —
  fine for correctness, a perf follow-up. The HID→keysym table covers a useful subset, not every key.
- **Follow-ups (deferred, each environment/hardware-gated):**
  - **R-LINUX-WAYLAND** — Wayland capture (PipeWire ScreenCast via the xdg-desktop-portal) + input
    (`libei`/`uinput`); needs a Wayland session + portal, absent here.
  - **R-LINUX-VAAPI** — VA-API hardware H.264/HEVC encode; `libva` is present but no driver/`vainfo`
    is confirmed. The software encode path in `sh-codec-hw` remains the portable fallback.
  - **R-LINUX-UINPUT** — `/dev/uinput` injection backend for Wayland/headless; root-only device here.
  - **R-LINUX-AUDIO** — PipeWire audio capture; socket present, deferred (heavy dep, no consumer yet).
  - MIT-SHM zero-copy capture fast path; full HID keymap.

## Alternatives considered

- **`/dev/uinput` as the primary injector** — rejected for an X11 session: needs root-only device
  access and injects below the X server (wrong session targeting). It is the right Wayland/headless
  backend and is deferred there.
- **Raw `libX11`/`libXtst` FFI** — rejected: introduces `unsafe` for no benefit; `x11rb` is safe,
  pure-Rust, and exposes XTEST + SHM + core imaging.
- **Wayland/PipeWire first** — impossible to verify here (no Wayland session/portal); would ship
  unverifiable code, which the quality gate forbids.
- **Mark P6-2 fully deferred** — rejected: the X11 capture+inject slice is genuinely verifiable
  (locally and under Xvfb in CI), so deferring it would understate what this environment supports.
