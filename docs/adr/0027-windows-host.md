# ADR 0027: Windows host platform — GDI capture + SendInput injection

- **Status:** Accepted
- **Date:** 2026-06-25
- **Deciders:** rust-staff-engineer (unsafe FFI), realtime-systems-engineer, security-engineer (consulted)

## Context

Phase 6 adds the Windows host (the third OS, alongside Linux X11 / P6-2 and macOS / P6-1). The
abstractions already exist as traits (`sh_media::ScreenCapturer`, `sh_input::InputInjector`); the
Windows crate implements them against Win32.

Unlike macOS (TCC) — and like Linux/Xvfb — Windows has **no per-app permission gate** for screen
capture or synthetic input within an interactive session, and GitHub Actions `windows-latest` runners
provide an interactive desktop. So Windows is the most CI-friendly of the three: CI compiles the crate
against the real Win32 SDK, builds the binary, and runs the capture/inject smoke tests, which on the
runner's desktop may execute end-to-end (not merely compile).

The one structural difference from the other two hosts: the Win32 calls (`BitBlt`, `GetDIBits`,
`SendInput`, …) are `unsafe extern` FFI. Linux (`x11rb`) and macOS (`core-graphics`) gave us safe
wrappers; Windows does not, so this crate **contains `unsafe`** — each block carries a `// SAFETY:`
justification and the crate is reviewed by `rust-staff-engineer` per CLAUDE.md §6.

## Decision

New crate **`crates/sh-platform-win`** (workspace member; Win32 code is `#[cfg(target_os = "windows")]`
-gated, and the `winapi` dep is **target-gated** to Windows, so the crate compiles to just the
OS-independent `keymap` on Linux/macOS and does not perturb their builds):

- **`GdiScreenCapturer`** implements `ScreenCapturer` via classic **GDI**: `GetDC(NULL)` → a memory DC
  + compatible bitmap → `BitBlt(SRCCOPY)` → `GetDIBits` with a top-down 32-bpp `BITMAPINFO` → a
  tightly-packed `PixelFormat::Bgra8` `VideoFrame` (GDI 32-bpp DIBs are already BGRA, top-down via a
  negative height). All GDI handles are released on every path (RAII guard). The newer **DXGI Desktop
  Duplication** zero-copy path is the documented follow-up (R-WIN-DXGI).
- **`SendInputInjector`** implements `InputInjector` via **`SendInput`**: pointer move maps **directly**
  (our `InputEvent` pointer coords are already normalized `0..=65535`, exactly what
  `MOUSEEVENTF_ABSOLUTE` expects, mapped to the **primary monitor** — `VIRTUALDESK` is intentionally
  **not** set so the pointer space matches the primary-monitor GDI capture; no `CoordMapper` needed), button
  press/release (`MOUSEEVENTF_{LEFT,RIGHT,MIDDLE}{DOWN,UP}` via mask-diff), wheel
  (`MOUSEEVENTF_WHEEL`, `±WHEEL_DELTA`), and key (USB-HID → Win32 virtual-key via `keymap`, with the
  generic modifier VKs pressed around the key). Touch/Pen → `InputError::Unsupported`. Unknown key →
  `Unsupported`, never a wild keystroke.
- **`keymap`** (`hid_to_vk`) is **pure and OS-independent** (a `u16 → u16` table), so it builds and is
  unit-tested on every platform — the security-relevant "unknown key → refused" property is covered in
  CI everywhere.

### Dependency

`winapi` (pinned, target-gated to Windows), with the narrow features `winuser`/`wingdi`/`windef`/
`minwindef`. `winapi` is chosen over the newer `windows` crate for **blind-compile stability**: its C
ABI signatures are fixed and unchanging across `0.3.x`, minimizing the CI-as-the-compiler iteration
for a Linux-hosted author. The `windows`-crate / DXGI migration is a tracked follow-up (R-WIN-DXGI).

### `unsafe` posture (CLAUDE.md §6)

The crate uses `unsafe` only for the Win32 FFI calls. Each block has a `// SAFETY:` comment, handles
are freed on all paths (no leaks), all buffer sizes are checked before `GetDIBits`/repack, and no raw
pointer derived from network input is dereferenced (pointer/button/key fields are passed by value into
`SendInput`). `rust-staff-engineer` reviews the `unsafe` as part of the gate.

### Verification

- **Build + clippy + tests on `windows-latest`** (a new `platform-win` CI job + the existing
  `test (windows-latest)` workspace job): the crate must compile + link against the real Win32 SDK
  with `-D warnings`, and the smoke tests run on the runner's interactive desktop.
- **Pure-logic unit tests** run everywhere (HID→VK subset incl. unknown→`None`).
- **Windows smoke tests**: construct the injector/capturer and drive each arm; assert panic-freedom
  and structural validity (a captured frame has consistent dimensions/length; supported inject arms
  return `Ok`, Unsupported arms return the typed error). On the runner's desktop these may exercise
  real GDI/SendInput; we do not assert a specific on-screen effect.
- Full interactive validation on a real Windows desktop is **R-WIN-INTERACTIVE** (and DXGI is
  R-WIN-DXGI).

### Security

Same posture as the other hosts: every network `InputEvent` field is treated as hostile (bounded, no
`unwrap/expect/panic`); unknown key / wheel-not-yet / touch / pen → `Unsupported`, never an arbitrary
action. Capture reads the whole virtual desktop; authorization (`Capabilities::VIEW`/`CONTROL`) is
enforced by the host-pipeline caller. §7: no screen pixels, keystroke values, or coordinates logged.

## Consequences

- **Positive:** a real Windows host crate, compile-verified (and likely runtime-exercised) in CI;
  reuses the trait seams; the `0..=65535` pointer normalization maps 1:1 to Win32 absolute mouse.
- **Negative / trade-offs:** contains `unsafe` FFI (justified + reviewed); GDI `BitBlt` copies the
  framebuffer (no zero-copy); `winapi` is in maintenance mode (the `windows`/DXGI path is the
  follow-up). Scroll uses one notch per event (no fractional).
- **Follow-ups (deferred):** R-WIN-DXGI (DXGI Desktop Duplication zero-copy + the `windows` crate),
  R-WIN-INTERACTIVE (full interactive capture/inject validation on a real desktop, incl. UAC/secure-
  desktop limitations), R-WIN-AUDIO (WASAPI loopback capture), full HID keymap, per-monitor capture.

## Alternatives considered

- **`windows` crate (official) instead of `winapi`** — better long-term, but its API churns across
  versions, raising the blind-compile iteration cost for a Linux-hosted author; deferred to the DXGI
  migration (R-WIN-DXGI) where the modern API is needed anyway.
- **DXGI Desktop Duplication first** — the right low-latency capture path, but far harder to bring up
  compile-only; GDI `BitBlt` is the pragmatic first cut, with DXGI as the tracked follow-up.
- **Mark the Windows host fully deferred** — rejected: CI can compile-verify + unit-test + build it on
  `windows-latest` (and likely run the smoke tests), so deferring everything understates what CI proves.
