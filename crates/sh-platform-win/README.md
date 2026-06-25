# sh-platform-win

Windows host platform for Streamhaul (Phase 6 — see [`docs/adr/0027-windows-host.md`](../../docs/adr/0027-windows-host.md)).

Implements the shared host-platform seams on Windows:

- **`GdiScreenCapturer`** — [`sh_media::ScreenCapturer`] via GDI `BitBlt` + `GetDIBits` → a
  tightly-packed primary-monitor `Bgra8` frame.
- **`SendInputInjector`** — [`sh_input::InputInjector`] via `SendInput` (pointer / button / wheel /
  key; touch / pen are `Unsupported` follow-ups). The wire's `0..=65535` pointer coords map 1:1 to
  `MOUSEEVENTF_ABSOLUTE`.
- **`keymap`** — pure, OS-independent USB-HID → Win32-virtual-key table (built + unit-tested on every
  platform).

The Win32 implementations are `#[cfg(target_os = "windows")]`-gated and the `winapi` dep is
target-gated, so on Linux/macOS this crate compiles to just `keymap`.

## `unsafe` and verification

Unlike the safe Linux (`x11rb`) / macOS (`core-graphics`) bindings, the Win32 calls are `unsafe` FFI;
each block carries a `// SAFETY:` justification, all GDI handles are freed on every path (RAII guard),
and the crate is reviewed by `rust-staff-engineer` (CLAUDE.md §6). CI compiles + clippy-checks +
tests on a real `windows-latest` runner ("CI as the compiler"); the smoke tests may exercise
capture/`SendInput` end-to-end on the runner's interactive desktop. Full interactive validation
(incl. UIPI / UAC secure-desktop limits) is **R-WIN-INTERACTIVE**; DXGI zero-copy + multi-monitor is
**R-WIN-DXGI**; WASAPI audio is **R-WIN-AUDIO**.

**Caller obligation:** Windows has **no per-app OS permission gate** within a session, so the upstream
`Capabilities::CONTROL` / `VIEW` check is the **sole** authorization gate — the host pipeline must
enforce it before constructing/feeding the injector/capturer.

[`sh_media::ScreenCapturer`]: ../sh-media
[`sh_input::InputInjector`]: ../sh-input
