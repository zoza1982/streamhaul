# sh-platform-mac

macOS host platform for Streamhaul (Phase 6, P6-1 — see [`docs/adr/0026-macos-host.md`](../../docs/adr/0026-macos-host.md)).

Implements the shared host-platform seams on macOS:

- **`CgDisplayCapturer`** — [`sh_media::ScreenCapturer`] via CoreGraphics `CGDisplay::image()` → a
  tightly-packed `Bgra8` frame.
- **`CgEventInjector`** — [`sh_input::InputInjector`] via CoreGraphics `CGEvent` (pointer / button /
  key; scroll / touch / pen are `Unsupported` follow-ups).
- **`keymap`** — pure, OS-independent USB-HID → macOS-virtual-keycode table (built and unit-tested on
  every platform).

The macOS implementations are `#[cfg(target_os = "macos")]`-gated and the `core-graphics` /
`core-foundation` deps are target-gated, so on Linux/Windows this crate compiles to just `keymap`.

## Verification & permissions

CI compiles + clippy-checks + unit-tests this crate on a real `macos-latest` runner ("CI as the
compiler"). The **runtime** capture/injection is gated behind macOS **TCC** (Screen Recording +
Accessibility) permissions that cannot be granted headlessly, so live capture/injection is verified
on real hardware — see **R-MAC-TCC** (and R-MAC-SCK / R-MAC-SCROLL / R-MAC-AUDIO) in
`IMPLEMENTATION_PLAN.md`. Without permission, capture returns a typed error and injection is a silent
no-op — never a crash.

Authorization (`Capabilities::VIEW` / `CONTROL`) is enforced by the host-pipeline caller; macOS adds
a second, non-bypassable TCC gate.

[`sh_media::ScreenCapturer`]: ../sh-media
[`sh_input::InputInjector`]: ../sh-input
