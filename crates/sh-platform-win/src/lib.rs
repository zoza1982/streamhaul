#![deny(missing_docs)]
//! Windows host platform for Streamhaul (P6-Windows — ADR-0027): GDI screen capture + `SendInput`
//! input injection.
//!
//! Two concrete implementations of the shared host-platform seams, **`#[cfg(target_os = "windows")]`-
//! gated** (the `winapi` dep is target-gated, so on Linux/macOS this crate compiles to just the
//! OS-independent [`keymap`] module):
//!
//! - [`GdiScreenCapturer`] implements [`sh_media::ScreenCapturer`] via GDI `BitBlt` + `GetDIBits`.
//! - [`SendInputInjector`] implements [`sh_input::InputInjector`] via `SendInput`.
//!
//! Both treat every network-delivered event/field as hostile (bounded, no `unwrap`/`panic`); the
//! Win32 FFI calls are `unsafe` (each block carries a `// SAFETY:` justification — CLAUDE.md §6),
//! and both fail-closed / refuse unsupported events.
//!
//! Unlike macOS (TCC), Windows has no per-app capture/inject permission gate within an interactive
//! session, so on an interactive desktop (incl. GitHub `windows-latest` runners) the capture/inject
//! paths may execute end-to-end — not merely compile. The OS-independent [`keymap`] (USB HID →
//! Win32 virtual-key) builds and is unit-tested on every platform, so the security-relevant "unknown
//! key → refused, never an arbitrary keystroke" property is covered in CI everywhere.

pub mod keymap;

#[cfg(target_os = "windows")]
mod capturer;
#[cfg(target_os = "windows")]
mod injector;

#[cfg(target_os = "windows")]
pub use capturer::GdiScreenCapturer;
#[cfg(target_os = "windows")]
pub use injector::SendInputInjector;
