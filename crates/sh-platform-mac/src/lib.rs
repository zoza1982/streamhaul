#![deny(missing_docs)]
//! macOS host platform for Streamhaul (P6-1 — ADR-0026): CoreGraphics screen capture + CGEvent
//! input injection.
//!
//! Two concrete implementations of the shared host-platform seams, **`#[cfg(target_os = "macos")]`-
//! gated** (the `core-graphics`/`core-foundation` deps are target-gated, so on Linux/Windows this
//! crate compiles to just the OS-independent [`keymap`] module):
//!
//! - [`CgDisplayCapturer`] implements [`sh_media::ScreenCapturer`] via `CGDisplay::image()`.
//! - [`CgEventInjector`] implements [`sh_input::InputInjector`] via `CGEvent`.
//!
//! Both treat every network-delivered event/field as hostile (bounded, no `unwrap`/`panic`, no
//! `unsafe` in our code; any `unsafe` lives in the vetted `core-graphics` bindings), and both
//! fail-closed.
//!
//! # Permissions (TCC) — why live behaviour is hardware-gated
//!
//! macOS gates capture behind **Screen Recording** and injection behind **Accessibility** (TCC).
//! These cannot be granted on a headless CI runner, so CI **compiles** this crate against the real
//! macOS SDK, runs clippy, and unit-tests the OS-independent [`keymap`] — but live capture/injection
//! is verified on real hardware (R-MAC-TCC). Without permission, capture returns a typed error and
//! injection is a silent no-op (never a crash).
//!
//! The OS-independent [`keymap`] (USB HID → macOS virtual keycode) builds and is unit-tested on every
//! platform, so the security-relevant "unknown key → refused, never an arbitrary keystroke" property
//! is covered in CI everywhere.
//!
//! # Example
//!
//! The [`keymap`] is `pub` (intentionally — it is the one OS-independent, all-platform-testable part)
//! and resolves a USB HID usage to a macOS virtual keycode; the macOS-only `CgDisplayCapturer` /
//! `CgEventInjector` are constructed via their `new()` on a real Mac (see their docs).
//!
//! ```
//! use sh_platform_mac::keymap::hid_to_cgkeycode;
//! assert_eq!(hid_to_cgkeycode(0x04), Some(0x00)); // HID 'a' → kVK_ANSI_A
//! assert_eq!(hid_to_cgkeycode(0xFFFF), None);      // unknown → refused by the injector
//! ```

pub mod keymap;

#[cfg(target_os = "macos")]
mod capturer;
#[cfg(target_os = "macos")]
mod injector;

#[cfg(target_os = "macos")]
pub use capturer::CgDisplayCapturer;
#[cfg(target_os = "macos")]
pub use injector::CgEventInjector;
