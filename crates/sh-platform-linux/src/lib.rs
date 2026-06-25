#![deny(missing_docs)]
//! Linux host platform for Streamhaul (P6-2 — ADR-0025): X11 screen capture + XTEST input
//! injection.
//!
//! This crate provides two concrete implementations of the shared host-platform seams:
//!
//! - [`X11ScreenCapturer`] implements [`sh_media::ScreenCapturer`] via the X11 `GetImage`
//!   request (pure-Rust `x11rb`, no `unsafe`). Every call captures the entire root window and
//!   returns a tightly-packed [`sh_media::PixelFormat::Bgra8`] [`sh_media::VideoFrame`].
//!
//! - [`XTestInjector`] implements [`sh_input::InputInjector`] via the XTEST extension. Pointer
//!   moves, button press/release, scroll wheel, and a documented subset of keyboard keys
//!   are supported. Unknown HID key codes return [`sh_input::InputError::Unsupported`] rather
//!   than synthesising an arbitrary keystroke. Touch and Pen events are deferred
//!   (R-LINUX-WAYLAND).
//!
//! Both constructors are **fail-closed**: a missing display, an unreachable X server, or an
//! absent XTEST extension returns an error immediately rather than silently succeeding.
//!
//! # CI headless testing
//!
//! Integration tests that require a display are guarded by
//! `if std::env::var_os("DISPLAY").is_none() { return; }` so they skip cleanly when no
//! display is available (e.g. a bare headless CI box) and run for real under Xvfb or on a
//! physical display. They never produce a false pass.
//!
//! # Example
//!
//! ```no_run
//! use sh_platform_linux::{X11ScreenCapturer, XTestInjector};
//! use sh_media::ScreenCapturer;
//! use sh_input::InputInjector;
//! use std::time::Duration;
//!
//! let mut cap = X11ScreenCapturer::new(None).expect("connect to X display");
//! let frame = cap.next_frame(Duration::from_millis(100)).expect("capture ok");
//!
//! let mut inj = XTestInjector::new(None).expect("connect to X display with XTEST");
//! ```

mod capturer;
mod injector;

pub use capturer::X11ScreenCapturer;
pub use injector::XTestInjector;
