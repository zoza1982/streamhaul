//! Portable input-injection seam for Streamhaul.
//!
//! # Overview
//!
//! On the host side of a Streamhaul session the transport delivers [`InputEvent`]s to the host
//! process on the reliable, ordered, highest-priority *Input* channel (`LLD.md` §3.1, §3.2).
//! This crate owns the path from a received [`InputEvent`] to OS interaction:
//!
//! ```text
//! Transport Input channel
//!       │ InputEvent (16-byte, sh_protocol)
//!       ▼
//!  CoordMapper          ← maps normalized 0..=65535 coords → absolute host pixels
//!       │ mapped (x, y): i32
//!       ▼
//!  InputInjector::inject()   ← sends the synthesized event to the OS
//!       │
//!       ▼
//!  OS (SendInput / uinput / CGEvent …)
//! ```
//!
//! Real platform backends (`sh-platform-win`, `sh-platform-linux`, `sh-platform-mac`) implement
//! [`InputInjector`] and drop in without touching callers — exactly the same seam as
//! `sh-media` (traits) / `sh-codec-hw` (impls).
//!
//! # Threading and real-time expectations
//!
//! Injection runs **off the async runtime** on a dedicated injection thread so it never blocks
//! the QUIC I/O executor. [`InputInjector::inject`] must be callable from a non-async context
//! and must complete in bounded time (no unbounded waits, no dynamic allocation on the hot path).
//! See `LLD.md` §1 for the thread-model overview.
//!
//! # What this crate provides
//!
//! | Item | Description |
//! |------|-------------|
//! | [`InputInjector`] | Object-safe trait: one method, `inject(&mut self, &InputEvent) -> Result` |
//! | [`CoordMapper`] | Maps normalized `0..=65535` pointer coords to absolute pixels |
//! | [`TargetRect`] | Virtual-desktop bounds (supports negative origins for multi-monitor) |
//! | [`NoopInjector`] | Accepts and drops every event — useful as a placeholder |
//! | [`RecordingInjector`] | Records every injected event for test assertions |
//! | [`RateLimiter`] | Token-bucket rate cap for hostile pointer-move floods (host side) |
//! | [`InputError`] | `thiserror`-derived error for injection failures |

#![deny(missing_docs)]

mod coord;
mod error;
mod injector;
mod noop;
mod rate_limiter;
mod recording;

pub use coord::{CoordMapper, MappedPoint, TargetRect};
pub use error::InputError;
pub use injector::{InputInjector, DEFINED_BUTTON_BITS};
pub use noop::NoopInjector;
pub use rate_limiter::RateLimiter;
pub use recording::RecordingInjector;
