//! Portable clipboard-access seam for Streamhaul.
//!
//! # Overview
//!
//! A Streamhaul session syncs the clipboard in **both** directions: text copied on one machine can
//! be pasted on the other. The transport carries a bare
//! [`ClipboardUpdate`](sh_protocol::ClipboardUpdate) over the reliable, ordered *Clipboard* channel
//! (`ChannelId::Clipboard`, ADR-0037). This crate owns the seam between that wire message and the
//! OS clipboard:
//!
//! ```text
//! Transport Clipboard channel
//!       │ ClipboardUpdate (bare [format][content], sh_protocol)
//!       ▼
//!  decode() → as_text()      ← validates format, bounds size (256 KiB), rejects non-UTF-8
//!       │ &str (valid UTF-8)
//!       ▼
//!  ClipboardAccess::set_text()   ← writes text to the OS clipboard (host→browser paste)
//!  ClipboardAccess::get_text()   ← reads text from the OS clipboard (browser→host paste)
//!       │
//!       ▼
//!  OS (X11 selections / NSPasteboard / Windows clipboard …)
//! ```
//!
//! Real platform backends (`sh-platform-linux`, `sh-platform-mac`, `sh-platform-win`) implement
//! [`ClipboardAccess`] and drop in without touching callers -- exactly the trait-seam pattern of
//! `sh-input`'s `InputInjector` / `sh-media` / `sh-codec-hw`.
//!
//! # Security
//!
//! Clipboard content is **untrusted** (a hostile peer sends arbitrary bytes) and is **session
//! data** (§7: never logged). The wire codec ([`ClipboardUpdate`](sh_protocol::ClipboardUpdate))
//! handles hostile-input parsing (bounded, UTF-8-validated, fuzzed). The *wiring* that drives this
//! trait carries the remaining obligations (ADR-0037): a fail-closed `CLIPBOARD` capability gate on
//! the receive path in both directions, no logging of content, and control-character normalization
//! before a paste sink. This crate provides the fail-closed default: a capability-denied session is
//! given a [`NoopClipboard`], which cannot touch the real OS clipboard.
//!
//! # What this crate provides
//!
//! | Item | Description |
//! |------|-------------|
//! | [`ClipboardAccess`] | Object-safe trait: `get_text` / `set_text` over the OS clipboard |
//! | [`NoopClipboard`] | Reads empty, discards writes -- placeholder and fail-closed stub |
//! | [`RecordingClipboard`] | Records writes, serves a preset read value -- test double |
//! | [`ClipboardError`] | `thiserror`-derived error for clipboard-access failures |

#![deny(missing_docs)]

mod access;
mod error;
mod noop;
mod recording;

pub use access::ClipboardAccess;
pub use error::ClipboardError;
pub use noop::NoopClipboard;
pub use recording::RecordingClipboard;
