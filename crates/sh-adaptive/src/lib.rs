//! `sh-adaptive` — Congestion control, content classification, and rate allocation for Streamhaul.
//!
//! This crate provides the [`CongestionController`] trait and a concrete **SCReAM** (Self-Clocked
//! Rate Adaptation for Multimedia) implementation following [RFC 8298] for the native (QUIC) path.
//! A GCC implementation for the WebRTC path arrives in Phase 4.
//!
//! # Design
//!
//! The crate is organized around a single trait seam:
//!
//! - [`CongestionController`] — the shared seam between `sh-adaptive` and the pacer in
//!   `sh-transport`. Every controller (SCReAM, GCC) implements this trait.
//! - [`TransportStats`] — the per-feedback struct consumed by `on_feedback`. Designed so both
//!   SCReAM (native path) and GCC (WebRTC path) can consume the same struct.
//! - [`Bitrate`] — a bits-per-second newtype used throughout the adaptive layer.
//! - [`ScreamController`] — the SCReAM implementation.
//!
//! # Clock injection
//!
//! Library code **never calls `std::time::Instant::now()`**. Callers pass the current `Instant`
//! into every feedback call (`on_feedback`). This keeps all behaviour deterministic and testable.
//!
//! [RFC 8298]: https://www.rfc-editor.org/rfc/rfc8298
#![deny(missing_docs)]

pub mod bitrate;
pub mod controller;
pub mod scream;
pub mod stats;

pub use bitrate::Bitrate;
pub use controller::CongestionController;
pub use scream::{ScreamConfig, ScreamController};
pub use stats::TransportStats;
