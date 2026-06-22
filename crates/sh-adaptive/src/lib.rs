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
//! - [`allocator::RateAllocator`] — cross-channel rate allocator; splits the SCReAM target bitrate
//!   across Video, Audio, Input, Control, Clipboard, and File channels following the product
//!   priority order defined in `LLD.md` §3.2.
//!
//! # Clock injection
//!
//! Library code **never calls `std::time::Instant::now()`**. Callers pass the current `Instant`
//! into every feedback call (`on_feedback`). This keeps all behaviour deterministic and testable.
//!
//! # Rate allocation
//!
//! The typical control-loop integration pattern (once the pacer lands in P2-6) is:
//!
//! ```rust
//! use sh_adaptive::{ScreamConfig, ScreamController, CongestionController};
//! use sh_adaptive::allocator::{AllocatorConfig, RateAllocator};
//! use sh_adaptive::stats::TransportStats;
//! use std::time::Instant;
//!
//! let allocator = RateAllocator::new(AllocatorConfig::default());
//! let mut controller = ScreamController::new(ScreamConfig::default());
//!
//! // On each control tick (e.g. every 20–100 ms):
//! // controller.on_feedback(&feedback, Instant::now());
//! let allocation = allocator.allocate(controller.target_bitrate());
//! // Hand allocations to the encoder / pacer:
//! // encoder.set_bitrate(allocation.video());
//! // audio_encoder.set_bitrate(allocation.audio());
//! ```
//!
//! [RFC 8298]: https://www.rfc-editor.org/rfc/rfc8298
#![deny(missing_docs)]

pub mod allocator;
pub mod bitrate;
pub mod controller;
pub mod scream;
pub mod stats;

pub use allocator::{AllocatorConfig, ChannelAllocation, RateAllocator};
pub use bitrate::Bitrate;
pub use controller::CongestionController;
pub use scream::{ScreamConfig, ScreamController};
pub use stats::TransportStats;
