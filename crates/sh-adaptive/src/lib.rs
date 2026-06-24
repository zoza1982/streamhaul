//! `sh-adaptive` — Congestion control, content classification, rate allocation, and loss recovery
//! for Streamhaul.
//!
//! This crate provides:
//!
//! - The [`CongestionController`] trait with two concrete implementations:
//!   **SCReAM** (Self-Clocked Rate Adaptation for Multimedia, RFC 8298) for the native (QUIC)
//!   path, and **GCC** (Google Congestion Control) for the WebRTC path.
//! - The **content classifier** (LLD §5.2): a 4-signal heuristic plus hysteresis FSM that maps
//!   real-time screen-content signals to [`classifier::ContentMode`] (`Work`, `Scrolling`,
//!   `Game`). The score function is swappable behind [`classifier::ScoreProvider`] for v2 ML.
//! - The **rate allocator** ([`allocator::RateAllocator`]): splits the SCReAM target bitrate
//!   across Video, Audio, Input, Control, Clipboard, and File channels following the product
//!   priority order in `LLD.md` §3.2.
//! - The **loss-recovery policy engine** ([`loss_recovery`], P2-6): tiered RTT-band escalation
//!   that recommends NACK, FEC, or IDR based on per-feedback loss state. Includes
//!   [`loss_recovery::GapDetector`] for 16-bit NACK bitmap tracking,
//!   [`loss_recovery::FecPolicy`] for adaptive FEC ratio selection, and
//!   [`loss_recovery::RollingIntraRefresh`] for self-healing without signaling.
//!
//! # Design
//!
//! The crate is organized around trait seams that decouple each subsystem:
//!
//! - [`CongestionController`] — the shared seam between `sh-adaptive` and the pacer in
//!   `sh-transport`. Every controller (SCReAM, GCC) implements this trait.
//! - [`TransportStats`] — the per-feedback struct consumed by `on_feedback`. Designed so both
//!   SCReAM (native path) and GCC (WebRTC path) can consume the same struct.
//! - [`Bitrate`] — a bits-per-second newtype used throughout the adaptive layer.
//! - [`ScreamController`] — the SCReAM implementation.
//! - [`classifier::ScoreProvider`] — maps [`classifier::Signals`] → score; v1 uses
//!   [`classifier::HeuristicScoreProvider`]; v2 swaps in an ONNX provider without touching the
//!   FSM.
//! - [`classifier::ContentClassifier`] — the FSM; holds a `Box<dyn ScoreProvider>` and exposes
//!   `on_tick(&Signals) -> ContentMode`.
//! - [`allocator::RateAllocator`] — cross-channel rate allocator.
//! - [`loss_recovery::LossRecoveryController`] — tiered NACK / FEC / IDR policy engine.
//!
//! # Clock injection
//!
//! Library code **never calls `std::time::Instant::now()`**. Callers pass the current `Instant`
//! into every feedback call (`on_feedback`). The content classifier is tick-driven (no wall-clock
//! state) — call [`classifier::ContentClassifier::on_tick`] once per 4-frame group.
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
//! # Content classification
//!
//! ```rust
//! use sh_adaptive::classifier::{
//!     ContentClassifier, HeuristicScoreProvider, Signals, AppClass,
//! };
//!
//! let mut classifier = ContentClassifier::new(Box::new(HeuristicScoreProvider));
//!
//! // Every 4 frames, build Signals and call on_tick:
//! let signals = Signals::from_raw(
//!     0.9,              // mb_diff_fraction: 90% of macroblocks changed
//!     0.85,             // dirty_rect_fraction: 85% of screen dirty
//!     AppClass::Game,   // foreground app is a game
//!     false,            // not fullscreen-exclusive
//!     1200.0,           // cursor at 1200 px/s
//! );
//! let mode = classifier.on_tick(&signals);
//! // mode starts as Work; Game is entered after GAME_ENTER_DWELL=8 consecutive high-score ticks.
//! # let _ = mode;
//! ```
//!
//! [RFC 8298]: https://www.rfc-editor.org/rfc/rfc8298
#![deny(missing_docs)]

pub mod allocator;
pub mod bitrate;
pub mod classifier;
pub mod controller;
pub mod gcc;
pub mod loss_recovery;
pub mod pacer;
pub mod scream;
pub mod stats;
pub(crate) mod util;

pub use allocator::{AllocatorConfig, ChannelAllocation, RateAllocator};
pub use bitrate::Bitrate;
pub use classifier::{
    AppClass, ContentClassifier, ContentMode, HeuristicScoreProvider, Score, ScoreProvider, Signals,
};
pub use controller::CongestionController;
pub use gcc::{GccConfig, GccController};
pub use loss_recovery::{
    FecPolicy, FecPolicyConfig, GapDetector, GapReport, LossRecoveryController, LossState,
    NackRequest, RecoveryAction, RefreshStripe, RollingIntraRefresh,
};
pub use pacer::TokenBucket;
pub use scream::{ScreamConfig, ScreamController};
pub use stats::TransportStats;
