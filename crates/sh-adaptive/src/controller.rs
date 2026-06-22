//! The [`CongestionController`] trait — the shared seam between `sh-adaptive` and the pacer.
//!
//! Every congestion controller (SCReAM for the native QUIC path, GCC for the WebRTC path in
//! Phase 4) implements this trait. The pacer in `sh-transport` holds a `Box<dyn
//! CongestionController>` and calls `on_feedback` on each receiver report, then reads
//! `target_bitrate` and `pacing_interval` to schedule sends.

use std::time::{Duration, Instant};

use crate::{Bitrate, TransportStats};

/// The congestion-controller trait — the shared seam between `sh-adaptive` and `sh-transport`.
///
/// # Contract
///
/// - **`on_feedback`** is called once per feedback report (ACK / RTCP RR / SHP feedback), with a
///   **monotonic** `now` supplied by the caller. The controller must be robust to non-monotonic
///   `now` values: it must not panic, but it may ignore the feedback report or clamp the delta.
///
/// - **`target_bitrate`** returns the current send-rate target derived from the congestion window
///   and RTT. The value is always within the configured `[min_bitrate, max_bitrate]` range and is
///   never `0` (unless `min_bitrate` is zero).
///
/// - **`pacing_interval`** returns the suggested inter-packet gap for the pacer, derived from
///   `target_bitrate` and a pacing window size. It is always `> Duration::ZERO` (the controller
///   clamps to a minimum of 1 µs to prevent divide-by-zero in the pacer).
///
/// # Object safety
///
/// This trait is object-safe: all methods take `&mut self` or `&self`, use no generics, and
/// return only concrete types. It can be stored as `Box<dyn CongestionController>`.
///
/// # Send
///
/// Implementations must be `Send` so the pacer task (tokio) can hold the controller across
/// `.await` points.
pub trait CongestionController: Send {
    /// Ingest one feedback report and update the congestion window / target bitrate.
    ///
    /// `now` must be a monotonic `Instant` supplied by the caller; the controller must not call
    /// `Instant::now()` internally. Non-monotonic `now` (i.e. `now < last_now`) is handled by
    /// ignoring the delta rather than panicking.
    ///
    /// `fb` may contain degenerate values (zero RTT, loss > acked, etc.). The controller must
    /// clamp / ignore all such cases and never panic.
    fn on_feedback(&mut self, fb: &TransportStats, now: Instant);

    /// The current target send rate.
    ///
    /// Always within `[min_bitrate, max_bitrate]` as configured at construction time.
    fn target_bitrate(&self) -> Bitrate;

    /// The suggested inter-packet pacing gap.
    ///
    /// Derived from `target_bitrate()` and the configured pacing packet size. Always
    /// `>= Duration::from_micros(1)`.
    fn pacing_interval(&self) -> Duration;
}
