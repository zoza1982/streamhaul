# sh-adaptive

Congestion control, content classification, and rate allocation for Streamhaul.

## What is here

| Item | Description |
|------|-------------|
| [`CongestionController`] | Trait seam between `sh-adaptive` and the pacer in `sh-transport`. |
| [`TransportStats`] | Per-feedback struct (RTT, queue delay, loss) consumed by every controller. |
| [`Bitrate`] | Strongly-typed bits-per-second newtype (integer, no float on the API boundary). |
| [`ScreamController`] | RFC 8298 SCReAM implementation for the native (QUIC) path. |

GCC (for the WebRTC path) arrives in Phase 4.

## SCReAM overview

SCReAM (Self-Clocked Rate Adaptation for Multimedia, [RFC 8298]) is a queue-delay-based
congestion controller designed for real-time media. It tracks the minimum observed RTT as a
baseline and uses the current one-way queuing delay to detect network congestion:

- **Additive increase** when the queue delay is below the threshold (20 ms).
- **Slow-start** (exponential increase) on cold start, until the first congestion signal.
- **Multiplicative decrease** (×0.85) when queue delay exceeds 20 ms or loss exceeds 2%.

The target bitrate is derived from the congestion window (CWND) and the smoothed RTT, then
clamped to `[min_bitrate, max_bitrate]` (defaults: 100 kbps – 50 Mbps).

## Clock injection

The controller **never calls `Instant::now()`**. All time is supplied by the caller:

```rust
use sh_adaptive::{ScreamController, CongestionController, TransportStats};
use std::time::{Duration, Instant};

let mut ctrl = ScreamController::with_defaults();

// In a feedback-processing loop (now comes from the caller, never Instant::now() inside):
let now = /* caller-provided monotonic Instant */;
let fb  = /* TransportStats from sh-transport */;
ctrl.on_feedback(&fb, now);

let target = ctrl.target_bitrate();  // always within [min, max]
let pacing = ctrl.pacing_interval(); // always >= 1 µs
```

## Robustness guarantees

The controller is designed to consume untrusted network data:

- Non-monotonic `now` → feedback silently ignored.
- Zero / huge RTT → clamped to `[100 µs, 10 s]`.
- `bytes_lost > bytes_acked` → treated as 100% loss (triggers decrease, no panic).
- All internal `f64` results → checked for NaN/Inf before updating state.
- No `unwrap`, `expect`, `panic`, or `todo` in production paths.

[RFC 8298]: https://www.rfc-editor.org/rfc/rfc8298
[`CongestionController`]: src/controller.rs
[`TransportStats`]: src/stats.rs
[`Bitrate`]: src/bitrate.rs
[`ScreamController`]: src/scream.rs
