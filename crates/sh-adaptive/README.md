# sh-adaptive

Congestion control, content classification, and rate allocation for Streamhaul.

## What is here

| Item | Description |
|------|-------------|
| [`CongestionController`] | Trait seam between `sh-adaptive` and the pacer in `sh-transport`. |
| [`TransportStats`] | Per-feedback struct (RTT, queue delay, loss) consumed by every controller. |
| [`Bitrate`] | Strongly-typed bits-per-second newtype (integer, no float on the API boundary). |
| [`ScreamController`] | RFC 8298 SCReAM implementation for the native (QUIC) path. |
| [`RateAllocator`] | Cross-channel rate allocator: splits the SCReAM target across Video/Audio/Input/Control/Clipboard/File. |
| [`ContentClassifier`] | 4-signal heuristic + hysteresis FSM → `Work | Scrolling | Game` (LLD §5.2). |
| [`ScoreProvider`] | Swappable scoring trait; v1 = `HeuristicScoreProvider`; v2 = ONNX (P3+). |
| [`Signals`] | The four normalized input signals (A=mb-diff, B=dirty-rect, C=app-class, D=cursor-vel). |

GCC (for the WebRTC path) arrives in Phase 4.

## Content classifier

The classifier maps screen-capture signals to one of three content modes that drive encoder reconfiguration (P2-4):

| Mode | Encoder config | Frame rate |
|------|---------------|-----------|
| `Work` | Conservative 4:2:0, damage-triggered keyframes | ≤30 fps |
| `Scrolling` | Game-quality fast encode, intra-refresh | ≤30 fps |
| `Game` | CBR 4:2:0, max throughput, intra-refresh | 60+ fps |

```rust
use sh_adaptive::{ContentClassifier, HeuristicScoreProvider, Signals, AppClass};

let mut clf = ContentClassifier::new(Box::new(HeuristicScoreProvider));

// Every 4 frames:
let signals = Signals::from_raw(
    0.9,              // mb_diff_fraction
    0.85,             // dirty_rect_fraction
    AppClass::Game,   // foreground app class
    false,            // not fullscreen-exclusive
    1200.0,           // cursor velocity px/s
);
let mode = clf.on_tick(&signals);
// mode enters Game after GAME_ENTER_DWELL=8 consecutive high-score ticks.
```

### Hysteresis constants (LLD §5.2)

| Constant | Value | Meaning |
|----------|-------|---------|
| `GAME_ENTER_THRESHOLD` | 0.65 | Score must exceed this (strictly) for 8 ticks to enter Game |
| `GAME_EXIT_THRESHOLD` | 0.40 | Score must be below this (strictly) for 30 ticks to exit Game |
| `GAME_ENTER_DWELL` | 8 | Ticks ≈ 530 ms @60 fps |
| `GAME_EXIT_DWELL` | 30 | Ticks ≈ 2 s @60 fps (protects against alt-tab glitches) |
| `SCROLL_ENTER_THRESHOLD` | 0.35 | Score must exceed this for 4 ticks to enter Scrolling |
| `SCROLL_EXIT_THRESHOLD` | 0.25 | Score must be below this for 10 ticks to leave Scrolling |
| `SCROLL_ENTER_DWELL` | 4 | Ticks ≈ 267 ms @60 fps; fast entry, low false-positive cost (same encode params as Game, lower fps) |
| `SCROLL_EXIT_DWELL` | 10 | Ticks ≈ 667 ms @60 fps; prevents pause-mid-scroll flapping |

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
