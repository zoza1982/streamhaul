# ADR 0018: WebRTC drive-loop async socket seam

- **Status:** Accepted
- **Date:** 2026-06-23
- **Deciders:** rust-staff-engineer, network-engineer, security-engineer

## Context

`PinnedWebRtcTransport` (backed by `str0m 0.20`) is a sans-IO WebRTC engine: callers must drive
it by calling `drive(now: Instant)` on a timer and feeding incoming UDP datagrams via
`handle_receive(...)`. The engine returns outbound datagrams (`Vec<str0m::net::Transmit>`) that
must be sent to the peer.

Phase 4 (P4-4 through P4-5) implemented the sans-IO surface and proved it correct in
synchronous/blocking tests. Phase 5 requires wiring it to a real async runtime. Two design
decisions needed to be made:

**Decision 1 — How to run the drive loop in an async context:**

The existing `UdpTransport` trait in `sh-ice` uses blocking `recv_from`. Reusing it on a tokio
worker thread would starve the runtime; it must not be used in an async context.

**Decision 2 — How to make the driver deterministically testable:**

`str0m` takes `std::time::Instant`; tokio timers use `tokio::time::Instant`. These types are not
directly convertible. Tests that use `tokio::time::pause()` + `tokio::time::advance()` need
deterministic std-clock values; the naive `Instant::now()` inside the driver would be
non-deterministic.

## Decision

### AsyncUdpSocket trait (injectable socket seam)

Define `AsyncUdpSocket: Send + Sync + 'static` with three methods:
- `fn local_addr(&self) -> SocketAddr`
- `async fn send_to(&self, data: &[u8], dst: SocketAddr) -> Result<(), TransportError>`
- `async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), TransportError>`

Two implementations:
- **`TokioUdpSocket`** — production: wraps `tokio::net::UdpSocket`, which is non-blocking and
  never stalls a tokio worker thread.
- **`SimUdpSocket`** / **`SimNetwork`** — test: in-memory `tokio::sync::mpsc` channels. Delivery
  does not depend on the tokio timer, so it works correctly under `tokio::time::pause()`. The
  `SimNetwork` routing table is `Arc<tokio::sync::Mutex<...>>` so multiple socket tasks can look
  up peer inboxes concurrently without `std::sync::Mutex`.

### Clock conversion via base-instant offset

At spawn time, two base instants are captured:
- `std_base: std::time::Instant` — supplied by the caller (typically a process-wide
  `OnceLock`-pinned base for determinism, or `Instant::now()` in production).
- `tokio_base: tokio::time::Instant::now()` — captured just before spawning the task.

Inside the driver:
```
std_now  = std_base  + (tokio::time::Instant::now() - tokio_base)
sleep_at = tokio_base + (str0m_deadline - std_base)
```

Under `tokio::time::pause()`, `tokio::time::Instant::now()` tracks paused virtual time, so all
derived `std::time::Instant` values advance only with `tokio::time::advance()`. This gives
bit-identical str0m clock sequences across runs.

### Driver loop (spawn_webrtc_driver)

Returns a `DriverHandle` with a `shutdown()` method. Internally spawns a `tokio::spawn` task
running a `tokio::select!` loop:
1. **Timer arm** — `sleep_until(next_drive_at() converted to tokio::time::Instant)`: calls
   `transport.drive(now)`, sends outbound datagrams.
2. **Recv arm** — `socket.recv_from(buf)`: feeds datagram to `transport.handle_receive(...)`,
   then calls `transport.drive(now)` to flush responses.
3. **Shutdown arm** — `tokio::sync::oneshot::Receiver<()>`: breaks the loop.

An initial `drive(now)` is called at task start to prime the engine (which sets the first
`next_drive_at()` deadline; before the first drive, `next_drive_at()` returns `None` and the
driver sleeps for a default 50 ms to avoid spinning before the engine is ready).

The `std::sync::Mutex<WebRtcInner>` inside `PinnedWebRtcTransport` is **never held across an
`.await`**: `drive()` and `handle_receive()` acquire the lock, do their work, release it, and
return — the subsequent async socket operations happen with no lock held.

### Shutdown mechanism

`tokio::sync::oneshot` channel: the `DriverHandle` holds the `Sender<()>`; the task holds the
`Receiver<()>`. No external crates (`tokio-util`, etc.) are needed.

## Consequences

**Positive:**
- The `AsyncUdpSocket` seam allows unit-testing the drive loop without OS sockets, `std::net`, or
  wall-clock time.
- `tokio::time::pause()` + `SimNetwork` gives fully deterministic CI results for the handshake
  test (`webrtc_driver_sim_handshake_deterministic`).
- No `std::sync::Mutex` is held across `.await` — satisfies the canonical Rust async safety rule.
- No new production dependencies (no `tokio-util`).
- The seam is backward-compatible with P5 requirements: `sh-core` can swap in any
  `Arc<dyn AsyncUdpSocket>` implementation (e.g. multiplexed ICE socket) without changing the
  driver.

**Negative / trade-offs:**
- `tokio/test-util` is added as a dev-dependency for `tokio::time::pause()`/`advance()`.
- The base-instant conversion is an approximation under wall-clock skew; under `tokio::time::pause()`
  it is exact. Production use (real time) is also exact since `std` and `tokio` time advance
  together.
- `SimNetwork` routing is O(1) hashmap lookup but holds a `tokio::sync::Mutex` across the
  lookup + channel send in `send_to`. This is only used in tests; it is not a production concern.

**Deferred (still in R-WEBRTC-LIVE):**
- (b) Wiring `PinnedWebRtcTransport` into `sh-core` (requires P4-6 session negotiation — already
  landed; the wiring itself is a P5 task).
- (c) Live `PinnedWebRtcTransport` ↔ browser `RTCPeerConnection` interop (P5 — needs SDP
  offer/answer via `sh-signaling`).
- (d) TWCC-based per-packet arrival-time feedback for GCC (P5 drive loop).
- (e) Live coturn relay path (blocked on R-COTURN-DEPLOY).

## Alternatives considered

- **Reuse `sh-ice::UdpTransport` (blocking `recv_from`):** Rejected. Blocking a tokio worker
  thread blocks the entire single-threaded runtime (in tests) or starves other tasks. The
  existing sync trait cannot be safely used in an async `select!` arm.

- **`tokio-util::CancellationToken` for shutdown:** Rejected for now to avoid an additional
  dependency. The `oneshot` channel is sufficient and idiomatic for a single producer/consumer
  shutdown signal.

- **Inject a `Box<dyn Fn() -> Instant>` clock:** Rejected. The base-offset approach achieves
  determinism without any additional trait or generic parameter on `spawn_webrtc_driver`. It
  also keeps the function signature simple for `sh-core` callers.

- **`tokio::sync::Mutex` for `WebRtcInner`:** Not adopted. `str0m::Rtc` is `!Sync` and holding a
  tokio mutex across `.await` is valid, but it would require restructuring the sync
  `PinnedWebRtcTransport` API (which also needs to be called from synchronous blocking tasks in
  existing tests). The `std::sync::Mutex` + "never hold across await" discipline is correct and
  well-established in this codebase.

- **Gate `SimNetwork`/`SimUdpSocket` behind a `test-utils` Cargo feature (S1 — deferred):** These
  types are currently part of the default public API surface even though they are only needed for
  tests. A future `test-utils` feature flag would exclude them from production builds and signal
  their test-only role more clearly. Tracked as a hygiene follow-up (non-blocking).
