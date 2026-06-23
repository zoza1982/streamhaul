# ADR 0012: WebRTC transport path via str0m + GCC congestion control

- **Status:** Accepted
- **Date:** 2026-06-23
- **Deciders:** rust-staff-engineer, software-architect, security-engineer

## Context

Phase 4 adds a WebRTC transport path so that browser-based thin clients can connect to
Streamhaul without requiring a native plugin. Browser WebRTC stacks implement data channels
over ICE/DTLS/SCTP and use GCC (Google Congestion Control) for rate adaptation — not SCReAM.

Streamhaul already has:
- A QUIC native path (`sh-transport`, `quinn`) using SCReAM congestion control (`sh-adaptive`).
- ICE/STUN/TURN helpers in `sh-ice` for the native path.

We need:
1. A Rust-side WebRTC engine for the relay/host side that can handshake with a browser.
2. A GCC congestion controller compatible with the existing `CongestionController` trait.

## Decision

1. **WebRTC engine: str0m 0.20 (sans-IO).** The Rust crate `str0m` is a sans-IO WebRTC
   implementation: it models the complete ICE/DTLS/SCTP/data-channel stack but leaves all
   network I/O, timers, and threading to the caller. This gives full control over the drive
   loop and avoids tokio dependency in the engine itself.

2. **GCC implementation: queue_delay as OWD-gradient proxy.** `GccController` in
   `sh-adaptive::gcc` implements the delay-based + loss-based GCC algorithm. It uses the
   `TransportStats::queue_delay` field (already produced by the transport layer) as a proxy
   for the one-way delay gradient, rather than computing a full Kalman/trendline filter on
   per-packet TWCC timestamps. Both controllers (`ScreamController`, `GccController`) implement
   the shared `CongestionController` trait.

3. **Two ICE stacks in production.** The native path will continue to use `sh-ice` (Quinn's
   ICE, LLD §250). The WebRTC path uses str0m's built-in ICE. This is deliberate: the two
   paths serve different client types (native vs. browser) and have independent security
   domains. Unifying them into a single ICE stack is a P5 deferred decision.

## Consequences

**Positive:**
- Browser clients can connect without a native plugin (primary P4 goal).
- `GccController` reuses the `CongestionController` trait; the rate allocator and pacer
  work unchanged.
- str0m's sans-IO design makes the drive loop fully testable in synchronous unit tests
  without mocking sockets or timers.
- Small dependency surface: str0m adds one crate subtree with no tokio runtime requirement.

**Negative / trade-offs:**
- Two ICE stacks means two code paths to audit for security bugs (ICE mismatch attacks, etc.).
  The security-engineer must review the str0m ICE fingerprint and credential exchange code at P5.
- GCC deviations (see `gcc.rs` module doc) mean the controller may not produce bit-for-bit
  identical behaviour to libwebrtc. This is acceptable for a server-side implementation that
  primarily talks to browsers (which implement the real TWCC GCC); correctness of the
  congestion signal is sufficient.
- `WebRtcTransport` must be driven by an external task (no internal timer). The production
  drive task is deferred to P5 (signaling wiring).

**Follow-ups / deferrals:**
- P5: Wire `WebRtcTransport` drive task to the tokio runtime and real UDP socket.
- P5: Wire coturn relay for TURN traversal.
- P5: Browser interop testing (offer/answer SDP exchange with Chrome/Firefox).
- P5: Replace OWD proxy with real TWCC inter-arrival gradient (Kalman filter) once
  TWCC feedback packets arrive from browsers.
- P5: Unify ICE stacks or make the choice explicit in an updated LLD.

## Alternatives considered

- **webrtc-rs** — heavier dependency tree, requires tokio, less actively maintained in 2026.
  str0m was chosen for its lighter profile, sans-IO design, and active maintenance.

- **SCReAM for WebRTC path** — SCReAM is designed for QUIC/RTP paths. Browsers implement GCC;
  using SCReAM on the server side would create a mismatched congestion control pair that could
  oscillate or starve the browser stream.

- **Single OWD proxy threshold vs. adaptive threshold** — libwebrtc uses an adaptive overuse
  threshold from the trendline filter. A fixed 25 ms threshold is simpler, deterministic, and
  sufficient for the P4 milestone. The adaptive threshold will be re-evaluated at P5 with
  real TWCC data.
