# ADR 0013: WebRTC transport path via str0m + GCC congestion control

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

**Negative / trade-offs:**
- Two ICE stacks means two code paths to audit for security bugs (ICE mismatch attacks, etc.).
  The security-engineer must review the str0m ICE fingerprint and credential exchange code at P5.
- GCC deviations (see `gcc.rs` module doc) mean the controller may not produce bit-for-bit
  identical behaviour to libwebrtc. This is acceptable for a server-side implementation that
  primarily talks to browsers (which implement the real TWCC GCC); correctness of the
  congestion signal is sufficient.
- `WebRtcTransport` must be driven by an external task (no internal timer). The production
  drive task is deferred to P5 (signaling wiring).

**Dependency reality (CLAUDE.md §7):**
`str0m = "=0.20.0"` is pinned with `default-features = false, features = ["rust-crypto"]`.
Despite the `rust-crypto` feature flag, str0m's transitive dependency `dimpl` pulls in
`aws-lc-rs` AND a second copy of `rcgen` (0.14, alongside the workspace's `rcgen 0.13`)
into the dependency tree. This means the tree contains both `ring` (via quinn/rustls) and
`aws-lc-rs` (via str0m→dimpl) as crypto backends. This is a **wider crypto surface than
the comment in `sh-transport/Cargo.toml` previously implied**. Mitigation: `cargo audit`
is clean, `str0m` itself is exact-pinned so the tree is deterministic, and str0m's
DTLS/crypto operations are isolated behind `WebRtcTransport`. If a future str0m version
avoids `dimpl`/`aws-lc-rs`, the dependency should be re-evaluated. This posture is
acceptable at P4 but must be revisited at GA (tracked as `R-STR0M-AUDIT`).

**What P4-4 does NOT do (doc honesty):**
- P4-4 establishes the DTLS transport and exposes the fingerprint seam
  (`WebRtcTransport::local_dtls_fingerprint()` and `set_remote_dtls_fingerprint()`), but
  does **NOT** bind the DTLS fingerprint to the device identity. That binding is the P4-5
  task (wiring `WebRtcTransport::local_dtls_fingerprint()` into `BindCertBuilder::dtls_fpr()`
  and verifying the remote fingerprint against the peer's `BindCert`).
- P4-4 does **NOT** feed live str0m stats (RTT/loss/queue_delay) into GCC. The
  `GccController` currently receives `TransportStats.queue_delay` from a placeholder; real
  TWCC extraction from str0m's per-packet receive timestamps is the P5 drive loop task.
- Do NOT interpret "DTLS established" as "peer authenticated" — peer authentication requires
  the P4-5 BindCert fingerprint binding. Until then, the DTLS channel is encrypted but the
  remote certificate is not bound to a device identity.

**Follow-ups / deferrals:**
- P4-5: Bind local DTLS fingerprint to `BindCert` (`BindCertBuilder::dtls_fpr`) and pin
  the remote fingerprint from the peer's verified `BindCert`. Closes the DTLS MITM surface.
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
