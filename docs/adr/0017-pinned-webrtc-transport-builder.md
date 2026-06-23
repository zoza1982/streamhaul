# ADR-0017: Structural Pin Enforcement via `PinnedWebRtcTransport` Builder

- **Status:** Accepted
- **Date:** 2026-06-23
- **Deciders:** security-engineer, rust-staff-engineer

## Context

P4-6 (`sh-core` `SessionEstablisher`) introduced a `TransportFactory` trait whose WebRTC arm
is contractually required to call `set_remote_dtls_fingerprint` before the DTLS handshake
begins. The code review gate for P4-6 identified a security API footgun: `WebRtcTransport::new`
was public, and `set_remote_dtls_fingerprint` was a separate public method — so a production
factory implementation could construct a bare `WebRtcTransport` without ever calling
`set_remote_dtls_fingerprint`, silently bypassing the DTLS identity-binding pin that ADR-0014
requires. The P4-6 gate deferred this as a mandatory P5 follow-up:

> The P5 live-socket wiring task MUST introduce a `PinnedWebRtcTransport` builder (or similar
> structural enforcement) that makes it impossible to construct a `WebRtcTransport` without
> applying the pin.

This ADR documents the P4-6 follow-up (landed as a standalone commit on
`feat/pinned-webrtc-transport` before live P5 sockets are wired up) that closes that gap.

## Decision

### 1. `WebRtcTransport` demoted to `pub(crate)`

`WebRtcTransport::new` and the `WebRtcTransport` struct are now `pub(crate)`. External callers
cannot construct or name the type. `set_remote_dtls_fingerprint` is removed from the public API
entirely — it is no longer needed, because the builder applies the fingerprint before the
`WebRtcTransport` is created.

### 2. `WebRtcTransportBuilder` — the gate

A new `pub struct WebRtcTransportBuilder { rtc: Rtc, local_addr, remote_addr }` holds the
configured `Rtc`. Its ONLY public finisher is:

```rust
pub fn pin_remote_dtls(mut self, fingerprint: Fingerprint) -> PinnedWebRtcTransport {
    self.rtc.direct_api().set_remote_fingerprint(fingerprint);
    PinnedWebRtcTransport(WebRtcTransport::new(self.rtc, self.local_addr, self.remote_addr))
}
```

This applies `set_remote_fingerprint` on the raw `Rtc` **before** wrapping it in
`WebRtcTransport`, guaranteeing the pin is in place before any DTLS traffic can flow.

### 3. `PinnedWebRtcTransport` — the only `impl Transport` for WebRTC

`PinnedWebRtcTransport` is a `pub` newtype over `WebRtcTransport`. It is the **only** type
that `impl Transport` for WebRTC in production builds. External callers cannot bypass it:
there is no public `WebRtcTransport` they could wrap in a `Box<dyn Transport>`.

`PinnedWebRtcTransport` re-exposes all the methods external callers need: `drive`,
`handle_receive`, `next_drive_at`, `local_dtls_fingerprint`, `remote_dtls_fingerprint`,
`rtt`, `packet_loss`.

### 4. `impl Transport for WebRtcTransport` gated to `#[cfg(test)]`

The inline module tests (`webrtc.rs::tests`) use `WebRtcTransport` directly (via `pub(crate)`
access) to test the engine without going through the builder. They need `Transport` trait
methods (`open_channel`, `accept_channel`). Rather than rewriting every inline test to use the
builder, `impl Transport for WebRtcTransport` is gated behind `#[cfg(test)]`. In production
builds, `PinnedWebRtcTransport` is the sole `impl Transport`; in test builds, both are
available (but `WebRtcTransport` is still `pub(crate)`, so external test crates cannot use it).

### 5. External test files updated

`crates/sh-transport/tests/dtls_identity_binding.rs` and
`crates/sh-core/tests/session_negotiation.rs` are updated to use
`WebRtcTransportBuilder::new(...).pin_remote_dtls(fp)` instead of
`WebRtcTransport::new(...)` + `set_remote_dtls_fingerprint(...)`. In both files, the
fingerprints used for the Noise handshake are read from the raw `Rtc` instances before they
are passed to the builder, so the ordering constraint is satisfied.

### 6. Public API surface

```rust
// Exported from sh_transport:
pub use webrtc::{PinnedWebRtcTransport, WebRtcChannel, WebRtcTransportBuilder};
// NOT exported: WebRtcTransport (pub(crate))
```

## Consequences

- **Positive:**
  - A production `TransportFactory` implementation CANNOT return a `Box<dyn Transport>` for
    WebRTC without going through `WebRtcTransportBuilder::pin_remote_dtls`. The type system
    enforces the security invariant rather than a contract comment.
  - `set_remote_dtls_fingerprint` is removed from the public API — callers cannot call it on
    an already-constructed transport after DTLS may have started.
  - The code change is self-documenting: the only way to get a WebRTC transport is through
    the builder, and the builder's only finisher requires the fingerprint.
  - Tests added: `builder_pin_applied_before_handshake` verifies the builder returns the right
    type with the correct initial state (pre-DTLS: `remote_dtls_fingerprint() == None`).

- **Negative / trade-offs:**
  - `impl Transport for WebRtcTransport` is gated to `#[cfg(test)]`, which means the
    production and test codepaths for `WebRtcTransport` differ. This is a minor inconsistency
    but is preferable to rewriting every inline test.
  - Callers who previously held `Arc<WebRtcTransport>` must now hold `Arc<PinnedWebRtcTransport>`.
    This is a breaking API change, but since the type was not yet used in any production call
    site (the live drive loop is deferred to P5), the impact is limited to test files.

- **Follow-ups:**
  - P5 live-socket drive loop must use `WebRtcTransportBuilder` — it inherits this requirement.
  - The DTLS-exporter channel binding (R-DTLS-EXPORTER-BIND, ADR-0014 §5) remains deferred;
    the structural pin enforcement here is the prerequisite gate that makes the P5 live path
    safe to land.

## Alternatives considered

- **Keep `WebRtcTransport` public with a doc contract** — this is what P4-6 shipped; the
  code review gate explicitly flagged it as insufficient. A doc contract cannot be enforced
  by the compiler and is silently bypassable.

- **Make `set_remote_dtls_fingerprint` a type-state transition** (e.g., `WebRtcTransport<Pinned>`
  vs. `WebRtcTransport<Unpinned>`) — adds type-parameter complexity throughout the API without
  a meaningfully cleaner interface than the builder pattern. The builder is simpler and equally
  expressive.

- **Remove `impl Transport for WebRtcTransport` entirely (no `#[cfg(test)]` gate)** and rewrite
  all inline tests to use `PinnedWebRtcTransport` — this is cleaner but requires changing every
  inline test. The `#[cfg(test)]` gate achieves the same production-build safety with less churn.
