# ADR 0015: Transport capability negotiation — wire format, symmetric negotiation, session seam, and DTLS security gate (P4-6)

- **Status:** Accepted
- **Date:** 2026-06-23
- **Deciders:** network-engineer, security-engineer, rust-staff-engineer
- **Builds on:** ADR-0003 (transport finalization), ADR-0011 (signaling envelope), ADR-0013 (str0m WebRTC backend), ADR-0014 (DTLS identity binding)
- **Phase / task:** P4-6 (`IMPLEMENTATION_PLAN.md`) — final Phase 4 task.

## Context

ADR-0003 decided that peers negotiate `transports: [quic, webrtc]` at signaling time, hiding both
stacks behind one `Transport` trait, with WebRTC as the v1.0 default and native↔native QUIC
promotion in v1.1. P4-6 is the task that implements this negotiation mechanism and the
session-orchestration seam that routes each established session to the correct transport backend.

Three sub-problems must be solved:

1. **Wire format** — how do peers advertise which transports they support? No existing wire type
   covers this.  The format must be compact, bounds-checked, hostile-input-safe, and forward-compatible.

2. **Negotiation rule** — how is the winner chosen? The rule must be **symmetric**
   (both peers derive the same answer from the same two cap-sets) so neither side can force a
   downgrade by advertising in a different order.

3. **Session-orchestration seam** — where does the "run Noise → negotiate → apply DTLS pin gate →
   build transport" flow live, and how can it be tested deterministically without live sockets?
   ADR-0014 §Follow-ups mandates that the `require_webrtc_dtls_pin → set_remote_dtls_fingerprint`
   glue move out of the P4-5 integration test and into `sh-core`.

## Decisions

### 1. `TransportKind` in `sh-types`

A leaf enum `TransportKind { Quic, Webrtc }` is added to `crates/sh-types`. Placing it in
`sh-types` (which has no crate-level dependencies within the workspace) avoids a circular
dependency: `sh-protocol` (negotiation logic) and `sh-transport` (factory implementations) both
import it cleanly.

### 2. `TransportCaps` wire format in `sh-protocol::transport_caps`

**2 bytes, fixed, big-endian:**

```text
BYTE 0:  VERSION          = 0x01 on encode; rejected (ProtocolError::UnknownVersion) on decode if != 0x01.
BYTE 1:  TRANSPORT_MASK   bit 0 = QUIC, bit 1 = WebRTC.
                           Bits 2-7 RESERVED: MUST be 0 on encode; SILENTLY IGNORED on decode.
```

The home crate is `sh-protocol` (mirroring the existing `CodecCapsPayload` codec-caps format). The
decoder is bounds-checked, panic-free, and never touches reserved bits. Reserved bits are **ignored**
on decode (unlike codec-caps, which rejects them) to enable forward compatibility: future protocol
versions may define new transport bits without breaking current decoders.

A `fuzz_decode_transport_caps` seam is provided for `cargo-fuzz` (mirroring the existing
`fuzz_decode_envelope` and `fuzz_decode_framing` seams).

The caps are carried in the `payload` field of a `MessageKind::Candidate` `SignalingEnvelope`
(per ADR-0011's guidance: "P4-6 will add a `Candidate`-style envelope for codec caps"). The
2-byte payload's VERSION byte (0x01) distinguishes it from longer ICE candidate blobs.

Kind-byte constants `KIND_TRANSPORT_CAPS_OFFER = 0x20` and `KIND_TRANSPORT_CAPS_ANSWER = 0x21`
are defined for future use by higher-level framing, but are not used by the P4-6 orchestrator
(which uses `MessageKind::Candidate` at the envelope level).

### 3. Symmetric negotiation function

```rust
pub fn negotiate(local: TransportCaps, peer: TransportCaps) -> Result<TransportKind, NegotiationError>
```

**Fixed global preference order: `[Quic, Webrtc]`.**

The function iterates this order and returns the first transport present in **both** sets. The
global order — not either side's caps order — determines the winner. This guarantees:

```
negotiate(a, b) == negotiate(b, a)  for all non-empty intersections
```

QUIC is first because: lower overhead (no DTLS+SRTP stack over QUIC-TLS), native multiplexing,
purpose-built congestion control (SCReAM over QUIC vs. GCC over WebRTC). WebRTC is the fallback for
browser endpoints (which cannot run QUIC).

An empty intersection returns `NegotiationError::NoCommonTransport { local, peer }` (thiserror).

A `proptest` property test proves symmetry for all (a, b) cap-set pairs.

### 4. Session-orchestration seam — `sh-core::session`

`SessionEstablisher<S: SignalingChannel, F: TransportFactory>` drives the four-phase flow:

```text
1. Cap-exchange   – each side sends its TransportCaps in a Candidate envelope and reads the peer's.
2. Negotiate      – select the preferred common transport via the fixed global order.
3. Security gate  – WebRTC only: extract the verified DTLS pin; QUIC: skip.
4. Build          – call the factory to construct the concrete Transport.
```

The two injected seams:

- **`SignalingChannel`** — `async fn send(&mut self, env: SignalingEnvelope)` / `async fn recv(&mut self)`
  (via `#[async_trait]`). The trait is **async**: the orchestrator's `establish_*` methods are `async`,
  and a synchronous `recv()` would block a tokio worker thread (the test double's
  `std::sync::mpsc::recv()` starved the runtime and made a `#[tokio::test]` flaky). The async trait lets
  `recv().await` yield, so `session_symmetric_exchange` can run both peers via `tokio::join!` on a
  single-threaded `#[tokio::test]` runtime. Cost: `async-trait` in `sh-core`'s prod deps (the trait is
  production surface, not just test infra).
- **`TransportFactory`** — `fn build(kind, path, webrtc_peer_pin: Option<[u8;32]>)`.
  Responsible for applying the DTLS pin when kind == Webrtc.

Both seams require `Send + 'static`; `SessionEstablisher` itself is not object-safe (generic params).

`sh-signaling` and `sh-ice` are added to `sh-core`'s `[dependencies]`. Existing `sh-core` tests
and harnesses are unaffected (their features remain unchanged).

### 5. The DTLS security gate — R-DTLS-EXPORTER-BIND invariant satisfied at the negotiation seam

Inside `negotiate_and_build` (the shared tail of `establish_as_initiator` /
`establish_as_responder`):

```rust
let webrtc_peer_pin = match kind {
    TransportKind::Webrtc => {
        let pin = noise_outcome.require_webrtc_dtls_pin()
            .map_err(|_| SessionError::DtlsBindingMissing)?;
        Some(pin)
    }
    TransportKind::Quic => {
        // A QUIC session must NOT carry a DTLS commitment; a present one is an anomaly → abort.
        if noise_outcome.peer_dtls_pin().is_some() {
            return Err(SessionError::UnexpectedDtlsCommitment);
        }
        None
    }
};
let transport = factory.build(kind, ice_path, webrtc_peer_pin)?;
```

**This gate is non-bypassable by construction:** there is exactly one code path that calls
`factory.build(Webrtc, ...)`, and it always passes through `require_webrtc_dtls_pin()?` first. A
peer whose `BindCert` commits `ALG=NONE` (the QUIC / "no DTLS" value) causes the call to return
`CryptoError::DtlsBindingMissing`, which is mapped to `SessionError::DtlsBindingMissing` and
aborts the session before any transport is constructed.

The QUIC branch does **not** call `require_webrtc_dtls_pin`. If a QUIC-negotiated peer's `BindCert`
anomalously carries a DTLS commitment (`peer_dtls_pin().is_some()`), the session is **hard-aborted**
with `SessionError::UnexpectedDtlsCommitment` rather than proceeding. Rationale: for a remote-control
product, a QUIC peer that committed a DTLS fingerprint for a transport it was not selected to use
signals a protocol violation or a confused/downgraded peer, not benign misconfiguration — failing
closed on the anomaly is the conservative choice. (This was tightened from an earlier warn-and-continue
design during the P4-6 security gate.)

The `session_webrtc_dtls_pin_gate` integration test proves: WebRTC negotiation + Noise outcome with
`ALG=NONE` → `DtlsBindingMissing`. The `session_mitm_dtls_cert_swap_rejected` integration test
proves non-vacuity: honest certs connect; MITM swapped cert is fail-closed by str0m.

**Risk register update:** `R-DTLS-EXPORTER-BIND` — the anti-downgrade gate (`require_webrtc_dtls_pin`
before any WebRTC transport construction) is now enforced at the negotiation seam in `sh-core`, not
only in the P4-5 integration test. The DTLS-exporter prologue binding (the additional anti-lift
property) remains deferred — see §Deferred below.

### 6. Relay fallback wiring

`IcePathOutcome { local_addr, remote_addr, is_relay }` carries the ICE path selection result.
The `is_relay` flag comes from `sh-ice::IceAgent` (which already nominates relay candidates for
Symmetric×Symmetric NAT via `add_relay_candidate` + the existing `nat_matrix_relay_fallback` test).
The factory receives the full outcome and is responsible for pointing the transport at the correct
address. The `relay_fallback_direct_path_selection` test proves that `is_relay=false` (direct) and
`is_relay=true` (relay) are both surfaced correctly through the orchestrator.

The relay path decision logic itself is NOT new in P4-6 — it is the existing `IceAgent` nomination
logic (P4-3, proven in `nat_matrix_relay_fallback`). P4-6 surfaces the nominated path to the
session orchestrator.

## Deferred (P5 or later)

| Item | Risk register row | Reason |
|------|-------------------|--------|
| Live DTLS/SRTP over a real UDP socket; tokio drive task for `WebRtcTransport` | R-WEBRTC-LIVE | Requires a real UDP port + async event loop; deferred to P5 |
| Live coturn server deployment + `IceAgent::gather()` real TURN allocation | R-COTURN-DEPLOY | Kubernetes + cloud infra work; deferred to P5 |
| Browser↔native WebRTC interop (`RTCPeerConnection` SDP exchange) | — | P5 scope |
| Unifying `sh-ice` native ICE stack and str0m's built-in ICE stack (ADR-0013 §3) | — | P5 scope; two stacks coexist until P5 |
| Noise-prologue↔DTLS-exporter channel binding (additional anti-lift property) | R-DTLS-EXPORTER-BIND | Conflicts with pin-before-handshake ordering; the fingerprint pin is a complete MITM defense |
| QUIC promotion wiring (`sh-ice` + `quinn` integration) | — | P8 scope |

## Consequences

- **Positive:**
  - The DTLS pin gate invariant (ADR-0014 follow-up) is now enforced in production code, not only
    in an integration test.
  - Negotiation is symmetric by construction (fixed global order) — neither peer can influence the
    transport selection beyond capability advertisement.
  - The orchestration seam is fully deterministic under injected seams — 6 integration tests, all
    green, no live sockets required.
  - Forward-compatible wire format: future transports add bits 2-7 without breaking current decoders.
  - Phase 4 is now complete at the capability/negotiation/security-gate level.
- **Negative / trade-offs:**
  - `SignalingChannel` is an `#[async_trait]`, so `sh-core` carries `async-trait` as a production
    dependency. (Chosen over a synchronous trait, whose blocking `recv` starved the tokio runtime and
    made a `#[tokio::test]` flaky — see §4.)
  - The `TransportFactory` is responsible for applying the DTLS pin — a production factory that
    forgets to call `set_remote_dtls_fingerprint` re-introduces the MITM vector.  Documentation
    and the security gate test mitigate this; a follow-up could enforce it structurally via a
    `PinnedWebRtcTransport` builder type.
- **Follow-ups:**
  - P5: wire `WebRtcTransport` into `sh-core` with a live tokio drive task.
  - P5: browser↔native SDP offer/answer via `sh-signaling`.
  - R-DTLS-EXPORTER-BIND: evaluate post-DTLS key-confirmation over the Noise+DTLS channel.

## Alternatives considered

- **Put `TransportKind` in `sh-transport`** — would create a circular dependency (sh-protocol needs
  it for `negotiate`; sh-transport already imports sh-protocol for channel headers). Rejected.
- **Put negotiation in `sh-signaling`** — that crate is the zero-knowledge relay; it must not parse
  payload content. Rejected; negotiation belongs in `sh-protocol` (same crate as `CodecCapsPayload`).
- **Synchronous `SignalingChannel` trait** — initially chosen (no `async-trait`, no runtime in
  tests), but the test double's blocking `std::sync::mpsc::recv()` parked a tokio worker inside the
  `async` `establish_*` methods and made `session_webrtc_dtls_pin_gate` flaky under runtime
  starvation. Rejected in favour of the async trait, which lets `recv().await` yield and runs both
  peers via `tokio::join!` on a single-threaded `#[tokio::test]`.
- **Reject reserved bits on decode (like `CodecCapsPayload`)** — would break decoders when future
  transport kinds are defined. Rejected in favor of silent-ignore for forward compatibility.
- **Async `SignalingChannel` trait** — would require `async-trait` and complicate the trait object
  story. Rejected; the current synchronous trait is simpler and all callers are in tests where
  blocking is acceptable.
- **Initiator/responder use Offer/Answer envelope kinds for caps** — natural but the ADR-0011 note
  says "Candidate-style" reuse; using Candidate keeps the orchestrator decoupled from the SDP
  offer/answer round-trip ordering. Accepted.
