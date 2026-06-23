# ADR 0014: Bind the WebRTC DTLS fingerprint to device identity (P4-5)

- **Status:** Accepted
- **Date:** 2026-06-23
- **Deciders:** security-engineer, network-engineer, rust-staff-engineer, code-reviewer
- **Builds on:** ADR-0007 (Noise handshake + identity-bound `BindCert`), ADR-0013 (str0m WebRTC backend).
- **Amends:** ADR-0007 §2.1 (the `DTLS_FPR_COMMIT` digest definition — see §2 below).
- **Phase / task:** P4-5 (`IMPLEMENTATION_PLAN.md`).

## Context

The WebRTC media/data path authenticates the peer's DTLS handshake by a fingerprint of its
self-signed certificate. That fingerprint is delivered to the peer **through the SDP via the
untrusted signaling server** (LLD §6.2/§6.3). A signaling/relay MITM that swaps the SDP fingerprint
for its own — and terminates DTLS — sits in the middle of the session: it sees and steers screen,
input, clipboard, and files. This is the single most important MITM vector on the WebRTC transport.

ADR-0007 already mints, inside the **encrypted, identity-authenticated Noise handshake**, a signed
`BindCert` that commits (among other fields) a `DTLS_FPR_COMMIT`. P4-5 is the consumer: extract that
committed fingerprint from the *verified* handshake and pin it on the transport so str0m fail-closes
any DTLS certificate that does not match the identity-signed commitment. The relayed SDP fingerprint
is then advisory; the **signed** commitment is authoritative.

Two concrete conflicts had to be resolved before implementing:

1. **Digest definition.** ADR-0007 §2.1 wrote `DTLS_FPR_COMMIT = SHA-256 of the DTLS SPKI`. But the
   chosen WebRTC engine (str0m 0.20, ADR-0013) computes a DTLS fingerprint as
   `SHA-256(whole DER certificate)` (the RFC 8122 fingerprint), exposes only that
   (`local_dtls_fingerprint().bytes`, 32 bytes), and **enforces that** against the peer cert
   (fail-closed). It does not expose the SPKI separately, and an SPKI digest would not match what
   str0m enforces.
2. **Downgrade vector.** A MITM cannot forge the Ed25519-signed commitment, so the only attack on a
   correctly-built `BindCert` is to **strip** the binding down to `DTLS_FPR_ALG = NONE` (the QUIC
   value) and present an unpinned DTLS cert.

## Decision

### 1. Pin-before-handshake (the mechanism)

The verifier, after a Noise handshake completes and the peer's `BindCert` is verified (signature +
identity self-consistency + Noise-static binding + expiry + trust, ADR-0007 §2.6), extracts the
peer's committed DTLS fingerprint and calls `WebRtcTransport::set_remote_dtls_fingerprint(...)`
**before** the DTLS handshake starts. str0m fail-closes any peer certificate whose RFC-8122
fingerprint does not equal the pinned value. This authenticates the untrusted SDP-relayed
fingerprint against the signed commitment delivered inside the authenticated Noise tunnel.

### 2. Digest = whole-certificate SHA-256 (amends ADR-0007 §2.1)

`DTLS_FPR_COMMIT` is the **SHA-256 of the whole DTLS certificate** (RFC 8122), exactly the value
`WebRtcTransport::local_dtls_fingerprint().bytes` returns and str0m enforces — **not** the SPKI
digest. The build side commits `local_dtls_fingerprint().bytes`; the verify side reconstructs
`str0m::crypto::Fingerprint { hash_func: "sha-256", bytes: commit.to_vec() }` and pins it.
`DTLS_FPR_ALG` stays `0x01` (`DTLS_FPR_ALG_SHA256`). ADR-0007 §2.1's wording is amended accordingly
(“SHA-256 of the DTLS certificate SPKI” → “SHA-256 of the whole DTLS certificate (RFC 8122
fingerprint, as computed and enforced by str0m)”). The TBS byte layout, offsets, `FIELD_COUNT`, and
canonical encoding are **unchanged** — only the documented meaning of the 32 commit bytes changes,
so the golden conformance vector and all existing `BindCert` tests still pass.

### 3. Downgrade defense — reject `ALG = NONE` for a WebRTC peer (CRITICAL)

For a **WebRTC** session the peer's `BindCert` MUST carry `DTLS_FPR_ALG = SHA256` with a non-zero
commit. `HandshakeOutcome::require_webrtc_dtls_pin()` (forwarding to
`BindCert::require_webrtc_dtls_pin()`) returns the 32-byte commit, or
`CryptoError::DtlsBindingMissing` if `ALG = NONE` (a stripped binding) or the commit is all-zero.
A WebRTC session that hits this **aborts** — there is no unpinned-DTLS fallback. QUIC sessions keep
`ALG = NONE` (no DTLS) and use `peer_dtls_pin()` (which returns `None`) — they never call the
`require_*` accessor.

### 4. API surface (owning crates; no new production cross-crate coupling)

- **Build side (`sh-crypto`):** a transport-agnostic `DtlsCommitment { alg, commit: [u8;32] }`
  (`DtlsCommitment::sha256(commit)`), a `BindCertBuilder::dtls_commitment(..)` setter, and
  `Option<DtlsCommitment>`-taking handshake constructors `NoiseHandshake::{initiator,responder}_{xk,ik}_with_dtls`.
  The existing no-`dtls` constructors are unchanged and delegate with `None` (→ `ALG = NONE`), so no
  existing call site or test breaks.
- **Verify side (`sh-crypto`):** `BindCert::dtls_pin() -> Option<DtlsPin>` and
  `BindCert::require_webrtc_dtls_pin() -> Result<[u8;32], CryptoError>`, mirrored on
  `HandshakeOutcome` as thin forwarders (`peer_dtls_pin`, `require_webrtc_dtls_pin`). `BindCert`
  remains the owner of the field semantics.
- **Transport (`sh-transport`):** added the read-back getter
  `WebRtcTransport::remote_dtls_fingerprint() -> Option<Fingerprint>` (closing the P4-4 review gap),
  enabling a post-connect assertion that str0m verified exactly the pinned fingerprint. Constant-time
  comparison is str0m's `Fingerprint: PartialEq` (it `ct_eq`s the bytes) — not hand-rolled.
- **Glue:** the few lines that read `outcome.require_webrtc_dtls_pin()?` and call
  `transport.set_remote_dtls_fingerprint(Fingerprint{..})` live in an **integration test**
  (`crates/sh-transport/tests/dtls_identity_binding.rs`) that dev-depends on both crates, since no
  `sh-core` session-orchestration layer exists yet (it lands with P4-6). The commit is a plain
  `[u8;32]`, so the binding primitive imposes no production `sh-transport → sh-crypto` dependency.

### 5. Deferred: WebRTC Noise prologue channel-binding to the DTLS exporter

ADR-0007 §1.4 / follow-up line 375 envisaged binding the Noise prologue's `session_context` to the
WebRTC **DTLS exporter** (as native QUIC binds to the QUIC TLS exporter). **This is deferred and is
NOT required for the P4-5 MITM defense.** It is fundamentally in tension with pin-before-handshake
ordering: the DTLS exporter does not exist until *after* the DTLS handshake, but the `BindCert`
(carrying the fingerprint commitment) must be pinned *before* DTLS starts. The fingerprint-pin
commit/verify is a complete MITM defense on its own — it cryptographically ties the DTLS cert the
peer presents to the trusted device identity. Tracked as Risk Register row `R-DTLS-EXPORTER-BIND`.

## Consequences

- **Positive:**
  - A signaling/SDP fingerprint swap is rejected: str0m fail-closes the DTLS handshake against the
    identity-signed commitment. Proven end-to-end (honest path connects; swapped cert never
    connects; a non-vacuity control shows the same swap connects only if the pin tracks the
    attacker, so the rejection is genuinely caused by the pin).
  - The downgrade-to-`ALG=NONE` strip is a typed, tested rejection (`DtlsBindingMissing`).
  - Zero new production cross-crate coupling; the binding primitive is a plain `[u8;32]`.
  - No change to the `BindCert` wire layout / canonical encoding (only the commit's documented
    meaning) — full backward compatibility with P3-2 conformance vectors.
- **Negative / trade-offs:**
  - The commitment is the whole-cert digest, so rotating the DTLS certificate invalidates the
    commitment (a fresh `BindCert` must be minted). Acceptable: `BindCert`s are short-lived (24 h,
    ADR-0007) and minted per handshake.
  - DTLS-exporter channel binding is deferred (`R-DTLS-EXPORTER-BIND`); the fingerprint pin does not
    additionally bind the Noise run to *this* DTLS connection's exporter. The pin already binds the
    peer cert to the identity, which is the property P4-5 needs.
- **Follow-ups:**
  - **P4-6:** move the glue (`require_webrtc_dtls_pin` → `set_remote_dtls_fingerprint`) into the
    `sh-core` session-orchestration layer once it exists; wire transport capability negotiation.
  - **R-DTLS-EXPORTER-BIND:** evaluate DTLS-exporter prologue binding (or a post-DTLS
    key-confirmation) without violating pin-before-handshake ordering.

## Alternatives considered

- **Commit the SPKI digest (literal ADR-0007 wording)** — Rejected. str0m does not expose the SPKI
  and enforces the whole-cert digest; an SPKI commitment would never match what str0m verifies, so
  the pin would be unenforceable. The whole-cert digest is the value on the wire and in str0m's
  fail-closed check.
- **Allow `ALG = NONE` on WebRTC and skip pinning if absent** — Rejected. That is exactly the MITM's
  downgrade path: strip the binding, present any cert. WebRTC must require the SHA-256 pin or abort.
- **Trust the SDP fingerprint directly (no signed commitment)** — Rejected. The SDP traverses the
  untrusted signaling server; a swap there is undetectable without the identity-signed commitment.
- **Bind the Noise prologue to the DTLS exporter now** — Deferred, not rejected. It conflicts with
  pin-before-handshake ordering and is unnecessary for the MITM defense (see Decision §5).
