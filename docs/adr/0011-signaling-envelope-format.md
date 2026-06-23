# ADR 0011: Signaling envelope wire format

- **Status:** Accepted
- **Date:** 2026-06-22
- **Deciders:** network-engineer, security-engineer

## Context

`sh-signaling` (P4-1) needs a wire format for the `SignalingEnvelope` that carries SDP offers,
ICE candidates, trickle-ICE, and lifecycle messages between two peers through the signaling
server. The server is a **zero-knowledge relay** — it routes opaque payloads without parsing
them (LLD §6.3). Requirements:

1. The server must route by `session_id` + `to_fp` only; `payload` must never be inspected.
2. Payloads are hostile input — the decoder must be bounds-checked and fuzz-tested.
3. The format must be compact and allocation-minimal (not a hot path, but large SDP blobs can
   appear in the payload; we cap them at 64 KiB).
4. No `serde`/`serde_json` — the repo has deliberately avoided serde (P2-5 decision), and all
   other on-wire formats are hand-rolled binary (see `sh-protocol`).

## Decision

**Hand-rolled 149-byte big-endian binary header + opaque payload.**

```text
Offset  Len   Field
0       1     kind: u8   (0=Hello … 6=Error, reserved ≥7)
1       16    session_id: [u8; 16]
17      64    from_fp:   [u8; 64]  (UTF-8 ASCII hex, 64 chars)
81      64    to_fp:     [u8; 64]  (UTF-8 ASCII hex, 64 chars)
145     4     payload_len: u32 BE  (0 for kinds with no payload)
149     N     opaque_payload (N ≤ MAX_PAYLOAD_LEN = 64 KiB)
```

The decoder (`envelope::decode`) checks bounds at every step, rejects unknown `kind` bytes,
rejects `payload_len > MAX_PAYLOAD_LEN`, rejects non-ASCII fingerprints, and never panics.
A `cargo-fuzz` target (`fuzz_envelope_decode`) is provided.

The `payload` field is carried as raw bytes and is never inspected by the server — this is the
structural enforcement of the zero-knowledge invariant.

## Consequences

- Positive:
  - Consistent with the repo's hand-rolled wire format style (`sh-protocol`).
  - Fixed-size header makes bound-checking trivial and branch-free.
  - The 64-byte hex fingerprint on the wire matches `sh_crypto::Fingerprint::as_str()` directly;
    no encoding translation needed.
  - `MAX_PAYLOAD_LEN = 64 KiB` prevents memory amplification from a hostile peer declaring
    an absurd payload length.
  - `cargo-fuzz` target ensures the decode path is continuously exercised.

- Negative / trade-offs:
  - 149-byte overhead per envelope is larger than a varint-compressed format, but signaling
    messages are infrequent and latency here is not critical.
  - Both fingerprint fields occupy 128 bytes even for control messages (Hello, Bye) where `to_fp`
    is not meaningful. A variable-length format would be more compact but harder to bound-check.

- Follow-ups:
  - P4-5 (BindCert) will carry the DTLS fingerprint in the `payload` field of an `Offer` envelope.
  - P4-6 (transport capability negotiation) will add a `Candidate`-style envelope for codec caps,
    reusing this same envelope format.
  - **R-SIG-AUTH (ADR-0016)** added `MessageKind::Challenge` (kind = 7) and carries the
    possession-of-identity-key proof in the opaque `payload` of `Hello`. The 149-byte routing
    header is unchanged; the server still routes only on `(session_id, to_fp)` and the payload
    remains opaque to routing (zero-knowledge invariant preserved).

## Alternatives considered

- **`serde_json`** — Human-readable, easy to debug in Wireshark. Rejected because: (a) the repo
  has a deliberate no-serde policy (P2-5); (b) the server must not parse `payload`, so human
  readability of the envelope header adds zero benefit; (c) serde_json pulls in a substantial
  dependency and introduces allocation pressure on every decode.

- **Protobuf / prost** — More compact, schema-enforced. Rejected because: (a) no existing protobuf
  dep in the workspace; (b) the `sh-protocol` precedent is hand-rolled binary; (c) fuzz coverage
  of a hand-rolled decoder is equally achievable.

- **Variable-length / varint fingerprints** — Would shrink Hello/Bye. Rejected because the
  fingerprint is always exactly 64 chars (SHA-256 hex of a 32-byte key) — variable-length adds
  complexity with no practical benefit.
