# ADR 0016: Signaling peer authentication (possession-of-identity-key proof)

- **Status:** Accepted
- **Date:** 2026-06-23
- **Deciders:** security-engineer, network-engineer

## Context

`sh-signaling` (P4-1, ADR-0011) is a zero-knowledge relay: it routes opaque envelopes between two
peers by `(session_id, to_fp)` and never parses the payload. P4-1 shipped with the authentication
seam stubbed — the only `PeerAuthenticator` was `AcceptAll` (test-only) — and tracked the gap as
risk **R-SIG-AUTH**. With `AcceptAll`, **any** peer that can reach the server can register **any**
fingerprint. That lets an attacker:

- **Impersonate** a victim by registering the victim's `from_fp` and receiving its Offers/Answers.
- **Hijack routing** by occupying a `(session_id, fp)` slot the legitimate peer needs.
- **DoS** a session by claiming a peer's fingerprint so the real peer is refused (per-session peer
  cap) or its messages are misrouted.

This is unacceptable for a public-internet, full-remote-control product (CLAUDE.md §1, §7). The
threat model explicitly includes a **malicious relay/signaling operator** (the zero-knowledge
invariant exists precisely because we don't trust the relay).

Constraints (from the task brief and CLAUDE.md §7/§11):

1. **Possession proof** — a connecting peer must prove it controls the Ed25519 device key behind
   its claimed `from_fp`. Reuse vetted `sh-crypto` primitives; do not roll new crypto.
2. **Replay resistance** — choose and justify a mechanism.
3. **Zero-knowledge preserved** — the server only handles PUBLIC data; routing stays keyed on
   `(session_id, to_fp)`; the opaque payload stays opaque to routing.
4. **Auth ≠ trust** — server-side auth proves *ownership*, not peer-to-peer *trust*.
5. **Self-hostable** — no external token issuer, no pre-shared server secret.
6. **Evolve the seam** — `PeerAuthenticator` must carry the proof context and return a typed,
   sanitized `Result`, and stay a trait so policy (allow-list / issuer) can layer on.
7. **Hostile input** — the proof arrives over the wire; parse it panic-free, bounds-checked, fuzz
   it, use `verify_strict`, constant-time compares, and leak nothing in errors.

## Decision

### Possession-of-identity-key proof, bound to a server-issued challenge nonce

The server issues a **fresh random 32-byte challenge** on every connection (a new `Challenge`
envelope, kind = 7, sent immediately on connect, nonce in the opaque payload). The connecting peer
signs a canonical, domain-separated message and presents an **`IdentityProof`** in the opaque
payload of its `Hello`. The server verifies:

1. **Challenge binding** (constant-time) — the proof echoes the exact challenge this connection
   issued. This is the anti-replay check.
2. **Key validity** — the presented Ed25519 public key decodes to a valid, **non-weak** point
   (`DeviceIdentity::from_public_key_bytes` rejects small-order keys).
3. **Fingerprint binding** (constant-time over the 64 hex bytes) — `Fingerprint::from(pubkey)`
   equals the claimed `from_fp`.
4. **Signature** — `Signature::verify` (→ `verify_strict`) over the recomputed TBS.

The proof lives entirely in `sh-crypto` (`peer_auth::IdentityProof`), reusing `DeviceIdentity`,
`Fingerprint`, `Signature` (`verify_strict`), `Keystore`, and `subtle`. No new crypto primitive
is introduced.

### Replay mechanism: server-issued challenge nonce (NOT a self-signed time-boxed token)

We chose option (a), the **server-issued challenge**, over option (b), a self-signed
short-validity token. Justification:

- The threat model includes a **malicious relay operator**. A self-signed token
  (`DOMAIN || session_id || from_fp || not_before || not_after`) is **replayable within its
  validity window** by anyone who observes it — and the relay observes every byte. A captured
  token would let a malicious relay (or a network MITM) re-present the victim's proof on a new
  connection and impersonate it until the window closes. Shrinking the window trades availability
  (clock-skew rejects) against exposure and never reaches zero.
- The challenge nonce makes every proof bound to a **fresh, server-chosen, unpredictable** value,
  so a recorded proof is useless on any other connection. The replay window is **zero**.
- Cost: one extra round-trip (connect → `Challenge` → `Hello`) and an injected CSPRNG seam on the
  server (`ChallengeSource`, default `OsChallengeSource` over `getrandom`; tests inject a fixed
  source for determinism). Signaling is not latency-critical (one-time session setup), so the
  round-trip is acceptable. No server-side challenge *store* is needed: the challenge is held in
  the per-connection task and verified in the same task, so there is no cross-connection state and
  no DoS amplification from tracking outstanding challenges.

### Canonical signed-message (TBS) encoding

Mirrors the `BindCert` TBS style (ADR-0007/0014): a domain tag first (prevents cross-structure
signature confusion — a `BindCert` TBS can never be replayed as a peer-auth TBS and vice-versa),
fixed-width fields, exactly one valid encoding.

```text
TBS (97 bytes, signed):
  offset  size  field
   0      16    DOMAIN_TAG = b"SHP-SIG-PEERAUTH"
  16       1    TBS_VERSION = 0x01
  17      16    SESSION_ID         (16-byte signaling session id)
  33      32    DEVICE_PUBKEY      (Ed25519 compressed public key)
  65      32    CHALLENGE          (server-issued 32-byte nonce)
```

```text
IdentityProof (128 bytes, wire payload of Hello):
  offset  size  field
   0      32    DEVICE_PUBKEY
  32      32    CHALLENGE          (echo of the server challenge)
  64      64    SIGNATURE          (Ed25519 over the TBS above)
```

`SESSION_ID` is bound into the TBS so a proof for session A cannot be replayed into session B even
if (hypothetically) the same challenge recurred. `DEVICE_PUBKEY` is bound so the signature commits
to the exact key whose fingerprint is being claimed.

### The seam: typed, sanitized, still a trait

```rust
pub trait PeerAuthenticator: Send + Sync + 'static {
    fn authenticate(&self, ctx: &AuthContext<'_>) -> Result<(), AuthError>;
}

pub struct AuthContext<'a> {
    pub claimed_fp: &'a str,
    pub session_id: SessionId,
    pub challenge: &'a [u8; 32],
    pub proof: &'a [u8],   // hostile: the opaque Hello payload
}
```

`IdentityProofAuthenticator` is the production impl (possession check above). `AuthError`
(`thiserror`) carries a richer reason **for server-side logging/tests only**; every variant's
`Display` is the uniform `"authentication failed"`, and the server collapses all rejections to a
single sanitized `Error` envelope — **no enumeration oracle** (a probing peer cannot tell a
fingerprint mismatch from a bad signature from a stale challenge). The trait stays the injection
point so an allow-list / rate-limiter / token-issuer policy can wrap the possession check.

`AcceptAll` / `InsecureLanLab` and the `insecure-lan` release `compile_error!` fence are preserved
exactly (integration tests still use them; the fence still fails a `--release --features
insecure-lan` build).

### Auth ≠ trust (explicit boundary)

A passing server-side check proves the connecting peer **owns** the claimed fingerprint — it stops
fingerprint spoofing/impersonation/DoS *at the relay*. It does **not** establish end-to-end trust
between the two endpoints. Peer trust is established separately and independently by the endpoints
via the Noise handshake + `BindCert` + TOFU pairing (P3). This boundary is stated in the
`peer_auth` rustdoc, the `auth` rustdoc, and the server/README docs so no one over-reads it.

## Consequences

- Positive:
  - Closes R-SIG-AUTH in code: a peer can no longer register a fingerprint it does not control.
  - Zero replay window (challenge nonce) even against a malicious relay.
  - Zero-knowledge preserved: the server still routes on `(session_id, to_fp)` only; the proof
    rides in the opaque payload and the 149-byte routing header (ADR-0011) is unchanged. The
    authenticator sees only public data (pubkey, signature, fingerprint, challenge).
  - Self-hostable: no issuer, no shared secret — just the server's CSPRNG.
  - Crypto stays in `sh-crypto`, reusing `verify_strict` + `subtle`; fuzzed decoder
    (`peer_auth_decode`).
- Negative / trade-offs:
  - One extra round-trip per (re)connect (`Challenge` before `Hello`). Acceptable for one-time
    session setup.
  - `MessageKind::Challenge` (kind 7) and a 128-byte `Hello` payload are new wire surface;
    `connect()` (empty-proof, test path) no longer works against a real `IdentityProofAuthenticator`
    — production clients must use `connect_authenticated()`.
- Follow-ups / deferred:
  - **R-SIG-TLS** (live WSS/TLS) is unchanged and still deferred; this ADR does not address
    transport confidentiality of the signaling channel (TLS terminates at a reverse proxy).
  - **Allow-list / issuer policy** layered on top of possession proof is left as a future trait
    impl (the seam supports it; not needed for the core guarantee).
  - **Rate-limiting** auth failures per source is a deployment concern (not in this crate yet).

## Alternatives considered

- **Self-signed short-validity token (option b)** — single message, no round-trip, but replayable
  within its window by the (untrusted) relay. Rejected: the malicious-relay threat makes any
  non-zero replay window a real impersonation vector. See the Decision rationale.
- **HMAC token issued by the server / a TURN-style credential** — requires a pre-shared secret or
  an issuing service, breaking the self-hostable, no-issuer constraint. Rejected.
- **Bare-bool `authenticate(fp) -> bool`** (the P4-1 seam) — cannot carry the proof and cannot
  return a precise, testable, sanitized reason. Rejected; the seam is redesigned to take
  `AuthContext` and return `Result<(), AuthError>`.
- **Carrying the proof in a new typed top-level message instead of the Hello payload** — would
  either bloat the fixed 149-byte routing header or add another round-trip. Rejected: the opaque
  `Hello` payload already exists, is ignored by routing, and keeps the header untouched.
