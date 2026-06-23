# ADR 0012: Hand-rolled STUN codec vs. external STUN crate (sh-ice, P4-2)

- **Status:** Accepted
- **Date:** 2026-06-22
- **Deciders:** network-engineer, security-engineer, rust-staff-engineer

## Context

`sh-ice` (P4-2) requires a STUN codec (RFC 8489 subset) to implement ICE connectivity
checks.  Two approaches were evaluated:

1. **Hand-rolled codec** — a purpose-built `StunMessage` encode/decode in `stun.rs` covering
   exactly the attributes ICE needs: `XOR-MAPPED-ADDRESS`, `USERNAME`, `MESSAGE-INTEGRITY`,
   `FINGERPRINT`, `PRIORITY`, `USE-CANDIDATE`, `ICE-CONTROLLED`, `ICE-CONTROLLING`,
   `ERROR-CODE`, and `SOFTWARE`.
2. **External crate** — e.g. `stun` (0.5.x), `stun-rs` (0.1.x), `webrtc-stun` (0.5.x).

### Forces

- Security: STUN messages arrive from the network as **hostile bytes**.  Any decoder is in
  the highest-risk parsing zone (CLAUDE.md §7 "fuzz every parser").  An external crate
  adds transitive deps and third-party trust surface.
- Feature scope: we need only the ~11 attributes ICE uses.  Full RFC 8489 (TURN sub-protocol,
  ALTERNATE-SERVER, long-term credentials, etc.) is not required and adds dead code surface.
- Existing precedent: `sh-protocol` already hand-rolls its binary codec (SHP headers, input
  events) following the same bounds-checked pattern.  The team is fluent in that style.
- Auditability: a ~1 000-line hand-rolled codec is entirely readable in a single security
  review.  Third-party crates import their own review burden.
- `cargo audit`: new dependencies must pass the workspace audit gate; adding an unvetted STUN
  crate could introduce an advisory-flagged transitive dep.

## Decision

**Hand-roll the STUN codec** in `crates/sh-ice/src/stun.rs`, following the same
bounds-checked, never-panic pattern established in `sh-protocol`:

- Use `.get(start..end).ok_or(IceError::...)` throughout — zero indexing-slicing lints.
- HMAC-SHA1 via `hmac = "=0.12.1"` + `sha1 = "=0.10.6"` (exact-pinned, crypto policy).
- CRC32 via `crc32fast = "=1.4.2"` (exact-pinned, non-crypto; widely audited).
- `subtle::ConstantTimeEq` for HMAC comparison (timing-safe; already in the workspace).
- `base64 = "=0.22.1"` for TURN credential password encoding.
- Enforce attribute ordering invariants: `MESSAGE-INTEGRITY` must be last (or followed only
  by `FINGERPRINT`); `FINGERPRINT` must be last.  Unknown comprehension-required attributes
  surface as a typed error, not silent skip.
- Provide a `cargo-fuzz` target (`stun_decode.rs`) exercising all decode paths.

## Consequences

**Positive:**
- Zero new transitive STUN crate trust surface; codec is entirely auditable by the team.
- Feature-exact: only the attributes ICE needs are decoded; dead code is minimal.
- Consistent style with `sh-protocol`; security review requires reading one file.
- `cargo audit` stays clean (new deps are small, well-known crates: `hmac`, `sha1`,
  `crc32fast`, `base64`).

**Negative / trade-offs:**
- ~1 000 lines of codec to maintain when RFC 8489 errata are published.  Mitigation:
  the codec only covers the ICE subset; full TURN is deferred to P4-3 and may justify
  re-evaluating an external crate at that point.
- XOR-MAPPED-ADDRESS IPv6 XOR logic requires care.  Mitigated by a dedicated unit test
  and the fuzz target.

**Follow-ups:**
- P4-3 (coturn + live NAT): if a full TURN implementation is needed (Allocate, Refresh,
  CreatePermission, ChannelBind), reconsider whether adding a STUN/TURN crate is then
  justified.  ADR to be updated at that point.
- R-ICE-FUZZ: schedule a nightly fuzz job for the `stun_decode` target (CI fuzz-compile
  gate already added to X-2 in `IMPLEMENTATION_PLAN.md`).

## Alternatives considered

- **`stun` crate (0.5.x)** — requires `webrtc-util`, `tokio`, and several other
  `webrtc-rs` crates.  Heavyweight for a sync codec use-case; `webrtc-util` is not in
  the workspace audit baseline.
- **`stun-rs` (0.1.x)** — smaller, but still includes attributes and methods beyond the
  ICE subset; introduces a new trust surface for a relatively niche crate.
- **`webrtc-stun` (0.5.x)** — part of the `webrtc-rs` monorepo (P4-4 `str0m` path);
  pulled in by `str0m` for the WebRTC backend, not this native QUIC ICE path.
