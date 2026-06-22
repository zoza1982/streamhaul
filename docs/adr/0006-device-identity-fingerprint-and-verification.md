# ADR 0006: Device Identity, Fingerprint Design, and Ed25519 Verification Policy

- **Status:** Accepted
- **Date:** 2026-06-22
- **Deciders:** rust-staff-engineer, security-engineer, code-reviewer

## Context

Streamhaul requires a stable, cryptographically verifiable device identity that:

1. Is created once per device and remains stable across reconnects.
2. Can be exchanged in-band during the Noise handshake (P3-2) and committed to a `BindCert`
   (P4-5) without exposing signing key material.
3. Is pinnable in a TOFU trust store (P3-3) and revocable by the operator.
4. Has a human-verifiable short form for SAS-style attended pairing.
5. Appears in audit receipts and anti-replay structures where signature uniqueness is assumed.

Three design choices required explicit decisions:

- **Which asymmetric primitive** — Ed25519 or an alternative (P-256, X25519+Signature, etc.).
- **What the `device_id` / fingerprint** is (wire-stable; used as a routing key by the relay).
- **Which Ed25519 verification mode** — cofactored (`verify`) vs. strict (`verify_strict`).

The TOFU trust store also needed a structural decision about how to represent trust vs. revocation
to avoid a latent invariant bug.

## Decision

### 1. Primitive: Ed25519 (RFC 8032)

We use Ed25519 via `ed25519-dalek` 2.x (backed by `curve25519-dalek`).

Rationale:
- Already in the dependency tree (`snow`/Noise uses it for `Noise_XK`).
- Compact 32-byte public keys and 64-byte signatures; no parameter choices.
- Hardware-accelerated on all target platforms via the `fast` feature.
- `ZeroizeOnDrop` via the `zeroize` feature clears the signing key scalar on drop.
- The signing key is `Box`ed so the 32-byte secret scalar lives at a single, stable heap
  address, reducing scatter across stack frames and crash dumps.

### 2. Fingerprint: SHA-256(compressed public key), lowercase hex, 64 characters

```
fingerprint = SHA-256(public_key_bytes[32]) as lowercase hex (64 chars)
short_form  = fingerprint[..16]  (display-only; 64 bits of entropy)
```

Rationale:
- SHA-256 is well-understood, hardware-accelerated, and already in the tree via `sha2`.
- Hex is unambiguous, copy-pasteable, and widely understood. Base32/Base58 would shorten
  display strings but add a dependency and a decoding layer.
- 256 bits is ample collision resistance for the TOFU pinning use case.
- The short form (16 hex chars = 64 bits) is sufficient for human comparison but NOT for
  automated identity checks. All programmatic comparisons use the full fingerprint.
- The fingerprint is the **wire-stable `device_id`** used by the relay routing layer.

### 3. Verification mode: `verify_strict` (not `verify`)

`Signature::verify` calls `VerifyingKey::verify_strict` rather than `VerifyingKey::verify`.

`verify_strict` additionally rejects:
- **Small-order public keys** (torsion subgroup, cofactor 8 on Ed25519). A small-order key
  lies in a subgroup of order 1, 2, 4, or 8 rather than the prime-order subgroup, allowing
  an attacker to construct signatures that satisfy the cofactored batch equation.
- **Non-canonical `R` components** in the signature itself (the `R` point must also not be
  small-order).

This is mandatory for a device-identity TRUST ROOT: signature uniqueness is assumed by
`BindCert`, anti-replay structures, and audit receipts. Accepting small-order keys or
malleable signatures would break those assumptions.

### 4. Defense-in-depth: small-order key rejection at identity construction

`DeviceIdentity::from_public_key_bytes` calls `VerifyingKey::is_weak()` (available in
`ed25519-dalek` 2.x) after decompression, and returns `CryptoError::MalformedKey` if the
key is a small-order point. This means:

- A small-order key can never be pinned in the trust store.
- A small-order key can never appear in a `BindCert` or audit log.
- The `verify_strict` check at verification time is a second, independent layer.

### 5. Trust store: single `HashMap<String, TrustState>` (not two `HashSet`s)

The trust state for each peer fingerprint is held in one `HashMap<String, TrustState>` where
`TrustState` is either `Trusted` or `Revoked`. This makes the "trusted AND revoked" state
structurally unrepresentable — a fingerprint maps to exactly one state at a time.

A missing entry means "never seen" (untrusted, not explicitly revoked).

### 6. Re-trust after revocation (SoftwareKeystore)

`SoftwareKeystore` **permits** re-trust after revocation: calling `trust_peer` on a previously
revoked identity moves it back to `Trusted`. This supports the factory-reset / re-pair scenario.

Production / hardware keystores SHOULD make revocation sticky. See item R-HW-KS in
`IMPLEMENTATION_PLAN.md`: once revoked, re-establishing trust must require a distinct,
explicitly operator-confirmed action. The P3-3 pairing layer must surface any implicit
re-trust-after-revoke to the operator.

## Consequences

- **Positive:**
  - Signature-uniqueness invariants are satisfied upstream of every consumer.
  - Small-order public keys are rejected at two independent checkpoints.
  - The trust store has no latent "simultaneously trusted and revoked" bug.
  - `+ 'static` on the `Keystore` trait allows `Arc<dyn Keystore>` across task boundaries.
  - The fingerprint is wire-stable and relay-routable.
  - Proptest + negative tests cover all critical paths.

- **Negative / trade-offs:**
  - `verify_strict` is slightly stricter than the RFC 8032 default batch-verification mode;
    any Ed25519 implementation that produces small-order `R` values would be rejected. This is
    acceptable — conformant implementations do not produce such values.
  - Re-trust after revocation in `SoftwareKeystore` is intentionally lenient. Operators using
    the software store must understand that `trust_peer` on a revoked identity re-admits it
    without additional ceremony.

- **Follow-ups:**
  - P3-2: Noise tunnel wires `DeviceIdentity` into the `Noise_XK` handshake.
  - P3-3: TOFU pairing and SAS comparison use `Fingerprint::short()` for display.
  - P4-5: `BindCert` commits the `DeviceIdentity` fingerprint; consumers depend on
    `verify_strict` for signature uniqueness.
  - P3+ (GA): Hardware keystore backends must enforce sticky revocation (R-HW-KS).

## Alternatives considered

- **`verify` (cofactored) instead of `verify_strict`** — Rejected. Accepts small-order keys
  and malleable signatures. Breaks signature-uniqueness assumptions relied on by BindCert and
  anti-replay structures. The cost of `verify_strict` is negligible.

- **Two `HashSet`s for trust/revoke** — Rejected. The "in both sets" state is representable
  and would need a defensive double-check that can silently mask bugs. A single `HashMap` with
  a typed `TrustState` enum eliminates the ambiguity at the type level.

- **P-256 instead of Ed25519** — Not considered for P3-1. P-256 requires parameter validation
  per key use, is not in the `snow` Noise handshake dependency chain, and has no `ZeroizeOnDrop`
  equivalent in the current tree. Ed25519 is preferred for all new signing use cases.

- **Base58 fingerprint** — Shorter display but adds a dependency and makes copy-paste
  comparison harder. Hex is sufficient and universally understood.
