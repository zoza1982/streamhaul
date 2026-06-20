# ADR 0005: Unattended access custody and session-recording key model

- **Status:** Accepted
- **Date:** 2026-06-19
- **Deciders:** security-engineer (LLD phase)
- **Resolves:** PRD §9 open question Q5

## Context

Unattended access (no human at the host to approve) and session recording are the two features most likely
to turn into a standing skeleton key or a plaintext honeypot. The product invariant is a **zero-knowledge
relay**: hosted infrastructure must never hold anything that decrypts session or recording content, and
unattended access must remain revocable even when the host is offline at revocation time.

## Decision

**Unattended = hardware-bound Unattended Grant Certificate (UGC).** The host's TPM/SE/StrongBox identity key
signs a UGC delegating *scoped* access to a *specific controller device_id*, gated by **WebAuthn/FIDO2 at
enrollment, not per-connect**. The UGC is inert without the controller's non-exportable hardware key (connect
requires a live `Noise_IK` as `grantee_id`). Revocation uses a **host-local monotonic `min_epoch`** floor
(kills sub-epoch grants with zero network), backed by bounded UGC lifetime (≤30d) and idle expiry. Off by
default; view-only default caps.

**Session recording = hybrid envelope encryption.** A per-recording AES-256-GCM DEK (chunk-ratcheted via
HKDF) is wrapped (HPKE, RFC 9180) to a recipient set `{operator device, customer-KMS escrow KEK, optionally
host}`. **Hosted infra is never a recipient.** The escrow KEK lives in the *customer's* KMS/HSM under their
IAM (optional M-of-N quorum), enabling e-discovery without Streamhaul ever seeing plaintext.

## Consequences

- Positive: no central granting secret or recording key; offline-survivable revocation; e-discovery without
  plaintext exposure; survives host loss via escrow.
- Negative: requires hardware keystores and WebAuthn enrollment UX; key-management surface is non-trivial.
- Follow-ups: normalize platform-attestation envelope; UGC lifetime per compliance tier; escrow quorum schema;
  standardize on SHA-256 for the Noise hash so SAS and `BindCert` share one primitive.

## Alternatives considered

- **Server-held connect token** — rejected: makes infra a fleet skeleton key.
- **Controller-stored host secret** — rejected: controller compromise = permanent, host-unrevocable access.
- **Single org KMS key for recordings** — rejected as sole model (single point of total compromise, no host
  re-access); retained only as one envelope recipient.
- **Push-CRL revocation** — rejected: fails open for offline hosts; replaced by stapled allow-lists + epoch floor.
