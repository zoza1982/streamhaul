# Security Policy

Streamhaul grants full remote control of a machine. We take security reports extremely seriously.

## Reporting a vulnerability

**Do not open a public issue or PR for security vulnerabilities.**

Please report privately via GitHub's **[Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)**
(Security tab → "Report a vulnerability"). If that is unavailable, contact the maintainer directly
through their GitHub profile.

Include, where possible:
- A description of the issue and its impact.
- Steps to reproduce or a proof of concept.
- Affected component(s), version(s), and platform(s).

We aim to acknowledge reports within **72 hours** and to provide a remediation timeline after triage.
Please give us a reasonable window to fix and release before any public disclosure (coordinated
disclosure). We will credit reporters who wish to be named.

## Scope (high-value areas)

- Cryptography, key handling, device identity, and pairing (the zero-knowledge guarantee).
- Transport (QUIC/WebRTC), packet parsing, and any decoding of untrusted network input.
- Authentication, authorization, session consent, and the unattended-access path.
- Privilege boundaries on the host agent (input injection, capture, elevation).

## Our commitments

- Vetted crypto libraries only; no homegrown primitives.
- All network input treated as hostile; parsers are fuzzed.
- Signaling/relay infrastructure cannot decrypt session content.
- Signed releases and an SBOM for every release.

## Third-party crypto posture

### `snow` (Noise Protocol Framework)

| Property | Status |
|----------|--------|
| Version pinned | Yes — `snow = ">=0.9.5, <0.10"` (excludes RUSTSEC-2024-0011) |
| Known advisory | RUSTSEC-2024-0011 (unauthenticated nonce increment) — **patched in 0.9.5**, requirement excludes affected versions |
| Independent audit | **NOT YET** — pre-GA item (Risk Register: `R-SNOW-AUDIT`) |
| Wrapper isolation | Yes — never exposed outside `sh_crypto::noise` |
| Fuzzing | Yes — `crates/sh-crypto/fuzz/fuzz_targets/noise_handshake_read.rs` |

`snow` provides `Noise_XK_25519_ChaChaPoly_SHA256` and `Noise_IK_25519_ChaChaPoly_SHA256`
handshakes. It has not been independently audited as of P3-2. Mitigations:

- All `snow` types are wrapped behind `NoiseHandshake` / `NoiseSession`; raw snow types
  are never part of the public API.
- Any `snow` version upgrade requires a security review before merge.
- The fuzz target `noise_handshake_read` guards against panics in `snow`'s message parser.
- `BindCert` verification (6 ordered checks in `sh_crypto::bind_cert`) is independent of
  `snow` and guards against MITM key confusion even if `snow` had an internal bug.

A full third-party audit of `snow` is a **blocking requirement before production GA**.

### `spake2` (PAKE for unattended pairing, P3-3)

| Property | Status |
|----------|--------|
| Version pinned | Yes — `spake2 = "=0.4.0"` (exact-pinned per CLAUDE.md §7) |
| Known advisory | None in RustSec database as of P3-3 (`cargo audit` clean) |
| Independent audit | **NOT YET** — pre-GA item (Risk Register: `R-SPAKE2-AUDIT`) |
| Wrapper isolation | Yes — all `spake2` types are wrapped behind `PakeExchange`; raw `spake2` types never appear in the public API |
| Fuzzing | Yes — `crates/sh-crypto/fuzz/fuzz_targets/pake_msg_parse.rs` and `pairing_code_parse.rs` |
| curve25519-dalek | Unified with existing workspace `curve25519-dalek v4.1.3`; `cargo tree -i curve25519-dalek` confirms a **single version** |

`spake2` provides the SPAKE2 balanced PAKE (Abdalla–Pointcheval) over `Ed25519Group`
(Curve25519). It carries the disclaimer "USE AT YOUR OWN RISK" and has not been independently
audited. Mitigations:

- All `spake2` types are wrapped behind `PakeExchange`; no raw `spake2` API surface is public.
- An **explicit HKDF-SHA-256 key-confirmation MAC** is layered over the SPAKE2 output, binding
  the shared key to both device identities AND the Noise handshake hash `h` (ADR-0008 §2.3,
  open-risk #1). Even if `spake2`'s internal MAC has a bug, this explicit confirmation catches it.
- The two fuzz targets guard against panics in `spake2`'s wire parser and in our pairing-code
  parser for all possible byte inputs.
- Any `spake2` version upgrade requires a security review before merge.
- The `curve25519-dalek` dependency of `spake2` is the **same v4.1.3** already present via
  `ed25519-dalek` and `x25519-dalek` — no duplicate or conflicting curve library.

A full third-party audit of `spake2` is a **blocking requirement before production GA** for
the unattended pairing path. This is tracked as Risk Register item `R-SPAKE2-AUDIT`.

### `ed25519-dalek` and `x25519-dalek`

Both have been reviewed by the Dalek developers and are widely deployed. `verify_strict` is
used (not `verify`) to reject small-order keys and non-canonical signatures (ADR-0006).
Signing keys zeroize on drop via `ZeroizeOnDrop`.

### `str0m` (WebRTC sans-IO engine, P4-4)

| Property | Status |
|----------|--------|
| Version pinned | Yes — `str0m = "=0.20.0"` (exact-pinned per CLAUDE.md §7) |
| Known advisory | None in RustSec database as of P4-4 (`cargo audit` clean) |
| Independent audit | **NOT YET** — pre-GA item (Risk Register: `R-STR0M-AUDIT`) |
| Wrapper isolation | Yes — all str0m types are wrapped behind `WebRtcTransport`/`WebRtcChannel`; raw str0m types never appear in the public `sh-transport` API |
| Fuzzing | Deferred — a `webrtc_framing` fuzz target for STUN/DTLS/SCTP input is a pre-GA requirement (see R-STR0M-AUDIT) |
| Dependency reality | `str0m` pulls `aws-lc-rs` (via `dimpl`) AND a second `rcgen 0.14` transitively, alongside the existing `ring`/`rustls` tree. See ADR-0013 for the justified dependency posture. |
| Fingerprint verification | str0m's `fingerprint_verification` flag defaults to `true` and is NOT disabled anywhere in production code. The seam to set the remote fingerprint before DTLS is exposed via `WebRtcTransport::set_remote_dtls_fingerprint()` (P4-5 binding path). |

`str0m` parses DTLS, STUN, RTP, and SCTP bytes from hostile network input. Mitigations:

- All `str0m` types are wrapped behind `WebRtcTransport`/`WebRtcChannel`; no raw str0m API
  surface is public.
- Per-channel receive queues are capped at 512 frames (`MAX_RECV_QUEUE_DEPTH`) to prevent
  memory exhaustion from a flooding peer.
- `WebRtcTransport::set_remote_dtls_fingerprint()` exposes the certificate-pin seam that
  P4-5 will wire to the signed `BindCert` commitment, closing the DTLS MITM surface.
- Any `str0m` version upgrade requires a security review before merge.

A full third-party audit of `str0m` (DTLS, STUN, SCTP, ICE parsers) is a **blocking
requirement before production GA**. This is tracked as Risk Register item `R-STR0M-AUDIT`.

### `rustls` / `quinn`

Used for the QUIC transport. `rustls` has been audited by Cure53. The TLS exporter label
`"shp noise binding"` channel-binds the Noise handshake prologue to the specific QUIC
connection (ADR-0007 §1.4), preventing message-lifting attacks.
