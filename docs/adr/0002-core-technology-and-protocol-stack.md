# ADR 0002: Core technology and protocol stack

- **Status:** Accepted
- **Date:** 2026-06-19
- **Deciders:** software-architect, network-engineer, realtime-systems-engineer, security-engineer (PRD phase)

## Context

We need a baseline, cross-platform, low-latency stack that supports gaming-grade streaming and crisp
remote work, runs P2P over the internet with relay fallback, and is browser-compatible. Full rationale
is in [`PRD.md`](../../PRD.md). This ADR records the load-bearing choices so they are binding until
explicitly superseded.

## Decision

- **Language:** Rust shared core + thin per-OS shims (capture/encode/input).
- **Protocol:** Streamhaul Protocol (SHP), codec-agnostic, over QUIC (native) and SRTP+SCTP (browser).
- **Transport:** QUIC (RFC 9000) + Datagrams (RFC 9221) for native peers; WebRTC for browser peers.
- **Congestion control:** GCC on the WebRTC path; SCReAM (RFC 8298) on the native path. BBR is rejected for media.
- **Codec ladder:** H.265/HEVC primary, H.264 browser fallback, AV1 as a hardware-gated roadmap upgrade.
- **NAT traversal:** ICE/STUN with self-hostable coturn (TURN) relay fallback.
- **Security:** end-to-end encryption with Ed25519 device identity pinned at pairing; zero-knowledge relay.
- **Business model:** open-core (Apache-2.0 protocol + clients; paid hosted relay + enterprise control plane).

## Consequences

- Positive: best-in-class native latency plus universal browser reach; openness builds trust.
- Negative: dual transport + dual crypto stack (QUIC/Noise and DTLS/SRTP) increases surface area and test burden.
- Follow-ups: resolve the open questions in `PRD.md` §9 during LLD (notably WebRTC-only vs QUIC-upgrade, and the OSS codec/licensing default).

## Alternatives considered

- **WebRTC-only everywhere** — simpler, one stack, but cedes native latency/connection-migration wins.
- **Raw UDP custom transport** — marginal latency gain not worth reimplementing congestion control, 0-RTT, and migration.
- **VP9 / H.264-only** — VP9 lacks a viable host HW encode path; H.264-only leaves bandwidth/quality on the table vs HEVC/AV1.
