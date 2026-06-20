# ADR 0003: Transport finalization — WebRTC-first, native QUIC fast-follow

- **Status:** Accepted
- **Date:** 2026-06-19
- **Deciders:** software-architect, network-engineer (LLD phase)
- **Resolves:** PRD §9 open question Q1

## Context

The PRD locked a dual-path transport (QUIC for native, WebRTC for browser) but left the sequencing open.
Browser support mandates WebRTC regardless; native QUIC adds connection migration, unreliable datagrams,
and lower handshake RTT. Building both stacks at once doubles peak integration and interop-test risk
(two crypto stacks: DTLS-SRTP and QUIC-TLS+Noise).

## Decision

Ship **WebRTC-first for v1.0** (browser + native + mobile, P2P + relay) and **promote native↔native
sessions to QUIC in v1.1**, both hidden behind one `Transport` trait. The **Phase-0 latency lab uses bare
`quinn`** (no ICE/crypto) purely to validate the codec/render budget. `sh-ice` is shared by both paths;
the congestion controller (GCC vs SCReAM) is selected by the transport backend, invisible to `sh-core`.
Peers negotiate `transports: [quic, webrtc]` at signaling.

## Consequences

- Positive: browser reach from day one; lower peak complexity; relay/ICE stabilized once then reused.
- Negative: a dual crypto/transport stack still exists by v1.1, with the attendant test matrix.
- Follow-ups: validate `str0m` Safari interop in Phase 4/5; confirm QUIC promotion negotiation.

## Alternatives considered

- **WebRTC-only forever** — simplest, but cedes native latency/migration wins central to the gaming pitch.
- **QUIC-first** — best native story but delays the mandatory browser path and the relay/NAT learning.
