# Streamhaul

> Your whole desktop, hauled anywhere — without the lag.

Streamhaul is a next-generation remote desktop, low-latency desktop video streaming, and
remote-management platform — *"VNC, but radically more advanced."* It streams a remote desktop with
cloud-gaming-grade latency (you can actually play games on it), supports full remote control, file
transfer, and remote management, and runs peer-to-peer over the public internet with a relay fallback.

A single adaptive pipeline auto-tunes between **Game Mode** (sub-frame latency, GPU encode) and
**Work Mode** (crisp text, accurate color, multi-monitor) based on content and network conditions.

**Business model:** open-core — open-source protocol + clients; paid hosted global relay and
enterprise control plane.

## Status

Early definition. This repo currently holds the high-level product requirements and the engineering
pipeline. Low-Level Design (LLD) is the next milestone.

- [`PRD.md`](./PRD.md) — High-level PRD (architecture, transport/protocol, video pipeline, security, scope).
- [`LLD.md`](./LLD.md) — Low-Level Design: crate layout, trait seams, SHP wire format, crypto, build plan;
  resolves the PRD's 8 open questions.
- [`docs/adr/`](./docs/adr/) — Architecture Decision Records (0001–0005).

## Development

This project enforces a strict quality bar (it ships a remote-control product). Before contributing,
read the rules — they apply to humans and AI alike.

- [`CLAUDE.md`](./CLAUDE.md) — **authoritative engineering rulebook**: the quality gate (test →
  `bug-bot` → `code-reviewer` → fix → only then push), testing/security/docs standards, agent map.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — branching, Conventional Commits, PR workflow.
- [`SECURITY.md`](./SECURITY.md) — private vulnerability disclosure.

**Pipeline:** `main` is protected — every change lands via a feature branch + PR with green CI
(`pr-title`, `lint`, `test` on Linux/Windows/macOS, `audit`) and a passing Definition of Done.

## Key technical decisions (at a glance)

| Area | Choice |
|------|--------|
| Core language | Rust (shared core) + per-OS shims |
| Protocol | Streamhaul Protocol (SHP) |
| Browser transport | WebRTC (SRTP + SCTP / DTLS 1.3) |
| Native transport | QUIC (RFC 9000) + Datagrams (RFC 9221), TLS 1.3 |
| Codec | H.265/HEVC primary, H.264 browser fallback, AV1 roadmap |
| NAT traversal | ICE/STUN + coturn (TURN) relay fallback |
| Security | E2E zero-knowledge relay; Ed25519 device identity pinned at pairing |
