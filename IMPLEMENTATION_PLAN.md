# Streamhaul — Implementation Plan & Tracker

**This is the living tracking document for building Streamhaul.** It decomposes the design in
[`LLD.md`](./LLD.md) into PR-sized tasks across the 8 build phases. Update it in the **same PR** that
completes a task (one task ≈ one PR). It is the source of truth for "what's done, what's next."

- **Design:** [`LLD.md`](./LLD.md) · **Product:** [`PRD.md`](./PRD.md) · **Rules:** [`CLAUDE.md`](./CLAUDE.md)
- **Every task** follows the CLAUDE.md quality gate: implement → tests → **`bug-bot`** → **`code-reviewer`**
  (→ `security-engineer` if it touches crypto/auth/transport) → fix → PR → green CI → merge. No exceptions.

## Status legend
`☐` Todo · `🟡` In progress · `✅` Done · `⛔` Blocked · `🔬` In review/gate

## How to use
1. Pick the next unblocked task whose dependencies are `✅`.
2. Branch `‹type›/‹task-id›-slug` (e.g. `feat/P0-3-shp-video-header`).
3. Implement to the task's **Exit criteria** + **Tests**; run the quality gate.
4. In the PR, flip the task to `✅` and fill the **PR** column. Update the phase gate when all its tasks pass.

---

## Milestone Overview

| Phase | Theme | Gate (exit) | Status |
|-------|-------|-------------|:------:|
| **P0** | Hello Pixels (latency lab) | Live Win→native render, ≤~30ms glass-to-glass LAN @60fps, zero-copy DXGI→NVENC, 10-min stable | ☐ |
| **P1** | Input + multi-channel + audio | Click-to-photon measured; audio AV-synced; input never starved by video | ☐ |
| **P2** | Adaptivity (Game/Work) | Smooth adapt under loss/bandwidth caps; mode switch no flapping; loss recovery works | ☐ |
| **P3** | Security & pairing | First-pair TOFU pins key; unpinned MITM rejected; all channels E2E; rotation tested | ☐ |
| **P4** | Connectivity (WebRTC+relay) | Connects across symmetric NAT via relay; relay carries only opaque ciphertext | ☐ |
| **P5** | Browser client | Chrome/FF/Safari view+control via H.264; same signaling/relay path | ☐ |
| **P6** | Cross-OS hosts | macOS + Linux hosts zero-copy capture→encode; host↔client matrix green | ☐ |
| **P7** | File transfer | Large transfer doesn't degrade video QoE; resumable; integrity-verified | ☐ |
| **P8** | QUIC promotion + mobile | Native↔native auto-selects QUIC, survives network change; mobile thin clients | ☐ |

**Progress:** 0 / 41 tasks complete.

---

## Cross-Cutting Workstreams (run continuously, not a phase)

| ID | Workstream | Notes | Agent | Status |
|----|-----------|-------|-------|:------:|
| X-1 | **CI activation** | `lint`/`test`/`audit` jobs go live automatically once `Cargo.toml` exists (done in P0-1). Add coverage gate (`cargo-llvm-cov` ≥80% on `sh-protocol`/`sh-crypto`/`sh-transport`). | devops-engineer | ☐ |
| X-2 | **Testing infra** | `LoopbackTransport`, injected `Clock`+seedable RNG, `proptest`, `cargo-fuzz` targets, `loom` for lock-free queues. Build incrementally with each crate. | qa-engineer, rust-staff-engineer | ☐ |
| X-3 | **Security review cadence** | `security-engineer` reviews **every** crypto/auth/transport PR; `cargo audit` clean; document `snow` unaudited status. | security-engineer | ☐ |
| X-4 | **Release engineering** | `xtask` for packaging/signing; signed releases (Sigstore/cosign), SBOM (CycloneDX), per-OS installers/services. | devops-engineer | ☐ |
| X-5 | **Open decisions** | Resolve LLD §9 items before they block: Noise pattern names (SHA-256, before P3), platform-attestation envelope, UGC lifetime per compliance tier, `str0m` Safari interop (before P4/5). | software-architect, security-engineer | ☐ |

---

## Phase 0 — Hello Pixels (latency lab)

> Goal: prove the latency budget on the thinnest vertical slice. Windows host → native client, LAN, H.264,
> **bare `quinn` QUIC (no ICE/crypto)**, no adaptivity. Validates codec/render pipeline in isolation.

| ID | Task | Crates | Depends | Agent | Tests | Status | PR |
|----|------|--------|---------|-------|-------|:------:|----|
| P0-1 | Cargo workspace scaffold + workspace lints (panic-ban) + activate CI | (all skeleton) | — | rust-staff-engineer | crates compile; clippy `-D warnings` clean; CI goes live | ☐ | |
| P0-2 | `sh-types`: IDs, units, `FrameId`/`Timestamp`/`ChannelId`, error scaffolding | sh-types | P0-1 | rust-staff-engineer | unit | ☐ | |
| P0-3 | `sh-protocol`: common header + video payload header (per LLD §3.1), encode/decode | sh-protocol | P0-2 | rust-staff-engineer, network-engineer | **proptest** (never-panic + roundtrip) + **cargo-fuzz** target | ☐ | |
| P0-4 | `sh-transport`: bare `quinn` backend (LAN, datagrams), no ICE/crypto | sh-transport | P0-2 | network-engineer | loopback integration | ☐ | |
| P0-5 | `sh-media`: `ScreenCapturer`/`VideoEncoder`/`VideoDecoder` traits + frame/surface types | sh-media | P0-2 | realtime-systems-engineer | trait doubles | ☐ | |
| P0-6 | `sh-platform-win`: DXGI Desktop Duplication capture (zero-copy D3D11 surface) | sh-platform-win | P0-5 | realtime-systems-engineer | manual + smoke | ☐ | |
| P0-7 | `sh-codec-hw`: NVENC H.264 encode + HW decode; zero-copy surface registration | sh-codec-hw | P0-5, P0-6 | realtime-systems-engineer | encode/decode roundtrip | ☐ | |
| P0-8 | `sh-render`: `wgpu` NV12→RGB present + frame pacing + latency overlay | sh-render | P0-5 | ui-engineer, realtime-systems-engineer | manual | ☐ | |
| P0-9 | Wire `streamhaul-host` + `streamhaul-client` end-to-end (capture→encode→QUIC→decode→render) | bins | P0-3,4,7,8 | rust-staff-engineer | e2e smoke | ☐ | |
| P0-10 | Latency harness; measure & validate **≤~30ms LAN @60fps**; confirm zero-copy; 10-min soak | host/client | P0-9 | performance-tuning-engineer | latency bench; soak | ☐ | |

**Gate P0:** ☐ live render · ☐ ≤~30ms glass-to-glass LAN · ☐ zero-copy DXGI→NVENC confirmed · ☐ 10-min stable.

---

## Phase 1 — Input + multi-channel + audio

| ID | Task | Crates | Depends | Agent | Tests | Status | PR |
|----|------|--------|---------|-------|-------|:------:|----|
| P1-1 | Promote `Transport`/`Channel` trait + `ChannelSpec`; multi-channel (video unreliable + input reliable, **input urgency 0**) | sh-transport | P0 | network-engineer, rust-staff-engineer | loopback multi-channel | ☐ | |
| P1-2 | `sh-protocol`: input event message (LLD §3.1) + control/RPC framing | sh-protocol | P0-3 | network-engineer | proptest + fuzz | ☐ | |
| P1-3 | `sh-platform-win`: `InputInjector` (SendInput/Raw Input), normalized coord mapping, multi-monitor | sh-platform-win | P1-1,P1-2 | realtime-systems-engineer | injection smoke | ☐ | |
| P1-4 | Audio: WASAPI loopback capture + Opus encode/decode + AV sync (shared monotonic clock) | sh-media, sh-codec-hw | P0 | realtime-systems-engineer | sync test | ☐ | |
| P1-5 | Channel prioritization (input > video) + file-channel congestion-isolation scaffolding | sh-transport | P1-1 | network-engineer | starvation test under load | ☐ | |

**Gate P1:** ☐ click-to-photon measured · ☐ audio AV-synced (±20ms) · ☐ input not starved under video load.

---

## Phase 2 — Adaptivity (Game/Work modes)

| ID | Task | Crates | Depends | Agent | Tests | Status | PR |
|----|------|--------|---------|-------|-------|:------:|----|
| P2-1 | `sh-adaptive`: `CongestionController` trait + **SCReAM** (native path) | sh-adaptive | P1 | network-engineer | sim: adapt to bandwidth caps | ☐ | |
| P2-2 | Rate allocator across channels (video/audio/file budgets) | sh-adaptive | P2-1 | network-engineer | allocation unit | ☐ | |
| P2-3 | Content classifier (4-signal heuristic + hysteresis FSM, LLD §5.2) | sh-adaptive | P1 | realtime-systems-engineer | FSM unit (no flapping) | ☐ | |
| P2-4 | Encoder reconfigure + **double-buffered mode switch** (4:2:0↔4:4:4, glitch-free) | sh-codec-hw | P2-3 | realtime-systems-engineer | switch test; NVENC session-limit guard | ☐ | |
| P2-5 | HEVC enable (commercial build feature flag) + codec negotiation/degradation ladder (ADR-0004) | sh-codec-hw, sh-protocol | P0-7 | realtime-systems-engineer | negotiation matrix | ☐ | |
| P2-6 | Loss recovery: rolling intra-refresh + adaptive FEC + selective NACK + forced IDR (LLD §4.4) | sh-adaptive, sh-protocol | P2-1 | network-engineer, realtime-systems-engineer | induced-loss recovery test | ☐ | |

**Gate P2:** ☐ smooth adapt under loss/caps · ☐ Game↔Work no flapping · ☐ keyframe/loss recovery verified.

---

## Phase 3 — Security & pairing (E2E)

> **Security applies from here on** (LLD §6). Every task in P3+ touching crypto requires `security-engineer` review.

| ID | Task | Crates | Depends | Agent | Tests | Status | PR |
|----|------|--------|---------|-------|-------|:------:|----|
| P3-1 | `sh-crypto`: Ed25519 device identity + `Keystore` trait + platform keystores (TPM/Keychain/DPAPI) | sh-crypto | P0 | security-engineer, rust-staff-engineer | unit + keystore mocks | ☐ | |
| P3-2 | Noise tunnel (`snow`, `Noise_XK` pair / `Noise_IK` connect) + identity-bound `BindCert` | sh-crypto, sh-transport | P3-1 | security-engineer | handshake unit + **fuzz** | ☐ | |
| P3-3 | TOFU pinning + SAS (from Noise hash) + PAKE pairing codes (SPAKE2/OPAQUE) | sh-crypto | P3-2 | security-engineer | MITM-rejection test | ☐ | |
| P3-4 | Channel encryption + key hierarchy + rotation (PFS ephemerals, rekey, channel subkeys) | sh-crypto, sh-transport | P3-2 | security-engineer | rotation test; negative tests | ☐ | |
| P3-5 | Authorization (capability mask, host-enforced, non-escalatable) + kill-switch (RAM key zeroize) | sh-core | P3-4 | security-engineer | cap-guard + kill-switch test | ☐ | |

**Gate P3:** ☐ TOFU pins on first pair · ☐ unpinned-key MITM rejected · ☐ all channels E2E · ☐ rotation + kill-switch verified.

---

## Phase 4 — Connectivity (WebRTC + signaling + relay)

| ID | Task | Crates | Depends | Agent | Tests | Status | PR |
|----|------|--------|---------|-------|-------|:------:|----|
| P4-1 | `sh-signaling`: client + self-hostable signaling server (WSS, SDP/ICE exchange, trickle) | sh-signaling | P3 | network-engineer | signaling integration | ☐ | |
| P4-2 | `sh-ice`: ICE/STUN candidate gathering, connectivity checks, P2P-vs-relay nomination | sh-ice | P4-1 | network-engineer | NAT-sim matrix | ☐ | |
| P4-3 | coturn deploy + short-lived HMAC TURN creds + **latency-probe relay steering** (LLD §4.3) | sh-ice, infra | P4-2 | network-engineer, devops-engineer | relay-fallback test | ☐ | |
| P4-4 | `sh-transport`: WebRTC backend (`str0m`) + **GCC** congestion control | sh-transport | P4-1 | network-engineer | webrtc loopback | ☐ | |
| P4-5 | Bind DTLS fingerprint to device identity via signed `BindCert` (kills signaling MITM, LLD §6.2) | sh-crypto, sh-transport | P3-2,P4-4 | security-engineer | fingerprint-swap rejection | ☐ | |
| P4-6 | Transport capability negotiation (`transports:[quic,webrtc]`) + relay fallback path | sh-transport, sh-signaling | P4-4 | network-engineer | negotiation + fallback | ☐ | |

**Gate P4:** ☐ connects across symmetric NAT via relay · ☐ P2P when possible · ☐ relay carries only opaque ciphertext (zero-knowledge verified).

---

## Phase 5 — Browser client

| ID | Task | Crates | Depends | Agent | Tests | Status | PR |
|----|------|--------|---------|-------|-------|:------:|----|
| P5-1 | `sh-protocol` → WASM (wire parity) + browser client over native `RTCPeerConnection` (`web-sys`) | sh-wasm | P4 | ui-engineer, network-engineer | browser e2e | ☐ | |
| P5-2 | Browser viewer/control UI + H.264 codec negotiation + input capture | sh-wasm (TS app) | P5-1 | ui-engineer, ux-engineer | Chrome/FF/Safari matrix | ☐ | |

**Gate P5:** ☐ Chrome/Firefox/Safari view + control · ☐ H.264 negotiated for browser · ☐ same relay path as native.

---

## Phase 6 — Cross-OS hosts

| ID | Task | Crates | Depends | Agent | Tests | Status | PR |
|----|------|--------|---------|-------|-------|:------:|----|
| P6-1 | `sh-platform-mac`: ScreenCaptureKit capture + VideoToolbox + CGEvent inject + Core Audio; permission flows | sh-platform-mac | P2 | mobile-engineer, realtime-systems-engineer | macOS capture/inject smoke | ☐ | |
| P6-2 | `sh-platform-linux`: PipeWire/DRM capture + VA-API + `uinput` inject + PipeWire audio; Wayland+X11 | sh-platform-linux | P2 | realtime-systems-engineer | Linux capture/inject smoke | ☐ | |
| P6-3 | Cross-OS host↔client interop matrix (all 3 hosts × all clients) | CI | P6-1,P6-2 | qa-engineer | matrix CI job | ☐ | |

**Gate P6:** ☐ all 3 OSes zero-copy capture→encode · ☐ permission flows handled · ☐ host↔client matrix green.

---

## Phase 7 — File transfer (congestion-isolated)

| ID | Task | Crates | Depends | Agent | Tests | Status | PR |
|----|------|--------|---------|-------|-------|:------:|----|
| P7-1 | File-transfer channel (own QUIC stream / WebRTC DC, congestion-isolated) + protocol framing | sh-protocol, sh-transport | P2,P4 | network-engineer | QoE-under-transfer test | ☐ | |
| P7-2 | Resumable transfer + integrity (hash) + client UI | sh-core, clients | P7-1 | rust-staff-engineer, ui-engineer | resume + integrity test | ☐ | |

**Gate P7:** ☐ large transfer doesn't degrade video QoE · ☐ resumable · ☐ integrity-verified.

---

## Phase 8 — Native QUIC promotion + mobile

| ID | Task | Crates | Depends | Agent | Tests | Status | PR |
|----|------|--------|---------|-------|-------|:------:|----|
| P8-1 | QUIC+ICE wiring; native↔native auto-selects QUIC; **connection migration** (Wi-Fi↔cellular) | sh-transport, sh-ice | P4 | network-engineer | migration test | ☐ | |
| P8-2 | `sh-ffi` (UniFFI) thin clients for iOS/Android (view + touch→pointer/gamepad) | sh-ffi | P4 | mobile-engineer | device smoke | ☐ | |

**Gate P8:** ☐ native peers auto-select QUIC · ☐ survives network change · ☐ mobile thin clients view+control (WebRTC fallback intact).

---

## Definition of Done (every task PR — mirrors CLAUDE.md §10)

- [ ] Branch + PR title follow Conventional Commits; scope is one task
- [ ] Tests written/updated; full suite green on Linux/Windows/macOS in CI
- [ ] `cargo fmt` + `cargo clippy --all-targets --all-features -- -D warnings` clean
- [ ] **`bug-bot` run on the diff — all confirmed issues fixed**
- [ ] **`code-reviewer` run on the diff — all findings addressed**
- [ ] Crypto/auth/transport? → `security-engineer` reviewed; `cargo audit` clean
- [ ] Public APIs documented (rustdoc); ADR added/updated if a decision was made
- [ ] No `unwrap/expect/panic` in production paths; no new `unsafe` without `// SAFETY:`
- [ ] Coverage not reduced; **this tracker updated** (task → `✅`, PR linked, gate updated)

---

## Risk Register / Open Decisions (from LLD §9 — resolve before they block)

| # | Item | Blocks | Owner |
|---|------|:------:|-------|
| R1 | Pin concrete Noise pattern names (SHA-256 hash per ADR-0005) | P3 | security-engineer |
| R2 | Normalize platform-attestation envelope (TPM quote / App Attest / Play Integrity) | P3/P8 | security-engineer |
| R3 | UGC max lifetime per compliance tier (HIPAA/PCI ≤7d) + escrow quorum schema | P3 | security-engineer |
| R4 | `snow` is unaudited — schedule a crypto review before GA | GA | security-engineer |
| R5 | `str0m` ↔ Safari WebRTC interop validation | P4/P5 | network-engineer |
| R6 | NVENC consumer session-limit behavior during double-buffer overlap | P2 | realtime-systems-engineer |
| R7 | Multi-GPU cross-adapter copy budget on target laptop SKUs | P0/P2 | realtime-systems-engineer |

---

*Update this document in the PR that changes status. It is the canonical answer to "where are we?"*
