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
| **P0** | Hello Pixels (latency lab) | Live Win→native render, ≤~30ms glass-to-glass LAN @60fps, zero-copy DXGI→NVENC, 10-min stable | 🟡 |
| **P1** | Input + multi-channel + audio | Click-to-photon measured; audio AV-synced; input never starved by video | 🟡 |
| **P2** | Adaptivity (Game/Work) | Smooth adapt under loss/bandwidth caps; mode switch no flapping; loss recovery works | 🟡 |
| **P3** | Security & pairing | First-pair TOFU pins key; unpinned MITM rejected; all channels E2E; rotation tested | 🟡 |
| **P4** | Connectivity (WebRTC+relay) | Connects across symmetric NAT via relay; relay carries only opaque ciphertext | ☐ |
| **P5** | Browser client | Chrome/FF/Safari view+control via H.264; same signaling/relay path | ☐ |
| **P6** | Cross-OS hosts | macOS + Linux hosts zero-copy capture→encode; host↔client matrix green | ☐ |
| **P7** | File transfer | Large transfer doesn't degrade video QoE; resumable; integrity-verified | ☐ |
| **P8** | QUIC promotion + mobile | Native↔native auto-selects QUIC, survives network change; mobile thin clients | ☐ |

**Progress:** Phase 0 complete (P0-1…P0-10; P0-6/7/8/10 via portable software paths, real DXGI/NVENC/wgpu + LAN-budget deferred to the on-hardware session). **Phase 1: P1-1, P1-2, P1-4, P1-5 done; P1-3 partial (🟡); Gate P1 click-to-photon proxy measured.** **Phase 3 COMPLETE (#28–#32): P3-1 device identity + Keystore (🟡 SW; HW deferred R-HW-KS), P3-2 Noise handshake + BindCert, P3-3 SAS + SPAKE2 pairing, P3-4 per-channel ChaCha20-Poly1305 + key rotation, P3-5 authorization + kill-switch — each through the full bug-bot + code-reviewer + security-engineer triple-gate (ADRs 0006–0010). Phase 2: P2-1 (SCReAM), P2-2 (rate allocator), P2-3 (content classifier), P2-4 (double-buffered mode switch), P2-5 (codec negotiation + HEVC flag), and P2-6 (loss recovery) — **all 6 merged** (#20–#25), each through the full bug-bot + code-reviewer (+ security-engineer/rust-staff where applicable) gate. Adaptivity is verified in simulation / portable form; real-network adaptation, NVENC pixel-format reconfigure (R6), and AV1/HEVC HW encoders (R-CODEC) land in the on-hardware session.** **Phase 4 started: P4-1 `sh-signaling` (signaling client + self-hostable WS server, SDP/ICE envelope routing, trickle-ICE, zero-knowledge relay, reconnect with injectable backoff, spoof rejection, cargo-fuzz target) — 39 tests (19 unit + 12 integration + 8 doc-tests), all green; ADR-0011; deferred: live-WSS/TLS (reverse-proxy terminated, R-SIG-TLS), peer auth token (R-SIG-AUTH); in gate (bug-bot + code-reviewer + security-engineer pending, feat/P4-1-signaling). P4-2 `sh-ice` (STUN RFC 8489 codec, ICE RFC 8445 agent, NAT simulator, TURN relay steering, cargo-fuzz target) — 41 tests (26 unit + 15 doc-tests), all green; subtle crate for constant-time HMAC comparison; security fixes: trailing-attribute injection blocked for MI and FP (regression-tested), ICE connectivity checks signed with MESSAGE-INTEGRITY + USERNAME per RFC 8445 §7.2.2, stale index cleared on check-list rebuild, TURN credential leeway direction corrected, unknown STUN methods rejected; bug-bot + code-reviewer + security-engineer gates complete; PR pending (feat/P4-2-ice). P4-3 `sh-ice` TURN relay integration — `TurnMessage` codec + `TurnClient` state machine (Unallocated→Allocating→Allocated via RFC 8656 401-challenge), `SimTurnServer` in-process TURN server, `IceAgent::add_relay_candidate()` wired so relay-destined connectivity checks route through TURN Send/Data Indications, `symmetric_symmetric_via_relay_connected` end-to-end test (Symmetric×Symmetric NAT → CONNECTED exclusively via relay, relay pair nominated), `nat_matrix_relay_fallback` matrix (5 Symmetric-involved combos all relay-nominate), fuzz target for TURN codec; 55 unit tests + 26 doc-tests green; branch feat/P4-3-turn-client.** — `run_input_rtt_harness` (`feat/P1-gate-input-rtt`) delivers 200-event loopback RTT: p50 = 722 µs, p95 = 1,117 µs over the reliable Input channel (true per-event serialized RTT; previous batch-send numbers of p50 = 4.6 ms, p95 = 5.4 ms reflected queue-drain time, not true transport RTT); P1-3 ships the portable `InputInjector` trait + `CoordMapper` + mocks in `sh-input`, but real platform injection (the click-to-photon enabler) is deferred — R14; P1-4 portable audio + `AvSync` done, real WASAPI/Opus deferred — R13. The full portable Phase-0 vertical slice runs end-to-end and is measured (loopback); Phase-1 input/control framing, multi-channel transport, input-injection seam, prioritization, and audio AV-sync are landed and gated.

> **Phase-0 local-vs-hardware note (overnight build):** the dev laptop is **Linux/Intel iGPU, no Windows SDK, no NVIDIA, no cmake/nasm/clang**, so the *real* hardware paths — DXGI capture (P0-6), NVENC encode (P0-7), wgpu-on-display (P0-8) — cannot be built or verified here. The overnight work delivers a **portable, pure-Rust software pipeline** (synthetic capture → raw codec → loopback QUIC → decode → headless sink → latency harness) that runs and is measured **locally and in CI**, achieving Phase 0's *purpose* (validate the vertical-slice latency budget). The hardware backends slot in behind the same traits during the on-hardware/LAN session.

---

## Cross-Cutting Workstreams (run continuously, not a phase)

| ID | Workstream | Notes | Agent | Status |
|----|-----------|-------|-------|:------:|
| X-1 | **CI activation** | ✅ Live: `pr-title`/`lint`/`test` (3 OSes)/`audit` now run real Rust gates; toolchain pinned (1.95.0). **Pending:** coverage gate (`cargo-llvm-cov` ≥80% on `sh-protocol`/`sh-crypto`/`sh-transport`), cross-OS clippy (lands with platform crates, P0-6), and an MSRV-verification job. | devops-engineer | 🟡 |
| X-2 | **Testing infra** | `LoopbackTransport`, injected `Clock`+seedable RNG, `proptest`, `cargo-fuzz` targets, `loom` for lock-free queues. Build incrementally with each crate. **Started:** proptest across sh-types/sh-protocol/sh-codec-hw/sh-core; `cargo-fuzz` targets `shp_decode` (P0-3) and `fuzz_reassembler_ingest` (P0-9). **Pending:** a **CI fuzz-target compile-check** (the fuzz crates are excluded from the workspace, so non-compiling targets rot undetected — caught manually in P3-3); a scheduled nightly fuzz job; `loom`; coverage gate. | qa-engineer, rust-staff-engineer | 🟡 |
| X-3 | **Security review cadence** | `security-engineer` reviews **every** crypto/auth/transport PR; `cargo audit` clean; document `snow` unaudited status. | security-engineer | ☐ |
| X-4 | **Release engineering** | `xtask` for packaging/signing; signed releases (Sigstore/cosign), SBOM (CycloneDX), per-OS installers/services. | devops-engineer | ☐ |
| X-5 | **Open decisions** | Resolve LLD §9 items before they block: Noise pattern names (SHA-256, before P3), platform-attestation envelope, UGC lifetime per compliance tier, `str0m` Safari interop (before P4/5). | software-architect, security-engineer | ☐ |

---

## Phase 0 — Hello Pixels (latency lab)

> Goal: prove the latency budget on the thinnest vertical slice. Windows host → native client, LAN, H.264,
> **bare `quinn` QUIC (no ICE/crypto)**, no adaptivity. Validates codec/render pipeline in isolation.
>
> **Scaffolding note (P0-1):** the workspace ships 10 portable `sh-*` libs + 2 bins. The platform/codec
> crates `sh-codec-hw` (P0-7) and `sh-platform-win` (P0-6), and the bindings `sh-ffi`/`sh-wasm` (P5/P8),
> are created **with their tasks** — they need real platform code to compile cross-OS, so adding empty
> stubs now would break `cargo test` on the Linux/macOS CI runners.

| ID | Task | Crates | Depends | Agent | Tests | Status | PR |
|----|------|--------|---------|-------|-------|:------:|----|
| P0-1 | Cargo workspace scaffold + workspace lints (panic-ban) + activate CI | (all skeleton) | — | rust-staff-engineer | crates compile; clippy `-D warnings` clean; CI goes live | ✅ | #5 |
| P0-2 | `sh-types`: IDs, units, `FrameId`/`Timestamp`/`ChannelId`, error scaffolding | sh-types | P0-1 | rust-staff-engineer | unit | ✅ | #5 |
| P0-3 | `sh-protocol`: common header + video payload header (per LLD §3.1), encode/decode | sh-protocol | P0-2 | rust-staff-engineer, network-engineer | **proptest** (never-panic + roundtrip) + **cargo-fuzz** target | ✅ | #6 |
| P0-4 | `sh-transport`: bare `quinn` backend (LAN, datagrams), no ICE/crypto | sh-transport | P0-2 | network-engineer | loopback integration | ✅ | #7 |
| P0-5 | `sh-media`: `ScreenCapturer`/`VideoEncoder`/`VideoDecoder` traits + frame/surface types | sh-media | P0-2 | realtime-systems-engineer | trait doubles | ✅ | #8 |
| P0-6 | Capture. **Portable `SyntheticCapturer` done + tested (local/CI), #8.** Real **DXGI Desktop Duplication** (`sh-platform-win`, zero-copy D3D11) is **deferred to the on-hardware session** — the dev laptop is Linux/Intel with no Windows SDK, so it can't be built/verified here. | sh-media / sh-platform-win | P0-5 | realtime-systems-engineer | manual + smoke (on hardware) | 🟡 | #8 |
| P0-7 | Codec. **Portable lossless `RawEncoder`/`RawDecoder` (+ `Codec::Raw`) done + tested (local/CI), #9.** Real **NVENC H.264** encode + HW decode (zero-copy surface registration) is **deferred to the on-hardware session** (no NVIDIA/Windows SDK/C build tooling on the dev laptop). | sh-codec-hw | P0-5 | realtime-systems-engineer | encode/decode roundtrip | 🟡 | #9 |
| P0-8 | Sink. **Headless `FrameSink` + `CollectingSink`/`NullSink` done + tested (in `sh-media`), #10.** Real **`wgpu` NV12→RGB present + latency overlay** (display) is **deferred to the on-hardware session**. | sh-media / sh-render | P0-5 | ui-engineer, realtime-systems-engineer | manual (on hardware) | 🟡 | #10 |
| P0-9 | **End-to-end wiring done + tested, #10.** `sh-core` packetize (SHP fragmentation + reorder-tolerant `Reassembler`) + async host/client pipelines; `streamhaul-host`/`streamhaul-client` bins runnable for a real LAN run. Real DXGI/NVENC/wgpu backends plug in behind the same traits. | bins, sh-core | P0-3,4,7,8 | rust-staff-engineer | e2e smoke | ✅ | #10 |
| P0-10 | **Loopback latency harness done + measured locally, #10/#11** (`run_loopback_harness`: 120 single-datagram frames, lossless among received, latency reported; deterministic + fast). The client tolerates datagram loss (returns partial) — multi-fragment reassembly is covered by packetize unit/proptests. **Real LAN + hardware glass-to-glass budget + 10-min soak are the user's LAN session.** | host/client | P0-9 | performance-tuning-engineer | latency bench; soak (LAN) | 🟡 | #10, #11 |

**Gate P0:** ☑ data-path slice runs + lossless (loopback) · ☐ ≤~30ms glass-to-glass **LAN** (user's session) · ☐ zero-copy DXGI→NVENC (hardware) · ☐ 10-min soak (LAN).

> **LAN test handoff (run when awake):** on the host machine `cargo run -p streamhaul-host --features sh-transport/insecure-lan -- 0.0.0.0:7878`; on the client `cargo run -p streamhaul-client --features sh-transport/insecure-lan -- <host-ip>:7878`. Both already apply `lan_lab_transport_config()` (datagrams enabled) via the insecure config helpers. The client prints received-frame/latency stats. (This is the LAN-lab insecure path — `compile_error!` blocks it from release builds.)

---

## Phase 1 — Input + multi-channel + audio

| ID | Task | Crates | Depends | Agent | Tests | Status | PR |
|----|------|--------|---------|-------|-------|:------:|----|
| P1-1 | Promote `Transport`/`Channel` trait + `ChannelSpec`; multi-channel (video unreliable + input reliable, **input urgency 0**) | sh-transport | P0 | network-engineer, rust-staff-engineer | loopback multi-channel | ✅ | #15 |
| P1-2 | `sh-protocol`: input event message (LLD §3.1) + control/RPC framing | sh-protocol | P0-3 | network-engineer | proptest + fuzz | ✅ | #14 |
| P1-3 | `sh-input`: portable `InputInjector` trait + `CoordMapper` (normalized→pixel, multi-monitor, i32 origins) + `NoopInjector` + `RecordingInjector` mocks. Real platform injection (Windows `SendInput`/Raw Input, Linux `uinput`, macOS `CGEvent`) deferred to `sh-platform-*` — see R14. | sh-input (trait/mocks); sh-platform-win/linux/mac (impls, deferred) | P1-1,P1-2 | realtime-systems-engineer | 27 unit + 1 doc-test; proptest mapped-coords-in-bounds | 🟡 | #18 |
| P1-4 | Audio: capture + encode/decode + AV sync (shared monotonic clock). **Portable slice done**: `AudioFrame`/`AudioEncoder`/`AudioDecoder` traits + `AudioCodec` + raw-PCM codec + `SyntheticAudioSource` + `AvSync` controller (±20ms, max skew 18.4ms). **Deferred** (no audio hardware on dev box): real WASAPI loopback capture + Opus — see note. | sh-media, sh-codec-hw | P0 | realtime-systems-engineer | sync test + raw-audio fuzz | ✅ | #17 |
| P1-5 | Channel prioritization (input > video) + file-channel congestion-isolation scaffolding | sh-transport | P1-1 | network-engineer | starvation test under load | ✅ | #16 |

**Gate P1:** 🟡 click-to-photon: **input round-trip latency measured over the reliable Input channel (loopback proxy: p50 = 722 µs, p95 = 1,117 µs, min = 483 µs, max = 2,234 µs, 200/200 events delivered in order)**. Measurement uses true per-event serialized RTT (send event i, await echo, then send event i+1); previous numbers (p50 = 4,627 µs, p95 = 5,357 µs) reflected batch-send queue-drain time, not the real transport contribution. True glass-to-photon deferred to the on-hardware session (needs real injection R14 + capture/encode P0-6/7/8). Cross-reference R9 (one-way latency needs clock sync; RTT is symmetric here). · ☑ audio AV-synced (±20ms) (`AvSync` controller; max skew 18.4ms < 20ms target, deterministic over 3 runs; test in `sh-media`) · ☑ input not starved under video load (structural per-stream isolation; loopback test #16).

> **Datagram demux** (route datagrams to the right channel by SHP CHANNEL field — needed once video+audio coexist) and a **bandwidth-shaped congestion-scheduling test** (loopback can't create real congestion) remain follow-ups (see Risk Register).
>
> **P1-4 audio hardware deferred** (R13): the portable software path (synthetic source → raw-PCM codec → `AvSync`) lands now so the pipeline is measurable on any machine incl. CI; real **WASAPI loopback capture** + **Opus** encode/decode arrive with platform crates (no audio capture hardware / Opus toolchain on the dev box). The trait seams (`AudioEncoder`/`AudioDecoder` + `AudioCodec`) are designed so Opus drops in without touching callers.
>
> **P1-3 platform injection deferred** (R14): `sh-input` delivers the portable `InputInjector` trait, `CoordMapper`, `NoopInjector`, and `RecordingInjector`. Real injection (`SendInput`/Raw Input on Windows, `uinput` on Linux, `CGEvent` on macOS) is deferred to `sh-platform-*` crates — no injection hardware available on the dev box. The trait seam is designed so platform crates drop in without touching callers.
>
> **Gate P1 click-to-photon proxy** (`run_input_rtt_harness`, `feat/P1-gate-input-rtt`): `sh-core` gains `input_harness.rs` (gated under `harness` feature). Client opens the reliable Input channel, sends 200 distinct `InputEvent`s (index encoded in `pointer_x`), host injects via `RecordingInjector` + echoes each raw 16-byte event back, client computes per-event RTT. RTT is measured with a serialized per-event round-trip (send event i, block waiting for echo, then send event i+1), yielding the true transport contribution rather than batch-send queue-drain time. Measured on dev box (Linux loopback): **p50 = 722 µs, p95 = 1,117 µs, min = 483 µs, max = 2,234 µs; 200/200 delivered in order; zero loss** (reliable channel guarantee). Network + transport contribution to click-to-photon is bounded at ~1.1 ms p95 on loopback; on a real LAN this will be dominated by the actual RTT (~0.5–2 ms) with protocol overhead well under 1 ms additional. (Previous numbers p50 = 4,627 µs, p95 = 5,357 µs reflected batch-send queue-drain inflation and did not represent true per-event transport RTT.)

---

## Phase 2 — Adaptivity (Game/Work modes)

| ID | Task | Crates | Depends | Agent | Tests | Status | PR |
|----|------|--------|---------|-------|-------|:------:|----|
| P2-1 | `sh-adaptive`: `CongestionController` trait + **SCReAM** (native path) | sh-adaptive | P1 | network-engineer | sim: adapt to bandwidth caps | ✅ | #20 |
| P2-2 | Rate allocator across channels (video/audio/file budgets) | sh-adaptive | P2-1 | network-engineer | allocation unit | ✅ | #21 |
| P2-3 | Content classifier (4-signal heuristic + hysteresis FSM, LLD §5.2) | sh-adaptive | P1 | realtime-systems-engineer | FSM unit (no flapping) | ✅ | #22 |
| P2-4 | Encoder reconfigure + **double-buffered mode switch** (4:2:0↔4:4:4, glitch-free) | sh-codec-hw | P2-3 | realtime-systems-engineer | switch test; NVENC session-limit guard | 🟡 | #24 |
| P2-5 | HEVC enable (commercial build feature flag) + codec negotiation/degradation ladder (ADR-0004) | sh-codec-hw, sh-protocol | P0-7 | realtime-systems-engineer | negotiation matrix | 🟡 | #25 |
| P2-6 | Loss recovery: rolling intra-refresh + adaptive FEC + selective NACK + forced IDR (LLD §4.4) | sh-adaptive, sh-protocol | P2-1 | network-engineer, realtime-systems-engineer | induced-loss recovery test | ✅ | #23 |

**Gate P2:** 🟡 smooth adapt under loss/caps (SCReAM sim verified, P2-1 ✅) · 🟡 cross-channel rate allocator (priority-ordered floors + video bulk + file leftover, P2-2 ✅) · ✅ Game↔Work no flapping (hysteresis FSM + 93 deterministic tests, P2-3 ✅) · ✅ keyframe/loss recovery verified (P2-6: tiered RTT-band policy, IDR suppression, rolling intra-refresh, NACK bitmap, gap detector — 20 tests all pass; escalation trace NACK→FEC→IDR confirmed) · 🟡 glitch-free double-buffered mode switch (P2-4: portable orchestration — `SessionLimiter`, `EncoderFactory`, `DoubleBufferedEncoder`, `BackpressurePolicy` — fully tested against `RawEncoder`; 37 unit + 7 doc-tests green; real NVENC 4:2:0↔4:4:4 hardware reconfigure deferred — see R6) · 🟡 codec negotiation ladder + HEVC feature flag (P2-5: `CodecNegotiator`/`CodecCapabilities`/`BuildFlavor` in `sh-codec-hw`; `CodecCapsPayload` binary wire format + `decode_caps`/`encode_caps` in `sh-protocol::capability`; `hevc` Cargo feature OFF=OSS / ON=Commercial; full negotiation matrix + wire roundtrip tests all pass; real AV1/HEVC HW encoder backends deferred — see R-CODEC). **Progress: 6/6 tasks merged (#20–#25). Phase 2 complete (portable/sim slice); real-network + HW-encoder validation deferred to the on-hardware session — R6, R-CODEC.**

> **P2-6 FEC symbol codec deferred (R-FEC):** P2-6 delivers the adaptive `FecPolicy` ratio engine and `NackFeedback` wire framing. The actual Reed-Solomon / XOR FEC symbol encode/decode codec is deferred: it requires its own fuzz-heavy parser of untrusted repair-symbol bytes and is independent of the policy. See Risk Register entry R-FEC below.

---

## Phase 3 — Security & pairing (E2E)

> **Security applies from here on** (LLD §6). Every task in P3+ touching crypto requires `security-engineer` review.

| ID | Task | Crates | Depends | Agent | Tests | Status | PR |
|----|------|--------|---------|-------|-------|:------:|----|
| P3-1 | `sh-crypto`: Ed25519 device identity + `Keystore` trait + platform keystores (TPM/Keychain/DPAPI) | sh-crypto | P0 | security-engineer, rust-staff-engineer | unit + keystore mocks | 🟡 | #28 |
| P3-2 | Noise tunnel (`snow`, `Noise_XK` pair / `Noise_IK` connect) + identity-bound `BindCert` | sh-crypto, sh-transport | P3-1 | security-engineer | handshake unit + **fuzz** | ✅ | #29 |
| P3-3 | TOFU pinning + SAS (from Noise hash) + PAKE pairing codes (SPAKE2/OPAQUE) | sh-crypto | P3-2 | security-engineer | MITM-rejection test | ✅ | #30 |
| P3-4 | Channel encryption + key hierarchy + rotation (PFS ephemerals, rekey, channel subkeys) | sh-crypto, sh-transport | P3-2 | security-engineer | rotation test; negative tests | ✅ | #31 |
| P3-5 | Authorization (capability mask, host-enforced, non-escalatable) + kill-switch (RAM key zeroize) | sh-core | P3-4 | security-engineer | cap-guard + kill-switch test | ✅ | #32 |

**Gate P3:** 🟡 TOFU pins on first pair (P3-1: software-backed, hardware deferred) · ✅ unpinned-key MITM rejected (P3-2) · ✅ SAS + SPAKE2 PAKE pairing + revoke gate (P3-3) · ✅ all channels E2E encrypted (P3-4) · ✅ kill-switch verified. **Progress: 5/5 tasks (P3-1 🟡 — identity + trait + SW keystore delivered; TPM/Keychain/DPAPI/StrongBox deferred as R-HW-KS. P3-2 ✅ — Noise handshake + BindCert + 6-check verification + fuzz. P3-3 ✅ — SAS from `h` via HKDF-SHA-256 + SPAKE2 PAKE with explicit key-confirmation MAC bound to `h`+ids + TOFU pin gated on confirm + revoke-gate surfaced + `was_peer_revoked` Keystore method; spake2 unaudited — pre-GA R-SPAKE2-AUDIT. P3-4 ✅ — ChaCha20-Poly1305 AEAD per-channel, HKDF key hierarchy 12 subkeys from Noise PRK, ratchet chain 1-way HKDF, sliding anti-replay bitmap 1024-bit, epoch rekey + grace prior slot, two-phase commit-on-AEAD-success for both epoch advance and ratchet advance, `zeroize_all` kill-switch including PRK, clock-regression-safe `needs_rekey`, `channel_frame_open` fuzz target; 160 tests all green. P3-5 ✅ — Capabilities bitflags (VIEW/CONTROL/CLIPBOARD/FILE/AUDIO/ELEVATION), UGC canonical 73-byte TBS (encode+decode+verify, 5-check, constant-time grantee binding, unknown-bit truncation), SessionAuthorizer sealed AND-intersection + no-widen invariant + ELEVATION default-deny without FreshPresence + kill-switch (zeroize_all + bump_min_epoch + Denied::Killed), MinEpochStore trait + InMemoryMinEpochStore (R-EPOCH-PERSIST deferred), MalformedUgc/UgcBadSignature/UgcWrongGrantee/UgcExpired/UgcRevoked in CryptoError, ugc_decode fuzz target; 50 unit tests + 11 doc-tests all green. Deferred: R-EPOCH-PERSIST (durable min_epoch store), R-ELEVATION-MFA (WebAuthn/FIDO2 issuance). ADR-0010 status: Accepted.).**

---

## Phase 4 — Connectivity (WebRTC + signaling + relay)

| ID | Task | Crates | Depends | Agent | Tests | Status | PR |
|----|------|--------|---------|-------|-------|:------:|----|
| P4-1 | `sh-signaling`: client + self-hostable signaling server (WSS, SDP/ICE exchange, trickle) | sh-signaling | P3 | network-engineer | signaling integration | ✅ | #34 |
| P4-2 | `sh-ice`: ICE/STUN candidate gathering, connectivity checks, P2P-vs-relay nomination | sh-ice | P4-1 | network-engineer | NAT-sim matrix | ✅ | #35 |
| P4-3 | TURN client (RFC 8656): Allocate/Refresh/CreatePermission/ChannelBind codec + long-term credential auth + SimTurnServer + `latency-probe relay steering` (LLD §4.3); `IceAgent::add_relay_candidate()` wired + symmetric×symmetric end-to-end relay test + `nat_matrix_relay_fallback` matrix; coturn deploy **deferred** → R-COTURN-DEPLOY | sh-ice | P4-2 | network-engineer | 401-challenge + channel roundtrip + relay-steering + ICE-relay integration tests (63 ✅) | 🟡 | #36 |
| P4-4 | `sh-transport`: WebRTC backend (`str0m`) + **GCC** congestion control | sh-transport, sh-adaptive | P4-1 | network-engineer | webrtc transport+loopback (9 ✅, 1 slow `#[ignore]`) + GCC sim (15 ✅) | ✅ | feat/P4-4-webrtc-gcc |
| P4-5 | Bind DTLS fingerprint to device identity via signed `BindCert` (kills signaling MITM, LLD §6.2) — whole-cert SHA-256 commit (ADR-0014), pin-before-handshake, `ALG=NONE` downgrade rejected for WebRTC; `remote_dtls_fingerprint()` getter added; DTLS-exporter prologue binding deferred → R-DTLS-EXPORTER-BIND | sh-crypto, sh-transport | P3-2,P4-4 | security-engineer | fingerprint-swap rejection (integration: honest connects + str0m-verified pin == committed; MITM swap rejected; non-vacuity control) + BindCert/downgrade units | ✅ | |
| P4-6 | Transport capability negotiation (`transports:[quic,webrtc]`) + relay fallback path | sh-transport, sh-signaling | P4-4 | network-engineer | negotiation + fallback | ☐ | |

**Gate P4:** 🟡 P2P when possible (NAT-sim matrix: FullCone×*, RestrictedCone×RestrictedCone, PortRestricted×PortRestricted → P2P nominated; Symmetric×Symmetric → relay fallback nominated — all verified in `agent::tests::nat_matrix`, P4-2 ✅) · 🟡 connects across symmetric NAT via relay (`IceAgent::add_relay_candidate()` wired; end-to-end relay connectivity proven in `agent::tests::symmetric_symmetric_via_relay_connected` + `nat_matrix_relay_fallback` with SimTurnServer + NatSimNetwork Symmetric NAT, P4-3 ✅; live coturn server wiring deferred → R-COTURN-DEPLOY) · ✅ WebRTC transport backend (`str0m` sans-IO, `WebRtcTransport`+`WebRtcChannel` implementing `Transport`+`Channel`, DataChannel loopback round-trip verified, `GccController` for WebRTC path, ADR-0013; P4-4) · ✅ DTLS-MITM closed — peer DTLS cert bound to device identity, fail-closed (P4-5); full zero-knowledge over a live relay pending R-WEBRTC-LIVE + R-COTURN-DEPLOY: the WebRTC DTLS fingerprint is bound to the trusted Ed25519 device identity via the Noise-delivered, identity-signed `BindCert` (whole-cert SHA-256 commit, ADR-0014). A signaling/SDP fingerprint swap is rejected (str0m fail-closes the DTLS handshake against the pinned commitment) and an `ALG=NONE` downgrade is a typed abort for WebRTC peers — so a DTLS-terminating relay cannot read session content. **Scope:** P4-5 verifies the anti-MITM *control* (cert↔identity binding, fail-closed), not yet the full zero-knowledge property over a live relay — live DTLS/SRTP and a real relay are still deferred (R-WEBRTC-LIVE, R-COTURN-DEPLOY). Proven by `crates/sh-transport/tests/dtls_identity_binding.rs` (honest path connects with str0m-verified fingerprint == committed; MITM cert swap never connects; a non-vacuity control proves the rejection is caused by the pin) plus `BindCert`/`require_webrtc_dtls_pin` units. **Residual (not blocking the MITM defense):** the Noise-prologue↔DTLS-exporter channel binding is deferred (conflicts with pin-before-handshake ordering) → R-DTLS-EXPORTER-BIND. **Deferred (P4-4):** browser-WebRTC interop (P5), live DTLS/SRTP over real network (needs P4-5 BindCert + real UDP socket), tokio drive task for production use (P4-6 wiring), TWCC-based loss/jitter extraction for GCC (a data-only DataChannel exchanges no RTCP, so `WebRtcTransport::rtt()` returns zero by design until media/TWCC exists — documented, not a stub — R-WEBRTC-LIVE).

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
| R6 | **NVENC 4:2:0↔4:4:4 hardware reconfigure deferred.** P2-4 delivers the fully portable double-buffer orchestration (`SessionLimiter`, `EncoderFactory` seam, `DoubleBufferedEncoder` swap logic) tested against `RawEncoder`. The real NVENC pixel-format reconfigure (changing chroma subsampling on a live NVENC session, which may require `NV_ENC_RECONFIGURE_PARAMS` or a full session teardown depending on driver version) is deferred to the on-hardware session (no NVIDIA GPU / Windows NVENC SDK on the dev box). The `EncoderFactory` seam is designed so the NVENC backend slots in without touching the orchestration. Note: consumer GeForce NVENC limits concurrent sessions to 3–5; the `SessionLimiter` default of 4 leaves one slot for the pipeline; the double-buffer overlap requires max ≥ 2. Verify driver-level behavior (does `NV_ENC_RECONFIGURE_PARAMS` permit format change, or does it require destroy+recreate?) on the target hardware before landing the NVENC backend. | P2/P6 | realtime-systems-engineer |
| R7 | Multi-GPU cross-adapter copy budget on target laptop SKUs | P0/P2 | realtime-systems-engineer |
| R8 | Remove `sh-transport`'s `insecure-lan` path (self-signed + skip-verify TLS) when real crypto lands — delete the module or move to a dev-only testkit crate. Meanwhile it is fenced by a non-default feature, an `InsecureLanLab` witness, and a `compile_error!` that blocks `--release --features insecure-lan`. | P4 | security-engineer |
| R9 | Lab bins (`streamhaul-host`/`streamhaul-client`) report **QUIC RTT**, not true one-way glass-to-photon latency — cross-machine one-way latency needs synchronized clocks (NTP/PTP). Add real one-way latency measurement once clock sync is available. | P0-10 / LAN | performance-tuning-engineer |
| R10 | The bins have no **client-done back-channel**: the host waits a fixed 1.5s drain `sleep` before dropping the connection (a hack). Replace with a proper completion handshake (like the loopback harness's oneshot) so the tail isn't lost and exit is deterministic. | P1 | rust-staff-engineer |
| R11 | Add a `--json` report mode to the lab bins so WiFi/LAN test runs are machine-parseable (automation, regression tracking). | P0-10 | rust-staff-engineer |
| R12 | `AudioCodec` has only `RawPcm` today, so `RawAudioDecoder`'s wrong-codec rejection guard is structurally untestable (`decode_rejects_wrong_codec` is `#[ignore]`d). Re-enable the test when a second variant (Opus) lands. | P2 (Opus) | realtime-systems-engineer |
| R13 | P1-4 ships the **portable audio path only** (synthetic source + raw-PCM codec + `AvSync`). Real **WASAPI loopback capture** + **Opus** encode/decode are deferred until platform crates land (no audio hardware / Opus toolchain on dev box). Trait seams (`AudioEncoder`/`AudioDecoder`/`AudioCodec`) are designed for drop-in Opus. | P2 | realtime-systems-engineer |
| R14 | P1-3 ships the **portable input-injection slice only** (`sh-input`: `InputInjector` trait + `CoordMapper` + `NoopInjector` + `RecordingInjector`). Real platform injection — **Windows `SendInput`/Raw Input**, **Linux `uinput`**, **macOS `CGEvent`** — is deferred to `sh-platform-*` crates (no injection hardware / OS SDKs on the dev box). The `InputInjector` trait is object-safe and designed so platform crates drop in without touching callers. | P2 | realtime-systems-engineer |
| R-FEC | **FEC symbol codec deferred.** P2-6 delivers the adaptive `FecPolicy` ratio engine and `NackFeedback` wire framing. The actual Reed-Solomon / XOR FEC symbol encode/decode codec (generation and reconstruction of repair symbols from the packet stream) is deferred to a follow-up task. It requires its own fuzz-heavy parser of untrusted repair-symbol bytes (a full cargo-fuzz target), significant bitmath, and possibly an external crate (`aes-gcm-siv`-based XOR or `reed-solomon-erasure`). The FEC channel budget and ratio signalling are already wired; the codec slots in via the existing seam without API changes. | P2/P3 | rust-staff-engineer, security-engineer |
| R-CODEC | **Real AV1 / HEVC hardware encoder backends deferred (P2-5).** The `CodecNegotiator` ladder, `CodecCapabilities` model, `BuildFlavor` OSS/Commercial flag, and `CodecCapsPayload` wire format are fully implemented and tested. The ladder correctly selects which codec to use. What is deferred: the actual `VideoEncoder` + `VideoDecoder` trait implementations for AV1 (NVENC AV1, VA-API AV1) and HEVC (VideoToolbox HEVC, VA-API HEVC, Media Foundation HEVC). These require OS-specific SDK bindings (no NVIDIA GPU / Windows SDK / Apple SDK on the dev box). They slot in behind the `EncoderFactory` seam from P2-4 (`mode_switch::EncoderFactory`) with zero negotiation logic changes. The ladder will drive which factory to invoke once the hardware backends exist. | P6 | realtime-systems-engineer |
| R-PLATFORM-ATTEST | **`BindCert` platform-attestation field accepted but not verified (P3-2).** The `PLATFORM_ATTEST` field in the `BindCert` TBS is defined in ADR-0007 §2 and carries a platform-specific attestation blob (TPM 2.0 quote, Apple App Attest, Play Integrity token, or empty). P3-2 accepts and round-trips the field structurally (parse, length-check, encode) but does not verify its semantic content. Verification requires OS-specific SDKs and a chain of trust to a known root (e.g. Apple's App Attest CA, Google's Play Integrity root). Until verification is implemented: (a) never treat `PLATFORM_ATTEST` as proof of hardware key custody — it is cosmetic; (b) do not advertise platform attestation in the product until R-PLATFORM-ATTEST is resolved; (c) the field is designed for zero-API-change drop-in verification. **Do not ship GA without platform attestation verification for clients advertising hardware-backed keys.** | P3/GA | security-engineer, rust-staff-engineer |
| R-HW-KS | **Hardware-non-exportable device identity key deferred (P3-1).** The LLD (§6.2, §6.3) specifies that the device identity Ed25519 key must be hardware-non-exportable (TPM 2.0 on Windows/Linux, Secure Enclave / Keychain on macOS/iOS, DPAPI on Windows, Android StrongBox). `SoftwareKeystore` (delivered in P3-1) stores the signing key in ordinary heap memory protected by `zeroize`-on-drop, but cannot prevent a root-level attacker from reading it. Hardware keystores are deferred because: (a) no hardware TPM / SE available on the dev machine, (b) each platform requires a distinct OS-SDK integration (`tpm2-tss` on Linux, `CryptoKit`/`Keychain Services` on Apple, `NCryptCreatePersistedKey`/`BCryptImportKeyPair` on Windows, `android.security.keystore` JNI on Android). The `Keystore` trait is designed so hardware backends drop in without API changes. **Do not use `SoftwareKeystore` in GA builds until a hardware backend is available and wired.** **Sticky revocation hardening note (security-engineer, P3+ gate):** `SoftwareKeystore` permits re-trust after revocation for the factory-reset/re-pair scenario (see ADR 0006). Production / hardware keystore implementations MUST make revocation sticky: once an identity is revoked, re-establishing trust must require a distinct, explicitly operator-confirmed action — not the ordinary first-pairing `trust_peer` call. The P3-3 pairing layer MUST surface any implicit re-trust-after-revoke to the operator before executing it. The `Keystore` trait signature (`trust_peer -> Result<()>`) is intentionally unchanged — this is a policy constraint on implementations, not the trait API. | P3+ (GA) | security-engineer, rust-staff-engineer |
| R-SPAKE2-AUDIT | **`spake2` crate is UNAUDITED (P3-3).** The RustCrypto `spake2 = "=0.4.0"` crate used for unattended PAKE pairing carries the disclaimer "USE AT YOUR OWN RISK" and has not been independently audited. Mitigations in place: (a) all `spake2` types are wrapped behind `PakeExchange`; no raw `spake2` API is public; (b) an explicit HKDF-SHA-256 key-confirmation MAC is layered over SPAKE2 output, binding confirmation to `h` + both device identities so a `spake2` internal MAC bug doesn't directly yield a pinning bypass; (c) two fuzz targets (`pake_msg_parse`, `pairing_code_parse`) guard the parser surface; (d) `cargo audit` is clean; (e) `curve25519-dalek` dependency is unified at v4.1.3 (same as ed25519-dalek / x25519-dalek). **A full third-party security audit of `spake2` (and our `PakeExchange` wrapper) is a mandatory blocker before GA for any deployment that uses unattended pairing.** Track alongside the `snow` audit (R-SNOW-AUDIT). | GA | security-engineer |
| R-SIG-TLS | **Signaling server uses plain WebSocket; WSS TLS is not terminated in-process (P4-1).** Production deployments MUST put a TLS-terminating reverse proxy (nginx, Caddy, AWS ALB) in front of `SignalingServer`. The `insecure-lan` feature gates `AcceptAll` (any peer admitted); production code must supply a real `PeerAuthenticator`. A `compile_error!` guard (mirroring `sh-transport`'s insecure-lan fence) should be added when the production auth path is wired. The zero-knowledge invariant (payload never parsed by the server) is structural and not dependent on TLS. | P4 / GA | security-engineer, network-engineer |
| R-SIG-AUTH | **Signaling peer authentication is a no-op in P4-1 (`AcceptAll` default).** Real authentication — validating that a connecting peer's fingerprint is backed by a signed token (e.g., a short-lived HMAC token issued by the host) — is not implemented. Any peer that can reach the server can register any fingerprint. This is acceptable for LAN/dev testing but is a security gap for public-internet deployment. Real auth lands with P4-3 (short-lived HMAC TURN creds) or as a standalone P4-auth task. Until then, firewall the signaling server to trusted networks. | P4-3 / GA | security-engineer |
| R-ICE-LIVE-NAT | **Live STUN/TURN server communication and real NAT traversal are deferred (P4-3 partial).** `sh-ice` (P4-3) delivers the complete TURN client codec (Allocate/Refresh/CreatePermission/ChannelBind/Send/Data), long-term credential authentication, ChannelData framing, and a SimTurnServer — all verified hermetically. What remains deferred (R-COTURN-DEPLOY): (a) live coturn deployment and the coturn REST credential endpoint integration; (b) `IceAgent::gather()` relay candidate gathering wired to a live TURN server; (c) TURNS-on-443 TLS configuration; (d) live NAT traversal on real internet paths. **Do not use `sh-ice` for production ICE until R-COTURN-DEPLOY is resolved; the current agent produces host candidates only, and the TURN client has never spoken to a real server.** | R-COTURN-DEPLOY | network-engineer, devops-engineer |
| R-COTURN-DEPLOY | **coturn server deployment and live TURN wiring are deferred from P4-3.** Deliverables: (a) coturn server deploy (Kubernetes manifest + Helm chart in `aws-eng-compute`); (b) TURNS-on-443 with TLS termination; (c) `IceAgent::gather()` extended to issue live Allocate requests and add `CandidateKind::Relay` candidates; (d) coturn REST HMAC credential endpoint wired to `TurnCredentials::generate`; (e) live connectivity test from two peers behind real symmetric NAT boxes. Blocking for GA; not blocking for P4-4 (WebRTC transport) or P4-5 (DTLS fingerprint binding). | GA | network-engineer, devops-engineer |
| R-ICE-FUZZ | **Schedule a nightly fuzz job for `stun_decode` and `turn_decode` (sh-ice/fuzz).** Both libFuzzer targets exercise decode paths against hostile bytes. The fuzz crate compiles (verified) but no nightly CI fuzz job exists yet (tracked in X-2). Fuzz continuously in an automated job; any panic that emerges is a security regression. | X-2 / GA | qa-engineer |
| R-WEBRTC-LIVE | **Live WebRTC / DTLS / SRTP over real network is deferred from P4-4.** `WebRtcTransport` + `WebRtcChannel` implement the `Transport`/`Channel` traits and the DataChannel loopback test (ICE+DTLS+SCTP+DataChannel) passes over a synthetic loopback. What is deferred: (a) tokio drive task binding a real UDP socket and running the `drive()`/`handle_receive()` loop (using `next_drive_at()` for scheduling); (b) wiring `WebRtcTransport` into `sh-core` (requires the P4-6 negotiation layer); (c) live `WebRtcTransport`↔browser RTCPeerConnection interop (P5 — needs SDP offer/answer via `sh-signaling`); (d) TWCC-based per-packet arrival-time feedback for GCC (currently `GccController` consumes `TransportStats.queue_delay` as a trendline proxy; real TWCC extraction from str0m stats arrives with P4-5/P4-6); (e) live coturn relay path through `WebRtcTransport` (blocked on R-COTURN-DEPLOY). **Doc-honesty invariants:** P4-4 does NOT bind DTLS to device identity (that is P4-5 BindCert); does NOT feed live str0m stats into GCC (P5 drive loop). Per-channel recv queues are capped at 512 frames to bound memory from flooding peers. The `WebRtcTransport` is fully functional at the sans-IO level and the drive-loop contract is documented. | P4-5/P4-6 | network-engineer |
| R-DTLS-EXPORTER-BIND | **WebRTC Noise-prologue ↔ DTLS-exporter channel binding is deferred from P4-5.** ADR-0007 §1.4 envisaged binding the Noise prologue's `session_context` to the WebRTC DTLS exporter (mirroring native QUIC's TLS-exporter binding), so the Noise run is cryptographically pinned to *this* DTLS connection. It is deferred because it conflicts with the P4-5 pin-before-handshake ordering: the DTLS exporter does not exist until *after* the DTLS handshake, but the identity-signed `BindCert` (carrying `DTLS_FPR_COMMIT`) must be pinned *before* DTLS starts. **This does NOT weaken the P4-5 MITM defense:** the fingerprint pin already binds the peer's DTLS certificate to the trusted Ed25519 identity (str0m fail-closes a mismatch), and the `ALG=NONE` downgrade is rejected for WebRTC peers. The residual gap is only the *additional* anti-lift property (preventing replay of the Noise messages onto a different DTLS connection sharing the same identity), which the cert pin makes low-value. Resolution options to evaluate: (a) a post-DTLS key-confirmation exchange over the established Noise+DTLS channel that mixes in the DTLS exporter; (b) a two-phase prologue. See ADR-0014 §5. **P4-6 invariant (carried from P4-5):** the `sh-core` session orchestrator MUST call `require_webrtc_dtls_pin()` (→ typed `DtlsBindingMissing` abort) for EVERY DTLS-bearing (WebRTC) session before its DTLS handshake, so transport-capability negotiation cannot route a session onto unpinned DTLS. str0m fails closed regardless (it refuses to complete DTLS without a pinned remote fingerprint), but the orchestrator-level requirement makes the anti-downgrade gate explicit and non-bypassable at the negotiation seam. | P4-6 / GA | security-engineer, network-engineer |
| R-STR0M-AUDIT | **`str0m` crate is UNAUDITED (P4-4).** `str0m = "=0.20.0"` is the sans-IO WebRTC engine that parses DTLS, STUN, RTP, and SCTP bytes from hostile network input. It has not been independently audited. Mitigations in place: (a) all `str0m` types are wrapped behind `WebRtcTransport`/`WebRtcChannel`; no raw str0m API surface is public; (b) per-channel receive queues are capped at 512 frames (`MAX_RECV_QUEUE_DEPTH`) to prevent memory exhaustion from a flooding peer; (c) `fingerprint_verification` is NOT disabled in production — the remote DTLS certificate is verified by default; (d) `cargo audit` is clean; (e) exact version pin ensures a deterministic dependency tree. **Dependency reality:** `str0m`'s transitive dep `dimpl` pulls `aws-lc-rs` AND a second `rcgen 0.14` into the tree alongside `ring`/`rustls`; see ADR-0013 for the justification. **A full third-party security audit of `str0m` (DTLS, STUN, ICE, SCTP parsers) AND a `webrtc_framing` fuzz target are mandatory blockers before GA.** Any `str0m` version upgrade requires a security review before merge. Tracked alongside `R-SNOW-AUDIT` and `R-SPAKE2-AUDIT`. | GA | security-engineer |

---

*Update this document in the PR that changes status. It is the canonical answer to "where are we?"*
