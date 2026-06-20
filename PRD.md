# Streamhaul — Product Requirements Document (High-Level)

**Codename:** Streamhaul
**Tagline:** *Your whole desktop, hauled anywhere — without the lag.*
**Document type:** High-level PRD (architecture + protocol + feature scope). A separate session will produce the Low-Level Design (LLD).
**Date:** 2026-06-19
**Status:** Draft for review

---

## 1. Executive Summary

Streamhaul is a next-generation remote desktop, low-latency desktop video streaming, and remote-management platform — *"VNC, but radically more advanced."* It streams a remote desktop with **cloud-gaming-grade latency** (you can actually play games on it), supports **full remote control, file transfer, and remote management**, and runs **peer-to-peer over the public internet** with a relay fallback.

It is built around **one adaptive media pipeline** that auto-tunes between a **Game Mode** (sub-frame latency, high fps, GPU encode) and a **Work Mode** (crisp text, accurate color, multi-monitor) based on content and network conditions — so a single product serves gamers, IT/support teams, developers, and power users.

**Business model: open-core.** The protocol and clients are open source (trust through transparency, RustDesk-style); the hosted global relay infrastructure and enterprise control plane are the commercial tier.

### Positioning
Streamhaul is for developers, IT teams, and power users who refuse to choose between speed, control, and openness — delivering **Parsec-grade low latency** you can game on, **TeamViewer-grade remote management** and file transfer, and **RustDesk-grade openness** in one product. Where legacy tools force a trade-off (fast-but-closed, open-but-laggy, or manageable-but-bloated), Streamhaul runs on an open protocol with an optional hosted relay and enterprise tier when you need scale, security, and support.

**Brand voice:** Fast. Transparent. Capable. Unpretentious.

---

## 2. Goals & Non-Goals

### Goals (v1)
- **Sub-50 ms motion-to-photon** on LAN/near-LAN paths; best-achievable (network-floor-bound) over the internet.
- A **single adaptive pipeline** that transitions between Game Mode and Work Mode automatically, without user intervention.
- **Cross-platform hosts:** Windows (primary), macOS, Linux.
- **Cross-platform clients:** native Windows/macOS/Linux, thin mobile (iOS/Android), and **browser** (WebRTC).
- **P2P over the internet** via ICE/STUN with **TURN-like relay fallback**; **self-hostable** signaling + relay.
- **End-to-end encryption** such that even our hosted infrastructure cannot decrypt content.
- **File transfer, clipboard sync, multi-monitor, audio**, and remote-management primitives.
- **Open-source protocol + client**; paid hosted infra and enterprise features.

### Non-Goals (v1)
- Multi-user collaborative control / session sharing beyond 1 controller (roadmap).
- A full MDM/RMM suite (we provide remote-management *primitives*, not a complete fleet-management product) — roadmap.
- Dolby Vision / dynamic HDR metadata (HDR10 static only, opt-in).
- AV1 as the default codec (roadmap; hardware-gated opt-in).

---

## 3. Target Users & Top Use Cases

| Persona | Primary need | Mode |
|---|---|---|
| **Gamer / streamer** | Play a desktop game remotely with no perceptible lag | Game Mode |
| **Developer / power user** | Crisp text, accurate color, multi-monitor remote workstation | Work Mode |
| **IT / support technician** | Attended remote support, file transfer, remote management | Work Mode + attended consent |
| **IT admin / fleet owner** | Unattended access to own machines/servers, audit, SSO | Work Mode + unattended |

---

## 4. System Architecture

### 4.1 Principles
- **The server is on the control path, never the hot data path** — except when relay fallback is required. Successful P2P sessions consume zero server bandwidth, which keeps the hosted offering cheap to scale and the self-hosted footprint light.
- **One pipeline, two regimes.** Game Mode and Work Mode are operating points of the same adaptive engine, not separate code paths.
- **Shared Rust core + thin platform shims.** Memory safety in a real-time multithreaded media path, one codebase across desktop/mobile, zero-cost FFI to OS and GPU APIs.

### 4.2 Components

| Component | Responsibility | Deployment |
|---|---|---|
| **Host Agent** | Capture, encode (GPU-first), packetize, transport; inject remote input; clipboard/file/RPC; enforce local auth/consent | Controlled machine (Win/macOS/Linux); background service + tray |
| **Client / Viewer** | Establish session, decode/render, capture & forward input, clipboard/file/control UX | Native (Win/macOS/Linux), thin mobile, browser (WebRTC) |
| **Signaling / Coordination Service** | Identity, device registry, presence, session brokering, ICE/SDP exchange, TURN credential minting, policy/ACL | Hosted multi-tenant **or** self-hosted single binary |
| **Relay Service (TURN-like)** | Forward **encrypted** media when P2P fails; geo-distributed | Hosted edge fleet; self-host optional |
| **Control Plane / Web Dashboard** | Accounts/orgs/teams, device enrollment, RBAC, billing/entitlements, audit logs, fleet view | Hosted SaaS (enterprise tier) |
| **STUN servers** | NAT reflexive address discovery | Hosted (stateless, cheap) |

### 4.3 Component Diagram

```
                          ┌──────────────────────────────────────────────┐
                          │            SERVER-SIDE (Control Plane)        │
   ┌───────────┐  HTTPS   │  ┌────────────┐   ┌─────────────────────┐    │
   │  Web /    │◄────────►│  │ Control    │   │  Signaling /        │    │
   │ Dashboard │          │  │ Plane API  │◄─►│  Coordination Svc   │    │
   └───────────┘          │  │ (accounts, │   │  (presence, session │    │
                          │  │ RBAC,      │   │   broker, SDP/ICE,  │    │
                          │  │ billing,   │   │   TURN cred mint)   │    │
                          │  │ audit)     │   └─────────┬───────────┘    │
                          │  └─────┬──────┘             │                │
                          │   ┌────┴───┐   ┌────────┬───┴──────────┐     │
                          │   │ DB /   │   │  STUN  │  Relay/TURN   │     │
                          │   │ Redis  │   │(reflex)│  edge fleet   │     │
                          │   └────────┘   └────────┴──────┬────────┘     │
                          └──────────────────────────┬─────┼─────────────┘
                              signaling (WSS)         │     │ relay fallback
              ┌──────────────────────────────────────┘     │ (encrypted media)
              ▼                                             ▼
   ┌────────────────────┐                          ┌────────────────────┐
   │   CLIENT / VIEWER  │   P2P media + input +    │     HOST AGENT     │
   │  decode │ render   │◄═════ data channels ════►│  capture │ encode  │
   │  input  │ UX       │  (SRTP/DTLS or QUIC,     │  inject  │ RPC     │
   └────────────────────┘   ICE-negotiated path)   └────────────────────┘
        ═══ = hot data path (P2P preferred, relay fallback)
        ──► = control path (always via server)
```

### 4.4 Session Data Flow
1. **Discovery / Auth** — Client authenticates (OAuth/OIDC/device token); queries presence. Host holds a persistent WSS to signaling.
2. **Session request / brokering** — Signaling checks ACL/policy, mints short-lived TURN creds, pushes "incoming session" to the host; host enforces consent.
3. **Signaling (ICE/SDP)** — Both peers gather host/server-reflexive/relay candidates; trickle-ICE offer/answer (codecs, channels, keys) exchanged.
4. **Connection establishment** — ICE connectivity checks pick the best path (direct > reflexive/hole-punch > relay); DTLS/QUIC handshake establishes E2E encryption; server drops out of the media path unless relay was chosen.
5. **Steady state** — Multiplexed channels run P2P; the adaptive engine continuously tunes the encoder from client feedback.
6. **Teardown** — Channels drained; signaling logs session end; control plane writes the audit record.

### 4.5 Host Agent Internal Layers
**Outbound (host→client):** Capture (GPU texture, cursor, audio, damage rects) → Pre-process (scale, color convert, dirty-region merge) → **Encode (GPU-first)** → Packetize/FEC → **Transport**.
**Inbound (client→host):** Transport → Input demux/decode → **Input injection** (mouse/kbd/gamepad, multi-monitor mapping).
The **Transport** and **Adaptive Engine** are shared Rust core; **Capture, Encode binding, Input injection** are the platform-specific edges.

### 4.6 Cross-Platform Strategy

| Concern | Windows | macOS | Linux |
|---|---|---|---|
| **Screen capture** | DXGI Desktop Duplication (full desktop, free dirty-rects); Windows.Graphics.Capture (per-window) | ScreenCaptureKit (12.3+) | PipeWire + xdg-desktop-portal (Wayland); XDamage/DRI3 (X11); KMS/DRM (headless) |
| **HW encode** | NVENC / AMD AMF / Intel QSV (oneVPL) | VideoToolbox | VA-API (Intel/AMD), NVENC (NVIDIA) |
| **Audio capture** | WASAPI loopback | Core Audio / ScreenCaptureKit | PipeWire / PulseAudio monitor |
| **Input injection** | SendInput / Raw Input; ViGEm virtual gamepad | CGEvent (accessibility perm) | uinput (evdev) |

**Shared Rust core:** transport (ICE/DTLS/QUIC), congestion control, FEC, packetization, adaptive engine + content classifier, channel multiplexing, clipboard/file/RPC logic, crypto, signaling client. Mobile = thin viewer via Swift/JNI bridge + platform HW decoders. Browser = WebRTC + WebCodecs.

### 4.7 Multi-Channel Design
Separate logical channels multiplexed over one transport — mixing them would force one delivery guarantee onto workloads with opposite needs.

| Channel | Direction | Reliability | Priority | Rationale |
|---|---|---|---|---|
| **Video** | host→client | Unreliable (drop stale) | Real-time high | Latest frame wins; never block on old-frame retransmit |
| **Audio** | host→client | Unreliable + FEC | Real-time high | Glitch-sensitive; small enough for aggressive FEC |
| **Input** | client→host | Reliable, ordered | **Highest** | Lost/reordered input unacceptable; tiny, must preempt |
| **Clipboard** | bidi | Reliable | Medium | Correctness over latency |
| **File transfer** | bidi | Reliable, **congestion-isolated** | Low | Bulk; consumes only spare bandwidth, can't starve video |
| **Control / RPC** | bidi | Reliable | Medium-high | Resolution/monitor switch, mode hints, stats, consent |

**Key rule: input is prioritized above video** (input-to-photon dominates perceived responsiveness). Over WebRTC: SRTP for media + multiple SCTP data channels. Over QUIC: datagrams (unreliable real-time) + streams (reliable).

### 4.8 Server-Side Scalability
Server cost scales with **session setup rate** and **relay fallback traffic**, not total media throughput.
- **Signaling:** stateless, horizontally scaled WSS nodes; presence/session state in **Redis** (pub/sub for cross-node peer routing); durable state in **PostgreSQL**.
- **STUN:** stateless, anycast-friendly, cheap.
- **Relay (cost center):** geo-distributed edge fleet, **stateful per relayed session**, scaled by *concurrent relayed sessions × bitrate*; short-lived HMAC-scoped TURN credentials; forwards opaque ciphertext only.
- **Self-hosted distribution:** signaling + STUN + relay as a **single binary / Compose stack** — the open-core hook (OSS coordinator; paid managed global relay + enterprise control plane).

---

## 5. Transport & Protocol

### 5.1 Streamhaul Protocol (SHP)
The open application-layer protocol — analog to RFB/RDP. Codec-agnostic; sits above **QUIC** (native) and above **SRTP+SCTP** (browser/WebRTC). Defines: session establishment & capability negotiation, RTP-extension latency telemetry, RTCP-equivalent feedback (delay reports, loss maps, keyframe requests, bitrate target), control-channel framing (input/clipboard/file), and mode signaling (game/work/adaptive). *(Neutral spec name option for broad community adoption: FluxRTP, with Streamhaul as the reference implementation.)*

### 5.2 Dual-Path Transport (decisive)
- **Browser path → WebRTC** (SRTP media + SCTP data channels over DTLS 1.3). The only way to get low-latency encrypted P2P UDP from a browser tab. Non-negotiable; we tune it rather than work around it.
- **Native path → QUIC over UDP (RFC 9000)** with QUIC **Datagram** frames (RFC 9221) for video (unordered/unacked, UDP-like) and reliable QUIC streams for input/files. Gains: 0-RTT resumption, built-in TLS 1.3, per-stream ordering without cross-stream head-of-line blocking, and **connection migration** (survives mobile IP changes). Implementation: `quinn` (Rust) or `msquic`.
- **Interop:** both paths share the same signaling plane, the same relay infra, and an **identical video payload/codec-negotiation format**. WebRTC is the baseline/interop profile; QUIC is a negotiated upgrade between native peers.

### 5.3 NAT Traversal (ICE / STUN / TURN)
Per RFC 8445/8489/8656. Candidates (host / server-reflexive via STUN / relay via TURN) gathered **in parallel**; connectivity checks run simultaneously; first successful pair nominated (host > reflexive > relay). Hole-punching succeeds on ~80–85% of real-world NATs; **relay fallback** auto-activates when no P2P pair succeeds within ~4 s, or when an established path degrades (>15% loss for 3 s). Self-hosted **coturn**, multi-region, UDP/3478 primary with **TURN-over-TCP/443 (TURNS)** for restrictive enterprise firewalls. Signaling is a stateless WSS broker — never in the media path.

### 5.4 Congestion Control
- **WebRTC path → GCC** (Google Congestion Control, Transport-CC / RFC 8888) — already battle-tested in libwebrtc; keep it.
- **Native path → SCReAM (RFC 8298)** — purpose-built for real-time multimedia, adapts within ~1 RTT. **BBR is explicitly rejected** for the media path (throughput-oriented; its probing fills queues and adds latency).
- Bitrate target must reach the encoder within one frame interval (~16 ms @ 60 fps).

### 5.5 Reliability (no TCP for media)
Layered, in order of latency cost:
1. **Intra-refresh** (rolling intra rows instead of periodic IDR) — zero added latency, self-healing, no bitrate spikes. Always on.
2. **Adaptive FEC** (XOR/RFC 5109, Raptor for harder cases) — overhead tuned to measured loss (≈10+1 at <1% loss → 10+4 at 5–15%). Decode immediately; don't wait on repair packets in Game Mode.
3. **Selective NACK** (RFC 4585) — only for reference-frame-critical packets, only when the RTT fits the decode deadline.
4. **Keyframe request** (PLI/FIR) — last resort, rate-limited (≤1 / 500 ms).

### 5.6 Latency Budget (Game Mode, 60 fps, HW encode)

| Stage | LAN | Cross-internet |
|---|---|---|
| Input capture + send | ~1 ms | ~1 ms |
| Network (each way) | 1–2 ms | 20–70 ms (RTT/2) |
| Render + capture + **HW encode** | ~6–12 ms | ~6–12 ms |
| Jitter buffer | 2–4 ms | 5–15 ms |
| HW decode + display | 3–7 ms | 3–7 ms |
| **Total motion-to-photon** | **~14–46 ms** | **~88–135 ms** |

Cross-internet network legs dominate and are a **speed-of-light floor**, not an engineering problem. Hardware encode/decode is mandatory; the jitter buffer is the primary tuning knob (minimal in Game Mode, larger in Work Mode). Clients use immediate-presentation (allow tearing) in Game Mode to avoid VSync scan-out latency.

### 5.7 Wire Encryption
- **WebRTC:** DTLS 1.3 (RFC 9147) + SRTP AES-128-GCM (RFC 7714); reject legacy SHA-1 profiles.
- **Native:** QUIC mandates TLS 1.3 (RFC 9001); AES-128-GCM / ChaCha20-Poly1305; 0-RTT for setup only (never for input commands). Certificate/key pinning on native clients.
- **No double encryption** — the transport layer already provides authenticated E2E; an extra app-layer envelope would add latency for no benefit (identity binding handled in §7).

---

## 6. Video / Audio Pipeline

### 6.1 Codec Ladder
- **Primary encode: H.265 / HEVC** — best compression-at-latency with effectively universal HW encode across NVENC (Turing+), AMD VCE, Intel QSV, Apple VideoToolbox; HW decode on all modern clients.
- **Browser fallback: H.264** — non-negotiable; HW decode everywhere including Safari. The receive path negotiates down to H.264 when HEVC is unavailable in the browser context.
- **Next-gen tier (v2, opt-in, hardware-gated): AV1** — ~25–30% bitrate savings vs HEVC on Ada Lovelace / RDNA 3 / Arc / Apple M3+. **Honest 2026 caveat:** AV1 HW encode exists but its installed base is still a minority of host machines, and Safari has no AV1 HW decode path — so AV1 is roadmap, not v1 default.
- **VP9: dropped** — no viable HW encode path on the host.

### 6.2 Hardware vs Software Encode
HW encoder priority: **NVENC → AMD AMF → Intel QSV/oneVPL → Apple VideoToolbox**. Software (x264/x265 `ultrafast --tune zerolatency`) is a **Work-Mode-only fallback** for GPU-less hosts (cloud VMs, headless) or exhausted encode sessions — never attempt software encode at 60 fps Game Mode (degrade to 30 fps or notify).

### 6.3 Game Mode vs Work Mode (pipeline level)

| | Game Mode | Work Mode |
|---|---|---|
| Rate control | CBR low-delay | CQP (bandwidth headroom on static content) |
| B-frames | Zero | Zero |
| Keyframes | Intra-refresh (no IDR spikes) | Intra-refresh + region-forced intra |
| Frame strategy | Full-frame, **sliced** (decode top while bottom encodes) | **Dirty-rect / damage-region** encode (80–95% bandwidth saving on static desktops) |
| Chroma | 4:2:0 | **4:4:4** (crisp colored text, terminals, IDEs) |
| Frame rate | 60–120+ fps | Event-driven; suppress encode when screen is static |
| Reference frames | 1 | — |
| Lossless option | — | Selectable for code/terminal/spreadsheet content |

**Content classification** is a lightweight CPU-side heuristic (not ML) using inter-frame macroblock diff, OS-provided dirty-rect fraction, foreground window/app identity (known game processes trigger Game Mode immediately), and cursor velocity. Switching uses **hysteresis** (e.g. Game Mode after >40% macroblocks change sustained >500 ms; Work Mode after <15% change sustained >2 s) to prevent flapping; an intermediate "scrolling" state handles uniform full-screen motion.

### 6.4 Frame Pacing & Jitter Buffer
Low-latency encoder config (NVENC example): infinite GOP + intra-refresh, `maxNumRefFrames=1`, B-frames disabled, `CBR_LOWDELAY_HQ`, adaptive quantization, 4 slices/frame, async encode, frame rate matched exactly to display. Receiver jitter buffer is **statistically sized** (EWMA over inter-arrival): 1–2 frames in Game Mode, 50–100 ms in Work Mode; a playout scheduler (not a plain FIFO) absorbs late-packet bursts while meeting per-frame playout deadlines.

### 6.5 Color / HDR / High-Refresh
- **4:4:4** in Work Mode for sub-pixel text fidelity (HEVC Main 4:4:4 on Turing+); ~30–40% bitrate cost, acceptable at Work-Mode rates. Mode switch reinitializes the encoder session (2–5 ms, hidden behind a forced keyframe).
- **HDR (opt-in, feature-flagged):** 10-bit HEVC Main 10 + HDR10 static metadata; tonemap to SDR if the client display is SDR; Dolby Vision out of scope for v1.
- **120/144 Hz:** capture at native refresh; frame-rate negotiated to the receiver's display capability (a 60 Hz client gets 60 fps, not 2:1 drop). 1080p120 sustainable on all Ada-class NVENC; 4K120 needs higher-end GPUs.

### 6.6 Audio
**Opus** (royalty-free, native in WebRTC). Game Mode: 10 ms frames, `RESTRICTED_LOWDELAY`, 192 kbps stereo; Work Mode: 20 ms frames. **In-band FEC enabled** for loss recovery without retransmit. **AV sync** uses a shared monotonic host capture clock (QPC / CLOCK_MONOTONIC) stamped into packet headers; receiver keeps separate audio/video playout queues driven by one clock, holding sync within ±20 ms (video leads, audio nudges).

---

## 7. Security & Trust

### 7.1 Non-Negotiables
- **Zero-knowledge relay** — hosted signaling/relay MUST be unable to decrypt media, input, or files. We are transport, not witness.
- **End-to-end by default** — crypto endpoints are host and client, never our servers. No "transport-only" mode.
- **Explicit human consent for control**, least-privilege per-session scoping, and full auditability.
- **Open-core honesty** — nothing security-critical hidden behind the paid tier; the OSS core is independently auditable.

### 7.2 E2E Encryption & Device Identity
- **Two profiles, one guarantee:** WebRTC path = DTLS 1.3 + SRTP; native path = QUIC/TLS 1.3 wrapped in a **Noise Protocol** handshake (`Noise_IK`/`Noise_XK`) so endpoint identity is keyed to **our own device-identity keypairs**, not the WebPKI/CA system.
- **Device identity:** each install generates a long-lived **Ed25519 keypair**; private key never leaves the device (hardware-backed: **TPM 2.0 / Secure Enclave / Android StrongBox**). Public key = stable `device_id` shown as a human-verifiable fingerprint.
- **The crux:** the DTLS fingerprint / Noise static key is **bound to the device-identity key and pinned at pairing**. Plain WebRTC trusts the signaling channel for keys — without this pinning a malicious relay could MITM and the zero-knowledge claim would be false. Ephemeral ECDHE per session gives **forward secrecy**.
- Crypto suite: X25519, Ed25519, ChaCha20-Poly1305 / AES-256-GCM, HKDF-SHA-256, TLS 1.3 floor. No RSA/CBC/SHA-1.

### 7.3 Pairing & Authentication (layered)
- **Layer A — TOFU + SAS (always on):** first connection pins the host fingerprint; a **Short Authentication String** derived from the DH transcript is compared on both screens to defeat MITM at pairing.
- **Layer B — Pairing codes (PAKE):** short single-use code / QR via **SPAKE2/OPAQUE** so the low-entropy secret is never transmitted.
- **Layer C — Account auth (teams):** OIDC / OAuth 2.0 + PKCE, SAML SSO, SCIM provisioning. The org server **issues authorization, never decryption capability.**
- **Layer D — Per-device ACL:** each host keeps an allow-list of authorized client keys + permission profile + expiry; revocation via signed short-lived allow-lists.
- *Recommendation:* consumer = A+B; enterprise = A+C+D.

### 7.4 Authorization, Consent & Anti-Abuse
- **Attended** (local user approves each session, default for support) vs **Unattended** (ACL-preauthorized, **off by default**, MFA-gated, opt-in per host).
- **Granular per-session permissions:** view-only / full-control / file-transfer (r/w) / clipboard / audio / multi-monitor / privileged-elevation. Enforced host-side; **no mid-session escalation** without fresh consent.
- **Always-available kill-switch:** global hotkey + persistent on-screen control that instantly terminates and revokes the session key; local input activity can pause/end remote control.
- **Anti-scam (the dominant real-world threat):** **WebAuthn/FIDO2** MFA; a persistent, **un-coverable** "your screen is being controlled by <verified identity>" banner; scam-interstitial warnings + cooling-off delay before first full-control grant from an unknown identity; **file-transfer + clipboard blocked by default** in attended support sessions.

### 7.5 Audit, Privacy & Compliance
- **Tamper-evident, hash-chained audit log** of pairing/auth/consent/permission-changes/file-manifests/session-lifecycle/kill-switch; JSON export to syslog/Splunk/Elastic/S3 (WORM optional). Optional **policy-gated session recording** (disclosed to all parties; stored as ciphertext under org keys).
- **Privacy:** hosted infra can see account IDs, device public keys, timestamps, relay byte counts, coarse IP/geo — and **cannot** see screen, input, files, clipboard, or audio (architecturally). Self-hosting keeps all data off our servers. **Telemetry is opt-in, off by default, never includes session content**, and fully disable-able in the OSS build.
- **Standards to design toward:** SOC 2 Type II, FIDO2/WebAuthn, Zero-Trust (NIST SP 800-207), NIST SP 800-63B (AAL2+ for privileged access), signed releases (Sigstore/cosign) + SBOM + SLSA provenance. Roadmap: HIPAA, PCI DSS scoping, optional FIPS 140-3 build.

---

## 8. Feature Summary (v1 scope)

| Area | v1 |
|---|---|
| **Streaming** | Adaptive Game/Work mode, H.265 primary + H.264 browser fallback, up to 4:4:4, 60–144 fps, multi-monitor, HDR (opt-in flag) |
| **Control** | Full keyboard/mouse, **virtual gamepad** injection, clipboard sync, multi-monitor switching |
| **Files** | Drag-and-drop bidirectional file transfer (congestion-isolated channel) |
| **Connectivity** | P2P (ICE/STUN) + relay fallback (coturn), self-hostable signaling+relay single-binary |
| **Clients** | Native Win/macOS/Linux, thin mobile (iOS/Android), browser (WebRTC) |
| **Security** | E2E encryption, device-identity pinning, TOFU+SAS / pairing codes, attended + unattended, granular permissions, kill-switch, WebAuthn MFA, anti-scam UX |
| **Management (primitives)** | Device registry, presence, audit logging; web dashboard for org/device/RBAC (enterprise tier) |

### Roadmap (post-v1)
AV1 default; multi-user/collaborative control; full RMM/MDM management suite; dynamic HDR; session recording at scale; FIPS build.

---

## 9. Open Questions for the LLD Session

1. **Transport finalization** — WebRTC-only baseline vs the QUIC upgrade for native peers (HoL-blocking gains vs interop complexity and a dual crypto stack).
2. **Codec default & licensing** for the OSS build — AV1 (royalty-free) vs H.265 (patent pool) vs H.264 (ubiquity); verify Safari HEVC-in-WebRTC support.
3. **Content classifier** — heuristic vs lightweight ML; host-side only.
4. **Relay steering** — anycast vs latency-probe-based selection.
5. **Unattended-access key custody & recording-key model** — org-managed KMS vs per-host keys; revocation transport (push CRL vs short-lived re-issued allow-lists) for offline hosts.
6. **Multi-GPU zero-copy** — handle iGPU-capture / dGPU-encode PCIe copy on Windows; Linux DMA-BUF→NVENC import latency.
7. **Intra-refresh recovery policy** — forced IDR after N consecutive losses vs waiting for the refresh sweep.
8. **Protocol-name fork** — branded "Streamhaul Protocol (SHP)" vs neutral "FluxRTP" for community adoption.

---

## Appendix A — Key Decisions at a Glance

| Decision | Choice |
|---|---|
| Product name | **Streamhaul** |
| Protocol name | **Streamhaul Protocol (SHP)** |
| Core language | **Rust** (shared core) + platform shims |
| Browser transport | **WebRTC** (SRTP + SCTP / DTLS 1.3) |
| Native transport | **QUIC** (RFC 9000) + Datagrams (RFC 9221), TLS 1.3 |
| Congestion control | GCC (browser) / **SCReAM** (native); BBR rejected for media |
| Loss recovery | Intra-refresh + adaptive FEC, then selective NACK, then keyframe |
| Primary codec | **H.265/HEVC**; H.264 browser fallback; AV1 roadmap |
| Encode | GPU-first (NVENC/AMF/QSV/VideoToolbox/VA-API); SW = Work-Mode fallback |
| Capture | DXGI Desktop Duplication / ScreenCaptureKit / PipeWire |
| Audio | **Opus** + in-band FEC |
| NAT traversal | ICE/STUN + **coturn** TURN fallback (UDP/3478, TURNS/443) |
| E2E identity | Ed25519 device keys; DTLS/Noise fingerprint pinned at pairing |
| Business model | **Open-core** (OSS protocol+client; paid global relay + enterprise) |
