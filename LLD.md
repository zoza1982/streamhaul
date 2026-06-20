# Streamhaul — Low-Level Design (LLD)

**Status:** Draft for review
**Date:** 2026-06-19
**Builds on:** [`PRD.md`](./PRD.md) (high-level product spec) and [`docs/adr/`](./docs/adr/).

This LLD resolves the 8 open questions left by the PRD (§9), fixes the buildable structure
(crates, trait seams, threading), specifies the **Streamhaul Protocol (SHP)** wire format, the
security/crypto design, the Rust implementation strategy, and a phased build plan. It is the input to
implementation. Illustrative Rust below is design intent, not committed code.

---

## 0. Resolved Decisions (the 8 open questions)

| # | Question | Decision |
|---|----------|----------|
| **Q1** | Transport finalization | **WebRTC-first for v1, native QUIC fast-follow (v1.1)**. Phase-0 latency lab uses bare QUIC. One `Transport` trait hides both. See §3.3, ADR-0003. |
| **Q2** | OSS codec & licensing | **OSS default = AV1 (royalty-free) + H.264 via OS system APIs only** (no bundled SW codec). **Commercial build adds HEVC.** See §5.1, ADR-0004. |
| **Q3** | Content classifier | **Heuristic-only for v1** (4 signals, weighted score, hysteresis state machine). ML behind a v2 flag via a `ScoreProvider` seam. See §5.2. |
| **Q4** | Relay steering | **Latency-probe-based selection** (STUN-probe all coturn candidates, score by initiator+responder RTT), optional anycast hint tier. See §4.3. |
| **Q5** | Unattended keys + recording keys | **Hardware-bound Unattended Grant Certificate (UGC)** (MFA at enrollment, not connect) + **HPKE envelope-encrypted recordings** to a recipient set incl. customer-KMS escrow; hosted infra is never a recipient. See §6.1. |
| **Q6** | Multi-GPU zero-copy | Detect display-vs-encode adapter; **single-adapter = zero-copy; cross-adapter = bounded pinned-memory copy to the faster (dGPU) encoder**, with a user override. See §5.3. |
| **Q7** | Intra-refresh recovery | **Tiered, RTT-adaptive**: rolling intra-refresh always on → NACK (RTT<100ms) → FEC → forced IDR (frame_gap≥3 / RTT≥200ms+loss / loss≥5%). See §4.4. |
| **Q8** | Protocol name | **Streamhaul Protocol (SHP)** is canonical — used in code, comments, and capability-negotiation strings. "FluxRTP" is an optional vendor-neutral alias for the *published spec document* only, if we later court third-party implementers; it is not used in the wire/code. |

> **Note — Q2 refines the PRD.** The PRD named H.265 the primary codec for quality/HW-coverage reasons.
> For the **open-source, Apache-2.0** build that stance is legally untenable (HEVC patent pools), so the
> OSS default becomes AV1 + OS-API H.264; HEVC ships in the commercial build. Performance intent is
> unchanged where HEVC is licensed. Recorded in ADR-0004.

---

## 1. System Architecture & Crate Layout

Single Cargo workspace. **Convention:** libraries use the `sh-` prefix; the umbrella facade is
`sh-core`; product binaries are `streamhaul-host` / `streamhaul-client`. `sh-core` depends only on
**traits**, never concrete impls — binaries do the concrete wiring (DI at the edge), which keeps the
engine testable with mocks and lets codec/transport be swapped.

| Crate | Type | Responsibility |
|-------|------|----------------|
| `sh-types` | lib | Leaf: IDs, error enums, `FrameId`, `Timestamp`, `ChannelId`, units. No sibling deps. |
| `sh-protocol` | lib | SHP wire format: headers, framing, varint, FEC framing, capability negotiation. Pure `bytes`/`prost`, no I/O. |
| `sh-crypto` | lib | Ed25519 identity, Noise glue, key derivation, E2E session/channel keys, keystore + pinning. |
| `sh-transport` | lib | `Transport`/`Channel` seam + QUIC (`quinn`) and WebRTC (`str0m`) backends (feature-gated). |
| `sh-ice` | lib | ICE/STUN/TURN orchestration (coturn-compatible), candidate gathering, P2P-vs-relay decision. |
| `sh-signaling` | lib | Signaling client: SDP/ICE exchange, pairing transport, reconnect. Server-agnostic over WSS. |
| `sh-media` | lib | Codec-agnostic `ScreenCapturer`/`VideoEncoder`/`VideoDecoder`/`AudioEncoder` traits + frame/surface types. |
| `sh-codec-hw` | lib | Concrete codecs: NVENC/AMF/QSV/VideoToolbox/VA-API; SW fallback (`rav1e`/`openh264`). |
| `sh-adaptive` | lib | `CongestionController` (GCC + SCReAM), content classifier, Game/Work/Scrolling FSM, rate allocator. |
| `sh-render` | lib | Client present: `wgpu` swapchain, YUV→RGB, jitter buffer, frame pacing, latency overlay. |
| `sh-platform` | lib | Real facade crate that re-exports the platform traits and, via `cfg(target_os)`, depends on exactly one of `sh-platform-{win,mac,linux}`. `sh-core` depends on `sh-platform`, never on a specific shim. |
| `sh-platform-win` | lib | DXGI Desktop Duplication / WGC capture, `SendInput`, WASAPI, ViGEm. `windows-rs`. |
| `sh-platform-mac` | lib | ScreenCaptureKit, CGEvent, Core Audio. `objc2`. |
| `sh-platform-linux` | lib | PipeWire/portal + DRM/KMS capture, `uinput`, PipeWire audio. |
| `sh-core` | lib | Umbrella facade: composes everything into `Session`/`HostEngine`/`ClientEngine` state machines. |
| `streamhaul-host` | **bin** | Host agent daemon: capture→encode→transport, RPC, service/tray lifecycle. |
| `streamhaul-client` | **bin** | Native desktop client: connect, decode, render, input grab. |
| `sh-ffi` | lib (cdylib) | C ABI / UniFFI surface for iOS/Android thin clients. Wraps `ClientEngine`. |
| `sh-wasm` | lib (wasm) | Browser client logic using the browser's native `RTCPeerConnection` (via `web-sys`) with SHP framing on SRTP/data channels; reuses `sh-protocol` (compiled to WASM) for wire parity. Does **not** use `str0m`. |
| `xtask` | bin | Build automation (codegen, packaging, signing). Dev-only. |

### Dependency DAG

```
                         sh-types  (leaf: IDs, errors, units)
                            ▲
   ┌──────────┬────────────┼───────────┬───────────┬───────────┐
   │          │            │           │           │           │
sh-protocol sh-crypto   sh-media   sh-adaptive  sh-render   sh-platform-*
   ▲          ▲            ▲  ▲        ▲            ▲           ▲
   │          │            │  └ sh-codec-hw ────────┘           │
sh-transport ◄┴────────────┘     (impls sh-media)               │
   ▲   ▲                                                        │
   │   └─ sh-ice ◄─ sh-signaling                                │
   │                    ▲                                       │
   └──────── sh-core (facade/engine) ◄── sh-platform ───────────┘
                 ▲            ▲
        streamhaul-host  streamhaul-client
                              │
                       sh-ffi / sh-wasm (wrap ClientEngine)
```

### Async runtime & concurrency model

**Runtime: `tokio` (multi-threaded)** for I/O (QUIC, signaling, control), with **real-time media work
on dedicated OS threads** off the tokio pool. `quinn` and `str0m` are tokio-friendly.

```
 Dedicated RT threads (priority-elevated, NOT tokio):
   [Capture] --GPU surface--> [Encode] --EncodedChunk--> (bridge)
     (SPSC ring, drop-oldest)                 │
 ──────────────────────────────────────────────┼──── channel boundary ──
   tokio runtime:                               ▼
     [Pacer/transport]  [Congestion/feedback]  [Input task→InputInjector]
     [Control/RPC] [clipboard] [file-transfer (own budget)] [signaling/ICE]
```

Rules: capture/encode never `tokio::spawn`; perishable frames use a **drop-oldest SPSC ring** (`rtrb`),
backpressure = drop, never block capture; no `.await` holds a GPU surface across a yield; **input is the
highest-priority reliable channel**; **file transfer is congestion-isolated** so a copy can't starve video.

---

## 2. Core Trait Seams

Object-safe seams that decouple `sh-core` from platform/codec/transport. `dyn`-dispatched async seams use
`async-trait` or `dynosaur` (object-safe `async fn` in traits is still not `dyn`-compatible mid-2026);
static-dispatch sites use native AFIT (`async fn` in traits, stable since Rust 1.75). Sync seams
(capture/encode) run on dedicated RT threads, not tokio.

```rust
// sh-transport — hides QUIC vs WebRTC
#[async_trait] pub trait Transport: Send + Sync + 'static {
    async fn open_channel(&self, spec: ChannelSpec) -> Result<Box<dyn Channel>>;
    async fn accept_channel(&self) -> Result<Box<dyn Channel>>;
    fn stats(&self) -> TransportStats;        // rtt, loss, cwnd, pacing
    fn rtt_us(&self) -> Option<u64>;
    async fn close(&self, reason: CloseReason);
}
pub trait Channel: Send + Sync {             // QUIC stream/datagram or WebRTC DC/SRTP
    fn spec(&self) -> &ChannelSpec;           // reliability, ordering, priority, FEC
    async fn send(&self, msg: Bytes) -> Result<()>;
    async fn recv(&self) -> Result<Option<Bytes>>;
}

// sh-media — capture & codec (sync, RT-thread)
pub trait ScreenCapturer {                    // DXGI / ScreenCaptureKit / PipeWire
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<CapturedFrame>>; // + dirty_rects
    fn supports_zero_copy(&self) -> GpuInterop;
    fn set_region(&mut self, r: CaptureRegion) -> Result<()>;
}
pub trait VideoEncoder: Send {                // NVENC/AMF/QSV/VideoToolbox/VA-API
    fn encode(&mut self, f: RawFrame) -> Result<EncodedPacket>;
    fn request_keyframe(&mut self);
    fn set_bitrate_kbps(&mut self, kbps: u32) -> Result<()>;
    fn reconfigure(&mut self, cfg: &EncoderConfig) -> Result<()>;   // Err(RequiresReinit) on chroma change
    fn capabilities(&self) -> &EncoderCaps;
}

// sh-adaptive — GCC / SCReAM behind one seam
pub trait CongestionController: Send {
    fn on_feedback(&mut self, fb: &TransportStats, now: Instant);
    fn target_bitrate(&self) -> Bitrate;
    fn pacing_interval(&self) -> Duration;
}

// sh-platform — input injection (async; some OSes need main-thread dispatch)
#[async_trait] pub trait InputInjector: Send + Sync {
    async fn inject(&self, ev: InputEvent) -> Result<()>;          // pointer/key/scroll/gamepad
    fn capabilities(&self) -> InjectCaps;
}

// sh-crypto — identity & secure storage
#[async_trait] pub trait Keystore: Send + Sync {
    async fn device_identity(&self) -> Result<DeviceIdentity>;     // Ed25519 pub + fingerprint
    async fn sign(&self, data: &[u8]) -> Result<Signature>;
    async fn trust_peer(&self, id: &DeviceIdentity) -> Result<()>; // TOFU pin at pairing
    async fn is_trusted(&self, id: &DeviceIdentity) -> Result<bool>;
    async fn revoke_peer(&self, id: &DeviceIdentity) -> Result<()>;
}
```

---

## 3. Transport & Protocol

### 3.1 SHP wire format

All multi-byte fields are **big-endian**. The SHP payload is **transport-agnostic** — identical bytes
over a QUIC datagram, a QUIC stream, or a WebRTC SRTP/SCTP channel — so a session can switch native↔relay
by re-wrapping, never re-encoding. Encryption is the transport's job (QUIC AEAD / DTLS-SRTP); SHP adds none.

**Capability handshake** (reliable control channel, 4-byte length-prefixed JSON): `shp_version`, `codecs`,
`fec_schemes`, `cc_algo`, `monitors[]`, `channels[]`, `max_datagram_size`, `features[]`. Responder replies
with the negotiated intersection + `session_id`, `selected_codec`, `selected_fec`.

**Common SHP header — 9 bytes** (byte offsets explicit; bit 7 = MSB of each byte):

| Bytes | Field | Size | Notes |
|-------|-------|------|-------|
| 0 (bits 7–6) | VER | 2 bits | version (`01`) |
| 0 (bits 5–2) | CHANNEL | 4 bits | 0=video,1=audio,2=input,3=clipboard,4=file,5=control |
| 0 (bits 1–0) | FLAGS | 2 bits | bit1=FRAG, bit0=LAST_FRAG |
| 1–2 | SEQUENCE | 16 bits | per-channel, wraps 2^16 |
| 3–6 | TIMESTAMP | 32 bits | µs since session epoch (monotonic) |
| 7–8 | PAYLOAD_LEN | 16 bits | payload bytes following header |

Total = 1 + 2 + 4 + 2 = **9 bytes**.

**Video payload header — 12 bytes** (appended after the common header for CHANNEL=0):

| Bytes | Field | Size | Notes |
|-------|-------|------|-------|
| 0–2 | FRAME_ID | 24 bits | monotonic, wraps 2^24 |
| 3 | FRAG_INDEX | 8 bits | fragment index within frame |
| 4 | TOTAL_FRAGS | 8 bits | total fragments for this frame |
| 5 (bits 7–4 / 3–2 / 1–0) | CODEC_ID(4) · FRAME_TYPE(2) · PRIORITY(2) | 8 bits | FRAME_TYPE: 0=P,1=IDR,2=intra-refresh |
| 6 (bits 7–4 / 3 / 2–0) | MONITOR_ID(4) · MARKER(1) · RESERVED(3) | 8 bits | MARKER=last fragment of frame |
| 7 | RESERVED | 8 bits | must be 0 (alignment / future flags) |
| 8–11 | ENCODE_TS | 32 bits | encoder capture µs (latency measurement) |

Total = **12 bytes**. Payload follows as raw NAL (H.264/H.265) or OBU (AV1) fragment.

**Input event — 14 bytes content + 2 bytes pad → 16:**

| Bytes | Field | Size | Notes |
|-------|-------|------|-------|
| 0 | EVENT_TYPE | 8 bits | move/button/wheel/key/touch/pen |
| 1 | MODIFIER_FLAGS | 8 bits | shift/ctrl/alt/meta/caps |
| 2–3 | POINTER_X | 16 bits | normalized 0–65535 |
| 4–5 | POINTER_Y | 16 bits | normalized 0–65535 |
| 6 | BUTTON_MASK | 8 bits | mouse buttons |
| 7–8 | KEY_CODE | 16 bits | USB HID usage id |
| 9–10 | SCROLL_X | int16 | px·8 fixed-point |
| 11–12 | SCROLL_Y | int16 | px·8 fixed-point |
| 13 | PRESSURE | 8 bits | stylus/touch 0–255 |
| 14–15 | RESERVED | 16 bits | pad to 16-byte alignment; gamepad axes reuse this in a typed extension |

Total = 14 bytes content + 2 pad = **16 bytes**.

**Feedback (RTCP-equivalent, native path):** `REPORT_TYPE(8)`, `SSRC(32)`, `HIGHEST_SEQ(16)`,
`CUMULATIVE_LOST(24)`, `FRACTION_LOST(8)`, `JITTER(32 µs)`, `RTT(32 µs)`, `BWE(32 kbps)`, `NACK_BITMAP(16)`.
WebRTC path uses standard RTCP (RFC 3550/4585/5104) plus SHP feedback on the control channel for GCC.

### 3.2 Channel → transport mapping

| Channel | Semantics | QUIC carrier | WebRTC carrier |
|---------|-----------|--------------|----------------|
| video | drop-stale | Datagram (RFC 9221) | SRTP/RTP (PT 127), AVPF feedback |
| audio | drop-stale + FEC | Datagram | SRTP/RTP (PT 126), Opus in-band FEC |
| input | reliable, ordered, **highest** | Stream, urgency 0 (RFC 9218) | DC `ordered, maxRetransmits=null` |
| clipboard | reliable, ordered | Stream, urgency 2 | DC ordered reliable |
| file | reliable, **congestion-isolated** | Stream per transfer, urgency 6, incremental | separate DC per transfer |
| control/RPC | reliable, ordered | Stream 0, urgency 1 | DC `shp-control` |

Input is urgency 0 (strictly highest) and control/RPC urgency 1, so the QUIC scheduler always drains
pending input ahead of control messages (a resolution-change RPC must never delay a keystroke).
Per-stream QUIC flow control / separate WebRTC DCs give file transfer its own back-pressure so it can't
HoL-block input.

### 3.3 Q1 — Transport finalization

**Decision: WebRTC-first for v1, native QUIC promotion in v1.1; both behind the `Transport` seam.**
Browser support forces WebRTC regardless, so build it first and never carry it as risk. The native QUIC
wins (connection migration, unreliable datagrams, lower handshake RTT) are *optimizations over* a working
baseline. Doing both stacks simultaneously doubles peak integration risk, so **sequence** them. **Phase-0
exception:** the internal latency lab uses bare `quinn` (no ICE/crypto) to isolate the codec/render budget.
`sh-ice` is shared across both paths; the only place that knows which controller (GCC vs SCReAM) applies is
the backend constructor — invisible to `sh-core`. Negotiated via `transports: [quic, webrtc]` capability list.

### 3.4 Connection establishment (native, two NATs, one STUN + one TURN)

Candidates (host / srflx via STUN / relay via TURN) gather **in parallel**; trickle-ICE flows through the
signaling server, which exits the path after `END_OF_CANDIDATES`. Rough budget: srflx pair connects ~100ms,
QUIC handshake done ~110ms (0-RTT on resume), first frame ~115ms; symmetric-NAT relay fallback ~210–220ms.
Failures: STUN miss → host+relay only; ICE timeout 5s → ICE restart; path RTT >2× baseline 3s → re-probe.

---

## 4. Networking Details

### 4.3 Q4 — Relay steering: latency-probe-based

BGP-anycast picks the topologically nearest PoP, not the lowest end-to-end relay RTT, and is impractical
for self-hosters. **Both peers STUN-probe all configured coturn candidates** (3 probes each, median RTT);
the signaling server scores `RTT_initiator + RTT_responder + 0.5·jitter` and selects the minimum, keeping a
standby within 10ms. **TURN credentials** are short-lived HMAC (coturn REST style): `username =
"<expiry>:<user_id>"`, `password = base64(HMAC-SHA1(K, username))`, default TTL 1h with 50-min refresh;
revocation by rotating `K`. Plain TURN runs on UDP/3478 (primary). TURNS (TURN-over-TLS) uses its IANA
default TCP/5349 (RFC 8656); we additionally deploy TURNS on **TCP/443** as a deliberate firewall-bypass
option for restrictive networks.

### 4.4 Q7 — Loss recovery policy (tiered, RTT-adaptive)

Rolling intra-refresh (period `ceil(fps/4)`) is **always on** (~8–12% overhead, self-heals without
signaling). On video loss:

1. **NACK** if `RTT < 100ms AND consecutive_loss ≤ 2`; wait ≤1·RTT for retransmit.
2. else rely on **FEC** if `loss_5s < fec_ratio AND frame_gap ≤ 1`.
3. else **forced IDR** (keyframe request) if any of: `frame_gap ≥ 3`, `RTT ≥ 200ms + recent loss`,
   `loss_5s ≥ 5%`, or `>10s since keyframe + >1% loss`. Suppress further requests for `max(500ms, 2·RTT)`.

By RTT band: <50ms NACK-first; 50–150ms NACK isolated/FEC burst/IDR at gap≥3; 150–300ms skip NACK, FEC+refresh,
IDR at gap≥2; >300ms FEC+refresh only, IDR on any freeze. **Audio:** always RFC 2198 redundancy (50% overhead,
cheap), never NACK, Opus PLC for residual loss.

---

## 5. Media Pipeline

### 5.1 Q2 — Codec & licensing (the crux)

**OSS (Apache-2.0) default: AV1, with H.264 via OS system codec APIs only. Commercial build adds HEVC.**

- **AV1** is genuinely royalty-free (AOM pledge) → clean for Apache-2.0. Gated by HW encode availability
  (NVENC Ada+, AMF RDNA3+, QSV Arc/Xe-LP). **Apple is the exception** — VideoToolbox has no AV1 *encode*;
  macOS OSS hosts fall back to H.264.
- **H.264 in OSS = OS-API only** (`VideoToolbox`/`Media Foundation`/`VA-API`), **never** bundling `x264`/
  `openh264`. The defensible boundary (used by OBS, browsers, WebRTC): we call a system-provided codec, we
  are not a "licensed encoder implementor." Not zero-risk, but the industry-standard line.
- **HEVC** ships in the **commercial** build (same OS-API pattern + a commercial HEVC license / enterprise
  device-license representation). Neither build bundles `x265`.
- **Negotiation/degradation:** OSS Game Mode `AV1 HW → H.264 HW(OS) → H.264 SW(last resort, rate-limited)`;
  commercial `HEVC HW → AV1 HW → H.264 HW(OS)`. Work Mode never SW-encodes. Browsers always offer H.264 decode.

### 5.2 Q3 — Content classifier (heuristic, v1)

Four cheap signals (sub-ms), sampled every 4 frames: **A** inter-frame macroblock diff on ¼-res luma
(fraction of 8×8 blocks with MAD>12), **B** OS dirty-rect coverage (DXGI/SCK/PipeWire damage), **C**
foreground-app class mapped to a scalar (`GAME→1.0, MEDIA→0.5, WORK→0.0`; fullscreen-exclusive ⇒ GAME),
**D** cursor velocity (normalized to 2000 px/s, clamped to 1.0).

`score = 0.45·A + 0.30·B + 0.15·C + 0.10·D` (all terms in [0,1]). **Hysteresis FSM** `WORK | SCROLLING | GAME`: enter GAME at
score>0.65 held 8 ticks; exit GAME at score<0.40 held 30 ticks (asymmetric dwell so a brief alt-tab doesn't
re-encode as Work). SCROLLING is Game-encode params + Work frame-rate. v2 ML swaps a `Box<dyn ScoreProvider>`
(ONNX MobileNetV3 on the same ¼-res luma); the FSM is unchanged.

### 5.3 Q6 — Multi-GPU zero-copy

At startup probe display-adapter LUID vs best-encoder LUID. **Same adapter → zero-copy** (DXGI texture
registered directly into NVENC; IOSurface→VideoToolbox; DMA-BUF→VA-API). **Cross-adapter** (iGPU display +
dGPU NVENC): capture on iGPU, **single pinned-memory copy** (`cuMemAllocHost` → NVENC `CUDADEVICEPTR`,
~0.375ms @1080p, ~1.5ms @4K — bounded, no jitter) and encode on the faster dGPU; expose `Encode GPU:
Auto/iGPU/dGPU`. Linux: probe `cuImportExternalMemory` on a test DMA-BUF; if cross-device import is
unsupported (IOMMU/P2P), fall back to PipeWire shmem capture (one extra copy, the safe default).

### 5.4 Threading, buffers, mode switches

Stages on dedicated threads, bounded queues: Capture(cap 2)→Preprocess(2)→Encode(8)→Packetize(16)→tokio I/O.
**Backpressure:** Game Mode drop-oldest (stale frame worthless); Work Mode skip-current frame when the encoder is busy
(a subsequent OS damage event re-sends the affected region, so nothing is lost), except large
dirty-cov>0.8 blocks one frame to avoid skipping a major update. **Jitter buffer:** Game 2–4 frames / ~20ms target; Work 1 frame
min / up to 200ms; statistically sized (EWMA, α=0.01 Game / 0.05 Work). **Mode switch glitch-free** via
**double-buffered encoders**: prime a new encoder with a forced IDR, atomically swap routing, drain+destroy
the old — one ~16ms decoder re-sync at the SPS/PPS change (imperceptible), portable across vendors (avoids
unreliable mid-session 4:2:0↔4:4:4 reconfigure). Mind **NVENC consumer session limits** (3–5) during the
overlap; track an `Arc<AtomicU32>` session counter and defer destroying the old session until the new allocates.

---

## 6. Security & Crypto

> **Applies from Phase 3 onward.** Phases 0–2 (§8) are an explicit latency/functionality lab on bare QUIC
> over trusted LANs with no auth. The crypto below is introduced in Phase 3 and is mandatory for any build
> that connects over untrusted networks (Phase 4+).

### 6.1 Q5 — Unattended custody & recording keys

**Unattended = host-issued, hardware-bound Unattended Grant Certificate (UGC)** — not a server token, not a
stored controller secret. The host's TPM/SE/StrongBox identity key signs a UGC delegating scoped access to a
**specific controller device_id**, gated by **WebAuthn/FIDO2 at enrollment** (not per-connect). The UGC is
inert without the controller's non-exportable hardware key (connect requires a live `Noise_IK` as
`grantee_id`); a stolen UGC file alone is useless. Offline revocation via a **host-local monotonic
`min_epoch`** (every UGC carries `epoch`; bumping the floor kills sub-epoch grants with zero network).
Off by default, view-only default caps, ≤30d lifetime + idle expiry.

**Session recording = hybrid envelope encryption.** Per-recording AES-256-GCM DEK (chunk-ratcheted via
HKDF), wrapped (HPKE, RFC 9180) to a recipient set: `{operator device, customer-KMS escrow KEK, optionally
host}`. **Hosted infra is never a recipient → cannot decrypt.** Escrow KEK lives in the *customer's*
KMS/HSM under their IAM (optional M-of-N quorum) so e-discovery works without Streamhaul touching plaintext.

### 6.2 Handshake & identity binding

Native: `quinn` QUIC carries an opaque stream; **authentication is a Noise tunnel inside** (relay stays
blind). `Noise_XK` at first pairing (hides controller identity from the relay), `Noise_IK` thereafter
(host static pinned, 1-RTT). Noise static keys are X25519; device identity is Ed25519 — bound by an
identity-signed **`BindCert`** = `sign(identity, {device_id, noise_static, dtls_fpr_commit, platform_attest,
not_after})`, exchanged inside the handshake and checked against the live static key. **SAS** for attended
pairing is derived from the Noise handshake hash `h` (a MITM can't make both sides compute the same `h`);
**SPAKE2/OPAQUE** PAKE over the pairing code for the no-human-at-host case.

**WebRTC binding:** the DTLS SPKI fingerprint is committed inside the identity-signed `BindCert` and pinned
over the authenticated channel; the **signaling-supplied SDP fingerprint is not trusted** — a swap →
mismatch → abort. Same hardware-identity trust root as native; kills the classic WebRTC signaling MITM.

### 6.3 Key hierarchy (what the relay can never see)

`Device Identity (Ed25519, HW, non-exportable)` → signs UGC, BindCert, audit receipts. `Noise static
(X25519, BindCert-bound)`. **Per-connection ephemerals (PFS)** → **native-path session transport keys
(Noise AEAD: ChaCha20-Poly1305 or AES-256-GCM, rekey ≤2²⁰ msgs or 15min)** → **per-channel subkeys (HKDF,
ratchet every N frames)**. The **WebRTC path** does not use the Noise AEAD ciphers above — its media cipher
is **SRTP AES-128-GCM negotiated from the DTLS handshake export**, fixed by DTLS, not by this hierarchy. Recording DEK + customer escrow KEK separate. **Relay/signaling sees only**
opaque ciphertext, public `device_id` fingerprints, routing metadata, opaque audit blobs — the enforced
zero-knowledge boundary.

### 6.4 Authorization, kill-switch, revocation

Per-session **capability mask** (`VIEW/CONTROL/CLIPBOARD/FILE/ELEVATION/AUDIO/…`) = most-restrictive of
{device ACL, UGC.caps, attended selection, account policy}, **enforced host-side on every privileged action**,
**sealed immutable** for the session (no in-band "upgrade"; ELEVATION needs fresh presence/MFA). **Kill-switch**
zeroizes session/channel keys in RAM instantly → post-kill ciphertext fails AEAD → no input actuates; no
network needed. **Revocation = short-lived re-issued stapled allow-lists + host-local epoch floor** (fail-closed,
offline-survivable), not push-CRL. Tamper-evident **hash-chained audit log** with head-hash anchoring.

### 6.5 Threat-model deltas

Stolen-UGC replay (inert w/o HW key), infra-skeleton-key (infra holds no granting secret/DEK), offline
revocation (epoch floor), mid-session escalation (sealed caps), signaling DTLS-MITM (pinned BindCert),
relay content read (E2E), cloned-host impersonation (non-exportable key + attestation), recording-store
breach (infra not a recipient), escrow abuse (customer KMS + quorum + audit), audit tampering (hash chain),
kill-switch race (RAM key zeroization), downgrade-pairing (SAS/PAKE mandatory). Full table in git history of
this section.

---

## 7. Rust Implementation Strategy

### 7.1 Errors & lint enforcement

Libraries use `thiserror` (typed); binaries use `anyhow` at the `main`/task boundary. **CLAUDE.md panic ban
is machine-enforced** via workspace lints:

```toml
[workspace.lints.clippy]
unwrap_used="deny"  expect_used="deny"  panic="deny"
unreachable="deny"  todo="deny"  unimplemented="deny"
indexing_slicing="warn"  arithmetic_side_effects="warn"
[workspace.lints.rust]
unsafe_op_in_unsafe_fn="deny"  unused_must_use="deny"  missing_docs="warn"
```
Test modules opt out with `#[cfg(test)] #[allow(clippy::unwrap_used, …)]`. CI runs
`cargo clippy --workspace --all-targets -- -D warnings`. HW init degrades through an ordered candidate list
(NVENC→AMF→QSV/VT→SW), logging each fallback via `tracing`.

### 7.2 Async vs real-time threads

tokio for QUIC/signaling/control/ICE/crypto-handshake; **dedicated priority OS threads** for capture/encode/
audio (`SCHED_RR` 50 / `THREAD_PRIORITY_HIGHEST`, documented `CAP_SYS_NICE` requirement). Bridges: capture→encode
**`rtrb` SPSC (lock-free, zero-alloc, drop-oldest)**; encode→transport **`crossbeam-channel` bounded** (blocking
send = backpressure); tokio-internal **`tokio::sync::mpsc`**. **Buffer pools** (pre-allocated, RAII recycle) +
`bytes::Bytes` for payloads → no steady-state allocation on the frame path. QUIC send-window = natural async
backpressure.

### 7.3 Key dependencies

| Role | Crate | Note |
|------|-------|------|
| QUIC | `quinn` 0.11 | pure-Rust, tokio-native |
| WebRTC (native peers) | **`str0m`** | sans-IO Rust WebRTC for the host/native-client WebRTC path; chosen over feature-frozen `webrtc-rs`. The **browser** uses its own `RTCPeerConnection` (web-sys), not str0m. |
| TLS | `rustls` + `aws-lc-rs` | `ring` backend feature-gated for WASM |
| Noise | `snow` | maintained but **unaudited — wrap + note in SECURITY.md** |
| Identity/ECDH | `ed25519-dalek`, `x25519-dalek` 2.x | `zeroize` integration |
| Wire (control) | `prost` (proto3) | explicit field numbers → version-skew safety |
| Hot-path serde | `postcard` | same-version intra-process |
| Channels | `rtrb` (SPSC), `crossbeam-channel` (MPMC) | `flume` rejected (maintenance mode) |
| GPU/OS | `windows-rs`, `objc2`+`metal`, `pipewire-rs`, `libva-sys` | per platform |
| Codecs | `nvenc-sys`/`amf`/`vpl-rs`/`objc2-video-toolbox`/`rav1e`/`openh264`/`opus` | via `VideoEncoder` |
| MFA / envelope | `webauthn-rs`, `hpke` (CFRG-compliant, RFC 9180) | |
| Obs/CLI/config | `tracing`, `clap`, `config` | |

**WASM constraints:** no tokio/`quinn`/`rtrb`/`str0m` in the browser; the browser path drives the native
`RTCPeerConnection` via `web-sys` (the browser handles ICE/DTLS/SRTP), with SHP framing on data channels.
Crypto that does run in WASM uses `rustls`+`ring` and `getrandom` (js feature); `prost`/`snow`/`sh-protocol`
compile to WASM for wire-parity and any client-side handshake logic.

### 7.4 Testing infrastructure

Hand-written test doubles (not `mockall`) for hot-path traits; an **in-memory `LoopbackTransport`** for full
pipeline integration tests without network; **injected `Clock` + seedable RNG** (no `Instant::now()`/`OsRng`
in testable code); **`proptest`** on the SHP parser (arbitrary bytes never panic; roundtrip); **`cargo-fuzz`**
targets for packet + Noise-handshake decoding (untrusted input); **`loom`** for the lock-free pool/queues;
**`cargo-llvm-cov`** with CI gates ≥80% on `sh-protocol`, `sh-crypto`, `sh-transport` (security-critical).

---

## 8. Milestone Build Plan

Each phase is internally demoable and gated. Target: **glass-to-glass < 30ms LAN @ 60fps** (Phase-0 gate).

| Phase | Goal | Exit criteria | Crates |
|-------|------|---------------|--------|
| **0 Hello Pixels** | Win host→native client, LAN, H.264, bare QUIC, no auth/adaptivity | live render; ≤~30ms LAN; zero-copy DXGI→NVENC confirmed; 10-min stable | sh-types, sh-protocol(min), sh-transport(quinn), sh-media, sh-codec-hw(NVENC), sh-platform-win(capture), sh-render |
| **1 Input + channels** | Bidirectional control; real `Transport`/`Channel` multi-channel; audio | click-to-photon measured; audio in sync; input never starved | +input shim, sh-transport trait, Opus |
| **2 Adaptivity** | SCReAM + rate allocator + classifier + encoder reconfigure; HEVC enabled (commercial) | smooth adapt under loss/caps; Game↔Work no flapping; keyframe recovery | sh-adaptive |
| **3 Security & pairing** | E2E crypto, Ed25519 identity, TOFU pin, encrypted channels | first-pair TOFU; unpinned MITM rejected; all channels E2E; rotation tested | sh-crypto, keystores |
| **4 Connectivity (WebRTC)** | WebRTC backend, signaling, ICE/STUN + coturn, zero-knowledge relay | connects across symmetric NAT via relay; relay carries opaque ciphertext | sh-signaling, sh-ice, sh-transport(str0m)+GCC, deploy |
| **5 Browser client** | Browser viewer/controller, H.264 fallback | Chrome/FF/Safari view+control; H.264 negotiated; same relay path | sh-wasm (TS app) |
| **6 Cross-OS hosts** | macOS + Linux host parity | all 3 OSes zero-copy capture→encode; perms handled; host↔client matrix green | sh-platform-mac, -linux |
| **7 File transfer** | Reliable congestion-isolated transfer | large transfer doesn't degrade video QoE; resumable; integrity-checked | file channel |
| **8 QUIC promotion + mobile** | native↔native QUIC (migration); thin mobile | native auto-selects QUIC; survives network change; mobile via sh-ffi | sh-ice/QUIC, sh-ffi |

Phases 0–3 are serial; 5 and 6 can parallelize after 4; 7 and 8 slot opportunistically.

---

## 9. Open Items for Implementation

- **Noise hash primitive — DECIDED (ADR-0005):** the Noise spec offers SHA-256, SHA-512, and BLAKE2s with
  no implied default; we use **SHA-256** so the SAS derivation and `BindCert` hashing share one primitive.
  Implementation task: pin the concrete pattern names (e.g. `Noise_IK_25519_ChaChaPoly_SHA256`) before Phase 3.
- **Platform attestation envelope:** normalize TPM 2.0 quote vs Apple App Attest vs Play Integrity into one
  `platform_attest` schema.
- **UGC lifetime per compliance tier** (HIPAA/PCI may require ≤7d) and **escrow quorum schema** (SOC 2 / e-discovery).
- **`snow` audit posture:** document unaudited status; consider a security review before GA.
- **`str0m` vs `webrtc-rs`** final validation against Safari interop in Phase 4/5.
- Confirm **NVENC session-limit** behavior across current driver branches during the double-buffer overlap.

---

*This LLD is the authoritative engineering design. Major decisions are mirrored as ADRs:
`docs/adr/0003-transport-finalization.md`, `docs/adr/0004-oss-codec-and-licensing.md`,
`docs/adr/0005-unattended-access-and-recording-keys.md`. The contribution and change process
(branch → tests/review gate → PR → green CI → merge) is defined in [`CONTRIBUTING.md`](./CONTRIBUTING.md).*
