# ADR 0028: Software H.264 encoder (OpenH264) — workspace-excluded crate

- **Status:** Accepted
- **Date:** 2026-06-28
- **Deciders:** realtime-systems-engineer, rust-staff-engineer, security-engineer (consulted)

## Context

The pipeline had only `RawEncoder` (uncompressed) — so the browser client (which decodes **H.264**
via WebCodecs) could never display real video, and the native path sent multi-MiB raw frames. The
`VideoEncoder` trait and codec **negotiation** (H264/H265/AV1, P2-5) already exist; only an actual
compressing encoder was missing. Hardware encoders (NVENC / VA-API / VideoToolbox / Media Foundation)
are the intended low-latency path but need real GPUs/drivers and can't be verified in this headless
environment (R-CODEC / R-LINUX-VAAPI / R-MAC-SCK).

A **software** encoder is the pragmatic way to unblock a real (CI-verifiable, browser-decodable)
video path. The options:

| Option | License | Verdict |
|---|---|---|
| **x264** (libx264) | **GPL** | ❌ Incompatible with this repo's Apache-2.0 OSS license. |
| **OpenH264** (`openh264` crate) | BSD-2 code; Cisco royalty-free **binary** grant | ✅ Chosen — pure-Rust-ish wrapper over vendored C; browser decodes H.264 natively; builds + runs in CI. |
| **rav1e** (AV1) | BSD, pure-Rust, royalty-free codec | Viable but AV1 (browser AV1-decode work) + slow software encode. Deferred alternative. |
| Pure-Rust H.264 | — | ❌ None production-grade. |

## Decision

Add **`OpenH264Encoder`** in a **new, workspace-EXCLUDED crate `sh-codec-openh264`**, implementing
`sh_media::VideoEncoder`. It converts a `PixelFormat::Bgra8` frame (even dimensions) BGRA→RGB→YUV and
emits **Annex-B** H.264 (`EncodedPacket{codec: H264, frame_type}`) that a browser `VideoDecoder` can
decode. `request_keyframe()` maps to OpenH264's `force_intra_frame()`. OpenH264's frame types map to
`sh_protocol::FrameType` as: `IDR`/`I` → `Idr` (full intra, valid seek point); `IPMixed` →
`IntraRefresh` (mixed I+P slices — an intra refresh that still depends on prior frames, **not** a
seek point); `P` → `Predicted`; `Skip`/`Invalid` → no packet (`Ok(None)`).

**Why an excluded crate, not a feature on `sh-codec-hw`:** a Cargo feature would be enabled by
`cargo build/clippy/test --workspace --all-features` — which the `lint` + `test` CI jobs run on
**all three OSes** — forcing the vendored OpenH264 **C build** onto every cross-OS run (slow, and a
real risk to the green Windows/macOS jobs). Excluding the crate from the workspace (the exact pattern
the wasm crates use) keeps `--all-features` from ever touching it; it is built only by its dedicated
`codec-openh264` job and by a build that explicitly depends on it. This also sharpens the licensing
posture: the default OSS workspace build **literally never links an H.264 encoder.**

### Licensing posture (this is why it is OFF by default)

H.264 is covered by the **MPEG-LA AVC patent pool**. Cisco's royalty-free grant attaches **only to
Cisco's pre-built OpenH264 binary** — **not** to OpenH264 **built from source**, which the
`openh264` crate's `OpenH264API::from_source()` does. So linking `sh-codec-openh264` is a
**licensing-gated, preview / non-distribution** choice, exactly mirroring the existing `hevc` feature
posture (`docs/adr/0004-oss-codec-and-licensing.md`). The default OSS build does not enable it and
does not link any H.264 encoder. A distributable build must either license H.264 or use the system/HW
encoder path. This is documented on the crate, the module, and `new`.

### Dependency / supply chain

`openh264 = "=0.9.3"` (pinned) in the excluded `sh-codec-openh264` crate. It builds the **vendored OpenH264 C source** via `cc`
(+ `nasm` for SIMD when present; falls back to portable C otherwise). No `unsafe` in *our* code — the
FFI lives inside the vetted `openh264`/`openh264-sys2` crates. `cargo audit` must stay clean.

### Verification

- A **round-trip unit test** (feature-gated): encode a synthetic BGRA frame → assert `Codec::H264` +
  `FrameType::Idr` + Annex-B start code → **decode it back with OpenH264** and assert the dimensions.
  This proves the output is valid, decodable H.264 — not just non-empty bytes.
- Hostile-input/edge tests: odd dimensions and non-BGRA input are rejected (`MediaError::Encode`);
  caps report software H.264.
- A dedicated **`codec-openh264` CI job** (Linux) builds + clippy + tests the excluded crate via
  `--manifest-path` (the default `--workspace --all-features` build/clippy/test never touches it).

## Consequences

- **Positive:** a real, CI-verified, browser-decodable H.264 encoder — unblocks the host→browser video
  path. Off by default, so the OSS build and every other crate are unchanged. No `unsafe` in our code.
- **Negative / trade-offs:** licensing-gated (patent posture above); software encode is CPU-heavy and
  not the low-latency destination (HW encode is, R-CODEC); v1 uses OpenH264's default rate control
  (bitrate/fps tuning from the allocator is a follow-up); requires a C toolchain to build the feature.
- **Follow-ups:** wiring into the pipeline + feeding the `RateAllocator` target is **done in
  ADR-0029** (configurable encoder, `EncoderFactory`, native decoder, deterministic fragment-compat
  test). Remaining: a workspace-excluded preview host binary + browser↔live-host glue that invoke the
  factory; HW encoders (R-CODEC); the `rav1e`/AV1 royalty-free alternative if H.264 licensing is
  undesirable for a distribution.

## Alternatives considered

- **x264** — GPL, license-incompatible. Rejected.
- **rav1e (AV1)** — royalty-free + pure-Rust (no C build), but the browser needs AV1-decode wiring and
  software AV1 encode is slower; kept as the licensing-clean alternative if H.264 patents are a
  blocker for shipping.
- **Stay raw-only** — rejected: blocks the browser video path indefinitely.
