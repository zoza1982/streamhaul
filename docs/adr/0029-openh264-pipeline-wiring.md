# ADR 0029: OpenH264 pipeline wiring — configurable encoder, factory, decoder, fragment-compat proof

- **Status:** Accepted
- **Date:** 2026-06-28
- **Deciders:** realtime-systems-engineer, rust-staff-engineer, security-engineer (consulted)
- **Builds on:** ADR-0028 (the workspace-excluded `sh-codec-openh264` crate)

## Context

ADR-0028 landed `OpenH264Encoder` as an isolated, workspace-excluded crate, proven only by a
standalone encode→decode round-trip. To actually feed a session we need three more things, and we
need them **without breaking ADR-0028's two invariants**:

1. **C-isolation:** `cargo build/clippy/test --workspace --all-features` (run by `lint` + `test` on
   all three OSes) must never compile the vendored OpenH264 C.
2. **Licensing:** the default OSS build — and in particular the default `streamhaul-host` binary —
   must link **no** H.264 encoder (Cisco's grant covers only the pre-built binary, not from-source).

The pipeline itself is already codec-agnostic: `sh_core::run_host_pipeline` / `run_client_pipeline`
take `&mut dyn VideoEncoder` / `&mut dyn VideoDecoder`, and `sh_media::EncoderConfig` already carries
`target_bitrate_kbps` + `target_fps`. The `sh_adaptive::RateAllocator` already yields a per-channel
video `Bitrate`. So the missing pieces are purely inside the excluded crate plus the glue type.

## Decision

Add the following **entirely inside the excluded `sh-codec-openh264` crate** (so both invariants hold
structurally — the default workspace build still never touches any of it):

1. **`OpenH264Encoder::with_config(&sh_media::EncoderConfig)`** — maps the negotiated/allocated config
   onto OpenH264: `target_bitrate_kbps` → `.bitrate(BitRate::from_bps(kbps*1000))` +
   `RateControlMode::Bitrate` (or leave OpenH264's default `Quality` mode when bitrate is `None`);
   `target_fps` → `.max_frame_rate`; and `UsageType::ScreenContentRealTime` (remote desktop, not
   camera). `new()` is retained as "OpenH264 defaults". This is how the **`RateAllocator` target reaches
   the encoder**: the host sets `EncoderConfig.target_bitrate_kbps = Some(alloc.video().as_kbps())`.

2. **`openh264_encoder_factory() -> sh_codec_hw::mode_switch::EncoderFactory`** — a boxed
   `FnMut(&EncoderConfig) -> Result<Box<dyn VideoEncoder>, MediaError>` that builds an
   `OpenH264Encoder::with_config`. This is the seam the existing `ModeSwitchEncoder` already drives for
   glitch-free mid-stream codec/bitrate switches — OpenH264 now slots in exactly where NVENC will,
   with no pipeline changes. (Adds a `sh-codec-hw` path dep to the excluded crate for the type alias.)

3. **`OpenH264Decoder`** implementing `sh_media::VideoDecoder` — decodes Annex-B back to a
   `VideoFrame` (`PixelFormat::Bgra8`, via OpenH264's `write_rgba8` + R/B swap), returning `Ok(None)`
   when the decoder needs more input. Needed for any native H.264 client and for the round-trip proof.
   (The browser remains the production decoder via WebCodecs; this is the native/test decoder.)

4. **A deterministic pipeline-compatibility test** — `encode → sh_core::fragment → sh_core::Reassembler
   → decode`, asserting frames survive fragmentation/reassembly and decode to the correct
   resolution/format. This exercises the **exact** host→wire→client packetization path with real
   OpenH264 Annex-B output (multi-NAL, variable size), **without** any QUIC/async/network — fully
   deterministic per CLAUDE.md §5 (no network/clock/random flakiness). `sh-core` is a **dev**-dependency
   of the excluded crate, so it compiles only in the `codec-openh264` CI job.

### Why not wire it into the `streamhaul-host` binary now

That binary is a workspace member; depending on (or feature-gating) the encoder there would either
compile the C under `--all-features` on every OS (invariant 1) or link H.264 into the default build
(invariant 2). A runnable H.264 host therefore belongs in a **separate, workspace-excluded** preview
binary — deferred to the browser↔live-host work (the next step), where a real H.264 client exists. The
deterministic fragment-compat test proves the same wiring in CI today, which CLAUDE.md values over a
manual-only binary.

### Real-time decisions (from the realtime-systems-engineer review)

- **Single frame-drop mechanism:** OpenH264's own `enable_skip_frame` is **disabled**
  (`skip_frames(false)`). The pipeline's backpressure/pacing is the only frame-drop path, so encoder
  skips can't silently create non-contiguous frame ids (indistinguishable from packet loss) or swallow
  a forced IDR under bitrate pressure.
- **Keyframe-request durability:** `request_keyframe()` arms a flag that is cleared **only when a real
  IDR packet is emitted** — never on a skipped/empty/errored encode. A loss-recovery keyframe request
  is therefore never lost.
- **Keyframe semantics:** only a true `IDR` maps to `FrameType::Idr` (a valid mid-stream join / seek /
  recovery point). Non-IDR `I` and `IPMixed` map to `FrameType::IntraRefresh` — intra-coded but they do
  not flush reference buffers, so the receiver must not treat them as seek points.

## Consequences

- **Positive:** OpenH264 is now a drop-in, bitrate-configurable `VideoEncoder` behind the existing
  `EncoderFactory`/`DoubleBufferedEncoder` seam, with a native decoder and a deterministic proof that
  its output survives the real packetization path. Both ADR-0028 invariants are preserved structurally.
- **Negative / trade-offs:** the `codec-openh264` CI job now also compiles `sh-core` (+ its transport
  deps) for the dev-only integration test (longer job, still isolated). The decoder emits BGRA via a
  YUV→RGB pass (lossy, as expected for H.264) — the round-trip test asserts dimensions/format + channel
  order (within tolerance), not byte-equality. OpenH264's own rate control is used; finer pacing/QP
  control is a follow-up.
- **Tracked follow-ups (NOT addressed here — do not use this preview path for latency baselines):**
  - **Hot-path color-conversion cost:** encode does BGRA→RGB then RGB→YUV (two full-frame passes, no
    SIMD); decode does YUV→RGBA, an in-place R↔B swap, then a `Bytes` copy (three passes + a per-frame
    allocation). A single-pass YUV→BGRA writing straight into the output `Bytes` is the obvious win.
    The HW encoders (R-CODEC) consume capture formats directly and avoid most of this.
  - **Dynamic resolution change:** OpenH264 re-initializes internally when frame dimensions change,
    a synchronous stall (~ms) on the encode thread. Tested for correctness (a valid IDR is produced);
    the latency spike is a known preview limitation.
  - **Real QUIC path (before the live path ships):** the deterministic test covers fragmentation +
    reassembly but NOT datagram **loss** (a lost fragment ⇒ the frame never reassembles; reassembler
    timeout/eviction must be verified), **reordering** (intra-frame datagram order isn't guaranteed),
    or **multi-frame interleaving** (adjacent frames' fragments interleave under pacing). These are
    exercised by the e2e harness with the next step's preview host, not here.
- **Follow-ups:** a workspace-excluded preview host binary + the browser↔live-host session glue (next
  step); driving `EncoderConfig` from the live `RateAllocator` inside that host; HW encoders (R-CODEC).

## Alternatives considered

- **Feature-gate the dep on `streamhaul-host`** — rejected: `--all-features` would compile the C on all
  OSes and link H.264 into the default build, breaking both ADR-0028 invariants.
- **QUIC-loopback integration test** — rejected for the in-crate proof: introduces async/network
  non-determinism (datagram loss, timing) that CLAUDE.md §5 forbids; `fragment`/`Reassembler` cover the
  same packetization surface deterministically. (A live QUIC path is exercised by the preview binary +
  e2e harness in the next step.)
