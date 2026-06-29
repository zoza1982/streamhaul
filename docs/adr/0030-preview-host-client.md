# ADR 0030: Preview host/client — real-screen OpenH264 video over QUIC

- **Status:** Accepted
- **Date:** 2026-06-29
- **Deciders:** realtime-systems-engineer, network-engineer (consulted), security-engineer (consulted)
- **Builds on:** ADR-0028 / ADR-0029 (the workspace-excluded `sh-codec-openh264` crate + pipeline wiring)

## Context

After ADR-0029, OpenH264 is a pipeline-ready codec, but nothing **runnable** exercises the full
real slice: capture the actual screen → compress with H.264 → move it over QUIC → decode it back.
The native `streamhaul-host`/`streamhaul-client` bins use a synthetic capturer and the raw (lossless)
codec; the real screen capturers (P6, `sh-platform-linux`) and OpenH264 had never been run together
end-to-end. We want a binary the developer can run locally to *see* the screen streamed, and a
CI-verifiable proof the slice holds together.

The hard constraint is unchanged from ADR-0028/0029: anything linking OpenH264 must stay **out of the
default workspace build** (the C must not compile under `--workspace --all-features`, and the default
OSS build must link no H.264 encoder, for licensing).

## Decision

Add a **workspace-excluded** crate `bins/streamhaul-preview` with two binaries and a shared lib:

- **`streamhaul-preview-host`** — binds QUIC (`InsecureLanLab` self-signed, LAN-lab only), captures the
  screen (X11 via `sh-platform-linux` on Linux; `SyntheticCapturer` elsewhere or with `--synthetic`),
  OpenH264-encodes at a `--bitrate-kbps` target, and streams over `sh_core::run_host_pipeline`. Prints
  `PREVIEW_HOST_ADDR=<addr>` for harnesses.
- **`streamhaul-preview-client`** — connects, runs `sh_core::run_client_pipeline` with
  `OpenH264Decoder` + a `CollectingSink`, writes the first/last decoded frames as PPM (visual
  confirmation), and prints delivery stats. Exits non-zero if zero frames decode.
- **`EvenDimCapturer<C>`** — a `ScreenCapturer` adapter that crops frames to **even** dimensions
  (OpenH264's 4:2:0 needs them; a real display/root window may be odd). Even frames pass through with
  no copy.

It is **excluded** from the workspace (same rationale and pattern as `sh-codec-openh264`) and depends
on `sh-platform-linux` only on `cfg(target_os = "linux")`. The reusable `serve`/`receive` helpers live
in the lib so the bins and the test share one code path.

### Verification

- **Deterministic loopback integration test** (`tests/loopback.rs`): synthetic capture → OpenH264 →
  **real QUIC** (127.0.0.1) → OpenH264 decode, in-process. Goes beyond ADR-0029's fragment/reassemble
  unit test by driving the actual datagram transport. No display ⇒ runs anywhere; asserts delivery +
  well-formed frames (not an exact count, since QUIC datagrams are unreliable).
- **Xvfb smoke** in the dedicated `preview` CI job: launches `streamhaul-preview-host` (real X11
  capture under `xvfb-run`) and `streamhaul-preview-client`, asserting ≥1 real frame decodes — the
  real capture→encode→QUIC→decode path on a real (in-memory) X server.

## Consequences

- **Positive:** a runnable, locally-demoable real-screen H.264-over-QUIC slice, plus CI proof (both a
  deterministic transport test and a real-capture Xvfb smoke). Both ADR-0028 invariants preserved.
- **Negative / trade-offs:** the QUIC path uses datagrams (unreliable) with no FEC/NACK yet, so under
  loss some frames never reassemble (P2 loss-recovery is future work); the preview reuses OpenH264's
  rate control and the unoptimized color-conversion path (ADR-0029 follow-ups — not a latency
  baseline). `InsecureLanLab` skips TLS verification and is for LAN-lab use only, never production.
- **Keyframe fragility under loss (tracked):** the host emits an IDR only for the first frame
  (`request_keyframe` is not called periodically and no GOP/`intra_frame_period` is set), so every
  later frame is a P-frame referencing it. On loopback there is no loss, but on a real lossy network
  losing any fragment of that single keyframe means nothing decodes until recovery. Fix is a periodic
  IDR (GOP via `intra_frame_period`, or a timed `request_keyframe`) + P2 loss recovery (FEC/NACK) —
  deferred with the rest of the live-network work.
- **Follow-ups:** the browser↔live-host path (next) reuses these `serve`/capture pieces but over the
  WebRTC host; input injection back-channel; loss recovery; periodic keyframes.
