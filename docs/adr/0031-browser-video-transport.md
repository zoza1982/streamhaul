# ADR 0031: Browser↔host video transport — host streams baked H.264 over the WebRTC DataChannel

- **Status:** Accepted
- **Date:** 2026-06-29
- **Deciders:** realtime-systems-engineer, security-engineer (consulted), ui-engineer (browser harness)
- **Builds on:** ADR-0028/0029/0030 (OpenH264 codec + preview slice), P5-3 (browser↔native WebRTC)

## Context

The browser viewer is already 100% wired to receive video: `clients/web/src/protocol/frame.ts`
parses an inbound DataChannel message as `CommonHeader(9) || VideoHeader(12) || Annex-B`, and
`clients/web/src/view/decoder.ts` decodes H.264 via WebCodecs onto a canvas (proven by the in-page
`loopback.spec.ts`). The native `streamhaul-webrtc-host`, however, established the identity-bound
Noise/DTLS connection + a DataChannel but only **echoed one frame and exited** — it produced no video.

The goal is staged (chosen with the user): **first** prove the browser↔host video *transport* end to
end in CI; **then** (ADR-0032, next) an excluded host that does live screen capture + on-host OpenH264.

The hard constraint is unchanged: `streamhaul-webrtc-host` is a **workspace member**, so it must not
depend on OpenH264 (that would build the vendored C under `--workspace --all-features` and link an
H.264 encoder into the default OSS build — ADR-0028/0029).

## Decision

Make `streamhaul-webrtc-host` stream a small, **baked** H.264 Annex-B clip as SHP video frames over
the existing "shp" DataChannel, behind a `--stream-video` flag (default keeps the echo path, so the
existing e2e tests are untouched).

- **The clip is pre-encoded bytes, not an encoder.** `crates/sh-codec-openh264/examples/gen_browser_fixture.rs`
  (in the EXCLUDED codec crate) encodes 16 synthetic 320×240 frames with OpenH264 and writes
  `bins/streamhaul-webrtc-host/fixtures/sample_h264.shv` (length+frame-type-prefixed, first frame an
  IDR with SPS/PPS so the browser can configure its decoder). The workspace host `include_bytes!`s the
  fixture — so the default build links **no** H.264 encoder; it only replays bytes. The generator is
  reviewable + reproducible.
- **Framing reuses `sh-protocol`.** The host assembles each frame with `CommonHeader::encode()` +
  `VideoHeader::encode()` (channel=Video, codec=H264, single non-fragmented frame, marker set). A Rust
  unit test round-trips a built frame through the **same** `sh-protocol` decoders the browser's wasm
  bridge runs, so the host framing cannot drift from what the browser parses. Frames are 320×240 so
  each stays under the SHP 16-bit (`payload_len`) cap — larger frames need fragmentation (follow-up).
- **DataChannel, not RTP.** The transport is SCTP DataChannels (str0m); the browser consumes opaque
  binary SHP frames. No RTP packetization / media-track negotiation is introduced.
- **CI proof.** The `browser-native` Playwright e2e gains a video test: it spawns the host with
  `--stream-video`, the browser runs the real `parseVideoFrame` + WebCodecs decode path, and asserts
  `framesReachedDecoder >= 1` (the frame reached + parsed by the production decoders — the meaningful
  transport proof, no WebCodecs needed) and, **only when WebCodecs is available** (headless Firefox
  H.264 decode is not guaranteed), `framesDecoded >= 1`.

## Consequences

- **Positive:** a browser tab renders **real H.264 video coming from the native host** over the
  identity-bound WebRTC session, proven in CI — the browser↔host video transport is now end-to-end
  real, not in-page loopback. Both ADR-0028/0029 invariants preserved (no H.264 encoder in the default
  build; the C never compiles in the workspace).
- **Negative / trade-offs:** the streamed content is a fixed test clip, not the live screen (that is
  ADR-0032). Single-fragment frames only (payload < 64 KB); >64 KB frames need SHP fragmentation +
  browser-side reassembly (follow-up). No GOP/periodic-keyframe or loss recovery yet (the browser
  joins before streaming starts, so it gets the leading IDR). `InsecureLanLab` signaling (LAN-lab only).
- **Follow-ups:** ADR-0032 — an excluded WebRTC host doing live X11 capture + OpenH264 over this same
  DataChannel path; SHP fragmentation for large frames; periodic keyframes; input back-channel.
