# ADR 0022: Browser viewer/control UI (P5-2)

- **Status:** Accepted
- **Date:** 2026-06-23
- **Deciders:** ui-engineer (+ security-engineer for the input/render path); builds on ADR-0019
  (`sh-wasm`), ADR-0020 (`sh-crypto-wasm`), ADR-0021 (`sh-web-client`).

## Context

P5-1/P5-1b/P5-1c delivered the three browser wasm bridges (SHP codec, identity/crypto, the
DTLS-pinned `WebClient`) and proved them in headless Firefox. P5-2 must turn those bridges into a
working browser client: receive + decode + render H.264 to a canvas (VIEW), capture DOM input and
send it to the host (CONTROL), and negotiate H.264 (browsers can't AV1-encode; H.264 is the browser
codec per ADR-0003 / `LLD.md`).

Constraints (`CLAUDE.md`): everything that ships is tested; host frame bytes are hostile (a
malformed frame must never crash the viewer); reuse the wasm bridges (do **not** reimplement
codec/crypto/transport in TS); strict TS, no `any` on the wire/security path; docs ship with code.

Environment: Node 20 + headless Firefox 152 + geckodriver 0.37 work (proven, ADR-0021). Chrome is
best-effort (chromedriver lags); Safari is impossible on Linux. Critically, **no H.264 *encoder***
is available anywhere in this environment (Firefox/Chromium WebCodecs `VideoEncoder` unsupported;
Playwright's bundled ffmpeg is VP8-only; no system ffmpeg/libx264) — but the WebCodecs *decoders*
decode H.264 fine.

## Decision

**A thin DOM/WebCodecs shell over the Rust/wasm client.** All security-/wire-critical logic stays
in wasm:

- **Architecture.** A strict-TypeScript app under `clients/web/`, bundled with **Vite**, unit-tested
  with **Vitest**, and e2e-tested with **`@playwright/test` driving headless Firefox** (all pinned
  devDeps). `sh-web-client` re-exports the `#[wasm_bindgen]` symbols of `sh-wasm` and
  `sh-crypto-wasm`, so the app loads **one wasm binary with one `init()`** and consumes the SHP
  codec, identity primitives, and `WebClient` from a single package. A hand-written typed facade
  (`src/bridge/`) exposes only the surface the app uses — the app never touches the loose,
  `any`-typed wasm-bindgen glue on the wire/security path. The generated wasm output
  (`src/wasm/`) is build artifact (gitignored); the source of truth is the Rust crates.

- **VIEW — WebCodecs H.264 decode + canvas render.** Inbound DataChannel SHP video frames are
  header-decoded by the wasm bridge (`decode_common_header`/`decode_video_header`, fuzzed +
  panic-free), the H.264 Annex-B payload is fed to a WebCodecs `VideoDecoder` (configured in
  `"annexb"` mode, codec string derived from the inline SPS), and produced `VideoFrame`s are drawn
  to a 2D `<canvas>`. **Hostile input is contained at every layer:** a frame too short / on the
  wrong channel / with a malformed header yields `null` (dropped); a decode/configure error is
  caught, the frame is dropped, the decoder is torn down, and the next keyframe re-primes it. A
  garbage frame can never crash the viewer.

- **CONTROL — input capture → SHP.** DOM mouse (move/button/wheel) and keyboard events on the
  canvas are mapped (pure, node-testable functions) to the 9 SHP `InputEvent` fields and encoded by
  the wasm `encode_input_event` (the TS never serializes the wire). Coordinates are mapped
  canvas-bounding-box-relative onto the SHP-normalized `0..=65535` range (clamped, divide-by-zero
  safe); keys map DOM physical `code` → USB HID usage ID; mouse buttons map to the SHP button-mask
  bits; wheel deltas map to the px×8 signed fixed-point field (saturating).

- **H.264 negotiation.** The browser advertises H.264 decode + `is_browser` via `encode_caps`, and
  `selectCodec` picks H.264 iff the host advertises an H.264 production path (HW or SW encode),
  echoing the selection in the capability answer. The negotiated codec is surfaced in the UI.

- **Test strategy.**
  - **Vitest (Node, pure logic):** input DOM-event→SHP-bytes mapping asserted **byte-exact**
    against the **real Rust codec** (a `--target nodejs` build of `sh-wasm`, not a TS
    re-implementation), codec negotiation, SHP frame-header parsing (hostile-input safe), coordinate
    mapping, Annex-B NAL/SPS/PPS parsing. WebCodecs/DOM are absent in Node, so these stay on the
    pure-logic seams.
  - **Playwright headless-Firefox e2e:** an **in-page browser loopback** — a real `WebClient` viewer
    (offerer) and a plain `RTCPeerConnection` host (answerer) on a real DTLS DataChannel. The host
    sends a real SHP-wrapped H.264 keyframe; the viewer routes it through the WebCodecs decode
    pipeline and (where the codec is available) paints it to a canvas. The test **always** asserts,
    codec-independently: the loopback connected over real DTLS; H.264 was negotiated; a malformed
    frame (sent first) did **not** crash the viewer; the SHP-wrapped frame **reached the decoder
    input over the wire** (`framesReachedDecoder ≥ 1` — proving transport + frame delivery + the
    decode pipeline); and a synthetic canvas click round-tripped to the host as the **exact** SHP
    input bytes (byte-for-byte vs an independently-computed expectation). It **conditionally**
    asserts decode→pixels (a 16×16 `VideoFrame` was produced **and** the canvas is non-blank) **iff**
    `VideoDecoder.isConfigSupported({codec:'avc1.42001e'})` reports support — i.e. where the
    OpenH264/ffmpeg codec is present (system Firefox locally; CI Firefox when `ffmpeg` is installed).
    Firefox decodes H.264 only with that codec, which a fresh Playwright-bundled Firefox lacks; so
    the pixel assertion is gracefully skipped (with a warning) there, keeping CI green while the
    codec-independent proofs still gate. The test is non-vacuous: a broken transport/control/pipeline
    or a wrong coord/encode changes the always-asserted values and fails; the pixel-decode is still
    proven everywhere the codec is present (locally, and in CI when `ffmpeg` enables it).

- **Sample-frame fixture.** `test/fixtures/h264-keyframe.generated.ts` is a real, decodable 16×16
  H.264 Annex-B keyframe. Because no encoder exists here, it is **constructed directly** per ISO/IEC
  14496-10 by `scripts/gen-h264-fixture.mjs` using an **I_PCM** macroblock (raw 8-bit samples, no
  transform/entropy coding) carrying a solid mid-gray picture — fully transparent and reproducible.
  Both Firefox and Chromium WebCodecs decoders decode it to a real 16×16 `VideoFrame`. (The
  committed synthetic NAL fixture in `test/fixtures/h264-sample.ts` is used only for the pure-logic
  parsing tests, which don't need a real decoder.)

- **CI.** A new `web-ui` job (ubuntu) builds the three wasm crates (`wasm-pack build --target web`),
  `npm ci` + `npm audit --audit-level=high` in `clients/web`, then `npm run build` + `vitest run` +
  the Playwright headless-Firefox e2e (Firefox + geckodriver pinned exactly as the
  `browser-webrtc-client` job). Before the e2e it installs `ffmpeg` (a best-effort attempt to give
  Firefox a H.264-capable libavcodec so the conditional pixel-decode assertion runs in CI too); the
  e2e does **not** depend on this succeeding — if H.264 decode is still unavailable it skips only the
  pixel assertion and the codec-independent transport/control proofs still gate. Existing jobs are
  untouched.

## Consequences

- **Positive:** the viewer/control surface is real and exercised end-to-end in a real browser; the
  security-critical logic stays in the audited wasm crates; the input wire format is proven
  byte-exact against the native codec; hostile host frames are provably non-fatal; the
  transport + frame-delivery + decode-pipeline + input round-trip are proven in **any** Firefox build
  (codec-independent), and the full H.264 decode→canvas-pixels assertion runs wherever the
  OpenH264/ffmpeg codec is present (system Firefox locally; CI when `ffmpeg` enables it) with a
  genuinely decodable, encoder-free fixture.
- **Negative / trade-offs:** Firefox-only in the gate (Chrome best-effort, Safari impossible on
  Linux); the e2e proves the viewer against an in-page loopback host, not a live native host; the
  decode→pixels assertion is **codec-gated** — it runs only where Firefox has the OpenH264/ffmpeg
  H.264 codec (so on a fresh CI runner without `ffmpeg` it is skipped, and CI's pixel coverage is
  best-effort rather than guaranteed); the I_PCM fixture is a single static keyframe (no inter-frame
  / multi-resolution coverage); visual/UX polish is deliberately absent.
- **Follow-ups:** live browser↔**native** video over `sh-signaling` (**R-BROWSER-INTEROP**); the
  Chrome/Safari matrix (**R-BROWSER-MATRIX**); clipboard/file channels and audio; fragment
  reassembly for multi-fragment frames; pointer-lock relative-mouse polish.

## Alternatives considered

- **Reimplement codec/input/negotiation in TS** — rejected: violates the reuse rule and duplicates
  the audited, fuzzed wire format outside the Rust surface (drift + attack-surface risk).
- **Generate the keyframe in-browser via WebCodecs `VideoEncoder`** — rejected: H.264 encode is
  unsupported in this environment (Firefox + headless Chromium both fail). The encoder-free I_PCM
  construction is the reproducible substitute.
- **`MediaSource`/`<video>` instead of WebCodecs+canvas** — rejected: WebCodecs gives frame-accurate,
  low-latency control and a direct `VideoFrame`→canvas path with no MSE buffering/segmenting; canvas
  pixels also make the e2e decode assertion directly observable.
- **Multi-browser gate now (Chrome/Safari)** — deferred: chromedriver lags Chrome here and Safari
  cannot run on Linux; same environment-gated posture as the Gate-P0 hardware items.
- **esbuild instead of Vite** — Vite chosen for its built-in `?url` wasm handling and a `preview`
  server Playwright can drive; esbuild would need extra wasm/server glue for no benefit at this size.
