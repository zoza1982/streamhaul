# Streamhaul Web Viewer (`clients/web`) — P5-2

A small, strict-TypeScript browser client that turns the merged Rust/wasm bridges into a working
viewer/control surface:

- **VIEW** — decode inbound H.264 (WebCodecs `VideoDecoder`) and render `VideoFrame`s to a
  `<canvas>`.
- **CONTROL** — capture DOM mouse/keyboard/wheel on the canvas, map to SHP input events, and send
  them to the host over the WebRTC DataChannel.
- **H.264 negotiation** — advertise + select H.264 for the browser (browsers can't AV1-encode;
  H.264 is the browser codec per ADR-0003).
- **Session lifecycle UI** — connect/disconnect, identity/connection status, negotiated codec, the
  canvas.

It is a **thin DOM/WebCodecs shell over the Rust/wasm client**. All security-/wire-critical logic
(SHP codec, identity/crypto, DTLS-pin gate, WebRTC orchestration) lives in the wasm crates and is
**not reimplemented in TypeScript**. See [ADR-0022](../../docs/adr/0022-browser-viewer-control-ui.md).

## Architecture

```
clients/web/
  src/
    bridge/        Typed facade over the merged wasm bridge (one wasm binary, one init)
    protocol/      Pure logic: input mapping, coords, codec negotiation, SHP frame parsing
    view/          Annex-B helpers + WebCodecs H.264 decoder → canvas (VIEW)
    control/       DOM input capture → SHP → DataChannel (CONTROL)
    client/        Session lifecycle (WebClient wrapper + observable state)
    app.ts         Minimal page wiring
    wasm/          GENERATED bridge output (gitignored; built by scripts/build-wasm.mjs)
  test/            Vitest pure-logic unit tests + fixtures + helpers
  e2e/             Playwright headless-Firefox loopback demo + spec
  scripts/         build-wasm.mjs, gen-h264-fixture.mjs
```

### How it imports the wasm modules

`sh-web-client` depends on `sh-wasm` (SHP codec) and `sh-crypto-wasm` (identity/crypto) and
**re-exports their `#[wasm_bindgen]` symbols**, so its generated package is a superset: one wasm
binary, one `init()`. `scripts/build-wasm.mjs` runs `wasm-pack build --target web` for all three
crates and stages the output into `src/wasm/`. `src/bridge/index.ts` initializes that single wasm
module and exposes a strict `ShBridge` surface (`src/bridge/types.ts`) — the app never touches the
loose, `any`-typed wasm-bindgen glue on the wire/security path.

For Vitest (which runs in Node, where the `--target web` fetch-init doesn't apply), the script also
builds `sh-wasm` for `--target nodejs` so the unit tests can call the **real Rust codec**
(`encode_input_event`, …) and assert byte-exact output — not a TS re-implementation.

## Build & test

```bash
npm ci                 # or: npm install
npm run build:wasm     # wasm-pack build the 3 crates (+ sh-wasm nodejs target for vitest)
npm run build          # build:wasm + strict tsc --noEmit + vite build
npm run test:unit      # vitest (pure logic, Node)
npm run test:e2e       # Playwright headless Firefox (build + preview + run)
npm test               # build:wasm + tsc + vitest + Playwright
```

Requires: Node ≥ 20, `wasm-pack`, the `wasm32-unknown-unknown` Rust target, and a Playwright
Firefox (`npx playwright install firefox`).

## Tests

- **Vitest (Node, pure logic):** input DOM-event→SHP-bytes mapping (exact `encode_input_event`
  bytes), codec negotiation (H.264 selected), SHP frame-header parsing (hostile-input safe),
  coordinate mapping, Annex-B NAL/SPS/PPS parsing.
- **Playwright headless-Firefox e2e (`e2e/loopback.spec.ts`):** an in-page browser loopback — a
  real `WebClient` viewer (offerer) and a plain `RTCPeerConnection` host (answerer) on a real DTLS
  DataChannel. The host sends a real SHP-wrapped H.264 keyframe; the viewer decodes it via
  WebCodecs and paints it to a canvas; the test asserts a 16×16 `VideoFrame` was produced and the
  canvas is non-blank, that a malformed frame sent first did **not** crash the viewer, that H.264
  was negotiated, and that a synthetic canvas click round-tripped to the host as the **exact** SHP
  input bytes (byte-for-byte against an independent expectation — non-vacuous).

### Sample H.264 keyframe fixture

`test/fixtures/h264-keyframe.generated.ts` is a real, decodable 16×16 H.264 Annex-B keyframe. No
H.264 *encoder* is available in this environment (Firefox/Chromium WebCodecs `VideoEncoder`
unsupported; Playwright ffmpeg is VP8-only; no system ffmpeg/libx264), but the decoders decode
H.264 fine. The fixture is therefore **constructed directly** per ISO/IEC 14496-10 by
`scripts/gen-h264-fixture.mjs` using an **I_PCM** macroblock (raw 8-bit samples, no
transform/CAVLC entropy coding) carrying a solid mid-gray picture — fully transparent and
reproducible (`node scripts/gen-h264-fixture.mjs`). Both Firefox and Chromium WebCodecs decoders
decode it to a real 16×16 `VideoFrame`.

## Browser matrix & deferrals

- **Firefox** (headless) is the proven browser here and in CI.
- **Chrome** — best-effort (chromedriver lag); not in the gate. **R-BROWSER-MATRIX**.
- **Safari** — impossible on Linux; documented, not attempted. **R-BROWSER-MATRIX**.
- **Live host↔browser video** (a real native `sh-transport` host over `sh-signaling`) is deferred —
  the loopback demo proves the viewer with a sample frame. **R-BROWSER-INTEROP**.
- Clipboard/file channels, audio, and visual/UX polish are out of scope (deferred).

See [ADR-0022](../../docs/adr/0022-browser-viewer-control-ui.md) and the P5 Risk Register.
