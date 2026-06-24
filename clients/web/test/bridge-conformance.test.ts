import { describe, it, expect } from "vitest";

import { loadCodecBridge } from "./helpers/bridge-node.js";

// The app consumes the wasm bridge through a hand-written `ShBridge` type via an
// `as unknown as ShBridge` cast (the documented escape hatch around the wasm-bindgen `any`
// glue). The cast means tsc cannot catch a renamed/dropped export — it would surface only at
// runtime as "undefined is not a function" on the wire path. This conformance test closes that
// gap for the codec surface (the only part loadable in Node): it asserts each codec function the
// `ShBridge` type promises actually exists on the real generated module.
//
// (The crypto/WebClient surface needs a browser to load; it is exercised by the Playwright e2e,
// which would fail at runtime if `WebClient` / `parse_sdp_fingerprint` were renamed.)

const REQUIRED_CODEC_EXPORTS = [
  "encode_input_event",
  "encode_caps",
  "decode_caps",
  "decode_video_header",
  "decode_common_header",
  "negotiate_transport",
] as const;

describe("wasm bridge conformance (codec surface)", () => {
  it("exposes every codec function the ShBridge type promises", () => {
    const bridge = loadCodecBridge() as unknown as Record<string, unknown>;
    for (const name of REQUIRED_CODEC_EXPORTS) {
      expect(typeof bridge[name], `missing/renamed export: ${name}`).toBe("function");
    }
  });
});
