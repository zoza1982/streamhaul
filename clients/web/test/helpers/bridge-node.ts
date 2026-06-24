// Load the REAL sh-wasm codec bridge in Node for Vitest.
//
// Vitest runs in Node, where the `--target web` (fetch-based) init does not apply. The
// `--target nodejs` build of sh-wasm self-initializes on require, so the exact codec
// `encode_*`/`decode_*` functions are callable directly. This lets the unit tests assert
// byte-exact `encode_input_event` output against the SAME Rust codec the browser runs —
// not a TS re-implementation.

import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import type { ShBridge } from "../../src/bridge/types.js";

/** The codec subset of the bridge exercised by the Node unit tests. */
export type CodecBridge = Pick<
  ShBridge,
  | "encode_input_event"
  | "encode_caps"
  | "decode_caps"
  | "decode_video_header"
  | "decode_common_header"
  | "negotiate_transport"
>;

let cached: CodecBridge | null = null;

/** Load (once) the Node-target sh-wasm codec bridge. */
export function loadCodecBridge(): CodecBridge {
  if (cached === null) {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = resolve(here, "..", "..", "src", "wasm", "sh-wasm-node", "sh_wasm.js");
    const require = createRequire(import.meta.url);
    cached = require(pkg) as CodecBridge;
  }
  return cached;
}
