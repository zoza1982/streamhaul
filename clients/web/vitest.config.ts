import { defineConfig } from "vitest/config";

// Unit tests run in Node and cover the PURE LOGIC seams only: input DOM-event → SHP-bytes
// mapping (exact `encode_input_event` output), codec negotiation, frame-header parsing, and
// coordinate mapping. WebCodecs/DOM are not present in Node — those paths are proven by the
// Playwright headless-Firefox e2e instead.
//
// The wasm bridge is loaded for the tests that assert exact encoded bytes, via a Node-side
// init of the `--target web` package (see test/helpers/bridge-node.ts).
export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    // The e2e specs live under e2e/ and are run by Playwright, not Vitest.
    exclude: ["e2e/**", "node_modules/**", "dist/**"],
  },
});
