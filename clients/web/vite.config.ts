import { defineConfig } from "vite";
import { resolve } from "node:path";

// Vite bundles the TS app and serves it (dev + Playwright preview). The wasm `?url` imports
// resolve the staged `src/wasm/*_bg.wasm` binaries; `fs.allow` is widened so the generated
// wasm under `src/wasm` is servable. WebCodecs/WebRTC need a secure-ish context, which
// `localhost` satisfies.
export default defineConfig({
  build: {
    target: "es2022",
    sourcemap: true,
    rollupOptions: {
      input: {
        // Main viewer page.
        main: resolve(import.meta.dirname, "index.html"),
        // The in-page browser-loopback demo driven by the Playwright e2e.
        loopback: resolve(import.meta.dirname, "e2e/loopback.html"),
        // Browser↔native WebRTC interop test page (P5-3).
        "browser-native": resolve(import.meta.dirname, "e2e/browser-native.html"),
      },
    },
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
  },
  preview: {
    host: "127.0.0.1",
    port: 4173,
  },
});
