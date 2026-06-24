import { defineConfig, devices } from "@playwright/test";

// Headless-Firefox e2e: the functional VIEW+CONTROL proof. Firefox is the proven browser for
// this environment (ADR-0021/0022); Chrome is best-effort and Safari is impossible on Linux —
// both deferred (R-BROWSER-MATRIX). The Vite preview server hosts the built app; the loopback
// demo page (e2e/loopback.html) drives an in-page "host" peer that sends a real H.264 keyframe.
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: [["list"]],
  timeout: 60_000,
  use: {
    baseURL: "http://127.0.0.1:4173",
    headless: true,
    trace: "off",
  },
  projects: [
    {
      name: "firefox",
      use: {
        ...devices["Desktop Firefox"],
        launchOptions: {
          firefoxUserPrefs: {
            // Allow RTCPeerConnection loopback (host↔host on the same machine) without ICE servers.
            "media.peerconnection.ice.loopback": true,
            // Enable WebCodecs (VideoEncoder/VideoDecoder) in this Firefox build.
            "dom.media.webcodecs.enabled": true,
            "dom.media.webcodecs.image-decoder.enabled": true,
          },
        },
      },
    },
  ],
  webServer: {
    command: "npm run build && npm run preview",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
