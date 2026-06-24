import { test, expect } from "@playwright/test";

import { encodeExpectedClickBytes } from "./expected-input.js";

// The functional VIEW + CONTROL + H.264 + wire proof, end-to-end in headless Firefox.
//
// The loopback page (`/e2e/loopback.html`, driven by `e2e/loopback.ts`) runs a real `WebClient`
// viewer (offerer) and a plain `RTCPeerConnection` host (answerer) connected by a real DTLS
// DataChannel. The host sends a real SHP-wrapped H.264 keyframe; the viewer routes it through the
// WebCodecs decode pipeline and (where H.264 decode is available) paints it to a `<canvas>`. Then
// a synthetic canvas mousedown is captured, encoded to SHP, and sent back to the host.
//
// ## What is always asserted (codec-INDEPENDENT — the real transport/control proof)
//
//   1. No page/demo error; the loopback connected over real DTLS.
//   2. H.264 was negotiated.
//   3. The viewer survived a malformed/garbage frame (sent before the good one) without dying.
//   4. The real SHP-wrapped video frame REACHED the decoder input over the DataChannel
//      (`framesReachedDecoder >= 1`) — proving transport + frame delivery + the decode pipeline.
//   5. The canvas input event round-tripped to the host as the EXACT expected SHP bytes
//      (byte-for-byte vs an independently-computed encoding — non-vacuous).
//
// ## What is conditionally asserted (H.264 decode → pixels)
//
// Firefox decodes H.264 only when the OpenH264/ffmpeg codec is present (system Firefox locally;
// CI Firefox when `ffmpeg` is installed). Playwright's bundled Firefox on a fresh CI runner lacks
// it. So when `h264DecodeSupported` is true we additionally assert the decoder produced a 16x16
// VideoFrame and the canvas is non-blank; otherwise that single assertion is skipped (with a
// warning) so CI stays green — the pixel-decode is still proven everywhere the codec is present.

interface DemoResult {
  webCodecsAvailable: boolean;
  h264DecodeSupported: boolean | null;
  loopbackConnected: boolean;
  negotiatedCodec: number | null;
  framesReachedDecoder: number;
  framesDecoded: number;
  framesDropped: number;
  decodedWidth: number;
  decodedHeight: number;
  canvasNonBlank: boolean;
  hostReceivedInputHex: string | null;
  malformedFrameSurvived: boolean;
  error: string | null;
}

test.describe("browser loopback: view + control + H.264", () => {
  test("delivers a real H.264 frame through the decode pipeline and round-trips an input event", async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(String(e)));

    await page.goto("/e2e/loopback.html");

    // Drive the in-page demo and read its structured result.
    const r = (await page.evaluate(async () => {
      const run = (globalThis as unknown as { __runDemo?: () => Promise<unknown> }).__runDemo;
      if (run === undefined) throw new Error("demo driver not loaded");
      return await run();
    })) as DemoResult;

    expect(errors, `page errors: ${errors.join("; ")}`).toHaveLength(0);
    expect(r.error, `demo error: ${r.error}`).toBeNull();

    // ── Codec-INDEPENDENT assertions (these catch a transport/control/pipeline regression) ──

    // (1) The loopback connected over a real DTLS DataChannel.
    expect(r.loopbackConnected).toBe(true);

    // (2) H.264 negotiated for the browser.
    expect(r.negotiatedCodec).toBe(0); // Codec.H264

    // (3) WebCodecs API present + the viewer survived hostile input without crashing.
    expect(r.webCodecsAvailable).toBe(true);
    expect(r.malformedFrameSurvived).toBe(true);

    // (4) The real SHP-wrapped H.264 frame reached the decoder input over the wire.
    expect(r.framesReachedDecoder).toBeGreaterThanOrEqual(1);

    // (5) CONTROL: the host received the EXACT SHP bytes for the center-click.
    expect(r.hostReceivedInputHex).not.toBeNull();
    const expected = encodeExpectedClickBytes();
    expect(r.hostReceivedInputHex).toBe(expected);

    // ── Conditional H.264 decode → pixels assertion ──
    if (r.h264DecodeSupported === true) {
      expect(r.framesDecoded).toBeGreaterThanOrEqual(1);
      expect(r.decodedWidth).toBe(16);
      expect(r.decodedHeight).toBe(16);
      expect(r.canvasNonBlank).toBe(true);
    } else {
      // eslint-disable-next-line no-console
      console.warn(
        "[e2e] H.264 WebCodecs decode unavailable in this Firefox build (no OpenH264/ffmpeg) — " +
          "transport + control + decode-pipeline verified; pixel-decode assertion skipped.",
      );
    }
  });
});
