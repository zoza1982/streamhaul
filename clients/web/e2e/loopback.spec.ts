import { test, expect } from "@playwright/test";

import { encodeExpectedClickBytes } from "./expected-input.js";

// The functional VIEW + CONTROL + H.264 + wire proof, end-to-end in headless Firefox.
//
// The loopback page (`/e2e/loopback.html`, driven by `e2e/loopback.ts`) runs a real `WebClient`
// viewer (offerer) and a plain `RTCPeerConnection` host (answerer) connected by a real DTLS
// DataChannel. The host sends a real SHP-wrapped H.264 keyframe; the viewer decodes it via
// WebCodecs and paints it to a `<canvas>`. Then a synthetic canvas mousedown is captured,
// encoded to SHP, and sent back to the host. We assert:
//
//   1. H.264 was negotiated.
//   2. The viewer survived a malformed/garbage frame (sent before the good one) without dying.
//   3. The decoder produced a VideoFrame of the expected 16x16 dimensions AND the canvas has
//      non-blank pixels (the decode -> paint path actually ran).
//   4. The host received the EXACT SHP input bytes for the center-click — byte-for-byte equal to
//      the independently-computed expected encoding (non-vacuous: a broken encode/coord/wire
//      path would change these bytes).

test.describe("browser loopback: view + control + H.264", () => {
  test("decodes a real H.264 keyframe to canvas and round-trips an input event", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(String(e)));

    await page.goto("/e2e/loopback.html");

    // Drive the in-page demo and read its structured result.
    const result = await page.evaluate(async () => {
      const run = (globalThis as unknown as { __runDemo?: () => Promise<unknown> }).__runDemo;
      if (run === undefined) throw new Error("demo driver not loaded");
      return await run();
    });

    const r = result as {
      webCodecsAvailable: boolean;
      negotiatedCodec: number | null;
      framesDecoded: number;
      framesDropped: number;
      decodedWidth: number;
      decodedHeight: number;
      canvasNonBlank: boolean;
      hostReceivedInputHex: string | null;
      malformedFrameSurvived: boolean;
      error: string | null;
    };

    expect(errors, `page errors: ${errors.join("; ")}`).toHaveLength(0);
    expect(r.error, `demo error: ${r.error}`).toBeNull();

    // (1) H.264 negotiated for the browser.
    expect(r.negotiatedCodec).toBe(0); // Codec.H264

    // (2) WebCodecs available + viewer survived hostile input.
    expect(r.webCodecsAvailable).toBe(true);
    expect(r.malformedFrameSurvived).toBe(true);

    // (3) Real decode -> paint: a 16x16 VideoFrame was produced and the canvas is non-blank.
    expect(r.framesDecoded).toBeGreaterThanOrEqual(1);
    expect(r.decodedWidth).toBe(16);
    expect(r.decodedHeight).toBe(16);
    expect(r.canvasNonBlank).toBe(true);

    // (4) Control: the host received the EXACT SHP bytes for the center-click.
    expect(r.hostReceivedInputHex).not.toBeNull();
    const expected = encodeExpectedClickBytes();
    expect(r.hostReceivedInputHex).toBe(expected);
  });
});
