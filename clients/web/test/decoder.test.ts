import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { CanvasH264Decoder } from "../src/view/decoder.js";
import { H264_SAMPLE_KEYFRAME, H264_SAMPLE_DELTA } from "./fixtures/h264-sample.js";

// CanvasH264Decoder needs the WebCodecs `VideoDecoder`/`EncodedVideoChunk` and a 2D canvas,
// none of which exist in Node. We install minimal fakes so the decoder's STATE MACHINE and
// HOSTILE-INPUT SAFETY (the parts that must never crash the app) are unit-testable: configure-
// on-keyframe, drop-before-keyframe, error recovery, drop counting, and SPS-codec caching.

interface FakeChunk {
  type: "key" | "delta";
  data: Uint8Array;
}

class FakeVideoFrame {
  constructor(
    readonly displayWidth: number,
    readonly displayHeight: number,
  ) {}
  closed = false;
  close(): void {
    this.closed = true;
  }
}

let configureCalls: Array<{ codec: string }> = [];
let decodeCalls: FakeChunk[] = [];
let closeCalls = 0;
// Controls how the fake decoder reacts to the next decode() call.
let nextDecodeBehavior: "frame" | "throw" | "error-callback" = "frame";

class FakeVideoDecoder {
  state: "unconfigured" | "configured" | "closed" = "unconfigured";
  constructor(
    private readonly init: {
      output: (f: FakeVideoFrame) => void;
      error: (e: unknown) => void;
    },
  ) {}
  configure(config: { codec: string }): void {
    configureCalls.push(config);
    this.state = "configured";
  }
  decode(chunk: FakeChunk): void {
    decodeCalls.push(chunk);
    if (nextDecodeBehavior === "throw") {
      throw new Error("decode threw");
    }
    if (nextDecodeBehavior === "error-callback") {
      this.init.error(new Error("decoder errored"));
      return;
    }
    // Produce a 16x16 frame asynchronously-but-synchronously for the test.
    this.init.output(new FakeVideoFrame(16, 16));
  }
  reset(): void {}
  close(): void {
    closeCalls += 1;
    this.state = "closed";
  }
}

class FakeChunkCtor {
  type: "key" | "delta";
  data: Uint8Array;
  constructor(init: { type: "key" | "delta"; timestamp: number; data: Uint8Array }) {
    this.type = init.type;
    this.data = init.data;
  }
}

interface FakeCtx {
  drawImage: ReturnType<typeof vi.fn>;
}

function makeCanvas(): HTMLCanvasElement {
  const ctx: FakeCtx = { drawImage: vi.fn() };
  const canvas = {
    width: 0,
    height: 0,
    getContext: (kind: string) => (kind === "2d" ? ctx : null),
  };
  return canvas as unknown as HTMLCanvasElement;
}

beforeEach(() => {
  configureCalls = [];
  decodeCalls = [];
  closeCalls = 0;
  nextDecodeBehavior = "frame";
  (globalThis as Record<string, unknown>).VideoDecoder = FakeVideoDecoder;
  (globalThis as Record<string, unknown>).EncodedVideoChunk = FakeChunkCtor;
});

afterEach(() => {
  delete (globalThis as Record<string, unknown>).VideoDecoder;
  delete (globalThis as Record<string, unknown>).EncodedVideoChunk;
});

describe("CanvasH264Decoder state machine", () => {
  it("drops delta frames until the first keyframe configures the decoder", () => {
    const dec = new CanvasH264Decoder(makeCanvas());
    // A delta (non-IDR) before any keyframe: dropped, no configure.
    expect(dec.pushAnnexB(H264_SAMPLE_DELTA, false)).toBe(false);
    expect(configureCalls).toHaveLength(0);
    expect(dec.stats.framesDropped).toBe(1);

    // The keyframe configures + decodes + paints.
    expect(dec.pushAnnexB(H264_SAMPLE_KEYFRAME, true)).toBe(true);
    expect(configureCalls).toHaveLength(1);
    expect(configureCalls[0]!.codec).toBe("avc1.42001e"); // from the fixture SPS
    expect(dec.stats.framesDecoded).toBe(1);
    expect(dec.stats.lastWidth).toBe(16);
    expect(dec.stats.lastHeight).toBe(16);
  });

  it("treats a payload with an inline IDR as a keyframe even if the header flag says delta", () => {
    const dec = new CanvasH264Decoder(makeCanvas());
    // Header flag false, but the bitstream carries an IDR → configured anyway.
    expect(dec.pushAnnexB(H264_SAMPLE_KEYFRAME, false)).toBe(true);
    expect(configureCalls).toHaveLength(1);
  });

  it("survives a decode that throws (counts a drop, closes the decoder, re-primes on next keyframe)", () => {
    const dec = new CanvasH264Decoder(makeCanvas());
    nextDecodeBehavior = "throw";
    expect(dec.pushAnnexB(H264_SAMPLE_KEYFRAME, true)).toBe(false);
    expect(dec.stats.framesDropped).toBeGreaterThanOrEqual(1);
    // FIX 10: the abandoned decoder must be close()-ed (not just nulled) so decoders do not
    // accumulate until GC under sustained hostile keyframes.
    expect(closeCalls).toBe(1);
    // Recovery: a subsequent good keyframe decodes.
    nextDecodeBehavior = "frame";
    expect(dec.pushAnnexB(H264_SAMPLE_KEYFRAME, true)).toBe(true);
    expect(dec.stats.framesDecoded).toBe(1);
  });

  it("survives the decoder error callback without throwing and closes the errored decoder", () => {
    const dec = new CanvasH264Decoder(makeCanvas());
    nextDecodeBehavior = "error-callback";
    expect(() => dec.pushAnnexB(H264_SAMPLE_KEYFRAME, true)).not.toThrow();
    expect(dec.stats.framesDropped).toBeGreaterThanOrEqual(1);
    // The error callback path also closes the abandoned decoder (FIX 10).
    expect(closeCalls).toBeGreaterThanOrEqual(1);
  });

  it("does not leak decoders under sustained hostile keyframes (one close per failure)", () => {
    const dec = new CanvasH264Decoder(makeCanvas());
    nextDecodeBehavior = "throw";
    for (let i = 0; i < 5; i++) {
      dec.pushAnnexB(H264_SAMPLE_KEYFRAME, true);
    }
    // Each failed keyframe creates and then closes one decoder → 5 closes, no accumulation.
    expect(closeCalls).toBe(5);
  });

  it("reuses the cached codec string for a later keyframe that omits its inline SPS", () => {
    const dec = new CanvasH264Decoder(makeCanvas());
    // First keyframe has SPS → derives avc1.42001e and decodes.
    expect(dec.pushAnnexB(H264_SAMPLE_KEYFRAME, true)).toBe(true);
    // Force a re-configure path by erroring, then send a keyframe WITHOUT inline SPS.
    nextDecodeBehavior = "error-callback";
    dec.pushAnnexB(H264_SAMPLE_KEYFRAME, true);
    nextDecodeBehavior = "frame";
    // An IDR slice with no SPS/PPS (raw IDR NAL only).
    const idrOnly = new Uint8Array([0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00]);
    expect(dec.pushAnnexB(idrOnly, true)).toBe(true);
    // The most recent configure used the cached codec string, not the baseline fallback default.
    expect(configureCalls.at(-1)!.codec).toBe("avc1.42001e");
  });

  it("never throws on garbage payloads", () => {
    const dec = new CanvasH264Decoder(makeCanvas());
    expect(() => dec.pushAnnexB(new Uint8Array(0), true)).not.toThrow();
    expect(() => dec.pushAnnexB(new Uint8Array([0xff, 0xff, 0xff]), true)).not.toThrow();
    expect(() => dec.pushAnnexB(new Uint8Array(64).fill(0xab), false)).not.toThrow();
  });
});
