import { describe, it, expect } from "vitest";

import { loadCodecBridge } from "./helpers/bridge-node.js";
import { buildShpVideoFrame } from "./helpers/shp-frame.js";
import { H264_SAMPLE_KEYFRAME } from "./fixtures/h264-sample.js";
import { parseVideoFrame, isH264Keyframe, CHANNEL_VIDEO } from "../src/protocol/frame.js";
import { Codec } from "../src/protocol/constants.js";
import type { ShBridge } from "../src/bridge/types.js";

function bridge(): ShBridge {
  return loadCodecBridge() as unknown as ShBridge;
}

describe("buildShpVideoFrame wire correctness (round-trips through production decoders)", () => {
  it("uses the canonical sh_types::ChannelId::Video discriminant (0)", () => {
    // Pin the value: Video=0 in sh-types (Audio=1, Input=2, Control=5). A regression to any
    // other value would make parseVideoFrame reject every real video frame.
    expect(CHANNEL_VIDEO).toBe(0);
  });

  it("decodes the emulated header via the real wasm decoders", () => {
    const b = bridge();
    const frame = buildShpVideoFrame({
      payload: H264_SAMPLE_KEYFRAME,
      frameId: 0x123456,
      sequence: 7,
      codec: Codec.H264,
      frameType: 1, // IDR
      priority: 2,
      monitorId: 3,
    });
    const common = b.decode_common_header(frame.subarray(0, 9));
    expect(common.channel).toBe(CHANNEL_VIDEO);
    expect(common.sequence).toBe(7);
    expect(common.payload_len).toBe(H264_SAMPLE_KEYFRAME.length);

    const vh = b.decode_video_header(frame.subarray(9, 21));
    expect(vh.frame_id).toBe(0x123456);
    expect(vh.codec).toBe(Codec.H264);
    expect(vh.frame_type).toBe(1);
    expect(vh.monitor_id).toBe(3);
  });
});

describe("parseVideoFrame (hostile input safe)", () => {
  it("parses a well-formed H.264 keyframe and exposes the payload slice", () => {
    const b = bridge();
    const frame = buildShpVideoFrame({ payload: H264_SAMPLE_KEYFRAME });
    const parsed = parseVideoFrame(b, frame);
    expect(parsed).not.toBeNull();
    expect(parsed!.header.codec).toBe(Codec.H264);
    expect(isH264Keyframe(parsed!)).toBe(true);
    expect(Array.from(parsed!.payload)).toEqual(Array.from(H264_SAMPLE_KEYFRAME));
  });

  it("returns null (no throw) on a truncated frame", () => {
    const b = bridge();
    expect(parseVideoFrame(b, new Uint8Array(5))).toBeNull();
    expect(parseVideoFrame(b, new Uint8Array(0))).toBeNull();
  });

  it("returns null (no throw) on garbage bytes", () => {
    const b = bridge();
    const garbage = new Uint8Array(64).fill(0xff);
    expect(parseVideoFrame(b, garbage)).toBeNull();
  });

  it("returns null when the frame is on a non-video channel", () => {
    const b = bridge();
    // A valid common header but on the Input channel (2) — not video.
    const frame = buildShpVideoFrame({ payload: H264_SAMPLE_KEYFRAME });
    // Rewrite byte0 to channel Input(2): (VER<<6)|(2<<2) = 0x48.
    const tampered = frame.slice();
    tampered[0] = (0b01 << 6) | (2 << 2);
    expect(parseVideoFrame(b, tampered)).toBeNull();
  });
});
