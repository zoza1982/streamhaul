import { describe, it, expect } from "vitest";

import { loadCodecBridge } from "./helpers/bridge-node.js";
import { buildBrowserOffer, selectCodec } from "../src/protocol/negotiate.js";
import { Codec, CODEC_NONE } from "../src/protocol/constants.js";
import type { ShBridge } from "../src/bridge/types.js";

// The negotiation functions need the codec subset of the bridge (encode_caps/decode_caps).
function bridge(): ShBridge {
  return loadCodecBridge() as unknown as ShBridge;
}

describe("buildBrowserOffer", () => {
  it("advertises H.264 decode, is_browser, no encode, no selection", () => {
    const b = bridge();
    const offer = buildBrowserOffer(b);
    expect(offer.length).toBe(4);
    const decoded = b.decode_caps(offer);
    expect(decoded.hw_encode_mask).toBe(0);
    expect(decoded.hw_decode_mask & (1 << Codec.H264)).not.toBe(0);
    expect(decoded.is_browser).toBe(true);
    expect(decoded.sw_h264_encode_available).toBe(false);
    expect(decoded.selected_codec).toBe(CODEC_NONE);
  });
});

describe("selectCodec", () => {
  it("selects H.264 when the host can hardware-encode H.264", () => {
    const b = bridge();
    // Host advertises HW H.264 encode (bit 0), not a browser.
    const hostCaps = b.encode_caps(1 << Codec.H264, 0, false, false, false, CODEC_NONE);
    const sel = selectCodec(b, hostCaps);
    expect(sel.codec).toBe(Codec.H264);
    const answer = b.decode_caps(sel.answerBytes);
    expect(answer.selected_codec).toBe(Codec.H264);
    expect(answer.is_browser).toBe(true);
  });

  it("selects H.264 when the host has only software H.264 encode", () => {
    const b = bridge();
    const hostCaps = b.encode_caps(0, 0, true, false, false, CODEC_NONE);
    const sel = selectCodec(b, hostCaps);
    expect(sel.codec).toBe(Codec.H264);
  });

  it("throws when the host advertises no H.264 production path", () => {
    const b = bridge();
    // Host can only HW-encode AV1 (bit 2), no SW H.264 → no common codec for a browser viewer.
    const hostCaps = b.encode_caps(1 << Codec.AV1, 0, false, false, false, CODEC_NONE);
    expect(() => selectCodec(b, hostCaps)).toThrowError(/no common codec/);
  });
});
