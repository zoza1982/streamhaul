import { describe, it, expect } from "vitest";

import {
  avcCodecString,
  containsIdr,
  extractParameterSets,
  splitNalUnits,
  NalType,
} from "../src/view/annexb.js";
import {
  H264_SAMPLE_KEYFRAME,
  H264_SAMPLE_CODEC_STRING,
  H264_SAMPLE_DELTA,
} from "./fixtures/h264-sample.js";

describe("splitNalUnits", () => {
  it("splits the committed keyframe into SPS, PPS, IDR (4-byte start codes)", () => {
    const units = splitNalUnits(H264_SAMPLE_KEYFRAME);
    expect(units.map((u) => u.type)).toEqual([NalType.Sps, NalType.Pps, NalType.IdrSlice]);
  });

  it("handles a 3-byte start code (delta NAL)", () => {
    const units = splitNalUnits(H264_SAMPLE_DELTA);
    expect(units).toHaveLength(1);
    expect(units[0]!.type).toBe(NalType.NonIdrSlice);
  });

  it("returns [] for a stream with no start code", () => {
    expect(splitNalUnits(new Uint8Array([1, 2, 3, 4]))).toEqual([]);
  });

  it("never throws on garbage / truncated input", () => {
    expect(() => splitNalUnits(new Uint8Array([0, 0, 0]))).not.toThrow();
    expect(() => splitNalUnits(new Uint8Array(0))).not.toThrow();
    expect(() => splitNalUnits(new Uint8Array([0, 0, 1]))).not.toThrow();
  });
});

describe("containsIdr", () => {
  it("is true for the keyframe and false for the delta", () => {
    expect(containsIdr(H264_SAMPLE_KEYFRAME)).toBe(true);
    expect(containsIdr(H264_SAMPLE_DELTA)).toBe(false);
  });
});

describe("extractParameterSets + avcCodecString", () => {
  it("extracts SPS/PPS and derives the avc1 codec string", () => {
    const { sps, pps } = extractParameterSets(H264_SAMPLE_KEYFRAME);
    expect(sps).not.toBeNull();
    expect(pps).not.toBeNull();
    expect(avcCodecString(sps!)).toBe(H264_SAMPLE_CODEC_STRING);
  });

  it("returns nulls when no parameter sets are present", () => {
    const { sps, pps } = extractParameterSets(H264_SAMPLE_DELTA);
    expect(sps).toBeNull();
    expect(pps).toBeNull();
  });

  it("falls back to a baseline codec string for a too-short SPS", () => {
    expect(avcCodecString(new Uint8Array([0x67]))).toBe("avc1.42001e");
  });
});
