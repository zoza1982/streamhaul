// Committed sample H.264 Annex-B fixture for the PURE-LOGIC unit tests.
//
// ## Provenance
//
// This is a hand-constructed, minimal Annex-B byte stream (NOT a fully decodable picture).
// It contains three start-code-delimited NAL units whose *headers* are real H.264:
//   1. SPS (nal_unit_type 7) with a Baseline profile_idc=0x42, constraint=0x00, level=0x1e,
//      matching the WebCodecs codec string `avc1.42001e` (H.264 Baseline, Level 3.0).
//   2. PPS (nal_unit_type 8).
//   3. IDR slice (nal_unit_type 5) — marks this access unit as a keyframe.
//
// It is deterministic and committed so the NAL-splitting / parameter-set-extraction /
// keyframe-detection logic in `src/view/annexb.ts` and `src/protocol/frame.ts` is tested
// against fixed bytes. It is deliberately NOT used for a real WebCodecs decode (the slice
// payload is filler, not a coded macroblock) — the e2e (`e2e/loopback.spec.ts`) instead
// encodes a REAL keyframe in-browser with WebCodecs `VideoEncoder` and decodes it back, so
// the decode→pixel path is proven with a genuinely decodable, decoder-matched frame.
//
// References: USB-irrelevant; H.264 / ISO-IEC 14496-10 Annex B (start codes) and §7.3
// (NAL unit syntax). The byte values below are the minimal well-formed NAL headers.

/** 4-byte Annex-B start code. */
const SC = [0x00, 0x00, 0x00, 0x01];

/** SPS NAL: header 0x67 (nal_ref_idc=3, type=7) + profile/constraints/level + filler. */
const SPS = [0x67, 0x42, 0x00, 0x1e, 0x8c, 0x8d, 0x40];

/** PPS NAL: header 0x68 (nal_ref_idc=3, type=8) + filler. */
const PPS = [0x68, 0xce, 0x3c, 0x80];

/** IDR slice NAL: header 0x65 (nal_ref_idc=3, type=5) + filler slice bytes. */
const IDR = [0x65, 0x88, 0x84, 0x00, 0x10, 0xff];

/** The committed Annex-B keyframe access unit (SPS + PPS + IDR), with 4-byte start codes. */
export const H264_SAMPLE_KEYFRAME: Uint8Array = new Uint8Array([
  ...SC,
  ...SPS,
  ...SC,
  ...PPS,
  ...SC,
  ...IDR,
]);

/** The expected WebCodecs codec string derived from the SPS above. */
export const H264_SAMPLE_CODEC_STRING = "avc1.42001e";

/** A delta (non-IDR) access unit: a single P-slice NAL (type 1) with a 3-byte start code. */
export const H264_SAMPLE_DELTA: Uint8Array = new Uint8Array([
  0x00, 0x00, 0x01, // 3-byte start code (exercise both start-code lengths)
  0x41, 0x9a, 0x00, 0x20, // header 0x41 (type=1, non-IDR) + filler
]);
