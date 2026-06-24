// H.264 Annex-B byte-stream helpers (HOSTILE INPUT).
//
// WebCodecs `VideoDecoder` accepts either `"annexb"` (start-code-delimited) or `"avc"`
// (length-prefixed + an avcC `description`) bitstreams. Streamhaul carries Annex-B NAL units
// in the SHP video payload; the browser decoder is configured in `"annexb"` mode, but it
// still needs SPS/PPS to start, which on a keyframe are typically inline. These helpers split
// NAL units and locate SPS/PPS so the decoder config (and keyframe detection) can be derived
// from the bytes.
//
// All functions treat their input as untrusted host bytes: they never throw on malformed
// input, they bound their scans, and they return empty/`null` results rather than indexing
// out of range.

/** H.264 NAL unit types we care about (nal_unit_type, lower 5 bits of the NAL header). */
export const NalType = {
  NonIdrSlice: 1,
  IdrSlice: 5,
  Sps: 7,
  Pps: 8,
} as const;

/** A located NAL unit: its type and a view of its payload (excluding the start code). */
export interface NalUnit {
  readonly type: number;
  /** The NAL bytes including the 1-byte NAL header, excluding the Annex-B start code. */
  readonly data: Uint8Array;
}

/**
 * Split an Annex-B byte stream into NAL units.
 *
 * Recognizes both 3-byte (`00 00 01`) and 4-byte (`00 00 00 01`) start codes. Returns an
 * empty array for input with no start code. Never throws; bounded by the input length.
 */
export function splitNalUnits(stream: Uint8Array): NalUnit[] {
  const units: NalUnit[] = [];
  const n = stream.length;
  // Find all start-code offsets first, then slice between them.
  const starts: { offset: number; scLen: number }[] = [];
  let i = 0;
  while (i + 3 <= n) {
    if (stream[i] === 0 && stream[i + 1] === 0) {
      if (stream[i + 2] === 1) {
        starts.push({ offset: i, scLen: 3 });
        i += 3;
        continue;
      }
      if (i + 4 <= n && stream[i + 2] === 0 && stream[i + 3] === 1) {
        starts.push({ offset: i, scLen: 4 });
        i += 4;
        continue;
      }
    }
    i += 1;
  }
  for (let s = 0; s < starts.length; s++) {
    const cur = starts[s];
    if (cur === undefined) continue;
    const dataStart = cur.offset + cur.scLen;
    const next = starts[s + 1];
    const dataEnd = next === undefined ? n : next.offset;
    if (dataStart >= dataEnd) continue;
    const data = stream.subarray(dataStart, dataEnd);
    const headerByte = data[0];
    if (headerByte === undefined) continue;
    const type = headerByte & 0x1f;
    units.push({ type, data });
  }
  return units;
}

/** Whether an Annex-B stream contains an IDR (keyframe) slice NAL. */
export function containsIdr(stream: Uint8Array): boolean {
  return splitNalUnits(stream).some((u) => u.type === NalType.IdrSlice);
}

/** The SPS and PPS NAL units found in an Annex-B stream (if present). */
export interface ParameterSets {
  readonly sps: Uint8Array | null;
  readonly pps: Uint8Array | null;
}

/** Extract the first SPS and PPS NAL units from an Annex-B stream. */
export function extractParameterSets(stream: Uint8Array): ParameterSets {
  let sps: Uint8Array | null = null;
  let pps: Uint8Array | null = null;
  for (const u of splitNalUnits(stream)) {
    if (u.type === NalType.Sps && sps === null) sps = u.data;
    else if (u.type === NalType.Pps && pps === null) pps = u.data;
  }
  return { sps, pps };
}

/**
 * Derive the WebCodecs `codec` string for an H.264 SPS NAL.
 *
 * The string is `"avc1.PPCCLL"` where PP=profile_idc, CC=constraint flags byte, LL=level_idc,
 * read from the first three bytes after the SPS NAL header. Falls back to a baseline-ish
 * `"avc1.42001e"` if the SPS is too short to read those bytes (so configuration can still be
 * attempted; the decoder will reject genuinely invalid input itself).
 */
export function avcCodecString(sps: Uint8Array): string {
  // sps.data[0] is the NAL header; profile/constraints/level are the next three bytes.
  const profile = sps[1];
  const constraints = sps[2];
  const level = sps[3];
  if (profile === undefined || constraints === undefined || level === undefined) {
    return "avc1.42001e";
  }
  const hex = (b: number): string => b.toString(16).padStart(2, "0");
  return `avc1.${hex(profile)}${hex(constraints)}${hex(level)}`;
}
