import { describe, it, expect } from "vitest";

import {
  VideoFragmentReassembler,
  isKeyframe,
  type CompleteAccessUnit,
} from "../src/protocol/reassembler.js";
import type { ParsedVideoFrame } from "../src/protocol/frame.js";
import type { WasmVideoHeader } from "../src/bridge/types.js";

// ── Test helpers ───────────────────────────────────────────────────────────────
//
// Pure logic tests: no wasm bridge, no browser. We build minimal `ParsedVideoFrame` objects
// directly, populating only the header fields the reassembler reads. The other `WasmVideoHeader`
// fields are filled with zeros so the object is structurally a valid header.

/** Fields a caller actually sets when fabricating a fragment for these tests. */
interface FragSpec {
  frameId: number;
  fragIndex: number;
  totalFrags: number;
  marker: boolean;
  payload: number[];
  codec?: number;
  frameType?: number;
}

/** Build a fake `ParsedVideoFrame` from a fragment spec (zero-fills unused header fields). */
function frag(spec: FragSpec): ParsedVideoFrame {
  const header: WasmVideoHeader = {
    frame_id: spec.frameId,
    frag_index: spec.fragIndex,
    total_frags: spec.totalFrags,
    codec: spec.codec ?? 0, // H264
    frame_type: spec.frameType ?? 0, // Predicted
    priority: 0,
    monitor_id: 0,
    marker: spec.marker,
    encode_ts_us: 0,
  };
  return { header, payload: new Uint8Array(spec.payload) };
}

/** Convenience: build a single-fragment (complete) frame. */
function whole(frameId: number, payload: number[], frameType = 0): ParsedVideoFrame {
  return frag({ frameId, fragIndex: 0, totalFrags: 1, marker: true, payload, frameType });
}

describe("VideoFragmentReassembler — single-fragment fast path", () => {
  it("returns the payload immediately for total_frags === 1", () => {
    const r = new VideoFragmentReassembler();
    const out = r.push(whole(7, [1, 2, 3], 1));
    expect(out).not.toBeNull();
    expect(Array.from(out!.payload)).toEqual([1, 2, 3]);
    expect(out!.frameType).toBe(1); // IDR propagated
    expect(out!.codec).toBe(0);
  });

  it("treats total_frags === 0 as a complete (unsplit) frame", () => {
    // A degenerate but non-fragmented header: emit as-is rather than buffer forever.
    const r = new VideoFragmentReassembler();
    const out = r.push(frag({ frameId: 1, fragIndex: 0, totalFrags: 0, marker: true, payload: [9] }));
    expect(out).not.toBeNull();
    expect(Array.from(out!.payload)).toEqual([9]);
  });

  it("returns an independent copy, not a view into the wire buffer", () => {
    const r = new VideoFragmentReassembler();
    const f = whole(1, [1, 2, 3]);
    const out = r.push(f);
    // Mutating the source payload after the call must not corrupt the returned access unit.
    f.payload[0] = 0xff;
    expect(Array.from(out!.payload)).toEqual([1, 2, 3]);
  });
});

describe("VideoFragmentReassembler — multi-fragment reassembly", () => {
  it("returns the exact concatenation only after the marker fragment", () => {
    const r = new VideoFragmentReassembler();
    expect(r.push(frag({ frameId: 5, fragIndex: 0, totalFrags: 3, marker: false, payload: [1, 2] }))).toBeNull();
    expect(r.push(frag({ frameId: 5, fragIndex: 1, totalFrags: 3, marker: false, payload: [3, 4] }))).toBeNull();
    const out = r.push(
      frag({ frameId: 5, fragIndex: 2, totalFrags: 3, marker: true, payload: [5, 6], frameType: 1 }),
    );
    expect(out).not.toBeNull();
    expect(Array.from(out!.payload)).toEqual([1, 2, 3, 4, 5, 6]);
    // frame_type/codec come from the FIRST fragment of the frame.
    expect(out!.frameType).toBe(0); // first fragment was Predicted
  });

  it("propagates frame_type/codec from the head fragment", () => {
    const r = new VideoFragmentReassembler();
    r.push(frag({ frameId: 8, fragIndex: 0, totalFrags: 2, marker: false, payload: [1], frameType: 1, codec: 0 }));
    const out = r.push(frag({ frameId: 8, fragIndex: 1, totalFrags: 2, marker: true, payload: [2], frameType: 0 }));
    expect(out!.frameType).toBe(1); // IDR from the head, not the tail
  });

  it("reassembles consecutive frames cleanly back to back", () => {
    const r = new VideoFragmentReassembler();
    r.push(frag({ frameId: 1, fragIndex: 0, totalFrags: 2, marker: false, payload: [1] }));
    const a = r.push(frag({ frameId: 1, fragIndex: 1, totalFrags: 2, marker: true, payload: [2] }));
    expect(Array.from(a!.payload)).toEqual([1, 2]);

    r.push(frag({ frameId: 2, fragIndex: 0, totalFrags: 2, marker: false, payload: [3] }));
    const b = r.push(frag({ frameId: 2, fragIndex: 1, totalFrags: 2, marker: true, payload: [4] }));
    expect(Array.from(b!.payload)).toEqual([3, 4]);
  });
});

describe("VideoFragmentReassembler — defensive / hostile input (never throws)", () => {
  it("drops a stray non-head fragment (frag_index !== 0 while idle)", () => {
    const r = new VideoFragmentReassembler();
    // We joined mid-frame: the first fragment we see is index 1. Drop it.
    expect(r.push(frag({ frameId: 5, fragIndex: 1, totalFrags: 3, marker: false, payload: [9] }))).toBeNull();
    // A subsequent clean head starts a fresh frame.
    expect(r.push(frag({ frameId: 6, fragIndex: 0, totalFrags: 2, marker: false, payload: [1] }))).toBeNull();
    const out = r.push(frag({ frameId: 6, fragIndex: 1, totalFrags: 2, marker: true, payload: [2] }));
    expect(Array.from(out!.payload)).toEqual([1, 2]);
  });

  it("drops the partial when a fragment for a DIFFERENT frame_id interrupts, then resyncs", () => {
    const r = new VideoFragmentReassembler();
    r.push(frag({ frameId: 1, fragIndex: 0, totalFrags: 3, marker: false, payload: [1] }));
    // A fragment for a different frame_id with frag_index===0 RESTARTS reassembly.
    expect(r.push(frag({ frameId: 2, fragIndex: 0, totalFrags: 2, marker: false, payload: [7] }))).toBeNull();
    const out = r.push(frag({ frameId: 2, fragIndex: 1, totalFrags: 2, marker: true, payload: [8] }));
    // Only the second frame's data survives — the abandoned partial did not corrupt it.
    expect(Array.from(out!.payload)).toEqual([7, 8]);
  });

  it("drops an out-of-order fragment (gap in frag_index) and returns null", () => {
    const r = new VideoFragmentReassembler();
    r.push(frag({ frameId: 1, fragIndex: 0, totalFrags: 3, marker: false, payload: [1] }));
    // Expected index 1, got 2 → corrupt; partial dropped, non-head fragment returns null.
    expect(r.push(frag({ frameId: 1, fragIndex: 2, totalFrags: 3, marker: true, payload: [3] }))).toBeNull();
    // Reassembler resynced: a fresh clean frame works.
    r.push(frag({ frameId: 2, fragIndex: 0, totalFrags: 2, marker: false, payload: [4] }));
    const out = r.push(frag({ frameId: 2, fragIndex: 1, totalFrags: 2, marker: true, payload: [5] }));
    expect(Array.from(out!.payload)).toEqual([4, 5]);
  });

  it("drops a duplicate fragment (same frag_index repeated) without corrupting output", () => {
    const r = new VideoFragmentReassembler();
    r.push(frag({ frameId: 1, fragIndex: 0, totalFrags: 3, marker: false, payload: [1] }));
    // Duplicate of index 0 (expected 1) → inconsistent. It's a non-head duplicate? frag_index 0 is
    // a head, so it RESTARTS the frame fresh on [1] again.
    expect(r.push(frag({ frameId: 1, fragIndex: 0, totalFrags: 3, marker: false, payload: [1] }))).toBeNull();
    r.push(frag({ frameId: 1, fragIndex: 1, totalFrags: 3, marker: false, payload: [2] }));
    const out = r.push(frag({ frameId: 1, fragIndex: 2, totalFrags: 3, marker: true, payload: [3] }));
    expect(Array.from(out!.payload)).toEqual([1, 2, 3]);
  });

  it("drops the partial if total_frags changes mid-frame", () => {
    const r = new VideoFragmentReassembler();
    r.push(frag({ frameId: 1, fragIndex: 0, totalFrags: 3, marker: false, payload: [1] }));
    // Same frame, same next index, but total_frags now disagrees → inconsistent, drop.
    expect(r.push(frag({ frameId: 1, fragIndex: 1, totalFrags: 4, marker: false, payload: [2] }))).toBeNull();
    // Resync on a clean head.
    r.push(frag({ frameId: 9, fragIndex: 0, totalFrags: 2, marker: false, payload: [5] }));
    const out = r.push(frag({ frameId: 9, fragIndex: 1, totalFrags: 2, marker: true, payload: [6] }));
    expect(Array.from(out!.payload)).toEqual([5, 6]);
  });

  it("drops the partial when the marker arrives early (before total_frags fragments)", () => {
    const r = new VideoFragmentReassembler();
    r.push(frag({ frameId: 1, fragIndex: 0, totalFrags: 3, marker: false, payload: [1] }));
    // marker on index 1 of a 3-fragment frame is inconsistent — drop, return null.
    expect(r.push(frag({ frameId: 1, fragIndex: 1, totalFrags: 3, marker: true, payload: [2] }))).toBeNull();
  });

  it("drops a fragment whose total_frags is absurdly large (memory bound)", () => {
    const r = new VideoFragmentReassembler();
    // 4097 > MAX_FRAGMENTS (4096): refuse to begin buffering.
    expect(
      r.push(frag({ frameId: 1, fragIndex: 0, totalFrags: 4097, marker: false, payload: [1] })),
    ).toBeNull();
    // The reassembler stays usable for a sane frame afterwards.
    r.push(frag({ frameId: 2, fragIndex: 0, totalFrags: 2, marker: false, payload: [1] }));
    const out = r.push(frag({ frameId: 2, fragIndex: 1, totalFrags: 2, marker: true, payload: [2] }));
    expect(Array.from(out!.payload)).toEqual([1, 2]);
  });

  it("a complete (single-fragment) frame mid-reassembly discards the orphaned partial", () => {
    const r = new VideoFragmentReassembler();
    r.push(frag({ frameId: 1, fragIndex: 0, totalFrags: 3, marker: false, payload: [1] }));
    // A complete frame arrives before the partial finished: emit it, drop the orphan.
    const out = r.push(whole(2, [9]));
    expect(Array.from(out!.payload)).toEqual([9]);
    // The next clean head starts fresh (the orphan is gone).
    r.push(frag({ frameId: 3, fragIndex: 0, totalFrags: 2, marker: false, payload: [4] }));
    const out2 = r.push(frag({ frameId: 3, fragIndex: 1, totalFrags: 2, marker: true, payload: [5] }));
    expect(Array.from(out2!.payload)).toEqual([4, 5]);
  });
});

describe("isKeyframe", () => {
  const unit = (codec: number, frameType: number): CompleteAccessUnit => ({
    codec,
    frameType,
    payload: new Uint8Array(0),
  });

  it("is true only for an H.264 (codec 0) IDR (frame_type 1)", () => {
    expect(isKeyframe(unit(0, 1))).toBe(true); // H.264 IDR
    expect(isKeyframe(unit(0, 0))).toBe(false); // H.264 predicted
    expect(isKeyframe(unit(0, 2))).toBe(false); // H.264 intra-refresh
    // A frame_type==1 of a non-H.264 codec must NOT be flagged a keyframe (codec guard).
    expect(isKeyframe(unit(1, 1))).toBe(false); // H.265 "IDR"
    expect(isKeyframe(unit(2, 1))).toBe(false); // AV1
  });
});
