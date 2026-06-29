// SHP video-fragment REASSEMBLY on the browser side (HOSTILE INPUT).
//
// The native host splits large H.264 access units into multiple SHP video fragments that share a
// `frame_id` and are sequenced by `frag_index` (0..total_frags-1), with `marker === true` only on
// the LAST fragment. Each inbound DataChannel message is one fragment, already parsed by
// `parseVideoFrame` into a `ParsedVideoFrame`. This module accumulates the fragments of one frame
// and returns the COMPLETE Annex-B access unit once the marker fragment lands.
//
// The DataChannel is reliable + ordered, so the common case is strictly in-order delivery. But
// every byte that crosses the wire is untrusted: a hostile/buggy host could send fragments out of
// order, with mismatched `total_frags`, for an interleaved `frame_id`, or an unbounded count. This
// reassembler is fully defensive — it NEVER throws, drops a corrupt partial frame and resyncs, and
// bounds the in-progress buffer so a malicious stream cannot exhaust memory.

import type { ParsedVideoFrame } from "./frame.js";
import { Codec } from "./constants.js";

/** A fully reassembled access unit, ready to hand to the decoder. */
export interface CompleteAccessUnit {
  /** `frame_type` of the completed frame (0=Predicted, 1=IDR, 2=IntraRefresh). */
  readonly frameType: number;
  /** Codec discriminant of the completed frame (0=H264, 1=H265, 2=AV1, 3=Raw). */
  readonly codec: number;
  /** The concatenated Annex-B access unit (a freshly-owned copy, not a view into wire buffers). */
  readonly payload: Uint8Array;
}

/** Whether a completed access unit is an H.264 IDR — a keyframe the decoder can start on. Guards
 *  on codec too, so a `frame_type==1` unit of a future non-H.264 codec is not mislabeled. */
export function isKeyframe(unit: CompleteAccessUnit): boolean {
  return unit.codec === Codec.H264 && unit.frameType === 1;
}

/**
 * Hard ceiling on how many fragments a single frame may be split into before we treat the stream
 * as hostile and drop the partial. `total_frags` is a wire field; a crafted huge value must not let
 * an attacker make us allocate an unbounded buffer array. The host's own `total_frags` is an 8-bit
 * field (≤ 255), so any legitimate value is far below 4096; the byte cap below is the binding limit
 * for oversized chunks.
 */
const MAX_FRAGMENTS = 4096;

/**
 * Hard ceiling on the total buffered payload bytes for one in-progress frame. A hostile host could
 * advertise a small `total_frags` yet send oversized chunks; this cap bounds memory independently
 * of the fragment count. 16 MiB comfortably exceeds any realistic single-frame access unit.
 */
const MAX_BUFFERED_BYTES = 16 * 1024 * 1024;

/**
 * Reassembles SHP video fragments into complete Annex-B access units.
 *
 * Construct ONE per session (fragment state is per-stream). Feed every parsed inbound video frame
 * to {@link push}; it returns the complete access unit when a frame finishes, or `null` while more
 * fragments are still needed (or when a corrupt fragment is dropped).
 *
 * The class is pure and synchronous: no I/O, no timers, no dependencies beyond `ParsedVideoFrame`.
 */
export class VideoFragmentReassembler {
  /** The `frame_id` currently being reassembled, or `null` when idle (no partial buffered). */
  private currentFrameId: number | null = null;
  /** The `total_frags` declared by the first fragment of the in-progress frame. */
  private expectedTotal = 0;
  /** The next `frag_index` we require (fragments must arrive strictly in order). */
  private nextIndex = 0;
  /** The codec discriminant of the in-progress frame (taken from its first fragment). */
  private codec = 0;
  /** The frame_type of the in-progress frame (taken from its first fragment). */
  private frameType = 0;
  /** Buffered payload chunks (copies) for the in-progress frame, in `frag_index` order. */
  private chunks: Uint8Array[] = [];
  /** Running total of buffered payload bytes, for the memory cap. */
  private bufferedBytes = 0;

  /**
   * Feed a parsed inbound video frame.
   *
   * @returns the COMPLETE access unit when the frame is fully reassembled (single-fragment frames
   *   complete immediately); `null` when more fragments are still required, or when a malformed /
   *   out-of-order fragment was dropped. Never throws.
   */
  public push(frame: ParsedVideoFrame): CompleteAccessUnit | null {
    const { total_frags, frag_index, frame_id, marker, codec, frame_type } = frame.header;

    // ── Fast path: a complete, unsplit frame. No buffering, no state interaction beyond
    //    discarding any (now-orphaned) partial — a complete frame mid-reassembly means the prior
    //    partial will never finish, so drop it to free memory and stay in sync. ──
    if (total_frags <= 1) {
      this.reset();
      return { frameType: frame_type, codec, payload: this.copyOf(frame.payload) };
    }

    // ── Multi-fragment frame. Guard the declared fragment count before trusting it. ──
    if (!Number.isInteger(total_frags) || total_frags > MAX_FRAGMENTS) {
      this.reset();
      return null;
    }

    const isFirst = this.currentFrameId === null;

    if (isFirst) {
      // Not mid-reassembly: only a frag_index===0 fragment may START a new frame. Anything else is
      // a stray middle/tail fragment (e.g. we joined the stream late, or lost the head) — drop it.
      if (frag_index !== 0) {
        return null;
      }
      this.begin(frame_id, total_frags, codec, frame_type);
    } else {
      // Mid-reassembly: the fragment MUST continue the current frame exactly. Any inconsistency
      // (different frame_id, changed total_frags, or a gap/duplicate in frag_index) means the
      // partial is corrupt. Drop it and resync: if this fragment is itself a clean frame head
      // (frag_index===0), start fresh on it; otherwise discard and wait for the next head.
      const consistent =
        frame_id === this.currentFrameId &&
        total_frags === this.expectedTotal &&
        frag_index === this.nextIndex;
      if (!consistent) {
        this.reset();
        if (frag_index === 0) {
          this.begin(frame_id, total_frags, codec, frame_type);
        } else {
          return null;
        }
      }
    }

    // Append this fragment's payload (as an owned copy — the wire buffer may be reused/detached).
    const copy = this.copyOf(frame.payload);
    this.bufferedBytes += copy.length;
    // Bound memory: a hostile host could send oversized chunks under a small total_frags. If the
    // partial exceeds the byte cap, treat the stream as hostile and drop it.
    if (this.bufferedBytes > MAX_BUFFERED_BYTES) {
      this.reset();
      return null;
    }
    this.chunks.push(copy);
    this.nextIndex += 1;

    // The marker fragment terminates the frame. It must be the LAST declared fragment; if `marker`
    // arrives early (frag_index < total_frags-1) the host is inconsistent — drop the partial.
    if (marker) {
      if (this.nextIndex !== this.expectedTotal) {
        this.reset();
        return null;
      }
      const result: CompleteAccessUnit = {
        frameType: this.frameType,
        codec: this.codec,
        payload: this.concatChunks(),
      };
      this.reset();
      return result;
    }

    // Not the last fragment yet, but if we've already collected `total_frags` fragments WITHOUT a
    // marker the host is inconsistent (no terminating marker) — drop to avoid waiting forever.
    if (this.nextIndex >= this.expectedTotal) {
      this.reset();
      return null;
    }

    return null; // more fragments needed
  }

  /** Begin buffering a fresh multi-fragment frame from its (validated) head fragment. */
  private begin(frameId: number, totalFrags: number, codec: number, frameType: number): void {
    this.currentFrameId = frameId;
    this.expectedTotal = totalFrags;
    this.nextIndex = 0;
    this.codec = codec;
    this.frameType = frameType;
    this.chunks = [];
    this.bufferedBytes = 0;
  }

  /** Discard any in-progress partial and return to the idle state. */
  private reset(): void {
    this.currentFrameId = null;
    this.expectedTotal = 0;
    this.nextIndex = 0;
    this.codec = 0;
    this.frameType = 0;
    this.chunks = [];
    this.bufferedBytes = 0;
  }

  /** Copy a wire payload view into an owned buffer (decouples it from a reusable wire buffer). */
  private copyOf(view: Uint8Array): Uint8Array {
    const owned = new Uint8Array(view.length);
    owned.set(view);
    return owned;
  }

  /** Concatenate the buffered fragment chunks into one contiguous access unit. */
  private concatChunks(): Uint8Array {
    const out = new Uint8Array(this.bufferedBytes);
    let offset = 0;
    for (const chunk of this.chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }
}
