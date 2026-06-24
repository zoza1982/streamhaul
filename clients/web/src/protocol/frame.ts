// SHP video-frame parsing on the browser side (HOSTILE INPUT).
//
// An inbound DataChannel message on the video channel is: [9-byte CommonHeader]
// [12-byte VideoHeader] [codec payload]. The header *decoding* is delegated to the wasm
// bridge (`decode_common_header` / `decode_video_header`), which is fuzzed and panic-free;
// this module only slices the payload off and surfaces a typed result. Every host byte is
// untrusted: a malformed frame yields `null` (caller drops it), never a throw that escapes.

import { Codec } from "./constants.js";
import type { ShBridge, WasmVideoHeader } from "../bridge/types.js";

/** Byte length of the SHP common header (9-byte wire prefix). */
export const COMMON_HEADER_LEN = 9;
/** Byte length of the SHP video header (12-byte, follows the common header). */
export const VIDEO_HEADER_LEN = 12;

/** SHP `ChannelId::Video` discriminant (matches `sh_types::ChannelId`: Video=0, Audio=1,
 * Input=2, Control=5). */
export const CHANNEL_VIDEO = 0;

/** A parsed SHP video frame: the decoded video header + the codec payload slice. */
export interface ParsedVideoFrame {
  readonly header: WasmVideoHeader;
  /** The codec payload (e.g. H.264 Annex-B / fragment bytes) — a view, not a copy owner. */
  readonly payload: Uint8Array;
}

/**
 * Parse an inbound SHP frame as a video frame, or return `null` if it is not a well-formed
 * video frame.
 *
 * Returns `null` (never throws) when:
 * - the buffer is too short for the common+video headers,
 * - the common header is malformed or not on the video channel,
 * - the video header is malformed (bad codec/reserved bits/etc.).
 *
 * The header decoders are the fuzzed, panic-free wasm bridge functions; any error they raise
 * is caught here so a hostile host can never crash the viewer with a crafted frame.
 */
export function parseVideoFrame(
  bridge: ShBridge,
  frame: Uint8Array,
): ParsedVideoFrame | null {
  if (frame.length < COMMON_HEADER_LEN + VIDEO_HEADER_LEN) {
    return null;
  }
  try {
    const common = bridge.decode_common_header(frame.subarray(0, COMMON_HEADER_LEN));
    if (common.channel !== CHANNEL_VIDEO) {
      return null;
    }
    const header = bridge.decode_video_header(
      frame.subarray(COMMON_HEADER_LEN, COMMON_HEADER_LEN + VIDEO_HEADER_LEN),
    );
    const payload = frame.subarray(COMMON_HEADER_LEN + VIDEO_HEADER_LEN);
    return { header, payload };
  } catch {
    // Malformed header from a hostile host — drop the frame, keep the session alive.
    return null;
  }
}

/** Whether a parsed frame is an H.264 keyframe (IDR) the decoder can start on. */
export function isH264Keyframe(frame: ParsedVideoFrame): boolean {
  // frame_type: 0=Predicted, 1=IDR, 2=IntraRefresh.
  return frame.header.codec === Codec.H264 && frame.header.frame_type === 1;
}
