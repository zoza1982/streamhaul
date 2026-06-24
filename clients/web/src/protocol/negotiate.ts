// H.264 codec negotiation for the browser, over the wasm capability codec.
//
// Per ADR-0003 / LLD: browsers cannot AV1-*encode* and the universally-decodable browser
// codec is H.264, so the browser advertises H.264 decode and the negotiated session codec is
// H.264. The capability *encoding* is performed by the wasm bridge (`encode_caps` /
// `decode_caps`); this module only assembles the browser's offer and applies the selection
// rule against a host's advertised capabilities.

import { Codec, CODEC_NONE } from "./constants.js";
import type { ShBridge, WasmCodecCaps } from "../bridge/types.js";

/** HW-decode mask bit for a codec discriminant (bit N = codec N). */
function decodeBit(codec: number): number {
  return 1 << codec;
}

/**
 * Build the browser's codec-capability OFFER bytes.
 *
 * The browser:
 * - advertises H.264 hardware/native decode (`hw_decode_mask` bit 0),
 * - sets `is_browser = true`,
 * - advertises no hardware encode and no software H.264 encode (a viewer-only browser
 *   client does not encode video), and
 * - leaves `selected_codec` unset (`0xFF`) — an offer does not pick the codec.
 */
export function buildBrowserOffer(bridge: ShBridge): Uint8Array {
  return bridge.encode_caps(
    0, // hw_encode_mask: browser does not encode video
    decodeBit(Codec.H264), // hw_decode_mask: native H.264 decode (WebCodecs / WebRTC)
    false, // sw_h264_encode_available
    false, // is_apple
    true, // is_browser
    CODEC_NONE, // selected_codec: none in an offer
  );
}

/** The result of negotiating a session codec from the browser offer + host caps. */
export interface CodecSelection {
  /** Selected codec discriminant (`Codec.*`). */
  readonly codec: number;
  /** The 4-byte capability ANSWER bytes (with `selected_codec` set), for the wire. */
  readonly answerBytes: Uint8Array;
}

/**
 * Select the session codec from the host's advertised capabilities and the browser's
 * constraints, returning the discriminant and the encoded capability answer.
 *
 * Rule (browser side): the browser can only render H.264, so H.264 is selected iff the host
 * can deliver it. The host can deliver H.264 if it can hardware- or software-encode H.264;
 * `decode_caps` exposes `hw_encode_mask` (bit 0 ⇒ HW H.264 encode) and
 * `sw_h264_encode_available`. If neither is present, there is no common codec.
 *
 * @throws if the host advertises no H.264 production path (no common codec).
 */
export function selectCodec(bridge: ShBridge, hostCapsBytes: Uint8Array): CodecSelection {
  const host: WasmCodecCaps = bridge.decode_caps(hostCapsBytes);
  const hostHasH264 =
    (host.hw_encode_mask & decodeBit(Codec.H264)) !== 0 ||
    host.sw_h264_encode_available;
  if (!hostHasH264) {
    throw new Error(
      "no common codec: host advertises no H.264 encode path, but the browser can only render H.264",
    );
  }
  // Echo the browser's decode capability with H.264 selected in the answer.
  const answerBytes = bridge.encode_caps(
    0,
    decodeBit(Codec.H264),
    false,
    false,
    true,
    Codec.H264,
  );
  return { codec: Codec.H264, answerBytes };
}
