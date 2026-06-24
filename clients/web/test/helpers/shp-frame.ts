// TEST-ONLY host emulation: build an SHP video frame (CommonHeader + VideoHeader + payload).
//
// The browser is a viewer: it only ever *decodes* SHP headers, so the production wasm bridge
// (`sh-wasm`) exposes header DECODE but not header ENCODE for video. To exercise the viewer's
// receive path (and to let the in-page loopback "host" in the e2e produce a frame the viewer
// can parse), this helper assembles the header bytes per the SHP wire layout.
//
// This is test scaffolding emulating the host's encoder — NOT production code. Its correctness
// is asserted in `test/frame.test.ts` ("buildShpVideoFrame wire correctness") by round-tripping
// the result through the production decoders (`decode_common_header` / `decode_video_header`,
// the same fuzzed wasm codec the browser runs) and checking every field (channel, sequence,
// payload_len, frame_id, codec, frame_type, monitor_id) — so the emulation cannot drift from the
// real wire format without failing a test.
//
// Wire layout (mirrors sh-protocol::common / sh-protocol::video, proven by sh-wasm golden tests):
//   CommonHeader byte0 = (VERSION<<6) | (channel<<2) | (fragment<<1) | last_fragment
//   VideoHeader  byte5 = (codec<<4) | (frame_type<<2) | priority
//   VideoHeader  byte6 = (monitor<<4) | (marker<<3)

const SHP_VERSION = 0b01;
// sh_types::ChannelId: Video=0, Audio=1, Input=2, Control=5.
const CHANNEL_VIDEO = 0;

/** Options for the emulated SHP video frame (sensible defaults for a single-fragment keyframe). */
export interface ShpVideoFrameOptions {
  readonly payload: Uint8Array;
  readonly frameId?: number;
  readonly sequence?: number;
  readonly codec?: number; // 0=H264
  readonly frameType?: number; // 1=IDR
  readonly priority?: number; // 2=High
  readonly monitorId?: number;
  readonly timestampUs?: number;
  readonly encodeTsUs?: number;
}

function u16be(v: number): [number, number] {
  return [(v >> 8) & 0xff, v & 0xff];
}
function u32be(v: number): [number, number, number, number] {
  return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
}

/** Assemble a single-fragment SHP video frame (CommonHeader + VideoHeader + payload). */
export function buildShpVideoFrame(opts: ShpVideoFrameOptions): Uint8Array {
  const frameId = opts.frameId ?? 1;
  const sequence = opts.sequence ?? 0;
  const codec = opts.codec ?? 0; // H264
  const frameType = opts.frameType ?? 1; // IDR
  const priority = opts.priority ?? 2; // High
  const monitorId = opts.monitorId ?? 0;
  const timestampUs = opts.timestampUs ?? 0;
  const encodeTsUs = opts.encodeTsUs ?? 0;
  const payloadLen = opts.payload.length;

  // CommonHeader (9 bytes), single non-fragmented packet (fragment=0, last_fragment=0).
  const byte0 = (SHP_VERSION << 6) | ((CHANNEL_VIDEO & 0x0f) << 2);
  const [s0, s1] = u16be(sequence);
  const [t0, t1, t2, t3] = u32be(timestampUs);
  const [l0, l1] = u16be(payloadLen);
  const common = [byte0, s0, s1, t0, t1, t2, t3, l0, l1];

  // VideoHeader (12 bytes). frame_id is a 24-bit wire field → low 3 bytes, big-endian.
  const fid = u32be(frameId);
  const fByte0 = fid[1] ?? 0;
  const fByte1 = fid[2] ?? 0;
  const fByte2 = fid[3] ?? 0;
  const fragIndex = 0;
  const totalFrags = 1;
  const byte5 = ((codec & 0x0f) << 4) | ((frameType & 0x03) << 2) | (priority & 0x03);
  const marker = 1; // last (only) fragment of the frame
  const byte6 = ((monitorId & 0x0f) << 4) | (marker << 3);
  const reserved = 0x00;
  const [e0, e1, e2, e3] = u32be(encodeTsUs);
  const video = [fByte0, fByte1, fByte2, fragIndex, totalFrags, byte5, byte6, reserved, e0, e1, e2, e3];

  const out = new Uint8Array(common.length + video.length + payloadLen);
  out.set(common, 0);
  out.set(video, common.length);
  out.set(opts.payload, common.length + video.length);
  return out;
}
