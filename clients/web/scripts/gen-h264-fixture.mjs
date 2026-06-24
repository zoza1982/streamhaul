// One-shot generator for the committed, decodable H.264 keyframe e2e fixture.
//
// ## Why constructed by hand (provenance)
//
// In this environment NO H.264 *encoder* is available: Firefox's WebCodecs VideoEncoder is
// unsupported, headless Chromium cannot create an H.264 encoder ("Encoder creation error"),
// Playwright's bundled ffmpeg has only a VP8 encoder, and the system has no ffmpeg/libx264.
// Both Firefox and Chromium WebCodecs *decoders* DO decode H.264, which is the path the viewer
// exercises. So we construct a minimal, genuinely-decodable H.264 baseline keyframe bitstream
// directly per ISO/IEC 14496-10, using **I_PCM macroblocks** (mb_type that carries raw pixel
// samples with no transform/CAVLC entropy coding) so the bytes are fully transparent and
// reproducible without any encoder dependency.
//
// The result is a 16x16, single-IDR-frame Annex-B bitstream (SPS + PPS + IDR) of a solid
// mid-gray picture (Y=128, Cb=Cr=128). Regenerate with `node scripts/gen-h264-fixture.mjs`.
//
// This is dev-only tooling; the generated fixture (committed) is consumed only by the e2e.

import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(here, "..");

const WIDTH = 16;
const HEIGHT = 16;

// ── Minimal bitstream writer (MSB-first) ──────────────────────────────────────
class BitWriter {
  constructor() {
    this.bytes = [];
    this.cur = 0;
    this.nbits = 0;
  }
  bit(b) {
    this.cur = (this.cur << 1) | (b & 1);
    this.nbits++;
    if (this.nbits === 8) {
      this.bytes.push(this.cur & 0xff);
      this.cur = 0;
      this.nbits = 0;
    }
  }
  u(value, n) {
    for (let i = n - 1; i >= 0; i--) this.bit((value >> i) & 1);
  }
  // Exp-Golomb unsigned.
  ue(value) {
    let v = value + 1;
    let bits = 0;
    let t = v;
    while (t > 1) {
      t >>= 1;
      bits++;
    }
    for (let i = 0; i < bits; i++) this.bit(0);
    for (let i = bits; i >= 0; i--) this.bit((v >> i) & 1);
  }
  se(value) {
    if (value === 0) this.ue(0);
    else if (value > 0) this.ue(2 * value - 1);
    else this.ue(-2 * value);
  }
  // Byte-align with rbsp_trailing_bits (a 1 then zeros).
  rbspTrailing() {
    this.bit(1);
    while (this.nbits !== 0) this.bit(0);
  }
  alignZero() {
    while (this.nbits !== 0) this.bit(0);
  }
  bytesOut() {
    if (this.nbits !== 0) {
      // flush remaining (should not happen after alignment)
      this.bytes.push((this.cur << (8 - this.nbits)) & 0xff);
      this.cur = 0;
      this.nbits = 0;
    }
    return this.bytes.slice();
  }
}

// Emulation-prevention: insert 0x03 after any 00 00 0x (x<=3) run in the RBSP.
function ebsp(rbsp) {
  const out = [];
  let zeros = 0;
  for (const b of rbsp) {
    if (zeros >= 2 && b <= 3) {
      out.push(0x03);
      zeros = 0;
    }
    out.push(b);
    zeros = b === 0 ? zeros + 1 : 0;
  }
  return out;
}

const START = [0, 0, 0, 1];

function nalUnit(nalRefIdc, nalType, rbspBytes) {
  const header = (0 << 7) | ((nalRefIdc & 3) << 5) | (nalType & 0x1f);
  return [...START, header, ...ebsp(rbspBytes)];
}

// ── SPS (Baseline, profile_idc=66, 16x16) ─────────────────────────────────────
function buildSps() {
  const w = new BitWriter();
  w.u(66, 8); // profile_idc = Baseline
  w.u(0, 8); // constraint flags + reserved
  w.u(20, 8); // level_idc = 2.0 (0x14)
  w.ue(0); // seq_parameter_set_id
  w.ue(0); // log2_max_frame_num_minus4
  w.ue(0); // pic_order_cnt_type
  w.ue(0); // log2_max_pic_order_cnt_lsb_minus4
  w.ue(1); // max_num_ref_frames
  w.bit(0); // gaps_in_frame_num_value_allowed_flag
  w.ue(WIDTH / 16 - 1); // pic_width_in_mbs_minus1 = 0
  w.ue(HEIGHT / 16 - 1); // pic_height_in_map_units_minus1 = 0
  w.bit(1); // frame_mbs_only_flag
  w.bit(0); // direct_8x8_inference_flag
  w.bit(0); // frame_cropping_flag
  w.bit(0); // vui_parameters_present_flag
  w.rbspTrailing();
  return w.bytesOut();
}

// ── PPS ────────────────────────────────────────────────────────────────────
function buildPps() {
  const w = new BitWriter();
  w.ue(0); // pic_parameter_set_id
  w.ue(0); // seq_parameter_set_id
  w.bit(0); // entropy_coding_mode_flag (CAVLC)
  w.bit(0); // bottom_field_pic_order_in_frame_present_flag
  w.ue(0); // num_slice_groups_minus1
  w.ue(0); // num_ref_idx_l0_default_active_minus1
  w.ue(0); // num_ref_idx_l1_default_active_minus1
  w.bit(0); // weighted_pred_flag
  w.u(0, 2); // weighted_bipred_idc
  w.se(0); // pic_init_qp_minus26
  w.se(0); // pic_init_qs_minus26
  w.se(0); // chroma_qp_index_offset
  w.bit(1); // deblocking_filter_control_present_flag
  w.bit(0); // constrained_intra_pred_flag
  w.bit(0); // redundant_pic_cnt_present_flag
  w.rbspTrailing();
  return w.bytesOut();
}

// ── IDR slice with one I_PCM macroblock (raw samples, no entropy coding) ───────
function buildIdrSlice() {
  const w = new BitWriter();
  // slice_header
  w.ue(0); // first_mb_in_slice
  w.ue(7); // slice_type = 7 (I, all slices in pic are I)
  w.ue(0); // pic_parameter_set_id
  w.u(0, 4); // frame_num (log2_max_frame_num_minus4=0 -> 4 bits)
  w.ue(0); // idr_pic_id
  w.u(0, 4); // pic_order_cnt_lsb (log2_max_poc_lsb_minus4=0 -> 4 bits)
  // dec_ref_pic_marking (IDR): no_output_of_prior_pics_flag, long_term_reference_flag
  w.bit(0);
  w.bit(0);
  w.se(0); // slice_qp_delta
  // deblocking_filter_control_present_flag=1 -> disable_deblocking_filter_idc
  w.ue(1); // disable deblocking

  // slice_data: one macroblock, I_PCM.
  // mb_type for I slice: I_PCM = 25 -> ue(25).
  w.ue(25);
  // pcm_alignment_zero_bits
  w.alignZero();
  // 16x16 luma samples + 8x8 Cb + 8x8 Cr, all 8-bit, value 128 (mid gray / neutral chroma).
  for (let i = 0; i < 16 * 16; i++) w.u(128, 8);
  for (let i = 0; i < 8 * 8; i++) w.u(128, 8);
  for (let i = 0; i < 8 * 8; i++) w.u(128, 8);
  // After I_PCM, slice ends; add rbsp trailing.
  w.rbspTrailing();
  return w.bytesOut();
}

const sps = nalUnit(3, 7, buildSps());
const pps = nalUnit(3, 8, buildPps());
const idr = nalUnit(3, 5, buildIdrSlice());
const bytes = [...sps, ...pps, ...idr];

const out = `// GENERATED by scripts/gen-h264-fixture.mjs — DO NOT EDIT BY HAND.
//
// A real, decodable H.264 keyframe (Annex-B) for the Playwright headless-Firefox e2e.
//
// ## Provenance (reproducible, encoder-free)
//
// No H.264 *encoder* exists in this environment (Firefox/Chromium WebCodecs VideoEncoder
// unsupported; Playwright ffmpeg = VP8 only; no system ffmpeg/libx264). This bitstream is
// therefore constructed directly per ISO/IEC 14496-10: a Baseline SPS (profile_idc=66,
// level 2.0, ${WIDTH}x${HEIGHT}) + PPS + an IDR slice whose single macroblock is **I_PCM**
// (raw 8-bit samples, no transform/CAVLC entropy coding) carrying a solid mid-gray picture
// (Y=Cb=Cr=128). I_PCM keeps the bytes fully transparent and decoder-independent. Both
// Firefox and Chromium WebCodecs decoders decode it to a real ${WIDTH}x${HEIGHT} VideoFrame —
// the exact viewer path the e2e asserts (decode -> canvas pixels).
//
// Regenerate with: \`node scripts/gen-h264-fixture.mjs\`.

/** Coded dimensions of the generated keyframe. */
export const H264_KEYFRAME_WIDTH = ${WIDTH};
export const H264_KEYFRAME_HEIGHT = ${HEIGHT};

/** The decodable H.264 Annex-B keyframe bytes (${bytes.length} bytes). */
export const H264_KEYFRAME = new Uint8Array([
  ${bytes.join(", ")},
]);
`;

const dest = resolve(webRoot, "test", "fixtures", "h264-keyframe.generated.ts");
writeFileSync(dest, out);
console.log(`wrote ${bytes.length}-byte keyframe -> ${dest}`);
