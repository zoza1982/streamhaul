//! Generate the baked H.264 fixture the workspace `streamhaul-webrtc-host` streams to the browser
//! (ADR-0031). This keeps a real, browser-decodable H.264 clip in the repo **without** the default
//! workspace build ever depending on OpenH264 (which lives only in this excluded crate).
//!
//! Run: `cargo run --manifest-path crates/sh-codec-openh264/Cargo.toml --example gen_browser_fixture`
//! It writes `bins/streamhaul-webrtc-host/fixtures/sample_h264.shv`.
//!
//! Fixture format (little-endian), a sequence of frames until EOF:
//!   [u32 payload_len][u8 frame_type (0=Predicted,1=Idr,2=IntraRefresh)][payload_len bytes Annex-B]
//!
//! The first frame is an IDR (with SPS/PPS) so the browser's WebCodecs decoder can configure and
//! start on it. Frames are 320x240 so each stays well under the SHP 16-bit payload-length cap.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::Write as _;

use bytes::Bytes;
use sh_codec_openh264::OpenH264Encoder;
use sh_media::{EncoderConfig, PixelFormat, Resolution, VideoEncoder, VideoFrame};
use sh_protocol::{Codec, FrameType};
use sh_types::{FrameId, TimestampUs};

const W: u32 = 320;
const H: u32 = 240;
const FRAMES: usize = 16;

fn synthetic_bgra(seq: usize) -> VideoFrame {
    let mut data = vec![0u8; (W as usize) * (H as usize) * 4];
    for (i, px) in data.chunks_exact_mut(4).enumerate() {
        // A moving gradient so successive frames differ (real P-frames, not skips).
        px[0] = ((i + seq * 23) % 251) as u8; // B
        px[1] = ((i / 4 + seq * 11) % 251) as u8; // G
        px[2] = ((i / 8 + seq * 5) % 251) as u8; // R
        px[3] = 255;
    }
    VideoFrame {
        data: Bytes::from(data),
        format: PixelFormat::Bgra8,
        resolution: Resolution::new(W, H),
        frame_id: FrameId(seq as u64),
        capture_ts_us: TimestampUs(seq as u64 * 1000),
    }
}

fn frame_type_byte(ft: FrameType) -> u8 {
    match ft {
        FrameType::Predicted => 0,
        FrameType::Idr => 1,
        FrameType::IntraRefresh => 2,
    }
}

fn main() {
    let cfg = EncoderConfig {
        codec: Codec::H264,
        resolution: Resolution::new(W, H),
        target_fps: 30,
        target_bitrate_kbps: Some(2_000),
    };
    let mut enc = OpenH264Encoder::with_config(&cfg).expect("encoder");
    enc.request_keyframe(); // first frame is an IDR (SPS/PPS) the browser can configure on

    let mut out: Vec<u8> = Vec::new();
    let mut count = 0usize;
    for seq in 0..FRAMES {
        let Some(pkt) = enc.encode(&synthetic_bgra(seq)).expect("encode") else {
            continue;
        };
        let len = u32::try_from(pkt.data.len()).expect("frame fits u32");
        assert!(
            len <= u32::from(u16::MAX),
            "frame exceeds SHP 16-bit payload cap"
        );
        out.extend_from_slice(&len.to_le_bytes());
        out.push(frame_type_byte(pkt.frame_type));
        out.extend_from_slice(&pkt.data);
        count += 1;
    }

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../bins/streamhaul-webrtc-host/fixtures/sample_h264.shv"
    );
    if let Some(dir) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(dir).expect("mkdir fixtures");
    }
    let mut f = std::fs::File::create(path).expect("create fixture");
    f.write_all(&out).expect("write fixture");
    println!("wrote {count} frames, {} bytes -> {path}", out.len());
}
