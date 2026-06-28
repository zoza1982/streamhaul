//! Deterministic pipeline-compatibility proof for the OpenH264 codec (ADR-0029).
//!
//! Drives the **exact** host→wire→client packetization path —
//! `OpenH264Encoder::encode` → [`sh_core::fragment`] → [`sh_core::Reassembler`] →
//! `OpenH264Decoder::decode` — with no QUIC/async/network, so it is fully deterministic
//! (CLAUDE.md §5: no network/clock/random flakiness). It proves OpenH264's real Annex-B output
//! (multi-NAL, variable size, fragmented across datagrams) survives reassembly and decodes back to
//! frames of the correct resolution and format.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects
)]

use bytes::Bytes;
use sh_codec_openh264::{OpenH264Decoder, OpenH264Encoder};
use sh_core::{fragment, Reassembler};
use sh_media::{EncoderConfig, PixelFormat, Resolution, VideoDecoder, VideoEncoder, VideoFrame};
use sh_protocol::Codec;
use sh_types::{FrameId, TimestampUs};

const WIDTH: u32 = 320;
const HEIGHT: u32 = 240;
// Small enough that a 320x240 keyframe spans several datagrams — exercising real fragmentation.
const MAX_DATAGRAM: usize = 1200;

fn synthetic_bgra(seq: usize) -> VideoFrame {
    let mut data = vec![0u8; (WIDTH as usize) * (HEIGHT as usize) * 4];
    for (i, px) in data.chunks_exact_mut(4).enumerate() {
        px[0] = ((i + seq * 31) % 251) as u8; // B
        px[1] = ((i / 5 + seq * 13) % 251) as u8; // G
        px[2] = ((i / 7 + seq * 3) % 251) as u8; // R
        px[3] = 255; // A
    }
    VideoFrame {
        data: Bytes::from(data),
        format: PixelFormat::Bgra8,
        resolution: Resolution::new(WIDTH, HEIGHT),
        frame_id: FrameId(seq as u64),
        capture_ts_us: TimestampUs(seq as u64 * 1000),
    }
}

#[test]
fn openh264_packets_survive_fragment_reassemble_decode() {
    let cfg = EncoderConfig {
        codec: Codec::H264,
        resolution: Resolution::new(WIDTH, HEIGHT),
        target_fps: 30,
        target_bitrate_kbps: Some(4_000),
    };
    let mut encoder = OpenH264Encoder::with_config(&cfg).unwrap();
    let mut decoder = OpenH264Decoder::new().unwrap();
    let mut reassembler = Reassembler::new();

    encoder.request_keyframe();

    let mut seq: u16 = 0;
    let mut multi_fragment_seen = false;
    let mut decoded = Vec::new();

    for s in 0..8 {
        let Some(packet) = encoder.encode(&synthetic_bgra(s)).unwrap() else {
            continue; // rate-control skip — no packet this frame
        };
        assert_eq!(packet.codec, Codec::H264);

        // Host side: fragment the encoded packet into wire datagrams.
        let datagrams = fragment(&packet, seq, MAX_DATAGRAM).unwrap();
        seq = seq.wrapping_add(u16::try_from(datagrams.len()).unwrap());
        if datagrams.len() > 1 {
            multi_fragment_seen = true;
        }

        // Client side: feed datagrams to the reassembler; a completed frame pops out.
        let mut reassembled = None;
        for dg in &datagrams {
            if let Some(p) = reassembler.ingest(dg) {
                reassembled = Some(p);
            }
        }
        let reassembled = reassembled.expect("all fragments fed: the frame must reassemble");
        assert_eq!(
            reassembled.data, packet.data,
            "reassembled bytes must be exact"
        );
        assert_eq!(reassembled.frame_id, packet.frame_id);
        assert_eq!(reassembled.capture_ts_us, packet.capture_ts_us);

        // Decode the reassembled packet and confirm metadata survives the full path: the decoded
        // frame must carry the id + capture timestamp of the packet that traversed fragment/reassembly.
        if let Some(frame) = decoder.decode(&reassembled).unwrap() {
            assert_eq!(frame.frame_id, reassembled.frame_id);
            assert_eq!(frame.capture_ts_us, reassembled.capture_ts_us);
            decoded.push(frame);
        }
    }

    assert!(
        multi_fragment_seen,
        "the keyframe should have spanned multiple datagrams at this MTU — fragmentation untested otherwise"
    );
    assert!(
        !decoded.is_empty(),
        "at least the keyframe must decode end-to-end through the pipeline"
    );
    for frame in &decoded {
        assert_eq!(frame.format, PixelFormat::Bgra8);
        assert_eq!(frame.resolution, Resolution::new(WIDTH, HEIGHT));
        frame
            .validate_len()
            .expect("decoded frame length self-consistent");
    }
}
