#![no_main]
//! Fuzz target: `RawDecoder::decode` must never panic on arbitrary bytes
//! (the never-panic contract for untrusted video bitstreams).

use libfuzzer_sys::fuzz_target;
use sh_codec_hw::RawDecoder;
use sh_media::{EncodedPacket, VideoDecoder};
use sh_protocol::{Codec, FrameType};
use sh_types::{FrameId, TimestampUs};

fuzz_target!(|data: &[u8]| {
    let mut dec = RawDecoder::new();
    let pkt = EncodedPacket {
        data: bytes::Bytes::copy_from_slice(data),
        codec: Codec::Raw,
        frame_id: FrameId(0),
        capture_ts_us: TimestampUs(0),
        frame_type: FrameType::Idr,
    };
    // Must not panic, hang, or read out of bounds on any input.
    let _ = dec.decode(&pkt);
});
