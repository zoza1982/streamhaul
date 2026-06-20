#![no_main]
//! Fuzz target: `RawAudioDecoder::decode` must never panic on arbitrary bytes
//! (the never-panic contract for untrusted audio bitstreams).

use libfuzzer_sys::fuzz_target;
use sh_codec_hw::{RawAudioDecoder, RAW_AUDIO_HEADER_LEN};
use sh_media::{AudioCodec, AudioDecoder, AudioEncodedPacket};
use sh_types::TimestampUs;

fuzz_target!(|data: &[u8]| {
    let _ = RAW_AUDIO_HEADER_LEN; // reference the constant to keep import live
    let mut dec = RawAudioDecoder::new();
    let pkt = AudioEncodedPacket {
        data: bytes::Bytes::copy_from_slice(data),
        capture_ts_us: TimestampUs(0),
        seq: 0,
        codec: AudioCodec::RawPcm,
    };
    // Must not panic, hang, or read out of bounds on any input.
    let _ = dec.decode(&pkt);
});
