#![no_main]
//! Fuzz target: SHP header decoders must never panic on arbitrary bytes (the never-panic contract).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // All decoders take untrusted network bytes; none may panic, hang, or read out of bounds.
    let _ = sh_protocol::CommonHeader::decode(data);
    let _ = sh_protocol::VideoHeader::decode(data);
    let _ = sh_protocol::InputEvent::decode(data);
    let _ = sh_protocol::decode_control(data);
    let _ = sh_protocol::NackFeedback::decode(data);
    // P2-5: codec capability offer/answer decoder (untrusted peer bytes).
    let _ = sh_protocol::capability::decode_caps(data);
    // P4-6: transport capability decoder (untrusted peer bytes — 2-byte fixed format).
    let _ = sh_protocol::decode_transport_caps(data);
    // P7: file-transfer control + chunk decoders (untrusted peer bytes — ADR-0024).
    let _ = sh_protocol::FileOffer::decode(data);
    let _ = sh_protocol::FileAccept::decode(data);
    let _ = sh_protocol::FileAbort::decode(data);
    let _ = sh_protocol::FileComplete::decode(data);
    let _ = sh_protocol::FileChunkHeader::decode(data);
});
