#![no_main]
//! Fuzz target: SHP header decoders must never panic on arbitrary bytes (the never-panic contract).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Both decoders take untrusted network bytes; neither may panic, hang, or read out of bounds.
    let _ = sh_protocol::CommonHeader::decode(data);
    let _ = sh_protocol::VideoHeader::decode(data);
});
