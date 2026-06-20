//! Fuzz target: feed arbitrary bytes to `Reassembler::ingest` and verify no panics.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sh_core::Reassembler;

fuzz_target!(|data: &[u8]| {
    let mut r = Reassembler::new();
    let _ = r.ingest(&bytes::Bytes::copy_from_slice(data));
});
