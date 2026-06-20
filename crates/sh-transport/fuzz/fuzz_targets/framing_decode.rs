#![no_main]
//! Fuzz target: the stream-framing parsers must never panic, hang, or over-allocate on arbitrary
//! bytes (the never-panic contract for untrusted network input, CLAUDE.md §5).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercises the 2-byte channel-open header decoder and the u32 length-prefix bound check
    // without a live connection. Must tolerate any input without panicking or allocating the
    // declared (possibly huge) payload.
    let _ = sh_transport::channel::fuzz_decode_framing(data);
});
