//! Fuzz target for the signaling envelope decoder.
//!
//! Feeds arbitrary bytes into [`sh_signaling::envelope::fuzz_decode_envelope`] and asserts
//! it never panics. All error variants are acceptable; only panics are failures.
//!
//! Run with:
//! ```sh
//! cargo +nightly fuzz run fuzz_envelope_decode
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use sh_signaling::envelope::fuzz_decode_envelope;

fuzz_target!(|data: &[u8]| {
    // Must never panic, regardless of input.
    let _ = fuzz_decode_envelope(data);
});
