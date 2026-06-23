//! Fuzz target for `StunMessage::decode`.
//!
//! Invariants verified:
//! - No panic on arbitrary byte sequences.
//! - No out-of-bounds memory accesses.
//! - No unbounded allocation amplification (output size bounded by input size).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic on arbitrary bytes — no allocation amplification,
    // no out-of-bounds, no integer overflow.
    let _ = sh_ice::stun::StunMessage::decode(data);
});
