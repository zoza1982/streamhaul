#![no_main]
//! Fuzz target: `Signature::decode` must never panic on arbitrary input (the never-panic contract
//! from CLAUDE.md §5 and §7 — we parse untrusted network bytes).
//!
//! The decoder is allowed to return `Err`; it is NOT allowed to panic, abort, or produce
//! undefined behavior for any input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic regardless of length or content.
    let _ = sh_crypto::Signature::decode(data);
});
