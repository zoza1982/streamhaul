#![no_main]
//! Fuzz target: `BindCert::decode` must never panic on arbitrary input.
//!
//! The decoder parses untrusted network bytes. For any input — truncated, garbage, oversized,
//! or crafted — it must return `Ok(_)` or `Err(_)` without panicking or aborting.
//!
//! Run with: `cargo +nightly fuzz run bindcert_decode`

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic regardless of input length or content.
    let _ = sh_crypto::bind_cert::BindCert::decode(data);
});
