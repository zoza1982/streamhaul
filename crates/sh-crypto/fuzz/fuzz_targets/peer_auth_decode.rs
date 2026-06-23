#![no_main]
//! Fuzz target: `IdentityProof::decode` must never panic on arbitrary input.
//!
//! The decoder parses untrusted network bytes (the signaling peer-auth proof, R-SIG-AUTH). For
//! any input — truncated, garbage, oversized, or crafted — it must return `Ok(_)` or `Err(_)`
//! without panicking or aborting.
//!
//! Run with: `cargo +nightly fuzz run peer_auth_decode`

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic regardless of input length or content.
    let _ = sh_crypto::peer_auth::fuzz_decode_identity_proof(data);
});
