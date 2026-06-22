#![no_main]
//! Fuzz target: `DeviceIdentity::from_public_key_bytes` must never panic on arbitrary 32-byte
//! input. The decoder validates that the bytes form a valid Ed25519 compressed point (and that
//! the key is not a small-order/weak point); on invalid input it returns `Err`, never panics.
//!
//! The input type is `[u8; 32]` rather than `&[u8]` so the fuzzer generates exactly 32-byte
//! inputs from the start, avoiding warmup cycles discarding non-32-byte inputs.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: [u8; 32]| {
    // Must not panic; may return Ok or Err.
    let _ = sh_crypto::DeviceIdentity::from_public_key_bytes(&data);
});
