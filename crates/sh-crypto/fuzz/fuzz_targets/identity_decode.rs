#![no_main]
//! Fuzz target: `DeviceIdentity::from_public_key_bytes` must never panic on arbitrary 32-byte
//! input. The decoder validates that the bytes form a valid Ed25519 compressed point; on invalid
//! input it returns `Err`, never panics.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(arr) = <&[u8; 32]>::try_from(data) {
        // Must not panic; may return Ok or Err.
        let _ = sh_crypto::DeviceIdentity::from_public_key_bytes(arr);
    }
});
