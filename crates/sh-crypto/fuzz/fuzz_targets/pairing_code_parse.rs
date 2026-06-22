#![no_main]
//! Fuzz target: `PairingCode::from_digits` must never panic on arbitrary input.
//!
//! Feeds arbitrary byte slices (interpreted as UTF-8 strings where possible) into the
//! pairing-code parser. The parser must return `Ok(_)` or `Err(_)` — never panic.
//!
//! Run with: `cargo +nightly fuzz run pairing_code_parse`

use libfuzzer_sys::fuzz_target;
use sh_crypto::pairing::{PairingCode, PairingCodeFormat};

fuzz_target!(|data: &[u8]| {
    // Interpret the bytes as a UTF-8 string; non-UTF-8 inputs are silently skipped.
    if let Ok(s) = std::str::from_utf8(data) {
        // Must never panic — only Ok or Err.
        let _ = PairingCode::from_digits(s, PairingCodeFormat::EightDigit, 2_000_000_000i64);
    }
});
