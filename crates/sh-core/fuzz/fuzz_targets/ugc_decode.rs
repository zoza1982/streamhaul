#![no_main]
//! Fuzz target: `Ugc::decode` must never panic on arbitrary input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sh_core::authz::Ugc::decode(data);
});
