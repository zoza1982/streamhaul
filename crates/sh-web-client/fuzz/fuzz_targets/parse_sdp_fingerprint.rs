//! Fuzz target for `sh-web-client`'s hostile-input SDP fingerprint parser.
//!
//! CLAUDE.md §5 makes `cargo-fuzz` mandatory for any parser of untrusted network bytes.  SDP
//! arrives over the untrusted signaling channel, so `parse_sdp_fingerprint` is exactly such a
//! parser.  The invariant under test: for ANY input, the parser must return `Ok`/`Err` and never
//! panic, trap, hang, or index out of bounds — and any `Ok` must be exactly 32 bytes.
//!
//! Run (from `crates/sh-web-client`):
//!     cargo +nightly fuzz run parse_sdp_fingerprint
//!
//! Runs in the `fuzz-nightly` CI workflow. The harness calls the host-runnable
//! [`sh_web_client::parse_sdp_fingerprint_host`] seam — NOT the `#[wasm_bindgen]`
//! `parse_sdp_fingerprint` wrapper, whose `JsValue` return aborts in wasm-bindgen glue on the
//! native target libFuzzer runs on. Both share the same parsing logic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz both valid-UTF-8 and lossy paths: SDP is text, but the wire may deliver arbitrary bytes.
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(fp) = sh_web_client::parse_sdp_fingerprint_host(s) {
            assert_eq!(fp.len(), 32, "a successful parse must yield exactly 32 bytes");
        }
    }
    let lossy = String::from_utf8_lossy(data);
    if let Ok(fp) = sh_web_client::parse_sdp_fingerprint_host(&lossy) {
        assert_eq!(fp.len(), 32, "a successful parse must yield exactly 32 bytes");
    }
});
