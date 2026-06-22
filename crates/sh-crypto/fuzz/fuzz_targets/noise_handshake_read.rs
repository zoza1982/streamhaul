#![no_main]
//! Fuzz target: `NoiseHandshake::read_message` must never panic on arbitrary input.
//!
//! Constructs a live XK responder handshake and feeds arbitrary bytes as the first message
//! (the initiator's `-> e, es` message). Snow's MAC check will reject malformed messages,
//! but the call must return `Ok(_)` or `Err(_)` — never panic.
//!
//! The keystore and Tokio runtime are constructed once (via `OnceLock`) so the fuzzer
//! spends its budget on mutating the message bytes rather than on keygen overhead.
//!
//! Run with: `cargo +nightly fuzz run noise_handshake_read`

use libfuzzer_sys::fuzz_target;
use sh_crypto::clock::FixedClock;
use sh_crypto::SoftwareKeystore;
use std::sync::OnceLock;
use tokio::runtime::Runtime;
use x25519_dalek::StaticSecret;

static RT: OnceLock<Runtime> = OnceLock::new();
static KS: OnceLock<SoftwareKeystore> = OnceLock::new();

fn runtime() -> &'static Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("tokio runtime")
    })
}

fn keystore() -> &'static SoftwareKeystore {
    KS.get_or_init(SoftwareKeystore::generate)
}

fuzz_target!(|data: &[u8]| {
    let clock = FixedClock(1_000_000_000);
    // A fixed static secret is intentional: we are fuzzing the *message parser*, not
    // key-generation. The key is constant across iterations so the fuzzer can build
    // stable corpus entries without re-seeding the CSPRNG every iteration.
    let local_static = StaticSecret::from([0x42u8; 32]);

    // Build a fresh handshake per iteration — NoiseHandshake is stateful and must not
    // be reused across iterations. The keystore (signing key) is shared and read-only.
    let result = runtime().block_on(sh_crypto::NoiseHandshake::responder_xk(
        keystore(),
        local_static,
        &[],
        rand_core::OsRng,
        &clock,
    ));

    if let Ok(mut hs) = result {
        // Feed arbitrary bytes as message 0. Must not panic — only Ok or Err.
        let _ = hs.read_message(data, &clock);
    }
});
