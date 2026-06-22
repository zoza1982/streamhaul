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

fn runtime() -> Option<&'static Runtime> {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            // SAFETY: if the runtime cannot be constructed the fuzzer iteration is a no-op;
            // we return a sentinel value that the caller checks. However, OnceLock requires
            // we always store *something*, so we fall back to a minimal multi-thread runtime.
            // If that also fails there is nothing sensible to do — the process exits.
            .unwrap_or_else(|_| {
                tokio::runtime::Runtime::new()
                    .unwrap_or_else(|_| std::process::abort())
            })
    });
    RT.get()
}

fn keystore() -> &'static SoftwareKeystore {
    KS.get_or_init(SoftwareKeystore::generate)
}

fuzz_target!(|data: &[u8]| {
    let Some(rt) = runtime() else { return };
    let clock = FixedClock(1_000_000_000);
    // A fixed static secret is intentional: we are fuzzing the *message parser*, not
    // key-generation. The key is constant across iterations so the fuzzer can build
    // stable corpus entries without re-seeding the CSPRNG every iteration.
    let local_static = StaticSecret::from([0x42u8; 32]);

    // Build a fresh handshake per iteration — NoiseHandshake is stateful and must not
    // be reused across iterations. The keystore (signing key) is shared and read-only.
    // Ephemeral generation is handled by snow's OS-backed default resolver; no RNG param.
    let result = rt.block_on(sh_crypto::NoiseHandshake::responder_xk(
        keystore(),
        local_static,
        &[],
        &clock,
    ));

    if let Ok(mut hs) = result {
        // Feed arbitrary bytes as message 0. Must not panic — only Ok or Err.
        let _ = hs.read_message(data, &clock);
    }
});
