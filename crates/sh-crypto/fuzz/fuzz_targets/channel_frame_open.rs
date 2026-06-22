#![no_main]
//! Fuzz target: `SessionKeys::open` must never panic on arbitrary frame bytes.
//!
//! Feeds arbitrary bytes as a channel frame. The header parser and AEAD must handle all
//! inputs without panicking — they may return `Ok(_)` or `Err(_)`.
//!
//! The Noise handshake and key derivation are performed **once** at startup and stored in a
//! `OnceLock`-backed `Mutex<SessionKeys>`. Each fuzz iteration only calls `open()` on the
//! pre-established session, keeping the handshake off the hot path. This means the fuzzer
//! exercises ~100-1000× more `open()` calls per second compared to re-running the handshake
//! on every iteration.
//!
//! Run with: `cargo +nightly fuzz run channel_frame_open`

use libfuzzer_sys::fuzz_target;
use sh_crypto::channel_crypto::SessionKeys;
use sh_crypto::clock::FixedClock;
use sh_crypto::noise::NoiseHandshake;
use sh_crypto::{Keystore, SoftwareKeystore};
use sh_types::ChannelId;
use std::sync::{Mutex, OnceLock};
use tokio::runtime::Runtime;
use x25519_dalek::StaticSecret;

// Single tokio runtime, initialized once.
static RT: OnceLock<Runtime> = OnceLock::new();

// Pre-established responder SessionKeys, shared across fuzz iterations.
// Wrapped in `Mutex` so the `&mut self` required by `open()` is sound.
static RESP_KEYS: OnceLock<Mutex<SessionKeys>> = OnceLock::new();

fn runtime() -> &'static Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap_or_else(|_| std::process::abort())
    })
}

/// Builds the responder `SessionKeys` once. Called by `RESP_KEYS.get_or_init`.
///
/// On any error we call `abort()` rather than panicking, to keep the fuzz target panic-free.
fn build_resp_keys() -> Mutex<SessionKeys> {
    let rt = runtime();
    let keys = rt.block_on(async {
        let clock = FixedClock(1_000_000_000);

        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();

        // Fixed key material so the session is deterministic across restarts.
        let resp_static = StaticSecret::from([0x42u8; 32]);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::from([0x43u8; 32]);

        let resp_id = resp_ks.device_identity().await.ok()?;
        let init_id = init_ks.device_identity().await.ok()?;
        init_ks.trust_peer(&resp_id).await.ok()?;
        resp_ks.trust_peer(&init_id).await.ok()?;

        let mut init =
            NoiseHandshake::initiator_xk(&init_ks, init_static, resp_pub.to_bytes(), &[], &clock)
                .await
                .ok()?;
        let mut resp = NoiseHandshake::responder_xk(&resp_ks, resp_static, &[], &clock)
            .await
            .ok()?;

        let msg0 = init.write_message().ok()?;
        resp.read_message(&msg0, &clock).ok()?;
        let msg1 = resp.write_message().ok()?;
        init.read_message(&msg1, &clock).ok()?;
        let msg2 = init.write_message().ok()?;
        resp.read_message(&msg2, &clock).ok()?;

        let resp_outcome = resp.complete(&resp_ks).await.ok()?;
        let resp_keys =
            SessionKeys::from_outcome(resp_outcome, Box::new(FixedClock(1_000_000_000))).ok()?;
        Some(resp_keys)
    });

    match keys {
        Some(k) => Mutex::new(k),
        None => std::process::abort(),
    }
}

fuzz_target!(|data: &[u8]| {
    // Initialize session exactly once; subsequent iterations reuse it.
    let mutex = RESP_KEYS.get_or_init(build_resp_keys);

    // Lock and call open(). The Mutex ensures `&mut SessionKeys` exclusivity.
    // `unwrap()` on `lock()` would only panic on a poisoned mutex, which cannot
    // happen here because `open()` never panics (by contract of this fuzz target).
    if let Ok(mut keys) = mutex.lock() {
        let _ = keys.open(ChannelId::Video, data);
    }
});
