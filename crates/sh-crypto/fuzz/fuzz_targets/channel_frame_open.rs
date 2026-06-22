#![no_main]
//! Fuzz target: `SessionKeys::open` must never panic on arbitrary frame bytes.
//!
//! Feeds arbitrary bytes as a channel frame. The header parser and AEAD must handle all
//! inputs without panicking — they may return `Ok(_)` or `Err(_)`.
//!
//! Run with: `cargo +nightly fuzz run channel_frame_open`

use libfuzzer_sys::fuzz_target;
use sh_crypto::channel_crypto::SessionKeys;
use sh_crypto::clock::FixedClock;
use sh_crypto::noise::NoiseHandshake;
use sh_crypto::{Keystore, SoftwareKeystore};
use sh_types::ChannelId;
use std::sync::OnceLock;
use tokio::runtime::Runtime;
use x25519_dalek::StaticSecret;

static RT: OnceLock<Runtime> = OnceLock::new();

fn runtime() -> Option<&'static Runtime> {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap_or_else(|_| std::process::abort())
    });
    RT.get()
}

fuzz_target!(|data: &[u8]| {
    let Some(rt) = runtime() else { return };
    let clock = FixedClock(1_000_000_000);

    let result = rt.block_on(async {
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();

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
        let mut resp =
            NoiseHandshake::responder_xk(&resp_ks, resp_static, &[], &clock)
                .await
                .ok()?;

        let msg0 = init.write_message().ok()?;
        resp.read_message(&msg0, &clock).ok()?;
        let msg1 = resp.write_message().ok()?;
        init.read_message(&msg1, &clock).ok()?;
        let msg2 = init.write_message().ok()?;
        resp.read_message(&msg2, &clock).ok()?;

        let resp_outcome = resp.complete(&resp_ks).await.ok()?;
        let mut resp_keys =
            SessionKeys::from_outcome(resp_outcome, Box::new(FixedClock(1_000_000_000))).ok()?;

        // Feed arbitrary bytes as a frame. Must not panic.
        let _ = resp_keys.open(ChannelId::Video, data);
        Some(())
    });
    let _ = result;
});
