#![no_main]
//! Fuzz target: `PakeExchange::read_peer_msg` must never panic on arbitrary input.
//!
//! Constructs a live PAKE initiator exchange and feeds arbitrary bytes as the peer's
//! first message. The SPAKE2 parser and our length checks must handle all inputs without
//! panicking — they may return `Ok(_)` or `Err(_)`.
//!
//! Run with: `cargo +nightly fuzz run pake_msg_parse`

use libfuzzer_sys::fuzz_target;
use sh_crypto::pairing::{PairingCode, PairingCodeFormat, PakeExchange, PakeRole};
use sh_crypto::SoftwareKeystore;
use sh_crypto::clock::FixedClock;
use sh_crypto::Keystore;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

static RT: OnceLock<Runtime> = OnceLock::new();
static KS_A: OnceLock<SoftwareKeystore> = OnceLock::new();
static KS_B: OnceLock<SoftwareKeystore> = OnceLock::new();

fn runtime() -> &'static Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap_or_else(|_| {
                tokio::runtime::Runtime::new()
                    .unwrap_or_else(|_| std::process::abort())
            })
    })
}

fuzz_target!(|data: &[u8]| {
    let rt = runtime();
    let clock = FixedClock(1_000_000_000);

    let ks_a = KS_A.get_or_init(SoftwareKeystore::generate);
    let ks_b = KS_B.get_or_init(SoftwareKeystore::generate);

    let (id_a, id_b) = rt.block_on(async {
        let a = ks_a.device_identity().await.unwrap_or_else(|_| std::process::abort());
        let b = ks_b.device_identity().await.unwrap_or_else(|_| std::process::abort());
        (a, b)
    });

    let not_after = 2_000_000_000i64;
    let code = match PairingCode::from_digits("12345678", PairingCodeFormat::EightDigit, not_after) {
        Ok(c) => c,
        Err(_) => return,
    };

    let _ = code.check_not_expired(&clock);

    let mut rng = rand_core::OsRng;
    let h = [0u8; 32];

    if let Ok(mut exc) = PakeExchange::start_with_rng(
        &mut rng,
        PakeRole::Initiator,
        &code,
        id_a,
        id_b,
        &h,
    ) {
        // Must never panic on arbitrary input — only Ok or Err.
        let _ = exc.read_peer_msg(data);
    }
});
