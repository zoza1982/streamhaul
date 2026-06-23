#![no_main]
//! Fuzz target: decode arbitrary bytes then run the full `Ugc::verify` path.
//!
//! Covers the untrusted-bytes path through Ed25519 signature verification, SHA-256
//! grantee binding (constant-time compare), expiry arithmetic, and epoch floor check.
//! The harness must NEVER panic regardless of what bytes are fed in.

use libfuzzer_sys::fuzz_target;
use rand_chacha::rand_core::SeedableRng;
use sh_crypto::{clock::FixedClock, DeviceIdentity, Keystore, SoftwareKeystore};
use sh_core::authz::Ugc;
use std::sync::OnceLock;

/// Fixed test identities initialised once per fuzz process.
struct FuzzFixtures {
    host_identity: DeviceIdentity,
    grantee_identity: DeviceIdentity,
}

static FIXTURES: OnceLock<FuzzFixtures> = OnceLock::new();

fn fixtures() -> &'static FuzzFixtures {
    FIXTURES.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("tokio rt");
        let host_ks =
            SoftwareKeystore::generate_with_rng(rand_chacha::ChaCha8Rng::seed_from_u64(0xFADE));
        let grantee_ks =
            SoftwareKeystore::generate_with_rng(rand_chacha::ChaCha8Rng::seed_from_u64(0xBEEF));
        let host_identity = rt.block_on(host_ks.device_identity()).expect("host identity");
        let grantee_identity = rt
            .block_on(grantee_ks.device_identity())
            .expect("grantee identity");
        FuzzFixtures {
            host_identity,
            grantee_identity,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let fx = fixtures();
    // Fixed clock at a mid-range Unix timestamp; chosen so nominal UGC windows are valid.
    let clock = FixedClock(1_700_000_300_i64);

    if let Ok(ugc) = Ugc::decode(data) {
        // The result is discarded — we only check for the absence of panics.
        let _ = ugc.verify(&fx.host_identity, &fx.grantee_identity, 0, &clock);
    }
});
