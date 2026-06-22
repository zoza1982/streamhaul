# sh-crypto

Device identity, key management, and end-to-end session/channel keys for Streamhaul.

## Overview

`sh-crypto` is the cryptographic foundation of Streamhaul (LLD §6). It provides:

| Item | Description |
|------|-------------|
| [`DeviceIdentity`] | Ed25519 verifying key + SHA-256 fingerprint; the public `device_id`. |
| [`Fingerprint`] | 64-char lowercase hex SHA-256 fingerprint with a 16-char SAS short form. |
| [`Signature`] | 64-byte Ed25519 signature newtype; panic-free wire encode/decode + verify. |
| [`Keystore`] | Async, object-safe trait for identity and TOFU trust management. |
| [`SoftwareKeystore`] | Portable in-memory `Keystore` backed by an Ed25519 signing key. |
| [`CryptoError`] | Typed error enum for all `sh-crypto` failures. |

## Quick start

```rust
use sh_crypto::{SoftwareKeystore, Keystore};

# tokio_test::block_on(async {
let ks = SoftwareKeystore::generate(); // production: OsRng
let id = ks.device_identity().await.unwrap();
let sig = ks.sign(b"payload").await.unwrap();
assert!(sig.verify(&id, b"payload").is_ok());
# });
```

## Security status (P3-1)

### What is delivered

- Ed25519 device identity (RFC 8032) via `ed25519-dalek` 2.x with `zeroize` on drop.
- `Keystore` trait and `SoftwareKeystore` implementation.
- SHA-256 device fingerprint for relay routing and SAS display.
- TOFU in-memory trust + revocation store.
- Panic-free wire decoders fuzzed via `crates/sh-crypto/fuzz/`.

### What is deferred (hardware non-exportable keys)

The LLD (§6.2, §6.3) specifies that the device identity key must be **hardware-non-exportable**
(TPM 2.0, Secure Enclave / Keychain, DPAPI, Android StrongBox). `SoftwareKeystore` does **NOT**
provide this guarantee — the signing key lives in ordinary heap memory and is zeroed on drop, but
can be read by a root-level attacker.

Platform hardware-keystore backends are tracked as risk entry **R-HW-KS** in
`IMPLEMENTATION_PLAN.md`. Do not deploy `SoftwareKeystore` in production until hardware backends
are available and wired in.

### Cryptographic primitives

| Primitive | Crate | Role |
|-----------|-------|------|
| Ed25519 (RFC 8032) | `ed25519-dalek` 2.2.0 | Sign/verify device identity |
| SHA-256 | `sha2` 0.10.9 | Fingerprint derivation |
| CSPRNG | `rand_core` 0.6 / `OsRng` | Key generation |
| Async boundary | `async-trait` 0.1 | Object-safe `Keystore` trait |

## Fuzzing

See `crates/sh-crypto/fuzz/README.md`. Targets cover `Signature::decode` and
`DeviceIdentity::from_public_key_bytes` — both accept untrusted network bytes.

## Phase roadmap

- **P3-1** (this PR): device identity, `Keystore` trait, `SoftwareKeystore`.
- **P3-2**: Noise tunnel (`snow`, `Noise_XK` / `Noise_IK`) + identity-bound `BindCert`.
- **P3-3**: TOFU pairing UI, SAS, PAKE (SPAKE2/OPAQUE).
- **P3-4**: Channel encryption + key hierarchy + PFS rotation.
- **P3-5**: Authorization capability mask + kill-switch.
