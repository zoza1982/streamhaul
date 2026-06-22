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
| [`SessionKeys`] | Per-session AEAD key set; created from a completed Noise handshake. |
| [`ChannelFrameHeader`] | Parsed 24-byte frame header (channel, direction, epoch, generation, seq). |
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

## Security status (P3-4)

### What is delivered

- Ed25519 device identity (RFC 8032) via `ed25519-dalek` 2.x with `zeroize` on drop.
- `Keystore` trait and `SoftwareKeystore` implementation.
- SHA-256 device fingerprint for relay routing and SAS display.
- TOFU in-memory trust + revocation store.
- Noise_XK tunnel (`snow`) with identity-bound `BindCert`.
- SPAKE2 PAKE pairing with SAS confirmation.
- Per-channel ChaCha20-Poly1305 AEAD with HKDF-SHA-256 key hierarchy and ratchet rotation.
- Replay-window anti-replay (1024-bit sliding bitmap, two-phase commit).
- Epoch-keyed rekey with single-slot grace window.
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
| SHA-256 | `sha2` 0.10.9 | Fingerprint derivation; HKDF-SHA-256 key derivation |
| HKDF-SHA-256 | `hkdf` 0.12 | Channel key derivation and ratchet advance |
| ChaCha20-Poly1305 | `chacha20poly1305` 0.10 | Per-channel AEAD seal/open |
| Noise_XK | `snow` 0.9 | Authenticated tunnel; exports session PRK |
| SPAKE2 | `spake2` 0.4 | PAKE pairing key exchange |
| CSPRNG | `rand_core` 0.6 / `OsRng` | Key generation |
| Async boundary | `async-trait` 0.1 | Object-safe `Keystore` trait |

## Fuzzing

See `crates/sh-crypto/fuzz/README.md`. Targets cover `Signature::decode`,
`DeviceIdentity::from_public_key_bytes`, `NoiseHandshake::read_message`, PAKE message parsing,
and `SessionKeys::open` — all accept untrusted network bytes. The `channel_frame_open` target
hoists the Noise handshake into a `OnceLock`-backed `Mutex<SessionKeys>` so only `open()` is on
the fuzzer's hot path.

## Phase roadmap

- **P3-1** ✅: device identity, `Keystore` trait, `SoftwareKeystore`.
- **P3-2** ✅: Noise tunnel (`snow`, `Noise_XK` / `Noise_IK`) + identity-bound `BindCert`.
- **P3-3** ✅: TOFU pairing UI, SAS, PAKE (SPAKE2/OPAQUE).
- **P3-4** ✅ (current): Channel encryption + key hierarchy + PFS rotation.
- **P3-5**: Authorization capability mask + kill-switch.
