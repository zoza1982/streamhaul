//! `sh-crypto` — Device identity, key management, and end-to-end session keys for Streamhaul.
//!
//! # Overview
//!
//! This crate is the cryptographic foundation of Streamhaul (LLD §6). It provides:
//!
//! - **[`DeviceIdentity`]** — the Ed25519 public verifying key plus a stable fingerprint that
//!   the relay sees and that users compare for out-of-band verification.
//! - **[`Signature`]** — a 64-byte Ed25519 signature newtype with wire encode/decode and
//!   constant-time-safe verification.
//! - **[`Keystore`]** — an async, object-safe trait for key storage backends (P3-1 delivers a
//!   software implementation; TPM/Keychain/DPAPI/StrongBox backends are deferred — see §Security
//!   notes below).
//! - **[`SoftwareKeystore`]** — a portable in-memory implementation of [`Keystore`] backed by an
//!   Ed25519 [`ed25519_dalek::SigningKey`] and an in-memory TOFU trust store.
//! - **[`SessionKeys`]** — the in-RAM AEAD key set for a session, created from a completed
//!   [`NoiseHandshake`] outcome. Provides `seal()` and `open()` over six independent channels
//!   with ChaCha20-Poly1305 and an HKDF-SHA-256 ratchet chain for forward secrecy.
//! - **[`ChannelFrameHeader`]** — the parsed 24-byte frame header (channel id, direction, epoch,
//!   ratchet generation, sequence number). AAD-committed to every AEAD seal/open call.
//! - **[`CryptoError`]** — a typed error enum covering all failure modes in this crate.
//!
//! # Security notes
//!
//! ## Software keystore is NOT hardware-non-exportable
//!
//! The LLD (§6.2, §6.3) specifies that the device identity key is hardware-non-exportable
//! (TPM 2.0, Secure Enclave / Keychain, DPAPI, StrongBox). **P3-1 delivers only the software
//! keystore**: the signing key lives in ordinary heap memory, protected by `zeroize`-on-drop but
//! extractable by a root-level attacker. Hardware keystore backends are tracked as a deferred risk
//! in the Risk Register (IMPLEMENTATION_PLAN.md §Risk Register, entry R-HW-KS).
//!
//! ## Never log secret material
//!
//! The `SigningKey` is not exposed via any public accessor. `Debug` on [`SoftwareKeystore`]
//! and [`DeviceIdentity`] deliberately omits private key material. Never pass a signing key
//! (or any value derived from it) to a logging call.
//!
//! ## Cryptographic primitives
//!
//! - **Ed25519**: RFC 8032, implemented by `ed25519-dalek` 2.x (which in turn uses
//!   `curve25519-dalek`). The `zeroize` feature is enabled; `SigningKey` zeroes its memory on
//!   drop. Verification uses `verify_strict` (not `verify`) to reject small-order public keys
//!   and non-canonical signatures — see ADR 0006 for the rationale.
//! - **SHA-256**: fingerprint derivation and HKDF-SHA-256 base for channel key derivation,
//!   implemented via `sha2` 0.10.x and `hkdf` 0.12.x.
//! - **ChaCha20-Poly1305**: per-channel AEAD seal/open via `chacha20poly1305` 0.10.x. Each
//!   12-byte nonce is deterministic: `generation_u32_be(4) || seq_u64_be(8)`.
//! - **HKDF-SHA-256**: epoch key derivation (`export_keying_material`) and per-generation
//!   ratchet advance (`shp ratchet v1` label). Keys are [`zeroize`](zeroize)-on-drop.
//! - **OsRng**: production key generation uses `rand_core::OsRng` (backed by `getrandom`).
//!   Test constructors accept an arbitrary `CryptoRng + RngCore` so tests are deterministic and
//!   seedable without touching the OS entropy pool.
//!
//! ## Design decisions
//!
//! Identity / fingerprint design, the `verify_strict` choice, the TOFU trust-store data model,
//! and revocation policy are recorded in [ADR 0006](../../../docs/adr/0006-device-identity-fingerprint-and-verification.md).

#![deny(missing_docs)]

pub mod bind_cert;
pub mod channel_crypto;
pub mod clock;
mod error;
mod identity;
mod keystore;
pub mod noise;
pub mod pairing;
pub mod sas;
mod signature;
mod software_keystore;

pub use bind_cert::{BindCert, BindCertBuilder};
pub use channel_crypto::{
    ChannelFrameHeader, Direction, SessionKeys, CHANNEL_HEADER_LEN, CHANNEL_MAGIC,
};
pub use error::CryptoError;
pub use identity::{DeviceIdentity, Fingerprint};
pub use keystore::Keystore;
pub use noise::{HandshakeOutcome, HandshakeRole, NoiseHandshake, NoisePattern, NoiseSession};
pub use signature::Signature;
pub use software_keystore::SoftwareKeystore;
