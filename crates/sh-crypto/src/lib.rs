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
//!   drop.
//! - **SHA-256**: fingerprint derivation via `sha2` 0.10.x.
//! - **OsRng**: production key generation uses `rand_core::OsRng` (backed by `getrandom`).
//!   Test constructors accept an arbitrary `CryptoRng + RngCore` so tests are deterministic and
//!   seedable without touching the OS entropy pool.

#![deny(missing_docs)]

mod error;
mod identity;
mod keystore;
mod signature;
mod software_keystore;

pub use error::CryptoError;
pub use identity::{DeviceIdentity, Fingerprint};
pub use keystore::Keystore;
pub use signature::Signature;
pub use software_keystore::SoftwareKeystore;
