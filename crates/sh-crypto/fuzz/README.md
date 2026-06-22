# sh-crypto fuzzing

Continuous fuzzing of the `sh-crypto` decoders, which parse untrusted network bytes
(CLAUDE.md §5 requires cargo-fuzz for any parser of untrusted input).

This crate is **excluded from the main workspace** and needs nightly Rust + `cargo-fuzz`:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run sig_decode
cargo +nightly fuzz run identity_decode
```

## Targets

- `sig_decode` — asserts `Signature::decode` never panics on arbitrary bytes.
  The decoder must return `Err` (not panic) for any input that is not exactly 64 bytes.
- `identity_decode` — asserts `DeviceIdentity::from_public_key_bytes` never panics on
  arbitrary 32-byte slices. Invalid compressed points return `Err`.

## CI integration

The in-CI equivalent is the `decode_arbitrary_bytes_never_panics` proptest in
`crates/sh-crypto/src/signature.rs`, which runs on every PR.

A scheduled nightly fuzz job is tracked as a follow-up in `IMPLEMENTATION_PLAN.md` (X-2).
