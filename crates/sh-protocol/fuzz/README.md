# sh-protocol fuzzing

Continuous fuzzing of the SHP decoders, which parse untrusted network bytes (CLAUDE.md §5 requires this
for any parser of untrusted input).

This crate is **excluded from the main workspace** and needs nightly Rust + `cargo-fuzz`:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run shp_decode
```

Targets:
- `shp_decode` — asserts `CommonHeader::decode` and `VideoHeader::decode` never panic on arbitrary input.

> The in-CI equivalent is the `decode_never_panics` proptest in `sh-protocol`, which runs on every PR.
> A scheduled nightly fuzz job is tracked as a follow-up in `IMPLEMENTATION_PLAN.md` (X-2).
