# sh-transport fuzzing

Continuous fuzzing of the stream-framing parsers, which parse untrusted network bytes (CLAUDE.md §5
requires this for any parser of untrusted input).

This crate is **excluded from the main workspace** and needs nightly Rust + `cargo-fuzz`:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run framing_decode
```

Targets:
- `framing_decode` — asserts the 2-byte channel-open header decoder
  (`ChannelSpec::decode_header`) and the `u32` length-prefix bound check never panic, hang, or
  over-allocate on arbitrary input (via `sh_transport::channel::fuzz_decode_framing`).

> The in-CI equivalents are the negative/hostile-input tests in
> `crates/sh-transport/tests/channel_loopback.rs`, which run on every PR.
> A scheduled nightly fuzz job is tracked as a follow-up in `IMPLEMENTATION_PLAN.md`.
