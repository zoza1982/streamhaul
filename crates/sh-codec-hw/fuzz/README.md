# sh-codec-hw fuzz targets

These targets exercise the untrusted-bytes parsers in `sh-codec-hw` under cargo-fuzz.
Both decoders must never panic, hang, or read out of bounds on arbitrary input.

## Prerequisites

```sh
cargo install cargo-fuzz
rustup toolchain install nightly
```

## Running

```sh
# From crates/sh-codec-hw/fuzz (this is a standalone workspace — NOT part of the main workspace)
cargo +nightly fuzz run raw_audio_decode
cargo +nightly fuzz run raw_decode
```
