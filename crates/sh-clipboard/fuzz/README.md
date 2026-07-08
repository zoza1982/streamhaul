# sh-clipboard fuzzing

Continuous fuzzing of the clipboard paste-injection sanitizer
(`sh_clipboard::sanitize_clipboard_text`). The sanitizer hardens untrusted clipboard text before it
reaches an OS paste sink (ADR-0037 §6); CLAUDE.md §5 requires fuzzing security-critical parsers of
untrusted input.

This crate is **excluded from the main workspace** and needs nightly Rust + `cargo-fuzz`:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run clipboard_sanitize --target x86_64-unknown-linux-gnu
```

(Pin `--target x86_64-unknown-linux-gnu`; cargo-fuzz's default host triple can be an
ASan-incompatible musl target in some CI images.)

Targets:
- `clipboard_sanitize` — feeds arbitrary UTF-8 to `sanitize_clipboard_text` and asserts the safety
  invariants: it never panics, no forbidden control/bidi/invisible scalar (nor `CR`) survives, the
  output never grows (preserving the 256 KiB wire bound), and it is idempotent.

> The in-CI equivalent is the `total_and_no_forbidden_survives` / `never_grows` / `idempotent` /
> `identity_on_safe_subset` proptests in `sh-clipboard`, which run on every PR. The scheduled nightly
> `fuzz-nightly` job runs this target under libFuzzer.
