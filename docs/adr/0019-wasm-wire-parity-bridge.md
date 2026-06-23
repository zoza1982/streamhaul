# ADR-0019: WASM Wire-Parity Bridge (`sh-wasm`)

- **Status:** Accepted
- **Date:** 2026-06-23
- **Deciders:** network-engineer, security-engineer (P5-1 wire-parity slice)

## Context

Phase 5 delivers the browser client.  The first and most critical property is **wire
parity**: the browser side must encode and decode the SHP wire format byte-for-byte
identically to the native Rust host.  A secondary format or an independent JS
re-implementation of the codec would be a reliability and security risk.

The production runtime environment for this slice is a Linux/Intel development box.  No
browser automation harness (chromedriver, geckodriver) is available.  `node` is available;
`wasm-pack 0.13.1` is installed; the `wasm32-unknown-unknown` target is installed.

## Decision

1. **Single source of truth:** The wire codec stays in `sh-protocol`.  `sh-wasm` is a thin
   `wasm-bindgen` wrapper that marshals between Rust types and JS-friendly types
   (`Uint8Array` / primitive fields / `JsError`).  No codec logic is duplicated.

2. **Crate layout:** `crates/sh-wasm` is `crate-type = ["cdylib", "rlib"]`.  It depends
   only on `sh-protocol`, `sh-types`, and `wasm-bindgen`.  No `tokio`, `quinn`, `str0m`,
   or other non-wasm-compatible crates enter this crate.

3. **Workspace exclusion:** `sh-wasm` is added to the root `Cargo.toml` `exclude = [...]`
   list, matching the pattern used for the `cargo-fuzz` crates.  The native
   `cargo build/test --workspace` and the three-OS CI jobs are unaffected.

4. **Verification strategy:** `wasm-pack test --node` runs the entire `#[wasm_bindgen_test]`
   suite in Node's WASM runtime without any browser.  The test suite decodes the same
   byte vectors used by `sh-protocol`'s native golden/conformance tests and asserts
   field-by-field equality.  It also asserts `native_encode` → `wasm_decode` byte
   identity.  This is the hard proof of wire parity.

5. **Hostile-input safety:** Every `decode_*` wrapper takes `&[u8]` from the network and
   maps `ProtocolError` → `JsError`.  No `unwrap/expect/panic` appears in any production
   path.  The `sh-protocol` decoders are already fuzz-verified; this wrapper inherits
   that posture at zero marginal cost.

6. **CI wasm job:** A dedicated `wasm` job on `ubuntu-latest` installs the
   `wasm32-unknown-unknown` target, installs `wasm-pack` via the official installer, runs
   `wasm-pack test --node crates/sh-wasm`, and runs `wasm-pack build --target web
   crates/sh-wasm` as an artifact smoke-check.  This prevents the wasm crate from
   silently rotting between browser-capable sessions (the "X-2 gap").

## Deferred items

### R-BROWSER-INTEROP — Live RTCPeerConnection ↔ native DataChannel e2e

The second half of P5-1 (and the whole of P5-2) requires a live browser:
`RTCPeerConnection`, `DataChannel` wiring via `web-sys`, SDP offer/answer through
`sh-signaling`, H.264 decode and `<video>` render, and input-event capture.  None of this
can run in the current environment (no `chromedriver`/`geckodriver`).  This is blocked on
a browser-equipped CI session or local browser.  It does NOT affect the wire-parity
deliverable — the codec layer is fully verified by `wasm-pack test --node`.

### R-BROWSER-MATRIX — Chrome / Firefox / Safari compatibility

Once the live browser client exists, it must be verified across Chrome, Firefox, and
Safari (including Safari's WKWebView constraints).  This requires the three-browser CI
matrix from P5-2 and is fully separate from wire-parity.

## Consequences

- **Positive:**
  - Wire parity is provably correct: the same bytes decode to the same field values in
    both native Rust and wasm, proven by golden-vector tests.
  - The source-of-truth codec remains in one place (`sh-protocol`).
  - Native CI (three-OS) is completely unaffected by the wasm crate.
  - A dedicated CI job prevents the wasm crate from rotting between browser sessions.
  - Hostile input from the network is safe: errors surface as JS exceptions, never traps.

- **Negative / trade-offs:**
  - A separate `wasm-pack` CI job adds install overhead (~30 s) on the ubuntu runner.
  - `wasm-pack test --node` does not validate browser-specific APIs (`RTCPeerConnection`,
    DOM); those require a browser and are deferred.

- **Follow-ups:**
  - P5-1 second half: wire `web-sys` `RTCPeerConnection`/`DataChannel` to `sh-wasm` once
    a browser is available (risk: R-BROWSER-INTEROP).
  - P5-2: browser viewer/control UI + H.264 render + input capture + three-browser matrix
    (risk: R-BROWSER-MATRIX).

## Alternatives considered

- **Ship a JS reimplementation of the SHP codec.** Rejected: two independent codec
  implementations will inevitably diverge; the JS one would need its own fuzz harness.

- **Use `wasm-pack test --chrome` or `--firefox`.** Rejected: no chromedriver/geckodriver
  available on this machine.  `--node` suffices for pure codec logic with no DOM
  dependency.

- **Add `sh-wasm` to the workspace members list.** Rejected: `wasm32-unknown-unknown` is
  not a supported target for most workspace crates (e.g. `sh-transport` links against
  `tokio`/`quinn`); adding `sh-wasm` to members would break `cargo build --workspace`
  unless every other crate also gained wasm-conditional feature flags — unnecessary
  complexity.  The `exclude` pattern (identical to the fuzz-crate pattern) is the
  established precedent.
