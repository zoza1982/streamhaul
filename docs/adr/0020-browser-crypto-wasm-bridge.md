# ADR-0020: Browser Crypto WASM Bridge (`sh-crypto-wasm`)

- **Status:** Accepted
- **Date:** 2026-06-23
- **Deciders:** security-engineer, rust-staff-engineer (P5 browser crypto slice)

## Context

Phase 5 requires the browser client to authenticate (R-SIG-AUTH) and complete the
identity-bound Noise XK/IK handshake (P4-5) in the browser.  `sh-crypto` holds all the
vetted primitives (Ed25519 identity, `IdentityProof`, `NoiseHandshake`, `HandshakeOutcome`,
`BindCert`, DTLS-binding gate), but it targets native Rust.  A JavaScript reimplementation
of any of this crypto would violate the "never roll your own crypto" rule (CLAUDE.md §7) and
introduce a second, inevitably-diverging implementation of security-critical logic.

Three hard constraints from the security model:
1. **Private signing keys must never cross the JS boundary as raw bytes.**  The Ed25519
   `SigningKey` is `ZeroizeOnDrop` inside `SoftwareKeystore`; once a byte slice escapes to
   JS it can be retained in GC roots outside Rust's control.
2. **WebCrypto CSPRNG is the only valid entropy source in the wasm sandbox.**  The OS
   `/dev/urandom` syscall is unavailable.  `getrandom` with the `js` feature routes all RNG
   through `window.crypto.getRandomValues` (browser) or Node's `crypto` module.
3. **All `sh-crypto` invariants must be preserved by the bridge.**  The bridge is a thin
   marshal layer, not a reimplementation; it calls `sh-crypto` APIs directly and maps
   `CryptoError` → `JsError` at the wasm boundary.

## Decision

### 1. Separate, workspace-excluded crate (`crates/sh-crypto-wasm`)

`sh-crypto-wasm` is a new `crate-type = ["cdylib", "rlib"]` crate with its own
`[workspace]` isolation table, added to the root `Cargo.toml` `exclude = [...]` list
alongside `sh-wasm` and the fuzz crates.  It is **not** an extension of `sh-wasm`.

**Rationale for a new crate instead of extending `sh-wasm`:**
- `sh-wasm` has a single focused responsibility (wire-codec parity), adding crypto types
  would couple two independent layers.
- `sh-crypto-wasm` depends on `sh-crypto` and a larger set of crypto deps (`async-trait`,
  `pollster`, `rand_core`, `x25519-dalek`, `subtle`), none of which are needed by `sh-wasm`.
- The two crates generate separate WASM binaries; bundlers can tree-shake: a codec-only
  build loads `sh-wasm` without pulling in the larger crypto binary.
- Security audit surface is scoped: `sh-crypto-wasm` is the single boundary where crypto
  types enter JS; its surface is narrow and independently auditable.

### 2. Private keys never leave wasm linear memory

`WasmKeystore` holds `sh_crypto::SoftwareKeystore` as an opaque Rust value.  No method on
`WasmKeystore` returns the private signing key.  The only exported key material is:
- `fingerprint()` → SHA-256 hex string (one-way, non-reversible to private key)
- `public_key_bytes()` → 32-byte Ed25519 public key

Noise static secrets (X25519) are generated inside `WasmNoiseHandshake::initiator_xk_*` /
`responder_xk_*` / `initiator_ik_*` / `responder_ik_*` via `OsRng` and passed directly to
`NoiseHandshake::initiator_xk_with_dtls` — they are never stored in a field, are `ZeroizeOnDrop`
inside `snow`, and are not exported.

### 3. WebCrypto as the sole entropy source (`getrandom = { features = ["js"] }`)

`getrandom/js` is the only entropy feature enabled.  There is no fallback stub.  If the
wasm binary loads in an environment where `window.crypto` or Node `crypto` is unavailable,
`getrandom` returns an error and key generation fails (rather than silently producing
weak keys from an uninitialized buffer).

The `rand_core = { version = "0.6", features = ["getrandom"] }` dependency makes
`rand_core::OsRng` use the same WebCrypto path for all direct RNG calls in this crate.

### 4. Synchronous wasm-bindgen surface via `pollster::block_on`

`sh-crypto`'s `Keystore` trait uses `async fn`.  WebAssembly currently has no built-in
async executor in the wasm sandbox (tokio requires OS threads).  `pollster 0.3.x` is a
zero-dependency executor that drives an immediately-resolving future synchronously.

All `SoftwareKeystore` async methods are purely synchronous internally (RwLock + in-memory
operations); no I/O or timer awaits occur.  `pollster::block_on` is therefore safe here:
it will never spin-wait.  This design choice is explicitly documented at every call site.

### 5. `WasmClock` backed by `js_sys::Date::now()`

`sh_types::SystemClock` calls `std::time::SystemTime::now()`, which panics on
`wasm32-unknown-unknown`.  `js_sys::Date::now()` returns `f64` milliseconds since epoch
and is available in all WASM environments.  `WasmClock` implements `sh_types::Clock` by
dividing by 1000 and truncating to `i64` (Unix seconds), matching the native
`SystemClock` contract without any OS syscall.

### 6. TOFU first-pairing via `TrustAllKeystore`

`NoiseHandshake::complete(keystore)` always calls `keystore.is_trusted()`.  For the
TOFU first-pairing flow (where the peer key is not yet in the trust store), we introduce
`TrustAllKeystore` — an ephemeral synthetic keystore whose `is_trusted` always returns
`true`.  It holds an ephemeral Ed25519 signing key used only to satisfy the `Keystore`
trait bound; that key is zeroized on drop.  The resulting `WasmHandshakeOutcome` delivers
`peer_pubkey()` to the caller, who then calls `trust_peer_by_key()` to persist the TOFU
pin.  Subsequent reconnects use `complete_trusted(keystore)`, which enforces the real
trust store check.

### 7. `WasmHandshakeOutcome` and the anti-downgrade gate

`WasmHandshakeOutcome` wraps `HandshakeOutcome` with:
- `peer_fingerprint()` — hex string of the peer's Ed25519 identity fingerprint
- `peer_pubkey()` — 32-byte slice (for TOFU registration)
- `dtls_pin()` — `Option<Vec<u8>>` — 32 bytes **only if the BindCert carried a non-zero
  SHA-256 commitment**; `None` for ALG=NONE *and* for an all-zero ALG=SHA256 commit
  (a malformed / downgrade-attempt peer).  This means JS `if (outcome.dtls_pin !== undefined)`
  is safe — a zero-commit Some would previously have slipped through as a non-null Uint8Array.
- `require_dtls_pin()` — throws `JsError(DtlsBindingMissing)` if the DTLS pin is absent
  or all-zeros (anti-downgrade gate; mirrors P4-5 / ADR-0014)
- `verify_peer_fingerprint(pinned_fp)` — constant-time comparison via `subtle::ConstantTimeEq`;
  rejects non-ASCII input with `JsError` rather than `Ok(false)` (a subtle correctness bug
  that would misclassify a trusted peer as unknown on reconnect)

JS callers MUST call `require_dtls_pin()` before wiring the WebRTC transport for the same
anti-downgrade guarantee that `sh-core::session` enforces on the native path.

### 8. Panic-free boundary (`JsError` on all error paths)

A `wasm_bindgen` function that panics terminates the wasm linear-memory process and
typically crashes the browser tab.  Every fallible entry point maps errors to `JsError`:

```
CryptoError → JsError (via format!("{e}"))
```

No `unwrap()`, `expect()`, `panic!`, or `todo!()` appears in any production path.  The
`[lints.clippy]` table in `Cargo.toml` denies `unwrap_used`, `expect_used`, and `panic`.

### 9. Fuzz disposition (§5 honesty)

`sh-crypto-wasm` cannot host a `cargo-fuzz` target natively.  Its `getrandom = { features=["js"] }`
dependency requires the `wasm32-unknown-unknown` target; `cargo-fuzz` compiles to the host target
and links LLVM libFuzzer — an incompatible combination.

The bridge's parse entry points (`verify_identity_proof`, `read_message`) do not reimplement
any parsing: they call `sh_crypto::IdentityProof::decode` and `sh_crypto::NoiseHandshake::read_message`
directly.  Those native decoders are covered by `cargo-fuzz` targets `peer_auth_decode` and
`noise_handshake_read` in `crates/sh-protocol/fuzz` / `crates/sh-crypto/fuzz` respectively.

The wasm marshalling layer (a `try_into` length check + `map_err(|_| JsError::new(…))`) is
too thin to benefit from a separate fuzz harness; its hostile-input behaviour is verified by
`identity_proof_empty_input_is_js_error`, `identity_proof_truncated_input_is_js_error`,
`identity_proof_garbage_input_is_js_error`, `noise_read_garbage_is_js_error`,
`noise_read_empty_is_js_error`, and `decode_proof_pubkey_wrong_length_is_js_error`.

This is an acknowledged gap, not an overlooked one.  See R-BROWSER-CRYPTO-LIVE for follow-up.

### 10. Test strategy (`wasm-pack test --node`)

| Category | Tests |
|----------|-------|
| Identity entropy | `two_generated_identities_differ` |
| Identity stability | `fingerprint_is_stable_and_correct_format`, `pubkey_bytes_to_fingerprint_roundtrip` |
| Trust store | `trust_store_roundtrip` |
| R-SIG-AUTH roundtrip | `identity_proof_valid_roundtrip` |
| R-SIG-AUTH cross-target parity | `identity_proof_cross_target_parity` (wasm proof → native verify + native proof → wasm verify) |
| R-SIG-AUTH rejections | `identity_proof_wrong_fingerprint_rejected`, `identity_proof_wrong_challenge_rejected`, `identity_proof_tampered_signature_rejected` |
| R-SIG-AUTH hostile input | `identity_proof_empty_input_is_js_error`, `identity_proof_truncated_input_is_js_error`, `identity_proof_garbage_input_is_js_error`, `decode_proof_pubkey_wrong_length_is_js_error` |
| Wasm-bridge XK (FIX 1) | `wasm_api_full_xk_handshake_complete_for_first_pairing` (exercises `write_message`, `read_message`, `complete_for_first_pairing`, `TrustAllKeystore`) |
| Wasm-bridge ALG=NONE gate (FIX 1b) | `wasm_api_alg_none_commit_yields_dtls_binding_missing` |
| Native XK + DTLS binding | `full_xk_handshake_with_dtls_binding` |
| Anti-downgrade | `dtls_binding_missing_is_js_error` |
| Hostile Noise input | `noise_read_garbage_is_js_error`, `noise_read_empty_is_js_error` |
| Constant-time FP compare | `verify_peer_fingerprint_constant_time` |
| Pubkey utilities | `fingerprint_from_pubkey_invalid_is_js_error` |

All tests pass under `wasm-pack test --node`.
`wasm-pack build --target web` succeeds (optimized release build, ~45 s).

## Deferred Items

### R-BROWSER-CRYPTO-LIVE — live Noise handshake over real WebSocket + WebRTC

The tests verify the handshake in a pure-Rust in-process simulation.  A live browser
session completing the Noise XK handshake over `window.WebSocket` → `sh-signaling` →
`RTCPeerConnection` requires WebDriver and is deferred to P5-2.

This deferred item also tracks: (a) stronger type-enforcement for `complete_for_first_pairing`
— a distinct outcome type that cannot be used to open a session without going through
`trust_peer_by_key` first (mirroring ADR-0017's `PinnedWebRtcTransportBuilder`); and
(b) fuzz coverage of the wasm marshal layer via a mock-getrandom native fuzz target if
the parser surface grows beyond the current thin `try_into` + `map_err` pattern.

### R-BROWSER-MATRIX — cross-browser WASM crypto compat

`wasm-pack test --node` verifies Node's WASM engine (V8).  Firefox SpiderMonkey and
Safari JavaScriptCore have known differences in WASM intrinsics; these require the
three-browser CI matrix from P5-2.

### R-WASM-HW-KEYSTORE — hardware-backed keys in wasm

`WasmKeystore` currently wraps `SoftwareKeystore` (keys in Rust heap, zeroized on drop).
A future `WebCryptoKeystore` variant using the Web Crypto API's `CryptoKey` non-extractable
key handles would give hardware-backed key protection on supported platforms (e.g. macOS
with Secure Enclave via Safari).  This is a follow-up to the R-HW-KS track (P3-1).

## Consequences

- **Positive:**
  - All `sh-crypto` crypto invariants (constant-time verify, zeroize, verify_strict,
    DTLS-binding gate) are preserved in the browser at zero marginal implementation cost —
    the bridge is 100% marshalling, not reimplementation.
  - Private keys remain inside wasm linear memory; only fingerprints and public keys cross
    the boundary.
  - WebCrypto CSPRNG is the real entropy source; there is no fallback stub.
  - Cross-target parity is proven by test: a proof created in wasm verifies natively and
    vice versa.
  - Native workspace (`cargo build/test/clippy --workspace`) is completely unaffected;
    CI three-OS matrix runs unchanged.

- **Negative / trade-offs:**
  - `pollster::block_on` is a synchronous executor; it will block the browser's main thread
    for the duration of any crypto operation.  Noise XK (3 messages) involves Ed25519 sign
    (fast, ~50 µs) and X25519 DH (fast, ~50 µs).  On modern hardware this is imperceptible;
    for slower devices or future heavier operations, a `wasm-bindgen-futures` async path
    should replace `pollster` (deferred, see R-BROWSER-CRYPTO-LIVE).
  - Separate wasm binary increases initial bundle size by the `sh-crypto` dependency graph
    (~150 KB gzipped estimated, to be measured at P5-2 bundle audit).

- **Follow-ups:**
  - P5-2: wire `WasmNoiseHandshake` / `WasmKeystore` into the live browser `RTCPeerConnection`
    path once WebDriver is available (R-BROWSER-CRYPTO-LIVE).
  - Async wasm-bindgen-futures path for long-running operations if needed (R-BROWSER-CRYPTO-LIVE).
  - Three-browser WASM compat matrix (R-BROWSER-MATRIX).
  - Non-extractable `WebCryptoKeystore` via Web Crypto API (R-WASM-HW-KEYSTORE).

## Alternatives Considered

- **Extend `sh-wasm` with crypto types.** Rejected: couples two independent layers; `sh-wasm`
  was designed for wire-codec parity only (ADR-0019); the crypto dependency set would bloat
  the codec binary and complicate the security audit surface.

- **JS reimplementation of `IdentityProof` + Noise handshake.** Rejected: violates CLAUDE.md §7
  ("never roll your own crypto"); two independent implementations will inevitably diverge,
  and a JS Noise handshake has no fuzz coverage.

- **Use `wasm-bindgen-futures` + async wasm-bindgen entry points.** Considered but deferred:
  `async` wasm-bindgen returns JS `Promise`, which requires the JS caller to `await` every
  crypto operation.  The existing API is simpler (synchronous) and sufficient for the
  current performance requirements.  An async upgrade path is left open (all internal
  code already uses Rust `async`).

- **Bundle both `sh-wasm` and `sh-crypto-wasm` into one wasm module.** Rejected: a single
  binary mixes two different security surface areas and prevents independent tree-shaking
  or per-crate audit.
