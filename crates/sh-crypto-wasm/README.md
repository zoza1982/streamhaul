# `sh-crypto-wasm`

WebAssembly crypto bridge for Streamhaul Phase 5.  Exposes `sh-crypto`'s device identity,
R-SIG-AUTH peer authentication, and identity-bound Noise XK/IK handshake (P4-5) to
browser JavaScript via `wasm-bindgen`.

**Target:** `wasm32-unknown-unknown` exclusively.  This crate is excluded from the root
workspace (`Cargo.toml` `exclude` list) and has its own `[workspace]` isolation table.
`cargo build --workspace` and the native CI three-OS matrix are unaffected.

## Security model

- **Private keys never cross the JS boundary.**  `WasmKeystore` is an opaque handle; only
  `fingerprint()` (SHA-256 hex, one-way) and `public_key_bytes()` (Ed25519 public key) are
  exported.  Ed25519 signing keys and Noise X25519 static secrets remain inside wasm linear
  memory and are `ZeroizeOnDrop`.

- **WebCrypto CSPRNG is the sole entropy source.**  `getrandom` is compiled with
  `features = ["js"]`, routing all randomness through `window.crypto.getRandomValues`
  (browser) or Node's `crypto` module.  There is no fallback stub; key generation fails
  rather than using weak entropy.

- **All `sh-crypto` invariants are preserved.**  This crate is a thin marshal layer — it
  calls `sh-crypto` APIs directly and maps `CryptoError` → `JsError` at the boundary.
  `verify_strict` (RFC-8032 compliant), constant-time comparisons (`subtle`), and zeroize
  are inherited from `sh-crypto` at zero marginal cost.

- **Panic-free boundary.**  Every fallible wasm-bindgen entry point returns `JsError`.
  No `unwrap/expect/panic` appears in production paths.  A wasm panic traps the linear-memory
  process and crashes the browser tab; this crate explicitly prevents that.

- **DTLS anti-downgrade gate.**  `WasmHandshakeOutcome::require_dtls_pin()` throws
  `JsError(DtlsBindingMissing)` if the handshake did not deliver a DTLS commitment
  (i.e., the peer sent `ALG=NONE`).  JS callers MUST call this before wiring the WebRTC
  transport, mirroring the `sh-core::session` native gate.

## Exposed API

### Identity

| Export | Description |
|--------|-------------|
| `WasmKeystore::generate()` | Generate a new device identity (Ed25519 keypair via WebCrypto RNG) |
| `WasmKeystore::fingerprint()` | SHA-256 hex fingerprint of the device public key (64 chars) |
| `WasmKeystore::public_key_bytes()` | 32-byte Ed25519 public key |
| `WasmKeystore::trust_peer_by_key(bytes)` | Add a peer's 32-byte public key to the trust store |
| `WasmKeystore::is_trusted_by_key(bytes)` | Check whether a peer is trusted |
| `WasmKeystore::revoke_peer_by_key(bytes)` | Remove a peer from the trust store |
| `fingerprint_from_pubkey(bytes)` | Derive fingerprint from a 32-byte Ed25519 public key |

### R-SIG-AUTH peer authentication

| Export | Description |
|--------|-------------|
| `create_identity_proof(ks, session_id, challenge)` | 128-byte possession proof (sign challenge under device key) |
| `verify_identity_proof(proof, fp, session_id, challenge)` | Verify a proof against a known fingerprint |
| `decode_identity_proof_pubkey(proof)` | Extract the device public key from a proof (for TOFU lookup) |

### Noise XK/IK handshake (P4-5)

| Export | Description |
|--------|-------------|
| `WasmNoiseHandshake::initiator_xk_with_dtls(ks, peer_pub, dtls_fp, ctx)` | XK initiator (first-pair, 3-message, 1.5-RTT) |
| `WasmNoiseHandshake::responder_xk_with_dtls(ks, dtls_fp, ctx)` | XK responder |
| `WasmNoiseHandshake::initiator_ik_with_dtls(ks, peer_pub, dtls_fp, ctx)` | IK initiator (reconnect, 2-message, 1-RTT) |
| `WasmNoiseHandshake::responder_ik_with_dtls(ks, dtls_fp, ctx)` | IK responder |
| `WasmNoiseHandshake::write_message()` | Write the next handshake message |
| `WasmNoiseHandshake::read_message(msg)` | Process an incoming handshake message |
| `WasmNoiseHandshake::complete_trusted(ks)` | Complete handshake, enforce trust check |
| `WasmNoiseHandshake::complete_for_first_pairing()` | Complete handshake for TOFU first pairing (accepts any peer key — do NOT use on reconnect; use `complete_trusted`) |

### Handshake outcome

| Export | Description |
|--------|-------------|
| `WasmHandshakeOutcome::peer_fingerprint()` | Peer's identity fingerprint (64-char hex) |
| `WasmHandshakeOutcome::peer_pubkey()` | Peer's 32-byte Ed25519 public key |
| `WasmHandshakeOutcome::dtls_pin()` | 32-byte DTLS commitment, or `undefined` if missing |
| `WasmHandshakeOutcome::require_dtls_pin()` | Throws `JsError` if DTLS binding is absent (anti-downgrade gate) |
| `WasmHandshakeOutcome::has_dtls_pin()` | Whether a non-zero DTLS pin is present |
| `WasmHandshakeOutcome::verify_peer_fingerprint(pinned_fp)` | Constant-time fingerprint comparison (returns bool) |

## Building

```sh
# Install prerequisites (once)
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# Test (Node runner, no browser required)
wasm-pack test --node crates/sh-crypto-wasm

# Build wasm binary (for bundler integration)
wasm-pack build --target web crates/sh-crypto-wasm
# Output: crates/sh-crypto-wasm/pkg/
```

## Tests (23 `#[wasm_bindgen_test]`)

```
test tests::two_generated_identities_differ          ... ok  (entropy)
test tests::fingerprint_is_stable_and_correct_format ... ok  (stability)
test tests::pubkey_bytes_to_fingerprint_roundtrip    ... ok
test tests::trust_store_roundtrip                    ... ok
test tests::identity_proof_valid_roundtrip           ... ok  (R-SIG-AUTH)
test tests::identity_proof_cross_target_parity       ... ok  (wasm↔native)
test tests::identity_proof_wrong_fingerprint_rejected ... ok
test tests::identity_proof_wrong_challenge_rejected  ... ok
test tests::identity_proof_tampered_signature_rejected ... ok
test tests::identity_proof_empty_input_is_js_error   ... ok  (hostile input)
test tests::identity_proof_truncated_input_is_js_error ... ok
test tests::identity_proof_garbage_input_is_js_error ... ok
test tests::decode_proof_pubkey_wrong_length_is_js_error ... ok
test tests::full_xk_handshake_with_dtls_binding      ... ok  (XK + DTLS)
test tests::dtls_binding_missing_is_js_error         ... ok  (anti-downgrade)
test tests::noise_read_garbage_is_js_error           ... ok  (hostile input)
test tests::noise_read_empty_is_js_error             ... ok
test tests::verify_peer_fingerprint_constant_time    ... ok  (subtle CT)
test tests::fingerprint_from_pubkey_invalid_is_js_error ... ok

test result: ok. 23 passed; 0 failed; 0 ignored
```

## Architecture decision

See [ADR-0020](../../docs/adr/0020-browser-crypto-wasm-bridge.md) for the rationale behind
the separate crate, WebCrypto RNG choice, private-key-in-wasm design, `pollster` executor,
and deferred items.
