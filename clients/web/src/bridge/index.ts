// Single entry point for the merged Rust/wasm bridge.
//
// `sh-web-client` depends on `sh-wasm` (SHP codec) and `sh-crypto-wasm` (identity/crypto)
// and re-exports their `#[wasm_bindgen]` symbols, so its generated package is a superset:
// one wasm binary, one `init()`. The TS app imports the SHP codec helpers, the identity
// primitives, AND the DTLS-pinned `WebClient` from here.
//
// Security-critical logic (codec wire format, crypto, DTLS-pin gate) lives in the wasm
// crates and is NOT reimplemented in TypeScript. This file is glue only.

// wasm-bindgen generates loose glue (`src/wasm/`, excluded from the strict typecheck).
// We assert the typed `ShBridge` surface (declared in ./types) over it.
// @ts-ignore — generated module has no strict types; re-typed via ShBridge below.
import init, * as bindings from "../wasm/sh-web-client/sh_web_client.js";
// The .wasm URL is resolved by Vite (`?url`) so the binary is fetched at runtime.
// @ts-ignore — Vite `?url` import suffix is resolved by the bundler, not tsc.
import wasmUrl from "../wasm/sh-web-client/sh_web_client_bg.wasm?url";

import type { ShBridge } from "./types.js";

let initialized: Promise<ShBridge> | null = null;

/**
 * Initialize the wasm bridge exactly once and return the typed surface.
 *
 * Idempotent: concurrent callers share a single in-flight init promise. If init REJECTS (e.g. a
 * wasm fetch 404 / corrupt module), the cached promise is cleared so a subsequent call retries
 * rather than returning the same rejected promise forever (which would otherwise require a full
 * page reload to recover).
 */
export function loadBridge(): Promise<ShBridge> {
  if (initialized === null) {
    initialized = (init as (opts: { module_or_path: string }) => Promise<unknown>)({
      module_or_path: wasmUrl as string,
    })
      .then(() => {
        const bridge = bindings as unknown as ShBridge;
        // Install the panic hook so a (never-expected) Rust panic surfaces a readable
        // browser-console stack trace instead of an opaque `unreachable` trap.
        try {
          bridge.set_panic_hook();
        } catch {
          // Non-fatal: the hook is a dev aid, not a correctness requirement.
        }
        return bridge;
      })
      .catch((e: unknown) => {
        // Do not cache the failure: allow a later loadBridge() to retry the init.
        initialized = null;
        throw e;
      });
  }
  return initialized;
}

export type * from "./types.js";
