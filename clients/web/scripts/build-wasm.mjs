// Build the three browser wasm bridges (`--target web`) and stage their generated
// JS/TS glue + .wasm into `src/wasm/<crate>/` for the TS app and tests to import.
//
// The bridges are the security-critical building blocks (SHP codec, identity/crypto,
// the DTLS-pinned WebClient). We do NOT reimplement any of them in TS — this script
// only compiles the existing Rust crates and copies the wasm-pack `pkg/` output in.
//
// Run via `npm run build:wasm` (invoked by `build`, `dev`, and `test`).
//
// Provenance note: the output under `src/wasm/` is generated build artifact (gitignored);
// the source of truth is `crates/sh-wasm`, `crates/sh-crypto-wasm`, `crates/sh-web-client`.

import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(here, "..");
const repoRoot = resolve(webRoot, "..", "..");

// Build sh-web-client LAST: it depends on sh-wasm + sh-crypto-wasm and re-exports their
// `#[wasm_bindgen]` symbols, so its `pkg/` is a superset. The app imports the codec/crypto
// helpers AND `WebClient` from this single package (one wasm binary, one init).
const crates = ["sh-wasm", "sh-crypto-wasm", "sh-web-client"];

const wasmPack = process.env.WASM_PACK ?? "wasm-pack";

for (const crate of crates) {
  const crateDir = resolve(repoRoot, "crates", crate);
  // eslint-disable-next-line no-console
  console.log(`[build-wasm] wasm-pack build --target web ${crate}`);
  execFileSync(wasmPack, ["build", "--target", "web", "--dev", crateDir], {
    stdio: "inherit",
    cwd: repoRoot,
  });

  const pkgDir = resolve(crateDir, "pkg");
  const dest = resolve(webRoot, "src", "wasm", crate);
  if (existsSync(dest)) {
    rmSync(dest, { recursive: true, force: true });
  }
  mkdirSync(dest, { recursive: true });
  cpSync(pkgDir, dest, { recursive: true });
  // eslint-disable-next-line no-console
  console.log(`[build-wasm] staged ${crate} -> src/wasm/${crate}`);
}

// Additionally build sh-wasm for the Node target so Vitest (which runs in Node, where the
// `--target web` fetch-based init does not apply) can call the REAL codec `encode_*`/`decode_*`
// functions and assert exact wire bytes. Only sh-wasm is needed for the pure-logic unit tests
// (codec/input mapping/negotiation/frame parsing) — not the crypto or WebRTC crates.
{
  const crate = "sh-wasm";
  const crateDir = resolve(repoRoot, "crates", crate);
  // eslint-disable-next-line no-console
  console.log(`[build-wasm] wasm-pack build --target nodejs ${crate} (for Vitest)`);
  execFileSync(
    wasmPack,
    ["build", "--target", "nodejs", "--dev", "--out-dir", "pkg-node", crateDir],
    { stdio: "inherit", cwd: repoRoot },
  );
  const pkgDir = resolve(crateDir, "pkg-node");
  const dest = resolve(webRoot, "src", "wasm", `${crate}-node`);
  if (existsSync(dest)) {
    rmSync(dest, { recursive: true, force: true });
  }
  mkdirSync(dest, { recursive: true });
  cpSync(pkgDir, dest, { recursive: true });
  // eslint-disable-next-line no-console
  console.log(`[build-wasm] staged ${crate} (nodejs) -> src/wasm/${crate}-node`);
}

// eslint-disable-next-line no-console
console.log("[build-wasm] done");
