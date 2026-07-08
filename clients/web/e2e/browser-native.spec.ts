/**
 * browser-native.spec.ts — Playwright e2e test for browser↔native WebRTC interop (P5-3).
 *
 * # What this test proves (Stage 2 — identity-bound, ADR-0023)
 *
 * A real Firefox `WebClient` (browser side) negotiates a DTLS DataChannel with the native
 * `streamhaul-webrtc-host` binary where the DTLS pin is **identity-bound**: it comes from the
 * Noise XK `BindCert` exchanged over signaling, NOT the untrusted SDP `a=fingerprint`.
 *
 *   (a) Identity-bound happy path — session establishes + echo, AND the pin the browser enforced
 *       equals the host's committed DTLS fingerprint (`pinUsedHex === host_fp`), proving the pin
 *       is sourced from the BindCert, not just any SDP value.
 *   (b) MITM rejection (non-vacuous) — a man-in-the-middle swaps the host's advertised DTLS
 *       fingerprint in the answer SDP after the BindCert committed a different one; the browser's
 *       fail-closed `verify_sdp_fingerprint_pin` ABORTS the connection. The happy-path arm above
 *       is the honest control proving the same setup connects when NOT tampered.
 *
 * # Test setup
 *
 * 1. `beforeEach` spawns ONLY `streamhaul-signaling` on a dynamic port.
 * 2. Each test calls `startHost([...extraArgs])` to spawn `streamhaul-webrtc-host` with
 *    mode-specific flags (echo, MITM, or `--stream-video`), then reads `HOST_DTLS_FP=<hex>`.
 * 3. Navigates to `/e2e/browser-native.html?session=<hex>&host_fp=<hex>[&mitm=1|&video=1]`.
 * 4. Polls `window.__interopResult` for up to 40 s.
 * 5. `afterEach` kills both child processes.
 *
 * # Environment requirements
 *
 * - `streamhaul-signaling` and `streamhaul-webrtc-host` binaries must be on `$PATH` or in
 *   `target/debug/` (the `CARGO_TARGET_DIR` or `../../target/debug/` relative to this file).
 * - Firefox must be available (same requirement as the existing loopback e2e).
 * - The test runs only when the environment variable `BROWSER_NATIVE_E2E=1` is set, to avoid
 *   requiring the native binaries in every CI run (they are built in the `browser-native-e2e`
 *   CI job, which sets that variable).
 *
 * # Security note
 *
 * Uses `insecure-lan` signaling (AcceptAll). Not for production.
 */

import { test, expect } from "@playwright/test";
import { type ChildProcess, spawn } from "child_process";
import { createInterface } from "readline";
import * as path from "path";
import { fileURLToPath } from "url";

// ESM has no `__dirname`; derive it from the module URL.
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Types ────────────────────────────────────────────────────────────────────

interface InteropResult {
  connected: boolean;
  echoed: boolean;
  frameHex: string | null;
  /** Hex of the DTLS pin the browser enforced (the host's BindCert commit), or null. */
  pinUsedHex: string | null;
  /** True iff the MITM SDP-fingerprint swap was rejected by the fail-closed pin gate. */
  mitmRejected: boolean;
  /** VIDEO mode: count of COMPLETE reassembled access units that reached the decoder. */
  framesReachedDecoder: number;
  /** VIDEO mode: count of frames the WebCodecs decoder successfully decoded. */
  framesDecoded: number;
  /** VIDEO mode: whether the browser exposes the WebCodecs `VideoDecoder` API. */
  webCodecs: boolean;
  /** VIDEO mode: whether the browser can actually decode the fixture's H.264 (probed). */
  h264DecodeSupported: boolean | null;
  /** VIDEO mode: count of synthetic input events the browser sent (remote control). */
  inputSent: number;
  /** VIDEO mode: count of clipboard updates the browser sent (browser→host paste). */
  clipboardSent: number;
  /** VIDEO mode: the sanitized text the browser received from the host (host→browser), or null. */
  clipboardReceived: string | null;
  error: string | null;
}

/**
 * A spawned child process with a persistent line buffer on stdout so multiple
 * callers can all `waitForStdoutLine` without racing on the same stream reader.
 */
interface ManagedProcess {
  child: ChildProcess;
  /** All stdout lines received so far (grows as the process runs). */
  stdoutLines: string[];
  /** Waiters: resolve when a line matching their prefix arrives. */
  waiters: Array<{ prefix: string; resolve: (rest: string) => void }>;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Find the path to a binary: first checks `target/debug/` relative to the workspace root,
 * then falls back to `$PATH`.
 */
function binaryPath(name: string): string {
  // Workspace root is ../../ relative to clients/web/e2e/
  const workspaceRoot = path.resolve(__dirname, "..", "..", "..");
  const debugPath = path.join(workspaceRoot, "target", "debug", name);
  return process.env[`STREAMHAUL_${name.toUpperCase().replace(/-/g, "_")}_BIN`] ?? debugPath;
}

/** Spawn a child process and install a persistent stdout/stderr listener. */
function spawnProcess(bin: string, args: string[] = []): ManagedProcess {
  const child = spawn(bin, args, {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, RUST_LOG: process.env["RUST_LOG"] ?? "info" },
  });
  const managed: ManagedProcess = { child, stdoutLines: [], waiters: [] };

  // Forward stderr to the Playwright test reporter for debugging.
  child.stderr?.on("data", (d: Buffer) => {
    process.stderr.write(`[${path.basename(bin)}] ${d}`);
  });

  // Persistent readline on stdout — all callers share the same stream.
  const rl = createInterface({ input: child.stdout! });
  rl.on("line", (line: string) => {
    managed.stdoutLines.push(line);
    // Wake any waiter whose prefix matches.
    managed.waiters = managed.waiters.filter((w) => {
      if (line.startsWith(w.prefix)) {
        w.resolve(line.slice(w.prefix.length));
        return false; // remove from waiters
      }
      return true; // keep waiting
    });
  });

  return managed;
}

/**
 * Wait for a line matching `prefix` on the child's stdout, then return the rest of that line.
 * Checks already-buffered lines first, then registers a waiter.
 * Rejects after `timeoutMs` ms.
 */
function waitForStdoutLine(
  mp: ManagedProcess,
  prefix: string,
  timeoutMs = 10_000,
): Promise<string> {
  // Check buffered lines first.
  for (const line of mp.stdoutLines) {
    if (line.startsWith(prefix)) {
      return Promise.resolve(line.slice(prefix.length));
    }
  }

  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () =>
        reject(
          new Error(
            `timed out waiting for "${prefix}" from pid ${mp.child.pid}. Stdout so far:\n${mp.stdoutLines.join("\n")}`,
          ),
        ),
      timeoutMs,
    );

    mp.waiters.push({
      prefix,
      resolve: (rest) => {
        clearTimeout(timer);
        resolve(rest);
      },
    });

    mp.child.once("exit", (code: number | null) => {
      clearTimeout(timer);
      // Remove our waiter to avoid double-reject.
      mp.waiters = mp.waiters.filter((w) => w.prefix !== prefix);
      reject(
        new Error(
          `process exited (code ${code}) before emitting "${prefix}". Stdout:\n${mp.stdoutLines.join("\n")}`,
        ),
      );
    });
  });
}

/** Kill a managed process gracefully (SIGTERM, then SIGKILL after 2 s if still alive). */
async function kill(mp: ManagedProcess): Promise<void> {
  const { child } = mp;
  if (child.exitCode !== null) return; // Already exited — nothing to do.
  try {
    child.kill("SIGTERM");
  } catch {
    return; // kill() threw → already dead.
  }
  // Wait for the process to exit on its own, or forcibly SIGKILL after 2 s.
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignore — already exited */
      }
      resolve();
    }, 2_000);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

// ── Test session state ────────────────────────────────────────────────────────

let signalingProc: ManagedProcess | null = null;
let hostProc: ManagedProcess | null = null;

const SESSION_HEX = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"; // fixed 32-char hex session

// ── Skip guard ───────────────────────────────────────────────────────────────

test.skip(
  () => process.env["BROWSER_NATIVE_E2E"] !== "1",
  "Skipping browser↔native e2e: set BROWSER_NATIVE_E2E=1 and ensure native binaries are built",
);

// ── Lifecycle ────────────────────────────────────────────────────────────────

test.beforeEach(async () => {
  // Start ONLY the signaling server on a DYNAMIC port (`:0`) so concurrent / re-run invocations
  // never collide on a fixed port (a stale process previously gave an opaque "Address already
  // in use"). The server prints its ACTUAL bound address on SIGNALING_READY.
  //
  // The host is spawned per-test via `startHost(...)` so each test can pass mode-specific args
  // (e.g. `--stream-video`) — the video test must NOT inherit the plain echo host.
  signalingProc = spawnProcess(binaryPath("streamhaul-signaling"), ["--addr", "127.0.0.1:0"]);
  const readyLine = await waitForStdoutLine(signalingProc, "SIGNALING_READY addr=");
  const sigAddr = readyLine.trim(); // e.g. "127.0.0.1:54321"
  if (!/^127\.0\.0\.1:\d{1,5}$/.test(sigAddr)) {
    throw new Error(`SIGNALING_READY addr is not a 127.0.0.1:<port> address: "${sigAddr}"`);
  }
  process.env["_TEST_SIGNALING_URL"] = `ws://${sigAddr}`;
});

/**
 * Spawn the native WebRTC host pointed at the (already-running) dynamic signaling URL, with the
 * fixed base args plus any test-specific `extraArgs` (e.g. `--stream-video`). Reads + validates
 * the host's `HOST_DTLS_FP=` line and stores it in `_TEST_HOST_FP` for the in-page driver.
 *
 * Call this at the START of each test, AFTER `beforeEach` has started signaling.
 */
async function startHost(extraArgs: string[] = []): Promise<void> {
  const signalingUrl = process.env["_TEST_SIGNALING_URL"];
  if (signalingUrl === undefined) {
    throw new Error("startHost called before signaling was started (beforeEach did not run?)");
  }
  hostProc = spawnProcess(binaryPath("streamhaul-webrtc-host"), [
    "--signaling-url",
    signalingUrl,
    "--session-id",
    SESSION_HEX,
    "--bind",
    "127.0.0.1:0",
    ...extraArgs,
  ]);
  // Read the DTLS fingerprint printed by the host.
  const hostFp = await waitForStdoutLine(hostProc, "HOST_DTLS_FP=");
  // Validate that the fingerprint is exactly 64 lowercase hex characters so a malformed value
  // surfaces immediately with a clear error rather than propagating into encodeEnvelope deep in
  // the browser where the failure message would be confusing.
  if (!/^[0-9a-f]{64}$/.test(hostFp)) {
    throw new Error(`HOST_DTLS_FP is not 64 lowercase hex chars: "${hostFp.slice(0, 80)}"`);
  }
  // Store for use in the test.
  process.env["_TEST_HOST_FP"] = hostFp;
}

test.afterEach(async () => {
  if (hostProc) {
    await kill(hostProc);
    hostProc = null;
  }
  if (signalingProc) {
    await kill(signalingProc);
    signalingProc = null;
  }
  delete process.env["_TEST_HOST_FP"];
  delete process.env["_TEST_SIGNALING_URL"];
});

// ── Test ─────────────────────────────────────────────────────────────────────

/** Run the in-page driver and return its {@link InteropResult}. */
async function runDriver(
  page: import("@playwright/test").Page,
  query: string,
): Promise<{ r: InteropResult; errors: string[] }> {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(String(e)));

  // Pass the dynamic signaling URL to the in-page driver so it connects to the actual port the
  // signaling server bound (the fixed-port assumption is gone).
  const sigUrl = process.env["_TEST_SIGNALING_URL"]!;
  await page.goto(`/e2e/browser-native.html?${query}&sig=${encodeURIComponent(sigUrl)}`);

  const result = await page.waitForFunction(
    () => {
      const r = (window as unknown as { __interopResult?: InteropResult }).__interopResult;
      return r !== undefined ? r : null;
    },
    null,
    { timeout: 40_000, polling: 500 },
  );

  const r = (await result.jsonValue()) as InteropResult;
  if (errors.length > 0) console.error("Page errors:", errors);
  if (r.error) console.error("InteropResult error:", r.error);
  return { r, errors };
}

test("identity-bound browser↔native DataChannel echo (P5-3 Stage 2)", async ({ page }) => {
  await startHost();
  const hostFp = process.env["_TEST_HOST_FP"]!;

  const { r, errors } = await runDriver(page, `session=${SESSION_HEX}&host_fp=${hostFp}`);

  expect(r.connected, `DataChannel should be open (error: ${r.error ?? "none"})`).toBe(true);
  expect(r.echoed, "should have received an echo frame from the native host").toBe(true);
  expect(r.frameHex, "echo frame hex should not be null").not.toBeNull();

  // NON-VACUOUS identity-binding assertion: the pin the browser ENFORCED equals the host's
  // committed DTLS fingerprint (sourced from the Noise BindCert), not just any SDP value.
  expect(r.pinUsedHex, "the enforced DTLS pin should be recorded").not.toBeNull();
  expect(
    r.pinUsedHex,
    "the enforced pin must equal the host's BindCert-committed DTLS fingerprint",
  ).toBe(hostFp);

  expect(errors, "no page errors").toHaveLength(0);
});

test("MITM SDP-fingerprint swap is rejected by the identity-bound pin (P5-3 Stage 2)", async ({
  page,
}) => {
  await startHost();
  const hostFp = process.env["_TEST_HOST_FP"]!;

  // mitm=1: a man-in-the-middle swaps the host's answer SDP a=fingerprint AFTER the BindCert
  // committed the real one. The fail-closed verify_sdp_fingerprint_pin gate must abort.
  const { r, errors } = await runDriver(page, `session=${SESSION_HEX}&host_fp=${hostFp}&mitm=1`);

  expect(
    r.mitmRejected,
    `the swapped SDP fingerprint must be rejected by the pin gate (error: ${r.error ?? "none"})`,
  ).toBe(true);
  // The session must NOT have connected under MITM.
  expect(r.connected, "MITM session must NOT connect").toBe(false);
  expect(r.echoed, "MITM session must NOT echo").toBe(false);
  // The pin was still sourced from the (honest) BindCert before the swap — proving the rejection
  // is caused by the SDP/pin MISMATCH, not a missing pin.
  expect(r.pinUsedHex, "the honest BindCert pin should still have been computed").toBe(hostFp);
  expect(errors, "no page errors").toHaveLength(0);
});

test("identity-bound browser↔native LIVE H.264 video (P5-3 Stage 2 + ADR-0031)", async ({
  page,
}) => {
  // Spawn the host in VIDEO mode: it streams 90 baked H.264 frames at 30 fps as SHP video frames
  // over the "shp" DataChannel (first frame is an IDR), instead of echoing the HELLO frame.
  //
  // `--max-fragment-bytes 4096` forces the host to SPLIT each ~9 KB fixture frame into 2-3 SHP
  // fragments, so the browser's reassembler is exercised end to end (the assertions below now prove
  // the browser correctly reassembles fragmented frames before decoding them).
  // `--offer-clipboard` makes the host offer a clipboard to the browser once at session start
  // (host→browser direction, ADR-0037); the driver's `on_clipboard` decodes+sanitizes it and the
  // assertion below proves the browser received it.
  await startHost([
    "--stream-video",
    "--frames",
    "90",
    "--fps",
    "30",
    "--max-fragment-bytes",
    "4096",
    "--offer-clipboard",
    "host offered clip",
  ]);
  const hostFp = process.env["_TEST_HOST_FP"]!;

  // video=1: the in-page driver parses the inbound SHP video frames and decodes them via WebCodecs.
  const { r, errors } = await runDriver(page, `session=${SESSION_HEX}&host_fp=${hostFp}&video=1`);

  expect(r.connected, `session should connect (error: ${r.error ?? "none"})`).toBe(true);
  // Core assertion: the browser RECEIVED and PARSED at least one SHP video frame from the host.
  expect(
    r.framesReachedDecoder,
    "browser must receive & parse >=1 SHP video frame from the native host",
  ).toBeGreaterThanOrEqual(1);

  // Decode is asserted ONLY when H.264 decode is actually SUPPORTED (probed via
  // VideoDecoder.isConfigSupported). API presence (`webCodecs`) is force-enabled in this harness and
  // is NOT proof the platform codec exists — headless Firefox may lack it — so gating on `webCodecs`
  // here would hard-require a codec that isn't guaranteed. The codec-independent transport proof
  // (framesReachedDecoder >= 1) above always runs.
  if (r.h264DecodeSupported === true) {
    expect(r.framesDecoded, "WebCodecs should decode >=1 frame").toBeGreaterThanOrEqual(1);
  }

  // CONTROL (ADR-0034): the browser sent synthetic input events; assert the host received, decoded,
  // and injected them. The host's StdoutInputLogger prints `INPUT_INJECTED ...` per event, proving
  // the browser→host remote-control path end to end (the live preview host injects into real X11).
  expect(r.inputSent, "browser should have sent input events").toBeGreaterThanOrEqual(1);
  await waitForStdoutLine(hostProc!, "INPUT_INJECTED", 15_000);

  // CLIPBOARD (ADR-0037): the browser sent a paste on the dedicated Clipboard channel; assert the
  // host received, decoded, sanitized, and applied it. The host's StdoutClipboardLogger prints
  // `CLIPBOARD_PASTED bytes=...` (byte count only, never content — §7), proving browser→host
  // clipboard sync end to end on a real DTLS DataChannel.
  expect(r.clipboardSent, "browser should have sent a clipboard update").toBeGreaterThanOrEqual(1);
  await waitForStdoutLine(hostProc!, "CLIPBOARD_PASTED", 15_000);

  // CLIPBOARD host→browser (ADR-0037): the host offered "host offered clip" via `--offer-clipboard`;
  // the browser's `on_clipboard` decoded + sanitized it. Assert the exact received text, proving the
  // host→browser clipboard direction end to end on a real DTLS DataChannel.
  expect(r.clipboardReceived, "browser should have received the host's offered clipboard").toBe(
    "host offered clip",
  );

  expect(errors, "no page errors").toHaveLength(0);
});
