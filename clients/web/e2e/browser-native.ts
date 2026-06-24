/**
 * browser-native.ts — browser-side driver for the browser↔native WebRTC interop test (P5-3).
 *
 * This script runs inside a Playwright-controlled Firefox page. It:
 *   1. Reads `session` and `host_fp` from the URL query string.
 *   2. Opens a WebSocket to the signaling server (`ws://127.0.0.1:8765`).
 *   3. Creates an `RTCPeerConnection`, adds a DataChannel, and generates an SDP offer.
 *   4. Sends the offer to the native host via signaling.
 *   5. Receives the SDP answer + trickle ICE candidates and applies them.
 *   6. Waits for the DataChannel to open, sends `SHP\x00\x00\x00\x00\x05HELLO`.
 *   7. Waits for an echo frame from the native host.
 *   8. Writes the result to `window.__interopResult`.
 *
 * The Playwright spec (`browser-native.spec.ts`) spawns the native binaries, then navigates to
 * this page and polls `window.__interopResult` to verify connectivity.
 *
 * # Security note
 *
 * This page uses `InsecureLanLab` / `AcceptAll`-compatible signaling (empty proof).
 * It is for local integration tests only.
 */

import {
  decodeEnvelope,
  encodeEnvelope,
  MessageKind,
  ENVELOPE_HEADER_LEN,
} from "../src/signaling/envelope.js";

/** The result written to `window.__interopResult` after the test completes. */
export interface InteropResult {
  /** True if the DataChannel reached the Open state. */
  connected: boolean;
  /** True if an echo frame was received from the native host. */
  echoed: boolean;
  /** The raw echo frame bytes (hex-encoded) or null if not received. */
  frameHex: string | null;
  /** Error message, if any. */
  error: string | null;
}

// ── Constants ────────────────────────────────────────────────────────────────

/** Magic prefix of the SHP frame sent to the host. */
const SHP_HELLO_FRAME = new Uint8Array([
  // "SHP" + version byte
  0x53, 0x48, 0x50, 0x00,
  // payload_len: 5 (u32 BE) = 0x00 0x00 0x00 0x05
  0x00, 0x00, 0x00, 0x05,
  // payload: "HELLO"
  0x48, 0x45, 0x4c, 0x4c, 0x4f,
]);

/** Signaling server WebSocket URL.
 *
 * Uses the explicit IPv4 loopback address to avoid DNS resolution to `::1` (IPv6) on
 * systems where `localhost` resolves to both IPv4 and IPv6, which would fail if the
 * signaling server is bound only to 127.0.0.1.
 */
const SIGNALING_URL = "ws://127.0.0.1:8765";

// ── Entry point ──────────────────────────────────────────────────────────────

/**
 * Main driver function called by the Playwright spec via `page.evaluate`.
 *
 * Reads URL params, establishes the WebRTC DataChannel, exchanges frames, and
 * returns the {@link InteropResult}.
 */
async function runInteropTest(): Promise<InteropResult> {
  const result: InteropResult = {
    connected: false,
    echoed: false,
    frameHex: null,
    error: null,
  };

  try {
    const params = new URLSearchParams(window.location.search);
    const sessionHex = params.get("session") ?? "0".repeat(32);
    const hostFp = params.get("host_fp") ?? "";

    if (hostFp.length !== 64) {
      result.error = `host_fp must be 64 hex chars, got ${hostFp.length}`;
      return result;
    }

    // SECURITY NOTE (Stage 1 / AcceptAll path only):
    // The browser fingerprint is set to 64 zeros because the AcceptAll authenticator does not
    // validate `from_fp`. This is intentionally unsafe for production — two tabs connecting to
    // the same session would silently overwrite each other's slot in the signaling registry.
    // Stage 2 will replace this with the real browser DTLS fingerprint (from WebClient.local_dtls_fingerprint())
    // and require it to be proven via the Noise XK handshake BindCert.
    // NEVER use AcceptAll or all-zeros from_fp outside of local test infrastructure.
    const browserFp = "0".repeat(64);

    // Parse session ID.
    const sessionId = hexToBytes(sessionHex.padEnd(32, "0").slice(0, 32));

    // Connect to signaling.
    const ws = await connectWs(SIGNALING_URL);

    // Send Hello (empty proof — AcceptAll path).
    sendEnvelope(ws, {
      kind: MessageKind.Hello,
      sessionId,
      fromFp: browserFp,
      toFp: hostFp,
      payload: new Uint8Array(0),
    });

    // Create RTCPeerConnection and DataChannel.
    const pc = new RTCPeerConnection({
      iceServers: [],
      // Allow loopback ICE candidates (Firefox-only pref set in playwright.config.ts).
    });

    const dc = pc.createDataChannel("sh-interop", { ordered: true });
    // Receive binary frames as ArrayBuffer (Firefox defaults DataChannel binaryType to "blob",
    // which the echo handler below does not accept).
    dc.binaryType = "arraybuffer";

    // Handle trickle ICE candidates — send to host via signaling.
    pc.onicecandidate = (e) => {
      if (e.candidate) {
        sendEnvelope(ws, {
          kind: MessageKind.Candidate,
          sessionId,
          fromFp: browserFp,
          toFp: hostFp,
          payload: new TextEncoder().encode(e.candidate.candidate),
        });
      } else {
        // End of candidates.
        sendEnvelope(ws, {
          kind: MessageKind.EndOfCandidates,
          sessionId,
          fromFp: browserFp,
          toFp: hostFp,
          payload: new Uint8Array(0),
        });
      }
    };

    // Create SDP offer.
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    // Send offer to native host.
    sendEnvelope(ws, {
      kind: MessageKind.Offer,
      sessionId,
      fromFp: browserFp,
      toFp: hostFp,
      payload: new TextEncoder().encode(offer.sdp ?? ""),
    });

    // Wait for the SDP answer from the host.
    //
    // We resolve as soon as the Answer envelope is received and applied, so that ICE
    // connectivity can start. The host also sends EndOfCandidates immediately after the
    // answer (no trickle candidates on the native side), but we do not gate on it —
    // this makes the flow robust to different sequencing models and avoids a race where
    // EndOfCandidates arrives before the Answer is processed.
    //
    // FIX 3 (FLAKE): track whether this promise is already settled so any trailing
    // Candidate/EndOfCandidates messages after pc.close() become no-ops, and remove the
    // listener immediately on settle to avoid calling addIceCandidate on a closed pc.
    let signalingDone = false;
    await new Promise<void>((resolve, reject) => {
      const timeout = window.setTimeout(
        () => reject(new Error("timed out waiting for SDP answer")),
        20_000,
      );

      // FIX 1: wrapping entire handler body in try-catch so any throw from decodeEnvelope,
      // setRemoteDescription, or addIceCandidate is forwarded to the outer reject instead of
      // becoming a silent unhandled rejection that produces a 20 s opaque timeout.
      // FIX 3: save handler reference so it can be removed immediately on settle.
      const handler = async (event: MessageEvent): Promise<void> => {
        try {
          // FIX 3: ignore trailing messages after the promise settled.
          if (signalingDone) return;

          let raw: Uint8Array;
          if (event.data instanceof ArrayBuffer) {
            raw = new Uint8Array(event.data);
          } else if (event.data instanceof Blob) {
            raw = new Uint8Array(await (event.data as Blob).arrayBuffer());
          } else {
            return;
          }

          if (raw.length < ENVELOPE_HEADER_LEN) return;

          const env = decodeEnvelope(raw);

          if (env.kind === MessageKind.Answer) {
            const answerSdp = new TextDecoder().decode(env.payload);
            await pc.setRemoteDescription({ type: "answer", sdp: answerSdp });
            window.clearTimeout(timeout);
            // FIX 3: mark done and remove listener BEFORE resolving to prevent any
            // concurrent message dispatch from seeing signalingDone=false.
            signalingDone = true;
            ws.removeEventListener("message", handler);
            resolve();
          } else if (env.kind === MessageKind.Candidate) {
            // FIX 3: guard against addIceCandidate on a closed/done pc.
            if (signalingDone) return;
            const candidateStr = new TextDecoder().decode(env.payload);
            // Firefox REQUIRES sdpMid (or sdpMLineIndex) on a remote candidate — there is a
            // single m=application (DataChannel) section, so index 0 / mid "0". (Chrome is
            // lenient; Firefox throws "Cannot add a candidate without specifying either sdpMid
            // or sdpMLineIndex".)
            await pc.addIceCandidate({
              candidate: candidateStr,
              sdpMid: "0",
              sdpMLineIndex: 0,
            });
          } else if (env.kind === MessageKind.EndOfCandidates) {
            // FIX 3: guard against addIceCandidate on a closed/done pc.
            if (signalingDone) return;
            // Signal to Firefox that the host will not trickle any more candidates.
            // Passing no argument to addIceCandidate signals end-of-candidates per the WebRTC
            // spec; this is the most broadly supported form (undefined/null are equivalent but
            // the no-arg call is idiomatic and avoids TypeScript type errors).
            await pc.addIceCandidate();
          } else if (env.kind === MessageKind.Error) {
            // FIX 2: surface signaling errors explicitly instead of waiting for the 20 s
            // timeout — a signaling-side reject never delivers an Answer, so without this
            // branch the caller would hang until the timeout fires.
            window.clearTimeout(timeout);
            signalingDone = true;
            ws.removeEventListener("message", handler);
            reject(
              new Error(
                "signaling error: " + new TextDecoder().decode(env.payload),
              ),
            );
          }
        } catch (err) {
          // FIX 1: propagate any synchronous or async throw to the outer reject.
          window.clearTimeout(timeout);
          signalingDone = true;
          ws.removeEventListener("message", handler);
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      };

      ws.addEventListener("message", handler);
    });

    // Wait for DataChannel to open.
    await new Promise<void>((resolve, reject) => {
      const timeout = window.setTimeout(
        () => reject(new Error("timed out waiting for DataChannel open")),
        20_000,
      );
      dc.onopen = () => {
        window.clearTimeout(timeout);
        resolve();
      };
      dc.onerror = (e) => {
        window.clearTimeout(timeout);
        reject(new Error(`DataChannel error: ${String(e)}`));
      };
    });

    result.connected = true;

    // Send the HELLO frame.
    dc.send(SHP_HELLO_FRAME.buffer);

    // Wait for the echo frame from the native host.
    const echoFrame = await new Promise<ArrayBuffer>((resolve, reject) => {
      const timeout = window.setTimeout(
        () => reject(new Error("timed out waiting for echo frame")),
        10_000,
      );
      dc.onmessage = (e: MessageEvent) => {
        window.clearTimeout(timeout);
        if (e.data instanceof ArrayBuffer) {
          resolve(e.data);
        } else {
          reject(new Error(`unexpected DataChannel message type: ${typeof e.data}`));
        }
      };
    });

    result.echoed = true;
    result.frameHex = Array.from(new Uint8Array(echoFrame))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    ws.close();
    pc.close();
  } catch (e) {
    result.error = e instanceof Error ? e.message : String(e);
  }

  return result;
}

// ── Utilities ────────────────────────────────────────────────────────────────

/** Open a WebSocket and wait for the connection to establish. */
function connectWs(url: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    ws.onopen = () => resolve(ws);
    ws.onerror = () => reject(new Error(`WebSocket connection failed: ${url}`));
  });
}

/** Send a signaling envelope over a WebSocket. */
function sendEnvelope(ws: WebSocket, env: Parameters<typeof encodeEnvelope>[0]): void {
  ws.send(encodeEnvelope(env));
}

/**
 * Decode a 32-char lowercase hex string to a Uint8Array (16 bytes).
 *
 * Throws if the string is not exactly 32 lowercase hex characters, so a malformed
 * URL parameter produces a clear error rather than silently producing all-zero bytes
 * (which `parseInt(..., 16)` returns as 0 for non-hex input).
 *
 * The regex guard `^[0-9a-f]{32}$` guarantees every group is valid hex before parsing,
 * so the `isNaN` check that previously appeared here was unreachable and is removed.
 */
function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-f]{32}$/.test(hex)) {
    throw new Error(
      `hexToBytes: expected 32 lowercase hex chars, got "${hex.slice(0, 64)}"`,
    );
  }
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// ── Expose to Playwright ─────────────────────────────────────────────────────

declare global {
  interface Window {
    __runInteropTest?: () => Promise<InteropResult>;
    __interopResult?: InteropResult;
  }
}

// Expose the driver function so the Playwright spec can call `page.evaluate`.
window.__runInteropTest = runInteropTest;

// Auto-run when the page loads and store the result.
void runInteropTest().then((r) => {
  window.__interopResult = r;
});
