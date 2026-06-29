/**
 * browser-native.ts — browser-side driver for the browser↔native WebRTC interop test (P5-3).
 *
 * # Stage 2: identity-bound DTLS pin (ADR-0023 / ADR-0014)
 *
 * This runs inside a Playwright-controlled Firefox page. Unlike Stage 1 (which pinned the host's
 * DTLS fingerprint from the SDP — transport interop only), Stage 2 layers the **live Noise XK
 * handshake** over signaling so the pin is **identity-bound**:
 *
 *   1. A production `WebClient` (offerer) creates the SDP offer; we read its local DTLS
 *      fingerprint (`local_dtls_fingerprint()`).
 *   2. We run the Noise XK handshake (`WasmNoiseHandshake`) over the signaling channel, committing
 *      the browser's local DTLS fingerprint inside the identity-signed `BindCert`, and extract the
 *      host's committed fingerprint (`require_dtls_pin()`).
 *   3. We feed that BindCert-committed pin into `WebClient.set_dtls_pin()` and let
 *      `connect_as_offerer()` verify the host's **answer** SDP `a=fingerprint` against it. A
 *      signaling/SDP fingerprint swap is rejected by the fail-closed `guard_remote_sdp` gate
 *      **before** `setRemoteDescription` — never touching DTLS.
 *
 * The host (native answerer) symmetrically pins the BROWSER's BindCert-committed fingerprint, not
 * the offer SDP. Together this is the browser↔native equivalent of the native
 * `dtls_identity_binding` MITM test.
 *
 * # Modes (URL query)
 *
 *   - `?session=<hex>&host_fp=<hex>`  — identity-bound happy path (assert connected + echo +
 *     pinUsedHex === hostFp).
 *   - `…&mitm=1`                      — a man-in-the-middle SWAPS the host's answer SDP
 *     `a=fingerprint` after the BindCert committed a different one → `connect_as_offerer` MUST
 *     ABORT with a pin mismatch (non-vacuous MITM rejection).
 *   - `…&video=1`                     — the host streams baked H.264 SHP video frames (ADR-0031);
 *     the browser parses + WebCodecs-decodes them. Assert `framesReachedDecoder >= 1` (and
 *     `framesDecoded >= 1` only when `h264DecodeSupported` is true).
 *
 * # Security note
 *
 * Uses `InsecureLanLab` / `AcceptAll`-compatible signaling (empty proof). The identity binding is
 * the Noise/BindCert layer, which is independent of the signaling auth (R-SIG-AUTH on the live
 * signaling path is deferred — ADR-0023). For local integration tests only.
 */

import { loadBridge } from "../src/bridge/index.js";
import type { ShBridge, WebClient, WasmNoiseHandshake } from "../src/bridge/types.js";
import {
  decodeEnvelope,
  encodeEnvelope,
  MessageKind,
  ENVELOPE_HEADER_LEN,
} from "../src/signaling/envelope.js";
// VIDEO mode (?video=1): parse inbound SHP video frames and decode them with WebCodecs, proving
// the browser can render the H.264 stream the native host produces (P5-3 Stage 2 + ADR-0031).
import { parseVideoFrame } from "../src/protocol/frame.js";
import { VideoFragmentReassembler, isKeyframe } from "../src/protocol/reassembler.js";
import { CanvasH264Decoder, isWebCodecsAvailable } from "../src/view/decoder.js";

/** avc1 codec string of the baked fixture (H.264 Baseline 0x42, level 0x1e / 3.0 — OpenH264 output,
 * matching the loopback e2e's probe). Used only to probe decode SUPPORT; the real decode path
 * derives the exact codec string from the stream's SPS. */
const FIXTURE_CODEC = "avc1.42001e";

/** Probe whether this browser can actually decode the fixture's H.264 — `null` if it can't be
 * determined. API presence (`isWebCodecsAvailable`) is NOT the same as codec support: headless
 * Firefox exposes `VideoDecoder` but may lack the H.264 codec, so the decode assertion is gated on
 * this probe (mirrors `loopback.ts`). */
async function probeH264DecodeSupport(): Promise<boolean | null> {
  try {
    const VD = (
      globalThis as unknown as {
        VideoDecoder?: {
          isConfigSupported?: (c: { codec: string }) => Promise<{ supported?: boolean }>;
        };
      }
    ).VideoDecoder;
    if (VD?.isConfigSupported === undefined) return null;
    const support = await VD.isConfigSupported({ codec: FIXTURE_CODEC });
    return support.supported === true;
  } catch {
    return null;
  }
}

/** The result written to `window.__interopResult` after the test completes. */
export interface InteropResult {
  /** True if the DataChannel reached the Open state. */
  connected: boolean;
  /** True if an echo frame was received from the native host. */
  echoed: boolean;
  /** The raw echo frame bytes (hex-encoded) or null if not received. */
  frameHex: string | null;
  /** Hex of the DTLS pin the browser actually enforced (the host's BindCert commit), or null. */
  pinUsedHex: string | null;
  /** True iff the MITM SDP-fingerprint swap was REJECTED by the fail-closed pin gate. */
  mitmRejected: boolean;
  /** VIDEO mode: count of COMPLETE access units that reached the decoder (multi-fragment frames
   * count once, only after their final fragment is reassembled — not per inbound fragment). */
  framesReachedDecoder: number;
  /** VIDEO mode: count of frames the WebCodecs decoder successfully decoded. */
  framesDecoded: number;
  /** VIDEO mode: whether the running browser exposes the WebCodecs `VideoDecoder` API. */
  webCodecs: boolean;
  /** VIDEO mode: whether this browser can actually DECODE the fixture's H.264 (probed via
   * `VideoDecoder.isConfigSupported`). `null` = couldn't probe. API presence ≠ codec support, so the
   * decode assertion is gated on this, not on `webCodecs`. */
  h264DecodeSupported: boolean | null;
  /** VIDEO mode: count of synthetic input events the browser sent to the host (remote control). */
  inputSent: number;
  /** Error message, if any. */
  error: string | null;
}

// Noise-over-signaling sub-types live in a dependency-free single-source module so the driver and
// its unit test cannot drift; the matching Rust values are guarded by a Rust test (see ADR-0023).
import { NOISE_SUB_HELLO, NOISE_SUB_HOST_STATIC_PUB, NOISE_SUB_MSG } from "./noise-subtypes.js";

/** Magic prefix of the SHP frame sent to the host. */
const SHP_HELLO_FRAME = new Uint8Array([
  // "SHP" + version byte
  0x53, 0x48, 0x50, 0x00,
  // payload_len: 5 (u32 BE) = 0x00 0x00 0x00 0x05
  0x00, 0x00, 0x00, 0x05,
  // payload: "HELLO"
  0x48, 0x45, 0x4c, 0x4c, 0x4f,
]);

/**
 * Default signaling WebSocket URL (explicit IPv4 loopback to avoid `::1` resolution). Used only as
 * a fallback; the Playwright harness passes the actual dynamic-port URL via the `sig` query param
 * (the signaling server binds `:0`, so the port is not fixed).
 */
const DEFAULT_SIGNALING_URL = "ws://127.0.0.1:8765";

/** Resolve the signaling URL from the `sig` query param, validating the scheme. */
function resolveSignalingUrl(params: URLSearchParams): string {
  const raw = params.get("sig");
  if (raw === null || raw === "") return DEFAULT_SIGNALING_URL;
  // Only accept ws://127.0.0.1:<port> / ws://localhost:<port> to avoid pointing the page at an
  // arbitrary attacker-controlled host if the query string is ever influenced externally.
  if (!/^ws:\/\/(127\.0\.0\.1|localhost):\d{1,5}$/.test(raw)) {
    throw new Error(`refusing to use non-loopback signaling URL: "${raw.slice(0, 80)}"`);
  }
  return raw;
}

// ── Entry point ──────────────────────────────────────────────────────────────

/**
 * Main driver: runs the identity-bound browser↔native session (or the MITM-rejection arm).
 */
async function runInteropTest(): Promise<InteropResult> {
  const result: InteropResult = {
    connected: false,
    echoed: false,
    frameHex: null,
    pinUsedHex: null,
    mitmRejected: false,
    framesReachedDecoder: 0,
    framesDecoded: 0,
    webCodecs: false,
    h264DecodeSupported: null,
    inputSent: 0,
    error: null,
  };

  let ws: WebSocket | null = null;
  let viewer: WebClient | null = null;
  // VIDEO mode only: the WebCodecs H.264 decoder painting into the hidden canvas. Held here so the
  // `finally` block can close it (release codec/GPU resources) regardless of how the run ends.
  let decoder: CanvasH264Decoder | null = null;

  try {
    const params = new URLSearchParams(window.location.search);
    const sessionHex = params.get("session") ?? "0".repeat(32);
    const hostFp = params.get("host_fp") ?? "";
    const mitm = params.get("mitm") === "1";
    // VIDEO mode: instead of echoing a HELLO frame, the host streams baked H.264 SHP video
    // frames; the browser parses + decodes them and we assert frames reached the decoder.
    const video = params.get("video") === "1";
    result.webCodecs = isWebCodecsAvailable();

    if (!/^[0-9a-f]{64}$/.test(hostFp)) {
      result.error = `host_fp must be 64 lowercase hex chars, got ${hostFp.length}`;
      return result;
    }

    const signalingUrl = resolveSignalingUrl(params);
    const sessionId = hexToBytes(sessionHex.padEnd(32, "0").slice(0, 32));

    const bridge: ShBridge = await loadBridge();

    // ── 1. Production WebClient (offerer): create the offer, read our local DTLS fp ──
    const noop = (): void => {};
    const SignalingChannel = bridge.SignalingChannel;
    viewer = new bridge.WebClient(new SignalingChannel(noop));

    // create_offer() builds the offerer's "shp" DataChannel and sets the local description, so
    // local_dtls_fingerprint() is valid afterwards. setLocalDescription also STARTS ICE gathering,
    // so we register the candidate handler immediately and BUFFER candidates until the WS is up
    // (the Noise handshake runs first and takes a few round-trips). Losing the browser's host
    // candidate would leave the native peer with no remote candidate → ICE failure.
    const offerSdp = await viewer.create_offer();
    const browserDtlsFp = viewer.local_dtls_fingerprint(); // 32 bytes
    const browserFp = toHex(browserDtlsFp); // 64-char hex (our signaling from_fp)
    if (!/^[0-9a-f]{64}$/.test(browserFp)) {
      throw new Error(`local DTLS fingerprint is not 64 hex chars: "${browserFp.slice(0, 80)}"`);
    }

    // Candidate buffer + sink. Until `flushCandidates` is wired to the live WS, candidates queue.
    const pendingCandidates: Array<string | null> = [];
    let candidateSink: ((cand: string | null) => void) | null = null;
    viewer.on_ice_candidate((cand: string | null) => {
      if (candidateSink !== null) candidateSink(cand);
      else pendingCandidates.push(cand);
    });

    // ── 2. Connect to signaling and register as the real browser DTLS fingerprint ──
    ws = await connectWs(signalingUrl);
    const inbound = makeEnvelopeQueue(ws);
    const liveWs = ws;

    sendEnvelope(ws, {
      kind: MessageKind.Hello,
      sessionId,
      fromFp: browserFp,
      toFp: hostFp,
      payload: new Uint8Array(0),
    });

    // ── 3. Identity-bound Noise XK handshake over signaling (browser = initiator) ──
    const hostPin = await runNoiseInitiator(
      bridge,
      ws,
      inbound,
      sessionId,
      browserFp,
      hostFp,
      browserDtlsFp,
    );
    result.pinUsedHex = toHex(hostPin);

    // ── 4. Pin the host's BindCert-committed fingerprint (NOT the SDP). ──
    viewer.set_dtls_pin(hostPin);

    // ── 5. Wire ICE trickle to the live WS and flush any candidates buffered during the Noise
    //      handshake (and all future ones). The browser's host candidate MUST reach the native
    //      peer or ICE never connects.
    const sendCandidate = (cand: string | null): void => {
      if (cand !== null && cand !== "") {
        sendEnvelope(liveWs, {
          kind: MessageKind.Candidate,
          sessionId,
          fromFp: browserFp,
          toFp: hostFp,
          payload: new TextEncoder().encode(cand),
        });
      } else {
        sendEnvelope(liveWs, {
          kind: MessageKind.EndOfCandidates,
          sessionId,
          fromFp: browserFp,
          toFp: hostFp,
          payload: new Uint8Array(0),
        });
      }
    };
    // Attach the DataChannel frame sink BEFORE connecting so no frame is missed.
    // - ECHO/MITM mode: resolve `echoPromise` on the FIRST inbound frame (the host's echo).
    // - VIDEO mode: register a PERSISTENT handler that parses each SHP video frame and feeds it to
    //   the WebCodecs decoder, counting frames that reached the decoder and frames decoded.
    let echoPromise: Promise<Uint8Array> | null = null;
    if (video) {
      const canvas = document.getElementById("screen") as HTMLCanvasElement;
      decoder = new CanvasH264Decoder(canvas);
      const dec = decoder; // narrow to non-null for the closure
      // The host fragments large H.264 access units across several SHP messages; reassemble them
      // before decoding. One reassembler for the whole stream (fragment state is per-session).
      const reassembler = new VideoFragmentReassembler();
      viewer!.on_frame((frame: Uint8Array) => {
        // `bridge` is in scope (loaded above). parseVideoFrame returns null for a non-video /
        // malformed frame (never throws) — drop those without counting them.
        const parsed = parseVideoFrame(bridge, frame);
        if (!parsed) return;
        // Feed the fragment to the reassembler. A non-null result is a COMPLETE access unit; a
        // partial (still-buffering) fragment returns null and must NOT count as a decoded frame.
        const complete = reassembler.push(parsed);
        if (!complete) return;
        result.framesReachedDecoder += 1;
        try {
          dec.pushAnnexB(complete.payload, isKeyframe(complete));
        } catch {
          /* ignore decode errors — a hostile/garbage frame must not crash the viewer */
        }
        result.framesDecoded = dec.stats.framesDecoded;
      });
    } else {
      echoPromise = new Promise<Uint8Array>((resolve) => {
        // viewer is non-null in this scope.
        viewer!.on_frame((frame: Uint8Array) => resolve(frame));
      });
    }

    // ── 6. Send the offer FIRST, then trickle candidates. ──
    // The native host's `receive_offer` loop drops any non-Offer envelope, so candidates sent
    // before the offer would be lost. We send the offer, THEN wire the candidate sink and flush
    // the buffered candidates — by which point the host has moved on to its candidate pump.
    sendEnvelope(ws, {
      kind: MessageKind.Offer,
      sessionId,
      fromFp: browserFp,
      toFp: hostFp,
      payload: new TextEncoder().encode(offerSdp),
    });

    candidateSink = sendCandidate;
    for (const cand of pendingCandidates.splice(0)) sendCandidate(cand);

    let answerSdp = await waitForAnswer(inbound, hostFp);

    // ── 6b. MITM arm: swap the host's advertised DTLS fingerprint in the answer SDP. ──
    // The BindCert committed the host's REAL fingerprint (hostPin); this tampered answer presents a
    // DIFFERENT fingerprint, so connect_as_offerer's fail-closed pin gate MUST abort.
    if (mitm) {
      answerSdp = swapSdpFingerprint(answerSdp);
    }

    // ── 7. Connect as offerer — pin-checked. On mismatch (MITM), this THROWS before setRemote. ──
    try {
      await viewer.connect_as_offerer(answerSdp);
    } catch (e) {
      if (mitm) {
        // Expected: the identity-bound pin gate rejected the swapped SDP fingerprint.
        result.mitmRejected = true;
        return result;
      }
      throw e;
    }

    if (mitm) {
      // The swap should have been rejected. Reaching here means the gate FAILED to fire — a bug.
      throw new Error("MITM SDP-fingerprint swap was NOT rejected by the pin gate");
    }

    // Pump trickle ICE candidates from the host until the DataChannel echo completes. A throw here
    // is surfaced as result.error (cleaner than a raw pageerror) rather than discarded.
    void pumpRemoteCandidates(viewer, inbound, hostFp).catch((e: unknown) => {
      if (result.error === null) {
        result.error = `candidate pump failed: ${e instanceof Error ? e.message : String(e)}`;
      }
    });

    // ── 8. Once the DataChannel opens, send the HELLO frame. ──
    // NOTE: the offerer's own channel-open is not exposed by WebClient (`on_data_channel` is the
    // ANSWERER's `ondatachannel`, which does not fire for the offerer's `createDataChannel`
    // channel). We therefore use the first successful `send_frame` as the open signal, and treat a
    // never-opens condition as a DISTINCT failure (rejects below) instead of masking it as the
    // generic timeout. In VIDEO mode we STILL send HELLO so the host's `accept_channel()` resolves
    // and it starts streaming (the host ignores the HELLO body in video mode).
    const sentFrame = sendFrameWhenOpen(viewer, SHP_HELLO_FRAME, 30_000);
    // Surface a never-opens rejection if it loses the race below (so it isn't unhandled).
    sentFrame.catch(() => undefined);

    if (video) {
      // ── 9a. VIDEO mode: wait until at least one SHP video frame reached the decoder. ──
      // Poll every 100 ms up to 30 s. Race against the channel-never-opened rejection so a failure
      // to open surfaces its specific cause rather than a generic timeout.
      const deadline = Date.now() + 30_000;
      const framesArrived = (async (): Promise<void> => {
        while (result.framesReachedDecoder < 1) {
          if (Date.now() > deadline) {
            throw new Error("timed out waiting for a video frame from the native host");
          }
          await new Promise((r) => window.setTimeout(r, 100));
        }
      })();
      await Promise.race([
        framesArrived,
        sentFrame.then(() => new Promise<void>(() => {})), // never resolves on its own; lets its rejection win
      ]);

      result.connected = true;

      // CONTROL: send a few synthetic input events (browser→host) to prove remote control. The host
      // decodes each 16-byte InputEvent off the DataChannel and injects it; the spec asserts the
      // host's `INPUT_INJECTED` log. EventType.PointerMove = 0; normalized coords in 0..=65535.
      // `send_frame` writes raw bytes to the single "shp" RTCDataChannel — the same call serves both
      // the video-test frames and input events (they share the one channel; the host demuxes by size).
      for (let i = 0; i < 5; i++) {
        try {
          const ev = bridge.encode_input_event(0, 0, 10_000 + i * 100, 20_000, 0, 0, 0, 0, 0);
          viewer.send_frame(ev);
          result.inputSent += 1;
        } catch {
          /* channel closed / not writable — best-effort, the host-side assertion is authoritative */
        }
      }
      // Keep the session alive long enough for the input to be transmitted, drained by the host
      // (it polls between video frames), and injected — otherwise the `finally` `viewer.close()`
      // (which fires as soon as this function returns, e.g. when H.264 decode is unsupported and the
      // decode-wait below is skipped) can tear down DTLS/SCTP before the input bytes leave the wire.
      await new Promise((r) => window.setTimeout(r, 1_500));

      // Decode is asserted by the spec only when H.264 decode is actually SUPPORTED (probed via
      // VideoDecoder.isConfigSupported — API presence alone is not enough; headless Firefox may lack
      // the codec). When supported, poll up to 3 s for an async decode output to land (a fixed sleep
      // can under-report on a slow box); when unsupported/unknown, skip the wait.
      result.h264DecodeSupported = await probeH264DecodeSupport();
      if (result.h264DecodeSupported === true && decoder !== null) {
        const decodeDeadline = Date.now() + 3_000;
        while (decoder.stats.framesDecoded < 1 && Date.now() < decodeDeadline) {
          await new Promise((r) => window.setTimeout(r, 100));
        }
        result.framesDecoded = decoder.stats.framesDecoded;
      }
    } else {
      // ── 9b. ECHO/MITM mode: wait for the DataChannel echo (proves the session connected). ──
      // Race the echo against (a) a channel-never-opened rejection and (b) an overall deadline, so
      // a failure to open the channel surfaces its specific cause rather than a generic timeout.
      // `echoPromise` is non-null in this branch (constructed above when !video).
      const echo = echoPromise ?? Promise.reject(new Error("echo promise missing"));
      const echoFrame = await Promise.race([
        echo,
        sentFrame.then(() => new Promise<Uint8Array>(() => {})), // never resolves on its own; lets its rejection win
        timeoutReject<Uint8Array>(30_000, "timed out waiting for echo frame"),
      ]);

      result.connected = true;
      result.echoed = true;
      result.frameHex = toHex(echoFrame);
    }
  } catch (e) {
    result.error = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
  } finally {
    try {
      ws?.close();
    } catch {
      /* ignore */
    }
    try {
      viewer?.close();
    } catch {
      /* ignore */
    }
    // VIDEO mode only: release the WebCodecs decoder / canvas resources if one was constructed.
    try {
      decoder?.close();
    } catch {
      /* ignore */
    }
  }

  return result;
}

// ── Noise XK initiator over signaling ─────────────────────────────────────────

/**
 * Run the browser side (XK initiator) of the identity-bound Noise handshake over signaling.
 *
 * Ordering (B=browser, H=host) — see `bins/streamhaul-webrtc-host`:
 * ```
 * B → H : Noise(HELLO, [])
 * H → B : Noise(HOST_STATIC_PUB, X)
 * B → H : Noise(MSG, msg0)
 * H → B : Noise(MSG, msg1)
 * B → H : Noise(MSG, msg2)
 * B     : complete_for_first_pairing() → require_dtls_pin()  (the host's committed DTLS fp)
 * ```
 *
 * Returns the host's BindCert-committed 32-byte DTLS pin.
 */
async function runNoiseInitiator(
  bridge: ShBridge,
  ws: WebSocket,
  inbound: EnvelopeQueue,
  sessionId: Uint8Array,
  browserFp: string,
  hostFp: string,
  browserDtlsFp: Uint8Array,
): Promise<Uint8Array> {
  const sendNoise = (sub: number, body: Uint8Array): void => {
    const payload = new Uint8Array(body.length + 1);
    payload[0] = sub;
    payload.set(body, 1);
    sendEnvelope(ws, {
      kind: MessageKind.Noise,
      sessionId,
      fromFp: browserFp,
      toFp: hostFp,
      payload,
    });
  };

  const recvNoise = async (expectedSub: number): Promise<Uint8Array> => {
    for (;;) {
      const env = await inbound.next(20_000);
      if (env.kind !== MessageKind.Noise || env.fromFp !== hostFp) continue;
      if (env.payload.length < 1) continue;
      if (env.payload[0] !== expectedSub) continue;
      return env.payload.slice(1);
    }
  };

  // 1. Announce ourselves so the host learns our from_fp.
  sendNoise(NOISE_SUB_HELLO, new Uint8Array(0));

  // 2. Receive the host's X25519 static public key.
  const hostStaticPub = await recvNoise(NOISE_SUB_HOST_STATIC_PUB);
  if (hostStaticPub.length !== 32) {
    throw new Error(`host static pub must be 32 bytes, got ${hostStaticPub.length}`);
  }

  // 3. Build the XK initiator, committing OUR DTLS fingerprint in the BindCert.
  const keystore = bridge.WasmKeystore.generate();
  const hs: WasmNoiseHandshake = bridge.WasmNoiseHandshake.initiator_xk_with_dtls(
    keystore,
    hostStaticPub,
    browserDtlsFp,
    new Uint8Array(0),
  );

  // 4. XK: write msg0, read msg1, write msg2.
  sendNoise(NOISE_SUB_MSG, hs.write_message());
  hs.read_message(await recvNoise(NOISE_SUB_MSG));
  sendNoise(NOISE_SUB_MSG, hs.write_message());

  if (!hs.is_finished()) {
    throw new Error("Noise handshake did not finish after 3 messages");
  }

  // 5. Complete (TOFU first pairing) and extract the host's committed DTLS pin.
  const outcome = hs.complete_for_first_pairing();
  return outcome.require_dtls_pin();
}

// ── Signaling envelope queue ──────────────────────────────────────────────────

interface DecodedEnvelope {
  kind: number;
  fromFp: string;
  payload: Uint8Array;
}

interface EnvelopeQueue {
  /** Resolve with the next decoded envelope, or reject after `timeoutMs`. */
  next(timeoutMs: number): Promise<DecodedEnvelope>;
}

interface QueueWaiter {
  resolve: (env: DecodedEnvelope) => void;
  reject: (err: Error) => void;
}

/**
 * Buffer all inbound signaling envelopes so sequential `await next()` calls never drop a message
 * that arrives between awaits (the Stage-1 single-handler model raced on out-of-order delivery).
 *
 * On WS `close`/`error` (server died / disconnect), all pending `next()` waiters are rejected
 * immediately with `WebSocket closed` rather than hanging until their per-call timeout — so a
 * dead signaling server surfaces a clear error fast instead of an opaque 20 s stall.
 */
function makeEnvelopeQueue(ws: WebSocket): EnvelopeQueue {
  const buffer: DecodedEnvelope[] = [];
  const waiters: QueueWaiter[] = [];
  let closed = false;

  const onMessage = async (event: MessageEvent): Promise<void> => {
    let raw: Uint8Array;
    if (event.data instanceof ArrayBuffer) {
      raw = new Uint8Array(event.data);
    } else if (event.data instanceof Blob) {
      raw = new Uint8Array(await event.data.arrayBuffer());
    } else {
      return;
    }
    if (raw.length < ENVELOPE_HEADER_LEN) return;
    let env: ReturnType<typeof decodeEnvelope>;
    try {
      env = decodeEnvelope(raw);
    } catch {
      return; // hostile/malformed envelope — drop, never throw out of the listener
    }
    const decoded: DecodedEnvelope = { kind: env.kind, fromFp: env.fromFp, payload: env.payload };
    const waiter = waiters.shift();
    if (waiter !== undefined) waiter.resolve(decoded);
    else buffer.push(decoded);
  };
  ws.addEventListener("message", (e) => void onMessage(e));

  const onClosed = (): void => {
    if (closed) return;
    closed = true;
    // Reject every pending waiter so no caller hangs until its timeout.
    while (waiters.length > 0) {
      waiters.shift()?.reject(new Error("WebSocket closed"));
    }
  };
  ws.addEventListener("close", onClosed);
  ws.addEventListener("error", onClosed);

  return {
    next(timeoutMs: number): Promise<DecodedEnvelope> {
      const buffered = buffer.shift();
      if (buffered !== undefined) return Promise.resolve(buffered);
      if (closed) return Promise.reject(new Error("WebSocket closed"));
      return new Promise<DecodedEnvelope>((resolve, reject) => {
        const waiter: QueueWaiter = {
          resolve: (env) => {
            window.clearTimeout(timer);
            resolve(env);
          },
          reject: (err) => {
            window.clearTimeout(timer);
            reject(err);
          },
        };
        const timer = window.setTimeout(() => {
          const idx = waiters.indexOf(waiter);
          if (idx >= 0) waiters.splice(idx, 1);
          reject(new Error("timed out waiting for a signaling envelope"));
        }, timeoutMs);
        waiters.push(waiter);
      });
    },
  };
}

/** Drain the queue until an `Answer` envelope from `hostFp` arrives; returns the answer SDP. */
async function waitForAnswer(inbound: EnvelopeQueue, hostFp: string): Promise<string> {
  for (;;) {
    const env = await inbound.next(20_000);
    if (env.kind === MessageKind.Answer && env.fromFp === hostFp) {
      return new TextDecoder().decode(env.payload);
    }
    // Ignore unrelated messages (e.g. an early Candidate); keep waiting for the Answer.
  }
}

/** Forward the host's trickle ICE candidates to the viewer until the queue stalls or closes. */
async function pumpRemoteCandidates(
  viewer: WebClient,
  inbound: EnvelopeQueue,
  hostFp: string,
): Promise<void> {
  for (;;) {
    let env: DecodedEnvelope;
    try {
      env = await inbound.next(30_000);
    } catch {
      return; // no more candidates within the window — connectivity already established or done
    }
    if (env.fromFp !== hostFp) continue;
    if (env.kind === MessageKind.Candidate) {
      const candidate = new TextDecoder().decode(env.payload);
      if (candidate.length === 0) continue;
      try {
        await viewer.add_ice_candidate(candidate);
      } catch {
        // A candidate may arrive after the pc closed (echo done) — ignore.
        return;
      }
    } else if (env.kind === MessageKind.EndOfCandidates || env.kind === MessageKind.Bye) {
      return;
    }
  }
}

// ── SDP MITM shim ─────────────────────────────────────────────────────────────

/**
 * Swap the SHA-256 `a=fingerprint` value in an SDP blob to a DIFFERENT (but well-formed) value,
 * simulating a signaling/SDP man-in-the-middle. The new fingerprint is structurally valid (so the
 * SDP parser accepts it) but does NOT match the host's BindCert-committed pin — so the
 * identity-bound `verify_sdp_fingerprint_pin` gate must reject it.
 */
function swapSdpFingerprint(sdp: string): string {
  return sdp.replace(
    /a=fingerprint:sha-256 ([0-9A-Fa-f:]+)/,
    (_match, hex: string) => {
      // Flip the first hex group so the value differs but stays 32 colon-separated byte groups.
      const groups = hex.split(":");
      const first = groups[0] ?? "00";
      const flipped = (parseInt(first, 16) ^ 0xff).toString(16).padStart(2, "0").toUpperCase();
      groups[0] = flipped;
      return `a=fingerprint:sha-256 ${groups.join(":")}`;
    },
  );
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
 * Send `frame` once the offerer's DataChannel is open, **distinguishing** a "channel never opened"
 * failure from the generic echo timeout.
 *
 * The `WebClient` exposes no offerer-channel-open event (`on_data_channel` is the *answerer*'s
 * `ondatachannel` — it does NOT fire for the offerer's own `createDataChannel` channel), so we use
 * the first successful `send_frame` (which throws on a not-yet-open channel) as the open signal.
 * Resolves on the first successful send; **rejects** with a distinct error if the channel never
 * becomes writable within `timeoutMs` (so the caller surfaces "DataChannel never opened" rather
 * than the opaque "timed out waiting for echo").
 */
async function sendFrameWhenOpen(
  viewer: WebClient,
  frame: Uint8Array,
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      viewer.send_frame(frame);
      return;
    } catch {
      if (Date.now() > deadline) {
        throw new Error(
          "DataChannel never opened (send_frame stayed un-writable) — ICE/DTLS likely failed",
        );
      }
      await new Promise((r) => window.setTimeout(r, 100));
    }
  }
}

/** A promise that rejects after `ms` with `label`. */
function timeoutReject<T>(ms: number, label: string): Promise<T> {
  return new Promise<T>((_, reject) => window.setTimeout(() => reject(new Error(label)), ms));
}

/** Hex-encode bytes (lowercase). */
function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/**
 * Decode a 32-char lowercase hex string to a Uint8Array (16 bytes).
 *
 * Throws if the string is not exactly 32 lowercase hex characters.
 */
function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-f]{32}$/.test(hex)) {
    throw new Error(`hexToBytes: expected 32 lowercase hex chars, got "${hex.slice(0, 64)}"`);
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
