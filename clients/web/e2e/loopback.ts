// In-page browser-loopback demo driver for the Playwright headless-Firefox e2e.
//
// This is the functional VIEW+CONTROL+H.264+wire proof, in ONE page, end-to-end in a real
// browser:
//
//   - VIEWER side: a real `WebClient` (offerer) — the production browser client. It owns the
//     SHP DataChannel, decodes inbound video frames to a `<canvas>` via WebCodecs
//     (`CanvasH264Decoder`), and sends captured input back via `send_frame`.
//   - HOST side: a plain `RTCPeerConnection` answerer that receives the offerer's DataChannel
//     (`ondatachannel`), sends a real SHP-wrapped H.264 keyframe to the viewer, and captures
//     the SHP input bytes the viewer sends back.
//
// The DTLS-pin gate is satisfied with the host's REAL local fingerprint (parsed from its
// answer SDP), so `connect_as_offerer` passes its fail-closed pin check on honest SDP — the
// MITM-rejection behavior itself is already proven by sh-web-client's own browser e2e (P5-1c).
//
// The page exposes results on `window.__demo` for the Playwright spec to assert on.

import { loadBridge } from "../src/bridge/index.js";
import type { ShBridge, WebClient } from "../src/bridge/types.js";
import { CanvasH264Decoder, isWebCodecsAvailable } from "../src/view/decoder.js";
import { parseVideoFrame, isH264Keyframe } from "../src/protocol/frame.js";
import { attachInputCapture } from "../src/control/input-capture.js";
import { buildBrowserOffer, selectCodec } from "../src/protocol/negotiate.js";
import { Codec } from "../src/protocol/constants.js";
import { buildShpVideoFrame } from "../test/helpers/shp-frame.js";
import { H264_KEYFRAME } from "../test/fixtures/h264-keyframe.generated.js";

/** Result surface read by the Playwright spec. */
export interface DemoResult {
  webCodecsAvailable: boolean;
  negotiatedCodec: number | null;
  framesDecoded: number;
  framesDropped: number;
  decodedWidth: number;
  decodedHeight: number;
  canvasNonBlank: boolean;
  /** The exact SHP input bytes the host received from the viewer (hex), or null. */
  hostReceivedInputHex: string | null;
  malformedFrameSurvived: boolean;
  error: string | null;
}

declare global {
  // eslint-disable-next-line no-var
  var __demo: DemoResult | undefined;
  // eslint-disable-next-line no-var
  var __runDemo: (() => Promise<DemoResult>) | undefined;
}

function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/** Resolve once `pc` finishes ICE gathering (so its candidates are in the local SDP). */
function waitIceGatheringComplete(pc: RTCPeerConnection): Promise<void> {
  if (pc.iceGatheringState === "complete") return Promise.resolve();
  return new Promise((resolve) => {
    let done = false;
    const finish = (): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      pc.removeEventListener("icegatheringstatechange", check);
      resolve();
    };
    const check = (): void => {
      if (pc.iceGatheringState === "complete") finish();
    };
    pc.addEventListener("icegatheringstatechange", check);
    // Safety timeout: proceed even if the state event is missed on a loaded runner.
    const timer = setTimeout(finish, 8_000);
  });
}

function once<T>(target: EventTarget, type: string, map: (e: Event) => T, timeoutMs: number, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${label} timeout`)), timeoutMs);
    target.addEventListener(
      type,
      (e) => {
        clearTimeout(t);
        resolve(map(e));
      },
      { once: true },
    );
  });
}

async function run(): Promise<DemoResult> {
  const result: DemoResult = {
    webCodecsAvailable: isWebCodecsAvailable(),
    negotiatedCodec: null,
    framesDecoded: 0,
    framesDropped: 0,
    decodedWidth: 0,
    decodedHeight: 0,
    canvasNonBlank: false,
    hostReceivedInputHex: null,
    malformedFrameSurvived: false,
    error: null,
  };

  try {
    const bridge: ShBridge = await loadBridge();

    // ── Codec negotiation (H.264 selected for the browser) ───────────────────
    // The browser builds its offer caps (advertising H.264 decode + is_browser); a real host
    // would receive these. Here the host advertises HW H.264 encode (bit 0) and the browser
    // selects the session codec from that. Decode the browser offer back to assert it is a
    // well-formed H.264-advertising browser offer, so the negotiation proof is not vacuous.
    const browserOffer = buildBrowserOffer(bridge);
    const browserOfferDecoded = bridge.decode_caps(browserOffer);
    if (!browserOfferDecoded.is_browser || (browserOfferDecoded.hw_decode_mask & (1 << Codec.H264)) === 0) {
      throw new Error("browser offer must advertise H.264 decode + is_browser");
    }
    const hostCaps = bridge.encode_caps(1 << Codec.H264, 0, false, false, false, 0xff);
    const selection = selectCodec(bridge, hostCaps);
    result.negotiatedCodec = selection.codec;

    // ── Viewer = production WebClient (offerer) ───────────────────────────────
    const noop = (): void => {};
    const SignalingChannel = bridge.SignalingChannel;
    const viewer: WebClient = new bridge.WebClient(new SignalingChannel(noop));

    // ── Host = plain answerer PC ──────────────────────────────────────────────
    const host = new RTCPeerConnection();

    // ICE wiring (no STUN/TURN; needs media.peerconnection.ice.loopback pref):
    //  - The viewer's candidates are trickled to the host (a raw PC we fully control, so we can
    //    supply sdpMid/sdpMLineIndex). The call is deferred via queueMicrotask so it never
    //    re-enters wasm while a `viewer` borrow is live.
    //  - The host is NON-trickle: we wait for its ICE gathering to complete so all host-local
    //    candidates ride in the ANSWER SDP. The viewer therefore never needs `add_ice_candidate`
    //    (whose init lacks sdpMid), sidestepping Firefox's bare-candidate restriction.
    viewer.on_ice_candidate((cand: string | null) => {
      if (cand !== null && cand !== "") {
        void host.addIceCandidate({ candidate: cand, sdpMid: "0", sdpMLineIndex: 0 });
      }
    });

    // The host receives the viewer's DataChannel and records input it gets from the viewer.
    const hostGotInput = new Promise<Uint8Array>((resolve) => {
      host.ondatachannel = (ev: RTCDataChannelEvent): void => {
        const ch = ev.channel;
        ch.binaryType = "arraybuffer";
        ch.onmessage = (msg: MessageEvent): void => {
          if (msg.data instanceof ArrayBuffer) {
            resolve(new Uint8Array(msg.data));
          }
        };
        // Once open, the host pushes a real SHP-wrapped H.264 keyframe to the viewer.
        const send = (): void => {
          const frame = buildShpVideoFrame({ payload: H264_KEYFRAME, codec: Codec.H264, frameType: 1 });
          // Also push a malformed frame FIRST to prove the viewer survives hostile input.
          ch.send(new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02]));
          ch.send(frame);
        };
        if (ch.readyState === "open") send();
        else ch.addEventListener("open", send, { once: true });
      };
    });

    const canvas = document.getElementById("screen") as HTMLCanvasElement;
    const decoder = new CanvasH264Decoder(canvas);

    // ── Offer/answer ──────────────────────────────────────────────────────────
    // create_offer() builds the offerer's "shp" DataChannel, so on_frame (which binds to it)
    // must be registered AFTER the offer is created.
    const offerSdp = await viewer.create_offer();

    // ── VIEW: route inbound frames through the decoder ────────────────────────
    viewer.on_frame((frame: Uint8Array) => {
      const parsed = parseVideoFrame(bridge, frame);
      if (parsed === null) {
        // Malformed/hostile frame dropped — viewer keeps going.
        result.malformedFrameSurvived = true;
        return;
      }
      decoder.pushAnnexB(parsed.payload, isH264Keyframe(parsed));
    });

    await host.setRemoteDescription({ type: "offer", sdp: offerSdp });
    const answer = await host.createAnswer();
    await host.setLocalDescription(answer);
    // Wait for the host's ICE gathering to complete so its candidates are embedded in the SDP.
    await waitIceGatheringComplete(host);
    const answerSdp = host.localDescription?.sdp ?? "";

    // Pin the host's REAL local fingerprint so the fail-closed gate passes on honest SDP.
    const hostFp = bridge.parse_sdp_fingerprint(answerSdp);
    viewer.set_dtls_pin(hostFp);
    await viewer.connect_as_offerer(answerSdp);

    // ── Wait for the host to send the video; decode to canvas ────────────────
    // Give ICE/DTLS time to converge and frames to flow.
    await once(
      // Resolve when the decoder has painted at least one frame, polled below.
      makePoller(() => decoder.stats.framesDecoded > 0 || decoder.stats.framesDropped > 2),
      "tick",
      () => undefined,
      30_000,
      "decode",
    ).catch(() => undefined);

    result.framesDecoded = decoder.stats.framesDecoded;
    result.framesDropped = decoder.stats.framesDropped;
    result.decodedWidth = decoder.stats.lastWidth;
    result.decodedHeight = decoder.stats.lastHeight;
    result.canvasNonBlank = canvasIsNonBlank(canvas);

    // ── CONTROL: capture a synthetic canvas input and prove it reaches the host ─
    attachInputCapture(canvas, bridge, (bytes) => viewer.send_frame(bytes));
    // Dispatch a real DOM mousedown on the canvas center.
    const rect = canvas.getBoundingClientRect();
    canvas.dispatchEvent(
      new MouseEvent("mousedown", {
        bubbles: true,
        clientX: rect.left + rect.width / 2,
        clientY: rect.top + rect.height / 2,
        button: 0,
      }),
    );

    const received = await Promise.race([
      hostGotInput,
      new Promise<Uint8Array>((_, rej) => setTimeout(() => rej(new Error("host input timeout")), 15_000)),
    ]);
    result.hostReceivedInputHex = toHex(received);

    decoder.close();
    host.close();
  } catch (e) {
    result.error = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
  }

  globalThis.__demo = result;
  return result;
}

// A tiny EventTarget that fires "tick" once `cond` is true (polled on rAF/timer).
function makePoller(cond: () => boolean): EventTarget {
  const et = new EventTarget();
  const tick = (): void => {
    if (cond()) {
      et.dispatchEvent(new Event("tick"));
    } else {
      setTimeout(tick, 50);
    }
  };
  setTimeout(tick, 50);
  return et;
}

/** Whether the canvas has any non-black pixel (proves the decoded frame was painted). */
function canvasIsNonBlank(canvas: HTMLCanvasElement): boolean {
  const ctx = canvas.getContext("2d");
  if (ctx === null || canvas.width === 0 || canvas.height === 0) return false;
  const { data } = ctx.getImageData(0, 0, canvas.width, canvas.height);
  for (let i = 0; i < data.length; i += 4) {
    const r = data[i] ?? 0;
    const g = data[i + 1] ?? 0;
    const b = data[i + 2] ?? 0;
    if (r !== 0 || g !== 0 || b !== 0) return true;
  }
  return false;
}

globalThis.__runDemo = run;
