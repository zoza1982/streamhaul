// Minimal viewer/control page wiring (functional, not polished — polish deferred per ADR-0022).
//
// Renders the session UI: connect/disconnect, identity/connection status, negotiated codec, and
// the video canvas. The VIEW (decode→render) and CONTROL (input capture) modules are wired to a
// real `WebClient` DataChannel. The live signaling/host handshake is out of P5-2 scope; this
// page demonstrates the viewer wiring, and the Playwright e2e drives it with an in-page loopback
// host that sends a real H.264 keyframe.

import { Session, type SessionState } from "./client/session.js";
import { CanvasH264Decoder, isWebCodecsAvailable } from "./view/decoder.js";
import { attachInputCapture } from "./control/input-capture.js";
import { parseVideoFrame, isH264Keyframe } from "./protocol/frame.js";
import { loadBridge } from "./bridge/index.js";
import { mountFileTransferUi } from "./file/ui.js";

function el<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (node === null) throw new Error(`missing element #${id}`);
  return node as T;
}

function render(state: SessionState): void {
  el("phase").textContent = state.phase;
  el("ice").textContent = state.iceState;
  el("codec").textContent = state.codec ?? "—";
  el("fingerprint").textContent = state.localFingerprint ?? "—";
  el("error").textContent = state.error ?? "";
}

async function main(): Promise<void> {
  const canvas = el<HTMLCanvasElement>("screen");
  el("webcodecs").textContent = isWebCodecsAvailable() ? "available" : "unavailable";

  const bridge = await loadBridge();
  const session = new Session();
  session.onChange(render);
  await session.init();

  const decoder = new CanvasH264Decoder(canvas);

  // FILE (P7-2): mount the drag-and-drop send + receive-progress affordance. It drives the
  // in-process sender→receiver loop (the live browser↔native file path is deferred, R-BROWSER-FILE).
  const fileHost = document.getElementById("file-transfer");
  // Keep the disposer so disconnect detaches the drag-drop listeners (mirrors `disposeInput`); the
  // listener closures capture the wasm bridge, so leaving them attached would pin its linear memory.
  const disposeFileUi = fileHost !== null ? mountFileTransferUi(fileHost) : (): void => {};

  // VIEW: route inbound video frames through the decoder. on_frame binds to the offerer's "shp"
  // DataChannel, which `create_offer` creates — so it must be registered AFTER the offer, inside
  // the connect handler (registering it at startup would throw "no DataChannel").
  const wireView = (): void => {
    session.onFrame((frame: Uint8Array) => {
      const parsed = parseVideoFrame(bridge, frame);
      if (parsed === null) {
        return; // hostile / non-video frame — dropped, session continues
      }
      decoder.pushAnnexB(parsed.payload, isH264Keyframe(parsed));
    });
  };

  // CONTROL: capture canvas input and send to the host over the DataChannel. attachInputCapture
  // returns a disposer that removes all six listeners; we keep it so disconnect can detach them.
  const disposeInput = attachInputCapture(canvas, bridge, (bytes) => {
    try {
      session.sendFrame(bytes);
    } catch {
      // No channel yet (not connected) — input is simply not delivered.
    }
  });

  el<HTMLButtonElement>("connect").addEventListener("click", () => {
    void session
      .createOffer()
      // wireView registers the inbound-frame handler; Session.onFrame is guarded so repeated
      // connect clicks do not stack overlapping handlers.
      .then(() => wireView())
      .catch(() => {
        /* surfaced via state.error */
      });
  });
  el<HTMLButtonElement>("disconnect").addEventListener("click", () => {
    disposeInput();
    disposeFileUi();
    decoder.close();
    // Close the WebClient (RTCPeerConnection + DataChannel), releasing ICE/DTLS resources.
    session.dispose();
  });
}

void main().catch((e: unknown) => {
  const node = document.getElementById("error");
  if (node !== null) node.textContent = e instanceof Error ? e.message : String(e);
});
