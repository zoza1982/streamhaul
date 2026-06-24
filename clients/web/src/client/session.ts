// Session lifecycle: owns the DTLS-pinned `WebClient`, exposes observable state to the UI.
//
// This is the orchestration shell. The security-critical pieces — DTLS-pin enforcement, SDP
// fingerprint parsing, the offer/answer flow — live inside the wasm `WebClient`; this wrapper
// only sequences the calls and surfaces state (connection state, negotiated codec, identity).
//
// NOTE: the live signaling transport (WebSocket → sh-signaling) and the in-browser identity
// handshake wiring are out of P5-2 scope (R-BROWSER-INTEROP / R-BROWSER-CRYPTO-LIVE). This
// module provides the seam (`SignalingSink`) and the codec-negotiation surface; the e2e proves
// view+control over a real DataChannel via an in-page loopback peer.

import { loadBridge } from "../bridge/index.js";
import type { ShBridge, WebClient } from "../bridge/types.js";
import { buildBrowserOffer, selectCodec } from "../protocol/negotiate.js";
import { codecName } from "../protocol/constants.js";
import { iceStateToPhase, toHex, type ConnectionPhase } from "./state.js";

export type { ConnectionPhase } from "./state.js";

/** A snapshot of session state rendered by the UI. */
export interface SessionState {
  readonly phase: ConnectionPhase;
  readonly iceState: string;
  /** Negotiated codec name, or null before negotiation. */
  readonly codec: string | null;
  /** Local DTLS fingerprint (hex) once the offer is created, or null. */
  readonly localFingerprint: string | null;
  readonly error: string | null;
}

/** A sink for outbound signaling payloads (SDP/ICE) — wired to a WebSocket in production. */
export type SignalingSink = (payload: string) => void;

/**
 * The browser session controller.
 *
 * Construct, subscribe via `onChange`, then drive with `init()` → `createOffer()`. The codec
 * negotiation (`negotiateCodec`) surfaces H.264 to the UI. Frame send/receive run through the
 * underlying `WebClient` (`sendFrame` / `onFrame`).
 */
export class Session {
  private bridge: ShBridge | null = null;
  private client: WebClient | null = null;
  /** Whether an inbound-frame callback is already registered (on_frame replaces, but we still
   * guard against repeated registration churn / double-wiring per session). */
  private frameHandlerRegistered = false;
  private listeners = new Set<(s: SessionState) => void>();
  private state: SessionState = {
    phase: "idle",
    iceState: "new",
    codec: null,
    localFingerprint: null,
    error: null,
  };

  constructor(private readonly signaling: SignalingSink = () => {}) {}

  /** Current state snapshot. */
  get current(): SessionState {
    return this.state;
  }

  /** Subscribe to state changes; returns an unsubscribe function. */
  onChange(cb: (s: SessionState) => void): () => void {
    this.listeners.add(cb);
    cb(this.state);
    return () => this.listeners.delete(cb);
  }

  private set(patch: Partial<SessionState>): void {
    this.state = { ...this.state, ...patch };
    for (const cb of this.listeners) cb(this.state);
  }

  /**
   * Load the wasm bridge and construct the WebClient + signaling channel.
   *
   * Idempotent and race-safe: a second call while (or after) a client already exists is a no-op,
   * so two concurrent callers cannot each `new WebClient` (which would leak the first client's
   * RTCPeerConnection).
   */
  async init(): Promise<void> {
    if (this.client !== null) return;
    this.set({ phase: "initializing", error: null });
    try {
      const bridge = await loadBridge();
      // Re-check after the await: another concurrent init() may have constructed the client
      // while we were awaiting the bridge load.
      if (this.client !== null) return;
      this.bridge = bridge;
      const channel = new bridge.SignalingChannel((payload: string) => this.signaling(payload));
      this.client = new bridge.WebClient(channel);
      this.set({ phase: "idle" });
    } catch (e) {
      this.set({ phase: "failed", error: errMsg(e) });
      throw e;
    }
  }

  /** Create the local WebRTC offer and surface the local DTLS fingerprint. */
  async createOffer(): Promise<string> {
    const client = this.requireClient();
    this.set({ phase: "offering" });
    try {
      const offer = await client.create_offer();
      try {
        this.set({ localFingerprint: toHex(client.local_dtls_fingerprint()) });
      } catch {
        // Fingerprint not parseable yet on some SDP shapes — non-fatal for the UI.
      }
      return offer;
    } catch (e) {
      // On reject, surface the failure instead of leaving the UI stuck at "offering".
      this.set({ phase: "failed", error: errMsg(e) });
      throw e;
    }
  }

  /**
   * Negotiate the session codec against the host's advertised capabilities.
   *
   * Returns the capability ANSWER bytes (H.264 selected) and updates the UI's codec field.
   * Throws if the host advertises no H.264 path (surfaced to the UI as an error).
   */
  negotiateCodec(hostCapsBytes: Uint8Array): Uint8Array {
    const bridge = this.requireBridge();
    try {
      const sel = selectCodec(bridge, hostCapsBytes);
      this.set({ codec: codecName(sel.codec) });
      return sel.answerBytes;
    } catch (e) {
      this.set({ error: errMsg(e) });
      throw e;
    }
  }

  /** The browser's codec-capability offer bytes (advertises H.264 decode, is_browser). */
  buildOfferCaps(): Uint8Array {
    return buildBrowserOffer(this.requireBridge());
  }

  /** Pin the peer's DTLS fingerprint (32 bytes from the verified Noise handshake). */
  setDtlsPin(pin: Uint8Array): void {
    this.requireClient().set_dtls_pin(pin);
  }

  /** Apply the remote SDP answer (pin-checked inside the wasm client). */
  async connectAsOfferer(remoteSdpAnswer: string): Promise<void> {
    this.set({ phase: "connecting" });
    await this.requireClient().connect_as_offerer(remoteSdpAnswer);
    this.refreshIce();
  }

  /**
   * Register a callback for inbound SHP frames on the DataChannel.
   *
   * The wasm `WebClient.on_frame` REPLACES the channel's `onmessage` handler (it does not append),
   * so calling it twice would not double-fire — but it would leak the previous callback's closure
   * (it is `forget()`-ed in wasm). We guard so a session registers at most one frame handler;
   * repeated calls are ignored. (`dispose()` resets the guard for a fresh session.)
   */
  onFrame(cb: (frame: Uint8Array) => void): void {
    if (this.frameHandlerRegistered) return;
    this.requireClient().on_frame(cb);
    this.frameHandlerRegistered = true;
  }

  /** Send an SHP frame over the DataChannel. */
  sendFrame(bytes: Uint8Array): void {
    this.requireClient().send_frame(bytes);
  }

  /** Poll the underlying ICE connection state into the UI. */
  refreshIce(): void {
    if (this.client === null) return;
    const ice = this.client.ice_connection_state();
    const phase = iceStateToPhase(ice, this.state.phase);
    this.set({ iceState: ice, phase });
  }

  /** The underlying WebClient (for the demo/e2e to attach loopback wiring). */
  get webClient(): WebClient | null {
    return this.client;
  }

  /**
   * Tear down the session: close the underlying `WebClient` (which closes its `RTCPeerConnection`
   * and DataChannel, releasing ICE/DTLS resources) and reset state to `closed`. Idempotent.
   *
   * Without this, disconnecting would leak the peer connection (the OS keeps the ICE sockets and
   * the DTLS session alive). After `dispose()`, `init()` can construct a fresh client.
   */
  dispose(): void {
    if (this.client !== null) {
      try {
        this.client.close();
      } catch {
        // Already closed / errored — ignore; teardown must not throw.
      }
    }
    this.client = null;
    this.frameHandlerRegistered = false;
    this.set({ phase: "closed", iceState: "closed", localFingerprint: null });
  }

  private requireClient(): WebClient {
    if (this.client === null) throw new Error("session not initialized (call init())");
    return this.client;
  }
  private requireBridge(): ShBridge {
    if (this.bridge === null) throw new Error("session not initialized (call init())");
    return this.bridge;
  }
}

function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  return String(e);
}
