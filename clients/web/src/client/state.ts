// Pure session-state helpers (no wasm/DOM), so they are unit-testable in Node.

/** Observable connection phase for the UI. */
export type ConnectionPhase =
  | "idle"
  | "initializing"
  | "offering"
  | "connecting"
  | "connected"
  | "failed"
  | "closed";

const HEX = "0123456789abcdef";

/** Lowercase hex of a byte array (used to surface the local DTLS fingerprint in the UI). */
export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) {
    s += HEX[(b >> 4) & 0xf];
    s += HEX[b & 0xf];
  }
  return s;
}

/**
 * Map a WebRTC `RTCIceConnectionState` string to the UI connection phase.
 *
 * `connected`/`completed` → `connected`; `failed`/`closed` map through; any other state
 * (`new`/`checking`/`disconnected`/`unknown`) leaves the phase unchanged (`prev`).
 */
export function iceStateToPhase(iceState: string, prev: ConnectionPhase): ConnectionPhase {
  switch (iceState) {
    case "connected":
    case "completed":
      return "connected";
    case "failed":
      return "failed";
    case "closed":
      return "closed";
    default:
      return prev;
  }
}
