import { describe, it, expect, vi, beforeEach } from "vitest";

import type { ShBridge, WebClient } from "../src/bridge/types.js";

// Mock the wasm bridge loader so Session can be unit-tested in Node without wasm/DOM. The mock
// records WebClient construction + close() calls to verify the init-guard (no double-construct)
// and dispose() (client closed) behaviors.

let constructCount = 0;
let closeCount = 0;
let createOfferImpl: () => Promise<string> = () => Promise.resolve("v=0\r\n");

class FakeWebClient {
  constructor() {
    constructCount += 1;
  }
  set_dtls_pin(): void {}
  create_offer(): Promise<string> {
    return createOfferImpl();
  }
  connect_as_offerer(): Promise<void> {
    return Promise.resolve();
  }
  connect_as_answerer(): Promise<string> {
    return Promise.resolve("");
  }
  add_ice_candidate(): Promise<void> {
    return Promise.resolve();
  }
  local_dtls_fingerprint(): Uint8Array {
    return new Uint8Array([0xab, 0xcd]);
  }
  send_frame(): void {}
  on_frame(): void {}
  on_data_channel(): void {}
  on_ice_candidate(): void {}
  ice_connection_state(): string {
    return "new";
  }
  close(): void {
    closeCount += 1;
  }
}

const fakeBridge = {
  SignalingChannel: class {
    constructor(_fn: (p: string) => void) {}
  },
  WebClient: FakeWebClient as unknown as ShBridge["WebClient"],
} as unknown as ShBridge;

vi.mock("../src/bridge/index.js", () => ({
  loadBridge: () => Promise.resolve(fakeBridge),
}));

// Import AFTER the mock is registered.
const { Session } = await import("../src/client/session.js");

beforeEach(() => {
  constructCount = 0;
  closeCount = 0;
  createOfferImpl = () => Promise.resolve("v=0\r\n");
});

describe("Session lifecycle", () => {
  it("init() is idempotent — concurrent/repeated calls construct at most one WebClient", async () => {
    const s = new Session();
    await Promise.all([s.init(), s.init(), s.init()]);
    await s.init();
    expect(constructCount).toBe(1);
  });

  it("dispose() closes the WebClient and resets to closed", async () => {
    const s = new Session();
    await s.init();
    s.dispose();
    expect(closeCount).toBe(1);
    expect(s.current.phase).toBe("closed");
    expect(s.current.iceState).toBe("closed");
    // After dispose, a fresh init() constructs a new client.
    await s.init();
    expect(constructCount).toBe(2);
  });

  it("dispose() is idempotent (no throw, no double close)", async () => {
    const s = new Session();
    await s.init();
    s.dispose();
    expect(() => s.dispose()).not.toThrow();
    expect(closeCount).toBe(1);
  });

  it("createOffer() sets phase=failed and rethrows when create_offer rejects", async () => {
    const s = new Session();
    await s.init();
    createOfferImpl = () => Promise.reject(new Error("createOffer boom"));
    await expect(s.createOffer()).rejects.toThrow("createOffer boom");
    expect(s.current.phase).toBe("failed");
    expect(s.current.error).toContain("createOffer boom");
  });

  it("onFrame registers at most once per session (guarded)", async () => {
    const s = new Session();
    await s.init();
    const client = s.webClient as unknown as WebClient;
    const spy = vi.spyOn(client, "on_frame");
    s.onFrame(() => {});
    s.onFrame(() => {});
    s.onFrame(() => {});
    expect(spy).toHaveBeenCalledTimes(1);
  });
});
