import { describe, it, expect } from "vitest";

import { iceStateToPhase, toHex } from "../src/client/state.js";

describe("toHex", () => {
  it("encodes bytes as lowercase hex in order (correct nibble order)", () => {
    expect(toHex(new Uint8Array([0x00, 0x0f, 0xa0, 0xff]))).toBe("000fa0ff");
    expect(toHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe("deadbeef");
  });
  it("returns empty string for empty input", () => {
    expect(toHex(new Uint8Array(0))).toBe("");
  });
});

describe("iceStateToPhase", () => {
  it("maps connected/completed to connected", () => {
    expect(iceStateToPhase("connected", "connecting")).toBe("connected");
    expect(iceStateToPhase("completed", "connecting")).toBe("connected");
  });
  it("maps failed and closed through", () => {
    expect(iceStateToPhase("failed", "connected")).toBe("failed");
    expect(iceStateToPhase("closed", "connected")).toBe("closed");
  });
  it("leaves the phase unchanged for transient/unknown states", () => {
    expect(iceStateToPhase("new", "offering")).toBe("offering");
    expect(iceStateToPhase("checking", "connecting")).toBe("connecting");
    expect(iceStateToPhase("disconnected", "connected")).toBe("connected");
    expect(iceStateToPhase("unknown", "idle")).toBe("idle");
  });
});
