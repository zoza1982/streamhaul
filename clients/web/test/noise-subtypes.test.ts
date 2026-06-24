// Pins the browser-side Noise-over-signaling sub-type wire values (ADR-0023).
//
// These are a cross-language wire contract with the native host
// (`bins/streamhaul-webrtc-host/src/main.rs`, asserted there by
// `noise_sub_type_wire_values_are_pinned`). This test guards the TS half: a change to
// `e2e/noise-subtypes.ts` (the single source the driver imports) breaks here, and the matching
// change must be mirrored in the Rust constants (whose test breaks if THEY drift). Together the
// two tests prevent the browser and native implementations from silently desyncing.

import { describe, it, expect } from "vitest";
import {
  NOISE_SUB_HELLO,
  NOISE_SUB_HOST_STATIC_PUB,
  NOISE_SUB_MSG,
} from "../e2e/noise-subtypes.js";

describe("Noise-over-signaling sub-type wire values (cross-language contract with the host)", () => {
  it("pins the exact discriminant bytes", () => {
    expect(NOISE_SUB_HELLO).toBe(0x00);
    expect(NOISE_SUB_HOST_STATIC_PUB).toBe(0x01);
    expect(NOISE_SUB_MSG).toBe(0x02);
  });

  it("keeps the three discriminants distinct", () => {
    const values = [NOISE_SUB_HELLO, NOISE_SUB_HOST_STATIC_PUB, NOISE_SUB_MSG];
    expect(new Set(values).size).toBe(values.length);
  });
});
