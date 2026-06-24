import { describe, it, expect } from "vitest";

import { clientToNormalized, type Rect } from "../src/protocol/coords.js";
import { POINTER_MAX } from "../src/protocol/constants.js";

describe("clientToNormalized", () => {
  const rect: Rect = { left: 100, top: 50, width: 800, height: 600 };

  it("maps the top-left corner to (0,0)", () => {
    expect(clientToNormalized(100, 50, rect)).toEqual({ x: 0, y: 0 });
  });

  it("maps the bottom-right corner to (65535, 65535)", () => {
    expect(clientToNormalized(900, 650, rect)).toEqual({ x: POINTER_MAX, y: POINTER_MAX });
  });

  it("maps the center to (~32768, ~32768)", () => {
    const c = clientToNormalized(500, 350, rect);
    expect(c.x).toBe(0x8000);
    expect(c.y).toBe(0x8000);
  });

  it("clamps points outside the canvas into range", () => {
    expect(clientToNormalized(0, 0, rect)).toEqual({ x: 0, y: 0 });
    expect(clientToNormalized(99999, 99999, rect)).toEqual({ x: POINTER_MAX, y: POINTER_MAX });
  });

  it("returns (0,0) for a zero-size rect rather than dividing by zero", () => {
    const z: Rect = { left: 0, top: 0, width: 0, height: 0 };
    expect(clientToNormalized(10, 10, z)).toEqual({ x: 0, y: 0 });
  });
});
