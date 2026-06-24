import { describe, it, expect } from "vitest";

import { keyCodeToHidUsage } from "../src/protocol/keymap.js";

describe("keyCodeToHidUsage (USB HID Keyboard/Keypad page)", () => {
  it("maps letters and digits", () => {
    expect(keyCodeToHidUsage("KeyA")).toBe(0x04);
    expect(keyCodeToHidUsage("KeyZ")).toBe(0x1d);
    expect(keyCodeToHidUsage("Digit1")).toBe(0x1e);
    expect(keyCodeToHidUsage("Digit0")).toBe(0x27);
  });

  it("maps the function row (F1–F12)", () => {
    expect(keyCodeToHidUsage("F1")).toBe(0x3a);
    expect(keyCodeToHidUsage("F5")).toBe(0x3e);
    expect(keyCodeToHidUsage("F12")).toBe(0x45);
  });

  it("maps the navigation/editing cluster", () => {
    expect(keyCodeToHidUsage("Insert")).toBe(0x49);
    expect(keyCodeToHidUsage("Home")).toBe(0x4a);
    expect(keyCodeToHidUsage("PageUp")).toBe(0x4b);
    expect(keyCodeToHidUsage("Delete")).toBe(0x4c);
    expect(keyCodeToHidUsage("End")).toBe(0x4d);
    expect(keyCodeToHidUsage("PageDown")).toBe(0x4e);
  });

  it("maps the numpad block", () => {
    expect(keyCodeToHidUsage("NumpadDivide")).toBe(0x54);
    expect(keyCodeToHidUsage("NumpadEnter")).toBe(0x58);
    expect(keyCodeToHidUsage("Numpad1")).toBe(0x59);
    expect(keyCodeToHidUsage("Numpad0")).toBe(0x62);
    expect(keyCodeToHidUsage("NumpadDecimal")).toBe(0x63);
    expect(keyCodeToHidUsage("NumpadAdd")).toBe(0x57);
    expect(keyCodeToHidUsage("NumpadSubtract")).toBe(0x56);
    expect(keyCodeToHidUsage("NumpadMultiply")).toBe(0x55);
  });

  it("maps arrows and modifiers", () => {
    expect(keyCodeToHidUsage("ArrowUp")).toBe(0x52);
    expect(keyCodeToHidUsage("ControlLeft")).toBe(0xe0);
    expect(keyCodeToHidUsage("MetaRight")).toBe(0xe7);
  });

  it("returns 0 (no-key sentinel) for an unmapped physical key", () => {
    expect(keyCodeToHidUsage("F13")).toBe(0);
    expect(keyCodeToHidUsage("Unidentified")).toBe(0);
    expect(keyCodeToHidUsage("")).toBe(0);
  });
});
