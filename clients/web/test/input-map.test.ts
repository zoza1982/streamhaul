import { describe, it, expect } from "vitest";

import { loadCodecBridge } from "./helpers/bridge-node.js";
import {
  mapButton,
  mapKey,
  mapPointerMove,
  mapWheel,
  modifierMask,
} from "../src/protocol/input-map.js";
import { EventType, Modifiers } from "../src/protocol/constants.js";
import type { Rect } from "../src/protocol/coords.js";

// A 1000×500 canvas at the page origin: client (500,250) is the exact center → 0x8000 each axis.
const RECT: Rect = { left: 0, top: 0, width: 1000, height: 500 };

function encode(fields: ReturnType<typeof mapPointerMove>): Uint8Array {
  const b = loadCodecBridge();
  return b.encode_input_event(
    fields.eventType,
    fields.modifiers,
    fields.pointerX,
    fields.pointerY,
    fields.buttonMask,
    fields.keyCode,
    fields.scrollX,
    fields.scrollY,
    fields.pressure,
  );
}

describe("modifierMask", () => {
  it("combines Ctrl+Shift into the SHP modifier byte", () => {
    const m = modifierMask({ shiftKey: true, ctrlKey: true, altKey: false, metaKey: false });
    expect(m).toBe(Modifiers.Shift | Modifiers.Ctrl);
  });
  it("sets Caps only when capsLock is true", () => {
    expect(modifierMask({ shiftKey: false, ctrlKey: false, altKey: false, metaKey: false, capsLock: true })).toBe(
      Modifiers.Caps,
    );
    expect(modifierMask({ shiftKey: false, ctrlKey: false, altKey: false, metaKey: false })).toBe(0);
  });
});

describe("mapKey → encode_input_event (exact bytes)", () => {
  it("reproduces the sh-wasm Key golden vector for KeyA with Ctrl+Shift", () => {
    // This mirrors sh-wasm's INPUT_GOLDEN intent: Key 'a' (HID 0x04), CTRL|SHIFT.
    const fields = mapKey(
      { code: "KeyA", shiftKey: true, ctrlKey: true, altKey: false, metaKey: false },
      true,
    );
    expect(fields.eventType).toBe(EventType.Key);
    expect(fields.keyCode).toBe(0x04);
    expect(fields.modifiers).toBe(0b0000_0011);
    expect(fields.buttonMask).toBe(1); // pressed

    const bytes = encode(fields);
    expect(bytes.length).toBe(16);
    // byte0 = EventType::Key (3); byte1 = CTRL|SHIFT; key_code 0x0004 at bytes 7..9.
    expect(bytes[0]).toBe(3);
    expect(bytes[1]).toBe(0b0000_0011);
    expect(bytes[7]).toBe(0x00);
    expect(bytes[8]).toBe(0x04);
    // button_mask carries press state in bit 0 (byte 6).
    expect(bytes[6]).toBe(1);
  });

  it("key release clears the press bit", () => {
    const up = mapKey({ code: "KeyA", shiftKey: false, ctrlKey: false, altKey: false, metaKey: false }, false);
    expect(up.buttonMask).toBe(0);
    const bytes = encode(up);
    expect(bytes[6]).toBe(0);
  });

  it("unmapped physical key yields key_code 0", () => {
    const f = mapKey({ code: "F13", shiftKey: false, ctrlKey: false, altKey: false, metaKey: false }, true);
    expect(f.keyCode).toBe(0);
  });
});

describe("mapPointerMove → encode_input_event (exact bytes + coords)", () => {
  it("maps canvas center to (0x8000, 0x8000)", () => {
    const f = mapPointerMove(
      { clientX: 500, clientY: 250, shiftKey: false, ctrlKey: false, altKey: false, metaKey: false },
      RECT,
    );
    expect(f.eventType).toBe(EventType.PointerMove);
    expect(f.pointerX).toBe(0x8000);
    expect(f.pointerY).toBe(0x8000);

    const bytes = encode(f);
    expect(bytes[0]).toBe(0); // PointerMove
    // pointer_x big-endian at bytes 2..4, pointer_y at 4..6.
    expect(bytes[2]).toBe(0x80);
    expect(bytes[3]).toBe(0x00);
    expect(bytes[4]).toBe(0x80);
    expect(bytes[5]).toBe(0x00);
  });

  it("clamps out-of-bounds coordinates into 0..=65535", () => {
    const f = mapPointerMove(
      { clientX: 5000, clientY: -100, shiftKey: false, ctrlKey: false, altKey: false, metaKey: false },
      RECT,
    );
    expect(f.pointerX).toBe(0xffff);
    expect(f.pointerY).toBe(0);
  });
});

describe("mapButton → encode_input_event", () => {
  it("left button down sets bit 0; up clears the mask", () => {
    const down = mapButton(
      { clientX: 0, clientY: 0, shiftKey: false, ctrlKey: false, altKey: false, metaKey: false },
      0,
      true,
      RECT,
    );
    expect(down.eventType).toBe(EventType.Button);
    expect(down.buttonMask).toBe(1 << 0);
    const up = mapButton(
      { clientX: 0, clientY: 0, shiftKey: false, ctrlKey: false, altKey: false, metaKey: false },
      0,
      false,
      RECT,
    );
    expect(up.buttonMask).toBe(0);
  });

  it("right button maps to bit 1", () => {
    const f = mapButton(
      { clientX: 0, clientY: 0, shiftKey: false, ctrlKey: false, altKey: false, metaKey: false },
      2,
      true,
      RECT,
    );
    expect(f.buttonMask).toBe(1 << 1);
  });

  it("preserves other held buttons in the STATE mask across a release (drag/chord)", () => {
    const mods = { shiftKey: false, ctrlKey: false, altKey: false, metaKey: false };
    // 1) Left down: DOM buttons=1 (left held after the event). Mask = left bit.
    const leftDown = mapButton({ ...mods, clientX: 0, clientY: 0, buttons: 1 }, 0, true, RECT);
    expect(leftDown.buttonMask).toBe(1 << 0);

    // 2) Right down WHILE left is held: DOM buttons=3 (left|right). Mask = left|right.
    const rightDown = mapButton({ ...mods, clientX: 0, clientY: 0, buttons: 3 }, 2, true, RECT);
    expect(rightDown.buttonMask).toBe((1 << 0) | (1 << 1));

    // 3) Right UP while left STILL held: DOM buttons=1 (only left remains). The release must NOT
    //    clear left — the STATE mask must still report left held.
    const rightUp = mapButton({ ...mods, clientX: 0, clientY: 0, buttons: 1 }, 2, false, RECT);
    expect(rightUp.buttonMask).toBe(1 << 0);
    expect(rightUp.buttonMask & (1 << 1)).toBe(0); // right cleared
    expect(rightUp.buttonMask & (1 << 0)).not.toBe(0); // left preserved

    // 4) Left UP last: DOM buttons=0. Mask empty.
    const leftUp = mapButton({ ...mods, clientX: 0, clientY: 0, buttons: 0 }, 0, false, RECT);
    expect(leftUp.buttonMask).toBe(0);
  });

  it("explicitly applies the changed bit even if DOM buttons is inconsistent on the transition", () => {
    const mods = { shiftKey: false, ctrlKey: false, altKey: false, metaKey: false };
    // A down event where DOM buttons does not yet include the new button: the bit is still set.
    const down = mapButton({ ...mods, clientX: 0, clientY: 0, buttons: 0 }, 0, true, RECT);
    expect(down.buttonMask & (1 << 0)).not.toBe(0);
    // An up event where DOM buttons still includes the button: the bit is still cleared.
    const up = mapButton({ ...mods, clientX: 0, clientY: 0, buttons: 1 }, 0, false, RECT);
    expect(up.buttonMask & (1 << 0)).toBe(0);
  });
});

describe("mapWheel → encode_input_event (px×8 fixed-point, signed)", () => {
  it("encodes signed scroll deltas as px×8", () => {
    const f = mapWheel(
      {
        clientX: 0,
        clientY: 0,
        deltaX: -3,
        deltaY: 5,
        shiftKey: false,
        ctrlKey: false,
        altKey: false,
        metaKey: false,
      },
      RECT,
    );
    expect(f.eventType).toBe(EventType.Wheel);
    expect(f.scrollX).toBe(-24); // -3 * 8
    expect(f.scrollY).toBe(40); // 5 * 8

    const bytes = encode(f);
    // scroll_x (i16 big-endian) at bytes 9..11: -24 = 0xFFE8.
    expect(bytes[9]).toBe(0xff);
    expect(bytes[10]).toBe(0xe8);
    // scroll_y at bytes 11..13: 40 = 0x0028.
    expect(bytes[11]).toBe(0x00);
    expect(bytes[12]).toBe(0x28);
  });

  it("saturates huge deltas to the i16 bounds", () => {
    const f = mapWheel(
      {
        clientX: 0,
        clientY: 0,
        deltaX: 1e9,
        deltaY: -1e9,
        shiftKey: false,
        ctrlKey: false,
        altKey: false,
        metaKey: false,
      },
      RECT,
    );
    expect(f.scrollX).toBe(32767);
    expect(f.scrollY).toBe(-32768);
  });
});
