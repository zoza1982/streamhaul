// Independently compute the exact SHP wire bytes for the e2e's center-click, so the e2e
// assertion is NON-VACUOUS: it compares the bytes the host actually received against a
// separately-derived expectation. A broken coordinate map, button map, or wire encode would
// change these bytes and fail the test.
//
// The click is a left-button mousedown at the exact center of the 16x16 loopback canvas. We
// reuse the SAME pure mapping (`mapButton`) and the SAME Rust codec (`encode_input_event` via
// the node bridge) the app uses, but assemble them here independently of the running page.

import { loadCodecBridge } from "../test/helpers/bridge-node.js";
import { mapButton } from "../src/protocol/input-map.js";
import type { Rect } from "../src/protocol/coords.js";

/** The 16x16 loopback canvas at the page origin (its absolute position is irrelevant to the
 * normalized mapping, which is bounding-box-relative — we model it at (0,0)). */
const CANVAS_RECT: Rect = { left: 0, top: 0, width: 16, height: 16 };

function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/** Hex of the exact SHP InputEvent bytes for a left mousedown at the canvas center. */
export function encodeExpectedClickBytes(): string {
  const bridge = loadCodecBridge();
  // Center of a 16x16 box: clientX/Y = 8 (relative to a (0,0) box).
  const fields = mapButton(
    { clientX: 8, clientY: 8, shiftKey: false, ctrlKey: false, altKey: false, metaKey: false },
    0, // DOM left button
    true, // pressed
    CANVAS_RECT,
  );
  const bytes = bridge.encode_input_event(
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
  return toHex(bytes);
}
