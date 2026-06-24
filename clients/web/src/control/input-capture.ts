// CONTROL: capture DOM mouse/keyboard/wheel on the canvas, map to SHP, send to the host.
//
// This wires real DOM events to the pure mapping in `protocol/input-map`, encodes each mapped
// event to its 16-byte SHP wire form via the wasm bridge (`encode_input_event`), and hands the
// bytes to a sink (the DataChannel `send_frame`). The mapping/encoding seam is unit-tested in
// node; this module is the thin DOM-attachment layer.

import {
  fieldsInBounds,
  mapButton,
  mapKey,
  mapPointerMove,
  mapWheel,
  type InputEventFields,
} from "../protocol/input-map.js";
import type { ShBridge } from "../bridge/types.js";

/** A sink for encoded SHP input bytes (e.g. `WebClient.send_frame`). */
export type FrameSink = (bytes: Uint8Array) => void;

/** Read the Caps-Lock modifier state defensively (not all events expose it). */
function capsLockOf(ev: KeyboardEvent | MouseEvent): boolean {
  try {
    return ev.getModifierState("CapsLock");
  } catch {
    return false;
  }
}

/** Build the modifier-bearing shape the pure mapper expects from a DOM UI event. */
function modsOf(ev: MouseEvent | KeyboardEvent): {
  shiftKey: boolean;
  ctrlKey: boolean;
  altKey: boolean;
  metaKey: boolean;
  capsLock: boolean;
} {
  return {
    shiftKey: ev.shiftKey,
    ctrlKey: ev.ctrlKey,
    altKey: ev.altKey,
    metaKey: ev.metaKey,
    capsLock: capsLockOf(ev),
  };
}

/**
 * Encode mapped SHP fields and push them to the sink.
 *
 * Returns the encoded bytes (for tests/observability) or `null` if the fields were out of
 * wire bounds or encoding failed (never throws out).
 */
export function encodeAndSend(
  bridge: ShBridge,
  sink: FrameSink,
  f: InputEventFields,
): Uint8Array | null {
  if (!fieldsInBounds(f)) {
    return null;
  }
  try {
    const bytes = bridge.encode_input_event(
      f.eventType,
      f.modifiers,
      f.pointerX,
      f.pointerY,
      f.buttonMask,
      f.keyCode,
      f.scrollX,
      f.scrollY,
      f.pressure,
    );
    sink(bytes);
    return bytes;
  } catch {
    return null;
  }
}

/** Options controlling capture behavior. */
export interface CaptureOptions {
  /** Capture keyboard events too (requires the canvas to be focusable / focused). */
  readonly captureKeyboard?: boolean;
}

/**
 * Attach SHP input capture to a canvas. Returns a disposer that removes all listeners.
 *
 * Mouse move/down/up/wheel are always captured; keyboard capture is opt-in (it requires the
 * canvas to hold focus). `contextmenu` is suppressed so a right-click maps to a host button
 * event rather than opening the browser menu.
 */
export function attachInputCapture(
  canvas: HTMLCanvasElement,
  bridge: ShBridge,
  sink: FrameSink,
  options: CaptureOptions = {},
): () => void {
  const rect = (): DOMRect => canvas.getBoundingClientRect();

  const onMove = (ev: MouseEvent): void => {
    encodeAndSend(bridge, sink, mapPointerMove({ ...modsOf(ev), clientX: ev.clientX, clientY: ev.clientY }, rect()));
  };
  const onDown = (ev: MouseEvent): void => {
    encodeAndSend(
      bridge,
      sink,
      mapButton(
        { ...modsOf(ev), clientX: ev.clientX, clientY: ev.clientY, buttons: ev.buttons },
        ev.button,
        true,
        rect(),
      ),
    );
  };
  const onUp = (ev: MouseEvent): void => {
    encodeAndSend(
      bridge,
      sink,
      mapButton(
        { ...modsOf(ev), clientX: ev.clientX, clientY: ev.clientY, buttons: ev.buttons },
        ev.button,
        false,
        rect(),
      ),
    );
  };
  const onWheel = (ev: WheelEvent): void => {
    ev.preventDefault();
    encodeAndSend(
      bridge,
      sink,
      mapWheel(
        { ...modsOf(ev), clientX: ev.clientX, clientY: ev.clientY, deltaX: ev.deltaX, deltaY: ev.deltaY },
        rect(),
      ),
    );
  };
  const onContextMenu = (ev: MouseEvent): void => ev.preventDefault();
  const onKeyDown = (ev: KeyboardEvent): void => {
    ev.preventDefault();
    encodeAndSend(bridge, sink, mapKey({ ...modsOf(ev), code: ev.code }, true));
  };
  const onKeyUp = (ev: KeyboardEvent): void => {
    ev.preventDefault();
    encodeAndSend(bridge, sink, mapKey({ ...modsOf(ev), code: ev.code }, false));
  };

  canvas.addEventListener("mousemove", onMove);
  canvas.addEventListener("mousedown", onDown);
  canvas.addEventListener("mouseup", onUp);
  canvas.addEventListener("wheel", onWheel, { passive: false });
  canvas.addEventListener("contextmenu", onContextMenu);
  if (options.captureKeyboard === true) {
    canvas.addEventListener("keydown", onKeyDown);
    canvas.addEventListener("keyup", onKeyUp);
  }

  return (): void => {
    canvas.removeEventListener("mousemove", onMove);
    canvas.removeEventListener("mousedown", onDown);
    canvas.removeEventListener("mouseup", onUp);
    canvas.removeEventListener("wheel", onWheel);
    canvas.removeEventListener("contextmenu", onContextMenu);
    canvas.removeEventListener("keydown", onKeyDown);
    canvas.removeEventListener("keyup", onKeyUp);
  };
}
