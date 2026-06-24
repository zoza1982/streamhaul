// DOM input event -> SHP input-event argument mapping (pure logic).
//
// This module decides *which SHP fields* a DOM mouse/keyboard/wheel event maps to. It does
// NOT serialize anything itself — the 9 fields it produces are handed verbatim to the wasm
// `encode_input_event`, which owns the wire encoding (16-byte SHP InputEvent). Keeping the
// mapping pure (plain-object inputs, plain-object output) makes it node-unit-testable
// without a DOM, and the encode step is proven byte-exact by `sh-wasm`'s golden tests.

import { EventType, Modifiers, buttonBit, domButtonsToShpMask, POINTER_MAX } from "./constants.js";
import { clientToNormalized, type Rect } from "./coords.js";
import { keyCodeToHidUsage } from "./keymap.js";

/** The exact, ordered argument tuple consumed by `encode_input_event`. */
export interface InputEventFields {
  readonly eventType: number;
  readonly modifiers: number;
  readonly pointerX: number;
  readonly pointerY: number;
  readonly buttonMask: number;
  readonly keyCode: number;
  readonly scrollX: number;
  readonly scrollY: number;
  readonly pressure: number;
}

/** Modifier-bearing fields common to all DOM UI events. */
export interface ModifierState {
  readonly shiftKey: boolean;
  readonly ctrlKey: boolean;
  readonly altKey: boolean;
  readonly metaKey: boolean;
  /** Optional Caps-Lock state (`getModifierState('CapsLock')`); absent ⇒ unset. */
  readonly capsLock?: boolean;
}

/** Plain shape of the mouse fields we read (subset of DOM `MouseEvent`). */
export interface MouseLike extends ModifierState {
  readonly clientX: number;
  readonly clientY: number;
  /**
   * DOM `MouseEvent.buttons` — the bitmask of buttons held *after* this event. Optional so
   * pointer-move/wheel callers (which don't need it) can omit it; `mapButton` uses it to build
   * the SHP held-button STATE mask so other still-held buttons survive a single release.
   */
  readonly buttons?: number;
}

/** Plain shape of the wheel fields we read (subset of DOM `WheelEvent`). */
export interface WheelLike extends MouseLike {
  readonly deltaX: number;
  readonly deltaY: number;
}

/** Plain shape of the keyboard fields we read (subset of DOM `KeyboardEvent`). */
export interface KeyLike extends ModifierState {
  /** The DOM `KeyboardEvent.code` (physical key, e.g. `"KeyA"`, `"Enter"`). */
  readonly code: string;
}

/** Build the SHP modifier bitmask from a DOM event's modifier flags. */
export function modifierMask(s: ModifierState): number {
  let m = 0;
  if (s.shiftKey) m |= Modifiers.Shift;
  if (s.ctrlKey) m |= Modifiers.Ctrl;
  if (s.altKey) m |= Modifiers.Alt;
  if (s.metaKey) m |= Modifiers.Meta;
  if (s.capsLock === true) m |= Modifiers.Caps;
  return m;
}

const ZERO_FIELDS = {
  buttonMask: 0,
  keyCode: 0,
  scrollX: 0,
  scrollY: 0,
  pressure: 0,
} as const;

/** Map a pointer-move (mouse move) to SHP `PointerMove` fields. */
export function mapPointerMove(ev: MouseLike, rect: Rect): InputEventFields {
  const p = clientToNormalized(ev.clientX, ev.clientY, rect);
  return {
    eventType: EventType.PointerMove,
    modifiers: modifierMask(ev),
    pointerX: p.x,
    pointerY: p.y,
    ...ZERO_FIELDS,
  };
}

/**
 * Map a mouse button down/up to SHP `Button` fields.
 *
 * SHP `button_mask` is a STATE bitmask of currently-held buttons (`sh_protocol::InputEvent`),
 * NOT a per-event delta. So the mask must reflect ALL buttons still held after this event, not
 * just the one that changed — otherwise a release while another button is held would tell the
 * host "all buttons up" and break drags / chorded clicks.
 *
 * We derive the held set from the DOM `ev.buttons` bitmask (the authoritative post-event state),
 * remapped to SHP bit positions, and then explicitly apply the changed button's bit
 * (set on press, clear on release) so the result is correct even if a browser reports `buttons`
 * inconsistently on the transition event.
 */
export function mapButton(
  ev: MouseLike,
  domButton: number,
  pressed: boolean,
  rect: Rect,
): InputEventFields {
  const p = clientToNormalized(ev.clientX, ev.clientY, rect);
  const bit = buttonBit(domButton);
  const heldFromDom = domButtonsToShpMask(ev.buttons ?? 0);
  const buttonMask = pressed ? heldFromDom | bit : heldFromDom & ~bit;
  return {
    eventType: EventType.Button,
    modifiers: modifierMask(ev),
    pointerX: p.x,
    pointerY: p.y,
    buttonMask: buttonMask & 0xff,
    keyCode: 0,
    scrollX: 0,
    scrollY: 0,
    pressure: 0,
  };
}

/** Saturate a scroll delta (px) to the SHP px×8 signed-16 fixed-point field. */
function scrollFixed(deltaPx: number): number {
  if (!Number.isFinite(deltaPx)) {
    return 0;
  }
  const fixed = Math.round(deltaPx * 8);
  if (fixed > 32767) return 32767;
  if (fixed < -32768) return -32768;
  return fixed;
}

/** Map a wheel event to SHP `Wheel` fields (deltas in px×8 fixed-point). */
export function mapWheel(ev: WheelLike, rect: Rect): InputEventFields {
  const p = clientToNormalized(ev.clientX, ev.clientY, rect);
  return {
    eventType: EventType.Wheel,
    modifiers: modifierMask(ev),
    pointerX: p.x,
    pointerY: p.y,
    buttonMask: 0,
    keyCode: 0,
    scrollX: scrollFixed(ev.deltaX),
    scrollY: scrollFixed(ev.deltaY),
    pressure: 0,
  };
}

/**
 * Map a key down/up to SHP `Key` fields.
 *
 * `button_mask` bit 0 carries the press/release state (1=down, 0=up); `key_code` is the USB
 * HID usage ID derived from the DOM `code`. An unmapped `code` yields `keyCode = 0` (the
 * host treats 0 as "no key").
 */
export function mapKey(ev: KeyLike, pressed: boolean): InputEventFields {
  return {
    eventType: EventType.Key,
    modifiers: modifierMask(ev),
    pointerX: 0,
    pointerY: 0,
    buttonMask: pressed ? 1 : 0,
    keyCode: keyCodeToHidUsage(ev.code),
    scrollX: 0,
    scrollY: 0,
    pressure: 0,
  };
}

/** Validate that mapped fields are within SHP wire bounds (defensive pre-encode check). */
export function fieldsInBounds(f: InputEventFields): boolean {
  return (
    f.pointerX >= 0 &&
    f.pointerX <= POINTER_MAX &&
    f.pointerY >= 0 &&
    f.pointerY <= POINTER_MAX &&
    f.scrollX >= -32768 &&
    f.scrollX <= 32767 &&
    f.scrollY >= -32768 &&
    f.scrollY <= 32767
  );
}
