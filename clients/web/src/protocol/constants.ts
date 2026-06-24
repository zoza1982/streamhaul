// SHP wire constants mirrored for the browser side.
//
// These values are the canonical SHP discriminants defined in `sh-protocol` (the Rust
// source of truth) and asserted byte-for-byte by `sh-wasm`'s golden-vector tests. They are
// duplicated here only as named constants for readable call sites; the *encoding* itself is
// always performed by the wasm bridge (`encode_input_event` / `encode_caps`), never in TS.

/** SHP input event-type discriminants (`sh_protocol::EventType`). */
export const EventType = {
  PointerMove: 0,
  Button: 1,
  Wheel: 2,
  Key: 3,
  Touch: 4,
  Pen: 5,
} as const;
export type EventType = (typeof EventType)[keyof typeof EventType];

/** SHP modifier bitmask (`sh_protocol::Modifiers`). */
export const Modifiers = {
  Shift: 1 << 0,
  Ctrl: 1 << 1,
  Alt: 1 << 2,
  Meta: 1 << 3,
  Caps: 1 << 4,
} as const;

/** SHP codec discriminants (`sh_protocol::Codec`). */
export const Codec = {
  H264: 0,
  H265: 1,
  AV1: 2,
  Raw: 3,
} as const;
export type Codec = (typeof Codec)[keyof typeof Codec];

/** Human-readable codec name for the UI. */
export function codecName(discriminant: number): string {
  switch (discriminant) {
    case Codec.H264:
      return "H.264";
    case Codec.H265:
      return "H.265";
    case Codec.AV1:
      return "AV1";
    case Codec.Raw:
      return "Raw";
    default:
      return `unknown(${discriminant})`;
  }
}

/** `selected_codec` sentinel for "none selected / this is an offer". */
export const CODEC_NONE = 0xff;

/** Full normalized pointer range: SHP normalizes pointer coords to `0..=65535`. */
export const POINTER_MAX = 0xffff;

/**
 * Mouse `button` (DOM `MouseEvent.button`) -> SHP button-mask bit.
 *
 * DOM: 0=left, 1=middle, 2=right, 3=back, 4=forward. SHP uses a button bitmask; we map to
 * the conventional left=bit0, right=bit1, middle=bit2 layout the host injector expects.
 */
export function buttonBit(domButton: number): number {
  switch (domButton) {
    case 0:
      return 1 << 0; // left
    case 2:
      return 1 << 1; // right
    case 1:
      return 1 << 2; // middle
    case 3:
      return 1 << 3; // back
    case 4:
      return 1 << 4; // forward
    default:
      return 0;
  }
}

/**
 * Remap the DOM `MouseEvent.buttons` bitmask (the set of buttons currently held) to the SHP
 * `button_mask` (a STATE bitmask of currently-held buttons, per `sh_protocol::InputEvent`).
 *
 * DOM `buttons` bits: 1=left, 2=right, 4=middle, 8=back, 16=forward. SHP bits: left=bit0,
 * right=bit1, middle=bit2, back=bit3, forward=bit4. The SHP `button_mask` is the absolute set
 * of held buttons (not a per-event delta), so this is used to preserve other still-held buttons
 * across a single button's press/release.
 */
export function domButtonsToShpMask(domButtons: number): number {
  let mask = 0;
  if (domButtons & 1) mask |= 1 << 0; // left
  if (domButtons & 2) mask |= 1 << 1; // right
  if (domButtons & 4) mask |= 1 << 2; // middle
  if (domButtons & 8) mask |= 1 << 3; // back
  if (domButtons & 16) mask |= 1 << 4; // forward
  return mask;
}
