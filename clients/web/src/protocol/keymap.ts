// DOM `KeyboardEvent.code` -> USB HID Keyboard/Keypad Page (0x07) usage ID.
//
// SHP carries `key_code` as a USB HID usage ID (see `sh_wasm::encode_input_event`), which is
// the platform-neutral identifier the host injector replays. We map from the DOM physical-key
// `code` (layout-independent) rather than `key` (layout/locale-dependent) so a press of the
// physical "A" key always produces HID usage 0x04 regardless of keyboard layout.
//
// Reference: USB HID Usage Tables v1.12, §10 (Keyboard/Keypad Page).

const HID: Readonly<Record<string, number>> = {
  // Letters: HID 0x04 (A) .. 0x1D (Z), contiguous.
  KeyA: 0x04,
  KeyB: 0x05,
  KeyC: 0x06,
  KeyD: 0x07,
  KeyE: 0x08,
  KeyF: 0x09,
  KeyG: 0x0a,
  KeyH: 0x0b,
  KeyI: 0x0c,
  KeyJ: 0x0d,
  KeyK: 0x0e,
  KeyL: 0x0f,
  KeyM: 0x10,
  KeyN: 0x11,
  KeyO: 0x12,
  KeyP: 0x13,
  KeyQ: 0x14,
  KeyR: 0x15,
  KeyS: 0x16,
  KeyT: 0x17,
  KeyU: 0x18,
  KeyV: 0x19,
  KeyW: 0x1a,
  KeyX: 0x1b,
  KeyY: 0x1c,
  KeyZ: 0x1d,
  // Digit row (top): HID 0x1E (1) .. 0x27 (0).
  Digit1: 0x1e,
  Digit2: 0x1f,
  Digit3: 0x20,
  Digit4: 0x21,
  Digit5: 0x22,
  Digit6: 0x23,
  Digit7: 0x24,
  Digit8: 0x25,
  Digit9: 0x26,
  Digit0: 0x27,
  // Control / whitespace.
  Enter: 0x28,
  Escape: 0x29,
  Backspace: 0x2a,
  Tab: 0x2b,
  Space: 0x2c,
  Minus: 0x2d,
  Equal: 0x2e,
  BracketLeft: 0x2f,
  BracketRight: 0x30,
  Backslash: 0x31,
  Semicolon: 0x33,
  Quote: 0x34,
  Backquote: 0x35,
  Comma: 0x36,
  Period: 0x37,
  Slash: 0x38,
  CapsLock: 0x39,
  // Function row: HID 0x3A (F1) .. 0x45 (F12), contiguous.
  F1: 0x3a,
  F2: 0x3b,
  F3: 0x3c,
  F4: 0x3d,
  F5: 0x3e,
  F6: 0x3f,
  F7: 0x40,
  F8: 0x41,
  F9: 0x42,
  F10: 0x43,
  F11: 0x44,
  F12: 0x45,
  // System / editing keys.
  PrintScreen: 0x46,
  ScrollLock: 0x47,
  Pause: 0x48,
  // Navigation cluster.
  Insert: 0x49,
  Home: 0x4a,
  PageUp: 0x4b,
  Delete: 0x4c,
  End: 0x4d,
  PageDown: 0x4e,
  // Arrows.
  ArrowRight: 0x4f,
  ArrowLeft: 0x50,
  ArrowDown: 0x51,
  ArrowUp: 0x52,
  // Keypad (Numpad). NumLock + the operators + digits + decimal.
  NumLock: 0x53,
  NumpadDivide: 0x54,
  NumpadMultiply: 0x55,
  NumpadSubtract: 0x56,
  NumpadAdd: 0x57,
  NumpadEnter: 0x58,
  Numpad1: 0x59,
  Numpad2: 0x5a,
  Numpad3: 0x5b,
  Numpad4: 0x5c,
  Numpad5: 0x5d,
  Numpad6: 0x5e,
  Numpad7: 0x5f,
  Numpad8: 0x60,
  Numpad9: 0x61,
  Numpad0: 0x62,
  NumpadDecimal: 0x63,
  // Modifiers (left/right).
  ControlLeft: 0xe0,
  ShiftLeft: 0xe1,
  AltLeft: 0xe2,
  MetaLeft: 0xe3,
  ControlRight: 0xe4,
  ShiftRight: 0xe5,
  AltRight: 0xe6,
  MetaRight: 0xe7,
};

/**
 * Map a DOM `KeyboardEvent.code` to its USB HID usage ID, or `0` if unmapped.
 *
 * `0` is SHP's "no key" sentinel; an unrecognized physical key is dropped rather than sent
 * as a wrong code.
 */
export function keyCodeToHidUsage(code: string): number {
  return HID[code] ?? 0;
}
