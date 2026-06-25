//! USB HID usage → macOS virtual keycode (`CGKeyCode`) mapping.
//!
//! This module is **pure and OS-independent** (a `u16 → u16` table), so it builds and is unit-tested
//! on every platform — including Linux CI — not just macOS. The injector resolves a network
//! `InputEvent`'s `key_code` (a USB HID Usage Page 0x07 id) to the macOS ANSI virtual keycode via
//! [`hid_to_cgkeycode`]; an unknown HID id returns `None`, and the injector then refuses the event
//! ([`sh_input::InputError::Unsupported`]) rather than synthesising an arbitrary keystroke.
//!
//! The virtual keycodes are the standard `kVK_*` ANSI values from
//! `HIToolbox/Events.h` (e.g. `kVK_ANSI_A = 0x00`, `kVK_Return = 0x24`).

/// Translate a USB HID Usage Page 0x07 (keyboard) usage id to a macOS virtual keycode.
///
/// Returns `None` for any usage not in the supported subset (letters a–z, digits 0–9, Enter/Esc/
/// Backspace/Tab/Space, common punctuation, F1–F12, the navigation cluster, arrows, and modifiers).
///
/// # Examples
/// ```
/// use sh_platform_mac::keymap::hid_to_cgkeycode;
/// assert_eq!(hid_to_cgkeycode(0x04), Some(0x00)); // HID 'a' → kVK_ANSI_A
/// assert_eq!(hid_to_cgkeycode(0x28), Some(0x24)); // HID Enter → kVK_Return
/// assert_eq!(hid_to_cgkeycode(0xFFFF), None);     // unknown → refused
/// ```
#[must_use]
pub fn hid_to_cgkeycode(hid: u16) -> Option<u16> {
    let kc = match hid {
        // Letters a–z (HID 0x04–0x1D) → kVK_ANSI_* (note the non-linear ANSI layout).
        0x04 => 0x00, // a
        0x05 => 0x0B, // b
        0x06 => 0x08, // c
        0x07 => 0x02, // d
        0x08 => 0x0E, // e
        0x09 => 0x03, // f
        0x0A => 0x05, // g
        0x0B => 0x04, // h
        0x0C => 0x22, // i
        0x0D => 0x26, // j
        0x0E => 0x28, // k
        0x0F => 0x25, // l
        0x10 => 0x2E, // m
        0x11 => 0x2D, // n
        0x12 => 0x1F, // o
        0x13 => 0x23, // p
        0x14 => 0x0C, // q
        0x15 => 0x0F, // r
        0x16 => 0x01, // s
        0x17 => 0x11, // t
        0x18 => 0x20, // u
        0x19 => 0x09, // v
        0x1A => 0x0D, // w
        0x1B => 0x07, // x
        0x1C => 0x10, // y
        0x1D => 0x06, // z

        // Digits 1–9, 0 (HID 0x1E–0x27).
        0x1E => 0x12, // 1
        0x1F => 0x13, // 2
        0x20 => 0x14, // 3
        0x21 => 0x15, // 4
        0x22 => 0x17, // 5
        0x23 => 0x16, // 6
        0x24 => 0x1A, // 7
        0x25 => 0x1C, // 8
        0x26 => 0x19, // 9
        0x27 => 0x1D, // 0

        // Control / whitespace.
        0x28 => 0x24, // Return
        0x29 => 0x35, // Escape
        0x2A => 0x33, // Delete (Backspace)
        0x2B => 0x30, // Tab
        0x2C => 0x31, // Space

        // Punctuation.
        0x2D => 0x1B, // - _
        0x2E => 0x18, // = +
        0x2F => 0x21, // [ {
        0x30 => 0x1E, // ] }
        0x31 => 0x2A, // \ |
        0x33 => 0x29, // ; :
        0x34 => 0x27, // ' "
        0x35 => 0x32, // ` ~
        0x36 => 0x2B, // , <
        0x37 => 0x2F, // . >
        0x38 => 0x2C, // / ?

        // Function keys F1–F12 (HID 0x3A–0x45).
        0x3A => 0x7A, // F1
        0x3B => 0x78, // F2
        0x3C => 0x63, // F3
        0x3D => 0x76, // F4
        0x3E => 0x60, // F5
        0x3F => 0x61, // F6
        0x40 => 0x62, // F7
        0x41 => 0x64, // F8
        0x42 => 0x65, // F9
        0x43 => 0x6D, // F10
        0x44 => 0x67, // F11
        0x45 => 0x6F, // F12

        // Navigation cluster (HID 0x49–0x4E).
        0x49 => 0x72, // Insert → Help
        0x4A => 0x73, // Home
        0x4B => 0x74, // Page Up
        0x4C => 0x75, // Delete-forward
        0x4D => 0x77, // End
        0x4E => 0x79, // Page Down

        // Arrows (HID 0x4F–0x52).
        0x4F => 0x7C, // Right
        0x50 => 0x7B, // Left
        0x51 => 0x7D, // Down
        0x52 => 0x7E, // Up

        // Modifier keys (HID 0xE0–0xE7).
        0xE0 => 0x3B, // Left Control
        0xE1 => 0x38, // Left Shift
        0xE2 => 0x3A, // Left Option (Alt)
        0xE3 => 0x37, // Left Command (Meta)
        0xE4 => 0x3E, // Right Control
        0xE5 => 0x3C, // Right Shift
        0xE6 => 0x3D, // Right Option
        0xE7 => 0x36, // Right Command

        _ => return None,
    };
    Some(kc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_map_to_ansi_keycodes() {
        assert_eq!(hid_to_cgkeycode(0x04), Some(0x00)); // a
        assert_eq!(hid_to_cgkeycode(0x1D), Some(0x06)); // z
        assert_eq!(hid_to_cgkeycode(0x16), Some(0x01)); // s
    }

    #[test]
    fn digits_and_controls() {
        assert_eq!(hid_to_cgkeycode(0x1E), Some(0x12)); // 1
        assert_eq!(hid_to_cgkeycode(0x27), Some(0x1D)); // 0
        assert_eq!(hid_to_cgkeycode(0x28), Some(0x24)); // Return
        assert_eq!(hid_to_cgkeycode(0x2C), Some(0x31)); // Space
        assert_eq!(hid_to_cgkeycode(0x2A), Some(0x33)); // Backspace
    }

    #[test]
    fn navigation_and_arrows() {
        assert_eq!(hid_to_cgkeycode(0x4A), Some(0x73)); // Home
        assert_eq!(hid_to_cgkeycode(0x4D), Some(0x77)); // End
        assert_eq!(hid_to_cgkeycode(0x4F), Some(0x7C)); // Right
        assert_eq!(hid_to_cgkeycode(0x52), Some(0x7E)); // Up
    }

    #[test]
    fn modifiers() {
        assert_eq!(hid_to_cgkeycode(0xE1), Some(0x38)); // Left Shift
        assert_eq!(hid_to_cgkeycode(0xE3), Some(0x37)); // Left Command
    }

    #[test]
    fn unknown_hid_returns_none() {
        // No mapping → the injector refuses with Unsupported (no arbitrary keystroke).
        assert_eq!(hid_to_cgkeycode(0x00), None);
        assert_eq!(hid_to_cgkeycode(0x65), None); // HID "Application" key — unmapped
        assert_eq!(hid_to_cgkeycode(0xFFFF), None);
    }
}
