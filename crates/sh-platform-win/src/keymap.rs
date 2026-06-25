//! USB HID usage → Windows virtual-key code (`VK_*`) mapping.
//!
//! This module is **pure and OS-independent** (a `u16 → u16` table), so it builds and is unit-tested
//! on every platform — including Linux CI — not just Windows. The injector resolves a network
//! `InputEvent`'s `key_code` (a USB HID Usage Page 0x07 id) to a Win32 virtual-key code via
//! [`hid_to_vk`]; an unknown HID id returns `None`, and the injector then refuses the event
//! ([`sh_input::InputError::Unsupported`]) rather than synthesising an arbitrary keystroke.
//!
//! The virtual-key codes are the standard `VK_*` values from `<winuser.h>` (e.g. `VK_RETURN = 0x0D`,
//! `VK_A = 0x41`).

/// Translate a USB HID Usage Page 0x07 (keyboard) usage id to a Windows virtual-key code.
///
/// Returns `None` for any usage not in the supported subset (letters a–z, digits 0–9, Enter/Esc/
/// Backspace/Tab/Space, common punctuation, F1–F12, the navigation cluster, arrows, and modifiers).
///
/// # Examples
/// ```
/// use sh_platform_win::keymap::hid_to_vk;
/// assert_eq!(hid_to_vk(0x04), Some(0x41)); // HID 'a' → VK_A
/// assert_eq!(hid_to_vk(0x28), Some(0x0D)); // HID Enter → VK_RETURN
/// assert_eq!(hid_to_vk(0xFFFF), None);     // unknown → refused
/// ```
// The linear ranges below bound every subtraction/addition (e.g. in `0x04..=0x1D`, `hid - 0x04` is
// `0..=0x19` and `0x41 + that` is `≤ 0x5A`), so no operation can overflow — hence the scoped allow.
#[allow(clippy::arithmetic_side_effects)]
#[must_use]
pub fn hid_to_vk(hid: u16) -> Option<u16> {
    let vk = match hid {
        // Letters a–z (HID 0x04–0x1D) → VK_A..VK_Z (0x41–0x5A), linear.
        0x04..=0x1D => 0x41 + (hid - 0x04),

        // Digits 1–9 (HID 0x1E–0x26) → VK_1..VK_9 (0x31–0x39); 0 (HID 0x27) → VK_0 (0x30).
        0x1E..=0x26 => 0x31 + (hid - 0x1E),
        0x27 => 0x30,

        // Control / whitespace.
        0x28 => 0x0D, // VK_RETURN
        0x29 => 0x1B, // VK_ESCAPE
        0x2A => 0x08, // VK_BACK
        0x2B => 0x09, // VK_TAB
        0x2C => 0x20, // VK_SPACE

        // Punctuation (OEM keys).
        0x2D => 0xBD, // - _   VK_OEM_MINUS
        0x2E => 0xBB, // = +   VK_OEM_PLUS
        0x2F => 0xDB, // [ {   VK_OEM_4
        0x30 => 0xDD, // ] }   VK_OEM_6
        0x31 => 0xDC, // \ |   VK_OEM_5
        // 0x32: non-US #/~ (ISO-layout key right of Left Shift) — intentionally unmapped (→ None).
        0x33 => 0xBA, // ; :   VK_OEM_1
        0x34 => 0xDE, // ' "   VK_OEM_7
        0x35 => 0xC0, // ` ~   VK_OEM_3
        0x36 => 0xBC, // , <   VK_OEM_COMMA
        0x37 => 0xBE, // . >   VK_OEM_PERIOD
        0x38 => 0xBF, // / ?   VK_OEM_2

        // Function keys F1–F12 (HID 0x3A–0x45) → VK_F1..VK_F12 (0x70–0x7B), linear.
        0x3A..=0x45 => 0x70 + (hid - 0x3A),

        // Navigation cluster (HID 0x49–0x4E).
        0x49 => 0x2D, // Insert    VK_INSERT
        0x4A => 0x24, // Home      VK_HOME
        0x4B => 0x21, // Page Up   VK_PRIOR
        0x4C => 0x2E, // Delete    VK_DELETE
        0x4D => 0x23, // End       VK_END
        0x4E => 0x22, // Page Down VK_NEXT

        // Arrows (HID 0x4F–0x52).
        0x4F => 0x27, // Right VK_RIGHT
        0x50 => 0x25, // Left  VK_LEFT
        0x51 => 0x28, // Down  VK_DOWN
        0x52 => 0x26, // Up    VK_UP

        // Modifier keys (HID 0xE0–0xE7).
        0xE0 => 0xA2, // Left Control  VK_LCONTROL
        0xE1 => 0xA0, // Left Shift    VK_LSHIFT
        0xE2 => 0xA4, // Left Alt      VK_LMENU
        0xE3 => 0x5B, // Left GUI      VK_LWIN
        0xE4 => 0xA3, // Right Control VK_RCONTROL
        0xE5 => 0xA1, // Right Shift   VK_RSHIFT
        0xE6 => 0xA5, // Right Alt     VK_RMENU
        0xE7 => 0x5C, // Right GUI     VK_RWIN

        _ => return None,
    };
    Some(vk)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn letters_are_linear_vk() {
        assert_eq!(hid_to_vk(0x04), Some(0x41)); // a → VK_A
        assert_eq!(hid_to_vk(0x1D), Some(0x5A)); // z → VK_Z
        assert_eq!(hid_to_vk(0x16), Some(0x53)); // s → VK_S
    }

    #[test]
    fn digits_and_controls() {
        assert_eq!(hid_to_vk(0x1E), Some(0x31)); // 1 → VK_1
        assert_eq!(hid_to_vk(0x27), Some(0x30)); // 0 → VK_0
        assert_eq!(hid_to_vk(0x28), Some(0x0D)); // Enter → VK_RETURN
        assert_eq!(hid_to_vk(0x2C), Some(0x20)); // Space → VK_SPACE
        assert_eq!(hid_to_vk(0x2A), Some(0x08)); // Backspace → VK_BACK
    }

    #[test]
    fn function_keys_linear() {
        assert_eq!(hid_to_vk(0x3A), Some(0x70)); // F1 → VK_F1
        assert_eq!(hid_to_vk(0x3F), Some(0x75)); // F6 → VK_F6 (midpoint, guards range off-by-one)
        assert_eq!(hid_to_vk(0x45), Some(0x7B)); // F12 → VK_F12
    }

    #[test]
    fn navigation_and_arrows() {
        assert_eq!(hid_to_vk(0x4A), Some(0x24)); // Home → VK_HOME
        assert_eq!(hid_to_vk(0x4C), Some(0x2E)); // Delete → VK_DELETE
        assert_eq!(hid_to_vk(0x4F), Some(0x27)); // Right → VK_RIGHT
        assert_eq!(hid_to_vk(0x52), Some(0x26)); // Up → VK_UP
    }

    #[test]
    fn modifiers() {
        assert_eq!(hid_to_vk(0xE1), Some(0xA0)); // L Shift → VK_LSHIFT
        assert_eq!(hid_to_vk(0xE3), Some(0x5B)); // L GUI → VK_LWIN
    }

    #[test]
    fn unknown_hid_returns_none() {
        assert_eq!(hid_to_vk(0x00), None);
        assert_eq!(hid_to_vk(0x65), None); // Application key — unmapped
        assert_eq!(hid_to_vk(0xFFFF), None);
    }
}
