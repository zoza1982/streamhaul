//! The 16-byte SHP input event carried on the input channel (`LLD.md` §3.1).
//!
//! Input events flow client → host on the reliable, ordered, highest-priority input channel. The
//! fixed 16-byte layout keeps parsing branch-light and bounds-checked.

use bitflags::bitflags;

use crate::bits::take_array;
use crate::error::ProtocolError;
use crate::INPUT_EVENT_LEN;

/// Kind of input event (`EVENT_TYPE`, byte 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// Pointer/cursor movement (uses `pointer_x`/`pointer_y`).
    PointerMove,
    /// Mouse button state change (uses `button_mask`).
    Button,
    /// Scroll wheel (uses `scroll_x`/`scroll_y`).
    Wheel,
    /// Keyboard key (uses `key_code` + `modifiers`).
    Key,
    /// Touch contact (uses `pointer_x`/`pointer_y` + `pressure`).
    Touch,
    /// Pen/stylus (uses `pointer_x`/`pointer_y` + `pressure`).
    Pen,
}

bitflags! {
    /// Modifier-key bitmask carried in byte 1 of an [`InputEvent`].
    ///
    /// Decoded with `from_bits_retain` so unknown bits from a future wire revision survive a
    /// round-trip rather than being silently dropped.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Modifiers: u8 {
        /// Shift held.
        const SHIFT = 1 << 0;
        /// Control held.
        const CTRL = 1 << 1;
        /// Alt/Option held.
        const ALT = 1 << 2;
        /// Meta/Win/Cmd held.
        const META = 1 << 3;
        /// Caps Lock active.
        const CAPS = 1 << 4;
    }
}

/// One input event. All pointer coordinates are normalized to `0..=65535` across the source surface so
/// they are resolution-independent; scroll deltas are pixels in 8-fractional fixed point (`px·8`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputEvent {
    /// What kind of event this is.
    pub event_type: EventType,
    /// Modifier-key bitmask (see [`Modifiers`]).
    pub modifiers: Modifiers,
    /// Pointer X, normalized `0..=65535`.
    pub pointer_x: u16,
    /// Pointer Y, normalized `0..=65535`.
    pub pointer_y: u16,
    /// Pressed-mouse-button bitmask.
    pub button_mask: u8,
    /// USB HID usage id of the key (for [`EventType::Key`]).
    pub key_code: u16,
    /// Horizontal scroll delta, pixels × 8 (signed).
    pub scroll_x: i16,
    /// Vertical scroll delta, pixels × 8 (signed).
    pub scroll_y: i16,
    /// Stylus/touch pressure `0..=255`.
    pub pressure: u8,
}

impl InputEvent {
    /// Serialize to the fixed 16-byte wire form (14 bytes of fields + 2 reserved/pad bytes).
    ///
    /// # Examples
    /// ```
    /// use sh_protocol::{EventType, InputEvent, Modifiers};
    /// let e = InputEvent {
    ///     event_type: EventType::Key,
    ///     modifiers: Modifiers::CTRL | Modifiers::SHIFT,
    ///     pointer_x: 0,
    ///     pointer_y: 0,
    ///     button_mask: 0,
    ///     key_code: 0x0004,
    ///     scroll_x: 0,
    ///     scroll_y: 0,
    ///     pressure: 0,
    /// };
    /// assert_eq!(InputEvent::decode(&e.encode()), Ok(e));
    /// ```
    #[must_use]
    pub fn encode(&self) -> [u8; INPUT_EVENT_LEN] {
        let [px0, px1] = self.pointer_x.to_be_bytes();
        let [py0, py1] = self.pointer_y.to_be_bytes();
        let [k0, k1] = self.key_code.to_be_bytes();
        let [sx0, sx1] = self.scroll_x.to_be_bytes();
        let [sy0, sy1] = self.scroll_y.to_be_bytes();
        [
            event_type_to_u8(self.event_type),
            self.modifiers.bits(),
            px0,
            px1,
            py0,
            py1,
            self.button_mask,
            k0,
            k1,
            sx0,
            sx1,
            sy0,
            sy1,
            self.pressure,
            0, // reserved
            0, // reserved
        ]
    }

    /// Parse an input event from the start of `data`. Never panics; rejects malformed input.
    ///
    /// # Errors
    /// - [`ProtocolError::Truncated`] if `data` is shorter than [`INPUT_EVENT_LEN`].
    /// - [`ProtocolError::InvalidEventType`] if byte 0 is not a known [`EventType`].
    /// - [`ProtocolError::ReservedBitsSet`] if either reserved byte (14, 15) is non-zero.
    ///
    /// # Examples
    /// ```
    /// use sh_protocol::{InputEvent, ProtocolError};
    /// assert!(matches!(
    ///     InputEvent::decode(&[0u8; 4]),
    ///     Err(ProtocolError::Truncated { needed: 16, have: 4 })
    /// ));
    /// ```
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        let [ty, modifiers, px0, px1, py0, py1, button_mask, k0, k1, sx0, sx1, sy0, sy1, pressure, r0, r1] =
            take_array::<INPUT_EVENT_LEN>(data)?;
        if r0 != 0 || r1 != 0 {
            return Err(ProtocolError::ReservedBitsSet);
        }
        Ok(Self {
            event_type: event_type_from_u8(ty)?,
            modifiers: Modifiers::from_bits_retain(modifiers),
            pointer_x: u16::from_be_bytes([px0, px1]),
            pointer_y: u16::from_be_bytes([py0, py1]),
            button_mask,
            key_code: u16::from_be_bytes([k0, k1]),
            scroll_x: i16::from_be_bytes([sx0, sx1]),
            scroll_y: i16::from_be_bytes([sy0, sy1]),
            pressure,
        })
    }
}

pub(crate) fn event_type_to_u8(event_type: EventType) -> u8 {
    match event_type {
        EventType::PointerMove => 0,
        EventType::Button => 1,
        EventType::Wheel => 2,
        EventType::Key => 3,
        EventType::Touch => 4,
        EventType::Pen => 5,
    }
}

pub(crate) fn event_type_from_u8(byte: u8) -> Result<EventType, ProtocolError> {
    match byte {
        0 => Ok(EventType::PointerMove),
        1 => Ok(EventType::Button),
        2 => Ok(EventType::Wheel),
        3 => Ok(EventType::Key),
        4 => Ok(EventType::Touch),
        5 => Ok(EventType::Pen),
        other => Err(ProtocolError::InvalidEventType(other)),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample() -> InputEvent {
        InputEvent {
            event_type: EventType::Key,
            modifiers: Modifiers::CTRL | Modifiers::SHIFT,
            pointer_x: 0x1234,
            pointer_y: 0x5678,
            button_mask: 0b0000_0101,
            key_code: 0x0004, // HID 'a'
            scroll_x: -3,
            scroll_y: 40,
            pressure: 200,
        }
    }

    #[test]
    fn known_layout_roundtrips() {
        let e = sample();
        let bytes = e.encode();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 3); // Key
        assert_eq!(bytes[1], 0b0000_0011); // CTRL|SHIFT
        assert_eq!([bytes[2], bytes[3]], [0x12, 0x34]); // pointer_x
        assert_eq!([bytes[14], bytes[15]], [0, 0]); // reserved
        assert_eq!(InputEvent::decode(&bytes), Ok(e));
    }

    #[test]
    fn decode_rejects_truncation() {
        assert_eq!(
            InputEvent::decode(&[0u8; 15]),
            Err(ProtocolError::Truncated {
                needed: 16,
                have: 15
            })
        );
    }

    #[test]
    fn decode_rejects_invalid_event_type() {
        let mut bytes = [0u8; INPUT_EVENT_LEN];
        bytes[0] = 9;
        assert_eq!(
            InputEvent::decode(&bytes),
            Err(ProtocolError::InvalidEventType(9))
        );
    }

    #[test]
    fn decode_rejects_reserved_bytes() {
        // Byte 14 and byte 15 are both reserved; either non-zero must be rejected.
        let mut b14 = [0u8; INPUT_EVENT_LEN];
        b14[14] = 1;
        assert_eq!(
            InputEvent::decode(&b14),
            Err(ProtocolError::ReservedBitsSet)
        );
        let mut bytes = [0u8; INPUT_EVENT_LEN];
        bytes[15] = 1;
        assert_eq!(
            InputEvent::decode(&bytes),
            Err(ProtocolError::ReservedBitsSet)
        );
    }

    #[test]
    fn event_type_wire_values_are_stable() {
        // Lock the on-wire discriminants so a reordering can't silently break interop.
        assert_eq!(event_type_to_u8(EventType::PointerMove), 0);
        assert_eq!(event_type_to_u8(EventType::Button), 1);
        assert_eq!(event_type_to_u8(EventType::Wheel), 2);
        assert_eq!(event_type_to_u8(EventType::Key), 3);
        assert_eq!(event_type_to_u8(EventType::Touch), 4);
        assert_eq!(event_type_to_u8(EventType::Pen), 5);
    }

    #[test]
    fn unknown_modifier_bits_survive_roundtrip() {
        // from_bits_retain keeps bits 5-7 (no named flag) so a future-rev modifier isn't dropped.
        let mut e = sample();
        e.modifiers = Modifiers::from_bits_retain(0b1110_0000);
        assert_eq!(InputEvent::decode(&e.encode()), Ok(e));
    }

    proptest! {
        #[test]
        fn roundtrips(
            ty in 0u8..=5,
            modifiers in any::<u8>(),
            pointer_x in any::<u16>(),
            pointer_y in any::<u16>(),
            button_mask in any::<u8>(),
            key_code in any::<u16>(),
            scroll_x in any::<i16>(),
            scroll_y in any::<i16>(),
            pressure in any::<u8>(),
        ) {
            let e = InputEvent {
                event_type: event_type_from_u8(ty).unwrap(),
                modifiers: Modifiers::from_bits_retain(modifiers),
                pointer_x,
                pointer_y,
                button_mask,
                key_code,
                scroll_x,
                scroll_y,
                pressure,
            };
            prop_assert_eq!(InputEvent::decode(&e.encode()), Ok(e));
        }

        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..40)) {
            let _ = InputEvent::decode(&data);
        }
    }
}
