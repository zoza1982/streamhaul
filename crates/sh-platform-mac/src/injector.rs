//! CGEvent-based input injector (macOS).
//!
//! Translates a network-delivered [`InputEvent`] into a CoreGraphics `CGEvent` and posts it. Pointer
//! moves, button press/release, and a documented subset of keyboard keys are supported; scroll wheel,
//! touch, and pen return [`InputError::Unsupported`] (follow-ups, see ADR-0026).
//!
//! `CGEventPost` silently no-ops without the **Accessibility** TCC permission — correct fail-soft for
//! the off-hardware (CI) build; live injection is gated on that permission on real hardware
//! (R-MAC-TCC).
//!
//! # Threading note
//!
//! `CGEventSource` wraps a non-`Send` CoreFoundation pointer, but [`InputInjector`] must be `Send`
//! (the host drives injection on a dedicated thread). So the injector stores **no** CoreGraphics
//! handle — it creates a fresh `CGEventSource` inside each [`inject`](CgEventInjector::inject) call.
//! The struct holds only plain data (the coordinate mapper, the button-mask state, and the last
//! pointer position as `(f64, f64)`), which is `Send`.
//!
//! # Button mask → macOS mouse buttons
//!
//! | Bit | Mask | Button | CGEventType (down/up) |
//! |-----|------|--------|-----------------------|
//! | 0   | 0x01 | Left   | LeftMouse{Down,Up}    |
//! | 1   | 0x02 | Middle | OtherMouse{Down,Up}   |
//! | 2   | 0x04 | Right  | RightMouse{Down,Up}   |
//!
//! Bits 3–7 are reserved and ignored (no injection, no error).

use core_graphics::display::CGDisplay;
use core_graphics::event::{CGEvent, CGEventFlags, CGEventTapLocation, CGEventType, CGMouseButton};
use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
use core_graphics::geometry::CGPoint;
use tracing::debug;

use sh_input::{CoordMapper, InputError, InputInjector, TargetRect, DEFINED_BUTTON_BITS};
use sh_protocol::{EventType, InputEvent, Modifiers};

use crate::keymap::hid_to_cgkeycode;

// CGEventFlags modifier bits (Quartz `CGEventFlags`), used to build the keyboard event's flags.
const FLAG_SHIFT: u64 = 0x0002_0000; // kCGEventFlagMaskShift
const FLAG_CONTROL: u64 = 0x0004_0000; // kCGEventFlagMaskControl
const FLAG_ALTERNATE: u64 = 0x0008_0000; // kCGEventFlagMaskAlternate (Option)
const FLAG_COMMAND: u64 = 0x0010_0000; // kCGEventFlagMaskCommand

/// An [`InputInjector`] that synthesises macOS input via CoreGraphics `CGEvent`.
///
/// Construct once per session. The constructor **fails closed** if the HID event source cannot be
/// created. Injection requires the **Accessibility** permission on real hardware; without it
/// `CGEventPost` is a no-op (no error) — see ADR-0026 / R-MAC-TCC.
pub struct CgEventInjector {
    mapper: CoordMapper,
    prev_button_mask: u8,
    /// Last pointer position (display points) as plain `(x, y)`, used as the location for button
    /// events. Stored as a tuple (not `CGPoint`) to keep the struct trivially `Send`.
    last_point: (f64, f64),
}

/// Saturating, sign-safe conversion of a CoreGraphics `f64` dimension to `u32`.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn dim_to_u32(v: f64) -> u32 {
    if v <= 0.0 {
        0
    } else if v >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        v as u32
    }
}

/// Create a fresh HID event source for one `inject` call.
fn event_source() -> Result<CGEventSource, InputError> {
    CGEventSource::new(CGEventSourceStateID::HIDSystemState)
        .map_err(|()| InputError::Backend("CGEventSource::new failed".to_string()))
}

impl CgEventInjector {
    /// Create an injector targeting the main display.
    ///
    /// # Errors
    /// Returns [`InputError::Backend`] if the HID event source (validated once here, fail-closed) or
    /// the coordinate mapper (from the main display bounds) cannot be constructed.
    pub fn new() -> Result<Self, InputError> {
        // Validate up front that we can create an event source (fail-closed), then drop it — the
        // source is non-Send, so we re-create it per inject (see the module-level threading note).
        let _ = event_source()?;

        let bounds = CGDisplay::main().bounds();
        let width = dim_to_u32(bounds.size.width);
        let height = dim_to_u32(bounds.size.height);
        let rect = TargetRect::new(0, 0, width, height).map_err(|e| {
            InputError::Backend(format!("invalid main-display bounds {width}×{height}: {e}"))
        })?;
        let mapper = CoordMapper::new(rect)
            .map_err(|e| InputError::Backend(format!("CoordMapper construction failed: {e}")))?;

        debug!(
            width,
            height, "CgEventInjector: constructed for main display"
        );
        Ok(Self {
            mapper,
            prev_button_mask: 0,
            last_point: (0.0, 0.0),
        })
    }

    /// Build the `CGEventFlags` for the active modifiers.
    fn modifier_flags(modifiers: Modifiers) -> CGEventFlags {
        let mut bits: u64 = 0;
        if modifiers.contains(Modifiers::SHIFT) {
            bits |= FLAG_SHIFT;
        }
        if modifiers.contains(Modifiers::CTRL) {
            bits |= FLAG_CONTROL;
        }
        if modifiers.contains(Modifiers::ALT) {
            bits |= FLAG_ALTERNATE;
        }
        if modifiers.contains(Modifiers::META) {
            bits |= FLAG_COMMAND;
        }
        CGEventFlags::from_bits_truncate(bits)
    }

    /// Post a mouse event of `event_type` for `button` at the last known cursor position.
    fn post_mouse(
        &self,
        source: &CGEventSource,
        event_type: CGEventType,
        button: CGMouseButton,
    ) -> Result<(), InputError> {
        let point = CGPoint::new(self.last_point.0, self.last_point.1);
        let event = CGEvent::new_mouse_event(source.clone(), event_type, point, button)
            .map_err(|()| InputError::Backend("CGEvent::new_mouse_event failed".to_string()))?;
        event.post(CGEventTapLocation::HID);
        Ok(())
    }
}

impl InputInjector for CgEventInjector {
    /// Inject one event. A fresh `CGEventSource` is created per call (see the threading note).
    ///
    /// # Errors
    /// - [`InputError::Unsupported`] for Wheel, Touch, Pen, or an unknown HID key code.
    /// - [`InputError::Backend`] if the per-call event source or any `CGEvent` cannot be created
    ///   (e.g. the HID source becomes unavailable mid-session).
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        let source = event_source()?;
        match event.event_type {
            EventType::PointerMove => {
                let pt = self.mapper.map(event.pointer_x, event.pointer_y);
                let point = CGPoint::new(f64::from(pt.x), f64::from(pt.y));
                self.last_point = (point.x, point.y);
                // §7: do NOT log the coordinate.
                debug!("CgEventInjector: PointerMove");
                let ev = CGEvent::new_mouse_event(
                    source,
                    CGEventType::MouseMoved,
                    point,
                    CGMouseButton::Left,
                )
                .map_err(|()| InputError::Backend("CGEvent mouse move failed".to_string()))?;
                ev.post(CGEventTapLocation::HID);
            }

            EventType::Button => {
                let curr = event.button_mask;
                let changed = curr ^ self.prev_button_mask;
                // (mask, button, down_type, up_type)
                const BUTTON_MAP: [(u8, CGMouseButton, CGEventType, CGEventType); 3] = [
                    (
                        0x01,
                        CGMouseButton::Left,
                        CGEventType::LeftMouseDown,
                        CGEventType::LeftMouseUp,
                    ),
                    (
                        0x02,
                        CGMouseButton::Center,
                        CGEventType::OtherMouseDown,
                        CGEventType::OtherMouseUp,
                    ),
                    (
                        0x04,
                        CGMouseButton::Right,
                        CGEventType::RightMouseDown,
                        CGEventType::RightMouseUp,
                    ),
                ];
                self.prev_button_mask = curr;
                for (mask, button, down, up) in BUTTON_MAP {
                    if changed & mask == 0 {
                        continue;
                    }
                    let pressed = curr & mask != 0;
                    debug!(pressed, "CgEventInjector: Button");
                    self.post_mouse(&source, if pressed { down } else { up }, button)?;
                }
            }

            EventType::Key => {
                let keycode = hid_to_cgkeycode(event.key_code).ok_or(InputError::Unsupported {
                    reason: "USB HID key code not in supported subset; key injection refused",
                })?;
                let flags = Self::modifier_flags(event.modifiers);
                // §7: log only the kind — never the keycode (would reconstruct typed keys).
                debug!("CgEventInjector: Key");
                for keydown in [true, false] {
                    let ev = CGEvent::new_keyboard_event(source.clone(), keycode, keydown)
                        .map_err(|()| {
                            InputError::Backend("CGEvent keyboard event failed".to_string())
                        })?;
                    ev.set_flags(flags);
                    ev.post(CGEventTapLocation::HID);
                }
            }

            EventType::Wheel => {
                return Err(InputError::Unsupported {
                    reason: "scroll wheel injection not yet implemented on macOS (R-MAC-SCROLL)",
                });
            }
            EventType::Touch | EventType::Pen => {
                return Err(InputError::Unsupported {
                    reason: "touch/pen injection not supported on macOS",
                });
            }
        }
        Ok(())
    }

    /// Release every mouse button still held down (per `prev_button_mask`) and reset the tracked
    /// state. Called on session end so a button whose release event was lost can't leave the
    /// controlled machine with a button stuck. Best-effort: a missing event source or a failed
    /// `CGEvent` is ignored (the session is ending). Keys/modifiers are emitted as atomic
    /// press+release pairs in `inject`, so they never latch and need no release here.
    fn release_all(&mut self) {
        let held = self.prev_button_mask;
        // Only bits 0–2 map to real buttons; nothing tracked means nothing to release.
        if held & DEFINED_BUTTON_BITS == 0 {
            return;
        }
        // Best-effort: without an event source there is nothing we can post — leave the tracked
        // state intact so a later call could still retry (the session is ending anyway).
        let Ok(source) = event_source() else {
            return;
        };
        // Reset only now that we know we can post: makes a re-entrant/idempotent call a cheap
        // early-return, and a partial mid-loop failure still leaves the mask clean.
        self.prev_button_mask = 0;
        // (mask, button, up_type) — same buttons as the Button inject arm.
        const RELEASE_MAP: [(u8, CGMouseButton, CGEventType); 3] = [
            (0x01, CGMouseButton::Left, CGEventType::LeftMouseUp),
            (0x02, CGMouseButton::Center, CGEventType::OtherMouseUp),
            (0x04, CGMouseButton::Right, CGEventType::RightMouseUp),
        ];
        for (mask, button, up) in RELEASE_MAP {
            if held & mask == 0 {
                continue;
            }
            debug!("CgEventInjector: release_all releasing held button");
            // Best-effort: ignore the result, the session is ending.
            let _ = self.post_mouse(&source, up, button);
        }
    }
}

// macOS runtime smoke tests. These run on the macos-latest CI runner. They construct the injector
// and drive each event arm — without Accessibility permission `CGEventPost` is a no-op (returns Ok),
// so these verify the construction + dispatch + Unsupported paths, NOT real keystrokes/clicks (which
// are TCC-gated and verified on hardware, R-MAC-TCC). They never assert an effect on the system.
#[cfg(all(test, target_os = "macos"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod mac_tests {
    use super::*;

    fn ev(event_type: EventType) -> InputEvent {
        InputEvent {
            event_type,
            modifiers: Modifiers::empty(),
            pointer_x: 32_767,
            pointer_y: 32_767,
            button_mask: 0,
            key_code: 0,
            scroll_x: 0,
            scroll_y: 0,
            pressure: 0,
        }
    }

    #[test]
    fn constructs_and_dispatches_each_arm() {
        let mut inj = CgEventInjector::new().expect("construct injector on main display");
        // Supported arms return Ok (post is a no-op without Accessibility — no effect asserted).
        inj.inject(&ev(EventType::PointerMove)).unwrap();
        inj.inject(&InputEvent {
            button_mask: 0x01,
            ..ev(EventType::Button)
        })
        .unwrap();
        inj.inject(&InputEvent {
            key_code: 0x04, // HID 'a'
            ..ev(EventType::Key)
        })
        .unwrap();
        // Unsupported arms are typed errors, never a wild injection.
        assert!(matches!(
            inj.inject(&InputEvent {
                key_code: 0xFFFF,
                ..ev(EventType::Key)
            }),
            Err(InputError::Unsupported { .. })
        ));
        assert!(matches!(
            inj.inject(&ev(EventType::Wheel)),
            Err(InputError::Unsupported { .. })
        ));
        assert!(matches!(
            inj.inject(&ev(EventType::Touch)),
            Err(InputError::Unsupported { .. })
        ));
    }

    #[test]
    fn release_all_clears_tracked_buttons_and_is_idempotent() {
        // Without Accessibility permission the posts are no-ops, so (like the other mac smoke
        // tests) we assert the injector's tracked state, not an OS effect. This guards the
        // bookkeeping that prevents a stuck button when a session ends mid-press.
        let mut inj = CgEventInjector::new().expect("construct injector on main display");
        // Press all three buttons (bits 0,1,2) — now tracked as held.
        inj.inject(&InputEvent {
            button_mask: 0x07,
            ..ev(EventType::Button)
        })
        .unwrap();
        assert_eq!(
            inj.prev_button_mask, 0x07,
            "buttons must be tracked as held"
        );

        inj.release_all();
        assert_eq!(
            inj.prev_button_mask, 0,
            "release_all must clear held buttons"
        );

        // Idempotent: a second call on a clean state stays clear (and must not panic).
        inj.release_all();
        assert_eq!(inj.prev_button_mask, 0);
    }

    #[test]
    fn modifier_flags_map_each_bit() {
        // Pure mapping check (no display interaction) for all four mapped modifiers.
        assert_eq!(
            CgEventInjector::modifier_flags(Modifiers::SHIFT),
            CGEventFlags::from_bits_truncate(FLAG_SHIFT)
        );
        assert_eq!(
            CgEventInjector::modifier_flags(Modifiers::CTRL),
            CGEventFlags::from_bits_truncate(FLAG_CONTROL)
        );
        assert_eq!(
            CgEventInjector::modifier_flags(Modifiers::ALT),
            CGEventFlags::from_bits_truncate(FLAG_ALTERNATE)
        );
        assert_eq!(
            CgEventInjector::modifier_flags(Modifiers::META),
            CGEventFlags::from_bits_truncate(FLAG_COMMAND)
        );
    }
}
