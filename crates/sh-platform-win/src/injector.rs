//! `SendInput`-based input injector (Windows).
//!
//! Translates a network-delivered [`InputEvent`] into one or more Win32 `INPUT` structures and
//! posts them via `SendInput`. Supported event types:
//!
//! - **[`EventType::PointerMove`]**: maps directly to an absolute `MOUSEEVENTF_ABSOLUTE |
//!   MOUSEEVENTF_MOVE` mouse event over the **primary monitor** (the wire coordinates are already
//!   `0..=65535`, matching what Win32 absolute mouse input expects — no coordinate mapper needed).
//!   `VIRTUALDESK` is intentionally not set so the pointer space matches the primary-monitor capture
//!   (`GdiScreenCapturer`); full virtual-desktop capture+inject is R-WIN-DXGI. See ADR-0027.
//! - **[`EventType::Button`]**: XOR-diff against the previous button mask; each changed bit
//!   issues the matching `MOUSEEVENTF_{LEFT,MIDDLE,RIGHT}{DOWN,UP}` event.
//! - **[`EventType::Wheel`]**: vertical scroll via `MOUSEEVENTF_WHEEL` (`±WHEEL_DELTA`);
//!   horizontal scroll via `MOUSEEVENTF_HWHEEL`. One notch per event.
//! - **[`EventType::Key`]**: USB HID → Win32 virtual-key via [`crate::keymap::hid_to_vk`];
//!   unknown HID codes return [`InputError::Unsupported`] (never a wild keystroke). Active
//!   modifiers (Shift, Control, Alt, Win) are pressed around the key and released in reverse
//!   order even if the key injection itself fails.
//! - **[`EventType::Touch`] / [`EventType::Pen`]**: return [`InputError::Unsupported`]
//!   (follow-up, see ADR-0027).
//!
//! # Threading note
//!
//! [`InputInjector`] requires `Send`. The struct holds only plain integer data — no Win32 handle
//! or raw pointer — so it is trivially `Send`.
//!
//! # Button mask → Win32 mouse buttons
//!
//! | Bit | Mask | Button | Down flag                | Up flag                |
//! |-----|------|--------|--------------------------|------------------------|
//! | 0   | 0x01 | Left   | `MOUSEEVENTF_LEFTDOWN`   | `MOUSEEVENTF_LEFTUP`   |
//! | 1   | 0x02 | Middle | `MOUSEEVENTF_MIDDLEDOWN` | `MOUSEEVENTF_MIDDLEUP` |
//! | 2   | 0x04 | Right  | `MOUSEEVENTF_RIGHTDOWN`  | `MOUSEEVENTF_RIGHTUP`  |
//!
//! Bits 3–7 are reserved and ignored (no injection, no error).

use std::mem::{size_of, zeroed};

use tracing::debug;
use winapi::shared::minwindef::DWORD;
use winapi::um::winuser::{
    SendInput, INPUT, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, MOUSEEVENTF_ABSOLUTE,
    MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
    MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
    MOUSEEVENTF_WHEEL, MOUSEINPUT, WHEEL_DELTA,
};

use sh_input::{InputError, InputInjector};
use sh_protocol::{EventType, InputEvent, Modifiers};

use crate::keymap::hid_to_vk;

/// Win32 virtual-key codes for the four generic modifier keys.
const VK_SHIFT: u16 = 0x10;
const VK_CONTROL: u16 = 0x11;
const VK_MENU: u16 = 0x12; // Alt
const VK_LWIN: u16 = 0x5B;

/// (button_mask_bit, down_flag, up_flag) for the three tracked mouse buttons.
const BUTTON_MAP: [(u8, DWORD, DWORD); 3] = [
    (0x01, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
    (0x02, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
    (0x04, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
];

/// Mask of the button bits this injector tracks (bits 0–2). Reserved bits 3–7 are ignored, so
/// `prev_button_mask & DEFINED_BUTTON_BITS == 0` means nothing is really held.
const DEFINED_BUTTON_BITS: u8 = 0x07;

/// An [`InputInjector`] that synthesises Windows input via `SendInput`.
///
/// Construct once per session via [`SendInputInjector::new`]. The struct holds only `Send` data
/// (one `u8` for the previous button mask), so it may be moved freely across threads.
///
/// `SendInput` works within any interactive Windows session; no per-app permission gate exists
/// (unlike macOS TCC). On a headless session (`UIPI` restrictions may apply in elevated
/// processes) the call silently drops inputs rather than returning an error; we treat that as
/// best-effort, mirroring macOS's TCC no-op behaviour (ADR-0027).
pub struct SendInputInjector {
    /// Tracks which mouse buttons are currently pressed so we can XOR-diff on the next
    /// `Button` event and emit only the changed up/down transitions.
    prev_button_mask: u8,
}

impl SendInputInjector {
    /// Create an injector.
    ///
    /// # Errors
    ///
    /// Always succeeds in the current implementation (no Win32 handles are opened at construction
    /// time); the `Result` is retained for trait consistency with potential future backends.
    pub fn new() -> Result<Self, InputError> {
        Ok(Self {
            prev_button_mask: 0,
        })
    }
}

/// Build and dispatch a single-slot `INPUT` struct with a `MOUSEINPUT` payload.
///
/// Returns `Ok(())` regardless of whether `SendInput` succeeded: the Win32 call is best-effort
/// (it may be silently dropped by UIPI in elevated processes, matching the macOS TCC no-op
/// behaviour — ADR-0027). A `SendInput` return of 0 is logged as a debug message but never
/// surfaced as an error.
#[allow(clippy::cast_possible_truncation)]
fn send_mouse(mi: MOUSEINPUT) -> Result<(), InputError> {
    // SAFETY: We construct a zero-initialised INPUT and write a valid MOUSEINPUT into its union
    // field `u` via `mi_mut()`. The `type_` field is set to `INPUT_MOUSE` which is the correct
    // discriminant. The struct lives on the stack and outlives the `SendInput` call. The size
    // argument is `size_of::<INPUT>()`, matching what Win32 expects.
    let sent = unsafe {
        let mut input: INPUT = zeroed();
        input.type_ = INPUT_MOUSE;
        *input.u.mi_mut() = mi;
        SendInput(1, &mut input, size_of::<INPUT>() as i32)
    };
    if sent == 0 {
        debug!("SendInput(MOUSE) returned 0 (possible UIPI drop)");
    }
    Ok(())
}

/// Build and dispatch a single-slot `INPUT` struct with a `KEYBDINPUT` payload.
///
/// Same best-effort / UIPI policy as [`send_mouse`].
#[allow(clippy::cast_possible_truncation)]
fn send_key(ki: KEYBDINPUT) -> Result<(), InputError> {
    // SAFETY: We construct a zero-initialised INPUT and write a valid KEYBDINPUT into its union
    // field `u` via `ki_mut()`. The `type_` field is set to `INPUT_KEYBOARD`. The struct lives
    // on the stack and outlives the `SendInput` call. The size argument is correct.
    let sent = unsafe {
        let mut input: INPUT = zeroed();
        input.type_ = INPUT_KEYBOARD;
        *input.u.ki_mut() = ki;
        SendInput(1, &mut input, size_of::<INPUT>() as i32)
    };
    if sent == 0 {
        debug!("SendInput(KEY) returned 0 (possible UIPI drop)");
    }
    Ok(())
}

/// Press (`keydown = true`) or release (`keydown = false`) a single virtual-key.
fn vk_event(vk: u16, keydown: bool) -> Result<(), InputError> {
    let flags = if keydown {
        0
    } else {
        winapi::um::winuser::KEYEVENTF_KEYUP
    };
    send_key(KEYBDINPUT {
        wVk: vk,
        wScan: 0,
        dwFlags: flags,
        time: 0,
        dwExtraInfo: 0,
    })
}

/// Build the list of modifier VKs active in `modifiers`, in the order they should be pressed.
/// The release order is the reverse of this list.
fn active_modifier_vks(modifiers: Modifiers) -> [Option<u16>; 4] {
    [
        modifiers.contains(Modifiers::SHIFT).then_some(VK_SHIFT),
        modifiers.contains(Modifiers::CTRL).then_some(VK_CONTROL),
        modifiers.contains(Modifiers::ALT).then_some(VK_MENU),
        modifiers.contains(Modifiers::META).then_some(VK_LWIN),
    ]
}

impl InputInjector for SendInputInjector {
    /// Inject one event into the Windows input system via `SendInput`.
    ///
    /// # Errors
    ///
    /// - [`InputError::Unsupported`] for Touch, Pen, and any HID key code not present in the
    ///   [`crate::keymap`] table (unknown key → refused, never an arbitrary keystroke).
    /// - This implementation never returns [`InputError::Backend`]: `SendInput` failures are
    ///   treated as best-effort (see the `SendInputInjector` doc).
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        match event.event_type {
            EventType::PointerMove => {
                // The wire coords are already 0..=65535, which is exactly what MOUSEEVENTF_ABSOLUTE
                // expects, mapped to the **primary monitor** — matching the primary-monitor capture
                // (SM_CXSCREEN/SM_CYSCREEN). VIRTUALDESK is intentionally NOT set: the capturer grabs
                // the primary monitor, so the pointer space must be the primary monitor too, or a
                // click on a multi-monitor host would land outside the streamed image (ADR-0027 /
                // R-WIN-DXGI tracks full virtual-desktop capture). §7: do NOT log the coordinates.
                debug!("SendInputInjector: PointerMove");
                send_mouse(MOUSEINPUT {
                    dx: i32::from(event.pointer_x),
                    dy: i32::from(event.pointer_y),
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                    time: 0,
                    dwExtraInfo: 0,
                })?;
            }

            EventType::Button => {
                let curr = event.button_mask;
                let changed = curr ^ self.prev_button_mask;
                // Update prev BEFORE the sends (mirror the mac injector pattern).
                self.prev_button_mask = curr;
                // §7: log only the kind — never the mask value.
                debug!("SendInputInjector: Button");
                for (mask, down_flag, up_flag) in BUTTON_MAP {
                    if changed & mask == 0 {
                        continue;
                    }
                    let pressed = curr & mask != 0;
                    let flags = if pressed { down_flag } else { up_flag };
                    send_mouse(MOUSEINPUT {
                        dx: 0,
                        dy: 0,
                        mouseData: 0,
                        dwFlags: flags,
                        time: 0,
                        dwExtraInfo: 0,
                    })?;
                }
            }

            EventType::Wheel => {
                // §7: log only the kind.
                debug!("SendInputInjector: Wheel");
                // Vertical scroll: scroll_y > 0 → scroll up (+WHEEL_DELTA);
                //                  scroll_y < 0 → scroll down (-WHEEL_DELTA).
                if event.scroll_y != 0 {
                    // WHEEL_DELTA = 120 (c_short). mouseData is DWORD (u32); we transmit the
                    // signed delta as a u32 bit-pattern (Win32 interprets it as a signed value
                    // internally). Casting i16 → i32 → u32 (bit-reinterpret) is the idiomatic
                    // Win32 pattern for WHEEL input.
                    #[allow(clippy::cast_sign_loss)]
                    let wheel_data = if event.scroll_y > 0 {
                        i32::from(WHEEL_DELTA) as u32
                    } else {
                        i32::from(WHEEL_DELTA).wrapping_neg() as u32
                    };
                    send_mouse(MOUSEINPUT {
                        dx: 0,
                        dy: 0,
                        mouseData: wheel_data,
                        dwFlags: MOUSEEVENTF_WHEEL,
                        time: 0,
                        dwExtraInfo: 0,
                    })?;
                }
                // Horizontal scroll via MOUSEEVENTF_HWHEEL.
                if event.scroll_x != 0 {
                    #[allow(clippy::cast_sign_loss)]
                    let hwheel_data = if event.scroll_x > 0 {
                        i32::from(WHEEL_DELTA) as u32
                    } else {
                        i32::from(WHEEL_DELTA).wrapping_neg() as u32
                    };
                    send_mouse(MOUSEINPUT {
                        dx: 0,
                        dy: 0,
                        mouseData: hwheel_data,
                        dwFlags: MOUSEEVENTF_HWHEEL,
                        time: 0,
                        dwExtraInfo: 0,
                    })?;
                }
            }

            EventType::Key => {
                let vk = hid_to_vk(event.key_code).ok_or(InputError::Unsupported {
                    reason: "USB HID key code not in supported subset; key injection refused",
                })?;
                let mod_vks = active_modifier_vks(event.modifiers);
                // §7: log only the kind — never the virtual-key code (would reconstruct typed keys).
                debug!("SendInputInjector: Key");

                // Press modifiers in order.
                for mv in mod_vks.into_iter().flatten() {
                    vk_event(mv, true)?;
                }

                // Press and release the key. If the key-down send fails we still release
                // modifiers (mirror the mac injector's pattern of always releasing).
                let key_result = vk_event(vk, true).and_then(|()| vk_event(vk, false));

                // Release modifiers in reverse order — always, even if key_result is Err.
                // We iterate in reverse over the same fixed-size array (no allocation needed).
                for mv in mod_vks.into_iter().rev().flatten() {
                    // Best-effort release: ignore individual release errors (same as mac injector).
                    let _ = vk_event(mv, false);
                }

                // Propagate the key error (if any) after modifiers have been released.
                key_result?;
            }

            EventType::Touch | EventType::Pen => {
                return Err(InputError::Unsupported {
                    reason: "touch/pen injection not supported on Windows",
                });
            }
        }
        Ok(())
    }

    /// Release every mouse button still held down (per `prev_button_mask`) and reset the tracked
    /// state. Called on session end so a button whose release event was lost can't leave the
    /// controlled machine with a button stuck. Best-effort: `SendInput` failures are ignored (the
    /// session is ending). Keys/modifiers are emitted as atomic press+release pairs in `inject`,
    /// so they never latch and need no release here.
    fn release_all(&mut self) {
        let held = self.prev_button_mask;
        // Only bits 0–2 map to real buttons; nothing tracked means nothing to release.
        if held & DEFINED_BUTTON_BITS == 0 {
            return;
        }
        // Reset BEFORE the sends so a re-entrant/idempotent call is a cheap early-return.
        self.prev_button_mask = 0;
        // §7: log only the kind — never the mask value.
        for (mask, _down_flag, up_flag) in BUTTON_MAP {
            if held & mask == 0 {
                continue;
            }
            debug!("SendInputInjector: release_all releasing held button");
            // Best-effort: ignore the result, the session is ending.
            let _ = send_mouse(MOUSEINPUT {
                dx: 0,
                dy: 0,
                mouseData: 0,
                dwFlags: up_flag,
                time: 0,
                dwExtraInfo: 0,
            });
        }
    }
}

// Windows runtime smoke tests. These run on the `windows-latest` CI runner, which provides an
// interactive desktop. The tests construct the injector and drive each event arm — `SendInput`
// may be silently dropped by UIPI but never panics. We verify construction + dispatch + the
// Unsupported paths, NOT that actual keystrokes/clicks reach the system (which would be
// interactive-only validation, R-WIN-INTERACTIVE).
#[cfg(all(test, target_os = "windows"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod win_tests {
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
        let mut inj = SendInputInjector::new().expect("construct SendInputInjector");

        // PointerMove — best-effort, returns Ok.
        inj.inject(&ev(EventType::PointerMove)).unwrap();

        // Button — press left, then release left.
        inj.inject(&InputEvent {
            button_mask: 0x01,
            ..ev(EventType::Button)
        })
        .unwrap();
        inj.inject(&InputEvent {
            button_mask: 0x00,
            ..ev(EventType::Button)
        })
        .unwrap();

        // Wheel vertical + horizontal.
        inj.inject(&InputEvent {
            scroll_y: 1,
            ..ev(EventType::Wheel)
        })
        .unwrap();
        inj.inject(&InputEvent {
            scroll_x: -1,
            ..ev(EventType::Wheel)
        })
        .unwrap();

        // Key — HID 'a' (0x04).
        inj.inject(&InputEvent {
            key_code: 0x04,
            ..ev(EventType::Key)
        })
        .unwrap();

        // Key — unknown HID code → Unsupported (never a wild keystroke).
        assert!(matches!(
            inj.inject(&InputEvent {
                key_code: 0xFFFF,
                ..ev(EventType::Key)
            }),
            Err(InputError::Unsupported { .. })
        ));

        // Touch / Pen → Unsupported.
        assert!(matches!(
            inj.inject(&ev(EventType::Touch)),
            Err(InputError::Unsupported { .. })
        ));
        assert!(matches!(
            inj.inject(&ev(EventType::Pen)),
            Err(InputError::Unsupported { .. })
        ));
    }

    #[test]
    fn release_all_clears_tracked_buttons_and_is_idempotent() {
        // `SendInput` may be dropped by UIPI, so (like the other win smoke tests) we assert the
        // injector's tracked state, not an OS effect. This guards the bookkeeping that prevents a
        // stuck button when a session ends mid-press.
        let mut inj = SendInputInjector::new().expect("construct SendInputInjector");
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
}
