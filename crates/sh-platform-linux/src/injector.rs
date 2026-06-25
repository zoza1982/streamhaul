//! XTest-based input injector.
//!
//! # Button mask mapping
//!
//! The [`sh_protocol::InputEvent`] `button_mask` field is a bitmask of currently-pressed
//! buttons. The mapping to X11 button numbers is:
//!
//! | Bit | Mask | X11 button | Meaning         |
//! |-----|------|-----------|-----------------|
//! | 0   | 0x01 | 1         | Left button     |
//! | 1   | 0x02 | 2         | Middle button   |
//! | 2   | 0x04 | 3         | Right button    |
//!
//! Bits 3–7 are reserved and ignored (no injection, no error).
//!
//! # Scroll wheel mapping
//!
//! X11 uses button events for scroll wheels:
//!
//! | Direction       | X11 button | Condition           |
//! |----------------|-----------|---------------------|
//! | Scroll up      | 4         | `scroll_y > 0`      |
//! | Scroll down    | 5         | `scroll_y < 0`      |
//! | Scroll right   | 7         | `scroll_x > 0`      |
//! | Scroll left    | 6         | `scroll_x < 0`      |
//!
//! One press+release pair is emitted per event (v1; fractional scroll is a follow-up).
//!
//! # USB HID → X keysym table
//!
//! The `hid_to_keysym` function covers USB HID Usage Page 0x07 (keyboard): letters a–z
//! (0x04–0x1D), digits 0–9 (0x1E–0x27), Enter/Esc/Backspace/Tab/Space (0x28–0x2C), common
//! punctuation, F1–F12 (0x3A–0x45), the navigation cluster (Insert/Home/Page_Up/Delete/End/
//! Page_Down, 0x49–0x4E), arrow keys, and the modifier keys (0xE0–0xE7). Unknown HID codes return
//! `None` and the injector returns [`sh_input::InputError::Unsupported`] — no arbitrary injection.

use sh_input::{CoordMapper, InputError, InputInjector, TargetRect};
use sh_protocol::{EventType, InputEvent, Modifiers};
use tracing::debug;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt as _, Window};
use x11rb::protocol::xtest::ConnectionExt as XTestConnectionExt;
use x11rb::rust_connection::RustConnection;

// X11 event type codes used by fake_input.
// These match the X11 protocol's event type numbers.
const MOTION_NOTIFY: u8 = 6;
const BUTTON_PRESS: u8 = 4;
const BUTTON_RELEASE: u8 = 5;
const KEY_PRESS: u8 = 2;
const KEY_RELEASE: u8 = 3;

/// An [`InputInjector`] that synthesises X11 events via the XTEST extension.
///
/// Construct once per session. The constructor **fails closed** if the X server does not
/// support XTEST — this prevents silent no-ops when the required extension is absent.
///
/// # Threading
///
/// [`inject`](XTestInjector::inject) must be called from the injection thread only
/// (not from async context). All X protocol messages are flushed synchronously.
///
/// # Example
///
/// ```no_run
/// use sh_platform_linux::XTestInjector;
/// use sh_input::InputInjector;
/// use sh_protocol::{EventType, InputEvent, Modifiers};
///
/// let mut inj = XTestInjector::new(None).expect("DISPLAY must be set with XTEST");
/// let event = InputEvent {
///     event_type: EventType::PointerMove,
///     modifiers: Modifiers::empty(),
///     pointer_x: 32767,
///     pointer_y: 32767,
///     button_mask: 0,
///     key_code: 0,
///     scroll_x: 0,
///     scroll_y: 0,
///     pressure: 0,
/// };
/// inj.inject(&event).expect("inject pointer move");
/// ```
pub struct XTestInjector {
    conn: RustConnection,
    root: Window,
    mapper: CoordMapper,
    /// Previous button mask state, used to diff on each `Button` event.
    prev_button_mask: u8,
    /// Cached keysym→keycode map (`keysym → first keycode that has it as a binding`).
    /// Built lazily on the first `Key` event and cached for the session.
    keysym_to_keycode: Option<KeysymMap>,
}

/// Lazy-built keysym→keycode mapping derived from `GetKeyboardMapping`.
struct KeysymMap {
    /// Vec of `(keysym, keycode)` pairs. Multiple keycodes may share the same keysym;
    /// we take the first one (lowest keycode index).
    entries: Vec<(u32, u8)>,
}

impl KeysymMap {
    fn lookup(&self, keysym: u32) -> Option<u8> {
        self.entries
            .iter()
            .find(|(ks, _)| *ks == keysym)
            .map(|(_, kc)| *kc)
    }
}

/// Build the `(keysym, keycode)` table from a `GetKeyboardMapping` reply.
///
/// Factored out (and made server-reply-agnostic) so the hostile-input edges are unit-testable
/// without a live X server.
///
/// # Errors
/// Returns [`InputError::Backend`] if `ks_per_kc == 0` — a malformed/hostile reply that would
/// otherwise panic `slice::chunks(0)`.
fn build_keysym_entries(
    keysyms: &[u32],
    ks_per_kc: usize,
    min_keycode: u8,
    count: usize,
) -> Result<Vec<(u32, u8)>, InputError> {
    if ks_per_kc == 0 {
        return Err(InputError::Backend(
            "GetKeyboardMapping returned keysyms_per_keycode = 0".to_string(),
        ));
    }
    let mut entries: Vec<(u32, u8)> = Vec::new();
    // Only scan the `count` keycodes we asked for; ignore any surplus a server may append.
    for (kc_offset, chunk) in keysyms.chunks(ks_per_kc).take(count).enumerate() {
        let keycode = min_keycode.saturating_add(u8::try_from(kc_offset).unwrap_or(u8::MAX));
        for &ks in chunk {
            // keysym 0 means "no symbol" — skip.
            if ks != 0 && !entries.iter().any(|(k, _)| *k == ks) {
                entries.push((ks, keycode));
            }
        }
    }
    Ok(entries)
}

impl XTestInjector {
    /// Connect to `display` (or `$DISPLAY`) and verify the XTEST extension is present.
    ///
    /// # Errors
    ///
    /// Returns [`InputError::Backend`] if:
    /// - The X server is unreachable or rejects the connection.
    /// - The XTEST extension is absent.
    /// - The display geometry is zero (would produce an invalid [`CoordMapper`]).
    pub fn new(display: Option<&str>) -> Result<Self, InputError> {
        let (conn, screen_num) = x11rb::connect(display)
            .map_err(|e| InputError::Backend(format!("x11rb::connect failed: {e}")))?;

        // Fail-closed if XTEST extension is absent.
        let xtest = conn
            .query_extension(b"XTEST")
            .map_err(|e| InputError::Backend(format!("query_extension send failed: {e}")))?
            .reply()
            .map_err(|e| InputError::Backend(format!("query_extension reply failed: {e}")))?;

        if !xtest.present {
            return Err(InputError::Backend(
                "XTEST extension is not available on this X server".to_string(),
            ));
        }

        let setup = conn.setup();
        let screen = setup
            .roots
            .get(screen_num)
            .ok_or_else(|| InputError::Backend(format!("screen {screen_num} not found")))?;

        let root = screen.root;
        let width = u32::from(screen.width_in_pixels);
        let height = u32::from(screen.height_in_pixels);

        // Fail-closed if the display has zero-size axes.
        let rect = TargetRect::new(0, 0, width, height).map_err(|e| {
            InputError::Backend(format!("invalid display geometry {width}×{height}: {e}"))
        })?;
        let mapper = CoordMapper::new(rect)
            .map_err(|e| InputError::Backend(format!("CoordMapper construction failed: {e}")))?;

        debug!(
            width,
            height,
            root,
            xtest_present = xtest.present,
            "XTestInjector: connected, XTEST verified"
        );

        Ok(Self {
            conn,
            root,
            mapper,
            prev_button_mask: 0,
            keysym_to_keycode: None,
        })
    }

    /// Build (or return cached) the keysym→keycode map from `GetKeyboardMapping`.
    fn keysym_map(&mut self) -> Result<&KeysymMap, InputError> {
        if self.keysym_to_keycode.is_none() {
            let setup = self.conn.setup();
            let min_keycode = setup.min_keycode;
            let max_keycode = setup.max_keycode;
            let count = max_keycode.saturating_sub(min_keycode).saturating_add(1);

            let mapping = self
                .conn
                .get_keyboard_mapping(min_keycode, count)
                .map_err(|e| InputError::Backend(format!("GetKeyboardMapping send failed: {e}")))?
                .reply()
                .map_err(|e| {
                    InputError::Backend(format!("GetKeyboardMapping reply failed: {e}"))
                })?;

            let ks_per_kc = usize::from(mapping.keysyms_per_keycode);
            // `count` keycodes were requested; bound the keysym scan to that many keycodes so a
            // hostile/oversized reply can't inflate the table or assign saturated keycode 255.
            let entries =
                build_keysym_entries(&mapping.keysyms, ks_per_kc, min_keycode, usize::from(count))?;
            self.keysym_to_keycode = Some(KeysymMap { entries });
        }
        // The `if self.keysym_to_keycode.is_none()` block above always sets the field,
        // so the `as_ref()` cannot be `None` here. Using ok_or converts to a typed error
        // rather than panic.
        self.keysym_to_keycode.as_ref().ok_or_else(|| {
            InputError::Backend("keysym map not initialised (internal error)".to_string())
        })
    }

    /// Synthesise a modifier key press or release. §7: logs only press/release, never the keycode.
    fn fake_modifier_key(&self, keycode: u8, press: bool) -> Result<(), InputError> {
        let event_type = if press { KEY_PRESS } else { KEY_RELEASE };
        debug!(press, "XTestInjector: modifier key");
        self.conn
            .xtest_fake_input(event_type, keycode, 0, self.root, 0, 0, 0)
            .map_err(|e| InputError::Backend(format!("fake_input modifier failed: {e}")))?;
        Ok(())
    }
}

impl InputInjector for XTestInjector {
    /// Inject one [`InputEvent`] into the X server.
    ///
    /// # Errors
    ///
    /// - [`InputError::Unsupported`] for Touch, Pen, or unknown HID key codes.
    /// - [`InputError::Backend`] if the X protocol call fails.
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        match event.event_type {
            EventType::PointerMove => {
                let pt = self.mapper.map(event.pointer_x, event.pointer_y);
                // `fake_input` takes i16 dst_x/dst_y relative to the root origin (0,0). Our
                // CoordMapper guarantees 0 ≤ pt.x < width; saturate to i16::MAX rather than wrap so
                // an ultra-wide (>32767 px) virtual desktop warps to the edge, not a negative coord.
                let px = i16::try_from(pt.x).unwrap_or(i16::MAX);
                let py = i16::try_from(pt.y).unwrap_or(i16::MAX);
                // §7: do NOT log the coordinate (it can reveal on-screen interaction targets).
                debug!("XTestInjector: PointerMove");
                self.conn
                    .xtest_fake_input(MOTION_NOTIFY, 0, 0, self.root, px, py, 0)
                    .map_err(|e| InputError::Backend(format!("fake_input motion failed: {e}")))?;
                self.conn
                    .flush()
                    .map_err(|e| InputError::Backend(format!("flush failed: {e}")))?;
            }

            EventType::Button => {
                let curr = event.button_mask;
                let prev = self.prev_button_mask;
                let changed = curr ^ prev;

                // Button bit-to-X11-button mapping (see module-level docs).
                // Only bits 0–2 are defined; bits 3–7 are silently ignored.
                // (mask, x11_button) pairs — avoids arithmetic that triggers
                // the `clippy::arithmetic_side_effects` lint.
                const BUTTON_MAP: [(u8, u8); 3] = [(0x01, 1), (0x02, 2), (0x04, 3)];
                // Record the new mask as the baseline BEFORE sending, so a mid-loop send error does
                // not leave `prev` stale (which would re-send an already-applied press next event).
                // The X server only observes these requests at the `flush()` below, so the order of
                // the local state update vs. the buffered sends is immaterial to the server.
                self.prev_button_mask = curr;
                for (mask, x_button) in BUTTON_MAP {
                    if changed & mask == 0 {
                        continue;
                    }
                    let pressed = curr & mask != 0;
                    let event_type = if pressed {
                        BUTTON_PRESS
                    } else {
                        BUTTON_RELEASE
                    };
                    debug!(x_button, pressed, "XTestInjector: Button");
                    self.conn
                        .xtest_fake_input(event_type, x_button, 0, self.root, 0, 0, 0)
                        .map_err(|e| {
                            InputError::Backend(format!("fake_input button failed: {e}"))
                        })?;
                }

                self.conn
                    .flush()
                    .map_err(|e| InputError::Backend(format!("flush failed: {e}")))?;
            }

            EventType::Wheel => {
                // Each axis: one press+release pair per event (v1).
                // See module-level docs for the button→direction table.
                let scroll_y = event.scroll_y;
                let scroll_x = event.scroll_x;

                if scroll_y != 0 {
                    // Positive scroll_y = scroll up = button 4.
                    // Negative scroll_y = scroll down = button 5.
                    let btn = if scroll_y > 0 { 4u8 } else { 5u8 };
                    debug!(scroll_y, btn, "XTestInjector: Wheel Y");
                    self.conn
                        .xtest_fake_input(BUTTON_PRESS, btn, 0, self.root, 0, 0, 0)
                        .map_err(|e| InputError::Backend(format!("fake_input wheel press: {e}")))?;
                    self.conn
                        .xtest_fake_input(BUTTON_RELEASE, btn, 0, self.root, 0, 0, 0)
                        .map_err(|e| {
                            InputError::Backend(format!("fake_input wheel release: {e}"))
                        })?;
                }

                if scroll_x != 0 {
                    // Positive scroll_x = scroll right = button 7.
                    // Negative scroll_x = scroll left = button 6.
                    let btn = if scroll_x > 0 { 7u8 } else { 6u8 };
                    debug!(scroll_x, btn, "XTestInjector: Wheel X");
                    self.conn
                        .xtest_fake_input(BUTTON_PRESS, btn, 0, self.root, 0, 0, 0)
                        .map_err(|e| InputError::Backend(format!("fake_input wheel press: {e}")))?;
                    self.conn
                        .xtest_fake_input(BUTTON_RELEASE, btn, 0, self.root, 0, 0, 0)
                        .map_err(|e| {
                            InputError::Backend(format!("fake_input wheel release: {e}"))
                        })?;
                }

                self.conn
                    .flush()
                    .map_err(|e| InputError::Backend(format!("flush failed: {e}")))?;
            }

            EventType::Key => {
                // Resolve USB HID usage → X keysym.
                let keysym = hid_to_keysym(event.key_code).ok_or(InputError::Unsupported {
                    reason: "USB HID key code not in supported subset; key injection refused",
                })?;

                // Resolve keysym → keycode via the server's keyboard mapping.
                let map = self.keysym_map()?;
                let keycode = map.lookup(keysym).ok_or(InputError::Unsupported {
                    reason: "keysym has no keycode binding on this X server",
                })?;

                let modifiers = event.modifiers;

                // Modifier keycodes (Shift, Ctrl, Alt, Meta). Skip any equal to the main keycode so
                // a "press Shift while Shift is the key" event doesn't double press/release it.
                let modifier_keycodes: Vec<(u32, u8)> = modifier_keycodes(&modifiers, map)
                    .into_iter()
                    .filter(|&(_, kc)| kc != keycode)
                    .collect();

                for &(_, kc) in &modifier_keycodes {
                    self.fake_modifier_key(kc, true)?;
                }

                // Press+release the main key. §7: log only the kind — never the keysym/keycode
                // (which would reconstruct typed keys / passwords from a debug log).
                debug!("XTestInjector: Key");
                let key_result: Result<(), InputError> = self
                    .conn
                    .xtest_fake_input(KEY_PRESS, keycode, 0, self.root, 0, 0, 0)
                    .map_err(|e| InputError::Backend(format!("fake_input key press failed: {e}")))
                    .and_then(|_| {
                        self.conn
                            .xtest_fake_input(KEY_RELEASE, keycode, 0, self.root, 0, 0, 0)
                            .map_err(|e| {
                                InputError::Backend(format!("fake_input key release failed: {e}"))
                            })
                    })
                    .map(|_| ());

                // ALWAYS release the modifiers we pressed (reverse order), even if the main key
                // failed — otherwise a partial failure leaves a modifier latched in the X server.
                for &(_, kc) in modifier_keycodes.iter().rev() {
                    let _ = self.fake_modifier_key(kc, false); // best-effort cleanup
                }
                key_result?;

                self.conn
                    .flush()
                    .map_err(|e| InputError::Backend(format!("flush failed: {e}")))?;
            }

            EventType::Touch => {
                // Touch injection via XTEST requires XI2 (XInputExtension 2.x) which is a
                // separate follow-up (R-LINUX-WAYLAND). Return Unsupported rather than silently
                // dropping or injecting garbage.
                return Err(InputError::Unsupported {
                    reason: "Touch injection is not yet supported on Linux X11 (deferred: R-LINUX-WAYLAND)",
                });
            }

            EventType::Pen => {
                // Pen/stylus injection likewise requires XI2 pressure events.
                return Err(InputError::Unsupported {
                    reason: "Pen/stylus injection is not yet supported on Linux X11 (deferred: R-LINUX-WAYLAND)",
                });
            }
        }

        Ok(())
    }
}

// ── Modifier keycodes ─────────────────────────────────────────────────────

/// Map [`Modifiers`] bits to `(keysym, keycode)` pairs using the keyboard map.
///
/// Returns only the modifiers that actually have a keycode binding. Unknown modifiers
/// are silently skipped (the key press proceeds without them).
fn modifier_keycodes(modifiers: &Modifiers, map: &KeysymMap) -> Vec<(u32, u8)> {
    // Standard X11 modifier keysyms.
    // Shift_L=0xFFE1, Control_L=0xFFE3, Alt_L=0xFFE9 (Mod1), Super_L=0xFFEB (Mod4).
    let candidates: &[(u32, bool)] = &[
        (0xFFE1, modifiers.contains(Modifiers::SHIFT)), // Shift_L
        (0xFFE3, modifiers.contains(Modifiers::CTRL)),  // Control_L
        (0xFFE9, modifiers.contains(Modifiers::ALT)),   // Alt_L / Meta_L
        (0xFFEB, modifiers.contains(Modifiers::META)),  // Super_L
    ];

    candidates
        .iter()
        .filter(|(_, active)| *active)
        .filter_map(|(ks, _)| map.lookup(*ks).map(|kc| (*ks, kc)))
        .collect()
}

// ── USB HID Usage Page 0x07 → X keysym table ─────────────────────────────

/// Map a USB HID Usage Page 0x07 (keyboard) usage ID to an X11 keysym.
///
/// Returns `None` for unknown / unsupported HID codes; the injector converts `None`
/// to [`sh_input::InputError::Unsupported`] rather than injecting an arbitrary key.
///
/// # Supported subset
///
/// | HID range   | Keys                              |
/// |-------------|-----------------------------------|
/// | 0x04–0x1D   | a–z                               |
/// | 0x1E–0x27   | 1–9, 0                            |
/// | 0x28        | Return / Enter                    |
/// | 0x29        | Escape                            |
/// | 0x2A        | Backspace / Delete                |
/// | 0x2B        | Tab                               |
/// | 0x2C        | Space                             |
/// | 0x2D        | Minus / Hyphen `-`                |
/// | 0x2E        | Equal `=`                         |
/// | 0x2F        | Left bracket `[`                  |
/// | 0x30        | Right bracket `]`                 |
/// | 0x31        | Backslash `\`                     |
/// | 0x33        | Semicolon `;`                     |
/// | 0x34        | Apostrophe `'`                    |
/// | 0x35        | Grave accent `` ` ``              |
/// | 0x36        | Comma `,`                         |
/// | 0x37        | Period `.`                        |
/// | 0x38        | Slash `/`                         |
/// | 0x4F–0x52   | Arrow keys (right/left/down/up)   |
/// | 0xE0–0xE7   | Modifier keys (Shift/Ctrl/Alt/Super left/right) |
///
/// The table intentionally covers the keys most used in remote-desktop sessions.
/// The full HID map is a follow-up item.
#[must_use]
pub(crate) fn hid_to_keysym(hid: u16) -> Option<u32> {
    match hid {
        // a–z: HID 0x04–0x1D → X keysym 0x0061–0x007A ('a'–'z').
        // The X server handles Shift→uppercase via the modifier layer.
        0x04 => Some(0x0061), // a
        0x05 => Some(0x0062), // b
        0x06 => Some(0x0063), // c
        0x07 => Some(0x0064), // d
        0x08 => Some(0x0065), // e
        0x09 => Some(0x0066), // f
        0x0A => Some(0x0067), // g
        0x0B => Some(0x0068), // h
        0x0C => Some(0x0069), // i
        0x0D => Some(0x006A), // j
        0x0E => Some(0x006B), // k
        0x0F => Some(0x006C), // l
        0x10 => Some(0x006D), // m
        0x11 => Some(0x006E), // n
        0x12 => Some(0x006F), // o
        0x13 => Some(0x0070), // p
        0x14 => Some(0x0071), // q
        0x15 => Some(0x0072), // r
        0x16 => Some(0x0073), // s
        0x17 => Some(0x0074), // t
        0x18 => Some(0x0075), // u
        0x19 => Some(0x0076), // v
        0x1A => Some(0x0077), // w
        0x1B => Some(0x0078), // x
        0x1C => Some(0x0079), // y
        0x1D => Some(0x007A), // z

        // 1–9, 0: HID 0x1E–0x27.
        0x1E => Some(0x0031), // 1
        0x1F => Some(0x0032), // 2
        0x20 => Some(0x0033), // 3
        0x21 => Some(0x0034), // 4
        0x22 => Some(0x0035), // 5
        0x23 => Some(0x0036), // 6
        0x24 => Some(0x0037), // 7
        0x25 => Some(0x0038), // 8
        0x26 => Some(0x0039), // 9
        0x27 => Some(0x0030), // 0

        // Common control keys.
        0x28 => Some(0xFF0D), // Return
        0x29 => Some(0xFF1B), // Escape
        0x2A => Some(0xFF08), // BackSpace
        0x2B => Some(0xFF09), // Tab
        0x2C => Some(0x0020), // Space

        // Punctuation (unshifted symbols).
        0x2D => Some(0x002D), // hyphen-minus -
        0x2E => Some(0x003D), // equal =
        0x2F => Some(0x005B), // left bracket [
        0x30 => Some(0x005D), // right bracket ]
        0x31 => Some(0x005C), // backslash \
        0x33 => Some(0x003B), // semicolon ;
        0x34 => Some(0x0027), // apostrophe '
        0x35 => Some(0x0060), // grave accent `
        0x36 => Some(0x002C), // comma ,
        0x37 => Some(0x002E), // period .
        0x38 => Some(0x002F), // slash /

        // Arrow keys.
        0x4F => Some(0xFF53), // Right
        0x50 => Some(0xFF51), // Left
        0x51 => Some(0xFF54), // Down
        0x52 => Some(0xFF52), // Up

        // Function keys F1–F12.
        0x3A => Some(0xFFBE), // F1
        0x3B => Some(0xFFBF), // F2
        0x3C => Some(0xFFC0), // F3
        0x3D => Some(0xFFC1), // F4
        0x3E => Some(0xFFC2), // F5
        0x3F => Some(0xFFC3), // F6
        0x40 => Some(0xFFC4), // F7
        0x41 => Some(0xFFC5), // F8
        0x42 => Some(0xFFC6), // F9
        0x43 => Some(0xFFC7), // F10
        0x44 => Some(0xFFC8), // F11
        0x45 => Some(0xFFC9), // F12

        // Navigation cluster (USB HID Usage Tables §10, page 0x07).
        0x49 => Some(0xFF63), // Insert       (XK_Insert)
        0x4A => Some(0xFF50), // Home         (XK_Home)
        0x4B => Some(0xFF55), // Page_Up      (XK_Page_Up)
        0x4C => Some(0xFFFF), // Delete-forward (XK_Delete)
        0x4D => Some(0xFF57), // End          (XK_End)
        0x4E => Some(0xFF56), // Page_Down    (XK_Page_Down)

        // Modifier keys (HID 0xE0–0xE7) → X keysyms.
        0xE0 => Some(0xFFE3), // Left Control
        0xE1 => Some(0xFFE1), // Left Shift
        0xE2 => Some(0xFFE9), // Left Alt
        0xE3 => Some(0xFFEB), // Left Super / Meta
        0xE4 => Some(0xFFE4), // Right Control
        0xE5 => Some(0xFFE2), // Right Shift
        0xE6 => Some(0xFFEA), // Right Alt
        0xE7 => Some(0xFFEC), // Right Super / Meta

        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use sh_protocol::{EventType, InputEvent, Modifiers};
    use x11rb::wrapper::ConnectionExt as _;

    // ── Pure unit tests (no display required) ─────────────────────────────

    #[test]
    fn hid_to_keysym_a() {
        // HID 0x04 → 'a' (X keysym 0x0061).
        assert_eq!(hid_to_keysym(0x04), Some(0x0061));
    }

    #[test]
    fn build_keysym_entries_rejects_zero_ks_per_kc() {
        // Regression: a hostile/buggy GetKeyboardMapping reply with keysyms_per_keycode = 0 must be
        // a typed error, NOT a `slice::chunks(0)` panic on the first injected key.
        let err = build_keysym_entries(&[], 0, 8, 248);
        assert!(matches!(err, Err(InputError::Backend(_))));
    }

    #[test]
    fn build_keysym_entries_maps_and_bounds_count() {
        // 3 keycodes, 2 keysyms each; keycodes start at min_keycode=8.
        let keysyms = [0x61, 0, 0x62, 0, 0x63, 0];
        let entries = build_keysym_entries(&keysyms, 2, 8, 3).unwrap();
        assert_eq!(entries, vec![(0x61, 8), (0x62, 9), (0x63, 10)]);
        // A surplus keysym list (server appends extra) is bounded to `count` keycodes.
        let surplus = [0x61, 0, 0x62, 0, 0x63, 0, 0x64, 0, 0x65, 0];
        let bounded = build_keysym_entries(&surplus, 2, 8, 3).unwrap();
        assert_eq!(bounded.len(), 3, "scan must stop at `count` keycodes");
    }

    #[test]
    fn hid_to_keysym_z() {
        // HID 0x1D → 'z' (X keysym 0x007A).
        assert_eq!(hid_to_keysym(0x1D), Some(0x007A));
    }

    #[test]
    fn hid_to_keysym_enter() {
        // HID 0x28 → Return (X keysym 0xFF0D).
        assert_eq!(hid_to_keysym(0x28), Some(0xFF0D));
    }

    #[test]
    fn hid_to_keysym_space() {
        // HID 0x2C → Space (X keysym 0x0020).
        assert_eq!(hid_to_keysym(0x2C), Some(0x0020));
    }

    #[test]
    fn hid_to_keysym_escape() {
        assert_eq!(hid_to_keysym(0x29), Some(0xFF1B));
    }

    #[test]
    fn hid_to_keysym_backspace() {
        assert_eq!(hid_to_keysym(0x2A), Some(0xFF08));
    }

    #[test]
    fn hid_to_keysym_arrows() {
        assert_eq!(hid_to_keysym(0x4F), Some(0xFF53)); // Right
        assert_eq!(hid_to_keysym(0x50), Some(0xFF51)); // Left
        assert_eq!(hid_to_keysym(0x51), Some(0xFF54)); // Down
        assert_eq!(hid_to_keysym(0x52), Some(0xFF52)); // Up
    }

    #[test]
    fn hid_to_keysym_navigation_cluster() {
        // USB HID Usage Tables §10 → X keysyms. Regression for the previously-wrong Home/Delete.
        assert_eq!(hid_to_keysym(0x49), Some(0xFF63)); // Insert
        assert_eq!(hid_to_keysym(0x4A), Some(0xFF50)); // Home (was wrongly End)
        assert_eq!(hid_to_keysym(0x4B), Some(0xFF55)); // Page_Up
        assert_eq!(hid_to_keysym(0x4C), Some(0xFFFF)); // Delete-forward (was wrongly BackSpace)
        assert_eq!(hid_to_keysym(0x4D), Some(0xFF57)); // End
        assert_eq!(hid_to_keysym(0x4E), Some(0xFF56)); // Page_Down
    }

    #[test]
    fn hid_to_keysym_digits() {
        // 1–9
        for (hid, expected_ks) in (0x1Eu16..=0x26).zip(0x31u32..=0x39) {
            assert_eq!(hid_to_keysym(hid), Some(expected_ks), "HID 0x{hid:02X}");
        }
        // 0
        assert_eq!(hid_to_keysym(0x27), Some(0x0030));
    }

    #[test]
    fn hid_to_keysym_unknown_returns_none() {
        // 0x00–0x03 are not key codes; 0xFF is undefined.
        assert_eq!(hid_to_keysym(0x00), None);
        assert_eq!(hid_to_keysym(0x03), None);
        assert_eq!(hid_to_keysym(0xFF), None);
    }

    #[test]
    fn no_display_returns_error() {
        // Explicitly bad display must fail-closed.
        let result = XTestInjector::new(Some("INVALID_DISPLAY_STRING"));
        assert!(result.is_err(), "bad display must yield error");
    }

    // ── Display-required integration tests ────────────────────────────────

    fn make_injector() -> XTestInjector {
        XTestInjector::new(None).expect("XTestInjector::new")
    }

    fn pointer_move_event(nx: u16, ny: u16) -> InputEvent {
        InputEvent {
            event_type: EventType::PointerMove,
            modifiers: Modifiers::empty(),
            pointer_x: nx,
            pointer_y: ny,
            button_mask: 0,
            key_code: 0,
            scroll_x: 0,
            scroll_y: 0,
            pressure: 0,
        }
    }

    fn button_event(mask: u8) -> InputEvent {
        InputEvent {
            event_type: EventType::Button,
            modifiers: Modifiers::empty(),
            pointer_x: 0,
            pointer_y: 0,
            button_mask: mask,
            key_code: 0,
            scroll_x: 0,
            scroll_y: 0,
            pressure: 0,
        }
    }

    fn wheel_event(scroll_x: i16, scroll_y: i16) -> InputEvent {
        InputEvent {
            event_type: EventType::Wheel,
            modifiers: Modifiers::empty(),
            pointer_x: 0,
            pointer_y: 0,
            button_mask: 0,
            key_code: 0,
            scroll_x,
            scroll_y,
            pressure: 0,
        }
    }

    fn key_event(hid: u16) -> InputEvent {
        InputEvent {
            event_type: EventType::Key,
            modifiers: Modifiers::empty(),
            pointer_x: 0,
            pointer_y: 0,
            button_mask: 0,
            key_code: hid,
            scroll_x: 0,
            scroll_y: 0,
            pressure: 0,
        }
    }

    /// **Pointer round-trip test** — the strongest integration assertion.
    ///
    /// Injects a [`PointerMove`](EventType::PointerMove) to a known normalized coordinate,
    /// then calls `QueryPointer` to verify the cursor actually moved to the mapped pixel.
    ///
    /// Tolerance: ±1 pixel, because some X servers may apply sub-pixel rounding.
    #[test]
    fn pointer_round_trip() {
        if std::env::var_os("DISPLAY").is_none() {
            return;
        }

        let mut inj = make_injector();
        let (conn, screen_num) = x11rb::connect(None).expect("connect for query_pointer");
        let root = conn.setup().roots[screen_num].root;
        let w = u32::from(conn.setup().roots[screen_num].width_in_pixels);
        let h = u32::from(conn.setup().roots[screen_num].height_in_pixels);

        // Move to normalized (32768, 32768) ≈ midpoint.
        let nx: u16 = 32768;
        let ny: u16 = 32768;
        inj.inject(&pointer_move_event(nx, ny))
            .expect("inject pointer move");

        // Brief sync to let the X server process the event.
        conn.sync().expect("sync");

        let qp = conn
            .query_pointer(root)
            .expect("QueryPointer send")
            .reply()
            .expect("QueryPointer reply");

        // Compute the expected pixel position using the same CoordMapper logic.
        use sh_input::{CoordMapper, TargetRect};
        let mapper = CoordMapper::new(TargetRect::new(0, 0, w, h).unwrap()).unwrap();
        let expected = mapper.map(nx, ny);

        let got_x = i32::from(qp.root_x);
        let got_y = i32::from(qp.root_y);

        assert!(
            (got_x - expected.x).abs() <= 1,
            "pointer X: expected {}, got {} (tolerance ±1)",
            expected.x,
            got_x
        );
        assert!(
            (got_y - expected.y).abs() <= 1,
            "pointer Y: expected {}, got {} (tolerance ±1)",
            expected.y,
            got_y
        );
    }

    #[test]
    fn button_press_and_release_ok() {
        if std::env::var_os("DISPLAY").is_none() {
            return;
        }
        let mut inj = make_injector();
        // Press left button (bit 0).
        inj.inject(&button_event(0x01)).expect("button press");
        // Release left button.
        inj.inject(&button_event(0x00)).expect("button release");
    }

    #[test]
    fn wheel_event_ok() {
        if std::env::var_os("DISPLAY").is_none() {
            return;
        }
        let mut inj = make_injector();
        // Scroll down.
        inj.inject(&wheel_event(0, -8)).expect("wheel down");
        // Scroll up.
        inj.inject(&wheel_event(0, 8)).expect("wheel up");
    }

    #[test]
    fn key_a_ok() {
        if std::env::var_os("DISPLAY").is_none() {
            return;
        }
        let mut inj = make_injector();
        // HID 0x04 = 'a'.
        inj.inject(&key_event(0x04)).expect("key 'a'");
    }

    #[test]
    fn touch_returns_unsupported() {
        if std::env::var_os("DISPLAY").is_none() {
            return;
        }
        let mut inj = make_injector();
        let ev = InputEvent {
            event_type: EventType::Touch,
            modifiers: Modifiers::empty(),
            pointer_x: 0,
            pointer_y: 0,
            button_mask: 0,
            key_code: 0,
            scroll_x: 0,
            scroll_y: 0,
            pressure: 0,
        };
        assert!(
            matches!(inj.inject(&ev), Err(InputError::Unsupported { .. })),
            "Touch must return Unsupported"
        );
    }

    #[test]
    fn unknown_hid_returns_unsupported() {
        if std::env::var_os("DISPLAY").is_none() {
            return;
        }
        let mut inj = make_injector();
        // HID 0x00 is not in the table.
        let ev = key_event(0x00);
        assert!(
            matches!(inj.inject(&ev), Err(InputError::Unsupported { .. })),
            "unknown HID must return Unsupported"
        );
    }
}
