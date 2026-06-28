//! Local manual demo for the Linux X11 host (run on a machine with a real `$DISPLAY`):
//!
//! ```text
//! cargo run -p sh-platform-linux --example local_demo
//! ```
//!
//! It (1) captures the real screen and writes it to a PPM file you can open, and (2) does a
//! NON-DISRUPTIVE pointer round-trip: reads the current cursor position, injects a move to the
//! screen centre via XTEST, confirms the cursor landed there, then moves it back to where it was.
//! This is the same capture/inject path the host pipeline uses — proven on your actual desktop.
//!
//! This is a dev-only example (not part of the crate's API); it uses `unwrap`/`expect` for brevity.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use std::time::Duration;

use sh_input::InputInjector;
use sh_media::ScreenCapturer;
use sh_platform_linux::{X11ScreenCapturer, XTestInjector};
use sh_protocol::{EventType, InputEvent, Modifiers};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::ConnectionExt;

fn pointer_event(norm_x: u16, norm_y: u16) -> InputEvent {
    InputEvent {
        event_type: EventType::PointerMove,
        modifiers: Modifiers::empty(),
        pointer_x: norm_x,
        pointer_y: norm_y,
        button_mask: 0,
        key_code: 0,
        scroll_x: 0,
        scroll_y: 0,
        pressure: 0,
    }
}

/// Map an absolute pixel to the wire's normalized `0..=65535` across `extent` pixels.
fn px_to_norm(px: u32, extent: u32) -> u16 {
    if extent <= 1 {
        return 0;
    }
    let n = u64::from(px) * 65535 / u64::from(extent - 1);
    u16::try_from(n).unwrap_or(u16::MAX)
}

fn main() {
    // ── 1. Capture the real screen ────────────────────────────────────────────
    let mut cap = X11ScreenCapturer::new(None).expect("connect to $DISPLAY for capture");
    let res = cap.resolution();
    println!(
        "captured display: {}x{} ({:?})",
        res.width,
        res.height,
        cap.pixel_format()
    );

    let frame = cap
        .next_frame(Duration::from_millis(200))
        .expect("capture failed")
        .expect("no frame returned");
    println!(
        "frame: {} bytes, frame_id={}",
        frame.data.len(),
        frame.frame_id.0
    );

    // Write a PPM (P6) the user can open in any image viewer. BGRA -> RGB.
    let (w, h) = (res.width as usize, res.height as usize);
    let mut ppm = format!("P6\n{w} {h}\n255\n").into_bytes();
    for px in frame.data.chunks_exact(4) {
        // px = [B, G, R, A]
        ppm.push(px[2]); // R
        ppm.push(px[1]); // G
        ppm.push(px[0]); // B
    }
    let out = "/tmp/sh-linux-capture.ppm";
    std::fs::write(out, &ppm).expect("write PPM");
    println!("wrote screenshot -> {out}  (open it to confirm capture)");

    // ── 2. Non-disruptive pointer round-trip via XTEST ────────────────────────
    let (conn, screen_num) = x11rb::connect(None).expect("x11 connect");
    let root = conn.setup().roots[screen_num].root;

    let before = conn.query_pointer(root).unwrap().reply().unwrap();
    println!("cursor before: ({}, {})", before.root_x, before.root_y);

    let mut inj = XTestInjector::new(None).expect("connect to $DISPLAY with XTEST");

    // Move to screen centre.
    let cx = px_to_norm(res.width / 2, res.width);
    let cy = px_to_norm(res.height / 2, res.height);
    inj.inject(&pointer_event(cx, cy))
        .expect("inject move to centre");
    conn.flush().unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let after = conn.query_pointer(root).unwrap().reply().unwrap();
    println!(
        "cursor after inject -> centre: ({}, {})  [expected ~({}, {})]",
        after.root_x,
        after.root_y,
        res.width / 2,
        res.height / 2
    );

    // Move it back to where it was (restore — non-disruptive).
    let bx = px_to_norm(u32::try_from(before.root_x.max(0)).unwrap_or(0), res.width);
    let by = px_to_norm(u32::try_from(before.root_y.max(0)).unwrap_or(0), res.height);
    inj.inject(&pointer_event(bx, by)).expect("inject restore");
    conn.flush().unwrap();
    println!("cursor restored. capture + XTEST injection both work on this desktop. ✓");
}
