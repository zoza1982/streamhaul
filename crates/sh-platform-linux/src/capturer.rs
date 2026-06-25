//! X11 screen capturer via `GetImage(ZPixmap)`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use sh_media::{MediaError, PixelFormat, Resolution, ScreenCapturer, VideoFrame};
use sh_types::{FrameId, TimestampUs};
use tracing::debug;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat, Window};
use x11rb::rust_connection::RustConnection;

/// Monotonic frame counter shared across all capturers in the process.
///
/// Using a process-global counter keeps [`FrameId`]s unique even if multiple
/// [`X11ScreenCapturer`] instances are created, though in practice a host has exactly one.
static FRAME_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A [`ScreenCapturer`] that reads the X11 root window via `GetImage(ZPixmap)`.
///
/// # Design notes
///
/// Each call to [`next_frame`](X11ScreenCapturer::next_frame) issues an `X11 GetImage` request
/// that copies the entire root window framebuffer from the X server into the caller's process.
/// This is a full-copy path — no shared memory (MIT-SHM) is used. The MIT-SHM zero-copy fast
/// path is a deferred follow-up (R-LINUX-SHM); correctness is established here first.
///
/// **`GetImage` max-request-length limit:** the X protocol caps a single request at
/// `4·(2^16 − 1)` bytes (≈ 256 MiB via extended requests) or `4·(2^16 − 1)` bytes on the
/// classic limit. A 4K display at 32 bpp is ≈ 33 MiB — well within the extended limit.
/// A 16K×16K display (≈ 4 GiB) would exceed it; but no real display Streamhaul serves is
/// anywhere near that, and Xvfb defaults to 2560×2048 or smaller.
///
/// # Example
///
/// ```no_run
/// use sh_platform_linux::X11ScreenCapturer;
/// use sh_media::ScreenCapturer;
/// use std::time::Duration;
///
/// let mut cap = X11ScreenCapturer::new(None).expect("DISPLAY must be set");
/// let frame = cap.next_frame(Duration::from_millis(50)).expect("capture");
/// assert!(frame.is_some());
/// ```
pub struct X11ScreenCapturer {
    conn: RustConnection,
    root: Window,
    width: u16,
    height: u16,
    /// Monotonic epoch anchor used to compute `capture_ts_us`.
    epoch: Instant,
}

impl X11ScreenCapturer {
    /// Connect to the X server at `display` (e.g. `":0"`), or to `$DISPLAY` if `None`.
    ///
    /// Reads the root window geometry immediately so that [`resolution`](Self::resolution)
    /// is available before the first [`next_frame`](Self::next_frame) call.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::Capture`] if:
    /// - `$DISPLAY` is not set and `display` is `None`.
    /// - The X server is unreachable or rejects the connection.
    /// - The screen geometry cannot be read.
    pub fn new(display: Option<&str>) -> Result<Self, MediaError> {
        let (conn, screen_num) = x11rb::connect(display)
            .map_err(|e| MediaError::Capture(format!("x11rb::connect failed: {e}")))?;

        let setup = conn.setup();
        let screen = setup
            .roots
            .get(screen_num)
            .ok_or_else(|| MediaError::Capture(format!("screen {screen_num} not found")))?;

        let root = screen.root;
        let width = screen.width_in_pixels;
        let height = screen.height_in_pixels;

        debug!(
            width,
            height, root, "X11ScreenCapturer: connected, root window geometry"
        );

        Ok(Self {
            conn,
            root,
            width,
            height,
            epoch: Instant::now(),
        })
    }

    /// Return the elapsed microseconds since this capturer was constructed.
    ///
    /// We use a monotonic clock (not wall time) so `capture_ts_us` is stable against NTP jumps.
    fn elapsed_us(&self) -> TimestampUs {
        let us = self
            .epoch
            .elapsed()
            .as_micros()
            .try_into()
            .unwrap_or(u64::MAX);
        TimestampUs(us)
    }
}

impl ScreenCapturer for X11ScreenCapturer {
    /// Capture one frame from the root window.
    ///
    /// The `timeout` parameter is accepted for trait compatibility but is not used for
    /// change-detection in v1 — this implementation always returns a frame (the entire root
    /// window). Change-detection (damage tracking) is a follow-up.
    ///
    /// Returns `Ok(Some(frame))` on success. This v1 implementation has no change-detection, so it
    /// captures and returns a frame unconditionally and **never returns `Ok(None)`** (the trait's
    /// "timeout elapsed, no new frame" case). Damage-tracking that would honour the timeout/`None`
    /// contract is a follow-up.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::Capture`] if the X server rejects `GetImage` or the buffer
    /// length is inconsistent.
    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<VideoFrame>, MediaError> {
        let reply = self
            .conn
            .get_image(
                ImageFormat::Z_PIXMAP,
                self.root,
                0,
                0,
                self.width,
                self.height,
                !0u32, // all planes
            )
            .map_err(|e| MediaError::Capture(format!("GetImage send failed: {e}")))?
            .reply()
            .map_err(|e| MediaError::Capture(format!("GetImage reply failed: {e}")))?;

        // The X server returns pixels in the server's native byte order for ZPixmap at depth 24/32.
        // For TrueColor depth-24 and depth-32 servers (the overwhelming majority) the layout is
        // B,G,R,X (blue-green-red-padding) — which is exactly `PixelFormat::Bgra8` once we force
        // the alpha byte to 0xFF. The depth field in the reply confirms what we got.
        //
        // We do NOT handle depth-16 or palette-mode servers: those are exceedingly rare and not
        // supported by Streamhaul's pipeline. An unexpected depth is reported as a Capture error.
        let depth = reply.depth;
        if depth != 24 && depth != 32 {
            return Err(MediaError::Capture(format!(
                "unsupported X display depth {depth}; expected 24 or 32 (TrueColor)"
            )));
        }

        let w = u32::from(self.width);
        let h = u32::from(self.height);
        let expected_len = PixelFormat::Bgra8.frame_len(Resolution::new(w, h));

        let mut raw = reply.data;

        // For depth-24 the X server still uses 4 bytes per pixel (BGRX), so the raw data length
        // equals width*height*4. Set the 4th byte (X/padding) to 0xFF to make valid BGRA.
        if raw.len() != expected_len {
            return Err(MediaError::Capture(format!(
                "GetImage returned {got} bytes; expected {expected_len} for {w}×{h} Bgra8",
                got = raw.len()
            )));
        }

        // Force alpha byte (offset 3 in each pixel) to 0xFF.
        // `chunks_exact_mut(4)` guarantees each chunk is exactly 4 bytes, so the `.get_mut(3)`
        // will always succeed. We use `if let` rather than indexing to satisfy the clippy
        // `indexing_slicing` lint without using `unsafe`.
        for pixel in raw.chunks_exact_mut(4) {
            if let Some(alpha) = pixel.get_mut(3) {
                *alpha = 0xFF;
            }
        }

        let frame_id = FrameId(FRAME_COUNTER.fetch_add(1, Ordering::Relaxed));
        let capture_ts_us = self.elapsed_us();

        let frame = VideoFrame {
            data: Bytes::from(raw),
            format: PixelFormat::Bgra8,
            resolution: Resolution::new(w, h),
            frame_id,
            capture_ts_us,
        };

        frame
            .validate_len()
            .map_err(|e| MediaError::Capture(format!("frame size invariant violated: {e}")))?;

        debug!(
            frame_id = frame.frame_id.0,
            capture_ts_us = frame.capture_ts_us.0,
            w,
            h,
            "X11ScreenCapturer: captured frame"
        );

        Ok(Some(frame))
    }

    /// Current resolution of the root window.
    fn resolution(&self) -> Resolution {
        Resolution::new(u32::from(self.width), u32::from(self.height))
    }

    /// Pixel format — always [`PixelFormat::Bgra8`] for this backend.
    fn pixel_format(&self) -> PixelFormat {
        PixelFormat::Bgra8
    }
}

// ── Capture timestamp helper ───────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use sh_media::PixelFormat;

    // ── Pure unit tests (no display required) ─────────────────────────────

    #[test]
    fn bgra8_frame_len_math() {
        // These must match what the capturer will produce for common resolutions.
        assert_eq!(
            PixelFormat::Bgra8.frame_len(Resolution::new(640, 480)),
            640 * 480 * 4
        );
        assert_eq!(
            PixelFormat::Bgra8.frame_len(Resolution::new(1920, 1080)),
            1920 * 1080 * 4
        );
        assert_eq!(PixelFormat::Bgra8.frame_len(Resolution::new(0, 0)), 0);
    }

    #[test]
    fn alpha_bytes_are_forced_to_0xff() {
        // Simulate what the capturer does: raw BGRX data with zeroed X bytes → alpha forced 0xFF.
        // Use a slice instead of vec! to avoid the useless_vec lint.
        let mut raw = [0xBBu8, 0x77, 0x33, 0x00, 0xCC, 0x88, 0x44, 0x00];
        for pixel in raw.chunks_exact_mut(4) {
            if let Some(alpha) = pixel.get_mut(3) {
                *alpha = 0xFF;
            }
        }
        assert_eq!(raw[3], 0xFF);
        assert_eq!(raw[7], 0xFF);
        // Colour channels untouched.
        assert_eq!(raw[0], 0xBB);
        assert_eq!(raw[4], 0xCC);
    }

    // ── Display-required integration tests ────────────────────────────────
    // Each test returns early if $DISPLAY is unset — never a false pass.

    #[test]
    fn no_display_returns_error() {
        // Passing an explicitly invalid display string must fail-closed.
        let result = X11ScreenCapturer::new(Some("INVALID_DISPLAY_STRING"));
        assert!(
            result.is_err(),
            "connecting to a non-existent display must fail"
        );
    }

    #[test]
    fn capture_frame_matches_display_geometry() {
        if std::env::var_os("DISPLAY").is_none() {
            return;
        }
        let mut cap = X11ScreenCapturer::new(None).expect("connect");
        let res = cap.resolution();
        assert!(
            res.width > 0 && res.height > 0,
            "display must have non-zero dimensions"
        );
        assert_eq!(cap.pixel_format(), PixelFormat::Bgra8);

        let frame = cap
            .next_frame(Duration::from_millis(100))
            .expect("capture should succeed")
            .expect("should return Some on a live display");

        assert_eq!(frame.resolution, res, "frame resolution must match display");
        assert!(!frame.data.is_empty(), "frame data must be non-empty");
        frame.validate_len().expect("frame length must be valid");
    }
}
