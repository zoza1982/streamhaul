//! GDI screen capturer (Windows).
//!
//! Grabs the **primary monitor** (`SM_CXSCREEN`/`SM_CYSCREEN`, from the `GetDC(NULL)` screen DC at
//! origin `(0,0)`) via `BitBlt(SRCCOPY)` + `GetDIBits` with a top-down 32-bpp `BITMAPINFO`, then
//! repacks into a tightly-packed [`PixelFormat::Bgra8`] [`VideoFrame`] with every pixel's alpha byte
//! forced to 0xFF (the screen surface is opaque). The pointer injector targets the same primary-
//! monitor space (no `VIRTUALDESK`). Full multi-monitor / virtual-desktop capture is R-WIN-DXGI.
//!
//! GDI `BitBlt` copies the framebuffer and works in any interactive Windows session (including
//! GitHub `windows-latest` CI runners) with no per-app permission gate. The DXGI Desktop
//! Duplication zero-copy path is the tracked follow-up (R-WIN-DXGI).
//!
//! # Handle lifetime
//!
//! All GDI handles are managed by [`GdiGuard`], a local RAII wrapper that frees every handle on
//! every return path — early `?`-returns included — so no handle is ever leaked.
//!
//! # Alpha channel
//!
//! GDI `GetDIBits` with `BI_RGB` / 32 bpp leaves the high byte of each pixel undefined. We set
//! it to 0xFF unconditionally before building the [`VideoFrame`].

use std::mem::size_of;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use sh_media::{MediaError, PixelFormat, Resolution, ScreenCapturer, VideoFrame};
use sh_types::{FrameId, TimestampUs};
use tracing::debug;
use winapi::shared::minwindef::LPVOID;
use winapi::shared::windef::{HBITMAP, HDC, HGDIOBJ};
use winapi::um::wingdi::{
    BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDIBits,
    SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, RGBQUAD, SRCCOPY,
};
use winapi::um::winuser::{GetDC, GetSystemMetrics, ReleaseDC, SM_CXSCREEN, SM_CYSCREEN};

/// Process-global monotonic frame counter (unique [`FrameId`]s across capturer instances).
static FRAME_COUNTER: AtomicU64 = AtomicU64::new(0);

/// RAII guard that holds all GDI handles allocated during one [`GdiScreenCapturer::next_frame`]
/// call and releases them (in allocation-reverse order) on drop.
///
/// Ensuring cleanup on every path — including early `?`-returns — without needing to thread
/// through cleanup calls manually. Each field is `None` until the corresponding GDI call
/// succeeds, so drop only frees handles that were actually allocated.
struct GdiGuard {
    /// Screen DC from `GetDC(NULL)`.
    screen_dc: HDC,
    /// Memory-compatible DC.
    mem_dc: Option<HDC>,
    /// Compatible bitmap.
    bmp: Option<HBITMAP>,
    /// The object that was in `mem_dc` before we selected `bmp` in.
    old_obj: Option<HGDIOBJ>,
}

impl GdiGuard {
    fn new(screen_dc: HDC) -> Self {
        Self {
            screen_dc,
            mem_dc: None,
            bmp: None,
            old_obj: None,
        }
    }
}

impl Drop for GdiGuard {
    fn drop(&mut self) {
        // SAFETY: SelectObject, DeleteObject, DeleteDC, and ReleaseDC all require valid (non-null)
        // GDI handles. Each `Option` field is only set to `Some(handle)` immediately after the
        // corresponding Win32 call returns a non-null value, and each handle is dropped at most
        // once here. The deselection must happen before DeleteObject(bmp), and DeleteDC(mem_dc)
        // must happen before ReleaseDC(screen_dc) — the ordering below matches that requirement.
        unsafe {
            if let (Some(mem_dc), Some(old)) = (self.mem_dc, self.old_obj) {
                // Restore the original object so the bitmap is no longer selected before we
                // delete it.
                SelectObject(mem_dc, old);
            }
            if let Some(bmp) = self.bmp {
                DeleteObject(bmp as HGDIOBJ);
            }
            if let Some(mem_dc) = self.mem_dc {
                DeleteDC(mem_dc);
            }
            // ReleaseDC for screen DC — first arg is NULL (whole-screen DC).
            ReleaseDC(null_mut(), self.screen_dc);
        }
    }
}

/// Saturating, sign-safe conversion of a Win32 `c_int` pixel dimension to `u32`.
///
/// `GetSystemMetrics` returns a signed `c_int`; negative or zero pixel counts are impossible in a
/// valid display but we clamp defensively rather than propagate an error for an infallible method.
#[allow(clippy::cast_sign_loss)]
fn dim_to_u32(v: i32) -> u32 {
    if v <= 0 {
        0
    } else {
        v as u32
    }
}

/// A [`ScreenCapturer`] that reads the Windows desktop via classic GDI `BitBlt` + `GetDIBits`.
///
/// Each [`next_frame`](GdiScreenCapturer::next_frame) call allocates a memory DC, BitBlts the
/// screen into it, calls `GetDIBits` to read back tightly-packed 32-bpp BGRA pixels, forces
/// alpha to 0xFF, then frees all GDI handles via RAII before returning the [`VideoFrame`].
///
/// There is no change-detection in v1 (a frame is always returned). The DXGI zero-copy path is
/// the tracked follow-up (R-WIN-DXGI).
pub struct GdiScreenCapturer {
    epoch: Instant,
}

impl GdiScreenCapturer {
    /// Create a capturer for the primary display.
    ///
    /// # Errors
    ///
    /// Always succeeds in the current GDI implementation (no handles are opened at construction
    /// time); the `Result` is retained for trait consistency and to accommodate future backends
    /// (e.g. DXGI, R-WIN-DXGI) that may fail at construction.
    pub fn new() -> Result<Self, MediaError> {
        Ok(Self {
            epoch: Instant::now(),
        })
    }

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

impl ScreenCapturer for GdiScreenCapturer {
    /// Capture one frame from the Windows desktop via GDI.
    ///
    /// The `timeout` parameter is accepted for trait compatibility but unused: this v1 has no
    /// change-detection, so it captures and returns a frame unconditionally and **never returns
    /// `Ok(None)`**.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::Capture`] if any Win32 call fails (screen DC unavailable, memory DC
    /// or bitmap creation failed, `BitBlt` failed, `GetDIBits` returned zero scan lines, or any
    /// dimension is zero or would overflow).
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<VideoFrame>, MediaError> {
        // SAFETY: GetDC(NULL) returns the screen DC. NULL is a valid argument for the screen case; we
        // BitBlt only the primary-monitor rect (SM_CXSCREEN/SM_CYSCREEN from origin). The return is
        // checked for null before use.
        let screen_dc = unsafe { GetDC(null_mut()) };
        if screen_dc.is_null() {
            return Err(MediaError::Capture(
                "GetDC(NULL) failed: could not obtain the screen DC".to_string(),
            ));
        }

        // GdiGuard takes ownership of screen_dc immediately; all subsequent `?`-returns will
        // release it via Drop.
        let mut guard = GdiGuard::new(screen_dc);

        // Pixel dimensions of the primary monitor. GetSystemMetrics returns c_int (signed); we
        // validate they are strictly positive before casting.
        // SAFETY: GetSystemMetrics is safe to call at any time; SM_CXSCREEN/SM_CYSCREEN are valid
        // constants returning the primary display width and height in pixels.
        let raw_w = unsafe { GetSystemMetrics(SM_CXSCREEN) };
        let raw_h = unsafe { GetSystemMetrics(SM_CYSCREEN) };
        if raw_w <= 0 || raw_h <= 0 {
            return Err(MediaError::Capture(format!(
                "GetSystemMetrics returned non-positive dimensions: {raw_w}×{raw_h}"
            )));
        }
        // Both values are strictly positive i32 at this point; the cast to i32 for Win32 calls
        // and to u32/usize for buffer arithmetic are both safe within these bounds.
        let width = raw_w as u32;
        let height = raw_h as u32;
        let w_i32 = raw_w; // already i32
        let h_i32 = raw_h;

        // SAFETY: CreateCompatibleDC requires a valid (non-null) HDC; screen_dc was validated
        // above. The returned DC is null on failure (we check below).
        let mem_dc = unsafe { CreateCompatibleDC(screen_dc) };
        if mem_dc.is_null() {
            return Err(MediaError::Capture("CreateCompatibleDC failed".to_string()));
        }
        guard.mem_dc = Some(mem_dc);

        // SAFETY: CreateCompatibleBitmap requires a valid DC and positive dimensions (both
        // checked above). Returns null on failure.
        let bmp = unsafe { CreateCompatibleBitmap(screen_dc, w_i32, h_i32) };
        if bmp.is_null() {
            return Err(MediaError::Capture(
                "CreateCompatibleBitmap failed".to_string(),
            ));
        }
        guard.bmp = Some(bmp);

        // SAFETY: SelectObject requires a valid DC and a valid HGDIOBJ; both are non-null here.
        // We must save the old object (returned by SelectObject) so that we can restore it before
        // deleting the bitmap — deleting a selected object is UB under Win32.
        let old_obj = unsafe { SelectObject(mem_dc, bmp as HGDIOBJ) };
        if old_obj.is_null() {
            return Err(MediaError::Capture(
                "SelectObject failed to select the bitmap into the memory DC".to_string(),
            ));
        }
        guard.old_obj = Some(old_obj);

        // SAFETY: BitBlt copies pixels from screen_dc (the validated screen DC) into mem_dc (a
        // compatible DC with the bitmap selected). Both DCs are non-null, the dimensions are
        // validated, SRCCOPY is a valid raster operation. Returns 0 on failure.
        let blt_ok = unsafe {
            BitBlt(
                mem_dc, 0,     // dest x
                0,     // dest y
                w_i32, // dest width
                h_i32, // dest height
                screen_dc, 0, // src x
                0, // src y
                SRCCOPY,
            )
        };
        if blt_ok == 0 {
            return Err(MediaError::Capture("BitBlt(SRCCOPY) failed".to_string()));
        }

        // GetDIBits requires the source bitmap to be **NOT selected into any DC** (Win32 contract —
        // calling it while selected is undefined and yields garbage/zero scanlines on some drivers).
        // Deselect `bmp` now (restoring `mem_dc`'s original object) BEFORE GetDIBits, and clear
        // `guard.old_obj` so the guard's Drop does not try to deselect a second time. The guard still
        // owns `bmp` (for DeleteObject) and `mem_dc` (for DeleteDC).
        // SAFETY: `mem_dc` and `old_obj` are both valid non-null handles obtained above; restoring the
        // saved original object into the DC is the documented teardown step.
        unsafe {
            SelectObject(mem_dc, old_obj);
        }
        guard.old_obj = None;

        // Prepare a BITMAPINFO for a top-down (negative biHeight) 32-bpp BI_RGB DIB. The
        // negative height tells GetDIBits to write pixels in top-down order (row 0 = topmost),
        // which is what we want for a direct BGRA frame. Stride = width * 4 (DWORD-aligned for
        // 32 bpp, always, since 4 bytes per pixel is already DWORD-aligned).
        //
        // biHeight is LONG (i32); we checked raw_h > 0 and raw_h <= i32::MAX (trivially, as it
        // came from GetSystemMetrics as i32), so negating with wrapping arithmetic is safe: the
        // value stays in [i32::MIN+1, -1].
        let neg_h = raw_h.wrapping_neg();
        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w_i32,
                biHeight: neg_h, // negative → top-down
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                biSizeImage: 0, // may be 0 for BI_RGB
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [RGBQUAD {
                rgbBlue: 0,
                rgbGreen: 0,
                rgbRed: 0,
                rgbReserved: 0,
            }],
        };

        // Allocate the pixel buffer: width * height * 4 bytes (stride is exactly width*4 for
        // 32-bpp BI_RGB top-down DIBs — DWORD-aligned trivially).
        let row_bytes = (width as usize)
            .checked_mul(4)
            .ok_or_else(|| MediaError::Capture("capture width * 4 overflowed usize".to_string()))?;
        let buf_len = row_bytes.checked_mul(height as usize).ok_or_else(|| {
            MediaError::Capture("capture buffer size (w*h*4) overflowed usize".to_string())
        })?;
        let mut pixels = vec![0u8; buf_len];

        // SAFETY: GetDIBits reads scanlines from the bitmap into `pixels`. Requirements:
        //   - `mem_dc` is a valid, non-null DC and `bmp` is NOT selected into it (deselected above,
        //     per the GetDIBits contract).
        //   - `bmp` is a valid, non-null HBITMAP.
        //   - `0` start scanline and `height` scan line count span the whole bitmap.
        //   - `pixels.as_mut_ptr()` is a valid pointer to a buffer of exactly `buf_len` bytes.
        //   - `buf_len` was computed as `width * height * 4`, matching the BITMAPINFO we provide.
        //   - `&mut bmi as LPBITMAPINFO` points to a validly initialized BITMAPINFO on the stack.
        //   - `DIB_RGB_COLORS` is the correct usage flag for an RGB (non-palette) DIB.
        // Returns the number of scan lines written; 0 indicates failure.
        let lines = unsafe {
            GetDIBits(
                mem_dc,
                bmp,
                0,      // start scan line
                height, // number of scan lines
                pixels.as_mut_ptr() as LPVOID,
                &mut bmi,
                DIB_RGB_COLORS,
            )
        };
        if lines == 0 {
            return Err(MediaError::Capture(
                "GetDIBits returned 0 scan lines".to_string(),
            ));
        }
        // Reject a partial read: GetDIBits returns the number of scan lines actually copied. If it
        // is short of `height`, the tail rows of `pixels` are still zero-initialized and the frame
        // would pass validate_len() with a black band — deliver a typed error instead. (`lines > 0`
        // here and `height ≤ i32::MAX`, so the cast cannot wrap.)
        if u32::try_from(lines).unwrap_or(0) != height {
            return Err(MediaError::Capture(format!(
                "GetDIBits copied {lines} scan lines; expected {height}"
            )));
        }

        // Force the alpha byte (index 3 in each BGRA pixel) to 0xFF. GDI leaves the fourth byte
        // undefined for BI_RGB / 32 bpp; the screen is always opaque.
        for px in pixels.chunks_exact_mut(4) {
            // SAFETY: chunks_exact_mut(4) yields exactly-4-byte slices; index 3 is always valid.
            if let Some(a) = px.get_mut(3) {
                *a = 0xFF;
            }
        }

        // `width`/`height` are already `u32` (validated strictly-positive from GetSystemMetrics).
        let (w, h) = (width, height);

        // Guard drop (releasing all GDI handles) happens here, before we build the frame.
        drop(guard);

        let frame = VideoFrame {
            data: Bytes::from(pixels),
            format: PixelFormat::Bgra8,
            resolution: Resolution::new(w, h),
            frame_id: FrameId(FRAME_COUNTER.fetch_add(1, Ordering::Relaxed)),
            capture_ts_us: self.elapsed_us(),
        };
        debug!(w, h, "GdiScreenCapturer: captured frame");
        frame.validate_len()?;
        Ok(Some(frame))
    }

    fn resolution(&self) -> Resolution {
        // Pixel dimensions of the primary monitor. The trait method is infallible, so on a
        // physically-impossible zero or negative dimension we fall back to 0 (a degenerate-but-
        // valid resolution) rather than erroring.
        //
        // SAFETY: GetSystemMetrics is safe to call at any time; SM_CXSCREEN/SM_CYSCREEN are
        // valid constants. No pointer indirection occurs.
        let w = dim_to_u32(unsafe { GetSystemMetrics(SM_CXSCREEN) });
        let h = dim_to_u32(unsafe { GetSystemMetrics(SM_CYSCREEN) });
        Resolution::new(w, h)
    }

    fn pixel_format(&self) -> PixelFormat {
        PixelFormat::Bgra8
    }
}

// Windows runtime smoke tests. These run on the `windows-latest` CI runner, which provides an
// interactive desktop. Construct the capturer, call `next_frame`, and assert that:
//   - construction does not panic,
//   - `pixel_format()` and `resolution()` do not panic,
//   - `next_frame` does not panic and, if it returns a `Some` frame, the frame passes
//     `validate_len()`.
// We do not assert that a frame *is* returned (though on an interactive runner it should be),
// nor do we inspect pixel content (we never log screen data — ADR-0027 §Security).
#[cfg(all(test, target_os = "windows"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod win_tests {
    use super::*;

    #[test]
    fn constructs_and_next_frame_is_panic_free() {
        let mut cap = GdiScreenCapturer::new().expect("construct GdiScreenCapturer");
        assert_eq!(cap.pixel_format(), PixelFormat::Bgra8);
        let _ = cap.resolution(); // must not panic
                                  // On the interactive CI desktop GetDC(NULL) succeeds and a frame is returned; headless
                                  // environments may return Err. Both outcomes are accepted — we only assert no panic.
        if let Ok(Some(frame)) = cap.next_frame(Duration::from_millis(0)) {
            frame.validate_len().unwrap();
        }
    }
}
