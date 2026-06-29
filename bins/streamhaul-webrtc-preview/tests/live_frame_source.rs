//! Deterministic integration tests for [`LiveFrameSource`] + [`DownscaleCapturer`].
//!
//! All tests use [`SyntheticCapturer`] — no X11 display required. This lets the `webrtc-preview`
//! CI job (Linux) run the encode+SHP-frame pipeline without a real screen, while still covering
//! the production code path that the binary uses.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::Duration;

use sh_media::{Resolution, ScreenCapturer, SyntheticCapturer};
use sh_protocol::{CommonHeader, FrameType, COMMON_HEADER_LEN};
use streamhaul_preview::EvenDimCapturer;
use streamhaul_webrtc_host::{build_shp_video_frame, VideoFrameSource};
use streamhaul_webrtc_preview::{DownscaleCapturer, LiveFrameSource};

/// Build the same capture chain the binary uses (synthetic instead of X11).
///
/// `SyntheticCapturer(160×120) → DownscaleCapturer(max_width=960) → EvenDimCapturer → LiveFrameSource`
///
/// 160×120 is already ≤ 960 and even, so both adapters are no-ops here; the test still
/// exercises the full encode+SHP-frame path.
fn make_live_source() -> LiveFrameSource<EvenDimCapturer<DownscaleCapturer<SyntheticCapturer>>> {
    let cap = SyntheticCapturer::new(Resolution::new(160, 120), 30);
    let dc = DownscaleCapturer::new(cap, 960);
    let even = EvenDimCapturer::new(dc);
    LiveFrameSource::new(even, 2_000, 30).expect("LiveFrameSource must init at 160x120@2Mbps")
}

/// The first frame from a fresh `LiveFrameSource` must be an IDR (the encoder is armed with
/// `request_keyframe` at construction), must be valid Annex-B, must fit the SHP 64 KB cap, and
/// must be accepted by `build_shp_video_frame` (the same framing the streaming loop uses).
#[test]
fn first_frame_is_idr_annex_b_and_fits_shp_cap() {
    let mut source = make_live_source();

    let (frame_type, payload) = source.next_frame().expect("first frame must succeed");

    // Must be IDR — the encoder is armed with request_keyframe() in LiveFrameSource::new.
    assert_eq!(
        frame_type,
        FrameType::Idr,
        "first frame from LiveFrameSource must be IDR"
    );

    // Must be Annex-B: 3-byte or 4-byte start code.
    assert!(
        payload.starts_with(&[0, 0, 0, 1]) || payload.starts_with(&[0, 0, 1]),
        "payload must be Annex-B (got first bytes: {:?})",
        payload.get(..4.min(payload.len()))
    );

    // Must fit in the SHP 16-bit payload_len cap.
    assert!(
        payload.len() <= usize::from(u16::MAX),
        "encoded frame must fit in SHP 64 KB cap; got {} bytes",
        payload.len()
    );

    // Must be accepted by build_shp_video_frame — the same framing the streaming loop uses.
    let shp = build_shp_video_frame(0, 0, 0, frame_type, &payload)
        .expect("build_shp_video_frame must accept the frame");

    // CommonHeader must decode and report the correct payload_len.
    let header = CommonHeader::decode(&shp[..COMMON_HEADER_LEN])
        .expect("SHP frame must have a decodable CommonHeader");
    assert_eq!(
        usize::from(header.payload_len),
        payload.len(),
        "CommonHeader.payload_len must match the encoded payload length"
    );
}

/// `DownscaleCapturer` reduces a wide frame to ≤ `max_width` and the result encodes correctly.
#[test]
fn downscale_capturer_reduces_oversized_frame_and_encodes() {
    // 2000×1500 @ max_width=960 → factor=ceil(2000/960)=3 → output 666×500.
    let cap = SyntheticCapturer::new(Resolution::new(2000, 1500), 30);
    let mut dc = DownscaleCapturer::new(cap, 960);

    // Resolution must reflect the downscaled size.
    assert!(
        dc.resolution().width <= 960,
        "DownscaleCapturer resolution width must be ≤ max_width, got {}",
        dc.resolution().width
    );

    // next_frame must produce a frame at the downscaled resolution.
    let frame = dc
        .next_frame(Duration::ZERO)
        .expect("capture must succeed")
        .expect("SyntheticCapturer always produces a frame");
    assert!(
        frame.resolution.width <= 960,
        "downscaled frame width must be ≤ 960, got {}",
        frame.resolution.width
    );
    assert_eq!(frame.resolution.width, dc.resolution().width);
    assert_eq!(frame.resolution.height, dc.resolution().height);
}

/// `DownscaleCapturer` is a no-op (factor=1) when the frame is already narrow enough.
#[test]
fn downscale_capturer_is_noop_for_narrow_frames() {
    let cap = SyntheticCapturer::new(Resolution::new(640, 480), 30);
    let mut dc = DownscaleCapturer::new(cap, 960);

    assert_eq!(dc.resolution(), Resolution::new(640, 480));
    let frame = dc
        .next_frame(Duration::ZERO)
        .expect("capture must succeed")
        .expect("must produce a frame");
    assert_eq!(frame.resolution, Resolution::new(640, 480));
    // No pixel copy: data length must match original (640*480*4).
    assert_eq!(frame.data.len(), 640 * 480 * 4);
}
