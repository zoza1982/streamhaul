//! Binary entry point for `streamhaul-webrtc-preview` (ADR-0032).
//!
//! Captures the real X11 screen (Linux only), encodes with OpenH264 via [`LiveFrameSource`], and
//! streams over the identity-bound WebRTC DataChannel, reusing all connection logic from the
//! `streamhaul-webrtc-host` library.
//!
//! # Usage
//!
//! ```text
//! streamhaul-webrtc-preview \
//!     --signaling-url ws://127.0.0.1:8765 \
//!     --session-id 00000000000000000000000000000000 \
//!     --bind 127.0.0.1:0 \
//!     [--max-width 960] [--bitrate-kbps 4000] [--fps 30] [--frames 120]
//! ```
//!
//! Prints `HOST_DTLS_FP=<hex>` on startup (same as `streamhaul-webrtc-host`).
//!
//! # Platform support
//!
//! Linux only (X11 capture via `sh-platform-linux`). On other platforms the binary
//! exits with a clear error.
//!
//! # Security note
//!
//! Uses the `insecure-lan` signaling path — for local development only. Never connect to a
//! production signaling server. See `streamhaul-webrtc-host` docs for the full security note.

use anyhow::Context as _;
use streamhaul_webrtc_host::{parse_session_id, HostConfig, StreamMode};
use tracing::{info, warn};

/// Parsed CLI arguments.
struct Args {
    signaling_url: String,
    session_id_hex: String,
    bind: String,
    /// Maximum output width in pixels; frames wider than this are downscaled.
    max_width: u32,
    /// Target encode bitrate in kbps.
    bitrate_kbps: u32,
    /// Target frame rate.
    fps: u32,
    /// Total number of SHP video frames to send before exiting.
    frames: usize,
    /// Maximum bytes per SHP fragment (frames larger than this are fragmented; ADR-0033).
    max_fragment_bytes: usize,
}

impl Args {
    fn parse_from_env() -> anyhow::Result<Self> {
        let mut signaling_url = "ws://127.0.0.1:8765".to_owned();
        let mut session_id_hex = "0".repeat(32);
        let mut bind = "127.0.0.1:0".to_owned();
        // Default to 4K: SHP fragmentation (ADR-0033) removed the 64 KiB per-frame cap, so typical
        // displays now stream at full resolution. `--max-width` remains a bandwidth/CPU knob.
        let mut max_width: u32 = 3840;
        let mut bitrate_kbps: u32 = 4_000;
        let mut fps: u32 = 30;
        // Stream until the browser disconnects (a real remote-desktop session, not a fixed clip).
        // The send loop exits cleanly on peer close; `--frames N` caps it for tests/demos.
        let mut frames: usize = usize::MAX;
        // Default to the SHP wire cap; the encoder's frames are fragmented to fit.
        let mut max_fragment_bytes: usize = usize::from(u16::MAX);

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--signaling-url" => {
                    signaling_url = args.next().context("--signaling-url requires a value")?;
                }
                "--session-id" => {
                    session_id_hex = args.next().context("--session-id requires a value")?;
                }
                "--bind" => {
                    bind = args.next().context("--bind requires a value")?;
                }
                "--max-width" => {
                    max_width = args
                        .next()
                        .context("--max-width requires a value")?
                        .parse()
                        .context("--max-width must be a positive integer")?;
                    anyhow::ensure!(max_width > 0, "--max-width must be > 0");
                }
                "--bitrate-kbps" => {
                    bitrate_kbps = args
                        .next()
                        .context("--bitrate-kbps requires a value")?
                        .parse()
                        .context("--bitrate-kbps must be a positive integer")?;
                    anyhow::ensure!(bitrate_kbps > 0, "--bitrate-kbps must be > 0");
                }
                "--fps" => {
                    fps = args
                        .next()
                        .context("--fps requires a value")?
                        .parse()
                        .context("--fps must be a positive integer")?;
                    anyhow::ensure!(fps > 0, "--fps must be > 0");
                }
                "--max-fragment-bytes" => {
                    max_fragment_bytes = args
                        .next()
                        .context("--max-fragment-bytes requires a value")?
                        .parse()
                        .context("--max-fragment-bytes must be an integer")?;
                    // Floor at 1 KiB (see streamhaul-webrtc-host): a tiny value would need > 255
                    // fragments per frame and drop every frame.
                    anyhow::ensure!(
                        max_fragment_bytes >= 1024,
                        "--max-fragment-bytes must be >= 1024"
                    );
                }
                "--frames" => {
                    frames = args
                        .next()
                        .context("--frames requires a value")?
                        .parse()
                        .context("--frames must be a positive integer")?;
                }
                other => {
                    warn!(flag = other, "unknown flag (ignored)");
                }
            }
        }

        Ok(Self {
            signaling_url,
            session_id_hex,
            bind,
            max_width,
            bitrate_kbps,
            fps,
            frames,
            max_fragment_bytes,
        })
    }
}

/// Entry point.
///
/// # Errors
///
/// Returns an error on non-Linux platforms, or if the WebRTC connection / capture / encode fails.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let args = Args::parse_from_env()?;
    // CLAUDE.md §7: never log session content (session ID is pairing material).
    info!(
        signaling_url = %args.signaling_url,
        "streamhaul-webrtc-preview starting"
    );

    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!(
            "streamhaul-webrtc-preview only supports Linux (X11 capture via sh-platform-linux). \
             On macOS use sh-platform-mac; on Windows use sh-platform-win (not yet wired)."
        );
    }

    #[cfg(target_os = "linux")]
    run_linux(args).await
}

/// Linux-specific execution path: build the X11 capture chain and run the WebRTC host.
#[cfg(target_os = "linux")]
async fn run_linux(args: Args) -> anyhow::Result<()> {
    use sh_platform_linux::{X11ScreenCapturer, XTestInjector};
    use streamhaul_preview::EvenDimCapturer;
    use streamhaul_webrtc_host::run_webrtc_host;
    use streamhaul_webrtc_preview::{DownscaleCapturer, LiveFrameSource};

    let session_id = parse_session_id(&args.session_id_hex)?;
    let config = HostConfig {
        signaling_url: args.signaling_url,
        session_id,
        bind: args.bind,
    };

    // Build the capture chain:
    //   X11ScreenCapturer → DownscaleCapturer (≤ max_width px wide) → EvenDimCapturer → LiveFrameSource
    //
    // DownscaleCapturer: an OPTIONAL bandwidth/CPU knob. ADR-0033 SHP fragmentation removed the
    //   64 KiB-per-frame correctness requirement, so this no longer caps resolution (default
    //   max_width=3840 / 4K passes typical displays through). Lower --max-width to save bandwidth.
    //   Factor = ceil(screen_width / max_width), so a 1920-wide screen at max_width=960 → factor 2.
    //
    // EvenDimCapturer: satisfies OpenH264's 4:2:0 chroma requirement for even dimensions.
    //   Reused from ADR-0030 (streamhaul_preview::EvenDimCapturer).
    let x11 = X11ScreenCapturer::new(None).context("failed to connect to X11 display")?;
    let downscaled = DownscaleCapturer::new(x11, args.max_width);
    let even = EvenDimCapturer::new(downscaled);
    let live_source = LiveFrameSource::new(even, args.bitrate_kbps, args.fps)
        .context("failed to create live frame source")?;

    // Real remote control: inject the browser's keyboard/mouse into the live X11 session via XTEST
    // (ADR-0034). This is what makes the preview an actual remote desktop, not just a viewer.
    let injector =
        XTestInjector::new(None).context("failed to open X11 XTEST for input injection")?;

    info!(
        max_width = args.max_width,
        bitrate_kbps = args.bitrate_kbps,
        fps = args.fps,
        frames = args.frames,
        "capture chain ready — connecting to signaling"
    );

    let mode = StreamMode::Video {
        frames: args.frames,
        fps: args.fps,
        max_fragment_bytes: args.max_fragment_bytes,
        source: Box::new(live_source),
        input: Box::new(injector),
    };

    run_webrtc_host(config, mode, |fp| {
        // Print HOST_DTLS_FP= before blocking on signaling so test harnesses can parse it.
        println!("HOST_DTLS_FP={fp}");
        use std::io::Write as _;
        std::io::stdout().flush().ok();
    })
    .await
}
