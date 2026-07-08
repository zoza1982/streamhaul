//! Thin binary entry point for `streamhaul-webrtc-host`.
//!
//! Parses CLI arguments and delegates to [`streamhaul_webrtc_host::run_webrtc_host`].
//! For the connection + streaming implementation see `src/lib.rs`.
//!
//! # Usage
//!
//! ```text
//! streamhaul-webrtc-host \
//!     --signaling-url ws://127.0.0.1:8765 \
//!     --session-id 00000000000000000000000000000000 \
//!     --bind 127.0.0.1:0
//! ```
//!
//! On startup the binary prints:
//! ```text
//! HOST_DTLS_FP=<64-char-hex>
//! ```
//! to stdout (followed by a newline and flush). Test harnesses should read this line to obtain
//! the fingerprint before sending the signaling URL to the browser.
//!
//! # Security note
//!
//! This binary uses the `insecure-lan` signaling path (`AcceptAll` authenticator), which sends
//! an **empty** identity proof. It is intended for local integration tests **only**. Never
//! connect it to a production signaling server. The identity binding proven here is the
//! **Noise/BindCert ↔ DTLS** layer, which is independent of (and not a substitute for) the
//! signaling-peer authentication (R-SIG-AUTH) deferred on this path.

use std::io::Write as _;

use anyhow::Context as _;
use sh_clipboard::{ClipboardAccess, ClipboardError};
use sh_input::{InputError, InputInjector};
use sh_protocol::InputEvent;
use streamhaul_webrtc_host::{parse_session_id, BakedFrameSource, HostConfig, StreamMode};
use tracing::{info, warn};

/// An [`InputInjector`] that does not touch the OS — it prints a machine-readable `INPUT_INJECTED`
/// line per event to stdout. The workspace `streamhaul-webrtc-host` runs in CI with no display, so
/// it cannot inject for real; this proves browser→host input was received + decoded (the e2e greps
/// for the line). The live `streamhaul-webrtc-preview` binary uses a real X11 injector instead.
#[derive(Default)]
struct StdoutInputLogger {
    count: u64,
}

impl InputInjector for StdoutInputLogger {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        self.count = self.count.saturating_add(1);
        println!(
            "INPUT_INJECTED seq={} type={:?}",
            self.count, event.event_type
        );
        std::io::stdout().flush().ok();
        Ok(())
    }
}

/// A [`ClipboardAccess`] that does not touch the OS — it prints a machine-readable
/// `CLIPBOARD_PASTED` line (byte count only, **never the content** — §7) per applied paste to
/// stdout, and never has anything to offer on a read. Same rationale as [`StdoutInputLogger`]: the
/// CI host is headless, so this proves a browser→host clipboard update was received + decoded +
/// sanitized (the e2e greps for the line) without a real OS clipboard. A real backend is deferred to
/// `sh-platform-*`; a capability-denied session uses `NoopClipboard`.
#[derive(Default)]
struct StdoutClipboardLogger {
    count: u64,
}

impl ClipboardAccess for StdoutClipboardLogger {
    fn get_text(&mut self) -> Result<Option<String>, ClipboardError> {
        Ok(None)
    }

    fn set_text(&mut self, text: &str) -> Result<(), ClipboardError> {
        self.count = self.count.saturating_add(1);
        // §7: byte count only, NEVER the text.
        println!("CLIPBOARD_PASTED seq={} bytes={}", self.count, text.len());
        std::io::stdout().flush().ok();
        Ok(())
    }
}

/// Parsed command-line arguments.
struct Args {
    signaling_url: String,
    session_id_hex: String,
    bind: String,
    stream_video: bool,
    frames: usize,
    fps: u32,
    max_fragment_bytes: usize,
}

impl Args {
    /// Parse flags from [`std::env::args`]: `--signaling-url`, `--session-id`, `--bind`,
    /// `--stream-video`, `--frames`, `--fps`.
    fn parse_from_env() -> anyhow::Result<Self> {
        let mut signaling_url = "ws://127.0.0.1:8765".to_owned();
        let mut session_id_hex = "0".repeat(32);
        // Default to loopback so the local ICE candidate is a concrete, routable address.
        // 0.0.0.0 is rejected by str0m's ICE implementation (`is_valid_ip` rejects unspecified).
        let mut bind = "127.0.0.1:0".to_owned();
        let mut stream_video = false;
        let mut frames: usize = 120;
        let mut fps: u32 = 30;
        // Default to the SHP wire cap; a test can pass a small value to force fragmentation.
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
                "--stream-video" => {
                    stream_video = true;
                }
                "--frames" => {
                    frames = args
                        .next()
                        .context("--frames requires a value")?
                        .parse()
                        .context("--frames must be an integer frame count")?;
                }
                "--fps" => {
                    fps = args
                        .next()
                        .context("--fps requires a value")?
                        .parse()
                        .context("--fps must be an integer")?;
                    anyhow::ensure!(fps > 0, "--fps must be a positive integer (> 0)");
                }
                "--max-fragment-bytes" => {
                    max_fragment_bytes = args
                        .next()
                        .context("--max-fragment-bytes requires a value")?
                        .parse()
                        .context("--max-fragment-bytes must be an integer")?;
                    // Floor at 1 KiB: a value so small that a frame needs > 255 fragments would
                    // drop every frame (silent black stream). 1 KiB is well below the e2e's 4096.
                    anyhow::ensure!(
                        max_fragment_bytes >= 1024,
                        "--max-fragment-bytes must be >= 1024"
                    );
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
            stream_video,
            frames,
            fps,
            max_fragment_bytes,
        })
    }
}

/// Entry point for the streamhaul-webrtc-host binary.
///
/// # Errors
///
/// Returns an error if signaling, the Noise handshake, SDP negotiation, or the DataChannel
/// exchange fails.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let args = Args::parse_from_env()?;
    // CLAUDE.md §7: never log session content. The session ID is equivalent to a meeting
    // code in Stage 2; even a partial prefix leaks pairing material. Log only the
    // signaling URL (non-sensitive routing configuration).
    info!(
        signaling_url = %args.signaling_url,
        "streamhaul-webrtc-host starting"
    );

    let session_id = parse_session_id(&args.session_id_hex)?;
    let config = HostConfig {
        signaling_url: args.signaling_url,
        session_id,
        bind: args.bind,
    };

    let mode = if args.stream_video {
        StreamMode::Video {
            frames: args.frames,
            fps: args.fps,
            max_fragment_bytes: args.max_fragment_bytes,
            source: Box::new(BakedFrameSource::new()),
            input: Box::new(StdoutInputLogger::default()),
            clipboard: Box::new(StdoutClipboardLogger::default()),
        }
    } else {
        StreamMode::Echo
    };

    streamhaul_webrtc_host::run_webrtc_host(config, mode, |fp| {
        // Print HOST_DTLS_FP= in a machine-readable form before blocking on signaling, so
        // test harnesses can parse the fingerprint. Flush immediately so the harness sees
        // the line before we connect.
        println!("HOST_DTLS_FP={fp}");
        use std::io::Write as _;
        std::io::stdout().flush().ok();
    })
    .await
}
