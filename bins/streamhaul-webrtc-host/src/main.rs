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

use anyhow::Context as _;
use streamhaul_webrtc_host::{parse_session_id, BakedFrameSource, HostConfig, StreamMode};
use tracing::{info, warn};

/// Parsed command-line arguments.
struct Args {
    signaling_url: String,
    session_id_hex: String,
    bind: String,
    stream_video: bool,
    frames: usize,
    fps: u32,
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
            source: Box::new(BakedFrameSource::new()),
        }
    } else {
        StreamMode::Echo
    };

    streamhaul_webrtc_host::run_webrtc_host(config, mode).await
}
