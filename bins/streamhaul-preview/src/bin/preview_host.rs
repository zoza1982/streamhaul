#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `streamhaul-preview-host` — stream the **real screen** as OpenH264 video over QUIC (ADR-0030).
//!
//! Binds a QUIC server, waits for a client, captures the screen (X11 on Linux; synthetic elsewhere
//! or with `--synthetic`), OpenH264-encodes it, and streams it. Prints `PREVIEW_HOST_ADDR=<addr>` on
//! startup so a harness can read the bound port.
//!
//! Example: `streamhaul-preview-host --bind 0.0.0.0:7878 --frames 300 --fps 30 --bitrate-kbps 8000`
//!
//! **Preview / non-distribution:** links a software H.264 encoder (licensing-gated; ADR-0028/0029).

use std::io::Write as _;
use std::net::SocketAddr;
use std::time::Instant;

use anyhow::Context as _;
use clap::Parser;
use sh_media::{Resolution, ScreenCapturer};

/// Streamhaul preview host (sends real-screen OpenH264 video over QUIC).
#[derive(Debug, Parser)]
#[command(about, long_about = None)]
struct Args {
    /// Address to bind the QUIC server to.
    #[arg(long, default_value = "0.0.0.0:7878")]
    bind: SocketAddr,
    /// Number of frames to capture and stream.
    #[arg(long, default_value_t = 300)]
    frames: usize,
    /// Frames per second (capture cadence / pacing hint / encoder target).
    #[arg(long, default_value_t = 30)]
    fps: u32,
    /// Target video bitrate in kbps (fed to the OpenH264 rate controller).
    #[arg(long, default_value_t = 8_000)]
    bitrate_kbps: u32,
    /// Use the synthetic capturer instead of the real screen (no display needed).
    #[arg(long)]
    synthetic: bool,
    /// Synthetic capture width (only with `--synthetic`).
    #[arg(long, default_value_t = 1280)]
    width: u32,
    /// Synthetic capture height (only with `--synthetic`).
    #[arg(long, default_value_t = 720)]
    height: u32,
    /// Send as fast as the link allows instead of pacing to `--fps`.
    #[arg(long)]
    no_pace: bool,
}

#[cfg(target_os = "linux")]
fn real_capturer() -> anyhow::Result<Box<dyn ScreenCapturer>> {
    let cap = sh_platform_linux::X11ScreenCapturer::new(None)
        .context("connect to $DISPLAY for X11 screen capture (set --synthetic to skip)")?;
    Ok(Box::new(streamhaul_preview::EvenDimCapturer::new(cap)))
}

#[cfg(not(target_os = "linux"))]
fn real_capturer() -> anyhow::Result<Box<dyn ScreenCapturer>> {
    anyhow::bail!("real screen capture is implemented only for Linux/X11 — re-run with --synthetic")
}

/// Entry point for the `streamhaul-preview-host` binary.
///
/// # Errors
/// Returns any capture, transport, or encode error encountered during startup or streaming.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let ack = sh_transport::InsecureLanLab::i_understand_this_skips_tls_verification();
    let server_config = sh_transport::self_signed_server_config(ack)
        .context("failed to create server TLS config")?;
    let server_ep = sh_transport::ServerEndpoint::bind(args.bind, server_config)
        .context("failed to bind server endpoint")?;
    let local = server_ep.local_addr().context("failed to get local addr")?;

    // Build the capturer BEFORE the readiness signal so a capture-init failure (e.g. no $DISPLAY)
    // surfaces as the real error instead of a later client connect failure. The synthetic capturer
    // is also wrapped in EvenDimCapturer so odd dimensions are cropped on both paths (single
    // "even before the encoder" invariant).
    let mut capturer: Box<dyn ScreenCapturer> = if args.synthetic {
        Box::new(streamhaul_preview::EvenDimCapturer::new(
            sh_media::SyntheticCapturer::new(Resolution::new(args.width, args.height), args.fps),
        ))
    } else {
        real_capturer()?
    };
    let res = capturer.resolution();

    // Machine-readable readiness line (harnesses parse this), then a human summary.
    println!("PREVIEW_HOST_ADDR={local}");
    std::io::stdout().flush().ok();
    println!(
        "streamhaul-preview-host listening on {local} — {}x{} @ {} fps, {} kbps, {} frames ({})",
        res.width,
        res.height,
        args.fps,
        args.bitrate_kbps,
        args.frames,
        if args.synthetic {
            "synthetic"
        } else {
            "screen"
        },
    );

    let conn = server_ep
        .accept()
        .await
        .context("failed to accept connection")?;
    println!("client connected from {}", conn.remote_address());

    let started = Instant::now();
    let send_times = streamhaul_preview::serve(
        &conn,
        capturer.as_mut(),
        args.bitrate_kbps,
        args.frames,
        args.fps,
        !args.no_pace,
    )
    .await
    .context("preview host pipeline failed")?;
    let elapsed = started.elapsed();

    // Brief drain so the last in-flight datagrams reach the client before we drop the connection.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    println!("--- preview host report ---");
    println!("  frames encoded+sent: {}", send_times.len());
    println!("  duration:            {:.2} s", elapsed.as_secs_f64());
    println!(
        "  quic rtt:            {:.1} ms",
        conn.rtt().as_secs_f64() * 1000.0
    );
    Ok(())
}
