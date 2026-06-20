//! streamhaul-host — synthetic host agent for LAN/WiFi testing.
//!
//! Binds a QUIC server, waits for a client, then streams `--frames` synthetic raw-encoded frames and
//! prints a throughput/RTT report. The capture→encode→fragment→send pipeline is orchestrated by
//! [`sh_core::run_host_pipeline`].
//!
//! Example: `streamhaul-host --bind 0.0.0.0:7878 --width 320 --height 180 --fps 30 --frames 300`

use std::net::SocketAddr;
use std::time::Instant;

use anyhow::Context as _;
use clap::Parser;

/// Synthetic Streamhaul host (sends video over QUIC).
#[derive(Debug, Parser)]
#[command(about, long_about = None)]
struct Args {
    /// Address to bind the QUIC server to.
    #[arg(long, default_value = "0.0.0.0:7878")]
    bind: SocketAddr,
    /// Frame width in pixels.
    #[arg(long, default_value_t = 320)]
    width: u32,
    /// Frame height in pixels.
    #[arg(long, default_value_t = 180)]
    height: u32,
    /// Frames per second (capture cadence / pacing hint).
    #[arg(long, default_value_t = 30)]
    fps: u32,
    /// Number of frames to stream.
    #[arg(long, default_value_t = 300)]
    frames: usize,
    /// Blast all frames as fast as the link allows instead of pacing to `--fps`.
    ///
    /// Pacing (the default) matches real streaming cadence and lets the receiver keep up. Blasting
    /// measures peak throughput but, for small frames, can overrun the receiver before it drains.
    #[arg(long)]
    no_pace: bool,
}

/// Entry point for the streamhaul-host binary.
///
/// # Errors
/// Returns any I/O or transport error encountered during startup or streaming.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let ack = sh_transport::InsecureLanLab::i_understand_this_skips_tls_verification();
    let server_config = sh_transport::self_signed_server_config(ack)
        .context("failed to create server TLS config")?;
    let server_ep = sh_transport::ServerEndpoint::bind(args.bind, server_config)
        .context("failed to bind server endpoint")?;
    let local = server_ep.local_addr().context("failed to get local addr")?;
    println!(
        "streamhaul-host listening on {local} ({}x{} @ {} fps, {} frames)",
        args.width, args.height, args.fps, args.frames
    );

    let conn = server_ep
        .accept()
        .await
        .context("failed to accept connection")?;
    println!("client connected from {}", conn.remote_address());

    let resolution = sh_media::Resolution::new(args.width, args.height);
    let mut capturer = sh_media::SyntheticCapturer::new(resolution, args.fps);
    let mut encoder = sh_codec_hw::RawEncoder::new();
    let params = sh_core::HostPipelineParams {
        frame_count: args.frames,
        fps: args.fps,
        pace_frames: !args.no_pace,
    };

    let started = Instant::now();
    let send_times = sh_core::run_host_pipeline(&conn, &mut capturer, &mut encoder, &params)
        .await
        .context("host pipeline failed")?;
    let elapsed = started.elapsed();

    // Brief drain so the last in-flight datagrams reach the client before we drop the connection
    // (the bins have no client-done back-channel; the loopback harness uses one instead).
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    // Payload bytes ≈ frames × width × height × 4 (BGRA). Excludes the raw codec's 10-byte per-frame
    // header and per-datagram SHP/QUIC header overhead; rewrite when real (compressed) codecs land.
    let frame_bytes = u64::from(args.width)
        .saturating_mul(u64::from(args.height))
        .saturating_mul(4);
    let total_bytes = frame_bytes.saturating_mul(u64::try_from(send_times.len()).unwrap_or(0));
    let secs = elapsed.as_secs_f64();
    // This is the *send rate*, not link capacity: in paced mode it reflects the fps-paced cadence; in
    // --no-pace (blast) mode it approaches the link's peak. The client's receive-window throughput is
    // the better measure of delivered rate.
    let mode = if args.no_pace { "blast" } else { "paced" };
    #[allow(clippy::cast_precision_loss)]
    let mbps = if secs > 0.0 {
        (total_bytes as f64) * 8.0 / secs / 1.0e6
    } else {
        0.0
    };

    println!("--- host report ---");
    println!("  frames sent:   {}", send_times.len());
    #[allow(clippy::cast_precision_loss)]
    {
        println!(
            "  payload:       {:.1} MiB",
            (total_bytes as f64) / (1024.0 * 1024.0)
        );
    }
    println!("  send duration: {secs:.2} s");
    println!("  send rate:     {mbps:.1} Mbps ({mode}, payload)");
    println!(
        "  quic rtt:      {:.1} ms",
        conn.rtt().as_secs_f64() * 1000.0
    );
    Ok(())
}
