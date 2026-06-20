//! streamhaul-client — synthetic client agent for LAN/WiFi testing.
//!
//! Connects to a host over QUIC, runs the receive→reassemble→decode→sink pipeline, and prints a
//! delivery/throughput/jitter/RTT report. Uses [`sh_core::run_client_pipeline`] internally.
//!
//! Example: `streamhaul-client 192.168.1.50:7878 --frames 300 --recv-timeout 60`

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use bytes::Bytes;
use clap::Parser;
use sh_types::FrameId;

/// Synthetic Streamhaul client (receives video over QUIC and reports link metrics).
#[derive(Debug, Parser)]
#[command(about, long_about = None)]
struct Args {
    /// Server address to connect to (e.g. 192.168.1.50:7878).
    server: SocketAddr,
    /// Expected frame count (the client stops once it has this many, or at the receive timeout).
    #[arg(long, default_value_t = 300)]
    frames: usize,
    /// Connection timeout in seconds (avoids hanging if the handshake is blocked/filtered).
    #[arg(long, default_value_t = 10)]
    connect_timeout: u64,
    /// Receive deadline in seconds — stop and report whatever arrived (datagram loss is expected).
    #[arg(long, default_value_t = 60)]
    recv_timeout: u64,
}

/// Entry point for the streamhaul-client binary.
///
/// # Errors
/// Returns any I/O or transport error encountered during startup or streaming.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let ack = sh_transport::InsecureLanLab::i_understand_this_skips_tls_verification();
    let client_config =
        sh_transport::insecure_client_config(ack).context("failed to create client TLS config")?;
    let client_ep = sh_transport::ClientEndpoint::bind(client_config)
        .context("failed to bind client endpoint")?;

    let conn = tokio::time::timeout(
        Duration::from_secs(args.connect_timeout),
        client_ep.connect(args.server, "localhost"),
    )
    .await
    .with_context(|| {
        format!(
            "connect to {} timed out after {}s",
            args.server, args.connect_timeout
        )
    })?
    .context("failed to connect to server")?;
    println!("streamhaul-client connected to {}", args.server);

    let mut decoder = sh_codec_hw::RawDecoder::new();
    let mut sink = sh_render::CollectingSink::new(args.frames);
    let recv_times = sh_core::run_client_pipeline(
        &conn,
        &mut decoder,
        &mut sink,
        args.frames,
        Duration::from_secs(args.recv_timeout),
    )
    .await
    .context("client pipeline failed")?;

    print_report(&args, &recv_times, sink.frames(), conn.rtt());
    Ok(())
}

/// Print the delivery / throughput / jitter / RTT report.
#[allow(clippy::cast_precision_loss)]
fn print_report(
    args: &Args,
    recv_times: &[(FrameId, Instant)],
    frames: &[sh_media::VideoFrame],
    rtt: Duration,
) {
    let received = recv_times.len();
    let lost = args.frames.saturating_sub(received);
    let loss_pct = if args.frames > 0 {
        (lost as f64) * 100.0 / (args.frames as f64)
    } else {
        0.0
    };

    // Decoded payload bytes actually delivered.
    let total_bytes: u64 = frames
        .iter()
        .map(|f| u64::try_from(f.data.len()).unwrap_or(0))
        .fold(0u64, u64::saturating_add);

    // Receive window = first → last arrival; throughput over that window.
    let window = match (recv_times.first(), recv_times.last()) {
        (Some((_, first)), Some((_, last))) => last.duration_since(*first),
        _ => Duration::ZERO,
    };
    let window_secs = window.as_secs_f64();
    let mbps = if window_secs > 0.0 {
        (total_bytes as f64) * 8.0 / window_secs / 1.0e6
    } else {
        0.0
    };

    // Inter-frame arrival gaps (jitter), in microseconds.
    let mut gaps_us: Vec<u64> = recv_times
        .windows(2)
        .filter_map(|w| match w {
            [a, b] => Some(u64::try_from(b.1.duration_since(a.1).as_micros()).unwrap_or(u64::MAX)),
            _ => None,
        })
        .collect();
    gaps_us.sort_unstable();
    let pct = |p: usize| -> u64 {
        if gaps_us.is_empty() {
            return 0;
        }
        let idx = gaps_us
            .len()
            .saturating_mul(p)
            .saturating_add(99)
            .saturating_div(100)
            .saturating_sub(1)
            .min(gaps_us.len().saturating_sub(1));
        gaps_us.get(idx).copied().unwrap_or(0)
    };

    // Cross-machine integrity check: the synthetic pattern is a deterministic function of
    // (frame_id, resolution), so regenerate the expected frames and byte-compare. (QUIC's AEAD
    // already guarantees no corruption, so this should equal the received count.)
    let lossless = verify_lossless(frames, args.frames);

    println!("--- client report ---");
    println!(
        "  frames:        {received}/{} received ({lost} lost, {loss_pct:.1}%)",
        args.frames
    );
    println!("  verified ok:   {lossless}/{received} byte-exact vs source");
    println!(
        "  payload:       {:.1} MiB",
        (total_bytes as f64) / (1024.0 * 1024.0)
    );
    println!("  recv window:   {window_secs:.2} s");
    println!("  throughput:    {mbps:.1} Mbps (payload)");
    println!(
        "  frame gap:     median {:.1} ms, p95 {:.1} ms",
        (pct(50) as f64) / 1000.0,
        (pct(95) as f64) / 1000.0
    );
    println!("  quic rtt:      {:.1} ms", rtt.as_secs_f64() * 1000.0);
}

/// Count how many delivered frames match the deterministic synthetic source pattern.
fn verify_lossless(frames: &[sh_media::VideoFrame], expected_count: usize) -> usize {
    use sh_media::ScreenCapturer as _;
    let Some(first) = frames.first() else {
        return 0;
    };
    // Regenerate the source sequence (fps is irrelevant to the pixel pattern).
    let mut gen = sh_media::SyntheticCapturer::new(first.resolution, 30);
    let mut expected: std::collections::HashMap<u64, Bytes> =
        std::collections::HashMap::with_capacity(expected_count);
    for _ in 0..expected_count {
        if let Ok(Some(f)) = gen.next_frame(Duration::ZERO) {
            expected.insert(f.frame_id.0, f.data);
        }
    }
    frames
        .iter()
        .filter(|f| expected.get(&f.frame_id.0).is_some_and(|e| *e == f.data))
        .count()
}
