#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `streamhaul-preview-client` — receive OpenH264 video over QUIC, decode it, and save frames.
//!
//! Connects to a [`streamhaul-preview-host`], runs the receive→reassemble→decode pipeline, writes the
//! first and last decoded frames as PPM images you can open, and prints delivery stats.
//!
//! Example: `streamhaul-preview-client 127.0.0.1:7878 --frames 300 --out-dir /tmp`
//!
//! **Preview / non-distribution:** links a software H.264 decoder (licensing-gated; ADR-0028/0029).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use sh_media::VideoFrame;

/// Streamhaul preview client (receives + decodes OpenH264 video over QUIC).
#[derive(Debug, Parser)]
#[command(about, long_about = None)]
struct Args {
    /// Host address to connect to (e.g. 127.0.0.1:7878).
    server: SocketAddr,
    /// Expected frame count (stop once this many decode, or at the receive timeout).
    #[arg(long, default_value_t = 300)]
    frames: usize,
    /// Connection timeout in seconds.
    #[arg(long, default_value_t = 10)]
    connect_timeout: u64,
    /// Receive deadline in seconds — stop and report whatever arrived (datagram loss is expected).
    #[arg(long, default_value_t = 60)]
    recv_timeout: u64,
    /// Directory to write the first/last decoded frames as PPM. Empty disables PPM output.
    #[arg(long, default_value = "/tmp")]
    out_dir: String,
    /// Do not write any PPM images.
    #[arg(long)]
    no_ppm: bool,
}

/// Encode a BGRA [`VideoFrame`] as a binary PPM (P6) and write it to `path`.
fn write_ppm(frame: &VideoFrame, path: &Path) -> anyhow::Result<()> {
    let (w, h) = (
        frame.resolution.width as usize,
        frame.resolution.height as usize,
    );
    let mut ppm = format!("P6\n{w} {h}\n255\n").into_bytes();
    ppm.reserve(w.saturating_mul(h).saturating_mul(3));
    for px in frame.data.chunks_exact(4) {
        // chunks_exact(4) guarantees 4 bytes per pixel: [B, G, R, A] → emit R, G, B.
        if let [b, g, r, _a] = px {
            ppm.push(*r);
            ppm.push(*g);
            ppm.push(*b);
        }
    }
    std::fs::write(path, &ppm).with_context(|| format!("write PPM to {}", path.display()))?;
    Ok(())
}

/// Entry point for the `streamhaul-preview-client` binary.
///
/// # Errors
/// Returns any connection, transport, or decode error, or if no frames are delivered.
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
    .map_err(|_| anyhow::anyhow!("connect to {} timed out", args.server))?
    .context("failed to connect to host")?;
    println!("streamhaul-preview-client connected to {}", args.server);

    let (recv_times, frames) =
        streamhaul_preview::receive(&conn, args.frames, Duration::from_secs(args.recv_timeout))
            .await
            .context("preview client pipeline failed")?;

    // Save the first and last decoded frames for visual confirmation.
    if !args.no_ppm && !args.out_dir.is_empty() {
        if let Some(first) = frames.first() {
            let p = PathBuf::from(&args.out_dir).join("preview-first.ppm");
            write_ppm(first, &p)?;
            println!("wrote {}", p.display());
        }
        if let Some(last) = frames.last() {
            if frames.len() > 1 {
                let p = PathBuf::from(&args.out_dir).join("preview-last.ppm");
                write_ppm(last, &p)?;
                println!("wrote {}", p.display());
            }
        }
    }

    let received = recv_times.len();
    let res = frames.first().map(|f| f.resolution);
    let total_bytes: u64 = frames
        .iter()
        .map(|f| u64::try_from(f.data.len()).unwrap_or(0))
        .fold(0u64, u64::saturating_add);

    println!("--- preview client report ---");
    match res {
        Some(r) => println!("  resolution:    {}x{} (decoded BGRA)", r.width, r.height),
        None => println!("  resolution:    (no frames decoded)"),
    }
    println!("  frames:        {received}/{} decoded", args.frames);
    #[allow(clippy::cast_precision_loss)]
    {
        println!(
            "  decoded bytes: {:.1} MiB",
            (total_bytes as f64) / (1024.0 * 1024.0)
        );
    }
    println!(
        "  quic rtt:      {:.1} ms",
        conn.rtt().as_secs_f64() * 1000.0
    );

    // A real, non-empty decode is the success criterion for the slice.
    anyhow::ensure!(
        received > 0,
        "no frames decoded — the preview slice did not deliver video"
    );
    Ok(())
}
