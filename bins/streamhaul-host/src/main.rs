//! streamhaul-host — synthetic host agent for LAN testing.
//!
//! Binds a QUIC server on the given address and streams raw-encoded video datagrams.
//! The capture, encode, fragment, and send pipeline is orchestrated by [`sh_core::run_host_pipeline`].
//!
//! # Usage
//! ```text
//! streamhaul-host [bind-addr]   (default: 0.0.0.0:7878)
//! ```

use anyhow::Context as _;

/// Entry point for the streamhaul-host binary.
///
/// # Errors
///
/// Returns any I/O or transport error encountered during startup or streaming.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bind_addr: std::net::SocketAddr = std::env::args()
        .nth(1)
        .as_deref()
        .unwrap_or("0.0.0.0:7878")
        .parse()
        .context("invalid bind address")?;

    let ack = sh_transport::InsecureLanLab::i_understand_this_skips_tls_verification();
    let server_config = sh_transport::self_signed_server_config(ack)
        .context("failed to create server TLS config")?;
    let server_ep = sh_transport::ServerEndpoint::bind(bind_addr, server_config)
        .context("failed to bind server endpoint")?;
    let local = server_ep.local_addr().context("failed to get local addr")?;
    println!("streamhaul-host listening on {local}");

    let conn = server_ep
        .accept()
        .await
        .context("failed to accept connection")?;
    println!("client connected from {}", conn.remote_address());

    let resolution = sh_media::Resolution::new(320, 180);
    let fps = 30u32;
    let frame_count = 300usize;
    let mut capturer = sh_media::SyntheticCapturer::new(resolution, fps);
    let mut encoder = sh_codec_hw::RawEncoder::new();

    let params = sh_core::HostPipelineParams {
        frame_count,
        fps,
        pace_frames: false,
    };
    let send_times = sh_core::run_host_pipeline(&conn, &mut capturer, &mut encoder, &params)
        .await
        .context("host pipeline failed")?;
    println!("host sent {} frames", send_times.len());
    Ok(())
}
