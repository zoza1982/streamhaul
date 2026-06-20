//! streamhaul-client — synthetic client agent for LAN testing.
//!
//! Connects to a host over QUIC and runs the receive→reassemble→decode→sink pipeline.
//! Uses [`sh_core::run_client_pipeline`] internally.
//!
//! # Usage
//! ```text
//! streamhaul-client [server-addr]   (default: 127.0.0.1:7878)
//! ```

use anyhow::Context as _;

/// Entry point for the streamhaul-client binary.
///
/// # Errors
///
/// Returns any I/O or transport error encountered during startup or streaming.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server_addr: std::net::SocketAddr = std::env::args()
        .nth(1)
        .as_deref()
        .unwrap_or("127.0.0.1:7878")
        .parse()
        .context("invalid server address")?;

    let ack = sh_transport::InsecureLanLab::i_understand_this_skips_tls_verification();
    let client_config =
        sh_transport::insecure_client_config(ack).context("failed to create client TLS config")?;
    let client_ep = sh_transport::ClientEndpoint::bind(client_config)
        .context("failed to bind client endpoint")?;
    let conn = client_ep
        .connect(server_addr, "localhost")
        .await
        .context("failed to connect to server")?;
    println!("streamhaul-client connected to {server_addr}");

    let frame_count = 300usize;
    let mut decoder = sh_codec_hw::RawDecoder::new();
    let mut sink = sh_render::CollectingSink::new(frame_count);

    let recv_times = sh_core::run_client_pipeline(
        &conn,
        &mut decoder,
        &mut sink,
        frame_count,
        std::time::Duration::from_secs(60),
    )
    .await
    .context("client pipeline failed")?;
    println!("client received {} frames", recv_times.len());
    Ok(())
}
