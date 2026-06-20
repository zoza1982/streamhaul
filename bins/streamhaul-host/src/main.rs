//! streamhaul-host — synthetic host agent for LAN testing.
//!
//! Binds a QUIC server on the given address and streams raw-encoded video datagrams.
//! The capture, encode, fragment, and send pipeline is orchestrated by [`sh_core::run_host_pipeline`].
//!
//! # Usage
//! ```text
//! streamhaul-host [bind-addr]   (default: 127.0.0.1:7878)
//! ```

/// Entry point for the streamhaul-host binary.
///
/// # Errors
///
/// Returns any I/O or transport error encountered during startup or streaming.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr: std::net::SocketAddr = std::env::args()
        .nth(1)
        .as_deref()
        .unwrap_or("127.0.0.1:7878")
        .parse()?;

    let ack = sh_transport::InsecureLanLab::i_understand_this_skips_tls_verification();
    let server_config = sh_transport::self_signed_server_config(ack)?;
    let server_ep = sh_transport::ServerEndpoint::bind(bind_addr, server_config)?;
    let local = server_ep.local_addr()?;
    println!("streamhaul-host listening on {local}");

    let conn = server_ep.accept().await?;
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
    let send_times =
        sh_core::run_host_pipeline(&conn, &mut capturer, &mut encoder, &params).await?;
    println!("host sent {} frames", send_times.len());
    Ok(())
}
