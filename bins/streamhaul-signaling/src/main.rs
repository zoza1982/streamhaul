//! `streamhaul-signaling` — standalone WebSocket signaling server for local/integration use.
//!
//! Binds a [`SignalingServer`] with the [`AcceptAll`] authenticator (available via the
//! `insecure-lan` feature, which is intentionally enabled for this binary). Intended for
//! **local development and browser↔native e2e testing (P5-3)** — not for production use.
//!
//! # Usage
//!
//! ```text
//! streamhaul-signaling --addr 127.0.0.1:8765
//! ```
//!
//! The default address is `127.0.0.1:8765`. Clients connect via plain WebSocket (`ws://`).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use sh_signaling::auth::AcceptAll;
use sh_signaling::SignalingServer;
use tracing::info;

/// Entry point for the streamhaul-signaling binary.
///
/// Parses `--addr <ADDR>` from command-line arguments, starts the signaling server, and
/// blocks until Ctrl+C is received (graceful shutdown).
///
/// # Errors
///
/// Returns an error if:
/// - The `--addr` value cannot be parsed as a [`SocketAddr`].
/// - The server fails to bind the TCP listener.
/// - The Ctrl+C signal handler cannot be installed.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let addr = parse_addr_arg()?;

    let server = SignalingServer::bind(addr, Arc::new(AcceptAll))
        .await
        .with_context(|| format!("failed to bind signaling server on {addr}"))?;

    // Resolve the ACTUAL bound address. When `--addr` requested port 0 the OS assigns an ephemeral
    // port; the requested `addr` still reads `:0`, so test harnesses must read the bound address
    // from this line to learn the real port (avoids fixed-port "Address already in use" flakiness
    // when a stale process lingers).
    let bound = server
        .local_addr()
        .context("failed to read signaling server bound address")?;

    info!(addr = %bound, "streamhaul-signaling listening");
    // Print machine-readable line so test harnesses can wait for ready and learn the real port.
    println!("SIGNALING_READY addr={bound}");
    // Flush stdout so the test harness can see the line immediately.
    use std::io::Write as _;
    std::io::stdout().flush().ok();

    // Run the server until Ctrl+C.
    tokio::select! {
        result = server.run() => {
            result.context("signaling server error")?;
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received Ctrl+C, shutting down");
        }
    }

    Ok(())
}

/// Parse the `--addr <ADDR>` argument from [`std::env::args`].
///
/// Returns `127.0.0.1:8765` if the flag is absent.
///
/// # Errors
///
/// Returns an error if `--addr` is present but its value is not a valid [`SocketAddr`].
fn parse_addr_arg() -> anyhow::Result<SocketAddr> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--addr" {
            let val = args.next().context("--addr requires a value")?;
            return val
                .parse::<SocketAddr>()
                .with_context(|| format!("invalid socket address: {val}"));
        }
    }
    // Default address — literal is known-valid so the error branch is unreachable in practice,
    // but we handle it to satisfy `clippy::expect_used`.
    "127.0.0.1:8765"
        .parse::<SocketAddr>()
        .map_err(|e| anyhow::anyhow!("default address is invalid: {e}"))
}
