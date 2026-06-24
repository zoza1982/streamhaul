//! `streamhaul-webrtc-host` — native WebRTC answerer for browser↔native interop testing (P5-3).
//!
//! Connects to a `streamhaul-signaling` server, advertises its DTLS fingerprint, waits for an
//! SDP offer from a browser peer, negotiates the DTLS DataChannel, and exchanges a simple echo
//! frame to verify connectivity.
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
//! connect it to a production signaling server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context as _;
use bytes::Bytes;
use sh_signaling::backoff::ExponentialBackoff;
use sh_signaling::envelope::{MessageKind, SessionId, SignalingEnvelope};
use sh_signaling::SignalingClient;
use sh_transport::channel::Transport;
use sh_transport::driver::{spawn_webrtc_driver, AsyncUdpSocket as _, TokioUdpSocket};
use sh_transport::webrtc::SdpBridgeBuilder;
use sh_transport::{PinnedWebRtcTransport, TransportError};
use str0m::Rtc;
use tracing::{debug, info, warn};

/// SHP echo frame: 3-byte magic + 1-byte version + 4-byte length (BE) + payload "ECHO".
///
/// A minimal test-only frame for the echo verification test. Uses a custom `"SHP"` magic
/// prefix to make the payload visually identifiable in logs. This is NOT the real
/// `sh-protocol` wire format (see `sh-protocol::CommonHeader`).
const SHP_ECHO_FRAME: &[u8] = b"SHP\x00\x00\x00\x00\x04ECHO";

/// Entry point for the streamhaul-webrtc-host binary.
///
/// # Errors
///
/// Returns an error if signaling, SDP negotiation, or DataChannel exchange fails.
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

    // ── Step 1: create Rtc and obtain the local DTLS fingerprint ─────────────
    //
    // We must get the fingerprint BEFORE connecting to signaling so we can register
    // with it as our `from_fp`. The builder only captures it; no DTLS traffic yet.
    let now = Instant::now();
    let mut rtc = Rtc::new(now);
    let local_fp = rtc.direct_api().local_dtls_fingerprint().clone();
    let local_fp_hex = hex_encode(&local_fp.bytes);
    if local_fp_hex.len() != 64 {
        anyhow::bail!(
            "unexpected fingerprint length (expected 64 hex chars, got {})",
            local_fp_hex.len()
        );
    }

    // Print in a machine-readable form so the test harness can parse it.
    println!("HOST_DTLS_FP={local_fp_hex}");
    // Flush immediately so the harness sees the line before we block on signaling.
    {
        use std::io::Write as _;
        std::io::stdout().flush().ok();
    }

    // ── Step 2: connect to the signaling server ───────────────────────────────
    let backoff = ExponentialBackoff::new(100, 5_000, 10);
    let mut sig_client = SignalingClient::connect(
        &args.signaling_url,
        args.session_id,
        local_fp_hex.clone(),
        backoff,
    )
    .await
    .context("failed to connect to signaling server")?;

    info!("connected to signaling server, waiting for browser offer");

    // ── Step 3: receive the SDP offer from the browser ────────────────────────
    let (offer_sdp, browser_fp) = receive_offer(&mut sig_client).await?;
    // SECURITY: browser_fp is security-sensitive pairing material in Stage 2. Do not
    // promote this log to info/warn in production code paths.
    debug!(browser_fp = %browser_fp, "received SDP offer from browser");

    // ── Step 4: bind UDP socket first so we know the concrete local address ───
    //
    // Bind before building the transport so we can register the concrete local address
    // as a host ICE candidate. str0m requires at least one local candidate before ICE
    // connectivity checks (and therefore DTLS/DataChannel setup) can begin.
    //
    // We bind to 127.0.0.1 (not 0.0.0.0) because str0m rejects unspecified IPs as ICE
    // candidates. For this loopback-only e2e test, 127.0.0.1 is sufficient; real
    // multi-interface deployments would enumerate interface IPs instead.
    let local_bind: SocketAddr = args.bind.parse().context("invalid --bind address")?;
    let udp_socket = TokioUdpSocket::bind(local_bind)
        .await
        .context("failed to bind UDP socket")?;
    let local_udp_addr = udp_socket.local_addr();
    info!(local_udp_addr = %local_udp_addr, "UDP socket bound");

    // We use "0.0.0.0:0" as the initial remote_addr placeholder; str0m discovers the real
    // remote address via ICE candidate exchange.
    let placeholder_remote: SocketAddr = "0.0.0.0:0"
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid placeholder remote addr: {e}"))?;

    let bridge_result = SdpBridgeBuilder::new(rtc)
        .accept_browser_offer(&offer_sdp, local_udp_addr, placeholder_remote)
        .map_err(|e| anyhow::anyhow!("SDP bridge error: {e}"))?;

    let answer_sdp = bridge_result.answer_sdp;
    let transport = Arc::new(bridge_result.transport);

    // Register the local host ICE candidate so str0m knows the UDP address to use, and capture
    // its SDP form so we can trickle it to the browser — the candidate is added AFTER the answer
    // SDP was generated, so it is NOT in the answer; the browser cannot reach the host without it.
    let local_candidate_sdp = transport
        .add_local_host_candidate(local_udp_addr)
        .context("failed to register local ICE candidate")?;
    info!(addr = %local_udp_addr, candidate = %local_candidate_sdp, "registered + will trickle local ICE candidate");

    // ── Step 5: send the SDP answer back to the browser ───────────────────────
    let answer_env = SignalingEnvelope {
        kind: MessageKind::Answer,
        session_id: args.session_id,
        from_fp: local_fp_hex.clone(),
        to_fp: browser_fp.clone(),
        payload: Bytes::from(answer_sdp.into_bytes()),
    };
    sig_client
        .send(answer_env)
        .await
        .context("failed to send SDP answer")?;
    info!("sent SDP answer to browser");

    // Trickle the host's local ICE candidate to the browser (it is not in the answer SDP).
    let cand_env = SignalingEnvelope {
        kind: MessageKind::Candidate,
        session_id: args.session_id,
        from_fp: local_fp_hex.clone(),
        to_fp: browser_fp.clone(),
        payload: Bytes::from(local_candidate_sdp.into_bytes()),
    };
    sig_client
        .send(cand_env)
        .await
        .context("failed to send local ICE candidate")?;
    info!("sent local ICE candidate to browser");

    // Send EndOfCandidates so the browser knows to stop waiting for trickle candidates.
    let eoc_env = SignalingEnvelope {
        kind: MessageKind::EndOfCandidates,
        session_id: args.session_id,
        from_fp: local_fp_hex.clone(),
        to_fp: browser_fp.clone(),
        payload: Bytes::new(),
    };
    sig_client
        .send(eoc_env)
        .await
        .context("failed to send EndOfCandidates")?;
    info!("sent EndOfCandidates to browser");

    // ── Step 6: start the drive loop ─────────────────────────────────────────

    let socket: Arc<dyn sh_transport::driver::AsyncUdpSocket> = Arc::new(udp_socket);
    let _driver_handle = spawn_webrtc_driver(Arc::clone(&transport), socket, now);

    // ── Step 7: forward any trickle ICE candidates from signaling ────────────
    //
    // Accept the next DataChannel in a separate task so we can simultaneously pump
    // trickle candidates from the signaling channel.
    let transport_for_accept = Arc::clone(&transport);
    let accept_task: tokio::task::JoinHandle<anyhow::Result<()>> =
        tokio::spawn(async move { run_data_channel(&transport_for_accept).await });

    // Pump trickle ICE candidates until we see end-of-candidates or the browser disconnects.
    pump_candidates(&mut sig_client, &transport).await?;
    sig_client.close().await.ok();

    // Wait for the DataChannel task to complete (echo exchange).
    accept_task
        .await
        .context("DataChannel task panicked")?
        .context("DataChannel exchange failed")?;

    // After run_data_channel completes, the echo frames are queued in the transport's outbound
    // buffer (inner.outbound) but not yet transmitted — the driver task dispatches outbound UDP
    // datagrams on its own timer cycle. Give the driver task time to flush the outbound queue
    // before we return and the tokio runtime shuts down all tasks.
    //
    // 500 ms is generous: the driver's default poll fires every 50 ms, and SCTP retransmit is
    // fast on a local loopback. In production the server never exits after one exchange anyway.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    info!("browser↔native interop test complete");
    Ok(())
}

/// Parsed command-line arguments.
struct Args {
    /// WebSocket URL of the signaling server.
    signaling_url: String,
    /// 16-byte session identifier (parsed from 32-char hex).
    session_id: SessionId,
    /// Local UDP bind address.
    bind: String,
}

impl Args {
    /// Parse `--signaling-url`, `--session-id`, and `--bind` from [`std::env::args`].
    fn parse_from_env() -> anyhow::Result<Self> {
        let mut signaling_url = "ws://127.0.0.1:8765".to_owned();
        let mut session_id_hex = "0".repeat(32);
        // Default to loopback so the local ICE candidate is a concrete, routable address.
        // 0.0.0.0 is rejected by str0m's ICE implementation (`is_valid_ip` rejects unspecified).
        let mut bind = "127.0.0.1:0".to_owned();

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
                other => {
                    warn!(flag = other, "unknown flag (ignored)");
                }
            }
        }

        let session_id = parse_session_id(&session_id_hex)?;
        Ok(Self {
            signaling_url,
            session_id,
            bind,
        })
    }
}

/// Parse a 32-char lowercase hex string into a [`SessionId`].
fn parse_session_id(hex: &str) -> anyhow::Result<SessionId> {
    if hex.len() != 32 {
        anyhow::bail!("session-id must be 32 hex chars, got {} chars", hex.len());
    }
    let mut bytes = Vec::with_capacity(16);
    for chunk in hex.as_bytes().chunks(2) {
        let s = std::str::from_utf8(chunk).context("invalid UTF-8 in session-id")?;
        let b =
            u8::from_str_radix(s, 16).with_context(|| format!("invalid hex in session-id: {s}"))?;
        bytes.push(b);
    }
    // Safety: hex is exactly 32 chars, so chunks(2) produces exactly 16 items.
    let arr: [u8; 16] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("session-id length mismatch (internal error)"))?;
    Ok(SessionId(arr))
}

/// Hex-encode a byte slice into a lowercase string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Wait for a `MessageKind::Offer` envelope from the signaling server.
///
/// Returns `(offer_sdp_text, browser_from_fp)`.
///
/// # Errors
///
/// Returns an error if the signaling connection closes before an offer arrives, or if the
/// payload is not valid UTF-8.
async fn receive_offer(sig: &mut SignalingClient) -> anyhow::Result<(String, String)> {
    loop {
        let Some(env) = sig.recv().await.context("signaling recv failed")? else {
            anyhow::bail!("signaling connection closed before receiving an offer");
        };
        if env.kind == MessageKind::Offer {
            let offer_sdp =
                String::from_utf8(env.payload.to_vec()).context("offer payload is not UTF-8")?;
            return Ok((offer_sdp, env.from_fp));
        }
        debug!(kind = ?env.kind, "ignoring non-offer signaling message");
    }
}

/// Forward `Candidate` messages from signaling to the transport until `EndOfCandidates` or
/// `Bye` / connection close.
///
/// # Errors
///
/// Returns an error if signaling I/O fails.
async fn pump_candidates(
    sig: &mut SignalingClient,
    transport: &Arc<PinnedWebRtcTransport>,
) -> anyhow::Result<()> {
    // Give ICE exchange some time; pump until end-of-candidates, Bye, or timeout.
    let deadline = tokio::time::sleep(std::time::Duration::from_secs(30));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            biased;
            _ = &mut deadline => {
                debug!("trickle-ICE candidate pump: timeout reached");
                break;
            }
            result = sig.recv() => {
                match result.context("signaling recv during candidate pump")? {
                    None => {
                        debug!("signaling closed during candidate pump");
                        break;
                    }
                    Some(env) => match env.kind {
                        MessageKind::Candidate => {
                            let candidate_str = match String::from_utf8(env.payload.to_vec()) {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!(error = %e, "trickle candidate payload is not valid UTF-8 (ignored)");
                                    continue;
                                }
                            };
                            match transport.add_remote_candidate(&candidate_str) {
                                Ok(()) => debug!("added remote candidate"),
                                Err(TransportError::CandidateParseError(e)) => {
                                    warn!(error = %e, "failed to parse trickle candidate (ignored)");
                                }
                                Err(e) => {
                                    warn!(error = %e, "unexpected error adding candidate (ignored)");
                                }
                            }
                        }
                        MessageKind::EndOfCandidates | MessageKind::Bye => {
                            debug!(kind = ?env.kind, "end of candidate stream");
                            break;
                        }
                        other => {
                            debug!(kind = ?other, "ignoring non-candidate signaling message during ICE pump");
                        }
                    },
                }
            }
        }
    }
    Ok(())
}

/// Accept the first incoming DataChannel, receive a message, and echo it back.
///
/// # Errors
///
/// Returns an error if the channel cannot be accepted or the echo exchange fails.
async fn run_data_channel(transport: &PinnedWebRtcTransport) -> anyhow::Result<()> {
    info!("waiting for browser to open DataChannel");
    let mut channel = transport
        .accept_channel()
        .await
        .context("failed to accept DataChannel")?;

    info!("DataChannel open — waiting for first frame");
    let Some(frame) = channel
        .recv()
        .await
        .context("failed to receive frame from DataChannel")?
    else {
        anyhow::bail!("DataChannel closed before receiving any frame");
    };

    info!(bytes = frame.len(), "received frame from browser");

    // Echo the received frame back.
    channel.send(frame).await.context("failed to echo frame")?;

    // Also send our own SHP ECHO frame so the browser can verify the native payload.
    channel
        .send(Bytes::from_static(SHP_ECHO_FRAME))
        .await
        .context("failed to send SHP ECHO frame")?;

    info!("echo complete");
    Ok(())
}
