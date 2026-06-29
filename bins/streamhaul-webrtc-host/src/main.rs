//! `streamhaul-webrtc-host` — native WebRTC answerer for browser↔native interop testing (P5-3).
//!
//! # Stage 2: identity-bound DTLS pin (ADR-0023 / ADR-0014)
//!
//! Connects to a `streamhaul-signaling` server, runs the **identity-bound Noise XK handshake**
//! with the browser over signaling (committing its own DTLS fingerprint inside an identity-signed
//! `BindCert` and extracting the browser's committed fingerprint), then accepts the browser SDP
//! offer pinning the **BindCert-committed** browser fingerprint — NOT the untrusted SDP
//! `a=fingerprint`. A signaling/SDP MITM that swaps the offer fingerprint is therefore rejected:
//! str0m fail-closes the DTLS handshake against the identity-bound pin.
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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use bytes::Bytes;
use sh_crypto::{DtlsCommitment, HandshakeOutcome, NoiseHandshake, SoftwareKeystore};
use sh_protocol::{Codec, CommonHeader, Flags, FrameType, Priority, VideoHeader, MAX_FRAME_ID};
use sh_signaling::backoff::ExponentialBackoff;
use sh_signaling::envelope::{MessageKind, SessionId, SignalingEnvelope};
use sh_signaling::SignalingClient;
use sh_transport::channel::Transport;
use sh_transport::driver::{spawn_webrtc_driver, AsyncUdpSocket as _, TokioUdpSocket};
use sh_transport::webrtc::SdpBridgeBuilder;
use sh_transport::{PinnedWebRtcTransport, TransportError};
use sh_types::{ChannelId, FrameId, TimestampUs};
use str0m::Rtc;
use tracing::{debug, info, warn};

/// SHP echo frame: 3-byte magic + 1-byte version + 4-byte length (BE) + payload "ECHO".
///
/// A minimal test-only frame for the echo verification test. Uses a custom `"SHP"` magic
/// prefix to make the payload visually identifiable in logs. This is NOT the real
/// `sh-protocol` wire format (see `sh-protocol::CommonHeader`).
const SHP_ECHO_FRAME: &[u8] = b"SHP\x00\x00\x00\x00\x04ECHO";

/// Per-step deadline for every blocking signaling receive in the handshake / offer phase.
///
/// Without this, a peer that connects but never sends the expected message (or sends them out of
/// order) would hang the host forever behind the test harness's opaque outer timeout. Each step
/// instead fails fast with a named error identifying which step stalled. 30 s is generous for a
/// loopback round-trip yet bounded.
const SIGNALING_STEP_TIMEOUT: Duration = Duration::from_secs(30);

// ── Noise-over-signaling sub-types (payload[0] of a `MessageKind::Noise` envelope) ──────────────
//
// The opaque `Noise` payload is `[sub_type: u8] || body`. The relay never inspects it
// (zero-knowledge); only the two peers parse it. See ADR-0023 for the full ordering.

/// `body` is empty. Browser→host: lets the host learn the browser's `from_fp` so it can address
/// its own Noise replies. (The host cannot send anything to the browser until it knows `to_fp`.)
const NOISE_SUB_HELLO: u8 = 0x00;
/// `body` is the host's 32-byte X25519 static **public** key. Host→browser, sent once so the
/// browser (XK initiator) can construct the handshake (XK requires the responder static up front).
const NOISE_SUB_HOST_STATIC_PUB: u8 = 0x01;
/// `body` is an opaque Noise XK handshake message. Either direction; carries the BindCert.
const NOISE_SUB_MSG: u8 = 0x02;

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
    // The 32-byte SHA-256 DTLS whole-cert fingerprint that we commit inside our BindCert.
    let local_dtls_commit: [u8; 32] = local_fp
        .bytes
        .as_slice()
        .try_into()
        .context("local DTLS fingerprint is not 32 bytes (expected SHA-256)")?;

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

    info!("connected to signaling server, waiting for browser Noise hello");

    // ── Step 3: identity-bound Noise XK handshake over signaling ──────────────
    //
    // The host is the XK responder. It generates its X25519 static, advertises the public key,
    // runs the 3-message XK exchange, and extracts the BROWSER's committed DTLS fingerprint to
    // pin. See `run_noise_responder` for the message ordering (ADR-0023).
    let keystore = SoftwareKeystore::generate();
    let (browser_fp, browser_dtls_pin) = run_noise_responder(
        &mut sig_client,
        &keystore,
        &args,
        &local_fp_hex,
        local_dtls_commit,
    )
    .await
    .context("identity-bound Noise handshake failed")?;
    info!("Noise XK handshake complete; pinning browser's identity-bound DTLS fingerprint");

    // ── Step 4: receive the SDP offer from the browser ────────────────────────
    let offer_sdp = receive_offer(&mut sig_client, &browser_fp).await?;
    debug!("received SDP offer from browser");

    // ── Step 5: bind UDP socket first so we know the concrete local address ───
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

    // STAGE 2: pin the browser's BindCert-committed DTLS fingerprint, NOT the offer's SDP
    // `a=fingerprint`. A signaling MITM that swaps the SDP fingerprint is rejected because str0m
    // fail-closes against this identity-bound pin (the genuine browser cert is required).
    let bridge_result = SdpBridgeBuilder::new(rtc)
        .accept_browser_offer_with_pin(
            &offer_sdp,
            browser_dtls_pin,
            local_udp_addr,
            placeholder_remote,
        )
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

    // ── Step 6: send the SDP answer back to the browser ───────────────────────
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

    // ── Step 7: start the drive loop ─────────────────────────────────────────

    let socket: Arc<dyn sh_transport::driver::AsyncUdpSocket> = Arc::new(udp_socket);
    let _driver_handle = spawn_webrtc_driver(Arc::clone(&transport), socket, now);

    // ── Step 8: forward any trickle ICE candidates from signaling ────────────
    //
    // Accept the next DataChannel in a separate task so we can simultaneously pump
    // trickle candidates from the signaling channel.
    let transport_for_accept = Arc::clone(&transport);
    let (stream_video, frames, fps) = (args.stream_video, args.frames, args.fps);
    let accept_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        if stream_video {
            run_video_stream(&transport_for_accept, frames, fps).await
        } else {
            run_data_channel(&transport_for_accept).await
        }
    });

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
    /// Stream the baked H.264 clip as SHP video frames instead of the echo exchange (ADR-0031).
    stream_video: bool,
    /// Number of video frames to stream in `--stream-video` mode.
    frames: usize,
    /// Frame pacing for `--stream-video` mode.
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

        let session_id = parse_session_id(&session_id_hex)?;
        Ok(Self {
            signaling_url,
            session_id,
            bind,
            stream_video,
            frames,
            fps,
        })
    }
}

/// A synthetic [`Keystore`] that trusts every peer, with **no-op trust-store mutation**.
///
/// Used for the Stage 2 TOFU **first pairing** path: the host has not pinned the browser's
/// identity ahead of time, so [`NoiseHandshake::complete`] would reject it as `UntrustedPeer`.
/// This wrapper returns `true` from `is_trusted`, mirroring the wasm `TrustAllKeystore` and the
/// `complete_for_first_pairing` browser path.
///
/// # Why the trust-store mutators are no-ops (Keystore-contract honesty, CLAUDE.md §6)
///
/// [`NoiseHandshake::complete`] only ever calls [`is_trusted`](sh_crypto::Keystore::is_trusted) on
/// the supplied keystore — never `trust_peer` / `trust_peer_if_not_revoked` / `revoke_peer`. The
/// other methods exist solely to satisfy the `Keystore` trait bound. They therefore **do not**
/// touch any backing store: writing to a throwaway inner keystore and then reporting
/// `TrustOutcome::Pinned` would be a lie (nothing is persisted), violating the trust-store
/// contract. Instead they are explicit no-ops that report "not revoked" / freshly-pinned without
/// persisting anything. Persistent TOFU pinning across reconnects is intentionally **deferred**
/// (ADR-0023); this binary is a single-session integration test only.
///
/// The host's own identity (`device_identity` / `sign`) is **not** served by this keystore — the
/// real `keystore` passed to the handshake constructor signs the host's `BindCert`. The
/// `device_identity` / `sign` impls here exist only to satisfy the trait and are never invoked by
/// `complete`; they return a uniform `CryptoError` if ever called so a future code path that does
/// reach them fails loudly rather than silently using a stand-in identity.
///
/// # Keep in sync
///
/// A semantically-equivalent `TrustAllKeystore` exists in `sh-crypto-wasm` (browser first-pairing,
/// `complete_for_first_pairing`). They are intentionally duplicated because this is a test/dev
/// binary and `sh-crypto-wasm` is a wasm32-only excluded crate; consolidating into a `sh-crypto`
/// test/dev-feature single source is tracked as a low-priority follow-up. If the `Keystore` trait
/// surface changes, update **both**.
struct TrustAllKeystore;

#[async_trait::async_trait]
impl sh_crypto::Keystore for TrustAllKeystore {
    async fn device_identity(&self) -> Result<sh_crypto::DeviceIdentity, sh_crypto::CryptoError> {
        // Never called by `complete`. Fail loudly rather than fabricate an identity.
        Err(sh_crypto::CryptoError::HandshakeFailed {
            reason: "TrustAllKeystore has no device identity (first-pairing trust-check only)",
        })
    }

    async fn sign(&self, _data: &[u8]) -> Result<sh_crypto::Signature, sh_crypto::CryptoError> {
        // Never called by `complete`. Fail loudly rather than sign with a stand-in key.
        Err(sh_crypto::CryptoError::HandshakeFailed {
            reason: "TrustAllKeystore cannot sign (first-pairing trust-check only)",
        })
    }

    async fn trust_peer(
        &self,
        _id: &sh_crypto::DeviceIdentity,
    ) -> Result<(), sh_crypto::CryptoError> {
        // No-op: TOFU persistence is intentionally not implemented in this test binary.
        Ok(())
    }

    async fn is_trusted(
        &self,
        _id: &sh_crypto::DeviceIdentity,
    ) -> Result<bool, sh_crypto::CryptoError> {
        Ok(true)
    }

    async fn revoke_peer(
        &self,
        _id: &sh_crypto::DeviceIdentity,
    ) -> Result<(), sh_crypto::CryptoError> {
        // No-op: nothing is persisted, so nothing is revoked.
        Ok(())
    }

    async fn was_peer_revoked(
        &self,
        _id: &sh_crypto::DeviceIdentity,
    ) -> Result<bool, sh_crypto::CryptoError> {
        // No persistent store ⇒ no peer is ever recorded as revoked.
        Ok(false)
    }

    async fn trust_peer_if_not_revoked(
        &self,
        _id: &sh_crypto::DeviceIdentity,
    ) -> Result<sh_crypto::pairing::TrustOutcome, sh_crypto::CryptoError> {
        // No-op trust-on-first-use: report freshly-pinned WITHOUT persisting (honest about the
        // no-op — there is no backing store to write to).
        Ok(sh_crypto::pairing::TrustOutcome::Pinned)
    }
}

/// Run the identity-bound Noise XK handshake as the **responder** (host side).
///
/// Message ordering (ADR-0023), with `B`=browser, `H`=host:
///
/// ```text
/// B → H : Noise(NOISE_SUB_HELLO, [])           // host learns browser's from_fp
/// H → B : Noise(NOISE_SUB_HOST_STATIC_PUB, X)  // host advertises X25519 static pub (XK needs it)
/// B → H : Noise(NOISE_SUB_MSG, msg0)
/// H → B : Noise(NOISE_SUB_MSG, msg1)
/// B → H : Noise(NOISE_SUB_MSG, msg2)
/// H     : complete() → extract browser's committed DTLS fingerprint
/// ```
///
/// Returns `(browser_from_fp, browser_committed_dtls_fp)`. The pin is the browser's identity-
/// signed `BindCert` DTLS commitment (`HandshakeOutcome::require_webrtc_dtls_pin`), which the
/// caller pins on the WebRTC transport.
async fn run_noise_responder(
    sig: &mut SignalingClient,
    keystore: &SoftwareKeystore,
    args: &Args,
    local_fp_hex: &str,
    local_dtls_commit: [u8; 32],
) -> anyhow::Result<(String, [u8; 32])> {
    // Generate the host's X25519 static. The public key is advertised; the secret never leaves
    // this function (consumed by the responder handshake constructor).
    let local_static = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let local_static_pub = x25519_dalek::PublicKey::from(&local_static);

    // 1. Wait for the browser's NOISE_HELLO so we learn its `from_fp` (the address for replies).
    let browser_fp = recv_noise_hello(sig).await?;

    // 2. Advertise our X25519 static public key.
    send_noise(
        sig,
        args,
        local_fp_hex,
        &browser_fp,
        NOISE_SUB_HOST_STATIC_PUB,
        local_static_pub.as_bytes(),
    )
    .await
    .context("failed to send host static pub")?;

    // 3. Construct the XK responder, committing OUR DTLS fingerprint in the BindCert.
    let clock = sh_types::SystemClock;
    let mut hs = NoiseHandshake::responder_xk_with_dtls(
        keystore,
        local_static,
        &[],
        DtlsCommitment::sha256(local_dtls_commit),
        &clock,
    )
    .await
    .context("failed to construct XK responder")?;

    // 4. XK is 3 messages: read msg0, write msg1, read msg2.
    let msg0 = recv_noise_msg(sig, &browser_fp).await?;
    hs.read_message(&msg0, &clock)
        .context("failed to read Noise msg0")?;

    let msg1 = hs.write_message().context("failed to write Noise msg1")?;
    send_noise(sig, args, local_fp_hex, &browser_fp, NOISE_SUB_MSG, &msg1)
        .await
        .context("failed to send Noise msg1")?;

    let msg2 = recv_noise_msg(sig, &browser_fp).await?;
    hs.read_message(&msg2, &clock)
        .context("failed to read Noise msg2")?;

    if !hs.is_finished() {
        anyhow::bail!("Noise handshake did not finish after 3 messages");
    }

    // 5. Complete with a trust-all keystore (TOFU first pairing). `complete` only calls
    //    `is_trusted` on this keystore; the host's own BindCert was already signed by `keystore`
    //    during the responder constructor. Extract the browser's committed DTLS fingerprint — the
    //    identity-bound pin.
    let outcome: HandshakeOutcome = hs
        .complete(&TrustAllKeystore)
        .await
        .context("Noise complete (first pairing) failed")?;

    let browser_dtls_pin = outcome
        .require_webrtc_dtls_pin()
        .context("browser BindCert carries no DTLS fingerprint (downgrade)")?;

    Ok((browser_fp, browser_dtls_pin))
}

/// Receive a single signaling envelope with a bounded [`SIGNALING_STEP_TIMEOUT`] deadline.
///
/// `step` names the handshake/offer step for the timeout / connection-closed error so a stall is
/// diagnosable instead of opaque. Returns the envelope, or an error if the deadline elapses, the
/// connection closes, or signaling I/O fails.
async fn recv_bounded(sig: &mut SignalingClient, step: &str) -> anyhow::Result<SignalingEnvelope> {
    let received = tokio::time::timeout(SIGNALING_STEP_TIMEOUT, sig.recv())
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for signaling message ({step})"))?
        .with_context(|| format!("signaling recv failed ({step})"))?;
    received.ok_or_else(|| anyhow::anyhow!("signaling connection closed before {step}"))
}

/// Wait for a `MessageKind::Noise` envelope carrying `NOISE_SUB_HELLO`; returns the browser's
/// `from_fp`.
async fn recv_noise_hello(sig: &mut SignalingClient) -> anyhow::Result<String> {
    loop {
        let env = recv_bounded(sig, "Noise hello").await?;
        if env.kind == MessageKind::Noise {
            match env.payload.first().copied() {
                Some(NOISE_SUB_HELLO) => return Ok(env.from_fp),
                Some(other) => {
                    debug!(
                        sub = other,
                        "ignoring non-hello Noise sub-type before hello"
                    );
                }
                None => warn!("empty Noise payload (ignored)"),
            }
        } else {
            debug!(kind = ?env.kind, "ignoring non-Noise signaling message before hello");
        }
    }
}

/// Wait for a `MessageKind::Noise` envelope carrying `NOISE_SUB_MSG` from `expected_fp`; returns
/// the opaque Noise body.
async fn recv_noise_msg(sig: &mut SignalingClient, expected_fp: &str) -> anyhow::Result<Vec<u8>> {
    loop {
        let env = recv_bounded(sig, "Noise handshake message").await?;
        if env.kind == MessageKind::Noise && env.from_fp == expected_fp {
            match env.payload.split_first() {
                Some((&NOISE_SUB_MSG, body)) => return Ok(body.to_vec()),
                Some((&other, _)) => {
                    debug!(
                        sub = other,
                        "ignoring unexpected Noise sub-type during exchange"
                    );
                }
                None => warn!("empty Noise payload during exchange (ignored)"),
            }
        } else {
            debug!(kind = ?env.kind, "ignoring unrelated signaling message during Noise exchange");
        }
    }
}

/// Send a `MessageKind::Noise` envelope with `sub_type` prefixed onto `body`.
async fn send_noise(
    sig: &mut SignalingClient,
    args: &Args,
    from_fp: &str,
    to_fp: &str,
    sub_type: u8,
    body: &[u8],
) -> anyhow::Result<()> {
    let mut payload = Vec::with_capacity(body.len().saturating_add(1));
    payload.push(sub_type);
    payload.extend_from_slice(body);
    let env = SignalingEnvelope {
        kind: MessageKind::Noise,
        session_id: args.session_id,
        from_fp: from_fp.to_owned(),
        to_fp: to_fp.to_owned(),
        payload: Bytes::from(payload),
    };
    sig.send(env).await.context("failed to send Noise envelope")
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

/// Wait for a `MessageKind::Offer` envelope from `expected_fp`.
///
/// Returns the `offer_sdp_text`.
///
/// # Errors
///
/// Returns an error if the signaling connection closes before an offer arrives, or if the
/// payload is not valid UTF-8.
async fn receive_offer(sig: &mut SignalingClient, expected_fp: &str) -> anyhow::Result<String> {
    loop {
        let env = recv_bounded(sig, "SDP offer").await?;
        if env.kind == MessageKind::Offer && env.from_fp == expected_fp {
            let offer_sdp =
                String::from_utf8(env.payload.to_vec()).context("offer payload is not UTF-8")?;
            return Ok(offer_sdp);
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

// ── Baked H.264 video streaming (ADR-0031) ──────────────────────────────────────
//
// A small, real H.264 Annex-B clip pre-encoded by OpenH264 (the excluded `sh-codec-openh264`
// crate's `gen_browser_fixture` example, which pins `openh264 = "=0.9.3"`) and checked in as bytes.
// Re-run that example to regenerate the fixture. Streaming it as SHP video frames
// lets the browser decode & render REAL video from this native host — proving the browser↔host video
// transport end to end — WITHOUT the default OSS build linking any H.264 encoder (the clip is just
// bytes). Live screen capture + on-host OpenH264 is the excluded preview host (next step). Fixture
// layout (little-endian, repeated to EOF): [u32 payload_len][u8 frame_type][payload_len bytes].
const BAKED_H264: &[u8] = include_bytes!("../fixtures/sample_h264.shv");

/// One pre-encoded H.264 access unit from the baked fixture.
struct BakedFrame {
    frame_type: FrameType,
    payload: &'static [u8],
}

/// Parse the baked fixture into per-frame Annex-B access units. Malformed/truncated trailing bytes
/// are ignored (the fixture is build-time data, but parse defensively rather than panic).
fn parse_baked_frames(mut data: &'static [u8]) -> Vec<BakedFrame> {
    let mut frames = Vec::new();
    while let Some(len_bytes) = data.get(..4) {
        let Ok(len_arr) = <[u8; 4]>::try_from(len_bytes) else {
            break;
        };
        let len = u32::from_le_bytes(len_arr) as usize;
        let Some(frame_type_byte) = data.get(4) else {
            break;
        };
        let frame_type = match frame_type_byte {
            1 => FrameType::Idr,
            2 => FrameType::IntraRefresh,
            _ => FrameType::Predicted,
        };
        let Some(rest) = data.get(5..) else { break };
        let Some(payload) = rest.get(..len) else {
            break;
        };
        frames.push(BakedFrame {
            frame_type,
            payload,
        });
        let Some(next) = rest.get(len..) else { break };
        data = next;
    }
    frames
}

/// Assemble one SHP video frame: `CommonHeader(9) || VideoHeader(12) || Annex-B payload`, matching
/// exactly what the browser's `parseVideoFrame` expects (single non-fragmented frame).
fn build_shp_video_frame(
    sequence: u16,
    frame_id: u32,
    ts_us: u64,
    frame_type: FrameType,
    payload: &[u8],
) -> anyhow::Result<Bytes> {
    let payload_len = u16::try_from(payload.len())
        .context("video frame exceeds SHP 16-bit payload-length cap")?;
    // `encode()` narrows both timestamps to their low 32 wire bits, so a u64 input is fine.
    let common = CommonHeader {
        channel: ChannelId::Video,
        flags: Flags {
            fragment: false,
            last_fragment: false,
        },
        sequence,
        timestamp_us: TimestampUs(ts_us),
        payload_len,
    }
    .encode();
    let video = VideoHeader {
        frame_id: FrameId(u64::from(frame_id)),
        frag_index: 0,
        total_frags: 1,
        codec: Codec::H264,
        frame_type,
        priority: Priority::High,
        monitor_id: 0,
        marker: true,
        encode_ts_us: TimestampUs(ts_us),
    }
    .encode()
    .context("encode video header")?;

    let cap = common
        .len()
        .saturating_add(video.len())
        .saturating_add(payload.len());
    let mut buf = Vec::with_capacity(cap);
    buf.extend_from_slice(&common);
    buf.extend_from_slice(&video);
    buf.extend_from_slice(payload);
    Ok(Bytes::from(buf))
}

/// Accept the browser's DataChannel and stream the baked H.264 clip as SHP video frames, paced to
/// `fps` and looping the clip until `frames_to_send` have been sent.
///
/// # Errors
/// Returns an error if the channel cannot be accepted, the fixture is empty/invalid, or a send fails.
async fn run_video_stream(
    transport: &PinnedWebRtcTransport,
    frames_to_send: usize,
    fps: u32,
) -> anyhow::Result<()> {
    info!("waiting for browser to open DataChannel (video mode)");
    let mut channel = transport
        .accept_channel()
        .await
        .context("failed to accept DataChannel")?;

    let baked = parse_baked_frames(BAKED_H264);
    anyhow::ensure!(!baked.is_empty(), "baked H.264 fixture parsed to 0 frames");
    anyhow::ensure!(
        frames_to_send > 0,
        "--frames must be > 0 in --stream-video mode"
    );
    info!(
        clip_frames = baked.len(),
        target = frames_to_send,
        fps,
        "streaming baked H.264 to browser"
    );

    // `checked_div` (not `/`) satisfies the arithmetic-side-effects lint; `fps.max(1)` guarantees a
    // non-zero divisor, so the `unwrap_or` fallback is unreachable.
    let per_us = 1_000_000u64
        .checked_div(u64::from(fps.max(1)))
        .unwrap_or(1)
        .max(1);
    let mut ticker = tokio::time::interval(Duration::from_micros(per_us));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut sent: usize = 0;
    let mut sequence: u16 = 0;
    while sent < frames_to_send {
        for bf in &baked {
            if sent >= frames_to_send {
                break;
            }
            ticker.tick().await;
            let n = sent as u64;
            // frame_id is a 24-bit wire field; mask into range. (`try_from` rather than `as u32` to
            // satisfy the cast-truncation lint; the mask guarantees it fits, so this never errors.)
            // Timestamps advance monotonically (WebCodecs wants increasing chunk timestamps);
            // encode() narrows them to their low 32 wire bits.
            let frame_id = u32::try_from(n & u64::from(MAX_FRAME_ID)).unwrap_or(0);
            let ts_us = n.wrapping_mul(per_us);
            let shp = build_shp_video_frame(sequence, frame_id, ts_us, bf.frame_type, bf.payload)?;
            // A send failure here means the browser closed the DataChannel — a NORMAL end of stream
            // (the viewer got what it needed and disconnected), not a host error. Treat it as a
            // clean end so the host exits 0 instead of logging a misleading failure.
            if let Err(e) = channel.send(shp).await {
                info!(frames = sent, error = %e, "peer closed channel — ending video stream");
                return Ok(());
            }
            sent = sent.saturating_add(1);
            sequence = sequence.wrapping_add(1);
        }
    }

    info!(frames = sent, "video stream complete");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        build_shp_video_frame, parse_baked_frames, BAKED_H264, NOISE_SUB_HELLO,
        NOISE_SUB_HOST_STATIC_PUB, NOISE_SUB_MSG,
    };
    use sh_protocol::{Codec, CommonHeader, FrameType, VideoHeader, COMMON_HEADER_LEN};
    use sh_types::ChannelId;

    /// The Noise sub-type wire values are a cross-language contract with the browser driver
    /// (`clients/web/e2e/browser-native.ts`). Pin the exact numeric values here so a change on the
    /// Rust side breaks this test (and the mirrored assertion in `browser-native.spec.ts` breaks on
    /// the TS side) rather than silently desyncing the two implementations. See ADR-0023.
    #[test]
    fn noise_sub_type_wire_values_are_pinned() {
        assert_eq!(NOISE_SUB_HELLO, 0x00, "NOISE_SUB_HELLO wire value changed");
        assert_eq!(
            NOISE_SUB_HOST_STATIC_PUB, 0x01,
            "NOISE_SUB_HOST_STATIC_PUB wire value changed"
        );
        assert_eq!(NOISE_SUB_MSG, 0x02, "NOISE_SUB_MSG wire value changed");
    }

    #[test]
    fn baked_fixture_parses_with_leading_idr() {
        let frames = parse_baked_frames(BAKED_H264);
        assert!(!frames.is_empty(), "baked fixture must contain frames");
        assert_eq!(
            frames[0].frame_type,
            FrameType::Idr,
            "the first baked frame must be an IDR so the browser can configure its decoder"
        );
        // Every frame must be Annex-B (starts with a 0x000001 / 0x00000001 start code) and fit the
        // SHP 16-bit payload cap.
        for f in &frames {
            assert!(
                f.payload.len() <= usize::from(u16::MAX),
                "frame exceeds SHP cap"
            );
            assert!(
                f.payload.starts_with(&[0, 0, 0, 1]) || f.payload.starts_with(&[0, 0, 1]),
                "payload is not Annex-B"
            );
        }
    }

    #[test]
    fn built_shp_frame_round_trips_through_sh_protocol_decoders() {
        // The host's framing must match what the browser decodes — assert it round-trips through the
        // SAME sh-protocol decoders the browser's wasm bridge runs.
        let payload = &[0u8, 0, 0, 1, 0x67, 0x42]; // fake Annex-B-ish bytes
        let frame =
            build_shp_video_frame(7, 5, 1234, FrameType::Idr, payload).expect("build frame");

        let common = CommonHeader::decode(&frame[..COMMON_HEADER_LEN]).expect("common header");
        assert_eq!(common.channel, ChannelId::Video);
        assert_eq!(common.sequence, 7);
        assert_eq!(usize::from(common.payload_len), payload.len());

        let video = VideoHeader::decode(&frame[COMMON_HEADER_LEN..COMMON_HEADER_LEN + 12])
            .expect("video header");
        assert_eq!(video.frame_id.0, 5);
        assert_eq!(video.codec, Codec::H264);
        assert_eq!(video.frame_type, FrameType::Idr);
        assert!(video.marker);
        assert_eq!(video.total_frags, 1);

        // The payload follows the 21-byte header prefix, byte-exact.
        assert_eq!(&frame[COMMON_HEADER_LEN + 12..], payload);
    }

    #[test]
    fn parse_baked_frames_handles_malformed_input() {
        // Empty / sub-header / truncated-payload / declared-len-overruns inputs must all parse to a
        // finite (possibly empty) list without panicking or looping forever.
        assert!(parse_baked_frames(&[]).is_empty());
        assert!(parse_baked_frames(&[0, 0]).is_empty()); // < 4-byte length prefix
        assert!(parse_baked_frames(&[1, 0, 0, 0]).is_empty()); // length but no frame_type byte
                                                               // Declares len=10 but only 2 payload bytes follow → dropped (no OOB).
        assert!(parse_baked_frames(&[10, 0, 0, 0, 1, 0xAA, 0xBB]).is_empty());
        // One valid frame (len=2, IDR, [0xAA,0xBB]) followed by a truncated second frame.
        let one = parse_baked_frames(&[2, 0, 0, 0, 1, 0xAA, 0xBB, 0, 0]);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].frame_type, FrameType::Idr);
        assert_eq!(one[0].payload, &[0xAA, 0xBB]);
    }

    #[test]
    fn build_shp_video_frame_rejects_oversize_payload() {
        // SHP CommonHeader.payload_len is u16; a >64 KiB payload must error, not truncate/panic.
        let big = vec![0u8; usize::from(u16::MAX) + 1];
        assert!(build_shp_video_frame(0, 0, 0, FrameType::Predicted, &big).is_err());
    }
}
