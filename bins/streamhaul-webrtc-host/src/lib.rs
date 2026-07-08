//! `streamhaul-webrtc-host` library — WebRTC connection logic and video frame streaming (ADR-0031/0032).
//!
//! This crate is the **library half** of the `streamhaul-webrtc-host` workspace member.
//! It provides the identity-bound WebRTC connection stack (Noise XK responder, SDP offer/answer,
//! DTLS pin, ICE, DataChannel accept) and a generic [`VideoFrameSource`] seam so any frame
//! producer can be plugged in. The workspace binary (`src/main.rs`) uses [`BakedFrameSource`] to
//! replay the pre-encoded H.264 fixture; the excluded `streamhaul-webrtc-preview` binary (ADR-0032)
//! uses a live X11+OpenH264 source.
//!
//! # Public API
//!
//! - [`VideoFrameSource`] — trait for pluggable frame sources.
//! - [`BakedFrameSource`] — cycles the pre-encoded H.264 fixture (workspace binary default).
//! - [`HostConfig`] — signaling URL + session ID + UDP bind address.
//! - [`StreamMode`] — echo or video streaming.
//! - [`run_webrtc_host`] — entry point: connect, negotiate, stream.
//! - [`parse_session_id`] — parse a 32-hex-char session ID string.
//! - [`build_shp_video_frame`] — assemble one (single) SHP video frame from Annex-B payload bytes.
//! - [`build_shp_video_fragments`] — split a large frame into reassemblable SHP fragments (ADR-0033).
//!
//! # Security note
//!
//! The signaling path uses the `insecure-lan` authenticator (`AcceptAll`). This is a development
//! tool for local integration tests only; never connect it to a production signaling server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use bytes::Bytes;
use sh_clipboard::{sanitize_for_paste, ClipboardAccess};
use sh_crypto::{DtlsCommitment, HandshakeOutcome, NoiseHandshake, SoftwareKeystore};
use sh_input::{InputInjector, RateLimiter};
use sh_protocol::{
    ClipboardUpdate, Codec, CommonHeader, EventType, Flags, FrameType, InputEvent, Priority,
    VideoHeader, INPUT_EVENT_LEN, MAX_FRAME_ID,
};
use sh_signaling::backoff::ExponentialBackoff;
use sh_signaling::envelope::{MessageKind, SessionId, SignalingEnvelope};
use sh_signaling::SignalingClient;
use sh_transport::channel::{Channel, Transport};
use sh_transport::driver::{spawn_webrtc_driver, AsyncUdpSocket as _, TokioUdpSocket};
use sh_transport::webrtc::SdpBridgeBuilder;
use sh_transport::{PinnedWebRtcTransport, TransportError};
use sh_types::{ChannelId, FrameId, TimestampUs};
use str0m::Rtc;
use tracing::{debug, info, warn};

// ── SHP echo frame ──────────────────────────────────────────────────────────────────────────────
//
// 3-byte magic + 1-byte version + 4-byte length (BE) + payload "ECHO".
// A minimal test-only frame for the echo verification test. NOT the real sh-protocol wire format.
const SHP_ECHO_FRAME: &[u8] = b"SHP\x00\x00\x00\x00\x04ECHO";

/// Per-step deadline for every blocking signaling receive in the handshake / offer phase.
///
/// Without this, a peer that connects but never sends the expected message (or sends them out of
/// order) would hang the host forever behind the test harness's opaque outer timeout. Each step
/// instead fails fast with a named error identifying which step stalled. 30 s is generous for a
/// loopback round-trip yet bounded.
const SIGNALING_STEP_TIMEOUT: Duration = Duration::from_secs(30);

// ── Noise-over-signaling sub-types ─────────────────────────────────────────────────────────────
//
// The opaque `Noise` payload is `[sub_type: u8] || body`. The relay never inspects it
// (zero-knowledge); only the two peers parse it. See ADR-0023 for the full ordering.

/// `body` is empty. Browser→host: lets the host learn the browser's `from_fp`.
const NOISE_SUB_HELLO: u8 = 0x00;
/// `body` is the host's 32-byte X25519 static public key.
const NOISE_SUB_HOST_STATIC_PUB: u8 = 0x01;
/// `body` is an opaque Noise XK handshake message.
const NOISE_SUB_MSG: u8 = 0x02;

/// Max input events drained from the channel per video frame, so a flood can't starve the video
/// send loop. 256/frame ≈ 7680 events/s at 30 fps — far above any human input rate.
const MAX_INPUT_PER_FRAME: usize = 256;

/// Bounded depth of the channel feeding the dedicated injection thread. A full queue drops further
/// events (backpressure) rather than blocking the video loop — the natural flood/rate-limit point.
const INPUT_QUEUE_DEPTH: usize = 256;

/// Sustained cap (events/second) on injected **drop-safe high-rate** input — `PointerMove` and
/// `Wheel` (see [`admit_input`]) — as a hostile-input DoS guard. Well above any human rate (browsers
/// coalesce moves to ~60–120/s; trackpad scroll adds tens/s) but throttles a synthetic flood before
/// it reaches the OS injection API. State-transition events (`Button`/`Key`) are never rate-limited
/// (a dropped release would stick — ADR-0034).
const MAX_THROTTLED_INPUT_PER_SEC: u32 = 500;

/// Burst allowance for the hostile-input rate limiter: a short idle period banks up to this many
/// events so a normal flick of the mouse / scroll gesture passes unthrottled.
const THROTTLED_INPUT_BURST: u32 = 120;

// ── VideoFrameSource trait ──────────────────────────────────────────────────────────────────────

/// A source of raw H.264 Annex-B access units for the video streaming loop.
///
/// Implementations provide one frame per call; pacing to the target fps is handled by the
/// streaming loop in [`run_webrtc_host`]. The streamer stops after the requested frame count.
///
/// # Errors
///
/// Returns an error if capture or encoding fails irrecoverably.
pub trait VideoFrameSource: Send {
    /// Return the next access unit as `(frame_type, Annex-B payload)`.
    ///
    /// The returned payload must fit in the SHP 16-bit `payload_len` field (< 64 KiB);
    /// [`build_shp_video_frame`] enforces this and returns an error if violated.
    ///
    /// # Errors
    ///
    /// Returns an error on capture or encode failure.
    fn next_frame(&mut self) -> anyhow::Result<(FrameType, Vec<u8>)>;

    /// Request that the **next** produced frame be a keyframe (IDR).
    ///
    /// The streamer calls this when it has to DROP a frame (e.g. an oversize IDR that exceeds the
    /// SHP 64 KiB cap): an encoder clears its armed-keyframe flag the moment it emits the IDR, so
    /// without re-arming, a dropped keyframe would leave the stream with no decodable keyframe
    /// (the receiver renders nothing). The default is a no-op — correct for sources whose frames
    /// are independently decodable or never dropped (e.g. [`BakedFrameSource`]).
    fn request_keyframe(&mut self) {}
}

// ── Baked H.264 fixture ─────────────────────────────────────────────────────────────────────────
//
// A small, real H.264 Annex-B clip pre-encoded by OpenH264 (the excluded `sh-codec-openh264`
// crate's `gen_browser_fixture` example) and checked in as bytes. Re-run that example to
// regenerate the fixture. The workspace binary `include_bytes!`s the fixture — so the default
// OSS build links NO H.264 encoder; it only replays bytes. Fixture layout (little-endian,
// repeated to EOF): [u32 payload_len][u8 frame_type][payload_len bytes].
const BAKED_H264: &[u8] = include_bytes!("../fixtures/sample_h264.shv");

/// One pre-encoded H.264 access unit from the baked fixture.
struct BakedFrame {
    frame_type: FrameType,
    payload: &'static [u8],
}

/// Parse the baked fixture into per-frame Annex-B access units.
///
/// Malformed/truncated trailing bytes are ignored (the fixture is build-time data, but parse
/// defensively rather than panic).
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

/// A [`VideoFrameSource`] that cycles the pre-encoded baked H.264 fixture (ADR-0031).
///
/// Used by the workspace binary (`--stream-video`) to stream a fixed test clip without linking
/// any H.264 encoder. The fixture bytes are `include_bytes!`d at compile time and parsed once
/// at construction. [`next_frame`](VideoFrameSource::next_frame) cycles the clip indefinitely;
/// the streaming loop stops when the requested frame count is reached.
pub struct BakedFrameSource {
    frames: Vec<BakedFrame>,
    index: usize,
}

impl BakedFrameSource {
    /// Create a new source cycling the baked H.264 fixture.
    ///
    /// The fixture is parsed at construction time. [`VideoFrameSource::next_frame`] returns an
    /// error if the fixture is empty, which would indicate a build problem.
    pub fn new() -> Self {
        Self {
            frames: parse_baked_frames(BAKED_H264),
            index: 0,
        }
    }
}

impl Default for BakedFrameSource {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoFrameSource for BakedFrameSource {
    fn next_frame(&mut self) -> anyhow::Result<(FrameType, Vec<u8>)> {
        anyhow::ensure!(!self.frames.is_empty(), "baked H.264 fixture is empty");
        let len = self.frames.len();
        // len > 0 guaranteed by the ensure above; checked_rem is always Some here.
        let idx = self.index.checked_rem(len).unwrap_or(0);
        let bf = self
            .frames
            .get(idx)
            .ok_or_else(|| anyhow::anyhow!("baked frame index out of bounds (internal error)"))?;
        let result = (bf.frame_type, bf.payload.to_vec());
        self.index = self.index.wrapping_add(1);
        Ok(result)
    }
}

// ── HostConfig / StreamMode ─────────────────────────────────────────────────────────────────────

/// Configuration for [`run_webrtc_host`]: signaling coordinates and the local UDP bind address.
pub struct HostConfig {
    /// WebSocket URL of the signaling server (e.g. `ws://127.0.0.1:8765`).
    pub signaling_url: String,
    /// 16-byte session identifier, matched on both sides of the connection.
    pub session_id: SessionId,
    /// Local UDP socket address to bind (e.g. `"127.0.0.1:0"` for OS-assigned port).
    pub bind: String,
}

/// How [`run_webrtc_host`] behaves once the WebRTC DataChannel is open.
pub enum StreamMode {
    /// Echo the first received frame back and also send the SHP ECHO frame, then exit.
    Echo,
    /// Stream `frames` H.264 video frames at `fps` fps from `source`, then exit.
    Video {
        /// Total number of SHP video frames to send.
        frames: usize,
        /// Target frame rate (frames per second). Must be > 0 (enforced by [`run_webrtc_host`]).
        fps: u32,
        /// Maximum bytes per SHP fragment (clamped to the 64 KiB wire cap). Frames larger than this
        /// are split into multiple fragments the receiver reassembles. Use the wire cap (65535) in
        /// production; tests pass a small value to force fragmentation of small frames.
        max_fragment_bytes: usize,
        /// The frame source; [`VideoFrameSource::next_frame`] is called once per tick.
        source: Box<dyn VideoFrameSource>,
        /// Sink for browser→host input events (remote control). Inbound 16-byte [`InputEvent`]s on
        /// the DataChannel are decoded and injected via this between video frames (ADR-0034). The
        /// binary supplies the OS injector (X11 for the live host; a logging/no-op one otherwise).
        input: Box<dyn InputInjector>,
        /// Sink for browser→host clipboard paste (ADR-0037). Inbound [`ClipboardUpdate`]s on the
        /// dedicated Clipboard channel are decoded, **sanitized** ([`sanitize_for_paste`]), and
        /// written via this. The binary supplies the backend; the fail-closed default is
        /// [`sh_clipboard::NoopClipboard`] (inert — cannot touch the real OS clipboard), so a
        /// session with no granted clipboard backend cannot read or write it.
        clipboard: Box<dyn ClipboardAccess>,
    },
}

// ── Public entry point ──────────────────────────────────────────────────────────────────────────

/// Connect to `config.signaling_url`, complete the identity-bound Noise XK handshake, negotiate
/// a WebRTC DataChannel, and run `mode` (echo or video streaming), then return.
///
/// `on_fingerprint` is called with the host's 64-hex-char DTLS fingerprint immediately after it
/// is derived — before any network I/O — so the caller can publish it (e.g. `println!`) or record
/// it. The callback must not block the tokio runtime.
///
/// # Errors
///
/// Returns an error if signaling, the Noise handshake, SDP negotiation, or the DataChannel
/// exchange fails, or if a [`StreamMode::Video`] is given with `frames == 0` or `fps == 0`.
pub async fn run_webrtc_host(
    config: HostConfig,
    mode: StreamMode,
    on_fingerprint: impl FnOnce(&str),
) -> anyhow::Result<()> {
    // ── Step 1: create Rtc and obtain the local DTLS fingerprint ─────────────────────────────
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

    // Deliver the fingerprint to the caller before any network I/O.
    // The caller decides how to publish it (e.g. println! + stdout flush in the binary).
    on_fingerprint(&local_fp_hex);

    // ── Step 2: connect to the signaling server ───────────────────────────────────────────────
    let backoff = ExponentialBackoff::new(100, 5_000, 10);
    let mut sig_client = SignalingClient::connect(
        &config.signaling_url,
        config.session_id,
        local_fp_hex.clone(),
        backoff,
    )
    .await
    .context("failed to connect to signaling server")?;

    info!("connected to signaling server, waiting for browser Noise hello");

    // ── Step 3: identity-bound Noise XK handshake over signaling ─────────────────────────────
    //
    // The host is the XK responder. It generates its X25519 static, advertises the public key,
    // runs the 3-message XK exchange, and extracts the BROWSER's committed DTLS fingerprint to
    // pin. See `run_noise_responder` for the message ordering (ADR-0023).
    let keystore = SoftwareKeystore::generate();
    let (browser_fp, browser_dtls_pin) = run_noise_responder(
        &mut sig_client,
        &keystore,
        config.session_id,
        &local_fp_hex,
        local_dtls_commit,
    )
    .await
    .context("identity-bound Noise handshake failed")?;
    info!("Noise XK handshake complete; pinning browser's identity-bound DTLS fingerprint");

    // ── Step 4: receive the SDP offer from the browser ────────────────────────────────────────
    let offer_sdp = receive_offer(&mut sig_client, &browser_fp).await?;
    debug!("received SDP offer from browser");

    // ── Step 5: bind UDP socket first so we know the concrete local address ───────────────────
    //
    // Bind before building the transport so we can register the concrete local address
    // as a host ICE candidate. str0m requires at least one local candidate before ICE
    // connectivity checks (and therefore DTLS/DataChannel setup) can begin.
    //
    // We bind to 127.0.0.1 (not 0.0.0.0) because str0m rejects unspecified IPs as ICE
    // candidates. For this loopback-only e2e test, 127.0.0.1 is sufficient; real
    // multi-interface deployments would enumerate interface IPs instead.
    let local_bind: SocketAddr = config.bind.parse().context("invalid --bind address")?;
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

    // ── Step 6: send the SDP answer back to the browser ───────────────────────────────────────
    let answer_env = SignalingEnvelope {
        kind: MessageKind::Answer,
        session_id: config.session_id,
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
        session_id: config.session_id,
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
        session_id: config.session_id,
        from_fp: local_fp_hex.clone(),
        to_fp: browser_fp.clone(),
        payload: Bytes::new(),
    };
    sig_client
        .send(eoc_env)
        .await
        .context("failed to send EndOfCandidates")?;
    info!("sent EndOfCandidates to browser");

    // ── Step 7: start the drive loop ─────────────────────────────────────────────────────────

    let socket: Arc<dyn sh_transport::driver::AsyncUdpSocket> = Arc::new(udp_socket);
    let _driver_handle = spawn_webrtc_driver(Arc::clone(&transport), socket, now);

    // ── Step 8: accept the DataChannel in a separate task; simultaneously pump trickle candidates
    let transport_for_accept = Arc::clone(&transport);
    let accept_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        match mode {
            StreamMode::Echo => run_data_channel(&transport_for_accept).await,
            StreamMode::Video {
                frames,
                fps,
                max_fragment_bytes,
                mut source,
                input,
                clipboard,
            } => {
                run_video_stream(
                    &transport_for_accept,
                    frames,
                    fps,
                    max_fragment_bytes,
                    &mut *source,
                    input,
                    clipboard,
                )
                .await
            }
        }
    });

    // Pump trickle ICE candidates until we see end-of-candidates or the browser disconnects.
    pump_candidates(&mut sig_client, &transport).await?;
    sig_client.close().await.ok();

    // Wait for the DataChannel task to complete (echo exchange or video stream).
    accept_task
        .await
        .context("DataChannel task panicked")?
        .context("DataChannel exchange failed")?;

    // After the DataChannel task completes, the echo frames are queued in the transport's outbound
    // buffer (inner.outbound) but not yet transmitted — the driver task dispatches outbound UDP
    // datagrams on its own timer cycle. Give the driver task time to flush the outbound queue
    // before we return and the tokio runtime shuts down all tasks.
    //
    // 500 ms is generous: the driver's default poll fires every 50 ms, and SCTP retransmit is
    // fast on a local loopback. In production the server never exits after one exchange anyway.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    info!("browser↔native interop complete");
    Ok(())
}

// ── Public helpers ──────────────────────────────────────────────────────────────────────────────

/// Parse a 32-char lowercase hex string into a [`SessionId`].
///
/// # Errors
///
/// Returns an error if `hex` is not exactly 32 characters or contains non-hex characters.
pub fn parse_session_id(hex: &str) -> anyhow::Result<SessionId> {
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
    // The `if` above guarantees `hex.len() == 32`, so `chunks(2)` produces exactly 16 items;
    // `try_into()` on a `Vec<u8>` of length 16 into `[u8; 16]` is infallible.
    let arr: [u8; 16] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("session-id length mismatch (internal error)"))?;
    Ok(SessionId(arr))
}

/// Assemble one SHP video frame: `CommonHeader(9) || VideoHeader(12) || Annex-B payload`,
/// matching exactly what the browser's `parseVideoFrame` expects (single non-fragmented frame).
///
/// # Errors
///
/// Returns an error if `payload.len()` exceeds the SHP 16-bit `payload_len` cap (65 535 bytes).
pub fn build_shp_video_frame(
    sequence: u16,
    frame_id: u32,
    ts_us: u64,
    frame_type: FrameType,
    payload: &[u8],
) -> anyhow::Result<Bytes> {
    // A single (non-fragmented) frame: frag 0 of 1. Byte-identical to the historical layout.
    build_one_fragment(sequence, frame_id, ts_us, frame_type, payload, 0, 1)
}

/// Assemble one SHP fragment: `CommonHeader(9) || VideoHeader(12) || chunk`.
///
/// For `total_frags == 1` this is a single, non-fragmented frame (flags both clear, marker set) —
/// byte-identical to a frame with no fragmentation. For `total_frags > 1`, the `fragment` flag is
/// set on every fragment and `last_fragment`/`marker` are set on the final one.
fn build_one_fragment(
    sequence: u16,
    frame_id: u32,
    ts_us: u64,
    frame_type: FrameType,
    chunk: &[u8],
    frag_index: u8,
    total_frags: u8,
) -> anyhow::Result<Bytes> {
    let payload_len =
        u16::try_from(chunk.len()).context("SHP fragment exceeds 16-bit payload-length cap")?;
    let is_multi = total_frags > 1;
    // The last fragment is the one whose index is total_frags - 1 (checked_sub avoids underflow).
    let is_last = total_frags.checked_sub(1) == Some(frag_index);
    // `encode()` narrows both timestamps to their low 32 wire bits, so a u64 input is fine.
    let common = CommonHeader {
        channel: ChannelId::Video,
        flags: Flags {
            fragment: is_multi,
            last_fragment: is_multi && is_last,
        },
        sequence,
        timestamp_us: TimestampUs(ts_us),
        payload_len,
    }
    .encode();
    let video = VideoHeader {
        frame_id: FrameId(u64::from(frame_id)),
        frag_index,
        total_frags,
        codec: Codec::H264,
        frame_type,
        priority: Priority::High,
        monitor_id: 0,
        marker: is_last,
        encode_ts_us: TimestampUs(ts_us),
    }
    .encode()
    .context("encode video header")?;

    let cap = common
        .len()
        .saturating_add(video.len())
        .saturating_add(chunk.len());
    let mut buf = Vec::with_capacity(cap);
    buf.extend_from_slice(&common);
    buf.extend_from_slice(&video);
    buf.extend_from_slice(chunk);
    Ok(Bytes::from(buf))
}

/// Split an encoded access unit into one or more SHP video fragments, each ≤ `max_fragment_bytes`
/// (clamped to the SHP 16-bit `payload_len` cap). Reassembled in order by the receiver via the
/// video header's `frag_index`/`total_frags`/`marker`.
///
/// Fragments share `frame_id` + `frame_type`; `sequence` increments per fragment from
/// `sequence_start`. This removes the hard 64 KiB per-frame limit (ADR-0033), so full-resolution
/// frames no longer need downscaling.
///
/// # Errors
/// Returns an error if the frame would need more than 255 fragments (the 8-bit `total_frags` cap —
/// ~16 MiB at the 64 KiB chunk size, far beyond any real frame) or a header fails to encode.
pub fn build_shp_video_fragments(
    sequence_start: u16,
    frame_id: u32,
    ts_us: u64,
    frame_type: FrameType,
    payload: &[u8],
    max_fragment_bytes: usize,
) -> anyhow::Result<Vec<Bytes>> {
    let chunk_size = max_fragment_bytes.clamp(1, usize::from(u16::MAX));
    // div_ceil, min 1 fragment even for an (unexpected) empty payload.
    let total = payload.len().div_ceil(chunk_size).max(1);
    let total_frags =
        u8::try_from(total).context("encoded frame needs more than 255 SHP fragments")?;

    let mut out = Vec::with_capacity(total);
    // Empty payload → a single empty fragment (keeps `total >= 1` consistent).
    if payload.is_empty() {
        out.push(build_one_fragment(
            sequence_start,
            frame_id,
            ts_us,
            frame_type,
            &[],
            0,
            total_frags,
        )?);
        return Ok(out);
    }
    for (i, chunk) in payload.chunks(chunk_size).enumerate() {
        // i < total <= 255 (checked above), so this never errors — but propagate rather than fall
        // back to a wrong index that would emit a corrupt fragment.
        let frag_index =
            u8::try_from(i).context("frag_index overflow (invariant: i < total_frags)")?;
        // sequence wraps per fragment (u16 wire field); the receiver reassembles by frame_id.
        let seq = sequence_start.wrapping_add(frag_index.into());
        out.push(build_one_fragment(
            seq,
            frame_id,
            ts_us,
            frame_type,
            chunk,
            frag_index,
            total_frags,
        )?);
    }
    Ok(out)
}

// ── Private implementation ──────────────────────────────────────────────────────────────────────

/// Hex-encode a byte slice into a lowercase string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A synthetic [`Keystore`](sh_crypto::Keystore) that trusts every peer, with no-op trust-store mutation.
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
        // No persistent store => no peer is ever recorded as revoked.
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
    session_id: SessionId,
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
        session_id,
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
    send_noise(
        sig,
        session_id,
        local_fp_hex,
        &browser_fp,
        NOISE_SUB_MSG,
        &msg1,
    )
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

/// Wait for a `MessageKind::Noise` envelope carrying `NOISE_SUB_HELLO`; returns the browser's
/// `from_fp`.
///
/// The entire filter loop runs inside a single [`SIGNALING_STEP_TIMEOUT`] window so a hostile peer
/// that sends junk on every iteration cannot hold the loop open indefinitely by arriving just
/// before a per-iteration expiry.
async fn recv_noise_hello(sig: &mut SignalingClient) -> anyhow::Result<String> {
    tokio::time::timeout(SIGNALING_STEP_TIMEOUT, async {
        loop {
            let env = sig
                .recv()
                .await
                .context("signaling recv failed (Noise hello)")?
                .ok_or_else(|| anyhow::anyhow!("signaling connection closed before Noise hello"))?;
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
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out waiting for Noise hello"))?
}

/// Wait for a `MessageKind::Noise` envelope carrying `NOISE_SUB_MSG` from `expected_fp`; returns
/// the opaque Noise body.
///
/// The entire filter loop runs inside a single [`SIGNALING_STEP_TIMEOUT`] window (same rationale
/// as [`recv_noise_hello`]).
async fn recv_noise_msg(sig: &mut SignalingClient, expected_fp: &str) -> anyhow::Result<Vec<u8>> {
    tokio::time::timeout(SIGNALING_STEP_TIMEOUT, async {
        loop {
            let env = sig
                .recv()
                .await
                .context("signaling recv failed (Noise handshake message)")?
                .ok_or_else(|| {
                    anyhow::anyhow!("signaling connection closed before Noise handshake message")
                })?;
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
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out waiting for Noise handshake message"))?
}

/// Send a `MessageKind::Noise` envelope with `sub_type` prefixed onto `body`.
async fn send_noise(
    sig: &mut SignalingClient,
    session_id: SessionId,
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
        session_id,
        from_fp: from_fp.to_owned(),
        to_fp: to_fp.to_owned(),
        payload: Bytes::from(payload),
    };
    sig.send(env).await.context("failed to send Noise envelope")
}

/// Wait for a `MessageKind::Offer` envelope from `expected_fp`; returns the offer SDP text.
///
/// The entire filter loop runs inside a single [`SIGNALING_STEP_TIMEOUT`] window (same rationale
/// as [`recv_noise_hello`]).
async fn receive_offer(sig: &mut SignalingClient, expected_fp: &str) -> anyhow::Result<String> {
    tokio::time::timeout(SIGNALING_STEP_TIMEOUT, async {
        loop {
            let env = sig
                .recv()
                .await
                .context("signaling recv failed (SDP offer)")?
                .ok_or_else(|| anyhow::anyhow!("signaling connection closed before SDP offer"))?;
            if env.kind == MessageKind::Offer && env.from_fp == expected_fp {
                let offer_sdp = String::from_utf8(env.payload.to_vec())
                    .context("offer payload is not UTF-8")?;
                return Ok(offer_sdp);
            }
            debug!(kind = ?env.kind, "ignoring non-offer signaling message");
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out waiting for SDP offer"))?
}

/// Forward `Candidate` messages from signaling to the transport until `EndOfCandidates` or
/// `Bye` / connection close.
async fn pump_candidates(
    sig: &mut SignalingClient,
    transport: &Arc<PinnedWebRtcTransport>,
) -> anyhow::Result<()> {
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

/// Accept the **video (primary)** DataChannel, receive a message, and echo it back.
///
/// The browser (ADR-0036) opens two channels; it sends the HELLO/echo on the primary (video)
/// channel via `send_frame`. We route to that channel by spec (not open order) so the echo is
/// deterministic; any Input channel is accepted and dropped (the echo path doesn't use input).
async fn run_data_channel(transport: &PinnedWebRtcTransport) -> anyhow::Result<()> {
    info!("waiting for browser to open DataChannel(s)");
    let mut channel = accept_channels(transport).await?.video;

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

/// Accept the browser's DataChannel and stream H.264 SHP video frames from `source`, paced to
/// `fps` and stopping after `frames_to_send` have been sent. Between frames it drains any inbound
/// browser→host input events and feeds them to `input` (remote control; ADR-0034).
///
/// # Errors
///
/// Returns an error if the channel cannot be accepted or `source.next_frame()` fails. A send/recv
/// failure or a clean peer close is **not** an error — it ends the stream and returns `Ok(())`.
async fn run_video_stream(
    transport: &PinnedWebRtcTransport,
    frames_to_send: usize,
    fps: u32,
    max_fragment_bytes: usize,
    source: &mut dyn VideoFrameSource,
    input: Box<dyn InputInjector>,
    clipboard: Box<dyn ClipboardAccess>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        frames_to_send > 0,
        "--frames must be > 0 in video stream mode"
    );
    anyhow::ensure!(fps > 0, "StreamMode::Video fps must be > 0");

    info!("waiting for browser to open DataChannel(s) (video mode)");
    let AcceptedChannels {
        video: video_ch,
        input: input_ch,
        clipboard: clipboard_ch,
    } = accept_channels(transport).await?;

    // `checked_div` (not `/`) satisfies the arithmetic-side-effects lint; the `fps > 0` guard above
    // makes the divisor non-zero, so the `unwrap_or` fallback is unreachable.
    let per_us = 1_000_000u64.checked_div(u64::from(fps)).unwrap_or(1).max(1);
    info!(
        target = frames_to_send,
        fps,
        has_input_channel = input_ch.is_some(),
        has_clipboard_channel = clipboard_ch.is_some(),
        "streaming H.264 video frames to browser"
    );

    run_video_session(
        video_ch,
        input_ch,
        clipboard_ch,
        frames_to_send,
        per_us,
        max_fragment_bytes,
        source,
        input,
        clipboard,
    )
    .await
}

/// Legacy multiplexed-input video loop: no dedicated Input channel is present, so browser→host input
/// is drained off the SAME video channel between frames (ADR-0034). The injection thread's lifecycle
/// (and its `release_all()` on drop) is owned by the caller ([`run_video_session`]); this function
/// only borrows a sender clone, so it must not be the last owner.
async fn run_video_send_loop_with_input_drain(
    mut channel: Box<dyn Channel>,
    frames_to_send: usize,
    per_us: u64,
    max_fragment_bytes: usize,
    source: &mut dyn VideoFrameSource,
    input_tx: &tokio::sync::mpsc::Sender<InputEvent>,
) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(Duration::from_micros(per_us));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut sent: usize = 0;
    let mut sequence: u16 = 0;
    // Hostile-input DoS guard: throttle drop-safe high-rate input (pointer-move + wheel; see the
    // const docs and `admit_input`). `throttled_events` counts events shed so a sustained flood is
    // observable in the logs (never per-event — §7).
    let mut input_limiter = RateLimiter::new(MAX_THROTTLED_INPUT_PER_SEC, THROTTLED_INPUT_BURST);
    let mut throttled_events: u64 = 0;
    let mut stream_err: Option<anyhow::Error> = None;
    'stream: while sent < frames_to_send {
        ticker.tick().await;
        match send_one_frame(
            &mut *channel,
            source,
            sent as u64,
            per_us,
            sequence,
            max_fragment_bytes,
        )
        .await
        {
            FrameStep::Sent(num_frags) => {
                sent = sent.saturating_add(1);
                sequence = sequence.wrapping_add(num_frags);
            }
            FrameStep::Skipped => continue,
            FrameStep::PeerClosed => {
                info!(frames = sent, "peer closed channel — ending video stream");
                break 'stream;
            }
            FrameStep::Failed(e) => {
                stream_err = Some(e);
                break 'stream;
            }
        }

        // Drain any browser→host input that arrived while pacing/sending this frame. `timeout(ZERO,
        // recv())` is a single non-blocking poll (recv is cancel-safe: it pops from the queue under
        // the mutex before awaiting, so cancelling leaves the message for the next poll). The
        // per-frame cap (`MAX_INPUT_PER_FRAME`) stops a flood from starving the video send loop; the
        // bounded `input_tx` channel is the second backpressure point.
        for _ in 0..MAX_INPUT_PER_FRAME {
            match tokio::time::timeout(Duration::ZERO, channel.recv()).await {
                Ok(Ok(Some(bytes))) => {
                    forward_input(&bytes, input_tx, &mut input_limiter, &mut throttled_events);
                }
                Ok(Ok(None)) => {
                    info!(frames = sent, "peer closed channel — ending video stream");
                    break 'stream;
                }
                Ok(Err(e)) => {
                    info!(frames = sent, error = %e, "channel recv error — ending video stream");
                    break 'stream;
                }
                Err(_elapsed) => break, // no more buffered input this round
            }
        }
    }

    if throttled_events > 0 {
        warn!(
            throttled_events,
            "throttled high-rate input events (pointer-move/wheel — hostile-input guard)"
        );
    }
    match stream_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// The mandatory video channel plus the optional dedicated Input (ADR-0036) and Clipboard
/// (ADR-0037) channels, resolved from the peer's opened DataChannels.
struct AcceptedChannels {
    /// The (mandatory) video channel — also the legacy single-channel peer's only channel.
    video: Box<dyn Channel>,
    /// The optional dedicated low-latency Input channel (ADR-0036).
    input: Option<Box<dyn Channel>>,
    /// The optional dedicated reliable Clipboard channel (ADR-0037).
    clipboard: Option<Box<dyn Channel>>,
}

/// Bounded wait for the OPTIONAL dedicated Input (ADR-0036) and/or Clipboard (ADR-0037) channels
/// after the mandatory video channel is accepted.
///
/// A single-channel (legacy) peer never opens a dedicated channel, so we must NOT block on the
/// transport's full 30 s accept timeout waiting for one. A multi-channel browser creates every
/// channel before `createOffer`, so their `ChannelOpen` events arrive within the same DTLS/SCTP
/// setup window (tens of ms apart) — 2 s is a ~100× margin over that skew.
///
/// Full wait for the FIRST extra channel to appear (a peer that opens none pays this once — the
/// legacy single-channel cost, unchanged). A multi-channel peer's first extra arrives in tens of ms.
const FIRST_EXTRA_CHANNEL_TIMEOUT: Duration = Duration::from_secs(2);

/// Wait for EACH SUBSEQUENT extra channel after the first arrives. All of a peer's channels open
/// within the same DTLS/SCTP setup window (tens of ms apart), so once the first extra is in, the
/// next is at most this far behind — a ~10× margin over the real skew. This is what keeps today's
/// two-channel (video + input) peer from paying the full 2 s waiting for a third channel it never
/// opens: it stops ~250 ms after input arrives, not 2 s (was the pre-Clipboard behavior's ~0, so a
/// small, bounded tax until the browser opens the Clipboard channel too — then the loop exits early
/// at [`MAX_EXTRA_CHANNELS`] with no skew wait at all).
const INTER_CHANNEL_SKEW: Duration = Duration::from_millis(250);

/// Optional dedicated channels a peer may open beyond the mandatory video channel (today: Input,
/// Clipboard). Bounds the accept loop so a peer can't make us wait on unbounded extra channels.
const MAX_EXTRA_CHANNELS: usize = 2;

/// Accept the video channel and the optional dedicated Input/Clipboard channels (ADR-0036/0037).
///
/// Accepts the first channel (transport's normal timeout), then runs a bounded window to pick up up
/// to [`MAX_EXTRA_CHANNELS`] more — a full [`FIRST_EXTRA_CHANNEL_TIMEOUT`] for the first extra, then
/// only an [`INTER_CHANNEL_SKEW`] for each subsequent one (all of a peer's channels open within tens
/// of ms of each other). Classifies them by parsed [`Channel::spec`]`().channel` — order-independent,
/// since SCTP stream numbering need not match the browser's `createDataChannel` order. A legacy
/// single-channel peer (whose `"shp"` label parses to [`ChannelId::Control`]) yields only `video` and
/// uses the between-frames drain path.
///
/// # Errors
/// Returns an error if the first channel cannot be accepted, or if no usable video channel opened.
async fn accept_channels(transport: &PinnedWebRtcTransport) -> anyhow::Result<AcceptedChannels> {
    let first = transport
        .accept_channel()
        .await
        .context("failed to accept the first DataChannel")?;

    let mut extra: Vec<Box<dyn Channel>> = Vec::with_capacity(MAX_EXTRA_CHANNELS);
    while extra.len() < MAX_EXTRA_CHANNELS {
        // Full window for the FIRST extra; only a short inter-channel skew for subsequent ones. This
        // is what stops today's {video, input} peer from waiting the full 2 s for a third channel it
        // never opens (it breaks ~250 ms after input arrives) while still catching a genuine third
        // channel that opens tens of ms behind the second.
        let wait = if extra.is_empty() {
            FIRST_EXTRA_CHANNEL_TIMEOUT
        } else {
            INTER_CHANNEL_SKEW
        };
        // `accept_channel` is cancel-safe (it pops from the accept queue under the lock BEFORE
        // awaiting), so a channel arriving after our bounded wait elapses stays queued, not lost.
        match tokio::time::timeout(wait, transport.accept_channel()).await {
            Ok(Ok(ch)) => extra.push(ch),
            // The transport's own timeout/closed, or our bounded wait elapsing → stop waiting.
            Ok(Err(_)) | Err(_) => break,
        }
    }
    classify_channels(std::iter::once(first).chain(extra).collect())
}

/// Partition accepted channels into video / optional input / optional clipboard by parsed
/// [`ChannelSpec`] — pure + order-independent (SCTP stream numbering need not match the browser's
/// `createDataChannel` order).
///
/// [`ChannelId::Input`] → the input channel; [`ChannelId::Clipboard`] → the clipboard channel;
/// anything else (Video, or the legacy `"shp"` label that parses to Control) → the video channel. A
/// second channel of any class is ignored.
///
/// # Errors
/// Returns an error if no usable video channel is present.
fn classify_channels(channels: Vec<Box<dyn Channel>>) -> anyhow::Result<AcceptedChannels> {
    let mut video: Option<Box<dyn Channel>> = None;
    let mut input: Option<Box<dyn Channel>> = None;
    let mut clipboard: Option<Box<dyn Channel>> = None;
    for ch in channels {
        match ch.spec().channel {
            ChannelId::Input => {
                if input.is_some() {
                    warn!("ignoring unexpected extra Input DataChannel");
                }
                input = Some(ch);
            }
            ChannelId::Clipboard => {
                if clipboard.is_some() {
                    warn!("ignoring unexpected extra Clipboard DataChannel");
                }
                clipboard = Some(ch);
            }
            other => {
                if video.is_none() {
                    video = Some(ch);
                } else {
                    warn!(channel = ?other, "ignoring unexpected extra DataChannel");
                }
            }
        }
    }
    let video = video.context("peer opened no usable video DataChannel")?;
    Ok(AcceptedChannels {
        video,
        input,
        clipboard,
    })
}

/// Spawn the dedicated injection thread.
///
/// The [`InputInjector`] contract requires `inject()` to run OFF the async runtime (XTEST etc. are
/// synchronous OS calls that could stall the executor). The thread is fed by a BOUNDED channel
/// (the natural backpressure/flood point — a full queue drops rather than blocks). When **all**
/// senders drop, the thread exits its `blocking_recv` loop and runs
/// [`InputInjector::release_all`](sh_input::InputInjector::release_all) so a disconnect can't leave
/// a button stuck (ADR-0034). (`release_all` runs on every sender-drop path; it would be skipped
/// only if an `inject()` call itself panicked and unwound the thread — the injector impls are
/// panic-free by construction, so this is not reachable in practice.) Returns the sender + handle.
fn spawn_injection_thread(
    input: Box<dyn InputInjector>,
) -> (
    tokio::sync::mpsc::Sender<InputEvent>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<InputEvent>(INPUT_QUEUE_DEPTH);
    let handle = tokio::task::spawn_blocking(move || {
        let mut injector = input;
        while let Some(event) = rx.blocking_recv() {
            if let Err(e) = injector.inject(&event) {
                // An injection failure (unsupported event / backend error) must not kill the
                // session — log and keep going.
                debug!(error = %e, "input injection failed");
            }
        }
        // All senders dropped (session ending): release any held button/key.
        injector.release_all();
    });
    (tx, handle)
}

/// Decode + admit one inbound input message and forward it to the injection thread.
/// Shared by the legacy drain and the dedicated input task. Malformed bytes are ignored;
/// throttled (rate-limited) events bump `throttled` instead of being enqueued.
fn forward_input(
    bytes: &[u8],
    input_tx: &tokio::sync::mpsc::Sender<InputEvent>,
    limiter: &mut RateLimiter,
    throttled: &mut u64,
) {
    if let Some(event) = decode_input(bytes) {
        if admit_input(&event, limiter, Instant::now()) {
            // Non-blocking enqueue; a full queue drops the event (backpressure), never blocks.
            let _ = input_tx.try_send(event);
        } else {
            *throttled = throttled.saturating_add(1);
        }
    }
}

/// Outcome of attempting to send one video frame (see [`send_one_frame`]).
enum FrameStep {
    /// Sent as `num_frags` SHP fragments; advance the sequence by this much.
    Sent(u16),
    /// Dropped (needed > 255 fragments) and a keyframe was re-armed — keep going.
    Skipped,
    /// A fragment send failed: the peer closed the channel — a NORMAL end of stream.
    PeerClosed,
    /// The frame source or a fragment-count invariant failed — an abnormal end.
    Failed(anyhow::Error),
}

/// Build and send one video frame as SHP fragments. Shared by both the legacy single-channel loop
/// and the dual-channel `run_video_send_loop` so the intricate fragmentation/sequence logic lives in
/// exactly one place. On a send failure it returns [`FrameStep::PeerClosed`] WITHOUT logging — the
/// caller logs it once, with the frame count for context (avoids a duplicate log line).
async fn send_one_frame(
    channel: &mut dyn Channel,
    source: &mut dyn VideoFrameSource,
    sent_index: u64,
    per_us: u64,
    sequence: u16,
    max_fragment_bytes: usize,
) -> FrameStep {
    let (frame_type, payload) = match source.next_frame() {
        Ok(v) => v,
        Err(e) => return FrameStep::Failed(e),
    };
    // frame_id is a 24-bit wire field; mask into range (`try_from` not `as` for the cast lint).
    let frame_id = u32::try_from(sent_index & u64::from(MAX_FRAME_ID)).unwrap_or(0);
    let ts_us = sent_index.wrapping_mul(per_us);
    let fragments = match build_shp_video_fragments(
        sequence,
        frame_id,
        ts_us,
        frame_type,
        &payload,
        max_fragment_bytes,
    ) {
        Ok(f) => f,
        Err(e) => {
            warn!(bytes = payload.len(), error = %e, "frame needs > 255 fragments — dropping");
            source.request_keyframe();
            return FrameStep::Skipped;
        }
    };
    let num_frags =
        match u16::try_from(fragments.len()).context("fragment count exceeded u16 (invariant)") {
            Ok(v) => v,
            Err(e) => return FrameStep::Failed(e),
        };
    for frag in fragments {
        // A send failure means the peer closed the DataChannel — a NORMAL end of stream. Return
        // without logging; the caller logs once with the frame count.
        if channel.send(frag).await.is_err() {
            return FrameStep::PeerClosed;
        }
    }
    FrameStep::Sent(num_frags)
}

/// Video send loop with NO inline input drain — the dual-channel path (ADR-0036) handles input on a
/// dedicated task/channel, so the video loop is never coupled to input pacing.
async fn run_video_send_loop(
    mut video_ch: Box<dyn Channel>,
    frames_to_send: usize,
    per_us: u64,
    max_fragment_bytes: usize,
    source: &mut dyn VideoFrameSource,
) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(Duration::from_micros(per_us));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut sent: usize = 0;
    let mut sequence: u16 = 0;
    while sent < frames_to_send {
        ticker.tick().await;
        match send_one_frame(
            &mut *video_ch,
            source,
            sent as u64,
            per_us,
            sequence,
            max_fragment_bytes,
        )
        .await
        {
            FrameStep::Sent(n) => {
                sent = sent.saturating_add(1);
                sequence = sequence.wrapping_add(n);
            }
            FrameStep::Skipped => continue,
            FrameStep::PeerClosed => {
                info!(frames = sent, "peer closed channel — ending video stream");
                return Ok(());
            }
            FrameStep::Failed(e) => return Err(e),
        }
    }
    info!(frames = sent, "video stream complete");
    Ok(())
}

/// Dedicated input-receive task (dual-channel path): own the Input channel and forward every event
/// to the injection thread the instant it arrives — no frame-pacing coupling. Returns when the peer
/// closes/errors the channel (or it is aborted at session end). Its `input_tx` clone drops on
/// return, removing one sender from the injection thread's view.
async fn run_input_recv(
    mut input_ch: Box<dyn Channel>,
    input_tx: tokio::sync::mpsc::Sender<InputEvent>,
) {
    let mut limiter = RateLimiter::new(MAX_THROTTLED_INPUT_PER_SEC, THROTTLED_INPUT_BURST);
    let mut throttled: u64 = 0;
    loop {
        match input_ch.recv().await {
            Ok(Some(bytes)) => forward_input(&bytes, &input_tx, &mut limiter, &mut throttled),
            Ok(None) => {
                info!("input channel closed by peer");
                break;
            }
            Err(e) => {
                info!(error = %e, "input channel recv error");
                break;
            }
        }
    }
    if throttled > 0 {
        warn!(
            throttled_events = throttled,
            "throttled high-rate input events (pointer-move/wheel — hostile-input guard)"
        );
    }
}

/// Unified video session driver (ADR-0036 Input, ADR-0037 Clipboard): the mandatory video channel
/// plus 0–2 optional dedicated channels, in any combination.
///
/// - **No dedicated Input channel** → the video loop drains input off the video channel between
///   frames (legacy peers; [`run_video_send_loop_with_input_drain`]).
/// - **Dedicated Input channel** → a dedicated input task RACES the inline video loop; whichever
///   ends first ends the session (ADR-0036, lowest click-to-photon).
/// - **Dedicated Clipboard channel** (if any) NEVER races the session — its close is a non-fatal,
///   expected event. It runs as its own task and is always aborted+awaited in teardown.
///
/// # Teardown (safety-critical)
/// The injection thread is fed by a bounded mpsc; on EVERY exit its senders are dropped so the
/// thread runs `release_all()` — no held button can leak (ADR-0034). The clipboard task is
/// unconditionally aborted+awaited (it is never a `select!` arm, so its `JoinHandle` is polled
/// exactly once here — no double-poll guard needed, unlike the input task).
#[allow(clippy::too_many_arguments)] // one coherent session; splitting the arg list would obscure it
async fn run_video_session(
    video_ch: Box<dyn Channel>,
    input_ch: Option<Box<dyn Channel>>,
    clipboard_ch: Option<Box<dyn Channel>>,
    frames_to_send: usize,
    per_us: u64,
    max_fragment_bytes: usize,
    source: &mut dyn VideoFrameSource,
    input: Box<dyn InputInjector>,
    clipboard: Box<dyn ClipboardAccess>,
) -> anyhow::Result<()> {
    let (input_tx, inject_task) = spawn_injection_thread(input);
    // The clipboard task, if a dedicated Clipboard channel opened. All-owned ⇒ `'static`.
    let clipboard_handle = clipboard_ch.map(|ch| tokio::spawn(run_clipboard(ch, clipboard)));

    let result = match input_ch {
        Some(input_ch) => {
            // Dedicated Input channel: race the inline video loop against a dedicated input task.
            let mut input_handle = tokio::spawn(run_input_recv(input_ch, input_tx.clone()));
            let video_fut =
                run_video_send_loop(video_ch, frames_to_send, per_us, max_fragment_bytes, source);
            tokio::pin!(video_fut);
            let mut input_finished = false;
            let result = tokio::select! {
                r = &mut video_fut => r,
                join = &mut input_handle => {
                    // The input task ended: a clean peer close/error, OR an unexpected panic.
                    // Surface a panic (don't silently end as a clean close); teardown is unaffected
                    // either way — the task's sender clone drops on unwind, so `release_all()` fires.
                    if join.as_ref().is_err_and(tokio::task::JoinError::is_panic) {
                        warn!("input recv task panicked — ending session (held input released)");
                    }
                    // End the session. The in-flight `video_fut` is dropped — its await points
                    // (`ticker.tick()`/`channel.send()`) are cancel-safe (at worst a partial
                    // fragment is lost, and the session is ending anyway).
                    input_finished = true;
                    Ok(())
                }
            };
            // If the input task already finished (its arm fired), its `JoinHandle` was polled to
            // completion — polling again would panic — and its sender clone already dropped.
            // Otherwise (video ended first) it is still running: abort + await so its clone drops.
            if !input_finished {
                input_handle.abort();
                let _ = input_handle.await;
            }
            result
        }
        None => {
            // No dedicated Input channel: legacy path drains input off the video channel.
            run_video_send_loop_with_input_drain(
                video_ch,
                frames_to_send,
                per_us,
                max_fragment_bytes,
                source,
                &input_tx,
            )
            .await
        }
    };

    // ── Teardown — runs on EVERY exit so `release_all()` always fires (ADR-0034). ──
    drop(input_tx); // drop the outer clone → injection thread sees all senders gone
    let _ = inject_task.await; // injection thread exits its loop and runs release_all()

    // The clipboard task never ends the session; abort+await it now so it stops cleanly. Aborting it
    // mid-`spawn_blocking` can't preempt an in-flight OS write, but a late clipboard write is
    // harmless (idempotent overwrite, no stuck-state hazard like held input).
    if let Some(handle) = clipboard_handle {
        handle.abort();
        let _ = handle.await;
    }

    match &result {
        Ok(()) => info!("video stream complete"),
        Err(_) => warn!("video stream ended with error (held input released)"),
    }
    result
}

/// Decode one inbound Clipboard message into paste-ready, **sanitized** text, or `None` when there
/// is nothing safe to write (malformed bytes / decode error, a non-text format, or content that
/// sanitizes to empty). Mirrors the input path's "malformed → ignore, never crash" contract.
///
/// §7: NEVER logs content — callers log only a byte count. The size/format/UTF-8 bounds are enforced
/// by [`ClipboardUpdate::decode`]; the paste-injection hardening by [`sanitize_for_paste`].
fn decode_clipboard_paste(bytes: &[u8]) -> Option<String> {
    let update = match ClipboardUpdate::decode(bytes) {
        Ok(u) => u,
        Err(e) => {
            debug!(error = %e, "dropping malformed clipboard update");
            return None;
        }
    };
    // Only `Text` exists today; a future non-text format would yield `None` here (it must get its
    // own sanitizer + threat model before it can be applied — ADR-0037 §7).
    let text = update.as_text()?;
    sanitize_for_paste(text)
}

/// Dedicated clipboard task (ADR-0037): owns the bidirectional Clipboard channel. On start it
/// **offers** the host's clipboard to the browser once (host→browser), then loops applying every
/// browser→host paste in arrival order. Unlike [`run_input_recv`], this task NEVER races the
/// session — its natural end (peer close/error) is a non-fatal, expected event; video/input remain
/// the only session drivers. It is always aborted+awaited by [`run_video_session`] on session end.
async fn run_clipboard(mut clipboard_ch: Box<dyn Channel>, clipboard: Box<dyn ClipboardAccess>) {
    let mut sink = clipboard;

    // ── Host→browser: offer the host's clipboard once at session start. ──
    // `get_text` may block on OS/IPC (the `ClipboardAccess` contract), so read it off the runtime.
    match tokio::task::spawn_blocking(move || {
        let read = sink.get_text();
        (sink, read)
    })
    .await
    {
        Ok((returned, Ok(Some(text)))) => {
            sink = returned;
            // Bound to the wire limit (a huge host clipboard is dropped, not truncated). §7: byte
            // count only, never content.
            match ClipboardUpdate::text(&text) {
                // Send failure is non-fatal (the browser→host receive loop below still runs) but is
                // logged like every other branch — §7: byte count / error only, never content.
                Ok(update) => match clipboard_ch.send(Bytes::from(update.encode())).await {
                    Ok(()) => debug!(bytes = text.len(), "offered host clipboard to browser"),
                    Err(e) => debug!(error = %e, "failed to send host clipboard offer"),
                },
                Err(e) => debug!(error = %e, "host clipboard too large to offer — skipped"),
            }
        }
        Ok((returned, Ok(None))) => sink = returned, // host clipboard empty / non-text — nothing to offer
        Ok((returned, Err(e))) => {
            debug!(error = %e, "reading host clipboard to offer failed");
            sink = returned;
        }
        Err(_join_err) => {
            warn!("clipboard get_text task panicked — ending clipboard task");
            return;
        }
    }

    // ── Browser→host: apply every inbound paste in wire order. ──
    loop {
        match clipboard_ch.recv().await {
            Ok(Some(bytes)) => {
                // §7: byte count only, never content.
                debug!(bytes = bytes.len(), "clipboard update received");
                let Some(text) = decode_clipboard_paste(&bytes) else {
                    continue;
                };
                // `set_text` may block on OS/IPC (see the `ClipboardAccess` contract) — never call
                // it inline on the async runtime. One `spawn_blocking` per update (not a persistent
                // thread: paste is rare/bursty and `set_text` has no ADR-0034-style stuck state to
                // guard on drop), awaited before the next `recv()` so writes apply in wire order.
                match tokio::task::spawn_blocking(move || {
                    let result = sink.set_text(&text);
                    (sink, result)
                })
                .await
                {
                    Ok((returned, Ok(()))) => sink = returned,
                    Ok((returned, Err(e))) => {
                        debug!(error = %e, "clipboard set_text failed");
                        sink = returned;
                    }
                    Err(_join_err) => {
                        // A panic in `set_text` loses `sink`'s ownership, ending this task —
                        // non-fatal: video/input are unaffected. Backends are panic-free by
                        // construction (same assumption as `InputInjector`).
                        warn!("clipboard set_text task panicked — ending clipboard receive");
                        return;
                    }
                }
            }
            Ok(None) => {
                info!("clipboard channel closed by peer");
                return;
            }
            Err(e) => {
                info!(error = %e, "clipboard channel recv error");
                return;
            }
        }
    }
}

/// Decide whether a decoded input event is admitted past the hostile-input rate limiter.
///
/// Events are classified by **drop-safety**, not by a single variant:
///
/// - **Rate-limited** — `PointerMove` and `Wheel`. Both are stateless, high-rate flood vectors that
///   are safe to shed: a move carries an absolute position (the next move supersedes a dropped one),
///   and a wheel event is one self-contained scroll notch (dropping it loses at most a notch, never
///   any held state). These are the events a hostile client can spam fastest, so they go through the
///   bucket.
/// - **Always admitted** — `Button` and `Key`. These are state *transitions*; dropping a *release*
///   would leave the controlled machine with a button or key stuck down — the exact hazard
///   [`sh_input::InputInjector::release_all`] exists to close (ADR-0034). They never touch the
///   limiter, so they never consume tokens and can never be throttled.
/// - **Always admitted (for now)** — `Touch` and `Pen`. These carry contact/lift state via
///   `pressure`, so they are *not* purely drop-safe, and they are `Unsupported` on every injector
///   today. They are admitted unthrottled until a deliberate contact-aware policy lands (tracked
///   follow-up) — they must not be silently shed by the move/wheel bucket.
///
/// NOTE: the "absolute position ⇒ drop-safe" property of `PointerMove` holds because this protocol's
/// `pointer_x`/`pointer_y` are absolute normalized coords. A future relative/pointer-lock input mode
/// would NOT be drop-safe and must revisit this classification.
///
/// Returns `true` to enqueue the event for injection, `false` to drop it.
fn admit_input(event: &InputEvent, limiter: &mut RateLimiter, now: Instant) -> bool {
    match event.event_type {
        // Stateless, high-rate, drop-safe vectors → rate-limited.
        EventType::PointerMove | EventType::Wheel => limiter.allow(now),
        // State transitions (a dropped release would stick) → always admitted.
        EventType::Button | EventType::Key => true,
        // Contact events carry lift/contact state and are Unsupported today → admit, don't shed.
        EventType::Touch | EventType::Pen => true,
    }
}

/// Decode one inbound DataChannel message as an [`InputEvent`], or `None` if it is not one.
///
/// The browser sends bare 16-byte `InputEvent`s on the video channel (the host only ever *sends*
/// video, so every *received* message is browser→host input). Messages that are not a well-formed
/// 16-byte input event (e.g. the browser's channel-open HELLO frame) return `None`; a hostile or
/// malformed event can never crash the host (decode is bounds-checked + proptest-fuzzed).
fn decode_input(bytes: &[u8]) -> Option<InputEvent> {
    if bytes.len() != INPUT_EVENT_LEN {
        return None; // not an input event (e.g. the HELLO open frame) — ignore
    }
    match InputEvent::decode(bytes) {
        Ok(event) => Some(event),
        Err(e) => {
            debug!(error = %e, "dropping malformed input event");
            None
        }
    }
}

// ── Unit tests (moved from src/main.rs — behavior must be identical) ────────────────────────────

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::{
        build_shp_video_fragments, build_shp_video_frame, parse_baked_frames, BAKED_H264,
        NOISE_SUB_HELLO, NOISE_SUB_HOST_STATIC_PUB, NOISE_SUB_MSG,
    };
    use bytes::Bytes;
    use sh_protocol::{
        Codec, CommonHeader, FrameType, VideoHeader, COMMON_HEADER_LEN, INPUT_EVENT_LEN,
    };
    use sh_types::ChannelId;

    /// Dedicated-input-channel (ADR-0036) host logic: channel classification + the safety-critical
    /// dual-channel teardown (`release_all` must fire on every exit order).
    mod dual {
        use super::super::{
            classify_channels, decode_clipboard_paste, run_clipboard, run_video_session,
            VideoFrameSource,
        };
        use bytes::Bytes;
        use sh_clipboard::{ClipboardAccess, ClipboardError, NoopClipboard};
        use sh_input::{InputError, InputInjector};
        use sh_protocol::{ClipboardUpdate, EventType, FrameType, InputEvent, Modifiers};
        use sh_transport::channel::{Channel, ChannelSpec};
        use sh_transport::TransportError;
        use sh_types::ChannelId;
        use std::collections::VecDeque;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        /// Convenience: the fail-closed clipboard sink for the input-focused tests.
        fn noop_clipboard() -> Box<dyn ClipboardAccess> {
            Box::new(NoopClipboard::new())
        }

        type RecvQueue = VecDeque<Result<Option<Bytes>, TransportError>>;

        /// A `Channel` test double: counts sends; replays a scripted `recv` queue, then either closes
        /// (`Ok(None)`) or pends forever — so a test can drive either exit order.
        struct MockChannel {
            spec: ChannelSpec,
            recvs: Mutex<RecvQueue>,
            pend_when_empty: bool,
            sent: Arc<Mutex<usize>>,
        }

        impl MockChannel {
            fn boxed(spec: ChannelSpec) -> Box<dyn Channel> {
                Box::new(Self {
                    spec,
                    recvs: Mutex::new(VecDeque::new()),
                    pend_when_empty: false,
                    sent: Arc::new(Mutex::new(0)),
                })
            }
        }

        #[async_trait::async_trait]
        impl Channel for MockChannel {
            async fn send(&mut self, _msg: Bytes) -> Result<(), TransportError> {
                *self.sent.lock().unwrap() += 1;
                Ok(())
            }
            async fn recv(&mut self) -> Result<Option<Bytes>, TransportError> {
                let next = self.recvs.lock().unwrap().pop_front();
                match next {
                    Some(r) => r,
                    // Never resolves — keeps the channel "open" so a test can drive the other exit
                    // path. `pending()` yields the arm's own type, so no `unreachable!` is needed.
                    None if self.pend_when_empty => std::future::pending().await,
                    None => Ok(None),
                }
            }
            fn spec(&self) -> &ChannelSpec {
                &self.spec
            }
        }

        /// A clipboard `Channel` double that CAPTURES sent bytes (so a test can decode the host's
        /// offer) and can be told to FAIL sends. `recvs` then `Ok(None)` closes it so `run_clipboard`
        /// returns deterministically.
        struct CaptureChannel {
            spec: ChannelSpec,
            sent: Arc<Mutex<Vec<Bytes>>>,
            send_ok: bool,
            recvs: Mutex<RecvQueue>,
        }
        impl CaptureChannel {
            fn boxed(
                sent: Arc<Mutex<Vec<Bytes>>>,
                send_ok: bool,
                recvs: RecvQueue,
            ) -> Box<dyn Channel> {
                Box::new(Self {
                    spec: ChannelSpec::clipboard(),
                    sent,
                    send_ok,
                    recvs: Mutex::new(recvs),
                })
            }
        }
        #[async_trait::async_trait]
        impl Channel for CaptureChannel {
            async fn send(&mut self, msg: Bytes) -> Result<(), TransportError> {
                if !self.send_ok {
                    return Err(TransportError::StreamClosed);
                }
                self.sent.lock().unwrap().push(msg);
                Ok(())
            }
            async fn recv(&mut self) -> Result<Option<Bytes>, TransportError> {
                match self.recvs.lock().unwrap().pop_front() {
                    Some(r) => r,
                    None => Ok(None), // closed → run_clipboard's receive loop returns
                }
            }
            fn spec(&self) -> &ChannelSpec {
                &self.spec
            }
        }

        /// An `InputInjector` that records inject count and whether `release_all` fired.
        struct TrackingInjector {
            injected: Arc<AtomicUsize>,
            released: Arc<AtomicBool>,
        }
        impl InputInjector for TrackingInjector {
            fn inject(&mut self, _e: &InputEvent) -> Result<(), InputError> {
                self.injected.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            fn release_all(&mut self) {
                self.released.store(true, Ordering::SeqCst);
            }
        }

        /// A `VideoFrameSource` yielding a tiny single-fragment IDR each call (the loop bounds count).
        struct TestFrameSource;
        impl VideoFrameSource for TestFrameSource {
            fn next_frame(&mut self) -> anyhow::Result<(FrameType, Vec<u8>)> {
                Ok((FrameType::Idr, vec![0u8; 8]))
            }
        }

        /// A 16-byte encoded `Button` event (always admitted past the rate limiter).
        fn button_bytes() -> Bytes {
            let ev = InputEvent {
                event_type: EventType::Button,
                modifiers: Modifiers::empty(),
                pointer_x: 0,
                pointer_y: 0,
                button_mask: 0x01,
                key_code: 0,
                scroll_x: 0,
                scroll_y: 0,
                pressure: 0,
            };
            Bytes::copy_from_slice(&ev.encode())
        }

        #[test]
        fn classify_routes_by_spec_order_independent() {
            // video then input
            let c = classify_channels(vec![
                MockChannel::boxed(ChannelSpec::video()),
                MockChannel::boxed(ChannelSpec::input()),
            ])
            .unwrap();
            assert_eq!(c.video.spec().channel, ChannelId::Video);
            assert_eq!(c.input.unwrap().spec().channel, ChannelId::Input);
            assert!(c.clipboard.is_none());
            // input then video (reversed open order) → same routing
            let c = classify_channels(vec![
                MockChannel::boxed(ChannelSpec::input()),
                MockChannel::boxed(ChannelSpec::video()),
            ])
            .unwrap();
            assert_eq!(c.video.spec().channel, ChannelId::Video);
            assert_eq!(c.input.unwrap().spec().channel, ChannelId::Input);
        }

        #[test]
        fn classify_routes_clipboard_order_independent() {
            // A three-channel peer (video + input + clipboard) in a scrambled open order still routes
            // each channel to its slot — the clipboard channel is not mistaken for video (the bug the
            // Clipboard match arm fixes).
            let c = classify_channels(vec![
                MockChannel::boxed(ChannelSpec::clipboard()),
                MockChannel::boxed(ChannelSpec::video()),
                MockChannel::boxed(ChannelSpec::input()),
            ])
            .unwrap();
            assert_eq!(c.video.spec().channel, ChannelId::Video);
            assert_eq!(c.input.unwrap().spec().channel, ChannelId::Input);
            assert_eq!(c.clipboard.unwrap().spec().channel, ChannelId::Clipboard);
        }

        #[test]
        fn classify_video_plus_clipboard_no_input() {
            // {video, clipboard} with NO input must NOT fall to the legacy path with clipboard lost:
            // clipboard is routed to its slot and video has no dedicated input.
            let c = classify_channels(vec![
                MockChannel::boxed(ChannelSpec::video()),
                MockChannel::boxed(ChannelSpec::clipboard()),
            ])
            .unwrap();
            assert_eq!(c.video.spec().channel, ChannelId::Video);
            assert!(c.input.is_none());
            assert_eq!(c.clipboard.unwrap().spec().channel, ChannelId::Clipboard);
        }

        #[test]
        fn classify_legacy_single_control_is_video_no_input() {
            // Today's browser opens one "shp" channel that parses to Control → routed as video, no
            // input channel → the caller uses the legacy between-frames drain.
            let c = classify_channels(vec![MockChannel::boxed(ChannelSpec::control())]).unwrap();
            assert_eq!(c.video.spec().channel, ChannelId::Control);
            assert!(c.input.is_none());
            assert!(c.clipboard.is_none());
        }

        #[test]
        fn classify_no_video_errors() {
            // Only an input channel and nothing video-class → no usable video → error.
            assert!(classify_channels(vec![MockChannel::boxed(ChannelSpec::input())]).is_err());
        }

        #[test]
        fn classify_duplicate_clipboard_keeps_one_no_panic() {
            // A hostile peer opening two Clipboard channels must not panic; the last wins (warned).
            let c = classify_channels(vec![
                MockChannel::boxed(ChannelSpec::video()),
                MockChannel::boxed(ChannelSpec::clipboard()),
                MockChannel::boxed(ChannelSpec::clipboard()),
            ])
            .unwrap();
            assert_eq!(c.clipboard.unwrap().spec().channel, ChannelId::Clipboard);
        }

        #[tokio::test]
        async fn dual_releases_input_when_input_channel_closes() {
            let injected = Arc::new(AtomicUsize::new(0));
            let released = Arc::new(AtomicBool::new(false));
            let injector = Box::new(TrackingInjector {
                injected: injected.clone(),
                released: released.clone(),
            });

            // Video channel: never closes (pends on recv — though the dual path never recvs here),
            // accepts every send. Many frames so it can't finish before input closes.
            let video = Box::new(MockChannel {
                spec: ChannelSpec::video(),
                recvs: Mutex::new(VecDeque::new()),
                pend_when_empty: true,
                sent: Arc::new(Mutex::new(0)),
            });
            // Input channel: two Button events, then closes (Ok(None)).
            let mut recvs = VecDeque::new();
            recvs.push_back(Ok(Some(button_bytes())));
            recvs.push_back(Ok(Some(button_bytes())));
            let input = Box::new(MockChannel {
                spec: ChannelSpec::input(),
                recvs: Mutex::new(recvs),
                pend_when_empty: false,
                sent: Arc::new(Mutex::new(0)),
            });

            let mut source = TestFrameSource;
            let result = run_video_session(
                video,
                Some(input),
                None,
                1_000_000,
                1_000,
                64_000,
                &mut source,
                injector,
                noop_clipboard(),
            )
            .await;

            assert!(result.is_ok(), "input-close is a normal end of stream");
            assert!(
                released.load(Ordering::SeqCst),
                "release_all MUST fire when the input channel closes mid-session"
            );
            assert_eq!(
                injected.load(Ordering::SeqCst),
                2,
                "both input events must be injected before the session ends"
            );
        }

        #[tokio::test]
        async fn dual_releases_input_when_video_completes() {
            let released = Arc::new(AtomicBool::new(false));
            let injector = Box::new(TrackingInjector {
                injected: Arc::new(AtomicUsize::new(0)),
                released: released.clone(),
            });

            let video_sent = Arc::new(Mutex::new(0usize));
            let video = Box::new(MockChannel {
                spec: ChannelSpec::video(),
                recvs: Mutex::new(VecDeque::new()),
                pend_when_empty: true,
                sent: video_sent.clone(),
            });
            // Input channel stays open (pends forever) — the input task never ends on its own, so the
            // VIDEO completion must drive teardown.
            let input = Box::new(MockChannel {
                spec: ChannelSpec::input(),
                recvs: Mutex::new(VecDeque::new()),
                pend_when_empty: true,
                sent: Arc::new(Mutex::new(0)),
            });

            let mut source = TestFrameSource;
            let result = run_video_session(
                video,
                Some(input),
                None,
                3,
                1_000,
                64_000,
                &mut source,
                injector,
                noop_clipboard(),
            )
            .await;

            assert!(result.is_ok());
            assert!(
                released.load(Ordering::SeqCst),
                "release_all MUST fire when the video stream completes (input task aborted)"
            );
            assert_eq!(*video_sent.lock().unwrap(), 3, "all 3 frames must be sent");
        }

        /// A `VideoFrameSource` that always errors — drives the abnormal (`FrameStep::Failed`) exit.
        struct FailingFrameSource;
        impl VideoFrameSource for FailingFrameSource {
            fn next_frame(&mut self) -> anyhow::Result<(FrameType, Vec<u8>)> {
                Err(anyhow::anyhow!("synthetic frame-source failure"))
            }
        }

        #[tokio::test]
        async fn dual_releases_input_when_video_source_errors() {
            let released = Arc::new(AtomicBool::new(false));
            let injector = Box::new(TrackingInjector {
                injected: Arc::new(AtomicUsize::new(0)),
                released: released.clone(),
            });
            let video = MockChannel::boxed(ChannelSpec::video());
            // Input pends (stays open) so the VIDEO source error must drive teardown.
            let input = Box::new(MockChannel {
                spec: ChannelSpec::input(),
                recvs: Mutex::new(VecDeque::new()),
                pend_when_empty: true,
                sent: Arc::new(Mutex::new(0)),
            });
            let mut source = FailingFrameSource;
            let result = run_video_session(
                video,
                Some(input),
                None,
                5,
                1_000,
                64_000,
                &mut source,
                injector,
                noop_clipboard(),
            )
            .await;
            assert!(result.is_err(), "a source error is an abnormal end → Err");
            assert!(
                released.load(Ordering::SeqCst),
                "release_all MUST fire on a video-source error (abnormal exit)"
            );
        }

        #[test]
        fn classify_duplicate_input_keeps_one_no_panic() {
            // A hostile peer opening two Input channels must not panic; the last wins (warned).
            let c = classify_channels(vec![
                MockChannel::boxed(ChannelSpec::video()),
                MockChannel::boxed(ChannelSpec::input()),
                MockChannel::boxed(ChannelSpec::input()),
            ])
            .unwrap();
            assert_eq!(c.video.spec().channel, ChannelId::Video);
            assert_eq!(c.input.unwrap().spec().channel, ChannelId::Input);
        }

        // ── Clipboard receive path (ADR-0037) ────────────────────────────────────────────────────

        /// A `ClipboardAccess` that records every successfully-applied `set_text` (content — this is a
        /// TEST double; production never retains content, §7). `fail_on` (1-based) makes that Nth
        /// call return a backend error WITHOUT recording, to exercise the non-fatal error path.
        struct RecordingClipboard {
            writes: Arc<Mutex<Vec<String>>>,
            calls: usize,
            fail_on: Option<usize>,
            offer: Option<String>,
        }
        impl RecordingClipboard {
            fn new(writes: Arc<Mutex<Vec<String>>>) -> Self {
                Self {
                    writes,
                    calls: 0,
                    fail_on: None,
                    offer: None,
                }
            }
            fn failing_on(writes: Arc<Mutex<Vec<String>>>, nth: usize) -> Self {
                Self {
                    writes,
                    calls: 0,
                    fail_on: Some(nth),
                    offer: None,
                }
            }
            /// Make `get_text` return `offer` — the host→browser clipboard the host will offer.
            fn offering(writes: Arc<Mutex<Vec<String>>>, offer: &str) -> Self {
                Self {
                    writes,
                    calls: 0,
                    fail_on: None,
                    offer: Some(offer.to_owned()),
                }
            }
        }
        impl ClipboardAccess for RecordingClipboard {
            fn get_text(&mut self) -> Result<Option<String>, ClipboardError> {
                Ok(self.offer.clone())
            }
            fn set_text(&mut self, text: &str) -> Result<(), ClipboardError> {
                self.calls += 1;
                if self.fail_on == Some(self.calls) {
                    return Err(ClipboardError::Backend(
                        "synthetic set_text failure".to_owned(),
                    ));
                }
                self.writes.lock().unwrap().push(text.to_owned());
                Ok(())
            }
        }

        fn text_update_bytes(s: &str) -> Bytes {
            Bytes::from(ClipboardUpdate::text(s).unwrap().encode())
        }

        #[test]
        fn decode_clipboard_paste_sanitizes_and_rejects() {
            // Valid text → sanitized (an embedded ESC is stripped, CRLF → LF).
            assert_eq!(
                decode_clipboard_paste(&text_update_bytes("ls\r\n\u{1b}[31m")),
                Some("ls\n[31m".to_owned())
            );
            // Malformed bytes (empty → no format byte) → None, never a panic.
            assert_eq!(decode_clipboard_paste(&[]), None);
            // Unknown format byte → None.
            assert_eq!(decode_clipboard_paste(&[0xFF, b'x']), None);
            // All-control text sanitizes to empty → None (skip the write, don't clobber).
            assert_eq!(
                decode_clipboard_paste(&text_update_bytes("\u{1b}\u{202e}\u{200b}")),
                None
            );
        }

        /// A clipboard channel that replays `msgs` then closes (`Ok(None)`) — so `run_clipboard`
        /// processes every message and returns on its own, deterministically (no race with teardown).
        fn clipboard_channel_closing_after(msgs: Vec<Bytes>) -> Box<dyn Channel> {
            let mut recvs: RecvQueue = msgs.into_iter().map(|b| Ok(Some(b))).collect();
            recvs.push_back(Ok(None));
            Box::new(MockChannel {
                spec: ChannelSpec::clipboard(),
                recvs: Mutex::new(recvs),
                pend_when_empty: false,
                sent: Arc::new(Mutex::new(0)),
            })
        }

        #[tokio::test]
        async fn clipboard_recv_applies_sanitized_pastes_in_order() {
            // Drive `run_clipboard` directly (deterministic — the channel closes itself): a valid
            // paste, an all-control paste (skipped, no clobber), then a second valid paste.
            let writes = Arc::new(Mutex::new(Vec::new()));
            let clipboard = Box::new(RecordingClipboard::new(writes.clone()));
            let ch = clipboard_channel_closing_after(vec![
                text_update_bytes("hello\r\nworld"),
                text_update_bytes("\u{1b}\u{200b}"), // all-control → sanitizes to empty → skipped
                text_update_bytes("second"),
            ]);

            run_clipboard(ch, clipboard).await;

            assert_eq!(
                *writes.lock().unwrap(),
                vec!["hello\nworld".to_owned(), "second".to_owned()],
                "both valid pastes applied (sanitized, in order); the all-control one was skipped"
            );
        }

        #[tokio::test]
        async fn clipboard_recv_set_text_error_is_non_fatal() {
            // A backend `set_text` error on the 1st paste must NOT end the task — the 2nd paste still
            // applies. (Recoverable-backend-hiccup contract; the erroring write is not recorded.)
            let writes = Arc::new(Mutex::new(Vec::new()));
            let clipboard = Box::new(RecordingClipboard::failing_on(writes.clone(), 1));
            let ch = clipboard_channel_closing_after(vec![
                text_update_bytes("first"),
                text_update_bytes("after-error"),
            ]);

            run_clipboard(ch, clipboard).await;

            assert_eq!(
                *writes.lock().unwrap(),
                vec!["after-error".to_owned()],
                "the failed write is skipped but the task keeps processing subsequent pastes"
            );
        }

        #[tokio::test]
        async fn clipboard_offers_host_clipboard_to_browser() {
            // Host→browser (ADR-0037): on start, `run_clipboard` reads the host clipboard (get_text)
            // and sends it once as a ClipboardUpdate. Assert exactly one message was sent AND that its
            // bytes decode back to the offered text (a real host→browser wire payload).
            let writes = Arc::new(Mutex::new(Vec::new()));
            let clipboard = Box::new(RecordingClipboard::offering(writes, "host clip 🌍"));
            let sent = Arc::new(Mutex::new(Vec::new()));
            let ch = CaptureChannel::boxed(sent.clone(), true, VecDeque::new());

            run_clipboard(ch, clipboard).await;

            let sent = sent.lock().unwrap();
            assert_eq!(
                sent.len(),
                1,
                "the host clipboard must be offered exactly once"
            );
            assert_eq!(
                ClipboardUpdate::decode(&sent[0]).unwrap().as_text(),
                Some("host clip 🌍"),
                "the offered bytes must be the exact ClipboardUpdate for the host clipboard"
            );
        }

        #[tokio::test]
        async fn clipboard_no_offer_when_host_clipboard_empty() {
            // get_text → None (empty host clipboard) means nothing is offered — no send.
            let writes = Arc::new(Mutex::new(Vec::new()));
            let clipboard = Box::new(RecordingClipboard::new(writes)); // get_text → None
            let sent = Arc::new(Mutex::new(Vec::new()));
            let ch = CaptureChannel::boxed(sent.clone(), true, VecDeque::new());

            run_clipboard(ch, clipboard).await;

            assert!(
                sent.lock().unwrap().is_empty(),
                "an empty host clipboard offers nothing"
            );
        }

        #[tokio::test]
        async fn clipboard_offer_send_failure_is_non_fatal() {
            // If the host→browser offer send fails, the browser→host receive loop must STILL run.
            let writes = Arc::new(Mutex::new(Vec::new()));
            let clipboard = Box::new(RecordingClipboard::offering(writes.clone(), "offered"));
            let sent = Arc::new(Mutex::new(Vec::new()));
            let mut recvs: RecvQueue = VecDeque::new();
            recvs.push_back(Ok(Some(text_update_bytes("paste after failed offer"))));
            // send_ok = false → the offer send errors; a paste is then delivered before close.
            let ch = CaptureChannel::boxed(sent.clone(), false, recvs);

            run_clipboard(ch, clipboard).await;

            assert!(
                sent.lock().unwrap().is_empty(),
                "the failing offer captured nothing"
            );
            assert_eq!(
                *writes.lock().unwrap(),
                vec!["paste after failed offer".to_owned()],
                "a failed offer must not stop the browser→host receive loop"
            );
        }

        #[tokio::test]
        async fn clipboard_oversize_offer_skipped_receive_still_runs() {
            // A host clipboard larger than the wire bound is dropped (not truncated), and the
            // browser→host receive loop still runs afterward.
            let writes = Arc::new(Mutex::new(Vec::new()));
            let big = "a".repeat(sh_protocol::MAX_CLIPBOARD_BYTES + 1);
            let clipboard = Box::new(RecordingClipboard::offering(writes.clone(), &big));
            let sent = Arc::new(Mutex::new(Vec::new()));
            let mut recvs: RecvQueue = VecDeque::new();
            recvs.push_back(Ok(Some(text_update_bytes("paste after oversize offer"))));
            let ch = CaptureChannel::boxed(sent.clone(), true, recvs);

            run_clipboard(ch, clipboard).await;

            assert!(
                sent.lock().unwrap().is_empty(),
                "an oversize host clipboard offers nothing (dropped, not truncated)"
            );
            assert_eq!(
                *writes.lock().unwrap(),
                vec!["paste after oversize offer".to_owned()],
                "an oversize offer must not stop the browser→host receive loop"
            );
        }

        #[tokio::test]
        async fn video_completes_with_both_input_and_clipboard_channels() {
            // The 4th combination: BOTH dedicated Input and Clipboard channels open. Video completes
            // first → session ends; assert `release_all` fired (input torn down) and every frame sent.
            // Both dedicated channels pend (never end on their own), so VIDEO completion drives end.
            let released = Arc::new(AtomicBool::new(false));
            let injector = Box::new(TrackingInjector {
                injected: Arc::new(AtomicUsize::new(0)),
                released: released.clone(),
            });
            let clipboard = Box::new(RecordingClipboard::new(Arc::new(Mutex::new(Vec::new()))));

            let video_sent = Arc::new(Mutex::new(0usize));
            let video = Box::new(MockChannel {
                spec: ChannelSpec::video(),
                recvs: Mutex::new(VecDeque::new()),
                pend_when_empty: true,
                sent: video_sent.clone(),
            });
            let input = Box::new(MockChannel {
                spec: ChannelSpec::input(),
                recvs: Mutex::new(VecDeque::new()),
                pend_when_empty: true,
                sent: Arc::new(Mutex::new(0)),
            });
            let clipboard_ch = Box::new(MockChannel {
                spec: ChannelSpec::clipboard(),
                recvs: Mutex::new(VecDeque::new()),
                pend_when_empty: true,
                sent: Arc::new(Mutex::new(0)),
            });

            let mut source = TestFrameSource;
            let result = run_video_session(
                video,
                Some(input),
                Some(clipboard_ch),
                3,
                1_000,
                64_000,
                &mut source,
                injector,
                clipboard,
            )
            .await;

            assert!(result.is_ok());
            assert!(
                released.load(Ordering::SeqCst),
                "release_all MUST fire with both dedicated channels present (input aborted)"
            );
            assert_eq!(*video_sent.lock().unwrap(), 3, "all 3 frames must be sent");
        }

        #[tokio::test]
        async fn clipboard_close_does_not_end_session() {
            // The clipboard channel closing early must NOT end the session — video keeps streaming to
            // completion. (If clipboard-close ended the session, fewer than all frames would send.)
            let writes = Arc::new(Mutex::new(Vec::new()));
            let clipboard = Box::new(RecordingClipboard::new(writes));

            let video_sent = Arc::new(Mutex::new(0usize));
            let video = Box::new(MockChannel {
                spec: ChannelSpec::video(),
                recvs: Mutex::new(VecDeque::new()),
                pend_when_empty: true,
                sent: video_sent.clone(),
            });
            // One paste then immediate close (Ok(None)).
            let mut recvs = VecDeque::new();
            recvs.push_back(Ok(Some(text_update_bytes("x"))));
            let clipboard_ch = Box::new(MockChannel {
                spec: ChannelSpec::clipboard(),
                recvs: Mutex::new(recvs),
                pend_when_empty: false, // returns Ok(None) after the paste → channel closes
                sent: Arc::new(Mutex::new(0)),
            });

            let injector = Box::new(TrackingInjector {
                injected: Arc::new(AtomicUsize::new(0)),
                released: Arc::new(AtomicBool::new(false)),
            });

            let mut source = TestFrameSource;
            let result = run_video_session(
                video,
                None,
                Some(clipboard_ch),
                4,
                1_000,
                64_000,
                &mut source,
                injector,
                clipboard,
            )
            .await;

            assert!(result.is_ok());
            assert_eq!(
                *video_sent.lock().unwrap(),
                4,
                "all 4 frames send even though the clipboard channel closed early"
            );
        }
    }

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

    /// Reassemble fragments the way the browser does: concatenate payloads in order, validating the
    /// video-header frag fields. Returns the rebuilt Annex-B + the decoded first/last headers.
    fn reassemble(fragments: &[Bytes]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, frag) in fragments.iter().enumerate() {
            let common = CommonHeader::decode(&frag[..COMMON_HEADER_LEN]).expect("common");
            assert_eq!(common.channel, ChannelId::Video);
            let vh = VideoHeader::decode(&frag[COMMON_HEADER_LEN..COMMON_HEADER_LEN + 12])
                .expect("video header");
            assert_eq!(usize::from(vh.frag_index), i, "frag_index in order");
            assert_eq!(usize::from(vh.total_frags), fragments.len(), "total_frags");
            let is_last = i + 1 == fragments.len();
            assert_eq!(vh.marker, is_last, "marker only on last fragment");
            out.extend_from_slice(&frag[COMMON_HEADER_LEN + 12..]);
        }
        out
    }

    #[test]
    fn fragments_single_is_byte_identical_to_build_shp_video_frame() {
        // A frame that fits the cap → exactly one fragment, byte-for-byte the same as the
        // single-frame builder (so the existing browser-native baked e2e is unchanged).
        let payload = vec![0u8, 0, 0, 1, 0x65, 0xAB, 0xCD];
        let single = build_shp_video_frame(7, 5, 1234, FrameType::Idr, &payload).unwrap();
        let frags =
            build_shp_video_fragments(7, 5, 1234, FrameType::Idr, &payload, usize::from(u16::MAX))
                .unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(
            frags[0], single,
            "single fragment must equal the non-fragmented frame"
        );
    }

    #[test]
    fn fragments_split_large_payload_and_reassemble_exactly() {
        // 200 KB payload at the 64 KiB cap → 4 fragments that reassemble to the original bytes.
        let payload: Vec<u8> = (0..200_000usize).map(|i| (i % 256) as u8).collect();
        let frags =
            build_shp_video_fragments(100, 9, 0, FrameType::Idr, &payload, usize::from(u16::MAX))
                .unwrap();
        assert_eq!(frags.len(), 4, "200000 / 65535 = 4 fragments");
        // Sequences increment per fragment from the start value.
        for (i, frag) in frags.iter().enumerate() {
            let common = CommonHeader::decode(&frag[..COMMON_HEADER_LEN]).unwrap();
            assert_eq!(common.sequence, 100u16.wrapping_add(i as u16));
            assert!(
                common.flags.fragment,
                "multi-fragment frames set the fragment flag"
            );
        }
        assert_eq!(
            reassemble(&frags),
            payload,
            "reassembled bytes must equal the original"
        );
    }

    #[test]
    fn fragments_force_small_chunks_reassemble() {
        // A small payload with a tiny max_fragment_bytes (as the e2e does) → many fragments.
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
        let frags =
            build_shp_video_fragments(0, 1, 0, FrameType::Predicted, &payload, 100).unwrap();
        assert_eq!(frags.len(), 10);
        assert_eq!(reassemble(&frags), payload);
    }

    #[test]
    fn fragments_exceeding_255_error() {
        // 256 one-byte fragments would need total_frags = 256 > the 8-bit cap → error.
        let payload = vec![0u8; 256];
        assert!(build_shp_video_fragments(0, 0, 0, FrameType::Idr, &payload, 1).is_err());
    }

    #[test]
    fn fragments_empty_payload_produces_one_empty_fragment() {
        // The explicit is_empty() branch: chunks() on [] yields nothing, so a single empty
        // fragment is emitted (total_frags = 1, reassembles to empty).
        let frags = build_shp_video_fragments(0, 0, 0, FrameType::Idr, &[], 1000).unwrap();
        assert_eq!(frags.len(), 1);
        assert!(reassemble(&frags).is_empty());
    }

    #[test]
    fn decode_input_round_trips_a_browser_input_event() {
        use sh_protocol::{EventType, InputEvent, Modifiers};

        // A browser-encoded input event (the exact 16-byte wire form the wasm bridge produces).
        let event = InputEvent {
            event_type: EventType::PointerMove,
            modifiers: Modifiers::empty(),
            pointer_x: 0x1234,
            pointer_y: 0x5678,
            button_mask: 0,
            key_code: 0,
            scroll_x: 0,
            scroll_y: 0,
            pressure: 0,
        };
        assert_eq!(
            super::decode_input(&event.encode()),
            Some(event),
            "the 16-byte wire form must decode verbatim"
        );
    }

    #[test]
    fn decode_input_rejects_non_input_messages() {
        // The channel-open HELLO frame (13 bytes) and other non-16-byte messages → None.
        assert!(super::decode_input(b"SHP\x00\x00\x00\x00\x05HELLO").is_none());
        assert!(super::decode_input(&[]).is_none());
        // A 16-byte but malformed event (bad event-type / reserved bits) → None, never a panic.
        assert!(super::decode_input(&[0xFF; INPUT_EVENT_LEN]).is_none());
    }

    #[test]
    fn admit_input_throttles_drop_safe_events_but_never_state_transitions() {
        use sh_input::RateLimiter;
        use sh_protocol::{EventType, InputEvent, Modifiers};
        use std::time::Instant;

        let ev = |event_type| InputEvent {
            event_type,
            modifiers: Modifiers::empty(),
            pointer_x: 0,
            pointer_y: 0,
            button_mask: 0x01,
            key_code: 0x04,
            scroll_x: 0,
            scroll_y: 1,
            pressure: 0,
        };

        // Both drop-safe high-rate vectors (PointerMove AND Wheel) share the bucket and are
        // throttled. A Wheel flood must NOT bypass the guard by relabeling its event type.
        for et in [EventType::PointerMove, EventType::Wheel] {
            let mut limiter = RateLimiter::new(500, 1); // burst 1
            let now = Instant::now();
            assert!(
                super::admit_input(&ev(et), &mut limiter, now),
                "{et:?}: first event (burst token) admitted"
            );
            assert!(
                !super::admit_input(&ev(et), &mut limiter, now),
                "{et:?}: second event at the same instant throttled"
            );
        }

        // Critical safety property: with the bucket fully empty, every state-transition event still
        // passes — dropping a Button/Key release would leave it stuck (ADR-0034). Touch/Pen also
        // pass (they carry contact state and are not purely drop-safe).
        let mut limiter = RateLimiter::new(500, 1);
        let now = Instant::now();
        assert!(super::admit_input(
            &ev(EventType::PointerMove),
            &mut limiter,
            now
        )); // drain token
        assert!(!super::admit_input(
            &ev(EventType::PointerMove),
            &mut limiter,
            now
        )); // bucket empty
        for et in [
            EventType::Button,
            EventType::Key,
            EventType::Touch,
            EventType::Pen,
        ] {
            assert!(
                super::admit_input(&ev(et), &mut limiter, now),
                "{et:?} must bypass the rate limiter even when the bucket is empty"
            );
        }
        // The always-admitted events consumed no tokens, so a move is still throttled.
        assert!(!super::admit_input(
            &ev(EventType::PointerMove),
            &mut limiter,
            now
        ));
    }
}
