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
use sh_crypto::{DtlsCommitment, HandshakeOutcome, NoiseHandshake, SoftwareKeystore};
use sh_input::InputInjector;
use sh_protocol::{
    Codec, CommonHeader, Flags, FrameType, InputEvent, Priority, VideoHeader, INPUT_EVENT_LEN,
    MAX_FRAME_ID,
};
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
            } => {
                run_video_stream(
                    &transport_for_accept,
                    frames,
                    fps,
                    max_fragment_bytes,
                    &mut *source,
                    input,
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

/// Accept the first incoming DataChannel, receive a message, and echo it back.
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
) -> anyhow::Result<()> {
    info!("waiting for browser to open DataChannel (video mode)");
    let mut channel = transport
        .accept_channel()
        .await
        .context("failed to accept DataChannel")?;

    anyhow::ensure!(
        frames_to_send > 0,
        "--frames must be > 0 in video stream mode"
    );
    anyhow::ensure!(fps > 0, "StreamMode::Video fps must be > 0");

    // ── Input injection runs on a DEDICATED blocking thread, never the async executor ──
    //
    // The `InputInjector` contract requires inject() to run off the runtime (XTEST etc. are
    // synchronous OS calls that could stall the video loop). We move the injector onto a
    // `spawn_blocking` task fed by a BOUNDED channel: the drain loop only `try_send`s decoded
    // events (truly non-blocking), and the bounded queue is the natural backpressure / flood point
    // (a full queue drops the event rather than blocking pacing). Dropping `input_tx` at the end
    // signals the thread to exit.
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<InputEvent>(INPUT_QUEUE_DEPTH);
    let inject_task = tokio::task::spawn_blocking(move || {
        let mut injector = input;
        while let Some(event) = input_rx.blocking_recv() {
            if let Err(e) = injector.inject(&event) {
                // An injection failure (unsupported event / backend error) must not kill the
                // session — log and keep going.
                debug!(error = %e, "input injection failed");
            }
        }
    });
    info!(
        target = frames_to_send,
        fps, "streaming H.264 video frames to browser"
    );

    // `checked_div` (not `/`) satisfies the arithmetic-side-effects lint; the `fps > 0` guard above
    // makes the divisor non-zero, so the `unwrap_or` fallback is unreachable.
    let per_us = 1_000_000u64.checked_div(u64::from(fps)).unwrap_or(1).max(1);
    let mut ticker = tokio::time::interval(Duration::from_micros(per_us));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut sent: usize = 0;
    let mut sequence: u16 = 0;
    'stream: while sent < frames_to_send {
        ticker.tick().await;
        let (frame_type, payload) = source.next_frame()?;
        let n = sent as u64;
        // frame_id is a 24-bit wire field; mask into range. (`try_from` rather than `as u32` to
        // satisfy the cast-truncation lint; the mask guarantees it fits, so this never errors.)
        // Timestamps advance monotonically (WebCodecs wants increasing chunk timestamps);
        // encode() narrows them to their low 32 wire bits.
        let frame_id = u32::try_from(n & u64::from(MAX_FRAME_ID)).unwrap_or(0);
        let ts_us = n.wrapping_mul(per_us);
        // Fragment the access unit into ≤ `max_fragment_bytes` SHP messages (ADR-0033). Removes the
        // hard 64 KiB per-frame cap; the receiver reassembles by frame_id. The only error is a
        // frame needing > 255 fragments (pathological, ~16 MiB) — drop + re-arm a keyframe.
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
                continue;
            }
        };
        // fragments.len() <= 255 (the total_frags u8 cap), so this never errors — but propagate
        // rather than fall back to a wrong count that would corrupt every later sequence number.
        let num_frags =
            u16::try_from(fragments.len()).context("fragment count exceeded u16 (invariant)")?;
        // Send every fragment in order. A send failure means the browser closed the DataChannel — a
        // NORMAL end of stream (the viewer disconnected), not a host error: exit 0.
        for frag in fragments {
            if let Err(e) = channel.send(frag).await {
                info!(frames = sent, error = %e, "peer closed channel — ending video stream");
                break 'stream;
            }
        }
        sent = sent.saturating_add(1);
        sequence = sequence.wrapping_add(num_frags);

        // Drain any browser→host input that arrived while pacing/sending this frame and hand it to
        // the injection thread. `timeout(ZERO, recv())` is a single non-blocking poll: it returns a
        // buffered message immediately or elapses with no idle wait. recv() is cancel-safe: it only
        // consumes a message after popping it from the queue under the mutex, so cancelling the
        // ZERO-timeout future at its internal `notified().await` leaves the queue untouched and the
        // message available on the next poll. We cap the drain at `MAX_INPUT_PER_FRAME` so a flood
        // can't starve the video send loop; the bounded `input_tx` channel is the second backpressure
        // point (a full queue drops the event rather than blocking).
        for _ in 0..MAX_INPUT_PER_FRAME {
            match tokio::time::timeout(Duration::ZERO, channel.recv()).await {
                Ok(Ok(Some(bytes))) => {
                    if let Some(event) = decode_input(&bytes) {
                        // Non-blocking enqueue to the injection thread; a full queue drops the
                        // event (backpressure) rather than stalling video pacing.
                        let _ = input_tx.try_send(event);
                    }
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

    info!(frames = sent, "video stream complete");
    // Close the input queue and let the injection thread drain + exit cleanly.
    drop(input_tx);
    let _ = inject_task.await;
    Ok(())
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
}
