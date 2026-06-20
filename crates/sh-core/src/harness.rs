//! End-to-end loopback latency harness (P0-10).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use sh_codec_hw::{RawDecoder, RawEncoder};
use sh_media::{Resolution, ScreenCapturer, SyntheticCapturer};
use sh_render::CollectingSink;

/// Parameters for the loopback latency harness.
#[derive(Debug, Clone)]
pub struct HarnessParams {
    /// Capture resolution (width x height).
    pub resolution: Resolution,
    /// Frames per second for the synthetic capturer.
    pub fps: u32,
    /// Number of frames to capture, send, and receive.
    pub frame_count: usize,
}

/// Per-frame latency measurement from the loopback harness.
#[derive(Debug, Clone)]
pub struct FrameMeasurement {
    /// Zero-based index of this frame in the received sequence.
    pub frame_idx: usize,
    /// Instant at which this frame's datagrams were sent.
    pub send_instant: Instant,
    /// Instant at which the reassembled frame was decoded.
    pub recv_instant: Instant,
    /// Whether the decoded frame data matches the original captured frame.
    pub lossless_match: bool,
}

/// Aggregate latency report from the loopback harness.
#[derive(Debug, Clone)]
pub struct HarnessReport {
    /// Total number of frames sent by the host pipeline.
    pub frames_sent: usize,
    /// Total number of frames received and decoded by the client pipeline.
    pub frames_received: usize,
    /// Number of frames whose decoded data exactly matches the source.
    pub lossless_match_count: usize,
    /// Minimum end-to-end latency across all measured frames, in microseconds.
    pub latency_min_us: u64,
    /// Median end-to-end latency, in microseconds.
    pub latency_median_us: u64,
    /// 95th-percentile end-to-end latency, in microseconds.
    pub latency_p95_us: u64,
    /// Maximum end-to-end latency, in microseconds.
    pub latency_max_us: u64,
    /// Per-frame measurements.
    pub measurements: Vec<FrameMeasurement>,
}

/// Errors that can occur during harness execution.
#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    /// A transport-layer error occurred.
    #[error("transport: {0}")]
    Transport(#[from] sh_transport::TransportError),
    /// A pipeline error occurred.
    #[error("pipeline: {0}")]
    Pipeline(#[from] crate::pipeline::PipelineError),
    /// A tokio task join error occurred.
    #[error("task join error: {0}")]
    Join(String),
}

/// Run a full end-to-end loopback latency harness.
///
/// Spins up a local QUIC server and client, runs the host capture/encode/send
/// pipeline on the server side and the client receive/decode/sink pipeline on
/// the client side concurrently, then computes latency statistics and lossless
/// correctness across all frames.
///
/// # Errors
///
/// Returns [`HarnessError::Transport`] if binding, connecting, or accepting fails.
/// Returns [`HarnessError::Pipeline`] if either pipeline returns an error.
/// Returns [`HarnessError::Join`] if a spawned task panics or the idle timeout
/// duration is invalid.
pub async fn run_loopback_harness(
    server_config: quinn::ServerConfig,
    client_config: quinn::ClientConfig,
    params: HarnessParams,
) -> Result<HarnessReport, HarnessError> {
    let mut transport = quinn::TransportConfig::default();
    // 120 frames × ~192 fragments × 1162 bytes = ~27 MB of datagrams. Use a 5-minute idle
    // timeout so the bulk datagram transfer (subject to QUIC congestion-window backpressure)
    // can complete without triggering idle closure. A 64 MiB receive buffer absorbs the burst.
    // Keep-alive interval is set to a third of the idle timeout so the connection stays alive
    // while `send_datagram_wait` holds for congestion-window space.
    let idle_timeout: quinn::IdleTimeout = Duration::from_secs(300)
        .try_into()
        .map_err(|_| HarnessError::Join("invalid idle timeout duration".to_owned()))?;
    transport.max_idle_timeout(Some(idle_timeout));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    // Enable QUIC datagrams with a 64 MiB receive buffer.
    // Without this, `max_datagram_size()` returns `None` and `send_datagram` returns
    // `DatagramsNotSupported`.
    transport.datagram_receive_buffer_size(Some(64 * 1024 * 1024));
    let transport = Arc::new(transport);

    let mut server_cfg = server_config;
    server_cfg.transport_config(Arc::clone(&transport));

    let mut client_cfg = client_config;
    client_cfg.transport_config(Arc::clone(&transport));

    let server_ep = sh_transport::ServerEndpoint::bind(
        "127.0.0.1:0"
            .parse()
            .map_err(|_| HarnessError::Join("invalid bind address".to_owned()))?,
        server_cfg,
    )?;
    let server_addr = server_ep.local_addr()?;

    let server_accept = tokio::spawn(async move { server_ep.accept().await });

    let client_ep = sh_transport::ClientEndpoint::bind(client_cfg)?;
    let client_conn = client_ep.connect(server_addr, "localhost").await?;

    let server_conn = server_accept
        .await
        .map_err(|e| HarnessError::Join(e.to_string()))?
        .map_err(HarnessError::Transport)?;

    let frame_count = params.frame_count;
    let resolution = params.resolution;
    let fps = params.fps;

    // Wrap the server connection in an Arc so it stays alive until both the host
    // pipeline task and the harness drop their handles. Dropping the quinn Connection
    // sends QUIC CONNECTION_CLOSE, which would abort the client mid-stream.
    let server_conn = Arc::new(server_conn);
    let server_conn_host = Arc::clone(&server_conn);

    // Channel that lets the client task signal completion so the server conn can be
    // dropped cleanly after the client has received all frames.
    let (client_done_tx, client_done_rx) = oneshot::channel::<()>();

    let host_handle = tokio::spawn(async move {
        let mut capturer = SyntheticCapturer::new(resolution, fps);
        let mut encoder = RawEncoder::new();
        let host_params = crate::pipeline::HostPipelineParams {
            frame_count,
            fps,
            pace_frames: false,
        };
        let result = crate::pipeline::run_host_pipeline(
            &server_conn_host,
            &mut capturer,
            &mut encoder,
            &host_params,
        )
        .await;
        // Wait for the client to signal it's done before dropping the connection.
        let _ = client_done_rx.await;
        result
    });

    let client_handle = tokio::spawn(async move {
        let mut decoder = RawDecoder::new();
        let mut sink = CollectingSink::new(frame_count);
        let recv_times = crate::pipeline::run_client_pipeline(
            &client_conn,
            &mut decoder,
            &mut sink,
            frame_count,
            Duration::from_secs(300),
        )
        .await?;
        // Signal the host that we've received all frames.
        let _ = client_done_tx.send(());
        Ok::<_, crate::pipeline::PipelineError>((recv_times, sink))
    });

    // Await both tasks concurrently so the server connection stays alive until the
    // client finishes receiving. The oneshot handshake above prevents CONNECTION_CLOSE
    // from racing with the final datagrams.
    let (host_result, client_result) = tokio::join!(host_handle, client_handle);

    // Drop the harness's Arc handle so the quinn Connection can close cleanly.
    drop(server_conn);

    let send_times = host_result
        .map_err(|e| HarnessError::Join(e.to_string()))?
        .map_err(HarnessError::Pipeline)?;

    let (recv_times, sink) = client_result
        .map_err(|e| HarnessError::Join(e.to_string()))?
        .map_err(HarnessError::Pipeline)?;

    let send_map: HashMap<u64, Instant> = send_times
        .into_iter()
        .map(|(fid, inst)| (fid.0, inst))
        .collect();

    let recv_map: HashMap<u64, Instant> = recv_times
        .into_iter()
        .map(|(fid, inst)| (fid.0, inst))
        .collect();

    let decoded_frames = sink.frames();
    let mut source_capturer = SyntheticCapturer::new(resolution, fps);
    let mut lossless_map: HashMap<u64, bool> = HashMap::new();
    for _ in 0..frame_count {
        if let Ok(Some(source_frame)) = source_capturer.next_frame(Duration::ZERO) {
            let fid = source_frame.frame_id.0;
            let matches = decoded_frames
                .iter()
                .any(|df| df.frame_id.0 == fid && df.data == source_frame.data);
            lossless_map.insert(fid, matches);
        }
    }

    let frames_sent = send_map.len();
    let frames_received = recv_map.len();

    let mut latencies_us: Vec<u64> = Vec::with_capacity(frames_received);
    let mut measurements: Vec<FrameMeasurement> = Vec::new();

    let mut ordered_recv: Vec<(u64, Instant)> = recv_map.iter().map(|(&k, &v)| (k, v)).collect();
    ordered_recv.sort_unstable_by_key(|(fid, _)| *fid);

    for (frame_idx, (fid, recv_instant)) in ordered_recv.iter().enumerate() {
        if let Some(&send_instant) = send_map.get(fid) {
            let latency = u64::try_from(recv_instant.duration_since(send_instant).as_micros())
                .unwrap_or(u64::MAX);
            latencies_us.push(latency);
            let lossless_match = lossless_map.get(fid).copied().unwrap_or(false);
            measurements.push(FrameMeasurement {
                frame_idx,
                send_instant,
                recv_instant: *recv_instant,
                lossless_match,
            });
        }
    }

    let lossless_match_count = measurements.iter().filter(|m| m.lossless_match).count();

    latencies_us.sort_unstable();
    let len = latencies_us.len();
    let latency_min_us = latencies_us.first().copied().unwrap_or(0);
    let latency_max_us = latencies_us.last().copied().unwrap_or(0);
    let latency_median_us = latencies_us.get(len / 2).copied().unwrap_or(0);
    let p95_idx = len.saturating_mul(95).saturating_div(100);
    let latency_p95_us = latencies_us.get(p95_idx).copied().unwrap_or(0);

    Ok(HarnessReport {
        frames_sent,
        frames_received,
        lossless_match_count,
        latency_min_us,
        latency_median_us,
        latency_p95_us,
        latency_max_us,
        measurements,
    })
}
