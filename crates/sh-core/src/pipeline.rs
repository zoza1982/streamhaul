//! Host and client pipeline orchestration.

use std::time::{Duration, Instant};

use bytes::Bytes;
use sh_media::{FrameSink, ScreenCapturer, VideoDecoder, VideoEncoder};
use sh_types::FrameId;

/// Errors that can occur during pipeline execution.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// A transport-layer error occurred.
    #[error("transport: {0}")]
    Transport(#[from] sh_transport::TransportError),
    /// An encoding error occurred.
    #[error("encode: {0}")]
    Encode(sh_media::MediaError),
    /// A decoding error occurred.
    #[error("decode: {0}")]
    Decode(sh_media::MediaError),
    /// A packetization error occurred.
    #[error("packetize: {0}")]
    Packetize(#[from] crate::packetize::PacketizeError),
    /// A render sink error occurred.
    #[error("render: {0}")]
    Render(#[from] sh_media::RenderError),
    /// The connection does not support datagrams.
    #[error("no datagram support on this connection")]
    NoDatagramSupport,
    /// The operation timed out.
    #[error("operation timed out")]
    Timeout,
    /// The capturer returned no frame.
    #[error("capture returned no frame")]
    NoFrame,
}

/// Parameters for the host-side capture/encode/send pipeline.
#[derive(Debug, Clone)]
pub struct HostPipelineParams {
    /// Number of frames to capture and send.
    pub frame_count: usize,
    /// Frames per second for the capturer.
    pub fps: u32,
    /// Whether to pace frames according to the configured FPS.
    pub pace_frames: bool,
}

/// Run the host-side pipeline: capture → encode → fragment → send.
///
/// Captures `params.frame_count` frames, encodes them, fragments each encoded
/// packet into QUIC datagrams, and sends them over `conn`.
///
/// The `max_datagram_size` is re-queried once per frame so that QUIC path-MTU
/// discovery changes are respected during a long burst transfer. Callers must
/// pass a connection whose transport config has datagrams enabled
/// (i.e. `datagram_receive_buffer_size` set to `Some(_)`).
///
/// Returns a list of `(FrameId, send_instant)` pairs for each frame sent.
///
/// # Errors
///
/// Returns [`PipelineError::NoDatagramSupport`] if the connection does not
/// support datagrams.
/// Returns [`PipelineError::NoFrame`] if the capturer returns `None`.
/// Returns [`PipelineError::Encode`] on capture or encode errors.
/// Returns [`PipelineError::Packetize`] on fragmentation errors.
/// Returns [`PipelineError::Transport`] on send errors.
pub async fn run_host_pipeline(
    conn: &sh_transport::Connection,
    capturer: &mut dyn ScreenCapturer,
    encoder: &mut dyn VideoEncoder,
    params: &HostPipelineParams,
) -> Result<Vec<(FrameId, Instant)>, PipelineError> {
    let mut seq: u16 = 0;
    let mut results = Vec::with_capacity(params.frame_count);

    for _ in 0..params.frame_count {
        let max_datagram = conn
            .max_datagram_size()
            .ok_or(PipelineError::NoDatagramSupport)?;

        let frame = capturer
            .next_frame(Duration::ZERO)
            .map_err(PipelineError::Encode)?
            .ok_or(PipelineError::NoFrame)?;

        let Some(packet) = encoder.encode(&frame).map_err(PipelineError::Encode)? else {
            continue;
        };

        let frame_id = packet.frame_id;
        let datagrams = crate::packetize::fragment(&packet, seq, max_datagram)?;
        let num_frags = u16::try_from(datagrams.len()).unwrap_or(u16::MAX);

        let send_instant = Instant::now();
        for dg in datagrams {
            conn.send_datagram_wait(dg).await?;
        }
        results.push((frame_id, send_instant));
        seq = seq.wrapping_add(num_frags);
    }

    // Flush encoder
    let tail = encoder.flush().map_err(PipelineError::Encode)?;
    for packet in tail {
        let max_datagram = conn
            .max_datagram_size()
            .ok_or(PipelineError::NoDatagramSupport)?;
        let frame_id = packet.frame_id;
        let datagrams = crate::packetize::fragment(&packet, seq, max_datagram)?;
        let num_frags = u16::try_from(datagrams.len()).unwrap_or(u16::MAX);
        let send_instant = Instant::now();
        for dg in datagrams {
            conn.send_datagram_wait(dg).await?;
        }
        results.push((frame_id, send_instant));
        seq = seq.wrapping_add(num_frags);
    }

    Ok(results)
}

/// Run the client-side pipeline: receive → reassemble → decode → sink.
///
/// Receives datagrams from `conn` until `frame_count` complete frames have been
/// decoded and delivered to `sink`, or until the overall deadline (computed once
/// from `timeout` at call time) elapses.
///
/// Returns a list of `(FrameId, recv_instant)` pairs for each decoded frame.
///
/// # Errors
///
/// Returns [`PipelineError::Timeout`] if no datagram arrives before the deadline.
/// Returns [`PipelineError::Transport`] on receive errors.
/// Returns [`PipelineError::Decode`] on decode errors.
/// Returns [`PipelineError::Render`] if the sink rejects a frame.
pub async fn run_client_pipeline(
    conn: &sh_transport::Connection,
    decoder: &mut dyn VideoDecoder,
    sink: &mut dyn FrameSink,
    frame_count: usize,
    timeout: Duration,
) -> Result<Vec<(FrameId, Instant)>, PipelineError> {
    let mut reassembler = crate::packetize::Reassembler::new();
    let mut results = Vec::with_capacity(frame_count);
    #[allow(clippy::arithmetic_side_effects)]
    let deadline = tokio::time::Instant::now() + timeout;

    while results.len() < frame_count {
        let datagram: Bytes = tokio::time::timeout_at(deadline, conn.read_datagram())
            .await
            .map_err(|_| PipelineError::Timeout)?
            .map_err(PipelineError::Transport)?;

        if let Some(packet) = reassembler.ingest(&datagram) {
            if let Some(frame) = decoder.decode(&packet).map_err(PipelineError::Decode)? {
                let frame_id = frame.frame_id;
                sink.deliver(frame).map_err(PipelineError::Render)?;
                results.push((frame_id, Instant::now()));
            }
        }
    }

    Ok(results)
}
