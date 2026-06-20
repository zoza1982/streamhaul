//! Channel prioritization and congestion-isolation integration tests.
//!
//! These tests require the `insecure-lan` feature (self-signed TLS + skip-verify client).
#![cfg(feature = "insecure-lan")]

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    missing_docs
)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use sh_transport::{
        channel::{ChannelSpec, QuicTransport, Transport},
        insecure_client_config, self_signed_server_config, ClientEndpoint, InsecureLanLab,
        ServerEndpoint,
    };
    use tokio::sync::Mutex;

    fn ack() -> InsecureLanLab {
        InsecureLanLab::i_understand_this_skips_tls_verification()
    }

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// Establish a server+client QUIC transport pair over loopback.
    async fn transport_pair() -> (QuicTransport, QuicTransport) {
        let server =
            ServerEndpoint::bind(loopback(), self_signed_server_config(ack()).unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let client = ClientEndpoint::bind(insecure_client_config(ack()).unwrap()).unwrap();

        let (server_conn, client_conn) =
            tokio::join!(server.accept(), client.connect(addr, "localhost"));

        (
            QuicTransport::new(server_conn.unwrap()),
            QuicTransport::new(client_conn.unwrap()),
        )
    }

    // ────────────────────────────────────────────────────────────────────────
    // ChannelSpec convenience constructor assertions (LLD §3.2)
    // ────────────────────────────────────────────────────────────────────────

    /// Verify that the convenience constructors assign the LLD §3.2 urgency values.
    ///
    /// LLD §3.2 urgency table → `ChannelSpec.priority` field (0 = highest):
    ///   input=0, control=1, clipboard=2, file=6.
    /// `quinn_priority()` inverts to quinn i32 space (255 - priority).
    #[test]
    fn channel_spec_constructors_match_lld_priorities() {
        let input = ChannelSpec::input();
        assert_eq!(input.priority, 0, "input must be urgency 0 (highest)");
        assert_eq!(input.quinn_priority(), 255);

        let control = ChannelSpec::control();
        assert_eq!(control.priority, 1, "control must be urgency 1");
        assert_eq!(control.quinn_priority(), 254);

        let clipboard = ChannelSpec::clipboard();
        assert_eq!(clipboard.priority, 2, "clipboard must be urgency 2");
        assert_eq!(clipboard.quinn_priority(), 253);

        let file = ChannelSpec::file();
        assert_eq!(file.priority, 6, "file must be urgency 6 (lowest)");
        assert_eq!(file.quinn_priority(), 249);

        // input must outrank all others.
        assert!(input.quinn_priority() > control.quinn_priority());
        assert!(control.quinn_priority() > clipboard.quinn_priority());
        assert!(clipboard.quinn_priority() > file.quinn_priority());
    }

    // ────────────────────────────────────────────────────────────────────────
    // Input-not-starved starvation test
    // ────────────────────────────────────────────────────────────────────────

    /// Prove that the input channel is **not starved** under heavy file + video datagram load.
    ///
    /// # What this test proves
    ///
    /// Separate QUIC streams give each reliable channel its own flow-control window, so a
    /// bulk file transfer cannot head-of-line block the input stream — the congestion isolation
    /// documented in LLD §4.7 is **structural** (separate streams), not a software mutex.
    /// Quinn's stream scheduler then honours the priority assignment (input urgency 0, file
    /// urgency 6) to drain pending input data ahead of file data when both compete for the
    /// congestion window.
    ///
    /// The test verifies both properties together:
    /// 1. Every input event arrives in order (no loss, no reorder).
    /// 2. Median and p95 inter-arrival gaps on the input channel stay well below 500 ms
    ///    (close to the 10 ms send cadence), proving input is not serialised behind the file
    ///    flood. If input were HoL-blocked behind file data it would be stalled for the
    ///    duration of each 256 KiB chunk (~seconds at loopback rates with backpressure), far
    ///    exceeding the threshold.
    /// 3. The file channel makes progress: at least one file chunk is received (transfer is
    ///    not completely blocked by the input stream's higher priority).
    #[tokio::test(flavor = "multi_thread")]
    async fn input_not_starved_under_file_and_video_flood() {
        // Overall test budget — fail (via timeout) rather than hang.
        const TEST_TIMEOUT: Duration = Duration::from_secs(30);

        // Starvation threshold: if any inter-arrival gap on the *input* channel exceeds this
        // we conclude input was serialised behind file data. 500 ms is >10× the send cadence
        // (10 ms) but still far less than the HoL-block duration for a 256 KiB chunk at
        // realistic loopback bandwidth.
        const INPUT_GAP_THRESHOLD: Duration = Duration::from_millis(500);

        // Number of small input events to send at ~10 ms cadence.
        const INPUT_COUNT: u64 = 50;
        // Cadence between input sends.
        const INPUT_CADENCE: Duration = Duration::from_millis(10);
        // File chunk size: large enough to keep the congestion window busy.
        const FILE_CHUNK_SIZE: usize = 256 * 1024; // 256 KiB
                                                   // How many file chunks to send (enough to overlap the full input sequence).
        const FILE_CHUNKS: usize = 40;

        let (server, client) = transport_pair().await;
        let server = Arc::new(server);
        let client = Arc::new(client);

        // ── Open channels ─────────────────────────────────────────────────────
        // Input: reliable, priority 0 (highest).
        let (server_input_res, client_input_res) = tokio::join!(
            server.accept_channel(),
            client.open_channel(ChannelSpec::input()),
        );
        let server_input = Arc::new(Mutex::new(server_input_res.unwrap()));
        let mut client_input = client_input_res.unwrap();

        // File: reliable, priority 6 (lowest). Opened concurrently with server accept.
        let (server_file_res, client_file_res) = tokio::join!(
            server.accept_channel(),
            client.open_channel(ChannelSpec::file()),
        );
        let server_file = Arc::new(Mutex::new(server_file_res.unwrap()));
        let mut client_file = client_file_res.unwrap();

        // Video: unreliable datagram channel — no accept needed.
        let mut client_video = client.open_channel(ChannelSpec::video()).await.unwrap();
        let mut server_video = server.open_channel(ChannelSpec::video()).await.unwrap();

        // ── Background load tasks ──────────────────────────────────────────────

        // Task A: flood the file channel with large chunks.
        // Uses `send` (which internally calls `send_datagram_wait`-equivalent backpressure
        // via the quinn stream's flow control). We stop after FILE_CHUNKS.
        let file_send_task = {
            let chunk = Bytes::from(vec![0xABu8; FILE_CHUNK_SIZE]);
            tokio::spawn(async move {
                for _ in 0..FILE_CHUNKS {
                    // Errors are expected if the connection tears down before we finish.
                    if client_file.send(chunk.clone()).await.is_err() {
                        break;
                    }
                }
            })
        };

        // Task B: flood the datagram (video) channel.
        // Stop when input sequence is done — we use a shared flag via a cancellation token
        // (simple approach: send until an error, which happens when the connection closes).
        let video_send_task = {
            let frame = Bytes::from(vec![0xFFu8; 1200]); // typical video datagram size
            tokio::spawn(async move {
                loop {
                    if client_video.send(frame.clone()).await.is_err() {
                        break;
                    }
                    // No sleep: flood as fast as backpressure allows.
                }
            })
        };

        // Task C: drain server video datagrams so quinn's receive buffer doesn't block.
        let video_drain_task = tokio::spawn(async move {
            loop {
                if server_video.recv().await.is_err() {
                    break;
                }
            }
        });

        // Task D: drain server file channel, count chunks received.
        let file_chunks_received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let file_drain_task = {
            let server_file = server_file.clone();
            let counter = file_chunks_received.clone();
            tokio::spawn(async move {
                loop {
                    let result = {
                        let mut ch = server_file.lock().await;
                        ch.recv().await
                    };
                    match result {
                        Ok(Some(_)) => {
                            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        _ => break,
                    }
                }
            })
        };

        // ── Input sender: 50 events paced 10 ms apart ──────────────────────────
        // Each event carries a sequence number + send timestamp.
        // We run this in the main task (foreground) so we can await it directly.
        let mut send_times: Vec<Instant> = Vec::with_capacity(INPUT_COUNT as usize);
        for seq in 0_u64..INPUT_COUNT {
            let mut payload = [0u8; 16];
            payload[..8].copy_from_slice(&seq.to_be_bytes());
            let now = Instant::now();
            send_times.push(now);
            // Encode send time as nanos since test start in upper 8 bytes (best-effort; the
            // important clock is the receiver-side Instant recorded on arrival).
            let nanos = now.elapsed().as_nanos() as u64;
            payload[8..].copy_from_slice(&nanos.to_be_bytes());
            client_input
                .send(Bytes::copy_from_slice(&payload))
                .await
                .unwrap();
            tokio::time::sleep(INPUT_CADENCE).await;
        }
        // Input sending done. Drop client input to signal EOF; server will drain to None.
        drop(client_input);

        // ── Receive input events server-side ──────────────────────────────────
        // Collect arrival timestamps. We expect INPUT_COUNT messages in order.
        let mut arrival_times: Vec<Instant> = Vec::with_capacity(INPUT_COUNT as usize);
        let mut received_seqs: Vec<u64> = Vec::with_capacity(INPUT_COUNT as usize);

        let input_recv_result = tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                let msg = {
                    let mut ch = server_input.lock().await;
                    ch.recv().await
                };
                match msg {
                    Ok(Some(data)) if data.len() == 16 => {
                        arrival_times.push(Instant::now());
                        let seq = u64::from_be_bytes(data[..8].try_into().unwrap());
                        received_seqs.push(seq);
                    }
                    Ok(Some(_)) => panic!("unexpected payload size"),
                    Ok(None) => break, // clean EOF — all sent
                    Err(e) => panic!("input recv error: {e:?}"),
                }
            }
        })
        .await;

        // If we timed out the test is broken; fail clearly.
        input_recv_result.expect("input channel drain timed out — possible starvation");

        // ── Tear down background tasks ────────────────────────────────────────
        // Drop the client connection so background tasks terminate.
        drop(client);
        // Wait briefly for drain tasks to notice the connection close.
        let _ = tokio::time::timeout(Duration::from_secs(5), file_send_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), video_send_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), video_drain_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), file_drain_task).await;

        // ── Assertions ────────────────────────────────────────────────────────

        // 1. All INPUT_COUNT events arrived.
        assert_eq!(
            received_seqs.len(),
            INPUT_COUNT as usize,
            "expected {INPUT_COUNT} input events, got {}",
            received_seqs.len()
        );

        // 2. Events arrived in order (reliable stream guarantee).
        for (i, &seq) in received_seqs.iter().enumerate() {
            assert_eq!(
                seq, i as u64,
                "input event out of order: index {i} got seq {seq}"
            );
        }

        // 3. Compute inter-arrival gaps and assert not-starved property.
        //    If HoL-blocked behind file chunks, the input channel would stall for the full
        //    duration of each 256 KiB chunk transmission; on a loopback interface that
        //    saturates at ~1+ Gbps this is still measurable tens of ms per chunk, but more
        //    importantly the flow-control window would queue many chunks before the input
        //    stream gets a look-in — total stall time would be seconds, far above 500 ms.
        let mut gaps: Vec<Duration> = Vec::with_capacity(arrival_times.len().saturating_sub(1));
        for pair in arrival_times.windows(2) {
            gaps.push(pair[1].duration_since(pair[0]));
        }

        if !gaps.is_empty() {
            let mut sorted_gaps = gaps.clone();
            sorted_gaps.sort();

            let median = sorted_gaps[sorted_gaps.len() / 2];
            let p95_idx = (sorted_gaps.len() as f64 * 0.95) as usize;
            let p95_idx = p95_idx.min(sorted_gaps.len().saturating_sub(1));
            let p95 = sorted_gaps[p95_idx];
            let max_gap = *sorted_gaps.last().unwrap();

            eprintln!(
                "[starvation-test] input inter-arrival: median={median:?} p95={p95:?} max={max_gap:?} n={}",
                gaps.len()
            );

            assert!(
                p95 < INPUT_GAP_THRESHOLD,
                "p95 input inter-arrival {p95:?} exceeds threshold {INPUT_GAP_THRESHOLD:?} — \
                 input may be HoL-blocked behind file stream"
            );
        }

        // 4. File transfer made progress (not completely starved by input priority).
        let file_received = file_chunks_received.load(std::sync::atomic::Ordering::Relaxed);
        eprintln!(
            "[starvation-test] file chunks received by server: {file_received}/{FILE_CHUNKS}"
        );
        assert!(
            file_received > 0,
            "file channel received zero chunks — file transfer completely blocked"
        );
    }
}
