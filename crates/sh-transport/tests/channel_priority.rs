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
    // Structural isolation test: input delivery under concurrent file + video load
    // ────────────────────────────────────────────────────────────────────────

    /// Verify that input events are delivered **completely, in order, and promptly**
    /// while a heavy file transfer and video-datagram flood run concurrently.
    ///
    /// # What this test actually proves
    ///
    /// Each reliable channel occupies its own QUIC stream with an independent flow-control
    /// window. This means a bulk file transfer physically cannot head-of-line-block the input
    /// stream — the isolation is **structural** (LLD §4.7): separate streams, not a software
    /// lock. That is the primary property asserted here.
    ///
    /// Additionally, the `ChannelSpec` priority assignment is confirmed correct (input urgency 0,
    /// file urgency 6) through the `channel_spec_constructors_match_lld_priorities` unit test;
    /// we therefore also confirm that opening channels with those specs succeeds and channels
    /// carry traffic correctly under load.
    ///
    /// # What this test does NOT prove
    ///
    /// The loopback interface saturates at ~40 Gbps and quinn's initial flow-control window
    /// is ~1 MiB, so even sending 40 × 256 KiB of file data creates at most a few
    /// milliseconds of queueing — far under the generous smoke-check thresholds used below.
    /// This means the inter-arrival latency check is a **smoke check**, not a proof that the
    /// quinn scheduler honours priorities under genuine bandwidth congestion. A rigorous
    /// congestion-scheduling test requires artificial bandwidth shaping (e.g. Linux `tc`/`netem`
    /// or a rate-limited mock transport) and is deferred.
    ///
    /// TODO(future): add a rate-limited transport harness and rerun this test at a constrained
    /// bandwidth (~10 Mbps) to produce a meaningful congestion-scheduling proof.
    #[tokio::test(flavor = "multi_thread")]
    async fn input_delivered_completely_and_in_order_under_concurrent_load() {
        // Overall test budget. On a busy CI host the 0.5 s of sleep plus drain time should
        // comfortably complete within 15 s; 30 s gives ample headroom without masking hangs.
        const TEST_TIMEOUT: Duration = Duration::from_secs(30);

        // Number of small input events to send at ~10 ms cadence.
        const INPUT_COUNT: u64 = 50;
        // Cadence between input sends (50 × 10 ms = 0.5 s total send window).
        const INPUT_CADENCE: Duration = Duration::from_millis(10);

        // File chunk size and count. These are large enough to keep the file stream busy
        // while the input sequence runs but small enough to drain quickly once we start
        // tearing down (40 × 256 KiB = 10 MiB; on loopback drains in <1 s).
        const FILE_CHUNK_SIZE: usize = 256 * 1024; // 256 KiB
        const FILE_CHUNKS: usize = 40;

        // Smoke-check: if the p95 inter-arrival gap on the input channel exceeds this
        // generous bound something is seriously wrong (scheduler loop, deadlock, etc.).
        // This is NOT a congestion-scheduling proof — see the doc comment above.
        const SMOKE_CHECK_GAP: Duration = Duration::from_millis(500);

        let (server, client) = transport_pair().await;

        // ── Open channels ─────────────────────────────────────────────────────
        // Input: reliable, priority 0 (highest per LLD §3.2).
        let (server_input_res, client_input_res) = tokio::join!(
            server.accept_channel(),
            client.open_channel(ChannelSpec::input()),
        );
        let mut server_input = server_input_res.unwrap();
        let mut client_input = client_input_res.unwrap();

        // File: reliable, priority 6 (lowest per LLD §3.2). Each file stream has its own
        // QUIC flow-control window independent of the input stream — the HoL-block immunity
        // is guaranteed at the QUIC layer, not by software scheduling.
        let (server_file_res, client_file_res) = tokio::join!(
            server.accept_channel(),
            client.open_channel(ChannelSpec::file()),
        );
        let mut client_file = client_file_res.unwrap();
        let mut server_file = server_file_res.unwrap();

        // Video: unreliable datagram channel — opened independently on both sides.
        let mut client_video = client.open_channel(ChannelSpec::video()).await.unwrap();
        let mut server_video = server.open_channel(ChannelSpec::video()).await.unwrap();

        // ── Background load tasks ──────────────────────────────────────────────
        // These run concurrently with the input sequence to exercise the isolation guarantee.

        // Task A: flood the file channel with large chunks until done or connection closes.
        let file_send_task = {
            let chunk = Bytes::from(vec![0xABu8; FILE_CHUNK_SIZE]);
            tokio::spawn(async move {
                for _ in 0..FILE_CHUNKS {
                    if client_file.send(chunk.clone()).await.is_err() {
                        break;
                    }
                }
            })
        };

        // Task B: flood the datagram (video) channel until the connection closes.
        let video_send_task = {
            let frame = Bytes::from(vec![0xFFu8; 1200]);
            tokio::spawn(async move {
                loop {
                    if client_video.send(frame.clone()).await.is_err() {
                        break;
                    }
                    // No sleep — flood as fast as backpressure allows.
                }
            })
        };

        // Task C: drain server video datagrams so quinn's receive buffer doesn't stall.
        let video_drain_task = tokio::spawn(async move {
            loop {
                if server_video.recv().await.is_err() {
                    break;
                }
            }
        });

        // Task D: drain server file channel; count chunks received to verify file progress.
        let file_chunks_received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let file_drain_task = {
            let counter = file_chunks_received.clone();
            tokio::spawn(async move {
                while let Ok(Some(_)) = server_file.recv().await {
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            })
        };

        // ── Input sender: 50 events paced 10 ms apart ──────────────────────────
        // Each event carries an 8-byte big-endian sequence number.
        // Arrival times are recorded receiver-side; no send timestamps needed.
        for seq in 0_u64..INPUT_COUNT {
            let payload = seq.to_be_bytes();
            client_input
                .send(Bytes::copy_from_slice(&payload))
                .await
                .unwrap();
            tokio::time::sleep(INPUT_CADENCE).await;
        }
        // Drop client_input to send a clean EOF; server drains to Ok(None).
        drop(client_input);

        // ── Receive input events server-side ──────────────────────────────────
        let mut arrival_times: Vec<Instant> = Vec::with_capacity(INPUT_COUNT as usize);
        let mut received_seqs: Vec<u64> = Vec::with_capacity(INPUT_COUNT as usize);

        let input_recv_result = tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                match server_input.recv().await {
                    Ok(Some(data)) if data.len() == 8 => {
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

        input_recv_result.expect("input channel drain timed out under concurrent load");

        // ── Tear down background tasks ────────────────────────────────────────
        // The video send and drain tasks run indefinite loops (they only stop on a connection
        // error). Aborting them is correct: tokio::JoinHandle::abort() cancels the future
        // safely; the channel state is irrelevant at this point.
        //
        // The file tasks are finite: file_send_task runs at most FILE_CHUNKS iterations, and
        // file_drain_task terminates once the file stream reaches EOF or error. We drop the
        // client transport to close the QUIC connection, which unblocks any pending sends.
        video_send_task.abort();
        video_drain_task.abort();

        // Drop the client transport so the remaining quinn connection is closed; this
        // signals the server-side file drain that no more data is coming.
        drop(client);

        // Await the finite tasks with a generous bound; surface panics.
        const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(10);
        tokio::time::timeout(TEARDOWN_TIMEOUT, file_send_task)
            .await
            .expect("file_send_task did not finish in time")
            .expect("file_send_task panicked");
        tokio::time::timeout(TEARDOWN_TIMEOUT, file_drain_task)
            .await
            .expect("file_drain_task did not finish in time")
            .expect("file_drain_task panicked");

        // ── Assertions ────────────────────────────────────────────────────────

        // 1. All INPUT_COUNT events arrived — the input stream was not dropped.
        assert_eq!(
            received_seqs.len(),
            INPUT_COUNT as usize,
            "expected {INPUT_COUNT} input events, got {}",
            received_seqs.len()
        );

        // 2. Events arrived in-order — reliable-stream guarantee of QUIC.
        for (i, &seq) in received_seqs.iter().enumerate() {
            assert_eq!(
                seq, i as u64,
                "input event out of order at index {i}: got seq {seq}"
            );
        }

        // 3. Smoke-check: compute inter-arrival gaps.
        //
        //    IMPORTANT: on loopback this does NOT prove congestion-scheduling correctness.
        //    The loopback RTT is ~40 µs and the QUIC cwnd is ~1 MiB, so 10 MiB of file data
        //    cannot create meaningful head-of-line pressure against the 8-byte input events.
        //    The assertion below only catches severe regressions (scheduler loop, deadlock,
        //    extreme OS scheduling jitter). A real congestion test needs bandwidth shaping.
        let mut gaps: Vec<Duration> = Vec::with_capacity(arrival_times.len().saturating_sub(1));
        for pair in arrival_times.windows(2) {
            gaps.push(pair[1].duration_since(pair[0]));
        }

        if !gaps.is_empty() {
            let mut sorted_gaps = gaps.clone();
            sorted_gaps.sort();

            let n = sorted_gaps.len();
            let median = sorted_gaps[n / 2];
            // Integer nearest-rank p95: index = ((n-1) * 95) / 100.
            let p95_idx = ((n.saturating_sub(1)).saturating_mul(95)) / 100;
            let p95 = sorted_gaps[p95_idx];
            let max_gap = *sorted_gaps.last().unwrap();

            eprintln!(
                "[isolation-test] input inter-arrival: median={median:?} p95={p95:?} \
                 max={max_gap:?} n={n} (smoke-check only; not a congestion-scheduling proof)"
            );

            // Smoke-check: not a congestion-scheduling proof. See doc comment.
            assert!(
                p95 < SMOKE_CHECK_GAP,
                "p95 input inter-arrival {p95:?} exceeded smoke-check bound \
                 {SMOKE_CHECK_GAP:?} — possible scheduler regression or severe OS jitter"
            );
        }

        // 4. File transfer also made progress while the input sequence ran, confirming the
        //    input stream's higher priority does not completely starve the file stream.
        let file_received = file_chunks_received.load(std::sync::atomic::Ordering::Relaxed);
        eprintln!("[isolation-test] file chunks received: {file_received}/{FILE_CHUNKS}");
        assert!(
            file_received > 0,
            "file channel received zero chunks — likely a drain-task failure"
        );
    }
}
