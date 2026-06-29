//! End-to-end loopback test for the preview slice: synthetic capture → OpenH264 encode → **real
//! QUIC** → OpenH264 decode, all in-process over 127.0.0.1. Uses the synthetic capturer (no display)
//! so it is deterministic and CI-runnable anywhere; the real-X11-capture path is exercised by the
//! `streamhaul-preview-host` binary under Xvfb in the dedicated CI job.
//!
//! This goes beyond the codec's fragment/reassemble unit test (sh-codec-openh264): it drives the
//! actual QUIC datagram transport (`serve`/`receive` over a loopback connection), proving the whole
//! capture→encode→transport→decode slice holds together.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use sh_media::{PixelFormat, Resolution, SyntheticCapturer};

#[tokio::test]
async fn synthetic_openh264_streams_over_quic_loopback() {
    const FRAMES: usize = 10;
    let res = Resolution::new(320, 240);

    let ack = sh_transport::InsecureLanLab::i_understand_this_skips_tls_verification();
    let server_config = sh_transport::self_signed_server_config(ack).unwrap();
    let server_ep =
        sh_transport::ServerEndpoint::bind("127.0.0.1:0".parse().unwrap(), server_config).unwrap();
    let addr = server_ep.local_addr().unwrap();

    // Host task: accept the connection, then capture + encode + stream (paced, so the receiver keeps
    // up over the unreliable datagram path).
    let host = tokio::spawn(async move {
        let conn = server_ep.accept().await.expect("accept");
        let mut cap = SyntheticCapturer::new(res, 30);
        let sent = streamhaul_preview::serve(&conn, &mut cap, 4_000, FRAMES, 30, true)
            .await
            .expect("serve");
        // Hold the connection (and server endpoint) open briefly so the client can drain the last
        // in-flight datagrams before we drop them (the bins do the same — there is no done channel).
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        sent
    });

    let client_ack = sh_transport::InsecureLanLab::i_understand_this_skips_tls_verification();
    let client_config = sh_transport::insecure_client_config(client_ack).unwrap();
    let client_ep = sh_transport::ClientEndpoint::bind(client_config).unwrap();
    let conn = client_ep.connect(addr, "localhost").await.expect("connect");

    let (recv_times, frames) = streamhaul_preview::receive(&conn, FRAMES, Duration::from_secs(10))
        .await
        .expect("receive");

    // The slice must actually deliver decoded video. (QUIC datagrams are unreliable, so we assert
    // delivery happened and every delivered frame is well-formed rather than an exact count.)
    assert!(
        !frames.is_empty(),
        "no frames decoded over the QUIC loopback — the preview slice did not deliver video"
    );
    assert_eq!(recv_times.len(), frames.len());
    for f in &frames {
        assert_eq!(f.format, PixelFormat::Bgra8);
        assert_eq!(f.resolution, res);
        f.validate_len().expect("decoded frame self-consistent");
    }

    let sent = host.await.expect("host task join");
    assert!(!sent.is_empty(), "host sent no frames");
}
