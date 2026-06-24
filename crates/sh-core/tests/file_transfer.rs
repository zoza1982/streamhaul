//! End-to-end file-transfer orchestration over a real QUIC transport (P7-2 — ADR-0024).
//!
//! Drives [`FileSender`]/[`FileReceiver`] across **real** QUIC channels — file control
//! (offer/accept/complete) on the reliable Control channel and chunks on a dedicated
//! `ChannelSpec::file()` stream — proving the resume + SHA-256 integrity path works over the
//! transport, not just in the in-memory unit tests. The `sh-transport` dev-dependency enables its
//! `insecure-lan` feature (self-signed TLS + skip-verify client) for these tests.

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects,
    clippy::panic,
    missing_docs
)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use bytes::Bytes;
    use sh_core::authz::Capabilities;
    use sh_core::{FileReceiver, FileSender};
    use sh_protocol::file::{
        FileAccept, FileComplete, FileOffer, KIND_FILE_ACCEPT, KIND_FILE_COMPLETE, KIND_FILE_OFFER,
    };
    use sh_protocol::{decode_control, encode_control};
    use sh_transport::{
        channel::{ChannelSpec, QuicTransport, Transport},
        insecure_client_config, self_signed_server_config, Channel, ClientEndpoint, InsecureLanLab,
        ServerEndpoint,
    };

    const CAP: u64 = 64 * 1024 * 1024;

    fn ack() -> InsecureLanLab {
        InsecureLanLab::i_understand_this_skips_tls_verification()
    }
    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    async fn transport_pair() -> (QuicTransport, QuicTransport) {
        let server =
            ServerEndpoint::bind(loopback(), self_signed_server_config(ack()).unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let client = ClientEndpoint::bind(insecure_client_config(ack()).unwrap()).unwrap();
        let (s, c) = tokio::join!(server.accept(), client.connect(addr, "localhost"));
        (
            QuicTransport::new(s.unwrap()),
            QuicTransport::new(c.unwrap()),
        )
    }

    fn deterministic_file(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
    }

    /// Receive exactly one control frame of `kind` from `ch` and return its payload bytes.
    async fn recv_control(ch: &mut dyn Channel, kind: u8) -> Vec<u8> {
        let msg = ch.recv().await.unwrap().expect("control channel closed");
        let frame = decode_control(&msg)
            .unwrap()
            .expect("incomplete control frame");
        assert_eq!(frame.kind, kind, "unexpected control kind");
        frame.payload.to_vec()
    }

    /// Run a transfer where the receiver starts with `already_have` bytes (resume when non-empty).
    /// Returns the receiver's reassembled bytes.
    async fn run_over_quic(data: Vec<u8>, already_have: Vec<u8>) -> Vec<u8> {
        let (server, client) = transport_pair().await;

        // Client = sender, server = receiver. Open control + file channels.
        let (s_ctrl, c_ctrl) = tokio::join!(
            server.accept_channel(),
            client.open_channel(ChannelSpec::control())
        );
        let (mut s_ctrl, mut c_ctrl) = (s_ctrl.unwrap(), c_ctrl.unwrap());
        let (s_file, c_file) = tokio::join!(
            server.accept_channel(),
            client.open_channel(ChannelSpec::file())
        );
        let (mut s_file, mut c_file) = (s_file.unwrap(), c_file.unwrap());

        // ── Sender task (client) ──────────────────────────────────────────────
        let send_data = data.clone();
        let sender_task = tokio::spawn(async move {
            let mut sender = FileSender::new(7, "payload.bin", send_data, 16 * 1024).unwrap();
            // Offer → Control.
            let offer_bytes = sender.offer().encode().unwrap();
            c_ctrl
                .send(Bytes::from(
                    encode_control(KIND_FILE_OFFER, &offer_bytes).unwrap(),
                ))
                .await
                .unwrap();
            // Await Accept ← Control.
            let payload = recv_control(c_ctrl.as_mut(), KIND_FILE_ACCEPT).await;
            let accept = FileAccept::decode(&payload).unwrap();
            sender.on_accept(&accept).unwrap();
            // Stream chunks → File channel.
            while let Some(frame) = sender.next_chunk().unwrap() {
                c_file.send(Bytes::from(frame)).await.unwrap();
            }
            // Await the receiver's terminal FileComplete ← Control and report its verdict.
            let payload = recv_control(c_ctrl.as_mut(), KIND_FILE_COMPLETE).await;
            FileComplete::decode(&payload).unwrap().ok
        });

        // ── Receiver task (server) ────────────────────────────────────────────
        let receiver_task = tokio::spawn(async move {
            let offer_payload = recv_control(s_ctrl.as_mut(), KIND_FILE_OFFER).await;
            let offer: FileOffer = FileOffer::decode(&offer_payload).unwrap();
            let (mut receiver, accept) =
                FileReceiver::accept_offer(Capabilities::FILE, &offer, &already_have, CAP).unwrap();
            // Accept → Control.
            s_ctrl
                .send(Bytes::from(
                    encode_control(KIND_FILE_ACCEPT, &accept.encode()).unwrap(),
                ))
                .await
                .unwrap();
            // Receive chunks until the whole size is present (empty file completes immediately).
            while !receiver.is_complete() {
                let frame = s_file
                    .recv()
                    .await
                    .unwrap()
                    .expect("file stream closed early");
                if receiver.on_chunk(&frame).unwrap() {
                    break;
                }
            }
            let (bytes, complete): (Vec<u8>, FileComplete) = receiver.finish().unwrap();
            assert!(complete.ok, "integrity must pass");
            // Send the terminal FileComplete → Control so the sender learns the verdict.
            s_ctrl
                .send(Bytes::from(
                    encode_control(KIND_FILE_COMPLETE, &complete.encode()).unwrap(),
                ))
                .await
                .unwrap();
            bytes
        });

        let sender_verdict = sender_task.await.unwrap();
        assert!(sender_verdict, "sender must observe ok=true completion");
        tokio::time::timeout(Duration::from_secs(30), receiver_task)
            .await
            .expect("receiver timed out")
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn full_transfer_over_quic_verifies_integrity() {
        let data = deterministic_file(512 * 1024 + 123);
        let got = run_over_quic(data.clone(), Vec::new()).await;
        assert_eq!(got, data);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resumed_transfer_over_quic_reconstructs_whole_file() {
        let data = deterministic_file(300_000);
        let prefix = data[..120_000].to_vec(); // receiver already holds a prefix
        let got = run_over_quic(data.clone(), prefix).await;
        assert_eq!(
            got, data,
            "resumed transfer must reconstruct the whole file"
        );
    }
}
