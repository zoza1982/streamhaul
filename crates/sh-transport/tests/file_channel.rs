//! File data-plane functional test over a real QUIC `ChannelSpec::file()` stream (P7 — ADR-0024).
//!
//! Frames a multi-chunk pseudo-file with the `sh-protocol::file` wire headers, streams it over the
//! file channel's own QUIC stream, and verifies the receiver reassembles it **byte-identically**
//! (correct offsets, correct `LAST` flag, no truncation). This exercises the real transport path
//! for the file data plane; the resume/integrity orchestration is tested in `sh-core` (P7-2).
//!
//! Requires the `insecure-lan` feature (self-signed TLS + skip-verify client), like the other
//! loopback transport tests.
#![cfg(feature = "insecure-lan")]

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::panic,
    missing_docs
)]
mod tests {
    use std::net::SocketAddr;

    use bytes::Bytes;
    use sh_protocol::file::{FileChunkHeader, FILE_CHUNK_HEADER_LEN};
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

    /// A deterministic pseudo-file: byte `i` is `(i * 31 + 7) % 251` — no RNG, easy to verify.
    fn make_file(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
    }

    /// Frame `data` into `chunk_size` chunks with `FileChunkHeader` and send each over `channel`.
    async fn send_framed_file(
        channel: &mut dyn sh_transport::Channel,
        transfer_id: u64,
        data: &[u8],
        chunk_size: usize,
    ) {
        let mut offset = 0usize;
        while offset < data.len() {
            let end = (offset + chunk_size).min(data.len());
            let payload = &data[offset..end];
            let last = end == data.len();
            let header = FileChunkHeader {
                transfer_id,
                offset: offset as u64,
                len: payload.len() as u32,
                last,
            }
            .encode()
            .unwrap();
            let mut frame = Vec::with_capacity(FILE_CHUNK_HEADER_LEN + payload.len());
            frame.extend_from_slice(&header);
            frame.extend_from_slice(payload);
            channel.send(Bytes::from(frame)).await.unwrap();
            offset = end;
        }
    }

    /// Receive framed chunks until `LAST`, validating offsets and reassembling the file.
    async fn recv_framed_file(
        channel: &mut dyn sh_transport::Channel,
        expect_transfer_id: u64,
    ) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        loop {
            let msg = channel
                .recv()
                .await
                .unwrap()
                .expect("file stream closed before LAST chunk");
            assert!(
                msg.len() >= FILE_CHUNK_HEADER_LEN,
                "chunk shorter than header"
            );
            let header = FileChunkHeader::decode(&msg[..FILE_CHUNK_HEADER_LEN]).unwrap();
            let payload = &msg[FILE_CHUNK_HEADER_LEN..];
            assert_eq!(header.transfer_id, expect_transfer_id, "wrong transfer id");
            assert_eq!(header.len as usize, payload.len(), "len/payload mismatch");
            assert_eq!(
                header.offset as usize,
                out.len(),
                "out-of-order / gapped chunk offset"
            );
            out.extend_from_slice(payload);
            if header.last {
                break;
            }
        }
        out
    }

    /// A real multi-chunk file streams over its own QUIC file stream and reassembles byte-identically.
    #[tokio::test(flavor = "multi_thread")]
    async fn file_streams_over_quic_file_channel_byte_identical() {
        const FILE_LEN: usize = 1024 * 1024 + 12_345; // ~1 MiB, deliberately not chunk-aligned
        const CHUNK: usize = 64 * 1024;
        const TRANSFER_ID: u64 = 0xF11E_0001;

        let (server, client) = transport_pair().await;
        let source = make_file(FILE_LEN);

        // Open the file channel: client opens, server accepts (one QUIC stream per transfer).
        let (server_ch, client_ch) = tokio::join!(
            server.accept_channel(),
            client.open_channel(ChannelSpec::file()),
        );
        let mut server_ch = server_ch.unwrap();
        let mut client_ch = client_ch.unwrap();

        // The accepted channel must be the File channel (channel-open header round-trips).
        assert_eq!(server_ch.spec().channel, sh_types::ChannelId::File);

        let send = {
            let src = source.clone();
            tokio::spawn(async move {
                send_framed_file(client_ch.as_mut(), TRANSFER_ID, &src, CHUNK).await;
                // Drop client_ch → clean EOF after LAST (receiver already breaks on LAST).
            })
        };
        let recv =
            tokio::spawn(async move { recv_framed_file(server_ch.as_mut(), TRANSFER_ID).await });

        send.await.unwrap();
        let received = tokio::time::timeout(std::time::Duration::from_secs(30), recv)
            .await
            .expect("file reassembly timed out")
            .unwrap();

        assert_eq!(received.len(), source.len(), "reassembled length mismatch");
        assert!(
            received == source,
            "reassembled file bytes differ from source"
        );
    }
}
