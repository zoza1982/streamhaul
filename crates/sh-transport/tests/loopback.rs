//! Integration tests for `sh-transport` — loopback datagram roundtrip.
//!
//! These tests require the `insecure-lan` feature and are gated accordingly.
#![cfg(feature = "insecure-lan")]

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]
mod tests {
    use bytes::Bytes;
    use sh_transport::{
        insecure_client_config, self_signed_server_config, ClientEndpoint, ServerEndpoint,
    };
    use std::net::SocketAddr;

    #[tokio::test]
    async fn loopback_datagram_roundtrip() {
        // Start server on an ephemeral port.
        let server_cfg = self_signed_server_config().unwrap();
        let server =
            ServerEndpoint::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), server_cfg).unwrap();
        let server_addr = server.local_addr().unwrap();

        // Concurrently: connect client and accept server.
        let client_cfg = insecure_client_config().unwrap();
        let client_ep = ClientEndpoint::bind(client_cfg).unwrap();

        let (server_conn, client_conn) =
            tokio::join!(server.accept(), client_ep.connect(server_addr, "localhost"),);
        let server_conn = server_conn.unwrap();
        let client_conn = client_conn.unwrap();

        // Send client -> server.
        let payload_c2s = Bytes::from_static(b"hello from client");
        client_conn.send_datagram(payload_c2s.clone()).unwrap();

        // Send server -> client.
        let payload_s2c = Bytes::from_static(b"hello from server");
        server_conn.send_datagram(payload_s2c.clone()).unwrap();

        // Await both receives.
        let received_by_server = server_conn.read_datagram().await.unwrap();
        let received_by_client = client_conn.read_datagram().await.unwrap();

        assert_eq!(received_by_server, payload_c2s);
        assert_eq!(received_by_client, payload_s2c);
    }

    #[tokio::test]
    async fn max_datagram_size_is_some_after_connect() {
        let server_cfg = self_signed_server_config().unwrap();
        let server =
            ServerEndpoint::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), server_cfg).unwrap();
        let server_addr = server.local_addr().unwrap();

        let client_cfg = insecure_client_config().unwrap();
        let client_ep = ClientEndpoint::bind(client_cfg).unwrap();

        let (_, client_conn) =
            tokio::join!(server.accept(), client_ep.connect(server_addr, "localhost"),);
        let client_conn = client_conn.unwrap();

        assert!(client_conn.max_datagram_size().is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_to_dead_address_errors() {
        // Bind a UDP socket, capture its address, then drop it so the port is
        // no longer listening. Any QUIC connect attempt to that address should
        // fail or time out.
        use std::net::UdpSocket;
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = sock.local_addr().unwrap();
        drop(sock);

        let client_cfg = insecure_client_config().unwrap();
        let client_ep = ClientEndpoint::bind(client_cfg).unwrap();

        // Either a TransportError or a timeout — we must NOT successfully connect.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client_ep.connect(dead_addr, "localhost"),
        )
        .await;

        match result {
            Ok(Err(_)) => {} // Got a TransportError — expected.
            Err(_) => {}     // Timed out — also acceptable.
            Ok(Ok(_)) => panic!("should not have connected to a dead address"),
        }
    }
}
