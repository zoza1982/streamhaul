//! Integration tests for `sh-transport` — loopback datagram roundtrip and error paths.
//!
//! These tests require the `insecure-lan` feature and are gated accordingly. They also account for
//! the bulk of `sh-transport`'s coverage, so the coverage gate must run with `--features insecure-lan`.
#![cfg(feature = "insecure-lan")]

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    missing_docs
)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use sh_transport::{
        insecure_client_config, self_signed_server_config, ClientEndpoint, InsecureLanLab,
        ServerEndpoint, TransportError,
    };

    fn ack() -> InsecureLanLab {
        InsecureLanLab::i_understand_this_skips_tls_verification()
    }

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// Bind a server, connect a client, and return both established connections.
    async fn connected_pair(
        server: &ServerEndpoint,
        client: &ClientEndpoint,
        addr: SocketAddr,
    ) -> (sh_transport::Connection, sh_transport::Connection) {
        let (server_conn, client_conn) =
            tokio::join!(server.accept(), client.connect(addr, "localhost"));
        (server_conn.unwrap(), client_conn.unwrap())
    }

    /// Read one datagram with a timeout so a (rare) dropped datagram fails fast instead of hanging.
    async fn read_one(conn: &sh_transport::Connection) -> Bytes {
        tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
            .await
            .expect("datagram not received within timeout")
            .expect("read_datagram failed")
    }

    #[tokio::test]
    async fn loopback_datagram_roundtrip() {
        let server =
            ServerEndpoint::bind(loopback(), self_signed_server_config(ack()).unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let client = ClientEndpoint::bind(insecure_client_config(ack()).unwrap()).unwrap();

        let (server_conn, client_conn) = connected_pair(&server, &client, addr).await;

        let c2s = Bytes::from_static(b"hello from client");
        let s2c = Bytes::from_static(b"hello from server");
        client_conn.send_datagram(c2s.clone()).unwrap();
        server_conn.send_datagram(s2c.clone()).unwrap();

        assert_eq!(read_one(&server_conn).await, c2s);
        assert_eq!(read_one(&client_conn).await, s2c);
    }

    #[tokio::test]
    async fn max_datagram_size_is_some_after_connect() {
        let server =
            ServerEndpoint::bind(loopback(), self_signed_server_config(ack()).unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let client = ClientEndpoint::bind(insecure_client_config(ack()).unwrap()).unwrap();

        let (_server_conn, client_conn) = connected_pair(&server, &client, addr).await;
        assert!(client_conn.max_datagram_size().is_some());
    }

    #[tokio::test]
    async fn oversized_datagram_is_rejected() {
        let server =
            ServerEndpoint::bind(loopback(), self_signed_server_config(ack()).unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let client = ClientEndpoint::bind(insecure_client_config(ack()).unwrap()).unwrap();

        let (_server_conn, client_conn) = connected_pair(&server, &client, addr).await;
        let max = client_conn.max_datagram_size().unwrap();
        let too_big = Bytes::from(vec![0u8; max + 1]);
        assert!(matches!(
            client_conn.send_datagram(too_big),
            Err(TransportError::SendDatagram(_))
        ));
    }

    #[tokio::test]
    async fn send_datagram_errors_when_peer_disables_datagrams() {
        // Server disables datagram receive support; the client must then see UnsupportedByPeer,
        // surfaced as the distinct DatagramsNotSupported variant.
        let mut server_cfg = self_signed_server_config(ack()).unwrap();
        let mut tc = quinn::TransportConfig::default();
        tc.datagram_receive_buffer_size(None);
        server_cfg.transport_config(Arc::new(tc));

        let server = ServerEndpoint::bind(loopback(), server_cfg).unwrap();
        let addr = server.local_addr().unwrap();
        let client = ClientEndpoint::bind(insecure_client_config(ack()).unwrap()).unwrap();

        let (_server_conn, client_conn) = connected_pair(&server, &client, addr).await;
        assert_eq!(client_conn.max_datagram_size(), None);
        assert!(matches!(
            client_conn.send_datagram(Bytes::from_static(b"x")),
            Err(TransportError::DatagramsNotSupported)
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_to_dead_address_errors() {
        // Bind then drop a UDP socket so its port has no listener.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = sock.local_addr().unwrap();
        drop(sock);

        // A short idle timeout makes the connect resolve with a real `Connection` error instead of
        // hanging until quinn's ~30s default idle timeout. To a black-holed port quinn still spends
        // ~3s on Initial-packet retransmissions before giving up — so this asserts the real error
        // path (not just a wall-clock timeout), at the cost of being the suite's one slow test.
        let mut client_cfg = insecure_client_config(ack()).unwrap();
        let mut tc = quinn::TransportConfig::default();
        tc.max_idle_timeout(Some(Duration::from_millis(700).try_into().unwrap()));
        client_cfg.transport_config(Arc::new(tc));
        let client = ClientEndpoint::bind(client_cfg).unwrap();

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            client.connect(dead_addr, "localhost"),
        )
        .await
        .expect("connect did not resolve within the safety timeout");

        assert!(
            matches!(result, Err(TransportError::Connection(_))),
            "expected a connection error to a dead address, got {result:?}"
        );
    }
}
