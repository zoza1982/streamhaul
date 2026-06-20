//! QUIC server and client endpoint wrappers for `sh-transport`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::{connection::Connection, error::TransportError};

/// Ephemeral IPv4 bind address (`0.0.0.0:0`) — the OS picks the port.
const EPHEMERAL_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// A QUIC server endpoint that listens for incoming connections.
#[derive(Debug)]
pub struct ServerEndpoint {
    inner: quinn::Endpoint,
}

impl ServerEndpoint {
    /// Bind a new QUIC server endpoint to `addr` using the given `config`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Bind`] if the underlying UDP socket cannot be
    /// bound to `addr`.
    pub fn bind(addr: SocketAddr, config: quinn::ServerConfig) -> Result<Self, TransportError> {
        let inner = quinn::Endpoint::server(config, addr).map_err(TransportError::Bind)?;
        Ok(Self { inner })
    }

    /// Returns the local address the endpoint is bound to.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Bind`] if the underlying socket returns an I/O
    /// error when queried for its local address.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.inner.local_addr().map_err(TransportError::Bind)
    }

    /// Accept the next incoming QUIC connection.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::EndpointClosed`] if the endpoint is closed
    /// before any connection arrives, or [`TransportError::Connection`] if the
    /// QUIC handshake fails.
    pub async fn accept(&self) -> Result<Connection, TransportError> {
        let incoming = self
            .inner
            .accept()
            .await
            .ok_or(TransportError::EndpointClosed)?;
        let conn = incoming
            .accept()
            .map_err(TransportError::Connection)?
            .await
            .map_err(TransportError::Connection)?;
        Ok(Connection::new(conn))
    }
}

/// A QUIC client endpoint for connecting to servers.
#[derive(Debug)]
pub struct ClientEndpoint {
    inner: quinn::Endpoint,
}

impl ClientEndpoint {
    /// Bind an ephemeral local UDP socket and create a QUIC client endpoint.
    ///
    /// `config` is installed as the default client configuration for all subsequent
    /// [`connect`](Self::connect) calls.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Bind`] if the underlying UDP socket cannot be
    /// bound to an ephemeral port.
    pub fn bind(config: quinn::ClientConfig) -> Result<Self, TransportError> {
        let mut inner = quinn::Endpoint::client(EPHEMERAL_V4).map_err(TransportError::Bind)?;
        inner.set_default_client_config(config);
        Ok(Self { inner })
    }

    /// Connect to a QUIC server at `addr` with the given `server_name`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Connect`] if the connection parameters are
    /// invalid, or [`TransportError::Connection`] if the QUIC handshake fails.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Connection, TransportError> {
        let connecting = self
            .inner
            .connect(addr, server_name)
            .map_err(TransportError::Connect)?;
        let conn = connecting.await.map_err(TransportError::Connection)?;
        Ok(Connection::new(conn))
    }
}
