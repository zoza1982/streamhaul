//! QUIC server and client endpoint wrappers for `sh-transport`.

use std::net::SocketAddr;

use crate::{connection::Connection, error::TransportError};

/// A QUIC server endpoint that listens for incoming connections.
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
pub struct ClientEndpoint {
    inner: quinn::Endpoint,
}

impl ClientEndpoint {
    /// Bind an ephemeral local UDP socket and create a QUIC client endpoint
    /// using the given `config` as the default client configuration.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Bind`] if the underlying UDP socket cannot be
    /// bound to an ephemeral port.
    pub fn bind(config: quinn::ClientConfig) -> Result<Self, TransportError> {
        let addr: SocketAddr = "0.0.0.0:0".parse().map_err(|e: std::net::AddrParseError| {
            TransportError::Bind(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;
        let mut inner = quinn::Endpoint::client(addr).map_err(TransportError::Bind)?;
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
