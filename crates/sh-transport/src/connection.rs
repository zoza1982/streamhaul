//! QUIC connection wrapper for `sh-transport`.

use std::net::SocketAddr;

use bytes::Bytes;

use crate::error::TransportError;

/// A wrapper around a `quinn::Connection` that exposes datagram send/receive.
pub struct Connection {
    inner: quinn::Connection,
}

impl Connection {
    /// Creates a new [`Connection`] from a raw `quinn::Connection`.
    pub(crate) fn new(inner: quinn::Connection) -> Self {
        Self { inner }
    }

    /// Send a datagram to the remote peer.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::SendDatagram`] if the datagram could not be sent,
    /// or [`TransportError::DatagramsNotSupported`] if the remote peer does not
    /// support datagrams.
    pub fn send_datagram(&self, data: Bytes) -> Result<(), TransportError> {
        self.inner
            .send_datagram(data)
            .map_err(TransportError::SendDatagram)
    }

    /// Receive the next datagram from the remote peer.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Connection`] if the connection is lost before
    /// a datagram arrives.
    pub async fn read_datagram(&self) -> Result<Bytes, TransportError> {
        self.inner
            .read_datagram()
            .await
            .map_err(TransportError::Connection)
    }

    /// Returns the maximum datagram payload size the connection supports, or `None`
    /// if the remote peer does not support datagrams.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }

    /// Returns the remote address of this connection.
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }
}
