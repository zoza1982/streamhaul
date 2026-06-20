//! QUIC connection wrapper for `sh-transport`.

use std::net::SocketAddr;

use bytes::Bytes;

use crate::error::TransportError;

/// A wrapper around a `quinn::Connection` that exposes datagram send/receive.
#[derive(Debug)]
pub struct Connection {
    inner: quinn::Connection,
}

impl Connection {
    /// Creates a new [`Connection`] from a raw `quinn::Connection`.
    ///
    /// Intentionally `pub(crate)`: callers obtain connections exclusively through
    /// [`ServerEndpoint::accept`](crate::ServerEndpoint::accept) or
    /// [`ClientEndpoint::connect`](crate::ClientEndpoint::connect).
    pub(crate) fn new(inner: quinn::Connection) -> Self {
        Self { inner }
    }

    /// Send a datagram to the remote peer.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::DatagramsNotSupported`] if the remote peer disabled datagram
    /// support, or [`TransportError::SendDatagram`] for any other send failure (e.g. the datagram
    /// exceeds [`max_datagram_size`](Self::max_datagram_size), or the connection is closing).
    pub fn send_datagram(&self, data: Bytes) -> Result<(), TransportError> {
        self.inner.send_datagram(data).map_err(|e| match e {
            quinn::SendDatagramError::UnsupportedByPeer => TransportError::DatagramsNotSupported,
            other => TransportError::SendDatagram(other),
        })
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
