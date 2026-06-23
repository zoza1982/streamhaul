//! Network seam for the ICE agent — [`UdpTransport`] trait and in-process NAT simulator.
//!
//! The [`UdpTransport`] trait is a thin abstraction over a UDP socket so that the
//! [`IceAgent`](crate::agent::IceAgent) can be tested without real networking.
//!
//! The [`NatSimNetwork`] provides an in-process "network fabric" that hosts multiple
//! [`SimSocket`]s, each optionally behind a simulated NAT.  Messages delivered
//! through the fabric are subject to the NAT translation rules of both the sender
//! and receiver.
//!
//! # NAT simulation model
//!
//! | Type | Mapping | Filtering |
//! |------|---------|-----------|
//! | [`NatType::FullCone`] | One external address per internal socket | Any external host may send |
//! | [`NatType::RestrictedCone`] | One external address per internal socket | Only hosts the internal has sent to |
//! | [`NatType::PortRestricted`] | One external address per internal socket | Only (host, port) pairs the internal has sent to |
//! | [`NatType::Symmetric`] | New external port per new destination | Same as PortRestricted |

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::error::IceError;

// ─── UdpTransport trait ───────────────────────────────────────────────────────

/// Abstraction over a UDP socket, used by [`IceAgent`](crate::agent::IceAgent) so
/// that tests can substitute an in-process simulator instead of real sockets.
pub trait UdpTransport: Send + Sync + 'static {
    /// Send `data` to `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::Transport`] if the underlying send fails.
    fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<(), IceError>;

    /// Receive one datagram, writing it into `buf`.
    ///
    /// Returns `(bytes_written, source_addr)`.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::Transport`] if the underlying receive fails (including
    /// a non-blocking "would block" condition).
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), IceError>;

    /// Return the local address of this socket.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::Transport`] if the address cannot be determined.
    fn local_addr(&self) -> Result<SocketAddr, IceError>;
}

// ─── NAT simulator ────────────────────────────────────────────────────────────

/// The four NAT types modelled by the simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatType {
    /// Any external host can reach the internal address after any outbound packet.
    FullCone,
    /// Only hosts that the internal has sent to can reach it (any port from that host).
    RestrictedCone,
    /// Only the exact (host, port) that the internal has sent to can reach it.
    PortRestricted,
    /// Each new destination gets a new external port mapping.
    Symmetric,
}

/// A pending datagram in the simulator's per-socket inbox.
#[derive(Debug)]
struct Pending {
    data: Vec<u8>,
    from: SocketAddr,
}

/// Per-socket NAT state shared within the network fabric.
struct SocketState {
    /// NAT type applied to outbound packets from this socket.
    nat_type: NatType,
    /// The external address assigned by the NAT for FullCone/RestrictedCone/PortRestricted.
    /// For Symmetric, this is the base external address; individual dest mappings are in
    /// `sym_mappings`.
    external_addr: SocketAddr,
    /// Symmetric-only: mapping from destination → external address for that dest.
    sym_mappings: HashMap<SocketAddr, SocketAddr>,
    /// Set of destinations this socket has sent to (for filter enforcement).
    sent_to: HashSet<SocketAddr>,
    /// Pending inbound datagrams.
    inbox: VecDeque<Pending>,
}

/// Shared network state.
struct NetworkInner {
    /// All sockets registered in this network, keyed by their internal address.
    sockets: HashMap<SocketAddr, SocketState>,
    /// Counter for allocating unique external ports.
    next_ext_port: u16,
    /// The external IP to use for all NAT translations.
    external_ip: std::net::IpAddr,
}

impl NetworkInner {
    fn alloc_ext_port(&mut self) -> u16 {
        let p = self.next_ext_port;
        self.next_ext_port = self.next_ext_port.wrapping_add(1).max(1024);
        p
    }

    /// Determine the external address that `internal` uses when sending to `dest`.
    fn external_for(&mut self, internal: SocketAddr, dest: SocketAddr) -> Option<SocketAddr> {
        // Read nat_type and existing mappings without holding a mutable reference,
        // then re-borrow mutably if we need to insert a new Symmetric mapping.
        let nat_type = self.sockets.get(&internal)?.nat_type;
        match nat_type {
            NatType::FullCone | NatType::RestrictedCone | NatType::PortRestricted => {
                Some(self.sockets.get(&internal)?.external_addr)
            }
            NatType::Symmetric => {
                // Check if we already have a mapping for this destination.
                if let Some(&mapped) = self.sockets.get(&internal)?.sym_mappings.get(&dest) {
                    return Some(mapped);
                }
                // Allocate a new external port and record the mapping.
                let ext_port = self.next_ext_port;
                self.next_ext_port = self.next_ext_port.wrapping_add(1).max(1024);
                let ext = SocketAddr::new(self.external_ip, ext_port);
                if let Some(state) = self.sockets.get_mut(&internal) {
                    state.sym_mappings.insert(dest, ext);
                }
                Some(ext)
            }
        }
    }

    /// Check whether `src_external` may deliver a packet to `dest_internal`.
    fn can_deliver(&self, src_external: SocketAddr, dest_internal: SocketAddr) -> bool {
        let state = match self.sockets.get(&dest_internal) {
            Some(s) => s,
            None => return false,
        };
        match state.nat_type {
            NatType::FullCone => true,
            NatType::RestrictedCone => state.sent_to.iter().any(|d| d.ip() == src_external.ip()),
            NatType::PortRestricted | NatType::Symmetric => state.sent_to.contains(&src_external),
        }
    }

    /// Deliver a datagram from `src_internal` to `dest_addr`.
    ///
    /// `dest_addr` is the address the sender is targeting — it may be an internal or
    /// external address.  The function resolves the target to an internal socket,
    /// applies NAT filtering, and pushes into the inbox.
    fn deliver(&mut self, src_internal: SocketAddr, dest_addr: SocketAddr, data: Vec<u8>) {
        // Record this send in the sender's sent_to set.
        if let Some(state) = self.sockets.get_mut(&src_internal) {
            state.sent_to.insert(dest_addr);
        }

        // Compute the external source address.
        let src_external = match self.external_for(src_internal, dest_addr) {
            Some(a) => a,
            None => return,
        };

        // Find the destination socket by matching dest_addr against internal or external addrs.
        let dest_internal = self.sockets.iter().find_map(|(int_addr, state)| {
            if *int_addr == dest_addr
                || state.external_addr == dest_addr
                || state.sym_mappings.values().any(|e| *e == dest_addr)
            {
                Some(*int_addr)
            } else {
                None
            }
        });

        let dest_internal = match dest_internal {
            Some(d) => d,
            None => return, // no such socket
        };

        if dest_internal == src_internal {
            // Loopback: deliver directly without NAT filtering.
            if let Some(state) = self.sockets.get_mut(&dest_internal) {
                state.inbox.push_back(Pending {
                    data,
                    from: src_external,
                });
            }
            return;
        }

        if !self.can_deliver(src_external, dest_internal) {
            tracing::trace!(
                %src_external,
                %dest_internal,
                "NAT blocked packet"
            );
            return;
        }

        if let Some(state) = self.sockets.get_mut(&dest_internal) {
            state.inbox.push_back(Pending {
                data,
                from: src_external,
            });
        }
    }
}

/// An in-process network fabric that hosts multiple [`SimSocket`]s.
///
/// Create sockets with [`NatSimNetwork::create_socket`], hand them to
/// [`IceAgent`](crate::agent::IceAgent)s, then call [`IceAgent::step`] in a loop
/// to drive the connectivity check state machine without real OS networking.
#[derive(Clone)]
pub struct NatSimNetwork {
    inner: Arc<Mutex<NetworkInner>>,
}

impl NatSimNetwork {
    /// Create a new network fabric.
    ///
    /// `external_ip` is the IP address used for all NAT-translated (external) addresses.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::IpAddr;
    /// use sh_ice::transport::{NatSimNetwork, NatType};
    ///
    /// let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
    /// ```
    #[must_use]
    pub fn new(external_ip: std::net::IpAddr) -> Self {
        Self {
            inner: Arc::new(Mutex::new(NetworkInner {
                sockets: HashMap::new(),
                next_ext_port: 20000,
                external_ip,
            })),
        }
    }

    /// Register a new simulated socket with the given `internal_addr` and `nat_type`.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::Transport`] if the mutex is poisoned.
    pub fn create_socket(
        &self,
        nat_type: NatType,
        internal_addr: SocketAddr,
    ) -> Result<SimSocket, IceError> {
        let mut inner = self.lock()?;
        let ext_port = inner.alloc_ext_port();
        let external_addr = SocketAddr::new(inner.external_ip, ext_port);
        inner.sockets.insert(
            internal_addr,
            SocketState {
                nat_type,
                external_addr,
                sym_mappings: HashMap::new(),
                sent_to: HashSet::new(),
                inbox: VecDeque::new(),
            },
        );
        drop(inner);
        Ok(SimSocket {
            internal_addr,
            network: self.inner.clone(),
        })
    }

    /// Return the external (NAT-translated) address for a given internal address, if any.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::Transport`] if the mutex is poisoned.
    pub fn external_addr_for(
        &self,
        internal_addr: SocketAddr,
    ) -> Result<Option<SocketAddr>, IceError> {
        let inner = self.lock()?;
        Ok(inner.sockets.get(&internal_addr).map(|s| s.external_addr))
    }

    fn lock(&self) -> Result<MutexGuard<'_, NetworkInner>, IceError> {
        self.inner
            .lock()
            .map_err(|e| IceError::Transport(format!("NAT sim mutex poisoned: {e}")))
    }
}

/// A simulated UDP socket that participates in the [`NatSimNetwork`].
pub struct SimSocket {
    internal_addr: SocketAddr,
    network: Arc<Mutex<NetworkInner>>,
}

impl SimSocket {
    /// Return the external (NAT-translated) address of this socket.
    ///
    /// For [`NatType::Symmetric`] sockets this is the base external address; the per-dest
    /// mapping is determined when the first packet is sent to a given destination.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::Transport`] if the mutex is poisoned or the socket is not found.
    pub fn external_addr(&self) -> Result<SocketAddr, IceError> {
        let inner = self
            .network
            .lock()
            .map_err(|e| IceError::Transport(format!("NAT sim mutex poisoned: {e}")))?;
        inner
            .sockets
            .get(&self.internal_addr)
            .map(|s| s.external_addr)
            .ok_or_else(|| IceError::Transport("socket not found in network".into()))
    }
}

impl UdpTransport for SimSocket {
    fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<(), IceError> {
        let mut inner = self
            .network
            .lock()
            .map_err(|e| IceError::Transport(format!("NAT sim mutex poisoned: {e}")))?;
        inner.deliver(self.internal_addr, addr, data.to_vec());
        Ok(())
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), IceError> {
        let mut inner = self
            .network
            .lock()
            .map_err(|e| IceError::Transport(format!("NAT sim mutex poisoned: {e}")))?;
        let state = inner
            .sockets
            .get_mut(&self.internal_addr)
            .ok_or_else(|| IceError::Transport("socket not found in network".into()))?;
        match state.inbox.pop_front() {
            Some(pending) => {
                let len = pending.data.len().min(buf.len());
                buf.get_mut(..len)
                    .ok_or_else(|| IceError::Transport("buffer too small".into()))?
                    .copy_from_slice(
                        pending
                            .data
                            .get(..len)
                            .ok_or_else(|| IceError::Transport("data truncation error".into()))?,
                    );
                Ok((len, pending.from))
            }
            None => Err(IceError::Transport("no data available".into())),
        }
    }

    fn local_addr(&self) -> Result<SocketAddr, IceError> {
        Ok(self.internal_addr)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::expect_used,
        clippy::panic
    )]

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn full_cone_delivers() {
        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let sock_a = net.create_socket(NatType::FullCone, addr(10001)).unwrap();
        let sock_b = net.create_socket(NatType::FullCone, addr(10002)).unwrap();

        let ext_b = sock_b.external_addr().unwrap();
        sock_a.send_to(b"hello", ext_b).unwrap();

        let mut buf = [0u8; 64];
        let (n, _from) = sock_b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[test]
    fn port_restricted_blocks_unreachable() {
        // PortRestricted NAT: a socket can receive from (host, port) only if it has
        // previously sent to that exact (host, port).  Delivery is synchronous, so the
        // first packet in each direction is blocked until the far side has also sent.
        // This test verifies the filter by:
        //   1. Both A and B send to each other's external addrs (populating sent_to).
        //   2. A second send from A to B now reaches B (hole is open in both directions).
        //   3. C never sends to A → C's packets to A are blocked.
        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let sock_a = net
            .create_socket(NatType::PortRestricted, addr(10003))
            .unwrap();
        let sock_b = net
            .create_socket(NatType::PortRestricted, addr(10004))
            .unwrap();
        let sock_c = net
            .create_socket(NatType::PortRestricted, addr(10005))
            .unwrap();

        let ext_a = sock_a.external_addr().unwrap();
        let ext_b = sock_b.external_addr().unwrap();

        // Mutual probe: both send to each other's external addr.
        // Neither arrives yet because neither has recorded the other in sent_to first.
        sock_a.send_to(b"probe-a", ext_b).unwrap(); // adds ext_b to sock_a.sent_to; B blocks it
        sock_b.send_to(b"probe-b", ext_a).unwrap(); // adds ext_a to sock_b.sent_to; A allows it (A sent to B)

        // After the mutual probe, sock_b's hole is now open for sock_a.
        // sock_a sends again → sock_b allows it (sent_to now contains ext_a).
        sock_a.send_to(b"hello", ext_b).unwrap();

        // sock_c never sent to sock_a → sock_a's filter blocks sock_c.
        sock_c.send_to(b"intruder", ext_a).unwrap();

        let mut buf = [0u8; 64];

        // sock_a should have received probe-b (B sent to ext_a after A had already sent to ext_b).
        let (n, _) = sock_a.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"probe-b");
        // sock_a should NOT receive the intruder (C never appeared in sock_a.sent_to).
        assert!(sock_a.recv_from(&mut buf).is_err());

        // sock_b should have received hello (second send from A, after B's sent_to was updated).
        let (n2, _) = sock_b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n2], b"hello");
    }
}
