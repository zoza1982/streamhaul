//! Async tokio drive loop for [`PinnedWebRtcTransport`].
//!
//! This module provides:
//!
//! - [`AsyncUdpSocket`] — an injectable async socket seam (production + test implementations).
//! - [`TokioUdpSocket`] — production wrapper around [`tokio::net::UdpSocket`].
//! - [`SimUdpSocket`] / [`SimNetwork`] — deterministic in-memory socket for tests with
//!   [`tokio::time::pause()`].
//! - [`spawn_webrtc_driver`] — spawns the tokio task that owns the drive loop for a
//!   [`PinnedWebRtcTransport`], returning a [`DriverHandle`] that can be used to shut it down.
//!
//! # Drive loop design
//!
//! The driver converts between [`std::time::Instant`] (required by `str0m`) and
//! [`tokio::time::Instant`] (required by `tokio::time::sleep_until`) using a pair of base
//! values captured at driver spawn time. Under `tokio::time::pause()` (used in deterministic
//! tests), `tokio::time::Instant::now()` tracks paused time, so the derived `std::time::Instant`
//! values advance only when `tokio::time::advance()` is called — giving perfectly deterministic
//! str0m clock inputs with no wall-clock dependency.
//!
//! # Safety note: no `std::sync::Mutex` held across `.await`
//!
//! [`PinnedWebRtcTransport::drive`] and [`PinnedWebRtcTransport::handle_receive`] each acquire and
//! release the inner `std::sync::Mutex<WebRtcInner>` synchronously. The driver never holds that
//! lock across an `.await` point — the send/recv operations on the socket happen after the mutex
//! has been released.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::error::TransportError;
use crate::webrtc::PinnedWebRtcTransport;

// ── AsyncUdpSocket trait ───────────────────────────────────────────────────────

/// An async UDP socket seam for the [`WebRtcDriver`] drive loop.
///
/// The production implementation is [`TokioUdpSocket`]; the deterministic test implementation
/// is [`SimUdpSocket`]. Implementors must be `Send + Sync + 'static` so they can be shared
/// across tokio tasks behind `Arc`.
///
/// # Design
///
/// This trait exists to decouple the driver from `tokio::net::UdpSocket` so tests can use
/// an in-memory [`SimNetwork`] rather than real OS sockets. The seam also prevents the driver
/// from accidentally using the blocking `std::net::UdpSocket` (which would stall a tokio
/// worker thread).
#[async_trait]
pub trait AsyncUdpSocket: Send + Sync + 'static {
    /// The local socket address this socket is bound to.
    fn local_addr(&self) -> SocketAddr;

    /// Send `data` to `dst`.
    ///
    /// Errors are logged by the driver but do not terminate the drive loop — a single failed
    /// send is not fatal (the remote will retransmit or the connection will time out naturally).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the underlying send operation fails.
    async fn send_to(&self, data: &[u8], dst: SocketAddr) -> Result<(), TransportError>;

    /// Receive one datagram into `buf`. Returns `(bytes_written, source_addr)`.
    ///
    /// If the datagram is larger than `buf`, the excess bytes are silently discarded —
    /// this matches platform UDP semantics (the kernel truncates, not the library).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the underlying receive operation fails. A receive
    /// error terminates the drive loop.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), TransportError>;
}

// ── TokioUdpSocket ─────────────────────────────────────────────────────────────

/// Production [`AsyncUdpSocket`] backed by [`tokio::net::UdpSocket`].
///
/// Bind with [`TokioUdpSocket::bind`]; the socket is immediately ready for use.
pub struct TokioUdpSocket(tokio::net::UdpSocket);

impl TokioUdpSocket {
    /// Bind to `addr` and return a ready-to-use `TokioUdpSocket`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Bind`] if the underlying `tokio::net::UdpSocket::bind` fails.
    pub async fn bind(addr: SocketAddr) -> Result<Self, TransportError> {
        let sock = tokio::net::UdpSocket::bind(addr).await?;
        Ok(Self(sock))
    }
}

#[async_trait]
impl AsyncUdpSocket for TokioUdpSocket {
    fn local_addr(&self) -> SocketAddr {
        // SAFETY: The socket was successfully bound in `TokioUdpSocket::bind`; a bound socket
        //         always has a valid local address. `local_addr()` on a bound socket cannot fail.
        #[allow(clippy::expect_used)]
        self.0
            .local_addr()
            .expect("TokioUdpSocket: socket is bound and always has a local_addr")
    }

    async fn send_to(&self, data: &[u8], dst: SocketAddr) -> Result<(), TransportError> {
        self.0
            .send_to(data, dst)
            .await
            .map(|_| ())
            .map_err(|e| TransportError::Webrtc(e.to_string()))
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), TransportError> {
        self.0
            .recv_from(buf)
            .await
            .map_err(|e| TransportError::Webrtc(e.to_string()))
    }
}

// ── SimNetwork / SimUdpSocket ──────────────────────────────────────────────────

/// Inner routing table for [`SimNetwork`].
struct SimNetworkInner {
    /// Maps each bound address to the sender side of that socket's inbox channel.
    sockets: HashMap<SocketAddr, mpsc::Sender<(Vec<u8>, SocketAddr)>>,
}

/// An in-memory simulated UDP network for deterministic tests.
///
/// Create sockets with [`SimNetwork::add_socket`]. Datagrams sent from one socket to another
/// are delivered via in-memory [`tokio::sync::mpsc`] channels — no OS sockets or real I/O is
/// involved. Works correctly under [`tokio::time::pause()`] because mpsc delivery does not
/// depend on the tokio timer.
///
/// # Example
///
/// ```rust,no_run
/// # #[tokio::main]
/// # async fn main() {
/// use std::net::SocketAddr;
/// use std::sync::Arc;
/// use sh_transport::driver::{SimNetwork, AsyncUdpSocket};
///
/// let a_addr: SocketAddr = "10.0.0.1:4000".parse().unwrap();
/// let b_addr: SocketAddr = "10.0.0.2:4001".parse().unwrap();
///
/// let mut net = SimNetwork::new();
/// let sock_a = Arc::new(net.add_socket(a_addr));
/// let sock_b = Arc::new(net.add_socket(b_addr));
///
/// sock_a.send_to(b"hello", b_addr).await.unwrap();
/// let mut buf = vec![0u8; 1500];
/// let (n, from) = sock_b.recv_from(&mut buf).await.unwrap();
/// assert_eq!(&buf[..n], b"hello");
/// assert_eq!(from, a_addr);
/// # }
/// ```
pub struct SimNetwork {
    inner: Arc<tokio::sync::Mutex<SimNetworkInner>>,
}

impl SimNetwork {
    /// Create a new empty simulated network.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(SimNetworkInner {
                sockets: HashMap::new(),
            })),
        }
    }

    /// Create a [`SimUdpSocket`] bound to `local_addr` in this network.
    ///
    /// Datagrams sent to `local_addr` from any other socket in the same `SimNetwork` will be
    /// delivered to the returned socket's [`AsyncUdpSocket::recv_from`].
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is contended when `add_socket` is called. In practice this
    /// is unreachable: `&mut self` guarantees exclusive access to `SimNetwork`, so no concurrent
    /// task can hold the lock. The `try_lock().expect(...)` is a belt-and-suspenders guard
    /// against hypothetical future refactors that break the exclusivity invariant.
    ///
    /// Callers must also ensure `local_addr` is not reused within the same network; a duplicate
    /// registration will silently replace the previous inbox (the old socket will never receive
    /// datagrams thereafter).
    pub fn add_socket(&mut self, local_addr: SocketAddr) -> SimUdpSocket {
        // Channel capacity of 1024 is generous for test traffic; in-memory so no real cost.
        let (tx, rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
        // Use a non-blocking `try_lock` on the tokio Mutex rather than `.lock().await`, since
        // `add_socket` is a synchronous `&mut self` constructor: no task can hold the lock, so
        // `try_lock` always succeeds and we avoid making construction async.
        //
        // SAFETY: During `add_socket`, no concurrent task holds the inner mutex because
        //         `SimNetwork::add_socket` takes `&mut self` — only one caller at a time.
        //         `try_lock().expect(...)` is safe here.
        #[allow(clippy::expect_used)]
        self.inner
            .try_lock()
            .expect("SimNetwork: inner mutex must be available during add_socket (no concurrent access while &mut self is held)")
            .sockets
            .insert(local_addr, tx);

        SimUdpSocket {
            local_addr,
            rx: tokio::sync::Mutex::new(rx),
            network: Arc::clone(&self.inner),
        }
    }
}

impl Default for SimNetwork {
    fn default() -> Self {
        Self::new()
    }
}

/// A simulated UDP socket backed by in-memory [`tokio::sync::mpsc`] channels.
///
/// Created by [`SimNetwork::add_socket`]. Implements [`AsyncUdpSocket`] for use with
/// [`spawn_webrtc_driver`] in deterministic tests.
pub struct SimUdpSocket {
    /// The address this socket is "bound to" in the simulated network.
    local_addr: SocketAddr,
    /// Inbox: receives `(data, source_addr)` from peers that `send_to(local_addr)`.
    ///
    /// Behind a `tokio::sync::Mutex` because `recv_from` needs `&mut Receiver` and we have `&self`.
    /// A tokio mutex (not std) is required because we `.await` while holding it in `recv_from`.
    rx: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    /// Shared routing table for this network — used to look up peers' inbox senders.
    network: Arc<tokio::sync::Mutex<SimNetworkInner>>,
}

#[async_trait]
impl AsyncUdpSocket for SimUdpSocket {
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    async fn send_to(&self, data: &[u8], dst: SocketAddr) -> Result<(), TransportError> {
        // Clone the sender while holding the lock, then DROP the lock before awaiting.
        // Holding the network mutex across `tx.send(...).await` would risk deadlock on a
        // full channel: driver A blocks in `send_to` holding the lock, while driver B
        // blocks waiting to acquire the same lock in its own `send_to` — neither can progress.
        let tx = {
            let net = self.network.lock().await;
            match net.sockets.get(&dst) {
                None => {
                    return Err(TransportError::Webrtc(format!(
                        "sim: no socket registered at {dst}"
                    )))
                }
                Some(tx) => tx.clone(),
            }
        }; // lock released here — safe to await below
           // A send error means the receiving socket was dropped. Non-fatal in tests.
        let _ = tx.send((data.to_vec(), self.local_addr)).await;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), TransportError> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            None => Err(TransportError::Webrtc(
                "sim: channel closed (all senders dropped)".to_owned(),
            )),
            Some((data, src)) => {
                let n = data.len().min(buf.len());
                // SAFETY: n = min(data.len(), buf.len()) — both slices have at least n bytes.
                #[allow(clippy::indexing_slicing)]
                buf[..n].copy_from_slice(&data[..n]);
                Ok((n, src))
            }
        }
    }
}

// ── DriverHandle ───────────────────────────────────────────────────────────────

/// A handle to a running [`WebRtcDriver`] task.
///
/// Obtained from [`spawn_webrtc_driver`]. Call [`shutdown`](Self::shutdown) to cleanly stop the
/// driver and wait for the task to exit.
pub struct DriverHandle {
    /// Oneshot sender: dropping or sending signals the driver to exit its select loop.
    shutdown_tx: oneshot::Sender<()>,
    /// Join handle for the spawned tokio task.
    task: tokio::task::JoinHandle<()>,
}

impl DriverHandle {
    /// Signal the driver to stop and wait for it to exit.
    ///
    /// Sends a shutdown signal to the drive loop and awaits the task's completion. After this
    /// returns, the driver task has fully exited and all resources it held are released.
    pub async fn shutdown(self) {
        // If the task already exited (e.g. recv error), the send will fail — that is fine.
        let _ = self.shutdown_tx.send(());
        // Ignore join errors (task panic or already-finished).
        let _ = self.task.await;
    }
}

// ── spawn_webrtc_driver ────────────────────────────────────────────────────────

/// Spawn a tokio task that drives `transport` using `socket`.
///
/// The driver runs a `tokio::select!` loop with three arms:
/// 1. **Timer:** fires at `transport.next_drive_at()`, calls `transport.drive(now)`, sends
///    outbound datagrams.
/// 2. **Receive:** waits on `socket.recv_from(...)`, feeds the datagram to
///    `transport.handle_receive(...)`, then immediately calls `transport.drive(now)` to flush
///    any responses.
/// 3. **Shutdown:** fires when the [`DriverHandle`] returned by this function is dropped or
///    [`DriverHandle::shutdown`] is called.
///
/// # Clock conversion
///
/// `str0m` uses [`std::time::Instant`]; tokio timers use [`tokio::time::Instant`]. The driver
/// converts between them using a pair of base values captured at spawn time:
/// - `std_base` — the `std::time::Instant` supplied by the caller (typically `Instant::now()`
///   or a deterministic per-process base like `sim_base()` in tests).
/// - `tokio_base` — `tokio::time::Instant::now()` captured just before spawning the task.
///
/// Under [`tokio::time::pause()`], `tokio::time::Instant::now()` returns the paused virtual
/// time, so all derived `std::time::Instant` values advance only with
/// [`tokio::time::advance()`]. This gives deterministic str0m clocks in tests.
///
/// # Parameters
///
/// - `transport` — the [`PinnedWebRtcTransport`] to drive.
/// - `socket` — the [`AsyncUdpSocket`] for I/O (production: [`TokioUdpSocket`]; tests: [`SimUdpSocket`]).
/// - `std_base` — base [`std::time::Instant`] for the str0m clock (use `Instant::now()` in
///   production; use a deterministic per-process value in tests).
///
/// # Returns
///
/// A [`DriverHandle`] that can be used to shut down the driver.
pub fn spawn_webrtc_driver(
    transport: Arc<PinnedWebRtcTransport>,
    socket: Arc<dyn AsyncUdpSocket>,
    std_base: Instant,
) -> DriverHandle {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let tokio_base = tokio::time::Instant::now();

    let task = tokio::spawn(driver_task(
        transport,
        socket,
        std_base,
        tokio_base,
        shutdown_rx,
    ));

    DriverHandle { shutdown_tx, task }
}

/// The actual driver task body. Separated from `spawn_webrtc_driver` for clarity and to keep
/// the public spawn function thin.
async fn driver_task(
    transport: Arc<PinnedWebRtcTransport>,
    socket: Arc<dyn AsyncUdpSocket>,
    std_base: Instant,
    tokio_base: tokio::time::Instant,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    // Datagram receive buffer: maximum UDP payload size.
    let mut buf = vec![0u8; 65535];

    // Default poll interval when str0m has not yet emitted a timeout (before first drive).
    let default_poll = Duration::from_millis(50);

    // Initial drive to prime the engine and get the first timeout.
    let now = std_now(std_base, tokio_base);
    match transport.drive(now) {
        Ok(transmits) => send_all(&*socket, transmits).await,
        Err(e) => {
            tracing::error!("WebRtcDriver: initial drive error: {e}");
            return;
        }
    }

    loop {
        // Compute the next sleep deadline from str0m's timeout.
        let sleep_until = {
            let raw = match transport.next_drive_at() {
                Some(std_instant) => {
                    // Convert std::time::Instant → tokio::time::Instant via the shared base offset.
                    let offset = std_instant
                        .checked_duration_since(std_base)
                        .unwrap_or(Duration::ZERO);
                    // checked_add: a large offset could theoretically overflow. On overflow we fall
                    // back to the default poll deadline — the engine will retransmit naturally.
                    tokio_base.checked_add(offset).unwrap_or_else(|| {
                        tokio_base.checked_add(default_poll).unwrap_or(tokio_base)
                    })
                }
                None => tokio_base.checked_add(default_poll).unwrap_or(tokio_base),
            };
            // Clamp to at least now + 1 ms so a past/present str0m deadline does not cause a
            // busy-spin. This mirrors str0m's own reference driver convention of a ≥1 ms floor.
            // Under `tokio::time::pause()`, `tokio::time::Instant::now()` tracks virtual time,
            // so the clamp is correct in both real-time and paused-time contexts.
            // Use `checked_add` to satisfy `clippy::arithmetic_side_effects`.
            let floor = tokio::time::Instant::now()
                .checked_add(Duration::from_millis(1))
                .unwrap_or_else(tokio::time::Instant::now);
            raw.max(floor)
        };

        tokio::select! {
            // Arm 1: timer fires — call drive() and send outbound datagrams.
            _ = tokio::time::sleep_until(sleep_until) => {
                let now = std_now(std_base, tokio_base);
                match transport.drive(now) {
                    Ok(transmits) => send_all(&*socket, transmits).await,
                    Err(e) => {
                        tracing::error!("WebRtcDriver: drive error: {e}");
                        break;
                    }
                }
            }

            // Arm 2: datagram received — feed it to the transport, then drive.
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, from)) => {
                        let now = std_now(std_base, tokio_base);
                        let to = socket.local_addr();
                        // SAFETY: n is returned by recv_from which guarantees n <= buf.len().
                        #[allow(clippy::indexing_slicing)]
                        let data = &buf[..n];
                        if let Err(e) = transport.handle_receive(from, to, data, now) {
                            tracing::warn!("WebRtcDriver: handle_receive error (non-fatal): {e}");
                        }
                        // Drive after receive to flush any outbound responses.
                        let now2 = std_now(std_base, tokio_base);
                        match transport.drive(now2) {
                            Ok(transmits) => send_all(&*socket, transmits).await,
                            Err(e) => {
                                tracing::error!("WebRtcDriver: post-recv drive error: {e}");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("WebRtcDriver: recv_from error: {e}");
                        break;
                    }
                }
            }

            // Arm 3: shutdown signal — exit the loop cleanly.
            _ = &mut shutdown_rx => {
                tracing::debug!("WebRtcDriver: shutdown signal received");
                break;
            }
        }
    }
}

/// Compute the current `std::time::Instant` from the tokio virtual clock.
///
/// Uses the offset between `tokio::time::Instant::now()` and `tokio_base` to advance `std_base`
/// by the same duration. Under `tokio::time::pause()`, `tokio::time::Instant::now()` tracks
/// paused virtual time, so this produces deterministic std instants in tests.
#[inline]
fn std_now(std_base: Instant, tokio_base: tokio::time::Instant) -> Instant {
    let elapsed = tokio::time::Instant::now().saturating_duration_since(tokio_base);
    // checked_add: if elapsed overflows Instant (extremely unlikely in practice), fall back to
    // std_base so the drive loop continues with a slightly stale timestamp rather than panicking.
    std_base.checked_add(elapsed).unwrap_or(std_base)
}

/// Send all outbound transmits, logging-and-continuing on individual send errors.
///
/// A single failed send is non-fatal: the remote will retransmit (STUN/DTLS have their own
/// retransmit logic) or the connection will eventually time out. Breaking the loop on a send
/// error would close the connection prematurely.
async fn send_all(socket: &dyn AsyncUdpSocket, transmits: Vec<str0m::net::Transmit>) {
    for t in transmits {
        if let Err(e) = socket.send_to(t.contents.as_ref(), t.destination).await {
            tracing::warn!(
                dst = %t.destination,
                "WebRtcDriver: send_to failed (non-fatal, continuing): {e}"
            );
        }
    }
}
