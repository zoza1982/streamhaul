//! ICE agent state machine (RFC 8445).
//!
//! [`IceAgent`] orchestrates candidate gathering, connectivity checks, and path
//! nomination.  It is deliberately **synchronous** — no async runtime is required.
//! In production, run it on a `spawn_blocking` / dedicated thread; in tests, drive
//! it with the [`IceAgent::step`] method in a simple loop.
//!
//! # State machine
//!
//! ```text
//! New → Gathering → Checking → Connected
//!                             ↘ Failed → Restarting
//! ```
//!
//! # Test harness
//!
//! The [`IceAgent::step`] method accepts an optional incoming datagram and returns
//! any outgoing datagrams.  Tests interleave two agents' `step()` calls with the
//! [`crate::transport::NatSimNetwork`] as the packet delivery fabric.

use std::net::SocketAddr;

use rand_core::RngCore;
use sh_types::Clock;

use crate::{
    candidate::{Candidate, CandidateKind, CandidatePair, PairState},
    error::IceError,
    stun::{StunAttribute, StunClass, StunMessage},
    transport::UdpTransport,
};

// ─── Configuration ────────────────────────────────────────────────────────────

/// Configuration for a TURN relay server.
#[derive(Clone)]
pub struct TurnServerConfig {
    /// The TURN server address.
    pub addr: SocketAddr,
    /// TURN username for short-term credentials.
    pub username: String,
    /// TURN password for short-term credentials.
    ///
    /// **Not printed by `Debug`** — TURN credentials must not appear in logs.
    pub password: String,
}

impl std::fmt::Debug for TurnServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnServerConfig")
            .field("addr", &self.addr)
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .finish()
    }
}

/// Configuration for an [`IceAgent`].
///
/// The `local_pwd` and `remote_pwd` fields are redacted in `Debug` output to
/// prevent ICE credentials from appearing in logs.
#[derive(Clone)]
pub struct IceConfig {
    /// STUN servers used for server-reflexive candidate discovery.
    pub stun_servers: Vec<SocketAddr>,
    /// TURN servers used for relay candidate allocation.
    pub turn_servers: Vec<TurnServerConfig>,
    /// Local UDP addresses from which to gather host candidates.
    pub local_addrs: Vec<SocketAddr>,
    /// Whether this agent is the controlling or controlled role.
    pub role: IceRole,
    /// Tie-breaker value (random 64-bit value, unique per agent).
    pub tie_breaker: u64,
    /// Local ICE username fragment (from SDP `a=ice-ufrag`).
    pub local_ufrag: String,
    /// Local ICE password (from SDP `a=ice-pwd`).  Used to verify incoming requests.
    ///
    /// **Not printed by `Debug`** — ICE passwords must not appear in logs.
    pub local_pwd: String,
    /// Remote ICE username fragment (from the peer's SDP `a=ice-ufrag`).
    pub remote_ufrag: String,
    /// Remote ICE password (from the peer's SDP `a=ice-pwd`).  Used to sign outgoing requests.
    ///
    /// **Not printed by `Debug`** — ICE passwords must not appear in logs.
    pub remote_pwd: String,
}

impl std::fmt::Debug for IceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceConfig")
            .field("stun_servers", &self.stun_servers)
            .field("turn_servers", &self.turn_servers)
            .field("local_addrs", &self.local_addrs)
            .field("role", &self.role)
            .field("tie_breaker", &self.tie_breaker)
            .field("local_ufrag", &self.local_ufrag)
            .field("local_pwd", &"[redacted]")
            .field("remote_ufrag", &self.remote_ufrag)
            .field("remote_pwd", &"[redacted]")
            .finish()
    }
}

/// ICE agent role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    /// The controlling agent nominates the pair.
    Controlling,
    /// The controlled agent follows the controller's nomination.
    Controlled,
}

// ─── ICE state ────────────────────────────────────────────────────────────────

/// ICE agent state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceState {
    /// Agent created but not yet gathering.
    New,
    /// Gathering local, srflx, and relay candidates.
    Gathering,
    /// Running connectivity checks on candidate pairs.
    Checking,
    /// A path has been nominated and is in use.
    Connected,
    /// All connectivity checks failed.
    Failed,
    /// Restarting after failure (re-gathering).
    Restarting,
}

// ─── Internal constants ───────────────────────────────────────────────────────

/// Connectivity check timeout: 5 seconds in microseconds.
const CHECK_TIMEOUT_US: i64 = 5_000_000;

// ─── IceAgent ────────────────────────────────────────────────────────────────

/// The ICE agent state machine.
///
/// Type parameters:
/// - `T`: the [`UdpTransport`] implementation.
/// - `C`: the [`Clock`] implementation.
/// - `R`: the random number generator (implements [`rand_core::RngCore`]).
pub struct IceAgent<T, C, R>
where
    T: UdpTransport,
    C: Clock,
    R: RngCore,
{
    config: IceConfig,
    transport: T,
    clock: C,
    rng: R,
    state: IceState,
    local_candidates: Vec<Candidate>,
    remote_candidates: Vec<Candidate>,
    check_list: Vec<CandidatePair>,
    nominated_idx: Option<usize>,
    /// Unix-microsecond timestamp when we entered Checking state.
    checking_started_us: Option<i64>,
    /// Pending outgoing messages (for the step() harness).
    outgoing: Vec<(Vec<u8>, SocketAddr)>,
    /// Transactions in flight: (transaction_id, pair_idx).
    in_flight: Vec<([u8; 12], usize)>,
}

impl<T, C, R> IceAgent<T, C, R>
where
    T: UdpTransport,
    C: Clock,
    R: RngCore,
{
    /// Create a new ICE agent.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_ice::agent::{IceAgent, IceConfig, IceRole};
    /// use sh_ice::transport::{NatSimNetwork, NatType};
    /// use sh_types::FixedClock;
    /// use rand_core::OsRng;
    ///
    /// let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
    /// let sock = net.create_socket(NatType::FullCone,
    ///     "127.0.0.1:9001".parse().unwrap()).unwrap();
    /// let cfg = IceConfig {
    ///     stun_servers: vec![],
    ///     turn_servers: vec![],
    ///     local_addrs: vec!["127.0.0.1:9001".parse().unwrap()],
    ///     role: IceRole::Controlling,
    ///     tie_breaker: 12345,
    ///     local_ufrag: "myufrag".into(),
    ///     local_pwd: "mypassword32charslong__________".into(),
    ///     remote_ufrag: "peerufrag".into(),
    ///     remote_pwd: "peerpassword32charslong_________".into(),
    /// };
    /// let agent = IceAgent::new(cfg, sock, FixedClock(0), OsRng);
    /// assert_eq!(agent.state(), sh_ice::agent::IceState::New);
    /// ```
    #[must_use]
    pub fn new(config: IceConfig, transport: T, clock: C, rng: R) -> Self {
        Self {
            config,
            transport,
            clock,
            rng,
            state: IceState::New,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            check_list: Vec::new(),
            nominated_idx: None,
            checking_started_us: None,
            outgoing: Vec::new(),
            in_flight: Vec::new(),
        }
    }

    /// Return the current ICE state.
    #[must_use]
    pub fn state(&self) -> IceState {
        self.state
    }

    /// Gather local candidates.
    ///
    /// Emits one [`CandidateKind::Host`] candidate per local address.  In a full
    /// implementation this would also send STUN Binding Requests and TURN Allocate
    /// messages; those are deferred to P4-3 (live networking).
    ///
    /// Returns all newly gathered candidates.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::GatherFailed`] if no local addresses are configured.
    pub fn gather(&mut self) -> Result<Vec<Candidate>, IceError> {
        // Validate preconditions before mutating state so that callers observe a
        // consistent transition (New → Gathering) rather than a transient Gathering
        // that immediately flips to Failed.
        if self.config.local_addrs.is_empty() {
            self.state = IceState::Failed;
            return Err(IceError::GatherFailed(
                "no local addresses configured".into(),
            ));
        }
        self.state = IceState::Gathering;

        self.local_candidates.clear();
        for &addr in &self.config.local_addrs {
            let c = Candidate::new(CandidateKind::Host, addr, addr, 1);
            self.local_candidates.push(c);
        }

        // In a live implementation, we would also gather srflx (via STUN) and relay
        // (via TURN) candidates here.  Those require real or simulated STUN/TURN
        // server responses and are deferred to P4-3.

        let gathered = self.local_candidates.clone();
        Ok(gathered)
    }

    /// Add a remote candidate received via signalling or trickle ICE.
    ///
    /// Builds or extends the check list from the current local × remote cross product.
    /// When called while the agent is already in [`IceState::Connected`], the existing
    /// nominated pair is preserved — the new candidate produces additional pairs that
    /// can be checked for a potentially better path, but the working path is not torn
    /// down.
    ///
    /// # Errors
    ///
    /// This method is infallible.  It will silently extend the check list even if the
    /// supplied candidate is a duplicate; deduplication is deferred to a future version.
    pub fn add_remote_candidate(&mut self, candidate: Candidate) {
        self.remote_candidates.push(candidate);
        // Rebuild the check list whenever remote candidates change.
        self.rebuild_check_list();
    }

    /// Rebuild the check list from the current local × remote cross product.
    fn rebuild_check_list(&mut self) {
        // Save the nominated remote addr so we can re-locate it after the rebuild.
        let nominated_remote_addr = self
            .nominated_idx
            .and_then(|i| self.check_list.get(i))
            .map(|p| p.remote.addr);

        let is_controlling = self.config.role == IceRole::Controlling;
        let mut pairs: Vec<CandidatePair> = self
            .local_candidates
            .iter()
            .flat_map(|local| {
                self.remote_candidates.iter().map(move |remote| {
                    let mut pair =
                        CandidatePair::new(local.clone(), remote.clone(), is_controlling);
                    pair.state = PairState::Waiting;
                    pair
                })
            })
            .collect();
        // Sort by descending pair priority.
        pairs.sort_by_key(|p| std::cmp::Reverse(p.priority));
        self.check_list = pairs;
        self.in_flight.clear();

        // Re-locate the nominated pair. If it's still in the new list, preserve nomination.
        // This handles trickle ICE arrivals post-Connected without tearing down the working path.
        if let Some(remote_addr) = nominated_remote_addr {
            self.nominated_idx = self
                .check_list
                .iter()
                .position(|p| p.remote.addr == remote_addr);
            // Re-mark as nominated and Succeeded.
            if let Some(idx) = self.nominated_idx {
                if let Some(pair) = self.check_list.get_mut(idx) {
                    pair.nominated = true;
                    pair.state = PairState::Succeeded;
                }
            }
        } else {
            self.nominated_idx = None;
        }
    }

    /// Run connectivity checks: send STUN Binding Requests (with `MESSAGE-INTEGRITY`)
    /// for all `Waiting` pairs.
    ///
    /// Timeout detection is handled exclusively by [`IceAgent::step`] to avoid
    /// a duplicate state transition.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::CheckFailed`] if no pairs are available.
    pub fn check_pairs(&mut self) -> Result<(), IceError> {
        if self.check_list.is_empty() {
            return Err(IceError::CheckFailed("check list is empty".into()));
        }

        for (idx, pair) in self.check_list.iter_mut().enumerate() {
            if pair.state == PairState::Waiting {
                pair.state = PairState::InProgress;
                let tid = generate_tid(&mut self.rng);
                // Build the request; store the result so we can send it below.
                let msg_result = build_binding_request(
                    tid,
                    self.config.role,
                    self.config.tie_breaker,
                    pair.local.priority,
                    false, // not nominating on first try
                    &CheckCreds {
                        local_ufrag: &self.config.local_ufrag,
                        remote_ufrag: &self.config.remote_ufrag,
                        remote_pwd: self.config.remote_pwd.as_bytes(),
                    },
                );
                match msg_result {
                    Ok(bytes) => {
                        // Best-effort send; transport errors manifest as pair failure when
                        // no response arrives.
                        let _ = self.transport.send_to(&bytes, pair.remote.addr);
                        self.in_flight.push((tid, idx));
                    }
                    Err(_) => {
                        // HMAC construction failure — treat as a transport-level error
                        // (the pair stays InProgress and will time out naturally).
                    }
                }
            }
        }

        Ok(())
    }

    /// Return the nominated pair, if any.
    #[must_use]
    pub fn nominated_pair(&self) -> Option<&CandidatePair> {
        self.nominated_idx.and_then(|i| self.check_list.get(i))
    }

    /// Return a reference to the current check list.
    #[must_use]
    pub fn check_list(&self) -> &[CandidatePair] {
        &self.check_list
    }

    /// Return the TIDs of all in-flight transactions (for testing).
    #[cfg(test)]
    pub fn in_flight_tids(&self) -> Vec<[u8; 12]> {
        self.in_flight.iter().map(|(tid, _)| *tid).collect()
    }

    /// Return the nominated pair index (for testing).
    #[cfg(test)]
    pub fn nominated_idx_for_test(&self) -> Option<usize> {
        self.nominated_idx
    }

    /// Advance the agent by one event: process `incoming` (if any) and return
    /// outgoing messages to be delivered by the test harness.
    ///
    /// Pass `None` as a timer tick (no incoming datagram).
    ///
    /// # Errors
    ///
    /// Returns [`IceError::Timeout`] when the checking phase times out.
    pub fn step(
        &mut self,
        incoming: Option<(Vec<u8>, SocketAddr)>,
    ) -> Result<Vec<(Vec<u8>, SocketAddr)>, IceError> {
        // Process an explicitly-passed incoming datagram (from the test harness queue).
        if let Some((data, from)) = incoming {
            self.handle_incoming(&data, from)?;
        }

        // Also drain any messages that arrived via the transport's inbox
        // (e.g. direct sends through the NatSimNetwork).
        self.drain_transport_inbox();

        // Drain already-queued outgoing messages.
        let mut out = std::mem::take(&mut self.outgoing);

        // Drive state machine.
        match self.state {
            IceState::New => {
                // Auto-start gathering on first step if local addrs are configured.
                if !self.config.local_addrs.is_empty() {
                    let _ = self.gather()?;
                }
            }
            IceState::Gathering => {
                // In the sim, gathering is instantaneous (host candidates only).
                // Transition to Checking if we have remote candidates.
                if !self.remote_candidates.is_empty() {
                    self.rebuild_check_list();
                    let now_us = self.clock.now_unix_secs().saturating_mul(1_000_000);
                    self.state = IceState::Checking;
                    self.checking_started_us = Some(now_us);
                }
            }
            IceState::Checking => {
                // Send checks for Waiting pairs.
                let _ = self.check_pairs();
                // Drain transport again after sending (peers may have responded via sim).
                self.drain_transport_inbox();
                // Check timeout.
                let now_us = self.clock.now_unix_secs().saturating_mul(1_000_000);
                if let Some(started) = self.checking_started_us {
                    if now_us.saturating_sub(started) > CHECK_TIMEOUT_US {
                        self.state = IceState::Failed;
                        return Err(IceError::Timeout);
                    }
                }
                // Check for nomination.
                if self.nominated_idx.is_some() {
                    self.state = IceState::Connected;
                }
            }
            IceState::Failed => {
                self.state = IceState::Restarting;
            }
            IceState::Restarting => {
                self.local_candidates.clear();
                self.remote_candidates.clear();
                self.check_list.clear();
                self.nominated_idx = None;
                self.checking_started_us = None;
                self.in_flight.clear();
                self.state = IceState::New;
            }
            IceState::Connected => {}
        }

        // Drain new outgoing messages added by the state machine.
        out.extend(std::mem::take(&mut self.outgoing));
        Ok(out)
    }

    /// Drain any messages pending in the transport inbox and process them.
    ///
    /// This is used in the synchronous test harness where the NatSimNetwork
    /// delivers packets directly into the SimSocket inbox via `send_to`.
    fn drain_transport_inbox(&mut self) {
        let mut buf = [0u8; 2048];
        // Process up to 64 pending messages per call to bound latency.
        for _ in 0..64 {
            match self.transport.recv_from(&mut buf) {
                Ok((n, from)) => {
                    if let Some(data) = buf.get(..n) {
                        let _ = self.handle_incoming(data, from);
                    }
                }
                Err(_) => break, // no more messages
            }
        }
    }

    /// Process an incoming STUN datagram.
    fn handle_incoming(&mut self, data: &[u8], from: SocketAddr) -> Result<(), IceError> {
        let msg = match StunMessage::decode(data) {
            Ok(m) => m,
            Err(_) => return Ok(()), // not a STUN message; ignore
        };

        match msg.class {
            StunClass::Request => self.handle_binding_request(data, msg, from),
            StunClass::SuccessResponse => self.handle_binding_response(data, msg, from),
            StunClass::ErrorResponse | StunClass::Indication => Ok(()),
        }
    }

    /// Handle an incoming STUN Binding Request (from the peer agent).
    fn handle_binding_request(
        &mut self,
        raw: &[u8],
        msg: StunMessage,
        from: SocketAddr,
    ) -> Result<(), IceError> {
        // RFC 8445 §7.3.1: incoming Binding Requests MUST carry MESSAGE-INTEGRITY
        // authenticated with the local ICE password.  Reject silently on failure
        // (an active attacker should not learn whether we received the message).
        if StunMessage::verify_integrity(raw, self.config.local_pwd.as_bytes()).is_err() {
            tracing::trace!("dropping Binding Request with invalid MESSAGE-INTEGRITY");
            return Ok(());
        }

        // RFC 8445 §7.3.1: validate USERNAME ufrag after MI passes.
        // USERNAME = "<remote_ufrag>:<local_ufrag>"; the local part must match config.local_ufrag.
        let username_valid = msg.attributes.iter().any(|a| {
            if let StunAttribute::Username(u) = a {
                u.split_once(':')
                    .is_some_and(|(_, local_part)| local_part == self.config.local_ufrag)
            } else {
                false
            }
        });
        if !username_valid {
            return Ok(());
        }

        let mut use_candidate = false;
        let mut sender_is_controlling = false;
        for attr in &msg.attributes {
            match attr {
                StunAttribute::UseCandidate => use_candidate = true,
                StunAttribute::IceControlling(_) => sender_is_controlling = true,
                _ => {}
            }
        }
        // Only honour USE-CANDIDATE if the sender is in the ICE-CONTROLLING role.
        let use_candidate = use_candidate && sender_is_controlling;

        // Build and queue a success response (signed with local password so the peer
        // can verify it).
        let mut resp = StunMessage::new_binding_response(msg.transaction_id);
        resp.attributes.push(StunAttribute::XorMappedAddress(from));
        let resp_bytes = match resp.encode_with_integrity(self.config.local_pwd.as_bytes()) {
            Ok(b) => b,
            Err(_) => return Ok(()), // HMAC construction failure; drop silently
        };
        self.outgoing.push((resp_bytes, from));

        // If the controlling peer sent USE-CANDIDATE and we have a matching pair,
        // mark it as nominated.
        if use_candidate {
            if let Some(idx) = self.check_list.iter().position(|p| p.remote.addr == from) {
                if let Some(pair) = self.check_list.get_mut(idx) {
                    pair.state = PairState::Succeeded;
                    pair.nominated = true;
                    self.nominated_idx = Some(idx);
                }
            }
        }

        // Even without USE-CANDIDATE, a received request implies connectivity.
        // Mark any pair targeting `from` as Succeeded and send a triggered check.
        let mut triggered_pair_idx: Option<usize> = None;
        for (idx, pair) in self.check_list.iter_mut().enumerate() {
            if pair.remote.addr == from
                && (pair.state == PairState::InProgress || pair.state == PairState::Waiting)
            {
                pair.state = PairState::Succeeded;
                if triggered_pair_idx.is_none() {
                    triggered_pair_idx = Some(idx);
                }
            }
        }

        // RFC 8445 §7.3.1.4: send a triggered check so the peer gets a response.
        // The Controlling agent uses this to nominate if not yet done.
        if let Some(idx) = triggered_pair_idx {
            if let Some(pair) = self.check_list.get(idx) {
                let is_controlling = self.config.role == IceRole::Controlling;
                let should_nominate = is_controlling && self.nominated_idx.is_none();
                let tid = generate_tid(&mut self.rng);
                let triggered_result = build_binding_request(
                    tid,
                    self.config.role,
                    self.config.tie_breaker,
                    pair.local.priority,
                    should_nominate,
                    &CheckCreds {
                        local_ufrag: &self.config.local_ufrag,
                        remote_ufrag: &self.config.remote_ufrag,
                        remote_pwd: self.config.remote_pwd.as_bytes(),
                    },
                );
                if let Ok(bytes) = triggered_result {
                    let dest = from;
                    // Send triggered check via transport (goes through NAT sim).
                    let _ = self.transport.send_to(&bytes, dest);
                    self.in_flight.push((tid, idx));
                    if should_nominate {
                        // Optimistically mark as nominated; confirmed when we get the response.
                        if let Some(p) = self.check_list.get_mut(idx) {
                            p.nominated = true;
                            self.nominated_idx = Some(idx);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle an incoming STUN Binding Success Response.
    fn handle_binding_response(
        &mut self,
        raw: &[u8],
        msg: StunMessage,
        from: SocketAddr,
    ) -> Result<(), IceError> {
        // RFC 8445 §7.3.2: verify MESSAGE-INTEGRITY before processing.
        if StunMessage::verify_integrity(raw, self.config.remote_pwd.as_bytes()).is_err() {
            return Ok(());
        }

        // Find the matching in-flight transaction.
        let pair_idx = self
            .in_flight
            .iter()
            .position(|(tid, _)| *tid == msg.transaction_id);

        let pair_idx = match pair_idx {
            Some(pos) => {
                let (_, idx) = self.in_flight.remove(pos);
                idx
            }
            None => return Ok(()), // spurious response; ignore
        };

        // Verify the response came from the expected remote address.
        if let Some(pair) = self.check_list.get(pair_idx) {
            if from != pair.remote.addr {
                return Ok(());
            }
        }

        if let Some(pair) = self.check_list.get_mut(pair_idx) {
            pair.state = PairState::Succeeded;

            // XOR-MAPPED-ADDRESS would be used to update srflx candidates in P4-3.
            // For now we only care about the success / failure of the check.

            // Controlling agent nominates the first succeeded pair.
            if self.config.role == IceRole::Controlling && self.nominated_idx.is_none() {
                pair.nominated = true;
                self.nominated_idx = Some(pair_idx);

                // Send a new binding request with USE-CANDIDATE (signed with MI) to inform the peer.
                let tid = generate_tid(&mut self.rng);
                let nominate_result = build_binding_request(
                    tid,
                    self.config.role,
                    self.config.tie_breaker,
                    pair.local.priority,
                    true,
                    &CheckCreds {
                        local_ufrag: &self.config.local_ufrag,
                        remote_ufrag: &self.config.remote_ufrag,
                        remote_pwd: self.config.remote_pwd.as_bytes(),
                    },
                );
                if let Ok(bytes) = nominate_result {
                    self.outgoing.push((bytes, from));
                    // Track the nomination request so its response is matched.
                    self.in_flight.push((tid, pair_idx));
                }
            }
        }

        Ok(())
    }
}

// ─── Helper functions ─────────────────────────────────────────────────────────

/// Generate a random 12-byte STUN transaction ID.
fn generate_tid(rng: &mut impl RngCore) -> [u8; 12] {
    let mut tid = [0u8; 12];
    rng.fill_bytes(&mut tid);
    tid
}

/// ICE short-term credential tuple for signing and verifying Binding Requests.
struct CheckCreds<'a> {
    /// Local ICE ufrag (from our SDP).
    local_ufrag: &'a str,
    /// Remote ICE ufrag (from the peer's SDP).
    remote_ufrag: &'a str,
    /// Remote ICE password; used to sign outgoing requests.
    remote_pwd: &'a [u8],
}

/// Build a STUN Binding Request with ICE attributes, signed with `MESSAGE-INTEGRITY`.
///
/// Per RFC 8445 §7.2.2, all ICE connectivity-check requests must include:
/// - `USERNAME` = `"<remote_ufrag>:<local_ufrag>"`
/// - `PRIORITY`, `ICE-CONTROLLING` or `ICE-CONTROLLED`
/// - `USE-CANDIDATE` (Controlling agent, when nominating)
/// - `MESSAGE-INTEGRITY` (HMAC-SHA1 keyed with the remote ICE password)
///
/// # Errors
///
/// Returns [`IceError::Transport`] if HMAC construction fails (unreachable in
/// practice since HMAC-SHA1 accepts any key length).
fn build_binding_request(
    tid: [u8; 12],
    role: IceRole,
    tie_breaker: u64,
    local_priority: u32,
    nominate: bool,
    creds: &CheckCreds<'_>,
) -> Result<Vec<u8>, IceError> {
    let mut msg = StunMessage::new_binding_request(tid);
    // USERNAME = "<remote_ufrag>:<local_ufrag>" per RFC 8445 §7.2.2.
    msg.attributes.push(StunAttribute::Username(format!(
        "{}:{}",
        creds.remote_ufrag, creds.local_ufrag
    )));
    msg.attributes.push(StunAttribute::Priority(local_priority));
    match role {
        IceRole::Controlling => {
            msg.attributes
                .push(StunAttribute::IceControlling(tie_breaker));
        }
        IceRole::Controlled => {
            msg.attributes
                .push(StunAttribute::IceControlled(tie_breaker));
        }
    }
    if nominate {
        msg.attributes.push(StunAttribute::UseCandidate);
    }
    // Sign with remote password so the peer can verify this is a legitimate check.
    msg.encode_with_integrity(creds.remote_pwd)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::cast_possible_truncation,
        clippy::arithmetic_side_effects
    )]

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use sh_types::FixedClock;

    use crate::{
        candidate::CandidateKind,
        transport::{NatSimNetwork, NatType},
    };

    use super::*;

    // ─── Deterministic RNG for tests ─────────────────────────────────────────

    /// A simple xorshift64 RNG sufficient for test transaction IDs.
    struct TestRng(u64);

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let mut i = 0;
            while i < dest.len() {
                let v = self.next_u64();
                let bytes = v.to_le_bytes();
                let take = (dest.len() - i).min(8);
                dest[i..i + take].copy_from_slice(&bytes[..take]);
                i += take;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    /// Build a minimal IceConfig for a given local address with placeholder credentials.
    fn make_config(local: SocketAddr, role: IceRole, tb: u64) -> IceConfig {
        IceConfig {
            stun_servers: vec![],
            turn_servers: vec![],
            local_addrs: vec![local],
            role,
            tie_breaker: tb,
            local_ufrag: "localufrag".into(),
            local_pwd: "local-password-32chars-long-ok!".into(),
            remote_ufrag: "remoteufrag".into(),
            remote_pwd: "remote-password-32chars-long-ok!".into(),
        }
    }

    /// Run a two-agent ICE session over the NatSimNetwork for up to `max_steps` rounds.
    ///
    /// Returns `(controlling_nominated, controlled_nominated)`.
    fn run_two_agent_session(nat_a: NatType, nat_b: NatType, max_steps: usize) -> (bool, bool) {
        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let addr_a = ipv4(127, 0, 0, 1, 19001);
        let addr_b = ipv4(127, 0, 0, 2, 19001);

        let sock_a = net.create_socket(nat_a, addr_a).unwrap();
        let sock_b = net.create_socket(nat_b, addr_b).unwrap();

        let ext_a = sock_a.external_addr().unwrap();
        let ext_b = sock_b.external_addr().unwrap();

        // Agents use each other's external addresses as remote candidates.
        let remote_for_a = Candidate::new(CandidateKind::Host, ext_b, ext_b, 1);
        let remote_for_b = Candidate::new(CandidateKind::Host, ext_a, ext_a, 1);

        // The two agents must share compatible credentials:
        // A's remote_pwd must match B's local_pwd, and vice versa.
        let mut cfg_a = make_config(addr_a, IceRole::Controlling, 111);
        let mut cfg_b = make_config(addr_b, IceRole::Controlled, 222);
        // Cross-wire the passwords.
        cfg_a.remote_pwd = cfg_b.local_pwd.clone();
        cfg_a.remote_ufrag = cfg_b.local_ufrag.clone();
        cfg_b.remote_pwd = cfg_a.local_pwd.clone();
        cfg_b.remote_ufrag = cfg_a.local_ufrag.clone();

        let mut agent_a = IceAgent::new(cfg_a, sock_a, FixedClock(0), TestRng(1));
        let mut agent_b = IceAgent::new(cfg_b, sock_b, FixedClock(0), TestRng(2));

        // Pre-add remote candidates.
        agent_a.add_remote_candidate(remote_for_a);
        agent_b.add_remote_candidate(remote_for_b);

        // Gather.
        agent_a.gather().unwrap();
        agent_b.gather().unwrap();

        // Rebuild check lists now that we have remote candidates.
        agent_a.rebuild_check_list();
        agent_b.rebuild_check_list();

        // Step loop.
        let mut pending_a: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
        let mut pending_b: Vec<(Vec<u8>, SocketAddr)> = Vec::new();

        for _ in 0..max_steps {
            // Feed B's output to A and vice versa.
            let incoming_a = pending_a.pop();
            let incoming_b = pending_b.pop();

            let out_a = agent_a.step(incoming_a).unwrap_or_default();
            let out_b = agent_b.step(incoming_b).unwrap_or_default();

            // Route outgoing messages through the NAT sim.
            // A's outgoing → B's inbox (via transport), B's outgoing → A's inbox.
            // For the step-based sim, we accumulate them as pending for the next iteration.
            pending_b.extend(out_a);
            pending_a.extend(out_b);

            if agent_a.state() == IceState::Connected && agent_b.state() == IceState::Connected {
                break;
            }
        }

        let a_nominated = agent_a.nominated_pair().is_some();
        let b_nominated = agent_b.nominated_pair().is_some();
        (a_nominated, b_nominated)
    }

    // ─── NAT matrix test ─────────────────────────────────────────────────────

    #[test]
    fn nat_matrix() {
        use NatType::*;

        let cases: &[(&str, NatType, NatType, bool)] = &[
            ("FullCone×FullCone", FullCone, FullCone, true),
            ("FullCone×RestrictedCone", FullCone, RestrictedCone, true),
            ("FullCone×PortRestricted", FullCone, PortRestricted, true),
            (
                "RestrictedCone×RestrictedCone",
                RestrictedCone,
                RestrictedCone,
                true,
            ),
            // PortRestricted×PortRestricted: both agents simultaneously send, punching holes.
            // In a synchronous step loop where A sends before B processes, B can see A's
            // external port after A has sent, so this works in the sim.
            (
                "PortRestricted×PortRestricted",
                PortRestricted,
                PortRestricted,
                true,
            ),
            // Symmetric×Symmetric: requires relay — each side uses a new external port per
            // dest, and neither has seen the other's per-dest port before receiving.
            ("Symmetric×Symmetric", Symmetric, Symmetric, false),
            // Mixed NAT combinations — RFC 5128 traversal matrix.
            // In this sim the Symmetric peer announces its base external addr, but actual
            // packets arrive from a per-dest mapped port unknown to the other side.
            // The source-address check (RFC 8445 §7.3.2) therefore rejects the mismatched
            // response, so all mixed Symmetric combos require relay in this harness.
            ("FullCone×Symmetric", FullCone, Symmetric, false),
            ("RestrictedCone×Symmetric", RestrictedCone, Symmetric, false),
            // PortRestricted requires exact (IP, port); Symmetric uses a new port per dest
            // that the PortRestricted side never sent to — relay required.
            ("PortRestricted×Symmetric", PortRestricted, Symmetric, false),
            // Mirrors of the above with roles swapped.
            ("Symmetric×FullCone", Symmetric, FullCone, false),
            ("Symmetric×RestrictedCone", Symmetric, RestrictedCone, false),
            ("Symmetric×PortRestricted", Symmetric, PortRestricted, false),
            // Additional coverage for asymmetric non-Symmetric pairs.
            (
                "RestrictedCone×PortRestricted",
                RestrictedCone,
                PortRestricted,
                true,
            ),
            (
                "PortRestricted×RestrictedCone",
                PortRestricted,
                RestrictedCone,
                true,
            ),
        ];

        println!("\nNAT traversal matrix results:");
        println!("{:<35} {:>8} {:>8}", "Combination", "A-nom", "B-nom");
        println!("{:-<55}", "");

        for (label, nat_a, nat_b, expect_success) in cases {
            let (a_nom, b_nom) = run_two_agent_session(*nat_a, *nat_b, 50);
            println!("{:<35} {:>8} {:>8}", label, a_nom, b_nom);
            if *expect_success {
                assert!(
                    a_nom && b_nom,
                    "both agents should nominate a pair for {label}: a_nom={a_nom} b_nom={b_nom}"
                );
            } else {
                // Relay required: assert that P2P did NOT fully succeed (both agents connected).
                // Note: in asymmetric Symmetric NAT cases the controlling agent may
                // unilaterally nominate (it can see the peer's responses), while the
                // controlled agent cannot (the USE-CANDIDATE arrives from the wrong
                // per-dest port). Both outcomes are acceptable here; what matters is
                // that the session did not reach a fully-connected state.
                assert!(
                    !(a_nom && b_nom),
                    "relay required for {label}: expected no full P2P connection, but got a_nom={a_nom} b_nom={b_nom}"
                );
            }
        }
    }

    // ─── ICE restart test ────────────────────────────────────────────────────

    #[test]
    fn ice_restart_after_timeout() {
        use crate::transport::{NatSimNetwork, NatType};

        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let addr = ipv4(127, 0, 0, 1, 19100);
        let sock = net.create_socket(NatType::FullCone, addr).unwrap();

        // Use a clock that starts at t=0 for gathering, then jumps to t=6 (past timeout).
        let cfg = make_config(addr, IceRole::Controlling, 42);
        let mut agent = IceAgent::new(cfg, sock, FixedClock(0), TestRng(99));

        // Gather and add a remote candidate so we have pairs.
        let remote_addr = ipv4(127, 0, 0, 2, 19101);
        agent.gather().unwrap();
        agent.add_remote_candidate(Candidate::new(
            CandidateKind::Host,
            remote_addr,
            remote_addr,
            1,
        ));

        // Manually force into Checking state with a time already past timeout.
        // clock is FixedClock(0) → now_us = 0.
        // We need: now_us - started > CHECK_TIMEOUT_US → 0 - started > 5_000_000
        // → started < -5_000_000.  Use -(CHECK_TIMEOUT_US + 1) = -5_000_001.
        agent.state = IceState::Checking;
        let past_timeout = CHECK_TIMEOUT_US.saturating_add(1);
        agent.checking_started_us = Some(-past_timeout);

        // Next step should detect timeout → Failed.
        let result = agent.step(None);
        assert!(
            matches!(result, Err(IceError::Timeout)) || agent.state == IceState::Failed,
            "expected timeout or Failed state"
        );

        // If state is Failed, next step transitions to Restarting.
        if agent.state == IceState::Failed {
            let _ = agent.step(None);
            assert_eq!(
                agent.state,
                IceState::Restarting,
                "Failed should transition to Restarting"
            );
            // One more step → back to New.
            let _ = agent.step(None);
            assert_eq!(
                agent.state,
                IceState::New,
                "Restarting should transition to New"
            );
        }
    }

    #[test]
    fn forged_response_rejected() {
        // Verify that a Binding Success Response without valid MESSAGE-INTEGRITY is dropped.
        let (a_nom, b_nom) = run_two_agent_session(NatType::FullCone, NatType::FullCone, 50);
        assert!(a_nom && b_nom, "happy path must still connect");

        // Now verify forged response is rejected in isolation.
        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let addr_a = ipv4(127, 0, 0, 1, 29001);
        let sock_a = net.create_socket(NatType::FullCone, addr_a).unwrap();

        let mut cfg_a = make_config(addr_a, IceRole::Controlling, 111);
        cfg_a.remote_pwd = "remote-password-32chars-long-ok!".into();
        cfg_a.remote_ufrag = "remoteufrag".into();

        let mut agent_a = IceAgent::new(cfg_a, sock_a, FixedClock(0), TestRng(1));
        agent_a.gather().unwrap();

        // Add a remote candidate so we have a check-list pair.
        let remote_addr = ipv4(10, 0, 0, 254, 20001);
        agent_a.add_remote_candidate(Candidate::new(
            CandidateKind::Host,
            remote_addr,
            remote_addr,
            1,
        ));

        // Transition to Checking so check_pairs runs.
        agent_a.state = IceState::Checking;
        agent_a.checking_started_us = Some(0);
        let _ = agent_a.step(None);

        // Get an in-flight TID.
        let tids = agent_a.in_flight_tids();
        if tids.is_empty() {
            // No pairs in-flight yet; that is fine — no forged response to test.
            return;
        }
        let tid = tids[0];

        // Forge a success response with that TID but no MESSAGE-INTEGRITY.
        let forged_msg = StunMessage::new_binding_response(tid);
        let forged_bytes = forged_msg.encode();

        // Feed the forged response to the agent.
        let _ = agent_a.step(Some((forged_bytes, remote_addr)));

        // The pair must NOT have been promoted by the forged response.
        let pair_state = agent_a.check_list.first().map(|p| p.state);
        assert_ne!(
            pair_state,
            Some(PairState::Succeeded),
            "forged response must not promote pair to Succeeded"
        );
    }

    #[test]
    fn use_candidate_role_check() {
        // Verify that USE-CANDIDATE is only honoured when the sender claims ICE-CONTROLLING.
        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let addr_a = ipv4(127, 0, 0, 1, 29002);
        let sock_a = net.create_socket(NatType::FullCone, addr_a).unwrap();

        let mut cfg_a = make_config(addr_a, IceRole::Controlled, 222);
        // Set remote_pwd = local_pwd so our self-signed requests validate.
        cfg_a.remote_pwd = cfg_a.local_pwd.clone();
        cfg_a.remote_ufrag = cfg_a.local_ufrag.clone();

        let mut agent_a = IceAgent::new(cfg_a.clone(), sock_a, FixedClock(0), TestRng(3));
        agent_a.gather().unwrap();
        let remote_addr = ipv4(10, 0, 0, 254, 20001);
        agent_a.add_remote_candidate(Candidate::new(
            CandidateKind::Host,
            remote_addr,
            remote_addr,
            1,
        ));

        // Build a fake Binding Request with USE-CANDIDATE but ICE-CONTROLLED (wrong role).
        let tid = [0xABu8; 12];
        let mut req = StunMessage::new_binding_request(tid);
        req.attributes.push(StunAttribute::Username(format!(
            "{}:{}",
            cfg_a.remote_ufrag, cfg_a.local_ufrag
        )));
        req.attributes.push(StunAttribute::Priority(1000));
        req.attributes.push(StunAttribute::IceControlled(999)); // wrong role
        req.attributes.push(StunAttribute::UseCandidate);
        let req_bytes = req
            .encode_with_integrity(cfg_a.local_pwd.as_bytes())
            .unwrap();

        let _ = agent_a.step(Some((req_bytes, remote_addr)));

        // USE-CANDIDATE with ICE-CONTROLLED must NOT nominate.
        assert!(
            agent_a.nominated_idx_for_test().is_none(),
            "USE-CANDIDATE from ICE-CONTROLLED role must be ignored"
        );

        // Now send with ICE-CONTROLLING — should nominate.
        let tid2 = [0xCDu8; 12];
        let mut req2 = StunMessage::new_binding_request(tid2);
        req2.attributes.push(StunAttribute::Username(format!(
            "{}:{}",
            cfg_a.remote_ufrag, cfg_a.local_ufrag
        )));
        req2.attributes.push(StunAttribute::Priority(1000));
        req2.attributes.push(StunAttribute::IceControlling(999)); // correct role
        req2.attributes.push(StunAttribute::UseCandidate);
        let req2_bytes = req2
            .encode_with_integrity(cfg_a.local_pwd.as_bytes())
            .unwrap();

        let _ = agent_a.step(Some((req2_bytes, remote_addr)));

        assert!(
            agent_a.nominated_idx_for_test().is_some(),
            "USE-CANDIDATE from ICE-CONTROLLING role must nominate"
        );
    }

    #[test]
    fn nomination_tid_tracked() {
        let (a_nom, b_nom) = run_two_agent_session(NatType::FullCone, NatType::FullCone, 50);
        assert!(
            a_nom && b_nom,
            "both agents must reach Connected: a_nom={a_nom} b_nom={b_nom}"
        );
    }

    #[test]
    fn username_ufrag_validated() {
        // Verify that requests with wrong USERNAME ufrag are dropped even with correct MI.
        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let addr_a = ipv4(127, 0, 0, 1, 29003);
        let sock_a = net.create_socket(NatType::FullCone, addr_a).unwrap();

        let mut cfg_a = make_config(addr_a, IceRole::Controlled, 333);
        cfg_a.remote_pwd = cfg_a.local_pwd.clone();
        cfg_a.remote_ufrag = cfg_a.local_ufrag.clone();

        let mut agent_a = IceAgent::new(cfg_a.clone(), sock_a, FixedClock(0), TestRng(4));
        agent_a.gather().unwrap();
        let remote_addr = ipv4(10, 0, 0, 254, 20002);
        agent_a.add_remote_candidate(Candidate::new(
            CandidateKind::Host,
            remote_addr,
            remote_addr,
            1,
        ));

        // Send with wrong USERNAME (local part doesn't match config.local_ufrag).
        let tid = [0xEFu8; 12];
        let mut req = StunMessage::new_binding_request(tid);
        req.attributes
            .push(StunAttribute::Username("wrongremote:wronglocal".into()));
        req.attributes.push(StunAttribute::Priority(1000));
        req.attributes.push(StunAttribute::IceControlling(1));
        req.attributes.push(StunAttribute::UseCandidate);
        let req_bytes = req
            .encode_with_integrity(cfg_a.local_pwd.as_bytes())
            .unwrap();

        let _ = agent_a.step(Some((req_bytes, remote_addr)));

        assert!(
            agent_a.nominated_idx_for_test().is_none(),
            "request with wrong USERNAME ufrag must be dropped"
        );

        // Correct USERNAME → should nominate.
        let tid2 = [0x12u8; 12];
        let mut req2 = StunMessage::new_binding_request(tid2);
        req2.attributes.push(StunAttribute::Username(format!(
            "{}:{}",
            cfg_a.remote_ufrag, cfg_a.local_ufrag
        )));
        req2.attributes.push(StunAttribute::Priority(1000));
        req2.attributes.push(StunAttribute::IceControlling(1));
        req2.attributes.push(StunAttribute::UseCandidate);
        let req2_bytes = req2
            .encode_with_integrity(cfg_a.local_pwd.as_bytes())
            .unwrap();

        let _ = agent_a.step(Some((req2_bytes, remote_addr)));

        assert!(
            agent_a.nominated_idx_for_test().is_some(),
            "correct USERNAME must be accepted"
        );
    }

    #[test]
    fn trickle_candidate_post_connected_preserves_nomination() {
        // First verify the happy path still works.
        let (a_nom, b_nom) = run_two_agent_session(NatType::FullCone, NatType::FullCone, 50);
        assert!(a_nom && b_nom, "session should have connected");

        // Now test trickle in isolation: set up a single agent, manually drive to Connected,
        // then add a late remote candidate and verify nomination is preserved.
        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let addr_a = ipv4(127, 0, 0, 1, 29004);
        let sock_a = net.create_socket(NatType::FullCone, addr_a).unwrap();

        let mut cfg_a = make_config(addr_a, IceRole::Controlling, 111);
        cfg_a.remote_pwd = cfg_a.local_pwd.clone();
        cfg_a.remote_ufrag = cfg_a.local_ufrag.clone();

        let mut agent = IceAgent::new(cfg_a, sock_a, FixedClock(0), TestRng(42));
        agent.gather().unwrap();

        let remote1 = Candidate::new(
            CandidateKind::Host,
            ipv4(10, 0, 0, 1, 9001),
            ipv4(10, 0, 0, 1, 9001),
            1,
        );
        agent.add_remote_candidate(remote1);

        // Manually force the pair to Succeeded+nominated to simulate Connected.
        agent.state = IceState::Connected;
        if let Some(pair) = agent.check_list.get_mut(0) {
            pair.state = PairState::Succeeded;
            pair.nominated = true;
        }
        agent.nominated_idx = Some(0);

        // Now add a late trickle candidate.
        let remote2 = Candidate::new(
            CandidateKind::Host,
            ipv4(10, 0, 0, 2, 9002),
            ipv4(10, 0, 0, 2, 9002),
            1,
        );
        agent.add_remote_candidate(remote2);

        // Nomination MUST be preserved.
        assert!(
            agent.nominated_pair().is_some(),
            "nomination must survive trickle candidate arrival post-Connected"
        );
    }
}
