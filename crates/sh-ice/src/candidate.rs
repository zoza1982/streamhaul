//! ICE candidate model — RFC 8445.
//!
//! A [`Candidate`] represents a transport address that an ICE agent may use to
//! reach a peer.  Three kinds are defined: [`CandidateKind::Host`] (a local
//! interface address), [`CandidateKind::ServerReflexive`] (an address discovered
//! via STUN from behind a NAT), and [`CandidateKind::Relay`] (an address
//! allocated at a TURN server).
//!
//! [`CandidatePair`] represents a (local, remote) tuple under evaluation.
//! Pair priority follows RFC 5245 §5.7.2.

use std::net::SocketAddr;

// ─── Candidate kinds ──────────────────────────────────────────────────────────

/// The kind of an ICE candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateKind {
    /// A candidate whose transport address is a local interface address.
    Host,
    /// A candidate discovered by sending STUN Binding Requests to a STUN server.
    ServerReflexive,
    /// A candidate obtained by allocating an address at a TURN relay server.
    Relay,
}

impl CandidateKind {
    /// RFC 5245 §4.1.2.2 — type preference values.
    #[must_use]
    pub fn type_preference(self) -> u32 {
        match self {
            CandidateKind::Host => 126,
            CandidateKind::ServerReflexive => 100,
            CandidateKind::Relay => 0,
        }
    }

    /// Single-character foundation prefix: `h`, `s`, or `r`.
    fn foundation_prefix(self) -> char {
        match self {
            CandidateKind::Host => 'h',
            CandidateKind::ServerReflexive => 's',
            CandidateKind::Relay => 'r',
        }
    }
}

// ─── Candidate ────────────────────────────────────────────────────────────────

/// An ICE candidate.
///
/// # Examples
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
/// use sh_ice::candidate::{Candidate, CandidateKind};
///
/// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000);
/// let c = Candidate::new(CandidateKind::Host, addr, addr, 1);
/// assert!(c.priority > 0);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The kind (host, srflx, relay).
    pub kind: CandidateKind,
    /// The public transport address of this candidate.
    pub addr: SocketAddr,
    /// The base address (local socket address from which packets are sent).
    pub base: SocketAddr,
    /// RFC 5245 §4.1.2.1 priority.
    pub priority: u32,
    /// RFC 5245 foundation string.
    pub foundation: String,
    /// Component ID (1 = RTP, 2 = RTCP; Streamhaul uses 1).
    pub component: u8,
}

impl Candidate {
    /// Create a new candidate, computing priority and foundation automatically.
    ///
    /// `local_preference` is 65535 for a single interface; use a lower value when
    /// multiple local interfaces are present so they can be differentiated.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// use sh_ice::candidate::{Candidate, CandidateKind};
    ///
    /// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5000);
    /// let c = Candidate::new(CandidateKind::Host, addr, addr, 1);
    /// assert_eq!(c.component, 1);
    /// ```
    #[must_use]
    pub fn new(kind: CandidateKind, addr: SocketAddr, base: SocketAddr, component: u8) -> Self {
        let local_preference = 65535u32;
        let priority = compute_priority(kind, local_preference, u32::from(component));
        let foundation = compute_foundation(kind, base);
        Self {
            kind,
            addr,
            base,
            priority,
            foundation,
            component,
        }
    }

    /// Create a candidate with an explicit local preference (for multi-homed hosts).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// use sh_ice::candidate::{Candidate, CandidateKind};
    ///
    /// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5000);
    /// let c = Candidate::with_local_preference(CandidateKind::Host, addr, addr, 1, 32768);
    /// assert!(c.priority > 0);
    /// ```
    #[must_use]
    pub fn with_local_preference(
        kind: CandidateKind,
        addr: SocketAddr,
        base: SocketAddr,
        component: u8,
        local_preference: u32,
    ) -> Self {
        let priority = compute_priority(kind, local_preference, u32::from(component));
        let foundation = compute_foundation(kind, base);
        Self {
            kind,
            addr,
            base,
            priority,
            foundation,
            component,
        }
    }
}

/// Compute RFC 5245 §4.1.2.1 candidate priority.
///
/// `priority = (2^24) * type_pref + (2^8) * local_pref + (256 - component_id)`
#[must_use]
pub fn compute_priority(kind: CandidateKind, local_preference: u32, component: u32) -> u32 {
    let type_pref = kind.type_preference();
    // Use saturating arithmetic to prevent overflow.
    let a = (1u32 << 24).saturating_mul(type_pref);
    let b = (1u32 << 8).saturating_mul(local_preference);
    let c = 256u32.saturating_sub(component);
    a.saturating_add(b).saturating_add(c)
}

/// Compute an RFC 5245 foundation string.
///
/// Foundation = `{prefix}{base_addr}` where prefix is `h`, `s`, or `r` and `base_addr`
/// is the `SocketAddr` Display form (`ip:port`), which avoids collisions between
/// addresses like `10.0.0.1:50` and `10.0.0.15:0`.
#[must_use]
pub fn compute_foundation(kind: CandidateKind, base: SocketAddr) -> String {
    format!("{}{}", kind.foundation_prefix(), base)
}

// ─── Candidate pair ───────────────────────────────────────────────────────────

/// State of a [`CandidatePair`] in the ICE check list (RFC 8445 §6.1.2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairState {
    /// The pair has not yet had a connectivity check scheduled.
    Waiting,
    /// A connectivity check is in progress.
    InProgress,
    /// The connectivity check succeeded.
    Succeeded,
    /// The connectivity check failed or timed out.
    Failed,
    /// The pair is frozen; it will not be checked until a trigger unfreezes it.
    Frozen,
}

/// A local-remote candidate pair under evaluation.
#[derive(Debug, Clone)]
pub struct CandidatePair {
    /// Stable identity assigned at pair creation.
    ///
    /// This ID survives check-list re-sorts; all in-flight and nominated remaps
    /// must use it instead of remote address alone, which is not unique when
    /// multiple local candidates share a remote (multi-homed host scenario).
    pub pair_id: u64,
    /// The local candidate.
    pub local: Candidate,
    /// The remote candidate.
    pub remote: Candidate,
    /// The current state of this pair in the check list.
    pub state: PairState,
    /// RFC 5245 §5.7.2 pair priority.
    pub priority: u64,
    /// Whether this pair has been nominated for use.
    pub nominated: bool,
    /// Round-trip time measured during connectivity checks, in microseconds.
    pub rtt_us: Option<u64>,
}

impl CandidatePair {
    /// Construct a candidate pair for the given role.
    ///
    /// `pair_id` must be a unique, stable identifier supplied by the caller
    /// (typically a monotonic counter on the owning [`crate::agent::IceAgent`]).
    /// It survives check-list re-sorts and is used by the agent to remap
    /// in-flight transactions and the nominated pair index after any sort.
    ///
    /// `is_controlling` determines which candidate is considered "G" (the
    /// controlling agent's candidate) in the RFC 5245 pair priority formula.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// use sh_ice::candidate::{Candidate, CandidatePair, CandidateKind};
    ///
    /// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000);
    /// let local = Candidate::new(CandidateKind::Host, addr, addr, 1);
    /// let remote = Candidate::new(CandidateKind::Host, addr, addr, 1);
    /// let pair = CandidatePair::new(1, local, remote, true);
    /// assert!(pair.priority > 0);
    /// ```
    #[must_use]
    pub fn new(pair_id: u64, local: Candidate, remote: Candidate, is_controlling: bool) -> Self {
        let priority = compute_pair_priority(local.priority, remote.priority, is_controlling);
        Self {
            pair_id,
            local,
            remote,
            state: PairState::Frozen,
            priority,
            nominated: false,
            rtt_us: None,
        }
    }
}

/// RFC 5245 §5.7.2 pair priority formula.
///
/// `priority = 2^32 * min(G, D) + 2 * max(G, D) + (G > D ? 1 : 0)`
///
/// where G is the controlling agent's candidate priority and D is the controlled
/// agent's candidate priority.
#[must_use]
pub fn compute_pair_priority(g: u32, d: u32, is_controlling: bool) -> u64 {
    let (controlling_p, controlled_p) = if is_controlling { (g, d) } else { (d, g) };
    let min_p = u64::from(controlling_p.min(controlled_p));
    let max_p = u64::from(controlling_p.max(controlled_p));
    let tie = if controlling_p > controlled_p {
        1u64
    } else {
        0u64
    };
    (1u64 << 32)
        .saturating_mul(min_p)
        .saturating_add(2u64.saturating_mul(max_p))
        .saturating_add(tie)
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

    fn ipv4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    #[test]
    fn host_priority_greater_than_srflx() {
        let host = Candidate::new(
            CandidateKind::Host,
            ipv4(10, 0, 0, 1, 5000),
            ipv4(10, 0, 0, 1, 5000),
            1,
        );
        let srflx = Candidate::new(
            CandidateKind::ServerReflexive,
            ipv4(1, 2, 3, 4, 5001),
            ipv4(10, 0, 0, 1, 5000),
            1,
        );
        let relay = Candidate::new(
            CandidateKind::Relay,
            ipv4(5, 6, 7, 8, 3478),
            ipv4(10, 0, 0, 1, 5000),
            1,
        );
        assert!(host.priority > srflx.priority, "host must beat srflx");
        assert!(srflx.priority > relay.priority, "srflx must beat relay");
    }

    #[test]
    fn pair_priority_ordering() {
        let a1 = ipv4(10, 0, 0, 1, 5000);
        let a2 = ipv4(1, 2, 3, 4, 5001);
        let high_local = Candidate::new(CandidateKind::Host, a1, a1, 1);
        let high_remote = Candidate::new(CandidateKind::Host, a2, a2, 1);
        let low_local = Candidate::new(CandidateKind::Relay, a1, a1, 1);
        let low_remote = Candidate::new(CandidateKind::Relay, a2, a2, 1);

        let high_pair = CandidatePair::new(1, high_local, high_remote, true);
        let low_pair = CandidatePair::new(2, low_local, low_remote, true);
        assert!(high_pair.priority > low_pair.priority);
    }

    #[test]
    fn foundation_differs_by_type() {
        let base = ipv4(10, 0, 0, 1, 5000);
        let host = Candidate::new(CandidateKind::Host, base, base, 1);
        let srflx = Candidate::new(
            CandidateKind::ServerReflexive,
            ipv4(1, 2, 3, 4, 9999),
            base,
            1,
        );
        assert_ne!(
            host.foundation, srflx.foundation,
            "same base but different type → different foundation"
        );
    }

    #[test]
    fn foundation_no_collision() {
        let base_a = ipv4(10, 0, 0, 1, 50);
        let base_b = ipv4(10, 0, 0, 15, 0);
        let f_a = compute_foundation(CandidateKind::Host, base_a);
        let f_b = compute_foundation(CandidateKind::Host, base_b);
        assert_ne!(f_a, f_b, "foundations must differ: {f_a} vs {f_b}");
    }
}
