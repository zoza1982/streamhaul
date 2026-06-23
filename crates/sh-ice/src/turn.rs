//! TURN client — RFC 8656 Allocate/Refresh/CreatePermission/ChannelBind/Send/Data.
//!
//! This module implements the TURN client-side message sequences needed to obtain a
//! relayed transport address (relay candidate) from a TURN server and relay data
//! through it.
//!
//! # Protocol overview
//!
//! ```text
//! Client                          TURN Server
//!   |---Allocate (no creds)---------->|
//!   |<--401 (realm, nonce)------------|
//!   |---Allocate (long-term cred)---->|
//!   |<--Allocate Success (relay addr)-|
//!   |
//!   |---CreatePermission(peer)------->|
//!   |<--CreatePermission Success------|
//!   |
//!   |---ChannelBind(ch, peer)-------->|
//!   |<--ChannelBind Success-----------|
//!   |
//!   |===ChannelData(ch, data)========>|===>peer
//!   peer===>|<==Data Indication(peer,data)==|
//! ```
//!
//! # Security
//!
//! All wire input enters through [`TurnMessage::decode`], which bounds-checks every
//! field before reading.  The long-term credential key is never logged; it is held
//! only for the lifetime of the allocation sequence.
//!
//! # Deployment deferral (R-COTURN-DEPLOY)
//!
//! The actual coturn server deployment and live TURN server communication are
//! deferred.  This client is tested exclusively against the in-process
//! [`sim_turn::SimTurnServer`] in the NAT simulator.  To connect to a real coturn
//! server, substitute a real [`UdpTransport`] socket; the protocol logic is
//! identical.
//!
//! # Examples
//!
//! ```
//! use sh_ice::turn::{TurnClient, TurnConfig};
//! use sh_ice::transport::{NatSimNetwork, NatType};
//! use sh_types::FixedClock;
//! use rand_core::OsRng;
//!
//! let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
//! let sock = net
//!     .create_socket(NatType::FullCone, "127.0.0.1:0".parse().unwrap())
//!     .unwrap();
//! let cfg = TurnConfig {
//!     server_addr: "10.0.0.1:3478".parse().unwrap(),
//!     username: "user".into(),
//!     password: "pass".into(),
//!     lifetime_secs: 600,
//! };
//! let _client = TurnClient::new(cfg, sock, FixedClock(0), OsRng);
//! ```

use std::net::SocketAddr;

use rand_core::RngCore;
use sh_types::Clock;
use subtle::ConstantTimeEq as _;

use crate::{error::IceError, transport::UdpTransport};

// ─── TURN method codes (RFC 8656) ─────────────────────────────────────────────

/// TURN Allocate method (0x003).
pub const METHOD_ALLOCATE: u16 = 0x003;
/// TURN Refresh method (0x004).
pub const METHOD_REFRESH: u16 = 0x004;
/// TURN Send indication method (0x006).
pub const METHOD_SEND: u16 = 0x006;
/// TURN Data indication method (0x007).
pub const METHOD_DATA: u16 = 0x007;
/// TURN CreatePermission method (0x008).
pub const METHOD_CREATE_PERMISSION: u16 = 0x008;
/// TURN ChannelBind method (0x009).
pub const METHOD_CHANNEL_BIND: u16 = 0x009;

// ─── TURN/STUN attribute type codes ──────────────────────────────────────────

/// USERNAME (0x0006).
const ATTR_USERNAME: u16 = 0x0006;
/// MESSAGE-INTEGRITY (0x0008).
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
/// ERROR-CODE (0x0009).
const ATTR_ERROR_CODE: u16 = 0x0009;
/// CHANNEL-NUMBER (0x000C).
const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
/// LIFETIME (0x000D).
const ATTR_LIFETIME: u16 = 0x000D;
/// XOR-PEER-ADDRESS (0x0012).
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
/// DATA (0x0013).
const ATTR_DATA: u16 = 0x0013;
/// REALM (0x0014).
const ATTR_REALM: u16 = 0x0014;
/// NONCE (0x0015).
const ATTR_NONCE: u16 = 0x0015;
/// XOR-RELAYED-ADDRESS (0x0016).
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
/// REQUESTED-TRANSPORT (0x0019).
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
/// XOR-MAPPED-ADDRESS (0x0020).
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

// ─── Wire constants ───────────────────────────────────────────────────────────

/// STUN magic cookie (RFC 8489 §6).
const MAGIC_COOKIE: u32 = 0x2112_A442;
/// STUN/TURN header length in bytes.
const STUN_HDR: usize = 20;
/// ChannelData header length in bytes.
const CHANNEL_HDR: usize = 4;
/// Minimum valid channel number per RFC 8656 §12.
pub const CHANNEL_MIN: u16 = 0x4000;
/// Maximum valid channel number per RFC 8656 §12.
pub const CHANNEL_MAX: u16 = 0x7FFF;

// ─── TURN client allocation state ────────────────────────────────────────────

/// State of the [`TurnClient`] allocation state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnState {
    /// No allocation exists.
    Unallocated,
    /// Unauthenticated Allocate request has been sent; awaiting 401 challenge.
    Allocating,
    /// Authenticated Allocate request sent; awaiting success response.
    AllocatingAuthenticated,
    /// Allocation is active and usable.
    Allocated,
    /// Refresh request is in flight.
    Refreshing,
    /// Allocation has expired or was explicitly released.
    Expired,
}

// ─── Configuration ────────────────────────────────────────────────────────────

/// Configuration for a [`TurnClient`].
///
/// # Security
///
/// The `password` field is never printed in `Debug` output.
#[derive(Clone)]
pub struct TurnConfig {
    /// The TURN server transport address.
    pub server_addr: SocketAddr,
    /// TURN username (coturn REST: `"<expiry>:<user_id>"`).
    pub username: String,
    /// TURN password.  Never logged.
    pub password: String,
    /// Requested allocation lifetime in seconds (coturn default: 3600 = 1h).
    pub lifetime_secs: u32,
}

impl std::fmt::Debug for TurnConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnConfig")
            .field("server_addr", &self.server_addr)
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .field("lifetime_secs", &self.lifetime_secs)
            .finish()
    }
}

// ─── TURN attribute ───────────────────────────────────────────────────────────

/// A decoded TURN/STUN attribute.
#[derive(Debug, Clone)]
pub enum TurnAttr {
    /// XOR-RELAYED-ADDRESS (0x0016): the relayed transport address.
    XorRelayedAddress(SocketAddr),
    /// XOR-PEER-ADDRESS (0x0012): a peer's transport address.
    XorPeerAddress(SocketAddr),
    /// XOR-MAPPED-ADDRESS (0x0020): the client's reflexive address.
    XorMappedAddress(SocketAddr),
    /// LIFETIME (0x000D): allocation lifetime in seconds.
    Lifetime(u32),
    /// CHANNEL-NUMBER (0x000C): channel number for ChannelBind.
    ChannelNumber(u16),
    /// DATA (0x0013): application data payload.
    Data(Vec<u8>),
    /// REALM (0x0014): authentication realm string.
    Realm(String),
    /// NONCE (0x0015): authentication nonce (opaque bytes).
    Nonce(Vec<u8>),
    /// ERROR-CODE (0x0009): numeric error code and reason phrase.
    ErrorCode {
        /// Numeric error code (e.g. 401, 437, 438, 442).
        code: u16,
        /// Human-readable reason phrase.
        reason: String,
    },
    /// REQUESTED-TRANSPORT (0x0019): IP protocol (17 = UDP).
    RequestedTransport(u8),
    /// USERNAME (0x0006).
    Username(String),
    /// MESSAGE-INTEGRITY (0x0008): raw 20-byte HMAC-SHA1.
    MessageIntegrity([u8; 20]),
    /// Any unrecognised attribute (passed through transparently).
    Unknown {
        /// Raw attribute type code.
        attr_type: u16,
        /// Raw value bytes (unpadded).
        value: Vec<u8>,
    },
}

// ─── TURN message ─────────────────────────────────────────────────────────────

/// A decoded TURN/STUN message.
///
/// The encoding follows the RFC 8489 §6 wire format; TURN methods (Allocate,
/// Refresh, etc.) are encoded with the same header as STUN Binding.
#[derive(Debug, Clone)]
pub struct TurnMessage {
    /// STUN/TURN method (e.g. [`METHOD_ALLOCATE`]).
    pub method: u16,
    /// STUN class (0 = Request, 1 = Indication, 2 = Success, 3 = Error).
    pub class: u8,
    /// 12-byte transaction ID.
    pub transaction_id: [u8; 12],
    /// Decoded attributes, in wire order.
    pub attrs: Vec<TurnAttr>,
}

impl TurnMessage {
    /// Decode a raw TURN/STUN message from bytes.
    ///
    /// All field accesses are bounds-checked; arbitrary hostile input cannot cause
    /// panics or out-of-bounds reads.
    ///
    /// # Errors
    ///
    /// - [`IceError::StunTruncated`] — buffer shorter than 20-byte header.
    /// - [`IceError::BadMagicCookie`] — wrong magic cookie.
    /// - [`IceError::InvalidMessageTypeBits`] — top two bits non-zero.
    /// - [`IceError::MessageLengthNotAligned`] — length not multiple of 4.
    /// - [`IceError::StunAttrTruncated`] — attribute value extends past buffer.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_ice::turn::{TurnMessage, METHOD_ALLOCATE};
    ///
    /// // 20-byte Allocate Request header (no attributes).
    /// let mut hdr = [0u8; 20];
    /// hdr[0] = 0x00; hdr[1] = 0x03; // Allocate Request type word
    /// hdr[4] = 0x21; hdr[5] = 0x12; hdr[6] = 0xA4; hdr[7] = 0x42; // magic cookie
    /// let msg = TurnMessage::decode(&hdr).unwrap();
    /// assert_eq!(msg.method, METHOD_ALLOCATE);
    /// assert_eq!(msg.class, 0);
    /// ```
    pub fn decode(raw: &[u8]) -> Result<Self, IceError> {
        if raw.len() < STUN_HDR {
            return Err(IceError::StunTruncated {
                needed: STUN_HDR,
                have: raw.len(),
            });
        }
        let type_word = u16::from_be_bytes([*raw.first().unwrap_or(&0), *raw.get(1).unwrap_or(&0)]);
        if type_word & 0xC000 != 0 {
            return Err(IceError::InvalidMessageTypeBits);
        }
        let msg_len = u16::from_be_bytes([*raw.get(2).unwrap_or(&0), *raw.get(3).unwrap_or(&0)]);
        if msg_len % 4 != 0 {
            return Err(IceError::MessageLengthNotAligned(msg_len));
        }
        let cookie = u32::from_be_bytes([
            *raw.get(4).unwrap_or(&0),
            *raw.get(5).unwrap_or(&0),
            *raw.get(6).unwrap_or(&0),
            *raw.get(7).unwrap_or(&0),
        ]);
        if cookie != MAGIC_COOKIE {
            return Err(IceError::BadMagicCookie(cookie));
        }

        // Extract method: M11..M7 at bits 13..9, M6..M4 at 7..5, M3..M0 at 3..0.
        let method = ((type_word >> 2) & 0xF80) | ((type_word >> 1) & 0x070) | (type_word & 0x00F);
        // Extract class: C1 at bit 8, C0 at bit 4.
        let c1 = (type_word >> 8) & 0x01;
        let c0 = (type_word >> 4) & 0x01;
        #[allow(clippy::cast_possible_truncation)]
        let class = ((c1 << 1) | c0) as u8;

        let tid_slice = raw.get(8..20).ok_or(IceError::StunTruncated {
            needed: 20,
            have: raw.len(),
        })?;
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(tid_slice);

        let total = STUN_HDR.saturating_add(usize::from(msg_len));
        if raw.len() < total {
            return Err(IceError::StunTruncated {
                needed: total,
                have: raw.len(),
            });
        }
        let attr_bytes = raw.get(STUN_HDR..total).ok_or(IceError::StunTruncated {
            needed: total,
            have: raw.len(),
        })?;

        let attrs = decode_attrs(attr_bytes, &transaction_id)?;
        Ok(Self {
            method,
            class,
            transaction_id,
            attrs,
        })
    }

    /// Encode this message to bytes without MESSAGE-INTEGRITY.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_ice::turn::{TurnMessage, METHOD_ALLOCATE};
    ///
    /// let msg = TurnMessage {
    ///     method: METHOD_ALLOCATE,
    ///     class: 0,
    ///     transaction_id: [0u8; 12],
    ///     attrs: vec![],
    /// };
    /// let bytes = msg.encode();
    /// assert_eq!(bytes.len(), 20);
    /// ```
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let attr_body = encode_attrs(&self.attrs, &self.transaction_id);
        build_header(
            self.method,
            self.class,
            &self.transaction_id,
            attr_body.len(),
        )
        .into_iter()
        .chain(attr_body)
        .collect()
    }

    /// Encode this message appending a long-term-credential MESSAGE-INTEGRITY.
    ///
    /// The long-term credential key is `MD5(username:realm:password)` per RFC 8489 §9.2.
    /// The MI covers all bytes up to but not including the MI attribute itself, with
    /// the header length field set to include the MI.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::Transport`] if HMAC construction fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_ice::turn::{TurnMessage, METHOD_ALLOCATE, long_term_key};
    ///
    /// let key = long_term_key("user", "realm", "pass");
    /// let msg = TurnMessage {
    ///     method: METHOD_ALLOCATE,
    ///     class: 0,
    ///     transaction_id: [1u8; 12],
    ///     attrs: vec![],
    /// };
    /// let bytes = msg.encode_with_integrity(&key).unwrap();
    /// TurnMessage::verify_integrity(&bytes, &key).unwrap();
    /// ```
    pub fn encode_with_integrity(&self, lt_key: &[u8]) -> Result<Vec<u8>, IceError> {
        let attr_body = encode_attrs(&self.attrs, &self.transaction_id);
        let mi_msg_len = attr_body.len().saturating_add(24);
        let mut out = build_header(self.method, self.class, &self.transaction_id, mi_msg_len);
        out.extend_from_slice(&attr_body);
        let hmac = hmac_sha1(lt_key, &out)?;
        out.extend_from_slice(&ATTR_MESSAGE_INTEGRITY.to_be_bytes());
        out.extend_from_slice(&20u16.to_be_bytes());
        out.extend_from_slice(&hmac);
        Ok(out)
    }

    /// Verify the MESSAGE-INTEGRITY in a raw encoded TURN/STUN message.
    ///
    /// # Errors
    ///
    /// - [`IceError::StunTruncated`] — buffer too short.
    /// - [`IceError::IntegrityMismatch`] — HMAC mismatch or no MI attribute.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_ice::turn::{TurnMessage, METHOD_ALLOCATE, long_term_key};
    ///
    /// let key = long_term_key("u", "r", "p");
    /// let msg = TurnMessage {
    ///     method: METHOD_ALLOCATE, class: 0,
    ///     transaction_id: [2u8; 12], attrs: vec![],
    /// };
    /// let bytes = msg.encode_with_integrity(&key).unwrap();
    /// assert!(TurnMessage::verify_integrity(&bytes, &key).is_ok());
    ///
    /// let bad = long_term_key("u", "r", "wrong");
    /// assert!(TurnMessage::verify_integrity(&bytes, &bad).is_err());
    /// ```
    pub fn verify_integrity(raw: &[u8], lt_key: &[u8]) -> Result<(), IceError> {
        let mi_off = find_attr(raw, ATTR_MESSAGE_INTEGRITY)?;
        // RFC 8489 §15.4: MI must be the last attribute, or followed only by FINGERPRINT (8 bytes, type 0x8028).
        let mi_end = mi_off.saturating_add(24);
        let msg_len = u16::from_be_bytes([*raw.get(2).unwrap_or(&0), *raw.get(3).unwrap_or(&0)]);
        let body_end = STUN_HDR.saturating_add(usize::from(msg_len));
        if mi_end < body_end {
            let trailer = raw.get(mi_end..body_end).unwrap_or(&[]);
            let is_only_fp =
                trailer.len() == 8 && trailer.get(0..2) == Some(&0x8028u16.to_be_bytes());
            if !is_only_fp {
                return Err(IceError::AttrOrderingViolation("MESSAGE-INTEGRITY"));
            }
        }
        let prefix = raw.get(..mi_off).ok_or(IceError::StunTruncated {
            needed: mi_off,
            have: raw.len(),
        })?;
        let hmac_msg_len = mi_off.saturating_add(24).saturating_sub(STUN_HDR);
        let mut buf = prefix.to_vec();
        #[allow(clippy::cast_possible_truncation)]
        let lb = (hmac_msg_len.min(usize::from(u16::MAX)) as u16).to_be_bytes();
        if let Some(f) = buf.get_mut(2..4) {
            f.copy_from_slice(&lb);
        }
        let expected = hmac_sha1(lt_key, &buf)?;
        let v_start = mi_off.saturating_add(4);
        let v_end = v_start.saturating_add(20);
        let stored_bytes = raw.get(v_start..v_end).ok_or(IceError::IntegrityMismatch)?;
        let stored: [u8; 20] = stored_bytes
            .try_into()
            .map_err(|_| IceError::IntegrityMismatch)?;
        if expected.ct_eq(&stored).into() {
            Ok(())
        } else {
            Err(IceError::IntegrityMismatch)
        }
    }

    // ─── Attribute accessors ──────────────────────────────────────────────────

    /// Return the first `XOR-RELAYED-ADDRESS`, if present.
    #[must_use]
    pub fn relay_address(&self) -> Option<SocketAddr> {
        self.attrs.iter().find_map(|a| {
            if let TurnAttr::XorRelayedAddress(addr) = a {
                Some(*addr)
            } else {
                None
            }
        })
    }

    /// Return the `REALM` string, if present.
    #[must_use]
    pub fn realm(&self) -> Option<&str> {
        self.attrs.iter().find_map(|a| {
            if let TurnAttr::Realm(r) = a {
                Some(r.as_str())
            } else {
                None
            }
        })
    }

    /// Return the `NONCE` bytes, if present.
    #[must_use]
    pub fn nonce(&self) -> Option<&[u8]> {
        self.attrs.iter().find_map(|a| {
            if let TurnAttr::Nonce(n) = a {
                Some(n.as_slice())
            } else {
                None
            }
        })
    }

    /// Return the numeric `ERROR-CODE`, if present.
    #[must_use]
    pub fn error_code(&self) -> Option<u16> {
        self.attrs.iter().find_map(|a| {
            if let TurnAttr::ErrorCode { code, .. } = a {
                Some(*code)
            } else {
                None
            }
        })
    }

    /// Return the `LIFETIME` in seconds, if present.
    #[must_use]
    pub fn lifetime(&self) -> Option<u32> {
        self.attrs.iter().find_map(|a| {
            if let TurnAttr::Lifetime(l) = a {
                Some(*l)
            } else {
                None
            }
        })
    }
}

// ─── Long-term credential key ─────────────────────────────────────────────────

/// Compute the RFC 8489 §9.2 long-term credential key:
/// `MD5(username ":" realm ":" password)`.
///
/// This is the only use of MD5 in Streamhaul and is mandated by the STUN/TURN RFCs.
/// The output is used exclusively as an HMAC-SHA1 key, not for any security-sensitive
/// hash comparison.
///
/// # Examples
///
/// ```
/// use sh_ice::turn::long_term_key;
///
/// let key = long_term_key("user", "realm.example.com", "password");
/// assert_eq!(key.len(), 16);
/// ```
#[must_use]
pub fn long_term_key(username: &str, realm: &str, password: &str) -> Vec<u8> {
    use md5::{Digest as _, Md5};
    let input = format!("{username}:{realm}:{password}");
    let mut h = Md5::new();
    h.update(input.as_bytes());
    h.finalize().to_vec()
}

// ─── TurnClient ───────────────────────────────────────────────────────────────

/// A TURN client implementing RFC 8656 Allocate/Refresh/CreatePermission/ChannelBind.
///
/// Uses injected [`UdpTransport`] and [`Clock`] — no real OS networking or wall-clock
/// reads occur, enabling deterministic hermetic testing.
///
/// # State machine
///
/// ```text
/// Unallocated
///   → Allocating            (start_allocate called)
///     → AllocatingAuthenticated  (401 challenge processed)
///       → Allocated         (success response processed)
///         → Refreshing      (send_refresh called)
///           → Allocated     (refresh success)
///         → Expired         (mark_expired / error response)
/// ```
///
/// # Examples
///
/// ```
/// use sh_ice::turn::{TurnClient, TurnConfig, TurnState};
/// use sh_ice::transport::{NatSimNetwork, NatType};
/// use sh_types::FixedClock;
/// use rand_core::OsRng;
///
/// let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
/// let sock = net
///     .create_socket(NatType::FullCone, "127.0.0.1:5001".parse().unwrap())
///     .unwrap();
/// let cfg = TurnConfig {
///     server_addr: "10.0.0.1:3478".parse().unwrap(),
///     username: "u".into(),
///     password: "p".into(),
///     lifetime_secs: 600,
/// };
/// let c = TurnClient::new(cfg, sock, FixedClock(0), OsRng);
/// assert_eq!(c.state(), TurnState::Unallocated);
/// ```
pub struct TurnClient<T, C, R>
where
    T: UdpTransport,
    C: Clock,
    R: RngCore,
{
    config: TurnConfig,
    transport: T,
    clock: C,
    rng: R,
    state: TurnState,
    relay_addr: Option<SocketAddr>,
    realm: Option<String>,
    nonce: Option<Vec<u8>>,
    /// RFC 8489 §9.2 long-term credential key (MD5 of username:realm:password).
    lt_key: Option<Vec<u8>>,
    expires_at: Option<i64>,
    pending_tid: Option<[u8; 12]>,
    /// Number of 401/438 auth retries attempted (capped at 2 per RFC 8489 §9.2).
    auth_attempts: u8,
}

impl<T, C, R> TurnClient<T, C, R>
where
    T: UdpTransport,
    C: Clock,
    R: RngCore,
{
    /// Create a new TURN client in [`TurnState::Unallocated`] state.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_ice::turn::{TurnClient, TurnConfig, TurnState};
    /// use sh_ice::transport::{NatSimNetwork, NatType};
    /// use sh_types::FixedClock;
    /// use rand_core::OsRng;
    ///
    /// let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
    /// let sock = net
    ///     .create_socket(NatType::FullCone, "127.0.0.1:5002".parse().unwrap())
    ///     .unwrap();
    /// let cfg = TurnConfig {
    ///     server_addr: "10.0.0.1:3478".parse().unwrap(),
    ///     username: "u".into(), password: "p".into(), lifetime_secs: 600,
    /// };
    /// let c = TurnClient::new(cfg, sock, FixedClock(0), OsRng);
    /// assert_eq!(c.state(), TurnState::Unallocated);
    /// ```
    #[must_use]
    pub fn new(config: TurnConfig, transport: T, clock: C, rng: R) -> Self {
        Self {
            config,
            transport,
            clock,
            rng,
            state: TurnState::Unallocated,
            relay_addr: None,
            realm: None,
            nonce: None,
            lt_key: None,
            expires_at: None,
            pending_tid: None,
            auth_attempts: 0,
        }
    }

    /// Current allocation state.
    #[must_use]
    pub fn state(&self) -> TurnState {
        self.state
    }

    /// The relayed transport address, if an allocation is active.
    #[must_use]
    pub fn relay_addr(&self) -> Option<SocketAddr> {
        self.relay_addr
    }

    /// Send the initial (unauthenticated) Allocate request to start the RFC 8656
    /// 401-challenge sequence.
    ///
    /// After calling this, feed incoming datagrams to [`Self::handle_incoming`] until
    /// [`Self::state`] is [`TurnState::Allocated`].
    ///
    /// # Errors
    ///
    /// Returns [`IceError::Transport`] if the underlying send fails.
    pub fn start_allocate(&mut self) -> Result<(), IceError> {
        self.state = TurnState::Allocating;
        let tid = self.gen_tid();
        self.pending_tid = Some(tid);
        let msg = TurnMessage {
            method: METHOD_ALLOCATE,
            class: 0,
            transaction_id: tid,
            attrs: vec![
                TurnAttr::RequestedTransport(17), // UDP
                TurnAttr::Lifetime(self.config.lifetime_secs),
            ],
        };
        self.transport
            .send_to(&msg.encode(), self.config.server_addr)
    }

    /// Send an authenticated Allocate, using the realm/nonce from the 401 challenge.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::CheckFailed`] if realm, nonce, or lt_key are not yet
    /// available, or [`IceError::Transport`] on send failure.
    pub fn send_authenticated_allocate(&mut self) -> Result<(), IceError> {
        let realm = self
            .realm
            .clone()
            .ok_or_else(|| IceError::CheckFailed("TURN realm not set".into()))?;
        let nonce = self
            .nonce
            .clone()
            .ok_or_else(|| IceError::CheckFailed("TURN nonce not set".into()))?;
        let lt_key = self
            .lt_key
            .clone()
            .ok_or_else(|| IceError::CheckFailed("TURN lt_key not set".into()))?;

        self.state = TurnState::AllocatingAuthenticated;
        let tid = self.gen_tid();
        self.pending_tid = Some(tid);
        let msg = TurnMessage {
            method: METHOD_ALLOCATE,
            class: 0,
            transaction_id: tid,
            attrs: vec![
                TurnAttr::RequestedTransport(17),
                TurnAttr::Lifetime(self.config.lifetime_secs),
                TurnAttr::Username(self.config.username.clone()),
                TurnAttr::Realm(realm),
                TurnAttr::Nonce(nonce),
            ],
        };
        let bytes = msg.encode_with_integrity(&lt_key)?;
        self.transport.send_to(&bytes, self.config.server_addr)
    }

    /// Send a Refresh request to extend the allocation lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::CheckFailed`] if not in [`TurnState::Allocated`].
    pub fn send_refresh(&mut self) -> Result<(), IceError> {
        if self.state != TurnState::Allocated {
            return Err(IceError::CheckFailed(
                "TURN Refresh requires Allocated state".into(),
            ));
        }
        let lt_key = self
            .lt_key
            .clone()
            .ok_or_else(|| IceError::CheckFailed("TURN lt_key not set".into()))?;
        let realm = self
            .realm
            .clone()
            .ok_or_else(|| IceError::CheckFailed("TURN realm not set".into()))?;
        let nonce = self
            .nonce
            .clone()
            .ok_or_else(|| IceError::CheckFailed("TURN nonce not set".into()))?;
        self.state = TurnState::Refreshing;
        let tid = self.gen_tid();
        self.pending_tid = Some(tid);
        let msg = TurnMessage {
            method: METHOD_REFRESH,
            class: 0,
            transaction_id: tid,
            attrs: vec![
                TurnAttr::Lifetime(self.config.lifetime_secs),
                TurnAttr::Username(self.config.username.clone()),
                TurnAttr::Realm(realm),
                TurnAttr::Nonce(nonce),
            ],
        };
        let bytes = msg.encode_with_integrity(&lt_key)?;
        self.transport.send_to(&bytes, self.config.server_addr)
    }

    /// Send a CreatePermission for `peer`, authorising the TURN server to accept
    /// packets from that peer and forward them to us.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::CheckFailed`] if not in [`TurnState::Allocated`].
    pub fn create_permission(&mut self, peer: SocketAddr) -> Result<(), IceError> {
        if self.state != TurnState::Allocated {
            return Err(IceError::CheckFailed(
                "TURN CreatePermission requires Allocated state".into(),
            ));
        }
        let lt_key = self
            .lt_key
            .clone()
            .ok_or_else(|| IceError::CheckFailed("TURN lt_key not set".into()))?;
        let realm = self
            .realm
            .clone()
            .ok_or_else(|| IceError::CheckFailed("TURN realm not set".into()))?;
        let nonce = self
            .nonce
            .clone()
            .ok_or_else(|| IceError::CheckFailed("TURN nonce not set".into()))?;
        let tid = self.gen_tid();
        let msg = TurnMessage {
            method: METHOD_CREATE_PERMISSION,
            class: 0,
            transaction_id: tid,
            attrs: vec![
                TurnAttr::XorPeerAddress(peer),
                TurnAttr::Username(self.config.username.clone()),
                TurnAttr::Realm(realm),
                TurnAttr::Nonce(nonce),
            ],
        };
        let bytes = msg.encode_with_integrity(&lt_key)?;
        self.transport.send_to(&bytes, self.config.server_addr)
    }

    /// Send a ChannelBind associating `channel` with `peer`.
    ///
    /// Valid channel numbers are `0x4000`–`0x7FFF` per RFC 8656 §12.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::CheckFailed`] if not allocated or channel number is out of
    /// the valid range.
    pub fn channel_bind(&mut self, channel: u16, peer: SocketAddr) -> Result<(), IceError> {
        if self.state != TurnState::Allocated {
            return Err(IceError::CheckFailed(
                "TURN ChannelBind requires Allocated state".into(),
            ));
        }
        if !(CHANNEL_MIN..=CHANNEL_MAX).contains(&channel) {
            return Err(IceError::CheckFailed(format!(
                "invalid TURN channel {channel:#06x}: must be {CHANNEL_MIN:#06x}–{CHANNEL_MAX:#06x}"
            )));
        }
        let lt_key = self
            .lt_key
            .clone()
            .ok_or_else(|| IceError::CheckFailed("TURN lt_key not set".into()))?;
        let realm = self
            .realm
            .clone()
            .ok_or_else(|| IceError::CheckFailed("TURN realm not set".into()))?;
        let nonce = self
            .nonce
            .clone()
            .ok_or_else(|| IceError::CheckFailed("TURN nonce not set".into()))?;
        let tid = self.gen_tid();
        let msg = TurnMessage {
            method: METHOD_CHANNEL_BIND,
            class: 0,
            transaction_id: tid,
            attrs: vec![
                TurnAttr::ChannelNumber(channel),
                TurnAttr::XorPeerAddress(peer),
                TurnAttr::Username(self.config.username.clone()),
                TurnAttr::Realm(realm),
                TurnAttr::Nonce(nonce),
            ],
        };
        let bytes = msg.encode_with_integrity(&lt_key)?;
        self.transport.send_to(&bytes, self.config.server_addr)
    }

    /// Send a Send indication relaying `data` to `peer` via the TURN server.
    ///
    /// Send indications are not authenticated (RFC 8656 §10).
    ///
    /// # Errors
    ///
    /// Returns [`IceError::CheckFailed`] if not allocated.
    pub fn send_indication(&mut self, peer: SocketAddr, data: &[u8]) -> Result<(), IceError> {
        if self.state != TurnState::Allocated {
            return Err(IceError::CheckFailed(
                "TURN Send indication requires Allocated state".into(),
            ));
        }
        let tid = self.gen_tid();
        let msg = TurnMessage {
            method: METHOD_SEND,
            class: 1, // Indication
            transaction_id: tid,
            attrs: vec![
                TurnAttr::XorPeerAddress(peer),
                TurnAttr::Data(data.to_vec()),
            ],
        };
        self.transport
            .send_to(&msg.encode(), self.config.server_addr)
    }

    /// Encode `data` as a ChannelData frame for the given channel number.
    ///
    /// Format: `channel(2) | length(2) | data(length)` padded to 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::CheckFailed`] if `channel` is outside `0x4000`–`0x7FFF`.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_ice::turn::TurnClient;
    /// use sh_ice::transport::{NatSimNetwork, NatType};
    /// use sh_types::FixedClock;
    /// use rand_core::OsRng;
    ///
    /// let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
    /// let sock = net.create_socket(NatType::FullCone, "127.0.0.1:5010".parse().unwrap()).unwrap();
    /// let cfg = sh_ice::turn::TurnConfig {
    ///     server_addr: "10.0.0.1:3478".parse().unwrap(),
    ///     username: "u".into(), password: "p".into(), lifetime_secs: 600,
    /// };
    /// let _client = TurnClient::new(cfg, sock, FixedClock(0), OsRng);
    ///
    /// let frame = TurnClient::<sh_ice::transport::SimSocket, FixedClock, OsRng>::build_channel_data(0x4000, b"hello").unwrap();
    /// assert_eq!(&frame[..2], &[0x40, 0x00]);
    /// ```
    pub fn build_channel_data(channel: u16, data: &[u8]) -> Result<Vec<u8>, IceError> {
        if !(CHANNEL_MIN..=CHANNEL_MAX).contains(&channel) {
            return Err(IceError::CheckFailed(format!(
                "invalid channel {channel:#06x}"
            )));
        }
        let len = data.len();
        let pad = len.wrapping_neg() & 3;
        let mut out = Vec::with_capacity(CHANNEL_HDR.saturating_add(len).saturating_add(pad));
        out.extend_from_slice(&channel.to_be_bytes());
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(len.min(usize::from(u16::MAX)) as u16).to_be_bytes());
        out.extend_from_slice(data);
        match pad {
            1 => out.extend_from_slice(&[0u8; 1]),
            2 => out.extend_from_slice(&[0u8; 2]),
            3 => out.extend_from_slice(&[0u8; 3]),
            _ => {}
        }
        Ok(out)
    }

    /// Decode a ChannelData frame, returning `(channel, data)`.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::StunTruncated`] if the frame is too short.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_ice::turn::TurnClient;
    /// use sh_ice::transport::{NatSimNetwork, NatType, SimSocket};
    /// use sh_types::FixedClock;
    /// use rand_core::OsRng;
    ///
    /// let frame = TurnClient::<SimSocket, FixedClock, OsRng>::build_channel_data(0x4001, b"world").unwrap();
    /// let (ch, data) = TurnClient::<SimSocket, FixedClock, OsRng>::decode_channel_data(&frame).unwrap();
    /// assert_eq!(ch, 0x4001);
    /// assert_eq!(data, b"world");
    /// ```
    pub fn decode_channel_data(raw: &[u8]) -> Result<(u16, &[u8]), IceError> {
        if raw.len() < CHANNEL_HDR {
            return Err(IceError::StunTruncated {
                needed: CHANNEL_HDR,
                have: raw.len(),
            });
        }
        let channel = u16::from_be_bytes([*raw.first().unwrap_or(&0), *raw.get(1).unwrap_or(&0)]);
        let len = usize::from(u16::from_be_bytes([
            *raw.get(2).unwrap_or(&0),
            *raw.get(3).unwrap_or(&0),
        ]));
        let end = CHANNEL_HDR.saturating_add(len);
        if raw.len() < end {
            return Err(IceError::StunTruncated {
                needed: end,
                have: raw.len(),
            });
        }
        let data = raw.get(CHANNEL_HDR..end).ok_or(IceError::StunTruncated {
            needed: end,
            have: raw.len(),
        })?;
        Ok((channel, data))
    }

    /// Process an incoming datagram from the TURN server, driving the state machine.
    ///
    /// - 401 Unauthorized → computes lt_key, sends authenticated Allocate.
    /// - 438 Stale Nonce → updates nonce, retries authenticated Allocate.
    /// - Allocate/Refresh Success → updates relay address and `expires_at`.
    /// - CreatePermission/ChannelBind Success → acknowledged silently.
    /// - Data indication → decoded and returned for the ICE layer.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::CheckFailed`] on unexpected TURN error responses.
    pub fn handle_incoming(
        &mut self,
        raw: &[u8],
    ) -> Result<Option<(SocketAddr, Vec<u8>)>, IceError> {
        let msg = match TurnMessage::decode(raw) {
            Ok(m) => m,
            Err(_) => return Ok(None), // not a STUN/TURN message
        };

        // Verify transaction ID for responses to prevent replay/stale-response acceptance.
        if msg.class == 2 || msg.class == 3 {
            if let Some(expected_tid) = self.pending_tid {
                if msg.transaction_id != expected_tid {
                    return Ok(None); // stale/replayed response — drop
                }
            }
        }

        // RFC 8489 §9.2: verify MESSAGE-INTEGRITY on authenticated responses.
        // 401/438 error responses are auth challenges — they never carry MI per spec.
        // Indications (class 1) are not request/response transactions and are not signed.
        let is_auth_challenge = msg.class == 3 && matches!(msg.error_code(), Some(401) | Some(438));
        let is_indication = msg.class == 1;
        if !is_auth_challenge && !is_indication {
            if let Some(ref key) = self.lt_key.clone() {
                if TurnMessage::verify_integrity(raw, key).is_err() {
                    return Ok(None); // forged/invalid — drop silently
                }
            }
        }

        match (msg.method, msg.class) {
            (METHOD_ALLOCATE, 2) => {
                // Allocate Success.
                if let Some(relay) = msg.relay_address() {
                    self.relay_addr = Some(relay);
                }
                let lifetime = msg.lifetime().unwrap_or(self.config.lifetime_secs);
                self.expires_at = Some(
                    self.clock
                        .now_unix_secs()
                        .saturating_add(i64::from(lifetime)),
                );
                self.state = TurnState::Allocated;
            }
            (METHOD_ALLOCATE, 3) => {
                let code = msg.error_code().unwrap_or(0);
                if code == 401 || code == 438 {
                    // Cap auth attempts to prevent infinite retry loops (RFC 8489 §9.2).
                    // Allow exactly one retry: the first 401 (to the unauthenticated request)
                    // is expected; a second 401 (to the authenticated retry) means bad creds.
                    if self.auth_attempts >= 1 {
                        self.state = TurnState::Expired;
                        return Err(IceError::CheckFailed(
                            "TURN auth failed: too many retries".into(),
                        ));
                    }
                    self.auth_attempts = self.auth_attempts.saturating_add(1);
                }
                if code == 401 {
                    if let Some(r) = msg.realm() {
                        self.realm = Some(r.to_owned());
                    }
                    if let Some(n) = msg.nonce() {
                        self.nonce = Some(n.to_vec());
                    }
                    if let (Some(realm), Some(_)) = (self.realm.as_deref(), &self.nonce) {
                        let key =
                            long_term_key(&self.config.username, realm, &self.config.password);
                        self.lt_key = Some(key);
                    }
                    self.send_authenticated_allocate()?;
                } else if code == 438 {
                    // Stale nonce — update nonce and retry.
                    if let Some(n) = msg.nonce() {
                        self.nonce = Some(n.to_vec());
                    }
                    self.send_authenticated_allocate()?;
                } else {
                    self.state = TurnState::Expired;
                    return Err(IceError::CheckFailed(format!("TURN Allocate error {code}")));
                }
            }
            (METHOD_REFRESH, 2) => {
                let lifetime = msg.lifetime().unwrap_or(self.config.lifetime_secs);
                self.expires_at = Some(
                    self.clock
                        .now_unix_secs()
                        .saturating_add(i64::from(lifetime)),
                );
                self.state = TurnState::Allocated;
            }
            (METHOD_REFRESH, 3) => {
                self.state = TurnState::Expired;
                return Err(IceError::CheckFailed("TURN Refresh rejected".into()));
            }
            (METHOD_DATA, 1) => {
                // Data indication: extract (peer_addr, data) and return for ICE layer.
                let peer = msg.attrs.iter().find_map(|a| {
                    if let TurnAttr::XorPeerAddress(p) = a {
                        Some(*p)
                    } else {
                        None
                    }
                });
                let data = msg.attrs.iter().find_map(|a| {
                    if let TurnAttr::Data(d) = a {
                        Some(d.clone())
                    } else {
                        None
                    }
                });
                if let (Some(peer_addr), Some(payload)) = (peer, data) {
                    return Ok(Some((peer_addr, payload)));
                }
            }
            // CreatePermission, ChannelBind success/error — acknowledged silently.
            _ => {}
        }

        Ok(None)
    }

    /// Return `true` if the allocation lifetime has elapsed according to the injected clock.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => self.clock.now_unix_secs() >= exp,
            None => false,
        }
    }

    /// Transition to [`TurnState::Expired`] and clear the relay address.
    pub fn mark_expired(&mut self) {
        self.state = TurnState::Expired;
        self.relay_addr = None;
    }

    /// Receive one datagram from the underlying transport socket.
    ///
    /// Used by the integration-test relay step loop to drain Data Indications from
    /// the TURN server and feed them to [`Self::handle_incoming`].  The transport
    /// field is private so this thin accessor is provided only for test contexts.
    #[cfg(test)]
    pub fn recv_one(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, std::net::SocketAddr), crate::error::IceError> {
        self.transport.recv_from(buf)
    }

    fn gen_tid(&mut self) -> [u8; 12] {
        let mut tid = [0u8; 12];
        self.rng.fill_bytes(&mut tid);
        tid
    }
}

// ─── Codec helpers ────────────────────────────────────────────────────────────

fn build_header(method: u16, class: u8, tid: &[u8; 12], attr_len: usize) -> Vec<u8> {
    // Interleave method bits and class bits per RFC 8489 §6.
    let c1 = u16::from((class >> 1) & 1);
    let c0 = u16::from(class & 1);
    let m_bits = ((method & 0xF80) << 2) | ((method & 0x070) << 1) | (method & 0x00F);
    let type_word = m_bits | (c1 << 8) | (c0 << 4);

    let mut out = Vec::with_capacity(STUN_HDR);
    out.extend_from_slice(&type_word.to_be_bytes());
    #[allow(clippy::cast_possible_truncation)]
    out.extend_from_slice(&(attr_len.min(usize::from(u16::MAX)) as u16).to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(tid);
    out
}

fn encode_attrs(attrs: &[TurnAttr], tid: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::new();
    for attr in attrs {
        encode_one_attr(attr, tid, &mut out);
    }
    out
}

fn encode_one_attr(attr: &TurnAttr, tid: &[u8; 12], buf: &mut Vec<u8>) {
    match attr {
        TurnAttr::XorRelayedAddress(a) => {
            push_tlv(buf, ATTR_XOR_RELAYED_ADDRESS, &xor_addr(*a, tid))
        }
        TurnAttr::XorPeerAddress(a) => push_tlv(buf, ATTR_XOR_PEER_ADDRESS, &xor_addr(*a, tid)),
        TurnAttr::XorMappedAddress(a) => push_tlv(buf, ATTR_XOR_MAPPED_ADDRESS, &xor_addr(*a, tid)),
        TurnAttr::Lifetime(s) => push_tlv(buf, ATTR_LIFETIME, &s.to_be_bytes()),
        TurnAttr::ChannelNumber(ch) => {
            // CHANNEL-NUMBER is 4 bytes: channel(2) + RFFU(2).
            let mut v = ch.to_be_bytes().to_vec();
            v.extend_from_slice(&[0u8, 0u8]);
            push_tlv(buf, ATTR_CHANNEL_NUMBER, &v);
        }
        TurnAttr::Data(d) => push_tlv(buf, ATTR_DATA, d),
        TurnAttr::Realm(r) => push_tlv(buf, ATTR_REALM, r.as_bytes()),
        TurnAttr::Nonce(n) => push_tlv(buf, ATTR_NONCE, n),
        TurnAttr::ErrorCode { code, reason } => {
            #[allow(clippy::cast_possible_truncation)]
            let class_byte = (code / 100) as u8;
            #[allow(clippy::cast_possible_truncation)]
            let num_byte = (code % 100) as u8;
            let mut v = vec![0u8, 0u8, class_byte, num_byte];
            v.extend_from_slice(reason.as_bytes());
            push_tlv(buf, ATTR_ERROR_CODE, &v);
        }
        TurnAttr::RequestedTransport(proto) => {
            push_tlv(buf, ATTR_REQUESTED_TRANSPORT, &[*proto, 0, 0, 0]);
        }
        TurnAttr::Username(u) => push_tlv(buf, ATTR_USERNAME, u.as_bytes()),
        TurnAttr::MessageIntegrity(h) => push_tlv(buf, ATTR_MESSAGE_INTEGRITY, h.as_slice()),
        TurnAttr::Unknown { attr_type, value } => push_tlv(buf, *attr_type, value),
    }
}

fn xor_addr(addr: SocketAddr, tid: &[u8; 12]) -> Vec<u8> {
    use std::net::{IpAddr, SocketAddr as SA};
    let mut v = Vec::new();
    match addr {
        SA::V4(a) => {
            #[allow(clippy::cast_possible_truncation)]
            let xport = a.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            let xip = u32::from_be_bytes(a.ip().octets()) ^ MAGIC_COOKIE;
            v.push(0);
            v.push(1);
            v.extend_from_slice(&xport.to_be_bytes());
            v.extend_from_slice(&xip.to_be_bytes());
        }
        SA::V6(a) => {
            #[allow(clippy::cast_possible_truncation)]
            let xport = a.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            let raw = a.ip().octets();
            let mc = MAGIC_COOKIE.to_be_bytes();
            let mut mask = [0u8; 16];
            if let Some(d) = mask.get_mut(..4) {
                d.copy_from_slice(&mc);
            }
            if let Some(d) = mask.get_mut(4..) {
                d.copy_from_slice(tid);
            }
            let mut xa = [0u8; 16];
            for (o, (r, m)) in xa.iter_mut().zip(raw.iter().zip(mask.iter())) {
                *o = r ^ m;
            }
            v.push(0);
            v.push(2);
            v.extend_from_slice(&xport.to_be_bytes());
            v.extend_from_slice(&xa);
        }
    }
    let _ = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST); // ensure IpAddr is used
    v
}

fn decode_attrs(attr_bytes: &[u8], tid: &[u8; 12]) -> Result<Vec<TurnAttr>, IceError> {
    let mut attrs = Vec::new();
    let mut pos = 0usize;
    while pos < attr_bytes.len() {
        if attr_bytes.len().saturating_sub(pos) < 4 {
            return Err(IceError::StunTruncated {
                needed: pos.saturating_add(4),
                have: attr_bytes.len().saturating_add(STUN_HDR),
            });
        }
        let at = u16::from_be_bytes([
            *attr_bytes.get(pos).unwrap_or(&0),
            *attr_bytes.get(pos.saturating_add(1)).unwrap_or(&0),
        ]);
        let al = usize::from(u16::from_be_bytes([
            *attr_bytes.get(pos.saturating_add(2)).unwrap_or(&0),
            *attr_bytes.get(pos.saturating_add(3)).unwrap_or(&0),
        ]));
        let v_start = pos.saturating_add(4);
        let v_end = v_start.saturating_add(al);
        if v_end > attr_bytes.len() {
            return Err(IceError::StunAttrTruncated { attr_type: at });
        }
        let value = attr_bytes
            .get(v_start..v_end)
            .ok_or(IceError::StunAttrTruncated { attr_type: at })?;
        attrs.push(decode_one_attr(at, value, tid)?);
        let padded = (al.saturating_add(3)) & !3;
        pos = v_start.saturating_add(padded);
    }
    Ok(attrs)
}

fn decode_one_attr(at: u16, value: &[u8], tid: &[u8; 12]) -> Result<TurnAttr, IceError> {
    match at {
        ATTR_XOR_RELAYED_ADDRESS => Ok(TurnAttr::XorRelayedAddress(dxor_addr(value, tid, at)?)),
        ATTR_XOR_PEER_ADDRESS => Ok(TurnAttr::XorPeerAddress(dxor_addr(value, tid, at)?)),
        ATTR_XOR_MAPPED_ADDRESS => Ok(TurnAttr::XorMappedAddress(dxor_addr(value, tid, at)?)),
        ATTR_LIFETIME => {
            let s = u32::from_be_bytes(
                value
                    .get(..4)
                    .ok_or(IceError::StunAttrTruncated { attr_type: at })?
                    .try_into()
                    .map_err(|_| IceError::StunAttrTruncated { attr_type: at })?,
            );
            Ok(TurnAttr::Lifetime(s))
        }
        ATTR_CHANNEL_NUMBER => {
            if value.len() < 2 {
                return Err(IceError::StunAttrTruncated { attr_type: at });
            }
            let ch =
                u16::from_be_bytes([*value.first().unwrap_or(&0), *value.get(1).unwrap_or(&0)]);
            Ok(TurnAttr::ChannelNumber(ch))
        }
        ATTR_DATA => Ok(TurnAttr::Data(value.to_vec())),
        ATTR_REALM => Ok(TurnAttr::Realm(String::from_utf8_lossy(value).into_owned())),
        ATTR_NONCE => Ok(TurnAttr::Nonce(value.to_vec())),
        ATTR_ERROR_CODE => {
            if value.len() < 4 {
                return Err(IceError::StunAttrTruncated { attr_type: at });
            }
            let class = u16::from(*value.get(2).unwrap_or(&0));
            let num = u16::from(*value.get(3).unwrap_or(&0));
            let code = class.saturating_mul(100).saturating_add(num);
            let reason = String::from_utf8_lossy(value.get(4..).unwrap_or(&[])).into_owned();
            Ok(TurnAttr::ErrorCode { code, reason })
        }
        ATTR_REQUESTED_TRANSPORT => Ok(TurnAttr::RequestedTransport(
            *value
                .first()
                .ok_or(IceError::StunAttrTruncated { attr_type: at })?,
        )),
        ATTR_USERNAME => {
            let s = String::from_utf8(value.to_vec())
                .map_err(|_| IceError::StunAttrTruncated { attr_type: at })?;
            Ok(TurnAttr::Username(s))
        }
        ATTR_MESSAGE_INTEGRITY => {
            if value.len() < 20 {
                return Err(IceError::StunAttrTruncated { attr_type: at });
            }
            let mut h = [0u8; 20];
            h.copy_from_slice(
                value
                    .get(..20)
                    .ok_or(IceError::StunAttrTruncated { attr_type: at })?,
            );
            Ok(TurnAttr::MessageIntegrity(h))
        }
        other => Ok(TurnAttr::Unknown {
            attr_type: other,
            value: value.to_vec(),
        }),
    }
}

fn dxor_addr(value: &[u8], tid: &[u8; 12], at: u16) -> Result<SocketAddr, IceError> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    if value.len() < 4 {
        return Err(IceError::StunAttrTruncated { attr_type: at });
    }
    let family = *value.get(1).unwrap_or(&0);
    let xport = u16::from_be_bytes([*value.get(2).unwrap_or(&0), *value.get(3).unwrap_or(&0)]);
    #[allow(clippy::cast_possible_truncation)]
    let port = xport ^ ((MAGIC_COOKIE >> 16) as u16);
    match family {
        1 => {
            if value.len() < 8 {
                return Err(IceError::StunAttrTruncated { attr_type: at });
            }
            let xip: [u8; 4] = value
                .get(4..8)
                .ok_or(IceError::StunAttrTruncated { attr_type: at })?
                .try_into()
                .map_err(|_| IceError::StunAttrTruncated { attr_type: at })?;
            let ip = u32::from_be_bytes(xip) ^ MAGIC_COOKIE;
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(ip.to_be_bytes())),
                port,
            ))
        }
        2 => {
            if value.len() < 20 {
                return Err(IceError::StunAttrTruncated { attr_type: at });
            }
            let xip = value
                .get(4..20)
                .ok_or(IceError::StunAttrTruncated { attr_type: at })?;
            let mc = MAGIC_COOKIE.to_be_bytes();
            let mut mask = [0u8; 16];
            if let Some(d) = mask.get_mut(..4) {
                d.copy_from_slice(&mc);
            }
            if let Some(d) = mask.get_mut(4..) {
                d.copy_from_slice(tid);
            }
            let mut ab = [0u8; 16];
            for (o, (x, m)) in ab.iter_mut().zip(xip.iter().zip(mask.iter())) {
                *o = x ^ m;
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ab)), port))
        }
        _ => Err(IceError::StunAttrTruncated { attr_type: at }),
    }
}

fn push_tlv(buf: &mut Vec<u8>, at: u16, value: &[u8]) {
    buf.extend_from_slice(&at.to_be_bytes());
    #[allow(clippy::cast_possible_truncation)]
    buf.extend_from_slice(&(value.len().min(usize::from(u16::MAX)) as u16).to_be_bytes());
    buf.extend_from_slice(value);
    let pad = value.len().wrapping_neg() & 3;
    match pad {
        1 => buf.extend_from_slice(&[0u8; 1]),
        2 => buf.extend_from_slice(&[0u8; 2]),
        3 => buf.extend_from_slice(&[0u8; 3]),
        _ => {}
    }
}

fn find_attr(raw: &[u8], target: u16) -> Result<usize, IceError> {
    if raw.len() < STUN_HDR {
        return Err(IceError::StunTruncated {
            needed: STUN_HDR,
            have: raw.len(),
        });
    }
    let ml = usize::from(u16::from_be_bytes([
        *raw.get(2).unwrap_or(&0),
        *raw.get(3).unwrap_or(&0),
    ]));
    let total = STUN_HDR.saturating_add(ml);
    let ab = raw.get(STUN_HDR..total).ok_or(IceError::StunTruncated {
        needed: total,
        have: raw.len(),
    })?;
    let mut pos = 0usize;
    while pos.saturating_add(4) <= ab.len() {
        let t = u16::from_be_bytes([
            *ab.get(pos).unwrap_or(&0),
            *ab.get(pos.saturating_add(1)).unwrap_or(&0),
        ]);
        let l = usize::from(u16::from_be_bytes([
            *ab.get(pos.saturating_add(2)).unwrap_or(&0),
            *ab.get(pos.saturating_add(3)).unwrap_or(&0),
        ]));
        let ve = pos.saturating_add(4).saturating_add(l);
        if ve > ab.len() {
            return Err(IceError::StunAttrTruncated { attr_type: t });
        }
        if t == target {
            return Ok(STUN_HDR.saturating_add(pos));
        }
        pos = pos
            .saturating_add(4)
            .saturating_add((l.saturating_add(3)) & !3);
    }
    Err(IceError::IntegrityMismatch)
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<[u8; 20], IceError> {
    use hmac::Mac as _;
    use sha1::Sha1;
    type H = hmac::Hmac<Sha1>;
    let mut mac =
        H::new_from_slice(key).map_err(|e| IceError::Transport(format!("HMAC-SHA1: {e}")))?;
    mac.update(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}

// ─── Simulated TURN server (test-only) ────────────────────────────────────────

/// Minimal in-process TURN server for hermetic integration testing.
///
/// Implements the Allocate (401 challenge + success), Refresh, CreatePermission,
/// ChannelBind, and Send/Data indication relay paths — enough to exercise
/// [`TurnClient`] and the ICE relay path in [`crate::agent`] tests.
///
/// This is `#[cfg(test)]` only.  It is not a production TURN server.
#[cfg(test)]
pub mod sim_turn {
    use std::{
        collections::{HashMap, HashSet, VecDeque},
        net::{IpAddr, SocketAddr},
        sync::{Arc, Mutex},
    };

    use crate::{
        error::IceError,
        transport::{NatSimNetwork, NatType, SimSocket, UdpTransport},
    };

    use super::{
        long_term_key, TurnAttr, TurnMessage, TurnMessage as Msg, METHOD_ALLOCATE,
        METHOD_CHANNEL_BIND, METHOD_CREATE_PERMISSION, METHOD_DATA, METHOD_REFRESH, METHOD_SEND,
    };

    /// Per-client allocation record.
    #[derive(Clone)]
    pub struct Allocation {
        /// The relayed transport address assigned to this client.
        pub relay_addr: SocketAddr,
        /// IP-level permissions: set of peer IPs allowed to send through the relay.
        pub permissions: HashSet<IpAddr>,
        /// Channel bindings: channel number → peer SocketAddr.
        pub channels: HashMap<u16, SocketAddr>,
    }

    struct Inner {
        username: String,
        password: String,
        realm: String,
        nonce: Vec<u8>,
        allocations: HashMap<SocketAddr, Allocation>,
        next_relay_port: u16,
        relay_ip: IpAddr,
        outbox: VecDeque<(Vec<u8>, SocketAddr)>,
    }

    impl Inner {
        #[allow(clippy::panic)]
        fn next_relay(&mut self) -> SocketAddr {
            loop {
                let p = self.next_relay_port;
                // Advance, clamping below 40_000 back up to 40_000 on wrap.
                self.next_relay_port = self.next_relay_port.wrapping_add(1).max(40_000);
                let addr = SocketAddr::new(self.relay_ip, p);
                // Skip ports already allocated to active relay addresses.
                if !self.allocations.values().any(|a| a.relay_addr == addr) {
                    return addr;
                }
                // If next_relay_port wraps all the way back to current p, all ports exhausted.
                if self.next_relay_port == p {
                    panic!("SimTurnServer: relay port space exhausted");
                }
            }
        }

        fn process(&mut self, raw: &[u8], src: SocketAddr) {
            let msg = match Msg::decode(raw) {
                Ok(m) => m,
                Err(_) => return,
            };
            match (msg.method, msg.class) {
                (METHOD_ALLOCATE, 0) => self.do_allocate(raw, &msg, src),
                (METHOD_REFRESH, 0) => self.do_refresh(&msg, src),
                (METHOD_CREATE_PERMISSION, 0) => self.do_create_permission(&msg, src),
                (METHOD_CHANNEL_BIND, 0) => self.do_channel_bind(&msg, src),
                (METHOD_SEND, 1) => self.do_send_indication(&msg, src),
                _ => {}
            }
        }

        fn do_allocate(&mut self, raw: &[u8], msg: &TurnMessage, src: SocketAddr) {
            let has_creds = msg.attrs.iter().any(|a| matches!(a, TurnAttr::Username(_)));
            if !has_creds {
                let resp = Msg {
                    method: METHOD_ALLOCATE,
                    class: 3,
                    transaction_id: msg.transaction_id,
                    attrs: vec![
                        TurnAttr::ErrorCode {
                            code: 401,
                            reason: "Unauthorized".into(),
                        },
                        TurnAttr::Realm(self.realm.clone()),
                        TurnAttr::Nonce(self.nonce.clone()),
                    ],
                };
                self.outbox.push_back((resp.encode(), src));
                return;
            }

            let username = msg.attrs.iter().find_map(|a| {
                if let TurnAttr::Username(u) = a {
                    Some(u.clone())
                } else {
                    None
                }
            });
            let realm = msg.attrs.iter().find_map(|a| {
                if let TurnAttr::Realm(r) = a {
                    Some(r.clone())
                } else {
                    None
                }
            });

            let (Some(uname), Some(realm_str)) = (username, realm) else {
                return;
            };
            if uname != self.username {
                let resp = Msg {
                    method: METHOD_ALLOCATE,
                    class: 3,
                    transaction_id: msg.transaction_id,
                    attrs: vec![TurnAttr::ErrorCode {
                        code: 441,
                        reason: "Wrong credentials".into(),
                    }],
                };
                self.outbox.push_back((resp.encode(), src));
                return;
            }

            let lt_key = long_term_key(&uname, &realm_str, &self.password);
            if TurnMessage::verify_integrity(raw, &lt_key).is_err() {
                let resp = Msg {
                    method: METHOD_ALLOCATE,
                    class: 3,
                    transaction_id: msg.transaction_id,
                    attrs: vec![TurnAttr::ErrorCode {
                        code: 401,
                        reason: "Bad MI".into(),
                    }],
                };
                self.outbox.push_back((resp.encode(), src));
                return;
            }

            let relay_addr = self.next_relay();
            self.allocations.insert(
                src,
                Allocation {
                    relay_addr,
                    permissions: HashSet::new(),
                    channels: HashMap::new(),
                },
            );

            let resp = Msg {
                method: METHOD_ALLOCATE,
                class: 2,
                transaction_id: msg.transaction_id,
                attrs: vec![
                    TurnAttr::XorRelayedAddress(relay_addr),
                    TurnAttr::XorMappedAddress(src),
                    TurnAttr::Lifetime(600),
                ],
            };
            // Sign the success response with MESSAGE-INTEGRITY so the client can verify it.
            let resp_bytes = resp
                .encode_with_integrity(&lt_key)
                .unwrap_or_else(|_| resp.encode());
            self.outbox.push_back((resp_bytes, src));
        }

        fn do_refresh(&mut self, msg: &TurnMessage, src: SocketAddr) {
            let resp = Msg {
                method: METHOD_REFRESH,
                class: 2,
                transaction_id: msg.transaction_id,
                attrs: vec![TurnAttr::Lifetime(600)],
            };
            self.outbox.push_back((resp.encode(), src));
        }

        fn do_create_permission(&mut self, msg: &TurnMessage, src: SocketAddr) {
            if let Some(alloc) = self.allocations.get_mut(&src) {
                for a in &msg.attrs {
                    if let TurnAttr::XorPeerAddress(peer) = a {
                        alloc.permissions.insert(peer.ip());
                    }
                }
            }
            let resp = Msg {
                method: METHOD_CREATE_PERMISSION,
                class: 2,
                transaction_id: msg.transaction_id,
                attrs: vec![],
            };
            self.outbox.push_back((resp.encode(), src));
        }

        fn do_channel_bind(&mut self, msg: &TurnMessage, src: SocketAddr) {
            let ch = msg.attrs.iter().find_map(|a| {
                if let TurnAttr::ChannelNumber(c) = a {
                    Some(*c)
                } else {
                    None
                }
            });
            let peer = msg.attrs.iter().find_map(|a| {
                if let TurnAttr::XorPeerAddress(p) = a {
                    Some(*p)
                } else {
                    None
                }
            });
            if let (Some(c), Some(p), Some(alloc)) = (ch, peer, self.allocations.get_mut(&src)) {
                alloc.channels.insert(c, p);
                alloc.permissions.insert(p.ip());
            }
            let resp = Msg {
                method: METHOD_CHANNEL_BIND,
                class: 2,
                transaction_id: msg.transaction_id,
                attrs: vec![],
            };
            self.outbox.push_back((resp.encode(), src));
        }

        fn do_send_indication(&mut self, msg: &TurnMessage, src: SocketAddr) {
            let peer_addr = msg.attrs.iter().find_map(|a| {
                if let TurnAttr::XorPeerAddress(p) = a {
                    Some(*p)
                } else {
                    None
                }
            });
            let payload = msg.attrs.iter().find_map(|a| {
                if let TurnAttr::Data(d) = a {
                    Some(d.clone())
                } else {
                    None
                }
            });
            let (Some(peer), Some(data)) = (peer_addr, payload) else {
                return;
            };

            // The relay address for src is what the peer will see as the source.
            let relay_of_src = self.allocations.get(&src).map(|a| a.relay_addr);

            // Find which client has an allocation matching the peer address.
            let dest_client = self.allocations.iter().find_map(|(client, alloc)| {
                if alloc.relay_addr == peer || *client == peer {
                    Some(*client)
                } else {
                    None
                }
            });

            if let Some(dest) = dest_client {
                let from_relay = relay_of_src.unwrap_or(src);
                let indication = Msg {
                    method: METHOD_DATA,
                    class: 1,
                    transaction_id: [0u8; 12],
                    attrs: vec![TurnAttr::XorPeerAddress(from_relay), TurnAttr::Data(data)],
                };
                self.outbox.push_back((indication.encode(), dest));
            }
        }

        fn allocation_for_relay(&self, relay: SocketAddr) -> Option<SocketAddr> {
            self.allocations.iter().find_map(|(client, alloc)| {
                if alloc.relay_addr == relay {
                    Some(*client)
                } else {
                    None
                }
            })
        }
    }

    /// An in-process simulated TURN server for hermetic ICE relay tests.
    ///
    /// The server is driven synchronously by calling [`SimTurnServer::step`] after each
    /// network round — it drains its inbox socket, processes all requests, and delivers
    /// responses back through the same [`NatSimNetwork`].
    pub struct SimTurnServer {
        inner: Arc<Mutex<Inner>>,
        /// The server's socket in the NAT sim.
        pub sock: SimSocket,
    }

    impl SimTurnServer {
        /// Create a new `SimTurnServer` registered at `server_addr` in `net`.
        ///
        /// # Errors
        ///
        /// Returns [`IceError::Transport`] if the socket cannot be created.
        pub fn new(
            server_addr: SocketAddr,
            relay_ip: IpAddr,
            username: &str,
            password: &str,
            net: &NatSimNetwork,
        ) -> Result<Self, IceError> {
            let sock = net.create_socket(NatType::FullCone, server_addr)?;
            let inner = Arc::new(Mutex::new(Inner {
                username: username.to_owned(),
                password: password.to_owned(),
                realm: "streamhaul.test".to_owned(),
                nonce: b"testnonce12345678".to_vec(),
                allocations: HashMap::new(),
                next_relay_port: 40_000,
                relay_ip,
                outbox: VecDeque::new(),
            }));
            Ok(Self { inner, sock })
        }

        /// Process all pending messages in the server's inbox and send responses.
        pub fn step(&self) {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = self.sock.recv_from(&mut buf) {
                if let Some(data) = buf.get(..n) {
                    if let Ok(mut g) = self.inner.lock() {
                        g.process(data, from);
                    }
                }
            }
            if let Ok(mut g) = self.inner.lock() {
                while let Some((data, dest)) = g.outbox.pop_front() {
                    let _ = self.sock.send_to(&data, dest);
                }
            }
        }

        /// Return the relay address assigned to `client_addr`, if any.
        pub fn relay_addr_for(&self, client_addr: SocketAddr) -> Option<SocketAddr> {
            self.inner
                .lock()
                .ok()?
                .allocations
                .get(&client_addr)
                .map(|a| a.relay_addr)
        }

        /// Return the client internal address whose relay matches `relay_addr`, if any.
        pub fn client_for_relay(&self, relay_addr: SocketAddr) -> Option<SocketAddr> {
            self.inner.lock().ok()?.allocation_for_relay(relay_addr)
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::print_stdout
    )]

    use rand_core::OsRng;
    use sh_types::FixedClock;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::transport::{NatSimNetwork, NatType, SimSocket, UdpTransport};

    use super::*;

    fn ipv4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    // ─── Codec tests ──────────────────────────────────────────────────────────

    #[test]
    fn allocate_request_decode() {
        let mut hdr = [0u8; 20];
        hdr[0] = 0x00;
        hdr[1] = 0x03; // Allocate Request
        hdr[4] = 0x21;
        hdr[5] = 0x12;
        hdr[6] = 0xA4;
        hdr[7] = 0x42;
        let msg = TurnMessage::decode(&hdr).unwrap();
        assert_eq!(msg.method, METHOD_ALLOCATE);
        assert_eq!(msg.class, 0);
    }

    #[test]
    fn allocate_success_decode() {
        // class=SuccessResponse(0b10): C1=1, C0=0 → bits 8 and 4 of type_word.
        // type_word = m_bits | (1<<8) | (0<<4) = 0x0003 | 0x0100 = 0x0103
        let mut hdr = [0u8; 20];
        hdr[0] = 0x01;
        hdr[1] = 0x03;
        hdr[4] = 0x21;
        hdr[5] = 0x12;
        hdr[6] = 0xA4;
        hdr[7] = 0x42;
        let msg = TurnMessage::decode(&hdr).unwrap();
        assert_eq!(msg.method, METHOD_ALLOCATE);
        assert_eq!(msg.class, 2); // Success
    }

    #[test]
    fn lifetime_roundtrip() {
        let msg = TurnMessage {
            method: METHOD_ALLOCATE,
            class: 0,
            transaction_id: [0xABu8; 12],
            attrs: vec![TurnAttr::Lifetime(3600)],
        };
        let decoded = TurnMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.lifetime(), Some(3600));
    }

    #[test]
    fn xor_relayed_address_roundtrip() {
        let relay = ipv4(203, 0, 113, 1, 49152);
        let tid = [0x11u8; 12];
        let msg = TurnMessage {
            method: METHOD_ALLOCATE,
            class: 2,
            transaction_id: tid,
            attrs: vec![TurnAttr::XorRelayedAddress(relay)],
        };
        let decoded = TurnMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.relay_address(), Some(relay));
    }

    #[test]
    fn xor_peer_address_roundtrip() {
        let peer = ipv4(192, 0, 2, 50, 12345);
        let tid = [0x22u8; 12];
        let msg = TurnMessage {
            method: METHOD_CREATE_PERMISSION,
            class: 0,
            transaction_id: tid,
            attrs: vec![TurnAttr::XorPeerAddress(peer)],
        };
        let decoded = TurnMessage::decode(&msg.encode()).unwrap();
        let got = decoded.attrs.iter().find_map(|a| {
            if let TurnAttr::XorPeerAddress(p) = a {
                Some(*p)
            } else {
                None
            }
        });
        assert_eq!(got, Some(peer));
    }

    #[test]
    fn error_code_401_roundtrip() {
        let msg = TurnMessage {
            method: METHOD_ALLOCATE,
            class: 3,
            transaction_id: [0u8; 12],
            attrs: vec![TurnAttr::ErrorCode {
                code: 401,
                reason: "Unauthorized".into(),
            }],
        };
        let decoded = TurnMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.error_code(), Some(401));
    }

    #[test]
    fn realm_nonce_roundtrip() {
        let msg = TurnMessage {
            method: METHOD_ALLOCATE,
            class: 3,
            transaction_id: [0u8; 12],
            attrs: vec![
                TurnAttr::Realm("streamhaul.example.com".into()),
                TurnAttr::Nonce(b"nonce12345678901".to_vec()),
            ],
        };
        let decoded = TurnMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.realm(), Some("streamhaul.example.com"));
        assert_eq!(decoded.nonce(), Some(b"nonce12345678901".as_ref()));
    }

    #[test]
    fn channel_bind_roundtrip() {
        let peer = ipv4(10, 0, 0, 1, 9000);
        let msg = TurnMessage {
            method: METHOD_CHANNEL_BIND,
            class: 0,
            transaction_id: [0u8; 12],
            attrs: vec![
                TurnAttr::ChannelNumber(0x4000),
                TurnAttr::XorPeerAddress(peer),
            ],
        };
        let decoded = TurnMessage::decode(&msg.encode()).unwrap();
        let ch = decoded.attrs.iter().find_map(|a| {
            if let TurnAttr::ChannelNumber(c) = a {
                Some(*c)
            } else {
                None
            }
        });
        assert_eq!(ch, Some(0x4000));
    }

    #[test]
    fn message_integrity_good_key() {
        let key = long_term_key("user", "realm.example.com", "pass");
        let msg = TurnMessage {
            method: METHOD_ALLOCATE,
            class: 0,
            transaction_id: [0u8; 12],
            attrs: vec![TurnAttr::RequestedTransport(17)],
        };
        let bytes = msg.encode_with_integrity(&key).unwrap();
        assert!(TurnMessage::verify_integrity(&bytes, &key).is_ok());
    }

    #[test]
    fn message_integrity_bad_key_rejected() {
        let good = long_term_key("user", "realm", "pass");
        let bad = long_term_key("user", "realm", "wrong");
        let msg = TurnMessage {
            method: METHOD_ALLOCATE,
            class: 0,
            transaction_id: [0u8; 12],
            attrs: vec![TurnAttr::RequestedTransport(17)],
        };
        let bytes = msg.encode_with_integrity(&good).unwrap();
        assert!(TurnMessage::verify_integrity(&bytes, &bad).is_err());
    }

    #[test]
    fn truncated_input_no_panic() {
        for len in 0..=25usize {
            let _ = TurnMessage::decode(&vec![0xABu8; len]);
        }
        // Valid magic cookie but claims 8 bytes of attrs (buffer too short).
        let mut buf = [0u8; 20];
        buf[4] = 0x21;
        buf[5] = 0x12;
        buf[6] = 0xA4;
        buf[7] = 0x42;
        buf[2] = 0x00;
        buf[3] = 0x08;
        let _ = TurnMessage::decode(&buf);
    }

    #[test]
    fn channel_data_encode_decode() {
        let data = b"test payload";
        let frame =
            TurnClient::<SimSocket, FixedClock, OsRng>::build_channel_data(0x4000, data).unwrap();
        assert_eq!(&frame[..2], &[0x40, 0x00]);
        assert_eq!(u16::from_be_bytes([frame[2], frame[3]]), data.len() as u16);
        let (ch, decoded) =
            TurnClient::<SimSocket, FixedClock, OsRng>::decode_channel_data(&frame).unwrap();
        assert_eq!(ch, 0x4000);
        assert_eq!(decoded, data);
    }

    #[test]
    fn channel_data_invalid_channel() {
        assert!(
            TurnClient::<SimSocket, FixedClock, OsRng>::build_channel_data(0x3FFF, b"x").is_err()
        );
        assert!(
            TurnClient::<SimSocket, FixedClock, OsRng>::build_channel_data(0x8000, b"x").is_err()
        );
    }

    #[test]
    fn channel_data_truncated_no_panic() {
        let _ = TurnClient::<SimSocket, FixedClock, OsRng>::decode_channel_data(&[]);
        let _ = TurnClient::<SimSocket, FixedClock, OsRng>::decode_channel_data(&[0x40, 0x00]);
        let _ = TurnClient::<SimSocket, FixedClock, OsRng>::decode_channel_data(&[
            0x40, 0x00, 0x00, 0x0A,
        ]);
    }

    // ─── TurnClient state machine ─────────────────────────────────────────────

    /// Drive a full 401-challenge → allocation sequence using the SimTurnServer.
    fn run_allocate(
        net: &NatSimNetwork,
        server_addr: SocketAddr,
        client_addr: SocketAddr,
        username: &str,
        password: &str,
    ) -> TurnClient<SimSocket, FixedClock, OsRng> {
        use sim_turn::SimTurnServer;

        let turn = SimTurnServer::new(
            server_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
            username,
            password,
            net,
        )
        .unwrap();
        let client_sock = net.create_socket(NatType::FullCone, client_addr).unwrap();
        let cfg = TurnConfig {
            server_addr,
            username: username.to_owned(),
            password: password.to_owned(),
            lifetime_secs: 600,
        };
        let mut client = TurnClient::new(cfg, client_sock, FixedClock(0), OsRng);

        // Step 1: client sends unauthenticated Allocate.
        client.start_allocate().unwrap();
        assert_eq!(client.state(), TurnState::Allocating);

        // Step 2: server processes → 401 challenge.
        turn.step();

        // Step 3: client receives 401 → sends authenticated Allocate.
        let mut buf = [0u8; 4096];
        let (n, _) = client.transport.recv_from(&mut buf).unwrap();
        client.handle_incoming(buf.get(..n).unwrap()).unwrap();
        assert_eq!(client.state(), TurnState::AllocatingAuthenticated);

        // Step 4: server processes authenticated Allocate → Allocate Success.
        turn.step();

        // Step 5: client receives success.
        let (n2, _) = client.transport.recv_from(&mut buf).unwrap();
        client.handle_incoming(buf.get(..n2).unwrap()).unwrap();
        assert_eq!(client.state(), TurnState::Allocated);
        assert!(
            client.relay_addr().is_some(),
            "relay address must be set after allocation"
        );

        client
    }

    #[test]
    fn turn_allocate_401_challenge_full_sequence() {
        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let server_addr = ipv4(10, 0, 0, 254, 13478);
        let client_addr = ipv4(127, 0, 0, 1, 25001);
        let client = run_allocate(&net, server_addr, client_addr, "testuser", "testpass");
        assert_eq!(client.state(), TurnState::Allocated);
        println!("relay addr = {:?}", client.relay_addr());
    }

    #[test]
    fn turn_refresh_success() {
        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let server_addr = ipv4(10, 0, 0, 254, 13479);
        let client_addr = ipv4(127, 0, 0, 1, 25002);
        let mut client = run_allocate(&net, server_addr, client_addr, "u2", "p2");

        // Now send Refresh.
        client.send_refresh().unwrap();
        assert_eq!(client.state(), TurnState::Refreshing);

        // Deliver success (simulated directly since the server socket was consumed).
        // Must use the actual pending_tid (set by send_refresh) so the TID check passes,
        // and must sign with MESSAGE-INTEGRITY so the MI check passes.
        let tid = client.pending_tid.unwrap();
        let lt_key = client.lt_key.clone().unwrap();
        let refresh_success = TurnMessage {
            method: METHOD_REFRESH,
            class: 2,
            transaction_id: tid,
            attrs: vec![TurnAttr::Lifetime(600)],
        };
        client
            .handle_incoming(&refresh_success.encode_with_integrity(&lt_key).unwrap())
            .unwrap();
        assert_eq!(client.state(), TurnState::Allocated);
    }

    #[test]
    fn turn_expiry_detected() {
        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let sock = net
            .create_socket(NatType::FullCone, ipv4(127, 0, 0, 1, 25003))
            .unwrap();
        let cfg = TurnConfig {
            server_addr: ipv4(10, 0, 0, 254, 13480),
            username: "u".into(),
            password: "p".into(),
            lifetime_secs: 100,
        };
        let mut client = TurnClient::new(cfg, sock, FixedClock(0), OsRng);
        client.state = TurnState::Allocated;
        client.expires_at = Some(100);

        assert!(!client.is_expired()); // clock=0 < 100

        // Simulate clock at expiry.
        let net2 = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let sock2 = net2
            .create_socket(NatType::FullCone, ipv4(127, 0, 0, 1, 25004))
            .unwrap();
        let cfg2 = TurnConfig {
            server_addr: ipv4(10, 0, 0, 254, 13480),
            username: "u".into(),
            password: "p".into(),
            lifetime_secs: 100,
        };
        let mut c2 = TurnClient::new(cfg2, sock2, FixedClock(100), OsRng);
        c2.state = TurnState::Allocated;
        c2.expires_at = Some(100);
        assert!(c2.is_expired()); // clock=100 >= 100

        c2.mark_expired();
        assert_eq!(c2.state(), TurnState::Expired);
        assert!(c2.relay_addr().is_none());
    }

    #[test]
    fn bad_turn_credentials_rejected_by_mi_check() {
        // Build an authenticated Allocate with wrong password and verify the lt_key mismatch.
        let correct_key = long_term_key("user", "streamhaul.test", "correct_password");
        let wrong_key = long_term_key("user", "streamhaul.test", "wrong_password");

        let msg = TurnMessage {
            method: METHOD_ALLOCATE,
            class: 0,
            transaction_id: [0u8; 12],
            attrs: vec![TurnAttr::RequestedTransport(17)],
        };
        let bytes = msg.encode_with_integrity(&wrong_key).unwrap();
        assert!(TurnMessage::verify_integrity(&bytes, &correct_key).is_err());
    }

    #[test]
    fn create_permission_requires_allocated() {
        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let sock = net
            .create_socket(NatType::FullCone, ipv4(127, 0, 0, 1, 25005))
            .unwrap();
        let cfg = TurnConfig {
            server_addr: ipv4(10, 0, 0, 254, 13481),
            username: "u".into(),
            password: "p".into(),
            lifetime_secs: 600,
        };
        let mut c = TurnClient::new(cfg, sock, FixedClock(0), OsRng);
        assert!(c.create_permission(ipv4(192, 168, 0, 1, 9000)).is_err());
    }

    #[test]
    fn channel_bind_requires_allocated() {
        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let sock = net
            .create_socket(NatType::FullCone, ipv4(127, 0, 0, 1, 25006))
            .unwrap();
        let cfg = TurnConfig {
            server_addr: ipv4(10, 0, 0, 254, 13482),
            username: "u".into(),
            password: "p".into(),
            lifetime_secs: 600,
        };
        let mut c = TurnClient::new(cfg, sock, FixedClock(0), OsRng);
        assert!(c.channel_bind(0x4000, ipv4(192, 168, 0, 1, 9000)).is_err());
    }

    #[test]
    fn relay_steering_picks_server() {
        use crate::steering::{score_relays, select_relay, RelayProbeResult};

        let r1 = "127.0.0.1:3478".parse::<SocketAddr>().unwrap();
        let r2 = "127.0.0.2:3478".parse::<SocketAddr>().unwrap();

        let init = vec![
            RelayProbeResult {
                server: r1,
                rtt_us: 5_000,
                jitter_us: 100,
            },
            RelayProbeResult {
                server: r2,
                rtt_us: 50_000,
                jitter_us: 5_000,
            },
        ];
        let resp = vec![
            RelayProbeResult {
                server: r1,
                rtt_us: 6_000,
                jitter_us: 200,
            },
            RelayProbeResult {
                server: r2,
                rtt_us: 45_000,
                jitter_us: 4_000,
            },
        ];
        let scores = score_relays(&init, &resp);
        let sel = select_relay(&scores).unwrap();
        // r1 scores 5_000 + 6_000 + (100+200)/2 = 11_150; r2 scores >> 11_150.
        assert_eq!(
            sel.primary.server, r1,
            "steering must pick the lower-latency TURN server"
        );
        // Standby only if within 10ms of primary.
        // r2 score ≈ 99_500 which is >> 10_000 away from primary.
        assert!(
            sel.standby.is_none(),
            "r2 is far from r1, no standby expected"
        );
    }

    // ─── Fix 6: Security regression tests ────────────────────────────────────

    /// A forged Allocate Success (no MESSAGE-INTEGRITY, or wrong key) must be dropped
    /// when lt_key is set (i.e. after the initial 401 challenge has derived the key).
    #[test]
    fn forged_allocate_success_rejected() {
        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let server_addr = ipv4(10, 0, 0, 254, 33478);
        let client_addr = ipv4(127, 0, 0, 1, 35001);
        let sock = net.create_socket(NatType::FullCone, client_addr).unwrap();
        let cfg = TurnConfig {
            server_addr,
            username: "u".into(),
            password: "p".into(),
            lifetime_secs: 600,
        };
        let mut client = TurnClient::new(cfg, sock, FixedClock(0), OsRng);

        // Manually set lt_key (simulates having completed the 401 exchange).
        client.lt_key = Some(long_term_key("u", "streamhaul.test", "p"));
        client.state = TurnState::AllocatingAuthenticated;
        let pending = [0xAAu8; 12];
        client.pending_tid = Some(pending);

        // Craft a forged Allocate Success with matching TID but NO MESSAGE-INTEGRITY.
        let forged = TurnMessage {
            method: METHOD_ALLOCATE,
            class: 2,
            transaction_id: pending,
            attrs: vec![TurnAttr::XorRelayedAddress(ipv4(10, 0, 0, 254, 50000))],
        };
        let _ = client.handle_incoming(&forged.encode());

        // Must be dropped: state stays AllocatingAuthenticated, relay_addr stays None.
        assert_eq!(
            client.state(),
            TurnState::AllocatingAuthenticated,
            "forged Allocate Success must not change state"
        );
        assert!(
            client.relay_addr().is_none(),
            "forged Allocate Success must not set relay_addr"
        );
    }

    /// Appending an attribute after the MESSAGE-INTEGRITY must be rejected.
    #[test]
    fn turn_mi_trailing_attr_injection_blocked() {
        let key = long_term_key("u", "r", "p");
        let msg = TurnMessage {
            method: METHOD_ALLOCATE,
            class: 2,
            transaction_id: [1u8; 12],
            attrs: vec![TurnAttr::Lifetime(600)],
        };
        let mut legit = msg.encode_with_integrity(&key).unwrap();

        // Append a spurious LIFETIME attribute after the MI — this is the injection.
        // LIFETIME TLV: type=0x000D, len=0x0004, value=0x00000258 (=600)
        let trailing: &[u8] = &[0x00, 0x0D, 0x00, 0x04, 0x00, 0x00, 0x02, 0x58];
        let orig_len = u16::from_be_bytes([legit[2], legit[3]]);
        #[allow(clippy::cast_possible_truncation)]
        let new_len = orig_len + trailing.len() as u16;
        legit[2] = (new_len >> 8) as u8;
        legit[3] = (new_len & 0xFF) as u8;
        legit.extend_from_slice(trailing);

        assert!(
            TurnMessage::verify_integrity(&legit, &key).is_err(),
            "trailing attribute after MI must be rejected"
        );
    }

    /// A response with a mismatched transaction ID must be silently dropped.
    #[test]
    fn turn_tid_mismatch_dropped() {
        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let server_addr = ipv4(10, 0, 0, 254, 33479);
        let client_addr = ipv4(127, 0, 0, 1, 35002);
        let sock = net.create_socket(NatType::FullCone, client_addr).unwrap();
        let cfg = TurnConfig {
            server_addr,
            username: "u".into(),
            password: "p".into(),
            lifetime_secs: 600,
        };
        let mut client = TurnClient::new(cfg, sock, FixedClock(0), OsRng);
        client.state = TurnState::AllocatingAuthenticated;
        client.pending_tid = Some([0xBBu8; 12]);

        // Send a response with a DIFFERENT transaction ID.
        let stale = TurnMessage {
            method: METHOD_ALLOCATE,
            class: 2,
            transaction_id: [0xCCu8; 12], // wrong TID
            attrs: vec![TurnAttr::XorRelayedAddress(ipv4(10, 0, 0, 254, 50001))],
        };
        let _ = client.handle_incoming(&stale.encode());

        assert_eq!(
            client.state(),
            TurnState::AllocatingAuthenticated,
            "stale TID must not change state"
        );
        assert!(
            client.relay_addr().is_none(),
            "stale TID must not set relay_addr"
        );
    }

    /// After two 401 responses the client must enter Expired and stop retrying.
    #[test]
    fn turn_repeated_401_bounded() {
        let net = NatSimNetwork::new("10.0.0.254".parse().unwrap());
        let server_addr = ipv4(10, 0, 0, 254, 33480);
        let client_addr = ipv4(127, 0, 0, 1, 35003);
        let sock = net.create_socket(NatType::FullCone, client_addr).unwrap();
        let cfg = TurnConfig {
            server_addr,
            username: "u".into(),
            password: "p".into(),
            lifetime_secs: 600,
        };
        let mut client = TurnClient::new(cfg, sock, FixedClock(0), OsRng);
        client.state = TurnState::Allocating;
        let tid = [0x01u8; 12];
        client.pending_tid = Some(tid);

        // First 401: normal — client derives key, sends authenticated Allocate.
        let challenge = TurnMessage {
            method: METHOD_ALLOCATE,
            class: 3,
            transaction_id: tid,
            attrs: vec![
                TurnAttr::ErrorCode {
                    code: 401,
                    reason: "Unauthorized".into(),
                },
                TurnAttr::Realm("streamhaul.test".into()),
                TurnAttr::Nonce(b"nonce1".to_vec()),
            ],
        };
        let r1 = client.handle_incoming(&challenge.encode());
        assert!(r1.is_ok(), "first 401 should be processed: {r1:?}");

        // After the first 401 the client sent an authenticated Allocate; grab the new TID.
        let tid2 = client.pending_tid.unwrap_or([0x02u8; 12]);

        // Second 401: should hit the cap and return Err.
        let challenge2 = TurnMessage {
            method: METHOD_ALLOCATE,
            class: 3,
            transaction_id: tid2,
            attrs: vec![
                TurnAttr::ErrorCode {
                    code: 401,
                    reason: "Unauthorized".into(),
                },
                TurnAttr::Realm("streamhaul.test".into()),
                TurnAttr::Nonce(b"nonce2".to_vec()),
            ],
        };
        let r2 = client.handle_incoming(&challenge2.encode());
        assert!(
            r2.is_err() || client.state() == TurnState::Expired,
            "second 401 should hit auth cap: state={:?} result={r2:?}",
            client.state()
        );
        assert_eq!(
            client.state(),
            TurnState::Expired,
            "state must be Expired after auth cap"
        );
    }
}
