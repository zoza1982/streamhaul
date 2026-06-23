//! STUN codec — RFC 8489 subset required by ICE (RFC 8445).
//!
//! Implements encoding and decoding of STUN `Binding` messages, `MESSAGE-INTEGRITY`
//! (HMAC-SHA1), and `FINGERPRINT` (CRC32 XOR `0x5354554E`).  All wire fields are
//! big-endian.  Every decode path bounds-checks before indexing so that arbitrary
//! hostile input cannot cause panics or out-of-bounds reads.
//!
//! # Wire format
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0|  STUN Message Type        |         Message Length        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Magic Cookie (0x2112A442)                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   Transaction ID (96 bits)                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Attributes follow as TLV triples padded to 4-byte alignment.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use hmac::Mac as _;
use sha1::Sha1;
use subtle::ConstantTimeEq as _;

use crate::error::IceError;

// ─── Constants ────────────────────────────────────────────────────────────────

/// STUN magic cookie value (RFC 8489 §6).
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Minimum length of a STUN message (20-byte header, no attributes).
const STUN_HEADER_LEN: usize = 20;

// ─── Message class and method ─────────────────────────────────────────────────

/// STUN message class (bits C1 and C0 of the message type word).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunClass {
    /// A client-to-server request expecting a response.
    Request,
    /// A server-to-client success response.
    SuccessResponse,
    /// A server-to-client error response.
    ErrorResponse,
    /// A message with no expected response (fire-and-forget).
    Indication,
}

/// STUN method.  This implementation only needs `Binding`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunMethod {
    /// RFC 8489 §14.1 — Binding method (value `0x001`).
    Binding,
}

// ─── Attribute types ──────────────────────────────────────────────────────────

/// A single decoded STUN attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunAttribute {
    /// `MAPPED-ADDRESS` (0x0001) — unobfuscated reflexive address.
    MappedAddress(SocketAddr),
    /// `XOR-MAPPED-ADDRESS` (0x0020) — XOR-obfuscated reflexive address.
    XorMappedAddress(SocketAddr),
    /// `USERNAME` (0x0006) — UTF-8 credential string.
    Username(String),
    /// `MESSAGE-INTEGRITY` (0x0008) — raw 20-byte HMAC-SHA1 value.
    MessageIntegrity([u8; 20]),
    /// `FINGERPRINT` (0x8028) — CRC32 value.
    Fingerprint(u32),
    /// `PRIORITY` (0x0024) — RFC 8445 candidate priority as big-endian u32.
    Priority(u32),
    /// `USE-CANDIDATE` (0x0025) — zero-length flag attribute.
    UseCandidate,
    /// `ICE-CONTROLLED` (0x8029) — 8-byte tie-breaker value.
    IceControlled(u64),
    /// `ICE-CONTROLLING` (0x802A) — 8-byte tie-breaker value.
    IceControlling(u64),
    /// `ERROR-CODE` (0x0009) — error code and textual reason phrase.
    ErrorCode {
        /// The numeric error code (e.g. 400, 401, 420, 438, 487).
        code: u16,
        /// Human-readable reason phrase (UTF-8).
        reason: String,
    },
    /// `UNKNOWN-ATTRIBUTES` (0x000A) — list of unrecognised comprehension-required attribute types.
    ///
    /// RFC 8489 §14.9: the value contains one or more 16-bit attribute type codes.
    UnknownComprehensionRequired(Vec<u16>),
    /// `SOFTWARE` (0x8022) — implementation description string.
    Software(String),
    /// Any attribute type not explicitly handled.
    Unknown {
        /// The raw attribute type code.
        attr_type: u16,
        /// The raw attribute value bytes (unpadded).
        value: Vec<u8>,
    },
}

// ─── StunMessage ──────────────────────────────────────────────────────────────

/// A decoded or constructed STUN message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMessage {
    /// The message class (Request, SuccessResponse, etc.).
    pub class: StunClass,
    /// The message method (always `Binding` for ICE).
    pub method: StunMethod,
    /// The 96-bit transaction ID.
    pub transaction_id: [u8; 12],
    /// The decoded attribute list, in wire order.
    pub attributes: Vec<StunAttribute>,
}

impl StunMessage {
    /// Construct a new STUN Binding Request with a given transaction ID.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_ice::stun::{StunMessage, StunClass, StunMethod};
    ///
    /// let tid = [0u8; 12];
    /// let msg = StunMessage::new_binding_request(tid);
    /// assert_eq!(msg.class, StunClass::Request);
    /// assert_eq!(msg.method, StunMethod::Binding);
    /// ```
    #[must_use]
    pub fn new_binding_request(transaction_id: [u8; 12]) -> Self {
        Self {
            class: StunClass::Request,
            method: StunMethod::Binding,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    /// Construct a new STUN Binding Success Response.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_ice::stun::{StunMessage, StunClass, StunMethod};
    ///
    /// let tid = [1u8; 12];
    /// let msg = StunMessage::new_binding_response(tid);
    /// assert_eq!(msg.class, StunClass::SuccessResponse);
    /// ```
    #[must_use]
    pub fn new_binding_response(transaction_id: [u8; 12]) -> Self {
        Self {
            class: StunClass::SuccessResponse,
            method: StunMethod::Binding,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    // ─── Encoding ────────────────────────────────────────────────────────────

    /// Encode the message to bytes **without** `MESSAGE-INTEGRITY` or `FINGERPRINT`.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_ice::stun::{StunMessage, MAGIC_COOKIE};
    ///
    /// let msg = StunMessage::new_binding_request([0u8; 12]);
    /// let bytes = msg.encode();
    /// assert_eq!(bytes.len(), 20); // header only, no attrs
    /// let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    /// assert_eq!(cookie, MAGIC_COOKIE);
    /// ```
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let attr_bytes = encode_attributes(&self.attributes, &self.transaction_id);
        build_header(
            self.class,
            self.method,
            &self.transaction_id,
            attr_bytes.len(),
        )
        .into_iter()
        .chain(attr_bytes)
        .collect()
    }

    /// Encode the message appending a `MESSAGE-INTEGRITY` attribute computed with `key`.
    ///
    /// The STUN message-length field in the header is temporarily set to include the
    /// `MESSAGE-INTEGRITY` attribute (24 bytes) before the HMAC is computed, per
    /// RFC 8489 §14.5.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::Transport`] if HMAC construction fails (unreachable in
    /// practice since HMAC-SHA1 accepts any key length).
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_ice::stun::StunMessage;
    ///
    /// let msg = StunMessage::new_binding_request([0u8; 12]);
    /// let key = b"secret";
    /// let bytes = msg.encode_with_integrity(key).unwrap();
    /// StunMessage::verify_integrity(&bytes, key).unwrap();
    /// ```
    pub fn encode_with_integrity(&self, key: &[u8]) -> Result<Vec<u8>, IceError> {
        let attr_bytes = encode_attributes(&self.attributes, &self.transaction_id);
        // The length in the header counts everything after the 20-byte header,
        // including the 24 bytes for the MI attr we are about to append.
        let mi_msg_len = attr_bytes.len().saturating_add(24);
        let mut out = build_header(self.class, self.method, &self.transaction_id, mi_msg_len);
        out.extend_from_slice(&attr_bytes);
        // Compute HMAC-SHA1 over all bytes so far (header with adjusted length + preceding attrs).
        let hmac_bytes = compute_hmac_sha1(key, &out)?;
        // Append MI attr: type=0x0008, length=20, value=hmac (20 bytes).
        out.extend_from_slice(&0x0008u16.to_be_bytes());
        out.extend_from_slice(&20u16.to_be_bytes());
        out.extend_from_slice(&hmac_bytes);
        Ok(out)
    }

    /// Encode the message appending `MESSAGE-INTEGRITY` followed by `FINGERPRINT`.
    ///
    /// Per RFC 8489, `FINGERPRINT` is computed over the entire message up to (but not
    /// including) the `FINGERPRINT` attribute, with the message-length field set to
    /// include the `FINGERPRINT` attribute (8 bytes).
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_ice::stun::StunMessage;
    ///
    /// let msg = StunMessage::new_binding_request([0u8; 12]);
    /// let key = b"secret";
    /// let bytes = msg.encode_with_integrity_and_fingerprint(key).unwrap();
    /// StunMessage::verify_integrity(&bytes, key).unwrap();
    /// StunMessage::verify_fingerprint(&bytes).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`IceError::Transport`] if HMAC construction fails (unreachable in
    /// practice since HMAC-SHA1 accepts any key length).
    pub fn encode_with_integrity_and_fingerprint(&self, key: &[u8]) -> Result<Vec<u8>, IceError> {
        // First build message with MI appended.
        let mut out = self.encode_with_integrity(key)?;
        // The FP covers all bytes so far; update msg-length to include FP (8 bytes).
        let fp_total_len = out.len().saturating_add(8).saturating_sub(STUN_HEADER_LEN);
        // Rewrite length field in the header (bytes 2..4).
        // STUN message length is bounded by UDP MTU, well within u16::MAX.
        #[allow(clippy::cast_possible_truncation)]
        let fp_len_bytes = (fp_total_len.min(usize::from(u16::MAX)) as u16).to_be_bytes();
        if let Some(len_field) = out.get_mut(2..4) {
            len_field.copy_from_slice(&fp_len_bytes);
        }
        let crc = crc32fast::hash(&out) ^ 0x5354_554E;
        // The FP attr is now appended. The length field was already updated to include it.
        out.extend_from_slice(&0x8028u16.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&crc.to_be_bytes());
        Ok(out)
    }

    // ─── Verification ────────────────────────────────────────────────────────

    /// Verify the `MESSAGE-INTEGRITY` attribute in a raw encoded STUN message.
    ///
    /// Finds the first `MESSAGE-INTEGRITY` attribute in `raw`, re-computes
    /// HMAC-SHA1 over all bytes preceding that attribute (with the length field set
    /// as the encoder set it), and compares the result with the stored value.
    ///
    /// # Errors
    ///
    /// - [`IceError::StunTruncated`] — message is shorter than the minimum header.
    /// - [`IceError::IntegrityMismatch`] — HMAC does not match or no MI attr present.
    pub fn verify_integrity(raw: &[u8], key: &[u8]) -> Result<(), IceError> {
        let mi_offset = find_attr_offset(raw, 0x0008).map_err(|e| match e {
            IceError::AttrNotFound { .. } => IceError::IntegrityMismatch,
            other => other,
        })?;

        // RFC 8489 §15.4: MESSAGE-INTEGRITY must be the last attribute, or may be followed
        // only by FINGERPRINT (0x8028).  Any other trailing attribute is a violation.
        // mi_offset + 24 = byte just past the MI value (4-byte TL + 20-byte HMAC).
        let mi_end = mi_offset.saturating_add(24);
        // Determine the end of the declared message body.
        let msg_len = u16::from_be_bytes([*raw.get(2).unwrap_or(&0), *raw.get(3).unwrap_or(&0)]);
        let body_end = STUN_HEADER_LEN.saturating_add(usize::from(msg_len));
        if mi_end < body_end {
            // There are bytes after MI. The only legal trailer is a single FINGERPRINT attr.
            let trailer = raw.get(mi_end..body_end).unwrap_or(&[]);
            let is_only_fp =
                trailer.len() == 8 && trailer.get(0..2) == Some(&0x8028u16.to_be_bytes());
            if !is_only_fp {
                return Err(IceError::AttrOrderingViolation("MESSAGE-INTEGRITY"));
            }
        }

        let prefix = raw.get(..mi_offset).ok_or(IceError::StunTruncated {
            needed: mi_offset,
            have: raw.len(),
        })?;
        // RFC 8489 §14.5: the Length field in the HMAC input is set to the value it would have
        // if MESSAGE-INTEGRITY were the last attribute (i.e. pointing just past the MI value).
        // mi_offset is the byte index of MI's type field; MI attr is 4 (TL) + 20 (value) = 24 bytes.
        // So the effective msg_len = (mi_offset + 24) - STUN_HEADER_LEN.
        let mi_msg_len = mi_offset.saturating_add(24).saturating_sub(STUN_HEADER_LEN);
        let mut prefix_buf = prefix.to_vec();
        #[allow(clippy::cast_possible_truncation)]
        let mi_len_bytes = (mi_msg_len.min(usize::from(u16::MAX)) as u16).to_be_bytes();
        if let Some(len_field) = prefix_buf.get_mut(2..4) {
            len_field.copy_from_slice(&mi_len_bytes);
        }
        let expected = compute_hmac_sha1(key, &prefix_buf)?;
        // The actual HMAC value is 20 bytes starting right after the 4-byte attr TL header.
        let value_start = mi_offset.saturating_add(4);
        let value_end = value_start.saturating_add(20);
        let stored = raw
            .get(value_start..value_end)
            .ok_or(IceError::IntegrityMismatch)?;
        // Use subtle::ConstantTimeEq to prevent timing side-channel on HMAC comparison.
        let stored_arr: [u8; 20] = stored.try_into().map_err(|_| IceError::IntegrityMismatch)?;
        if expected.ct_eq(&stored_arr).into() {
            Ok(())
        } else {
            Err(IceError::IntegrityMismatch)
        }
    }

    /// Verify the `FINGERPRINT` attribute in a raw encoded STUN message.
    ///
    /// Finds the `FINGERPRINT` attribute, computes CRC32 of all bytes preceding it
    /// (with the header length field updated to include the fingerprint attribute),
    /// XORs with `0x5354554E`, and compares against the stored value.
    ///
    /// # Errors
    ///
    /// - [`IceError::StunTruncated`] — message too short.
    /// - [`IceError::FingerprintMismatch`] — CRC does not match or no FP attr present.
    pub fn verify_fingerprint(raw: &[u8]) -> Result<(), IceError> {
        let fp_offset = find_attr_offset(raw, 0x8028).map_err(|e| match e {
            IceError::AttrNotFound { .. } => IceError::FingerprintMismatch,
            other => other,
        })?;

        // RFC 8489 §15.5: FINGERPRINT must be the last attribute in the message.
        // fp_offset + 8 = byte just past the FINGERPRINT value (4-byte TL + 4-byte CRC).
        let fp_end = fp_offset.saturating_add(8);
        let msg_len = u16::from_be_bytes([*raw.get(2).unwrap_or(&0), *raw.get(3).unwrap_or(&0)]);
        let body_end = STUN_HEADER_LEN.saturating_add(usize::from(msg_len));
        if fp_end != body_end {
            return Err(IceError::AttrOrderingViolation("FINGERPRINT"));
        }

        // Build a copy of the prefix with the length field set to include the FP attr.
        let fp_total_len = fp_offset.saturating_add(8).saturating_sub(STUN_HEADER_LEN);
        let prefix = raw.get(..fp_offset).ok_or(IceError::StunTruncated {
            needed: fp_offset,
            have: raw.len(),
        })?;
        let mut prefix_buf = prefix.to_vec();
        #[allow(clippy::cast_possible_truncation)]
        let fp_len_bytes = (fp_total_len.min(usize::from(u16::MAX)) as u16).to_be_bytes();
        if let Some(len_field) = prefix_buf.get_mut(2..4) {
            len_field.copy_from_slice(&fp_len_bytes);
        }
        let computed = crc32fast::hash(&prefix_buf) ^ 0x5354_554E;
        // Read stored FP value (4 bytes after the 4-byte TL header).
        let value_start = fp_offset.saturating_add(4);
        let value_end = value_start.saturating_add(4);
        let stored_bytes = raw
            .get(value_start..value_end)
            .ok_or(IceError::FingerprintMismatch)?;
        let stored = u32::from_be_bytes(
            stored_bytes
                .try_into()
                .map_err(|_| IceError::FingerprintMismatch)?,
        );
        if computed == stored {
            Ok(())
        } else {
            Err(IceError::FingerprintMismatch)
        }
    }

    // ─── Decoding ────────────────────────────────────────────────────────────

    /// Decode a STUN message from raw bytes.
    ///
    /// Validates the header (magic cookie, top-two-bit rule, length alignment), then
    /// iterates over attributes.  Unknown comprehension-required attributes (type
    /// `< 0x8000`) are collected as [`StunAttribute::UnknownComprehensionRequired`]
    /// rather than producing an immediate error; callers that need strict RFC
    /// compliance should inspect the returned attribute list.
    ///
    /// # Errors
    ///
    /// Returns an [`IceError`] variant for any structural violation:
    /// [`IceError::StunTruncated`], [`IceError::BadMagicCookie`],
    /// [`IceError::InvalidMessageTypeBits`], [`IceError::MessageLengthNotAligned`],
    /// [`IceError::StunAttrTruncated`].
    pub fn decode(raw: &[u8]) -> Result<Self, IceError> {
        if raw.len() < STUN_HEADER_LEN {
            return Err(IceError::StunTruncated {
                needed: STUN_HEADER_LEN,
                have: raw.len(),
            });
        }

        // Bounds-safe header reads (already checked len >= 20).
        let type_word = u16::from_be_bytes([*raw.first().unwrap_or(&0), *raw.get(1).unwrap_or(&0)]);
        let msg_len = u16::from_be_bytes([*raw.get(2).unwrap_or(&0), *raw.get(3).unwrap_or(&0)]);
        let cookie = u32::from_be_bytes([
            *raw.get(4).unwrap_or(&0),
            *raw.get(5).unwrap_or(&0),
            *raw.get(6).unwrap_or(&0),
            *raw.get(7).unwrap_or(&0),
        ]);

        // Top two bits must be 0b00.
        if type_word & 0xC000 != 0 {
            return Err(IceError::InvalidMessageTypeBits);
        }
        // Message length must be a multiple of 4.
        if msg_len % 4 != 0 {
            return Err(IceError::MessageLengthNotAligned(msg_len));
        }
        // Magic cookie.
        if cookie != MAGIC_COOKIE {
            return Err(IceError::BadMagicCookie(cookie));
        }

        // Decode message type into class + method.
        let (class, method) = decode_type(type_word)?;

        // Transaction ID.
        let tid_slice = raw.get(8..20).ok_or(IceError::StunTruncated {
            needed: 20,
            have: raw.len(),
        })?;
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(tid_slice);

        // Attribute bytes: from byte 20 up to 20 + msg_len.
        let total_len = STUN_HEADER_LEN.saturating_add(usize::from(msg_len));
        if raw.len() < total_len {
            return Err(IceError::StunTruncated {
                needed: total_len,
                have: raw.len(),
            });
        }
        let attr_bytes = raw
            .get(STUN_HEADER_LEN..total_len)
            .ok_or(IceError::StunTruncated {
                needed: total_len,
                have: raw.len(),
            })?;

        let attributes = decode_attributes(attr_bytes, &transaction_id)?;

        Ok(Self {
            class,
            method,
            transaction_id,
            attributes,
        })
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Encode the STUN message class + method into a 16-bit type word.
fn encode_type(class: StunClass, method: StunMethod) -> u16 {
    // Method bits: STUN type word layout (RFC 8489 §6)
    //   Bits: M11 M10 M9 M8 M7 C1 M6 M5 M4 C0 M3 M2 M1 M0
    //   Binding method = 0x001 (bits M0..M3 only)
    let m = match method {
        StunMethod::Binding => 0x0001u16,
    };
    // C1 = bit 8 of the type word, C0 = bit 4.
    let c = match class {
        StunClass::Request => 0x0000u16,
        StunClass::Indication => 0x0010u16,
        StunClass::SuccessResponse => 0x0100u16,
        StunClass::ErrorResponse => 0x0110u16,
    };
    // For Binding (M = 0x001), bits M3..M0 map to positions 0..3 (below C0 at bit 4).
    // M = method bits; we need to interleave class bits.
    // The standard Binding type words are:
    //   Binding Request          = 0x0001
    //   Binding Indication       = 0x0011
    //   Binding Success Response = 0x0101
    //   Binding Error Response   = 0x0111
    // This comes from: (M & 0xF80) << 2 | C1 | (M & 0x070) << 1 | C0 | (M & 0x00F)
    // For M = 1: (0<<2) | C1 | (0<<1) | C0 | 1 = C1 | C0 | 1
    let m_bits = ((m & 0xF80) << 2) | ((m & 0x070) << 1) | (m & 0x00F);
    m_bits | c
}

/// Decode a STUN type word into class and method.
fn decode_type(type_word: u16) -> Result<(StunClass, StunMethod), IceError> {
    // Extract class bits: C1 at bit 8, C0 at bit 4.
    let c1 = (type_word >> 8) & 0x01;
    let c0 = (type_word >> 4) & 0x01;
    let class = match (c1, c0) {
        (0, 0) => StunClass::Request,
        (0, 1) => StunClass::Indication,
        (1, 0) => StunClass::SuccessResponse,
        (1, 1) => StunClass::ErrorResponse,
        // INVARIANT: c1 and c0 are each masked to 1 bit → only 4 combinations, all covered above.
        _ => StunClass::Request,
    };
    // Extract method bits: M11..M7 from bits 13..9, M6..M4 from bits 7..5, M3..M0 from bits 3..0.
    let m = ((type_word >> 2) & 0xF80) | ((type_word >> 1) & 0x070) | (type_word & 0x00F);
    let method = match m {
        0x001 => StunMethod::Binding,
        other => return Err(IceError::UnsupportedMethod(other)),
    };
    Ok((class, method))
}

/// Build a 20-byte STUN message header.
fn build_header(
    class: StunClass,
    method: StunMethod,
    transaction_id: &[u8; 12],
    attr_body_len: usize,
) -> Vec<u8> {
    let mut hdr = Vec::with_capacity(STUN_HEADER_LEN);
    let type_word = encode_type(class, method);
    hdr.extend_from_slice(&type_word.to_be_bytes());
    // STUN message length fits in u16 (max UDP payload << 65535). Saturate on overflow.
    #[allow(clippy::cast_possible_truncation)]
    let len_field = attr_body_len.min(usize::from(u16::MAX)) as u16;
    hdr.extend_from_slice(&len_field.to_be_bytes());
    hdr.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    hdr.extend_from_slice(transaction_id);
    hdr
}

/// Encode a list of STUN attributes (without MI or FP — those are appended separately).
fn encode_attributes(attrs: &[StunAttribute], tid: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::new();
    for attr in attrs {
        encode_one_attribute(attr, tid, &mut out);
    }
    out
}

/// Encode one STUN attribute into `buf`.
fn encode_one_attribute(attr: &StunAttribute, tid: &[u8; 12], buf: &mut Vec<u8>) {
    match attr {
        StunAttribute::MappedAddress(addr) => {
            let value = encode_mapped_address(*addr);
            push_tlv(buf, 0x0001, &value);
        }
        StunAttribute::XorMappedAddress(addr) => {
            let value = encode_xor_mapped_address(*addr, tid);
            push_tlv(buf, 0x0020, &value);
        }
        StunAttribute::Username(s) => {
            push_tlv(buf, 0x0006, s.as_bytes());
        }
        StunAttribute::MessageIntegrity(hmac) => {
            push_tlv(buf, 0x0008, hmac.as_slice());
        }
        StunAttribute::Fingerprint(crc) => {
            push_tlv(buf, 0x8028, &crc.to_be_bytes());
        }
        StunAttribute::Priority(p) => {
            push_tlv(buf, 0x0024, &p.to_be_bytes());
        }
        StunAttribute::UseCandidate => {
            push_tlv(buf, 0x0025, &[]);
        }
        StunAttribute::IceControlled(tb) => {
            push_tlv(buf, 0x8029, &tb.to_be_bytes());
        }
        StunAttribute::IceControlling(tb) => {
            push_tlv(buf, 0x802A, &tb.to_be_bytes());
        }
        StunAttribute::ErrorCode { code, reason } => {
            // code is a 3-digit STUN error code (300–699); class is 3–6, number 0–99.
            // Both fit in u8 after division/modulo by 100.
            #[allow(clippy::cast_possible_truncation)]
            let class = (code / 100) as u8;
            #[allow(clippy::cast_possible_truncation)]
            let number = (code % 100) as u8;
            let mut v = vec![0, 0, class, number];
            v.extend_from_slice(reason.as_bytes());
            push_tlv(buf, 0x0009, &v);
        }
        StunAttribute::UnknownComprehensionRequired(types) => {
            let mut v: Vec<u8> = Vec::with_capacity(types.len().saturating_mul(2));
            for &t in types {
                v.extend_from_slice(&t.to_be_bytes());
            }
            push_tlv(buf, 0x000A, &v);
        }
        StunAttribute::Software(s) => {
            push_tlv(buf, 0x8022, s.as_bytes());
        }
        StunAttribute::Unknown { attr_type, value } => {
            push_tlv(buf, *attr_type, value);
        }
    }
}

/// Encode a `MAPPED-ADDRESS` value (family + port + addr).
fn encode_mapped_address(addr: SocketAddr) -> Vec<u8> {
    let mut v = Vec::new();
    match addr {
        SocketAddr::V4(a) => {
            v.push(0x00);
            v.push(0x01); // family IPv4
            v.extend_from_slice(&a.port().to_be_bytes());
            v.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            v.push(0x00);
            v.push(0x02); // family IPv6
            v.extend_from_slice(&a.port().to_be_bytes());
            v.extend_from_slice(&a.ip().octets());
        }
    }
    v
}

/// Encode an `XOR-MAPPED-ADDRESS` value.
///
/// For IPv4: port ^ (MAGIC_COOKIE >> 16), addr ^ MAGIC_COOKIE.
/// For IPv6: port ^ (MAGIC_COOKIE >> 16), addr ^ (MAGIC_COOKIE || transaction_id).
fn encode_xor_mapped_address(addr: SocketAddr, tid: &[u8; 12]) -> Vec<u8> {
    let mut v = Vec::new();
    match addr {
        SocketAddr::V4(a) => {
            // MAGIC_COOKIE >> 16 = 0x2112, which always fits in u16.
            #[allow(clippy::cast_possible_truncation)]
            let xport = a.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            let xaddr = u32::from(Ipv4Addr::from(a.ip().octets())) ^ MAGIC_COOKIE;
            v.push(0x00);
            v.push(0x01);
            v.extend_from_slice(&xport.to_be_bytes());
            v.extend_from_slice(&xaddr.to_be_bytes());
        }
        SocketAddr::V6(a) => {
            // MAGIC_COOKIE >> 16 = 0x2112, which always fits in u16.
            #[allow(clippy::cast_possible_truncation)]
            let xport = a.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            let raw = a.ip().octets();
            let mc_bytes = MAGIC_COOKIE.to_be_bytes();
            // Build 16-byte XOR mask: first 4 bytes = magic cookie, next 12 = tid.
            let mask: [u8; 16] = {
                let mut m = [0u8; 16];
                // Copy magic cookie into first 4 bytes.
                if let Some(dst) = m.get_mut(..4) {
                    dst.copy_from_slice(&mc_bytes);
                }
                // Copy transaction ID into bytes 4..16.
                if let Some(dst) = m.get_mut(4..) {
                    dst.copy_from_slice(tid);
                }
                m
            };
            let mut xaddr = [0u8; 16];
            for (out, (r, m)) in xaddr.iter_mut().zip(raw.iter().zip(mask.iter())) {
                *out = r ^ m;
            }
            v.push(0x00);
            v.push(0x02);
            v.extend_from_slice(&xport.to_be_bytes());
            v.extend_from_slice(&xaddr);
        }
    }
    v
}

/// Decode an `XOR-MAPPED-ADDRESS` value.
fn decode_xor_mapped_address(
    value: &[u8],
    tid: &[u8; 12],
    attr_type: u16,
) -> Result<SocketAddr, IceError> {
    if value.len() < 4 {
        return Err(IceError::StunAttrTruncated { attr_type });
    }
    let family = *value
        .get(1)
        .ok_or(IceError::StunAttrTruncated { attr_type })?;
    let xport_bytes: [u8; 2] = value
        .get(2..4)
        .ok_or(IceError::StunAttrTruncated { attr_type })?
        .try_into()
        .map_err(|_| IceError::StunAttrTruncated { attr_type })?;
    let xport = u16::from_be_bytes(xport_bytes);
    // MAGIC_COOKIE >> 16 = 0x2112, which fits in u16.
    #[allow(clippy::cast_possible_truncation)]
    let port = xport ^ ((MAGIC_COOKIE >> 16) as u16);

    match family {
        0x01 => {
            // IPv4
            if value.len() < 8 {
                return Err(IceError::StunAttrTruncated { attr_type });
            }
            let xaddr_bytes: [u8; 4] = value
                .get(4..8)
                .ok_or(IceError::StunAttrTruncated { attr_type })?
                .try_into()
                .map_err(|_| IceError::StunAttrTruncated { attr_type })?;
            let xaddr = u32::from_be_bytes(xaddr_bytes) ^ MAGIC_COOKIE;
            let ip = Ipv4Addr::from(xaddr.to_be_bytes());
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            // IPv6
            if value.len() < 20 {
                return Err(IceError::StunAttrTruncated { attr_type });
            }
            let xaddr: &[u8] = value
                .get(4..20)
                .ok_or(IceError::StunAttrTruncated { attr_type })?;
            let mc_bytes = MAGIC_COOKIE.to_be_bytes();
            let mask: [u8; 16] = {
                let mut m = [0u8; 16];
                if let Some(dst) = m.get_mut(..4) {
                    dst.copy_from_slice(&mc_bytes);
                }
                if let Some(dst) = m.get_mut(4..) {
                    dst.copy_from_slice(tid);
                }
                m
            };
            let mut addr_bytes = [0u8; 16];
            for (out, (x, m)) in addr_bytes.iter_mut().zip(xaddr.iter().zip(mask.iter())) {
                *out = x ^ m;
            }
            let ip = Ipv6Addr::from(addr_bytes);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => Err(IceError::StunAttrTruncated { attr_type }),
    }
}

/// Decode a `MAPPED-ADDRESS` value.
fn decode_mapped_address(value: &[u8], attr_type: u16) -> Result<SocketAddr, IceError> {
    if value.len() < 4 {
        return Err(IceError::StunAttrTruncated { attr_type });
    }
    let family = *value
        .get(1)
        .ok_or(IceError::StunAttrTruncated { attr_type })?;
    let port_bytes: [u8; 2] = value
        .get(2..4)
        .ok_or(IceError::StunAttrTruncated { attr_type })?
        .try_into()
        .map_err(|_| IceError::StunAttrTruncated { attr_type })?;
    let port = u16::from_be_bytes(port_bytes);
    match family {
        0x01 => {
            if value.len() < 8 {
                return Err(IceError::StunAttrTruncated { attr_type });
            }
            let addr_bytes: [u8; 4] = value
                .get(4..8)
                .ok_or(IceError::StunAttrTruncated { attr_type })?
                .try_into()
                .map_err(|_| IceError::StunAttrTruncated { attr_type })?;
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(addr_bytes)),
                port,
            ))
        }
        0x02 => {
            if value.len() < 20 {
                return Err(IceError::StunAttrTruncated { attr_type });
            }
            let addr_bytes: [u8; 16] = value
                .get(4..20)
                .ok_or(IceError::StunAttrTruncated { attr_type })?
                .try_into()
                .map_err(|_| IceError::StunAttrTruncated { attr_type })?;
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(addr_bytes)),
                port,
            ))
        }
        _ => Err(IceError::StunAttrTruncated { attr_type }),
    }
}

/// Decode all attributes from the attribute-body slice.
fn decode_attributes(attr_bytes: &[u8], tid: &[u8; 12]) -> Result<Vec<StunAttribute>, IceError> {
    let mut attrs = Vec::new();
    let mut pos = 0usize;

    while pos < attr_bytes.len() {
        // Need at least 4 bytes for the TL header.
        if attr_bytes.len().saturating_sub(pos) < 4 {
            return Err(IceError::StunTruncated {
                needed: pos.saturating_add(4),
                have: attr_bytes.len().saturating_add(STUN_HEADER_LEN),
            });
        }
        let type_bytes: [u8; 2] = attr_bytes
            .get(pos..pos.saturating_add(2))
            .ok_or(IceError::StunTruncated {
                needed: pos.saturating_add(2),
                have: attr_bytes.len(),
            })?
            .try_into()
            .map_err(|_| IceError::StunTruncated {
                needed: pos.saturating_add(2),
                have: attr_bytes.len(),
            })?;
        let attr_type = u16::from_be_bytes(type_bytes);

        let len_bytes: [u8; 2] = attr_bytes
            .get(pos.saturating_add(2)..pos.saturating_add(4))
            .ok_or(IceError::StunTruncated {
                needed: pos.saturating_add(4),
                have: attr_bytes.len(),
            })?
            .try_into()
            .map_err(|_| IceError::StunTruncated {
                needed: pos.saturating_add(4),
                have: attr_bytes.len(),
            })?;
        let attr_len = usize::from(u16::from_be_bytes(len_bytes));
        let padded_len = (attr_len.saturating_add(3)) & !3;

        let value_start = pos.saturating_add(4);
        let value_end = value_start.saturating_add(attr_len);
        if value_end > attr_bytes.len() {
            return Err(IceError::StunAttrTruncated { attr_type });
        }
        let value = attr_bytes
            .get(value_start..value_end)
            .ok_or(IceError::StunAttrTruncated { attr_type })?;

        let attr = decode_one_attribute(attr_type, value, tid)?;
        attrs.push(attr);

        pos = value_start.saturating_add(padded_len);
    }

    Ok(attrs)
}

/// Decode one STUN attribute.
fn decode_one_attribute(
    attr_type: u16,
    value: &[u8],
    tid: &[u8; 12],
) -> Result<StunAttribute, IceError> {
    match attr_type {
        0x0001 => Ok(StunAttribute::MappedAddress(decode_mapped_address(
            value, attr_type,
        )?)),
        0x0006 => {
            // RFC 8489 §14.3: USERNAME must be a valid UTF-8 SASLprep string.
            // Reject non-UTF-8 bytes rather than silently substituting U+FFFD, which
            // would cause credential mismatches instead of an explicit error.
            let s = String::from_utf8(value.to_vec())
                .map_err(|_| IceError::StunAttrTruncated { attr_type })?;
            Ok(StunAttribute::Username(s))
        }
        0x0008 => {
            if value.len() < 20 {
                return Err(IceError::StunAttrTruncated { attr_type });
            }
            let mut hmac = [0u8; 20];
            hmac.copy_from_slice(
                value
                    .get(..20)
                    .ok_or(IceError::StunAttrTruncated { attr_type })?,
            );
            Ok(StunAttribute::MessageIntegrity(hmac))
        }
        0x0009 => {
            if value.len() < 4 {
                return Err(IceError::StunAttrTruncated { attr_type });
            }
            let class = u16::from(
                *value
                    .get(2)
                    .ok_or(IceError::StunAttrTruncated { attr_type })?,
            );
            let number = u16::from(
                *value
                    .get(3)
                    .ok_or(IceError::StunAttrTruncated { attr_type })?,
            );
            let code = class.saturating_mul(100).saturating_add(number);
            let reason = String::from_utf8_lossy(value.get(4..).unwrap_or(&[])).into_owned();
            Ok(StunAttribute::ErrorCode { code, reason })
        }
        0x000A => {
            // RFC 8489 §14.9: UNKNOWN-ATTRIBUTES contains a sequence of 16-bit codes.
            if value.len() % 2 != 0 {
                return Err(IceError::StunAttrTruncated { attr_type });
            }
            let types: Vec<u16> = value
                .chunks_exact(2)
                .map(|b| {
                    let arr: [u8; 2] = [*b.first().unwrap_or(&0), *b.get(1).unwrap_or(&0)];
                    u16::from_be_bytes(arr)
                })
                .collect();
            Ok(StunAttribute::UnknownComprehensionRequired(types))
        }
        0x0020 => Ok(StunAttribute::XorMappedAddress(decode_xor_mapped_address(
            value, tid, attr_type,
        )?)),
        0x0024 => {
            if value.len() < 4 {
                return Err(IceError::StunAttrTruncated { attr_type });
            }
            let p = u32::from_be_bytes(
                value
                    .get(..4)
                    .ok_or(IceError::StunAttrTruncated { attr_type })?
                    .try_into()
                    .map_err(|_| IceError::StunAttrTruncated { attr_type })?,
            );
            Ok(StunAttribute::Priority(p))
        }
        0x0025 => Ok(StunAttribute::UseCandidate),
        0x8022 => {
            let s = String::from_utf8_lossy(value).into_owned();
            Ok(StunAttribute::Software(s))
        }
        0x8028 => {
            if value.len() < 4 {
                return Err(IceError::StunAttrTruncated { attr_type });
            }
            let crc = u32::from_be_bytes(
                value
                    .get(..4)
                    .ok_or(IceError::StunAttrTruncated { attr_type })?
                    .try_into()
                    .map_err(|_| IceError::StunAttrTruncated { attr_type })?,
            );
            Ok(StunAttribute::Fingerprint(crc))
        }
        0x8029 => {
            if value.len() < 8 {
                return Err(IceError::StunAttrTruncated { attr_type });
            }
            let tb = u64::from_be_bytes(
                value
                    .get(..8)
                    .ok_or(IceError::StunAttrTruncated { attr_type })?
                    .try_into()
                    .map_err(|_| IceError::StunAttrTruncated { attr_type })?,
            );
            Ok(StunAttribute::IceControlled(tb))
        }
        0x802A => {
            if value.len() < 8 {
                return Err(IceError::StunAttrTruncated { attr_type });
            }
            let tb = u64::from_be_bytes(
                value
                    .get(..8)
                    .ok_or(IceError::StunAttrTruncated { attr_type })?
                    .try_into()
                    .map_err(|_| IceError::StunAttrTruncated { attr_type })?,
            );
            Ok(StunAttribute::IceControlling(tb))
        }
        other => Ok(StunAttribute::Unknown {
            attr_type: other,
            value: value.to_vec(),
        }),
    }
}

/// Write a TLV attribute (with padding) into `buf`.
fn push_tlv(buf: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    buf.extend_from_slice(&attr_type.to_be_bytes());
    // Attribute values are bounded by STUN message length (u16), so the cast is safe.
    #[allow(clippy::cast_possible_truncation)]
    buf.extend_from_slice(&(value.len().min(usize::from(u16::MAX)) as u16).to_be_bytes());
    buf.extend_from_slice(value);
    // Pad to 4-byte alignment: number of zero bytes needed so (value.len() + pad) % 4 == 0.
    // wrapping_neg() & 3 is equivalent to (4 - len % 4) % 4 without any arithmetic side effects.
    let pad = value.len().wrapping_neg() & 3;
    // pad is 0..=3, which fits in [0u8; 3]; use an explicit match to avoid slicing.
    match pad {
        1 => buf.extend_from_slice(&[0u8; 1]),
        2 => buf.extend_from_slice(&[0u8; 2]),
        3 => buf.extend_from_slice(&[0u8; 3]),
        _ => {} // 0 — no padding needed
    }
}

/// Find the byte offset of the first occurrence of an attribute type in the raw message.
///
/// Returns the absolute byte offset (from the start of `raw`) of the attribute's TYPE
/// field (i.e. the start of the TLV triple).
///
/// # Errors
///
/// - [`IceError::StunTruncated`] — `raw` is shorter than the STUN header.
/// - [`IceError::StunAttrTruncated`] — an attribute's claimed length extends past the
///   message body (stops traversal so an oversized length cannot skip the target).
/// - [`IceError::AttrNotFound`] — the target attribute type is not present.
fn find_attr_offset(raw: &[u8], target_type: u16) -> Result<usize, IceError> {
    if raw.len() < STUN_HEADER_LEN {
        return Err(IceError::StunTruncated {
            needed: STUN_HEADER_LEN,
            have: raw.len(),
        });
    }
    // Header length field is at bytes 2-3 (already validated len >= 20).
    let msg_len = u16::from_be_bytes([*raw.get(2).unwrap_or(&0), *raw.get(3).unwrap_or(&0)]);
    let total = STUN_HEADER_LEN.saturating_add(usize::from(msg_len));
    let attr_bytes = raw
        .get(STUN_HEADER_LEN..total)
        .ok_or(IceError::StunTruncated {
            needed: total,
            have: raw.len(),
        })?;

    let mut pos = 0usize;
    while pos.saturating_add(4) <= attr_bytes.len() {
        let t = u16::from_be_bytes([
            *attr_bytes.get(pos).unwrap_or(&0),
            *attr_bytes.get(pos.saturating_add(1)).unwrap_or(&0),
        ]);
        let l = usize::from(u16::from_be_bytes([
            *attr_bytes.get(pos.saturating_add(2)).unwrap_or(&0),
            *attr_bytes.get(pos.saturating_add(3)).unwrap_or(&0),
        ]));
        // Bounds-check the attribute value before advancing past it.
        // Without this, an oversized length field could skip the target attribute,
        // allowing trailing-attribute injection to bypass integrity checks.
        let value_end = pos.saturating_add(4).saturating_add(l);
        if value_end > attr_bytes.len() {
            return Err(IceError::StunAttrTruncated { attr_type: t });
        }
        if t == target_type {
            return Ok(STUN_HEADER_LEN.saturating_add(pos));
        }
        let padded = (l.saturating_add(3)) & !3;
        pos = pos.saturating_add(4).saturating_add(padded);
    }
    Err(IceError::AttrNotFound {
        attr_type: target_type,
    })
}

/// Compute HMAC-SHA1 over `data` with `key`.
///
/// Returns `Err` if HMAC construction fails (impossible in practice for HMAC-SHA1
/// since HMAC accepts any key length).
fn compute_hmac_sha1(key: &[u8], data: &[u8]) -> Result<[u8; 20], IceError> {
    type HmacSha1 = hmac::Hmac<Sha1>;
    // HMAC-SHA1 accepts any key length; this error branch is unreachable in practice.
    let mut mac = HmacSha1::new_from_slice(key)
        .map_err(|e| IceError::Transport(format!("HMAC-SHA1 key construction failed: {e}")))?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    Ok(out)
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

    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::*;

    fn tid(seed: u8) -> [u8; 12] {
        [seed; 12]
    }

    #[test]
    fn roundtrip_binding_request() {
        let mut msg = StunMessage::new_binding_request(tid(1));
        let addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 5678);
        msg.attributes.push(StunAttribute::XorMappedAddress(addr));
        let bytes = msg.encode();
        let decoded = StunMessage::decode(&bytes).unwrap();
        assert_eq!(decoded.class, StunClass::Request);
        assert_eq!(decoded.method, StunMethod::Binding);
        assert_eq!(decoded.transaction_id, tid(1));
        assert_eq!(decoded.attributes.len(), 1);
        // XOR-MAPPED-ADDRESS round-trip: verify the address decoded correctly.
        match &decoded.attributes[0] {
            StunAttribute::XorMappedAddress(decoded_addr) => {
                assert_eq!(*decoded_addr, addr);
            }
            other => panic!("expected XorMappedAddress, got {other:?}"),
        }
    }

    #[test]
    fn xor_mapped_address_v4() {
        let addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
        let tid_val = [0xABu8; 12];
        let encoded = encode_xor_mapped_address(addr, &tid_val);
        // Decode with same tid.
        let decoded = decode_xor_mapped_address(&encoded, &tid_val, 0x0020).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn xor_mapped_address_v6() {
        let addr = SocketAddr::new(
            std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            443,
        );
        let tid_val = [0x12u8; 12];
        let encoded = encode_xor_mapped_address(addr, &tid_val);
        let decoded = decode_xor_mapped_address(&encoded, &tid_val, 0x0020).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn message_integrity_accept() {
        let msg = StunMessage::new_binding_request(tid(2));
        let key = b"correct-horse";
        let bytes = msg.encode_with_integrity(key).unwrap();
        assert!(StunMessage::verify_integrity(&bytes, key).is_ok());
    }

    #[test]
    fn message_integrity_reject_bad_key() {
        let msg = StunMessage::new_binding_request(tid(3));
        let bytes = msg.encode_with_integrity(b"good-key").unwrap();
        let result = StunMessage::verify_integrity(&bytes, b"bad-key");
        assert!(matches!(result, Err(IceError::IntegrityMismatch)));
    }

    #[test]
    fn fingerprint_roundtrip() {
        let msg = StunMessage::new_binding_request(tid(4));
        let key = b"mykey";
        let bytes = msg.encode_with_integrity_and_fingerprint(key).unwrap();
        assert!(StunMessage::verify_integrity(&bytes, key).is_ok());
        assert!(StunMessage::verify_fingerprint(&bytes).is_ok());
    }

    #[test]
    fn truncated_header() {
        let result = StunMessage::decode(&[0u8; 5]);
        assert!(matches!(result, Err(IceError::StunTruncated { .. })));
    }

    #[test]
    fn truncated_attr() {
        // Valid header but attr with length > remaining bytes.
        let mut msg = StunMessage::new_binding_request(tid(5));
        msg.attributes.push(StunAttribute::Priority(1234));
        let mut bytes = msg.encode();
        // Corrupt the attr length field to claim 100 bytes when only 4 are present.
        bytes[22] = 0;
        bytes[23] = 100;
        let result = StunMessage::decode(&bytes);
        assert!(matches!(result, Err(IceError::StunAttrTruncated { .. })));
    }

    #[test]
    fn bad_magic_cookie() {
        let msg = StunMessage::new_binding_request(tid(6));
        let mut bytes = msg.encode();
        // Overwrite magic cookie bytes 4..8.
        bytes[4] = 0xDE;
        bytes[5] = 0xAD;
        bytes[6] = 0xBE;
        bytes[7] = 0xEF;
        let result = StunMessage::decode(&bytes);
        assert!(matches!(result, Err(IceError::BadMagicCookie(_))));
    }

    #[test]
    fn zero_length_attr_use_candidate() {
        let mut msg = StunMessage::new_binding_request(tid(7));
        msg.attributes.push(StunAttribute::UseCandidate);
        let bytes = msg.encode();
        let decoded = StunMessage::decode(&bytes).unwrap();
        assert_eq!(decoded.attributes.len(), 1);
        assert!(matches!(decoded.attributes[0], StunAttribute::UseCandidate));
    }

    /// Security regression: appending a trailing attribute AFTER MESSAGE-INTEGRITY
    /// must cause verify_integrity to fail with AttrOrderingViolation.
    /// An on-path attacker must not be able to inject attributes into a signed message.
    #[test]
    fn mi_trailing_attr_injection_blocked() {
        let msg = StunMessage::new_binding_request(tid(8));
        let key = b"secret";
        let mut bytes = msg.encode_with_integrity(key).unwrap();

        // Craft a PRIORITY(9999) attribute (type=0x0024, len=4, value=4 bytes).
        let injected: &[u8] = &[0x00, 0x24, 0x00, 0x04, 0x00, 0x00, 0x27, 0x0F];

        // Extend the bytes with the injected attribute.
        bytes.extend_from_slice(injected);

        // Bump the message-length field in the header to account for the extra 8 bytes.
        let orig_len = u16::from_be_bytes([bytes[2], bytes[3]]);
        let new_len_bytes = orig_len.saturating_add(8).to_be_bytes();
        bytes[2] = new_len_bytes[0];
        bytes[3] = new_len_bytes[1];

        // Integrity verification MUST fail — trailing injection detected.
        let result = StunMessage::verify_integrity(&bytes, key);
        assert!(
            matches!(result, Err(IceError::AttrOrderingViolation(_))),
            "expected AttrOrderingViolation, got {result:?}"
        );
    }

    /// Security regression: appending a trailing attribute AFTER FINGERPRINT
    /// must cause verify_fingerprint to fail with AttrOrderingViolation.
    #[test]
    fn fp_trailing_attr_injection_blocked() {
        let msg = StunMessage::new_binding_request(tid(9));
        let key = b"fp-secret";
        let mut bytes = msg.encode_with_integrity_and_fingerprint(key).unwrap();

        // Craft a SOFTWARE("x") attribute (type=0x8022, len=1, value=1 byte + 3 pad).
        let injected: &[u8] = &[0x80, 0x22, 0x00, 0x01, b'x', 0, 0, 0];
        bytes.extend_from_slice(injected);
        // Bump length.
        let orig_len = u16::from_be_bytes([bytes[2], bytes[3]]);
        let new_len_bytes = orig_len.saturating_add(8).to_be_bytes();
        bytes[2] = new_len_bytes[0];
        bytes[3] = new_len_bytes[1];

        let result = StunMessage::verify_fingerprint(&bytes);
        assert!(
            matches!(result, Err(IceError::AttrOrderingViolation(_))),
            "expected AttrOrderingViolation, got {result:?}"
        );
    }

    /// Unknown STUN methods must be rejected, not coerced to Binding.
    #[test]
    fn unknown_method_rejected() {
        // Build a syntactically valid STUN header with method=0x003 (TURN Allocate).
        // Type word: class=Request(0b00_00), method=0x003 → type = 0x0003.
        let mut header = [0u8; 20];
        header[0] = 0x00;
        header[1] = 0x03;
        // Length = 0 (no attributes).
        // Magic cookie.
        header[4] = 0x21;
        header[5] = 0x12;
        header[6] = 0xA4;
        header[7] = 0x42;
        // TID — rest already zero.
        let result = StunMessage::decode(&header);
        assert!(
            matches!(result, Err(IceError::UnsupportedMethod(_))),
            "expected UnsupportedMethod, got {result:?}"
        );
    }
}
