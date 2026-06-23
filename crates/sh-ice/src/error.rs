//! Error types for the `sh-ice` crate.

use thiserror::Error;

/// All errors that can be produced by the `sh-ice` crate.
#[derive(Debug, Error)]
pub enum IceError {
    /// A STUN message header or body is shorter than the minimum required length.
    #[error("STUN message too short: need {needed}, have {have}")]
    StunTruncated {
        /// The number of bytes required.
        needed: usize,
        /// The number of bytes actually available.
        have: usize,
    },

    /// A STUN attribute's value field extends past the end of the buffer.
    #[error("STUN attribute value truncated: attr type {attr_type:#06x}")]
    StunAttrTruncated {
        /// The attribute type code of the truncated attribute.
        attr_type: u16,
    },

    /// The 32-bit STUN magic cookie field does not equal `0x2112A442`.
    #[error("bad STUN magic cookie: {0:#010x}")]
    BadMagicCookie(u32),

    /// A comprehension-required STUN attribute (top bit clear) was encountered that
    /// this implementation does not understand.
    #[error("unknown comprehension-required STUN attribute: {0:#06x}")]
    UnknownComprehensionRequired(u16),

    /// The HMAC-SHA1 `MESSAGE-INTEGRITY` attribute did not match the supplied key.
    #[error("MESSAGE-INTEGRITY verification failed")]
    IntegrityMismatch,

    /// The CRC32 `FINGERPRINT` attribute did not match the computed value.
    #[error("FINGERPRINT verification failed")]
    FingerprintMismatch,

    /// The top two bits of the STUN message type word were not `0b00`.
    #[error("STUN message type bits invalid (top 2 bits must be 0)")]
    InvalidMessageTypeBits,

    /// The message length field is not a multiple of four.
    #[error("STUN message length {0} is not a multiple of 4")]
    MessageLengthNotAligned(u16),

    /// Candidate gathering failed.
    #[error("ICE gather failed: {0}")]
    GatherFailed(String),

    /// Connectivity check failed.
    #[error("ICE check failed: {0}")]
    CheckFailed(String),

    /// TURN credential timestamp would overflow `i64`.
    #[error("TURN credential generation failed: timestamp overflow")]
    TurnCredTimestampOverflow,

    /// An underlying transport operation failed.
    #[error("transport error: {0}")]
    Transport(String),

    /// No candidates are available to form pairs.
    #[error("no candidates available")]
    NoCandidates,

    /// The ICE connectivity-check phase timed out without finding a usable path.
    #[error("ICE timed out")]
    Timeout,

    /// A required STUN attribute was not found in the message.
    #[error("required STUN attribute {attr_type:#06x} not found")]
    AttrNotFound {
        /// The attribute type code that was expected.
        attr_type: u16,
    },

    /// The STUN message type contains an unsupported method.
    #[error("unsupported STUN method: {0:#05x}")]
    UnsupportedMethod(u16),

    /// The STUN MESSAGE-INTEGRITY or FINGERPRINT attribute was not the last attribute.
    #[error("STUN attribute ordering violation: {0} must be last")]
    AttrOrderingViolation(&'static str),
}
