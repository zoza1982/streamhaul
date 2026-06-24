//! File-transfer wire framing (LLD §3.2 / §4.7, P7 — ADR-0024).
//!
//! File transfer has two planes, both big-endian and hostile-input-safe (never panic, never
//! index out of bounds, every field bounds-checked):
//!
//! ## Control plane — carried on the reliable **Control** channel
//!
//! Four message types, each serialized as the payload of a [`ControlFrame`](crate::ControlFrame)
//! with a `KIND_FILE_*` kind byte (the same pattern as the codec [`capability`](crate::capability)
//! handshake):
//!
//! | Kind  | Message        | Direction        | Wire layout |
//! |-------|----------------|------------------|-------------|
//! | `0x30` [`KIND_FILE_OFFER`]   | [`FileOffer`]  | sender → receiver | `transfer_id u64 \| total_size u64 \| chunk_size u32 \| sha256 [u8;32] \| name_len u8 \| name[name_len]` |
//! | `0x31` [`KIND_FILE_ACCEPT`]  | [`FileAccept`] | receiver → sender | `transfer_id u64 \| resume_offset u64` |
//! | `0x32` [`KIND_FILE_ABORT`]   | [`FileAbort`]  | either           | `transfer_id u64 \| code u8` |
//! | `0x33` [`KIND_FILE_COMPLETE`]| [`FileComplete`]| receiver → sender| `transfer_id u64 \| ok u8` |
//!
//! ## Data plane — carried on a dedicated **File** stream (one QUIC stream / DataChannel per transfer)
//!
//! Each chunk is a fixed [`FILE_CHUNK_HEADER_LEN`]-byte [`FileChunkHeader`] followed by `len`
//! payload bytes:
//!
//! ```text
//! transfer_id u64 | offset u64 | len u32 | flags u8 || <len payload bytes>
//! ```
//!
//! `flags` bit 0 ([`CHUNK_FLAG_LAST`]) marks the final chunk of the transfer.
//!
//! ## Bounds (DoS hardening)
//!
//! - A file **name** is at most [`MAX_FILE_NAME`] bytes (1-byte length prefix). The bytes are opaque
//!   here; the orchestrator (`sh-core`) rejects path separators / `..` / non-UTF-8.
//! - A chunk `len` and an offered `chunk_size` must be in `1..=`[`MAX_FILE_CHUNK`]; zero or larger is
//!   rejected with [`ProtocolError::FileChunkTooLarge`]. This bounds the buffer a hostile peer can
//!   force the receiver to allocate per chunk.
//! - [`FileComplete::ok`] and [`FileAbort::code`] are range-validated on decode.
//!
//! The `shp_decode` cargo-fuzz target exercises every decoder here on arbitrary bytes.

use crate::bits::take_array;
use crate::error::ProtocolError;

// ── Control frame kind bytes ──────────────────────────────────────────────────

// NOTE: these share the single control-channel `kind` byte space with `capability` (0x10–0x11) and
// `transport_caps` (0x20–0x21). File uses the 0x30 block. A compile-time assertion in `lib.rs`
// (`all KIND_* distinct`) guards against future collisions across modules.

/// `ControlFrame::kind` for a [`FileOffer`] (sender announces a file).
pub const KIND_FILE_OFFER: u8 = 0x30;
/// `ControlFrame::kind` for a [`FileAccept`] (receiver accepts, carrying a resume offset).
pub const KIND_FILE_ACCEPT: u8 = 0x31;
/// `ControlFrame::kind` for a [`FileAbort`] (either side cancels a transfer).
pub const KIND_FILE_ABORT: u8 = 0x32;
/// `ControlFrame::kind` for a [`FileComplete`] (receiver reports integrity success/failure).
pub const KIND_FILE_COMPLETE: u8 = 0x33;

// ── Bounds ────────────────────────────────────────────────────────────────────

/// Maximum file-name length in bytes (the 1-byte `name_len` field caps this at 255 anyway, but the
/// named constant documents intent and is used by the orchestrator).
pub const MAX_FILE_NAME: usize = 255;

/// Maximum file chunk payload size (1 MiB). Bounds the per-chunk receive allocation; also the upper
/// bound for an offered `chunk_size`. A `len`/`chunk_size` of `0` or above this is rejected.
pub const MAX_FILE_CHUNK: u32 = 1024 * 1024;

/// Wire length of a [`FileChunkHeader`]: `transfer_id(8) | offset(8) | len(4) | flags(1)`.
pub const FILE_CHUNK_HEADER_LEN: usize = 21;

/// Wire length of a [`FileAccept`] payload: `transfer_id(8) | resume_offset(8)`.
pub const FILE_ACCEPT_LEN: usize = 16;

/// Wire length of a [`FileAbort`] payload: `transfer_id(8) | code(1)`.
pub const FILE_ABORT_LEN: usize = 9;

/// Wire length of a [`FileComplete`] payload: `transfer_id(8) | ok(1)`.
pub const FILE_COMPLETE_LEN: usize = 9;

/// Fixed prefix length of a [`FileOffer`] payload, before the variable-length name:
/// `transfer_id(8) | total_size(8) | chunk_size(4) | sha256(32) | name_len(1)`.
pub const FILE_OFFER_FIXED_LEN: usize = 53;

/// `flags` bit 0: this is the final chunk of the transfer.
pub const CHUNK_FLAG_LAST: u8 = 0b0000_0001;

/// Reserved chunk-flag bits (1–7) — must be zero; rejected on decode to keep the format unambiguous.
const CHUNK_FLAGS_RESERVED: u8 = 0b1111_1110;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Validate a chunk `len` / offered `chunk_size`: must be `1..=MAX_FILE_CHUNK`.
fn check_chunk_size(value: u32) -> Result<(), ProtocolError> {
    if value == 0 || value > MAX_FILE_CHUNK {
        return Err(ProtocolError::FileChunkTooLarge(u64::from(value)));
    }
    Ok(())
}

// ── FileOffer ───────────────────────────────────────────────────────────────

/// A file-transfer offer: the sender announces a file's identity, size, chunking, and digest.
///
/// The `sha256` is computed over the **entire** file content; the receiver verifies it after
/// reassembly (ADR-0024 integrity). `chunk_size` is the sender's intended payload size per chunk
/// (`1..=`[`MAX_FILE_CHUNK`]).
///
/// # Examples
///
/// ```
/// use sh_protocol::file::FileOffer;
///
/// let offer = FileOffer {
///     transfer_id: 1,
///     total_size: 4096,
///     chunk_size: 1024,
///     sha256: [0u8; 32],
///     name: b"notes.txt".to_vec(),
/// };
/// let bytes = offer.encode().unwrap();
/// assert_eq!(FileOffer::decode(&bytes).unwrap(), offer);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOffer {
    /// Opaque transfer identifier, unique per active transfer on the session.
    pub transfer_id: u64,
    /// Total file size in bytes.
    pub total_size: u64,
    /// Intended chunk payload size in bytes (`1..=MAX_FILE_CHUNK`).
    pub chunk_size: u32,
    /// SHA-256 digest of the whole file (integrity check after reassembly).
    pub sha256: [u8; 32],
    /// File name bytes (≤ [`MAX_FILE_NAME`]). Opaque here; sanitized by the orchestrator.
    pub name: Vec<u8>,
}

impl FileOffer {
    /// Serialize to the wire form.
    ///
    /// # Errors
    /// - [`ProtocolError::FileChunkTooLarge`] if `chunk_size` is `0` or above [`MAX_FILE_CHUNK`].
    /// - [`ProtocolError::InvalidFileField`] if `name` exceeds [`MAX_FILE_NAME`] bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        check_chunk_size(self.chunk_size)?;
        let name_len = u8::try_from(self.name.len())
            .map_err(|_| ProtocolError::InvalidFileField(self.name.len() as u64))?;
        let mut buf = Vec::with_capacity(FILE_OFFER_FIXED_LEN.saturating_add(self.name.len()));
        buf.extend_from_slice(&self.transfer_id.to_be_bytes());
        buf.extend_from_slice(&self.total_size.to_be_bytes());
        buf.extend_from_slice(&self.chunk_size.to_be_bytes());
        buf.extend_from_slice(&self.sha256);
        buf.push(name_len);
        buf.extend_from_slice(&self.name);
        Ok(buf)
    }

    /// Parse from the wire form. Never panics.
    ///
    /// # Errors
    /// - [`ProtocolError::Truncated`] if the buffer is too short for the fixed prefix or the
    ///   declared name length.
    /// - [`ProtocolError::FileChunkTooLarge`] if `chunk_size` is out of range.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        let mut c = data;
        let transfer_id = u64::from_be_bytes(read_array::<8>(&mut c)?);
        let total_size = u64::from_be_bytes(read_array::<8>(&mut c)?);
        let chunk_size = u32::from_be_bytes(read_array::<4>(&mut c)?);
        check_chunk_size(chunk_size)?;
        let sha256 = read_array::<32>(&mut c)?;
        let [name_len] = read_array::<1>(&mut c)?;
        let name_len = usize::from(name_len);
        // `c` now points just past the fixed prefix; the name is the next `name_len` bytes.
        let name = c
            .get(..name_len)
            .ok_or(ProtocolError::Truncated {
                needed: name_len,
                have: c.len(),
            })?
            .to_vec();
        Ok(Self {
            transfer_id,
            total_size,
            chunk_size,
            sha256,
            name,
        })
    }
}

// ── FileAccept ──────────────────────────────────────────────────────────────

/// Receiver's acceptance of an offer, advertising how many contiguous leading bytes it already
/// holds (`resume_offset`); the sender resumes from there. `resume_offset == 0` means start fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileAccept {
    /// The offered transfer id being accepted.
    pub transfer_id: u64,
    /// Byte offset to resume from (count of contiguous bytes already held by the receiver).
    pub resume_offset: u64,
}

impl FileAccept {
    /// Serialize to the 16-byte wire form.
    #[must_use]
    pub fn encode(&self) -> [u8; FILE_ACCEPT_LEN] {
        let mut buf = [0u8; FILE_ACCEPT_LEN];
        buf[0..8].copy_from_slice(&self.transfer_id.to_be_bytes());
        buf[8..16].copy_from_slice(&self.resume_offset.to_be_bytes());
        buf
    }

    /// Parse from the 16-byte wire form. Never panics.
    ///
    /// # Errors
    /// [`ProtocolError::Truncated`] if fewer than [`FILE_ACCEPT_LEN`] bytes.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        // Length-gate to the fixed size (clean `needed: 16` error), then read from the validated
        // array — the inner reads cannot fail.
        let b = take_array::<FILE_ACCEPT_LEN>(data)?;
        let mut c: &[u8] = &b;
        Ok(Self {
            transfer_id: u64::from_be_bytes(read_array::<8>(&mut c)?),
            resume_offset: u64::from_be_bytes(read_array::<8>(&mut c)?),
        })
    }
}

// ── FileAbort ───────────────────────────────────────────────────────────────

/// Reason a transfer was aborted. Wire discriminant must round-trip exactly.
///
/// `#[non_exhaustive]`: future protocol versions may add codes (e.g. `Timeout`, `QuotaExceeded`), so
/// downstream `match` must carry a catch-all arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum AbortCode {
    /// The receiver declined the offer (e.g. user rejected, capability missing).
    Declined = 0,
    /// Integrity check (SHA-256) failed after reassembly.
    IntegrityFailed = 1,
    /// An internal error on either side (I/O, resource).
    InternalError = 2,
    /// The offered transfer was unsupported (bad chunk size, name, etc.).
    Unsupported = 3,
}

impl AbortCode {
    /// Map a wire byte to an [`AbortCode`].
    ///
    /// # Errors
    /// [`ProtocolError::InvalidFileField`] for an unknown discriminant.
    pub fn from_u8(v: u8) -> Result<Self, ProtocolError> {
        match v {
            0 => Ok(Self::Declined),
            1 => Ok(Self::IntegrityFailed),
            2 => Ok(Self::InternalError),
            3 => Ok(Self::Unsupported),
            other => Err(ProtocolError::InvalidFileField(u64::from(other))),
        }
    }
}

/// Either side cancels an in-flight transfer with a reason [`AbortCode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileAbort {
    /// The transfer being aborted.
    pub transfer_id: u64,
    /// Why it was aborted.
    pub code: AbortCode,
}

impl FileAbort {
    /// Serialize to the 9-byte wire form.
    #[must_use]
    pub fn encode(&self) -> [u8; FILE_ABORT_LEN] {
        let mut buf = [0u8; FILE_ABORT_LEN];
        buf[0..8].copy_from_slice(&self.transfer_id.to_be_bytes());
        buf[8] = self.code as u8;
        buf
    }

    /// Parse from the 9-byte wire form. Never panics.
    ///
    /// # Errors
    /// - [`ProtocolError::Truncated`] if fewer than [`FILE_ABORT_LEN`] bytes.
    /// - [`ProtocolError::InvalidFileField`] for an unknown abort code.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        let b = take_array::<FILE_ABORT_LEN>(data)?;
        let mut c: &[u8] = &b;
        let transfer_id = u64::from_be_bytes(read_array::<8>(&mut c)?);
        let [code] = read_array::<1>(&mut c)?;
        Ok(Self {
            transfer_id,
            code: AbortCode::from_u8(code)?,
        })
    }
}

// ── FileComplete ──────────────────────────────────────────────────────────────

/// Receiver's terminal report: the reassembled file's SHA-256 matched the offer (`ok = true`) or
/// did not (`ok = false`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileComplete {
    /// The completed transfer.
    pub transfer_id: u64,
    /// Whether the integrity check passed.
    pub ok: bool,
}

impl FileComplete {
    /// Serialize to the 9-byte wire form.
    #[must_use]
    pub fn encode(&self) -> [u8; FILE_COMPLETE_LEN] {
        let mut buf = [0u8; FILE_COMPLETE_LEN];
        buf[0..8].copy_from_slice(&self.transfer_id.to_be_bytes());
        buf[8] = u8::from(self.ok);
        buf
    }

    /// Parse from the 9-byte wire form. Never panics.
    ///
    /// # Errors
    /// - [`ProtocolError::Truncated`] if fewer than [`FILE_COMPLETE_LEN`] bytes.
    /// - [`ProtocolError::InvalidFileField`] if the `ok` byte is not `0` or `1`.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        let b = take_array::<FILE_COMPLETE_LEN>(data)?;
        let mut c: &[u8] = &b;
        let transfer_id = u64::from_be_bytes(read_array::<8>(&mut c)?);
        let [ok_byte] = read_array::<1>(&mut c)?;
        let ok = match ok_byte {
            0 => false,
            1 => true,
            other => return Err(ProtocolError::InvalidFileField(u64::from(other))),
        };
        Ok(Self { transfer_id, ok })
    }
}

// ── FileChunkHeader (data plane) ───────────────────────────────────────────────

/// The fixed 21-byte header prefixing every file data chunk on the File stream.
///
/// The `offset` is the byte position of this chunk's payload within the whole file — redundant with
/// the ordered stream, but it makes resume robust and lets the receiver validate placement.
///
/// # Examples
///
/// ```
/// use sh_protocol::file::FileChunkHeader;
///
/// let h = FileChunkHeader { transfer_id: 1, offset: 0, len: 1024, last: false };
/// let bytes = h.encode().unwrap();
/// assert_eq!(FileChunkHeader::decode(&bytes).unwrap(), h);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileChunkHeader {
    /// The transfer this chunk belongs to.
    pub transfer_id: u64,
    /// Byte offset of this chunk's payload within the file.
    pub offset: u64,
    /// Payload length in bytes following this header (`1..=MAX_FILE_CHUNK`).
    pub len: u32,
    /// True if this is the last chunk of the transfer.
    pub last: bool,
}

impl FileChunkHeader {
    /// Serialize to the 21-byte wire form.
    ///
    /// # Errors
    /// [`ProtocolError::FileChunkTooLarge`] if `len` is `0` or above [`MAX_FILE_CHUNK`].
    pub fn encode(&self) -> Result<[u8; FILE_CHUNK_HEADER_LEN], ProtocolError> {
        check_chunk_size(self.len)?;
        let mut buf = [0u8; FILE_CHUNK_HEADER_LEN];
        buf[0..8].copy_from_slice(&self.transfer_id.to_be_bytes());
        buf[8..16].copy_from_slice(&self.offset.to_be_bytes());
        buf[16..20].copy_from_slice(&self.len.to_be_bytes());
        buf[20] = if self.last { CHUNK_FLAG_LAST } else { 0 };
        Ok(buf)
    }

    /// Parse only the 21-byte header (not the payload). Never panics.
    ///
    /// # Errors
    /// - [`ProtocolError::Truncated`] if fewer than [`FILE_CHUNK_HEADER_LEN`] bytes.
    /// - [`ProtocolError::FileChunkTooLarge`] if the declared `len` is out of range.
    /// - [`ProtocolError::ReservedBitsSet`] if any reserved flag bit is set.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        let b = take_array::<FILE_CHUNK_HEADER_LEN>(data)?;
        let mut c: &[u8] = &b;
        let transfer_id = u64::from_be_bytes(read_array::<8>(&mut c)?);
        let offset = u64::from_be_bytes(read_array::<8>(&mut c)?);
        let len = u32::from_be_bytes(read_array::<4>(&mut c)?);
        check_chunk_size(len)?;
        let [flags] = read_array::<1>(&mut c)?;
        if (flags & CHUNK_FLAGS_RESERVED) != 0 {
            return Err(ProtocolError::ReservedBitsSet);
        }
        Ok(Self {
            transfer_id,
            offset,
            len,
            last: (flags & CHUNK_FLAG_LAST) != 0,
        })
    }
}

// ── Panic-free sequential reader ────────────────────────────────────────────────
//
// A tiny cursor over the input: each read pulls a fixed `N`-byte array off the front and advances.
// Built on `take_array` (bounds-checked, `Truncated` on short input) so there is no indexing and no
// silent zero-fill — a short buffer is a hard error, never a corrupt field.

/// Read a fixed `N`-byte array from the front of `*cursor` and advance past it.
///
/// # Errors
/// [`ProtocolError::Truncated`] if fewer than `N` bytes remain.
fn read_array<const N: usize>(cursor: &mut &[u8]) -> Result<[u8; N], ProtocolError> {
    let arr = take_array::<N>(cursor)?;
    // `take_array` succeeded, so `cursor.len() >= N`; the suffix slice is always present.
    *cursor = cursor.get(N..).unwrap_or_default();
    Ok(arr)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn kind_bytes_are_distinct() {
        let kinds = [
            KIND_FILE_OFFER,
            KIND_FILE_ACCEPT,
            KIND_FILE_ABORT,
            KIND_FILE_COMPLETE,
        ];
        for (i, a) in kinds.iter().enumerate() {
            for b in &kinds[i + 1..] {
                assert_ne!(a, b, "file kind bytes must be distinct");
            }
        }
    }

    #[test]
    fn offer_known_layout_roundtrips() {
        let offer = FileOffer {
            transfer_id: 0x0102_0304_0506_0708,
            total_size: 0x1122_3344_5566_7788,
            chunk_size: 65536,
            sha256: [0xAB; 32],
            name: b"report.pdf".to_vec(),
        };
        let bytes = offer.encode().unwrap();
        // Fixed prefix (53) + name (10) = 63.
        assert_eq!(bytes.len(), FILE_OFFER_FIXED_LEN + 10);
        assert_eq!(&bytes[0..8], &offer.transfer_id.to_be_bytes());
        assert_eq!(&bytes[8..16], &offer.total_size.to_be_bytes());
        assert_eq!(&bytes[16..20], &offer.chunk_size.to_be_bytes());
        assert_eq!(&bytes[20..52], &offer.sha256);
        assert_eq!(bytes[52], 10); // name_len
        assert_eq!(&bytes[53..63], b"report.pdf");
        assert_eq!(FileOffer::decode(&bytes), Ok(offer));
    }

    #[test]
    fn offer_empty_name_roundtrips() {
        let offer = FileOffer {
            transfer_id: 7,
            total_size: 0,
            chunk_size: 1,
            sha256: [0; 32],
            name: Vec::new(),
        };
        let bytes = offer.encode().unwrap();
        assert_eq!(bytes.len(), FILE_OFFER_FIXED_LEN);
        assert_eq!(FileOffer::decode(&bytes), Ok(offer));
    }

    #[test]
    fn offer_rejects_zero_and_oversized_chunk_size() {
        let mut offer = FileOffer {
            transfer_id: 1,
            total_size: 10,
            chunk_size: 0,
            sha256: [0; 32],
            name: vec![],
        };
        assert_eq!(offer.encode(), Err(ProtocolError::FileChunkTooLarge(0)));
        offer.chunk_size = MAX_FILE_CHUNK + 1;
        assert_eq!(
            offer.encode(),
            Err(ProtocolError::FileChunkTooLarge(u64::from(
                MAX_FILE_CHUNK + 1
            )))
        );
    }

    #[test]
    fn offer_decode_rejects_truncated_name() {
        // name_len says 5 but only 2 name bytes present.
        let mut bytes = FileOffer {
            transfer_id: 1,
            total_size: 1,
            chunk_size: 16,
            sha256: [0; 32],
            name: b"hello".to_vec(),
        }
        .encode()
        .unwrap();
        bytes.truncate(FILE_OFFER_FIXED_LEN + 2); // drop 3 name bytes
        assert!(matches!(
            FileOffer::decode(&bytes),
            Err(ProtocolError::Truncated { .. })
        ));
    }

    #[test]
    fn offer_decode_rejects_oversized_chunk_size_from_wire() {
        let mut bytes = FileOffer {
            transfer_id: 1,
            total_size: 1,
            chunk_size: 16,
            sha256: [0; 32],
            name: vec![],
        }
        .encode()
        .unwrap();
        // Overwrite chunk_size (bytes 16..20) with MAX+1.
        bytes[16..20].copy_from_slice(&(MAX_FILE_CHUNK + 1).to_be_bytes());
        assert!(matches!(
            FileOffer::decode(&bytes),
            Err(ProtocolError::FileChunkTooLarge(_))
        ));
    }

    #[test]
    fn accept_roundtrips() {
        let a = FileAccept {
            transfer_id: 0xDEAD_BEEF_0000_0001,
            resume_offset: 4096,
        };
        let bytes = a.encode();
        assert_eq!(bytes.len(), FILE_ACCEPT_LEN);
        assert_eq!(FileAccept::decode(&bytes), Ok(a));
        assert_eq!(
            FileAccept::decode(&bytes[..15]),
            Err(ProtocolError::Truncated {
                needed: 16,
                have: 15
            })
        );
    }

    #[test]
    fn abort_roundtrips_all_codes() {
        for code in [
            AbortCode::Declined,
            AbortCode::IntegrityFailed,
            AbortCode::InternalError,
            AbortCode::Unsupported,
        ] {
            let a = FileAbort {
                transfer_id: 42,
                code,
            };
            assert_eq!(FileAbort::decode(&a.encode()), Ok(a));
        }
    }

    #[test]
    fn abort_decode_rejects_unknown_code() {
        let mut bytes = FileAbort {
            transfer_id: 1,
            code: AbortCode::Declined,
        }
        .encode();
        bytes[8] = 9;
        assert_eq!(
            FileAbort::decode(&bytes),
            Err(ProtocolError::InvalidFileField(9))
        );
    }

    #[test]
    fn complete_roundtrips() {
        for ok in [true, false] {
            let c = FileComplete {
                transfer_id: 99,
                ok,
            };
            assert_eq!(FileComplete::decode(&c.encode()), Ok(c));
        }
    }

    #[test]
    fn complete_decode_rejects_bad_ok_byte() {
        let mut bytes = FileComplete {
            transfer_id: 1,
            ok: true,
        }
        .encode();
        bytes[8] = 2;
        assert_eq!(
            FileComplete::decode(&bytes),
            Err(ProtocolError::InvalidFileField(2))
        );
    }

    #[test]
    fn chunk_header_known_layout_roundtrips() {
        let h = FileChunkHeader {
            transfer_id: 0x0102_0304_0506_0708,
            offset: 1_048_576,
            len: 65536,
            last: true,
        };
        let bytes = h.encode().unwrap();
        assert_eq!(bytes.len(), FILE_CHUNK_HEADER_LEN);
        assert_eq!(&bytes[0..8], &h.transfer_id.to_be_bytes());
        assert_eq!(&bytes[8..16], &h.offset.to_be_bytes());
        assert_eq!(&bytes[16..20], &h.len.to_be_bytes());
        assert_eq!(bytes[20], CHUNK_FLAG_LAST);
        assert_eq!(FileChunkHeader::decode(&bytes), Ok(h));
    }

    #[test]
    fn chunk_header_not_last_has_zero_flags() {
        let h = FileChunkHeader {
            transfer_id: 1,
            offset: 0,
            len: 16,
            last: false,
        };
        let bytes = h.encode().unwrap();
        assert_eq!(bytes[20], 0);
        assert_eq!(FileChunkHeader::decode(&bytes), Ok(h));
    }

    #[test]
    fn chunk_header_rejects_zero_and_oversized_len() {
        let mut h = FileChunkHeader {
            transfer_id: 1,
            offset: 0,
            len: 0,
            last: false,
        };
        assert_eq!(h.encode(), Err(ProtocolError::FileChunkTooLarge(0)));
        h.len = MAX_FILE_CHUNK + 1;
        assert_eq!(
            h.encode(),
            Err(ProtocolError::FileChunkTooLarge(u64::from(
                MAX_FILE_CHUNK + 1
            )))
        );
    }

    #[test]
    fn chunk_header_decode_rejects_reserved_flag_bits() {
        let mut bytes = FileChunkHeader {
            transfer_id: 1,
            offset: 0,
            len: 16,
            last: true,
        }
        .encode()
        .unwrap();
        for bit in 1u8..=7 {
            bytes[20] = CHUNK_FLAG_LAST | (1 << bit);
            assert_eq!(
                FileChunkHeader::decode(&bytes),
                Err(ProtocolError::ReservedBitsSet),
                "reserved flag bit {bit} must be rejected"
            );
        }
    }

    #[test]
    fn chunk_header_decode_rejects_oversized_len_from_wire() {
        let mut bytes = FileChunkHeader {
            transfer_id: 1,
            offset: 0,
            len: 16,
            last: false,
        }
        .encode()
        .unwrap();
        bytes[16..20].copy_from_slice(&(MAX_FILE_CHUNK + 1).to_be_bytes());
        assert!(matches!(
            FileChunkHeader::decode(&bytes),
            Err(ProtocolError::FileChunkTooLarge(_))
        ));
    }

    proptest! {
        #[test]
        fn offer_roundtrip(
            transfer_id in any::<u64>(),
            total_size in any::<u64>(),
            chunk_size in 1u32..=MAX_FILE_CHUNK,
            sha in proptest::array::uniform32(any::<u8>()),
            name in proptest::collection::vec(any::<u8>(), 0..=MAX_FILE_NAME),
        ) {
            let offer = FileOffer { transfer_id, total_size, chunk_size, sha256: sha, name };
            let bytes = offer.encode().unwrap();
            prop_assert_eq!(FileOffer::decode(&bytes), Ok(offer));
        }

        #[test]
        fn accept_roundtrip(transfer_id in any::<u64>(), resume_offset in any::<u64>()) {
            let a = FileAccept { transfer_id, resume_offset };
            prop_assert_eq!(FileAccept::decode(&a.encode()), Ok(a));
        }

        #[test]
        fn chunk_header_roundtrip(
            transfer_id in any::<u64>(),
            offset in any::<u64>(),
            len in 1u32..=MAX_FILE_CHUNK,
            last in any::<bool>(),
        ) {
            let h = FileChunkHeader { transfer_id, offset, len, last };
            prop_assert_eq!(FileChunkHeader::decode(&h.encode().unwrap()), Ok(h));
        }

        #[test]
        fn decoders_never_panic(data in proptest::collection::vec(any::<u8>(), 0..128)) {
            let _ = FileOffer::decode(&data);
            let _ = FileAccept::decode(&data);
            let _ = FileAbort::decode(&data);
            let _ = FileComplete::decode(&data);
            let _ = FileChunkHeader::decode(&data);
        }
    }
}
