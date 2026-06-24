//! File-transfer orchestration: resume + SHA-256 integrity, capability-gated (P7-2 — ADR-0024).
//!
//! The wire framing lives in [`sh_protocol::file`]; this module is the **stateful orchestrator** that
//! drives a transfer and enforces every cross-message / stateful invariant the pure framing layer
//! cannot (ADR-0024 §"P7-2 orchestrator requirements"). It is split into two side-agnostic state
//! machines so the security-critical logic is testable without any transport or async runtime:
//!
//! - [`FileSender`] — owns the file bytes, emits the [`FileOffer`], honours the receiver's
//!   resume offset, and produces framed chunks from that offset to EOF.
//! - [`FileReceiver`] — checks [`Capabilities::FILE`], **sanitizes the offered name**, bounds the
//!   transfer against an aggregate buffer cap, accepts with a resume offset equal to the bytes it
//!   already holds, validates every chunk (right transfer, contiguous offset, within `total_size`),
//!   reassembles, and verifies the whole-file **SHA-256** before reporting [`FileComplete`].
//!
//! # Resume
//!
//! The receiver advertises how many contiguous leading bytes it already has as the
//! [`FileAccept::resume_offset`]; the sender resumes from there. The receiver seeds its hash with the
//! retained prefix so integrity is still verified over the *entire* file.
//!
//! # Security (all enforced here, not in the framing layer)
//!
//! `Capabilities::FILE` is required; the name is rejected if it equals `.` or `..`, contains a path
//! separator (`/` or `\`) or any control character, or is empty / non-UTF-8; `resume_offset ≤
//! total_size`; each chunk must be for this transfer, start exactly at the next expected offset
//! (contiguous, monotonic, non-overlapping), stay within `total_size`, and (when it carries the
//! `LAST` flag) end exactly at `total_size`; the offered `total_size` must not exceed the caller's
//! aggregate buffer cap; and the reassembled bytes must hash to the offered digest.
//!
//! # Example
//!
//! ```
//! use sh_core::authz::Capabilities;
//! use sh_core::{FileReceiver, FileSender};
//!
//! let data = b"hello, streamhaul".to_vec();
//! let mut sender = FileSender::new(1, "greeting.txt", data.clone(), 4)?;
//!
//! // Receiver validates the offer (capability + name + size) and accepts (fresh: no prefix).
//! let (mut receiver, accept) =
//!     FileReceiver::accept_offer(Capabilities::FILE, &sender.offer(), &[], 1 << 20)?;
//! sender.on_accept(&accept)?;
//!
//! // Stream framed chunks until the receiver reports the file is complete.
//! while let Some(frame) = sender.next_chunk()? {
//!     if receiver.on_chunk(&frame)? {
//!         break;
//!     }
//! }
//! let (bytes, complete) = receiver.finish()?; // verifies the whole-file SHA-256
//! assert!(complete.ok);
//! assert_eq!(bytes, data);
//! # Ok::<(), sh_core::FileError>(())
//! ```

use sha2::{Digest, Sha256};

use sh_protocol::file::{
    FileAccept, FileChunkHeader, FileComplete, FileOffer, FILE_CHUNK_HEADER_LEN, MAX_FILE_NAME,
};
use sh_protocol::ProtocolError;

use crate::authz::Capabilities;

/// Errors raised while orchestrating a file transfer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FileError {
    /// The session lacks [`Capabilities::FILE`].
    #[error("file transfer not permitted: session lacks the FILE capability")]
    CapabilityDenied,
    /// The offered file name is unsafe or malformed.
    #[error("offered file name rejected: {0}")]
    NameRejected(&'static str),
    /// `resume_offset` exceeds the offered `total_size`.
    #[error("resume offset {resume} exceeds total size {total}")]
    ResumeBeyondSize {
        /// The advertised resume offset.
        resume: u64,
        /// The offered total size.
        total: u64,
    },
    /// The offered `total_size` exceeds the receiver's aggregate buffer cap.
    #[error("offered size {total} exceeds the {cap}-byte aggregate buffer cap")]
    TooLarge {
        /// Offered total size.
        total: u64,
        /// Configured cap.
        cap: u64,
    },
    /// A chunk referenced a different (unknown) transfer id.
    #[error("chunk for unknown transfer id {got} (expected {expected})")]
    UnknownTransfer {
        /// The chunk's transfer id.
        got: u64,
        /// The active transfer id.
        expected: u64,
    },
    /// A chunk did not start at the next expected offset (gap, overlap, or reorder).
    #[error("chunk offset {got} is not the expected {expected} (gap/overlap/reorder)")]
    OffsetMismatch {
        /// The expected next offset.
        expected: u64,
        /// The chunk's offset.
        got: u64,
    },
    /// A chunk would write past the offered `total_size`.
    #[error("chunk [{offset}, {offset}+{len}) exceeds total size {total}")]
    ChunkBeyondSize {
        /// Chunk start offset.
        offset: u64,
        /// Chunk length.
        len: u32,
        /// Offered total size.
        total: u64,
    },
    /// A chunk's declared `len` did not match the payload actually delivered.
    #[error("chunk len {declared} != payload length {actual}")]
    LenMismatch {
        /// `len` field in the chunk header.
        declared: u32,
        /// Bytes after the header.
        actual: usize,
    },
    /// A chunk carried the `LAST` flag but did not end exactly at `total_size` (a malformed or
    /// hostile early terminator).
    #[error("LAST chunk ends at {end} but total size is {total}")]
    LastChunkNotAtEnd {
        /// Where the `LAST` chunk ended.
        end: u64,
        /// The offered total size.
        total: u64,
    },
    /// The offered `chunk_size` is zero or exceeds the protocol maximum.
    #[error("invalid chunk size {0}")]
    InvalidChunkSize(u32),
    /// The reassembled file's SHA-256 did not match the offered digest.
    #[error("integrity check failed: reassembled SHA-256 does not match the offer")]
    IntegrityFailed,
    /// The underlying wire framing was malformed.
    #[error("file framing error: {0}")]
    Framing(#[from] ProtocolError),
}

/// Reject names that could escape a directory or are otherwise unsafe. The framing layer treats the
/// name as opaque bytes; sanitization is the orchestrator's job (ADR-0024).
fn sanitize_name(name: &[u8]) -> Result<&str, FileError> {
    if name.is_empty() {
        return Err(FileError::NameRejected("empty"));
    }
    if name.len() > MAX_FILE_NAME {
        return Err(FileError::NameRejected("too long"));
    }
    let s = core::str::from_utf8(name).map_err(|_| FileError::NameRejected("not UTF-8"))?;
    if s.contains('/') || s.contains('\\') {
        return Err(FileError::NameRejected("contains a path separator"));
    }
    // Reject ASCII/Unicode control characters (covers NUL, CR/LF, DEL, etc.) — a remote peer must
    // not be able to smuggle terminal-control or line-break bytes into a displayed/saved file name.
    if s.chars().any(char::is_control) {
        return Err(FileError::NameRejected("contains a control character"));
    }
    // Reject the directory aliases outright (path separators are already blocked above).
    if s == ".." || s == "." {
        return Err(FileError::NameRejected("path traversal"));
    }
    Ok(s)
}

// ── Sender ────────────────────────────────────────────────────────────────────

/// Drives the sending side of a transfer: offer, honour the resume offset, emit framed chunks.
#[derive(Debug, Clone)]
pub struct FileSender {
    transfer_id: u64,
    name: Vec<u8>,
    data: Vec<u8>,
    chunk_size: u32,
    sha256: [u8; 32],
    /// Next byte offset to send (advances as chunks are produced).
    cursor: u64,
}

impl FileSender {
    /// Create a sender for `data` named `name`, chunked at `chunk_size` (`1..=`[`MAX_FILE_CHUNK`]).
    ///
    /// Computes the whole-file SHA-256 up front (carried in the offer for the receiver to verify).
    ///
    /// [`MAX_FILE_CHUNK`]: sh_protocol::file::MAX_FILE_CHUNK
    ///
    /// # Errors
    /// [`FileError::NameRejected`] if the name is unsafe; the chunk-size bound is checked when the
    /// offer is encoded.
    pub fn new(
        transfer_id: u64,
        name: impl Into<Vec<u8>>,
        data: impl Into<Vec<u8>>,
        chunk_size: u32,
    ) -> Result<Self, FileError> {
        let name = name.into();
        sanitize_name(&name)?;
        if chunk_size == 0 || chunk_size > sh_protocol::file::MAX_FILE_CHUNK {
            return Err(FileError::InvalidChunkSize(chunk_size));
        }
        let data = data.into();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let sha256: [u8; 32] = hasher.finalize().into();
        Ok(Self {
            transfer_id,
            name,
            data,
            chunk_size,
            sha256,
            cursor: 0,
        })
    }

    /// The offer to send to the receiver on the Control channel.
    #[must_use]
    pub fn offer(&self) -> FileOffer {
        FileOffer {
            transfer_id: self.transfer_id,
            total_size: self.data.len() as u64,
            chunk_size: self.chunk_size,
            sha256: self.sha256,
            name: self.name.clone(),
        }
    }

    /// Apply the receiver's acceptance: resume from `resume_offset`.
    ///
    /// # Errors
    /// [`FileError::ResumeBeyondSize`] if `resume_offset` exceeds the file size, or
    /// [`FileError::UnknownTransfer`] if it is for a different transfer.
    pub fn on_accept(&mut self, accept: &FileAccept) -> Result<(), FileError> {
        if accept.transfer_id != self.transfer_id {
            return Err(FileError::UnknownTransfer {
                got: accept.transfer_id,
                expected: self.transfer_id,
            });
        }
        if accept.resume_offset > self.data.len() as u64 {
            return Err(FileError::ResumeBeyondSize {
                resume: accept.resume_offset,
                total: self.data.len() as u64,
            });
        }
        self.cursor = accept.resume_offset;
        Ok(())
    }

    /// Produce the next framed chunk (`FileChunkHeader` ++ payload), or `None` when the file is fully
    /// sent. The final chunk has the `LAST` flag set.
    ///
    /// # Errors
    /// [`FileError::Framing`] only if `chunk_size` is out of range (guarded at construction time in
    /// practice).
    pub fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, FileError> {
        let total = self.data.len() as u64;
        if self.cursor >= total {
            return Ok(None);
        }
        // `cursor < total = data.len()`, so this conversion cannot fail; treat the impossible
        // overflow as "done" rather than panicking.
        let Ok(start) = usize::try_from(self.cursor) else {
            return Ok(None);
        };
        let remaining = self.data.len().saturating_sub(start);
        // `chunk_size` fits usize (u32), and `take ≤ chunk_size`, so the u32 conversion below is
        // always exact.
        let chunk = usize::try_from(self.chunk_size).unwrap_or(usize::MAX);
        let take = remaining.min(chunk);
        let take_len = u32::try_from(take).unwrap_or(self.chunk_size);
        let end = start.saturating_add(take);
        // Invariant: `start ≤ end ≤ data.len()` by construction above. `get` keeps this panic-free
        // even if that ever broke; the debug assertion surfaces a logic error in tests.
        debug_assert!(
            end <= self.data.len(),
            "chunk end {end} exceeds data length"
        );
        let payload = self.data.get(start..end).unwrap_or_default();
        let last = end as u64 >= total;
        let header = FileChunkHeader {
            transfer_id: self.transfer_id,
            offset: self.cursor,
            len: take_len,
            last,
        }
        .encode()?;
        let mut frame = Vec::with_capacity(FILE_CHUNK_HEADER_LEN.saturating_add(take));
        frame.extend_from_slice(&header);
        frame.extend_from_slice(payload);
        self.cursor = end as u64;
        Ok(Some(frame))
    }

    /// Whether all bytes have been emitted.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.cursor >= self.data.len() as u64
    }
}

// ── Receiver ──────────────────────────────────────────────────────────────────

/// Drives the receiving side: capability + name gate, resume, bounded reassembly, SHA-256 verify.
///
/// `Debug` is implemented by hand to print only progress metadata — never the buffered file bytes
/// (`received` is **session content**; CLAUDE.md §7 forbids logging it) nor the raw digest.
pub struct FileReceiver {
    transfer_id: u64,
    total_size: u64,
    expected_sha: [u8; 32],
    hasher: Sha256,
    /// Bytes received so far (includes any retained resume prefix).
    received: Vec<u8>,
    /// Aggregate buffer cap — the offer is refused if `total_size` exceeds this.
    cap: u64,
}

impl core::fmt::Debug for FileReceiver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Deliberately omits `received` (session content) and `expected_sha`/`hasher`.
        f.debug_struct("FileReceiver")
            .field("transfer_id", &self.transfer_id)
            .field("bytes_received", &self.received.len())
            .field("total_size", &self.total_size)
            .finish_non_exhaustive()
    }
}

impl FileReceiver {
    /// Validate an offer and produce the [`FileAccept`] to return.
    ///
    /// `already_have` is the contiguous leading prefix the receiver still holds from a prior,
    /// interrupted attempt (empty to start fresh); the accept's `resume_offset` is its length and the
    /// hash is seeded with it so integrity covers the whole file. `cap` bounds the total bytes the
    /// receiver will buffer for **this** transfer.
    ///
    /// # Caller obligations (this is a single-transfer state machine)
    ///
    /// This type validates one transfer. A dispatch layer that owns concurrent transfers MUST:
    /// - keep a `transfer_id → FileReceiver` registry and route each inbound chunk by id, dropping
    ///   chunks for unknown / already-completed / aborted ids (this type only knows its own id);
    /// - reject a second offer that reuses an in-flight `transfer_id` (collision/hijack);
    /// - enforce a **per-session** aggregate cap across all transfers — `cap` here bounds one
    ///   transfer, so N concurrent transfers can use up to `N × cap`;
    /// - keep `cap ≤ usize::MAX` (it is compared in `u64`; an absurd `cap` on a 32-bit target could
    ///   let `Vec` growth OOM before the cap gate fires);
    /// - before writing the (sanitized) `offer.name` to disk, apply OS-specific filtering (e.g.
    ///   reserved Windows device names `CON`/`NUL`/`COM1`…), and never pass the name unescaped to a
    ///   shell. This function blocks path separators, `.`/`..`, control characters, and non-UTF-8,
    ///   but does not know the destination filesystem.
    ///
    /// # Errors
    /// [`FileError::CapabilityDenied`], [`FileError::NameRejected`], [`FileError::TooLarge`],
    /// [`FileError::ResumeBeyondSize`], or a framing error.
    pub fn accept_offer(
        caps: Capabilities,
        offer: &FileOffer,
        already_have: &[u8],
        cap: u64,
    ) -> Result<(Self, FileAccept), FileError> {
        if !caps.contains(Capabilities::FILE) {
            return Err(FileError::CapabilityDenied);
        }
        // Name sanitization (rejects path separators / . / .. / control chars / non-UTF-8 / empty).
        sanitize_name(&offer.name)?;
        // Aggregate buffer cap: refuse a transfer we could not hold (total_size is attacker-chosen).
        if offer.total_size > cap {
            return Err(FileError::TooLarge {
                total: offer.total_size,
                cap,
            });
        }
        let resume = already_have.len() as u64;
        if resume > offer.total_size {
            return Err(FileError::ResumeBeyondSize {
                resume,
                total: offer.total_size,
            });
        }
        let mut hasher = Sha256::new();
        hasher.update(already_have);
        let recv = Self {
            transfer_id: offer.transfer_id,
            total_size: offer.total_size,
            expected_sha: offer.sha256,
            hasher,
            received: already_have.to_vec(),
            cap,
        };
        let accept = FileAccept {
            transfer_id: offer.transfer_id,
            resume_offset: resume,
        };
        Ok((recv, accept))
    }

    /// Ingest one framed chunk (`FileChunkHeader` ++ payload). Returns `true` once the whole file has
    /// been received (size reached). Validates transfer id, contiguity, and size bounds.
    ///
    /// # Errors
    /// [`FileError::UnknownTransfer`], [`FileError::OffsetMismatch`], [`FileError::ChunkBeyondSize`],
    /// [`FileError::LenMismatch`], [`FileError::TooLarge`], or a framing error.
    pub fn on_chunk(&mut self, frame: &[u8]) -> Result<bool, FileError> {
        let header_bytes = frame
            .get(..FILE_CHUNK_HEADER_LEN)
            .ok_or(ProtocolError::Truncated {
                needed: FILE_CHUNK_HEADER_LEN,
                have: frame.len(),
            })?;
        let header = FileChunkHeader::decode(header_bytes)?;
        let payload = frame.get(FILE_CHUNK_HEADER_LEN..).unwrap_or_default();

        if header.transfer_id != self.transfer_id {
            return Err(FileError::UnknownTransfer {
                got: header.transfer_id,
                expected: self.transfer_id,
            });
        }
        if header.len as usize != payload.len() {
            return Err(FileError::LenMismatch {
                declared: header.len,
                actual: payload.len(),
            });
        }
        // Contiguous, monotonic, non-overlapping placement.
        let expected = self.received.len() as u64;
        if header.offset != expected {
            return Err(FileError::OffsetMismatch {
                expected,
                got: header.offset,
            });
        }
        // Stay within the declared file.
        let end = header.offset.saturating_add(u64::from(header.len));
        if end > self.total_size {
            return Err(FileError::ChunkBeyondSize {
                offset: header.offset,
                len: header.len,
                total: self.total_size,
            });
        }
        // Defensive aggregate cap (total_size ≤ cap was checked at accept, but re-check on every
        // append in case of any inconsistency).
        if end > self.cap {
            return Err(FileError::TooLarge {
                total: end,
                cap: self.cap,
            });
        }
        // The LAST flag is a validated cross-check: if set, the chunk must end exactly at EOF. This
        // rejects a hostile/early terminator. (Completion itself is authoritative on byte count, so
        // empty files and full-prefix resumes — which carry no LAST chunk — still complete.)
        if header.last && end != self.total_size {
            return Err(FileError::LastChunkNotAtEnd {
                end,
                total: self.total_size,
            });
        }
        self.hasher.update(payload);
        self.received.extend_from_slice(payload);
        Ok(self.received.len() as u64 >= self.total_size)
    }

    /// Finalize: verify the whole-file SHA-256 and report completion.
    ///
    /// # Errors
    /// [`FileError::IntegrityFailed`] if the digest does not match.
    pub fn finish(self) -> Result<(Vec<u8>, FileComplete), FileError> {
        let digest: [u8; 32] = self.hasher.finalize().into();
        let ok = digest == self.expected_sha && self.received.len() as u64 == self.total_size;
        let complete = FileComplete {
            transfer_id: self.transfer_id,
            ok,
        };
        if !ok {
            return Err(FileError::IntegrityFailed);
        }
        Ok((self.received, complete))
    }

    /// Bytes received so far (for resume accounting / progress).
    #[must_use]
    pub fn bytes_received(&self) -> u64 {
        self.received.len() as u64
    }

    /// Whether the size has been fully received.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.received.len() as u64 >= self.total_size
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    const CAP: u64 = 64 * 1024 * 1024;

    fn full_caps() -> Capabilities {
        Capabilities::VIEW | Capabilities::FILE
    }

    fn deterministic_file(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
    }

    /// Drive a complete transfer through both state machines; return the reassembled bytes.
    fn run_transfer(
        caps: Capabilities,
        data: &[u8],
        chunk_size: u32,
        already_have: &[u8],
    ) -> Result<Vec<u8>, FileError> {
        let mut sender = FileSender::new(1, "file.bin", data.to_vec(), chunk_size)?;
        let offer = sender.offer();
        let (mut receiver, accept) = FileReceiver::accept_offer(caps, &offer, already_have, CAP)?;
        sender.on_accept(&accept)?;
        while let Some(frame) = sender.next_chunk()? {
            if receiver.on_chunk(&frame)? {
                break;
            }
        }
        let (bytes, complete) = receiver.finish()?;
        assert!(complete.ok);
        Ok(bytes)
    }

    #[test]
    fn full_transfer_reassembles_and_verifies() {
        let data = deterministic_file(100_000);
        let got = run_transfer(full_caps(), &data, 16 * 1024, &[]).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn empty_file_transfers() {
        let got = run_transfer(full_caps(), &[], 1024, &[]).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn resume_from_prefix_completes_whole_file_and_verifies_integrity() {
        let data = deterministic_file(50_000);
        // Receiver already holds the first 20_000 bytes (a prior interrupted attempt).
        let prefix = &data[..20_000];
        let got = run_transfer(full_caps(), &data, 8 * 1024, prefix).unwrap();
        assert_eq!(
            got, data,
            "resumed transfer must reconstruct the whole file"
        );
    }

    #[test]
    fn resume_sender_only_sends_the_tail() {
        let data = deterministic_file(40_000);
        let mut sender = FileSender::new(1, "f", data.clone(), 8 * 1024).unwrap();
        let offer = sender.offer();
        let (_recv, accept) =
            FileReceiver::accept_offer(full_caps(), &offer, &data[..30_000], CAP).unwrap();
        assert_eq!(accept.resume_offset, 30_000);
        sender.on_accept(&accept).unwrap();
        // First chunk after resume must start at offset 30_000, not 0.
        let frame = sender.next_chunk().unwrap().unwrap();
        let header = FileChunkHeader::decode(&frame[..FILE_CHUNK_HEADER_LEN]).unwrap();
        assert_eq!(header.offset, 30_000);
    }

    #[test]
    fn integrity_failure_on_corrupted_chunk_is_detected() {
        let data = deterministic_file(20_000);
        let mut sender = FileSender::new(1, "f", data.clone(), 4096).unwrap();
        let offer = sender.offer();
        let (mut receiver, accept) =
            FileReceiver::accept_offer(full_caps(), &offer, &[], CAP).unwrap();
        sender.on_accept(&accept).unwrap();
        let mut complete_ok = None;
        while let Some(mut frame) = sender.next_chunk().unwrap() {
            // Corrupt one payload byte of the first chunk.
            if frame.len() > FILE_CHUNK_HEADER_LEN {
                frame[FILE_CHUNK_HEADER_LEN] ^= 0xFF;
            }
            if receiver.on_chunk(&frame).unwrap() {
                complete_ok = Some(receiver.finish());
                break;
            }
        }
        // Size matches but content was tampered → SHA-256 mismatch.
        assert_eq!(complete_ok.unwrap(), Err(FileError::IntegrityFailed));
    }

    #[test]
    fn missing_file_capability_is_denied() {
        let data = deterministic_file(10);
        let err = run_transfer(Capabilities::VIEW, &data, 1024, &[]).unwrap_err();
        assert_eq!(err, FileError::CapabilityDenied);
    }

    #[test]
    fn unsafe_names_are_rejected() {
        for bad in [
            &b"../etc/passwd"[..],
            b"a/b",
            b"a\\b",
            b"..",
            b".",
            b"",
            b"x\0y",
        ] {
            assert!(
                FileSender::new(1, bad.to_vec(), b"x".to_vec(), 16).is_err(),
                "name {bad:?} must be rejected"
            );
        }
        // Non-UTF-8 rejected at the receiver (sender takes &str-able input, but the wire can carry
        // arbitrary bytes, so accept_offer must reject them).
        let offer = FileOffer {
            transfer_id: 1,
            total_size: 1,
            chunk_size: 16,
            sha256: [0; 32],
            name: vec![0xFF, 0xFE],
        };
        assert!(matches!(
            FileReceiver::accept_offer(full_caps(), &offer, &[], CAP),
            Err(FileError::NameRejected(_))
        ));
    }

    #[test]
    fn oversized_offer_rejected_by_aggregate_cap() {
        let offer = FileOffer {
            transfer_id: 1,
            total_size: CAP + 1,
            chunk_size: 1024,
            sha256: [0; 32],
            name: b"big.bin".to_vec(),
        };
        assert!(matches!(
            FileReceiver::accept_offer(full_caps(), &offer, &[], CAP),
            Err(FileError::TooLarge { .. })
        ));
    }

    #[test]
    fn resume_offset_beyond_size_rejected() {
        let offer = FileOffer {
            transfer_id: 1,
            total_size: 100,
            chunk_size: 1024,
            sha256: [0; 32],
            name: b"f".to_vec(),
        };
        // Receiver claims to already have more than the whole file.
        let already = vec![0u8; 101];
        assert!(matches!(
            FileReceiver::accept_offer(full_caps(), &offer, &already, CAP),
            Err(FileError::ResumeBeyondSize { .. })
        ));
    }

    #[test]
    fn chunk_for_unknown_transfer_rejected() {
        let offer = FileOffer {
            transfer_id: 1,
            total_size: 1000,
            chunk_size: 1024,
            sha256: [0; 32],
            name: b"f".to_vec(),
        };
        let (mut receiver, _) = FileReceiver::accept_offer(full_caps(), &offer, &[], CAP).unwrap();
        let frame = FileChunkHeader {
            transfer_id: 999, // wrong id
            offset: 0,
            len: 4,
            last: false,
        }
        .encode()
        .unwrap();
        let mut f = frame.to_vec();
        f.extend_from_slice(&[1, 2, 3, 4]);
        assert!(matches!(
            receiver.on_chunk(&f),
            Err(FileError::UnknownTransfer { .. })
        ));
    }

    #[test]
    fn out_of_order_chunk_rejected() {
        let offer = FileOffer {
            transfer_id: 1,
            total_size: 1000,
            chunk_size: 1024,
            sha256: [0; 32],
            name: b"f".to_vec(),
        };
        let (mut receiver, _) = FileReceiver::accept_offer(full_caps(), &offer, &[], CAP).unwrap();
        // A chunk at offset 100 when 0 is expected (gap/reorder).
        let mut f = FileChunkHeader {
            transfer_id: 1,
            offset: 100,
            len: 4,
            last: false,
        }
        .encode()
        .unwrap()
        .to_vec();
        f.extend_from_slice(&[1, 2, 3, 4]);
        assert!(matches!(
            receiver.on_chunk(&f),
            Err(FileError::OffsetMismatch {
                expected: 0,
                got: 100
            })
        ));
    }

    #[test]
    fn chunk_past_total_size_rejected() {
        let offer = FileOffer {
            transfer_id: 1,
            total_size: 10,
            chunk_size: 1024,
            sha256: [0; 32],
            name: b"f".to_vec(),
        };
        let (mut receiver, _) = FileReceiver::accept_offer(full_caps(), &offer, &[], CAP).unwrap();
        // A 16-byte chunk at offset 0 overflows the declared 10-byte file.
        let mut f = FileChunkHeader {
            transfer_id: 1,
            offset: 0,
            len: 16,
            last: true,
        }
        .encode()
        .unwrap()
        .to_vec();
        f.extend_from_slice(&[0u8; 16]);
        assert!(matches!(
            receiver.on_chunk(&f),
            Err(FileError::ChunkBeyondSize { .. })
        ));
    }

    #[test]
    fn full_prefix_resume_completes_with_no_chunks() {
        // Receiver already holds the ENTIRE file: resume_offset == total_size, zero chunks sent.
        let data = deterministic_file(12_345);
        let got = run_transfer(full_caps(), &data, 4096, &data).unwrap();
        assert_eq!(got, data, "full-prefix resume must verify with no chunks");
    }

    #[test]
    fn control_characters_in_name_rejected() {
        for bad in [&b"foo\nbar"[..], b"x\ry", b"tab\there", b"bell\x07"] {
            assert!(
                FileSender::new(1, bad.to_vec(), b"x".to_vec(), 16).is_err(),
                "control-char name {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn zero_and_oversized_chunk_size_rejected_at_construction() {
        let data = deterministic_file(10);
        assert!(matches!(
            FileSender::new(1, "f", data.clone(), 0),
            Err(FileError::InvalidChunkSize(0))
        ));
        let too_big = sh_protocol::file::MAX_FILE_CHUNK + 1;
        assert!(matches!(
            FileSender::new(1, "f", data, too_big),
            Err(FileError::InvalidChunkSize(n)) if n == too_big
        ));
    }

    #[test]
    fn early_last_flag_rejected() {
        let offer = FileOffer {
            transfer_id: 1,
            total_size: 100,
            chunk_size: 1024,
            sha256: [0; 32],
            name: b"f".to_vec(),
        };
        let (mut receiver, _) = FileReceiver::accept_offer(full_caps(), &offer, &[], CAP).unwrap();
        // A LAST chunk that ends at 10, well short of the declared 100-byte file.
        let mut f = FileChunkHeader {
            transfer_id: 1,
            offset: 0,
            len: 10,
            last: true,
        }
        .encode()
        .unwrap()
        .to_vec();
        f.extend_from_slice(&[0u8; 10]);
        assert!(matches!(
            receiver.on_chunk(&f),
            Err(FileError::LastChunkNotAtEnd {
                end: 10,
                total: 100
            })
        ));
    }

    #[test]
    fn debug_does_not_leak_file_content() {
        let offer = FileOffer {
            transfer_id: 1,
            total_size: 8,
            chunk_size: 1024,
            sha256: [0; 32],
            name: b"f".to_vec(),
        };
        let secret = b"SECRET!!";
        let (receiver, _) = FileReceiver::accept_offer(full_caps(), &offer, secret, CAP).unwrap();
        let dbg = format!("{receiver:?}");
        assert!(
            !dbg.contains("SECRET"),
            "Debug must not print buffered file content: {dbg}"
        );
    }

    #[test]
    fn len_payload_mismatch_rejected() {
        let offer = FileOffer {
            transfer_id: 1,
            total_size: 1000,
            chunk_size: 1024,
            sha256: [0; 32],
            name: b"f".to_vec(),
        };
        let (mut receiver, _) = FileReceiver::accept_offer(full_caps(), &offer, &[], CAP).unwrap();
        let mut f = FileChunkHeader {
            transfer_id: 1,
            offset: 0,
            len: 8, // claims 8
            last: false,
        }
        .encode()
        .unwrap()
        .to_vec();
        f.extend_from_slice(&[1, 2, 3]); // delivers 3
        assert!(matches!(
            receiver.on_chunk(&f),
            Err(FileError::LenMismatch {
                declared: 8,
                actual: 3
            })
        ));
    }
}
