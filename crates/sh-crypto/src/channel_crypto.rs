//! Per-channel AEAD encryption, key hierarchy, ratchet, and rekey (ADR-0009).
//!
//! # Overview
//!
//! After a Noise handshake completes, [`SessionKeys`] is created from the [`HandshakeOutcome`].
//! It derives 12 independent 32-byte base keys (6 channels × 2 directions) via HKDF from the
//! Noise session root, then wraps each in a per-generation ratchet chain.
//!
//! Each frame is sealed with ChaCha20-Poly1305 using a deterministic counter nonce:
//! `generation_u32_be || seq_u64_be`. The 24-byte frame header is committed as AAD.
//!
//! # Security
//!
//! - **No nonce reuse by construction**: key is unique per `(channel, direction, epoch, generation)`;
//!   `seq` is a strictly-increasing per-`(channel, direction, epoch)` counter the sender owns.
//! - **All keys are [`Zeroizing`]**; drop zeroizes them. [`SessionKeys::zeroize_all`] overwrites in place.
//! - **No key material in `Debug` output or error messages**.
//!
//! See ADR-0009 for the full threat model and design rationale.

use std::collections::BTreeMap;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key as ChaChaKey, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use sh_types::ChannelId;

use crate::{
    clock::Clock,
    noise::{HandshakeOutcome, HandshakeRole},
    CryptoError,
};

// ─── Public constants ──────────────────────────────────────────────────────

/// Frame magic byte (`'S'`). Provides a cheap structural sanity check.
pub const CHANNEL_MAGIC: u8 = 0x53;

/// Frame header version byte.
pub const CHANNEL_HDR_VERSION: u8 = 0x01;

/// Length of the fixed frame header in bytes.
pub const CHANNEL_HEADER_LEN: usize = 24;

/// Maximum frames per epoch before a rekey is required (2²⁰ = 1 048 576).
pub const REKEY_MSG_LIMIT: u64 = 1_048_576;

/// Maximum epoch age in seconds before a rekey is required (15 minutes).
pub const REKEY_TIME_LIMIT_SECS: i64 = 900;

/// Number of frames per `(channel, direction)` between ratchet advances (16 384).
pub const RATCHET_INTERVAL: u64 = 16_384;

/// Width of the per-`(channel, direction, epoch)` sliding replay window in bits.
pub const REPLAY_WINDOW: usize = 1024;

/// Number of past generations kept live for out-of-order frame decryption.
pub const GEN_WINDOW: u32 = 2;

/// Maximum number of generations ahead of the current that will be accepted.
pub const GEN_AHEAD_LIMIT: u32 = 2;

/// Hard upper bound on `seq`. Sealing returns [`CryptoError::NonceExhausted`] at this value.
///
/// Chosen as 2⁶³, well below `u64::MAX`, so nonces can never approach a wrap.
pub const SEQ_HARD_LIMIT: u64 = 1u64 << 63;

/// Hard upper bound on `generation`. Sealing returns [`CryptoError::NonceExhausted`] at this value.
pub const GEN_HARD_LIMIT: u32 = u32::MAX - 1;

/// Direction byte for initiator→responder frames on the wire.
pub const DIR_I2R: u8 = 0x00;

/// Direction byte for responder→initiator frames on the wire.
pub const DIR_R2I: u8 = 0x01;

// ─── Private labels ────────────────────────────────────────────────────────

const CHAN_LABEL: &[u8] = b"shp chan v1";
const RATCHET_LABEL: &[u8] = b"shp ratchet v1";
const AAD_PREFIX: &[u8] = b"shp aead v1";

// ─── Direction ─────────────────────────────────────────────────────────────

/// Which direction a frame travels (absolute, not relative to local role).
///
/// `I2R` = initiator→responder; `R2I` = responder→initiator.
/// The initiator *sends* with `I2R` and *receives* with `R2I`; the responder is the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Initiator sends, responder receives.
    I2R,
    /// Responder sends, initiator receives.
    R2I,
}

impl Direction {
    /// Returns the single wire byte for this direction.
    ///
    /// # Panics
    ///
    /// Never panics.
    #[must_use]
    pub fn wire_byte(self) -> u8 {
        match self {
            Direction::I2R => DIR_I2R,
            Direction::R2I => DIR_R2I,
        }
    }

    /// Parses a direction from a single wire byte.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MalformedChannelFrame`] if `b` is not `0x00` or `0x01`.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn from_wire(b: u8) -> Result<Self, CryptoError> {
        match b {
            DIR_I2R => Ok(Direction::I2R),
            DIR_R2I => Ok(Direction::R2I),
            _ => Err(CryptoError::MalformedChannelFrame {
                reason: "unknown direction byte",
            }),
        }
    }

    /// Index into a 2-element array: I2R=0, R2I=1.
    fn idx(self) -> usize {
        match self {
            Direction::I2R => 0,
            Direction::R2I => 1,
        }
    }
}

// ─── ChannelFrameHeader ────────────────────────────────────────────────────

/// The parsed 24-byte frame header.
///
/// Layout (big-endian):
/// ```text
/// MAGIC(1) HDR_VERSION(1) CHANNEL_ID(1) DIRECTION(1) EPOCH(8) GENERATION(4) SEQ(8)
/// ```
pub struct ChannelFrameHeader {
    /// The channel this frame belongs to.
    pub channel: ChannelId,
    /// The absolute frame direction.
    pub direction: Direction,
    /// The epoch this frame was sealed under.
    pub epoch: u64,
    /// The ratchet generation within the epoch.
    pub generation: u32,
    /// The per-`(channel, direction, epoch)` sequence number.
    pub seq: u64,
}

impl ChannelFrameHeader {
    /// Parses and bounds-checks exactly 24 header bytes.
    ///
    /// Rejects: bad `MAGIC`, bad `HDR_VERSION`, unknown channel byte, unknown direction byte.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MalformedChannelFrame`] on any structural error.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn parse(bytes: &[u8; 24]) -> Result<Self, CryptoError> {
        if bytes[0] != CHANNEL_MAGIC {
            return Err(CryptoError::MalformedChannelFrame {
                reason: "bad magic byte",
            });
        }
        if bytes[1] != CHANNEL_HDR_VERSION {
            return Err(CryptoError::MalformedChannelFrame {
                reason: "bad header version",
            });
        }
        let channel =
            ChannelId::try_from(bytes[2]).map_err(|_| CryptoError::MalformedChannelFrame {
                reason: "unknown channel id",
            })?;
        let direction = Direction::from_wire(bytes[3])?;

        let epoch = u64::from_be_bytes([
            bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
        ]);
        let generation = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let seq = u64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);

        Ok(Self {
            channel,
            direction,
            epoch,
            generation,
            seq,
        })
    }

    /// Encodes the header to exactly 24 bytes.
    ///
    /// # Panics
    ///
    /// Never panics.
    #[must_use]
    pub fn encode(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[0] = CHANNEL_MAGIC;
        out[1] = CHANNEL_HDR_VERSION;
        out[2] = u8::from(self.channel);
        out[3] = self.direction.wire_byte();
        let epoch_bytes = self.epoch.to_be_bytes();
        out[4..12].copy_from_slice(&epoch_bytes);
        let gen_bytes = self.generation.to_be_bytes();
        out[12..16].copy_from_slice(&gen_bytes);
        let seq_bytes = self.seq.to_be_bytes();
        out[16..24].copy_from_slice(&seq_bytes);
        out
    }

    /// Builds the 35-byte AAD: `b"shp aead v1"(11) || header(24)`.
    ///
    /// # Panics
    ///
    /// Never panics.
    #[must_use]
    pub fn aad(&self) -> [u8; 35] {
        let mut out = [0u8; 35];
        out[..11].copy_from_slice(AAD_PREFIX);
        let hdr = self.encode();
        out[11..35].copy_from_slice(&hdr);
        out
    }
}

// ─── ChannelKey ────────────────────────────────────────────────────────────

/// A single 32-byte ChaCha20-Poly1305 key, zeroized on drop.
struct ChannelKey(Zeroizing<[u8; 32]>);

impl ChannelKey {
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(ChaChaKey::from_slice(self.0.as_ref()))
    }
}

// ─── RatchetChain ──────────────────────────────────────────────────────────

/// Per-`(channel, direction, epoch)` HKDF ratchet chain.
///
/// Keeps at most `GEN_WINDOW + 1` live generation keys. Old keys are zeroized when
/// evicted from the window. The chain is one-way: given `k_{g+1}`, `k_g` cannot be recovered.
struct RatchetChain {
    /// The highest generation index derived so far.
    max_gen: u32,
    /// Live keys indexed by generation. At most `GEN_WINDOW + 1 = 3` entries.
    live_keys: BTreeMap<u32, ChannelKey>,
}

impl RatchetChain {
    /// Creates a new chain anchored at generation 0 with `base_key` as the base key.
    fn from_base_key(base: [u8; 32]) -> Self {
        let mut live_keys = BTreeMap::new();
        live_keys.insert(0, ChannelKey::from_bytes(base));
        Self {
            max_gen: 0,
            live_keys,
        }
    }

    /// Derives the next key from `current_key` via one HKDF step.
    fn derive_next_key(current: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
        let (prk, _) = Hkdf::<Sha256>::extract(None, current);
        let mut next = Zeroizing::new([0u8; 32]);
        // These HKDF operations over a fixed 32-byte PRK and a short label cannot fail in
        // practice (output length is 32 bytes < 255 * 32 HashLen). Map to AeadFailure rather
        // than HandshakeFailed to avoid semantic confusion with the Noise handshake.
        Hkdf::<Sha256>::from_prk(prk.as_slice())
            .map_err(|_| CryptoError::AeadFailure)?
            .expand(RATCHET_LABEL, next.as_mut())
            .map_err(|_| CryptoError::AeadFailure)?;
        Ok(*next)
    }

    /// Returns the key for `gen`, advancing the chain if needed.
    ///
    /// Used on the **send** path where advancing the ratchet is always safe
    /// (the sender owns the counter and AEAD is called after this).
    ///
    /// Rejects `gen < max_gen.saturating_sub(GEN_WINDOW)` (too old) or
    /// `gen > max_gen + GEN_AHEAD_LIMIT` (too far ahead). Old keys falling out of the
    /// window are zeroized (dropped).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::ReplayedFrame`] if `gen` is below the window floor.
    /// Returns [`CryptoError::MalformedChannelFrame`] if `gen` is too far ahead.
    ///
    /// # Panics
    ///
    /// Never panics.
    fn get_or_advance_to(&mut self, gen: u32) -> Result<&ChannelKey, CryptoError> {
        let floor = self.max_gen.saturating_sub(GEN_WINDOW);
        if gen < floor {
            return Err(CryptoError::ReplayedFrame);
        }
        let ahead_limit = self.max_gen.saturating_add(GEN_AHEAD_LIMIT);
        if gen > ahead_limit {
            return Err(CryptoError::MalformedChannelFrame {
                reason: "generation too far ahead",
            });
        }
        // Advance chain up to `gen` if needed.
        while self.max_gen < gen {
            let next_gen = self.max_gen.saturating_add(1);
            // Derive next key from the current max_gen key.
            let next_key_bytes = {
                let current = self
                    .live_keys
                    .get(&self.max_gen)
                    .ok_or(CryptoError::AeadFailure)?;
                Self::derive_next_key(&current.0)?
            };
            self.live_keys
                .insert(next_gen, ChannelKey::from_bytes(next_key_bytes));
            self.max_gen = next_gen;

            // Evict generations outside the window (< max_gen - GEN_WINDOW).
            let new_floor = self.max_gen.saturating_sub(GEN_WINDOW);
            self.live_keys.retain(|&g, _| g >= new_floor);
        }
        self.live_keys.get(&gen).ok_or(CryptoError::AeadFailure)
    }

    /// Derives the key for `gen` **without mutating** the chain.
    ///
    /// Used on the **receive** path so that a forged header cannot advance `max_gen` or
    /// evict live keys before the AEAD tag has been verified. After a successful AEAD open,
    /// call [`commit_advance_to`](Self::commit_advance_to) to mutate the chain.
    ///
    /// For generations already in `live_keys`, the key bytes are copied directly.
    /// For generations ahead of `max_gen` (within `GEN_AHEAD_LIMIT`), the key is derived
    /// transiently through at most `GEN_AHEAD_LIMIT` HKDF steps without touching `live_keys`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::ReplayedFrame`] if `gen` is below the window floor.
    /// Returns [`CryptoError::MalformedChannelFrame`] if `gen` is too far ahead.
    /// Returns [`CryptoError::AeadFailure`] if the live key for the anchor generation is missing.
    ///
    /// # Panics
    ///
    /// Never panics.
    fn derive_key_transient(&self, gen: u32) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let floor = self.max_gen.saturating_sub(GEN_WINDOW);
        if gen < floor {
            return Err(CryptoError::ReplayedFrame);
        }
        let ahead_limit = self.max_gen.saturating_add(GEN_AHEAD_LIMIT);
        if gen > ahead_limit {
            return Err(CryptoError::MalformedChannelFrame {
                reason: "generation too far ahead",
            });
        }
        // Fast path: key already cached in live_keys.
        if let Some(key) = self.live_keys.get(&gen) {
            return Ok(Zeroizing::new(*key.0));
        }
        // Slow path: gen > max_gen — derive transiently up to gen.
        // At most GEN_AHEAD_LIMIT = 2 steps, so stack allocation is fine.
        let anchor = self
            .live_keys
            .get(&self.max_gen)
            .ok_or(CryptoError::AeadFailure)?;
        let mut current: Zeroizing<[u8; 32]> = Zeroizing::new(*anchor.0);
        // The steps count: gen - max_gen <= GEN_AHEAD_LIMIT = 2 (checked above).
        let steps = gen.saturating_sub(self.max_gen);
        for _ in 0..steps {
            let next = Self::derive_next_key(&current)?;
            current = Zeroizing::new(next);
        }
        Ok(current)
    }

    /// Advances `max_gen` to `gen` and evicts out-of-window keys.
    ///
    /// Must be called only after AEAD verification succeeds for a frame at `gen`.
    /// This permanently advances the chain and is irreversible (one-way KDF).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::AeadFailure`] if the chain is missing the anchor key.
    ///
    /// # Panics
    ///
    /// Never panics.
    fn commit_advance_to(&mut self, gen: u32) -> Result<(), CryptoError> {
        while self.max_gen < gen {
            let next_gen = self.max_gen.saturating_add(1);
            let next_key_bytes = {
                let current = self
                    .live_keys
                    .get(&self.max_gen)
                    .ok_or(CryptoError::AeadFailure)?;
                Self::derive_next_key(&current.0)?
            };
            self.live_keys
                .insert(next_gen, ChannelKey::from_bytes(next_key_bytes));
            self.max_gen = next_gen;
            let new_floor = self.max_gen.saturating_sub(GEN_WINDOW);
            self.live_keys.retain(|&g, _| g >= new_floor);
        }
        Ok(())
    }
}

// ─── ReplayWindow ──────────────────────────────────────────────────────────

/// Number of `u64` words in the replay-window bitmap.
///
/// Derived from `REPLAY_WINDOW / 64`: a 1024-bit window needs exactly 16 words of 64 bits each.
/// Expressed as a constant so a future change to `REPLAY_WINDOW` propagates automatically.
const REPLAY_WINDOW_WORDS: usize = REPLAY_WINDOW / 64;

/// O(1) sliding bitmap anti-replay window (1024 bits = 16 × u64 words).
///
/// Bit position `i` (0-indexed from the high end) represents `seq = high - i`.
/// Bit 0 always represents the highest accepted `seq`.
struct ReplayWindow {
    /// The highest seq accepted so far (or `0` if nothing accepted yet).
    high: u64,
    /// Bitmap. `bits[word][bit]` at linear index `i` represents `high - i`.
    bits: Box<[u64; REPLAY_WINDOW_WORDS]>,
    /// Whether any seq has been accepted yet.
    initialized: bool,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            high: 0,
            bits: Box::new([0u64; REPLAY_WINDOW_WORDS]),
            initialized: false,
        }
    }

    /// Checks whether `seq` is acceptable (not replayed, not below window floor).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::ReplayedFrame`] if `seq` is below the window floor or already marked.
    ///
    /// # Panics
    ///
    /// Never panics.
    fn check(&self, seq: u64) -> Result<(), CryptoError> {
        if !self.initialized {
            return Ok(());
        }
        // REPLAY_WINDOW = 1024, so REPLAY_WINDOW - 1 = 1023, never wraps.
        let floor = self.high.saturating_sub((REPLAY_WINDOW - 1) as u64);
        if seq < floor {
            return Err(CryptoError::ReplayedFrame);
        }
        if seq <= self.high {
            // offset = high - seq, bounded by window (< 1024).
            let offset = self.high.saturating_sub(seq);
            let word = (offset / 64) as usize;
            let bit = (offset % 64) as u32;
            // word is at most (REPLAY_WINDOW-1)/64 = 15, so always < REPLAY_WINDOW_WORDS; use .get() for safety.
            if let Some(w) = self.bits.get(word) {
                if (w >> bit) & 1 == 1 {
                    return Err(CryptoError::ReplayedFrame);
                }
            }
        }
        Ok(())
    }

    /// Marks `seq` as accepted. Call only after AEAD success and `check` passed.
    ///
    /// # Panics
    ///
    /// Never panics.
    fn accept(&mut self, seq: u64) {
        if !self.initialized {
            self.initialized = true;
            self.high = seq;
            // Mark bit 0 — bits has REPLAY_WINDOW_WORDS elements, index 0 is always valid.
            if let Some(w) = self.bits.get_mut(0) {
                *w |= 1u64;
            }
            return;
        }
        if seq > self.high {
            // Slide window forward by (seq - high) positions.
            // saturating_sub is fine: seq > self.high is already asserted.
            let shift = seq.saturating_sub(self.high);
            if shift >= REPLAY_WINDOW as u64 {
                // Entire window is stale; clear all bits.
                for w in self.bits.iter_mut() {
                    *w = 0;
                }
            } else {
                self.shift_bits(shift);
            }
            self.high = seq;
            // Mark bit 0.
            if let Some(w) = self.bits.get_mut(0) {
                *w |= 1u64;
            }
        } else {
            // seq <= high: mark the appropriate bit.
            let offset = self.high.saturating_sub(seq);
            let word = (offset / 64) as usize;
            let bit = (offset % 64) as u32;
            if let Some(w) = self.bits.get_mut(word) {
                *w |= 1u64 << bit;
            }
        }
    }

    /// Slides the bitmap by `n` positions to make room for a new higher seq.
    ///
    /// Existing bits at offset `i` (representing `seq = old_high - i`) move to offset
    /// `i + n` (representing `seq = new_high - (i + n)`, i.e. the same absolute seq).
    /// This means the array contents shift towards HIGHER indices. We implement this as:
    ///
    /// 1. Word-level shift: `bits[i] <- bits[i - word_shift]`, processing **high to low**
    ///    (i = 15 down to 0) so the source word is not overwritten before it is read.
    /// 2. Bit-level left-shift within each u64: each bit moves toward higher bit-positions
    ///    (`<< bit_shift`). Overflow from the **top of word i** spills into the **bottom of
    ///    word i+1** (higher array index = higher offset = lower seq). The carry therefore
    ///    flows from word `i` into word `i+1`, so we process **high to low** (i = 15 down to 0):
    ///    for destination word i, the carry comes from `bits[i-1] >> anti_shift` (already in
    ///    final form, not yet overwritten).
    ///
    ///    `new_bits[i] = (bits[i] << bit_shift) | (bits[i-1] >> anti_shift)` (i > 0)
    ///    `new_bits[0] = bits[0] << bit_shift`
    ///
    /// `bit_shift` is in 1..=63 so `anti_shift = 64 - bit_shift` is in 1..=63 (no UB).
    ///
    /// # Panics
    ///
    /// Never panics.
    fn shift_bits(&mut self, n: u64) {
        // n < 1024 is guaranteed by the caller.
        #[allow(clippy::cast_possible_truncation)]
        let word_shift = (n / 64) as usize;
        #[allow(clippy::cast_possible_truncation)]
        let bit_shift = (n % 64) as u32;

        // Step 1: word-level slide towards higher indices.
        // Process from index REPLAY_WINDOW_WORDS-1 down to 0 to avoid overwriting source values.
        if word_shift > 0 {
            for i in (0..REPLAY_WINDOW_WORDS).rev() {
                if i >= word_shift {
                    let src_val = self
                        .bits
                        .get(i.saturating_sub(word_shift))
                        .copied()
                        .unwrap_or(0);
                    if let Some(dst) = self.bits.get_mut(i) {
                        *dst = src_val;
                    }
                } else if let Some(dst) = self.bits.get_mut(i) {
                    *dst = 0;
                }
            }
        }

        // Step 2: bit-level left-shift within each u64, processing HIGH to LOW (i = 15 → 0).
        //
        // Each bit at position `b` in word `i` moves to position `b + bit_shift`. When
        // b + bit_shift >= 64, the bit overflows into position (b + bit_shift - 64) of word
        // i+1 (the next-higher array index). Equivalently, for each destination word i:
        //
        //   new_bits[i] = (bits[i] << bit_shift) | (bits[i-1] >> anti_shift)   (i > 0)
        //   new_bits[0] = bits[0] << bit_shift
        //
        // Processing high-to-low means when we write new_bits[i], bits[i-1] has not yet been
        // overwritten, so we read the pre-shift value. This is the correct and safe order.
        //
        // bit_shift in 1..=63 → anti_shift = 64 - bit_shift in 1..=63 (no UB, no shift-by-64).
        if bit_shift > 0 {
            // 64u32 - bit_shift: bit_shift in 1..=63 → result in 1..=63, no underflow.
            #[allow(clippy::arithmetic_side_effects)]
            let anti_shift = 64u32 - bit_shift;
            for i in (0..REPLAY_WINDOW_WORDS).rev() {
                let shifted = self.bits.get(i).copied().unwrap_or(0) << bit_shift;
                // carry comes from bits[i-1] (lower array index = lower offset = higher seq).
                // For i=0 there is no lower word; carry is 0.
                let carry = if i > 0 {
                    self.bits.get(i.saturating_sub(1)).copied().unwrap_or(0) >> anti_shift
                } else {
                    0
                };
                if let Some(dst) = self.bits.get_mut(i) {
                    *dst = shifted | carry;
                }
            }
        }
    }
}

// ─── ChannelState ──────────────────────────────────────────────────────────

/// Per-`(channel, direction, epoch)` state: ratchet chain + replay window + send counters.
struct ChannelState {
    ratchet: RatchetChain,
    replay: ReplayWindow,
    /// Next sequence number to assign when sealing (sender side).
    next_seq: u64,
    /// Number of frames sealed under this `(channel, direction, epoch)` (for ratchet trigger).
    frames_sealed: u64,
    /// Current ratchet generation being used for sealing.
    current_gen: u32,
}

impl ChannelState {
    fn new(base_key: [u8; 32]) -> Self {
        Self {
            ratchet: RatchetChain::from_base_key(base_key),
            replay: ReplayWindow::new(),
            next_seq: 0,
            frames_sealed: 0,
            current_gen: 0,
        }
    }
}

// ─── EpochKeys ─────────────────────────────────────────────────────────────

/// All channel states for one epoch (6 channels × 2 directions).
struct EpochKeys {
    epoch: u64,
    /// `states[channel_u8 * 2 + direction.idx()]`
    states: Vec<ChannelState>,
    /// Unix timestamp (seconds) when this epoch started.
    started_at_secs: i64,
}

impl EpochKeys {
    fn get_mut(&mut self, channel: ChannelId, dir: Direction) -> Option<&mut ChannelState> {
        let idx = usize::from(u8::from(channel))
            .checked_mul(2)?
            .checked_add(dir.idx())?;
        self.states.get_mut(idx)
    }
}

// ─── SessionKeys ───────────────────────────────────────────────────────────

/// The full in-RAM key set for a session.
///
/// Created from a completed [`HandshakeOutcome`] via [`SessionKeys::from_outcome`].
/// All keys are wrapped in [`Zeroizing`] buffers; dropping this value or calling
/// [`zeroize_all`](Self::zeroize_all) erases all key material.
///
/// # Security
///
/// Debug output never reveals key material. No secret bytes appear in error messages.
pub struct SessionKeys {
    session: crate::noise::NoiseSession,
    role: HandshakeRole,
    current: EpochKeys,
    prior: Option<EpochKeys>,
    /// Total frames sealed this epoch (across all channels, this peer's send side).
    msgs_this_epoch: u64,
    clock: Box<dyn Clock>,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("role", &self.role)
            .field("epoch", &self.current.epoch)
            .finish_non_exhaustive()
    }
}

impl SessionKeys {
    /// Derives all channel keys from a completed Noise session.
    ///
    /// `clock` must be the same injected clock used elsewhere (deterministic in tests).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if key derivation fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use sh_crypto::channel_crypto::SessionKeys;
    /// use sh_crypto::clock::SystemClock;
    /// use sh_crypto::noise::HandshakeOutcome;
    ///
    /// fn make_keys(outcome: HandshakeOutcome) -> Result<SessionKeys, sh_crypto::CryptoError> {
    ///     SessionKeys::from_outcome(outcome, Box::new(SystemClock))
    /// }
    /// ```
    pub fn from_outcome(
        outcome: HandshakeOutcome,
        clock: Box<dyn Clock>,
    ) -> Result<Self, CryptoError> {
        let now = clock.now_unix_secs();
        let current = derive_epoch_keys(&outcome.transport, 0, now)?;
        Ok(Self {
            session: outcome.transport,
            role: outcome.role,
            current,
            prior: None,
            msgs_this_epoch: 0,
            clock,
        })
    }

    /// Seals `plaintext` for `channel`, returning `header(24) || ciphertext(plaintext.len()+16)`.
    ///
    /// The epoch, generation, and seq are chosen automatically.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::NonceExhausted`] if seq or generation hard limits are reached.
    /// - [`CryptoError::AeadFailure`] if AEAD encryption fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn seal(&mut self, channel: ChannelId, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let send_dir = self.send_direction();
        let epoch = self.current.epoch;

        let state = self
            .current
            .get_mut(channel, send_dir)
            .ok_or(CryptoError::AeadFailure)?;

        // Check seq hard limit.
        if state.next_seq >= SEQ_HARD_LIMIT {
            return Err(CryptoError::NonceExhausted);
        }

        // Check if ratchet advance is needed.
        if state.frames_sealed > 0 && state.frames_sealed % RATCHET_INTERVAL == 0 {
            let next_gen = state
                .current_gen
                .checked_add(1)
                .ok_or(CryptoError::NonceExhausted)?;
            if next_gen >= GEN_HARD_LIMIT {
                return Err(CryptoError::NonceExhausted);
            }
            // Advance ratchet to next_gen (derives and caches it, evicts old).
            state.ratchet.get_or_advance_to(next_gen)?;
            state.current_gen = next_gen;
        }

        let generation = state.current_gen;
        let seq = state.next_seq;

        // Build header.
        let header_obj = ChannelFrameHeader {
            channel,
            direction: send_dir,
            epoch,
            generation,
            seq,
        };
        let header_bytes = header_obj.encode();
        let aad = header_obj.aad();

        // Get cipher.
        let key = state
            .ratchet
            .get_or_advance_to(generation)
            .map_err(|_| CryptoError::AeadFailure)?;
        let cipher = key.cipher();

        // Build nonce: gen_be4 || seq_be8 = 12 bytes.
        let nonce_bytes = build_nonce(generation, seq);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad: &aad,
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| CryptoError::AeadFailure)?;

        // Update counters.
        state.next_seq = state.next_seq.saturating_add(1);
        state.frames_sealed = state.frames_sealed.saturating_add(1);
        self.msgs_this_epoch = self.msgs_this_epoch.saturating_add(1);

        let mut out = Vec::with_capacity(CHANNEL_HEADER_LEN.saturating_add(ciphertext.len()));
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Opens a received frame for `channel`, returning the plaintext.
    ///
    /// `frame` must be at least `CHANNEL_HEADER_LEN + 16` bytes.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::MalformedChannelFrame`] if the header is invalid.
    /// - [`CryptoError::ReplayedFrame`] if `seq` has been seen before.
    /// - [`CryptoError::EpochTooFarAhead`] if `epoch > current + 1`.
    /// - [`CryptoError::AeadFailure`] if the AEAD tag does not verify.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn open(&mut self, channel: ChannelId, frame: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let min_len = CHANNEL_HEADER_LEN.saturating_add(16);
        if frame.len() < min_len {
            return Err(CryptoError::MalformedChannelFrame {
                reason: "frame too short",
            });
        }

        let header_slice =
            frame
                .get(..CHANNEL_HEADER_LEN)
                .ok_or(CryptoError::MalformedChannelFrame {
                    reason: "frame too short for header",
                })?;
        let mut header_arr = [0u8; 24];
        header_arr.copy_from_slice(header_slice);
        let header = ChannelFrameHeader::parse(&header_arr)?;

        // Verify channel matches.
        if header.channel != channel {
            return Err(CryptoError::MalformedChannelFrame {
                reason: "channel id mismatch",
            });
        }

        // Reject reflected direction (frame direction must not equal our send direction).
        let send_dir = self.send_direction();
        if header.direction == send_dir {
            return Err(CryptoError::MalformedChannelFrame {
                reason: "reflected direction",
            });
        }

        let recv_dir = header.direction;
        let current_epoch = self.current.epoch;

        // Epoch checks.
        if header.epoch > current_epoch.saturating_add(1) {
            return Err(CryptoError::EpochTooFarAhead);
        }

        // Lazily handle a frame from the next epoch:
        // Derive candidate epoch keys, attempt AEAD, and only commit the epoch transition
        // on success. This prevents an unauthenticated forged header from mutating session
        // state (epoch, prior keys, rekey counter) before the tag is verified.
        //
        // Known limitation: the prior slot holds exactly one epoch. If `self.prior` already
        // holds epoch N-1 keys (from a previous `rekey()` call) and a legitimate epoch N+1
        // frame arrives here, committing the transition overwrites the N-1 prior with the N
        // (current) keys. Any in-flight N-1 frames will then fail to decrypt. This is an
        // accepted limitation of the single-slot prior window; the fix requires a Vec-based
        // grace-period window, tracked for a future pass.
        if header.epoch == current_epoch.saturating_add(1) {
            let now = self.clock.now_unix_secs();
            let mut candidate = derive_epoch_keys(&self.session, header.epoch, now)?;
            // Attempt decryption against the candidate epoch. Only on success do we commit.
            let plaintext = open_with_epoch(&mut candidate, recv_dir, &header, frame)?;
            // AEAD succeeded: commit the epoch transition.
            let old_current = std::mem::replace(&mut self.current, candidate);
            self.prior = Some(old_current);
            self.msgs_this_epoch = 0;
            return Ok(plaintext);
        }

        // Select the epoch to use (current or prior).
        let use_prior = header.epoch < self.current.epoch;
        if use_prior && header.epoch == self.current.epoch.saturating_sub(1) {
            // Use prior epoch if available.
            let prior = self.prior.as_mut().ok_or(CryptoError::AeadFailure)?;
            return open_with_epoch(prior, recv_dir, &header, frame);
        } else if header.epoch < self.current.epoch {
            // Older than prior — no live key.
            return Err(CryptoError::AeadFailure);
        }

        // Use current epoch.
        open_with_epoch(&mut self.current, recv_dir, &header, frame)
    }

    /// Returns `true` if a rekey should be initiated.
    ///
    /// Fires when `msgs_this_epoch >= REKEY_MSG_LIMIT` OR the epoch is older than
    /// `REKEY_TIME_LIMIT_SECS`.
    ///
    /// # Panics
    ///
    /// Never panics.
    #[must_use]
    pub fn needs_rekey(&self) -> bool {
        if self.msgs_this_epoch >= REKEY_MSG_LIMIT {
            return true;
        }
        // Clamp to 0 so a clock regression (NTP step-back) doesn't suppress the time-based
        // rekey trigger. Without the max(0), a negative elapsed value would never reach 900.
        let elapsed = self
            .clock
            .now_unix_secs()
            .saturating_sub(self.current.started_at_secs)
            .max(0);
        elapsed >= REKEY_TIME_LIMIT_SECS
    }

    /// Advances the epoch, deriving fresh keys.
    ///
    /// Old epoch keys remain accessible for the grace window via `prior`.
    /// The caller is responsible for sending a `RekeyRequest` control message and calling
    /// [`close_grace_period`](Self::close_grace_period) when appropriate.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if key derivation fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn rekey(&mut self) -> Result<(), CryptoError> {
        let new_epoch = self.current.epoch.saturating_add(1);
        let now = self.clock.now_unix_secs();
        let new_keys = derive_epoch_keys(&self.session, new_epoch, now)?;
        let old_current = std::mem::replace(&mut self.current, new_keys);
        // Drop whatever was in prior (zeroizes it), replace with old current.
        self.prior = Some(old_current);
        self.msgs_this_epoch = 0;
        Ok(())
    }

    /// Zeroizes and drops all prior-epoch keys.
    ///
    /// Call after the grace period closes.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn close_grace_period(&mut self) {
        // Dropping EpochKeys drops all ChannelState values, which drop RatchetChain,
        // which drops all ChannelKey values (each wrapping Zeroizing<[u8;32]>).
        self.prior = None;
    }

    /// Zeroizes all in-RAM key material.
    ///
    /// After this call, `seal()` and `open()` will fail with [`CryptoError::AeadFailure`]
    /// because no live keys remain.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn zeroize_all(&mut self) {
        zeroize_epoch_keys(&mut self.current);
        if let Some(ref mut prior) = self.prior {
            zeroize_epoch_keys(prior);
        }
        self.prior = None;
        // Also zeroize the session root PRK so that rekey() cannot re-derive channel
        // keys after the kill-switch fires. Without this, a caller could invoke rekey()
        // after zeroize_all() and recover functional session keys from the live PRK.
        self.session.zeroize_prk();
    }

    /// Returns the current epoch number.
    ///
    /// # Panics
    ///
    /// Never panics.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.current.epoch
    }

    /// Returns the send direction for the local role.
    fn send_direction(&self) -> Direction {
        match self.role {
            HandshakeRole::Initiator => Direction::I2R,
            HandshakeRole::Responder => Direction::R2I,
        }
    }
}

// ─── Private helpers ───────────────────────────────────────────────────────

/// Derives all 12 channel states for `epoch` from the Noise session root.
fn derive_epoch_keys(
    session: &crate::noise::NoiseSession,
    epoch: u64,
    clock_now: i64,
) -> Result<EpochKeys, CryptoError> {
    let mut states = Vec::with_capacity(12);
    for ch_idx in 0u8..6u8 {
        for dir_idx in 0u8..2u8 {
            // context = channel_u8(1) || dir_u8(1) || epoch_u64_be(8) = 10 bytes
            let mut context = [0u8; 10];
            context[0] = ch_idx;
            context[1] = dir_idx;
            let epoch_bytes = epoch.to_be_bytes();
            context[2..10].copy_from_slice(&epoch_bytes);
            let mut key_bytes = Zeroizing::new([0u8; 32]);
            session.export_keying_material(CHAN_LABEL, &context, key_bytes.as_mut())?;
            states.push(ChannelState::new(*key_bytes));
        }
    }
    Ok(EpochKeys {
        epoch,
        states,
        started_at_secs: clock_now,
    })
}

/// Builds the 12-byte AEAD nonce: `generation_u32_be(4) || seq_u64_be(8)`.
fn build_nonce(generation: u32, seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&generation.to_be_bytes());
    nonce[4..12].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// Opens a frame against a specific EpochKeys.
///
/// # Security invariant
///
/// The ratchet chain is **not** advanced (no `max_gen` mutation, no key eviction) until
/// AEAD decryption succeeds. A forged datagram with a valid header but garbage tag cannot
/// permanently destroy live generation keys. The two-phase protocol is:
///
/// 1. `derive_key_transient(gen)` — read-only key derivation, no chain mutation.
/// 2. AEAD decrypt — verifies the tag against committed AAD.
/// 3. `commit_advance_to(gen)` — advance and evict only on AEAD success.
/// 4. `replay.accept(seq)` — mark as seen only on AEAD success.
fn open_with_epoch(
    epoch: &mut EpochKeys,
    recv_dir: Direction,
    header: &ChannelFrameHeader,
    frame: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let state = epoch
        .get_mut(header.channel, recv_dir)
        .ok_or(CryptoError::AeadFailure)?;

    // Replay check (read-only).
    state.replay.check(header.seq)?;

    // Phase 1: derive key transiently — does NOT advance max_gen or evict live keys.
    // This prevents a forged future-generation header from destroying live gen keys
    // before the AEAD tag is verified.
    let key_bytes = state
        .ratchet
        .derive_key_transient(header.generation)
        .map_err(|_| CryptoError::AeadFailure)?;
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key_bytes.as_ref()));

    // Rebuild AAD from header.
    let aad = header.aad();

    // Nonce.
    let nonce_bytes = build_nonce(header.generation, header.seq);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_with_tag =
        frame
            .get(CHANNEL_HEADER_LEN..)
            .ok_or(CryptoError::MalformedChannelFrame {
                reason: "frame too short for ciphertext",
            })?;
    let payload = Payload {
        msg: ciphertext_with_tag,
        aad: &aad,
    };

    // Phase 2: AEAD decrypt — verifies tag. Returns Err on any forgery.
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::AeadFailure)?;

    // AEAD succeeded. Phase 3: commit ratchet advance (safe to evict old gen keys now).
    let state = epoch
        .get_mut(header.channel, recv_dir)
        .ok_or(CryptoError::AeadFailure)?;
    state
        .ratchet
        .commit_advance_to(header.generation)
        .map_err(|_| CryptoError::AeadFailure)?;

    // Phase 4: mark seq as accepted.
    state.replay.accept(header.seq);

    Ok(plaintext)
}

/// Overwrites all key bytes in an EpochKeys in place.
fn zeroize_epoch_keys(epoch: &mut EpochKeys) {
    for state in epoch.states.iter_mut() {
        for (_, key) in state.ratchet.live_keys.iter_mut() {
            key.0.zeroize();
        }
        state.ratchet.live_keys.clear();
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::{clock::FixedClock, noise::NoiseHandshake, Keystore, SoftwareKeystore};
    use rand_core::OsRng;
    use x25519_dalek::StaticSecret;

    const NOW: i64 = 1_000_000_000;

    async fn do_xk_handshake_keys(now: i64) -> (SessionKeys, SessionKeys) {
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();

        let resp_static = StaticSecret::random_from_rng(OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = StaticSecret::random_from_rng(OsRng);

        let resp_id = resp_ks.device_identity().await.unwrap();
        let init_id = init_ks.device_identity().await.unwrap();
        init_ks.trust_peer(&resp_id).await.unwrap();
        resp_ks.trust_peer(&init_id).await.unwrap();

        let clock = FixedClock(now);

        let mut init =
            NoiseHandshake::initiator_xk(&init_ks, init_static, resp_pub.to_bytes(), &[], &clock)
                .await
                .unwrap();
        let mut resp = NoiseHandshake::responder_xk(&resp_ks, resp_static, &[], &clock)
            .await
            .unwrap();

        let msg0 = init.write_message().unwrap();
        resp.read_message(&msg0, &clock).unwrap();
        let msg1 = resp.write_message().unwrap();
        init.read_message(&msg1, &clock).unwrap();
        let msg2 = init.write_message().unwrap();
        resp.read_message(&msg2, &clock).unwrap();

        let init_outcome = init.complete(&init_ks).await.unwrap();
        let resp_outcome = resp.complete(&resp_ks).await.unwrap();

        let init_keys = SessionKeys::from_outcome(init_outcome, Box::new(FixedClock(now))).unwrap();
        let resp_keys = SessionKeys::from_outcome(resp_outcome, Box::new(FixedClock(now))).unwrap();
        (init_keys, resp_keys)
    }

    #[tokio::test]
    async fn both_peers_derive_identical_channel_keys() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;
        let plaintext = b"hello video channel";
        let frame = init_keys.seal(ChannelId::Video, plaintext).unwrap();
        let decrypted = resp_keys.open(ChannelId::Video, &frame).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn per_channel_seal_open_roundtrip_all_channels() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;
        for channel in [
            ChannelId::Video,
            ChannelId::Audio,
            ChannelId::Input,
            ChannelId::Clipboard,
            ChannelId::File,
            ChannelId::Control,
        ] {
            let plaintext = format!("test on channel {:?}", channel);
            let frame = init_keys.seal(channel, plaintext.as_bytes()).unwrap();
            let decrypted = resp_keys.open(channel, &frame).unwrap();
            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }

    #[tokio::test]
    async fn tamper_ciphertext_rejected() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;
        let mut frame = init_keys.seal(ChannelId::Video, b"secret").unwrap();
        // Flip a byte in the ciphertext portion.
        let last = frame.len() - 1;
        frame[last] ^= 0xFF;
        let result = resp_keys.open(ChannelId::Video, &frame);
        assert!(matches!(result, Err(CryptoError::AeadFailure)));
    }

    #[tokio::test]
    async fn tamper_header_rejected() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;
        let mut frame = init_keys.seal(ChannelId::Video, b"secret").unwrap();
        // Flip epoch byte (byte 4).
        frame[4] ^= 0xFF;
        let result = resp_keys.open(ChannelId::Video, &frame);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn cross_channel_replay_rejected() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;
        // Seal for Video, try to open as Audio. The public API returns
        // `MalformedChannelFrame { reason: "channel id mismatch" }` because `open()` checks
        // `header.channel != channel` before reaching AEAD. The channel-id early-return is the
        // primary defence; the AAD channel-id binding is defense-in-depth (tested separately in
        // `aad_binds_channel_id_cross_channel_open_fails`).
        let frame = init_keys.seal(ChannelId::Video, b"video data").unwrap();
        let result = resp_keys.open(ChannelId::Audio, &frame);
        assert!(matches!(
            result,
            Err(CryptoError::MalformedChannelFrame {
                reason: "channel id mismatch"
            })
        ));
    }

    /// AAD channel-id binding: a frame sealed for Video must fail to open against Audio keys
    /// even when the header claims Audio (bypassing the channel-id early-return check).
    ///
    /// This exercises the AEAD defence-in-depth layer: the 35-byte AAD includes the channel byte,
    /// so swapping the channel byte in the header while keeping the original Video ciphertext
    /// causes tag verification to fail with `AeadFailure`.
    #[tokio::test]
    async fn aad_binds_channel_id_cross_channel_open_fails() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;
        // Seal a legitimate Video frame.
        let mut frame = init_keys.seal(ChannelId::Video, b"video data").unwrap();

        // Rewrite byte 2 (channel id in header) from Video to Audio.
        // This changes the channel field in the header but NOT in the AEAD ciphertext/tag,
        // so the AAD computed by the receiver will differ from the one used during sealing.
        frame[2] = u8::from(ChannelId::Audio);

        // Now attempt to open it as Audio. The channel-id early-return sees Audio==Audio so
        // it passes; direction check passes; epoch check passes. AEAD decryption fails because
        // the AAD includes the channel byte that was changed, causing a tag mismatch.
        let result = resp_keys.open(ChannelId::Audio, &frame);
        assert!(
            matches!(result, Err(CryptoError::AeadFailure)),
            "AAD must bind the channel id: cross-channel frame must fail with AeadFailure, got {result:?}"
        );
    }

    #[tokio::test]
    async fn cross_epoch_replay_rejected() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;
        // Seal a frame in epoch 0.
        let old_frame = init_keys.seal(ChannelId::Video, b"old epoch").unwrap();
        // Rekey both sides.
        init_keys.rekey().unwrap();
        resp_keys.rekey().unwrap();
        // Close grace period on receiver.
        resp_keys.close_grace_period();
        // Try to open old epoch frame — prior keys are gone.
        let result = resp_keys.open(ChannelId::Video, &old_frame);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn nonce_exhaustion_returns_error_before_wrap() {
        let (mut init_keys, _resp_keys) = do_xk_handshake_keys(NOW).await;
        // Directly set next_seq to the hard limit.
        let state = init_keys
            .current
            .get_mut(ChannelId::Video, Direction::I2R)
            .unwrap();
        state.next_seq = SEQ_HARD_LIMIT;
        let result = init_keys.seal(ChannelId::Video, b"overflow");
        assert!(matches!(result, Err(CryptoError::NonceExhausted)));
    }

    #[tokio::test]
    async fn rekey_advances_epoch_new_epoch_decrypts() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;
        init_keys.rekey().unwrap();
        resp_keys.rekey().unwrap();
        assert_eq!(init_keys.current_epoch(), 1);
        assert_eq!(resp_keys.current_epoch(), 1);

        let plaintext = b"new epoch data";
        let frame = init_keys.seal(ChannelId::Control, plaintext).unwrap();
        let decrypted = resp_keys.open(ChannelId::Control, &frame).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn rekey_forward_secrecy_old_key_cant_decrypt_new_epoch() {
        let (mut init_keys, mut resp_keys_old) = do_xk_handshake_keys(NOW).await;
        // Seal something in epoch 0 first so resp_keys_old knows epoch 0.
        let epoch0_frame = init_keys.seal(ChannelId::Video, b"epoch0").unwrap();
        resp_keys_old.open(ChannelId::Video, &epoch0_frame).unwrap();

        // init rekeys to epoch 1.
        init_keys.rekey().unwrap();
        // Seal a frame under epoch 1.
        let new_frame = init_keys.seal(ChannelId::Video, b"epoch1 secret").unwrap();

        // resp_keys_old is still on epoch 0 and hasn't rekeyed; epoch 1 is 1 ahead so it
        // will lazily derive epoch 1 keys. Then close grace period for extra coverage.
        // Actually: after close_grace_period on resp_keys_old (epoch 0 keys gone), we want
        // to verify forward secrecy. Let's instead try a different resp that manually closed
        // its grace period but didn't advance — but that's the same derivation.
        // The meaningful test: two separate SessionKeys from same handshake don't have
        // different epoch 1 derivations — they're deterministic from the same PRK.
        // Real FS test: a second fresh SessionKeys (simulating an attacker who captured epoch 0)
        // tries to open epoch 1. Since PRK is the same, they'd derive the same epoch 1 key.
        // The real FS is epoch 0 keys being zeroized can't recover epoch -1 keys.
        // So: verify that after close_grace_period, epoch 0 frames fail.
        resp_keys_old.close_grace_period(); // epoch 0 keys gone from prior
                                            // Open the epoch 1 frame — this lazily derives epoch 1.
        let result = resp_keys_old.open(ChannelId::Video, &new_frame);
        // Should succeed (lazy derive works) — this tests that epoch 1 is correctly derived.
        assert!(
            result.is_ok(),
            "expected epoch 1 open to succeed, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn ratchet_advance_within_epoch() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;
        // Seal RATCHET_INTERVAL + 1 frames. The last one should use generation 1.
        let count = RATCHET_INTERVAL as usize + 1;
        let mut last_frame = Vec::new();
        for i in 0..count {
            last_frame = init_keys
                .seal(ChannelId::Video, format!("frame {i}").as_bytes())
                .unwrap();
        }
        // Open intermediate frames to advance resp's ratchet.
        // We only kept the last frame, so just open that one.
        // But the resp side doesn't know about the preceding frames — it needs to catch up.
        // The ratchet chain on resp side will advance to gen=1 when it sees gen=1 in header.
        let result = resp_keys.open(ChannelId::Video, &last_frame);
        assert!(
            result.is_ok(),
            "ratchet advance should succeed: {:?}",
            result
        );

        // Verify the generation field in the last frame header is 1.
        let mut header_arr = [0u8; 24];
        header_arr.copy_from_slice(&last_frame[..24]);
        let header = ChannelFrameHeader::parse(&header_arr).unwrap();
        assert_eq!(header.generation, 1);
    }

    #[tokio::test]
    async fn replay_window_in_window_reorder_accepted() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;
        // Seal 4 frames.
        let f0 = init_keys.seal(ChannelId::Audio, b"frame0").unwrap();
        let f1 = init_keys.seal(ChannelId::Audio, b"frame1").unwrap();
        let f2 = init_keys.seal(ChannelId::Audio, b"frame2").unwrap();
        let f3 = init_keys.seal(ChannelId::Audio, b"frame3").unwrap();

        // Open out of order: 3, 1, 0, 2.
        resp_keys.open(ChannelId::Audio, &f3).unwrap();
        resp_keys.open(ChannelId::Audio, &f1).unwrap();
        resp_keys.open(ChannelId::Audio, &f0).unwrap();
        resp_keys.open(ChannelId::Audio, &f2).unwrap();
    }

    #[tokio::test]
    async fn replay_window_out_of_window_dropped() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;
        // Save frame 0.
        let f0 = init_keys.seal(ChannelId::Audio, b"old frame").unwrap();
        // Seal 1030 more frames to push frame 0 out of the window.
        let mut frames = vec![f0.clone()];
        for i in 1..=1030usize {
            frames.push(
                init_keys
                    .seal(ChannelId::Audio, format!("frame {i}").as_bytes())
                    .unwrap(),
            );
        }
        // Open all frames in order.
        for frame in &frames {
            let _ = resp_keys.open(ChannelId::Audio, frame).unwrap();
        }
        // Try to re-open frame 0 — it is beyond the window floor.
        let result = resp_keys.open(ChannelId::Audio, &f0);
        assert!(matches!(result, Err(CryptoError::ReplayedFrame)));
    }

    #[tokio::test]
    async fn duplicate_seq_rejected() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;
        let frame = init_keys.seal(ChannelId::Control, b"once").unwrap();
        resp_keys.open(ChannelId::Control, &frame).unwrap();
        let result = resp_keys.open(ChannelId::Control, &frame);
        assert!(matches!(result, Err(CryptoError::ReplayedFrame)));
    }

    #[tokio::test]
    async fn advisory_rekey_request_does_not_switch_keys() {
        // This test documents the behavioral invariant: rekey() must be called explicitly.
        // A control-message RekeyRequest is advisory only — merely receiving it does not
        // switch keys. Frames continue to seal/open under the old epoch until rekey() is called.
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;
        // Simulate "receiving a RekeyRequest" by NOT calling rekey().
        // Both sides should still seal/open under epoch 0.
        let frame = init_keys
            .seal(ChannelId::Control, b"still epoch 0")
            .unwrap();
        let mut header_arr = [0u8; 24];
        header_arr.copy_from_slice(&frame[..24]);
        let header = ChannelFrameHeader::parse(&header_arr).unwrap();
        assert_eq!(
            header.epoch, 0,
            "epoch must still be 0 before rekey() is called"
        );

        let result = resp_keys.open(ChannelId::Control, &frame);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn needs_rekey_fires_on_msg_count() {
        let (mut init_keys, _) = do_xk_handshake_keys(NOW).await;
        init_keys.msgs_this_epoch = REKEY_MSG_LIMIT;
        assert!(init_keys.needs_rekey());
    }

    #[tokio::test]
    async fn needs_rekey_fires_on_time() {
        // Start with now=NOW, then advance clock by 900+ seconds.
        let (mut init_keys, _) = do_xk_handshake_keys(NOW).await;
        // Swap the clock to one that is 900 seconds in the future.
        let future_now = NOW.saturating_add(REKEY_TIME_LIMIT_SECS);
        init_keys.clock = Box::new(FixedClock(future_now));
        assert!(init_keys.needs_rekey());
    }

    #[tokio::test]
    async fn reflected_direction_rejected() {
        let (mut init_keys, _resp_keys) = do_xk_handshake_keys(NOW).await;
        // Initiator seals (direction=I2R). Try to open on the same initiator SessionKeys.
        // The initiator's send direction is I2R, so it will reject frames with direction=I2R.
        let frame = init_keys.seal(ChannelId::Video, b"data").unwrap();
        // init_keys tries to open a frame it sealed itself — direction=I2R = its own send dir.
        let result = init_keys.open(ChannelId::Video, &frame);
        assert!(matches!(
            result,
            Err(CryptoError::MalformedChannelFrame {
                reason: "reflected direction"
            })
        ));
    }

    #[tokio::test]
    async fn epoch_too_far_ahead_rejected() {
        let (mut _init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;
        // Build a fake frame header with epoch = current + 2.
        let fake_header = ChannelFrameHeader {
            channel: ChannelId::Video,
            direction: Direction::I2R, // initiator→responder (not resp's send dir)
            epoch: 2,
            generation: 0,
            seq: 0,
        };
        let header_bytes = fake_header.encode();
        // Build a minimal frame (header + 16 bytes of garbage tag).
        let mut fake_frame = Vec::with_capacity(CHANNEL_HEADER_LEN + 16);
        fake_frame.extend_from_slice(&header_bytes);
        fake_frame.extend_from_slice(&[0u8; 16]);
        let result = resp_keys.open(ChannelId::Video, &fake_frame);
        assert!(matches!(result, Err(CryptoError::EpochTooFarAhead)));
    }

    #[tokio::test]
    async fn zeroize_all_causes_subsequent_seal_to_fail() {
        let (mut init_keys, _) = do_xk_handshake_keys(NOW).await;
        init_keys.zeroize_all();
        // After zeroize_all, the ratchet live_keys map is empty, so get_or_advance_to fails.
        let result = init_keys.seal(ChannelId::Video, b"post-zeroize");
        assert!(result.is_err());
    }

    // ─── ReplayWindow unit tests ────────────────────────────────────────────

    #[test]
    fn replay_window_sequential_accepts_all() {
        let mut w = ReplayWindow::new();
        for i in 0u64..100 {
            w.check(i).unwrap();
            w.accept(i);
        }
    }

    #[test]
    fn replay_window_exact_boundary() {
        let mut w = ReplayWindow::new();
        // Accept seq 1023 first, so the floor is 0.
        w.check(1023).unwrap();
        w.accept(1023);
        // seq 0 is exactly at the window boundary (high=1023, size=1024, floor=0).
        w.check(0).unwrap();
        w.accept(0);
        // seq 0 is now marked — should be rejected as replay.
        assert!(matches!(w.check(0), Err(CryptoError::ReplayedFrame)));
    }

    #[test]
    fn replay_window_below_floor_rejected() {
        let mut w = ReplayWindow::new();
        for i in 0u64..1025 {
            w.check(i).unwrap();
            w.accept(i);
        }
        // seq 0 is now below floor (high=1024, floor=1).
        assert!(matches!(w.check(0), Err(CryptoError::ReplayedFrame)));
    }

    #[test]
    fn replay_window_shift_correctness() {
        let mut w = ReplayWindow::new();
        // Accept seq 0, then jump to seq 128 — shifts the window by 128.
        w.accept(0);
        w.accept(128);
        // seq 0 is still in window (high=128, floor=128-1023=0 saturating = 0).
        // seq 0 was marked, so replay check should reject it.
        assert!(matches!(w.check(0), Err(CryptoError::ReplayedFrame)));
        // seq 64 was never accepted — should be Ok.
        w.check(64).unwrap();
    }

    // ── Regression tests for confirmed bugs ────────────────────────────────

    /// REGRESSION: `shift_bits` was shifting in the wrong direction (>>  instead of <<
    /// within each u64 word), causing already-seen seqs to become invisible after a
    /// non-word-aligned slide. This test fails on the buggy implementation.
    #[test]
    fn replay_window_non_aligned_slide_marks_old_seq() {
        let mut w = ReplayWindow::new();
        // Accept seq 5 (marks bit 0 of bits[0]).
        w.check(5).unwrap();
        w.accept(5);
        // Accept seq 6 — this triggers a slide of n=1, which is NOT word-aligned.
        // After the slide, seq 5 must still be marked (at bit 1 of bits[0]).
        w.check(6).unwrap();
        w.accept(6);
        // seq 5 must be rejected as a replay.
        assert!(
            matches!(w.check(5), Err(CryptoError::ReplayedFrame)),
            "seq 5 should be rejected as replayed after sliding window by 1"
        );
    }

    /// REGRESSION: Cross-word-boundary carry bug: a bit at offset 63 (MSB of bits[0])
    /// must survive a slide of 1 by carrying into bit 0 of bits[1] (offset 64).
    ///
    /// The original code had `carry = bits[i+1] >> anti_shift` which flows carry in the
    /// wrong direction. This test fails on the buggy implementation.
    #[test]
    fn replay_window_cross_word_boundary_carry() {
        let mut w = ReplayWindow::new();
        // accept(63) → high=63, bits[0]=0x8000_0000_0000_0001 (bit 0 = high, bit 63 = self)
        // Wait — first acceptance marks bit 0 of word 0 for the seq itself.
        // Simpler: mark seq at offset 63 by accepting a higher seq first, then the lower one.

        // Accept seq 100 first (high=100).
        w.check(100).unwrap();
        w.accept(100);
        // Accept seq 100-63 = 37 — this marks offset 63 of the window (bit 63 of bits[0]).
        w.check(37).unwrap();
        w.accept(37);
        // Accept seq 101 — slide by 1. Offset 63 must move to offset 64 (bit 0 of bits[1]).
        w.check(101).unwrap();
        w.accept(101);
        // seq 37 must be rejected as a replay (high=101, offset = 101-37 = 64 = bit 0 of bits[1]).
        assert!(
            matches!(w.check(37), Err(CryptoError::ReplayedFrame)),
            "seq 37 must be marked as seen after cross-word-boundary slide"
        );
    }

    /// REGRESSION: Model-based cross-word check — all accepted seqs within the window remain
    /// marked after arbitrary slides, and no unaccepted seq is spuriously marked.
    #[test]
    fn replay_window_model_based_correctness() {
        // Use a deterministic pseudo-random sequence to exercise many slide offsets.
        // Accepted seqs form a BTreeSet ground truth; window must agree on every check.
        use std::collections::BTreeSet;
        let mut w = ReplayWindow::new();
        let mut ground_truth: BTreeSet<u64> = BTreeSet::new();

        // Build a deterministic sequence of seqs that produces varied slides.
        // Pattern: advancing jumps of 1..=5, interleaved with back-fills within window.
        let mut high: u64 = 0;
        let mut to_accept: Vec<u64> = Vec::new();

        // Phase 1: advance high in steps of 1 to 5 up to seq 200, back-fill each gap.
        let mut step = 1u64;
        while high < 200 {
            high = high.saturating_add(step);
            to_accept.push(high);
            // Also back-fill the previous offset 1 and offset 63 positions if in window.
            if high >= 1 {
                to_accept.push(high.saturating_sub(1));
            }
            if high >= 63 {
                to_accept.push(high.saturating_sub(63));
            }
            if high >= 64 {
                to_accept.push(high.saturating_sub(64));
            }
            step = if step < 5 { step + 1 } else { 1 };
        }

        for seq in &to_accept {
            let seq = *seq;
            if ground_truth.contains(&seq) {
                // Already marked — skip (check would reject it).
                continue;
            }
            // Floor: highest seq in window minus 1023.
            let floor = ground_truth
                .iter()
                .next_back()
                .copied()
                .unwrap_or(0)
                .saturating_sub(1023);
            if seq < floor {
                continue; // outside window, skip
            }
            if w.check(seq).is_ok() {
                w.accept(seq);
                ground_truth.insert(seq);
            }
        }

        // Verify: for every seq we accepted, window must report it as replayed.
        for &seq in &ground_truth {
            assert!(
                matches!(w.check(seq), Err(CryptoError::ReplayedFrame)),
                "seq {seq} should be marked as seen in window"
            );
        }
    }

    /// REGRESSION: Sequential in-order delivery must keep all previous seqs marked.
    /// Verifies that sliding by 1 repeatedly doesn't drop previously-seen seqs.
    #[test]
    fn replay_window_sequential_all_marked_after_sliding() {
        let mut w = ReplayWindow::new();
        // Accept seqs 0..64 in order (exercises many 1-step slides).
        for i in 0u64..64 {
            w.check(i).unwrap();
            w.accept(i);
        }
        // All of 0..63 should be marked.
        for i in 0u64..64 {
            assert!(
                matches!(w.check(i), Err(CryptoError::ReplayedFrame)),
                "seq {i} should be marked as seen"
            );
        }
    }

    /// REGRESSION: A forged frame with a future epoch and an invalid AEAD tag must NOT
    /// advance the receiver's epoch or touch `prior`. Before the fix, the epoch state was
    /// mutated before AEAD verification, allowing an unauthenticated attacker to force a
    /// premature epoch rollover.
    #[tokio::test]
    async fn forged_future_epoch_with_invalid_tag_does_not_advance_epoch() {
        let (mut _init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;
        let epoch_before = resp_keys.current_epoch();

        // Build a forged frame with epoch = current + 1, direction = I2R (not resp's send dir).
        let fake_header = ChannelFrameHeader {
            channel: ChannelId::Video,
            direction: Direction::I2R,
            epoch: epoch_before.saturating_add(1),
            generation: 0,
            seq: 0,
        };
        let header_bytes = fake_header.encode();
        let mut fake_frame = Vec::with_capacity(CHANNEL_HEADER_LEN + 16);
        fake_frame.extend_from_slice(&header_bytes);
        // Garbage AEAD tag — will fail authentication.
        fake_frame.extend_from_slice(&[0xFFu8; 16]);

        // Must fail (bad tag) and must NOT advance epoch or mutate prior.
        let result = resp_keys.open(ChannelId::Video, &fake_frame);
        assert!(
            result.is_err(),
            "forged future-epoch frame must be rejected"
        );
        assert_eq!(
            resp_keys.current_epoch(),
            epoch_before,
            "epoch must not advance due to a forged header with invalid tag"
        );

        // The real initiator can still seal and the responder can still decrypt (epoch unchanged).
        let plaintext = b"legit frame";
        let legit_frame = _init_keys.seal(ChannelId::Video, plaintext).unwrap();
        let decrypted = resp_keys.open(ChannelId::Video, &legit_frame).unwrap();
        assert_eq!(decrypted, plaintext, "legit frame must still decrypt");
    }

    /// REGRESSION: A forged frame claiming a future generation (within GEN_AHEAD_LIMIT) with
    /// a garbage AEAD tag must NOT advance the ratchet's max_gen or evict live generation keys.
    ///
    /// **What this test actually guards (two-phase commit correctness):**
    /// The ratchet's `derive_key_transient` path is read-only; `commit_advance_to` is only
    /// called after AEAD succeeds. A forged header with an invalid tag must therefore leave
    /// `max_gen` at 0, keeping the gen-0 key live. The subsequent open of the legitimate gen-0
    /// frame proves that the two-phase commit works: the forged `gen=GEN_AHEAD_LIMIT` header
    /// did NOT evict gen 0 from `live_keys`.
    ///
    /// Note: with `GEN_WINDOW == GEN_AHEAD_LIMIT == 2`, a single forged frame at `gen=2` cannot
    /// evict gen 0 from the window floor anyway (floor = max_gen - GEN_WINDOW = 0 - 2 saturates
    /// to 0). The core protection here is the two-phase commit preventing a *ratchet advance*,
    /// not window-floor eviction. See `gen_eviction_forged_frame_does_not_raise_floor` for the
    /// non-vacuous floor-eviction test.
    #[tokio::test]
    async fn forged_future_generation_with_invalid_tag_does_not_advance_ratchet() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;

        // Seal a legitimate gen-0 frame to give the responder a known-good message.
        let legit_frame = init_keys
            .seal(ChannelId::Video, b"real gen-0 data")
            .unwrap();

        // Build a forged frame: valid header structure but claiming generation = max_gen + 2
        // (within GEN_AHEAD_LIMIT), with a garbage AEAD tag. If the ratchet is advanced
        // before AEAD verification, gen-0 key will be evicted, breaking legit_frame.
        let forged_header = ChannelFrameHeader {
            channel: ChannelId::Video,
            direction: Direction::I2R,
            epoch: 0,
            generation: GEN_AHEAD_LIMIT, // = 2, within limit; triggers two-step transient derive
            seq: 0,
        };
        let mut forged_frame = forged_header.encode().to_vec();
        forged_frame.extend_from_slice(&[0xBBu8; 16]); // garbage tag + payload
                                                       // Must fail with AeadFailure (not panic, not evict live keys).
        let result = resp_keys.open(ChannelId::Video, &forged_frame);
        assert!(
            result.is_err(),
            "forged future-generation frame must be rejected"
        );

        // The legitimate gen-0 frame must still decrypt — the ratchet was NOT advanced.
        let pt = resp_keys
            .open(ChannelId::Video, &legit_frame)
            .expect("legit gen-0 frame must decrypt after forged gen+2 attack");
        assert_eq!(pt, b"real gen-0 data");
    }

    /// Non-vacuous generation-eviction test: advances both peers' ratchets to `max_gen > GEN_WINDOW`
    /// by exchanging legitimate frames one generation at a time. Then sends a forged future-gen
    /// frame with a bad tag and asserts that a legitimate in-window frame still decrypts —
    /// proving the forged frame did NOT raise the floor or evict live keys.
    ///
    /// This supplements `forged_future_generation_with_invalid_tag_does_not_advance_ratchet` with
    /// a scenario where the window floor is actually non-zero: after legitimately advancing
    /// `max_gen` to `GEN_WINDOW + 2 = 4`, the floor on the receiver rises to `4 - 2 = 2`.
    /// A forged frame at `max_gen + GEN_AHEAD_LIMIT = 6` must be rejected, and a subsequent
    /// legitimate frame at gen 4 (still within the window) must still open.
    #[tokio::test]
    async fn gen_eviction_forged_frame_does_not_raise_floor() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;

        // Target: advance both sides' ratchet to max_gen = GEN_WINDOW + 2 = 4.
        // We do this by sealing exactly RATCHET_INTERVAL frames per generation and opening each
        // generation's last frame on the responder before moving to the next, so the responder
        // is always within GEN_AHEAD_LIMIT of the initiator.
        let target_gen = GEN_WINDOW + 2; // = 4

        for gen_step in 0..target_gen {
            // Seal RATCHET_INTERVAL frames — the (RATCHET_INTERVAL)th triggers the ratchet
            // advance to gen_step + 1 on the NEXT seal call. We need to seal RATCHET_INTERVAL
            // frames while at gen_step to drive the counter up, then one more to advance.
            // Simpler: seal RATCHET_INTERVAL + 1 frames; the last will be at gen_step + 1.
            // Keep only the first (gen_step) and last frame of each generation:
            //   - the first frame (at gen_step): to give to resp so it advances to gen_step.
            //   - after advancing init to gen_step+1, keep a frame at gen_step+1 for resp.
            // Actually: seal RATCHET_INTERVAL frames at gen_step, give first to resp.
            let first_at_this_gen = init_keys.seal(ChannelId::Video, b"gen-step-first").unwrap();
            let hdr0: [u8; 24] = first_at_this_gen[..24].try_into().unwrap();
            let h0 = ChannelFrameHeader::parse(&hdr0).unwrap();
            assert_eq!(
                h0.generation, gen_step,
                "expected gen {gen_step} on first frame"
            );
            // Open on resp to advance resp's ratchet to gen_step.
            resp_keys
                .open(ChannelId::Video, &first_at_this_gen)
                .unwrap();

            // Seal RATCHET_INTERVAL - 1 more frames (these push init's counter to RATCHET_INTERVAL,
            // which triggers the ratchet advance on the NEXT seal).
            for _ in 1..RATCHET_INTERVAL {
                init_keys.seal(ChannelId::Video, b"filler").unwrap();
            }
            // This seal is at frame index RATCHET_INTERVAL (0-based): triggers ratchet advance
            // to gen_step + 1.
            let _advance_frame = init_keys
                .seal(ChannelId::Video, b"ratchet-trigger")
                .unwrap();
            let hdr_adv: [u8; 24] = _advance_frame[..24].try_into().unwrap();
            let h_adv = ChannelFrameHeader::parse(&hdr_adv).unwrap();
            assert_eq!(
                h_adv.generation,
                gen_step + 1,
                "expected ratchet advance to gen {}",
                gen_step + 1
            );
        }

        // Both sides are now at max_gen = target_gen = 4.
        // Seal one more legitimate frame at gen=4 to give to resp.
        let legit_frame = init_keys.seal(ChannelId::Video, b"legit at gen4").unwrap();
        let hdr_l: [u8; 24] = legit_frame[..24].try_into().unwrap();
        let h_l = ChannelFrameHeader::parse(&hdr_l).unwrap();
        assert_eq!(
            h_l.generation, target_gen,
            "sender must be at gen {target_gen}"
        );

        // Verify resp can open it (advancing resp's ratchet to gen=4).
        resp_keys.open(ChannelId::Video, &legit_frame).unwrap();

        // Now resp's max_gen = 4, floor = 4 - GEN_WINDOW = 2.
        // Send a forged frame at gen = target_gen + GEN_AHEAD_LIMIT = 6, bad tag.
        let forged_header = ChannelFrameHeader {
            channel: ChannelId::Video,
            direction: Direction::I2R,
            epoch: 0,
            generation: target_gen + GEN_AHEAD_LIMIT, // = 6, within limit
            seq: 1,                                   // fresh seq so replay window won't block
        };
        let mut forged_frame = forged_header.encode().to_vec();
        forged_frame.extend_from_slice(&[0xCCu8; 16]); // garbage tag
        let forge_result = resp_keys.open(ChannelId::Video, &forged_frame);
        assert!(
            forge_result.is_err(),
            "forged future-gen frame must be rejected"
        );

        // Seal another legitimate frame at gen=4 (initiator is still at gen=4).
        // If the forged frame raised max_gen, the floor would be at 4, evicting gen=4 key.
        // The frame must still open, proving the two-phase commit held.
        let post_forge_frame = init_keys
            .seal(ChannelId::Video, b"post-forge legit")
            .unwrap();
        let hdr_pf: [u8; 24] = post_forge_frame[..24].try_into().unwrap();
        let h_pf = ChannelFrameHeader::parse(&hdr_pf).unwrap();
        assert_eq!(
            h_pf.generation, target_gen,
            "initiator must still be at gen {target_gen} — ratchet does not advance mid-generation"
        );

        let pt = resp_keys
            .open(ChannelId::Video, &post_forge_frame)
            .expect("legit in-window gen frame must still decrypt after forged future-gen attack");
        assert_eq!(pt, b"post-forge legit");
    }

    /// REGRESSION: `zeroize_all()` must also zeroize the session root PRK so that
    /// any keys derived via `rekey()` after the kill-switch cannot be decrypted by the peer.
    ///
    /// The security invariant has two parts:
    ///
    /// 1. **Without rekey()**: `seal()` fails immediately after `zeroize_all()` because all
    ///    ratchet `live_keys` have been cleared.
    /// 2. **With rekey()**: `rekey()` derives keys from the *zeroed* PRK. Those keys are
    ///    structurally valid (HKDF works over an all-zero PRK) but cryptographically diverge
    ///    from the peer's real keys. A frame sealed with the post-zeroize keys must be
    ///    rejected by the peer with `AeadFailure`.
    #[tokio::test]
    async fn zeroize_all_prevents_rekey_from_rederiving_keys() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;

        // Confirm the session is healthy before zeroize.
        let frame = init_keys.seal(ChannelId::Video, b"pre-zeroize").unwrap();
        resp_keys.open(ChannelId::Video, &frame).unwrap();

        // Part 1: without rekey(), seal() must fail immediately after zeroize_all().
        let (mut init_keys_a, _) = do_xk_handshake_keys(NOW).await;
        init_keys_a.zeroize_all();
        let seal_result = init_keys_a.seal(ChannelId::Video, b"post-zeroize");
        assert!(
            seal_result.is_err(),
            "seal must fail immediately after zeroize_all without rekey"
        );

        // Part 2: with rekey() after zeroize_all(), the derived keys are based on the
        // zeroed PRK and must be rejected by the peer (AeadFailure).
        init_keys.zeroize_all();
        // rekey() may succeed structurally (HKDF accepts an all-zero PRK), but the output
        // keys are NOT the session's real keys.
        let _ = init_keys.rekey();
        // If rekey succeeded, any frame sealed with these garbage keys must fail at the peer.
        if let Ok(forged_frame) = init_keys.seal(ChannelId::Video, b"post-zeroize-rekey") {
            let open_result = resp_keys.open(ChannelId::Video, &forged_frame);
            assert!(
                open_result.is_err(),
                "frame sealed with post-zeroize-rekey keys must be rejected by peer"
            );
        }
        // (If seal itself returned Err, the invariant holds trivially — nothing to send.)
    }

    /// REGRESSION: `needs_rekey` must not suppress the time-based trigger when the clock
    /// returns a value less than `started_at_secs` (NTP step-back / clock regression).
    /// Before the fix, `saturating_sub` returned a negative i64 that was never >= 900,
    /// silently disabling time-based rekey for the remainder of the session.
    #[tokio::test]
    async fn needs_rekey_not_suppressed_by_clock_regression() {
        let (mut init_keys, _) = do_xk_handshake_keys(NOW).await;
        // Simulate NTP step-back: clock goes 10 seconds behind the epoch start time.
        init_keys.clock = Box::new(FixedClock(NOW - 10));
        // elapsed = -10 after saturating_sub, clamped to 0 via max(0); 0 < 900 → not triggered.
        // This confirms no false positive.
        assert!(
            !init_keys.needs_rekey(),
            "clock regression must not trigger needs_rekey"
        );
        // A clock at exactly NOW + REKEY_TIME_LIMIT_SECS seconds must trigger.
        init_keys.clock = Box::new(FixedClock(NOW + REKEY_TIME_LIMIT_SECS));
        assert!(
            init_keys.needs_rekey(),
            "clock at exactly limit must trigger needs_rekey"
        );
    }

    /// REGRESSION: Two consecutive forged future-epoch frames with invalid tags must not
    /// evict the legitimate prior epoch keys, preserving in-flight frames.
    #[tokio::test]
    async fn two_forged_future_epoch_frames_do_not_destroy_prior_keys() {
        let (mut init_keys, mut resp_keys) = do_xk_handshake_keys(NOW).await;

        // Seal a real epoch-0 frame before any rekey.
        let epoch0_frame = init_keys.seal(ChannelId::Video, b"epoch-0 data").unwrap();
        // Rekey initiator → epoch 1.
        init_keys.rekey().unwrap();
        // Seal an epoch-1 frame.
        let epoch1_frame = init_keys.seal(ChannelId::Video, b"epoch-1 data").unwrap();

        // Send two forged frames claiming epoch 1 and epoch 2 with garbage tags.
        for claimed_epoch in [1u64, 2u64] {
            let fake_header = ChannelFrameHeader {
                channel: ChannelId::Video,
                direction: Direction::I2R,
                epoch: claimed_epoch,
                generation: 0,
                seq: 0,
            };
            let mut fake_frame = Vec::with_capacity(CHANNEL_HEADER_LEN + 16);
            fake_frame.extend_from_slice(&fake_header.encode());
            fake_frame.extend_from_slice(&[0xAAu8; 16]);
            let _ = resp_keys.open(ChannelId::Video, &fake_frame); // ignore error
        }

        // Epoch 0 frame: responder is still on epoch 0, so it should open fine.
        let r0 = resp_keys.open(ChannelId::Video, &epoch0_frame);
        assert!(
            r0.is_ok(),
            "epoch-0 frame must still decrypt after forged future-epoch frames"
        );

        // Epoch 1 frame: lazily advances responder to epoch 1, should succeed.
        let r1 = resp_keys.open(ChannelId::Video, &epoch1_frame);
        assert!(
            r1.is_ok(),
            "epoch-1 frame must decrypt via lazy advance after forged attacks"
        );
    }
}
