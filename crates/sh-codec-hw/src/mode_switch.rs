//! Glitch-free, double-buffered encoder mode switch (LLD §5.4).
//!
//! ## Overview
//!
//! When a [`ContentMode`] change arrives (e.g. Work → Game) the pipeline must swap the active
//! encoder — potentially changing pixel format (4:2:0 ↔ 4:4:4) or bitrate strategy — without
//! emitting a single un-decodable frame.  The naïve approach of re-configuring the active
//! encoder mid-session produces corrupt output because pipelined hardware encoders (NVENC,
//! VideoToolbox) buffer several frames internally; any format change hits those buffered frames
//! and typically produces garbage.
//!
//! The **double-buffered** approach used here:
//!
//! 1. **Acquire** a new session slot from the [`SessionLimiter`].
//! 2. **Build** the new encoder via the [`EncoderFactory`].
//! 3. **Prime** the new encoder with a forced IDR so its very first output packet is
//!    independently decodable — the viewer never needs to reference a frame produced by the old
//!    encoder to decode frames from the new one.
//! 4. **Swap** routing atomically: future frames go to the new encoder.
//! 5. **Drain** (`flush`) the old encoder so its tail frames are not silently dropped.
//! 6. **Destroy** the old encoder, which releases its session slot (via RAII [`SessionGuard`]).
//!
//! The invariant **slot-before-destroy** is critical on NVENC, which enforces a per-process
//! concurrent-session limit of 3–5 depending on driver version and GPU SKU.  If the old encoder
//! were destroyed *before* the new one is allocated, a transient window where both are gone would
//! risk a race with another thread also trying to create a session.  More importantly, if the new
//! allocation *fails* (limit reached), we must retain the old encoder — there is no safe fallback
//! if it has already been torn down.
//!
//! ## Backpressure policy
//!
//! [`BackpressurePolicy`] is a **pure advisory selector**: it tells the pipeline which queue
//! discipline to apply for the current [`ContentMode`].  The actual bounded-queue enforcement
//! (drop-oldest or skip-current) lives in the pipeline stage described in LLD §5.4.
//! [`DoubleBufferedEncoder::encode`] does not perform backpressure itself; it submits frames
//! unconditionally.  The pipeline reads [`DoubleBufferedEncoder::backpressure_policy`] and applies
//! the correct drop logic before calling `encode`.
//!
//! | [`ContentMode`] | Policy | Rationale |
//! |----------------|--------|-----------|
//! | `Game` | [`BackpressurePolicy::DropOldest`] | A stale game frame has zero value — always encode the freshest frame. Dropping the oldest minimizes latency at the cost of a potential missed frame. |
//! | `Work` | [`BackpressurePolicy::SkipCurrent`] | Work content rarely changes rapidly; dropping the *current* (new) frame and keeping the in-flight encode preserves the most-recently-committed state. |
//! | `Scrolling` | [`BackpressurePolicy::DropOldest`] | Scrolling uses Game-quality encode params (fast, intra-refresh). The freshest frame is the most useful during a rapid scroll gesture. |
//!
//! ## NVENC session limit (R6)
//!
//! Consumer NVENC drivers limit concurrent encoder sessions to **3–5** (GeForce/consumer GPUs).
//! [`SessionLimiter`] wraps a [`tokio::sync::Semaphore`] with a fixed number of permits.  During
//! the double-buffer overlap both the old and new encoder hold a slot, so the limit must be ≥ 2
//! for glitch-free swap.  If `max_sessions` is 1 (e.g. an extremely constrained environment), the
//! swap returns [`ModeSwitchError::NoSessionAvailable`] and the old encoder is retained intact —
//! the caller can retry after freeing capacity.
//!
//! ## Deferred
//!
//! The real NVENC 4:2:0 ↔ 4:4:4 hardware reconfigure (changing pixel format on a live NVENC
//! session) is deferred to the on-hardware session; see Risk Register entry R6 and the note in
//! the crate root.  The orchestration logic here is fully portable and is exercised against the
//! [`RawEncoder`] test backend.

use std::sync::Arc;

use sh_adaptive::classifier::ContentMode;
use sh_media::{EncodedPacket, EncoderConfig, MediaError, VideoEncoder};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::RawEncoder;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced by [`DoubleBufferedEncoder`] operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModeSwitchError {
    /// The [`SessionLimiter`] has no free slot for the new encoder.
    ///
    /// The old encoder is retained and remains fully usable.  The caller may retry after freeing
    /// capacity (e.g. by waiting for another encoder session in the process to be released).
    #[error("no NVENC session available (limit={limit}, active={active})")]
    NoSessionAvailable {
        /// Maximum concurrent sessions this limiter permits.
        limit: u32,
        /// Number of sessions currently in use at the moment of the failed acquire.
        active: u32,
    },

    /// The [`EncoderFactory`] returned an error when building the new encoder.
    ///
    /// The old encoder is retained and the session slot acquired for the new encoder is released.
    #[error("encoder factory failed during mode switch: {0}")]
    FactoryError(#[from] MediaError),
}

// ── SwitchOutcome ─────────────────────────────────────────────────────────────

/// The outcome of a successful [`DoubleBufferedEncoder::switch_to`] call.
///
/// A `SwitchOutcome` is returned when the swap itself succeeded (new encoder is live).
/// It carries the tail packets drained from the old encoder and — separately — whether
/// the old encoder's drain itself succeeded.  This distinction matters because the swap
/// is a two-phase operation:
///
/// * Phase 1 (the swap): could fail with [`ModeSwitchError`].  If it does, `switch_to`
///   returns `Err` and the old encoder is retained untouched.
/// * Phase 2 (the drain): can only run after a successful swap.  If the drain fails the
///   new encoder is already live and cannot be rolled back.  We surface the failure via
///   `flush_error` so callers can log/metric it without conflating it with a swap failure.
///
/// ## What to do with each field
///
/// * `tail_packets` — forward to the viewer *before* the new IDR arrives so the stream
///   has no gap.  May be empty for encoders that buffer nothing internally (e.g. [`RawEncoder`]).
/// * `flush_error` — log or increment a metric.  There is nothing the caller can do to
///   recover lost tail frames; this field is informational.
#[derive(Debug)]
pub struct SwitchOutcome {
    /// Packets drained from the old encoder after the swap.
    ///
    /// These are valid packets from *before* the switch point; the caller should forward
    /// them to the viewer before the new IDR packet.  Empty when the drain failed
    /// (see [`flush_error`](Self::flush_error)) or when the old encoder had no buffered frames.
    pub tail_packets: Vec<EncodedPacket>,

    /// Error from the old encoder's `flush`, if any.
    ///
    /// `None` when the drain succeeded (even if it produced zero packets).
    /// `Some(e)` when `flush()` returned an error and tail frames may be lost.
    ///
    /// The new encoder is live regardless of this field.
    pub flush_error: Option<MediaError>,
}

// ── SessionLimiter ────────────────────────────────────────────────────────────

/// Tracks the number of concurrent hardware encoder sessions.
///
/// On consumer NVENC GPUs the driver enforces a limit of **3–5** simultaneous encode sessions
/// per process.  This limiter wraps a [`tokio::sync::Semaphore`] — a vetted, sound primitive —
/// so hand-rolled atomic CAS loops and the associated `loom` testing burden are unnecessary.
///
/// `try_acquire` is non-blocking: it either returns an [`OwnedSemaphorePermit`]-backed
/// [`SessionGuard`] immediately or returns `None` without parking.  No async runtime is required.
///
/// [`SessionGuard`] is the RAII handle that holds one permit; it releases it on drop.
///
/// # Examples
///
/// ```
/// use sh_codec_hw::mode_switch::SessionLimiter;
///
/// let limiter = SessionLimiter::new(4);
/// let guard = limiter.try_acquire().expect("slot should be free");
/// assert_eq!(limiter.active_sessions(), 1);
/// drop(guard);
/// assert_eq!(limiter.active_sessions(), 0);
/// ```
#[derive(Debug, Clone)]
pub struct SessionLimiter {
    semaphore: Arc<Semaphore>,
    max_sessions: u32,
}

impl SessionLimiter {
    /// Create a new limiter with `max_sessions` available slots.
    ///
    /// The default for NVENC consumer SKUs is **4** (the driver limit is typically 5, leaving one
    /// slot for other components in the process).  Pass `1` to force single-buffer mode; pass a
    /// larger value for multi-stream or professional GPU scenarios.
    ///
    /// # Panics
    ///
    /// Does not panic.  `max_sessions = 0` is technically valid (all `try_acquire` calls fail
    /// immediately) but useful only for testing.
    #[must_use]
    pub fn new(max_sessions: u32) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_sessions as usize)),
            max_sessions,
        }
    }

    /// Attempt to acquire one session slot, returning a [`SessionGuard`] on success.
    ///
    /// Returns `None` when the current active count equals `max_sessions`.  The operation is
    /// non-blocking: it calls `try_acquire_owned` on the underlying [`Semaphore`] and returns
    /// immediately.  No async runtime or thread parking occurs.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_codec_hw::mode_switch::SessionLimiter;
    ///
    /// let limiter = SessionLimiter::new(1);
    /// let g1 = limiter.try_acquire();
    /// assert!(g1.is_some(), "first acquire should succeed");
    /// let g2 = limiter.try_acquire();
    /// assert!(g2.is_none(), "second acquire should fail when max=1");
    /// ```
    #[must_use]
    pub fn try_acquire(&self) -> Option<SessionGuard> {
        // Semaphore::try_acquire_owned is non-blocking: returns Ok(permit) if a permit is
        // available, or Err(TryAcquireError::NoPermits) if the semaphore is exhausted.
        // We use try_acquire_owned (rather than try_acquire) so the OwnedSemaphorePermit is
        // 'static / Send — it holds an Arc<Semaphore> internally and can be stored in structs
        // and moved across threads without lifetime annotations.
        Arc::clone(&self.semaphore)
            .try_acquire_owned()
            .ok()
            .map(|permit| SessionGuard { _permit: permit })
    }

    /// Current number of active sessions.  Useful for tests and diagnostics.
    ///
    /// Computed as `max_sessions - available_permits()`.
    #[must_use]
    pub fn active_sessions(&self) -> u32 {
        // available_permits() is the number of permits *not* currently held.
        // We cast via u32: max_sessions <= usize::MAX on all supported platforms.
        #[allow(clippy::cast_possible_truncation)]
        let available = self.semaphore.available_permits() as u32;
        self.max_sessions.saturating_sub(available)
    }

    /// Maximum sessions this limiter permits.
    #[must_use]
    pub fn max_sessions(&self) -> u32 {
        self.max_sessions
    }
}

// ── SessionGuard ──────────────────────────────────────────────────────────────

/// RAII guard that holds one encoder session slot in a [`SessionLimiter`].
///
/// Releases the slot back to the semaphore on drop.  Dropping a `SessionGuard` is always safe
/// and does not panic — the [`OwnedSemaphorePermit`] handles the release atomically.
#[derive(Debug)]
pub struct SessionGuard {
    // The OwnedSemaphorePermit releases exactly one permit on drop — sound, no manual bookkeeping.
    _permit: OwnedSemaphorePermit,
}

// ── BackpressurePolicy ────────────────────────────────────────────────────────

/// Advisory selector for the backpressure discipline to apply at a given [`ContentMode`].
///
/// This type is a **pure selector** — it carries no queue or enforcement mechanism itself.
/// The actual bounded-queue enforcement (drop-oldest or skip-current) is the pipeline's
/// responsibility (LLD §5.4 pipeline stages).  The pipeline calls
/// [`DoubleBufferedEncoder::backpressure_policy`] to discover the current policy and applies
/// the correct drop logic *before* submitting a frame to
/// [`DoubleBufferedEncoder::encode`].
///
/// `DoubleBufferedEncoder::encode` never blocks and never drops frames by itself — if the
/// pipeline skips calling `encode` based on this policy, that is the enforcement.
///
/// # Selection by mode
///
/// | [`ContentMode`] | Policy | Rationale |
/// |----------------|--------|-----------|
/// | `Game`       | [`DropOldest`](Self::DropOldest)  | Stale game frames are worthless. Always prefer the freshest frame. |
/// | `Work`       | [`SkipCurrent`](Self::SkipCurrent)| Work content changes slowly; preserve the committed in-flight encode. |
/// | `Scrolling`  | [`DropOldest`](Self::DropOldest)  | Same as Game: use Game-like encode params, prioritize freshness during scroll. |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressurePolicy {
    /// Drop the *oldest* pending frame and enqueue the new one.
    ///
    /// Minimizes output latency at the cost of one skipped frame. Correct for game and
    /// fast-scrolling content where a stale frame has no value to the viewer.
    DropOldest,

    /// Skip the *current* (incoming) frame; do not enqueue it.
    ///
    /// Keeps the in-flight encode from being disrupted.  Correct for Work content where the
    /// existing frame is likely still current and resubmitting would not add information.
    SkipCurrent,
}

impl BackpressurePolicy {
    /// Return the correct backpressure policy for a given [`ContentMode`].
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_adaptive::classifier::ContentMode;
    /// use sh_codec_hw::mode_switch::BackpressurePolicy;
    ///
    /// assert_eq!(
    ///     BackpressurePolicy::for_mode(ContentMode::Game),
    ///     BackpressurePolicy::DropOldest,
    /// );
    /// assert_eq!(
    ///     BackpressurePolicy::for_mode(ContentMode::Work),
    ///     BackpressurePolicy::SkipCurrent,
    /// );
    /// assert_eq!(
    ///     BackpressurePolicy::for_mode(ContentMode::Scrolling),
    ///     BackpressurePolicy::DropOldest,
    /// );
    /// ```
    #[must_use]
    pub fn for_mode(mode: ContentMode) -> Self {
        match mode {
            // Game: latency matters most; the freshest frame is always the most valuable.
            ContentMode::Game => BackpressurePolicy::DropOldest,
            // Work: content is slow-changing; preserve the in-flight encode rather than
            // interrupting it with a duplicate or near-duplicate frame.
            ContentMode::Work => BackpressurePolicy::SkipCurrent,
            // Scrolling: uses Game-quality encode params (fast, intra-refresh) and similarly
            // benefits from always encoding the freshest frame during a scroll gesture.
            ContentMode::Scrolling => BackpressurePolicy::DropOldest,
        }
    }
}

// ── EncoderFactory ────────────────────────────────────────────────────────────

/// A factory function that constructs a new [`VideoEncoder`] from an [`EncoderConfig`].
///
/// Using a `FnMut` closure offers ergonomic capture of backend state (e.g. device handles)
/// compared with a named trait object.  The trade-off: closures are harder to name in
/// signatures and do not implement `Debug`.  The tests pass a closure that returns a
/// [`RawEncoder`]; the production NVENC backend slots in a closure that calls
/// `NvencEncoder::new(config)`.
///
/// # Errors
///
/// Returns [`MediaError`] if the backend cannot create an encoder for the requested config (e.g.
/// the codec is unsupported, the resolution exceeds hardware limits, or the NVENC session limit
/// has already been reached at the driver level before the [`SessionLimiter`] fires).
pub type EncoderFactory =
    Box<dyn FnMut(&EncoderConfig) -> Result<Box<dyn VideoEncoder>, MediaError> + Send>;

/// Construct a default [`EncoderFactory`] that always produces a [`RawEncoder`].
///
/// Useful for tests and development pipelines that do not need a real hardware encoder.
///
/// # Examples
///
/// ```
/// use sh_media::{EncoderConfig, VideoEncoder};
/// use sh_protocol::Codec;
/// use sh_media::{PixelFormat, Resolution};
/// use sh_codec_hw::mode_switch::raw_encoder_factory;
///
/// let mut factory = raw_encoder_factory();
/// let config = EncoderConfig {
///     codec: Codec::Raw,
///     resolution: sh_media::Resolution::new(1920, 1080),
///     target_fps: 60,
///     target_bitrate_kbps: None,
/// };
/// let encoder = factory(&config);
/// assert!(encoder.is_ok());
/// ```
#[must_use]
pub fn raw_encoder_factory() -> EncoderFactory {
    Box::new(
        |_config: &EncoderConfig| -> Result<Box<dyn VideoEncoder>, MediaError> {
            Ok(Box::new(RawEncoder::new()))
        },
    )
}

// ── DoubleBufferedEncoder ─────────────────────────────────────────────────────

/// Glitch-free encoder switcher with session-limit guard and mode-aware backpressure.
///
/// ## Lifecycle
///
/// ```text
/// DoubleBufferedEncoder::new(config, mode, factory, limiter)
///   │
///   ├─ encode(&frame)  ─────────────────────────────────▶ Option<EncodedPacket>
///   │                  Pipeline applies backpressure_policy() before calling encode.
///   │
///   └─ switch_to(new_config, new_mode)
///        │
///        ├─ 1. try_acquire() new slot  ── fail ──▶ Err(NoSessionAvailable) (old retained)
///        │
///        ├─ 2. factory(new_config)     ── fail ──▶ Err(FactoryError) (slot released, old retained)
///        │
///        ├─ 3. request_keyframe() + [prime on next encode call]
///        │      The new encoder's first packet MUST be IDR so the stream is decodable from
///        │      the switch point.  We call request_keyframe() immediately after construction
///        │      so the first encode() call on the new encoder emits an IDR.
///        │
///        ├─ 4. swap active encoder (old ← new)
///        │
///        └─ 5. flush() old encoder (drain tail frames) → Ok(SwitchOutcome)
///               SwitchOutcome.tail_packets = drained frames (forward to viewer)
///               SwitchOutcome.flush_error  = Some(e) if drain itself failed
/// ```
///
/// ## Slot ordering invariant
///
/// The new slot is **acquired before** the old encoder is destroyed.  This means during the
/// overlap window `active_sessions` is `old_count + 1`.  Only after the new encoder is live
/// and the old is flushed/dropped does the count return to `old_count`.  This ordering prevents
/// a window where zero encoders hold sessions, which would (a) allow another component to sneak
/// in and steal the last slot, and (b) break the invariant that the pipeline is never encoding-less.
///
/// ## IDR ordering invariant
///
/// `request_keyframe()` is called on the new encoder *before* the swap.  The first frame
/// submitted to it (the frame immediately after the swap) will therefore be encoded as an IDR.
/// The viewer can decode from the switch point without referencing any frame produced by the old
/// encoder.
pub struct DoubleBufferedEncoder {
    active: Box<dyn VideoEncoder>,
    /// RAII guard for the active encoder's session slot.
    _guard: SessionGuard,
    limiter: SessionLimiter,
    factory: EncoderFactory,
    current_mode: ContentMode,
    current_config: EncoderConfig,
}

impl DoubleBufferedEncoder {
    /// Construct a new `DoubleBufferedEncoder`.
    ///
    /// Acquires the first session slot from `limiter`.  Returns an error if no slot is available.
    ///
    /// # Errors
    ///
    /// - [`ModeSwitchError::NoSessionAvailable`] if the limiter has no free slot (unusual at
    ///   construction time; indicates the process already saturated its session budget).
    /// - [`ModeSwitchError::FactoryError`] if `factory` fails to build the initial encoder.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_adaptive::classifier::ContentMode;
    /// use sh_codec_hw::mode_switch::{DoubleBufferedEncoder, SessionLimiter, raw_encoder_factory};
    /// use sh_media::EncoderConfig;
    /// use sh_protocol::Codec;
    ///
    /// let config = EncoderConfig {
    ///     codec: Codec::Raw,
    ///     resolution: sh_media::Resolution::new(1920, 1080),
    ///     target_fps: 60,
    ///     target_bitrate_kbps: None,
    /// };
    /// let limiter = SessionLimiter::new(4);
    /// let enc = DoubleBufferedEncoder::new(
    ///     config,
    ///     ContentMode::Work,
    ///     raw_encoder_factory(),
    ///     limiter,
    /// );
    /// assert!(enc.is_ok());
    /// ```
    pub fn new(
        config: EncoderConfig,
        mode: ContentMode,
        mut factory: EncoderFactory,
        limiter: SessionLimiter,
    ) -> Result<Self, ModeSwitchError> {
        let guard = limiter
            .try_acquire()
            .ok_or_else(|| ModeSwitchError::NoSessionAvailable {
                limit: limiter.max_sessions(),
                active: limiter.active_sessions(),
            })?;
        let encoder = factory(&config)?;
        Ok(Self {
            active: encoder,
            _guard: guard,
            limiter,
            factory,
            current_mode: mode,
            current_config: config,
        })
    }

    /// Return the current [`ContentMode`].
    #[must_use]
    pub fn current_mode(&self) -> ContentMode {
        self.current_mode
    }

    /// Return the current [`EncoderConfig`].
    #[must_use]
    pub fn current_config(&self) -> &EncoderConfig {
        &self.current_config
    }

    /// Return the current [`BackpressurePolicy`] for this mode.
    ///
    /// The pipeline calls this method to determine the correct frame-drop discipline before
    /// submitting frames to [`encode`](Self::encode).  `encode` itself is unconditional.
    #[must_use]
    pub fn backpressure_policy(&self) -> BackpressurePolicy {
        BackpressurePolicy::for_mode(self.current_mode)
    }

    /// Encode one frame, routing it through the active encoder.
    ///
    /// This method is **unconditional** — it always submits the frame to the encoder.  The
    /// caller is responsible for implementing the [`BackpressurePolicy`] returned by
    /// [`Self::backpressure_policy`] *before* calling this method: if the policy is
    /// [`BackpressurePolicy::SkipCurrent`] and the encoder is busy, the caller should skip the
    /// `encode` call entirely.  If the policy is [`BackpressurePolicy::DropOldest`], the caller
    /// should drop the oldest queued frame and then call `encode` with the new one.
    ///
    /// `encode` may return `None` for pipelined hardware encoders that buffer frames internally.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError`] if the underlying encoder fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use bytes::Bytes;
    /// use sh_adaptive::classifier::ContentMode;
    /// use sh_codec_hw::mode_switch::{DoubleBufferedEncoder, SessionLimiter, raw_encoder_factory};
    /// use sh_media::{EncoderConfig, VideoFrame, PixelFormat, Resolution};
    /// use sh_protocol::{Codec, FrameType};
    /// use sh_types::{FrameId, TimestampUs};
    ///
    /// let config = EncoderConfig {
    ///     codec: Codec::Raw,
    ///     resolution: Resolution::new(2, 2),
    ///     target_fps: 60,
    ///     target_bitrate_kbps: None,
    /// };
    /// let limiter = SessionLimiter::new(4);
    /// let mut enc = DoubleBufferedEncoder::new(
    ///     config,
    ///     ContentMode::Work,
    ///     raw_encoder_factory(),
    ///     limiter,
    /// ).unwrap();
    ///
    /// let frame = VideoFrame {
    ///     data: Bytes::from(vec![0u8; PixelFormat::Bgra8.frame_len(Resolution::new(2, 2))]),
    ///     format: PixelFormat::Bgra8,
    ///     resolution: Resolution::new(2, 2),
    ///     frame_id: FrameId(1),
    ///     capture_ts_us: TimestampUs(0),
    /// };
    /// let pkt = enc.encode(&frame).unwrap();
    /// assert!(pkt.is_some());
    /// ```
    pub fn encode(
        &mut self,
        frame: &sh_media::VideoFrame,
    ) -> Result<Option<EncodedPacket>, MediaError> {
        self.active.encode(frame)
    }

    /// Request that the next encoded frame from the active encoder be a keyframe.
    ///
    /// Useful after packet loss is detected (P2-6 triggers this path).
    pub fn request_keyframe(&mut self) {
        self.active.request_keyframe();
    }

    /// Update the mode without changing the encoder configuration.
    ///
    /// This changes only the active [`BackpressurePolicy`]; it does **not** trigger an encoder
    /// swap.  Use [`switch_to`](Self::switch_to) when the [`EncoderConfig`] must also change.
    pub fn request_mode(&mut self, mode: ContentMode) {
        self.current_mode = mode;
    }

    /// Perform a glitch-free double-buffered encoder swap to a new config and mode.
    ///
    /// Returns `Ok(`[`SwitchOutcome`]`)` when the swap completes (new encoder is live).
    /// Returns `Err(`[`ModeSwitchError`]`)` when the swap could not be initiated, in which case
    /// the old encoder is retained completely untouched and the pipeline continues without
    /// interruption.
    ///
    /// See [`SwitchOutcome`] for how to handle `tail_packets` and `flush_error`.
    ///
    /// ## Swap ordering (both correctness and the *why*)
    ///
    /// 1. **Acquire slot first** (`try_acquire`):  If the limit is already reached, return
    ///    [`ModeSwitchError::NoSessionAvailable`] immediately.  The old encoder is completely
    ///    untouched — the pipeline continues without interruption.  We must acquire *before*
    ///    destroying the old encoder because destroying the old one first would leave a window
    ///    where the pipeline has no encoder at all, and a concurrent session-creation failure
    ///    would leave the pipeline broken with nothing to fall back to.
    ///
    /// 2. **Build new encoder** (`factory`):  If the factory returns an error (e.g. unsupported
    ///    config, driver-level limit hit), release the just-acquired guard and return
    ///    [`ModeSwitchError::FactoryError`].  The old encoder is retained.
    ///
    /// 3. **Prime with IDR** (`request_keyframe` on the new encoder):  The new encoder's first
    ///    encoded packet must be an IDR so the viewer can start decoding from the switch point
    ///    without referencing any frame produced by the old encoder.  Calling `request_keyframe`
    ///    *before* the swap ensures this property regardless of when the first frame is submitted.
    ///
    /// 4. **Atomic swap** (replace `self.active` and `self._guard`):  From this point all new
    ///    frames go to the new encoder.  The old encoder is held temporarily while we drain it.
    ///
    /// 5. **Drain old encoder** (`flush`):  Hardware encoders buffer frames internally.  Flushing
    ///    emits any tail packets so they are not silently lost.  On success, these tail packets
    ///    appear in [`SwitchOutcome::tail_packets`].  On failure, `SwitchOutcome::flush_error`
    ///    is set and `tail_packets` is empty.
    ///
    /// 6. **Destroy old encoder** (drop): releasing the old guard decrements `active_sessions`.
    ///
    /// After step 6 the session count is back to exactly what it was before the switch (no leak).
    ///
    /// # Errors
    ///
    /// - [`ModeSwitchError::NoSessionAvailable`]: no slot free; old encoder retained and usable.
    /// - [`ModeSwitchError::FactoryError`]: factory failed; old encoder retained and usable.
    ///
    /// # Panics
    ///
    /// Does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use bytes::Bytes;
    /// use sh_adaptive::classifier::ContentMode;
    /// use sh_codec_hw::mode_switch::{DoubleBufferedEncoder, SessionLimiter, raw_encoder_factory};
    /// use sh_media::{EncoderConfig, VideoFrame, PixelFormat, Resolution};
    /// use sh_protocol::{Codec, FrameType};
    /// use sh_types::{FrameId, TimestampUs};
    ///
    /// let res = Resolution::new(4, 4);
    /// let config = EncoderConfig {
    ///     codec: Codec::Raw,
    ///     resolution: res,
    ///     target_fps: 60,
    ///     target_bitrate_kbps: None,
    /// };
    /// let limiter = SessionLimiter::new(4);
    /// let mut enc = DoubleBufferedEncoder::new(
    ///     config,
    ///     ContentMode::Work,
    ///     raw_encoder_factory(),
    ///     limiter,
    /// ).unwrap();
    ///
    /// // Perform a mode switch.
    /// let new_config = EncoderConfig {
    ///     codec: Codec::Raw,
    ///     resolution: res,
    ///     target_fps: 60,
    ///     target_bitrate_kbps: Some(4000),
    /// };
    /// let outcome = enc.switch_to(new_config, ContentMode::Game).unwrap();
    /// // tail_packets contains drained frames from the old encoder (may be empty for RawEncoder).
    /// assert!(outcome.flush_error.is_none());
    /// assert_eq!(enc.current_mode(), ContentMode::Game);
    /// ```
    pub fn switch_to(
        &mut self,
        new_config: EncoderConfig,
        new_mode: ContentMode,
    ) -> Result<SwitchOutcome, ModeSwitchError> {
        tracing::debug!("acquiring new session slot for double-buffer swap");

        // Step 1: acquire new slot BEFORE destroying the old encoder.
        let new_guard = match self.limiter.try_acquire() {
            Some(g) => g,
            None => {
                let active = self.limiter.active_sessions();
                let limit = self.limiter.max_sessions();
                tracing::warn!(
                    limit,
                    active,
                    "no session slot available — retaining old encoder"
                );
                return Err(ModeSwitchError::NoSessionAvailable { limit, active });
            }
        };

        // Step 2: build the new encoder via the factory.
        let mut new_encoder = match (self.factory)(&new_config) {
            Ok(e) => e,
            Err(err) => {
                // Drop new_guard here → releases the slot we just acquired.
                drop(new_guard);
                tracing::warn!(%err, "factory error — retaining old encoder, releasing new slot");
                return Err(ModeSwitchError::FactoryError(err));
            }
        };

        // Step 3: prime the new encoder with a forced IDR.
        // Calling request_keyframe BEFORE the swap guarantees the new encoder's very first
        // encode() call emits an IDR packet, making the stream decodable from the switch point.
        new_encoder.request_keyframe();
        tracing::debug!("new encoder primed with IDR request");

        // Step 4: atomically swap the active encoder and its guard.
        // From this point new frames route to new_encoder.
        let mut old_encoder = std::mem::replace(&mut self.active, new_encoder);
        let old_guard = std::mem::replace(&mut self._guard, new_guard);

        self.current_config = new_config;
        self.current_mode = new_mode;
        tracing::debug!("routing swapped to new encoder");

        // Step 5: drain the old encoder so tail frames are not silently lost.
        // The old encoder is still alive here; its session is still counted by old_guard.
        let (tail_packets, flush_error) = match old_encoder.flush() {
            Ok(pkts) => {
                tracing::debug!(count = pkts.len(), "old encoder flushed");
                (pkts, None)
            }
            Err(err) => {
                // Flush failure is non-fatal: the swap has already committed to the new encoder.
                // Surface the error in SwitchOutcome so the caller can log/metric it.
                tracing::warn!(%err, "old encoder flush error — tail frames may be lost");
                (Vec::new(), Some(err))
            }
        };

        // Step 6: drop old encoder and its guard → decrements active_sessions.
        drop(old_encoder);
        drop(old_guard);
        tracing::debug!("old encoder destroyed, session slot released");

        Ok(SwitchOutcome {
            tail_packets,
            flush_error,
        })
    }
}

impl std::fmt::Debug for DoubleBufferedEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoubleBufferedEncoder")
            .field("current_mode", &self.current_mode)
            .field("current_config", &self.current_config)
            .field("active_sessions", &self.limiter.active_sessions())
            .finish()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sh_media::{EncoderCaps, EncoderConfig, PixelFormat, Resolution, VideoFrame};
    use sh_protocol::{Codec, FrameType};
    use sh_types::{FrameId, TimestampUs};
    use std::sync::{Arc, Mutex};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn base_config() -> EncoderConfig {
        EncoderConfig {
            codec: Codec::Raw,
            resolution: Resolution::new(4, 4),
            target_fps: 30,
            target_bitrate_kbps: None,
        }
    }

    fn game_config() -> EncoderConfig {
        EncoderConfig {
            codec: Codec::Raw,
            resolution: Resolution::new(4, 4),
            target_fps: 60,
            target_bitrate_kbps: Some(8000),
        }
    }

    /// Build a valid 4×4 BGRA frame.
    fn make_frame(id: u64) -> VideoFrame {
        let res = Resolution::new(4, 4);
        let len = PixelFormat::Bgra8.frame_len(res);
        VideoFrame {
            data: Bytes::from(vec![id as u8; len]),
            format: PixelFormat::Bgra8,
            resolution: res,
            frame_id: FrameId(id),
            capture_ts_us: TimestampUs(id),
        }
    }

    fn make_enc(mode: ContentMode, limit: u32) -> DoubleBufferedEncoder {
        DoubleBufferedEncoder::new(
            base_config(),
            mode,
            raw_encoder_factory(),
            SessionLimiter::new(limit),
        )
        .unwrap()
    }

    // ── KeyframeTrackingEncoder mock ──────────────────────────────────────────
    //
    // This mock is essential for testing the IDR-priming invariant and tail-drain correctness.
    // Unlike RawEncoder (which returns IDR for every frame and ignores request_keyframe), this
    // mock:
    //   - emits FrameType::Predicted by default
    //   - emits FrameType::Idr on the FIRST encode call after request_keyframe() (then resets)
    //   - buffers one tail packet in its internal queue, returned by flush()
    //
    // This means:
    //   (a) Deleting the request_keyframe() call in switch_to() causes
    //       first_packet_after_switch_is_idr_via_priming to FAIL.
    //   (b) The tail packet buffered before the swap appears in SwitchOutcome.tail_packets,
    //       proving the drain is real (not vacuous).

    #[derive(Debug)]
    struct KeyframeTrackingEncoder {
        /// True when the next encode call should emit IDR.
        keyframe_pending: bool,
        /// Buffered tail packet — returned by flush(), simulating a pipelined encoder.
        tail_buffer: Vec<sh_media::EncodedPacket>,
        /// Shared log: records ("encode"|"keyframe_request"|"flush") for assertions.
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl KeyframeTrackingEncoder {
        fn new(log: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                keyframe_pending: false,
                tail_buffer: Vec::new(),
                log,
            }
        }

        /// Pre-load a tail packet that flush() will return.
        fn push_tail_packet(&mut self, pkt: sh_media::EncodedPacket) {
            self.tail_buffer.push(pkt);
        }
    }

    impl VideoEncoder for KeyframeTrackingEncoder {
        fn encode(
            &mut self,
            frame: &VideoFrame,
        ) -> Result<Option<sh_media::EncodedPacket>, MediaError> {
            self.log.lock().unwrap().push("encode");
            let frame_type = if self.keyframe_pending {
                self.keyframe_pending = false;
                FrameType::Idr
            } else {
                FrameType::Predicted
            };
            Ok(Some(sh_media::EncodedPacket {
                data: frame.data.clone(),
                codec: Codec::Raw,
                frame_id: frame.frame_id,
                capture_ts_us: frame.capture_ts_us,
                frame_type,
            }))
        }

        fn request_keyframe(&mut self) {
            self.log.lock().unwrap().push("keyframe_request");
            self.keyframe_pending = true;
        }

        fn flush(&mut self) -> Result<Vec<sh_media::EncodedPacket>, MediaError> {
            self.log.lock().unwrap().push("flush");
            Ok(std::mem::take(&mut self.tail_buffer))
        }

        fn caps(&self) -> EncoderCaps {
            EncoderCaps {
                codec: Codec::Raw,
                hardware: false,
                max_resolution: Resolution::new(u32::MAX, u32::MAX),
                accepted_input_formats: &[],
            }
        }
    }

    // ── SessionLimiter ────────────────────────────────────────────────────────

    #[test]
    fn session_limiter_acquire_release_cycle() {
        let lim = SessionLimiter::new(4);
        assert_eq!(lim.active_sessions(), 0);

        let g1 = lim.try_acquire().unwrap();
        assert_eq!(lim.active_sessions(), 1);
        let g2 = lim.try_acquire().unwrap();
        assert_eq!(lim.active_sessions(), 2);

        drop(g1);
        assert_eq!(lim.active_sessions(), 1);
        drop(g2);
        assert_eq!(lim.active_sessions(), 0);
    }

    #[test]
    fn session_limiter_enforces_max() {
        let lim = SessionLimiter::new(2);
        let _g1 = lim.try_acquire().unwrap();
        let _g2 = lim.try_acquire().unwrap();
        let g3 = lim.try_acquire();
        assert!(g3.is_none(), "third acquire must fail when max=2");
    }

    #[test]
    fn session_limiter_zero_max_always_fails() {
        let lim = SessionLimiter::new(0);
        assert!(lim.try_acquire().is_none());
    }

    #[test]
    fn session_guard_drop_releases_permit() {
        let lim = SessionLimiter::new(4);
        let g = lim.try_acquire().unwrap();
        assert_eq!(lim.active_sessions(), 1);
        drop(g);
        // Permit must be returned to the semaphore — active count back to zero.
        assert_eq!(lim.active_sessions(), 0);
    }

    #[test]
    fn session_limiter_no_leak_after_n_switches() {
        let lim = SessionLimiter::new(4);
        let mut enc = DoubleBufferedEncoder::new(
            base_config(),
            ContentMode::Work,
            raw_encoder_factory(),
            lim.clone(),
        )
        .unwrap();
        assert_eq!(lim.active_sessions(), 1);

        for _ in 0..10 {
            let outcome = enc.switch_to(game_config(), ContentMode::Game).unwrap();
            assert!(outcome.flush_error.is_none());
            assert_eq!(
                lim.active_sessions(),
                1,
                "after each switch exactly 1 session must be active"
            );
        }
    }

    // ── IDR priming: KeyframeTrackingEncoder tests ────────────────────────────

    /// Verifies that the new encoder's first post-swap packet is IDR *because* of the priming
    /// call in switch_to.  If the request_keyframe() call is removed from switch_to, this test
    /// fails because KeyframeTrackingEncoder emits Predicted by default.
    #[test]
    fn first_packet_after_switch_is_idr_via_priming() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log_clone = Arc::clone(&log);

        let factory: EncoderFactory = Box::new(move |_| {
            Ok(
                Box::new(KeyframeTrackingEncoder::new(Arc::clone(&log_clone)))
                    as Box<dyn VideoEncoder>,
            )
        });

        let lim = SessionLimiter::new(4);
        let mut enc =
            DoubleBufferedEncoder::new(base_config(), ContentMode::Work, factory, lim).unwrap();

        // Encode a few frames on the old encoder (these will be Predicted by default).
        for i in 0..3u64 {
            let pkt = enc.encode(&make_frame(i)).unwrap().unwrap();
            assert_eq!(
                pkt.frame_type,
                FrameType::Predicted,
                "pre-switch frames must be Predicted (no prime yet)"
            );
        }

        // Switch — switch_to must call request_keyframe() on the new encoder before the swap.
        let outcome = enc.switch_to(game_config(), ContentMode::Game).unwrap();
        assert!(outcome.flush_error.is_none());

        // The FIRST packet from the new encoder must be IDR because of the priming.
        let first_pkt = enc.encode(&make_frame(100)).unwrap().unwrap();
        assert_eq!(
            first_pkt.frame_type,
            FrameType::Idr,
            "first packet after switch must be IDR — IDR priming is working"
        );

        // The second packet must revert to Predicted (keyframe_pending resets after one IDR).
        let second_pkt = enc.encode(&make_frame(101)).unwrap().unwrap();
        assert_eq!(
            second_pkt.frame_type,
            FrameType::Predicted,
            "second packet after switch must be Predicted"
        );

        // Verify the call log contains a keyframe_request between construction and encode(100).
        let calls = log.lock().unwrap();
        // log contains: encode×3 (pre-switch) | keyframe_request (priming) | flush (drain) |
        //               encode×2 (post-switch)
        assert!(
            calls.contains(&"keyframe_request"),
            "request_keyframe must appear in call log: {calls:?}"
        );
        assert!(
            calls.contains(&"flush"),
            "flush must appear in call log (drain): {calls:?}"
        );
    }

    /// Verifies that a tail packet pre-loaded into the old encoder's buffer appears in
    /// SwitchOutcome.tail_packets — proving the drain path is real, not vacuous.
    #[test]
    fn tail_drain_returns_old_encoder_buffered_packets() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log_clone = Arc::clone(&log);
        let mut call_count = 0u32;

        let factory: EncoderFactory = Box::new(move |_| {
            let enc = if call_count == 0 {
                // First call: build the initial old encoder and pre-load it with a tail packet.
                let mut e = KeyframeTrackingEncoder::new(Arc::clone(&log_clone));
                // Simulate a pipelined encoder that has one buffered frame.
                let tail_pkt = sh_media::EncodedPacket {
                    data: Bytes::from_static(b"tail"),
                    codec: Codec::Raw,
                    frame_id: FrameId(999),
                    capture_ts_us: sh_types::TimestampUs(999),
                    frame_type: FrameType::Predicted,
                };
                e.push_tail_packet(tail_pkt);
                e
            } else {
                KeyframeTrackingEncoder::new(Arc::clone(&log_clone))
            };
            call_count = call_count.saturating_add(1);
            Ok(Box::new(enc) as Box<dyn VideoEncoder>)
        });

        let lim = SessionLimiter::new(4);
        let mut enc =
            DoubleBufferedEncoder::new(base_config(), ContentMode::Work, factory, lim).unwrap();

        let outcome = enc.switch_to(game_config(), ContentMode::Game).unwrap();

        assert!(
            outcome.flush_error.is_none(),
            "flush must succeed for KeyframeTrackingEncoder"
        );
        assert_eq!(
            outcome.tail_packets.len(),
            1,
            "the old encoder's buffered tail packet must appear in SwitchOutcome"
        );
        let first_tail = outcome
            .tail_packets
            .first()
            .expect("tail_packets is non-empty, asserted above");
        assert_eq!(
            first_tail.frame_id,
            FrameId(999),
            "tail packet must be the one pre-loaded into the old encoder"
        );
    }

    // ── Glitch-free swap: first packet is IDR (RawEncoder path) ──────────────

    #[test]
    fn first_packet_after_switch_is_idr() {
        let lim = SessionLimiter::new(4);
        let mut enc = DoubleBufferedEncoder::new(
            base_config(),
            ContentMode::Work,
            raw_encoder_factory(),
            lim,
        )
        .unwrap();

        // Encode a few frames on the old encoder.
        for i in 0..3u64 {
            enc.encode(&make_frame(i)).unwrap();
        }

        // Switch to Game mode.
        let outcome = enc.switch_to(game_config(), ContentMode::Game).unwrap();
        assert!(outcome.flush_error.is_none());

        eprintln!(
            "[test] switch produced {} tail packets from old encoder",
            outcome.tail_packets.len()
        );

        // The FIRST packet from the new encoder must be an IDR.
        let first_pkt = enc.encode(&make_frame(100)).unwrap().unwrap();
        eprintln!(
            "[test] first new-encoder packet: frame_type={:?}",
            first_pkt.frame_type
        );
        assert_eq!(
            first_pkt.frame_type,
            FrameType::Idr,
            "first packet after switch must be IDR"
        );
    }

    // ── Session-limit guard: max=1 ────────────────────────────────────────────

    #[test]
    fn switch_fails_when_no_session_available_max1() {
        // With max_sessions=1, the single slot is held by the active encoder.
        // A switch requires a second slot during overlap → must fail.
        let lim = SessionLimiter::new(1);
        let mut enc = DoubleBufferedEncoder::new(
            base_config(),
            ContentMode::Work,
            raw_encoder_factory(),
            lim.clone(),
        )
        .unwrap();

        assert_eq!(lim.active_sessions(), 1);

        let result = enc.switch_to(game_config(), ContentMode::Game);
        assert!(
            matches!(result, Err(ModeSwitchError::NoSessionAvailable { .. })),
            "switch must fail when max_sessions=1"
        );

        // Old encoder must still work.
        let pkt = enc.encode(&make_frame(0)).unwrap().unwrap();
        assert_eq!(
            pkt.frame_type,
            FrameType::Idr,
            "old encoder still usable after failed switch"
        );

        // Mode must be unchanged.
        assert_eq!(enc.current_mode(), ContentMode::Work);
        // Session count must still be exactly 1.
        assert_eq!(lim.active_sessions(), 1);
    }

    // ── Session-limit guard: max>=2, count returns to 1 ──────────────────────

    #[test]
    fn switch_with_max2_counter_returns_to_1() {
        let lim = SessionLimiter::new(2);
        let mut enc = DoubleBufferedEncoder::new(
            base_config(),
            ContentMode::Work,
            raw_encoder_factory(),
            lim.clone(),
        )
        .unwrap();

        assert_eq!(lim.active_sessions(), 1);

        let outcome = enc.switch_to(game_config(), ContentMode::Game).unwrap();
        assert!(outcome.flush_error.is_none());

        assert_eq!(
            lim.active_sessions(),
            1,
            "after swap counter must be 1, not 2 (old slot must be released)"
        );
    }

    // ── Factory failure: old encoder retained ─────────────────────────────────

    #[test]
    fn factory_failure_retains_old_encoder() {
        // Use a call-count factory: call 0 (constructor) succeeds, call 1+ (switch) fails.
        // This tests that when the factory fails during a switch the old encoder is retained,
        // the newly acquired session slot is released, and the session count does not leak.
        let mut call_count = 0u32;
        let mixed_factory: EncoderFactory = Box::new(move |_| {
            let n = call_count;
            call_count = call_count.saturating_add(1);
            if n == 0 {
                // First call (constructor): succeed.
                Ok(Box::new(RawEncoder::new()) as Box<dyn VideoEncoder>)
            } else {
                // Subsequent calls (switch): fail — simulates NVENC driver error.
                Err(MediaError::Unsupported(
                    "simulated NVENC factory error".to_owned(),
                ))
            }
        });

        let lim = SessionLimiter::new(4);
        let mut enc = DoubleBufferedEncoder::new(
            base_config(),
            ContentMode::Work,
            mixed_factory,
            lim.clone(),
        )
        .unwrap();

        // Switch must fail (factory returns Err on the 2nd call).
        let result = enc.switch_to(game_config(), ContentMode::Game);
        assert!(
            matches!(result, Err(ModeSwitchError::FactoryError(_))),
            "switch must fail on factory error"
        );

        // Old encoder must still work.
        let pkt = enc.encode(&make_frame(0)).unwrap().unwrap();
        assert_eq!(pkt.frame_type, FrameType::Idr);

        // Mode unchanged.
        assert_eq!(enc.current_mode(), ContentMode::Work);

        // Session count must be 1 (the slot acquired for the failed new encoder must have been
        // released by drop(new_guard) in the factory-error path).
        assert_eq!(lim.active_sessions(), 1);
        drop(enc);
        assert_eq!(lim.active_sessions(), 0);
    }

    // ── Flush error surface ───────────────────────────────────────────────────

    /// Verify that a flush error is surfaced in SwitchOutcome.flush_error, not silently swallowed.
    #[test]
    fn flush_error_surfaced_in_switch_outcome() {
        /// An encoder whose flush always fails.
        struct FailFlushEncoder(RawEncoder);

        impl VideoEncoder for FailFlushEncoder {
            fn encode(
                &mut self,
                frame: &VideoFrame,
            ) -> Result<Option<sh_media::EncodedPacket>, MediaError> {
                self.0.encode(frame)
            }

            fn request_keyframe(&mut self) {
                self.0.request_keyframe();
            }

            fn flush(&mut self) -> Result<Vec<sh_media::EncodedPacket>, MediaError> {
                Err(MediaError::Encode("simulated flush failure".to_owned()))
            }

            fn caps(&self) -> EncoderCaps {
                self.0.caps()
            }
        }

        let mut call_count = 0u32;
        let factory: EncoderFactory = Box::new(move |_| {
            let n = call_count;
            call_count = call_count.saturating_add(1);
            if n == 0 {
                // Initial encoder: fails on flush.
                Ok(Box::new(FailFlushEncoder(RawEncoder::new())) as Box<dyn VideoEncoder>)
            } else {
                // Replacement encoder: normal.
                Ok(Box::new(RawEncoder::new()) as Box<dyn VideoEncoder>)
            }
        });

        let lim = SessionLimiter::new(4);
        let mut enc =
            DoubleBufferedEncoder::new(base_config(), ContentMode::Work, factory, lim.clone())
                .unwrap();

        // The swap itself succeeds; the old encoder's flush fails.
        let outcome = enc.switch_to(game_config(), ContentMode::Game).unwrap();

        assert!(
            outcome.flush_error.is_some(),
            "flush_error must be Some when old encoder flush fails"
        );
        assert!(
            outcome.tail_packets.is_empty(),
            "no tail packets when flush fails"
        );

        // New encoder must be live and usable despite the old encoder's flush error.
        let pkt = enc.encode(&make_frame(0)).unwrap().unwrap();
        assert_eq!(pkt.frame_type, FrameType::Idr);

        // Session count must be 1 (no leak even when flush fails).
        assert_eq!(lim.active_sessions(), 1);
    }

    // ── Backpressure policy ───────────────────────────────────────────────────

    #[test]
    fn backpressure_game_is_drop_oldest() {
        assert_eq!(
            BackpressurePolicy::for_mode(ContentMode::Game),
            BackpressurePolicy::DropOldest
        );
    }

    #[test]
    fn backpressure_work_is_skip_current() {
        assert_eq!(
            BackpressurePolicy::for_mode(ContentMode::Work),
            BackpressurePolicy::SkipCurrent
        );
    }

    #[test]
    fn backpressure_scrolling_is_drop_oldest() {
        assert_eq!(
            BackpressurePolicy::for_mode(ContentMode::Scrolling),
            BackpressurePolicy::DropOldest
        );
    }

    #[test]
    fn double_buffered_encoder_backpressure_reflects_mode() {
        let mut enc = make_enc(ContentMode::Work, 4);
        assert_eq!(enc.backpressure_policy(), BackpressurePolicy::SkipCurrent);

        enc.request_mode(ContentMode::Game);
        assert_eq!(enc.backpressure_policy(), BackpressurePolicy::DropOldest);

        enc.request_mode(ContentMode::Scrolling);
        assert_eq!(enc.backpressure_policy(), BackpressurePolicy::DropOldest);
    }

    // ── Encode delegation ─────────────────────────────────────────────────────

    #[test]
    fn encode_routes_to_active_encoder() {
        let mut enc = make_enc(ContentMode::Game, 4);
        let frame = make_frame(42);
        let pkt = enc.encode(&frame).unwrap().unwrap();
        assert_eq!(pkt.frame_id, FrameId(42));
        assert_eq!(pkt.frame_type, FrameType::Idr);
    }

    // ── Switch trace ──────────────────────────────────────────────────────────

    #[test]
    fn switch_trace_exercises_full_swap_path() {
        // This test exercises the full swap path and validates correctness.
        // Run with `cargo test -p sh-codec-hw -- --nocapture` to see tracing output
        // if a tracing subscriber is installed (tracing emits nothing without one by default).
        let lim = SessionLimiter::new(4);
        let mut enc = DoubleBufferedEncoder::new(
            base_config(),
            ContentMode::Work,
            raw_encoder_factory(),
            lim.clone(),
        )
        .unwrap();

        eprintln!("\n=== Swap trace begin ===");
        eprintln!(
            "old encoder active (mode=Work, sessions={})",
            lim.active_sessions()
        );

        // Encode a couple of frames on old encoder.
        enc.encode(&make_frame(1)).unwrap();
        enc.encode(&make_frame(2)).unwrap();

        eprintln!("switching Work → Game …");
        let outcome = enc.switch_to(game_config(), ContentMode::Game).unwrap();
        eprintln!(
            "old encoder drained: {} tail packet(s), flush_error={:?}",
            outcome.tail_packets.len(),
            outcome.flush_error
        );
        eprintln!("new session active (sessions={})", lim.active_sessions());

        let first_new = enc.encode(&make_frame(3)).unwrap().unwrap();
        eprintln!(
            "first new-encoder packet: frame_type={:?} (must be IDR)",
            first_new.frame_type
        );
        eprintln!("=== Swap trace end ===\n");

        assert!(outcome.flush_error.is_none());
        assert_eq!(first_new.frame_type, FrameType::Idr);
        assert_eq!(lim.active_sessions(), 1);
    }
}
