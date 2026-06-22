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
//! The [`BackpressurePolicy`] controls what happens when the encoder is busy (e.g. its internal
//! queue is full or the pipeline is momentarily saturated):
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
//! [`SessionLimiter`] tracks the live count with an `Arc<AtomicU32>`.  During the double-buffer
//! overlap both the old and new encoder hold a slot, so the limit must be ≥ 2 for glitch-free
//! swap.  If `max_sessions` is 1 (e.g. an extremely constrained environment), the swap returns
//! [`ModeSwitchError::NoSessionAvailable`] and the old encoder is retained intact — the caller can
//! retry after freeing capacity.
//!
//! ## Deferred
//!
//! The real NVENC 4:2:0 ↔ 4:4:4 hardware reconfigure (changing pixel format on a live NVENC
//! session) is deferred to the on-hardware session; see Risk Register entry R6 and the note in
//! the crate root.  The orchestration logic here is fully portable and is exercised against the
//! [`RawEncoder`] test backend.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use sh_adaptive::classifier::ContentMode;
use sh_media::{EncoderConfig, MediaError, VideoEncoder};

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
        /// Number of sessions currently in use.
        active: u32,
    },

    /// The [`EncoderFactory`] returned an error when building the new encoder.
    ///
    /// The old encoder is retained and the session slot acquired for the new encoder is released.
    #[error("encoder factory failed during mode switch: {0}")]
    FactoryError(#[from] MediaError),
}

// ── SessionLimiter ────────────────────────────────────────────────────────────

/// Tracks the number of concurrent hardware encoder sessions.
///
/// On consumer NVENC GPUs the driver enforces a limit of **3–5** simultaneous encode sessions
/// per process.  This limiter tracks the live count with an [`AtomicU32`]; a new session is only
/// allocated when the count is below `max_sessions`.  During a double-buffer swap both the old
/// and new encoder hold a slot, so the max should be ≥ 2 for glitch-free operation (the default
/// of 4 is a safe choice for NVENC consumer SKUs where the limit is typically 5).
///
/// [`SessionGuard`] is the RAII handle that holds a slot; it releases it on drop.
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
    counter: Arc<AtomicU32>,
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
            counter: Arc::new(AtomicU32::new(0)),
            max_sessions,
        }
    }

    /// Attempt to acquire one session slot, returning a [`SessionGuard`] on success.
    ///
    /// Returns `None` when the current active count equals `max_sessions`.  The operation is
    /// lock-free: it uses a compare-and-swap loop to increment the counter only if it is below the
    /// limit.  The CAS loop is wait-free under non-contention (the common case — encoder session
    /// creation is serialized by the pipeline) and terminates in bounded iterations under
    /// contention (at most `max_sessions` iterations before all slots are observed full).
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
        // CAS loop: increment only if counter < max_sessions.
        loop {
            let current = self.counter.load(Ordering::Acquire);
            if current >= self.max_sessions {
                return None;
            }
            // Attempt to go from `current` → `current + 1`.
            // Use `current.saturating_add(1)` to avoid any arithmetic overflow (the value is
            // bounded by `max_sessions` so overflow is not reachable in practice, but
            // saturating_add removes any doubt and satisfies the arithmetic_side_effects lint).
            let next = current.saturating_add(1);
            match self
                .counter
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Some(SessionGuard {
                        counter: Arc::clone(&self.counter),
                    })
                }
                Err(_) => {
                    // Another thread raced; retry.
                    continue;
                }
            }
        }
    }

    /// Current number of active sessions.  Useful for tests and diagnostics.
    #[must_use]
    pub fn active_sessions(&self) -> u32 {
        self.counter.load(Ordering::Acquire)
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
/// Decrements the counter on drop.  Dropping a `SessionGuard` is always safe and does not panic.
#[derive(Debug)]
pub struct SessionGuard {
    counter: Arc<AtomicU32>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        // Saturating sub: should never underflow (we only create guards by incrementing), but
        // saturating avoids any theoretical panic if a guard is somehow double-dropped in tests.
        let prev = self
            .counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                Some(v.saturating_sub(1))
            });
        // fetch_update with an infallible closure (always returns Some) never returns Err.
        let _ = prev;
    }
}

// ── BackpressurePolicy ────────────────────────────────────────────────────────

/// What to do when the encoder pipeline is saturated and a new frame arrives.
///
/// This is a pure descriptor — the *mechanism* (bounded queue, frame drop) lives in the
/// transport/pipeline layer.  `DoubleBufferedEncoder` exposes the policy so the caller can
/// implement the correct queue discipline.
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
/// Using a `FnMut` closure (rather than a trait object) keeps the seam simple and avoids an
/// extra heap allocation for the factory itself.  The tests pass a closure that returns a
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
///   │                                                     (backpressure via policy)
///   │
///   └─ switch_to(new_config, new_mode)
///        │
///        ├─ 1. try_acquire() new slot  ── fail ──▶ NoSessionAvailable (old retained)
///        │
///        ├─ 2. factory(new_config)     ── fail ──▶ FactoryError (slot released, old retained)
///        │
///        ├─ 3. request_keyframe() + [prime on next encode call]
///        │      The new encoder's first packet MUST be IDR so the stream is decodable from
///        │      the switch point.  We call request_keyframe() immediately after construction
///        │      so the first encode() call on the new encoder emits an IDR.
///        │
///        ├─ 4. swap active encoder (old ← new)
///        │
///        └─ 5. flush() old encoder (drain tail frames) then drop (releases old slot)
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
    #[must_use]
    pub fn backpressure_policy(&self) -> BackpressurePolicy {
        BackpressurePolicy::for_mode(self.current_mode)
    }

    /// Encode one frame, routing it through the active encoder.
    ///
    /// The caller is responsible for implementing the [`BackpressurePolicy`] returned by
    /// [`Self::backpressure_policy`].  `encode` itself never blocks — it submits the frame to
    /// the active encoder and returns whatever the encoder produces (which may be `None` for
    /// pipelined hardware encoders that buffer frames internally).
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
    ) -> Result<Option<sh_media::EncodedPacket>, MediaError> {
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
    ///    emits any tail packets so they are not silently lost.  These tail packets are returned
    ///    to the caller as [`flush_packets`] alongside `Ok(())`.  They were encoded by the old
    ///    encoder and are valid packets from *before* the switch point; the caller may forward
    ///    them to the viewer before the new IDR arrives (or discard them if the viewer has reset).
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
    /// let (tail_packets, _result) = enc.switch_to(new_config, ContentMode::Game);
    /// // tail_packets contains drained frames from the old encoder (may be empty for RawEncoder).
    /// assert_eq!(enc.current_mode(), ContentMode::Game);
    /// ```
    pub fn switch_to(
        &mut self,
        new_config: EncoderConfig,
        new_mode: ContentMode,
    ) -> (Vec<sh_media::EncodedPacket>, Result<(), ModeSwitchError>) {
        tracing_log("acquiring new session slot for double-buffer swap");

        // Step 1: acquire new slot BEFORE destroying the old encoder.
        let new_guard = match self.limiter.try_acquire() {
            Some(g) => g,
            None => {
                let active = self.limiter.active_sessions();
                let limit = self.limiter.max_sessions();
                tracing_log("no session slot available — retaining old encoder");
                return (
                    Vec::new(),
                    Err(ModeSwitchError::NoSessionAvailable { limit, active }),
                );
            }
        };

        // Step 2: build the new encoder via the factory.
        let new_encoder = match (self.factory)(&new_config) {
            Ok(e) => e,
            Err(err) => {
                // Drop new_guard here → releases the slot we just acquired.
                drop(new_guard);
                tracing_log("factory error — retaining old encoder, releasing new slot");
                return (Vec::new(), Err(ModeSwitchError::FactoryError(err)));
            }
        };

        // Step 3: prime the new encoder with a forced IDR.
        // Calling request_keyframe BEFORE the swap guarantees the new encoder's very first
        // encode() call emits an IDR packet, making the stream decodable from the switch point.
        let mut new_encoder = new_encoder;
        new_encoder.request_keyframe();
        tracing_log("new encoder primed with IDR request");

        // Step 4: atomically swap the active encoder and its guard.
        // From this point new frames route to new_encoder.
        let old_encoder = std::mem::replace(&mut self.active, new_encoder);
        // We need to update the guard — build a wrapper that holds both temporarily, then drop old.
        // Take the old guard out by replacing with new_guard.
        let old_guard = std::mem::replace(&mut self._guard, new_guard);

        self.current_config = new_config;
        self.current_mode = new_mode;
        tracing_log("routing swapped to new encoder");

        // Step 5: drain the old encoder so tail frames are not silently lost.
        // The old encoder is still alive here; its session is still counted by old_guard.
        let mut old_encoder = old_encoder;
        let flush_packets = match old_encoder.flush() {
            Ok(pkts) => {
                tracing_log("old encoder flushed");
                pkts
            }
            Err(_) => {
                // Flush failure is non-fatal: we've already committed to the new encoder.
                // Drop the old encoder and its guard below; return empty tail.
                tracing_log("old encoder flush error — discarding tail");
                Vec::new()
            }
        };

        // Step 6: drop old encoder and its guard → decrements active_sessions.
        drop(old_encoder);
        drop(old_guard);
        tracing_log("old encoder destroyed, session slot released");

        (flush_packets, Ok(()))
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

/// Minimal tracing shim that writes to stderr in tests (zero-dep, no async).
///
/// In production this would route through `tracing`; for now it provides the
/// "swap trace" output required by the Definition of Done without adding a
/// dependency on the full `tracing` crate.
fn tracing_log(msg: &str) {
    // Only emit output when running under `cargo test` so production builds are silent.
    #[cfg(test)]
    eprintln!("[mode_switch] {msg}");
    #[cfg(not(test))]
    let _ = msg;
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
    use sh_media::{EncoderConfig, PixelFormat, Resolution, VideoFrame};
    use sh_protocol::{Codec, FrameType};
    use sh_types::{FrameId, TimestampUs};

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
    fn session_guard_drop_does_not_underflow() {
        let lim = SessionLimiter::new(4);
        let g = lim.try_acquire().unwrap();
        drop(g);
        // Counter must be 0, not u32::MAX (underflow guard).
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
            let (_, result) = enc.switch_to(game_config(), ContentMode::Game);
            result.unwrap();
            assert_eq!(
                lim.active_sessions(),
                1,
                "after each switch exactly 1 session must be active"
            );
        }
    }

    // ── Glitch-free swap: first packet is IDR ─────────────────────────────────

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
        let (tail_pkts, result) = enc.switch_to(game_config(), ContentMode::Game);
        result.unwrap();

        // The old encoder's tail must have been drained (RawEncoder has no internal buffer,
        // so tail_pkts is empty — but the flush call must have been made).
        eprintln!(
            "[test] switch produced {} tail packets from old encoder",
            tail_pkts.len()
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

        let (tail, result) = enc.switch_to(game_config(), ContentMode::Game);
        assert!(
            matches!(result, Err(ModeSwitchError::NoSessionAvailable { .. })),
            "switch must fail when max_sessions=1"
        );
        assert!(tail.is_empty(), "no tail packets when switch failed");

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

        let (_, result) = enc.switch_to(game_config(), ContentMode::Game);
        result.unwrap();

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
        let call_count = Arc::new(AtomicU32::new(0));
        let call_count_clone = Arc::clone(&call_count);
        let mixed_factory: EncoderFactory = Box::new(move |_| {
            let n = call_count_clone.fetch_add(1, Ordering::SeqCst);
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
        let (tail, result) = enc.switch_to(game_config(), ContentMode::Game);
        assert!(
            matches!(result, Err(ModeSwitchError::FactoryError(_))),
            "switch must fail on factory error"
        );
        assert!(tail.is_empty());

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
    fn switch_trace_printed_to_stderr() {
        // This test primarily exercises the full swap path so the "swap trace" prints to stderr
        // during `cargo test -p sh-codec-hw -- --nocapture`.
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
        let (tail, result) = enc.switch_to(game_config(), ContentMode::Game);
        result.unwrap();
        eprintln!("old encoder drained: {} tail packet(s)", tail.len());
        eprintln!("new session active (sessions={})", lim.active_sessions());

        let first_new = enc.encode(&make_frame(3)).unwrap().unwrap();
        eprintln!(
            "first new-encoder packet: frame_type={:?} (must be IDR)",
            first_new.frame_type
        );
        eprintln!("=== Swap trace end ===\n");

        assert_eq!(first_new.frame_type, FrameType::Idr);
        assert_eq!(lim.active_sessions(), 1);
    }
}
