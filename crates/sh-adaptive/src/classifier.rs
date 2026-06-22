//! Content classifier (LLD §5.2): 4-signal heuristic + hysteresis FSM for Game/Work/Scrolling.
//!
//! ## Overview
//!
//! The classifier converts four cheap, sub-millisecond signals sampled every 4 frames into a
//! [`ContentMode`] that downstream components (P2-4 encoder reconfigure) use to pick encode
//! parameters and frame-rate targets.
//!
//! ```text
//! Signals ──► ScoreProvider::score() ──► f64 in [0,1] ──► FSM ──► ContentMode
//! ```
//!
//! ## Tick cadence contract
//!
//! The caller must call [`ContentClassifier::on_tick`] **once per classification tick**. The
//! authoritative cadence is **every 4 frames** — so at 60 fps the tick rate is 15 Hz, at 30 fps
//! it is 7.5 Hz. The FSM counts ticks, not wall-clock time. Do **not** call `on_tick` from a
//! timer; drive it from the frame pipeline so that all dwell counters are in units of 4-frame
//! groups rather than real time.
//!
//! ## Swappable score provider
//!
//! The FSM is fully decoupled from the scoring function via the [`ScoreProvider`] trait. The v1
//! heuristic ([`HeuristicScoreProvider`]) computes a weighted sum of the four signals. v2 will
//! swap in an ONNX-backed `MobileNetV3` provider without changing any FSM code.
//!
//! ## Mode semantics
//!
//! | Mode | Encode params | Frame rate |
//! |------|--------------|-----------|
//! | [`ContentMode::Work`] | `4:2:0`, lower QP, keyframe-on-damage | Work rate (up to 30 fps) |
//! | [`ContentMode::Scrolling`] | Game params (`4:2:0` fast, intra-refresh) | Work rate (≤30 fps) |
//! | [`ContentMode::Game`] | `4:2:0` CBR, max perf, intra-refresh | Full rate (60+ fps) |
//!
//! `Scrolling` is a hybrid: it uses Game-quality encode parameters (preventing compression
//! artefacts during fast document scrolls) but targets the Work-mode frame rate (since the content
//! isn't full-motion video). P2-4 reads the mode and configures the encoder accordingly.
//!
//! ## Hysteresis design rationale
//!
//! All mode transitions require the triggering condition to hold for a minimum **dwell period**
//! (measured in ticks) before the transition fires. This eliminates flapping caused by a brief
//! score excursion crossing a threshold. The dwell periods are intentionally asymmetric:
//!
//! - **Game entry** is fast (8 ticks ≈ 530 ms @60 fps) to react promptly to game launches.
//! - **Game exit** is slow (30 ticks ≈ 2 s @60 fps) so that alt-tab windows and brief menu
//!   overlays do not trigger a Work re-encode, which would cause a visible glitch.
//!
//! See [`GAME_ENTER_DWELL`], [`GAME_EXIT_DWELL`], [`SCROLL_ENTER_DWELL`],
//! [`SCROLL_EXIT_DWELL`], [`SCROLL_ENTER_THRESHOLD`], and [`SCROLL_EXIT_THRESHOLD`] for the
//! named constants and their rationale.

use std::fmt;

// ── Score weights (LLD §5.2) ──────────────────────────────────────────────────

/// Weight for signal A: inter-frame macroblock diff on ¼-res luma.
///
/// Highest weight because motion detection is the most reliable discriminator between static
/// Work content (near-zero diff) and fast Game/video content (high diff).
pub const WEIGHT_A: f64 = 0.45;

/// Weight for signal B: OS dirty-rect coverage.
///
/// Strong secondary signal. The OS damage region is cheap (one system call) and correlates
/// tightly with content motion — games dirty nearly the whole screen every frame.
pub const WEIGHT_B: f64 = 0.30;

/// Weight for signal C: foreground-app class scalar.
///
/// Moderate weight. The app class (GAME/MEDIA/WORK) provides explicit intent when available,
/// e.g. a game that runs at low frame rate for a loading screen still warrants Game-mode params.
pub const WEIGHT_C: f64 = 0.15;

/// Weight for signal D: cursor velocity normalized to 2000 px/s.
///
/// Smallest weight. Cursor velocity is a weak signal on its own (e.g. moving the mouse fast
/// across a static desktop), but it helps disambiguate Scrolling from pure Work.
pub const WEIGHT_D: f64 = 0.10;

// ── Hysteresis thresholds and dwell periods ───────────────────────────────────

/// Score threshold above which the FSM *considers* entering Game mode.
///
/// When `score > GAME_ENTER_THRESHOLD` is sustained for [`GAME_ENTER_DWELL`] consecutive ticks,
/// the FSM transitions to Game mode.
pub const GAME_ENTER_THRESHOLD: f64 = 0.65;

/// Score threshold below which the FSM *considers* leaving Game mode.
///
/// When `score < GAME_EXIT_THRESHOLD` is sustained for [`GAME_EXIT_DWELL`] consecutive ticks,
/// the FSM leaves Game mode. The exit threshold is intentionally lower than the entry threshold
/// (0.40 < 0.65), creating a hysteresis band in [0.40, 0.65] where the mode is stable.
pub const GAME_EXIT_THRESHOLD: f64 = 0.40;

/// Dwell period (ticks) required before entering Game mode.
///
/// 8 ticks ≈ 530 ms @60 fps. Fast enough to react to a game launch within a few frames.
pub const GAME_ENTER_DWELL: u32 = 8;

/// Dwell period (ticks) required before exiting Game mode.
///
/// 30 ticks ≈ 2 s @60 fps. Deliberately slow so that brief alt-tab windows, loading screens,
/// or menu overlays that temporarily drop the score below [`GAME_EXIT_THRESHOLD`] do not
/// trigger a full Work re-encode (which would restart the encoder session and cause a visible
/// glitch). The brief score dip must be sustained for the entire 30-tick window before any
/// transition fires.
pub const GAME_EXIT_DWELL: u32 = 30;

/// Score threshold above which the FSM *considers* entering Scrolling mode from Work.
///
/// Scrolling is the mid-band state: score in [`SCROLL_ENTER_THRESHOLD`, `GAME_ENTER_THRESHOLD`]
/// indicates significant motion (dirty rect or cursor) without the sustained high score of a
/// game. Typical trigger: fast document scroll, web-page pan, or animation in a Work app.
///
/// Value 0.35 is deliberately below [`GAME_ENTER_THRESHOLD`] (0.65) and above pure Work noise
/// (< 0.30) so that the Scrolling region captures the mid-band without colliding with the Game
/// band.
pub const SCROLL_ENTER_THRESHOLD: f64 = 0.35;

/// Score threshold below which the FSM *considers* leaving Scrolling mode back to Work.
///
/// Lower than [`SCROLL_ENTER_THRESHOLD`] by 0.10 to create a hysteresis band [0.25, 0.35]
/// that prevents flapping when a scroll deceleration oscillates around the entry threshold.
pub const SCROLL_EXIT_THRESHOLD: f64 = 0.25;

/// Dwell period (ticks) required before entering Scrolling mode.
///
/// 4 ticks ≈ 267 ms @60 fps. Slightly less than Game entry (8 ticks) because the cost of a
/// false positive (briefly entering Scrolling on a Work machine) is low — Scrolling uses the
/// same encoder params as Game, just at a lower frame rate. React quickly to scroll gestures.
pub const SCROLL_ENTER_DWELL: u32 = 4;

/// Dwell period (ticks) required before leaving Scrolling mode back to Work.
///
/// 10 ticks ≈ 667 ms @60 fps. Long enough that the score must be consistently below
/// [`SCROLL_EXIT_THRESHOLD`] for most of a second before committing to Work mode, preventing
/// flapping when the user pauses mid-scroll.
pub const SCROLL_EXIT_DWELL: u32 = 10;

// ── AppClass ──────────────────────────────────────────────────────────────────

/// The OS-reported foreground application class.
///
/// Maps to signal C: `GAME → 1.0`, `Media → 0.5`, `Work → 0.0`. When the host reports
/// fullscreen-exclusive mode (DirectX exclusive-fullscreen, SCK kiosk) the class is overridden
/// to [`AppClass::Game`] regardless of the app's registered type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppClass {
    /// Standard desktop/office application. C = 0.0.
    Work,
    /// Media player or browser with video. C = 0.5.
    Media,
    /// Game or fullscreen-exclusive application. C = 1.0.
    Game,
}

impl AppClass {
    /// Convert the app class to the normalized signal C scalar in \[0, 1\].
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_adaptive::classifier::AppClass;
    /// assert_eq!(AppClass::Work.to_signal_c(), 0.0);
    /// assert_eq!(AppClass::Media.to_signal_c(), 0.5);
    /// assert_eq!(AppClass::Game.to_signal_c(), 1.0);
    /// ```
    #[must_use]
    pub fn to_signal_c(self) -> f64 {
        match self {
            AppClass::Work => 0.0,
            AppClass::Media => 0.5,
            AppClass::Game => 1.0,
        }
    }
}

// ── Signals ───────────────────────────────────────────────────────────────────

/// Maximum cursor velocity (px/s) used to normalize signal D.
///
/// Cursor velocities at or above this value saturate signal D to 1.0.
pub const CURSOR_VELOCITY_MAX_PX_S: f64 = 2000.0;

/// The four normalized input signals consumed by [`ScoreProvider::score`].
///
/// Each field is clamped to \[0, 1\] at construction time. Use [`Signals::new`] or the
/// convenience constructor [`Signals::from_raw`] which normalizes raw inputs (fractional values,
/// cursor px/s, app-class enum, fullscreen flag) so callers never hand-normalize incorrectly.
///
/// # Signal definitions (LLD §5.2)
///
/// | Field | Definition |
/// |-------|-----------|
/// | `a`   | Inter-frame macroblock diff on ¼-res luma: fraction of 8×8 blocks with MAD > 12 |
/// | `b`   | OS dirty-rect coverage: fraction of screen area marked damaged |
/// | `c`   | Foreground-app class scalar: `GAME→1.0`, `MEDIA→0.5`, `WORK→0.0`; fullscreen-exclusive ⇒ 1.0 |
/// | `d`   | Cursor velocity normalized to 2000 px/s, clamped to 1.0 |
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Signals {
    /// Signal A: inter-frame macroblock diff on ¼-res luma (fraction of 8×8 blocks with MAD>12).
    /// Clamped to \[0, 1\].
    pub a: f64,
    /// Signal B: OS dirty-rect coverage (fraction of screen area). Clamped to \[0, 1\].
    pub b: f64,
    /// Signal C: foreground-app class scalar. Clamped to \[0, 1\].
    pub c: f64,
    /// Signal D: cursor velocity normalized to 2000 px/s, clamped to 1.0. Clamped to \[0, 1\].
    pub d: f64,
}

impl Signals {
    /// Clamp a single signal value to \[0, 1\], treating NaN as 0.0.
    fn clamp_signal(v: f64) -> f64 {
        if v.is_nan() {
            0.0
        } else {
            v.clamp(0.0, 1.0)
        }
    }

    /// Construct `Signals` from four pre-normalized values, clamping each to \[0, 1\].
    ///
    /// Use this constructor when the caller has already computed fractional values in \[0, 1\].
    /// For raw OS inputs (cursor px/s, app-class enum, fullscreen flag) use [`Signals::from_raw`].
    ///
    /// NaN inputs are treated as 0.0. Values outside \[0, 1\] are silently clamped.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_adaptive::classifier::Signals;
    /// // Values outside [0,1] are silently clamped — never panic.
    /// let s = Signals::new(1.5, -0.2, 0.5, 0.8);
    /// assert_eq!(s.a, 1.0);
    /// assert_eq!(s.b, 0.0);
    /// // NaN is treated as 0.0.
    /// let s2 = Signals::new(f64::NAN, 0.5, 0.0, 0.0);
    /// assert_eq!(s2.a, 0.0);
    /// ```
    #[must_use]
    pub fn new(a: f64, b: f64, c: f64, d: f64) -> Self {
        Self {
            a: Self::clamp_signal(a),
            b: Self::clamp_signal(b),
            c: Self::clamp_signal(c),
            d: Self::clamp_signal(d),
        }
    }

    /// Construct `Signals` from raw OS inputs, performing all normalization internally.
    ///
    /// This is the preferred constructor for production callers — pass the values as the OS
    /// reports them and the function handles normalization, so there is no risk of the caller
    /// forgetting to divide cursor velocity by 2000 or mixing up the fullscreen override.
    ///
    /// # Parameters
    ///
    /// - `mb_diff_fraction`: fraction of 8×8 blocks on the ¼-res luma plane with MAD > 12 —
    ///   already a fraction in \[0, 1\]. Clamped if out of range.
    /// - `dirty_rect_fraction`: fraction of screen area covered by OS damage rects — already a
    ///   fraction in \[0, 1\]. Clamped if out of range.
    /// - `app_class`: OS-reported foreground application class.
    /// - `fullscreen_exclusive`: `true` when the host reports fullscreen-exclusive mode (DXGI
    ///   exclusive-fullscreen, SCK kiosk). Overrides `app_class` to produce C = 1.0.
    /// - `cursor_velocity_px_s`: raw cursor velocity in pixels per second. Normalized to
    ///   \[0, 1\] by dividing by [`CURSOR_VELOCITY_MAX_PX_S`] (2000 px/s), then clamped to 1.0.
    ///   Negative values are treated as zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_adaptive::classifier::{Signals, AppClass};
    ///
    /// // Fullscreen exclusive overrides app class to Game (C=1.0).
    /// let s = Signals::from_raw(0.8, 0.9, AppClass::Work, true, 3000.0);
    /// assert_eq!(s.c, 1.0);
    /// assert_eq!(s.d, 1.0); // 3000 px/s clamped to 1.0
    ///
    /// // Normal Work session: low motion, low dirty rect, Work class, cursor at rest.
    /// let s = Signals::from_raw(0.02, 0.05, AppClass::Work, false, 100.0);
    /// assert!(s.c == 0.0);
    /// ```
    #[must_use]
    pub fn from_raw(
        mb_diff_fraction: f64,
        dirty_rect_fraction: f64,
        app_class: AppClass,
        fullscreen_exclusive: bool,
        cursor_velocity_px_s: f64,
    ) -> Self {
        let c = if fullscreen_exclusive {
            1.0
        } else {
            app_class.to_signal_c()
        };
        // Normalize cursor velocity: divide by max, clamp negative values to 0, cap at 1.0.
        // Use clamp_signal to guard against NaN cursor readings from platform APIs.
        let d = Self::clamp_signal(cursor_velocity_px_s / CURSOR_VELOCITY_MAX_PX_S);
        Self::new(mb_diff_fraction, dirty_rect_fraction, c, d)
    }
}

impl fmt::Display for Signals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signals(A={:.3} B={:.3} C={:.3} D={:.3})",
            self.a, self.b, self.c, self.d
        )
    }
}

// ── Score newtype ─────────────────────────────────────────────────────────────

/// A score value in \[0, 1\] produced by a [`ScoreProvider`].
///
/// The inner `f64` is clamped to \[0, 1\] on construction. NaN inputs are treated as 0.0.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Score(f64);

impl Score {
    /// Construct a `Score`, clamping the value to \[0, 1\]. NaN → 0.0.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_adaptive::classifier::Score;
    /// assert_eq!(Score::new(1.5).as_f64(), 1.0);
    /// assert_eq!(Score::new(-0.1).as_f64(), 0.0);
    /// assert_eq!(Score::new(f64::NAN).as_f64(), 0.0);
    /// ```
    #[must_use]
    pub fn new(v: f64) -> Self {
        // f64::clamp propagates NaN in Rust; handle it explicitly.
        if v.is_nan() {
            Self(0.0)
        } else {
            Self(v.clamp(0.0, 1.0))
        }
    }

    /// Return the inner value in \[0, 1\].
    #[must_use]
    pub fn as_f64(self) -> f64 {
        self.0
    }
}

impl fmt::Display for Score {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.4}", self.0)
    }
}

// ── ScoreProvider trait ───────────────────────────────────────────────────────

/// Maps four normalized signals to a classification score in \[0, 1\].
///
/// v1 uses [`HeuristicScoreProvider`] (weighted sum). v2 will swap in an ONNX-backed
/// `MobileNetV3` implementation without touching the [`ContentClassifier`] FSM.
///
/// # Object safety
///
/// This trait is object-safe and can be stored as `Box<dyn ScoreProvider>`. Implementations
/// must be `Send` so the classifier can cross `.await` points in tokio tasks.
///
/// # Contract
///
/// - `score` must return a value clamped to \[0, 1\]. Wrapping in [`Score::new`] is recommended.
/// - `score` must be pure (no side effects, no I/O, no allocation in the hot path).
/// - `score` must not panic for any `Signals` input (all fields are already clamped to \[0, 1\]).
pub trait ScoreProvider: Send + Sync {
    /// Compute the classification score for the given signals.
    ///
    /// The returned [`Score`] is in \[0, 1\]. Higher values indicate more game-like content.
    ///
    /// # Panics
    ///
    /// Implementations must not panic for any input. All [`Signals`] fields are already clamped
    /// to `[0.0, 1.0]` before this method is called; implementations are responsible for
    /// defending against any NaN produced internally (e.g. by an ONNX inference runtime).
    fn score(&self, signals: &Signals) -> Score;
}

// ── HeuristicScoreProvider ────────────────────────────────────────────────────

/// Heuristic v1 score provider: weighted sum `0.45·A + 0.30·B + 0.15·C + 0.10·D`.
///
/// Weights are defined as named constants ([`WEIGHT_A`], [`WEIGHT_B`], [`WEIGHT_C`],
/// [`WEIGHT_D`]) for documentation and testability.
///
/// Because all signal values are in \[0, 1\] and the weights sum to 1.0, the result is always in
/// \[0, 1\] assuming no floating-point pathology. [`Score::new`] clamps the result defensively.
///
/// # Examples
///
/// ```
/// use sh_adaptive::classifier::{HeuristicScoreProvider, Signals, ScoreProvider};
///
/// let provider = HeuristicScoreProvider;
/// let signals = Signals::new(1.0, 1.0, 1.0, 1.0);
/// assert_eq!(provider.score(&signals).as_f64(), 1.0);
///
/// let signals = Signals::new(0.0, 0.0, 0.0, 0.0);
/// assert_eq!(provider.score(&signals).as_f64(), 0.0);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct HeuristicScoreProvider;

impl ScoreProvider for HeuristicScoreProvider {
    fn score(&self, s: &Signals) -> Score {
        Score::new(WEIGHT_A * s.a + WEIGHT_B * s.b + WEIGHT_C * s.c + WEIGHT_D * s.d)
    }
}

// ── ContentMode ───────────────────────────────────────────────────────────────

/// The content-classification output consumed by the downstream encoder reconfiguration (P2-4).
///
/// | Mode | Encoder config | Frame rate |
/// |------|---------------|-----------|
/// | `Work` | Conservative `4:2:0`, lower bitrate, damage-triggered keyframes | ≤30 fps |
/// | `Scrolling` | Game-like fast encode params, intra-refresh | ≤30 fps |
/// | `Game` | `4:2:0` CBR, maximum throughput, intra-refresh, no damage trigger | 60+ fps |
///
/// P2-4 reads this mode after each tick and configures the encoder pipeline accordingly. A mode
/// change triggers a double-buffered encoder switch (prime new encoder → atomic swap → drain old)
/// as described in LLD §5.4, avoiding mid-session `4:2:0 ↔ 4:4:4` reconfigure glitches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentMode {
    /// Standard desktop / office application content.
    ///
    /// Use conservative encode parameters optimized for static or low-motion content:
    /// quality-biased `4:2:0`, damage-region keyframes, lower frame rate (≤30 fps).
    Work,
    /// Fast-scrolling or transient-motion content: document pan, web-page scroll, animation.
    ///
    /// Use Game-quality encode parameters (fast `4:2:0`, intra-refresh) to avoid compression
    /// artefacts during rapid motion, but target the Work frame rate (≤30 fps) because the
    /// content is not full-motion video.
    Scrolling,
    /// Full-motion game or fullscreen media content.
    ///
    /// Use maximum-performance encode parameters: CBR, `4:2:0`, intra-refresh, highest frame
    /// rate (60+ fps). Encoder remains live continuously rather than waiting for OS damage events.
    Game,
}

impl fmt::Display for ContentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentMode::Work => f.write_str("Work"),
            ContentMode::Scrolling => f.write_str("Scrolling"),
            ContentMode::Game => f.write_str("Game"),
        }
    }
}

// ── FSM state ─────────────────────────────────────────────────────────────────

/// Internal FSM state tracking which dwell counter is active.
///
/// Each variant embeds its in-progress dwell counter(s) directly. A counter of zero means "no
/// pressure in that direction yet". Because the FSM transitions are driven solely by the incoming
/// score and the current counter values, the struct is `Copy` and requires no heap allocation.
///
/// # Variant roles
///
/// - `Work { scroll_counter }`: settled in Work; `scroll_counter` counts consecutive ticks with
///   `score > SCROLL_ENTER_THRESHOLD` (toward Scrolling), reset on any tick below that.
/// - `WorkToGame { counter }`: in Work but counting consecutive high-score ticks toward Game.
///   The mode presented externally is still Work until the counter reaches `GAME_ENTER_DWELL`.
/// - `Scrolling { game_counter, exit_counter }`: settled in Scrolling; `game_counter` counts
///   toward Game, `exit_counter` toward Work. Only one can be nonzero at a time.
/// - `Game { exit_counter }`: settled in Game; `exit_counter` counts consecutive low-score ticks
///   toward Work exit. Reset to zero on any tick at or above `GAME_EXIT_THRESHOLD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FsmState {
    /// Settled in Work mode.
    ///
    /// `scroll_counter` counts consecutive ticks with `score > SCROLL_ENTER_THRESHOLD`; resets
    /// to 0 when the score drops back into the Work band.
    Work { scroll_counter: u32 },
    /// In Work mode but counting consecutive high-score ticks toward Game entry.
    ///
    /// Presented externally as [`ContentMode::Work`] until `counter` reaches `GAME_ENTER_DWELL`.
    WorkToGame { counter: u32 },
    /// Settled in Scrolling mode.
    ///
    /// `game_counter` counts ticks with `score > GAME_ENTER_THRESHOLD` (toward Game).
    /// `exit_counter` counts ticks with `score < SCROLL_EXIT_THRESHOLD` (toward Work).
    /// Both reset to 0 when pressure reverses direction.
    Scrolling {
        game_counter: u32,
        exit_counter: u32,
    },
    /// Settled in Game mode.
    ///
    /// `exit_counter` counts consecutive ticks with `score < GAME_EXIT_THRESHOLD` (toward Work).
    /// Resets to 0 on any tick at or above `GAME_EXIT_THRESHOLD`.
    Game { exit_counter: u32 },
}

impl FsmState {
    /// The [`ContentMode`] that this FSM state presents to the outside world.
    fn mode(self) -> ContentMode {
        match self {
            FsmState::Work { .. } | FsmState::WorkToGame { .. } => ContentMode::Work,
            FsmState::Scrolling { .. } => ContentMode::Scrolling,
            FsmState::Game { .. } => ContentMode::Game,
        }
    }
}

// ── ContentClassifier ─────────────────────────────────────────────────────────

/// Hysteresis FSM that maps a stream of classification scores to a stable [`ContentMode`].
///
/// ## Construction
///
/// ```rust
/// use sh_adaptive::classifier::{ContentClassifier, HeuristicScoreProvider};
///
/// let classifier = ContentClassifier::new(Box::new(HeuristicScoreProvider));
/// ```
///
/// ## Usage
///
/// Call [`on_tick`] once per classification tick (every 4 frames). The method advances the FSM
/// and returns the current [`ContentMode`].
///
/// ```rust
/// # use sh_adaptive::classifier::{ContentClassifier, HeuristicScoreProvider, Signals, AppClass};
/// let mut classifier = ContentClassifier::new(Box::new(HeuristicScoreProvider));
/// let signals = Signals::from_raw(0.9, 0.9, AppClass::Game, false, 500.0);
/// let mode = classifier.on_tick(&signals);
/// // mode is Work until the Game entry dwell completes (8 ticks).
/// # let _ = mode;
/// ```
///
/// ## Determinism
///
/// `ContentClassifier` holds no wall-clock state. All dwell counters are in units of ticks.
/// The sequence of `on_tick` calls completely determines the output sequence, making testing
/// fully deterministic without injecting any clock.
///
/// ## Anti-flap guarantees
///
/// Between any two `Game ↔ Work` transitions there are at least `min(GAME_ENTER_DWELL,
/// GAME_EXIT_DWELL)` = 8 ticks. The Scrolling intermediate follows the same rule with its own
/// dwell constants. Score oscillation within a hysteresis band (e.g. bouncing around 0.65) does
/// **not** produce transitions.
///
/// [`on_tick`]: ContentClassifier::on_tick
pub struct ContentClassifier {
    provider: Box<dyn ScoreProvider>,
    state: FsmState,
}

impl ContentClassifier {
    /// Construct a new classifier starting in [`ContentMode::Work`].
    ///
    /// `provider` is the score function. Pass `Box::new(HeuristicScoreProvider)` for the v1
    /// heuristic; swap in an ONNX provider for v2 without changing any FSM code.
    #[must_use]
    pub fn new(provider: Box<dyn ScoreProvider>) -> Self {
        Self {
            provider,
            state: FsmState::Work { scroll_counter: 0 },
        }
    }

    /// Advance the FSM by one classification tick and return the current [`ContentMode`].
    ///
    /// The caller must invoke this method **once per classification tick** (every 4 frames).
    /// The FSM never calls wall-clock functions; all timing is tick-based.
    ///
    /// # Algorithm
    ///
    /// 1. Compute `score = provider.score(signals)`.
    /// 2. Advance the active dwell counter(s) based on whether `score` is above/below the
    ///    relevant threshold.
    /// 3. When a dwell counter reaches its configured limit, fire the transition.
    /// 4. Return the mode corresponding to the (possibly updated) FSM state.
    ///
    /// The returned mode reflects the state *after* processing this tick, so a caller that
    /// collects 8 consecutive ticks with score > 0.65 will see `Game` on the 8th call.
    pub fn on_tick(&mut self, signals: &Signals) -> ContentMode {
        let score = self.provider.score(signals).as_f64();
        self.state = Self::advance(self.state, score);
        self.state.mode()
    }

    /// Return the current [`ContentMode`] without advancing the FSM.
    #[must_use]
    pub fn current_mode(&self) -> ContentMode {
        self.state.mode()
    }

    /// Pure FSM transition function: given the current state and the new score, return the next
    /// state.
    ///
    /// Keeping this as a separate pure function makes the logic easy to unit-test in isolation
    /// without constructing a full `ContentClassifier`.
    fn advance(state: FsmState, score: f64) -> FsmState {
        match state {
            // ── Settled in Work ───────────────────────────────────────────────
            FsmState::Work { scroll_counter } => {
                if score > GAME_ENTER_THRESHOLD {
                    // Begin counting toward Work→Game directly (skip Scrolling; the score is
                    // already in the Game band).
                    FsmState::WorkToGame { counter: 1 }
                } else if score > SCROLL_ENTER_THRESHOLD {
                    let next = scroll_counter.saturating_add(1);
                    if next >= SCROLL_ENTER_DWELL {
                        FsmState::Scrolling {
                            game_counter: 0,
                            exit_counter: 0,
                        }
                    } else {
                        FsmState::Work {
                            scroll_counter: next,
                        }
                    }
                } else {
                    // Score in Work band — reset the Scrolling entry counter.
                    FsmState::Work { scroll_counter: 0 }
                }
            }

            // ── Counting Work→Game dwell ──────────────────────────────────────
            FsmState::WorkToGame { counter } => {
                if score > GAME_ENTER_THRESHOLD {
                    let next = counter.saturating_add(1);
                    if next >= GAME_ENTER_DWELL {
                        // Transition fires: enter Game.
                        FsmState::Game { exit_counter: 0 }
                    } else {
                        FsmState::WorkToGame { counter: next }
                    }
                } else {
                    // Score dropped out of Game band — fall back to the appropriate state.
                    if score > SCROLL_ENTER_THRESHOLD {
                        // Score is in the Scrolling band; start counting toward Scrolling.
                        FsmState::Work { scroll_counter: 1 }
                    } else {
                        FsmState::Work { scroll_counter: 0 }
                    }
                }
            }

            // ── Settled in Scrolling ──────────────────────────────────────────
            FsmState::Scrolling {
                game_counter,
                exit_counter,
            } => {
                // Invariant: at most one of (game_counter, exit_counter) is nonzero.
                // Each branch that increments one counter explicitly zeroes the other.
                debug_assert!(
                    game_counter == 0 || exit_counter == 0,
                    "Scrolling FSM invariant violated: both counters nonzero ({game_counter}, {exit_counter})"
                );
                if score > GAME_ENTER_THRESHOLD {
                    // Begin counting toward Scrolling→Game.
                    let next_gc = game_counter.saturating_add(1);
                    if next_gc >= GAME_ENTER_DWELL {
                        FsmState::Game { exit_counter: 0 }
                    } else {
                        FsmState::Scrolling {
                            game_counter: next_gc,
                            exit_counter: 0, // reset exit counter on upward pressure
                        }
                    }
                } else if score < SCROLL_EXIT_THRESHOLD {
                    // Begin counting toward Scrolling→Work.
                    let next_ec = exit_counter.saturating_add(1);
                    if next_ec >= SCROLL_EXIT_DWELL {
                        FsmState::Work { scroll_counter: 0 }
                    } else {
                        FsmState::Scrolling {
                            game_counter: 0, // reset game counter on downward pressure
                            exit_counter: next_ec,
                        }
                    }
                } else {
                    // Score in Scrolling stable band [SCROLL_EXIT_THRESHOLD, GAME_ENTER_THRESHOLD].
                    // Reset both counters to zero: dwell requires *consecutive* ticks; a single
                    // stable-band tick resets any in-progress game or exit counter so that the
                    // next run of pressure must be unbroken to fire.
                    FsmState::Scrolling {
                        game_counter: 0,
                        exit_counter: 0,
                    }
                }
            }

            // ── Settled in Game ───────────────────────────────────────────────
            FsmState::Game { exit_counter } => {
                if score < GAME_EXIT_THRESHOLD {
                    let next = exit_counter.saturating_add(1);
                    if next >= GAME_EXIT_DWELL {
                        // Exit Game; land in Work (not Scrolling) because the score has been
                        // consistently low for 30 ticks — this is a genuine mode change, not a
                        // transient scroll. If the score immediately bounces into the Scroll band
                        // the FSM will enter Scrolling on the very next tick.
                        FsmState::Work { scroll_counter: 0 }
                    } else {
                        FsmState::Game { exit_counter: next }
                    }
                } else {
                    // Score at or above exit threshold — reset the exit counter.
                    FsmState::Game { exit_counter: 0 }
                }
            }
        }
    }
}

impl fmt::Debug for ContentClassifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentClassifier")
            .field("state", &self.state)
            .finish()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── Helper constructors ───────────────────────────────────────────────────

    fn heuristic() -> ContentClassifier {
        ContentClassifier::new(Box::new(HeuristicScoreProvider))
    }

    /// Synthesize `Signals` that the `HeuristicScoreProvider` maps to approximately `target`.
    ///
    /// Uses a greedy A→B→C→D fill. Due to floating-point rounding the reconstructed score may
    /// differ from `target` by a tiny amount (~1e-16). Do NOT use this helper with values that
    /// exactly equal a threshold (0.65, 0.40, 0.35, 0.25) — use a `FixedScoreProvider` or
    /// hand-crafted `Signals` for boundary-condition tests.
    fn make_signals_for_score(target: f64) -> Signals {
        // A alone can cover up to 0.45. Use A=1.0 and B to cover the rest up to 0.75.
        // B alone can cover 0.30 more. C alone 0.15, D 0.10.
        // Strategy: fill greedily A→B→C→D.
        let a = (target / WEIGHT_A).min(1.0);
        let remaining = target - WEIGHT_A * a;
        let b = (remaining / WEIGHT_B).clamp(0.0, 1.0);
        let remaining2 = remaining - WEIGHT_B * b;
        let c = (remaining2 / WEIGHT_C).clamp(0.0, 1.0);
        let remaining3 = remaining2 - WEIGHT_C * c;
        let d = (remaining3 / WEIGHT_D).clamp(0.0, 1.0);
        Signals::new(a, b, c, d)
    }

    /// A trivial `ScoreProvider` that always returns the same fixed score, used to pin boundary
    /// conditions at exact threshold values that floating-point arithmetic cannot reach reliably
    /// via `make_signals_for_score`.
    struct FixedScoreProvider(f64);
    impl ScoreProvider for FixedScoreProvider {
        fn score(&self, _signals: &Signals) -> Score {
            Score::new(self.0)
        }
    }

    fn fixed_clf(score: f64) -> ContentClassifier {
        ContentClassifier::new(Box::new(FixedScoreProvider(score)))
    }

    fn run_ticks(clf: &mut ContentClassifier, signals: &Signals, n: u32) -> ContentMode {
        let mut mode = ContentMode::Work;
        for _ in 0..n {
            mode = clf.on_tick(signals);
        }
        mode
    }

    // ── Score math ────────────────────────────────────────────────────────────

    #[test]
    fn weighted_sum_all_ones() {
        let p = HeuristicScoreProvider;
        let s = Signals::new(1.0, 1.0, 1.0, 1.0);
        let score = p.score(&s);
        assert!(
            (score.as_f64() - 1.0).abs() < 1e-9,
            "all-ones score should be 1.0, got {}",
            score
        );
    }

    #[test]
    fn weighted_sum_all_zeros() {
        let p = HeuristicScoreProvider;
        let s = Signals::new(0.0, 0.0, 0.0, 0.0);
        assert_eq!(p.score(&s).as_f64(), 0.0);
    }

    #[test]
    fn weighted_sum_known_value() {
        let p = HeuristicScoreProvider;
        // A=0.8, B=0.6, C=0.4, D=0.2
        // score = 0.45*0.8 + 0.30*0.6 + 0.15*0.4 + 0.10*0.2
        //       = 0.36 + 0.18 + 0.06 + 0.02 = 0.62
        let s = Signals::new(0.8, 0.6, 0.4, 0.2);
        let score = p.score(&s);
        assert!(
            (score.as_f64() - 0.62).abs() < 1e-9,
            "expected 0.62 got {}",
            score
        );
    }

    #[test]
    fn signals_clamp_out_of_range() {
        let s = Signals::new(2.0, -1.0, 1.5, -0.5);
        assert_eq!(s.a, 1.0);
        assert_eq!(s.b, 0.0);
        assert_eq!(s.c, 1.0);
        assert_eq!(s.d, 0.0);
    }

    #[test]
    fn signals_clamping_does_not_panic_on_nan() {
        // NaN inputs are defined to produce 0.0 (not panic, not produce NaN).
        let s = Signals::new(f64::NAN, f64::NAN, f64::NAN, f64::NAN);
        assert_eq!(s.a, 0.0, "NaN signal A should become 0.0");
        assert_eq!(s.b, 0.0, "NaN signal B should become 0.0");
        assert_eq!(s.c, 0.0, "NaN signal C should become 0.0");
        assert_eq!(s.d, 0.0, "NaN signal D should become 0.0");
    }

    #[test]
    fn fullscreen_exclusive_overrides_app_class() {
        // Even with AppClass::Work, fullscreen_exclusive forces C = 1.0.
        let s = Signals::from_raw(0.0, 0.0, AppClass::Work, true, 0.0);
        assert_eq!(s.c, 1.0, "fullscreen exclusive must set C=1.0");
    }

    #[test]
    fn app_class_scalars() {
        assert_eq!(AppClass::Work.to_signal_c(), 0.0);
        assert_eq!(AppClass::Media.to_signal_c(), 0.5);
        assert_eq!(AppClass::Game.to_signal_c(), 1.0);
    }

    #[test]
    fn cursor_velocity_normalization() {
        // 2000 px/s → 1.0; 1000 px/s → 0.5; 4000 px/s → 1.0 (clamped).
        let s2000 = Signals::from_raw(0.0, 0.0, AppClass::Work, false, 2000.0);
        assert!((s2000.d - 1.0).abs() < 1e-9, "2000 px/s should give D=1.0");

        let s1000 = Signals::from_raw(0.0, 0.0, AppClass::Work, false, 1000.0);
        assert!((s1000.d - 0.5).abs() < 1e-9, "1000 px/s should give D=0.5");

        let s4000 = Signals::from_raw(0.0, 0.0, AppClass::Work, false, 4000.0);
        assert_eq!(s4000.d, 1.0, "4000 px/s should be clamped to D=1.0");

        // Negative velocity → clamped to 0.
        let s_neg = Signals::from_raw(0.0, 0.0, AppClass::Work, false, -100.0);
        assert_eq!(s_neg.d, 0.0, "negative velocity should give D=0.0");
    }

    #[test]
    fn score_newtype_clamps_nan() {
        let s = Score::new(f64::NAN);
        assert_eq!(s.as_f64(), 0.0);
    }

    #[test]
    fn score_newtype_clamps_out_of_range() {
        assert_eq!(Score::new(2.0).as_f64(), 1.0);
        assert_eq!(Score::new(-1.0).as_f64(), 0.0);
    }

    // ── Game enter dwell ──────────────────────────────────────────────────────

    /// 7 ticks above the Game entry threshold must NOT enter Game mode.
    #[test]
    fn game_enter_dwell_7_ticks_not_game() {
        let mut clf = heuristic();
        // Score well above GAME_ENTER_THRESHOLD (0.65): use all-ones (score = 1.0).
        let high = Signals::new(1.0, 1.0, 1.0, 1.0);
        let mode = run_ticks(&mut clf, &high, GAME_ENTER_DWELL - 1);
        assert_ne!(
            mode,
            ContentMode::Game,
            "should NOT be Game after only {} ticks (need {})",
            GAME_ENTER_DWELL - 1,
            GAME_ENTER_DWELL
        );
    }

    /// 8 ticks above the Game entry threshold must enter Game mode.
    #[test]
    fn game_enter_dwell_8_ticks_is_game() {
        let mut clf = heuristic();
        let high = Signals::new(1.0, 1.0, 1.0, 1.0);
        let mode = run_ticks(&mut clf, &high, GAME_ENTER_DWELL);
        assert_eq!(
            mode,
            ContentMode::Game,
            "should be Game after exactly {} ticks",
            GAME_ENTER_DWELL
        );
    }

    // ── Game exit dwell ───────────────────────────────────────────────────────

    fn enter_game(clf: &mut ContentClassifier) {
        let high = Signals::new(1.0, 1.0, 1.0, 1.0);
        run_ticks(clf, &high, GAME_ENTER_DWELL);
        assert_eq!(clf.current_mode(), ContentMode::Game);
    }

    /// In Game mode, 29 ticks below the exit threshold must NOT leave Game mode.
    #[test]
    fn game_exit_dwell_29_ticks_still_game() {
        let mut clf = heuristic();
        enter_game(&mut clf);
        // Score well below GAME_EXIT_THRESHOLD (0.40): use all-zeros (score = 0.0).
        let low = Signals::new(0.0, 0.0, 0.0, 0.0);
        let mode = run_ticks(&mut clf, &low, GAME_EXIT_DWELL - 1);
        assert_eq!(
            mode,
            ContentMode::Game,
            "should still be Game after only {} ticks below exit threshold",
            GAME_EXIT_DWELL - 1
        );
    }

    /// In Game mode, 30 ticks below the exit threshold must leave Game mode.
    #[test]
    fn game_exit_dwell_30_ticks_leaves_game() {
        let mut clf = heuristic();
        enter_game(&mut clf);
        let low = Signals::new(0.0, 0.0, 0.0, 0.0);
        let mode = run_ticks(&mut clf, &low, GAME_EXIT_DWELL);
        assert_ne!(
            mode,
            ContentMode::Game,
            "should have left Game after {} ticks below exit threshold",
            GAME_EXIT_DWELL
        );
    }

    // ── Anti-flapping tests ───────────────────────────────────────────────────

    /// Brief alt-tab: score drops below 0.40 for 29 ticks then recovers — must stay in Game.
    #[test]
    fn brief_alt_tab_stays_in_game() {
        let mut clf = heuristic();
        enter_game(&mut clf);

        let low = Signals::new(0.0, 0.0, 0.0, 0.0);
        let high = Signals::new(1.0, 1.0, 1.0, 1.0);

        // 29 ticks below exit threshold (one short of exiting).
        run_ticks(&mut clf, &low, GAME_EXIT_DWELL - 1);
        assert_eq!(
            clf.current_mode(),
            ContentMode::Game,
            "still Game after 29 low ticks"
        );

        // Score recovers — counter resets.
        clf.on_tick(&high);
        assert_eq!(
            clf.current_mode(),
            ContentMode::Game,
            "still Game after recovery"
        );

        // Another 29 ticks below — still should not exit.
        run_ticks(&mut clf, &low, GAME_EXIT_DWELL - 1);
        assert_eq!(
            clf.current_mode(),
            ContentMode::Game,
            "still Game after second dip"
        );
    }

    /// Oscillating score around the Game enter threshold (0.65) must NOT cause rapid transitions.
    #[test]
    fn oscillating_score_around_enter_threshold_no_flap() {
        let mut clf = heuristic();
        // Alternate between score just above and just below GAME_ENTER_THRESHOLD.
        // Above: A=1.0 → score = 0.45 < 0.65. Need more. A=1.0,B=1.0 → 0.75 > 0.65.
        let above = make_signals_for_score(0.70); // above 0.65
        let below = make_signals_for_score(0.60); // below 0.65

        let mut transitions = 0u32;
        let mut last_mode = ContentMode::Work;

        for i in 0..60 {
            let s = if i % 2 == 0 { &above } else { &below };
            let m = clf.on_tick(s);
            if m != last_mode {
                transitions = transitions.saturating_add(1);
                last_mode = m;
            }
        }
        // With oscillation, the Game entry dwell (8) can never be met — zero transitions.
        assert_eq!(
            transitions, 0,
            "no transitions expected with alternating above/below Game enter threshold"
        );
    }

    /// Oscillating score around the Game exit threshold (0.40) in Game mode must NOT flap.
    #[test]
    fn oscillating_score_around_exit_threshold_no_flap() {
        let mut clf = heuristic();
        enter_game(&mut clf);

        let above_exit = make_signals_for_score(0.50); // above GAME_EXIT_THRESHOLD
        let below_exit = make_signals_for_score(0.30); // below GAME_EXIT_THRESHOLD

        let mut transitions = 0u32;
        let mut last_mode = ContentMode::Game;

        for i in 0..100 {
            let s = if i % 2 == 0 { &above_exit } else { &below_exit };
            let m = clf.on_tick(s);
            if m != last_mode {
                transitions = transitions.saturating_add(1);
                last_mode = m;
            }
        }
        // With alternating ticks, the exit dwell (30) can never be met — zero transitions.
        assert_eq!(
            transitions, 0,
            "no transitions expected with alternating ticks around Game exit threshold"
        );
    }

    // ── Scrolling transitions ─────────────────────────────────────────────────

    #[test]
    fn scroll_enter_dwell_3_ticks_not_scrolling() {
        let mut clf = heuristic();
        // Score in Scrolling band (above SCROLL_ENTER_THRESHOLD=0.35, below GAME_ENTER_THRESHOLD=0.65).
        let scroll_score = make_signals_for_score(0.50);
        let mode = run_ticks(&mut clf, &scroll_score, SCROLL_ENTER_DWELL - 1);
        assert_ne!(
            mode,
            ContentMode::Scrolling,
            "should NOT be Scrolling after only {} ticks",
            SCROLL_ENTER_DWELL - 1
        );
    }

    #[test]
    fn scroll_enter_dwell_4_ticks_is_scrolling() {
        let mut clf = heuristic();
        let scroll_score = make_signals_for_score(0.50);
        let mode = run_ticks(&mut clf, &scroll_score, SCROLL_ENTER_DWELL);
        assert_eq!(
            mode,
            ContentMode::Scrolling,
            "should be Scrolling after exactly {} ticks",
            SCROLL_ENTER_DWELL
        );
    }

    #[test]
    fn scroll_exit_dwell_9_ticks_still_scrolling() {
        let mut clf = heuristic();
        // Enter Scrolling first.
        let scroll_score = make_signals_for_score(0.50);
        run_ticks(&mut clf, &scroll_score, SCROLL_ENTER_DWELL);
        assert_eq!(clf.current_mode(), ContentMode::Scrolling);

        // Score drops below SCROLL_EXIT_THRESHOLD (0.25).
        let work_score = make_signals_for_score(0.10);
        let mode = run_ticks(&mut clf, &work_score, SCROLL_EXIT_DWELL - 1);
        assert_eq!(
            mode,
            ContentMode::Scrolling,
            "should still be Scrolling after only {} ticks below exit threshold",
            SCROLL_EXIT_DWELL - 1
        );
    }

    #[test]
    fn scroll_exit_dwell_10_ticks_leaves_scrolling() {
        let mut clf = heuristic();
        let scroll_score = make_signals_for_score(0.50);
        run_ticks(&mut clf, &scroll_score, SCROLL_ENTER_DWELL);
        assert_eq!(clf.current_mode(), ContentMode::Scrolling);

        let work_score = make_signals_for_score(0.10);
        let mode = run_ticks(&mut clf, &work_score, SCROLL_EXIT_DWELL);
        assert_ne!(
            mode,
            ContentMode::Scrolling,
            "should have left Scrolling after {} ticks below exit threshold",
            SCROLL_EXIT_DWELL
        );
    }

    /// Oscillating score around Scrolling entry threshold must not cause rapid Scrolling↔Work flaps.
    #[test]
    fn oscillating_around_scroll_entry_no_flap() {
        let mut clf = heuristic();
        let above = make_signals_for_score(0.40); // above SCROLL_ENTER_THRESHOLD
        let below = make_signals_for_score(0.20); // below SCROLL_ENTER_THRESHOLD

        let mut transitions = 0u32;
        let mut last_mode = ContentMode::Work;

        for i in 0..60 {
            let s = if i % 2 == 0 { &above } else { &below };
            let m = clf.on_tick(s);
            if m != last_mode {
                transitions = transitions.saturating_add(1);
                last_mode = m;
            }
        }
        assert_eq!(
            transitions, 0,
            "no transitions expected with alternating above/below Scrolling entry threshold"
        );
    }

    // ── Scrolling→Game transition ─────────────────────────────────────────────

    /// 7 high-score ticks from Scrolling must NOT enter Game.
    #[test]
    fn scrolling_to_game_dwell_7_ticks_not_game() {
        let mut clf = heuristic();
        // Enter Scrolling.
        let scroll_score = make_signals_for_score(0.50);
        run_ticks(&mut clf, &scroll_score, SCROLL_ENTER_DWELL);
        assert_eq!(clf.current_mode(), ContentMode::Scrolling);

        // 7 ticks above GAME_ENTER_THRESHOLD from Scrolling — one short of the dwell.
        let high = Signals::new(1.0, 1.0, 1.0, 1.0);
        let mode = run_ticks(&mut clf, &high, GAME_ENTER_DWELL - 1);
        assert_ne!(
            mode,
            ContentMode::Game,
            "should NOT enter Game after only {} ticks above threshold from Scrolling",
            GAME_ENTER_DWELL - 1
        );
    }

    /// 8 high-score ticks from Scrolling must enter Game.
    #[test]
    fn scrolling_to_game_dwell_8_ticks_is_game() {
        let mut clf = heuristic();
        // Enter Scrolling.
        let scroll_score = make_signals_for_score(0.50);
        run_ticks(&mut clf, &scroll_score, SCROLL_ENTER_DWELL);
        assert_eq!(clf.current_mode(), ContentMode::Scrolling);

        // 8 ticks above GAME_ENTER_THRESHOLD from Scrolling — should fire.
        let high = Signals::new(1.0, 1.0, 1.0, 1.0);
        let mode = run_ticks(&mut clf, &high, GAME_ENTER_DWELL);
        assert_eq!(
            mode,
            ContentMode::Game,
            "should enter Game after exactly {} ticks above threshold from Scrolling",
            GAME_ENTER_DWELL
        );
    }

    // ── Threshold boundary conditions ─────────────────────────────────────────

    /// A score exactly equal to GAME_ENTER_THRESHOLD (0.65) must NOT trigger Game entry.
    /// The spec uses strict `>`, so 0.65 is in the stable Scrolling band, not the Game band.
    #[test]
    fn score_exactly_at_game_enter_threshold_does_not_enter_game() {
        // Use FixedScoreProvider to hit exactly 0.65 — unreachable via make_signals_for_score.
        let mut clf = fixed_clf(GAME_ENTER_THRESHOLD);
        // Run many ticks; mode should stabilize at Scrolling, never reaching Game.
        run_ticks(
            &mut clf,
            &Signals::new(0.0, 0.0, 0.0, 0.0),
            SCROLL_ENTER_DWELL,
        );
        // Score is exactly 0.65 for all subsequent ticks — enter Scrolling, not Game.
        let mode = run_ticks(
            &mut clf,
            &Signals::new(0.0, 0.0, 0.0, 0.0),
            GAME_ENTER_DWELL * 2,
        );
        assert_ne!(
            mode,
            ContentMode::Game,
            "score == GAME_ENTER_THRESHOLD (0.65) must not enter Game (strict > required)"
        );
    }

    /// A score exactly equal to GAME_EXIT_THRESHOLD (0.40) must NOT trigger Game exit.
    /// The spec uses strict `<`, so 0.40 resets the exit counter (stable band), not increments it.
    #[test]
    fn score_exactly_at_game_exit_threshold_does_not_exit_game() {
        // Test the FSM pure transition function directly with score == 0.40 exactly.
        // When score == GAME_EXIT_THRESHOLD, the condition `score < GAME_EXIT_THRESHOLD` is false,
        // so the exit counter resets to zero — no progress toward leaving Game.
        let next =
            ContentClassifier::advance(FsmState::Game { exit_counter: 5 }, GAME_EXIT_THRESHOLD);
        assert_eq!(
            next,
            FsmState::Game { exit_counter: 0 },
            "score == 0.40 must reset exit counter (stable, strict < required)"
        );

        // Also verify via the heuristic: sustained 0.40 in Game for many ticks never exits.
        let mut clf = heuristic();
        enter_game(&mut clf);
        let at_threshold = make_signals_for_score(0.40);
        let score_actual = HeuristicScoreProvider.score(&at_threshold).as_f64();
        // make_signals_for_score may produce a value slightly above 0.40 due to float rounding;
        // either way, a score >= GAME_EXIT_THRESHOLD must not trigger exit.
        if score_actual >= GAME_EXIT_THRESHOLD {
            run_ticks(&mut clf, &at_threshold, GAME_EXIT_DWELL * 2);
            assert_eq!(
                clf.current_mode(),
                ContentMode::Game,
                "score >= 0.40 (score_actual={:.6}) must not exit Game",
                score_actual
            );
        }
    }

    // ── Work→Game→Work transition trace ──────────────────────────────────────

    /// Full round-trip: Work→Game (8 ticks) → brief dip (29 ticks, stays Game) → exit (30 more).
    #[test]
    fn work_to_game_to_work_round_trip_with_trace() {
        let mut clf = heuristic();
        let high = Signals::new(1.0, 1.0, 1.0, 1.0); // score = 1.0
        let low = Signals::new(0.0, 0.0, 0.0, 0.0); // score = 0.0

        let mut trace = Vec::new();

        // Phase 1: 8 ticks → Game.
        for t in 1..=8u32 {
            let m = clf.on_tick(&high);
            trace.push((t, m));
        }
        assert_eq!(
            clf.current_mode(),
            ContentMode::Game,
            "should be Game at tick 8"
        );

        // Phase 2: 29 ticks low → stays in Game.
        for t in 9..=37u32 {
            let m = clf.on_tick(&low);
            trace.push((t, m));
        }
        assert_eq!(
            clf.current_mode(),
            ContentMode::Game,
            "should still be Game after 29 low ticks"
        );

        // Phase 3: 1 tick high (reset exit counter).
        let m = clf.on_tick(&high);
        trace.push((38, m));

        // Phase 4: 30 ticks low → exits Game.
        for t in 39..=68u32 {
            let m = clf.on_tick(&low);
            trace.push((t, m));
        }
        let final_mode = clf.current_mode();
        assert_ne!(
            final_mode,
            ContentMode::Game,
            "should have left Game after 30 sustained low ticks"
        );

        // Print trace for --nocapture verification.
        println!("Work→Game→Work mode trace:");
        for (tick, mode) in &trace {
            println!("  tick {:>3}: {}", tick, mode);
        }
        println!("  Final mode: {}", final_mode);
    }

    // ── Property test ─────────────────────────────────────────────────────────

    // The minimum number of ticks between any two Game↔Work transitions is at least
    // `min(GAME_ENTER_DWELL, GAME_EXIT_DWELL)` = 8.
    //
    // More precisely: a transition from Work→Game requires at least GAME_ENTER_DWELL consecutive
    // high ticks; a subsequent Game→Work requires at least GAME_EXIT_DWELL consecutive low ticks.
    // Under any arbitrary sequence the FSM must never panic, and all modes must be valid.
    proptest! {
        #[test]
        fn prop_no_panic_and_valid_modes(
            scores in prop::collection::vec(0.0f64..=1.0f64, 1..200),
        ) {
            let mut clf = heuristic();
            for score in &scores {
                let signals = make_signals_for_score(*score);
                let mode = clf.on_tick(&signals);
                // Mode must always be one of the three valid variants.
                prop_assert!(
                    matches!(mode, ContentMode::Work | ContentMode::Scrolling | ContentMode::Game),
                    "invalid mode: {:?}", mode
                );
            }
        }

        /// The minimum gap between any two `Game ↔ non-Game` transitions must be at least
        /// `min(GAME_ENTER_DWELL, GAME_EXIT_DWELL)` = 8 ticks.
        #[test]
        fn prop_game_transitions_respect_min_dwell(
            scores in prop::collection::vec(0.0f64..=1.0f64, 1..400),
        ) {
            let mut clf = heuristic();
            let mut transition_ticks: Vec<usize> = Vec::new();
            let mut last_mode = ContentMode::Work;

            for (tick, score) in scores.iter().enumerate() {
                let signals = make_signals_for_score(*score);
                let mode = clf.on_tick(&signals);
                if (mode == ContentMode::Game) != (last_mode == ContentMode::Game) {
                    transition_ticks.push(tick);
                    last_mode = mode;
                }
            }

            let min_dwell = GAME_ENTER_DWELL.min(GAME_EXIT_DWELL) as usize;
            for window in transition_ticks.windows(2) {
                // windows(2) always produces slices of exactly 2 elements; both Options are Some.
                if let (Some(&t0), Some(&t1)) = (window.first(), window.get(1)) {
                    let gap = t1.saturating_sub(t0);
                    prop_assert!(
                        gap >= min_dwell,
                        "Game transition gap {} < min_dwell {} at ticks [{}, {}]",
                        gap,
                        min_dwell,
                        t0,
                        t1
                    );
                }
            }
        }

        /// Signals with arbitrary raw values (before clamping) must never cause score panics.
        #[test]
        fn prop_out_of_range_signals_no_panic(
            a in -10.0f64..10.0f64,
            b in -10.0f64..10.0f64,
            c in -10.0f64..10.0f64,
            d in -10.0f64..10.0f64,
        ) {
            let s = Signals::new(a, b, c, d);
            // All fields must be in [0,1].
            prop_assert!((0.0..=1.0).contains(&s.a));
            prop_assert!((0.0..=1.0).contains(&s.b));
            prop_assert!((0.0..=1.0).contains(&s.c));
            prop_assert!((0.0..=1.0).contains(&s.d));

            let p = HeuristicScoreProvider;
            let score = p.score(&s).as_f64();
            prop_assert!((0.0..=1.0).contains(&score), "score {} out of range", score);
        }

        /// Arbitrary cursor velocities (including negative and extreme) must produce valid D.
        #[test]
        fn prop_cursor_velocity_always_valid(velocity_px_s in -10_000.0f64..10_000.0f64) {
            let s = Signals::from_raw(0.0, 0.0, AppClass::Work, false, velocity_px_s);
            prop_assert!(
                (0.0..=1.0).contains(&s.d),
                "D={} out of [0,1] for velocity {}",
                s.d, velocity_px_s
            );
        }
    }
}
