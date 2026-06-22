//! Codec negotiation and degradation ladder (LLD §5.1 / ADR-0004, P2-5).
//!
//! This module is the **pure, deterministic core** of codec selection.  It takes two sets of
//! endpoint capabilities plus a content mode and build flavor, and produces an ordered
//! degradation ladder — a ranked list of [`CodecChoice`]s, from most preferred to least.
//!
//! ## Design overview
//!
//! The negotiator is **data-driven**: all platform rules (Apple no-AV1-encode, browser always
//! H.264, Work no-SW) are expressed as predicates on [`CodecCapabilities`] fields, not as nested
//! `#[cfg(...)]` branches.  This keeps the logic testable on any platform and separates the
//! capability *advertisement* (hardware probing, which is OS-specific) from the *selection* logic
//! (pure Rust, always compiled).
//!
//! ## Degradation ladders (ADR-0004)
//!
//! ### OSS build (`hevc` feature OFF) — Game mode
//!
//! ```text
//! 1. AV1  HW  (skipped on Apple encode-side)
//! 2. H264 HW
//! 3. H264 SW  (rate-limited; skipped in Work mode)
//! ```
//!
//! ### Commercial build (`hevc` feature ON) — Game mode
//!
//! ```text
//! 1. HEVC HW
//! 2. AV1  HW  (skipped on Apple encode-side)
//! 3. H264 HW
//! ```
//!
//! ### Work mode — both builds
//!
//! Same order as above but **`H264 SW` is never emitted** regardless of build flavor.
//!
//! ### Apple exception
//!
//! When `local.is_apple` is `true`, AV1 is removed from the encode ladder (VideoToolbox
//! provides no AV1 encoder as of 2026).  The fallback is H.264.
//!
//! ### Browser exception
//!
//! When `remote.is_browser` is `true`, H.264 is always reachable: even if `remote.hw_decode_mask`
//! does not explicitly set the H.264 bit, the negotiator treats H.264 decode as available because
//! all browsers support it via their built-in WebRTC stack.
//!
//! ### Mutual-support filter
//!
//! Every rung is checked: local must be able to **encode** the codec (HW or SW as appropriate)
//! *and* remote must be able to **decode** it (HW or SW, H.264 guaranteed for browsers).  Rungs
//! that fail this intersection test are silently dropped from the ladder.
//!
//! ## Examples
//!
//! ```
//! use sh_codec_hw::negotiation::{
//!     BuildFlavor, CodecCapabilities, CodecChoice, CodecNegotiator, ContentMode,
//! };
//!
//! let local = CodecCapabilities {
//!     hw_encode_mask: 0b0100, // AV1 HW encode
//!     hw_decode_mask: 0b0101, // H264 + AV1 HW decode
//!     sw_h264_encode_available: true,
//!     is_apple: false,
//!     is_browser: false,
//! };
//! let remote = CodecCapabilities {
//!     hw_encode_mask: 0b0001, // H264 HW encode (remote)
//!     hw_decode_mask: 0b0101, // H264 + AV1 HW decode
//!     sw_h264_encode_available: false,
//!     is_apple: false,
//!     is_browser: false,
//! };
//! let ladder = CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Oss);
//! // AV1 HW passes (local can encode, remote can decode), H264 HW also passes, SW last.
//! assert!(!ladder.is_empty());
//! let first = CodecNegotiator::select(&ladder);
//! assert!(first.is_some());
//! ```

use sh_protocol::Codec;

/// Re-exported for caller convenience: codec ladder construction depends on [`ContentMode`].
///
/// Callers can use `sh_codec_hw::negotiation::ContentMode` instead of importing from
/// `sh_adaptive::classifier` directly.
pub use sh_adaptive::classifier::ContentMode;

// ── Public types ──────────────────────────────────────────────────────────────

/// Build flavor controlling which codecs are eligible for the ladder.
///
/// `Oss` is the default Apache-2.0 build; `Commercial` adds HEVC.  In production the flavor is
/// derived from whether the `hevc` Cargo feature is enabled (see
/// [`BuildFlavor::from_compile_time`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildFlavor {
    /// OSS / Apache-2.0 build: AV1 + H.264 only.  HEVC is never offered or selected.
    Oss,
    /// Commercial build: adds HEVC to the top of the ladder.
    ///
    /// Requires a valid HEVC license from the patent-pool holder(s) (ADR-0004).
    Commercial,
}

impl BuildFlavor {
    /// Return the build flavor derived from compile-time feature flags.
    ///
    /// Returns [`BuildFlavor::Commercial`] when the `hevc` Cargo feature is enabled,
    /// [`BuildFlavor::Oss`] otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_codec_hw::negotiation::BuildFlavor;
    ///
    /// // In an OSS build (default, `hevc` feature OFF):
    /// #[cfg(not(feature = "hevc"))]
    /// assert_eq!(BuildFlavor::from_compile_time(), BuildFlavor::Oss);
    ///
    /// // In a commercial build (`hevc` feature ON):
    /// #[cfg(feature = "hevc")]
    /// assert_eq!(BuildFlavor::from_compile_time(), BuildFlavor::Commercial);
    /// ```
    #[must_use]
    pub fn from_compile_time() -> Self {
        #[cfg(feature = "hevc")]
        {
            BuildFlavor::Commercial
        }
        #[cfg(not(feature = "hevc"))]
        {
            BuildFlavor::Oss
        }
    }
}

// Codec discriminant bit-positions (matching `sh_protocol::capability` and the video wire format).
const DISC_H264: u8 = 0; // Codec::H264
const DISC_H265: u8 = 1; // Codec::H265 (HEVC)
const DISC_AV1: u8 = 2; // Codec::Av1

/// Per-endpoint codec capabilities, derived by probing the OS encoder/decoder APIs at startup.
///
/// This struct mirrors [`sh_protocol::capability::CodecCapsPayload`] but lives in `sh-codec-hw`
/// because it is populated by hardware-probing code in the platform backends (NVENC,
/// VideoToolbox, VA-API).  It converts to/from the wire form via the helper functions in
/// [`sh_protocol::capability`].
///
/// # Platform rules (encoded as data, not `#[cfg]` branches)
///
/// - **Apple** (`is_apple = true`): VideoToolbox has no AV1 *encode*.  The negotiator removes
///   AV1 from the encode ladder when this flag is set.
/// - **Browser** (`is_browser = true`): all browsers support H.264 decode natively.  The
///   negotiator guarantees H.264 is reachable in the ladder when the remote peer is a browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecCapabilities {
    /// Bitmask of codec discriminants this endpoint can **hardware-encode**.
    ///
    /// Bit `n` = 1 ↔ codec with wire discriminant `n` is available for HW encode.
    /// Only bits 0 (H264), 1 (H265/HEVC), and 2 (AV1) are meaningful; other bits are ignored.
    pub hw_encode_mask: u8,

    /// Bitmask of codec discriminants this endpoint can **hardware-decode**.
    ///
    /// Same bit numbering as `hw_encode_mask`.
    pub hw_decode_mask: u8,

    /// Whether this endpoint can encode H.264 in software (CPU, last resort).
    ///
    /// Software H.264 encoding is the final rung of the OSS Game-mode ladder.  Work mode never
    /// sets this because Work mode never software-encodes.
    pub sw_h264_encode_available: bool,

    /// Whether this endpoint is an Apple device (VideoToolbox host).
    ///
    /// Set to `true` on macOS hosts.  When `true`, AV1 is removed from the encode side of the
    /// ladder because VideoToolbox provides no AV1 encoder.
    pub is_apple: bool,

    /// Whether this endpoint is a browser peer.
    ///
    /// When `true`, H.264 decode is implicitly available regardless of `hw_decode_mask`.
    pub is_browser: bool,
}

impl CodecCapabilities {
    /// Convert from the wire [`sh_protocol::capability::CodecCapsPayload`].
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_protocol::capability::CodecCapsPayload;
    /// use sh_codec_hw::negotiation::CodecCapabilities;
    ///
    /// let wire = CodecCapsPayload {
    ///     hw_encode_mask: 0b0100,
    ///     hw_decode_mask: 0b0101,
    ///     sw_h264_encode_available: false,
    ///     is_apple: true,
    ///     is_browser: false,
    ///     selected_codec: None,
    /// };
    /// let caps = CodecCapabilities::from_wire(&wire);
    /// assert_eq!(caps.hw_encode_mask, 0b0100);
    /// assert!(caps.is_apple);
    /// ```
    #[must_use]
    pub fn from_wire(wire: &sh_protocol::capability::CodecCapsPayload) -> Self {
        Self {
            hw_encode_mask: wire.hw_encode_mask,
            hw_decode_mask: wire.hw_decode_mask,
            sw_h264_encode_available: wire.sw_h264_encode_available,
            is_apple: wire.is_apple,
            is_browser: wire.is_browser,
        }
    }

    /// Convert to the wire [`sh_protocol::capability::CodecCapsPayload`] (for encoding an offer).
    ///
    /// `selected_codec` is set to `None` (use `0xFF` sentinel = "offer, not yet selected").
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_codec_hw::negotiation::CodecCapabilities;
    ///
    /// let caps = CodecCapabilities {
    ///     hw_encode_mask: 0b0100,
    ///     hw_decode_mask: 0b0101,
    ///     sw_h264_encode_available: true,
    ///     is_apple: false,
    ///     is_browser: false,
    /// };
    /// let wire = caps.to_wire_offer();
    /// assert_eq!(wire.selected_codec, None);
    /// ```
    #[must_use]
    pub fn to_wire_offer(&self) -> sh_protocol::capability::CodecCapsPayload {
        sh_protocol::capability::CodecCapsPayload {
            hw_encode_mask: self.hw_encode_mask,
            hw_decode_mask: self.hw_decode_mask,
            sw_h264_encode_available: self.sw_h264_encode_available,
            is_apple: self.is_apple,
            is_browser: self.is_browser,
            selected_codec: None,
        }
    }

    /// Return `true` if this endpoint can hardware-encode the given codec discriminant.
    fn can_hw_encode(&self, disc: u8) -> bool {
        (self.hw_encode_mask >> disc) & 1 == 1
    }

    /// Return `true` if this endpoint can hardware-decode the given codec discriminant.
    fn can_hw_decode(&self, disc: u8) -> bool {
        (self.hw_decode_mask >> disc) & 1 == 1
    }

    /// Return `true` if this endpoint can decode `disc` (HW or browser-implicit H264).
    fn can_decode(&self, disc: u8) -> bool {
        if self.can_hw_decode(disc) {
            return true;
        }
        // Browsers always support H.264 decode.
        if self.is_browser && disc == DISC_H264 {
            return true;
        }
        false
    }
}

/// A single codec rung in the degradation ladder.
///
/// Carry both the codec identity and the encoding tier so callers know whether to start a
/// hardware encoder or a software (rate-limited) path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecChoice {
    /// The negotiated codec.
    pub codec: Codec,
    /// `true` when the codec is hardware-accelerated; `false` for software encode.
    pub hardware: bool,
    /// `true` when this rung uses software H.264 and must be rate-limited.
    ///
    /// Only set when `codec == Codec::H264 && !hardware`.  The pipeline reads this flag to apply
    /// the appropriate bitrate cap before starting the software encoder.
    pub rate_limited: bool,
}

impl CodecChoice {
    fn hw(codec: Codec) -> Self {
        Self {
            codec,
            hardware: true,
            rate_limited: false,
        }
    }

    fn sw_h264() -> Self {
        Self {
            codec: Codec::H264,
            hardware: false,
            rate_limited: true,
        }
    }
}

/// Wire discriminant for a [`CodecChoice`].
///
/// Returns the `sh_protocol::capability` discriminant byte matching the codec, for use in
/// an answer's `selected_codec` field.
#[must_use]
pub fn choice_to_discriminant(choice: &CodecChoice) -> u8 {
    match choice.codec {
        Codec::H264 => DISC_H264,
        Codec::H265 => DISC_H265,
        Codec::Av1 => DISC_AV1,
        Codec::Raw => 3, // Raw never appears in a real ladder; included for exhaustiveness.
    }
}

// ── Negotiator ────────────────────────────────────────────────────────────────

/// Pure, stateless codec ladder builder and selector.
///
/// All methods are `fn` (no `self`), deterministic, and allocation-free beyond the returned `Vec`.
/// They contain no I/O, no `async`, and no OS calls — safe to run in unit tests on any platform.
pub struct CodecNegotiator;

impl CodecNegotiator {
    /// Build the ordered degradation ladder filtered to mutually-supported codecs.
    ///
    /// The ladder is ordered from most-preferred to least-preferred.  Each rung satisfies:
    ///
    /// - **Local can encode** the codec (HW, or SW for the last H264 rung).
    /// - **Remote can decode** the codec (HW, or browser-implicit for H264).
    /// - **Build flavor** allows the codec (HEVC only when `hevc` feature is ON /
    ///   `flavor == Commercial`).
    /// - **Apple exception** respected: AV1 dropped from encode side when `local.is_apple`.
    /// - **Work-mode rule**: H264 SW rung never emitted for `ContentMode::Work`.
    ///
    /// Returns an empty `Vec` when no mutually supported codec exists.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_codec_hw::negotiation::{
    ///     BuildFlavor, CodecCapabilities, CodecNegotiator, ContentMode,
    /// };
    /// use sh_protocol::Codec;
    ///
    /// // Both sides support AV1 HW encode/decode.
    /// let local = CodecCapabilities {
    ///     hw_encode_mask: 0b0100, // AV1
    ///     hw_decode_mask: 0b0100,
    ///     sw_h264_encode_available: false,
    ///     is_apple: false,
    ///     is_browser: false,
    /// };
    /// let remote = CodecCapabilities {
    ///     hw_encode_mask: 0,
    ///     hw_decode_mask: 0b0100, // AV1 decode
    ///     sw_h264_encode_available: false,
    ///     is_apple: false,
    ///     is_browser: false,
    /// };
    /// let ladder = CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Oss);
    /// assert_eq!(ladder.first().map(|c| c.codec), Some(Codec::Av1));
    /// ```
    #[must_use]
    pub fn ladder(
        local: &CodecCapabilities,
        remote: &CodecCapabilities,
        mode: ContentMode,
        flavor: BuildFlavor,
    ) -> Vec<CodecChoice> {
        let mut ladder = Vec::with_capacity(4);

        // Produce candidate rungs in preference order, then filter.
        for candidate in Self::candidate_rungs(mode, flavor) {
            if Self::rung_is_viable(candidate, local, remote) {
                ladder.push(candidate);
            }
        }

        ladder
    }

    /// Return the first (most-preferred) viable rung, or `None` when the ladder is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_codec_hw::negotiation::{
    ///     BuildFlavor, CodecCapabilities, CodecNegotiator, ContentMode,
    /// };
    ///
    /// // Neither side supports anything.
    /// let empty = CodecCapabilities {
    ///     hw_encode_mask: 0,
    ///     hw_decode_mask: 0,
    ///     sw_h264_encode_available: false,
    ///     is_apple: false,
    ///     is_browser: false,
    /// };
    /// let ladder = CodecNegotiator::ladder(&empty, &empty, ContentMode::Game, BuildFlavor::Oss);
    /// assert_eq!(CodecNegotiator::select(&ladder), None);
    /// ```
    #[must_use]
    pub fn select(ladder: &[CodecChoice]) -> Option<CodecChoice> {
        ladder.first().copied()
    }

    /// Step down the ladder after the current rung failed (e.g. encoder-init error).
    ///
    /// Returns the next rung after `current` in `ladder`, or `None` when `current` is the last
    /// rung or not found.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_codec_hw::negotiation::{
    ///     BuildFlavor, CodecCapabilities, CodecChoice, CodecNegotiator, ContentMode,
    /// };
    /// use sh_protocol::Codec;
    ///
    /// let local = CodecCapabilities {
    ///     hw_encode_mask: 0b0101, // H264 + AV1 HW
    ///     hw_decode_mask: 0b0101,
    ///     sw_h264_encode_available: true,
    ///     is_apple: false,
    ///     is_browser: false,
    /// };
    /// let remote = CodecCapabilities {
    ///     hw_encode_mask: 0,
    ///     hw_decode_mask: 0b0101,
    ///     sw_h264_encode_available: false,
    ///     is_apple: false,
    ///     is_browser: false,
    /// };
    /// let ladder = CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Oss);
    /// let first = CodecNegotiator::select(&ladder).unwrap();
    /// assert_eq!(first.codec, Codec::Av1);
    ///
    /// // Simulate AV1 encoder-init failure → step down.
    /// let next = CodecNegotiator::degrade(&first, &ladder).unwrap();
    /// assert_eq!(next.codec, Codec::H264);
    /// assert!(next.hardware);
    ///
    /// // Step down past H264 HW → H264 SW.
    /// let last = CodecNegotiator::degrade(&next, &ladder).unwrap();
    /// assert!(!last.hardware);
    ///
    /// // Past the last rung → None (no panic).
    /// assert_eq!(CodecNegotiator::degrade(&last, &ladder), None);
    /// ```
    #[must_use]
    pub fn degrade(current: &CodecChoice, ladder: &[CodecChoice]) -> Option<CodecChoice> {
        let pos = ladder.iter().position(|r| r == current)?;
        // pos.checked_add(1) is always Some for usize unless pos == usize::MAX — unreachable in
        // practice for a ladder of at most 4 rungs, but we use checked_add to satisfy the
        // arithmetic_side_effects lint.
        let next = pos.checked_add(1)?;
        ladder.get(next).copied()
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Produce the full ordered candidate list for a (mode, flavor) pair — **before** the
    /// mutual-support filter.  The filter in [`ladder`](Self::ladder) then removes rungs that
    /// aren't viable for the specific local/remote capabilities.
    ///
    /// Returns a `Vec` (rather than a `&'static [...]`) because [`CodecChoice`] has no
    /// `const`-constructible path in stable Rust — the enum field ([`Codec`]) is not `Copy`-const.
    fn candidate_rungs(mode: ContentMode, flavor: BuildFlavor) -> Vec<CodecChoice> {
        match (flavor, mode) {
            // ── Commercial builds ─────────────────────────────────────────
            (BuildFlavor::Commercial, ContentMode::Game | ContentMode::Scrolling) => {
                // HEVC HW → AV1 HW → H264 HW (no SW rung in commercial)
                vec![
                    CodecChoice::hw(Codec::H265),
                    CodecChoice::hw(Codec::Av1),
                    CodecChoice::hw(Codec::H264),
                ]
            }
            (BuildFlavor::Commercial, ContentMode::Work) => {
                // Same order, no SW rung (Work mode never SW-encodes in any flavor).
                vec![
                    CodecChoice::hw(Codec::H265),
                    CodecChoice::hw(Codec::Av1),
                    CodecChoice::hw(Codec::H264),
                ]
            }
            // ── OSS builds ────────────────────────────────────────────────
            (BuildFlavor::Oss, ContentMode::Game | ContentMode::Scrolling) => {
                // AV1 HW → H264 HW → H264 SW (rate-limited, last resort)
                vec![
                    CodecChoice::hw(Codec::Av1),
                    CodecChoice::hw(Codec::H264),
                    CodecChoice::sw_h264(),
                ]
            }
            (BuildFlavor::Oss, ContentMode::Work) => {
                // No SW rung — Work mode never software-encodes.
                vec![CodecChoice::hw(Codec::Av1), CodecChoice::hw(Codec::H264)]
            }
        }
    }

    /// Return `true` if `candidate` is mutually viable for the given endpoints.
    fn rung_is_viable(
        candidate: CodecChoice,
        local: &CodecCapabilities,
        remote: &CodecCapabilities,
    ) -> bool {
        let disc = choice_to_discriminant(&candidate);

        // ── Local can encode ──────────────────────────────────────────────
        let local_can_encode = if candidate.hardware {
            // Hardware rung: local must have HW encode capability.
            // Apple exception: AV1 is never available for HW encode on Apple.
            if local.is_apple && disc == DISC_AV1 {
                false
            } else {
                local.can_hw_encode(disc)
            }
        } else {
            // Software rung (only H264 SW exists).
            disc == DISC_H264 && local.sw_h264_encode_available
        };

        if !local_can_encode {
            return false;
        }

        // ── Remote can decode ─────────────────────────────────────────────
        remote.can_decode(disc)
    }
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
    use sh_protocol::Codec;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Caps that can do everything (all HW encode/decode, SW H264, not Apple, not browser).
    fn full_caps() -> CodecCapabilities {
        CodecCapabilities {
            hw_encode_mask: 0b0000_0111, // H264 + H265 + AV1
            hw_decode_mask: 0b0000_0111,
            sw_h264_encode_available: true,
            is_apple: false,
            is_browser: false,
        }
    }

    fn h264_only_caps() -> CodecCapabilities {
        CodecCapabilities {
            hw_encode_mask: 0b0000_0001, // H264 only
            hw_decode_mask: 0b0000_0001,
            sw_h264_encode_available: true,
            is_apple: false,
            is_browser: false,
        }
    }

    fn no_caps() -> CodecCapabilities {
        CodecCapabilities {
            hw_encode_mask: 0,
            hw_decode_mask: 0,
            sw_h264_encode_available: false,
            is_apple: false,
            is_browser: false,
        }
    }

    fn codec_seq(ladder: &[CodecChoice]) -> Vec<Codec> {
        ladder.iter().map(|c| c.codec).collect()
    }

    fn hw_seq(ladder: &[CodecChoice]) -> Vec<bool> {
        ladder.iter().map(|c| c.hardware).collect()
    }

    // ── Ladder shape: OSS Game ────────────────────────────────────────────────

    #[test]
    fn oss_game_ladder_full_caps() {
        let local = full_caps();
        let remote = full_caps();
        let ladder = CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Oss);

        // Expected: AV1 HW → H264 HW → H264 SW
        assert_eq!(
            codec_seq(&ladder),
            vec![Codec::Av1, Codec::H264, Codec::H264],
            "OSS Game ladder: [AV1 HW, H264 HW, H264 SW]"
        );
        assert_eq!(hw_seq(&ladder), vec![true, true, false]);
        assert!(ladder[2].rate_limited, "SW rung must be rate-limited");

        eprintln!("\nOSS Game ladder:");
        for r in &ladder {
            eprintln!(
                "  {:?} {} {}",
                r.codec,
                if r.hardware { "HW" } else { "SW" },
                if r.rate_limited { "(rate-limited)" } else { "" }
            );
        }
    }

    // ── Ladder shape: Commercial Game ─────────────────────────────────────────

    #[test]
    #[cfg(feature = "hevc")]
    fn commercial_game_ladder_full_caps() {
        let local = full_caps();
        let remote = full_caps();
        let ladder =
            CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Commercial);

        // Expected: HEVC HW → AV1 HW → H264 HW (no SW rung)
        assert_eq!(
            codec_seq(&ladder),
            vec![Codec::H265, Codec::Av1, Codec::H264],
            "Commercial Game ladder: [HEVC HW, AV1 HW, H264 HW]"
        );
        assert_eq!(hw_seq(&ladder), vec![true, true, true]);
        assert!(
            !ladder.iter().any(|r| r.rate_limited),
            "no SW rung in commercial Game"
        );

        eprintln!("\nCommercial Game ladder:");
        for r in &ladder {
            eprintln!("  {:?} {}", r.codec, if r.hardware { "HW" } else { "SW" });
        }
    }

    // ── Work mode: no SW rung ─────────────────────────────────────────────────

    #[test]
    fn oss_work_ladder_never_sw() {
        let local = full_caps();
        let remote = full_caps();
        let ladder = CodecNegotiator::ladder(&local, &remote, ContentMode::Work, BuildFlavor::Oss);

        // SW rung must never appear.
        assert!(
            !ladder.iter().any(|r| r.rate_limited),
            "Work mode must never have SW/rate-limited rung"
        );
        assert!(
            ladder.iter().all(|r| r.hardware),
            "Work mode: all rungs must be HW"
        );

        eprintln!("\nOSS Work ladder: {:?}", codec_seq(&ladder));
    }

    #[test]
    #[cfg(feature = "hevc")]
    fn commercial_work_ladder_never_sw() {
        let local = full_caps();
        let remote = full_caps();
        let ladder =
            CodecNegotiator::ladder(&local, &remote, ContentMode::Work, BuildFlavor::Commercial);

        assert!(
            !ladder.iter().any(|r| r.rate_limited),
            "Commercial Work mode must never have SW rung"
        );
    }

    // ── Apple exception: AV1 removed from encode ladder ──────────────────────

    #[test]
    fn apple_host_no_av1_encode_in_ladder() {
        let mut local = full_caps();
        local.is_apple = true;
        let remote = full_caps();

        let oss_ladder =
            CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Oss);

        assert!(
            !oss_ladder.iter().any(|r| r.codec == Codec::Av1),
            "Apple host: AV1 must not appear in the encode ladder"
        );
        // H264 must still be reachable.
        assert!(
            oss_ladder.iter().any(|r| r.codec == Codec::H264),
            "Apple host: H264 must still be reachable"
        );

        eprintln!("\nApple OSS Game ladder: {:?}", codec_seq(&oss_ladder));
    }

    // ── Browser peer: H264 always reachable ──────────────────────────────────

    #[test]
    fn browser_peer_h264_always_reachable() {
        // Remote browser advertises no HW decode at all, but is_browser=true.
        let local = full_caps();
        let mut remote = no_caps();
        remote.is_browser = true;

        let ladder = CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Oss);

        assert!(
            ladder.iter().any(|r| r.codec == Codec::H264),
            "browser peer: H264 must always be reachable in the ladder"
        );

        eprintln!("\nBrowser peer OSS Game ladder: {:?}", codec_seq(&ladder));
    }

    // ── Intersection: remote can't decode AV1 → AV1 skipped ─────────────────

    #[test]
    fn intersection_av1_skipped_when_remote_cant_decode() {
        let local = full_caps();
        let mut remote = full_caps();
        // Remote can't decode AV1.
        remote.hw_decode_mask = 0b0000_0001; // H264 only

        let ladder = CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Oss);

        assert!(
            !ladder.iter().any(|r| r.codec == Codec::Av1),
            "AV1 must be skipped when remote cannot decode it"
        );
        assert!(
            ladder.iter().any(|r| r.codec == Codec::H264),
            "H264 must still be reachable"
        );
    }

    // ── Empty intersection → select() returns None ────────────────────────────

    #[test]
    fn empty_intersection_select_is_none() {
        // Local can only HW-encode AV1; remote can only HW-decode H265; no SW.
        let local = CodecCapabilities {
            hw_encode_mask: 0b0000_0100, // AV1 only
            hw_decode_mask: 0,
            sw_h264_encode_available: false,
            is_apple: false,
            is_browser: false,
        };
        let remote = CodecCapabilities {
            hw_encode_mask: 0,
            hw_decode_mask: 0b0000_0010, // H265 only (can't decode AV1)
            sw_h264_encode_available: false,
            is_apple: false,
            is_browser: false,
        };
        let ladder = CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Oss);
        assert!(
            ladder.is_empty(),
            "no intersection: ladder must be empty, not panic"
        );
        assert_eq!(
            CodecNegotiator::select(&ladder),
            None,
            "select() must return None for empty ladder"
        );
    }

    // ── Degradation: degrade() steps down the ladder ─────────────────────────

    #[test]
    fn degrade_steps_through_ladder() {
        let local = full_caps();
        let remote = full_caps();
        let ladder = CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Oss);

        let first = CodecNegotiator::select(&ladder).unwrap();
        assert_eq!(first.codec, Codec::Av1);

        let second = CodecNegotiator::degrade(&first, &ladder).unwrap();
        assert_eq!(second.codec, Codec::H264);
        assert!(second.hardware);

        let third = CodecNegotiator::degrade(&second, &ladder).unwrap();
        assert_eq!(third.codec, Codec::H264);
        assert!(!third.hardware);
        assert!(third.rate_limited);

        // Past last rung → None (must NOT panic).
        let beyond = CodecNegotiator::degrade(&third, &ladder);
        assert_eq!(beyond, None, "past last rung must return None, not panic");
    }

    #[test]
    fn degrade_on_empty_ladder_is_none() {
        let current = CodecChoice::hw(Codec::H264);
        let empty: Vec<CodecChoice> = Vec::new();
        assert_eq!(CodecNegotiator::degrade(&current, &empty), None);
    }

    // ── Feature flag: OSS build never produces HEVC ───────────────────────────

    #[test]
    fn oss_ladder_never_contains_hevc() {
        let local = full_caps();
        let remote = full_caps();

        for mode in [ContentMode::Game, ContentMode::Work, ContentMode::Scrolling] {
            let ladder = CodecNegotiator::ladder(&local, &remote, mode, BuildFlavor::Oss);
            assert!(
                !ladder.iter().any(|r| r.codec == Codec::H265),
                "OSS ladder must never contain HEVC (mode={mode:?})"
            );
        }
    }

    // ── Commercial ladder leads with HEVC (runtime test, `--features hevc`) ───

    #[test]
    #[cfg(feature = "hevc")]
    fn commercial_ladder_leads_with_hevc() {
        let local = full_caps();
        let remote = full_caps();
        let ladder =
            CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Commercial);
        assert_eq!(
            ladder.first().map(|r| r.codec),
            Some(Codec::H265),
            "Commercial Game ladder must lead with HEVC"
        );
    }

    // ── BuildFlavor::from_compile_time ────────────────────────────────────────

    #[test]
    #[cfg(feature = "hevc")]
    fn from_compile_time_is_commercial_with_hevc_feature() {
        assert_eq!(BuildFlavor::from_compile_time(), BuildFlavor::Commercial);
    }

    #[test]
    #[cfg(not(feature = "hevc"))]
    fn from_compile_time_is_oss_without_hevc_feature() {
        assert_eq!(BuildFlavor::from_compile_time(), BuildFlavor::Oss);
    }

    // ── Wire conversion round-trip ─────────────────────────────────────────────

    #[test]
    fn caps_wire_roundtrip() {
        let caps = CodecCapabilities {
            hw_encode_mask: 0b0000_0110,
            hw_decode_mask: 0b0000_0111,
            sw_h264_encode_available: true,
            is_apple: false,
            is_browser: true,
        };
        let wire = caps.to_wire_offer();
        let back = CodecCapabilities::from_wire(&wire);
        assert_eq!(back, caps);
        assert_eq!(wire.selected_codec, None);
    }

    // ── Scrolling mode follows Game rules ─────────────────────────────────────

    #[test]
    fn scrolling_mode_follows_game_rules() {
        let local = full_caps();
        let remote = full_caps();
        let game = CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Oss);
        let scroll =
            CodecNegotiator::ladder(&local, &remote, ContentMode::Scrolling, BuildFlavor::Oss);
        assert_eq!(
            codec_seq(&game),
            codec_seq(&scroll),
            "Scrolling and Game must produce the same ladder"
        );
    }

    // ── choice_to_discriminant ────────────────────────────────────────────────

    #[test]
    fn discriminant_matches_wire_encoding() {
        assert_eq!(choice_to_discriminant(&CodecChoice::hw(Codec::H264)), 0);
        assert_eq!(choice_to_discriminant(&CodecChoice::hw(Codec::H265)), 1);
        assert_eq!(choice_to_discriminant(&CodecChoice::hw(Codec::Av1)), 2);
    }

    // ── h264_only: full ladder with only H264 caps ────────────────────────────

    #[test]
    fn h264_only_ladder_oss_game() {
        let local = h264_only_caps();
        let remote = h264_only_caps();
        let ladder = CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Oss);

        // AV1 missing from both sides, SW H264 available.
        // Expected: H264 HW → H264 SW
        assert_eq!(codec_seq(&ladder), vec![Codec::H264, Codec::H264]);
        assert_eq!(hw_seq(&ladder), vec![true, false]);
    }

    #[test]
    fn h264_only_work_mode_no_sw() {
        let local = h264_only_caps();
        let remote = h264_only_caps();
        let ladder = CodecNegotiator::ladder(&local, &remote, ContentMode::Work, BuildFlavor::Oss);

        // Work mode drops SW rung → only H264 HW.
        assert_eq!(codec_seq(&ladder), vec![Codec::H264]);
        assert_eq!(hw_seq(&ladder), vec![true]);
    }

    // ── Apple + browser combined ──────────────────────────────────────────────

    #[test]
    fn apple_encoder_browser_decoder() {
        // Apple host (no AV1 encode) sending to browser peer (implicit H264 decode).
        let mut local = full_caps();
        local.is_apple = true;
        let mut remote = no_caps();
        remote.is_browser = true;

        let ladder = CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Oss);

        // AV1 excluded (Apple). Browser guarantees H264 decode even with empty hw_decode_mask.
        assert!(!ladder.iter().any(|r| r.codec == Codec::Av1));
        assert!(ladder.iter().any(|r| r.codec == Codec::H264));

        eprintln!("\nApple→Browser OSS Game ladder: {:?}", codec_seq(&ladder));
    }

    // ── Printed ladder table (required by the task spec) ─────────────────────

    #[test]
    fn print_ladder_table() {
        let local = full_caps();
        let remote = full_caps();
        let mut apple_local = full_caps();
        apple_local.is_apple = true;
        let mut browser_remote = no_caps();
        browser_remote.is_browser = true;

        fn print_ladder(label: &str, ladder: &[CodecChoice]) {
            eprintln!("\n=== {} ===", label);
            if ladder.is_empty() {
                eprintln!("  (empty — no mutual codec)");
                return;
            }
            for (i, r) in ladder.iter().enumerate() {
                eprintln!(
                    "  [{}] {:?} {} {}",
                    i.saturating_add(1),
                    r.codec,
                    if r.hardware { "HW" } else { "SW" },
                    if r.rate_limited { "(rate-limited)" } else { "" }
                );
            }
        }

        print_ladder(
            "OSS Game (full caps)",
            &CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Oss),
        );
        print_ladder(
            "OSS Work (full caps)",
            &CodecNegotiator::ladder(&local, &remote, ContentMode::Work, BuildFlavor::Oss),
        );
        print_ladder(
            "OSS Game (Apple encoder)",
            &CodecNegotiator::ladder(&apple_local, &remote, ContentMode::Game, BuildFlavor::Oss),
        );
        print_ladder(
            "OSS Game (Browser peer, no HW decode mask)",
            &CodecNegotiator::ladder(&local, &browser_remote, ContentMode::Game, BuildFlavor::Oss),
        );
        #[cfg(feature = "hevc")]
        print_ladder(
            "Commercial Game (full caps)",
            &CodecNegotiator::ladder(&local, &remote, ContentMode::Game, BuildFlavor::Commercial),
        );
    }
}
