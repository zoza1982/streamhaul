#![deny(missing_docs)]
//! `sh-web-client` — browser WebRTC client for Streamhaul with DTLS identity pinning.
//!
//! This crate orchestrates a browser [`web_sys::RtcPeerConnection`] session and enforces the
//! **same MITM defense as the native transport (P4-5 / ADR-0014)**: the peer's DTLS certificate
//! fingerprint, committed inside the identity-authenticated Noise handshake (`BindCert`), is
//! pinned and checked against the SDP `a=fingerprint` *before* the remote description is applied.
//! A signaling/SDP fingerprint swap is therefore rejected before any DTLS traffic flows.
//!
//! # Why a Rust/wasm orchestrator
//!
//! The orchestration (SDP fingerprint extraction, pin comparison, handshake sequencing) is the
//! security-critical glue.  Implementing it in Rust/wasm — rather than TypeScript — keeps that
//! logic inside the audited, panic-free, constant-time-comparison Rust surface and minimizes the
//! attack surface in untyped JS.  The crypto itself lives in [`sh_crypto_wasm`]; the SHP codec in
//! [`sh_wasm`]; this crate re-implements neither.
//!
//! # The DTLS identity pin (MITM defense)
//!
//! 1. Create the [`web_sys::RtcPeerConnection`], `createOffer`, `setLocalDescription`, gather ICE.
//! 2. Extract the **local** `a=fingerprint` from the local SDP ([`parse_sdp_fingerprint`]).
//! 3. Run the Noise XK handshake ([`sh_crypto_wasm::WasmNoiseHandshake`]) over signaling,
//!    committing the local DTLS fingerprint in the `BindCert`.
//! 4. Complete the handshake (TOFU first pairing) → obtain the peer identity and
//!    `require_dtls_pin()` (the peer's committed 32-byte DTLS fingerprint).
//! 5. **Before `setRemoteDescription`**, parse the remote SDP's `a=fingerprint` and compare it
//!    byte-for-byte (constant-time) against the pin ([`verify_sdp_fingerprint_pin`]).  On a
//!    mismatch, abort — never call `setRemoteDescription`.
//! 6. On a match, apply the remote description, finish ICE, open the DataChannel.
//!
//! # Security constraints
//!
//! - **No panics in production paths.**  Every fallible entry point returns `Result<_, JsValue>`
//!   (a catchable JS exception), never a wasm trap (which crashes the browser tab).
//! - **SDP and signaling are hostile input.**  [`parse_sdp_fingerprint`] returns an error on any
//!   malformed line; it never panics or indexes out of bounds.
//! - **Private keys stay in wasm.**  Key material is owned by [`sh_crypto_wasm`]; this crate never
//!   touches raw private bytes.
//! - **SHP payload is opaque.**  Frames pass through the DataChannel verbatim; their contents are
//!   never inspected here.
//!
//! See ADR-0021 for the full design rationale and deferrals.

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    MessageEvent, RtcDataChannel, RtcDataChannelEvent, RtcPeerConnection,
    RtcPeerConnectionIceEvent, RtcSdpType, RtcSessionDescriptionInit,
};

// ── SDP fingerprint parsing (hostile input) ──────────────────────────────────

/// The number of bytes in a SHA-256 DTLS fingerprint (RFC 8122).
const SHA256_FP_LEN: usize = 32;

/// Upper bound on the SDP blob we will scan for an `a=fingerprint` line.
///
/// SDP arrives over the untrusted signaling channel and is hostile input.  A legitimate WebRTC
/// offer/answer is a few kilobytes; 64 KiB is far above any honest payload while bounding the work
/// a malicious peer can force the parser to do (DoS guard).
const MAX_SDP_BYTES: usize = 65_536;

/// Parse the SHA-256 DTLS fingerprint from an SDP blob.
///
/// Looks for the first `a=fingerprint:sha-256 <HEX>` attribute line (case-insensitive on the
/// `sha-256` algorithm token) and decodes the colon-separated hex bytes that follow into a
/// 32-byte vector.  This is the RFC 8122 whole-certificate fingerprint — exactly the value the
/// Noise `BindCert` commits and that `WasmHandshakeOutcome::require_dtls_pin` returns.
///
/// # Hostile input
///
/// SDP arrives over the untrusted signaling channel and is treated as hostile.  Malformed input
/// (missing line, wrong algorithm, wrong byte count, non-hex digits) returns a `JsError` — this
/// function never panics, never traps, and never indexes out of bounds.
///
/// # Errors
///
/// Returns a `JsError` if no `a=fingerprint:sha-256` line is present, or the hex payload does not
/// decode to exactly 32 bytes.
#[wasm_bindgen]
pub fn parse_sdp_fingerprint(sdp: &str) -> Result<Vec<u8>, JsValue> {
    parse_sdp_fingerprint_inner(sdp).map_err(|e| JsError::new(e).into())
}

/// Host-callable entry point for the parser, used by the `cargo-fuzz` harness.
///
/// The `#[wasm_bindgen]` [`parse_sdp_fingerprint`] wrapper cannot run off-wasm — building its
/// `JsValue`/`JsError` return aborts in wasm-bindgen glue on a native target — so libFuzzer (which
/// runs on the host) must call this seam instead. It is the **same** parsing/validation logic with
/// a plain `&'static str` error in place of `JsValue`; it adds no behavior and is `#[doc(hidden)]`
/// (a test seam, not public API). Keeping this hostile-input SDP parser fuzz-covered on the native
/// target requires a host-callable entry point, since `#[wasm_bindgen]` exports are not linkable
/// outside wasm.
#[doc(hidden)]
pub fn parse_sdp_fingerprint_host(sdp: &str) -> Result<Vec<u8>, &'static str> {
    parse_sdp_fingerprint_inner(sdp)
}

/// Internal parser returning a `&'static str` error so callers can map it once.
///
/// SDP lines are separated by CRLF or LF; we split on `\n` and trim a trailing `\r`.
fn parse_sdp_fingerprint_inner(sdp: &str) -> Result<Vec<u8>, &'static str> {
    // Hostile-input bound: reject oversized SDP before scanning it (DoS guard).
    if sdp.len() > MAX_SDP_BYTES {
        return Err("SDP exceeds maximum allowed length");
    }
    for raw_line in sdp.split('\n') {
        let line = raw_line.trim_end_matches('\r').trim();
        // SDP attribute: `a=fingerprint:<algorithm> <value>`.
        let Some(rest) = line.strip_prefix("a=fingerprint:") else {
            continue;
        };
        // Split `<algorithm> <value>` on the first ASCII whitespace run.
        let mut parts = rest.splitn(2, char::is_whitespace);
        let Some(alg) = parts.next() else {
            // Structurally unreachable: `splitn(2, …)` on a non-empty `rest` always yields ≥1
            // token.  Treat the impossible empty case as "no usable fingerprint here" and keep
            // scanning rather than failing the whole parse.
            continue;
        };
        let value = match parts.next() {
            Some(v) => v.trim(),
            // A `a=fingerprint:<alg>` line with no whitespace+value carries no fingerprint we can
            // use; keep scanning in case a later line carries a well-formed SHA-256 one — the same
            // non-fatal treatment as a wrong-algorithm line below.
            None => continue,
        };
        if !alg.eq_ignore_ascii_case("sha-256") {
            // A non-SHA-256 fingerprint cannot match our 32-byte commitment; keep scanning in
            // case a later line carries the SHA-256 one.
            continue;
        }
        return decode_colon_hex(value);
    }
    Err("no a=fingerprint:sha-256 attribute found in SDP")
}

/// Decode a colon-separated uppercase/lowercase hex fingerprint (`AA:BB:CC:...`) into bytes.
///
/// Enforces exactly [`SHA256_FP_LEN`] bytes.  Rejects empty tokens, non-hex digits, and any
/// token that is not exactly two hex characters — i.e. it is strict, not best-effort.
fn decode_colon_hex(value: &str) -> Result<Vec<u8>, &'static str> {
    let mut out: Vec<u8> = Vec::with_capacity(SHA256_FP_LEN);
    for token in value.split(':') {
        if token.len() != 2 {
            return Err("each fingerprint hex group must be exactly two hex digits");
        }
        let mut byte: u8 = 0;
        for ch in token.chars() {
            // `to_digit(16)` yields 0..=15, which always fits a u8; mask to make that explicit and
            // satisfy the cast-truncation lint without an allow.
            let nibble = match ch.to_digit(16) {
                Some(n) => (n & 0xF) as u8,
                None => return Err("fingerprint contains a non-hex character"),
            };
            // `byte` holds at most one nibble here, so `<< 4 | nibble` cannot overflow a u8.
            byte = (byte << 4) | nibble;
        }
        if out.len() == SHA256_FP_LEN {
            return Err("fingerprint has more than 32 bytes");
        }
        out.push(byte);
    }
    if out.len() != SHA256_FP_LEN {
        return Err("fingerprint did not decode to exactly 32 bytes");
    }
    Ok(out)
}

/// Verify that the SHA-256 DTLS fingerprint in `sdp` matches the pinned value `pin`.
///
/// This is the WebRTC MITM gate: `pin` is the peer's DTLS fingerprint committed inside the
/// identity-authenticated Noise handshake (`WasmHandshakeOutcome::require_dtls_pin`); `sdp` is the
/// remote description relayed through the untrusted signaling server.  The comparison is
/// constant-time and byte-exact.  Call this BEFORE `setRemoteDescription`; on `Err`, abort the
/// session and never apply the remote SDP.
///
/// # Errors
///
/// Returns a `JsError` if `pin` is not exactly 32 bytes, the SDP fingerprint cannot be parsed, or
/// the parsed fingerprint does not equal `pin`.  All three return the same opaque error shape so a
/// caller cannot distinguish a parse failure from a mismatch.
#[wasm_bindgen]
pub fn verify_sdp_fingerprint_pin(sdp: &str, pin: &[u8]) -> Result<(), JsValue> {
    if pin.len() != SHA256_FP_LEN {
        return Err(JsError::new("pin must be exactly 32 bytes").into());
    }
    let parsed = parse_sdp_fingerprint_inner(sdp)
        .map_err(|_| JsError::new("DTLS fingerprint verification failed"))?;
    // Constant-time comparison: both operands are 32 bytes here.
    let mut diff: u8 = 0;
    for i in 0..SHA256_FP_LEN {
        // Bounds are guaranteed: `parsed` is exactly 32 bytes (decode_colon_hex enforces it) and
        // `pin` is checked above.  Use `get` to stay clear of the indexing_slicing lint.
        let (a, b) = match (parsed.get(i), pin.get(i)) {
            (Some(a), Some(b)) => (a, b),
            _ => return Err(JsError::new("DTLS fingerprint verification failed").into()),
        };
        diff |= a ^ b;
    }
    if diff == 0 {
        Ok(())
    } else {
        Err(JsError::new("DTLS fingerprint verification failed").into())
    }
}

// ── Panic hook (development aid) ──────────────────────────────────────────────

/// Install the `console_error_panic_hook` so a Rust panic surfaces a readable stack trace in the
/// browser console instead of an opaque `RuntimeError: unreachable`.
///
/// Production paths never panic (every fallible entry point returns `Result<_, JsValue>`); this is
/// a development aid for the test harness and for diagnosing bugs in the browser console.  Calling
/// it is idempotent and side-effect-free beyond installing the hook.
#[wasm_bindgen]
pub fn set_panic_hook() {
    console_error_panic_hook::set_once();
}

// ── SignalingChannel ──────────────────────────────────────────────────────────

/// A thin wrapper around a JS callback used to send signaling payloads (SDP / ICE) to the peer.
///
/// The browser client does not own the transport for signaling messages — that is the host page's
/// responsibility (a `WebSocket` to `sh-signaling`, or, in tests, a direct in-page function).
/// [`WebClient`] calls [`SignalingChannel::send`] to emit a payload; the host page is responsible
/// for delivering it to the peer.
///
/// # Examples (JavaScript)
///
/// ```js
/// const channel = new SignalingChannel((payload) => ws.send(payload));
/// const client = new WebClient(channel);
/// ```
#[wasm_bindgen]
pub struct SignalingChannel {
    send_fn: js_sys::Function,
}

#[wasm_bindgen]
impl SignalingChannel {
    /// Create a signaling channel backed by the JS function `send_fn`.
    ///
    /// `send_fn` is invoked with a single string argument (the signaling payload) whenever the
    /// client needs to transmit an SDP or ICE message to the peer.
    #[wasm_bindgen(constructor)]
    pub fn new(send_fn: js_sys::Function) -> SignalingChannel {
        SignalingChannel { send_fn }
    }

    /// Send `payload` to the peer via the wrapped JS function.
    ///
    /// # Errors
    ///
    /// Returns the `JsValue` thrown by the JS callback if it raises.
    #[wasm_bindgen]
    pub fn send(&self, payload: &str) -> Result<(), JsValue> {
        self.send_fn
            .call1(&JsValue::NULL, &JsValue::from_str(payload))
            .map(|_| ())
    }
}

// ── WebClient ─────────────────────────────────────────────────────────────────

/// The browser WebRTC session client.
///
/// Owns an [`web_sys::RtcPeerConnection`] and the signaling channel, and orchestrates the
/// offer/answer + DTLS-pin + DataChannel flow.  Construct with [`WebClient::new`], drive the
/// offerer side with [`WebClient::create_offer`], then connect with the pin-checked
/// [`WebClient::connect_as_offerer`] / [`WebClient::connect_as_answerer`].
#[wasm_bindgen]
pub struct WebClient {
    pc: RtcPeerConnection,
    /// Held for the session lifetime so the JS signaling callback it wraps is not dropped while
    /// the client is alive.  Not yet driven from inside this crate (the host page relays SDP/ICE
    /// today); retaining it keeps the seam available without changing ownership semantics.
    #[expect(
        dead_code,
        reason = "held to own the JS signaling callback for the client's lifetime; not read \
                  internally yet — the host page relays SDP/ICE today"
    )]
    signaling: SignalingChannel,
    /// The offerer's DataChannels: video (host→browser frames, label `"0:128:1"`, ADR-0036), input
    /// (browser→host events, label `"2:0:1"`, ADR-0036), and clipboard (browser→host paste, label
    /// `"3:2:1"`, ADR-0037). Separate SCTP streams so input is never gated by video pacing or
    /// head-of-line-blocked by a large video fragment, and clipboard is reliable+ordered.
    video_channel: Option<RtcDataChannel>,
    input_channel: Option<RtcDataChannel>,
    clipboard_channel: Option<RtcDataChannel>,
    /// The peer's DTLS pin (from the verified Noise handshake), set via [`WebClient::set_dtls_pin`].
    dtls_pin: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl WebClient {
    /// Create a new client with the given signaling channel.
    ///
    /// Builds a default-configured [`web_sys::RtcPeerConnection`] (no ICE servers — the loopback
    /// and same-LAN paths need none; STUN/TURN configuration is layered on later, see P5-2).
    ///
    /// # Errors
    ///
    /// Returns a `JsValue` if the browser fails to construct the `RTCPeerConnection`.
    #[wasm_bindgen(constructor)]
    pub fn new(signaling: SignalingChannel) -> Result<WebClient, JsValue> {
        let pc = RtcPeerConnection::new()?;
        Ok(WebClient {
            pc,
            signaling,
            video_channel: None,
            input_channel: None,
            clipboard_channel: None,
            dtls_pin: None,
        })
    }

    /// Pin the peer's DTLS fingerprint obtained from the verified Noise handshake.
    ///
    /// `pin` must be the 32-byte SHA-256 commitment returned by
    /// `WasmHandshakeOutcome::require_dtls_pin`.  [`connect_as_offerer`](Self::connect_as_offerer)
    /// and [`connect_as_answerer`](Self::connect_as_answerer) refuse to apply a remote description
    /// whose `a=fingerprint` does not match this pin.
    ///
    /// # Errors
    ///
    /// Returns a `JsValue` if `pin` is not exactly 32 bytes.
    #[wasm_bindgen]
    pub fn set_dtls_pin(&mut self, pin: &[u8]) -> Result<(), JsValue> {
        if pin.len() != SHA256_FP_LEN {
            return Err(JsError::new("DTLS pin must be exactly 32 bytes").into());
        }
        self.dtls_pin = Some(pin.to_vec());
        Ok(())
    }

    /// Extract the local SDP `a=fingerprint:sha-256` value as 32 bytes.
    ///
    /// Valid only after [`create_offer`](Self::create_offer) /
    /// [`connect_as_answerer`](Self::connect_as_answerer) has set the local description.  This is
    /// the fingerprint the client commits in its Noise `BindCert`.
    ///
    /// # Errors
    ///
    /// Returns a `JsValue` if there is no local description yet, or its SDP lacks a parseable
    /// SHA-256 fingerprint.
    #[wasm_bindgen]
    pub fn local_dtls_fingerprint(&self) -> Result<Vec<u8>, JsValue> {
        let sdp = self
            .pc
            .local_description()
            .ok_or_else(|| JsError::new("no local description set yet"))?
            .sdp();
        parse_sdp_fingerprint(&sdp)
    }

    /// Create the local SDP offer (after `createOffer` + `setLocalDescription`).
    ///
    /// Returns the offer SDP string for delivery to the peer via signaling.
    ///
    /// # Errors
    ///
    /// Returns a `JsValue` if `createOffer` or `setLocalDescription` rejects.
    #[wasm_bindgen]
    pub async fn create_offer(&mut self) -> Result<String, JsValue> {
        // At least one DataChannel must exist before createOffer so the SDP includes an
        // m=application line (and a DTLS fingerprint). We create ALL channels here (ADR-0036/0037) so
        // they share that single m=application section / SCTP association. The labels encode the
        // host's `ChannelSpec` as `channel:priority:ordered`, where `priority` is the ChannelSpec
        // scale (0 = MOST urgent, `quinn_priority = 255 - priority`): `"0:128:1"` = Video (moderate),
        // `"2:0:1"` = Input (highest urgency, matching `ChannelSpec::input()`), `"3:2:1"` = Clipboard
        // (reliable+ordered, urgency 2, matching `ChannelSpec::clipboard()`). The host routes by the
        // parsed `ChannelId` (Video = 0, Input = 2, Clipboard = 3), so these MUST match its
        // `parse_channel_label` contract — see `dedicated_input_channel_labels_route_correctly`.
        if self.video_channel.is_none() {
            self.video_channel = Some(self.pc.create_data_channel("0:128:1"));
        }
        if self.input_channel.is_none() {
            self.input_channel = Some(self.pc.create_data_channel("2:0:1"));
        }
        if self.clipboard_channel.is_none() {
            self.clipboard_channel = Some(self.pc.create_data_channel("3:2:1"));
        }
        let offer = JsFuture::from(self.pc.create_offer()).await?;
        let offer: RtcSessionDescriptionInit = offer.unchecked_into();
        JsFuture::from(self.pc.set_local_description(&offer)).await?;
        local_sdp(&self.pc)
    }

    /// Internal building block: apply a remote offer and produce the local answer.
    ///
    /// This calls `setRemoteDescription` DIRECTLY and performs **no** DTLS-pin check, so it is NOT
    /// exposed to JS (`pub(crate)`, no `#[wasm_bindgen]`).  Exposing it would let a JS caller invoke
    /// it directly and bypass the MITM defense.  The only caller is
    /// [`connect_as_answerer`](Self::connect_as_answerer), which pin-checks the offer first and is
    /// the sole supported answerer entry point.
    ///
    /// # Errors
    ///
    /// Returns a `JsValue` if any of `setRemoteDescription`, `createAnswer`, or
    /// `setLocalDescription` rejects, or `remote_offer` is not valid SDP.
    pub(crate) async fn create_answer(&mut self, remote_offer: String) -> Result<String, JsValue> {
        let remote = sdp_init(RtcSdpType::Offer, &remote_offer);
        JsFuture::from(self.pc.set_remote_description(&remote)).await?;
        let answer = JsFuture::from(self.pc.create_answer()).await?;
        let answer: RtcSessionDescriptionInit = answer.unchecked_into();
        JsFuture::from(self.pc.set_local_description(&answer)).await?;
        local_sdp(&self.pc)
    }

    /// Connect as the OFFERER side: pin-check then apply the remote SDP answer.
    ///
    /// MITM gate: if a DTLS pin has been set ([`set_dtls_pin`](Self::set_dtls_pin)), the remote
    /// answer's `a=fingerprint` is verified against it *before* `setRemoteDescription`.  On a
    /// mismatch this returns an error and the remote description is NOT applied.
    ///
    /// # Errors
    ///
    /// Returns a `JsValue` if the pin check fails (MITM rejection), or `setRemoteDescription`
    /// rejects.
    #[wasm_bindgen]
    pub async fn connect_as_offerer(&mut self, remote_sdp_answer: String) -> Result<(), JsValue> {
        self.guard_remote_sdp(&remote_sdp_answer)?;
        let remote = sdp_init(RtcSdpType::Answer, &remote_sdp_answer);
        JsFuture::from(self.pc.set_remote_description(&remote)).await?;
        Ok(())
    }

    /// Connect as the ANSWERER side: pin-check the remote offer, then produce a pinned answer.
    ///
    /// MITM gate: if a DTLS pin has been set, the remote offer's `a=fingerprint` is verified
    /// against it *before* `setRemoteDescription`.  On a mismatch this returns an error and the
    /// remote description is NOT applied (no answer is produced).  On success it sets the remote
    /// offer, creates and sets the local answer, and returns the answer SDP.
    ///
    /// # Errors
    ///
    /// Returns a `JsValue` if the pin check fails (MITM rejection), or any WebRTC step rejects.
    #[wasm_bindgen]
    pub async fn connect_as_answerer(
        &mut self,
        remote_sdp_offer: String,
    ) -> Result<String, JsValue> {
        self.guard_remote_sdp(&remote_sdp_offer)?;
        self.create_answer(remote_sdp_offer).await
    }

    /// Add a remote ICE candidate received via signaling.
    ///
    /// The candidate is associated with the single `m=application` (DataChannel) section
    /// (`sdpMid = "0"`, `sdpMLineIndex = 0`). **Firefox requires** an `sdpMid` or
    /// `sdpMLineIndex` on a remote candidate — it throws `"Cannot add a candidate without
    /// specifying either sdpMid or sdpMLineIndex"` for a bare candidate string. A browser↔native
    /// Streamhaul session always has exactly one DataChannel section at index 0, so this binding is
    /// correct (see ADR-0023 quirk #2). Chrome is lenient and accepts the explicit values too.
    ///
    /// An empty candidate string is treated as an end-of-candidates marker and is silently
    /// ignored (some browsers emit `""` to signal EOC; it carries no routable candidate).
    ///
    /// # Errors
    ///
    /// Returns a `JsValue` if the candidate is malformed or `addIceCandidate` rejects.
    #[wasm_bindgen]
    pub async fn add_ice_candidate(&self, candidate: String) -> Result<(), JsValue> {
        if candidate.is_empty() {
            return Ok(());
        }
        let init = web_sys::RtcIceCandidateInit::new(&candidate);
        init.set_sdp_mid(Some("0"));
        init.set_sdp_m_line_index(Some(0));
        let cand = web_sys::RtcIceCandidate::new(&init)?;
        JsFuture::from(
            self.pc
                .add_ice_candidate_with_opt_rtc_ice_candidate(Some(&cand)),
        )
        .await?;
        Ok(())
    }

    /// Send a message on the **Video** (primary) DataChannel.
    ///
    /// This is the primary channel: the host echoes on it (echo/MITM test), the browser sends the
    /// channel-open HELLO on it, and the host streams video on it. Browser→host **input** goes on
    /// the separate Input channel via [`send_input`](Self::send_input) (ADR-0036).
    ///
    /// The payload is opaque (already encoded by [`sh_wasm`]); its contents are never inspected here.
    ///
    /// # Errors
    ///
    /// Returns a `JsValue` if the video channel is not open, or the underlying `send` rejects.
    #[wasm_bindgen]
    pub fn send_frame(&self, frame: &[u8]) -> Result<(), JsValue> {
        let ch = self
            .video_channel
            .as_ref()
            .ok_or_else(|| JsError::new("no video DataChannel open"))?;
        ch.send_with_u8_array(frame)
    }

    /// Send a browser→host 16-byte SHP `InputEvent` on the dedicated **Input** DataChannel
    /// (ADR-0036) — a separate SCTP stream so input is never gated by video pacing or
    /// head-of-line-blocked by a large video fragment.
    ///
    /// The payload is opaque (already encoded by [`sh_wasm`]); its contents are never inspected here.
    ///
    /// # Errors
    ///
    /// Returns a `JsValue` if the input channel is not open, or the underlying `send` rejects.
    #[wasm_bindgen]
    pub fn send_input(&self, event: &[u8]) -> Result<(), JsValue> {
        let ch = self
            .input_channel
            .as_ref()
            .ok_or_else(|| JsError::new("no input DataChannel open"))?;
        ch.send_with_u8_array(event)
    }

    /// Send a browser→host `ClipboardUpdate` (`[format:u8][content]`, encoded by [`sh_wasm`]) on the
    /// dedicated reliable+ordered **Clipboard** DataChannel (ADR-0037). The host decodes, sanitizes,
    /// and applies it (paste). The payload is opaque here; its contents are never inspected.
    ///
    /// # Errors
    ///
    /// Returns a `JsValue` if the clipboard channel is not open, or the underlying `send` rejects.
    #[wasm_bindgen]
    pub fn send_clipboard(&self, update: &[u8]) -> Result<(), JsValue> {
        let ch = self
            .clipboard_channel
            .as_ref()
            .ok_or_else(|| JsError::new("no clipboard DataChannel open"))?;
        ch.send_with_u8_array(update)
    }

    /// Set a callback invoked with each received SHP video frame (`Uint8Array`) on the **Video**
    /// DataChannel (ADR-0036).
    ///
    /// The callback fires for every `message` event whose data is binary.  Text messages are
    /// ignored (SHP frames are always binary).
    ///
    /// # Errors
    ///
    /// Returns a `JsValue` if the video channel does not exist yet.
    #[wasm_bindgen]
    pub fn on_frame(&self, callback: js_sys::Function) -> Result<(), JsValue> {
        let ch = self
            .video_channel
            .as_ref()
            .ok_or_else(|| JsError::new("no video DataChannel to attach on_frame to"))?;
        let cb = Closure::<dyn FnMut(MessageEvent)>::new(move |evt: MessageEvent| {
            let data = evt.data();
            if let Ok(buf) = data.dyn_into::<js_sys::ArrayBuffer>() {
                let arr = js_sys::Uint8Array::new(&buf);
                if let Err(e) = callback.call1(&JsValue::NULL, &arr) {
                    web_sys::console::warn_1(&e);
                }
            }
        });
        ch.set_binary_type(web_sys::RtcDataChannelType::Arraybuffer);
        ch.set_onmessage(Some(cb.as_ref().unchecked_ref()));
        // Leak the closure so it outlives this call (the channel holds the only reference).  The
        // client lives for the session; this is a one-shot per-channel registration.
        cb.forget();
        Ok(())
    }

    /// Register a callback for the answerer's inbound DataChannel (`ondatachannel`).
    ///
    /// The answerer does not call `createDataChannel`; instead it receives the offerer's channel
    /// via the `datachannel` event. This callback hands the channel to `on_open` as a raw JS
    /// [`RtcDataChannel`] object; the caller drives it directly (set `onmessage`, call `send`, …)
    /// on that JS object.
    ///
    /// Note: the channel is **not** stored in this `WebClient`, so
    /// [`send_frame`](Self::send_frame) / [`send_input`](Self::send_input) / [`on_frame`](Self::on_frame)
    /// — which operate on the *offerer's* own `createDataChannel` channels — do not apply to the
    /// answerer's inbound channel. (Storing it would require `&mut self`; that lands with the P5-2
    /// answerer wiring.)
    ///
    /// Because the channel is delivered asynchronously, this takes a JS callback rather than
    /// returning the channel synchronously.
    #[wasm_bindgen]
    pub fn on_data_channel(&self, on_open: js_sys::Function) {
        let cb = Closure::<dyn FnMut(RtcDataChannelEvent)>::new(move |evt: RtcDataChannelEvent| {
            let ch = evt.channel();
            if let Err(e) = on_open.call1(&JsValue::NULL, &JsValue::from(ch)) {
                web_sys::console::warn_1(&e);
            }
        });
        self.pc.set_ondatachannel(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }

    /// Register a callback for locally-gathered ICE candidates (`onicecandidate`).
    ///
    /// Fires once per candidate with the candidate string, and once with `null` when gathering
    /// completes.  The host page relays each candidate to the peer via signaling.
    #[wasm_bindgen]
    pub fn on_ice_candidate(&self, callback: js_sys::Function) {
        let cb = Closure::<dyn FnMut(RtcPeerConnectionIceEvent)>::new(
            move |evt: RtcPeerConnectionIceEvent| {
                let result = if let Some(cand) = evt.candidate() {
                    callback.call1(&JsValue::NULL, &JsValue::from_str(&cand.candidate()))
                } else {
                    callback.call1(&JsValue::NULL, &JsValue::NULL)
                };
                if let Err(e) = result {
                    web_sys::console::warn_1(&e);
                }
            },
        );
        self.pc
            .set_onicecandidate(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }

    /// The current ICE connection state as a canonical WebRTC string.
    ///
    /// Returns one of the RFC/WHATWG `RTCIceConnectionState` values
    /// (`"new"`, `"checking"`, `"connected"`, `"completed"`, `"failed"`, `"disconnected"`,
    /// `"closed"`), or `"unknown"` for any future/unmapped variant.  The strings are spelled out
    /// explicitly (not derived from `{:?}`) so the JS API stays stable regardless of the wasm-bindgen
    /// enum's `Debug` representation.
    #[wasm_bindgen]
    pub fn ice_connection_state(&self) -> String {
        use web_sys::RtcIceConnectionState as S;
        let s = match self.pc.ice_connection_state() {
            S::New => "new",
            S::Checking => "checking",
            S::Connected => "connected",
            S::Completed => "completed",
            S::Failed => "failed",
            S::Disconnected => "disconnected",
            S::Closed => "closed",
            _ => "unknown",
        };
        s.to_owned()
    }

    /// Close the underlying [`web_sys::RtcPeerConnection`], tearing down the DTLS session, all three
    /// DataChannels (video, input, and clipboard), and all ICE transports, and release the three
    /// stored channel handles.
    ///
    /// Idempotent: calling `close()` on an already-closed connection is a no-op (the browser
    /// tolerates it).  After this, the client must not be reused — construct a new [`WebClient`]
    /// for a fresh session.  This exists so a viewer/UI can deterministically free the peer
    /// connection on disconnect rather than leaking the ICE sockets and DTLS state until GC.
    #[wasm_bindgen]
    pub fn close(&mut self) {
        self.pc.close();
        self.video_channel = None;
        self.input_channel = None;
        self.clipboard_channel = None;
    }

    // ── internal ─────────────────────────────────────────────────────────────

    /// Enforce the DTLS pin against a remote SDP.  **Fail-closed**: if no pin has been set, this
    /// returns an error rather than silently skipping the MITM check.
    ///
    /// A pin is only available after the identity-authenticated Noise handshake has completed and
    /// [`set_dtls_pin`](Self::set_dtls_pin) has been called.  Reaching a `setRemoteDescription`
    /// path without a pin means the MITM defense was bypassed (forgotten handshake / forgotten
    /// `set_dtls_pin`), so we refuse to apply any remote description.
    fn guard_remote_sdp(&self, remote_sdp: &str) -> Result<(), JsValue> {
        let pin = self.dtls_pin.as_deref().ok_or_else(|| {
            JsValue::from(js_sys::Error::new(
                "DTLS pin not set: Noise handshake must complete and set_dtls_pin must be called \
                 before applying remote SDP",
            ))
        })?;
        verify_sdp_fingerprint_pin(remote_sdp, pin)
    }
}

// ── SDP helpers ───────────────────────────────────────────────────────────────

/// Build an `RtcSessionDescriptionInit` of the given type from raw SDP text.
fn sdp_init(kind: RtcSdpType, sdp: &str) -> RtcSessionDescriptionInit {
    let init = RtcSessionDescriptionInit::new(kind);
    init.set_sdp(sdp);
    init
}

/// Read the peer connection's current local SDP, erroring if none is set.
fn local_sdp(pc: &RtcPeerConnection) -> Result<String, JsValue> {
    pc.local_description()
        .map(|d| d.sdp())
        .ok_or_else(|| JsError::new("no local description after setLocalDescription").into())
}

// ── Unit tests (no DOM required) ──────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    // Run in the browser so a single `wasm-pack test --headless --firefox` invocation covers both
    // these pure-logic SDP-parser unit tests and the `tests/browser_e2e.rs` WebRTC integration
    // suite (which requires `RTCPeerConnection`, hence Firefox).  These tests touch no DOM, so the
    // browser runner is just as valid as Node for them.
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    const SAMPLE_SDP: &str = "v=0\r\n\
o=- 0 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:\
AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
a=setup:actpass\r\n";

    #[wasm_bindgen_test]
    fn parse_known_fingerprint() {
        let fp = crate::parse_sdp_fingerprint_inner(SAMPLE_SDP).unwrap();
        assert_eq!(fp.len(), 32);
        assert_eq!(fp[0], 0xAA);
        assert_eq!(fp[1], 0xBB);
        assert_eq!(fp[31], 0x99);
    }

    #[wasm_bindgen_test]
    fn host_seam_matches_inner_parser() {
        // The `parse_sdp_fingerprint_host` fuzz seam must stay a pure delegate to the real parser,
        // so the nightly fuzzer exercises production logic — not a drifted copy. Lock that contract.
        assert_eq!(
            crate::parse_sdp_fingerprint_host(SAMPLE_SDP),
            crate::parse_sdp_fingerprint_inner(SAMPLE_SDP),
            "host seam must return exactly what the inner parser returns on valid SDP"
        );
        assert_eq!(
            crate::parse_sdp_fingerprint_host("v=0\r\ns=-\r\n"),
            crate::parse_sdp_fingerprint_inner("v=0\r\ns=-\r\n"),
            "host seam must propagate the inner parser's error verbatim"
        );
        // And it satisfies the fuzz target's invariant directly.
        assert_eq!(
            crate::parse_sdp_fingerprint_host(SAMPLE_SDP).unwrap().len(),
            32
        );
    }

    #[wasm_bindgen_test]
    fn parse_lowercase_alg_token() {
        let sdp = SAMPLE_SDP.replace("sha-256", "SHA-256");
        let fp = crate::parse_sdp_fingerprint_inner(&sdp).unwrap();
        assert_eq!(fp.len(), 32);
    }

    #[wasm_bindgen_test]
    fn missing_fingerprint_is_err() {
        assert!(crate::parse_sdp_fingerprint_inner("v=0\r\ns=-\r\n").is_err());
    }

    #[wasm_bindgen_test]
    fn truncated_fingerprint_is_err() {
        let sdp = "a=fingerprint:sha-256 AA:BB:CC\r\n";
        assert!(crate::parse_sdp_fingerprint_inner(sdp).is_err());
    }

    #[wasm_bindgen_test]
    fn non_hex_fingerprint_is_err() {
        let sdp = "a=fingerprint:sha-256 ZZ:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:\
                   AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n";
        assert!(crate::parse_sdp_fingerprint_inner(sdp).is_err());
    }

    #[wasm_bindgen_test]
    fn one_char_group_is_err() {
        let sdp = "a=fingerprint:sha-256 A:BB\r\n";
        assert!(crate::parse_sdp_fingerprint_inner(sdp).is_err());
    }

    #[wasm_bindgen_test]
    fn empty_input_is_err() {
        assert!(crate::parse_sdp_fingerprint_inner("").is_err());
    }

    #[wasm_bindgen_test]
    fn oversized_sdp_is_err() {
        // A blob larger than MAX_SDP_BYTES must be rejected before any scanning, even if it would
        // otherwise contain a valid fingerprint line.
        let mut sdp = String::new();
        sdp.push_str(SAMPLE_SDP);
        while sdp.len() <= crate::MAX_SDP_BYTES {
            sdp.push('x');
        }
        assert!(sdp.len() > crate::MAX_SDP_BYTES);
        assert!(crate::parse_sdp_fingerprint_inner(&sdp).is_err());
    }

    #[wasm_bindgen_test]
    fn at_limit_sdp_is_ok() {
        // Exactly MAX_SDP_BYTES must still be scanned (the cap rejects only strictly-larger input).
        let mut sdp = String::from(SAMPLE_SDP);
        // Pad with comment-like filler lines that the parser ignores, up to the cap.
        while sdp.len() < crate::MAX_SDP_BYTES {
            sdp.push('\n');
        }
        sdp.truncate(crate::MAX_SDP_BYTES);
        assert_eq!(sdp.len(), crate::MAX_SDP_BYTES);
        assert!(crate::parse_sdp_fingerprint_inner(&sdp).is_ok());
    }

    #[wasm_bindgen_test]
    fn valueless_fingerprint_line_is_skipped_not_fatal() {
        // A `a=fingerprint:` line with no value must NOT abort the parse; a later well-formed
        // SHA-256 line must still be found (consistent with wrong-algorithm line handling).
        let sdp = "a=fingerprint:\r\n\
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:\
AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n";
        let fp = crate::parse_sdp_fingerprint_inner(sdp).unwrap();
        assert_eq!(fp.len(), 32);
        assert_eq!(fp[0], 0xAA);
    }

    #[wasm_bindgen_test]
    fn valueless_sha256_fingerprint_line_is_skipped_not_fatal() {
        // Even a `a=fingerprint:sha-256` line with no whitespace+value must be skipped (not fatal),
        // so a later well-formed line still resolves.
        let sdp = "a=fingerprint:sha-256\r\n\
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:\
AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n";
        let fp = crate::parse_sdp_fingerprint_inner(sdp).unwrap();
        assert_eq!(fp.len(), 32);
    }
}
