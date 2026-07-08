#![deny(missing_docs)]
//! `sh-wasm` — WebAssembly wire-parity bridge for the Streamhaul Protocol (SHP).
//!
//! This crate exposes the SHP wire codec from [`sh_protocol`] to browser JavaScript via
//! [`wasm_bindgen`].  The source of truth for every codec stays in `sh-protocol`; this bridge
//! only marshals between the Rust types and JS-friendly representations (`Uint8Array`, JS
//! objects, `JsError`).
//!
//! # Design constraints
//!
//! - **No panics in production paths.** Every wrapper that receives network bytes from JS maps
//!   [`sh_protocol::ProtocolError`] → [`wasm_bindgen::JsError`] and returns `Err(_)` rather
//!   than calling `unwrap/expect/panic`.
//! - **Hostile input safe.** All `decode_*` wrappers accept `&[u8]` from the network and
//!   propagate malformed-input errors as JS exceptions rather than trapping.
//! - **Zero non-wasm deps.** This crate depends only on `sh-protocol`, `sh-types`, and
//!   `wasm-bindgen`.  No `tokio`, `quinn`, `str0m`, or other non-wasm-compatible crates.
//! - **Wire parity proven by `wasm-pack test --node`.** See [`tests`] module.  The same
//!   byte vectors used by `sh-protocol`'s native golden tests are decoded here to prove the
//!   browser codec is byte-for-byte identical to the native wire format.
//!
//! # What is deferred
//!
//! The live browser client over `web-sys` `RTCPeerConnection`/`DataChannel` (live SDP
//! offer/answer wiring, H.264 decode and render, input-event capture to the host) is deferred
//! to P5-1 second half / P5-2.  That work requires a browser with WebDriver (Chrome/Firefox/
//! Safari) which is not available in this build environment.  See ADR-0019 and Risk Register
//! entries `R-BROWSER-INTEROP` and `R-BROWSER-MATRIX`.

use wasm_bindgen::prelude::*;

// ── Internal helper ─────────────────────────────────────────────────────────

/// Convert a [`sh_protocol::ProtocolError`] into a JS-throwable [`JsError`].
///
/// This is the single mapping point so every decode wrapper handles errors uniformly.
fn proto_err(e: sh_protocol::ProtocolError) -> JsError {
    JsError::new(&e.to_string())
}

// ── CommonHeader bridge ──────────────────────────────────────────────────────

/// A decoded SHP common header (9-byte wire prefix on every SHP packet).
///
/// Obtain via [`decode_common_header`].  Field accessors expose each decoded value to
/// JavaScript.  The struct is always produced by decoding; there is no JS constructor
/// because the browser side always *receives* headers, never constructs them from scratch.
#[wasm_bindgen]
pub struct WasmCommonHeader {
    inner: sh_protocol::CommonHeader,
}

#[wasm_bindgen]
impl WasmCommonHeader {
    /// The logical channel discriminant byte (matches `ChannelId` wire values).
    #[wasm_bindgen(getter)]
    pub fn channel(&self) -> u8 {
        u8::from(self.inner.channel)
    }

    /// Whether the fragmentation flag is set.
    #[wasm_bindgen(getter)]
    pub fn fragment(&self) -> bool {
        self.inner.flags.fragment
    }

    /// Whether the last-fragment flag is set.
    #[wasm_bindgen(getter)]
    pub fn last_fragment(&self) -> bool {
        self.inner.flags.last_fragment
    }

    /// Per-channel sequence number (wraps at 2^16).
    #[wasm_bindgen(getter)]
    pub fn sequence(&self) -> u16 {
        self.inner.sequence
    }

    /// Timestamp in microseconds since the session epoch (low 32 bits only — wire field).
    ///
    /// Only the low 32 bits are recovered from the 32-bit wire field; the in-memory `u64`
    /// value is always `<= u32::MAX` after decoding.
    #[wasm_bindgen(getter)]
    pub fn timestamp_us(&self) -> u32 {
        // The wire TIMESTAMP field is 32 bits; `decode` stores it as `u64::from(u32::…)` so the
        // value is always <= u32::MAX.  The truncating cast is safe by the decode invariant.
        #[allow(clippy::cast_possible_truncation)]
        let ts = self.inner.timestamp_us.0 as u32;
        ts
    }

    /// Length in bytes of the payload following this header.
    #[wasm_bindgen(getter)]
    pub fn payload_len(&self) -> u16 {
        self.inner.payload_len
    }
}

/// Decode the 9-byte SHP common header from `data`.
///
/// Returns a [`WasmCommonHeader`] on success, or throws a `JsError` describing the
/// protocol violation on malformed input (truncated, unknown version, invalid channel).
///
/// # Errors
///
/// Throws a `JsError` if `data` is shorter than 9 bytes, the version bits are not `0b01`,
/// or the channel bits do not map to a known channel.
#[wasm_bindgen]
pub fn decode_common_header(data: &[u8]) -> Result<WasmCommonHeader, JsError> {
    sh_protocol::CommonHeader::decode(data)
        .map(|inner| WasmCommonHeader { inner })
        .map_err(proto_err)
}

// ── VideoHeader bridge ───────────────────────────────────────────────────────

/// A decoded SHP video payload header (12-byte, follows the common header on the video channel).
///
/// Obtain via [`decode_video_header`].
#[wasm_bindgen]
pub struct WasmVideoHeader {
    inner: sh_protocol::VideoHeader,
}

#[wasm_bindgen]
impl WasmVideoHeader {
    /// Monotonic frame counter (24-bit wire field, returned as `u32`).
    #[wasm_bindgen(getter)]
    pub fn frame_id(&self) -> u32 {
        // The wire FRAME_ID field is 24 bits; decode validates <= MAX_FRAME_ID (0x00FF_FFFF),
        // which fits in u32.  The truncating cast is safe by the decode invariant.
        #[allow(clippy::cast_possible_truncation)]
        let id = self.inner.frame_id.0 as u32;
        id
    }

    /// Fragment index within this frame (0-based).
    #[wasm_bindgen(getter)]
    pub fn frag_index(&self) -> u8 {
        self.inner.frag_index
    }

    /// Total fragment count for this frame.
    #[wasm_bindgen(getter)]
    pub fn total_frags(&self) -> u8 {
        self.inner.total_frags
    }

    /// Codec discriminant: 0=H264, 1=H265, 2=AV1, 3=Raw.
    #[wasm_bindgen(getter)]
    pub fn codec(&self) -> u8 {
        match self.inner.codec {
            sh_protocol::Codec::H264 => 0,
            sh_protocol::Codec::H265 => 1,
            sh_protocol::Codec::Av1 => 2,
            sh_protocol::Codec::Raw => 3,
        }
    }

    /// Frame type discriminant: 0=Predicted, 1=IDR, 2=IntraRefresh.
    #[wasm_bindgen(getter)]
    pub fn frame_type(&self) -> u8 {
        match self.inner.frame_type {
            sh_protocol::FrameType::Predicted => 0,
            sh_protocol::FrameType::Idr => 1,
            sh_protocol::FrameType::IntraRefresh => 2,
        }
    }

    /// Priority: 0=DropEligible, 1=Normal, 2=High.
    #[wasm_bindgen(getter)]
    pub fn priority(&self) -> u8 {
        match self.inner.priority {
            sh_protocol::Priority::DropEligible => 0,
            sh_protocol::Priority::Normal => 1,
            sh_protocol::Priority::High => 2,
        }
    }

    /// Source monitor index (4-bit wire field).
    #[wasm_bindgen(getter)]
    pub fn monitor_id(&self) -> u8 {
        self.inner.monitor_id
    }

    /// RTP-marker-analogue: `true` on the last fragment of a frame.
    #[wasm_bindgen(getter)]
    pub fn marker(&self) -> bool {
        self.inner.marker
    }

    /// Encoder capture timestamp in microseconds (low 32 bits only — wire field).
    #[wasm_bindgen(getter)]
    pub fn encode_ts_us(&self) -> u32 {
        // The wire ENCODE_TS field is 32 bits; `decode` stores it as `u64::from(u32::…)` so the
        // value is always <= u32::MAX.  The truncating cast is safe by the decode invariant.
        #[allow(clippy::cast_possible_truncation)]
        let ts = self.inner.encode_ts_us.0 as u32;
        ts
    }
}

/// Decode the 12-byte SHP video payload header from `data`.
///
/// Returns a [`WasmVideoHeader`] on success, or throws a `JsError` on malformed input.
///
/// # Errors
///
/// Throws a `JsError` if `data` is shorter than 12 bytes, reserved bits are set, or any
/// field holds an unknown discriminant.
#[wasm_bindgen]
pub fn decode_video_header(data: &[u8]) -> Result<WasmVideoHeader, JsError> {
    sh_protocol::VideoHeader::decode(data)
        .map(|inner| WasmVideoHeader { inner })
        .map_err(proto_err)
}

// ── InputEvent bridge ────────────────────────────────────────────────────────

/// Encode an SHP input event to its 16-byte wire form for transmission to the host.
///
/// The browser captures keyboard/mouse/touch/pen events and encodes them with this function
/// before sending over the DataChannel.
///
/// All pointer coordinates must be normalized to `0..=65535` across the source surface.
/// Scroll deltas are in pixels × 8 (fixed-point signed).
///
/// # Parameters
///
/// - `event_type`: 0=PointerMove, 1=Button, 2=Wheel, 3=Key, 4=Touch, 5=Pen.
/// - `modifiers`: bitmask — bit 0=Shift, 1=Ctrl, 2=Alt, 3=Meta, 4=Caps.
/// - `pointer_x`, `pointer_y`: normalized pointer position `0..=65535`.
/// - `button_mask`: pressed-button bitmask.
/// - `key_code`: USB HID usage ID (for Key events).
/// - `scroll_x`, `scroll_y`: scroll deltas in px×8 (signed).
/// - `pressure`: stylus/touch pressure `0..=255`.
///
/// # Errors
///
/// Throws a `JsError` if `event_type` is not a known value (0–5).
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn encode_input_event(
    event_type: u8,
    modifiers: u8,
    pointer_x: u16,
    pointer_y: u16,
    button_mask: u8,
    key_code: u16,
    scroll_x: i16,
    scroll_y: i16,
    pressure: u8,
) -> Result<Vec<u8>, JsError> {
    let event_type = event_type_from_u8(event_type)?;
    let event = sh_protocol::InputEvent {
        event_type,
        modifiers: sh_protocol::Modifiers::from_bits_retain(modifiers),
        pointer_x,
        pointer_y,
        button_mask,
        key_code,
        scroll_x,
        scroll_y,
        pressure,
    };
    Ok(event.encode().to_vec())
}

/// Encode a browser→host clipboard-paste `ClipboardUpdate` (`[format:u8][content]`) for the
/// dedicated Clipboard DataChannel (ADR-0037). v1 is `text/plain` (UTF-8) only.
///
/// The host decodes, **sanitizes** (paste-injection hardening), and applies this. The TS never
/// serializes the wire format — it calls this so the browser and host share one codec.
///
/// # Errors
///
/// Throws a `JsError` if `text` exceeds the 256 KiB clipboard bound (`MAX_CLIPBOARD_BYTES`).
#[wasm_bindgen]
pub fn encode_clipboard_text(text: &str) -> Result<Vec<u8>, JsError> {
    let update = sh_protocol::ClipboardUpdate::text(text)
        .map_err(|e| JsError::new(&format!("clipboard text too large: {e}")))?;
    Ok(update.encode())
}

/// Decode a host→browser `ClipboardUpdate` off the Clipboard channel and return the **sanitized**
/// text safe to write to the browser clipboard, or `undefined` when there is nothing safe to apply
/// (malformed bytes, a non-text format, or content that sanitizes to empty) — ADR-0037.
///
/// Host clipboard content is untrusted (a hostile/compromised host could craft a hostile paste), so
/// this runs the SAME paste-injection hardening the host applies to browser→host pastes
/// (`sh_clipboard::sanitize_for_paste`): control/bidi/invisible stripping + line-ending
/// normalization. The caller writes the returned string to `navigator.clipboard` only when it is
/// present. Never throws: any malformed input yields `undefined`, never a panic (the wire decoder is
/// total and fuzzed).
#[wasm_bindgen]
pub fn decode_and_sanitize_clipboard(data: &[u8]) -> Option<String> {
    let update = sh_protocol::ClipboardUpdate::decode(data).ok()?;
    let text = update.as_text()?;
    sh_clipboard::sanitize_for_paste(text)
}

/// Decode the 16-byte SHP input event from `data`.
///
/// Returns field values via a flat struct.  Primarily used for testing wire parity.
///
/// # Errors
///
/// Throws a `JsError` if `data` is shorter than 16 bytes, the event type is unknown, or
/// the reserved bytes are non-zero.
#[wasm_bindgen]
pub fn decode_input_event(data: &[u8]) -> Result<WasmInputEvent, JsError> {
    sh_protocol::InputEvent::decode(data)
        .map(|inner| WasmInputEvent { inner })
        .map_err(proto_err)
}

/// A decoded SHP input event.  Obtain via [`decode_input_event`].
#[wasm_bindgen]
pub struct WasmInputEvent {
    inner: sh_protocol::InputEvent,
}

#[wasm_bindgen]
impl WasmInputEvent {
    /// Event type discriminant: 0=PointerMove, 1=Button, 2=Wheel, 3=Key, 4=Touch, 5=Pen.
    #[wasm_bindgen(getter)]
    pub fn event_type(&self) -> u8 {
        match self.inner.event_type {
            sh_protocol::EventType::PointerMove => 0,
            sh_protocol::EventType::Button => 1,
            sh_protocol::EventType::Wheel => 2,
            sh_protocol::EventType::Key => 3,
            sh_protocol::EventType::Touch => 4,
            sh_protocol::EventType::Pen => 5,
        }
    }

    /// Modifier bitmask (bit 0=Shift, 1=Ctrl, 2=Alt, 3=Meta, 4=Caps).
    #[wasm_bindgen(getter)]
    pub fn modifiers(&self) -> u8 {
        self.inner.modifiers.bits()
    }

    /// Pointer X normalized to `0..=65535`.
    #[wasm_bindgen(getter)]
    pub fn pointer_x(&self) -> u16 {
        self.inner.pointer_x
    }

    /// Pointer Y normalized to `0..=65535`.
    #[wasm_bindgen(getter)]
    pub fn pointer_y(&self) -> u16 {
        self.inner.pointer_y
    }

    /// Pressed-button bitmask.
    #[wasm_bindgen(getter)]
    pub fn button_mask(&self) -> u8 {
        self.inner.button_mask
    }

    /// USB HID usage ID (Key events).
    #[wasm_bindgen(getter)]
    pub fn key_code(&self) -> u16 {
        self.inner.key_code
    }

    /// Horizontal scroll delta in pixels × 8 (signed).
    #[wasm_bindgen(getter)]
    pub fn scroll_x(&self) -> i16 {
        self.inner.scroll_x
    }

    /// Vertical scroll delta in pixels × 8 (signed).
    #[wasm_bindgen(getter)]
    pub fn scroll_y(&self) -> i16 {
        self.inner.scroll_y
    }

    /// Stylus/touch pressure `0..=255`.
    #[wasm_bindgen(getter)]
    pub fn pressure(&self) -> u8 {
        self.inner.pressure
    }
}

// ── NackFeedback bridge ──────────────────────────────────────────────────────

/// Encode a NACK feedback message to its 25-byte wire form.
///
/// The browser reports reception statistics and missing sequence numbers to the host by
/// encoding a `NackFeedback` and sending it over the feedback DataChannel.
///
/// # Parameters
///
/// - `report_type`: application-defined type byte; 0 = standard.
/// - `ssrc`: synchronization source identifier.
/// - `highest_seq`: highest sequence number received.
/// - `cumulative_lost`: total packets lost (24-bit max = 16 777 215).
/// - `fraction_lost`: fraction lost in last interval (0–255 RTCP encoding).
/// - `jitter_us`: interarrival jitter estimate in microseconds.
/// - `rtt_us`: round-trip time estimate in microseconds.
/// - `bwe_kbps`: bandwidth estimate in kbps.
/// - `nack_bitmap`: 16-bit missing-packet bitmap.
///
/// # Errors
///
/// Throws a `JsError` if `cumulative_lost` exceeds the 24-bit maximum (16 777 215).
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn encode_nack_feedback(
    report_type: u8,
    ssrc: u32,
    highest_seq: u16,
    cumulative_lost: u32,
    fraction_lost: u8,
    jitter_us: u32,
    rtt_us: u32,
    bwe_kbps: u32,
    nack_bitmap: u16,
) -> Result<Vec<u8>, JsError> {
    let fb = sh_protocol::NackFeedback {
        report_type,
        ssrc,
        highest_seq,
        cumulative_lost,
        fraction_lost,
        jitter_us,
        rtt_us,
        bwe_kbps,
        nack_bitmap,
    };
    fb.encode().map(|arr| arr.to_vec()).map_err(proto_err)
}

/// Decode a 25-byte NACK feedback message from `data`.
///
/// Returns a [`WasmNackFeedback`] on success.
///
/// # Errors
///
/// Throws a `JsError` if `data` is shorter than 25 bytes.
#[wasm_bindgen]
pub fn decode_nack_feedback(data: &[u8]) -> Result<WasmNackFeedback, JsError> {
    sh_protocol::NackFeedback::decode(data)
        .map(|inner| WasmNackFeedback { inner })
        .map_err(proto_err)
}

/// A decoded NACK feedback message.  Obtain via [`decode_nack_feedback`].
#[wasm_bindgen]
pub struct WasmNackFeedback {
    inner: sh_protocol::NackFeedback,
}

#[wasm_bindgen]
impl WasmNackFeedback {
    /// Application-defined report type byte.
    #[wasm_bindgen(getter)]
    pub fn report_type(&self) -> u8 {
        self.inner.report_type
    }

    /// Synchronization source identifier.
    #[wasm_bindgen(getter)]
    pub fn ssrc(&self) -> u32 {
        self.inner.ssrc
    }

    /// Highest sequence number received.
    #[wasm_bindgen(getter)]
    pub fn highest_seq(&self) -> u16 {
        self.inner.highest_seq
    }

    /// Cumulative packets lost (24-bit field).
    #[wasm_bindgen(getter)]
    pub fn cumulative_lost(&self) -> u32 {
        self.inner.cumulative_lost
    }

    /// Fraction lost (0–255 RTCP encoding).
    #[wasm_bindgen(getter)]
    pub fn fraction_lost(&self) -> u8 {
        self.inner.fraction_lost
    }

    /// Interarrival jitter in microseconds.
    #[wasm_bindgen(getter)]
    pub fn jitter_us(&self) -> u32 {
        self.inner.jitter_us
    }

    /// Round-trip time in microseconds.
    #[wasm_bindgen(getter)]
    pub fn rtt_us(&self) -> u32 {
        self.inner.rtt_us
    }

    /// Bandwidth estimate in kbps.
    #[wasm_bindgen(getter)]
    pub fn bwe_kbps(&self) -> u32 {
        self.inner.bwe_kbps
    }

    /// 16-bit NACK bitmap.
    #[wasm_bindgen(getter)]
    pub fn nack_bitmap(&self) -> u16 {
        self.inner.nack_bitmap
    }
}

// ── Codec capability bridge ──────────────────────────────────────────────────

/// Encode a codec capability payload to its 4-byte wire form.
///
/// Used during the capability handshake.  A browser always sets `is_browser = true` and
/// sets `hw_decode_mask` bit 0 (H.264) to advertise native H.264 decode via the WebRTC
/// stack.
///
/// # Errors
///
/// Throws a `JsError` if `hw_encode_mask` or `hw_decode_mask` have reserved bits set
/// (bits 3–7), or if `selected_codec` is not a recognized discriminant (0–2) or 0xFF.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn encode_caps(
    hw_encode_mask: u8,
    hw_decode_mask: u8,
    sw_h264_encode_available: bool,
    is_apple: bool,
    is_browser: bool,
    selected_codec: u8,
) -> Result<Vec<u8>, JsError> {
    let selected = if selected_codec == 0xFF {
        None
    } else {
        Some(selected_codec)
    };
    let payload = sh_protocol::capability::CodecCapsPayload {
        hw_encode_mask,
        hw_decode_mask,
        sw_h264_encode_available,
        is_apple,
        is_browser,
        selected_codec: selected,
    };
    sh_protocol::capability::encode_caps(&payload)
        .map(|arr| arr.to_vec())
        .map_err(proto_err)
}

/// Decode a 4-byte codec capability payload from `data`.
///
/// Returns a [`WasmCodecCaps`] on success.
///
/// # Errors
///
/// Throws a `JsError` if `data` is shorter than 4 bytes, reserved bits are set, or
/// `selected_codec` is an unknown discriminant.
#[wasm_bindgen]
pub fn decode_caps(data: &[u8]) -> Result<WasmCodecCaps, JsError> {
    sh_protocol::capability::decode_caps(data)
        .map(|inner| WasmCodecCaps { inner })
        .map_err(proto_err)
}

/// A decoded codec capability payload.  Obtain via [`decode_caps`].
#[wasm_bindgen]
pub struct WasmCodecCaps {
    inner: sh_protocol::capability::CodecCapsPayload,
}

#[wasm_bindgen]
impl WasmCodecCaps {
    /// Bitmask of hardware-encode-capable codec discriminants (bits 0–2).
    #[wasm_bindgen(getter)]
    pub fn hw_encode_mask(&self) -> u8 {
        self.inner.hw_encode_mask
    }

    /// Bitmask of hardware-decode-capable codec discriminants (bits 0–2).
    #[wasm_bindgen(getter)]
    pub fn hw_decode_mask(&self) -> u8 {
        self.inner.hw_decode_mask
    }

    /// Whether software H.264 encode is available.
    #[wasm_bindgen(getter)]
    pub fn sw_h264_encode_available(&self) -> bool {
        self.inner.sw_h264_encode_available
    }

    /// Whether this is an Apple (VideoToolbox) host.
    #[wasm_bindgen(getter)]
    pub fn is_apple(&self) -> bool {
        self.inner.is_apple
    }

    /// Whether this peer is a browser.
    #[wasm_bindgen(getter)]
    pub fn is_browser(&self) -> bool {
        self.inner.is_browser
    }

    /// Negotiated codec discriminant, or 0xFF if none selected / this is an offer.
    #[wasm_bindgen(getter)]
    pub fn selected_codec(&self) -> u8 {
        self.inner.selected_codec.unwrap_or(0xFF)
    }
}

// ── TransportCaps bridge ─────────────────────────────────────────────────────

/// Encode a transport capabilities payload to its 2-byte wire form.
///
/// A browser that only supports WebRTC would set `supports_quic = false`,
/// `supports_webrtc = true`.
#[wasm_bindgen]
pub fn encode_transport_caps(supports_quic: bool, supports_webrtc: bool) -> Vec<u8> {
    let caps = sh_protocol::transport_caps::TransportCaps {
        supports_quic,
        supports_webrtc,
    };
    sh_protocol::transport_caps::encode_transport_caps(&caps).to_vec()
}

/// Decode a 2-byte transport capabilities payload from `data`.
///
/// Returns a [`WasmTransportCaps`] on success.
///
/// # Errors
///
/// Throws a `JsError` if `data` is shorter than 2 bytes or the version byte is not `0x01`.
#[wasm_bindgen]
pub fn decode_transport_caps(data: &[u8]) -> Result<WasmTransportCaps, JsError> {
    sh_protocol::transport_caps::decode_transport_caps(data)
        .map(|inner| WasmTransportCaps { inner })
        .map_err(proto_err)
}

/// A decoded transport capability set.  Obtain via [`decode_transport_caps`].
#[wasm_bindgen]
pub struct WasmTransportCaps {
    inner: sh_protocol::transport_caps::TransportCaps,
}

#[wasm_bindgen]
impl WasmTransportCaps {
    /// Whether QUIC is supported.
    #[wasm_bindgen(getter)]
    pub fn supports_quic(&self) -> bool {
        self.inner.supports_quic
    }

    /// Whether WebRTC is supported.
    #[wasm_bindgen(getter)]
    pub fn supports_webrtc(&self) -> bool {
        self.inner.supports_webrtc
    }
}

/// Negotiate a transport from two capability sets.
///
/// Applies the global preference order (QUIC > WebRTC).  Returns 0 for QUIC, 1 for WebRTC.
///
/// # Errors
///
/// Throws a `JsError` if there is no transport in common between the two capability sets.
#[wasm_bindgen]
pub fn negotiate_transport(
    local_quic: bool,
    local_webrtc: bool,
    peer_quic: bool,
    peer_webrtc: bool,
) -> Result<u8, JsError> {
    let local = sh_protocol::transport_caps::TransportCaps {
        supports_quic: local_quic,
        supports_webrtc: local_webrtc,
    };
    let peer = sh_protocol::transport_caps::TransportCaps {
        supports_quic: peer_quic,
        supports_webrtc: peer_webrtc,
    };
    sh_protocol::transport_caps::negotiate(local, peer)
        .map(|kind| match kind {
            sh_types::TransportKind::Quic => 0,
            sh_types::TransportKind::Webrtc => 1,
        })
        .map_err(|e| JsError::new(&e.to_string()))
}

// ── File-transfer framing bridge (sh-protocol::file, P7-2 — ADR-0024) ─────────
//
// Pure wire bridge: every function delegates to `sh_protocol::file`, which is fuzzed and never
// panics on hostile input. The TS file module (`clients/web/src/file/`) wraps these encoders /
// decoders and mirrors the `sh-core` orchestrator's stateful validation — but the *bytes* are
// always produced and parsed here, never re-implemented in TypeScript.

/// Encode a [`FileOffer`](sh_protocol::file::FileOffer) to its wire form
/// (`transfer_id u64 | total_size u64 | chunk_size u32 | sha256[32] | name_len u8 | name`).
///
/// `transfer_id` and `total_size` are passed as `f64` because JavaScript numbers are doubles;
/// callers MUST keep them `<= 2^53` (the safe-integer range) — `BigInt` is intentionally avoided
/// to match the existing bridge's plain-`number` surface. `sha256` must be exactly 32 bytes.
///
/// # Errors
///
/// Throws a `JsError` if `sha256` is not 32 bytes, `chunk_size` is `0` or above
/// [`MAX_FILE_CHUNK`](sh_protocol::file::MAX_FILE_CHUNK), `name` exceeds
/// [`MAX_FILE_NAME`](sh_protocol::file::MAX_FILE_NAME) bytes, or `transfer_id`/`total_size` are
/// negative / non-integral.
#[wasm_bindgen]
pub fn encode_file_offer(
    transfer_id: f64,
    total_size: f64,
    chunk_size: u32,
    sha256: &[u8],
    name: &[u8],
) -> Result<Vec<u8>, JsError> {
    let transfer_id = u64_from_f64(transfer_id, "transfer_id")?;
    let total_size = u64_from_f64(total_size, "total_size")?;
    let sha = sha256_from_slice(sha256)?;
    let offer = sh_protocol::file::FileOffer {
        transfer_id,
        total_size,
        chunk_size,
        sha256: sha,
        name: name.to_vec(),
    };
    offer.encode().map_err(proto_err)
}

/// Decode a [`FileOffer`](sh_protocol::file::FileOffer) from `data`.
///
/// Returns a [`WasmFileOffer`] on success.
///
/// # Errors
///
/// Throws a `JsError` if `data` is truncated, `chunk_size` is out of range, or the declared name
/// length runs past the buffer.
#[wasm_bindgen]
pub fn decode_file_offer(data: &[u8]) -> Result<WasmFileOffer, JsError> {
    let inner = sh_protocol::file::FileOffer::decode(data).map_err(proto_err)?;
    ensure_safe_u64(inner.transfer_id, "transfer_id")?;
    ensure_safe_u64(inner.total_size, "total_size")?;
    Ok(WasmFileOffer { inner })
}

/// A decoded [`FileOffer`](sh_protocol::file::FileOffer). Obtain via [`decode_file_offer`].
#[wasm_bindgen]
pub struct WasmFileOffer {
    inner: sh_protocol::file::FileOffer,
}

#[wasm_bindgen]
impl WasmFileOffer {
    /// Opaque transfer identifier (returned as `f64`; always a safe integer for real transfers).
    #[wasm_bindgen(getter)]
    pub fn transfer_id(&self) -> f64 {
        self.inner.transfer_id as f64
    }

    /// Total file size in bytes (returned as `f64`).
    #[wasm_bindgen(getter)]
    pub fn total_size(&self) -> f64 {
        self.inner.total_size as f64
    }

    /// Intended chunk payload size in bytes.
    #[wasm_bindgen(getter)]
    pub fn chunk_size(&self) -> u32 {
        self.inner.chunk_size
    }

    /// SHA-256 digest of the whole file (32 bytes).
    #[wasm_bindgen(getter)]
    pub fn sha256(&self) -> Vec<u8> {
        self.inner.sha256.to_vec()
    }

    /// File-name bytes (opaque; the caller mirrors the `sh-core` sanitizer).
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> Vec<u8> {
        self.inner.name.clone()
    }
}

/// Encode a [`FileChunkHeader`](sh_protocol::file::FileChunkHeader) to its fixed 21-byte wire form
/// (`transfer_id u64 | offset u64 | len u32 | flags u8`). The payload bytes follow this header on
/// the wire but are NOT included here.
///
/// # Errors
///
/// Throws a `JsError` if `len` is `0` or above [`MAX_FILE_CHUNK`](sh_protocol::file::MAX_FILE_CHUNK),
/// or `transfer_id`/`offset` are negative / non-integral.
#[wasm_bindgen]
pub fn encode_file_chunk_header(
    transfer_id: f64,
    offset: f64,
    len: u32,
    last: bool,
) -> Result<Vec<u8>, JsError> {
    let transfer_id = u64_from_f64(transfer_id, "transfer_id")?;
    let offset = u64_from_f64(offset, "offset")?;
    let header = sh_protocol::file::FileChunkHeader {
        transfer_id,
        offset,
        len,
        last,
    };
    header.encode().map(|arr| arr.to_vec()).map_err(proto_err)
}

/// Decode the fixed 21-byte [`FileChunkHeader`](sh_protocol::file::FileChunkHeader) from `data`
/// (the payload, if any, is whatever follows the first 21 bytes — not parsed here).
///
/// Returns a [`WasmFileChunkHeader`] on success.
///
/// # Errors
///
/// Throws a `JsError` if `data` is shorter than 21 bytes, `len` is out of range, or a reserved flag
/// bit is set.
#[wasm_bindgen]
pub fn decode_file_chunk_header(data: &[u8]) -> Result<WasmFileChunkHeader, JsError> {
    let inner = sh_protocol::file::FileChunkHeader::decode(data).map_err(proto_err)?;
    ensure_safe_u64(inner.transfer_id, "transfer_id")?;
    ensure_safe_u64(inner.offset, "offset")?;
    Ok(WasmFileChunkHeader { inner })
}

/// A decoded [`FileChunkHeader`](sh_protocol::file::FileChunkHeader). Obtain via
/// [`decode_file_chunk_header`].
#[wasm_bindgen]
pub struct WasmFileChunkHeader {
    inner: sh_protocol::file::FileChunkHeader,
}

#[wasm_bindgen]
impl WasmFileChunkHeader {
    /// The transfer this chunk belongs to (returned as `f64`).
    #[wasm_bindgen(getter)]
    pub fn transfer_id(&self) -> f64 {
        self.inner.transfer_id as f64
    }

    /// Byte offset of this chunk's payload within the file (returned as `f64`).
    #[wasm_bindgen(getter)]
    pub fn offset(&self) -> f64 {
        self.inner.offset as f64
    }

    /// Payload length in bytes following this header.
    //
    // `len` mirrors the wire field name; it is a scalar accessor, not a collection length, so the
    // `is_empty` companion clippy expects is not meaningful here.
    #[wasm_bindgen(getter)]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u32 {
        self.inner.len
    }

    /// True if this is the last chunk of the transfer.
    #[wasm_bindgen(getter)]
    pub fn last(&self) -> bool {
        self.inner.last
    }
}

/// Encode a [`FileAccept`](sh_protocol::file::FileAccept) to its 16-byte wire form
/// (`transfer_id u64 | resume_offset u64`).
///
/// # Errors
///
/// Throws a `JsError` if `transfer_id`/`resume_offset` are negative or non-integral.
#[wasm_bindgen]
pub fn encode_file_accept(transfer_id: f64, resume_offset: f64) -> Result<Vec<u8>, JsError> {
    let transfer_id = u64_from_f64(transfer_id, "transfer_id")?;
    let resume_offset = u64_from_f64(resume_offset, "resume_offset")?;
    let accept = sh_protocol::file::FileAccept {
        transfer_id,
        resume_offset,
    };
    Ok(accept.encode().to_vec())
}

/// Decode a [`FileAccept`](sh_protocol::file::FileAccept) from `data`.
///
/// Returns a [`WasmFileAccept`] on success.
///
/// # Errors
///
/// Throws a `JsError` if `data` is shorter than 16 bytes.
#[wasm_bindgen]
pub fn decode_file_accept(data: &[u8]) -> Result<WasmFileAccept, JsError> {
    let inner = sh_protocol::file::FileAccept::decode(data).map_err(proto_err)?;
    ensure_safe_u64(inner.transfer_id, "transfer_id")?;
    ensure_safe_u64(inner.resume_offset, "resume_offset")?;
    Ok(WasmFileAccept { inner })
}

/// A decoded [`FileAccept`](sh_protocol::file::FileAccept). Obtain via [`decode_file_accept`].
#[wasm_bindgen]
pub struct WasmFileAccept {
    inner: sh_protocol::file::FileAccept,
}

#[wasm_bindgen]
impl WasmFileAccept {
    /// The offered transfer id being accepted (returned as `f64`).
    #[wasm_bindgen(getter)]
    pub fn transfer_id(&self) -> f64 {
        self.inner.transfer_id as f64
    }

    /// Byte offset to resume from (returned as `f64`).
    #[wasm_bindgen(getter)]
    pub fn resume_offset(&self) -> f64 {
        self.inner.resume_offset as f64
    }
}

/// Encode a [`FileComplete`](sh_protocol::file::FileComplete) to its 9-byte wire form
/// (`transfer_id u64 | ok u8`).
///
/// # Errors
///
/// Throws a `JsError` if `transfer_id` is negative or non-integral.
#[wasm_bindgen]
pub fn encode_file_complete(transfer_id: f64, ok: bool) -> Result<Vec<u8>, JsError> {
    let transfer_id = u64_from_f64(transfer_id, "transfer_id")?;
    let complete = sh_protocol::file::FileComplete { transfer_id, ok };
    Ok(complete.encode().to_vec())
}

/// Decode a [`FileComplete`](sh_protocol::file::FileComplete) from `data`.
///
/// Returns a [`WasmFileComplete`] on success.
///
/// # Errors
///
/// Throws a `JsError` if `data` is shorter than 9 bytes or the `ok` byte is not `0`/`1`.
#[wasm_bindgen]
pub fn decode_file_complete(data: &[u8]) -> Result<WasmFileComplete, JsError> {
    let inner = sh_protocol::file::FileComplete::decode(data).map_err(proto_err)?;
    ensure_safe_u64(inner.transfer_id, "transfer_id")?;
    Ok(WasmFileComplete { inner })
}

/// A decoded [`FileComplete`](sh_protocol::file::FileComplete). Obtain via [`decode_file_complete`].
#[wasm_bindgen]
pub struct WasmFileComplete {
    inner: sh_protocol::file::FileComplete,
}

#[wasm_bindgen]
impl WasmFileComplete {
    /// The completed transfer (returned as `f64`).
    #[wasm_bindgen(getter)]
    pub fn transfer_id(&self) -> f64 {
        self.inner.transfer_id as f64
    }

    /// Whether the integrity check passed.
    #[wasm_bindgen(getter)]
    pub fn ok(&self) -> bool {
        self.inner.ok
    }
}

// ── Internal helpers (not exported to JS) ───────────────────────────────────

/// Convert a JS `f64` to a `u64`, rejecting negative, non-integral, or out-of-range values.
///
/// The bridge surface uses plain `number` (doubles) for the 64-bit file fields rather than
/// `BigInt`; this guards the (lossless) narrowing so a hostile / buggy caller cannot smuggle a
/// fractional or negative value into a wire `u64`. The accepted range is **enforced** at the JS
/// safe-integer ceiling (`2^53 - 1` = `Number.MAX_SAFE_INTEGER`): above that, an `f64` can no
/// longer represent consecutive integers, so a value could only have arrived already rounded — we
/// reject it rather than silently encoding a corrupted `u64` (this also closes the `2^64 as f64`
/// rounds-up-and-saturates edge). 2^53 bytes (~9 PB) is far above any practical browser transfer.
const MAX_SAFE_U64_F64: f64 = 9_007_199_254_740_991.0; // 2^53 - 1 (Number.MAX_SAFE_INTEGER)

fn u64_from_f64(value: f64, field: &str) -> Result<u64, JsError> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > MAX_SAFE_U64_F64 {
        return Err(JsError::new(&format!(
            "invalid {field}: {value}; expected a non-negative integer <= 2^53-1"
        )));
    }
    // Guarded above: finite, non-negative, integral, and within the JS safe-integer range.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(value as u64)
}

/// Reject a wire `u64` that cannot round-trip through a JS `f64` (`> 2^53 - 1`).
///
/// The decode getters return `u64 as f64`; above the safe-integer ceiling that cast silently rounds,
/// so a re-encode of the rounded value would emit a different `u64` (e.g. a `FileAccept` echoing a
/// host's `transfer_id` would mismatch). We reject such values at the decode boundary so decode is
/// symmetric with [`u64_from_f64`]. A browser transfer can never legitimately exceed this (the
/// aggregate cap is ~64 MiB), so this only rejects malformed/hostile offers.
fn ensure_safe_u64(value: u64, field: &str) -> Result<(), JsError> {
    // 2^53 - 1 = Number.MAX_SAFE_INTEGER, the same ceiling `u64_from_f64` enforces on encode.
    const MAX_SAFE_U64: u64 = 9_007_199_254_740_991;
    if value > MAX_SAFE_U64 {
        return Err(JsError::new(&format!(
            "decoded {field} {value} exceeds the JS safe-integer ceiling (2^53-1)"
        )));
    }
    Ok(())
}

/// Convert a JS byte slice into the fixed 32-byte SHA-256 array, rejecting any other length.
fn sha256_from_slice(sha256: &[u8]) -> Result<[u8; 32], JsError> {
    <[u8; 32]>::try_from(sha256).map_err(|_| {
        JsError::new(&format!(
            "invalid sha256: {} bytes; expected exactly 32",
            sha256.len()
        ))
    })
}

fn event_type_from_u8(byte: u8) -> Result<sh_protocol::EventType, JsError> {
    match byte {
        0 => Ok(sh_protocol::EventType::PointerMove),
        1 => Ok(sh_protocol::EventType::Button),
        2 => Ok(sh_protocol::EventType::Wheel),
        3 => Ok(sh_protocol::EventType::Key),
        4 => Ok(sh_protocol::EventType::Touch),
        5 => Ok(sh_protocol::EventType::Pen),
        other => Err(JsError::new(&format!(
            "invalid event type: {other}; expected 0–5"
        ))),
    }
}

// ── Wire-parity tests (wasm-pack test --node) ────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    // Configure the test runner to use Node.js (no browser required).
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_node_experimental);

    // ── Golden byte vectors ──────────────────────────────────────────────────
    //
    // These byte arrays are taken verbatim from the native golden tests in
    // `sh-protocol` (common.rs, video.rs, input.rs, feedback.rs, capability.rs,
    // transport_caps.rs).  Decoding the same bytes here in wasm proves byte-for-byte
    // wire parity with the native host codec.

    /// Golden bytes for CommonHeader (from `sh-protocol::common::tests::known_layout_roundtrips`)
    /// VER=01, CHANNEL=Input(2), FLAGS=fragment → byte0 = 0x4A
    const COMMON_GOLDEN: [u8; 9] = [0x4A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    /// Golden bytes for VideoHeader (from `sh-protocol::video::tests::known_layout_roundtrips`)
    /// frame_id=0xABCDEF, frag_index=3, total_frags=7, codec=H265(1), frame_type=Idr(1),
    /// priority=High(2), monitor_id=0xA, marker=true, encode_ts=0xDEADBEEF
    /// byte5 = CODEC_ID(4)=0001 | FRAME_TYPE(2)=01 | PRIORITY(2)=10 = 0x16
    /// byte6 = MONITOR(4)=1010 | MARKER(1)=1 | RESERVED(3)=000 = 0xA8
    const VIDEO_GOLDEN: [u8; 12] = [
        0xAB, 0xCD, 0xEF, // frame_id 24-bit
        3, 7,    // frag_index, total_frags
        0x16, // byte5: codec=H265(1) ft=Idr(1) pri=High(2)
        0xA8, // byte6: monitor=0xA marker=1
        0x00, // reserved
        0xDE, 0xAD, 0xBE, 0xEF, // encode_ts
    ];

    /// Golden bytes for InputEvent (Key, CTRL|SHIFT)
    /// byte0=3(Key), byte1=0b0000_0011(CTRL|SHIFT), px=0x1234, py=0x5678,
    /// button_mask=5, key_code=0x0004, scroll_x=-3→0xFFFD, scroll_y=40→0x0028,
    /// pressure=200, reserved=0x00,0x00
    const INPUT_GOLDEN: [u8; 16] = [
        3,           // EventType::Key
        0b0000_0011, // Modifiers: CTRL | SHIFT
        0x12,
        0x34, // pointer_x = 0x1234
        0x56,
        0x78,        // pointer_y = 0x5678
        0b0000_0101, // button_mask
        0x00,
        0x04, // key_code = HID 'a'
        0xFF,
        0xFD, // scroll_x = -3 (big-endian i16)
        0x00,
        0x28, // scroll_y = 40
        200,  // pressure
        0x00,
        0x00, // reserved
    ];

    /// Golden bytes for NackFeedback (from feedback.rs roundtrip_basic)
    /// report_type=0, ssrc=0xDEADBEEF, highest_seq=1000, cumulative_lost=42,
    /// fraction_lost=5, jitter_us=1500, rtt_us=25000, bwe_kbps=2048, nack_bitmap=0x0003
    const NACK_GOLDEN: [u8; 25] = [
        0x00, // report_type
        0xDE, 0xAD, 0xBE, 0xEF, // ssrc
        0x03, 0xE8, // highest_seq = 1000
        0x00, 0x00, 0x2A, // cumulative_lost = 42 (24-bit)
        5,    // fraction_lost
        0x00, 0x00, 0x05, 0xDC, // jitter_us = 1500
        0x00, 0x00, 0x61, 0xA8, // rtt_us = 25000
        0x00, 0x00, 0x08, 0x00, // bwe_kbps = 2048
        0x00, 0x03, // nack_bitmap = 3
    ];

    /// Golden bytes for CodecCapsPayload (browser offer: hw_decode_mask=0b0101 H264+AV1,
    /// is_browser=true, no hw_encode, sw_h264=false, selected_codec=None(0xFF))
    const CAPS_GOLDEN: [u8; 4] = [
        0b0000_0000, // hw_encode_mask: none
        0b0000_0101, // hw_decode_mask: H264(bit0) + AV1(bit2)
        0b0000_0100, // FLAGS: is_browser bit 2
        0xFF,        // selected_codec: None (offer)
    ];

    /// Golden bytes for TransportCaps (QUIC + WebRTC)
    /// byte0=VERSION(0x01), byte1=QUIC(bit0)|WebRTC(bit1) = 0x03
    const TRANSPORT_GOLDEN: [u8; 2] = [0x01, 0x03];

    // ── CommonHeader parity tests ────────────────────────────────────────────

    #[wasm_bindgen_test]
    fn common_header_golden_bytes_decode() {
        let h = crate::decode_common_header(&COMMON_GOLDEN).unwrap();
        // channel = Input = 2
        assert_eq!(h.channel(), 2, "channel should be Input (2)");
        assert!(h.fragment(), "fragment flag should be set");
        assert!(!h.last_fragment(), "last_fragment flag should not be set");
        assert_eq!(h.sequence(), 0x0102);
        assert_eq!(h.timestamp_us(), 0x0304_0506);
        assert_eq!(h.payload_len(), 0x0708);
    }

    #[wasm_bindgen_test]
    fn common_header_encode_decode_roundtrip() {
        // Verify the native encoder produces COMMON_GOLDEN — proves the WASM decoder
        // accepts bytes byte-identical to what the native host would send.
        use sh_protocol::{CommonHeader, Flags};
        use sh_types::{ChannelId, TimestampUs};
        let h = CommonHeader {
            channel: ChannelId::Input,
            flags: Flags {
                fragment: true,
                last_fragment: false,
            },
            sequence: 0x0102,
            timestamp_us: TimestampUs(0x0304_0506),
            payload_len: 0x0708,
        };
        let encoded = h.encode();
        assert_eq!(
            encoded, COMMON_GOLDEN,
            "native encode must match golden bytes"
        );
        let decoded = crate::decode_common_header(&encoded).unwrap();
        assert_eq!(decoded.channel(), 2);
        assert_eq!(decoded.sequence(), 0x0102);
        assert_eq!(decoded.timestamp_us(), 0x0304_0506);
        assert_eq!(decoded.payload_len(), 0x0708);
    }

    #[wasm_bindgen_test]
    fn common_header_truncated_is_js_error() {
        // 8 bytes — one short; must return an error (not trap/panic).
        let result = crate::decode_common_header(&[0u8; 8]);
        assert!(result.is_err(), "truncated common header must return error");
    }

    #[wasm_bindgen_test]
    fn common_header_bad_version_is_js_error() {
        // Version bits 0b11 (0xC0) != 0b01 (SHP_VERSION).
        let bad = [0xC0u8, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = crate::decode_common_header(&bad);
        assert!(result.is_err(), "bad version must return error");
    }

    #[wasm_bindgen_test]
    fn common_header_unknown_channel_is_js_error() {
        // VER=01, CHANNEL=1111(15), FLAGS=00 → 0x7C
        let bad = [0x7Cu8, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = crate::decode_common_header(&bad);
        assert!(result.is_err(), "unknown channel must return error");
    }

    #[wasm_bindgen_test]
    fn common_header_empty_is_js_error() {
        let result = crate::decode_common_header(&[]);
        assert!(result.is_err(), "empty input must return error");
    }

    // ── VideoHeader parity tests ─────────────────────────────────────────────

    #[wasm_bindgen_test]
    fn video_header_golden_bytes_decode() {
        let h = crate::decode_video_header(&VIDEO_GOLDEN).unwrap();
        assert_eq!(h.frame_id(), 0x00AB_CDEF);
        assert_eq!(h.frag_index(), 3);
        assert_eq!(h.total_frags(), 7);
        assert_eq!(h.codec(), 1, "codec should be H265 (1)");
        assert_eq!(h.frame_type(), 1, "frame_type should be IDR (1)");
        assert_eq!(h.priority(), 2, "priority should be High (2)");
        assert_eq!(h.monitor_id(), 0x0A);
        assert!(h.marker(), "marker should be set");
        assert_eq!(h.encode_ts_us(), 0xDEAD_BEEF);
    }

    #[wasm_bindgen_test]
    fn video_header_native_encode_matches_golden() {
        // Native encoder output must equal VIDEO_GOLDEN — proves wasm decode is byte-identical.
        use sh_protocol::{Codec, FrameType, Priority, VideoHeader};
        use sh_types::{FrameId, TimestampUs};
        let h = VideoHeader {
            frame_id: FrameId(0x00AB_CDEF),
            frag_index: 3,
            total_frags: 7,
            codec: Codec::H265,
            frame_type: FrameType::Idr,
            priority: Priority::High,
            monitor_id: 0x0A,
            marker: true,
            encode_ts_us: TimestampUs(0xDEAD_BEEF),
        };
        let encoded = h.encode().unwrap();
        assert_eq!(
            encoded, VIDEO_GOLDEN,
            "native encode must match golden bytes"
        );
    }

    #[wasm_bindgen_test]
    fn video_header_truncated_is_js_error() {
        let result = crate::decode_video_header(&[0u8; 11]);
        assert!(result.is_err(), "11-byte video header must return error");
    }

    #[wasm_bindgen_test]
    fn video_header_invalid_codec_is_js_error() {
        // byte5 codec nibble = 0xF (15) — unassigned
        let mut bad = [0u8; 12];
        bad[5] = 0xF0;
        let result = crate::decode_video_header(&bad);
        assert!(result.is_err(), "invalid codec nibble must return error");
    }

    #[wasm_bindgen_test]
    fn video_header_reserved_bits_set_is_js_error() {
        let mut bad = [0u8; 12];
        bad[7] = 1; // reserved byte must be zero
        let result = crate::decode_video_header(&bad);
        assert!(result.is_err(), "reserved bits set must return error");
    }

    // ── ClipboardUpdate parity tests ─────────────────────────────────────────

    #[wasm_bindgen_test]
    fn clipboard_text_encode_matches_codec() {
        // The wasm encoder must produce exactly what the Rust codec produces, and re-decode.
        let bytes = crate::encode_clipboard_text("hello, 世界 🌍").unwrap();
        let expected = sh_protocol::ClipboardUpdate::text("hello, 世界 🌍")
            .unwrap()
            .encode();
        assert_eq!(
            bytes, expected,
            "wasm clipboard encode must match the Rust codec"
        );
        let decoded = sh_protocol::ClipboardUpdate::decode(&bytes).unwrap();
        assert_eq!(decoded.as_text(), Some("hello, 世界 🌍"));
        // Wire layout: format byte 0 (Text) then UTF-8 content.
        assert_eq!(bytes.first(), Some(&0u8), "format byte must be 0 (Text)");
    }

    #[wasm_bindgen_test]
    fn clipboard_text_encode_rejects_oversize() {
        let big = "a".repeat(sh_protocol::MAX_CLIPBOARD_BYTES + 1);
        assert!(
            crate::encode_clipboard_text(&big).is_err(),
            "text over the 256 KiB bound must be rejected"
        );
    }

    #[wasm_bindgen_test]
    fn decode_and_sanitize_clipboard_roundtrips_and_hardens() {
        // A host→browser update decodes and is sanitized (CRLF→LF, ESC stripped).
        let wire = crate::encode_clipboard_text("host\r\nclip\u{1b}[0m").unwrap();
        assert_eq!(
            crate::decode_and_sanitize_clipboard(&wire),
            Some("host\nclip[0m".to_owned())
        );
    }

    #[wasm_bindgen_test]
    fn decode_and_sanitize_clipboard_rejects_malformed_and_all_control() {
        // Malformed bytes → None, never a panic.
        assert_eq!(crate::decode_and_sanitize_clipboard(&[]), None);
        assert_eq!(crate::decode_and_sanitize_clipboard(&[0xFF, b'x']), None);
        // All-control content sanitizes to empty → None (nothing safe to write).
        let wire = crate::encode_clipboard_text("\u{1b}\u{202e}\u{200b}").unwrap();
        assert_eq!(crate::decode_and_sanitize_clipboard(&wire), None);
    }

    // ── InputEvent parity tests ──────────────────────────────────────────────

    #[wasm_bindgen_test]
    fn input_event_encode_matches_golden() {
        let bytes = crate::encode_input_event(
            3,           // Key
            0b0000_0011, // CTRL | SHIFT
            0x1234,      // pointer_x
            0x5678,      // pointer_y
            0b0000_0101, // button_mask
            0x0004,      // key_code
            -3,          // scroll_x
            40,          // scroll_y
            200,         // pressure
        )
        .unwrap();
        assert_eq!(bytes.len(), 16, "input event must be 16 bytes");
        assert_eq!(
            &bytes[..],
            &INPUT_GOLDEN[..],
            "encoded bytes must match golden"
        );
    }

    #[wasm_bindgen_test]
    fn input_event_roundtrip() {
        let bytes =
            crate::encode_input_event(3, 0b0000_0011, 0x1234, 0x5678, 5, 4, -3, 40, 200).unwrap();
        let decoded = crate::decode_input_event(&bytes).unwrap();
        assert_eq!(decoded.event_type(), 3);
        assert_eq!(decoded.modifiers(), 0b0000_0011);
        assert_eq!(decoded.pointer_x(), 0x1234);
        assert_eq!(decoded.pointer_y(), 0x5678);
        assert_eq!(decoded.key_code(), 4);
        assert_eq!(decoded.scroll_x(), -3);
        assert_eq!(decoded.scroll_y(), 40);
        assert_eq!(decoded.pressure(), 200);
    }

    #[wasm_bindgen_test]
    fn input_event_native_encode_matches_wasm_encode() {
        // Prove native and wasm produce identical bytes for the same input.
        use sh_protocol::{EventType, InputEvent, Modifiers};
        let native = InputEvent {
            event_type: EventType::Key,
            modifiers: Modifiers::CTRL | Modifiers::SHIFT,
            pointer_x: 0x1234,
            pointer_y: 0x5678,
            button_mask: 0b0000_0101,
            key_code: 0x0004,
            scroll_x: -3,
            scroll_y: 40,
            pressure: 200,
        }
        .encode();
        let wasm_bytes =
            crate::encode_input_event(3, 0b0000_0011, 0x1234, 0x5678, 5, 4, -3, 40, 200).unwrap();
        assert_eq!(
            native.to_vec(),
            wasm_bytes,
            "native and wasm encode must be byte-identical"
        );
    }

    #[wasm_bindgen_test]
    fn input_event_unknown_event_type_is_js_error() {
        // event_type = 9 is unassigned.
        let result = crate::encode_input_event(9, 0, 0, 0, 0, 0, 0, 0, 0);
        assert!(result.is_err(), "unknown event type must return error");
    }

    #[wasm_bindgen_test]
    fn input_event_truncated_decode_is_js_error() {
        let result = crate::decode_input_event(&[0u8; 15]);
        assert!(result.is_err(), "truncated input event must return error");
    }

    #[wasm_bindgen_test]
    fn input_event_reserved_bytes_set_is_js_error() {
        let mut bad = INPUT_GOLDEN;
        bad[14] = 1; // reserved byte
        let result = crate::decode_input_event(&bad);
        assert!(result.is_err(), "reserved bytes set must return error");
    }

    // ── NackFeedback parity tests ────────────────────────────────────────────

    #[wasm_bindgen_test]
    fn nack_feedback_encode_matches_golden() {
        let bytes = crate::encode_nack_feedback(
            0,
            0xDEAD_BEEF,
            1000,
            42,
            5,
            1500,
            25_000,
            2048,
            0b0000_0011,
        )
        .unwrap();
        assert_eq!(bytes.len(), 25, "nack must be 25 bytes");
        assert_eq!(
            &bytes[..],
            &NACK_GOLDEN[..],
            "encoded bytes must match golden"
        );
    }

    #[wasm_bindgen_test]
    fn nack_feedback_roundtrip() {
        let bytes = crate::encode_nack_feedback(0, 0xDEAD_BEEF, 1000, 42, 5, 1500, 25_000, 2048, 3)
            .unwrap();
        let decoded = crate::decode_nack_feedback(&bytes).unwrap();
        assert_eq!(decoded.report_type(), 0);
        assert_eq!(decoded.ssrc(), 0xDEAD_BEEF);
        assert_eq!(decoded.highest_seq(), 1000);
        assert_eq!(decoded.cumulative_lost(), 42);
        assert_eq!(decoded.fraction_lost(), 5);
        assert_eq!(decoded.jitter_us(), 1500);
        assert_eq!(decoded.rtt_us(), 25_000);
        assert_eq!(decoded.bwe_kbps(), 2048);
        assert_eq!(decoded.nack_bitmap(), 3);
    }

    #[wasm_bindgen_test]
    fn nack_feedback_native_encode_matches_wasm_encode() {
        use sh_protocol::NackFeedback;
        let native = NackFeedback {
            report_type: 0,
            ssrc: 0xDEAD_BEEF,
            highest_seq: 1000,
            cumulative_lost: 42,
            fraction_lost: 5,
            jitter_us: 1500,
            rtt_us: 25_000,
            bwe_kbps: 2048,
            nack_bitmap: 3,
        }
        .encode()
        .unwrap();
        let wasm_bytes =
            crate::encode_nack_feedback(0, 0xDEAD_BEEF, 1000, 42, 5, 1500, 25_000, 2048, 3)
                .unwrap();
        assert_eq!(
            native.to_vec(),
            wasm_bytes,
            "native and wasm nack encode must be byte-identical"
        );
    }

    #[wasm_bindgen_test]
    fn nack_feedback_cumulative_lost_overflow_is_js_error() {
        // 24-bit max = 0x00FF_FFFF = 16777215; 16777216 exceeds it.
        let result = crate::encode_nack_feedback(0, 0, 0, 16_777_216, 0, 0, 0, 0, 0);
        assert!(
            result.is_err(),
            "cumulative_lost overflow must return error"
        );
    }

    #[wasm_bindgen_test]
    fn nack_feedback_truncated_decode_is_js_error() {
        let result = crate::decode_nack_feedback(&[0u8; 10]);
        assert!(result.is_err(), "truncated nack must return error");
    }

    // ── CodecCaps parity tests ───────────────────────────────────────────────

    #[wasm_bindgen_test]
    fn caps_encode_browser_offer_matches_golden() {
        // Browser offer: hw_encode_mask=0, hw_decode_mask=0b0101 (H264+AV1),
        // is_browser=true, selected_codec=None(0xFF)
        let bytes = crate::encode_caps(0b0000_0000, 0b0000_0101, false, false, true, 0xFF).unwrap();
        assert_eq!(bytes.len(), 4, "caps payload must be 4 bytes");
        assert_eq!(
            &bytes[..],
            &CAPS_GOLDEN[..],
            "browser offer must match golden"
        );
    }

    #[wasm_bindgen_test]
    fn caps_roundtrip() {
        let bytes = crate::encode_caps(0b0000_0100, 0b0000_0101, true, false, true, 0xFF).unwrap();
        let decoded = crate::decode_caps(&bytes).unwrap();
        assert_eq!(decoded.hw_encode_mask(), 0b0000_0100);
        assert_eq!(decoded.hw_decode_mask(), 0b0000_0101);
        assert!(decoded.sw_h264_encode_available());
        assert!(!decoded.is_apple());
        assert!(decoded.is_browser());
        assert_eq!(decoded.selected_codec(), 0xFF, "no codec selected");
    }

    #[wasm_bindgen_test]
    fn caps_native_encode_matches_wasm_encode() {
        use sh_protocol::capability::{encode_caps, CodecCapsPayload};
        let payload = CodecCapsPayload {
            hw_encode_mask: 0,
            hw_decode_mask: 0b0000_0101,
            sw_h264_encode_available: false,
            is_apple: false,
            is_browser: true,
            selected_codec: None,
        };
        let native = encode_caps(&payload).unwrap();
        let wasm_bytes =
            crate::encode_caps(0b0000_0000, 0b0000_0101, false, false, true, 0xFF).unwrap();
        assert_eq!(
            native.to_vec(),
            wasm_bytes,
            "native and wasm caps encode must be byte-identical"
        );
    }

    #[wasm_bindgen_test]
    fn caps_selected_h264_answer() {
        // Answer with H264 selected
        let bytes = crate::encode_caps(0, 0b0000_0001, false, false, true, 0).unwrap();
        let decoded = crate::decode_caps(&bytes).unwrap();
        assert_eq!(decoded.selected_codec(), 0, "should select H264 (0)");
    }

    #[wasm_bindgen_test]
    fn caps_reserved_bits_is_js_error() {
        // hw_encode_mask with reserved bits set (bit 3 = Raw — not a negotiable codec)
        let result = crate::encode_caps(0b0000_1000, 0, false, false, false, 0xFF);
        assert!(
            result.is_err(),
            "reserved bits in encode mask must return error"
        );
    }

    #[wasm_bindgen_test]
    fn caps_truncated_decode_is_js_error() {
        let result = crate::decode_caps(&[0u8; 3]);
        assert!(result.is_err(), "truncated caps must return error");
    }

    #[wasm_bindgen_test]
    fn caps_invalid_selected_codec_is_js_error() {
        // Discriminant 5 is unassigned.
        let result = crate::decode_caps(&[0, 0, 0, 5]);
        assert!(result.is_err(), "invalid selected_codec must return error");
    }

    // ── TransportCaps parity tests ───────────────────────────────────────────

    #[wasm_bindgen_test]
    fn transport_caps_encode_matches_golden() {
        let bytes = crate::encode_transport_caps(true, true);
        assert_eq!(bytes.len(), 2, "transport caps must be 2 bytes");
        assert_eq!(
            &bytes[..],
            &TRANSPORT_GOLDEN[..],
            "encoded bytes must match golden"
        );
    }

    #[wasm_bindgen_test]
    fn transport_caps_roundtrip() {
        let bytes = crate::encode_transport_caps(false, true);
        let decoded = crate::decode_transport_caps(&bytes).unwrap();
        assert!(!decoded.supports_quic());
        assert!(decoded.supports_webrtc());
    }

    #[wasm_bindgen_test]
    fn transport_caps_native_encode_matches_wasm_encode() {
        use sh_protocol::transport_caps::{encode_transport_caps, TransportCaps};
        let caps = TransportCaps {
            supports_quic: true,
            supports_webrtc: true,
        };
        let native = encode_transport_caps(&caps);
        let wasm_bytes = crate::encode_transport_caps(true, true);
        assert_eq!(
            native.to_vec(),
            wasm_bytes,
            "native and wasm transport caps encode must be byte-identical"
        );
    }

    #[wasm_bindgen_test]
    fn transport_caps_truncated_is_js_error() {
        let result = crate::decode_transport_caps(&[0x01]);
        assert!(
            result.is_err(),
            "truncated transport caps must return error"
        );
    }

    #[wasm_bindgen_test]
    fn transport_caps_bad_version_is_js_error() {
        let result = crate::decode_transport_caps(&[0x02, 0x03]);
        assert!(result.is_err(), "bad version must return error");
    }

    // ── Negotiate parity tests ───────────────────────────────────────────────

    #[wasm_bindgen_test]
    fn negotiate_both_prefer_quic() {
        // Both support all → QUIC wins (preference order)
        let result = crate::negotiate_transport(true, true, true, true).unwrap();
        assert_eq!(result, 0, "QUIC (0) must be preferred");
    }

    #[wasm_bindgen_test]
    fn negotiate_webrtc_fallback() {
        // Local: QUIC+WebRTC, peer: WebRTC-only → WebRTC selected
        let result = crate::negotiate_transport(true, true, false, true).unwrap();
        assert_eq!(
            result, 1,
            "WebRTC (1) must be fallback when peer has no QUIC"
        );
    }

    #[wasm_bindgen_test]
    fn negotiate_no_common_is_js_error() {
        // Local: QUIC only, peer: WebRTC only → no common transport
        let result = crate::negotiate_transport(true, false, false, true);
        assert!(result.is_err(), "no common transport must return error");
    }

    #[wasm_bindgen_test]
    fn negotiate_symmetry() {
        // negotiate(a,b) == negotiate(b,a) for all inputs
        let cases = [
            (true, true, true, true),
            (true, false, false, true),
            (false, true, true, false),
            (true, true, false, true),
        ];
        for (lq, lw, pq, pw) in cases {
            let ab = crate::negotiate_transport(lq, lw, pq, pw);
            let ba = crate::negotiate_transport(pq, pw, lq, lw);
            match (ab, ba) {
                (Ok(x), Ok(y)) => assert_eq!(x, y, "negotiate must be symmetric"),
                (Err(_), Err(_)) => {} // symmetric failure — correct
                _ => panic!("negotiate symmetry violated for ({lq},{lw},{pq},{pw})"),
            }
        }
    }

    // ── Hostile-input tests ──────────────────────────────────────────────────

    #[wasm_bindgen_test]
    fn all_decoders_handle_empty_input() {
        // Every decoder must return Err, never trap.
        assert!(crate::decode_common_header(&[]).is_err());
        assert!(crate::decode_video_header(&[]).is_err());
        assert!(crate::decode_input_event(&[]).is_err());
        assert!(crate::decode_nack_feedback(&[]).is_err());
        assert!(crate::decode_caps(&[]).is_err());
        assert!(crate::decode_transport_caps(&[]).is_err());
    }

    #[wasm_bindgen_test]
    fn all_decoders_handle_oversized_garbage() {
        // 256 bytes of 0xFF — must return Err (not trap) for every decoder.
        let garbage = [0xFFu8; 256];
        assert!(crate::decode_common_header(&garbage).is_err());
        assert!(crate::decode_video_header(&garbage).is_err());
        assert!(crate::decode_input_event(&garbage).is_err());
        // NackFeedback: 0xFF bytes — report_type is fine (u8), but cumulative_lost is only
        // checked on *encode*, not decode; decode accepts any 25 bytes. So we check only
        // that it does NOT trap.
        let _ = crate::decode_nack_feedback(&garbage);
        // Caps: hw_encode_mask=0xFF has reserved bits set → error.
        assert!(crate::decode_caps(&[0xFF, 0xFF, 0xFF, 0xFF]).is_err());
        // TransportCaps: version 0xFF != 0x01 → error.
        assert!(crate::decode_transport_caps(&[0xFF, 0xFF]).is_err());
    }

    #[wasm_bindgen_test]
    fn single_byte_inputs_never_trap() {
        // One byte each — all must return Err for the length-gated decoders.
        assert!(crate::decode_common_header(&[0x40]).is_err());
        assert!(crate::decode_video_header(&[0xAB]).is_err());
        assert!(crate::decode_input_event(&[3]).is_err());
        assert!(crate::decode_nack_feedback(&[0]).is_err());
        assert!(crate::decode_caps(&[0]).is_err());
        assert!(crate::decode_transport_caps(&[0x01]).is_err());
    }

    // ── File-transfer framing parity tests (P7-2) ────────────────────────────

    #[wasm_bindgen_test]
    fn file_offer_native_encode_matches_wasm_encode() {
        // Prove the wasm bridge produces bytes byte-identical to the native `sh-protocol` encoder.
        use sh_protocol::file::FileOffer;
        let sha = [0xABu8; 32];
        let native = FileOffer {
            transfer_id: 0x0102_0304_0506,
            total_size: 4096,
            chunk_size: 1024,
            sha256: sha,
            name: b"report.pdf".to_vec(),
        }
        .encode()
        .unwrap();
        let wasm_bytes = crate::encode_file_offer(
            0x0102_0304_0506_u64 as f64,
            4096.0,
            1024,
            &sha,
            b"report.pdf",
        )
        .unwrap();
        assert_eq!(
            native, wasm_bytes,
            "native and wasm file-offer encode must be byte-identical"
        );
    }

    #[wasm_bindgen_test]
    fn file_offer_roundtrip() {
        let sha = [0x11u8; 32];
        let bytes = crate::encode_file_offer(7.0, 12_345.0, 4096, &sha, b"notes.txt").unwrap();
        let decoded = crate::decode_file_offer(&bytes).unwrap();
        assert_eq!(decoded.transfer_id(), 7.0);
        assert_eq!(decoded.total_size(), 12_345.0);
        assert_eq!(decoded.chunk_size(), 4096);
        assert_eq!(decoded.sha256(), sha.to_vec());
        assert_eq!(decoded.name(), b"notes.txt".to_vec());
    }

    #[wasm_bindgen_test]
    fn file_offer_bad_sha_len_is_js_error() {
        // 31-byte digest must be rejected (wire field is exactly 32).
        let result = crate::encode_file_offer(1.0, 1.0, 16, &[0u8; 31], b"f");
        assert!(result.is_err(), "short sha256 must return error");
    }

    #[wasm_bindgen_test]
    fn file_offer_zero_chunk_size_is_js_error() {
        let result = crate::encode_file_offer(1.0, 1.0, 0, &[0u8; 32], b"f");
        assert!(result.is_err(), "zero chunk_size must return error");
    }

    #[wasm_bindgen_test]
    fn file_offer_oversized_chunk_size_is_js_error() {
        let too_big = sh_protocol::file::MAX_FILE_CHUNK + 1;
        let result = crate::encode_file_offer(1.0, 1.0, too_big, &[0u8; 32], b"f");
        assert!(result.is_err(), "oversized chunk_size must return error");
    }

    #[wasm_bindgen_test]
    fn file_offer_negative_id_is_js_error() {
        let result = crate::encode_file_offer(-1.0, 1.0, 16, &[0u8; 32], b"f");
        assert!(result.is_err(), "negative transfer_id must return error");
    }

    #[wasm_bindgen_test]
    fn file_offer_fractional_size_is_js_error() {
        let result = crate::encode_file_offer(1.0, 1.5, 16, &[0u8; 32], b"f");
        assert!(result.is_err(), "fractional total_size must return error");
    }

    #[wasm_bindgen_test]
    fn file_offer_above_safe_integer_is_js_error() {
        // 2^53 is the first integer an f64 can no longer represent consecutively; reject it (and
        // anything larger, incl. the `2^64 as f64` saturating edge) rather than encode a corrupt
        // u64.
        let two_pow_53 = 9_007_199_254_740_992.0; // 2^53
        assert!(
            crate::encode_file_offer(1.0, two_pow_53, 16, &[0u8; 32], b"f").is_err(),
            "total_size above 2^53-1 must return error"
        );
        let two_pow_64 = 18_446_744_073_709_551_616.0; // 2^64
        assert!(
            crate::encode_file_chunk_header(two_pow_64, 0.0, 16, false).is_err(),
            "transfer_id at 2^64 must return error (no silent u64::MAX saturation)"
        );
        // The largest accepted value (2^53 - 1) must still encode.
        assert!(
            crate::encode_file_accept(9_007_199_254_740_991.0, 0.0).is_ok(),
            "2^53-1 must still be accepted"
        );
    }

    #[wasm_bindgen_test]
    fn file_chunk_header_native_encode_matches_wasm_encode() {
        use sh_protocol::file::FileChunkHeader;
        // transfer_id/offset stay within the JS safe-integer range (<= 2^53); the bridge surface
        // carries 64-bit fields as f64, so values above 2^53 are out of contract by design.
        let native = FileChunkHeader {
            transfer_id: 0x0001_0203_0405,
            offset: 1_048_576,
            len: 65536,
            last: true,
        }
        .encode()
        .unwrap();
        let wasm_bytes =
            crate::encode_file_chunk_header(0x0001_0203_0405_u64 as f64, 1_048_576.0, 65536, true)
                .unwrap();
        assert_eq!(
            native.to_vec(),
            wasm_bytes,
            "native and wasm chunk-header encode must be byte-identical"
        );
    }

    #[wasm_bindgen_test]
    fn file_chunk_header_roundtrip() {
        let bytes = crate::encode_file_chunk_header(9.0, 2048.0, 512, false).unwrap();
        assert_eq!(bytes.len(), 21);
        let decoded = crate::decode_file_chunk_header(&bytes).unwrap();
        assert_eq!(decoded.transfer_id(), 9.0);
        assert_eq!(decoded.offset(), 2048.0);
        assert_eq!(decoded.len(), 512);
        assert!(!decoded.last());
    }

    #[wasm_bindgen_test]
    fn file_chunk_header_zero_len_is_js_error() {
        let result = crate::encode_file_chunk_header(1.0, 0.0, 0, false);
        assert!(result.is_err(), "zero chunk len must return error");
    }

    #[wasm_bindgen_test]
    fn file_chunk_header_decode_rejects_offset_above_safe_integer() {
        // Hand-craft a 21-byte header whose offset (bytes 8..16, BE) is 2^53 — decode must reject it
        // so the f64 getter never silently rounds (symmetric with the encode-side guard).
        let mut bytes = crate::encode_file_chunk_header(1.0, 0.0, 16, false).unwrap();
        let two_pow_53: u64 = 1 << 53;
        // offset occupies bytes 8..16 (BE); use get_mut to stay clear of the indexing_slicing ban.
        if let Some(slot) = bytes.get_mut(8..16) {
            slot.copy_from_slice(&two_pow_53.to_be_bytes());
        }
        assert!(
            crate::decode_file_chunk_header(&bytes).is_err(),
            "offset above 2^53 must be rejected at decode"
        );
    }

    #[wasm_bindgen_test]
    fn file_chunk_header_reserved_bits_decode_is_js_error() {
        // Encode a valid header, then flip a reserved flag bit (bit 1) in the wire bytes.
        let mut bytes = crate::encode_file_chunk_header(1.0, 0.0, 16, true).unwrap();
        // The flags byte is the last of the 21-byte header; set a reserved bit on it.
        *bytes.last_mut().unwrap() |= 0b0000_0010;
        assert!(
            crate::decode_file_chunk_header(&bytes).is_err(),
            "reserved flag bit must return error"
        );
    }

    #[wasm_bindgen_test]
    fn file_accept_native_encode_matches_wasm_encode() {
        use sh_protocol::file::FileAccept;
        let native = FileAccept {
            transfer_id: 0xDEAD_BEEF,
            resume_offset: 4096,
        }
        .encode();
        let wasm_bytes = crate::encode_file_accept(0xDEAD_BEEF_u64 as f64, 4096.0).unwrap();
        assert_eq!(native.to_vec(), wasm_bytes);
    }

    #[wasm_bindgen_test]
    fn file_accept_roundtrip() {
        let bytes = crate::encode_file_accept(3.0, 1024.0).unwrap();
        let decoded = crate::decode_file_accept(&bytes).unwrap();
        assert_eq!(decoded.transfer_id(), 3.0);
        assert_eq!(decoded.resume_offset(), 1024.0);
    }

    #[wasm_bindgen_test]
    fn file_complete_native_encode_matches_wasm_encode() {
        use sh_protocol::file::FileComplete;
        for ok in [true, false] {
            let native = FileComplete {
                transfer_id: 42,
                ok,
            }
            .encode();
            let wasm_bytes = crate::encode_file_complete(42.0, ok).unwrap();
            assert_eq!(native.to_vec(), wasm_bytes);
        }
    }

    #[wasm_bindgen_test]
    fn file_complete_roundtrip() {
        let bytes = crate::encode_file_complete(99.0, true).unwrap();
        let decoded = crate::decode_file_complete(&bytes).unwrap();
        assert_eq!(decoded.transfer_id(), 99.0);
        assert!(decoded.ok());
    }

    #[wasm_bindgen_test]
    fn file_decoders_handle_empty_input() {
        assert!(crate::decode_file_offer(&[]).is_err());
        assert!(crate::decode_file_chunk_header(&[]).is_err());
        assert!(crate::decode_file_accept(&[]).is_err());
        assert!(crate::decode_file_complete(&[]).is_err());
    }

    #[wasm_bindgen_test]
    fn file_decoders_handle_oversized_garbage() {
        // 256 bytes of 0xFF — must return Err (not trap) for every length/bounds-checked decoder.
        let garbage = [0xFFu8; 256];
        // Offer: chunk_size bytes are 0xFFFFFFFF → exceeds MAX_FILE_CHUNK → error.
        assert!(crate::decode_file_offer(&garbage).is_err());
        // Chunk header: len 0xFFFFFFFF exceeds MAX_FILE_CHUNK → error.
        assert!(crate::decode_file_chunk_header(&garbage).is_err());
        // Complete: ok byte 0xFF is neither 0 nor 1 → error.
        assert!(crate::decode_file_complete(&garbage).is_err());
        // Accept: any 16 bytes are structurally valid; must not trap.
        let _ = crate::decode_file_accept(&garbage);
    }
}
