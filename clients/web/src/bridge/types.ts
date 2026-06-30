// Hand-written, strict TypeScript types for the subset of the wasm bridge the app uses.
//
// The wasm-bindgen-generated `.d.ts` is loose (it appears under `src/wasm/`, excluded from
// the strict typecheck). We re-declare exactly the functions/classes we consume so the
// security-/wire-path code is fully typed (no `any`).

/** A decoded SHP common header (9-byte prefix on every packet). */
export interface WasmCommonHeader {
  readonly channel: number;
  readonly fragment: boolean;
  readonly last_fragment: boolean;
  readonly sequence: number;
  readonly timestamp_us: number;
  readonly payload_len: number;
}

/** A decoded SHP video payload header (12-byte, follows the common header). */
export interface WasmVideoHeader {
  readonly frame_id: number;
  readonly frag_index: number;
  readonly total_frags: number;
  /** 0=H264, 1=H265, 2=AV1, 3=Raw. */
  readonly codec: number;
  /** 0=Predicted, 1=IDR, 2=IntraRefresh. */
  readonly frame_type: number;
  readonly priority: number;
  readonly monitor_id: number;
  readonly marker: boolean;
  readonly encode_ts_us: number;
}

/** A decoded codec-capability payload. */
export interface WasmCodecCaps {
  readonly hw_encode_mask: number;
  readonly hw_decode_mask: number;
  readonly sw_h264_encode_available: boolean;
  readonly is_apple: boolean;
  readonly is_browser: boolean;
  /** Negotiated codec discriminant, or 0xFF if none selected. */
  readonly selected_codec: number;
}

/** The DTLS-pinned browser WebRTC session client (from `sh-web-client`). */
export interface WebClient {
  set_dtls_pin(pin: Uint8Array): void;
  create_offer(): Promise<string>;
  connect_as_offerer(remoteSdpAnswer: string): Promise<void>;
  connect_as_answerer(remoteSdpOffer: string): Promise<string>;
  add_ice_candidate(candidate: string): Promise<void>;
  local_dtls_fingerprint(): Uint8Array;
  /** Send on the video (primary) channel — host echo + channel-open HELLO + video. */
  send_frame(frame: Uint8Array): void;
  /** Send a 16-byte SHP InputEvent on the dedicated Input DataChannel (ADR-0036). */
  send_input(event: Uint8Array): void;
  on_frame(callback: (frame: Uint8Array) => void): void;
  on_data_channel(onOpen: (channel: RTCDataChannel) => void): void;
  on_ice_candidate(callback: (candidate: string | null) => void): void;
  ice_connection_state(): string;
  /** Close the underlying RTCPeerConnection (and its DataChannel), releasing ICE/DTLS resources. */
  close(): void;
}

/** Constructor surface for `SignalingChannel`. */
export interface SignalingChannelCtor {
  new (sendFn: (payload: string) => void): unknown;
}

// ── Identity-bound Noise handshake (sh-crypto-wasm) ─────────────────────────────
//
// Used by the P5-3 Stage 2 browser↔native e2e to run the live Noise XK handshake whose
// BindCert commits the browser's DTLS fingerprint and yields the host's committed pin. Private
// keys never cross this boundary (see `crates/sh-crypto-wasm`).

/** The completed, fully-verified Noise handshake result. */
export interface WasmHandshakeOutcome {
  readonly peer_fingerprint: string;
  readonly peer_pubkey: Uint8Array;
  /** The peer's committed 32-byte DTLS pin, throwing if absent/all-zero (anti-downgrade gate). */
  require_dtls_pin(): Uint8Array;
  has_dtls_pin(): boolean;
}

/** An in-progress Noise XK/IK handshake. */
export interface WasmNoiseHandshake {
  write_message(): Uint8Array;
  read_message(msg: Uint8Array): void;
  is_finished(): boolean;
  /** Completes for TOFU first pairing (skips the trust check; caller pins via the outcome). */
  complete_for_first_pairing(): WasmHandshakeOutcome;
  complete_trusted(keystore: WasmKeystore): WasmHandshakeOutcome;
}

/** Static constructors for `WasmNoiseHandshake` (mirrors the `#[wasm_bindgen]` associated fns). */
export interface WasmNoiseHandshakeCtor {
  /** XK initiator committing `local_dtls_fp`; needs the responder's X25519 static up front. */
  initiator_xk_with_dtls(
    keystore: WasmKeystore,
    peerStaticPub: Uint8Array,
    localDtlsFp: Uint8Array,
    sessionContext: Uint8Array,
  ): WasmNoiseHandshake;
}

/** An opaque device identity + TOFU trust store (Ed25519 signing key stays in wasm). */
export interface WasmKeystore {
  fingerprint(): string;
  public_key_bytes(): Uint8Array;
  trust_peer_by_key(peerPubkey: Uint8Array): void;
  is_trusted_by_key(peerPubkey: Uint8Array): boolean;
}

/** Static constructors for `WasmKeystore`. */
export interface WasmKeystoreCtor {
  generate(): WasmKeystore;
}

/** Constructor surface for `WebClient`. */
export interface WebClientCtor {
  new (signaling: unknown): WebClient;
}

// ── File-transfer framing (sh-wasm::file, P7-2 — ADR-0024) ──────────────────────
//
// 64-bit wire fields (transfer_id, total_size, offset, resume_offset) cross this boundary as
// plain `number` (JS doubles): exact only up to 2^53. That is far above any practical browser
// transfer, and matches the existing bridge's plain-`number` surface (BigInt is avoided). The
// wasm encoders reject negative / non-integral / out-of-range values.

/** A decoded `FileOffer` (sender → receiver announcement). */
export interface WasmFileOffer {
  readonly transfer_id: number;
  readonly total_size: number;
  readonly chunk_size: number;
  /** SHA-256 of the whole file (32 bytes). */
  readonly sha256: Uint8Array;
  /** File-name bytes (opaque; the receiver mirrors the sh-core sanitizer). */
  readonly name: Uint8Array;
}

/** A decoded `FileChunkHeader` (fixed 21-byte data-plane header). */
export interface WasmFileChunkHeader {
  readonly transfer_id: number;
  readonly offset: number;
  readonly len: number;
  readonly last: boolean;
}

/** A decoded `FileAccept` (receiver → sender, carrying a resume offset). */
export interface WasmFileAccept {
  readonly transfer_id: number;
  readonly resume_offset: number;
}

/** A decoded `FileComplete` (receiver → sender integrity report). */
export interface WasmFileComplete {
  readonly transfer_id: number;
  readonly ok: boolean;
}

/** The typed bridge surface used by the app. */
export interface ShBridge {
  // ── SHP codec (sh-wasm) ────────────────────────────────────────────────
  decode_video_header(data: Uint8Array): WasmVideoHeader;
  decode_common_header(data: Uint8Array): WasmCommonHeader;
  encode_input_event(
    event_type: number,
    modifiers: number,
    pointer_x: number,
    pointer_y: number,
    button_mask: number,
    key_code: number,
    scroll_x: number,
    scroll_y: number,
    pressure: number,
  ): Uint8Array;
  encode_caps(
    hw_encode_mask: number,
    hw_decode_mask: number,
    sw_h264_encode_available: boolean,
    is_apple: boolean,
    is_browser: boolean,
    selected_codec: number,
  ): Uint8Array;
  decode_caps(data: Uint8Array): WasmCodecCaps;
  negotiate_transport(
    local_quic: boolean,
    local_webrtc: boolean,
    peer_quic: boolean,
    peer_webrtc: boolean,
  ): number;

  // ── File-transfer framing (sh-wasm::file, P7-2) ────────────────────────
  encode_file_offer(
    transfer_id: number,
    total_size: number,
    chunk_size: number,
    sha256: Uint8Array,
    name: Uint8Array,
  ): Uint8Array;
  decode_file_offer(data: Uint8Array): WasmFileOffer;
  encode_file_chunk_header(
    transfer_id: number,
    offset: number,
    len: number,
    last: boolean,
  ): Uint8Array;
  decode_file_chunk_header(data: Uint8Array): WasmFileChunkHeader;
  encode_file_accept(transfer_id: number, resume_offset: number): Uint8Array;
  decode_file_accept(data: Uint8Array): WasmFileAccept;
  encode_file_complete(transfer_id: number, ok: boolean): Uint8Array;
  decode_file_complete(data: Uint8Array): WasmFileComplete;

  // ── WebRTC client (sh-web-client) ──────────────────────────────────────
  WebClient: WebClientCtor;
  SignalingChannel: SignalingChannelCtor;
  set_panic_hook(): void;
  /** Parse the SHA-256 DTLS fingerprint (32 bytes) from an SDP blob (hostile-input safe). */
  parse_sdp_fingerprint(sdp: string): Uint8Array;

  // ── Identity-bound Noise handshake (sh-crypto-wasm) ────────────────────
  WasmKeystore: WasmKeystoreCtor;
  WasmNoiseHandshake: WasmNoiseHandshakeCtor;
}
