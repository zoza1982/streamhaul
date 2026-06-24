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
  send_frame(frame: Uint8Array): void;
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

/** Constructor surface for `WebClient`. */
export interface WebClientCtor {
  new (signaling: unknown): WebClient;
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

  // ── WebRTC client (sh-web-client) ──────────────────────────────────────
  WebClient: WebClientCtor;
  SignalingChannel: SignalingChannelCtor;
  set_panic_hook(): void;
  /** Parse the SHA-256 DTLS fingerprint (32 bytes) from an SDP blob (hostile-input safe). */
  parse_sdp_fingerprint(sdp: string): Uint8Array;
}
