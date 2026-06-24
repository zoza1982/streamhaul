/**
 * Signaling envelope: wire format encoding/decoding for the browser side.
 *
 * Wire format matches `sh-signaling/src/envelope.rs` exactly (big-endian throughout):
 *
 * ```
 * Offset  Len   Field
 * 0       1     kind: u8  (0=Hello…6=Error, 7=Challenge)
 * 1       16    session_id: [u8; 16]
 * 17      64    from_fp: UTF-8 hex (64 chars)
 * 81      64    to_fp:   UTF-8 hex (64 chars)
 * 145     4     payload_len: u32 BE
 * 149     N     opaque_payload (N = payload_len, max 65536)
 * ```
 */

/** Kind discriminant for a signaling envelope. */
export const MessageKind = {
  Hello: 0,
  Offer: 1,
  Answer: 2,
  Candidate: 3,
  EndOfCandidates: 4,
  Bye: 5,
  Error: 6,
  Challenge: 7,
} as const;

/** Union of all valid message kind values. */
export type MessageKind = (typeof MessageKind)[keyof typeof MessageKind];

/** Fixed byte length of the envelope header (before the payload). */
export const ENVELOPE_HEADER_LEN = 149;

/** Maximum payload length accepted in a single envelope (64 KiB). */
export const MAX_PAYLOAD_LEN = 64 * 1024;

/** Length of a fingerprint field on the wire (64 ASCII hex chars). */
const FP_LEN = 64;

/** Offset of `session_id` in the wire buffer. */
const SESSION_ID_OFFSET = 1;

/** Offset of `from_fp` in the wire buffer. */
const FROM_FP_OFFSET = 17;

/** Offset of `to_fp` in the wire buffer. */
const TO_FP_OFFSET = 81;

/** Offset of `payload_len` (u32 BE) in the wire buffer. */
const PAYLOAD_LEN_OFFSET = 145;

/** A decoded signaling envelope. */
export interface SignalingEnvelope {
  /** Message kind (0–7). */
  kind: number;
  /** 16-byte session identifier. */
  sessionId: Uint8Array;
  /** 64-char lowercase hex fingerprint of the sender. */
  fromFp: string;
  /** 64-char lowercase hex fingerprint of the intended recipient. */
  toFp: string;
  /** Opaque payload bytes. */
  payload: Uint8Array;
}

/**
 * Regular expression for a valid 64-char lowercase hex fingerprint.
 *
 * Validation must use this regex (not just `.length === 64`) because `TextEncoder`
 * encodes non-ASCII characters to multi-byte UTF-8, which would silently corrupt the
 * adjacent field in the wire buffer when the encoded length exceeds 64 bytes.
 */
const FP_RE = /^[0-9a-f]{64}$/;

/**
 * Encode a {@link SignalingEnvelope} into its wire representation.
 *
 * @throws if `fromFp` or `toFp` is not exactly 64 lowercase ASCII hex characters.
 * @throws if `payload` exceeds {@link MAX_PAYLOAD_LEN}.
 */
export function encodeEnvelope(env: SignalingEnvelope): Uint8Array {
  if (!FP_RE.test(env.fromFp)) {
    throw new Error(
      `encodeEnvelope: fromFp must be 64 lowercase hex chars, got "${env.fromFp.slice(0, 80)}"`,
    );
  }
  if (!FP_RE.test(env.toFp)) {
    throw new Error(
      `encodeEnvelope: toFp must be 64 lowercase hex chars, got "${env.toFp.slice(0, 80)}"`,
    );
  }
  if (env.payload.length > MAX_PAYLOAD_LEN) {
    throw new Error(
      `encodeEnvelope: payload too large (${env.payload.length} > ${MAX_PAYLOAD_LEN})`,
    );
  }

  const total = ENVELOPE_HEADER_LEN + env.payload.length;
  const buf = new Uint8Array(total);
  const view = new DataView(buf.buffer);

  // kind (1 byte)
  buf[0] = env.kind & 0xff;

  // session_id (16 bytes)
  buf.set(env.sessionId.subarray(0, 16), SESSION_ID_OFFSET);

  // from_fp (64 bytes UTF-8)
  const enc = new TextEncoder();
  buf.set(enc.encode(env.fromFp), FROM_FP_OFFSET);
  buf.set(enc.encode(env.toFp), TO_FP_OFFSET);

  // payload_len (u32 BE)
  view.setUint32(PAYLOAD_LEN_OFFSET, env.payload.length, false /* big-endian */);

  // payload
  buf.set(env.payload, ENVELOPE_HEADER_LEN);

  return buf;
}

/**
 * Decode a wire buffer into a {@link SignalingEnvelope}.
 *
 * @throws if `buf` is shorter than {@link ENVELOPE_HEADER_LEN}.
 * @throws if the declared `payload_len` exceeds {@link MAX_PAYLOAD_LEN}.
 * @throws if the buffer is shorter than `header + payload_len`.
 */
export function decodeEnvelope(buf: Uint8Array): SignalingEnvelope {
  if (buf.length < ENVELOPE_HEADER_LEN) {
    throw new Error(
      `decodeEnvelope: buffer too short (${buf.length} < ${ENVELOPE_HEADER_LEN})`,
    );
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);

  const kind = buf[0]!;
  const sessionId = buf.slice(SESSION_ID_OFFSET, SESSION_ID_OFFSET + 16);

  const dec = new TextDecoder("utf-8", { fatal: true });
  const fromFp = dec.decode(buf.slice(FROM_FP_OFFSET, FROM_FP_OFFSET + FP_LEN));
  const toFp = dec.decode(buf.slice(TO_FP_OFFSET, TO_FP_OFFSET + FP_LEN));

  const payloadLen = view.getUint32(PAYLOAD_LEN_OFFSET, false /* big-endian */);
  if (payloadLen > MAX_PAYLOAD_LEN) {
    throw new Error(
      `decodeEnvelope: payload_len too large (${payloadLen} > ${MAX_PAYLOAD_LEN})`,
    );
  }

  const expectedTotal = ENVELOPE_HEADER_LEN + payloadLen;
  if (buf.length < expectedTotal) {
    throw new Error(
      `decodeEnvelope: buffer too short for declared payload (need ${expectedTotal}, have ${buf.length})`,
    );
  }

  const payload = buf.slice(ENVELOPE_HEADER_LEN, expectedTotal);

  return { kind, sessionId, fromFp, toFp, payload };
}
