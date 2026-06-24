// Thin typed wrappers over the sh-wasm file-framing functions (P7-2 — ADR-0024).
//
// The file wire format (FileOffer / FileChunkHeader / FileAccept / FileComplete) lives in Rust
// (`crates/sh-protocol/src/file.rs`) and is exposed via `crates/sh-wasm/src/lib.rs`. This module
// is glue only: it forwards to the wasm encoders/decoders so the bytes are ALWAYS produced and
// parsed by the same fuzzed, panic-free Rust codec the native host uses — never re-implemented in
// TypeScript. The stateful security validation is mirrored in `transfer.ts` (the receiver), the
// way `sh-core::file::FileReceiver` mirrors it on the host.

import type {
  ShBridge,
  WasmFileAccept,
  WasmFileChunkHeader,
  WasmFileComplete,
  WasmFileOffer,
} from "../bridge/types.js";

/**
 * The file-framing subset of {@link ShBridge}. Both the full browser bridge and the Node-target
 * codec bridge satisfy this, so the file module works in the app and in Vitest without a cast.
 */
export type FileBridge = Pick<
  ShBridge,
  | "encode_file_offer"
  | "decode_file_offer"
  | "encode_file_chunk_header"
  | "decode_file_chunk_header"
  | "encode_file_accept"
  | "decode_file_accept"
  | "encode_file_complete"
  | "decode_file_complete"
>;

/** Wire length of a `FileChunkHeader` (`transfer_id u64 | offset u64 | len u32 | flags u8`). */
export const FILE_CHUNK_HEADER_LEN = 21;

/** Maximum file chunk payload size (1 MiB) — mirrors `sh_protocol::file::MAX_FILE_CHUNK`. */
export const MAX_FILE_CHUNK = 1024 * 1024;

/** Maximum file-name length in bytes — mirrors `sh_protocol::file::MAX_FILE_NAME`. */
export const MAX_FILE_NAME = 255;

// NOTE: the control-channel kind bytes (`KIND_FILE_OFFER`=0x30 … `KIND_FILE_COMPLETE`=0x33) live in
// `sh_protocol::file`. They are intentionally NOT re-declared here: the browser has no control-frame
// router yet (offer/accept/complete are driven in-process by the UI), so a TS copy would be dead
// code that drifts from the Rust source of truth. Add them with the dispatcher when it lands.

/** Fields of a `FileOffer` as the sender supplies them (before wire encoding). */
export interface FileOfferFields {
  readonly transferId: number;
  readonly totalSize: number;
  readonly chunkSize: number;
  /** SHA-256 of the whole file (must be exactly 32 bytes). */
  readonly sha256: Uint8Array;
  /** File-name bytes (the wasm encoder enforces the ≤255 bound). */
  readonly name: Uint8Array;
}

/** Encode a `FileOffer` to its wire bytes (throws on out-of-range fields). */
export function encodeFileOffer(bridge: FileBridge, fields: FileOfferFields): Uint8Array {
  return bridge.encode_file_offer(
    fields.transferId,
    fields.totalSize,
    fields.chunkSize,
    fields.sha256,
    fields.name,
  );
}

/** Decode a `FileOffer` from wire bytes (throws on malformed input). */
export function decodeFileOffer(bridge: FileBridge, data: Uint8Array): WasmFileOffer {
  return bridge.decode_file_offer(data);
}

/** Fields of a `FileChunkHeader` (the 21-byte data-plane header; payload follows separately). */
export interface FileChunkHeaderFields {
  readonly transferId: number;
  readonly offset: number;
  readonly len: number;
  readonly last: boolean;
}

/** Encode the 21-byte `FileChunkHeader` (throws if `len` is 0 or above `MAX_FILE_CHUNK`). */
export function encodeFileChunkHeader(
  bridge: FileBridge,
  fields: FileChunkHeaderFields,
): Uint8Array {
  return bridge.encode_file_chunk_header(
    fields.transferId,
    fields.offset,
    fields.len,
    fields.last,
  );
}

/** Decode the 21-byte `FileChunkHeader` (throws on truncation / reserved bits / bad len). */
export function decodeFileChunkHeader(
  bridge: FileBridge,
  data: Uint8Array,
): WasmFileChunkHeader {
  return bridge.decode_file_chunk_header(data);
}

/** Encode a `FileAccept` to its 16-byte wire form. */
export function encodeFileAccept(
  bridge: FileBridge,
  transferId: number,
  resumeOffset: number,
): Uint8Array {
  return bridge.encode_file_accept(transferId, resumeOffset);
}

/** Decode a `FileAccept` from its 16-byte wire form (throws on truncation). */
export function decodeFileAccept(bridge: FileBridge, data: Uint8Array): WasmFileAccept {
  return bridge.decode_file_accept(data);
}

/** Encode a `FileComplete` to its 9-byte wire form. */
export function encodeFileComplete(
  bridge: FileBridge,
  transferId: number,
  ok: boolean,
): Uint8Array {
  return bridge.encode_file_complete(transferId, ok);
}

/** Decode a `FileComplete` from its 9-byte wire form (throws on truncation / bad ok byte). */
export function decodeFileComplete(bridge: FileBridge, data: Uint8Array): WasmFileComplete {
  return bridge.decode_file_complete(data);
}

/**
 * Frame a chunk: the 21-byte `FileChunkHeader` followed immediately by its `payload` bytes — the
 * exact on-the-wire layout of a File-stream chunk (`FILE_CHUNK_HEADER_LEN` prefix ++ payload).
 */
export function frameChunk(
  bridge: FileBridge,
  fields: FileChunkHeaderFields,
  payload: Uint8Array,
): Uint8Array {
  const header = encodeFileChunkHeader(bridge, fields);
  const frame = new Uint8Array(header.length + payload.length);
  frame.set(header, 0);
  frame.set(payload, header.length);
  return frame;
}
