// In-browser file-transfer state machines (P7-2 — ADR-0024).
//
// These TS state machines MIRROR the host-side Rust orchestrator (`sh-core::file::FileSender` /
// `FileReceiver`). The wire BYTES are produced/parsed exclusively by the Rust/wasm codec via
// `./framing.ts`; this layer only drives the transfer and enforces the same stateful, security-
// critical validation the Rust receiver does. Keep the two in lockstep — any rule added to
// `sh-core::file` must be added here.
//
// Validation mirrored from `sh-core::file::FileReceiver` (see that file's module docs):
//   - name sanitization: reject empty, > MAX_FILE_NAME bytes, non-UTF-8, a path separator
//     (`/` or `\`), `.` / `..`, or any control character;
//   - `resume_offset (== already_have.length) <= total_size`;
//   - aggregate buffer cap: refuse an offer whose `total_size` exceeds the configured cap;
//   - each chunk: right transfer id; `offset == received_len` (contiguous, monotonic,
//     non-overlapping); declared `len == payload.length`; `offset + len <= total_size`;
//     a LAST chunk must end exactly at `total_size`;
//   - whole-file SHA-256 (seeded with any retained resume prefix) must match the offer.
//
// NOTE (R-BROWSER-FILE, deferred): the live browser↔native file transfer over a real DataChannel
// is intentionally out of scope for P7-2 — there is no Playwright e2e for it. The UI drives these
// in-process state machines (sender → receiver) to exercise the full validated path.
//
// CALLER OBLIGATION when a save/download sink is added (mirrors `sh-core::file::accept_offer`):
// the verified bytes from `finish()` must be saved using ONLY the sanitized name
// (`FileTransferReceiver.name()`), never the raw offer name; set the download attribute /
// `showSaveFilePicker` suggested name from it; and apply OS-specific filtering (e.g. Windows
// reserved device names CON/NUL/COM1…) before writing to disk. `sanitizeFileName` blocks path
// separators, `.`/`..`, control chars, and non-UTF-8, but does not know the destination filesystem.

import {
  decodeFileChunkHeader,
  encodeFileOffer,
  frameChunk,
  MAX_FILE_CHUNK,
  MAX_FILE_NAME,
  FILE_CHUNK_HEADER_LEN,
  type FileOfferFields,
} from "./framing.js";
import type { WasmFileOffer } from "../bridge/types.js";
import type { FileBridge } from "./framing.js";

/** Default aggregate buffer cap for a single in-browser transfer (64 MiB), mirroring the host. */
export const DEFAULT_FILE_CAP = 64 * 1024 * 1024;

/** A framed offer + the bytes the receiver will validate against. */
export interface OfferResult {
  /** The `FileOffer` wire bytes (sender → receiver on the Control channel). */
  readonly offerBytes: Uint8Array;
  /** The decoded fields, for the in-process driver / progress display. */
  readonly fields: FileOfferFields;
}

/** A textual reason a transfer was rejected — useful for the UI and tests. */
export class FileTransferError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FileTransferError";
  }
}

/** Compute the SHA-256 of `data` via WebCrypto, returned as a 32-byte `Uint8Array`. */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  // `crypto.subtle` is the platform digest (browser + Node ≥ 20). The buffer copy keeps the
  // ArrayBuffer view exact regardless of the input's byteOffset.
  const buf = data.slice().buffer;
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return new Uint8Array(digest);
}

/** Constant-time-ish equality for two byte arrays (digests). Length-checked first. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    // `noUncheckedIndexedAccess`: indices are in-bounds by the length guard above.
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
}

/**
 * Validate an offered file name with the SAME rules as `sh-core::file::sanitize_name`.
 *
 * Returns the decoded UTF-8 name on success; throws {@link FileTransferError} otherwise. The bytes
 * are decoded with a fatal TextDecoder so non-UTF-8 input is rejected (mirroring the Rust
 * `from_utf8` gate).
 */
export function sanitizeFileName(name: Uint8Array): string {
  if (name.length === 0) {
    throw new FileTransferError("offered file name rejected: empty");
  }
  if (name.length > MAX_FILE_NAME) {
    throw new FileTransferError("offered file name rejected: too long");
  }
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(name);
  } catch {
    throw new FileTransferError("offered file name rejected: not UTF-8");
  }
  if (decoded.includes("/") || decoded.includes("\\")) {
    throw new FileTransferError("offered file name rejected: contains a path separator");
  }
  // Reject any Unicode control character (C0: U+0000..U+001F + U+007F DEL; C1: U+0080..U+009F).
  // Mirrors Rust's `char::is_control`; scanning code points avoids embedding control bytes.
  for (const ch of decoded) {
    const cp = ch.codePointAt(0) as number;
    if (cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f)) {
      throw new FileTransferError("offered file name rejected: contains a control character");
    }
  }
  if (decoded === "." || decoded === "..") {
    throw new FileTransferError("offered file name rejected: path traversal");
  }
  return decoded;
}

/** Encode a name string to UTF-8 bytes for an offer. */
export function encodeFileName(name: string): Uint8Array {
  return new TextEncoder().encode(name);
}

// ── Sender ──────────────────────────────────────────────────────────────────────

/**
 * Drives the sending side: computes the whole-file SHA-256, emits the `FileOffer`, honours the
 * receiver's resume offset, and yields framed chunks (`FileChunkHeader` ++ payload) to EOF.
 *
 * Mirrors `sh-core::file::FileSender`. Construct via {@link FileTransferSender.create} (async,
 * because the SHA-256 is computed up front via WebCrypto).
 */
export class FileTransferSender {
  private cursor = 0;

  private constructor(
    private readonly bridge: FileBridge,
    private readonly transferId: number,
    private readonly nameBytes: Uint8Array,
    private readonly data: Uint8Array,
    private readonly chunkSize: number,
    private readonly digest: Uint8Array,
  ) {}

  /**
   * Create a sender for `data` named `name`, chunked at `chunkSize` (`1..=MAX_FILE_CHUNK`).
   *
   * Throws {@link FileTransferError} if the name is unsafe or the chunk size is out of range.
   */
  static async create(
    bridge: FileBridge,
    transferId: number,
    name: string,
    data: Uint8Array,
    chunkSize: number,
  ): Promise<FileTransferSender> {
    const nameBytes = encodeFileName(name);
    // Sanitize the name up front (the sender must not offer an unsafe name).
    sanitizeFileName(nameBytes);
    if (chunkSize <= 0 || chunkSize > MAX_FILE_CHUNK || !Number.isInteger(chunkSize)) {
      throw new FileTransferError(`invalid chunk size ${chunkSize}`);
    }
    const digest = await sha256(data);
    return new FileTransferSender(bridge, transferId, nameBytes, data, chunkSize, digest);
  }

  /** The offer fields + encoded bytes to send on the Control channel. */
  offer(): OfferResult {
    const fields: FileOfferFields = {
      transferId: this.transferId,
      totalSize: this.data.length,
      chunkSize: this.chunkSize,
      sha256: this.digest,
      name: this.nameBytes,
    };
    return { offerBytes: encodeFileOffer(this.bridge, fields), fields };
  }

  /**
   * Apply the receiver's resume offset (from a decoded `FileAccept`). The sender resumes from
   * there. Throws {@link FileTransferError} if it exceeds the file size.
   */
  onAccept(resumeOffset: number): void {
    if (resumeOffset < 0 || resumeOffset > this.data.length || !Number.isInteger(resumeOffset)) {
      throw new FileTransferError(
        `resume offset ${resumeOffset} exceeds total size ${this.data.length}`,
      );
    }
    this.cursor = resumeOffset;
  }

  /**
   * Produce the next framed chunk, or `null` when the file is fully sent. The final chunk carries
   * the LAST flag.
   */
  nextChunk(): Uint8Array | null {
    const total = this.data.length;
    if (this.cursor >= total) {
      return null;
    }
    const start = this.cursor;
    const take = Math.min(total - start, this.chunkSize);
    const end = start + take;
    const payload = this.data.subarray(start, end);
    const frame = frameChunk(
      this.bridge,
      { transferId: this.transferId, offset: start, len: take, last: end >= total },
      payload,
    );
    this.cursor = end;
    return frame;
  }

  /** Whether all bytes have been emitted. */
  isDone(): boolean {
    return this.cursor >= this.data.length;
  }
}

// ── Receiver ──────────────────────────────────────────────────────────────────────

/** Progress snapshot for the UI. */
export interface FileReceiveProgress {
  readonly name: string;
  readonly bytesReceived: number;
  readonly totalSize: number;
  /** 0..1 fraction received. */
  readonly fraction: number;
}

/**
 * Drives the receiving side: validates the offer (name + aggregate cap + resume), ingests chunks
 * with the SAME validation as `sh-core::file::FileReceiver`, reassembles, and verifies the whole-
 * file SHA-256 via WebCrypto.
 *
 * Construct via {@link FileTransferReceiver.accept}. There is no capability gate in the browser
 * (capability is a host-side authz concept); every other invariant is mirrored.
 */
export class FileTransferReceiver {
  /**
   * The reassembly buffer, preallocated to `totalSize` (bounded by the aggregate `cap` at accept,
   * so this allocation is safe). Chunks are written at their offset, avoiding the O(n²)
   * realloc-and-copy a growable buffer would incur. `receivedLen` tracks the contiguous prefix
   * filled so far.
   */
  private readonly buffer: Uint8Array;
  private receivedLen: number;
  private complete = false;

  private constructor(
    private readonly bridge: FileBridge,
    private readonly transferId: number,
    private readonly totalSize: number,
    private readonly expectedSha: Uint8Array,
    private readonly safeName: string,
    private readonly cap: number,
    alreadyHave: Uint8Array,
  ) {
    this.buffer = new Uint8Array(totalSize);
    // Seed the retained resume prefix (its length was validated `<= totalSize` at accept).
    this.buffer.set(alreadyHave.subarray(0, totalSize), 0);
    this.receivedLen = alreadyHave.length;
    this.complete = this.receivedLen >= this.totalSize;
  }

  /**
   * Validate an offer and produce the receiver + the `resume_offset` to advertise back to the
   * sender (the length of `alreadyHave`).
   *
   * Throws {@link FileTransferError} on an unsafe name, an offer above the aggregate `cap`, or a
   * resume prefix longer than the offered file.
   */
  static accept(
    bridge: FileBridge,
    offer: WasmFileOffer,
    alreadyHave: Uint8Array = new Uint8Array(0),
    cap: number = DEFAULT_FILE_CAP,
  ): { receiver: FileTransferReceiver; resumeOffset: number } {
    // Snapshot each wasm getter ONCE (the `sha256` getter allocates a fresh array per call; reading
    // it twice would let a Proxy/mock return different bytes for the length check vs the stored value).
    const safeName = sanitizeFileName(offer.name);
    const totalSize = offer.total_size;
    const transferId = offer.transfer_id;
    const expectedSha = offer.sha256;
    if (totalSize > cap) {
      throw new FileTransferError(
        `offered size ${totalSize} exceeds the ${cap}-byte aggregate buffer cap`,
      );
    }
    if (expectedSha.length !== 32) {
      throw new FileTransferError("offer carries a malformed (non-32-byte) digest");
    }
    const resumeOffset = alreadyHave.length;
    if (resumeOffset > totalSize) {
      throw new FileTransferError(
        `resume offset ${resumeOffset} exceeds total size ${totalSize}`,
      );
    }
    const receiver = new FileTransferReceiver(
      bridge,
      transferId,
      totalSize,
      expectedSha,
      safeName,
      cap,
      alreadyHave,
    );
    return { receiver, resumeOffset };
  }

  /**
   * Ingest one framed chunk (`FileChunkHeader` ++ payload). Returns `true` once the whole file has
   * been received (size reached). Validates transfer id, contiguity, size bounds, and LAST-at-EOF.
   *
   * Throws {@link FileTransferError} on any violation. The header is decoded by the fuzzed wasm
   * codec, so malformed header bytes surface as a thrown decode error caught here.
   */
  onChunk(frame: Uint8Array): boolean {
    // Reject stray chunks after the file is already fully received. The contiguity check below
    // would also catch them (any further chunk has offset == totalSize and len > 0 → overflow),
    // but an explicit guard makes the invariant defensive and gives a clearer error.
    if (this.complete) {
      throw new FileTransferError("transfer already complete: spurious chunk rejected");
    }
    if (frame.length < FILE_CHUNK_HEADER_LEN) {
      throw new FileTransferError("chunk frame shorter than the 21-byte header");
    }
    const header = decodeFileChunkHeader(this.bridge, frame.subarray(0, FILE_CHUNK_HEADER_LEN));
    const payload = frame.subarray(FILE_CHUNK_HEADER_LEN);

    if (header.transfer_id !== this.transferId) {
      throw new FileTransferError(
        `chunk for unknown transfer id ${header.transfer_id} (expected ${this.transferId})`,
      );
    }
    if (header.len !== payload.length) {
      throw new FileTransferError(`chunk len ${header.len} != payload length ${payload.length}`);
    }
    const expected = this.receivedLen;
    if (header.offset !== expected) {
      throw new FileTransferError(
        `chunk offset ${header.offset} is not the expected ${expected} (gap/overlap/reorder)`,
      );
    }
    const end = header.offset + header.len;
    if (end > this.totalSize) {
      throw new FileTransferError(
        `chunk [${header.offset}, ${end}) exceeds total size ${this.totalSize}`,
      );
    }
    // Defensive aggregate cap re-check (total_size <= cap was checked at accept).
    if (end > this.cap) {
      throw new FileTransferError(`reassembly ${end} exceeds the ${this.cap}-byte cap`);
    }
    // LAST flag must end exactly at EOF — rejects a hostile / early terminator.
    if (header.last && end !== this.totalSize) {
      throw new FileTransferError(`LAST chunk ends at ${end} but total size is ${this.totalSize}`);
    }
    // Write the payload at its (validated, contiguous) offset into the preallocated buffer.
    this.buffer.set(payload, header.offset);
    this.receivedLen = end;
    this.complete = this.receivedLen >= this.totalSize;
    return this.complete;
  }

  /**
   * Finalize: verify the whole-file SHA-256 and return the reassembled bytes. Throws
   * {@link FileTransferError} if the size is short or the digest does not match (integrity fail).
   */
  async finish(): Promise<Uint8Array> {
    if (this.receivedLen !== this.totalSize) {
      throw new FileTransferError(
        `incomplete: have ${this.receivedLen} of ${this.totalSize} bytes`,
      );
    }
    const digest = await sha256(this.buffer);
    if (!bytesEqual(digest, this.expectedSha)) {
      throw new FileTransferError(
        "integrity check failed: reassembled SHA-256 does not match the offer",
      );
    }
    // Return a COPY: the internal buffer must not be aliased to the caller (a caller mutation would
    // corrupt the receiver's state and make a re-`finish()` falsely fail integrity).
    return this.buffer.slice();
  }

  /** Progress snapshot for the UI. */
  progress(): FileReceiveProgress {
    const fraction = this.totalSize === 0 ? 1 : this.receivedLen / this.totalSize;
    return {
      name: this.safeName,
      bytesReceived: this.receivedLen,
      totalSize: this.totalSize,
      fraction,
    };
  }

  /** The sanitized (display-safe) file name. */
  name(): string {
    return this.safeName;
  }

  /** Whether all bytes have been received (integrity not yet verified — call `finish`). */
  isComplete(): boolean {
    return this.complete;
  }
}
