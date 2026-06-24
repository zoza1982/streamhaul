import { describe, it, expect } from "vitest";

import { loadCodecBridge } from "./helpers/bridge-node.js";
import {
  encodeFileOffer,
  encodeFileChunkHeader,
  frameChunk,
  FILE_CHUNK_HEADER_LEN,
  type FileBridge,
} from "../src/file/framing.js";
import {
  FileTransferSender,
  FileTransferReceiver,
  FileTransferError,
  sanitizeFileName,
  encodeFileName,
  sha256,
} from "../src/file/transfer.js";

// The file module is a thin shell over the SAME Rust/wasm codec the browser runs. These tests:
//   (a) byte-parity — the TS-built offer + chunk-header bytes match the exact, known wire layout
//       produced by the Rust `sh-protocol::file` encoder (loaded via the nodejs wasm build);
//   (b) receiver validation — every stateful rule the `sh-core` orchestrator enforces is mirrored;
//   (c) in-process round-trip — sender → receiver reassembles byte-identically and integrity
//       passes, including a resume case (the receiver pre-seeded with a contiguous prefix).
//
// NOTE (R-BROWSER-FILE): the live browser↔native file transfer is deferred — there is no e2e here.

const bridge = loadCodecBridge() as FileBridge;

/** A deterministic test file (matches the `sh-core` `deterministic_file` shape). */
function deterministicFile(len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = (i * 31 + 7) % 251;
  }
  return out;
}

function bigEndianU64(value: number): number[] {
  const out: number[] = [];
  for (let shift = 56; shift >= 0; shift -= 8) {
    // Numbers here are small (< 2^32), so `>>>` after dividing keeps exact bytes.
    out.push(Math.floor(value / 2 ** shift) % 256);
  }
  return out;
}

describe("file framing — byte parity with the Rust wire format", () => {
  it("encodes a FileOffer to the exact 53-byte-prefix + name layout", async () => {
    // Fixed inputs mirror the Rust golden `offer_known_layout_roundtrips`.
    const name = encodeFileName("report.pdf");
    const digest = new Uint8Array(32).fill(0xab);
    const bytes = encodeFileOffer(bridge, {
      transferId: 0x0102_0304_0506,
      totalSize: 0x1122_3344,
      chunkSize: 65536,
      sha256: digest,
      name,
    });

    // Fixed prefix (53) + name (10) = 63.
    expect(bytes.length).toBe(53 + 10);
    // transfer_id (big-endian u64) at bytes 0..8.
    expect(Array.from(bytes.subarray(0, 8))).toEqual(bigEndianU64(0x0102_0304_0506));
    // total_size at 8..16.
    expect(Array.from(bytes.subarray(8, 16))).toEqual(bigEndianU64(0x1122_3344));
    // chunk_size (u32) at 16..20: 65536 = 0x00010000.
    expect(Array.from(bytes.subarray(16, 20))).toEqual([0x00, 0x01, 0x00, 0x00]);
    // sha256 at 20..52.
    expect(Array.from(bytes.subarray(20, 52))).toEqual(Array.from(digest));
    // name_len at byte 52, then the name.
    expect(bytes[52]).toBe(10);
    expect(Array.from(bytes.subarray(53, 63))).toEqual(Array.from(name));
  });

  it("encodes 64-bit fields above 2^32 exactly (high word is not truncated)", () => {
    // A value spanning the 32-bit boundary but within the JS safe-integer range.
    const transferId = 0x1_0000_0001; // 2^32 + 1
    const offset = 0x2_0000_0003;
    const bytes = encodeFileChunkHeader(bridge, { transferId, offset, len: 16, last: false });
    expect(Array.from(bytes.subarray(0, 8))).toEqual(bigEndianU64(transferId));
    expect(Array.from(bytes.subarray(8, 16))).toEqual(bigEndianU64(offset));
    const header = bridge.decode_file_chunk_header(bytes);
    expect(header.transfer_id).toBe(transferId);
    expect(header.offset).toBe(offset);
  });

  it("rejects a 64-bit field above the JS safe-integer ceiling", () => {
    // 2^53 is the first non-representable consecutive integer; the wasm guard rejects it.
    expect(() =>
      encodeFileChunkHeader(bridge, { transferId: 2 ** 53, offset: 0, len: 16, last: false }),
    ).toThrow();
  });

  it("encodes a FileChunkHeader to the exact 21-byte layout (LAST flag set)", () => {
    const bytes = encodeFileChunkHeader(bridge, {
      transferId: 0x0001_0203_0405,
      offset: 1_048_576,
      len: 65536,
      last: true,
    });
    expect(bytes.length).toBe(FILE_CHUNK_HEADER_LEN);
    expect(Array.from(bytes.subarray(0, 8))).toEqual(bigEndianU64(0x0001_0203_0405));
    expect(Array.from(bytes.subarray(8, 16))).toEqual(bigEndianU64(1_048_576));
    // len (u32) at 16..20: 65536 = 0x00010000.
    expect(Array.from(bytes.subarray(16, 20))).toEqual([0x00, 0x01, 0x00, 0x00]);
    // flags byte: CHUNK_FLAG_LAST (bit 0).
    expect(bytes[20]).toBe(0b0000_0001);
  });

  it("clears the flags byte when not the last chunk", () => {
    const bytes = encodeFileChunkHeader(bridge, {
      transferId: 1,
      offset: 0,
      len: 16,
      last: false,
    });
    expect(bytes[20]).toBe(0);
  });

  it("rejects an out-of-range chunk size at the (Rust) encoder", () => {
    expect(() =>
      encodeFileChunkHeader(bridge, { transferId: 1, offset: 0, len: 0, last: false }),
    ).toThrow();
    expect(() =>
      encodeFileChunkHeader(bridge, {
        transferId: 1,
        offset: 0,
        len: 1024 * 1024 + 1,
        last: false,
      }),
    ).toThrow();
  });
});

describe("name sanitization — mirrors sh-core::file::sanitize_name", () => {
  it("accepts a plain UTF-8 name", () => {
    expect(sanitizeFileName(encodeFileName("notes.txt"))).toBe("notes.txt");
  });

  it("rejects unsafe names", () => {
    const bad = ["../etc/passwd", "a/b", "a\\b", "..", ".", "", "x\u0000y", "foo\nbar", "tab\there"];
    for (const name of bad) {
      expect(() => sanitizeFileName(encodeFileName(name)), `name ${JSON.stringify(name)}`).toThrow(
        FileTransferError,
      );
    }
  });

  it("rejects non-UTF-8 bytes", () => {
    expect(() => sanitizeFileName(new Uint8Array([0xff, 0xfe]))).toThrow(FileTransferError);
  });

  it("rejects a name longer than 255 bytes", () => {
    expect(() => sanitizeFileName(encodeFileName("a".repeat(256)))).toThrow(FileTransferError);
  });
});

describe("receiver validation — mirrors sh-core::file::FileReceiver", () => {
  it("rejects an unsafe offered name", () => {
    const offer = bridge.decode_file_offer(
      encodeFileOffer(bridge, {
        transferId: 1,
        totalSize: 1,
        chunkSize: 16,
        sha256: new Uint8Array(32),
        name: encodeFileName("a/b"),
      }),
    );
    expect(() => FileTransferReceiver.accept(bridge, offer)).toThrow(FileTransferError);
  });

  it("rejects an offer above the aggregate cap", () => {
    const offer = bridge.decode_file_offer(
      encodeFileOffer(bridge, {
        transferId: 1,
        totalSize: 1000,
        chunkSize: 16,
        sha256: new Uint8Array(32),
        name: encodeFileName("big.bin"),
      }),
    );
    expect(() => FileTransferReceiver.accept(bridge, offer, new Uint8Array(0), 999)).toThrow(
      /aggregate buffer cap/,
    );
  });

  it("rejects a resume prefix longer than the offered file", () => {
    const offer = bridge.decode_file_offer(
      encodeFileOffer(bridge, {
        transferId: 1,
        totalSize: 100,
        chunkSize: 16,
        sha256: new Uint8Array(32),
        name: encodeFileName("f"),
      }),
    );
    expect(() => FileTransferReceiver.accept(bridge, offer, new Uint8Array(101))).toThrow(
      /resume offset/,
    );
  });

  it("rejects a chunk for an unknown transfer id", () => {
    const data = deterministicFile(64);
    const offerBytes = encodeFileOffer(bridge, {
      transferId: 1,
      totalSize: data.length,
      chunkSize: 64,
      sha256: new Uint8Array(32),
      name: encodeFileName("f"),
    });
    const { receiver } = FileTransferReceiver.accept(bridge, bridge.decode_file_offer(offerBytes));
    const frame = frameChunk(bridge, { transferId: 999, offset: 0, len: 4, last: false }, data.subarray(0, 4));
    expect(() => receiver.onChunk(frame)).toThrow(/unknown transfer id/);
  });

  it("rejects an out-of-order (offset mismatch) chunk", () => {
    const offerBytes = encodeFileOffer(bridge, {
      transferId: 1,
      totalSize: 1000,
      chunkSize: 64,
      sha256: new Uint8Array(32),
      name: encodeFileName("f"),
    });
    const { receiver } = FileTransferReceiver.accept(bridge, bridge.decode_file_offer(offerBytes));
    const frame = frameChunk(bridge, { transferId: 1, offset: 100, len: 4, last: false }, new Uint8Array(4));
    expect(() => receiver.onChunk(frame)).toThrow(/not the expected 0/);
  });

  it("rejects a chunk that overflows total_size", () => {
    const offerBytes = encodeFileOffer(bridge, {
      transferId: 1,
      totalSize: 10,
      chunkSize: 64,
      sha256: new Uint8Array(32),
      name: encodeFileName("f"),
    });
    const { receiver } = FileTransferReceiver.accept(bridge, bridge.decode_file_offer(offerBytes));
    const frame = frameChunk(bridge, { transferId: 1, offset: 0, len: 16, last: true }, new Uint8Array(16));
    expect(() => receiver.onChunk(frame)).toThrow(/exceeds total size/);
  });

  it("rejects a LAST chunk that does not end at EOF", () => {
    const offerBytes = encodeFileOffer(bridge, {
      transferId: 1,
      totalSize: 100,
      chunkSize: 64,
      sha256: new Uint8Array(32),
      name: encodeFileName("f"),
    });
    const { receiver } = FileTransferReceiver.accept(bridge, bridge.decode_file_offer(offerBytes));
    const frame = frameChunk(bridge, { transferId: 1, offset: 0, len: 10, last: true }, new Uint8Array(10));
    expect(() => receiver.onChunk(frame)).toThrow(/LAST chunk ends at 10/);
  });

  it("rejects a spurious chunk fed after the transfer is already complete", async () => {
    const data = deterministicFile(64);
    const sender = await FileTransferSender.create(bridge, 1, "f.bin", data, 64);
    const { receiver, resumeOffset } = FileTransferReceiver.accept(
      bridge,
      bridge.decode_file_offer(sender.offer().offerBytes),
    );
    sender.onAccept(resumeOffset);
    const frame = sender.nextChunk() as Uint8Array;
    expect(receiver.onChunk(frame)).toBe(true); // single chunk = whole file
    expect(receiver.isComplete()).toBe(true);
    // A stray extra chunk after completion must be rejected outright.
    const stray = frameChunk(bridge, { transferId: 1, offset: 64, len: 1, last: false }, new Uint8Array(1));
    expect(() => receiver.onChunk(stray)).toThrow(/already complete/);
  });

  it("detects an integrity mismatch (flipped byte → SHA fails)", async () => {
    const data = deterministicFile(2048);
    const sender = await FileTransferSender.create(bridge, 1, "f.bin", data, 512);
    const { receiver, resumeOffset } = FileTransferReceiver.accept(
      bridge,
      bridge.decode_file_offer(sender.offer().offerBytes),
    );
    sender.onAccept(resumeOffset);
    // Corrupt one payload byte of the first chunk; size still matches, so SHA must fail.
    let first = true;
    for (let frame = sender.nextChunk(); frame !== null; frame = sender.nextChunk()) {
      if (first && frame.length > FILE_CHUNK_HEADER_LEN) {
        // First payload byte is in-bounds by the length guard above.
        frame[FILE_CHUNK_HEADER_LEN] = (frame[FILE_CHUNK_HEADER_LEN] as number) ^ 0xff;
        first = false;
      }
      if (receiver.onChunk(frame)) break;
    }
    await expect(receiver.finish()).rejects.toThrow(/integrity check failed/);
  });

  it("rejects a truncated transfer (finish before all bytes received)", async () => {
    const data = deterministicFile(2048);
    const sender = await FileTransferSender.create(bridge, 1, "f.bin", data, 512);
    const { receiver, resumeOffset } = FileTransferReceiver.accept(
      bridge,
      bridge.decode_file_offer(sender.offer().offerBytes),
    );
    sender.onAccept(resumeOffset);
    // Feed only the first chunk, then finalize early → incomplete.
    const first = sender.nextChunk() as Uint8Array;
    expect(receiver.onChunk(first)).toBe(false);
    await expect(receiver.finish()).rejects.toThrow(/incomplete/);
  });

  it("completes on byte count even if the EOF chunk lacks the LAST flag", async () => {
    // Completion is authoritative on byte count (matches sh-core); a final chunk that reaches
    // total_size with last:false still completes and verifies.
    const data = deterministicFile(40);
    const sha = await sha256(data);
    const offerBytes = encodeFileOffer(bridge, {
      transferId: 1,
      totalSize: 40,
      chunkSize: 64,
      sha256: sha,
      name: new TextEncoder().encode("f.bin"),
    });
    const { receiver } = FileTransferReceiver.accept(bridge, bridge.decode_file_offer(offerBytes));
    // One full-size chunk, but last:false.
    const frame = frameChunk(bridge, { transferId: 1, offset: 0, len: 40, last: false }, data);
    expect(receiver.onChunk(frame)).toBe(true);
    await expect(receiver.finish()).resolves.toEqual(data);
  });
});

describe("in-process round-trip — sender → receiver", () => {
  async function runTransfer(
    data: Uint8Array,
    chunkSize: number,
    alreadyHave: Uint8Array = new Uint8Array(0),
  ): Promise<Uint8Array> {
    const sender = await FileTransferSender.create(bridge, 7, "payload.bin", data, chunkSize);
    const { receiver, resumeOffset } = FileTransferReceiver.accept(
      bridge,
      bridge.decode_file_offer(sender.offer().offerBytes),
      alreadyHave,
    );
    sender.onAccept(resumeOffset);
    for (let frame = sender.nextChunk(); frame !== null; frame = sender.nextChunk()) {
      if (receiver.onChunk(frame)) break;
    }
    return receiver.finish();
  }

  it("reassembles a multi-chunk file byte-identically and verifies integrity", async () => {
    const data = deterministicFile(100_000);
    const got = await runTransfer(data, 16 * 1024);
    expect(Array.from(got)).toEqual(Array.from(data));
  });

  it("handles an empty file", async () => {
    const got = await runTransfer(new Uint8Array(0), 1024);
    expect(got.length).toBe(0);
  });

  it("returns an independent copy from finish() (caller mutation cannot corrupt the receiver)", async () => {
    const data = deterministicFile(2048);
    const sender = await FileTransferSender.create(bridge, 7, "payload.bin", data, 512);
    const { receiver, resumeOffset } = FileTransferReceiver.accept(
      bridge,
      bridge.decode_file_offer(sender.offer().offerBytes),
    );
    sender.onAccept(resumeOffset);
    for (let frame = sender.nextChunk(); frame !== null; frame = sender.nextChunk()) {
      if (receiver.onChunk(frame)) break;
    }
    const first = await receiver.finish();
    first.fill(0); // a caller scrubbing its copy must not affect the receiver
    const second = await receiver.finish();
    expect(Array.from(second)).toEqual(Array.from(data));
  });

  it("handles a file whose size is an exact multiple of the chunk size", async () => {
    const data = deterministicFile(4096);
    const got = await runTransfer(data, 1024);
    expect(Array.from(got)).toEqual(Array.from(data));
  });

  it("resumes from a pre-seeded contiguous prefix and reconstructs the whole file", async () => {
    const data = deterministicFile(50_000);
    const prefix = data.subarray(0, 20_000);
    const got = await runTransfer(data, 8 * 1024, prefix);
    expect(Array.from(got)).toEqual(Array.from(data));
  });

  it("completes a full-prefix resume with no chunks sent", async () => {
    const data = deterministicFile(12_345);
    const got = await runTransfer(data, 4096, data);
    expect(Array.from(got)).toEqual(Array.from(data));
  });

  it("the sender only emits the tail after a resume", async () => {
    const data = deterministicFile(40_000);
    const sender = await FileTransferSender.create(bridge, 1, "f", data, 8 * 1024);
    const { resumeOffset } = FileTransferReceiver.accept(
      bridge,
      bridge.decode_file_offer(sender.offer().offerBytes),
      data.subarray(0, 30_000),
    );
    expect(resumeOffset).toBe(30_000);
    sender.onAccept(resumeOffset);
    const frame = sender.nextChunk();
    expect(frame).not.toBeNull();
    const header = bridge.decode_file_chunk_header((frame as Uint8Array).subarray(0, FILE_CHUNK_HEADER_LEN));
    expect(header.offset).toBe(30_000);
  });
});

describe("sha256 helper", () => {
  it("matches the offer digest the sender computes", async () => {
    const data = deterministicFile(1234);
    const sender = await FileTransferSender.create(bridge, 1, "f", data, 256);
    const offer = bridge.decode_file_offer(sender.offer().offerBytes);
    expect(Array.from(offer.sha256)).toEqual(Array.from(await sha256(data)));
  });
});
