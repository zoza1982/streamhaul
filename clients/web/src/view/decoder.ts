// VIEW: H.264 decode (WebCodecs `VideoDecoder`) + canvas render.
//
// Inbound SHP video payloads are Annex-B H.264. We feed them to a WebCodecs `VideoDecoder`
// configured in `"annexb"` mode and draw each produced `VideoFrame` to a 2D canvas. Every
// host byte is untrusted: decode errors are caught, the offending frame is dropped, and the
// decoder is recreated on the next keyframe — a malformed/garbage frame never crashes the app.

import { avcCodecString, containsIdr, extractParameterSets } from "./annexb.js";

/** WebCodecs surface (typed minimally so the module compiles without DOM-lib WebCodecs). */
interface VideoFrameLike {
  readonly displayWidth: number;
  readonly displayHeight: number;
  close(): void;
}

interface EncodedVideoChunkInit {
  type: "key" | "delta";
  timestamp: number;
  data: Uint8Array;
}

type CanvasImageSourceLike = CanvasImageSource;

interface VideoDecoderInit {
  output: (frame: VideoFrameLike) => void;
  error: (e: DOMException) => void;
}

interface VideoDecoderConfig {
  codec: string;
  optimizeForLatency?: boolean;
}

interface VideoDecoderLike {
  readonly state: "unconfigured" | "configured" | "closed";
  configure(config: VideoDecoderConfig): void;
  decode(chunk: unknown): void;
  reset(): void;
  close(): void;
}

interface VideoDecoderCtor {
  new (init: VideoDecoderInit): VideoDecoderLike;
}

interface EncodedVideoChunkCtor {
  new (init: EncodedVideoChunkInit): unknown;
}

/** Whether the running browser exposes the WebCodecs `VideoDecoder` API. */
export function isWebCodecsAvailable(): boolean {
  return (
    typeof globalThis !== "undefined" &&
    "VideoDecoder" in globalThis &&
    "EncodedVideoChunk" in globalThis
  );
}

/** Stats surfaced to the UI / tests; deliberately small and observable. */
export interface DecoderStats {
  framesDecoded: number;
  framesDropped: number;
  lastWidth: number;
  lastHeight: number;
}

/**
 * Drives a WebCodecs `VideoDecoder` and paints frames to the given canvas.
 *
 * Lifecycle: construct, then call `pushAnnexB(payload, isKeyframe)` for each inbound video
 * payload. Configuration is derived from the first keyframe's SPS. Decode errors are swallowed
 * (counted in `stats.framesDropped`); the next keyframe re-primes the decoder.
 */
export class CanvasH264Decoder {
  private readonly ctx: CanvasRenderingContext2D;
  private decoder: VideoDecoderLike | null = null;
  private configured = false;
  private timestamp = 0;
  /** Codec string from the most recent SPS seen, cached so a later keyframe that omits its
   * inline SPS can still configure with the correct profile/level (not the baseline fallback). */
  private codecString: string | null = null;
  readonly stats: DecoderStats = {
    framesDecoded: 0,
    framesDropped: 0,
    lastWidth: 0,
    lastHeight: 0,
  };

  constructor(private readonly canvas: HTMLCanvasElement) {
    const ctx = canvas.getContext("2d", { alpha: false });
    if (ctx === null) {
      throw new Error("canvas 2D context unavailable");
    }
    this.ctx = ctx;
  }

  /** Tear down the decoder, releasing GPU/codec resources. Safe to call repeatedly. */
  close(): void {
    this.discardDecoder();
  }

  /**
   * Close (if open) and drop the current decoder, resetting to the unconfigured state.
   *
   * Always calls `.close()` on the abandoned decoder before nulling it: under sustained hostile
   * keyframes (one configure/decode failure each) the WebCodecs decoder objects would otherwise
   * accumulate until GC, since WebCodecs does not auto-close a synchronously-failed decoder.
   */
  private discardDecoder(): void {
    const dec = this.decoder;
    if (dec !== null && dec.state !== "closed") {
      try {
        dec.close();
      } catch {
        // already closed / errored — ignore
      }
    }
    this.decoder = null;
    this.configured = false;
  }

  private ensureDecoder(): VideoDecoderLike {
    if (this.decoder !== null && this.decoder.state !== "closed") {
      return this.decoder;
    }
    const Ctor = (globalThis as unknown as { VideoDecoder: VideoDecoderCtor }).VideoDecoder;
    const decoder = new Ctor({
      output: (frame: VideoFrameLike) => this.paint(frame),
      error: (_e: DOMException) => {
        // Hostile/garbage input can put the decoder into an error state. Count it, close+drop the
        // decoder, and wait for the next keyframe to re-prime — never propagate as a crash.
        this.stats.framesDropped += 1;
        this.discardDecoder();
      },
    });
    this.decoder = decoder;
    this.configured = false;
    return decoder;
  }

  private paint(frame: VideoFrameLike): void {
    try {
      const w = frame.displayWidth;
      const h = frame.displayHeight;
      if (this.canvas.width !== w || this.canvas.height !== h) {
        this.canvas.width = w;
        this.canvas.height = h;
      }
      this.ctx.drawImage(frame as unknown as CanvasImageSourceLike, 0, 0);
      this.stats.framesDecoded += 1;
      this.stats.lastWidth = w;
      this.stats.lastHeight = h;
    } catch {
      this.stats.framesDropped += 1;
    } finally {
      frame.close();
    }
  }

  /**
   * Feed one Annex-B H.264 payload to the decoder.
   *
   * @param payload the codec payload bytes (untrusted host input).
   * @param isKeyframe whether the SHP video header marked this as an IDR keyframe.
   * @returns `true` if the chunk was handed to the decoder, `false` if it was dropped
   *          (no keyframe yet to configure on, or a decode error).
   */
  pushAnnexB(payload: Uint8Array, isKeyframe: boolean): boolean {
    // Treat a payload that carries an inline IDR as a keyframe even if the SHP header flag and
    // the bitstream disagree — the bitstream is authoritative for the decoder.
    const key = isKeyframe || containsIdr(payload);
    try {
      const decoder = this.ensureDecoder();
      if (!this.configured) {
        if (!key) {
          // Cannot start mid-GOP: wait for a keyframe before configuring.
          this.stats.framesDropped += 1;
          return false;
        }
        // Prefer the codec string from this keyframe's inline SPS. If a keyframe carries no
        // inline SPS (some hosts send SPS/PPS only on the first IDR), reuse the codec string we
        // derived from an earlier SPS; only fall back to Baseline 3.0 if we have never seen one.
        const { sps } = extractParameterSets(payload);
        if (sps !== null) {
          this.codecString = avcCodecString(sps);
        }
        const codec = this.codecString ?? "avc1.42001e";
        decoder.configure({ codec, optimizeForLatency: true });
        this.configured = true;
      }
      const ChunkCtor = (
        globalThis as unknown as { EncodedVideoChunk: EncodedVideoChunkCtor }
      ).EncodedVideoChunk;
      const chunk = new ChunkCtor({
        type: key ? "key" : "delta",
        timestamp: this.timestamp,
        data: payload,
      });
      this.timestamp += 1;
      decoder.decode(chunk);
      return true;
    } catch {
      // Malformed bytes / configure rejection — close+drop and recover on the next keyframe.
      this.stats.framesDropped += 1;
      this.discardDecoder();
      return false;
    }
  }
}
