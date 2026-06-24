// Canvas-relative -> host-normalized coordinate mapping.
//
// SHP normalizes pointer coordinates to `0..=65535` across the source surface (see
// `sh_wasm::encode_input_event` docs). The browser captures pixel coordinates relative to
// the canvas bounding box; this maps them onto the normalized range the host expects,
// independent of the canvas's CSS size vs. the host's pixel resolution.

import { POINTER_MAX } from "./constants.js";

/** A minimal rectangle shape (subset of DOM `DOMRect`) — keeps this node-testable. */
export interface Rect {
  readonly left: number;
  readonly top: number;
  readonly width: number;
  readonly height: number;
}

/** Normalized pointer position in `0..=65535` on each axis. */
export interface NormalizedPoint {
  readonly x: number;
  readonly y: number;
}

/** Clamp `v` into the inclusive `0..=max` integer range. */
function clampToRange(v: number, max: number): number {
  if (!Number.isFinite(v)) {
    return 0;
  }
  const r = Math.round(v);
  if (r < 0) {
    return 0;
  }
  if (r > max) {
    return max;
  }
  return r;
}

/**
 * Map a client-space pointer (`clientX`/`clientY`) to SHP-normalized host coordinates,
 * given the canvas's bounding rectangle.
 *
 * - A click at the canvas's top-left maps to `(0, 0)`.
 * - A click at the bottom-right maps to `(65535, 65535)`.
 * - Out-of-bounds points (e.g. a drag that left the canvas) are clamped into range.
 * - A zero-size rect (detached/hidden canvas) maps to `(0, 0)` rather than dividing by zero.
 */
export function clientToNormalized(
  clientX: number,
  clientY: number,
  rect: Rect,
): NormalizedPoint {
  const relX = clientX - rect.left;
  const relY = clientY - rect.top;
  const nx = rect.width > 0 ? (relX / rect.width) * POINTER_MAX : 0;
  const ny = rect.height > 0 ? (relY / rect.height) * POINTER_MAX : 0;
  return { x: clampToRange(nx, POINTER_MAX), y: clampToRange(ny, POINTER_MAX) };
}
