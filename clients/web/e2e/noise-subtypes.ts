/**
 * Noise-over-signaling sub-type discriminants (payload[0] of a `MessageKind.Noise` envelope).
 *
 * SINGLE SOURCE OF TRUTH for the browser side. These are a cross-language wire contract that MUST
 * match `bins/streamhaul-webrtc-host/src/main.rs` (`NOISE_SUB_*`):
 *
 * | value | name                    | direction      | body                                  |
 * |-------|-------------------------|----------------|---------------------------------------|
 * | 0x00  | `HELLO`                 | browser → host | empty (host learns browser `from_fp`) |
 * | 0x01  | `HOST_STATIC_PUB`       | host → browser | 32-byte host X25519 static public key |
 * | 0x02  | `MSG`                   | either         | opaque Noise XK message (BindCert)     |
 *
 * The exact values are asserted on the Rust side (`noise_sub_type_wire_values_are_pinned`) and on
 * the TS side (`clients/web/test/noise-subtypes.test.ts`). Defining them once here means
 * `browser-native.ts` and the test cannot drift from each other; the Rust test guards the
 * cross-language half. See ADR-0023.
 *
 * This module is intentionally dependency-free (no browser/wasm imports) so it is safe to import
 * from a Node-side Vitest unit test as well as the in-browser driver.
 */

/** Browser→host: empty body; lets the host learn the browser's `from_fp`. */
export const NOISE_SUB_HELLO = 0x00;
/** Host→browser: 32-byte host X25519 static public key (XK needs the responder static up front). */
export const NOISE_SUB_HOST_STATIC_PUB = 0x01;
/** Either direction: opaque Noise XK handshake message (carries the BindCert). */
export const NOISE_SUB_MSG = 0x02;
