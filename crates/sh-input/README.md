# sh-input

Portable input-injection seam for the Streamhaul host daemon.

## What this crate provides

| Item | Description |
|------|-------------|
| `InputInjector` | Object-safe trait: one method, `inject(&mut self, &InputEvent) -> Result<(), InputError>` |
| `CoordMapper` | Maps normalized `0..=65535` pointer coords to absolute host pixels |
| `TargetRect` | Virtual-desktop bounds; supports negative origins for multi-monitor layouts |
| `NoopInjector` | Accepts and discards every event; useful as a placeholder |
| `RecordingInjector` | Records every injected event for test assertions (test double) |
| `InputError` | `thiserror`-derived error type for injection failures |

## Architecture

```
Transport Input channel
      │ InputEvent (16-byte, sh_protocol)
      ▼
 CoordMapper          ← maps normalized 0..=65535 coords to absolute host pixels
      │ MappedPoint { x: i32, y: i32 }
      ▼
 InputInjector::inject()   ← synthesizes the OS event
      │
      ▼
 OS (SendInput / uinput / CGEvent …)
```

Real platform backends (`sh-platform-win`, `sh-platform-linux`, `sh-platform-mac`) implement
`InputInjector` and drop in without touching callers — the same trait-seam pattern as
`sh-media` (traits) / `sh-codec-hw` (impls).

## Coordinate mapping

Wire pointer coordinates are `u16` in `0..=65535`, resolution-independent across the client
surface. `CoordMapper` converts them to absolute host pixels using integer half-up rounding:

```
pixel_offset = (norm as u64 × (extent − 1) as u64 + 32767) / 65535
```

Multi-monitor layouts with negative origins (secondary display to the left of primary) are
supported via `i32` origin fields in `TargetRect`.

## Status

Portable slice complete (P1-3). Real platform injection (Windows `SendInput`/Raw Input,
Linux `uinput`, macOS `CGEvent`) is deferred to `sh-platform-*` crates — see Risk Register
entry R14 in `IMPLEMENTATION_PLAN.md`.
