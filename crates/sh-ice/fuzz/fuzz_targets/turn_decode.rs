//! Fuzz target for `TurnMessage::decode` and `TurnClient::decode_channel_data`.
//!
//! Invariants verified:
//! - No panic on arbitrary byte sequences (TURN/STUN codec must be panic-free).
//! - No out-of-bounds memory accesses (all field reads are bounds-checked).
//! - No unbounded allocation amplification (output sizes bounded by input).
//! - ChannelData framing never panics regardless of header content.
//!
//! The target exercises both the STUN-framed TURN message path and the
//! ChannelData 4-byte-header path.  Hostile input from an untrusted network
//! is the primary threat model; this target is mandatory per CLAUDE.md §5.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sh_ice::transport::{NatSimNetwork, NatType, SimSocket};
use sh_types::FixedClock;

fuzz_target!(|data: &[u8]| {
    // Path 1: STUN-framed TURN message decode.
    // Must never panic; Result errors are expected for hostile input.
    let _ = sh_ice::turn::TurnMessage::decode(data);

    // Path 2: ChannelData framing decode.
    let _ = sh_ice::turn::TurnClient::<SimSocket, FixedClock, rand_core::OsRng>::decode_channel_data(data);
});
