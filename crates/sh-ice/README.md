# sh-ice

ICE/STUN/TURN orchestration and P2P-vs-relay path selection for Streamhaul.

## Purpose

`sh-ice` establishes the lowest-latency network path between a Streamhaul host and
client.  It implements the Interactive Connectivity Establishment (ICE) protocol
(RFC 8445) to discover and verify candidate transport addresses, then selects the
best path — direct P2P if NAT traversal succeeds, or a relay via TURN otherwise.

## STUN subset (RFC 8489)

The STUN codec in `sh_ice::stun` handles:

- **Message types**: Binding Request, Binding Success/Error Response, Binding Indication.
- **Attributes**: `MAPPED-ADDRESS`, `XOR-MAPPED-ADDRESS`, `USERNAME`,
  `MESSAGE-INTEGRITY` (HMAC-SHA1), `FINGERPRINT` (CRC32 XOR `0x5354554E`),
  `PRIORITY`, `USE-CANDIDATE`, `ICE-CONTROLLED`, `ICE-CONTROLLING`, `ERROR-CODE`,
  `SOFTWARE`, and unknown/pass-through attributes.
- **Integrity**: `StunMessage::encode_with_integrity` / `verify_integrity` use
  HMAC-SHA1 with a short-term credential key.
- **Fingerprint**: `encode_with_integrity_and_fingerprint` / `verify_fingerprint`
  append a CRC32 check per RFC 8489 §14.7.
- **Security**: every decode path bounds-checks before indexing; hostile input
  cannot cause panics or out-of-bounds reads.

## Candidate types

Three candidate kinds (RFC 8445 §5):

| Kind | Description | Priority preference |
|------|-------------|---------------------|
| `Host` | Local interface address | 126 |
| `ServerReflexive` | Discovered via STUN from behind NAT | 100 |
| `Relay` | Allocated at a TURN server | 0 |

Priority formula (RFC 5245 §4.1.2.1):
`priority = 2^24 × type_pref + 2^8 × local_pref + (256 − component_id)`

Pair priority (RFC 5245 §5.7.2):
`pair_priority = 2^32 × min(G,D) + 2 × max(G,D) + (G > D ? 1 : 0)`

## ICE state machine

```
New → Gathering → Checking → Connected
                            ↘ Failed → Restarting → New
```

- **Gathering**: emits Host candidates from `IceConfig::local_addrs`.
  Srflx and relay gathering (live STUN/TURN) is deferred to P4-3.
- **Checking**: forms all local×remote pairs, sends STUN Binding Requests,
  processes responses, marks pairs Succeeded/Failed.
- **Nomination**: the `Controlling` agent marks the first Succeeded pair and
  sends a Binding Request with `USE-CANDIDATE`.
- **Timeout**: after 5 seconds in Checking without nomination → `Failed →
  Restarting → New`.

### Synchronous step harness

```rust
// In tests — drive with step():
let out = agent.step(Some((data, from)))?;
// out is Vec<(Vec<u8>, SocketAddr)> — messages to deliver to the peer.
```

## Relay steering

`sh_ice::steering` provides:

- **`RelayProbeResult`**: median RTT and jitter for one server from a 3-probe sequence.
- **`score_relays(initiator, responder) -> Vec<RelayScore>`**: combined score =
  `rtt_init + rtt_resp + (jitter_init + jitter_resp) / 2` (all µs), sorted ascending.
- **`select_relay(scores) -> Option<RelaySelection>`**: primary = best; standby =
  second-best if within 10 ms of primary.

### TURN credentials (coturn REST API)

```rust
let creds = TurnCredentials::generate(shared_key, user_id, 3600, now_unix_secs)?;
// username = "<expiry_unix_secs>:<user_id>"
// password = base64(HMAC-SHA1(shared_key, username))
assert!(creds.is_valid(now_unix_secs));
```

## NAT simulator for tests

`sh_ice::transport::NatSimNetwork` provides an in-process network fabric:

```rust
let net = NatSimNetwork::new("10.0.0.254".parse()?);
let sock_a = net.create_socket(NatType::FullCone, "127.0.0.1:9001".parse()?)?;
let sock_b = net.create_socket(NatType::RestrictedCone, "127.0.0.2:9001".parse()?)?;
// sock_a and sock_b implement UdpTransport — pass them to IceAgent::new.
```

Modelled NAT types:

| Type | Mapping | Filtering |
|------|---------|-----------|
| `FullCone` | One external per socket | Any external host |
| `RestrictedCone` | One external per socket | Hosts the internal has sent to |
| `PortRestricted` | One external per socket | (Host, port) pairs sent to |
| `Symmetric` | New external port per destination | Same as PortRestricted |

The NAT matrix test (`agent::tests::nat_matrix`) exercises all combinations and
prints a results table to stdout.

## Deferred items (P4-3)

- Live STUN `Binding` requests to real STUN servers (`stun.l.google.com`, etc.)
- TURN `Allocate` / `Refresh` / `CreatePermission` / `ChannelBind` sequences
- Coturn deployment and REST credential endpoint integration
- Live NAT traversal testing on real internet paths
- Srflx and relay candidate gathering in `IceAgent::gather`

## Fuzz testing

```sh
cargo +nightly fuzz run stun_decode
```

The target exercises `StunMessage::decode` with arbitrary input, verifying no
panics, no out-of-bounds accesses, and no allocation amplification.
