# KeepTalkingSFU (iroh branch)

A Rust rewrite of the KeepTalking SFU. It does two things:

- **Relay.** It embeds [`iroh-relay`](https://docs.rs/iroh-relay). The relay coordinates hole punching and carries traffic between peers that can't reach each other directly. It only ever sees QUIC ciphertext.
- **Presence.** A hub iroh endpoint keeps one room per context: who is in it, and each member's latest opaque presence blob.

It carries **no message traffic**. Messages, blobs and voice go peer to peer over iroh connections. Each connection starts on this relay and upgrades to direct in the background when hole punching works.

This branch is an orphan and shares no history with the Swift SFU on `main`. Nothing here is wired into the SDK yet.

## Layout

| Path | What |
|---|---|
| `src/proto.rs` | Presence wire format: frames, codec, limits. The protocol reference is in the module docs. |
| `src/server.rs` | `Sfu`: embedded relay, hub endpoint, rooms. |
| `src/client.rs` | Reference presence client plus client endpoint setup. The Swift SDK should mirror this on `iroh-ffi`. |
| `src/tls.rs` | PEM loading (reloaded for cert-manager) and self-signed dev certs. |
| `src/bin/kt-sfu.rs` | The service. |
| `src/bin/kt-probe.rs` | Probe: joins a room and forms a full mesh with every other probe in it. |
| `tests/presence.rs` | End-to-end tests against an in-process server. |

## Design rules

- **No DNS or DHT discovery.** Endpoints use iroh's `Minimal` preset and a relay map containing only this server. Peers dial each other with `EndpointAddr { id, relay_url }` and nothing else.
- **Identity comes from sealed presence, never from the server.** The hub reports membership, but the `EndpointId` a peer dials must come out of the context-sealed presence blob. That way a malicious server can't substitute its own key. `kt-probe` enforces this: it checks that the blob's id matches the server-reported id.
- **Ephemeral client keys.** Clients bind with a fresh key per session. Only the hub key is persistent (`--hub-key`), because clients pin the hub id.
- **The QUIC connection is the identity.** The hub reads `conn.remote_id()`, which is authenticated by the handshake. There is no hello/challenge exchange.
- **One connection, many contexts.** A process joins every context over a single hub connection.
- **A newer connection owns the slot.** If an endpoint reconnects before its old connection times out, the old connection closing does not evict it.
- **Slow readers are dropped.** A client whose outbox fills up is disconnected rather than allowed to stall a room.
- **No relay access control yet** (`AllowAll`).

## Presence protocol (summary)

ALPN is `keeptalking/presence/1`. The client opens one bidirectional stream and sends first. Frames are `[u32 BE len][u8 tag][body]`, the same framing as the Swift `SFUFrame`.

| Direction | Tag | Frame | Body |
|---|---|---|---|
| C→S | 0x11 | JOIN | ctx(16) |
| C→S | 0x12 | LEAVE | ctx(16) |
| C→S | 0x13 | PUBLISH | ctx(16) ‖ blob (≤ 16 KiB) |
| S→C | 0x14 | SNAPSHOT | ctx(16) ‖ u16 n ‖ n × (id(32) ‖ u32 len ‖ blob) |
| S→C | 0x15 | JOINED | ctx(16) ‖ id(32) |
| S→C | 0x16 | LEFT | ctx(16) ‖ id(32) |
| S→C | 0x17 | PRESENCE | ctx(16) ‖ id(32) ‖ blob |
| S→C | 0x3F | ERROR | UTF-8 |

- `ctx` is RFC 4122 byte order, the same as Swift's `UUID.uuid`.
- After a JOIN, the joiner always gets the SNAPSHOT before any other event for that room.
- A zero-length blob in a snapshot means the member hasn't published yet.

## Run it locally

```bash
cargo run --bin kt-sfu -- --dev \
  --relay-http-bind 127.0.0.1:18080 --relay-https-bind 127.0.0.1:18443 \
  --relay-quic-bind 127.0.0.1:17842 --hub-bind 127.0.0.1:19702
```

`--dev` generates a self-signed certificate. It writes it to `kt-sfu-dev-cert.pem`, and the hub key to `kt-sfu-hub.key`. On startup the server prints a ready-to-paste probe command. Run that command in two or more terminals with the same `--context`:

```bash
cargo run --bin kt-probe -- room --hub <hub id> --relay https://127.0.0.1:18443/ \
  --qad-port 17842 --relay-ca kt-sfu-dev-cert.pem --context <uuid> --duration 20
```

The probe reports:
- when each peer was learned and connected
- when the connection switched from the relay to a direct path (`path … selected Ip(…)`)
- QUIC RTT on the selected path, ping round trips, and datagram echoes

Useful flags:
- `--relay-only` drops IP transports, so that probe's connections stay on the relay.
- `--paths` logs every path iroh opens and closes, not just the selected one.

To test across machines, add `--dev-host <lan ip or name>` to the server so the dev certificate covers it, and use that host in `--relay`.

## Tests

```bash
cargo test
```

- **Room lifecycle:** snapshot, join, publish, late-joiner snapshot, leave, disconnect, and refusing a publish to a context the client hasn't joined.
- **Slot ownership across a reconnect.**
- **Relay-only peers communicate through the embedded relay.**
- **Direct upgrade:** peers dialed with only the relay URL upgrade to a direct path.

## Production notes (not deployed)

| Port | Proto | Purpose | Required |
|---|---|---|---|
| 443 → 8443 | TCP | relay HTTPS (`/relay`) | yes |
| 80 → 8080 | TCP | captive-portal probe | recommended |
| 7842 | UDP | QUIC address discovery | recommended (better hole punching) |
| 9702 | UDP | hub endpoint | optional |

- **Relay-only still works.** With only TCP 443 exposed everything still works: the hub is a client of its own relay, so presence rides the relay like everything else.
- **TLS:** `--tls-cert` / `--tls-key` take cert-manager's PEM files directly, with no PKCS#12 step, and are re-read periodically.
- **Public addresses:** set `--public-relay-url https://signal.rcex.live`, plus `--public-quic-port` if the load balancer remaps it.
- **Hub key:** mount `--hub-key` from a Secret. Clients pin the hub id, so the key must survive restarts.
- **CI:** this branch has no CI workflow, so it never publishes the `latest` image that Keel rolls out.

## Next steps

- Hub fan-out ALPN for large rooms: one upload from the sender, forwarded by the hub to every member. Useful for voice and big contexts. It becomes a routing switch in `ContextTransport`.
- A Swift client on a vendored `iroh-ffi`, implementing `proto.rs` and `client.rs`.
- Deploy manifests (mixed TCP/UDP Service) and CI for this branch.
- Relay access control once there is a credential to check.
