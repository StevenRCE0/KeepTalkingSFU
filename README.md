# KeepTalkingSFU (iroh branch)

A Rust rewrite of the KeepTalking SFU. It does three things:

- **Relay.** It embeds [`iroh-relay`](https://docs.rs/iroh-relay). The relay coordinates hole punching and carries traffic between peers that can't reach each other directly. It only ever sees QUIC ciphertext.
- **SFU.** An iroh endpoint keeps one room per **topic**: 32 bytes the clients derive from their context secret, so the SFU never learns which context a room is. It relays each member's sealed presence blob and, when a sender chooses SFU delivery, fans a published payload or datagram out to the rest of the room so the sender uploads once.
- **Info.** `GET /kt/sfu` tells clients the SFU id, so apps only configure the relay's domain.

Peers choose per message between **mesh** delivery (their own iroh connections, which start on this relay and go direct when hole punching works) and **SFU** delivery (one upload, fanned out here). The SFU never needs to read a payload.

This branch is an orphan and shares no history with the Swift SFU on `main`.

## Layout

| Path | What |
|---|---|
| `src/proto.rs` | SFU wire format: frames, datagrams, limits. The protocol reference is in the module docs. |
| `src/server.rs` | `Sfu`: embedded relay, SFU endpoint, rooms, publish and datagram fan-out, and the resource bounds (`Limits`). |
| `src/info.rs` | The one-route HTTP listener behind `/kt/sfu`, and `fetch_info`, its client. |
| `src/client.rs` | Reference SFU client plus client endpoint setup. The Swift SDK mirrors it on `iroh-ffi`. |
| `src/tls.rs` | PEM loading (reloaded for cert-manager) and self-signed dev certs. |
| `src/bin/kt-sfu.rs` | The service. |
| `src/bin/kt-probe.rs` | Probe: subscribes to a topic and measures both mesh and SFU delivery to every other probe in it. |
| `tests/sfu.rs`, `tests/protocol.rs`, `tests/hardening.rs` | End-to-end tests against an in-process server (`tests/common` is the harness). |

## Design rules

- **No DNS or DHT discovery.** Endpoints use iroh's `Minimal` preset and a relay map containing only this server.
- **Topics, not contexts.** Clients derive the topic from the context secret; the SFU groups by those 32 bytes and never sees a context id.
- **Identity comes from sealed presence, never from the server.** The `EndpointId` a peer dials must come out of the topic-sealed presence blob, so a malicious server can't substitute its own key.
- **Ephemeral client keys.** Clients bind with a fresh key per session. Only the SFU key is persistent (`--sfu-key`); clients get its id from `/kt/sfu`.
- **The QUIC connection is the identity.** The SFU reads `conn.remote_id()`, which is authenticated by the handshake. There is no hello/challenge exchange.
- **One connection, many topics.** A process subscribes to every topic over a single SFU connection.
- **A newer connection owns the slot.** If an endpoint reconnects before its old connection times out, the old connection closing does not evict it.
- **Slow readers are dropped.** Each connection's outbound queue is bounded in bytes. A reader that goes over budget, or whose stream stops accepting bytes, is disconnected rather than allowed to stall a room.
- **Everything a stranger can make us hold is bounded.** Anyone can connect with any key, so connections, streams, receive windows, queues, room sizes, topics per connection and send rates all have caps (see [Limits](#limits)).
- **Only subscribers may announce, publish or send datagrams** to a topic.
- **No relay access control yet** (`AllowAll`), but every relay client is rate limited.

## SFU protocol (summary)

ALPN is `keeptalking/sfu/1`. The client opens one bidirectional stream and sends first. Frames are `[u32 BE len][u8 tag][body]`.

| Direction | Tag | Frame | Body |
|---|---|---|---|
| C→S | 0x21 | SUBSCRIBE | topic(32) |
| C→S | 0x22 | UNSUBSCRIBE | topic(32) |
| C→S | 0x23 | ANNOUNCE | topic(32) ‖ blob (≤ 1 KiB) |
| C→S | 0x24 | PUBLISH | topic(32) ‖ payload (≤ 1 MiB) |
| S→C | 0x31 | SNAPSHOT | topic(32) ‖ flags(u8) ‖ u16 n ‖ n × (id(32) ‖ u32 len ‖ blob) |
| S→C | 0x32 | JOINED | topic(32) ‖ id(32) |
| S→C | 0x33 | LEFT | topic(32) ‖ id(32) |
| S→C | 0x34 | PRESENCE | topic(32) ‖ id(32) ‖ blob |
| S→C | 0x35 | DELIVER | topic(32) ‖ payload |
| S→C | 0x3F | ERROR | topic(32) ‖ UTF-8 reason (all-zero topic = not about a topic) |

- After a SUBSCRIBE, the subscriber's first frame for that topic is its SNAPSHOT. A SUBSCRIBE for a topic the connection already holds is a no-op (no second snapshot).
- SNAPSHOT is chunked: flags bit 0 is MORE. The SFU cuts chunks at 256 entries or 256 KiB of body and sends them back to back; an empty room is one chunk with n = 0 and MORE clear. Clients merge chunks until one without MORE. Other flag bits are reserved (send 0, ignore).
- A zero-length blob in a snapshot means the member hasn't announced yet.
- A room holds at most 1024 members (`ERROR(topic, "room full")`, not subscribed); a connection at most 512 topics (`"too many topics"`). The all-zero topic is reserved.
- PUBLISH reaches every *other* subscriber as DELIVER; DELIVER doesn't name the sender (the sealed payload does).
- Refusals are `ERROR(topic, reason)` with fixed reasons: `room full`, `too many topics`, `rate limited`, `not subscribed`, `announce too large`, `publish too large`, `reserved topic`.
- A frame with a valid length but an unknown tag or malformed body is skipped (the SFU answers `ERROR(0, "malformed frame …")`); clients skip unknown server frames too. A length prefix of 0 or above 1 MiB + 64 KiB is fatal: the connection is closed (SFU close code 2).
- QUIC datagrams on the SFU connection are `topic(32) ‖ payload`; the SFU forwards the same bytes to every other subscriber, best effort.

The full reference, including close codes, is the module doc of `src/proto.rs`.

## Limits

Defaults from `server::Limits` and the protocol constants in `src/proto.rs`.

| What | Default | When exceeded |
|---|---|---|
| Concurrent SFU connections | 10 000 (`--max-connections`) | handshake refused |
| QUIC handshake | 15 s | connection dropped |
| Opening the bidi stream | 10 s | closed, code 4 `no stream opened` |
| QUIC streams per connection | 1 bidi, 0 uni | not grantable |
| QUIC receive windows | 4 MiB per connection, 2 MiB per stream | flow control |
| Datagram receive buffer | 512 KiB | QUIC drops datagrams |
| Outbound queue per connection | 8 MiB (an empty queue always takes one frame) | closed, code 1 `slow consumer` |
| No write progress on the stream | 20 s | closed, code 3 `stalled` |
| PUBLISH + ANNOUNCE | 4 MiB/s (4 MiB burst) and 200 frames/s (400 burst) | `ERROR(topic, "rate limited")`, frame dropped |
| Room joins (SUBSCRIBE) | 50/s (600 burst) | `ERROR(topic, "rate limited")`, not subscribed |
| Datagrams | 1 MiB/s (2 MiB burst) and 1000/s (2000 burst) | dropped silently |
| Members per room | 1024 | `ERROR(topic, "room full")` |
| Topics per connection | 512 | `ERROR(topic, "too many topics")` |
| Presence blob / publish payload | 1 KiB / 1 MiB | `ERROR(topic, "announce too large" / "publish too large")` |
| Relay reads per client | 2 MiB/s, 4 MiB burst (`--relay-client-rate`, `--relay-client-burst`) | relay stops reading (backpressure) |

The publish burst is half the outbound budget, so one publisher's burst cannot by itself push a healthy reader over it. The relay limit also applies to the SFU endpoint's own relay connection, which carries its fan-out to clients that can only reach it through the relay: their combined SFU traffic shares that 2 MiB/s. Raise `--relay-client-rate` (or set it to 0) if relay-only clients make up much of the load.

## Run it locally

```bash
cargo run --bin kt-sfu -- --dev \
  --relay-http-bind 127.0.0.1:18080 --relay-https-bind 127.0.0.1:18443 \
  --relay-quic-bind 127.0.0.1:17842 --sfu-bind 127.0.0.1:19702 \
  --info-bind 127.0.0.1:18090
```

`--dev` generates a self-signed certificate. It writes it to `kt-sfu-dev-cert.pem`, and the SFU key to `kt-sfu.key`. On startup the server prints ready-to-paste probe commands. Run one in two or more terminals with the same `--context`:

```bash
cargo run --bin kt-probe -- room --info http://127.0.0.1:18090/kt/sfu \
  --relay-ca kt-sfu-dev-cert.pem --context <uuid> --duration 20
```

`--info <url>` looks the SFU id, relay URL and QAD port up at the info endpoint (`http` or `https`, e.g. `https://signal.rcex.live/kt/sfu`) and refuses an SFU that speaks another protocol version. Without it, pass `--sfu <id> --relay <url> [--qad-port <port>]`.

The probe reports, per peer:
- **mesh:** when the peer was learned and connected, when the connection switched from the relay to a direct path (`path … selected Ip(…)`), QUIC RTT, ping round trips and datagram echoes
- **SFU:** round trip of a ping published through the SFU and answered through the SFU, and how many SFU-forwarded datagrams arrived

Useful flags:
- `--relay-only` drops IP transports, so that probe's connections stay on the relay.
- `--paths` logs every path iroh opens and closes, not just the selected one.

To test across machines, add `--dev-host <lan ip or name>` to the server so the dev certificate covers it, and use that host in `--relay`.

## Tests

```bash
cargo test
```

`tests/sfu.rs`:
- **Room lifecycle:** snapshot, subscribe, announce, late-subscriber snapshot, unsubscribe, disconnect, and refusing an announce to a topic the client isn't subscribed to.
- **Publish fan-out:** every other subscriber gets one DELIVER, the sender gets none, other topics stay quiet, and an unsubscribed publish is refused.
- **Datagram fan-out** to the room's other subscribers.
- **Info endpoint:** `/kt/sfu` names the SFU, relay, ALPN and QAD port and `fetch_info` reads it back; `/kt/hub` and other paths are 404; idle clients don't block it.
- **Slot ownership across a reconnect.**
- **Relay-only peers communicate through the embedded relay.**
- **Direct upgrade:** peers dialed with only the relay URL upgrade to a direct path.

`tests/protocol.rs`:
- **Snapshot chunking:** MORE on every chunk but the last, the union is the room, and `SfuClient` merges it (with lowered chunk limits; `src/proto.rs` unit tests cover the real 256-entry and 256 KiB cuts).
- **Room cap** (`room full`, reconnects still take their slot), **topic cap**, **duplicate SUBSCRIBE** is a no-op.
- **Oversized announce/publish** and the reserved all-zero topic are refused.
- **Malformed frames** are skipped and counted, the connection carries on; a bad length prefix closes it.
- **Empty rooms are removed**; **datagrams from non-subscribers** are not forwarded.

`tests/hardening.rs`:
- **Slow consumer** dropped by the byte budget, **stalled consumer** dropped by the stall timeout; the publisher and a healthy reader get every frame.
- **Rate limits** on publish frames, publish/announce bytes, room joins and datagrams.
- **A connection that opens no stream** is closed; **the connection cap** refuses handshakes until a slot frees up.

## Production

| Port | Proto | Purpose | Required |
|---|---|---|---|
| 443 → 8443 | TCP | relay HTTPS (`/relay`) | yes |
| 80 → 8080 | TCP | captive-portal probe | recommended |
| 7842 | UDP | QUIC address discovery | recommended (better hole punching) |
| 9702 | UDP | SFU endpoint | optional |
| 127.0.0.1:18090 | TCP | `/kt/sfu` info (proxied at `https://<relay>/kt/sfu`) | yes |

- **Relay-only still works.** With only TCP 443 exposed everything still works: the SFU is a client of its own relay, so SFU traffic rides the relay like everything else.
- **TLS:** `--tls-cert` / `--tls-key` take cert-manager's PEM files directly, with no PKCS#12 step, and are re-read periodically.
- **Public addresses:** set `--public-relay-url https://signal.rcex.live`, plus `--public-quic-port` if the load balancer remaps it.
- **SFU flags:** `--sfu-bind` (UDP, default `[::]:9702`), `--sfu-key`, `--info-bind`, `--max-connections`, `--relay-client-rate`, `--relay-client-burst` (env `KT_SFU_BIND`, `KT_SFU_KEY`, `KT_SFU_INFO_BIND`, `KT_SFU_MAX_CONNECTIONS`, `KT_SFU_RELAY_CLIENT_RATE`, `KT_SFU_RELAY_CLIENT_BURST`).
- **SFU key:** persist `--sfu-key`. Clients look the SFU id up at `/kt/sfu`, but a changing id still drops every SFU session on restart.
- **CI:** this branch has no CI workflow, so it never publishes the `latest` image that Keel rolls out.

## Deployed

Runs on the signal host as the podman quadlet `keeptalking-sfu-iroh.container` (host networking, Caddy in front: `/relay /derp /ping` → the relay, the info route → the info listener). The image is built locally (`git archive HEAD | docker build --platform linux/amd64 …`) and loaded with `podman load`; the SFU key lives in `/opt/keeptalking-sfu-iroh/hub.key`.

The deployed build predates the SFU rename. Deploying this one is a flag day: the quadlet's `--hub-bind`/`--hub-key` become `--sfu-bind`/`--sfu-key` (keep pointing `--sfu-key` at the existing `hub.key` so the id stays the same), the Caddy route moves from `/kt/hub` to `/kt/sfu`, and clients must speak `keeptalking/sfu/1`.

## Next steps

- Relay access control once there is a credential to check.
- CI that publishes the image, so deploys stop being a manual `podman load`.
- Watch relay and SFU bandwidth once voice moves over (relayed mesh and SFU fan-out both multiply on this box).
- Rate limits are per sending connection, so fan-out still multiplies them by the room size (up to 1023 copies). Charging a sender per delivered copy would bound the SFU's egress directly.
