# KeepTalkingSFU (iroh branch)

A Rust rewrite of the KeepTalking SFU. It does three things:

- **Relay.** It embeds [`iroh-relay`](https://docs.rs/iroh-relay). The relay coordinates hole punching and carries traffic between peers that can't reach each other directly. It only ever sees QUIC ciphertext.
- **SFU.** An iroh endpoint keeps one room per **topic**: 32 bytes the clients derive from their context secret, so the SFU never learns which context a room is. It relays each member's sealed presence blob and, when a sender chooses SFU delivery, fans a published payload or datagram out to the rest of the room so the sender uploads once, or hands a payload to one named member, so large rooms don't need a full mesh. Payloads travel on three prioritised lanes (control, interactive, bulk), so a large transfer never holds up small messages.
- **Info.** `GET /kt/sfu` tells clients the SFU id, so apps only configure the relay's domain.

Peers choose per message between **mesh** delivery (their own iroh connections, which start on this relay and go direct when hole punching works) and **SFU** delivery (one upload, fanned out here). The SFU never needs to read a payload.

This branch is an orphan and shares no history with the Swift SFU on `main`.

## Layout

| Path | What |
|---|---|
| `src/proto.rs` | SFU wire format: frames, datagrams, limits. The protocol reference is in the module docs. |
| `src/server.rs` | `Sfu`: embedded relay, SFU endpoint, rooms, the session and lane streams, publish (fan-out and directed) and datagram forwarding, and the resource bounds (`Limits`). |
| `src/info.rs` | The one-route HTTP listener behind `/kt/sfu`, and `fetch_info`, its client. |
| `src/client.rs` | Reference SFU client plus client endpoint setup. The Swift SDK mirrors it on `iroh-ffi`. |
| `src/tls.rs` | PEM loading (reloaded for cert-manager) and self-signed dev certs. |
| `src/bin/kt-sfu.rs` | The service. |
| `src/bin/kt-probe.rs` | Probe: subscribes to a topic and measures both mesh and SFU delivery to every other probe in it. |
| `tests/sfu.rs`, `tests/protocol.rs`, `tests/lanes.rs`, `tests/hardening.rs` | End-to-end tests against an in-process server (`tests/common` is the harness). |

## Design rules

- **No DNS or DHT discovery.** Endpoints use iroh's `Minimal` preset and a relay map containing only this server.
- **Topics, not contexts.** Clients derive the topic from the context secret; the SFU groups by those 32 bytes and never sees a context id.
- **Identity comes from sealed presence, never from the server.** The `EndpointId` a peer dials must come out of the topic-sealed presence blob, so a malicious server can't substitute its own key.
- **Ephemeral client keys.** Clients bind with a fresh key per session. Only the SFU key is persistent (`--sfu-key`); clients get its id from `/kt/sfu`.
- **The QUIC connection is the identity.** The SFU reads `conn.remote_id()`, which is authenticated by the handshake. There is no hello/challenge exchange.
- **One connection, many topics.** A process subscribes to every topic over a single SFU connection.
- **Lanes, not one stream.** Room management has its own stream; payloads ride per-lane QUIC streams with priorities (control > interactive > bulk), so a 1 MiB context-sync page never sits in front of an ack or a liveness frame.
- **A newer connection owns the slot.** If an endpoint reconnects before its old connection times out, the old connection closing does not evict it.
- **Slow readers are dropped, slow bulk readers lose bulk.** A connection's session, control and interactive queues share a byte budget; a reader that goes over it, or whose stream stops accepting bytes, is disconnected rather than allowed to stall a room. Bulk has its own budget: over it the reader's oldest queued bulk deliveries are dropped and a stuck bulk stream is reset, but the connection stays.
- **Everything a stranger can make us hold is bounded.** Anyone can connect with any key, so connections, streams, receive windows, queues, room sizes, topics per connection and send rates all have caps (see [Limits](#limits)).
- **Only subscribers may announce, publish or send datagrams** to a topic, and a directed publish only reaches another subscriber of it.
- **No relay access control yet** (`AllowAll`), but every relay client is rate limited.

## SFU protocol (summary)

ALPN is `keeptalking/sfu/2` (a flag day: `sfu/1` is gone). Every stream carries frames `[u32 BE len][u8 tag][body]`. A connection has one **session stream**, **lane streams** in both directions, and datagrams.

**Session stream.** The client opens exactly one bidirectional stream, before any lane stream, and sends first (the SFU only sees the stream once bytes arrive; it closes a connection that opens none within 10 s). Room management only:

| Direction | Tag | Frame | Body |
|---|---|---|---|
| C→S | 0x21 | SUBSCRIBE | topic(32) |
| C→S | 0x22 | UNSUBSCRIBE | topic(32) |
| C→S | 0x23 | ANNOUNCE | topic(32) ‖ blob (≤ 1 KiB) |
| S→C | 0x31 | SNAPSHOT | topic(32) ‖ flags(u8) ‖ u16 n ‖ n × (id(32) ‖ u32 len ‖ blob) |
| S→C | 0x32 | JOINED | topic(32) ‖ id(32) |
| S→C | 0x33 | LEFT | topic(32) ‖ id(32) |
| S→C | 0x34 | PRESENCE | topic(32) ‖ id(32) ‖ blob |
| S→C | 0x3F | ERROR | topic(32) ‖ UTF-8 reason (all-zero topic = not about a topic) |

A PUBLISH or PUBLISH_TO on the session stream is refused with `ERROR(topic, "publish on a lane stream")`.

**Lane streams.** Unidirectional; the first byte names the lane, frames follow.

| Byte | Lane | Client → SFU | SFU → client | QUIC priority |
|---|---|---|---|---|
| 0x01 | control | long-lived, many frames | one stream per client, opened on first DELIVER | 2 (as the session stream) |
| 0x02 | interactive | long-lived, many frames | one stream per client, opened on first DELIVER | 1 |
| 0x03 | bulk | one frame, then FIN; a new stream per publish | one DELIVER, then FIN; a new stream per delivery | 0 |

| Direction | Tag | Frame | Body |
|---|---|---|---|
| C→S | 0x24 | PUBLISH | topic(32) ‖ payload (≤ 1 MiB) |
| C→S | 0x25 | PUBLISH_TO | topic(32) ‖ recipient endpoint id(32) ‖ payload (≤ 1 MiB) |
| S→C | 0x35 | DELIVER | topic(32) ‖ payload |

- PUBLISH reaches every *other* subscriber as DELIVER on the same lane. PUBLISH_TO reaches only the recipient, on the same lane, if it is subscribed to the topic and isn't the sender; otherwise `ERROR(topic, "no such recipient")` on the session stream. DELIVER doesn't name the sender either way (the sealed payload does).
- The sender must be subscribed, on any lane. Lane streams are not ordered against the session stream, so a client publishes to a topic only after its SNAPSHOT has arrived (and may see a DELIVER before a snapshot is complete).
- Order holds within one control or interactive stream; nothing is ordered across lanes or across bulk streams.
- An unknown lane byte: the SFU stops the stream (STOP_SENDING code 1). Data after a bulk stream's frame: stopped with code 2 (the frame itself was forwarded). A malformed frame on a bulk stream: code 3. Malformed frames (or session frames) on control and interactive streams are skipped like on the session stream. The SFU resets a bulk stream it sends that makes no progress for 20 s with code 4.
- Priorities are noq's `SendStream::set_priority`: a higher value is sent first and equal values share round-robin (send fairness stays on; without it noq finishes a partly sent stream before switching, priority or not).

**Rooms and errors.**

- After a SUBSCRIBE, the subscriber's first session frame for that topic is its SNAPSHOT. A SUBSCRIBE for a topic the connection already holds is a no-op (no second snapshot).
- SNAPSHOT is chunked: flags bit 0 is MORE. The SFU cuts chunks at 256 entries or 256 KiB of body and sends them back to back; an empty room is one chunk with n = 0 and MORE clear. Clients merge chunks until one without MORE. Other flag bits are reserved (send 0, ignore).
- A zero-length blob in a snapshot means the member hasn't announced yet.
- A room holds at most 1024 members (`ERROR(topic, "room full")`, not subscribed); a connection at most 512 topics (`"too many topics"`). The all-zero topic is reserved.
- Refusals are `ERROR(topic, reason)` with fixed reasons: `room full`, `too many topics`, `rate limited`, `not subscribed`, `announce too large`, `publish too large`, `reserved topic`, `publish on a lane stream`, `no such recipient`.
- A frame with a valid length but an unknown tag or malformed body is skipped (the SFU answers `ERROR(0, "malformed frame …")`); clients skip unknown server frames too. A length prefix of 0 or above 1 MiB + 64 KiB, on any stream, is fatal: the connection is closed (SFU close code 2).

**Datagrams.** QUIC datagrams on the SFU connection are `topic(32) ‖ payload`; the SFU forwards the same bytes to every other subscriber, best effort (voice).

The full reference, including close codes, is the module doc of `src/proto.rs`.

### Writing a client

What the Swift SDK has to do, in order:

1. Connect with ALPN `keeptalking/sfu/2`, open the bidirectional session stream, set its priority to 2, and send SUBSCRIBE (and ANNOUNCE) on it.
2. Accept at least 18 concurrent incoming uni streams (the SFU's two long-lived lanes plus up to 16 bulk streams; iroh's default is 100). Keep the connection receive window unbounded (the default) or read every stream promptly: unread bulk data must not use up the window the control lane needs.
3. Accept every uni stream the SFU opens, read its first byte to learn the lane, then read DELIVERs until FIN. Control and interactive streams stay open; a bulk stream carries one DELIVER. Skip streams with an unknown first byte and frames other than DELIVER.
4. Publish only after the topic's SNAPSHOT arrived. For control and interactive, open one uni stream per lane on first use, write the lane byte, set its priority (2, 1), and keep writing frames to it. For bulk, open a new uni stream per publish, priority 0, write `0x03`, one frame, and finish. The SFU allows 16 concurrent uni streams per client, so a 15th bulk upload waits for stream credit.
5. PUBLISH_TO is PUBLISH with the recipient's 32-byte endpoint id between the topic and the payload, tag 0x25. The recipient is a member's id as learnt from its sealed presence.

## Limits

Defaults from `server::Limits` and the protocol constants in `src/proto.rs`.

| What | Default | When exceeded |
|---|---|---|
| Concurrent SFU connections | 10 000 (`--max-connections`) | handshake refused |
| QUIC handshake | 15 s | connection dropped |
| Opening the session stream | 10 s | closed, code 4 `no stream opened` |
| Client-opened QUIC streams per connection | 1 bidi (session), 16 uni (two lanes + concurrent bulk uploads) | not grantable (the client waits for credit) |
| QUIC receive windows | 4 MiB per connection, 2 MiB per stream | flow control |
| QUIC send window | bulk budget + 8 MiB (16 MiB) | never reached by design, so priorities decide |
| Datagram receive buffer | 512 KiB | QUIC drops datagrams |
| Outbound session + control + interactive queues | 8 MiB per connection, shared (an empty budget always takes one frame) | closed, code 1 `slow consumer` |
| No write progress on the session, control or interactive stream | 20 s | closed, code 3 `stalled` |
| Outbound bulk, queued or unacknowledged | 8 MiB per connection | oldest queued bulk deliveries dropped (`bulk_dropped`) |
| Concurrent SFU → client bulk streams | 16 per connection | further deliveries queue (and count against the bulk budget) |
| No progress on one SFU → client bulk stream (writing or awaiting its ack) | 20 s | that stream reset, code 4 (`bulk_stalled`); connection stays |
| PUBLISH + PUBLISH_TO (all lanes) + ANNOUNCE | 4 MiB/s (4 MiB burst) and 200 frames/s (400 burst) | `ERROR(topic, "rate limited")`, frame dropped |
| Room joins (SUBSCRIBE) | 50/s (600 burst) | `ERROR(topic, "rate limited")`, not subscribed |
| Datagrams | 1 MiB/s (2 MiB burst) and 1000/s (2000 burst) | dropped silently |
| Members per room | 1024 | `ERROR(topic, "room full")` |
| Topics per connection | 512 | `ERROR(topic, "too many topics")` |
| Presence blob / publish payload | 1 KiB / 1 MiB | `ERROR(topic, "announce too large" / "publish too large")` |
| Relay reads per client | 2 MiB/s, 4 MiB burst (`--relay-client-rate`, `--relay-client-burst`) | relay stops reading (backpressure) |

The publish burst is half the disconnecting budget, so one publisher's burst cannot by itself push a healthy reader over it, even if it is all on the interactive lane. Partly received frames are bounded by the stream limits: at most one per open stream, so 17 × (1 MiB + 64 KiB) per connection. Bulk deliveries count against the bulk budget until the client acknowledges them, which keeps bulk from filling the QUIC send window and queueing control frames behind it. The relay limit also applies to the SFU endpoint's own relay connection, which carries its fan-out to clients that can only reach it through the relay: their combined SFU traffic shares that 2 MiB/s. Raise `--relay-client-rate` (or set it to 0) if relay-only clients make up much of the load.

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
- **SFU:** round trip of a ping published on the control lane and answered with a pong directed back through the SFU (PUBLISH_TO), how many SFU-forwarded datagrams arrived, and the bulk lane: each probe publishes one 256 KiB bulk payload per run once it sees a peer, every receiver acknowledges it with a directed control message, and the summary shows who acknowledged and the round trip

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

`tests/lanes.rs`:
- **Lane routing:** a publish on a lane is delivered on that lane, in order; the SFU uses one long-lived stream per lane for control and interactive and a fresh stream per bulk delivery, ended after one DELIVER.
- **Directed publish** reaches only the recipient, on every lane; a recipient that isn't a member (or is the sender) gets `no such recipient`, a sender outside the room `not subscribed`.
- **Stream rules:** a publish on the session stream is refused; an unknown lane byte, data after a bulk frame and a malformed bulk frame stop the stream with their codes; malformed frames on a control stream are skipped.
- **Bulk backpressure:** a receiver that never reads bulk loses bulk deliveries to its budget but stays connected while its control lane delivers; a stuck bulk stream is reset after the stall timeout, the connection stays.
- **No head-of-line blocking:** an interactive DELIVER arrives within 500 ms while 4 MiB of bulk to the same receiver is still being read slowly.

`tests/protocol.rs`:
- **Snapshot chunking:** MORE on every chunk but the last, the union is the room, and `SfuClient` merges it (with lowered chunk limits; `src/proto.rs` unit tests cover the real 256-entry and 256 KiB cuts).
- **Room cap** (`room full`, reconnects still take their slot), **topic cap**, **duplicate SUBSCRIBE** is a no-op.
- **Oversized announce/publish** (on every lane) and the reserved all-zero topic are refused.
- **Malformed frames** are skipped and counted, the connection carries on; a bad length prefix closes it.
- **Empty rooms are removed**; **datagrams from non-subscribers** are not forwarded.

`tests/hardening.rs`:
- **Slow consumer** dropped by the byte budget (interactive lane), **stalled consumer** dropped by the stall timeout (control lane); the publisher and a healthy reader get every frame.
- **Rate limits** on publish frames (broadcast and directed, across lanes), publish/announce bytes, room joins and datagrams.
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

The deployed build speaks `keeptalking/sfu/1`; the SFU rename already shipped with it (`--sfu-bind`/`--sfu-key` pointing at the existing `hub.key`, so the id is unchanged, and the Caddy route `/kt/sfu`). Deploying this one is a flag day for clients only: they must speak `keeptalking/sfu/2`, which the KeepTalking SDK does from its transport rewrite on. `/kt/sfu` reports `"alpn":"keeptalking/sfu/2"`, so a client built for another version (including `kt-probe --info`) refuses the SFU instead of failing mid-handshake; ship the Swift client update with the deploy. Nothing in the quadlet changes for lanes: same ports, flags and key.

## Next steps

- Relay access control once there is a credential to check.
- CI that publishes the image, so deploys stop being a manual `podman load`.
- Watch relay and SFU bandwidth once voice moves over (relayed mesh and SFU fan-out both multiply on this box).
- Rate limits are per sending connection, so fan-out still multiplies them by the room size (up to 1023 copies). Charging a sender per delivered copy would bound the SFU's egress directly; directed publishes already cost one copy.
- The `sfu totals` log line (every minute) now has per-lane `published.*`/`delivered.*`, `directed`, `bulk_dropped`, `bulk_stalled`, `bad_lanes` and `bulk_stopped`; watch `bulk_dropped` once context sync moves to the bulk lane.
