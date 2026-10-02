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
| `src/server.rs` | `Sfu`: embedded relay, SFU endpoint, rooms, publish and datagram fan-out. |
| `src/info.rs` | The one-route HTTP listener behind `/kt/sfu`. |
| `src/client.rs` | Reference SFU client plus client endpoint setup. The Swift SDK mirrors it on `iroh-ffi`. |
| `src/tls.rs` | PEM loading (reloaded for cert-manager) and self-signed dev certs. |
| `src/bin/kt-sfu.rs` | The service. |
| `src/bin/kt-probe.rs` | Probe: subscribes to a topic and measures both mesh and SFU delivery to every other probe in it. |
| `tests/sfu.rs`, `tests/protocol.rs` | End-to-end tests against an in-process server (`tests/common` is the harness). |

## Design rules

- **No DNS or DHT discovery.** Endpoints use iroh's `Minimal` preset and a relay map containing only this server.
- **Topics, not contexts.** Clients derive the topic from the context secret; the SFU groups by those 32 bytes and never sees a context id.
- **Identity comes from sealed presence, never from the server.** The `EndpointId` a peer dials must come out of the topic-sealed presence blob, so a malicious server can't substitute its own key.
- **Ephemeral client keys.** Clients bind with a fresh key per session. Only the SFU key is persistent (`--sfu-key`); clients get its id from `/kt/sfu`.
- **The QUIC connection is the identity.** The SFU reads `conn.remote_id()`, which is authenticated by the handshake. There is no hello/challenge exchange.
- **One connection, many topics.** A process subscribes to every topic over a single SFU connection.
- **A newer connection owns the slot.** If an endpoint reconnects before its old connection times out, the old connection closing does not evict it.
- **Slow readers are dropped.** A client whose outbox fills up is disconnected rather than allowed to stall a room.
- **Only subscribers may announce, publish or send datagrams** to a topic.
- **No relay access control yet** (`AllowAll`).

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

## Run it locally

```bash
cargo run --bin kt-sfu -- --dev \
  --relay-http-bind 127.0.0.1:18080 --relay-https-bind 127.0.0.1:18443 \
  --relay-quic-bind 127.0.0.1:17842 --sfu-bind 127.0.0.1:19702 \
  --info-bind 127.0.0.1:18090
```

`--dev` generates a self-signed certificate. It writes it to `kt-sfu-dev-cert.pem`, and the SFU key to `kt-sfu.key`. On startup the server prints a ready-to-paste probe command. Run that command in two or more terminals with the same `--context`:

```bash
cargo run --bin kt-probe -- room --sfu <sfu id> --relay https://127.0.0.1:18443/ \
  --qad-port 17842 --relay-ca kt-sfu-dev-cert.pem --context <uuid> --duration 20
```

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

- **Room lifecycle:** snapshot, subscribe, announce, late-subscriber snapshot, unsubscribe, disconnect, and refusing an announce to a topic the client isn't subscribed to.
- **Publish fan-out:** every other subscriber gets one DELIVER, the sender gets none, other topics stay quiet, and an unsubscribed publish is refused.
- **Datagram fan-out** to the room's other subscribers.
- **Info endpoint:** `/kt/sfu` names the SFU, relay, ALPN and QAD port; other paths are 404.
- **Slot ownership across a reconnect.**
- **Relay-only peers communicate through the embedded relay.**
- **Direct upgrade:** peers dialed with only the relay URL upgrade to a direct path.

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
- **SFU key:** persist `--sfu-key`. Clients look the SFU id up at `/kt/sfu`, but a changing id still drops every SFU session on restart.
- **CI:** this branch has no CI workflow, so it never publishes the `latest` image that Keel rolls out.

## Deployed

Runs on the signal host as the podman quadlet `keeptalking-sfu-iroh.container` (host networking, Caddy in front: `/relay /derp /ping` → the relay, `/kt/sfu` → the info listener). The image is built locally (`git archive HEAD | docker build --platform linux/amd64 …`) and loaded with `podman load`; the SFU key lives in `/opt/keeptalking-sfu-iroh/hub.key`.

## Next steps

- Relay access control once there is a credential to check.
- CI that publishes the image, so deploys stop being a manual `podman load`.
- Watch relay and SFU bandwidth once voice moves over (relayed mesh and SFU fan-out both multiply on this box).
