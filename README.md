# browsermesh-servers

Three standalone Node.js services that support the browser-based P2P mesh of
[johnhenry/browsermesh](https://github.com/johnhenry/browsermesh): a signalling
server, a relay, and an always-on server pod ("kernel"). Each can be deployed on
its own; the only runtime dependencies are `ws` (signalling, relay, kernel),
`@johnhenry/wsh` (relay, only if the pipe route is enabled), and the mesh packages
and `multicast-dns` (kernel).

```
Browser pods <──WebSocket──> Signalling server (port 8787)   offers, answers, ICE
             <──WebSocket──> Relay server      (port 8788)   JSON envelopes; optional wsh pipes
             <──WebRTC────>  other pods (direct, after signalling)

Server kernel  (port 8789, mDNS)  an always-on pod with `fs` and `agent` services
```

**Read this first.** Nothing here is a trust anchor. Signalling and relay forward
bytes; they can drop, delay and observe who talks to whom. What is and is not
protected on the mesh as a whole is written down in
[`docs/security.md`](https://github.com/johnhenry/browsermesh/blob/main/docs/security.md)
of johnhenry/browsermesh (signed pod messages, the wsh link, the relay's place in
it); the per-server notes below say only what these processes themselves do.

## Services

### `signaling/` — WebRTC signalling (port 8787)

Pods register with a pod id, then exchange `offer`, `answer`, `ice-candidate` and
`signal` messages through the server, which forwards them with `source` (the
sender's registered id), `sourceVerified` and, if the sender included `from`, a
`from` it sets itself. It never interprets the payload.

**Modes (`AUTH_MODE`)**

- `open` (default): any pod id is accepted. Nothing proves who a client is, so
  every peer is stamped `verified: false` (`registered`, `peers`, `peer-joined`)
  and every forwarded message `sourceVerified: false`. Clients can tell.
- `authenticated` (protocol 2): the server sends a `challenge` (random nonce,
  single use, `AUTH_NONCE_TTL_MS`, default 30 s). The client answers
  `{ type: 'register', protocol: 2, podId, pubKey, nonce, signature }`, signing

  ```
  browsermesh-signaling/2
  purpose:register
  origin:<the server's ws(s) origin>
  podId:<pod id>
  nonce:<nonce>
  ```

  with its Ed25519 key. `podId` must equal `base64url(SHA-256(raw public key))`
  exactly (what `PodIdentity` derives); `origin` is the server's own origin as the
  client knows it and must match the server's `PUBLIC_ORIGIN`. Peers are stamped
  `verified: true`. A client that does not speak protocol 2 is refused with
  `code: 'protocol-unsupported'`; an id is released only by the connection that
  holds it, and the same key reconnecting takes over its stale connection. An
  unknown `AUTH_MODE` is an error, not open mode.

`PEER_DISCOVERY=none` stops the peer list and join/leave events (default `all`).
The published `SignalingClient` does not speak protocol 2 yet.

**HTTP**

- `GET /health` → `{ status, peers }`
- `GET /ice-servers` → an array of ICE servers with **time-limited TURN
  credentials**. Answered only to a caller with `Authorization: Bearer
  <ICE_API_TOKEN>` or the same origin as the server; everyone else gets 401.
  Rate limited per address; `Cache-Control: no-store`. CORS is granted only to an
  exactly listed `ORIGINS` entry, never `*`.
- ICE: nothing third-party by default (empty list). Configure `STUN_URLS`,
  `TURN_URLS` + `TURN_SECRET` (the coturn `static-auth-secret`; username
  `<expiry>:<random>`, credential `base64(HMAC-SHA1(secret, username))`), or opt in to
  public STUN with `ALLOW_PUBLIC_STUN=1`.

**Environment**

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | 8787 | listen port |
| `ORIGINS` | none (any origin) | comma-separated allowed origins for WebSocket upgrades, and the only origins granted CORS. Set it. |
| `AUTH_MODE` | `open` | `open` or `authenticated` |
| `PUBLIC_ORIGIN` | — | authenticated mode: this server's own `ws://`/`wss://` origin (required there) |
| `AUTH_NONCE_TTL_MS` | 30000 | lifetime of a challenge |
| `PEER_DISCOVERY` | `all` | `all` or `none` |
| `ICE_API_TOKEN` | — | bearer token that unlocks `/ice-servers` for non-same-origin callers |
| `ICE_RATE_LIMIT_PER_MINUTE` | 30 | `/ice-servers` requests per client address |
| `STUN_URLS` | — | comma-separated STUN URLs of your own |
| `ALLOW_PUBLIC_STUN` | off | `1` adds a third-party public STUN list |
| `TURN_URLS` | — | comma-separated `turn:` / `turns:` URLs |
| `TURN_SECRET` | — | shared secret, at least 16 characters; **environment only**, never returned or logged |
| `TURN_TTL_SECONDS` | 600 | credential lifetime (60 to 86400) |
| `ICE_SERVERS` | — | JSON array that replaces all of the above (static) |
| `TURN_USERNAME`, `TURN_CREDENTIAL` | — | legacy static TURN login, used only when `TURN_SECRET` is unset |
| `MAX_CONNECTIONS` | 1024 | concurrent WebSocket connections |
| `MAX_CONNECTIONS_PER_IP` | 100 | concurrent connections per client address |
| `MAX_CONNECTS_PER_MINUTE_PER_IP` | 120 | new connections per client address per minute |
| `MAX_MESSAGES_PER_MINUTE` | 300 | messages per connection per minute (every message counts) |
| `MAX_BUFFERED_BYTES` | 1048576 | a receiver with more unsent than this is dropped |
| `IDLE_TIMEOUT_MS` | 0 (off) | close a registered connection silent for this long |
| `TRUST_PROXY` | off | `1` behind a proxy that sets `Fly-Client-IP` / `X-Forwarded-For` |

Messages are limited to 64 KiB (checked by `ws` on the frame header, before
parsing); registration must happen within 10 s; nothing a client sends is logged.

### `relay/` — envelope relay (port 8788)

Forwards opaque JSON envelopes between pods that cannot connect directly.
`{ type: 'register', podId }`, then `{ type: 'relay', target, envelope }`; the
target receives `{ type: 'relayed', source, sourceVerified: false, envelope }`.
The relay is **open**: it does not verify pod ids, which it says on the wire.
Protection of what travels through it is end to end (signed pod messages).

- HTTP: `GET /health`, `GET /stats`. CORS only for exactly listed `ORIGINS`.
- Limits: per-address connections and connects per minute, every message counted,
  64 KiB messages, 8 messages before registering, slow receivers dropped,
  optional idle timeout, nothing client-sent logged.

**wsh pipe route (off by default).** With `PIPE_RELAY=1`, a WebSocket upgrade at
`<PIPE_BASE_PATH>/r/<rendezvous id>` (`?role=host` for the waiting side) is
handed to `createPipeRelay().accept()` from `@johnhenry/wsh/pipe-relay`, so two
browsers can form a sealed wsh peer link (`WshPeerLinks` in
`@johnhenry/browsermesh-transport`; see
[`docs/design/wsh-peer-link.md`](https://github.com/johnhenry/browsermesh/blob/main/docs/design/wsh-peer-link.md)).
Binary frames only, never parsed, never logged. **It vouches for nothing:** the
two ends authenticate each other and seal the session; the relay sees
ciphertext, its sizes and timing, who dials which id and when, and can drop,
delay or end a pipe. Admission only limits abuse (Origin allow-list, per-address
and per-id rate limits, a per-address cap) and a third connection to an id that
already has a pair is never joined to it. Use `wss://` (the proxy's TLS). Needs
Node 26 for the end-to-end wsh link (wsh's own requirement); the route itself ran
on Node 24 in tests.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | 8788 | listen port |
| `ORIGINS` | none (any origin) | allowed WebSocket origins and CORS origins (exact) |
| `MAX_MESSAGES_PER_MINUTE` | 600 | per peer, every message counted |
| `MAX_CONNECTIONS` | 1024 | concurrent connections |
| `MAX_CONNECTIONS_PER_IP` | 100 | per client address |
| `MAX_CONNECTS_PER_MINUTE_PER_IP` | 120 | per client address |
| `MAX_BUFFERED_BYTES` | 1048576 | slow-receiver bound |
| `IDLE_TIMEOUT_MS` | 0 (off) | idle close |
| `TRUST_PROXY` | off | trust `Fly-Client-IP` / `X-Forwarded-For` |
| `PIPE_RELAY` | off | `1` enables the wsh pipe route |
| `PIPE_BASE_PATH` | none | route prefix, e.g. `/mesh` |
| `PIPE_ORIGINS` | `ORIGINS` | allowed Origins for the route; one of this, `ORIGINS` or `PIPE_ALLOW_ANY_ORIGIN=1` is required |
| `PIPE_ALLOW_ANY_ORIGIN`, `PIPE_ALLOW_NO_ORIGIN` | off | accept any Origin / clients that send none |
| `PIPE_MAX_WAITING` | 256 | halves waiting for a partner, all ids |
| `PIPE_RENDEZVOUS_TIMEOUT_MS` | 60000 | how long a half waits |
| `PIPE_IDLE_TIMEOUT_MS` | 300000 | a pipe with no traffic closes |
| `PIPE_MAX_LIFETIME_MS` | 3600000 | a pipe closes this long after pairing |
| `PIPE_MAX_BYTES` | 67108864 | bytes per pipe, both directions |
| `PIPE_MAX_MESSAGE_BYTES` | 1048576 | largest frame |
| `PIPE_EARLY_BYTES` | 65536 | what a half may send before its partner arrives |
| `PIPE_HIGH_WATER_BYTES` | 1048576 | unsent bytes at which a sender is paused |
| `PIPE_CONNECTS_PER_MINUTE_PER_IP` / `_PER_ID` | 60 / 30 | rate limits |
| `PIPE_MAX_CONNECTIONS_PER_IP` | 32 | concurrent pipe connections per address |

### `kernel/` — server-side pod (port 8789)

An always-on pod (`ServerPod`, which extends the mesh `Pod`; the older
`PeerNodeServer` remains) with a file service (`fs`: path-contained,
symlink-safe, 10 MB write limit) and a stub or LLM-backed `agent`. It does not
yet open a connection to the signalling server itself; the `SIGNALING_URL`
setting is reserved.

- **Remote calls** go through `callService(name, method, args, token)`: the
  token is compared in constant time, only **declared** methods of services on
  the remote allow-list (`fs` and `agent`, or `registerService(..., { remote: true })`)
  can be reached, through a null-prototype table; nothing inherited is callable.
- **mDNS** (`MDNS_PORT` set) advertises and discovers `_browsermesh._tcp.local`
  and, for older pods, the former `_clawser._tcp.local` name (`MDNS_LEGACY=false`
  stops that). Records from the network are validated and bounded.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SIGNALING_URL` | — | reserved |
| `DATA_DIR` | `./data` | root of the `fs` service |
| `AGENT_NAME` | `server-agent` | agent name |
| `POD_LABEL` | hostname | label |
| `MAX_MEMORIES` | 1024 | agent memory entries |
| `LLM_PROVIDER` | — | `openai` or `anthropic`; unset = echo mode |
| `LLM_API_KEY`, `LLM_MODEL` | — | provider key and model |
| `MDNS_PORT` | — | port to advertise; enables mDNS |
| `MDNS_LEGACY` | on | `false` drops the `_clawser` service name |

## What is and is not protected

Protected by these servers: bounded message sizes, rate limits and connection
limits, origin allow-lists (when `ORIGINS` is set), no wildcard CORS, protected
`/ice-servers` with short-lived TURN credentials, pod ids bound to keys in
`authenticated` signalling mode, path containment and declared-method dispatch in
the kernel, no client text in logs.

Not protected, by design: **the relay and open signalling do not authenticate
pods**, so a `source` they report is only as good as `verified` says; neither
hides who talks to whom, when, or how much; TLS is the proxy's (use `wss://`);
with `ORIGINS` unset any origin may connect. For what pods protect end to end see
[`docs/security.md`](https://github.com/johnhenry/browsermesh/blob/main/docs/security.md).

## Quick start

```bash
npm ci
npm run start:signaling     # or start:relay, start:kernel
npm test                    # all three suites
```

Tests use real HTTP/WebSocket connections on ephemeral ports. CI runs them on
Node 24 and 26, plus a job against the newest published
`@johnhenry/browsermesh-*` packages.

## Deployment and releases

Nothing is published to npm (every package here is `private`). **Deployment is
by GitHub Actions to Fly.io:** `.github/workflows/deploy.yml` runs on every push
to `main`, tests signalling and relay, then runs `flyctl deploy` for
`deploy/fly.signaling.toml` (app `browsermesh-signaling`, `Dockerfile.signaling`)
and `deploy/fly.relay.toml` (app `browsermesh-relay`, `Dockerfile.relay`) with the
`FLY_API_TOKEN` secret. Merging to `main` therefore deploys. Secrets and settings
(`TURN_SECRET`, `ICE_API_TOKEN`, `ORIGINS`, `PUBLIC_ORIGIN`, `TRUST_PROXY=1`, ...)
are set on the Fly apps (`fly secrets set`), not in the repository. The kernel is
not deployed by the workflow.

Local: `deploy/docker-compose.yml` starts all three (`cd deploy && docker compose up`).
`deploy/fly.toml` is an older single-app config for the signalling server whose
app name is kept as it is in the Fly account (changing `app` creates a different
app); the two `fly.*.toml` files are the ones CI uses.

## License

MIT
