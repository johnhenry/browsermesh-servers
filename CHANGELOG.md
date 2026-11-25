# Changelog

## Unreleased

- Relay tests: the test servers bind 127.0.0.1 (`listen(port, host)`, new optional second argument; the default bind is unchanged) so a connection meant for the relay cannot reach another local program that holds the same port number, and a failed connect in the pipe tests fails the test instead of leaving it waiting. No change to how the relay serves

- Relay: `@johnhenry/wsh` pinned to exactly 0.50.0 (was `^0.45.0`, which admits 0.45 only); tested against 0.45.0, 0.46.1, 0.48.0 and 0.50.0. Relay test dependencies updated to browsermesh-transport 0.9 / primitives 0.6.1 (their peer range admits newer wsh). `relay/package-lock.json` now lists the dependency tree. The pipe route is still off unless `PIPE_RELAY=1`

- Signalling (authenticated mode): one verified pod id may hold up to `MAX_CONNECTIONS_PER_POD` (default 2) connections, so a pod with a primary and a secondary connection to the same server no longer replaces itself in a loop; a connection pushed out by a newer one is sent `code: 'replaced'`, `reconnect: false` and closed `4409`. Open mode is unchanged
- Signalling: `/ice-servers` gives TURN credentials only to the bearer token; a same-origin claim gets the STUN part only (new `ICE_ALLOW_SAME_ORIGIN_TURN=1` opts back in); with `TURN_SECRET` and `TURN_URLS` set the server requires `ICE_API_TOKEN` to start. No change without TURN credentials configured

- Signalling: no third-party STUN by default; time-limited TURN credentials (`TURN_SECRET`); `/ice-servers` answered only to the bearer token or the same origin, rate limited; exact-origin CORS
- Signalling: authenticated mode is a challenge/response protocol (protocol 2) that binds the pod id to the proven key; open mode stamps peers `verified: false`; per-address limits, backpressure, idle timeout
- Relay: origin allow-list, per-address limits, backpressure, idle timeout; envelopes stamped `sourceVerified: false`; optional wsh pipe-relay route (`PIPE_RELAY=1`)
- Kernel: remote calls reach only declared methods of allow-listed services; constant-time token check; contained file paths; validated mDNS input; mDNS service renamed `_browsermesh._tcp` (the former `_clawser` name still works)
- Depend on the scoped `@johnhenry/browsermesh-*` packages
- Signalling tests: the test servers bind 127.0.0.1 (`listen(port, host)`, new optional second argument; the default bind is unchanged) so a connection meant for the server cannot reach another local program that holds the same port number. No change to how the server runs

## 0.1.0 (2026-03-15)

- Initial release: signaling, relay, and kernel servers extracted from the private monorepo
- WebRTC signaling with configurable STUN/TURN
- Envelope relay with per-peer rate limiting
- Server kernel with filesystem and stub agent services
- Docker Compose and Fly.io deployment configs
- Full test suites for all three services
