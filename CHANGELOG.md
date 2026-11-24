# Changelog

## Unreleased

- Signalling: no third-party STUN by default; time-limited TURN credentials (`TURN_SECRET`); `/ice-servers` answered only to the bearer token or the same origin, rate limited; exact-origin CORS
- Signalling: authenticated mode is a challenge/response protocol (protocol 2) that binds the pod id to the proven key; open mode stamps peers `verified: false`; per-address limits, backpressure, idle timeout
- Relay: origin allow-list, per-address limits, backpressure, idle timeout; envelopes stamped `sourceVerified: false`; optional wsh pipe-relay route (`PIPE_RELAY=1`)
- Kernel: remote calls reach only declared methods of allow-listed services; constant-time token check; contained file paths; validated mDNS input; mDNS service renamed `_browsermesh._tcp` (the former `_clawser` name still works)
- Depend on the scoped `@johnhenry/browsermesh-*` packages

## 0.1.0 (2026-03-15)

- Initial release: signaling, relay, and kernel servers extracted from the private monorepo
- WebRTC signaling with configurable STUN/TURN
- Envelope relay with per-peer rate limiting
- Server kernel with filesystem and stub agent services
- Docker Compose and Fly.io deployment configs
- Full test suites for all three services
