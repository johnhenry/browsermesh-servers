# browsermesh-servers

Three standalone Node.js services that support browser-based P2P mesh networking. Each is independently deployable with zero shared dependencies beyond `ws`.

## Architecture

```
Browser Pods <──WebSocket──> Signaling Server (port 8787)
             <──WebSocket──> Relay Server     (port 8788)
             <──WebRTC────>  (direct, after signaling)

Server Kernel <──WebSocket──> Signaling Server
              (always-on mesh peer with fs + agent services)
```

## Services

### `signaling/` -- WebRTC Signaling Server (port 8787)

Coordinates WebRTC peer connections by forwarding offer/answer/ICE candidate messages between browser pods. Supports configurable STUN/TURN servers, origin allowlisting, and registration timeouts.

- **Protocol**: register with podId, then exchange offers/answers/ICE candidates via WebSocket
- **HTTP**: `GET /health`, `GET /ice-servers`
- **Env**: `PORT` (8787), `ORIGINS`, `AUTH_MODE`, `ICE_SERVERS`, `TURN_URLS`, `TURN_USERNAME`, `TURN_CREDENTIAL`

### `relay/` -- Envelope Relay Server (port 8788)

Forwards opaque envelopes between peers that cannot establish direct WebRTC connections (symmetric NAT, firewalls). The server never inspects message content.

- **Protocol**: register with podId, then relay envelopes to target peers
- **HTTP**: `GET /health`, `GET /stats`
- **Env**: `PORT` (8788), `MAX_MESSAGES_PER_MINUTE` (600)
- **Features**: per-peer rate limiting, relay/reject counters

### `kernel/` -- Server-Side Mesh Peer (port 8789)

An always-on Node.js peer that participates in the mesh network. Provides file storage (`fs` service) and a stub agent (`agent` service) that can be extended with LLM backends.

- **Components**: ServerIdentity, ServerFileSystem (path traversal prevention, 10MB limit), ServerAgent, PeerNodeServer
- **Env**: `SIGNALING_URL`, `DATA_DIR` (./data), `AGENT_NAME`, `POD_LABEL`
- **mDNS**: optional local network discovery via `multicast-dns`

## Quick Start

```bash
# Install all dependencies
npm install

# Start individual services
npm run start:signaling
npm run start:relay
npm run start:kernel

# Run all tests
npm test
```

## Docker Deployment

All three services can be deployed together with Docker Compose:

```bash
cd deploy
docker compose up
```

This exposes:
- Signaling on `localhost:8787`
- Relay on `localhost:8788`
- Kernel connects to signaling automatically, data persisted in a `kernel-data` volume

### Fly.io

The `deploy/fly.toml` is configured for deploying the signaling server with TLS on port 443:

```bash
cd deploy
fly deploy
```

## Testing

```bash
# All tests
npm test

# Individual
cd signaling && npm test   # 28 tests
cd relay && npm test        # 19 tests
cd kernel && npm test       # 35 tests
```

All tests use real HTTP/WebSocket connections (no mocks) with ephemeral ports.

## Security Notes

- **No auth by default** -- `AUTH_MODE=open` accepts any podId
- **No TLS in dev** -- use a reverse proxy or Fly.io for production
- **Rate limiting** -- relay server enforces per-peer message limits
- **Path traversal** -- kernel filesystem prevents `../` escapes
- **File size** -- kernel enforces 10MB write limit

## License

MIT
