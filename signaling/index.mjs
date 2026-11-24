/**
 * BrowserMesh WebSocket Signaling Server
 *
 * Pods register with a pod id, then exchange offers/answers/ICE candidates
 * through the server. The server forwards; it never interprets the payload.
 *
 * Two registration modes (AUTH_MODE):
 *
 *   open (default)  — any pod id is accepted. Nothing proves who a client is,
 *                     so every peer is stamped `verified: false` (in
 *                     `registered`, `peers`, `peer-joined`, and `sourceVerified`
 *                     on every forwarded message) and clients can tell.
 *   authenticated   — protocol 2, see auth.mjs. A pod id must be the hash of
 *                     the Ed25519 key the client proves it holds, by signing a
 *                     single-use server nonce together with the id, the
 *                     server's origin and a purpose. Peers are stamped
 *                     `verified: true`. A client that does not speak protocol 2
 *                     is refused with `code: 'protocol-unsupported'`.
 *
 * Protocol:
 *   1. Client connects via WebSocket. (authenticated: server sends
 *      { type: 'challenge', protocol: 2, purpose, origin, nonce, ttlMs })
 *   2. Client sends: { type: 'register', podId } (authenticated: plus
 *      protocol: 2, pubKey, nonce, signature)
 *   3. Server confirms: { type: 'registered', podId, mode, verified }
 *   4. Server sends the new peer { type: 'peers', peers: [...], verified } and
 *      tells the others { type: 'peer-joined', podId, verified }
 *      (PEER_DISCOVERY=none turns these, and peer-left, off)
 *   5. Client sends signaling messages:
 *        { type: 'offer'|'answer'|'ice-candidate'|'signal', target: '<podId>', ...payload }
 *   6. Server forwards to target with `source`, `from` and `sourceVerified`
 *      set by the server (whatever the sender put there is overwritten)
 *   7. On disconnect, server tells the others { type: 'peer-left', podId }
 *
 * HTTP endpoints:
 *   GET /health      → { status: 'ok', peers: N }
 *   GET /ice-servers  → ICE server configuration array (time-limited TURN
 *                       credentials). Answered only to a caller that sends
 *                       `Authorization: Bearer <ICE_API_TOKEN>` or that is the
 *                       same origin as this server; rate limited per address.
 *
 * Env vars:
 *   PORT        — listen port (default 8787)
 *   ORIGINS     — comma-separated allowed origins for WebSocket upgrades (empty =
 *                 allow all) and for CORS (granted only to an exactly listed origin)
 *   AUTH_MODE   — 'open' (default) | 'authenticated'; anything else is an error
 *   PUBLIC_ORIGIN — authenticated mode: this server's own ws:// or wss:// origin
 *                 (what clients sign); required there
 *   AUTH_NONCE_TTL_MS — lifetime of a challenge (default 30000)
 *   PEER_DISCOVERY — 'all' (default) | 'none': whether peers learn the other pod ids
 *   ICE_SERVERS, STUN_URLS, ALLOW_PUBLIC_STUN, TURN_URLS, TURN_SECRET,
 *   TURN_TTL_SECONDS — see stun-turn.mjs
 *   MAX_CONNECTIONS       — max concurrent WebSocket connections (default 1024)
 *   MAX_CONNECTIONS_PER_IP — max concurrent connections per client address (default 100)
 *   MAX_CONNECTS_PER_MINUTE_PER_IP — new connections per client address per minute (default 120)
 *   MAX_MESSAGES_PER_MINUTE — per-connection message limit (default 300)
 *   MAX_BUFFERED_BYTES    — a receiver with more than this unsent is dropped (default 1 MiB)
 *   IDLE_TIMEOUT_MS       — close a registered connection that sent nothing for this long (default 0 = off)
 *   ICE_API_TOKEN         — Bearer token that unlocks /ice-servers for non-same-origin callers
 *   ICE_RATE_LIMIT_PER_MINUTE — /ice-servers requests per client address (default 30)
 *   TRUST_PROXY           — set to 1 behind a proxy that sets Fly-Client-IP / X-Forwarded-For
 */

import http from 'node:http'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'
import { WebSocketServer } from 'ws'
import { getIceServers, assertIceConfig } from './stun-turn.mjs'
import { RateLimiter, safeEqual, clientIp, envFlag } from './limits.mjs'
import { PROTOCOL_VERSION, REGISTER_PURPOSE, verifyRegistration } from './auth.mjs'

// ─── Helpers ──────────────────────────────────────────────────────────

const MAX_MESSAGE_BYTES = 64 * 1024
const PRE_REGISTRATION_MESSAGE_LIMIT = 8

function send(ws, data) {
  if (ws.readyState === 1 /* OPEN */) {
    ws.send(JSON.stringify(data))
  }
}

function parseOrigins(raw) {
  if (!raw) return null
  return raw.split(',').map(o => o.trim()).filter(Boolean)
}

function originAllowed(origin, allowedOrigins) {
  if (!allowedOrigins) return true
  if (!origin) return false
  return allowedOrigins.includes(origin)
}

/** A short, printable form of something a client sent, for echoing back. */
function brief(v) {
  return typeof v === 'string' ? JSON.stringify(v.slice(0, 64)) : typeof v
}

/** Normalise PUBLIC_ORIGIN to a ws:// or wss:// origin, or throw. */
function parsePublicOrigin(raw) {
  let u
  try { u = new URL(String(raw)) } catch { u = null }
  if (!u || (u.protocol !== 'ws:' && u.protocol !== 'wss:') || u.username || u.password) {
    throw new Error('PUBLIC_ORIGIN must be this server\'s ws:// or wss:// origin, for example wss://signal.example.org')
  }
  return u.origin
}

// ─── Signaling message types that get forwarded ──────────────────────

const FORWARDABLE = new Set(['offer', 'answer', 'ice-candidate', 'signal'])

// ─── Server factory ──────────────────────────────────────────────────

/**
 * Create and return the HTTP + WebSocket signaling server.
 *
 * @param {object} [opts]
 * @param {number} [opts.port]       — listen port (default from env or 8787)
 * @param {string} [opts.origins]    — comma-separated allowed origins
 * @param {string} [opts.authMode]   — 'open' | 'authenticated'
 * @param {object} [opts.env]        — environment overrides
 * @param {() => number} [opts.now]  — clock (ms), for tests
 * @returns {{ server: http.Server, wss: WebSocketServer, peerCount: number, listPeers: () => string[], listen: (port?: number) => Promise<number>, close: () => Promise<void> }}
 */
export function createServer(opts = {}) {
  const env = opts.env ?? process.env
  const now = opts.now ?? Date.now
  const port = opts.port ?? (Number(env.PORT) || 8787)
  const allowedOrigins = parseOrigins(opts.origins ?? env.ORIGINS)
  const authMode = opts.authMode ?? env.AUTH_MODE ?? 'open'
  if (authMode !== 'open' && authMode !== 'authenticated') {
    throw new Error(`AUTH_MODE must be "open" or "authenticated" (got ${brief(authMode)})`)
  }
  const authenticated = authMode === 'authenticated'
  const publicOrigin = authenticated ? parsePublicOrigin(opts.publicOrigin ?? env.PUBLIC_ORIGIN) : null
  const nonceTtlMs = Number(env.AUTH_NONCE_TTL_MS) > 0 ? Number(env.AUTH_NONCE_TTL_MS) : 30_000
  const peerDiscovery = env.PEER_DISCOVERY ?? 'all'
  if (peerDiscovery !== 'all' && peerDiscovery !== 'none') {
    throw new Error(`PEER_DISCOVERY must be "all" or "none" (got ${brief(peerDiscovery)})`)
  }
  const announcePeers = peerDiscovery === 'all'
  assertIceConfig(env) // fail at startup on an unusable TURN_SECRET
  const trustProxy = envFlag(env.TRUST_PROXY)
  const iceRateLimiter = new RateLimiter({
    limit: Number(env.ICE_RATE_LIMIT_PER_MINUTE) || 30,
    windowMs: 60_000,
    now,
  })
  const maxConnections = opts.maxConnections ?? (Number(env.MAX_CONNECTIONS) || 1024)
  const maxConnectionsPerIp = opts.maxConnectionsPerIp ?? (Number(env.MAX_CONNECTIONS_PER_IP) || 100)
  const connectRateLimiter = new RateLimiter({
    limit: opts.maxConnectsPerMinutePerIp ?? (Number(env.MAX_CONNECTS_PER_MINUTE_PER_IP) || 120),
    windowMs: 60_000,
    now,
  })
  const maxMessagesPerMinute = opts.maxMessagesPerMinute ?? (Number(env.MAX_MESSAGES_PER_MINUTE) || 300)
  const maxBufferedBytes = opts.maxBufferedBytes ?? (Number(env.MAX_BUFFERED_BYTES) || 1024 * 1024)
  const idleTimeoutMs = opts.idleTimeoutMs ?? (Number(env.IDLE_TIMEOUT_MS) || 0)
  const iceApiToken = env.ICE_API_TOKEN ?? null

  /** @type {Map<string, import('ws').WebSocket>} podId → ws */
  const peers = new Map()

  /** @type {Map<string, number>} client address → open connections */
  const connectionsByIp = new Map()

  // ── HTTP server ──────────────────────────────────────────────────

  /**
   * CORS headers for a request: the request's Origin is reflected only when it
   * is exactly one of the configured ORIGINS (never a wildcard), and the
   * response then varies by Origin.
   */
  function corsHeaders(req) {
    const origin = req.headers.origin
    const headers = { Vary: 'Origin' }
    if (origin && allowedOrigins && allowedOrigins.includes(origin)) {
      headers['Access-Control-Allow-Origin'] = origin
    }
    return headers
  }

  /** True when the caller is the page this server itself serves (same origin). */
  function isSameOrigin(req) {
    if (req.headers['sec-fetch-site'] === 'same-origin') return true
    const origin = req.headers.origin
    const host = req.headers.host
    if (!origin || !host) return false
    try {
      return new URL(origin).host === host
    } catch {
      return false
    }
  }

  /** Bearer token check, constant time. */
  function hasValidToken(req) {
    if (!iceApiToken) return false
    const auth = req.headers.authorization
    if (typeof auth !== 'string' || !auth.startsWith('Bearer ')) return false
    return safeEqual(auth.slice(7), iceApiToken)
  }

  const server = http.createServer((req, res) => {
    let pathname
    try {
      pathname = new URL(req.url, 'http://localhost').pathname
    } catch {
      res.writeHead(400)
      return res.end()
    }

    // CORS preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        ...corsHeaders(req),
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Authorization, Content-Type',
        'Access-Control-Max-Age': '600',
      })
      return res.end()
    }

    const headers = {
      'Content-Type': 'application/json',
      ...corsHeaders(req),
    }

    if (req.method === 'GET' && pathname === '/health') {
      res.writeHead(200, headers)
      return res.end(JSON.stringify({ status: 'ok', peers: peers.size }))
    }

    if (req.method === 'GET' && pathname === '/ice-servers') {
      headers['Cache-Control'] = 'no-store'

      // Rate limit first, so failed attempts cost the caller too.
      const rl = iceRateLimiter.hit(clientIp(req, trustProxy))
      if (!rl.ok) {
        res.writeHead(429, { ...headers, 'Retry-After': String(Math.ceil(rl.retryAfterMs / 1000)) })
        return res.end(JSON.stringify({ error: 'rate limit exceeded' }))
      }

      // Only a caller holding the token, or the page this server itself
      // serves, gets credentials. Everyone else is refused.
      if (!hasValidToken(req) && !isSameOrigin(req)) {
        res.writeHead(401, headers)
        return res.end(JSON.stringify({ error: 'unauthorized' }))
      }

      res.writeHead(200, headers)
      return res.end(JSON.stringify(getIceServers(env)))
    }

    res.writeHead(404, headers)
    res.end(JSON.stringify({ error: 'not found' }))
  })

  // ── WebSocket server ─────────────────────────────────────────────

  // maxPayload is enforced by ws on the frame header, before any of the
  // message is buffered or parsed.
  const wss = new WebSocketServer({ server, maxPayload: MAX_MESSAGE_BYTES })

  /**
   * Send to a peer; a receiver that has fallen too far behind is dropped
   * rather than letting its queue grow.
   * @returns {boolean} whether the message was handed to the socket
   */
  function sendToPeer(ws, data) {
    if (ws.readyState !== 1) return false
    if (ws.bufferedAmount > maxBufferedBytes) {
      ws.close(4413, 'receiver too slow')
      setImmediate(() => ws.terminate())
      return false
    }
    ws.send(JSON.stringify(data))
    return true
  }

  function broadcast(data, exclude) {
    if (!announcePeers) return
    for (const [, ws] of peers) {
      if (ws !== exclude) sendToPeer(ws, data)
    }
  }

  wss.on('connection', (ws, req) => {
    const ip = clientIp(req, trustProxy)

    const origin = req.headers.origin
    if (!originAllowed(origin, allowedOrigins)) {
      send(ws, { type: 'error', message: 'origin not allowed' })
      ws.close(4403, 'origin not allowed')
      return
    }

    if (wss.clients.size > maxConnections) {
      send(ws, { type: 'error', message: 'server at capacity' })
      ws.close(4503, 'too many connections')
      return
    }

    if ((connectionsByIp.get(ip) ?? 0) >= maxConnectionsPerIp || !connectRateLimiter.hit(ip).ok) {
      send(ws, { type: 'error', message: 'too many connections from this address' })
      ws.close(4429, 'too many connections from this address')
      return
    }
    connectionsByIp.set(ip, (connectionsByIp.get(ip) ?? 0) + 1)

    ws.isAlive = true
    ws.on('pong', () => { ws.isAlive = true })
    const heartbeat = setInterval(() => {
      if (!ws.isAlive) { ws.terminate(); return }
      ws.isAlive = false
      ws.ping()
    }, 30_000)

    let registered = false
    let podId = null
    let preRegistrationMessages = 0
    const messageLimiter = new RateLimiter({ limit: maxMessagesPerMinute, windowMs: 60_000, maxKeys: 1, now })

    // Clients must register within 10 seconds
    const registrationTimeout = setTimeout(() => {
      if (!registered) {
        send(ws, { type: 'error', message: 'registration timeout' })
        ws.close(4408, 'registration timeout')
      }
    }, 10_000)

    // Registered connections that go silent are closed when IDLE_TIMEOUT_MS is set.
    let idleTimer = null
    function touch() {
      if (!idleTimeoutMs || !registered) return
      clearTimeout(idleTimer)
      idleTimer = setTimeout(() => {
        send(ws, { type: 'error', message: 'idle timeout' })
        ws.close(4408, 'idle timeout')
      }, idleTimeoutMs)
    }

    // Authenticated mode: one challenge per connection, usable once.
    let challenge = null
    if (authenticated) {
      challenge = { nonce: randomBytes(16).toString('base64url'), issuedAt: now(), used: false }
      send(ws, {
        type: 'challenge',
        protocol: PROTOCOL_VERSION,
        purpose: REGISTER_PURPOSE,
        origin: publicOrigin,
        nonce: challenge.nonce,
        ttlMs: nonceTtlMs,
      })
    }

    /** Refuse an authentication attempt and end the connection. */
    function refuse(code, message, closeCode = 4401, extra = {}) {
      clearTimeout(registrationTimeout)
      send(ws, { type: 'error', code, message, ...extra })
      ws.close(closeCode, code)
    }

    async function register(msg) {
      if (typeof msg.podId !== 'string' || !msg.podId) {
        send(ws, { type: 'error', message: 'first message must be { type: "register", podId: string }' })
        return
      }

      if (msg.podId.length > 128) {
        send(ws, { type: 'error', message: 'podId must be 128 chars or fewer' })
        ws.close(4400, 'invalid podId')
        clearTimeout(registrationTimeout)
        return
      }

      if (authenticated) {
        // Old clients: no protocol 2 answer to the challenge.
        if (msg.protocol !== PROTOCOL_VERSION) {
          return refuse(
            'protocol-unsupported',
            `this server requires protocol ${PROTOCOL_VERSION}: answer the "challenge" message with { type: "register", protocol: ${PROTOCOL_VERSION}, podId, pubKey, nonce, signature }`,
            4426,
            { required: PROTOCOL_VERSION },
          )
        }
        // The challenge is spent by the first attempt, right or wrong.
        if (challenge.used) return refuse('bad-nonce', 'challenge already used')
        challenge.used = true
        if (typeof msg.nonce !== 'string' || !safeEqual(msg.nonce, challenge.nonce)) {
          return refuse('bad-nonce', 'nonce does not match the challenge issued on this connection')
        }
        if (now() - challenge.issuedAt > nonceTtlMs) {
          return refuse('challenge-expired', 'challenge expired; reconnect and try again')
        }
        const result = await verifyRegistration({
          podId: msg.podId,
          pubKey: msg.pubKey,
          signature: msg.signature,
          nonce: challenge.nonce,
          origin: publicOrigin,
        })
        if (!result.ok) return refuse(result.code, result.message)
        if (ws.readyState !== 1) return // went away while verifying
      }

      const existing = peers.get(msg.podId)
      if (existing) {
        if (!authenticated) {
          send(ws, { type: 'error', message: 'podId already registered' })
          ws.close(4409, 'podId already registered')
          clearTimeout(registrationTimeout)
          return
        }
        // Authenticated: the id is the hash of a key this client just proved
        // it holds, so it is the same pod reconnecting; it replaces its stale
        // connection.
        existing.close(4409, 'replaced by a newer connection')
      }

      podId = msg.podId
      registered = true
      clearTimeout(registrationTimeout)
      touch()

      peers.set(podId, ws)

      // Confirm registration
      send(ws, { type: 'registered', podId, mode: authMode, verified: authenticated })

      // Send full peer list to the new peer; notify others of join
      if (announcePeers) {
        send(ws, { type: 'peers', peers: [...peers.keys()], verified: authenticated })
        if (!existing) broadcast({ type: 'peer-joined', podId, verified: authenticated }, ws)
      }
    }

    ws.on('message', async (raw) => {
      let msg
      try {
        msg = JSON.parse(raw.toString())
      } catch {
        send(ws, { type: 'error', message: 'invalid JSON' })
        return
      }
      if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
        send(ws, { type: 'error', message: 'messages must be JSON objects' })
        return
      }

      // ── Registration ─────────────────────────────────────────────
      if (!registered) {
        if (++preRegistrationMessages > PRE_REGISTRATION_MESSAGE_LIMIT) {
          ws.close(4429, 'too many messages before registration')
          return
        }
        if (msg.type !== 'register') {
          send(ws, { type: 'error', message: 'first message must be { type: "register", podId: string }' })
          return
        }
        try {
          await register(msg)
        } catch {
          // Never let a handler error escape: it would take the process down.
          send(ws, { type: 'error', message: 'registration failed' })
          ws.close(1011, 'internal error')
        }
        return
      }

      touch()

      // Every message counts, not only forwarded ones.
      const rl = messageLimiter.hit('c')
      if (!rl.ok) {
        send(ws, { type: 'error', message: 'rate limit exceeded' })
        return
      }

      // ── Forwarding ───────────────────────────────────────────────
      if (FORWARDABLE.has(msg.type)) {
        const { target, ...payload } = msg
        if (typeof target !== 'string' || !target) {
          send(ws, { type: 'error', message: 'forwarded messages require a "target" field' })
          return
        }

        const targetWs = peers.get(target)
        if (!targetWs) {
          send(ws, { type: 'error', message: 'peer not found', target: target.slice(0, 128) })
          return
        }

        // Forward with source identification. The server decides who the
        // sender is and whether that was verified: whatever the sender put in
        // these fields is overwritten.
        const forwarded = { ...payload, source: podId, sourceVerified: authenticated }
        if (Object.hasOwn(payload, 'from')) forwarded.from = podId
        if (!sendToPeer(targetWs, forwarded)) {
          send(ws, { type: 'error', message: 'peer is not accepting messages', target: target.slice(0, 128) })
        }
        return
      }

      // ── Ping / keep-alive ────────────────────────────────────────
      if (msg.type === 'ping') {
        send(ws, { type: 'pong', timestamp: now() })
        return
      }

      send(ws, { type: 'error', message: `unknown message type: ${brief(msg.type)}` })
    })

    ws.on('close', () => {
      clearInterval(heartbeat)
      clearTimeout(registrationTimeout)
      clearTimeout(idleTimer)
      const n = (connectionsByIp.get(ip) ?? 1) - 1
      if (n > 0) connectionsByIp.set(ip, n)
      else connectionsByIp.delete(ip)
      // Only the connection that currently holds the id releases it.
      if (podId && peers.get(podId) === ws) {
        peers.delete(podId)

        // Notify remaining peers
        broadcast({ type: 'peer-left', podId })
      }
    })

    ws.on('error', () => {
      // Let 'close' handle cleanup
    })
  })

  // ── Public API ───────────────────────────────────────────────────

  /**
   * Start listening and return the assigned port.
   * Pass port 0 for an OS-assigned ephemeral port.
   *
   * @param {number} [listenPort]
   * @returns {Promise<number>} — the actual port the server is listening on
   */
  function listen(listenPort) {
    const p = listenPort ?? port
    return new Promise((resolve, reject) => {
      const onError = (err) => reject(err)
      server.once('error', onError)
      server.listen(p, () => {
        server.removeListener('error', onError)
        const addr = server.address()
        resolve(typeof addr === 'object' ? addr.port : p)
      })
    })
  }

  /**
   * Gracefully shut down the server.
   * @returns {Promise<void>}
   */
  function close() {
    return new Promise((resolve) => {
      // Close all WebSocket connections (registered + unregistered)
      for (const ws of wss.clients) {
        ws.terminate()
      }
      peers.clear()

      wss.close(() => {
        server.close(() => resolve())
      })
    })
  }

  return { server, wss, get peerCount() { return peers.size }, listPeers: () => [...peers.keys()], listen, close }
}

// ─── Direct execution ────────────────────────────────────────────────

const isMain = process.argv[1] === fileURLToPath(import.meta.url)

if (isMain) {
  const instance = createServer()
  const port = await instance.listen()
  console.log(`[signaling] listening on port ${port}`)
  console.log(`[signaling] auth mode: ${process.env.AUTH_MODE ?? 'open'}`)
  if ((process.env.AUTH_MODE ?? 'open') === 'open') {
    console.log('[signaling] open mode: pod ids are not verified and peers are stamped unverified')
  }
  if (!process.env.ORIGINS) {
    console.log('[signaling] ORIGINS is not set: WebSocket connections are accepted from any origin')
  }
  console.log(`[signaling] health check: http://localhost:${port}/health`)

  const shutdown = async () => {
    console.log('\n[signaling] shutting down...')
    await instance.close()
    process.exitCode = 0
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}
