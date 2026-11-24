/**
 * Clawser P2P Mesh — WebSocket Signaling Server
 *
 * Adapted from the webrtc-chat server pattern but uses podId-based
 * registration instead of URL params.
 *
 * Protocol:
 *   1. Client connects via WebSocket
 *   2. Client sends: { type: 'register', podId: '<unique-id>' }
 *   3. Server confirms: { type: 'registered', podId }
 *   4. Server broadcasts: { type: 'peers', peers: [...] }
 *   5. Client sends signaling messages:
 *        { type: 'offer'|'answer'|'ice-candidate'|'signal', target: '<podId>', ...payload }
 *   6. Server forwards to target with `source` field injected
 *   7. On disconnect, server broadcasts: { type: 'disconnected', podId }
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
 *   ORIGINS     — comma-separated allowed origins (empty = allow all WebSocket
 *                 origins; CORS is granted only to an exactly listed origin)
 *   AUTH_MODE   — 'open' (default) | 'authenticated' (stub)
 *   ICE_SERVERS, STUN_URLS, ALLOW_PUBLIC_STUN, TURN_URLS, TURN_SECRET,
 *   TURN_TTL_SECONDS — see stun-turn.mjs
 *   MAX_CONNECTIONS       — max concurrent WebSocket connections (default 1024)
 *   MAX_MESSAGES_PER_MINUTE — per-pod rate limit (default 300)
 *   ICE_API_TOKEN         — Bearer token that unlocks /ice-servers for non-same-origin callers
 *   ICE_RATE_LIMIT_PER_MINUTE — /ice-servers requests per client address (default 30)
 *   TRUST_PROXY           — set to 1 behind a proxy that sets Fly-Client-IP / X-Forwarded-For
 */

import http from 'node:http'
import { fileURLToPath } from 'node:url'
import { webcrypto } from 'node:crypto'
import { WebSocketServer } from 'ws'
import { getIceServers, assertIceConfig } from './stun-turn.mjs'
import { RateLimiter, safeEqual, clientIp, envFlag } from './limits.mjs'

// ─── Helpers ──────────────────────────────────────────────────────────

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
 * @returns {{ server: http.Server, wss: WebSocketServer, peers: Map, listen: (port?: number) => Promise<number> }}
 */
export function createServer(opts = {}) {
  const env = opts.env ?? process.env
  const port = opts.port ?? (Number(env.PORT) || 8787)
  const allowedOrigins = parseOrigins(opts.origins ?? env.ORIGINS)
  const authMode = opts.authMode ?? env.AUTH_MODE ?? 'open'
  assertIceConfig(env) // fail at startup on an unusable TURN_SECRET
  const trustProxy = envFlag(env.TRUST_PROXY)
  const iceRateLimiter = new RateLimiter({
    limit: Number(env.ICE_RATE_LIMIT_PER_MINUTE) || 30,
    windowMs: 60_000,
  })
  const maxConnections = opts.maxConnections ?? (Number(env.MAX_CONNECTIONS) || 1024)
  const maxMessagesPerMinute = opts.maxMessagesPerMinute ?? (Number(env.MAX_MESSAGES_PER_MINUTE) || 300)
  const iceApiToken = env.ICE_API_TOKEN ?? null

  /** @type {Map<string, import('ws').WebSocket>} podId → ws */
  const peers = new Map()

  /** @type {Map<import('ws').WebSocket, string>} ws → podId (reverse lookup) */
  const wsBySocket = new Map()

  /** @type {Map<string, { count: number, resetAt: number }>} */
  const rateLimits = new Map()

  function checkRateLimit(podId) {
    const now = Date.now()
    let entry = rateLimits.get(podId)
    if (!entry || now >= entry.resetAt) {
      entry = { count: 0, resetAt: now + 60_000 }
      rateLimits.set(podId, entry)
    }
    entry.count++
    return entry.count <= maxMessagesPerMinute
  }

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

  const wss = new WebSocketServer({ server, maxPayload: 64 * 1024 })

  wss.on('connection', (ws, req) => {
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

    ws.isAlive = true
    ws.on('pong', () => { ws.isAlive = true })
    const heartbeat = setInterval(() => {
      if (!ws.isAlive) { ws.terminate(); return }
      ws.isAlive = false
      ws.ping()
    }, 30_000)

    let registered = false
    let podId = null

    // Clients must register within 10 seconds
    const registrationTimeout = setTimeout(() => {
      if (!registered) {
        send(ws, { type: 'error', message: 'registration timeout' })
        ws.close(4408, 'registration timeout')
      }
    }, 10_000)

    ws.on('message', async (raw) => {
      let msg
      try {
        msg = JSON.parse(raw.toString())
      } catch {
        send(ws, { type: 'error', message: 'invalid JSON' })
        return
      }

      // ── Registration ─────────────────────────────────────────────
      if (!registered) {
        if (msg.type !== 'register' || typeof msg.podId !== 'string' || !msg.podId) {
          send(ws, { type: 'error', message: 'first message must be { type: "register", podId: string }' })
          return
        }

        if (msg.podId.length > 128) {
          send(ws, { type: 'error', message: 'podId must be 128 chars or fewer' })
          ws.close(4400, 'invalid podId')
          clearTimeout(registrationTimeout)
          return
        }

        // Auth check — Ed25519 signature verification
        if (authMode === 'authenticated') {
          if (!msg.pubKey || !msg.signature) {
            send(ws, { type: 'error', message: 'authenticated mode requires pubKey and signature' })
            ws.close(4401, 'missing credentials')
            clearTimeout(registrationTimeout)
            return
          }
          try {
            const pubKeyBytes = Uint8Array.from(atob(msg.pubKey), c => c.charCodeAt(0))
            const sigBytes = Uint8Array.from(atob(msg.signature), c => c.charCodeAt(0))
            const key = await webcrypto.subtle.importKey('raw', pubKeyBytes, { name: 'Ed25519' }, false, ['verify'])
            const valid = await webcrypto.subtle.verify('Ed25519', key, sigBytes, new TextEncoder().encode(msg.podId))
            if (!valid) {
              send(ws, { type: 'error', message: 'signature verification failed' })
              ws.close(4401, 'invalid signature')
              clearTimeout(registrationTimeout)
              return
            }
          } catch (err) {
            send(ws, { type: 'error', message: 'authentication failed' })
            ws.close(4401, 'auth error')
            clearTimeout(registrationTimeout)
            return
          }
        }

        // Reject duplicate podId
        if (peers.has(msg.podId)) {
          send(ws, { type: 'error', message: 'podId already registered' })
          ws.close(4409, 'podId already registered')
          clearTimeout(registrationTimeout)
          return
        }

        podId = msg.podId
        registered = true
        clearTimeout(registrationTimeout)

        peers.set(podId, ws)
        wsBySocket.set(ws, podId)

        // Confirm registration
        send(ws, { type: 'registered', podId })

        // Send full peer list to the new peer; notify others of join
        send(ws, { type: 'peers', peers: [...peers.keys()] })
        broadcast({ type: 'peer-joined', podId }, ws)
        return
      }

      // ── Forwarding ───────────────────────────────────────────────
      if (FORWARDABLE.has(msg.type)) {
        if (!checkRateLimit(podId)) {
          send(ws, { type: 'error', message: 'rate limit exceeded' })
          return
        }
        const { target, ...payload } = msg
        if (typeof target !== 'string' || !target) {
          send(ws, { type: 'error', message: 'forwarded messages require a "target" field' })
          return
        }

        const targetWs = peers.get(target)
        if (!targetWs) {
          send(ws, { type: 'error', message: `peer "${target}" not found` })
          return
        }

        // Forward with source identification
        send(targetWs, { ...payload, source: podId })
        return
      }

      // ── Ping / keep-alive ────────────────────────────────────────
      if (msg.type === 'ping') {
        send(ws, { type: 'pong', timestamp: Date.now() })
        return
      }

      send(ws, { type: 'error', message: `unknown message type: ${msg.type}` })
    })

    ws.on('close', () => {
      clearInterval(heartbeat)
      clearTimeout(registrationTimeout)
      if (podId) {
        peers.delete(podId)
        wsBySocket.delete(ws)

        // Notify remaining peers
        broadcast({ type: 'peer-left', podId })
        rateLimits.delete(podId)
      }
    })

    ws.on('error', () => {
      // Let 'close' handle cleanup
    })
  })

  // ── Broadcasting helpers ─────────────────────────────────────────

  function broadcast(data, exclude) {
    for (const [, ws] of peers) {
      if (ws !== exclude) send(ws, data)
    }
  }

  // broadcastPeerList() removed — replaced by incremental peer-joined/peer-left events

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
      wsBySocket.clear()

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
  console.log(`[signaling] health check: http://localhost:${port}/health`)

  const shutdown = async () => {
    console.log('\n[signaling] shutting down...')
    await instance.close()
    process.exitCode = 0
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}
