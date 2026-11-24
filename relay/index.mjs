/**
 * BrowserMesh P2P Mesh — Relay Server
 *
 * Envelope forwarding for peers behind symmetric NAT. Peers register
 * with their podId, then relay envelopes to each other. The server
 * never inspects or stores message content.
 *
 * The relay is OPEN: it does not verify that a pod id belongs to the client
 * using it, so every relayed envelope is stamped `sourceVerified: false`.
 * Protection of what travels through it is end to end (signed pod messages;
 * see johnhenry/browsermesh docs/security.md), not the relay's.
 *
 * Protocol:
 *   1. Client connects via WebSocket
 *   2. Client sends: { type: 'register', podId: '<unique-id>' }
 *   3. Server confirms: { type: 'registered', podId }
 *   4. Client sends: { type: 'relay', target: '<podId>', envelope: {...} }
 *   5. Server forwards { type: 'relayed', source, sourceVerified: false, envelope }
 *      to the target; `source` is set by the server
 *   6. On disconnect, server cleans up peer entry
 *
 * HTTP endpoints:
 *   GET /health → { status: 'ok', peers: N }
 *   GET /stats  → { peers: N, relayed: N, rejected: N, uptime: N }
 *
 * Env vars:
 *   PORT                    — listen port (default 8788)
 *   ORIGINS                 — comma-separated allowed origins for WebSocket upgrades
 *                             (empty = allow all) and for CORS (exactly listed only)
 *   MAX_MESSAGES_PER_MINUTE — per-peer rate limit, every message counted (default 600)
 *   MAX_CONNECTIONS          — max simultaneous WebSocket connections (default 1024)
 *   MAX_CONNECTIONS_PER_IP   — max concurrent connections per client address (default 100)
 *   MAX_CONNECTS_PER_MINUTE_PER_IP — new connections per client address per minute (default 120)
 *   MAX_BUFFERED_BYTES       — a receiver with more than this unsent is dropped (default 1 MiB)
 *   IDLE_TIMEOUT_MS          — close a registered connection silent for this long (default 0 = off)
 *   TRUST_PROXY              — set to 1 behind a proxy that sets Fly-Client-IP / X-Forwarded-For
 */

import http from 'node:http'
import { WebSocketServer } from 'ws'
import { fileURLToPath } from 'node:url'
import { RateLimiter, clientIp, envFlag } from './limits.mjs'
import { PipeRoute, resolvePipeConfig } from './pipe.mjs'

// Anything that looks like `.../r/<something>` belongs to the pipe route (or to
// nobody when it is off): it never falls through to the JSON relay.
const PIPE_PATH_RE = /\/r\/[^/]*$/
function safePathname(req) {
  try { return new URL(req.url, 'http://localhost').pathname } catch { return '' }
}

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

// ─── RelayServer ──────────────────────────────────────────────────────

class RelayServer {
  /** @type {Map<string, import('ws').WebSocket>} */
  #peers = new Map()

  #limiter
  #maxBufferedBytes
  #onLog
  #relayedCount = 0
  #rejectedCount = 0

  /**
   * @param {object} [opts]
   * @param {number} [opts.maxMessagesPerMinute] — rate limit per peer (default 600)
   * @param {number} [opts.maxBufferedBytes]     — drop a receiver holding more unsent than this (default 1 MiB)
   * @param {(msg: string) => void} [opts.onLog]
   */
  constructor(opts = {}) {
    this.#limiter = new RateLimiter({ limit: opts.maxMessagesPerMinute ?? 600, windowMs: 60_000 })
    this.#maxBufferedBytes = opts.maxBufferedBytes ?? 1024 * 1024
    this.#onLog = opts.onLog ?? (() => {})
  }

  /**
   * Register a peer connection.
   * @param {string} podId
   * @param {import('ws').WebSocket} ws
   */
  register(podId, ws) {
    this.#peers.set(podId, ws)
    // Pod ids come from clients and are never written to a log.
    this.#onLog(`[relay] peer registered (${this.#peers.size} connected)`)
  }

  /**
   * Unregister a peer connection. Only the connection that holds the id may
   * release it.
   * @param {string} podId
   * @param {import('ws').WebSocket} [ws]
   */
  unregister(podId, ws) {
    if (ws && this.#peers.get(podId) !== ws) return
    this.#peers.delete(podId)
    this.#onLog(`[relay] peer unregistered (${this.#peers.size} connected)`)
  }

  /**
   * Relay an envelope from one peer to another.
   * @param {string} fromPodId
   * @param {string} toPodId
   * @param {object} envelope
   * @returns {{ success: boolean, error?: string }}
   */
  relay(fromPodId, toPodId, envelope) {
    if (!this.checkRateLimit(fromPodId)) {
      this.#rejectedCount++
      return { success: false, error: 'rate limit exceeded' }
    }

    const targetWs = this.#peers.get(toPodId)
    if (!targetWs) {
      return { success: false, error: 'peer not found' }
    }

    // A receiver that has fallen too far behind is dropped rather than
    // letting its queue grow.
    if (targetWs.bufferedAmount > this.#maxBufferedBytes) {
      targetWs.close?.(4413, 'receiver too slow')
      setImmediate(() => targetWs.terminate?.())
      this.#rejectedCount++
      return { success: false, error: 'peer is not accepting messages' }
    }

    send(targetWs, { type: 'relayed', source: fromPodId, sourceVerified: false, envelope })
    this.#relayedCount++
    return { success: true }
  }

  /**
   * List all registered peer IDs.
   * @returns {string[]}
   */
  listPeers() {
    return Array.from(this.#peers.keys())
  }

  /**
   * Check whether a peer is registered.
   * @param {string} podId
   * @returns {boolean}
   */
  hasPeer(podId) {
    return this.#peers.has(podId)
  }

  /** @returns {number} */
  get size() {
    return this.#peers.size
  }

  /** @returns {number} */
  get relayedCount() {
    return this.#relayedCount
  }

  /** @returns {number} */
  get rejectedCount() {
    return this.#rejectedCount
  }

  /**
   * Check and consume a rate-limit token for a peer.
   * Returns true if the message is allowed, false if rate-limited.
   * @param {string} podId
   * @returns {boolean}
   */
  checkRateLimit(podId) {
    return this.#limiter.hit(podId).ok
  }
}

// ─── Server factory ───────────────────────────────────────────────────

/**
 * Create and return the HTTP + WebSocket relay server.
 *
 * @param {object} [opts]
 * @param {number} [opts.port]                   — listen port (default from env or 8788)
 * @param {number} [opts.maxMessagesPerMinute]    — per-peer rate limit
 * @param {(msg: string) => void} [opts.onLog]
 * @param {object} [opts.env]                    — environment overrides
 * @returns {{ server: http.Server, wss: WebSocketServer, relay: RelayServer, listen: (port?: number) => Promise<number>, close: () => Promise<void> }}
 */
function createRelayServer(opts = {}) {
  const env = opts.env ?? process.env
  const port = opts.port ?? (Number(env.PORT) || 8788)
  const maxMessagesPerMinute = opts.maxMessagesPerMinute ?? (Number(env.MAX_MESSAGES_PER_MINUTE) || 600)
  const maxConnections = opts.maxConnections ?? (Number(env.MAX_CONNECTIONS) || 1024)
  const maxConnectionsPerIp = opts.maxConnectionsPerIp ?? (Number(env.MAX_CONNECTIONS_PER_IP) || 100)
  const maxBufferedBytes = opts.maxBufferedBytes ?? (Number(env.MAX_BUFFERED_BYTES) || 1024 * 1024)
  const idleTimeoutMs = opts.idleTimeoutMs ?? (Number(env.IDLE_TIMEOUT_MS) || 0)
  const allowedOrigins = parseOrigins(opts.origins ?? env.ORIGINS)
  const trustProxy = envFlag(env.TRUST_PROXY)
  const onLog = opts.onLog ?? console.log

  const connectRateLimiter = new RateLimiter({
    limit: opts.maxConnectsPerMinutePerIp ?? (Number(env.MAX_CONNECTS_PER_MINUTE_PER_IP) || 120),
    windowMs: 60_000,
  })
  /** @type {Map<string, number>} client address → open connections */
  const connectionsByIp = new Map()

  const startedAt = Date.now()
  const relay = new RelayServer({ maxMessagesPerMinute, maxBufferedBytes, onLog })

  // wsh pipe relay route: null unless enabled (PIPE_RELAY=1)
  const pipeConfig = resolvePipeConfig(env, opts.pipe, allowedOrigins)
  const pipe = pipeConfig ? new PipeRoute(pipeConfig, { trustProxy }) : null

  // ── HTTP server ──────────────────────────────────────────────────

  /** CORS: the request's Origin is reflected only when exactly listed; never a wildcard. */
  function corsHeaders(req) {
    const origin = req.headers.origin
    const headers = { Vary: 'Origin' }
    if (origin && allowedOrigins && allowedOrigins.includes(origin)) {
      headers['Access-Control-Allow-Origin'] = origin
    }
    return headers
  }

  const server = http.createServer((req, res) => {
    let pathname
    try {
      pathname = new URL(req.url, 'http://localhost').pathname
    } catch {
      res.writeHead(400)
      return res.end()
    }

    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        ...corsHeaders(req),
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      })
      return res.end()
    }

    const headers = {
      'Content-Type': 'application/json',
      ...corsHeaders(req),
    }

    if (req.method === 'GET' && pathname === '/health') {
      res.writeHead(200, headers)
      return res.end(JSON.stringify({ status: 'ok', peers: relay.size }))
    }

    if (req.method === 'GET' && pathname === '/stats') {
      res.writeHead(200, headers)
      return res.end(JSON.stringify({
        peers: relay.size,
        relayed: relay.relayedCount,
        rejected: relay.rejectedCount,
        uptime: Math.floor((Date.now() - startedAt) / 1000),
      }))
    }

    res.writeHead(404, headers)
    res.end(JSON.stringify({ error: 'not found' }))
  })

  // ── WebSocket server ─────────────────────────────────────────────

  // maxPayload is enforced by ws on the frame header, before any of the
  // message is buffered or parsed.
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_MESSAGE_BYTES })

  // Upgrades are routed by hand: `<base>/r/<id>` belongs to the wsh pipe relay
  // (when enabled), everything else to the JSON relay below.
  server.on('upgrade', (req, socket, head) => {
    socket.on('error', () => {})
    const isPipePath = pipe ? pipe.matches(req) : PIPE_PATH_RE.test(safePathname(req))
    if (isPipePath) {
      if (pipe) return pipe.handleUpgrade(req, socket, head)
      // Not enabled: the route does not exist.
      socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
      return socket.destroy()
    }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req))
  })

  wss.on('connection', (ws, req) => {
    const ip = clientIp(req, trustProxy)

    if (!originAllowed(req.headers.origin, allowedOrigins)) {
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

    ws.on('message', (raw) => {
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
        if (msg.type !== 'register' || typeof msg.podId !== 'string' || !msg.podId) {
          send(ws, { type: 'error', message: 'first message must be { type: "register", podId: string }' })
          return
        }

        if (msg.podId.length > 128) {
          send(ws, { type: 'error', message: 'podId must be a string of 128 chars or fewer' })
          ws.close(4400, 'invalid podId')
          clearTimeout(registrationTimeout)
          return
        }

        if (relay.hasPeer(msg.podId)) {
          send(ws, { type: 'error', message: 'podId already registered' })
          ws.close(4409, 'podId already registered')
          clearTimeout(registrationTimeout)
          return
        }

        podId = msg.podId
        registered = true
        clearTimeout(registrationTimeout)
        touch()

        relay.register(podId, ws)

        send(ws, { type: 'registered', podId, verified: false })
        return
      }

      touch()

      // ── Relay ────────────────────────────────────────────────────
      // (relay.relay counts every relay attempt against the peer's budget;
      // everything else is counted here so no message type is free.)
      if (msg.type === 'relay') {
        const { target, envelope } = msg
        if (typeof target !== 'string' || !target) {
          send(ws, { type: 'error', message: 'relay messages require a "target" field' })
          return
        }
        if (!envelope || typeof envelope !== 'object') {
          send(ws, { type: 'error', message: 'relay messages require an "envelope" field' })
          return
        }

        const result = relay.relay(podId, target, envelope)
        if (!result.success) {
          send(ws, { type: 'error', message: result.error })
        }
        return
      }

      if (!relay.checkRateLimit(podId)) {
        send(ws, { type: 'error', message: 'rate limit exceeded' })
        return
      }

      // ── Ping / keep-alive ────────────────────────────────────────
      if (msg.type === 'ping') {
        send(ws, { type: 'pong', timestamp: Date.now() })
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
      if (podId) relay.unregister(podId, ws)
    })

    ws.on('error', () => {
      // Let 'close' handle cleanup
    })
  })

  // ── Public API ─────────────────────────────────────────────────────

  /**
   * Start listening and return the assigned port.
   * @param {number} [listenPort]
   * @returns {Promise<number>}
   */
  function listen(listenPort) {
    const p = listenPort ?? port
    return (pipe ? pipe.start() : Promise.resolve()).then(() => new Promise((resolve, reject) => {
      const onError = (err) => reject(err)
      server.once('error', onError)
      server.listen(p, () => {
        server.removeListener('error', onError)
        const addr = server.address()
        resolve(typeof addr === 'object' ? addr.port : p)
      })
    }))
  }

  /**
   * Gracefully shut down the server.
   * @returns {Promise<void>}
   */
  function close() {
    return Promise.resolve(pipe?.close()).then(() => new Promise((resolve) => {
      // Terminate all clients (registered + unregistered)
      for (const ws of wss.clients) {
        ws.terminate()
      }

      wss.close(() => {
        server.close(() => resolve())
      })
    }))
  }

  return { server, wss, relay, pipe, listen, close }
}

// ─── Direct execution ────────────────────────────────────────────────

const isMain = process.argv[1] === fileURLToPath(import.meta.url)

if (isMain) {
  const instance = createRelayServer()
  const port = await instance.listen()
  console.log(`[relay] listening on port ${port}`)
  if (!process.env.ORIGINS) {
    console.log('[relay] ORIGINS is not set: WebSocket connections are accepted from any origin')
  }
  console.log(`[relay] health check: http://localhost:${port}/health`)
  console.log(`[relay] stats: http://localhost:${port}/stats`)

  const shutdown = async () => {
    console.log('\n[relay] shutting down...')
    await instance.close()
    process.exitCode = 0
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}

export { createRelayServer, RelayServer }
