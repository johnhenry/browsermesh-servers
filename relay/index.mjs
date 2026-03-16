/**
 * Clawser P2P Mesh — Relay Server
 *
 * Envelope forwarding for peers behind symmetric NAT. Peers register
 * with their podId, then relay envelopes to each other. The server
 * never inspects or stores message content.
 *
 * Protocol:
 *   1. Client connects via WebSocket
 *   2. Client sends: { type: 'register', podId: '<unique-id>' }
 *   3. Server confirms: { type: 'registered', podId }
 *   4. Client sends: { type: 'relay', target: '<podId>', envelope: {...} }
 *   5. Server forwards to target with `source` field injected
 *   6. On disconnect, server cleans up peer entry
 *
 * HTTP endpoints:
 *   GET /health → { status: 'ok', peers: N }
 *   GET /stats  → { peers: N, relayed: N, rejected: N, uptime: N }
 *
 * Env vars:
 *   PORT                    — listen port (default 8788)
 *   MAX_MESSAGES_PER_MINUTE — per-peer rate limit (default 600)
 *   MAX_CONNECTIONS          — max simultaneous WebSocket connections (default 1024)
 */

import http from 'node:http'
import { WebSocketServer } from 'ws'
import { fileURLToPath } from 'node:url'

// ─── Helpers ──────────────────────────────────────────────────────────

function send(ws, data) {
  if (ws.readyState === 1 /* OPEN */) {
    ws.send(JSON.stringify(data))
  }
}

// ─── RelayServer ──────────────────────────────────────────────────────

class RelayServer {
  /** @type {Map<string, import('ws').WebSocket>} */
  #peers = new Map()

  /** @type {Map<string, { count: number, resetAt: number }>} */
  #rateLimits = new Map()

  #maxMessagesPerMinute
  #onLog
  #relayedCount = 0
  #rejectedCount = 0

  /**
   * @param {object} [opts]
   * @param {number} [opts.maxMessagesPerMinute] — rate limit per peer (default 600)
   * @param {(msg: string) => void} [opts.onLog]
   */
  constructor(opts = {}) {
    this.#maxMessagesPerMinute = opts.maxMessagesPerMinute ?? 600
    this.#onLog = opts.onLog ?? (() => {})
  }

  /**
   * Register a peer connection.
   * @param {string} podId
   * @param {import('ws').WebSocket} ws
   */
  register(podId, ws) {
    this.#peers.set(podId, ws)
    this.#onLog(`[relay] registered: ${podId}`)
  }

  /**
   * Unregister a peer connection.
   * @param {string} podId
   */
  unregister(podId) {
    this.#peers.delete(podId)
    this.#rateLimits.delete(podId)
    this.#onLog(`[relay] unregistered: ${podId}`)
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
      return { success: false, error: `peer "${toPodId}" not found` }
    }

    send(targetWs, { type: 'relayed', source: fromPodId, envelope })
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
    const now = Date.now()
    let entry = this.#rateLimits.get(podId)

    if (!entry || now >= entry.resetAt) {
      entry = { count: 0, resetAt: now + 60_000 }
      this.#rateLimits.set(podId, entry)
    }

    entry.count++
    return entry.count <= this.#maxMessagesPerMinute
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
  const onLog = opts.onLog ?? console.log

  const startedAt = Date.now()
  const relay = new RelayServer({ maxMessagesPerMinute, onLog })

  /** @type {Map<import('ws').WebSocket, string>} ws → podId (reverse lookup) */
  const wsBySocket = new Map()

  // ── HTTP server ──────────────────────────────────────────────────

  const server = http.createServer((req, res) => {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      })
      return res.end()
    }

    const headers = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    }

    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, headers)
      return res.end(JSON.stringify({ status: 'ok', peers: relay.size }))
    }

    if (req.method === 'GET' && req.url === '/stats') {
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

  const wss = new WebSocketServer({ server, maxPayload: 64 * 1024 })

  wss.on('connection', (ws) => {
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

    ws.on('message', (raw) => {
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

        if (typeof msg.podId !== 'string' || msg.podId.length > 128) {
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

        relay.register(podId, ws)
        wsBySocket.set(ws, podId)

        send(ws, { type: 'registered', podId })
        return
      }

      // ── Relay ────────────────────────────────────────────────────
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
        relay.unregister(podId)
        wsBySocket.delete(ws)
      }
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
      // Terminate all clients (registered + unregistered)
      for (const ws of wss.clients) {
        ws.terminate()
      }
      wsBySocket.clear()

      wss.close(() => {
        server.close(() => resolve())
      })
    })
  }

  return { server, wss, relay, listen, close }
}

// ─── Direct execution ────────────────────────────────────────────────

const isMain = process.argv[1] === fileURLToPath(import.meta.url)

if (isMain) {
  const instance = createRelayServer()
  const port = await instance.listen()
  console.log(`[relay] listening on port ${port}`)
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
