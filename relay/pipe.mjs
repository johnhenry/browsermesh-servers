/**
 * wsh pipe-relay route for the relay server.
 *
 * A WebSocket upgrade at `<base>/r/<rendezvous id>` (`?role=host` for the side
 * that waits; no role = the side that dials) is handed to wsh's pipe relay
 * (`createPipeRelay().accept(socket, { id, role })` from
 * `@johnhenry/wsh/pipe-relay`), which pairs the two sockets that name the same
 * id and copies their binary frames.
 *
 * What this route is and is not:
 *
 *  - OFF unless enabled (`PIPE_RELAY=1`).
 *  - Opaque: frames are binary only, never parsed, never logged. wsh's own log
 *    lines (which carry a prefix of the rendezvous id, a capability) are not
 *    forwarded anywhere.
 *  - It vouches for nothing. It does not know or check who connects: the two
 *    ends authenticate each other and seal the session themselves (browsermesh
 *    `WshPeerLinks`). The relay sees ciphertext, its sizes and timing, who
 *    dials which id, and when. It can drop, delay or end a pipe.
 *  - Admission only limits abuse: an Origin allow-list, per-address and
 *    per-id rate limits, a per-address cap on concurrent connections, and the
 *    pipe relay's own bounds.
 *
 * Env vars (all optional except where noted):
 *   PIPE_RELAY                      — 1 to enable
 *   PIPE_BASE_PATH                  — route prefix (default none: /r/<id>)
 *   PIPE_ORIGINS                    — comma-separated allowed Origins (falls back to ORIGINS);
 *                                     required unless PIPE_ALLOW_ANY_ORIGIN=1
 *   PIPE_ALLOW_ANY_ORIGIN           — 1: accept any Origin
 *   PIPE_ALLOW_NO_ORIGIN            — 1: accept clients that send no Origin (non-browser)
 *   PIPE_MAX_WAITING                — halves waiting for a partner, all ids (default 256)
 *   PIPE_RENDEZVOUS_TIMEOUT_MS      — how long a half waits (default 60000)
 *   PIPE_IDLE_TIMEOUT_MS            — a pipe with no traffic closes after this (default 300000)
 *   PIPE_MAX_LIFETIME_MS            — a pipe closes this long after pairing (default 3600000)
 *   PIPE_MAX_BYTES                  — bytes copied per pipe, both directions (default 67108864)
 *   PIPE_MAX_MESSAGE_BYTES          — largest single frame (default 1048576)
 *   PIPE_EARLY_BYTES                — what a half may send before its partner arrives (default 65536)
 *   PIPE_HIGH_WATER_BYTES           — unsent bytes at which the sender is paused (default 1048576)
 *   PIPE_CONNECTS_PER_MINUTE_PER_IP — default 60
 *   PIPE_CONNECTS_PER_MINUTE_PER_ID — default 30
 *   PIPE_MAX_CONNECTIONS_PER_IP     — concurrent pipe connections per address (default 32)
 */

import { WebSocketServer } from 'ws'
import { RateLimiter, clientIp, envFlag } from './limits.mjs'

const NUMBERS = {
  maxWaiting: ['PIPE_MAX_WAITING', 256],
  rendezvousTimeoutMs: ['PIPE_RENDEZVOUS_TIMEOUT_MS', 60_000],
  idleTimeoutMs: ['PIPE_IDLE_TIMEOUT_MS', 300_000],
  maxLifetimeMs: ['PIPE_MAX_LIFETIME_MS', 3_600_000],
  maxBytes: ['PIPE_MAX_BYTES', 64 * 1024 * 1024],
  maxMessageBytes: ['PIPE_MAX_MESSAGE_BYTES', 1024 * 1024],
  earlyBytes: ['PIPE_EARLY_BYTES', 64 * 1024],
  highWaterBytes: ['PIPE_HIGH_WATER_BYTES', 1024 * 1024],
  connectsPerMinutePerIp: ['PIPE_CONNECTS_PER_MINUTE_PER_IP', 60],
  connectsPerMinutePerId: ['PIPE_CONNECTS_PER_MINUTE_PER_ID', 30],
  maxConnectionsPerIp: ['PIPE_MAX_CONNECTIONS_PER_IP', 32],
}

function parseList(raw) {
  if (!raw) return []
  return String(raw).split(',').map(s => s.trim()).filter(Boolean)
}

/**
 * Resolve the pipe-relay configuration, or null when it is not enabled.
 *
 * @param {Record<string, string|undefined>} env
 * @param {object} [over]  — programmatic overrides (same names as the fields of the result,
 *                           plus `enabled`, `origins`, `authorize`)
 * @param {string[]|null} [defaultOrigins] — origins of the JSON relay, used when PIPE_ORIGINS is unset
 * @returns {object|null}
 */
export function resolvePipeConfig(env, over = {}, defaultOrigins = null) {
  const enabled = over.enabled ?? envFlag(env.PIPE_RELAY)
  if (!enabled) return null

  const cfg = {}
  for (const [name, [envName, dflt]] of Object.entries(NUMBERS)) {
    const raw = over[name] ?? env[envName]
    if (raw === undefined || raw === '') { cfg[name] = dflt; continue }
    const n = Number(raw)
    if (!Number.isInteger(n) || n <= 0) throw new Error(`${envName} must be a positive integer`)
    cfg[name] = n
  }

  const listed = over.origins ?? parseList(env.PIPE_ORIGINS)
  cfg.origins = listed.length ? listed : (defaultOrigins ?? [])
  cfg.allowAnyOrigin = over.allowAnyOrigin ?? envFlag(env.PIPE_ALLOW_ANY_ORIGIN)
  cfg.allowNoOrigin = over.allowNoOrigin ?? envFlag(env.PIPE_ALLOW_NO_ORIGIN)
  if (!cfg.origins.length && !cfg.allowAnyOrigin) {
    throw new Error('the wsh pipe relay needs an origin policy: set PIPE_ORIGINS (or ORIGINS), or PIPE_ALLOW_ANY_ORIGIN=1')
  }

  const base = over.basePath ?? env.PIPE_BASE_PATH ?? ''
  if (base && !/^\/[A-Za-z0-9._~/-]*[A-Za-z0-9._~-]$/.test(base)) {
    throw new Error('PIPE_BASE_PATH must be a path such as /mesh')
  }
  cfg.basePath = base
  if (over.authorize !== undefined && typeof over.authorize !== 'function') {
    throw new TypeError('pipe authorize must be a function')
  }
  cfg.authorize = over.authorize ?? null
  return cfg
}

export class PipeRoute {
  #cfg
  #trustProxy
  #relay = null
  #wss
  #routeRe
  #ipRate
  #idRate
  /** @type {Map<string, number>} */
  #open = new Map()

  /**
   * @param {object} cfg — from resolvePipeConfig
   * @param {{ trustProxy?: boolean }} [opts]
   */
  constructor(cfg, { trustProxy = false } = {}) {
    this.#cfg = cfg
    this.#trustProxy = trustProxy
    const base = cfg.basePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    this.#routeRe = new RegExp(`^${base}/r/([A-Za-z0-9_-]{22,128})$`)
    this.#ipRate = new RateLimiter({ limit: cfg.connectsPerMinutePerIp, windowMs: 60_000 })
    this.#idRate = new RateLimiter({ limit: cfg.connectsPerMinutePerId, windowMs: 60_000 })
    // Frames may be larger than the JSON relay's 64 KiB; ws enforces this from
    // the frame header, before the message is buffered.
    this.#wss = new WebSocketServer({ noServer: true, maxPayload: cfg.maxMessageBytes })
  }

  /** Load wsh's pipe relay (lazily, so a deployment that never enables the route does not need it). */
  async start() {
    let mod
    try {
      mod = await import('@johnhenry/wsh/pipe-relay')
    } catch (err) {
      throw new Error('PIPE_RELAY is enabled but @johnhenry/wsh could not be loaded (npm install @johnhenry/wsh)', { cause: err })
    }
    const c = this.#cfg
    this.#relay = mod.createPipeRelay({
      maxWaiting: c.maxWaiting,
      rendezvousTimeoutMs: c.rendezvousTimeoutMs,
      idleTimeoutMs: c.idleTimeoutMs,
      maxLifetimeMs: c.maxLifetimeMs,
      maxBytes: c.maxBytes,
      maxMessageBytes: c.maxMessageBytes,
      earlyBytes: c.earlyBytes,
      highWaterBytes: c.highWaterBytes,
      authorize: (who) => this.#authorize(who),
      // wsh's log lines carry a prefix of the rendezvous id; drop them.
      onLog: () => {},
    })
  }

  /** Whether an upgrade request targets the pipe route. */
  matches(req) {
    try {
      return /\/r\/[^/]*$/.test(new URL(req.url, 'http://localhost').pathname)
    } catch {
      return false
    }
  }

  #originAllowed(origin) {
    if (!origin) return this.#cfg.allowNoOrigin
    if (this.#cfg.allowAnyOrigin) return true
    return this.#cfg.origins.includes(origin)
  }

  async #authorize({ id, role, remote }) {
    // Admission without identity: limits abuse, vouches for nobody.
    if (!this.#originAllowed(remote?.origin)) return false
    if (!this.#idRate.hit(id).ok) return false
    if (this.#cfg.authorize) {
      return (await this.#cfg.authorize({ id, role, remote })) === true
    }
    return true
  }

  /**
   * Handle an HTTP upgrade for a request that `matches`.
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:net').Socket} socket
   * @param {Buffer} head
   */
  handleUpgrade(req, socket, head) {
    const refuse = (status, text) => {
      socket.write(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`)
      socket.destroy()
    }
    if (!this.#relay) return refuse(503, 'Service Unavailable')

    const url = new URL(req.url, 'http://localhost')
    const id = this.#routeRe.exec(url.pathname)?.[1]
    if (!id) return refuse(404, 'Not Found')

    const roleParam = url.searchParams.get('role')
    if (roleParam !== null && roleParam !== 'host' && roleParam !== 'operator') return refuse(400, 'Bad Request')
    const role = roleParam === 'host' ? 'host' : 'operator'

    const origin = req.headers.origin
    if (!this.#originAllowed(origin)) return refuse(403, 'Forbidden')

    const ip = clientIp(req, this.#trustProxy)
    if (!this.#ipRate.hit(ip).ok) return refuse(429, 'Too Many Requests')
    if ((this.#open.get(ip) ?? 0) >= this.#cfg.maxConnectionsPerIp) return refuse(429, 'Too Many Requests')

    this.#wss.handleUpgrade(req, socket, head, (ws) => {
      this.#open.set(ip, (this.#open.get(ip) ?? 0) + 1)
      ws.on('error', () => {})
      ws.on('close', () => {
        const n = (this.#open.get(ip) ?? 1) - 1
        if (n > 0) this.#open.set(ip, n)
        else this.#open.delete(ip)
      })
      this.#relay
        .accept(ws, { id, role, remote: { address: ip, origin } })
        .catch(() => { try { ws.close(1011, 'error') } catch { /* gone */ } })
    })
  }

  stats() {
    return this.#relay?.stats() ?? { waiting: 0, pipes: 0 }
  }

  async close() {
    for (const ws of this.#wss.clients) ws.terminate()
    await this.#relay?.close()
    await new Promise((resolve) => this.#wss.close(resolve))
  }
}
