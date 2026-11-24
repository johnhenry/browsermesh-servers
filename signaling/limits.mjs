/**
 * Small, dependency-free helpers shared by the HTTP and WebSocket paths:
 * a bounded fixed-window rate limiter, a constant-time string comparison,
 * and the client address of a request.
 *
 * Each server directory is deployed on its own (see deploy/), so the same
 * helpers are kept as a copy next to each server rather than imported across
 * directories.
 */

import { createHash, timingSafeEqual } from 'node:crypto'

/**
 * Compare two strings in constant time with respect to their content.
 * Both sides are hashed first so the inputs may differ in length without
 * the length leaking through the comparison.
 *
 * @param {unknown} a
 * @param {unknown} b
 * @returns {boolean}
 */
export function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  const da = createHash('sha256').update(a, 'utf8').digest()
  const db = createHash('sha256').update(b, 'utf8').digest()
  return timingSafeEqual(da, db)
}

/**
 * Fixed-window counter per key with a bound on the number of remembered keys.
 */
export class RateLimiter {
  #limit
  #windowMs
  #maxKeys
  #now
  /** @type {Map<string, { count: number, resetAt: number }>} */
  #entries = new Map()

  /**
   * @param {object} opts
   * @param {number} opts.limit       — hits allowed per window per key
   * @param {number} [opts.windowMs]  — window length (default 60 000)
   * @param {number} [opts.maxKeys]   — most keys remembered at once (default 10 000)
   * @param {() => number} [opts.now]
   */
  constructor({ limit, windowMs = 60_000, maxKeys = 10_000, now = Date.now }) {
    this.#limit = limit
    this.#windowMs = windowMs
    this.#maxKeys = maxKeys
    this.#now = now
  }

  get size() { return this.#entries.size }

  /**
   * Count one hit for `key`.
   * @param {string} key
   * @returns {{ ok: boolean, retryAfterMs: number }}
   */
  hit(key) {
    const now = this.#now()
    let entry = this.#entries.get(key)
    if (!entry || now >= entry.resetAt) {
      if (!entry && this.#entries.size >= this.#maxKeys) this.#evict(now)
      entry = { count: 0, resetAt: now + this.#windowMs }
      this.#entries.set(key, entry)
    }
    entry.count++
    return entry.count <= this.#limit
      ? { ok: true, retryAfterMs: 0 }
      : { ok: false, retryAfterMs: Math.max(1, entry.resetAt - now) }
  }

  /** Forget a key (for example when its connection closes). */
  delete(key) { this.#entries.delete(key) }

  #evict(now) {
    for (const [k, e] of this.#entries) {
      if (now >= e.resetAt) this.#entries.delete(k)
    }
    // Still full of live entries: drop the oldest ones (insertion order).
    while (this.#entries.size >= this.#maxKeys) {
      const oldest = this.#entries.keys().next().value
      this.#entries.delete(oldest)
    }
  }
}

/**
 * The address a request came from. Forwarding headers are only honoured when
 * the operator says a proxy that sets them sits in front of the server
 * (`trustProxy`); otherwise any client could pick its own address.
 *
 * With a trusted proxy: `Fly-Client-IP` if present, else the last entry of
 * `X-Forwarded-For` (the one the nearest proxy appended).
 *
 * @param {import('node:http').IncomingMessage} req
 * @param {boolean} [trustProxy]
 * @returns {string}
 */
export function clientIp(req, trustProxy = false) {
  if (trustProxy) {
    const fly = req.headers['fly-client-ip']
    if (typeof fly === 'string' && fly.trim()) return fly.trim()
    const xff = req.headers['x-forwarded-for']
    if (typeof xff === 'string' && xff.trim()) {
      const parts = xff.split(',')
      return parts[parts.length - 1].trim()
    }
  }
  return req.socket?.remoteAddress ?? 'unknown'
}

/**
 * Parse a boolean-ish environment value.
 * @param {string|undefined} v
 * @returns {boolean}
 */
export function envFlag(v) {
  return typeof v === 'string' && /^(1|true|yes|on)$/i.test(v.trim())
}
