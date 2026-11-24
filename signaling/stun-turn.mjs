/**
 * ICE server configuration for the signaling server.
 *
 * Nothing here points at a third party by default: with no environment set the
 * list is empty and peers use host candidates only. A deployment adds its own
 * STUN/TURN servers; public STUN is an explicit opt-in.
 *
 * TURN credentials are time-limited, following the TURN REST API as coturn
 * implements it with `use-auth-secret` / `static-auth-secret`:
 *
 *   username   = "<expiry, seconds since 1970>" [ ":" "<user>" ]
 *   credential = base64( HMAC-SHA1( key = shared secret, data = username ) )
 *
 * The shared secret only ever comes from the environment (TURN_SECRET) and is
 * never returned to a client or logged.
 *
 * Env vars:
 *   TURN_URLS         — comma-separated turn:/turns: URLs
 *   TURN_SECRET       — shared secret (>= 16 chars), same value as coturn's static-auth-secret
 *   TURN_TTL_SECONDS  — credential lifetime (default 600, min 60, max 86400)
 *   STUN_URLS         — comma-separated stun: URLs of the operator's own STUN servers
 *   ALLOW_PUBLIC_STUN — set to 1 to also hand out PUBLIC_STUN_SERVERS (third party)
 *   ICE_SERVERS       — JSON array that replaces everything above (static; may carry fixed credentials)
 *   TURN_USERNAME / TURN_CREDENTIAL — legacy static TURN login, used only when TURN_SECRET is unset
 */

import { createHmac, randomBytes } from 'node:crypto'
import { envFlag } from './limits.mjs'

/** A third-party STUN service. Never used unless ALLOW_PUBLIC_STUN is set. */
export const PUBLIC_STUN_SERVERS = Object.freeze([
  Object.freeze({ urls: 'stun:stun.l.google.com:19302' }),
  Object.freeze({ urls: 'stun:stun1.l.google.com:19302' }),
])

export const DEFAULT_TURN_TTL_SECONDS = 600
export const MIN_TURN_TTL_SECONDS = 60
export const MAX_TURN_TTL_SECONDS = 86_400
export const MIN_TURN_SECRET_LENGTH = 16

/**
 * Build one time-limited TURN credential.
 *
 * @param {object} opts
 * @param {string} opts.secret        — shared secret
 * @param {number} [opts.ttlSeconds]  — lifetime (default 600)
 * @param {string} [opts.user]        — optional user part of the username
 * @param {number} [opts.now]         — ms since epoch (default Date.now())
 * @returns {{ username: string, credential: string, expiresAt: number }}
 */
export function createTurnCredentials({ secret, ttlSeconds = DEFAULT_TURN_TTL_SECONDS, user, now = Date.now() }) {
  const expiresAt = Math.floor(now / 1000) + ttlSeconds
  const username = user ? `${expiresAt}:${user}` : String(expiresAt)
  const credential = createHmac('sha1', secret).update(username).digest('base64')
  return { username, credential, expiresAt }
}

function splitUrls(raw) {
  return String(raw).split(',').map(s => s.trim()).filter(Boolean)
}

function urlsValue(list) {
  return list.length === 1 ? list[0] : list
}

function ttlFrom(raw) {
  const n = Number(raw)
  if (!raw || !Number.isFinite(n) || n <= 0) return DEFAULT_TURN_TTL_SECONDS
  return Math.min(MAX_TURN_TTL_SECONDS, Math.max(MIN_TURN_TTL_SECONDS, Math.floor(n)))
}

/**
 * Validate the configuration without producing credentials. Throws (without
 * echoing any secret) when TURN_SECRET is set but too short.
 *
 * @param {Record<string, string | undefined>} env
 */
export function assertIceConfig(env = process.env) {
  if (env.TURN_SECRET && env.TURN_SECRET.length < MIN_TURN_SECRET_LENGTH) {
    throw new Error(`TURN_SECRET must be at least ${MIN_TURN_SECRET_LENGTH} characters`)
  }
}

/**
 * Return an array of RTCIceServer-compatible objects, with TURN credentials
 * minted for `now`. Call it per request: every answer carries fresh
 * credentials.
 *
 * @param {Record<string, string | undefined>} env
 * @param {number} [now] — ms since epoch
 * @returns {Array<{ urls: string | string[], username?: string, credential?: string }>}
 */
export function getIceServers(env = process.env, now = Date.now()) {
  assertIceConfig(env)

  // Full override via JSON blob
  if (env.ICE_SERVERS) {
    try {
      const parsed = JSON.parse(env.ICE_SERVERS)
      if (Array.isArray(parsed) && parsed.length > 0) return parsed
    } catch {
      // The parser's message can quote part of the input, which may hold a
      // credential: say only that it was invalid.
      console.warn('[stun-turn] ICE_SERVERS is not valid JSON; ignoring it')
    }
  }

  const servers = []

  if (env.STUN_URLS) {
    const urls = splitUrls(env.STUN_URLS)
    if (urls.length) servers.push({ urls })
  }

  if (envFlag(env.ALLOW_PUBLIC_STUN)) {
    servers.push(...PUBLIC_STUN_SERVERS.map(s => ({ ...s })))
  }

  if (env.TURN_URLS) {
    const urls = splitUrls(env.TURN_URLS)
    if (urls.length) {
      if (env.TURN_SECRET) {
        const { username, credential } = createTurnCredentials({
          secret: env.TURN_SECRET,
          ttlSeconds: ttlFrom(env.TURN_TTL_SECONDS),
          user: randomBytes(8).toString('hex'),
          now,
        })
        servers.push({ urls: urlsValue(urls), username, credential })
      } else {
        servers.push({
          urls: urlsValue(urls),
          ...(env.TURN_USERNAME && { username: env.TURN_USERNAME }),
          ...(env.TURN_CREDENTIAL && { credential: env.TURN_CREDENTIAL }),
        })
      }
    }
  }

  return servers
}
