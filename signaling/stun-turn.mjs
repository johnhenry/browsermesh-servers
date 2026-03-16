/**
 * ICE server configuration helper for the Clawser signaling server.
 *
 * Reads ICE_SERVERS from the environment (JSON array) or falls back to
 * the default public Google STUN servers.  Optional TURN credentials can
 * be supplied via TURN_URLS, TURN_USERNAME, and TURN_CREDENTIAL env vars.
 */

export const DEFAULT_STUN_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
]

/**
 * Return an array of RTCIceServer-compatible objects.
 *
 * Resolution order:
 *   1. ICE_SERVERS env var — must be a JSON array of RTCIceServer objects
 *   2. TURN_URLS / TURN_USERNAME / TURN_CREDENTIAL env vars — appended to defaults
 *   3. DEFAULT_STUN_SERVERS alone
 *
 * @param {Record<string, string | undefined>} env
 * @returns {Array<{ urls: string, username?: string, credential?: string }>}
 */
export function getIceServers(env = process.env) {
  // Full override via JSON blob
  if (env.ICE_SERVERS) {
    try {
      const parsed = JSON.parse(env.ICE_SERVERS)
      if (Array.isArray(parsed) && parsed.length > 0) return parsed
    } catch (err) {
      console.warn(`[stun-turn] Invalid ICE_SERVERS JSON (falling back to defaults): ${err.message}`)
    }
  }

  const servers = [...DEFAULT_STUN_SERVERS]

  // Additive TURN config
  if (env.TURN_URLS) {
    servers.push({
      urls: env.TURN_URLS,
      ...(env.TURN_USERNAME && { username: env.TURN_USERNAME }),
      ...(env.TURN_CREDENTIAL && { credential: env.TURN_CREDENTIAL }),
    })
  }

  return servers
}
