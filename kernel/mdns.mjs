/**
 * mDNS/DNS-SD discovery for server-side Clawser pods.
 *
 * Advertises the local pod as a `_clawser._tcp.local` service and
 * discovers other pods on the LAN. Browser pods benefit transitively
 * through PEX (Peer Exchange) — they connect to any server pod and
 * receive the full peer list.
 *
 * Env vars:
 *   MDNS_ENABLED   — set to 'true' to enable (default: false)
 *   MDNS_PORT      — port to advertise (default: signaling port)
 *
 * Usage:
 *   const mdns = new MdnsDiscovery({ podId, port, onLog })
 *   mdns.onPeerDiscovered(({ podId, host, port }) => { ... })
 *   await mdns.start()
 *   // ... later
 *   await mdns.stop()
 */

import multicastDns from 'multicast-dns'
import { hostname } from 'node:os'

// ─── Constants ───────────────────────────────────────────────────────

const SERVICE_TYPE = '_clawser._tcp.local'
const ANNOUNCE_INTERVAL_MS = 15_000
const DEFAULT_TTL = 120 // seconds

// ─── MdnsDiscovery ───────────────────────────────────────────────────

export class MdnsDiscovery {
  #podId
  #port
  #label
  #host
  #onLog
  #mdns = null
  #announceTimer = null
  #running = false

  /** @type {Map<string, { podId: string, host: string, port: number, label: string, discoveredAt: number }>} */
  #peers = new Map()

  /** @type {Function[]} */
  #discoveredCallbacks = []

  /**
   * @param {object} opts
   * @param {string} opts.podId   — local pod identifier
   * @param {number} opts.port    — port to advertise
   * @param {string} [opts.label] — human-readable label (default: hostname)
   * @param {string} [opts.host]  — hostname to advertise (default: os.hostname())
   * @param {(msg: string) => void} [opts.onLog]
   */
  constructor({ podId, port, label, host, onLog }) {
    if (!podId || typeof podId !== 'string') {
      throw new Error('podId is required')
    }
    if (!port || typeof port !== 'number') {
      throw new Error('port is required and must be a number')
    }
    this.#podId = podId
    this.#port = port
    this.#label = label ?? hostname()
    this.#host = host ?? hostname()
    this.#onLog = onLog ?? (() => {})
  }

  // ── Public API ─────────────────────────────────────────────────────

  /**
   * Start advertising and listening for peers on the local network.
   * @returns {Promise<void>}
   */
  async start() {
    if (this.#running) return
    this.#running = true

    this.#mdns = multicastDns({ reuseAddr: true })

    // Listen for responses containing our service type
    this.#mdns.on('response', (response) => {
      this.#handleResponse(response)
    })

    // Respond to queries for our service type
    this.#mdns.on('query', (query) => {
      const isOurs = query.questions.some(q =>
        q.name === SERVICE_TYPE || q.name === `${this.#podId}.${SERVICE_TYPE}`
      )
      if (isOurs) this.#announce()
    })

    // Initial announcement
    this.#announce()

    // Periodic re-announcement
    this.#announceTimer = setInterval(() => this.#announce(), ANNOUNCE_INTERVAL_MS)

    // Initial query to discover existing peers
    this.#query()

    this.#onLog(`[mdns] started: ${this.#podId} on port ${this.#port}`)
  }

  /**
   * Stop advertising and close the mDNS socket.
   * @returns {Promise<void>}
   */
  async stop() {
    if (!this.#running) return
    this.#running = false

    clearInterval(this.#announceTimer)
    this.#announceTimer = null

    // Send goodbye (TTL=0)
    if (this.#mdns) {
      try { this.#sendGoodbye() } catch { /* best effort */ }
      this.#mdns.destroy()
      this.#mdns = null
    }

    this.#peers.clear()
    this.#onLog(`[mdns] stopped`)
  }

  /**
   * Register a callback for when a new peer is discovered.
   * @param {Function} cb - ({ podId, host, port, label }) => void
   */
  onPeerDiscovered(cb) {
    this.#discoveredCallbacks.push(cb)
  }

  /** @returns {boolean} */
  get running() {
    return this.#running
  }

  /** @returns {string} */
  get podId() {
    return this.#podId
  }

  /**
   * Return all discovered peers.
   * @returns {Array<{ podId: string, host: string, port: number, label: string }>}
   */
  listPeers() {
    return [...this.#peers.values()]
  }

  /** @returns {number} */
  get peerCount() {
    return this.#peers.size
  }

  // ── Internal ───────────────────────────────────────────────────────

  /** Announce our service via mDNS response. */
  #announce() {
    if (!this.#mdns) return

    const instanceName = `${this.#podId}.${SERVICE_TYPE}`

    this.#mdns.respond({
      answers: [
        // PTR — service type points to our instance
        {
          name: SERVICE_TYPE,
          type: 'PTR',
          ttl: DEFAULT_TTL,
          data: instanceName,
        },
        // SRV — instance points to host:port
        {
          name: instanceName,
          type: 'SRV',
          ttl: DEFAULT_TTL,
          data: {
            port: this.#port,
            target: `${this.#host}.local`,
            weight: 0,
            priority: 0,
          },
        },
        // TXT — metadata (podId, label)
        {
          name: instanceName,
          type: 'TXT',
          ttl: DEFAULT_TTL,
          data: [
            `podId=${this.#podId}`,
            `label=${this.#label}`,
          ],
        },
      ],
    })
  }

  /** Send a goodbye announcement (TTL=0). */
  #sendGoodbye() {
    if (!this.#mdns) return

    const instanceName = `${this.#podId}.${SERVICE_TYPE}`

    this.#mdns.respond({
      answers: [
        {
          name: SERVICE_TYPE,
          type: 'PTR',
          ttl: 0,
          data: instanceName,
        },
      ],
    })
  }

  /** Query the network for other clawser pods. */
  #query() {
    if (!this.#mdns) return

    this.#mdns.query({
      questions: [
        { name: SERVICE_TYPE, type: 'PTR' },
      ],
    })
  }

  /** Process an mDNS response and extract peer info. */
  #handleResponse(response) {
    // Collect all records by name for correlation
    const srvRecords = new Map()
    const txtRecords = new Map()

    for (const answer of [...(response.answers || []), ...(response.additionals || [])]) {
      if (answer.type === 'SRV' && answer.name.endsWith(SERVICE_TYPE)) {
        srvRecords.set(answer.name, answer.data)
      }
      if (answer.type === 'TXT' && answer.name.endsWith(SERVICE_TYPE)) {
        txtRecords.set(answer.name, answer.data)
      }
    }

    // Match SRV + TXT records for each instance
    for (const [name, srv] of srvRecords) {
      const txt = txtRecords.get(name)
      const meta = this.#parseTxt(txt)
      const podId = meta.podId || name.replace(`.${SERVICE_TYPE}`, '')

      // Skip self
      if (podId === this.#podId) continue

      // Skip if already known
      if (this.#peers.has(podId)) continue

      const peer = {
        podId,
        host: srv.target || srv.host,
        port: srv.port,
        label: meta.label || podId.slice(0, 8),
        discoveredAt: Date.now(),
      }

      this.#peers.set(podId, peer)
      this.#onLog(`[mdns] discovered: ${podId} at ${peer.host}:${peer.port}`)

      for (const cb of this.#discoveredCallbacks) {
        try { cb(peer) } catch { /* non-fatal */ }
      }
    }
  }

  /**
   * Parse TXT record data into a key-value map.
   * TXT data comes as an array of Buffers or strings like "key=value".
   */
  #parseTxt(data) {
    const result = {}
    if (!data) return result

    const entries = Array.isArray(data) ? data : [data]
    for (const entry of entries) {
      const str = Buffer.isBuffer(entry) ? entry.toString('utf-8') : String(entry)
      const eq = str.indexOf('=')
      if (eq > 0) {
        result[str.slice(0, eq)] = str.slice(eq + 1)
      }
    }
    return result
  }
}
