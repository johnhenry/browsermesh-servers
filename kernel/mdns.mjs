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

const DEFAULT_MAX_PEERS = 256
const INSTANCE_NAME_RE = /^([A-Za-z0-9_-]{1,128})\._clawser\._tcp\.local$/
const HOST_RE = /^[^\s\u0000-\u001f\u007f-\u009f]+$/u

/** A display label from the network: no control characters, bounded length. */
function cleanLabel(v) {
  if (typeof v !== 'string') return ''
  return v.replace(/[\u0000-\u001f\u007f-\u009f]/g, '').slice(0, 64).trim()
}

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
  #maxPeers
  #createMdns

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
   * @param {number} [opts.maxPeers] — most peers remembered (default 256)
   * @param {() => object} [opts.createMdns] — socket factory (default: multicast-dns), for tests
   */
  constructor({ podId, port, label, host, onLog, maxPeers, createMdns }) {
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
    this.#maxPeers = maxPeers ?? DEFAULT_MAX_PEERS
    this.#createMdns = createMdns ?? (() => multicastDns({ reuseAddr: true }))
  }

  // ── Public API ─────────────────────────────────────────────────────

  /**
   * Start advertising and listening for peers on the local network.
   * @returns {Promise<void>}
   */
  async start() {
    if (this.#running) return
    this.#running = true

    this.#mdns = this.#createMdns()

    // Listen for responses containing our service type
    this.#mdns.on('response', (response) => {
      this.#handleResponse(response)
    })

    // Respond to queries for our service type
    this.#mdns.on('query', (query) => {
      const isOurs = Array.isArray(query?.questions) && query.questions.some(q =>
        q?.name === SERVICE_TYPE || q?.name === `${this.#podId}.${SERVICE_TYPE}`
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

  /**
   * Process an mDNS response and extract peer info. Everything in a response
   * comes from the local network and is untrusted: names, ports and hosts are
   * validated, the number of remembered peers is bounded, and nothing raw is
   * logged.
   */
  #handleResponse(response) {
    if (!response || typeof response !== 'object') return

    // Collect all records by name for correlation
    const srvRecords = new Map()
    const txtRecords = new Map()

    const records = [
      ...(Array.isArray(response.answers) ? response.answers : []),
      ...(Array.isArray(response.additionals) ? response.additionals : []),
    ]
    for (const answer of records) {
      if (!answer || typeof answer !== 'object' || typeof answer.name !== 'string') continue
      if (answer.type === 'SRV' && answer.name.endsWith(SERVICE_TYPE)) {
        srvRecords.set(answer.name, answer.data)
      }
      if (answer.type === 'TXT' && answer.name.endsWith(SERVICE_TYPE)) {
        txtRecords.set(answer.name, answer.data)
      }
    }

    // Match SRV + TXT records for each instance
    for (const [name, srv] of srvRecords) {
      // The instance name decides the id; a TXT podId is not consulted.
      const idMatch = INSTANCE_NAME_RE.exec(name)
      if (!idMatch || !srv || typeof srv !== 'object') continue
      const podId = idMatch[1]

      const host = srv.target ?? srv.host
      const port = srv.port
      if (typeof host !== 'string' || host.length === 0 || host.length > 253 || !HOST_RE.test(host)) continue
      if (!Number.isInteger(port) || port < 1 || port > 65535) continue

      // Skip self
      if (podId === this.#podId) continue

      // Skip if already known
      if (this.#peers.has(podId)) continue

      // Bound what a hostile neighbour can make us hold
      if (this.#peers.size >= this.#maxPeers) continue

      const meta = this.#parseTxt(txtRecords.get(name))
      const label = cleanLabel(meta.label) || podId.slice(0, 8)

      const peer = { podId, host, port, label, discoveredAt: Date.now() }

      this.#peers.set(podId, peer)
      this.#onLog(`[mdns] discovered: ${podId} at ${host}:${port}`)

      for (const cb of this.#discoveredCallbacks) {
        try { cb(peer) } catch { /* non-fatal */ }
      }
    }
  }

  /**
   * Parse TXT record data into a key-value map (null prototype: a key from
   * the network can never be an inherited name).
   * TXT data comes as an array of Buffers or strings like "key=value".
   */
  #parseTxt(data) {
    const result = Object.create(null)
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
