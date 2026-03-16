/**
 * server-pod.mjs — ServerPod extends Pod for Node.js runtime.
 *
 * Replaces PeerNodeServer with a proper Pod subclass that shares identity,
 * messaging, and discovery protocol with browser pods.
 *
 * Uses PodIdentity (Ed25519) from browsermesh-primitives — same identity
 * model as browser pods. Node.js 24+ has full crypto.subtle Ed25519 support.
 */

import { Pod, EventEmitterTransport, NullDiscovery } from 'browsermesh-pod'
import { PodIdentity } from 'browsermesh-primitives'
import { hostname } from 'node:os'
import { webcrypto } from 'node:crypto'
import { ServerFileSystem } from './index.mjs'
import { ServerAgent } from './index.mjs'

/**
 * Server-side Pod — always-on mesh peer running in Node.js.
 *
 * Extends the browsermesh-pod Pod base class with:
 * - File system service (Node.js fs)
 * - Agent service (LLM-backed or echo)
 * - Optional mDNS LAN discovery
 * - Service registry for remote procedure calls
 */
export class ServerPod extends Pod {
  #fileSystem
  #agent
  #services = new Map()
  #serviceToken
  #label
  #mdns = null
  #mdnsPort = null
  #onLog

  /**
   * @param {object} [opts]
   * @param {string} [opts.dataDir='./data']  — root directory for file storage
   * @param {string} [opts.agentName]         — name for the built-in agent
   * @param {string} [opts.label]             — human-readable label (default: hostname)
   * @param {string} [opts.serviceToken]      — auth token for remote service calls
   * @param {number} [opts.maxMemories]       — max memory entries for the agent
   * @param {string} [opts.llmProvider]       — 'openai' or 'anthropic' (omit for echo mode)
   * @param {string} [opts.llmApiKey]         — API key for the LLM provider
   * @param {string} [opts.llmModel]          — model name override
   * @param {number} [opts.mdnsPort]          — port to advertise via mDNS (enables LAN discovery)
   * @param {(msg: string) => void} [opts.onLog]
   */
  constructor(opts = {}) {
    super()
    this.#fileSystem = new ServerFileSystem(opts.dataDir ?? './data')
    this.#agent = new ServerAgent({
      name: opts.agentName ?? 'server-agent',
      maxMemories: opts.maxMemories,
      provider: opts.llmProvider,
      apiKey: opts.llmApiKey,
      model: opts.llmModel,
    })
    this.#label = opts.label ?? hostname()
    this.#serviceToken = opts.serviceToken ?? webcrypto.randomUUID()
    this.#mdnsPort = opts.mdnsPort ?? null
    this.#onLog = opts.onLog ?? console.log

    // Register built-in services
    this.registerService('fs', {
      list: (args) => this.#fileSystem.list(args?.path),
      read: (args) => this.#fileSystem.read(args?.path),
      write: (args) => this.#fileSystem.write(args?.path, args?.data),
      delete: (args) => this.#fileSystem.delete(args?.path),
      stat: (args) => this.#fileSystem.stat(args?.path),
    })

    this.registerService('agent', {
      run: (args) => this.#agent.run(args?.message),
      executeTool: (args) => this.#agent.executeTool(args?.name, args?.args ?? {}),
      searchMemories: (args) => this.#agent.searchMemories(args?.query),
    })
  }

  /**
   * Start the server pod.
   * Generates a PodIdentity (Ed25519), boots the Pod base class, and
   * optionally starts mDNS LAN discovery.
   *
   * @param {object} [opts]
   * @param {PodIdentity} [opts.identity] — pre-existing identity (skips generation)
   * @param {object} [opts.transport]     — TransportAdapter (default: EventEmitterTransport)
   * @param {object} [opts.discovery]     — DiscoveryAdapter (default: NullDiscovery)
   * @param {number} [opts.discoveryTimeout] — ms (default: 500)
   */
  async start(opts = {}) {
    const identity = opts.identity ?? await PodIdentity.generate()
    const transport = opts.transport ?? new EventEmitterTransport()
    const discovery = opts.discovery ?? new NullDiscovery()

    // Minimal globalThis stub for Node.js (no browser APIs)
    const g = {
      addEventListener: () => {},
      removeEventListener: () => {},
    }

    await this.boot({
      identity,
      transport,
      discovery,
      globalThis: g,
      handshakeTimeout: 0,
      discoveryTimeout: opts.discoveryTimeout ?? 500,
    })

    this.#onLog(`[kernel] started: ${this.podId} (${this.#label})`)

    // Start mDNS LAN discovery if a port is configured
    if (this.#mdnsPort) {
      try {
        const { MdnsDiscovery } = await import('./mdns.mjs')
        this.#mdns = new MdnsDiscovery({
          podId: this.podId,
          port: this.#mdnsPort,
          label: this.#label,
          onLog: this.#onLog,
        })
        this.#mdns.onPeerDiscovered((peer) => {
          this.#onLog(`[kernel] mDNS peer: ${peer.podId} at ${peer.host}:${peer.port}`)
        })
        await this.#mdns.start()
      } catch (err) {
        this.#onLog(`[kernel] mDNS init failed (non-fatal): ${err.message}`)
      }
    }
  }

  /**
   * Stop the server pod.
   */
  async stop() {
    if (this.#mdns) {
      await this.#mdns.stop()
      this.#mdns = null
    }
    await this.shutdown({ silent: false })
    this.#onLog(`[kernel] stopped: ${this.podId}`)
  }

  /** @returns {string} */
  get label() { return this.#label }

  /** @returns {ServerFileSystem} */
  get fileSystem() { return this.#fileSystem }

  /** @returns {ServerAgent} */
  get agent() { return this.#agent }

  /** @returns {string} */
  get serviceToken() { return this.#serviceToken }

  /** @returns {object|null} */
  get mdns() { return this.#mdns }

  /**
   * Register a named service.
   * @param {string} name
   * @param {object} handler — map of method names to async functions
   */
  registerService(name, handler) {
    this.#services.set(name, handler)
  }

  /**
   * List registered service names.
   * @returns {string[]}
   */
  listServices() {
    return Array.from(this.#services.keys())
  }

  /**
   * Get a registered service.
   * @param {string} name
   * @returns {object|undefined}
   */
  getService(name) {
    return this.#services.get(name)
  }

  /**
   * Remove a registered service.
   * @param {string} name
   * @returns {boolean}
   */
  unregisterService(name) {
    return this.#services.delete(name)
  }

  /**
   * Authenticated service call for remote peers.
   * @param {string} name
   * @param {string} method
   * @param {object} args
   * @param {string} token
   * @returns {Promise<object>}
   */
  async callService(name, method, args, token) {
    if (token !== this.#serviceToken) {
      return { success: false, error: 'unauthorized' }
    }
    const svc = this.#services.get(name)
    if (!svc || !svc[method]) {
      return { success: false, error: `unknown service method: ${name}.${method}` }
    }
    return svc[method](args)
  }

  /** @returns {object} */
  toJSON() {
    return {
      ...super.toJSON(),
      label: this.#label,
      services: this.listServices(),
    }
  }
}
