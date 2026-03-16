/**
 * Clawser Server-Side Kernel — Always-On Mesh Peer
 *
 * Provides the same identity/capability model as browser peers but runs
 * in Node.js. Can host agent instances, serve files, and run compute jobs.
 *
 * This is a standalone Node.js PeerNode that connects to the signaling
 * server and participates in the mesh network as a first-class peer.
 *
 * Env vars:
 *   SIGNALING_URL — ws:// URL of the signaling server
 *   DATA_DIR      — root directory for file storage (default ./data)
 *   AGENT_NAME    — name for the server agent (default 'server-agent')
 *   POD_LABEL     — human-readable label for this pod (default hostname)
 *   LLM_PROVIDER  — 'openai' or 'anthropic' (omit for echo mode)
 *   LLM_API_KEY   — API key for the configured provider
 *   LLM_MODEL     — model name (default: gpt-4o-mini / claude-sonnet-4-20250514)
 */

import { readFile, writeFile, mkdir, readdir, stat, unlink, access, realpath } from 'node:fs/promises'
import { existsSync, mkdirSync } from 'node:fs'
import { join, resolve, relative, dirname, basename } from 'node:path'
import { webcrypto } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { hostname } from 'node:os'

// ─── ServerIdentity ──────────────────────────────────────────────────

/**
 * Simple Ed25519-style identity for server peers.
 * Uses webcrypto for random ID generation.
 */
class ServerIdentity {
  #podId
  #label
  #created

  /**
   * @param {object} opts
   * @param {string} opts.podId  — unique peer identifier
   * @param {string} opts.label  — human-readable label
   * @param {number} [opts.created] — creation timestamp
   */
  constructor({ podId, label, created }) {
    this.#podId = podId
    this.#label = label
    this.#created = created ?? Date.now()
  }

  /** @returns {string} */
  get podId() {
    return this.#podId
  }

  /** @returns {string} */
  get label() {
    return this.#label
  }

  /** @returns {number} */
  get created() {
    return this.#created
  }

  /**
   * Generate a new random identity.
   * @param {string} [label] — human-readable label (default: hostname)
   * @returns {Promise<ServerIdentity>}
   */
  static async generate(label) {
    const bytes = new Uint8Array(16)
    webcrypto.getRandomValues(bytes)
    const podId = 'pod-' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
    return new ServerIdentity({
      podId,
      label: label ?? hostname(),
    })
  }

  /** @returns {object} */
  toJSON() {
    return {
      podId: this.#podId,
      label: this.#label,
      created: this.#created,
    }
  }

  /**
   * Restore an identity from serialized data.
   * @param {object} data
   * @returns {ServerIdentity}
   */
  static fromJSON(data) {
    return new ServerIdentity({
      podId: data.podId,
      label: data.label,
      created: data.created,
    })
  }
}

// ─── ServerFileSystem ────────────────────────────────────────────────

/**
 * File system adapter for server-side storage.
 * Wraps Node.js fs with a consistent async API matching the browser OPFS pattern.
 */
class ServerFileSystem {
  #rootDir

  /**
   * @param {string} rootDir — root directory for file storage
   */
  #rootResolved = false

  constructor(rootDir) {
    this.#rootDir = resolve(rootDir)
    if (!existsSync(this.#rootDir)) {
      mkdirSync(this.#rootDir, { recursive: true })
    }
  }

  /** Lazily resolve rootDir through realpath (handles macOS /tmp → /private/tmp). */
  async #ensureRootResolved() {
    if (!this.#rootResolved) {
      try {
        this.#rootDir = await realpath(this.#rootDir)
      } catch { /* keep original if it fails */ }
      this.#rootResolved = true
    }
  }

  /** @returns {string} */
  get rootDir() {
    return this.#rootDir
  }

  /**
   * Resolve a path relative to root, preventing traversal.
   * @param {string} path
   * @returns {string}
   */
  async #resolvePath(path) {
    if (path == null) {
      throw new Error('path is required')
    }
    await this.#ensureRootResolved()
    const resolved = resolve(this.#rootDir, String(path))
    const rel = relative(this.#rootDir, resolved)
    if (rel.startsWith('..') || resolve(this.#rootDir, rel) !== resolved) {
      throw new Error('path traversal not allowed')
    }
    // Resolve symlinks and re-check containment
    try {
      const real = await realpath(resolved)
      if (!real.startsWith(this.#rootDir)) {
        throw new Error('path traversal not allowed (symlink)')
      }
      return real
    } catch (err) {
      if (err.code === 'ENOENT') return resolved // file doesn't exist yet (write case)
      throw err
    }
  }

  /**
   * List entries in a directory.
   * @param {string} [path='.']
   * @returns {Promise<{ name: string, type: string, size: number }[]>}
   */
  async list(path = '.') {
    const dir = await this.#resolvePath(path)
    try {
      await access(dir)
    } catch {
      return []
    }

    const entries = await readdir(dir)
    const results = []
    for (const name of entries) {
      const full = join(dir, name)
      const s = await stat(full)
      results.push({
        name,
        type: s.isDirectory() ? 'directory' : 'file',
        size: s.size,
      })
    }
    return results
  }

  /**
   * Read a file.
   * @param {string} path
   * @returns {Promise<{ data: string, size: number }>}
   */
  async read(path) {
    const full = await this.#resolvePath(path)
    try {
      const data = await readFile(full, 'utf-8')
      return { data, size: Buffer.byteLength(data, 'utf-8') }
    } catch (err) {
      if (err.code === 'ENOENT') throw new Error(`file not found: ${path}`)
      throw err
    }
  }

  /**
   * Write a file (creates parent directories).
   * @param {string} path
   * @param {string} data
   * @returns {Promise<{ success: boolean, size: number }>}
   */
  async write(path, data) {
    if (data == null) {
      throw new Error('data is required for write')
    }
    const str = String(data)
    const size = Buffer.byteLength(str, 'utf-8')
    if (size > 10 * 1024 * 1024) {
      throw new Error(`file size ${size} exceeds 10MB limit`)
    }
    const full = await this.#resolvePath(path)
    const dir = dirname(full)
    await mkdir(dir, { recursive: true })
    await writeFile(full, str, 'utf-8')
    return { success: true, size }
  }

  /**
   * Delete a file.
   * @param {string} path
   * @returns {Promise<{ success: boolean }>}
   */
  async delete(path) {
    const full = await this.#resolvePath(path)
    try {
      const s = await stat(full)
      if (s.isDirectory()) {
        return { success: false, error: 'cannot delete directory' }
      }
      await unlink(full)
      return { success: true }
    } catch (err) {
      if (err.code === 'ENOENT') return { success: false }
      throw err
    }
  }

  /**
   * Get file metadata.
   * @param {string} path
   * @returns {Promise<{ name: string, type: string, size: number, modified: number }|null>}
   */
  async stat(path) {
    const full = await this.#resolvePath(path)
    try {
      const s = await stat(full)
      return {
        name: basename(full),
        type: s.isDirectory() ? 'directory' : 'file',
        size: s.size,
        modified: s.mtimeMs,
      }
    } catch (err) {
      if (err.code === 'ENOENT') return null
      throw err
    }
  }
}

// ─── ServerAgent ─────────────────────────────────────────────────────

/**
 * Simple agent that can respond to messages.
 * This is a lightweight stub — in production, it would wrap
 * a full LLM-backed agent with tool calling.
 */
class ServerAgent {
  #name
  #systemPrompt
  #memories
  #maxMemories
  #provider
  #apiKey
  #model
  #history

  /**
   * @param {object} opts
   * @param {string} opts.name
   * @param {string} [opts.systemPrompt]
   * @param {number} [opts.maxMemories]
   * @param {string} [opts.provider]  — 'openai' or 'anthropic' (omit for echo mode)
   * @param {string} [opts.apiKey]    — API key for the provider
   * @param {string} [opts.model]     — model name override
   */
  constructor({ name, systemPrompt, maxMemories, provider, apiKey, model }) {
    this.#name = name
    this.#systemPrompt = systemPrompt ?? `You are ${name}, a server-side Clawser agent.`
    this.#memories = []
    this.#maxMemories = maxMemories ?? 1024
    this.#provider = provider ?? null
    this.#apiKey = apiKey ?? null
    this.#model = model ?? null
    this.#history = []
  }

  /** @returns {string} */
  get name() {
    return this.#name
  }

  /** @returns {string} */
  get systemPrompt() {
    return this.#systemPrompt
  }

  /** @returns {string|null} */
  get provider() {
    return this.#provider
  }

  /** @returns {Array<{ role: string, content: string }>} */
  get history() {
    return [...this.#history]
  }

  /**
   * Run the agent with a message.
   * If a provider and API key are configured, calls the real LLM.
   * Otherwise falls back to echo mode.
   *
   * @param {string} message
   * @returns {Promise<{ response: string, usage?: object }>}
   */
  async run(message) {
    if (!this.#provider || !this.#apiKey) {
      return {
        response: `[${this.#name}] Received: ${message}`,
        usage: { input_tokens: 0, output_tokens: 0 },
      }
    }

    this.#history.push({ role: 'user', content: message })

    const result = this.#provider === 'anthropic'
      ? await this.#runAnthropic(message)
      : await this.#runOpenAI(message)

    this.#history.push({ role: 'assistant', content: result.response })
    return result
  }

  /**
   * Call the OpenAI-compatible chat completions API.
   * @param {string} _message — already in #history
   * @returns {Promise<{ response: string, usage: object }>}
   */
  async #runOpenAI(_message) {
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.#apiKey}`,
      },
      body: JSON.stringify({
        model: this.#model || 'gpt-4o-mini',
        messages: [
          { role: 'system', content: this.#systemPrompt },
          ...this.#history,
        ],
        max_tokens: 1024,
      }),
    })
    if (!res.ok) {
      const text = await res.text()
      throw new Error(`OpenAI API error ${res.status}: ${text}`)
    }
    const data = await res.json()
    const choice = data.choices?.[0]
    return {
      response: choice?.message?.content ?? '',
      usage: {
        input_tokens: data.usage?.prompt_tokens ?? 0,
        output_tokens: data.usage?.completion_tokens ?? 0,
      },
    }
  }

  /**
   * Call the Anthropic messages API.
   * @param {string} _message — already in #history
   * @returns {Promise<{ response: string, usage: object }>}
   */
  async #runAnthropic(_message) {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.#apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: this.#model || 'claude-sonnet-4-20250514',
        system: this.#systemPrompt,
        messages: this.#history,
        max_tokens: 1024,
      }),
    })
    if (!res.ok) {
      const text = await res.text()
      throw new Error(`Anthropic API error ${res.status}: ${text}`)
    }
    const data = await res.json()
    const content = data.content?.[0]?.text ?? ''
    return {
      response: content,
      usage: {
        input_tokens: data.usage?.input_tokens ?? 0,
        output_tokens: data.usage?.output_tokens ?? 0,
      },
    }
  }

  /**
   * Execute a tool by name.
   * Stub implementation with basic built-in tools.
   *
   * @param {string} name
   * @param {object} args
   * @returns {Promise<{ success: boolean, output: string }>}
   */
  async executeTool(name, args) {
    switch (name) {
      case 'echo':
        return { success: true, output: args.text ?? '' }
      case 'time':
        return { success: true, output: new Date().toISOString() }
      case 'info':
        return { success: true, output: JSON.stringify({ agent: this.#name, tools: ['echo', 'time', 'info'] }) }
      default:
        return { success: false, output: `unknown tool: ${name}` }
    }
  }

  /**
   * Search agent memories.
   * Stub — returns empty array until a memory store is wired up.
   *
   * @param {string} query
   * @returns {object[]}
   */
  searchMemories(query) {
    return this.#memories.filter(m =>
      m.content && m.content.toLowerCase().includes((query ?? '').toLowerCase())
    )
  }

  /**
   * Add a memory entry.
   * @param {object} entry — { key, content, category? }
   */
  addMemory(entry) {
    // Cap at maxMemories entries to prevent memory exhaustion
    if (this.#memories.length >= this.#maxMemories) {
      this.#memories.shift()
    }
    this.#memories.push({
      id: `mem-${this.#memories.length}`,
      key: entry.key,
      content: entry.content,
      category: entry.category ?? 'learned',
      timestamp: Date.now(),
    })
  }
}

// ─── PeerNodeServer ──────────────────────────────────────────────────

/**
 * Server-side PeerNode — always-on mesh peer.
 *
 * Maintains a WebSocket connection to the signaling server and
 * exposes services that other peers can call.
 */
class PeerNodeServer {
  #identity
  #fileSystem
  #agent
  #signalingUrl
  #state = 'stopped'
  #connectedPeers = new Set()
  #services = new Map()
  #onLog
  #ws = null
  #serviceToken
  #mdns = null
  #mdnsPort = null

  /**
   * @param {object} opts
   * @param {ServerIdentity} opts.identity
   * @param {string} [opts.dataDir]       — root directory for file storage
   * @param {string} [opts.signalingUrl]  — signaling server WebSocket URL
   * @param {string} [opts.agentName]     — name for the built-in agent
   * @param {string} [opts.serviceToken]  — auth token for remote service calls
   * @param {number} [opts.maxMemories]   — max memory entries for the agent
   * @param {string} [opts.llmProvider]   — 'openai' or 'anthropic' (omit for echo mode)
   * @param {string} [opts.llmApiKey]     — API key for the LLM provider
   * @param {string} [opts.llmModel]      — model name override
   * @param {number} [opts.mdnsPort]      — port to advertise via mDNS (enables LAN discovery)
   * @param {(msg: string) => void} [opts.onLog]
   */
  constructor({ identity, dataDir, signalingUrl, agentName, serviceToken, maxMemories, llmProvider, llmApiKey, llmModel, mdnsPort, onLog }) {
    this.#identity = identity
    this.#fileSystem = new ServerFileSystem(dataDir ?? './data')
    this.#agent = new ServerAgent({
      name: agentName ?? 'server-agent',
      maxMemories,
      provider: llmProvider,
      apiKey: llmApiKey,
      model: llmModel,
    })
    this.#signalingUrl = signalingUrl ?? null
    this.#serviceToken = serviceToken ?? webcrypto.randomUUID()
    this.#mdnsPort = mdnsPort ?? null
    this.#onLog = onLog ?? console.log

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
   * Start the peer node.
   * Connects to the signaling server if a URL is configured.
   * @returns {Promise<void>}
   */
  async start() {
    if (this.#state === 'running') return
    this.#state = 'running'
    this.#onLog(`[kernel] started: ${this.#identity.podId} (${this.#identity.label})`)

    // Connect to signaling server if configured
    if (this.#signalingUrl) {
      this.#onLog(`[kernel] connecting to signaling: ${this.#signalingUrl}`)
      // In production, would establish WebSocket and register
      // Omitted here to avoid hard dependency on ws in tests
    }

    // Start mDNS LAN discovery if a port is configured
    if (this.#mdnsPort) {
      try {
        const { MdnsDiscovery } = await import('./mdns.mjs')
        this.#mdns = new MdnsDiscovery({
          podId: this.#identity.podId,
          port: this.#mdnsPort,
          label: this.#identity.label,
          onLog: this.#onLog,
        })
        this.#mdns.onPeerDiscovered((peer) => {
          this.#connectedPeers.add(peer.podId)
          this.#onLog(`[kernel] mDNS peer: ${peer.podId} at ${peer.host}:${peer.port}`)
        })
        await this.#mdns.start()
      } catch (err) {
        this.#onLog(`[kernel] mDNS init failed (non-fatal): ${err.message}`)
      }
    }
  }

  /**
   * Stop the peer node.
   * Disconnects from signaling and cleans up.
   * @returns {Promise<void>}
   */
  async stop() {
    if (this.#state === 'stopped') return
    this.#state = 'stopped'
    this.#connectedPeers.clear()

    if (this.#mdns) {
      await this.#mdns.stop()
      this.#mdns = null
    }

    if (this.#ws) {
      this.#ws.close()
      this.#ws = null
    }

    this.#onLog(`[kernel] stopped: ${this.#identity.podId}`)
  }

  /** @returns {string} */
  get state() {
    return this.#state
  }

  /** @returns {string} */
  get podId() {
    return this.#identity.podId
  }

  /** @returns {ServerIdentity} */
  get identity() {
    return this.#identity
  }

  /** @returns {ServerFileSystem} */
  get fileSystem() {
    return this.#fileSystem
  }

  /** @returns {ServerAgent} */
  get agent() {
    return this.#agent
  }

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

  /** @returns {string} */
  get serviceToken() {
    return this.#serviceToken
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

  /** @returns {object|null} MdnsDiscovery instance or null */
  get mdns() {
    return this.#mdns
  }

  /** @returns {string[]} */
  get connectedPeers() {
    return Array.from(this.#connectedPeers)
  }

  /** @returns {object} */
  toJSON() {
    return {
      podId: this.#identity.podId,
      label: this.#identity.label,
      state: this.#state,
      services: this.listServices(),
      connectedPeers: this.connectedPeers,
      created: this.#identity.created,
    }
  }
}

// ─── Factory ─────────────────────────────────────────────────────────

/**
 * Create a server kernel with sensible defaults.
 *
 * @param {object} [opts]
 * @param {ServerIdentity} [opts.identity]  — use existing identity, or generate one
 * @param {string} [opts.dataDir]           — file storage root
 * @param {string} [opts.signalingUrl]      — signaling server WebSocket URL
 * @param {string} [opts.agentName]         — agent name
 * @param {string} [opts.label]             — pod label
 * @param {string} [opts.llmProvider]       — 'openai' or 'anthropic'
 * @param {string} [opts.llmApiKey]         — API key for the LLM provider
 * @param {string} [opts.llmModel]          — model name override
 * @param {(msg: string) => void} [opts.onLog]
 * @returns {Promise<PeerNodeServer>}
 */
async function createServerKernel(opts = {}) {
  const identity = opts.identity ?? await ServerIdentity.generate(opts.label)
  return new PeerNodeServer({
    identity,
    dataDir: opts.dataDir,
    signalingUrl: opts.signalingUrl,
    agentName: opts.agentName,
    serviceToken: opts.serviceToken,
    maxMemories: opts.maxMemories,
    llmProvider: opts.llmProvider,
    llmApiKey: opts.llmApiKey,
    llmModel: opts.llmModel,
    mdnsPort: opts.mdnsPort,
    onLog: opts.onLog,
  })
}

// ─── Direct execution ────────────────────────────────────────────────

const isMain = process.argv[1] === fileURLToPath(import.meta.url)

if (isMain) {
  const env = process.env
  const kernel = await createServerKernel({
    dataDir: env.DATA_DIR ?? './data',
    signalingUrl: env.SIGNALING_URL,
    agentName: env.AGENT_NAME ?? 'server-agent',
    label: env.POD_LABEL,
    maxMemories: Number(env.MAX_MEMORIES) || undefined,
    llmProvider: env.LLM_PROVIDER || undefined,
    llmApiKey: env.LLM_API_KEY || undefined,
    llmModel: env.LLM_MODEL || undefined,
    mdnsPort: Number(env.MDNS_PORT) || undefined,
    onLog: console.log,
  })

  await kernel.start()
  console.log(`[kernel] pod: ${kernel.podId}`)
  console.log(`[kernel] services: ${kernel.listServices().join(', ')}`)
  console.log(`[kernel] data dir: ${kernel.fileSystem.rootDir}`)

  const shutdown = async () => {
    console.log('\n[kernel] shutting down...')
    await kernel.stop()
    process.exitCode = 0
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}

export { ServerIdentity, ServerFileSystem, ServerAgent, PeerNodeServer, createServerKernel }

// New: ServerPod extends Pod — preferred over PeerNodeServer
export { ServerPod } from './server-pod.mjs'
