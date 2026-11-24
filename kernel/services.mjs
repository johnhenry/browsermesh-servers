/**
 * Service registry for the server kernel.
 *
 * Remote callers name a service and a method as strings. The registry makes
 * sure those strings can only ever select something that was declared:
 *
 *  - services live in a Map, so a name like "constructor" is just a key;
 *  - each service's callable methods are a snapshot taken at registration into
 *    a null-prototype table and looked up with Object.hasOwn: nothing inherited
 *    from Object.prototype, from a handler's class, or added later is reachable;
 *  - only services on the remote allow-list can be called remotely at all
 *    (the built-ins `fs` and `agent` by default; others need `{ remote: true }`).
 *
 * Handlers stay available to trusted in-process code through `handler(name)`.
 */

import { createHash, timingSafeEqual } from 'node:crypto'

const SERVICE_NAME_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/
const METHOD_NAME_RE = /^[A-Za-z_$][A-Za-z0-9_$]{0,63}$/
const FORBIDDEN_METHODS = new Set(['__proto__', 'constructor', 'prototype'])

export const DEFAULT_REMOTE_SERVICES = Object.freeze(['fs', 'agent'])

/**
 * Compare two strings in constant time with respect to their content: both are
 * hashed to equal-length digests first, so differing lengths neither throw nor
 * leak through the comparison.
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

/** A short printable rendering of a caller-supplied value for an error message. */
function shown(v) {
  if (typeof v !== 'string') return typeof v
  return v.slice(0, 64).replace(/[^\x20-\x7e]/g, '?')
}

function isMethodName(m) {
  return typeof m === 'string' && METHOD_NAME_RE.test(m) && !FORBIDDEN_METHODS.has(m)
}

export class ServiceRegistry {
  /** @type {Map<string, { handler: object, methods: Record<string, Function> }>} */
  #entries = new Map()
  /** @type {Set<string>} */
  #remote

  /**
   * @param {object} [opts]
   * @param {Iterable<string>} [opts.remote] — services callable remotely (default: fs, agent)
   */
  constructor({ remote = DEFAULT_REMOTE_SERVICES } = {}) {
    this.#remote = new Set(remote)
  }

  /**
   * Register a service.
   *
   * @param {string} name
   * @param {object} handler
   * @param {object} [opts]
   * @param {string[]} [opts.methods] — declare the callable methods explicitly
   *        (they may live on the handler's prototype); default: the handler's
   *        own enumerable function properties
   * @param {boolean} [opts.remote]   — allow remote callers to reach this service
   */
  register(name, handler, { methods, remote } = {}) {
    if (typeof name !== 'string' || !SERVICE_NAME_RE.test(name)) {
      throw new TypeError('service name must be 1-64 characters: a letter, then letters, digits, "_", "." or "-"')
    }
    if (handler === null || typeof handler !== 'object') {
      throw new TypeError('service handler must be an object')
    }
    const table = Object.create(null)
    if (methods !== undefined) {
      for (const m of methods) {
        if (!isMethodName(m) || typeof handler[m] !== 'function') {
          throw new TypeError(`method "${shown(m)}" is not a declarable function of service "${name}"`)
        }
        table[m] = handler[m]
      }
    } else {
      for (const m of Object.keys(handler)) {
        if (isMethodName(m) && typeof handler[m] === 'function') table[m] = handler[m]
      }
    }
    this.#entries.set(name, { handler, methods: Object.freeze(table) })
    if (remote === true) this.#remote.add(name)
    else if (remote === false) this.#remote.delete(name)
  }

  /** @returns {boolean} whether it existed */
  unregister(name) {
    this.#remote.delete(name)
    return this.#entries.delete(name)
  }

  /** @returns {string[]} every registered service name */
  list() {
    return [...this.#entries.keys()]
  }

  /** @returns {string[]} names that remote callers may reach */
  listRemote() {
    return [...this.#entries.keys()].filter(n => this.#remote.has(n))
  }

  /** The registered handler, for trusted in-process use. */
  handler(name) {
    return this.#entries.get(name)?.handler
  }

  /** The declared method table of a service (null-prototype), or undefined. */
  methodsOf(name) {
    return this.#entries.get(name)?.methods
  }

  /**
   * Call a method on behalf of a remote caller. Authorization is the
   * caller's job; this decides what can be named.
   *
   * @param {unknown} name
   * @param {unknown} method
   * @param {unknown} args
   * @returns {Promise<unknown>}
   */
  async call(name, method, args) {
    const unknown = { success: false, error: `unknown service method: ${shown(name)}.${shown(method)}` }
    if (typeof name !== 'string' || typeof method !== 'string') return unknown
    const entry = this.#entries.get(name)
    if (!entry || !this.#remote.has(name)) return unknown
    if (!Object.hasOwn(entry.methods, method)) return unknown
    if (args !== undefined && (args === null || typeof args !== 'object' || Array.isArray(args))) {
      return { success: false, error: 'args must be an object' }
    }
    return entry.methods[method].call(entry.handler, args)
  }
}
