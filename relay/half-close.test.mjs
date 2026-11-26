/**
 * wsh 0.57 keeps a half-closed gateway connection open until both sides have finished, or until nothing has moved in either
 * direction for the host's `gateway.halfCloseIdleMs`. This route is a byte copier between two WebSockets: a half-close is a frame
 * inside a wsh session, and the route never sees it as one. What these tests pin is what that means here:
 *
 *  - a client that half-closes a connection and waits for a late answer through the pipe route gets it, and the pair is
 *    still joined (a half-close does not end a pair; only a WebSocket close, the route's bounds or the session ending do);
 *  - a connection left half-closed and abandoned does not hold the pair beyond the route's own bound: `PIPE_IDLE_TIMEOUT_MS`
 *    (no byte either way) and `PIPE_MAX_LIFETIME_MS` are the route's, not wsh's, and 0.57 did not change them.
 *
 * Real wsh host and client on both ends, over real loopback sockets, through this server's pipe route. Needs no ML-KEM: the
 * session is not sealed here (the sealed link is covered by wsh-links.test.mjs).
 */

import { describe, it, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import WebSocket from 'ws'
import { createRelayServer } from './index.mjs'

const ORIGIN = 'https://app.example'
const newId = () => randomBytes(16).toString('base64url')
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const enc = new TextEncoder()
const dec = new TextDecoder()

let wsh = null
let memory = null
try {
  wsh = await import('@johnhenry/wsh')
  memory = await import('@johnhenry/wsh/memory')
} catch { /* skipped below */ }

/** ws with the Origin header a browser would send. */
class OriginWebSocket extends WebSocket {
  constructor(url, protocols) { super(url, protocols, { origin: ORIGIN }) }
}

async function readAll(duplex) {
  const reader = duplex.readable.getReader()
  const parts = []
  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    parts.push(Buffer.from(value))
  }
  return Buffer.concat(parts)
}

describe('wsh half-close through the pipe route', { skip: wsh ? false : '@johnhenry/wsh is not installed' }, () => {
  let instance
  const cleanups = []
  afterEach(async () => {
    for (const c of cleanups.splice(0).reverse()) await c().catch(() => {})
    await instance?.close()
    instance = null
  })

  /** A relay with the pipe route, a wsh host waiting at it, and a wsh client logged in through it. */
  async function pair({ env = {}, endpoints }) {
    instance = createRelayServer({ port: 0, onLog: () => {}, env: { PIPE_RELAY: '1', PIPE_ORIGINS: ORIGIN, ...env } })
    const port = await instance.listen(0, '127.0.0.1')
    const id = newId()
    const base = `ws://127.0.0.1:${port}/r/${id}`

    const hostKey = await wsh.generateKeyPair()
    const clientKey = await wsh.generateKeyPair()
    const host = memory.createMemoryHost({
      hostKey,
      dataStreams: false,
      auth: () => true,
      endpoints,
      onLog: () => {},
    })
    cleanups.push(async () => host.close())
    const hostSocket = new OriginWebSocket(`${base}?role=host`)
    cleanups.push(async () => hostSocket.close())
    await new Promise((resolve, reject) => { hostSocket.once('open', resolve); hostSocket.once('error', reject) })
    void host.accept(hostSocket).catch(() => {})

    const closed = Promise.withResolvers()
    const client = new wsh.WshClient({
      transportFactories: {
        ws: () => new wsh.WebSocketTransport({ WebSocket: class { constructor() { return new OriginWebSocket(base) } } }),
        wt: () => { throw new Error('no WebTransport') },
      },
    })
    client.onClose = (info) => closed.resolve(info)
    await client.connect(base, { username: 'tester', keyPair: clientKey, transport: 'ws', sealSession: false })
    cleanups.push(async () => client.disconnect())
    return { client, closed: closed.promise, relay: instance }
  }

  it('an answer that arrives two seconds after the client half-closed is delivered, and the pair is still joined', { timeout: 30_000 }, async () => {
    const { client, relay } = await pair({
      endpoints: {
        late: async (duplex) => {
          const got = await readAll(duplex) // until the client's half-close
          await sleep(2000)
          const w = duplex.writable.getWriter()
          await w.write(enc.encode(`got ${got.length} bytes`))
          await w.close()
        },
      },
    })
    assert.equal(relay.pipe.stats().pipes, 1)
    const duplex = await client.openEndpoint('late')
    const w = duplex.writable.getWriter()
    await w.write(enc.encode('hello'))
    await w.close() // half-close: nothing more from the client
    assert.equal(dec.decode(await readAll(duplex)), 'got 5 bytes')
    assert.equal(relay.pipe.stats().pipes, 1, 'the half-close did not end the pair')
  })

  it('the session goes on working while one of its connections is half-closed and silent', { timeout: 30_000 }, async () => {
    const { client, relay } = await pair({
      endpoints: {
        silent: async (duplex) => { await readAll(duplex); await sleep(60_000) }, // reads to the end, never answers, never closes
        echo: async (duplex) => {
          const got = await readAll(duplex)
          const w = duplex.writable.getWriter()
          await w.write(got)
          await w.close()
        },
      },
    })
    const quiet = await client.openEndpoint('silent')
    await quiet.writable.getWriter().close() // half-closed, and abandoned: nobody reads it
    await sleep(300)
    assert.equal(relay.pipe.stats().pipes, 1, 'a half-closed connection does not end the pair')
    const second = await client.openEndpoint('echo')
    const w = second.writable.getWriter()
    await w.write(enc.encode('still works'))
    await w.close()
    assert.equal(dec.decode(await readAll(second)), 'still works')
  })

  it('a pair is bounded by the route\'s own idle bound, whatever state a connection inside it is in', { timeout: 30_000 }, async () => {
    const { client, closed, relay } = await pair({
      env: { PIPE_IDLE_TIMEOUT_MS: '400' },
      endpoints: { silent: async (duplex) => { await readAll(duplex); await sleep(60_000) } },
    })
    const quiet = await client.openEndpoint('silent')
    await quiet.writable.getWriter().close()
    // nothing moves: the route closes the pipe at its bound (wsh's own five minutes for the connection never gets the chance)
    await closed
    for (let i = 0; i < 100 && relay.pipe.stats().pipes; i++) await sleep(10)
    assert.equal(relay.pipe.stats().pipes, 0)
  })
})
