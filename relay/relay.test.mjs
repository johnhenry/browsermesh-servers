/**
 * Tests for the Clawser P2P relay server.
 *
 * Uses real HTTP + WebSocket connections against a server started on an
 * OS-assigned ephemeral port (port 0).
 */

import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { createRelayServer, RelayServer } from './index.mjs'
import WebSocket from 'ws'

// ─── Helpers ──────────────────────────────────────────────────────────

/** Connect a WS client and return it with a message collector. */
function connect(port) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`)
    const messages = []
    ws.on('open', () => resolve({ ws, messages }))
    ws.on('message', (raw) => messages.push(JSON.parse(raw.toString())))
    ws.on('error', reject)
  })
}

/** Send a JSON message. */
function send(ws, data) {
  ws.send(JSON.stringify(data))
}

/** Wait until the messages array has at least `n` entries. */
function waitForMessages(messages, n, timeout = 2000) {
  return new Promise((resolve, reject) => {
    const start = Date.now()
    const check = () => {
      if (messages.length >= n) return resolve()
      if (Date.now() - start > timeout) return reject(new Error(`timeout waiting for ${n} messages, got ${messages.length}: ${JSON.stringify(messages)}`))
      setTimeout(check, 20)
    }
    check()
  })
}

/** Simple HTTP GET that returns parsed JSON. */
async function httpGet(port, path) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`)
  return { status: res.status, body: await res.json() }
}

// ─── RelayServer unit tests ──────────────────────────────────────────

describe('RelayServer', () => {
  it('registers and unregisters peers', () => {
    const relay = new RelayServer()
    const fakeWs = { readyState: 1, send: () => {} }

    relay.register('pod-a', fakeWs)
    assert.equal(relay.size, 1)
    assert.ok(relay.hasPeer('pod-a'))
    assert.deepEqual(relay.listPeers(), ['pod-a'])

    relay.unregister('pod-a')
    assert.equal(relay.size, 0)
    assert.ok(!relay.hasPeer('pod-a'))
  })

  it('relays envelopes between peers', () => {
    const relay = new RelayServer()
    const received = []
    const wsA = { readyState: 1, send: () => {} }
    const wsB = { readyState: 1, send: (data) => received.push(JSON.parse(data)) }

    relay.register('pod-a', wsA)
    relay.register('pod-b', wsB)

    const result = relay.relay('pod-a', 'pod-b', { data: 'hello' })
    assert.equal(result.success, true)
    assert.equal(received.length, 1)
    assert.equal(received[0].type, 'relayed')
    assert.equal(received[0].source, 'pod-a')
    assert.deepEqual(received[0].envelope, { data: 'hello' })
  })

  it('returns error when relaying to unknown peer', () => {
    const relay = new RelayServer()
    const wsA = { readyState: 1, send: () => {} }
    relay.register('pod-a', wsA)

    const result = relay.relay('pod-a', 'pod-ghost', { data: 'hi' })
    assert.equal(result.success, false)
    assert.ok(result.error.includes('not found'))
  })

  it('enforces rate limits', () => {
    const relay = new RelayServer({ maxMessagesPerMinute: 3 })
    const wsA = { readyState: 1, send: () => {} }
    const wsB = { readyState: 1, send: () => {} }
    relay.register('pod-a', wsA)
    relay.register('pod-b', wsB)

    // First 3 should succeed
    assert.equal(relay.relay('pod-a', 'pod-b', { n: 1 }).success, true)
    assert.equal(relay.relay('pod-a', 'pod-b', { n: 2 }).success, true)
    assert.equal(relay.relay('pod-a', 'pod-b', { n: 3 }).success, true)

    // 4th should be rate-limited
    const result = relay.relay('pod-a', 'pod-b', { n: 4 })
    assert.equal(result.success, false)
    assert.ok(result.error.includes('rate limit'))
    assert.equal(relay.rejectedCount, 1)
  })

  it('tracks relayed and rejected counts', () => {
    const relay = new RelayServer({ maxMessagesPerMinute: 2 })
    const wsA = { readyState: 1, send: () => {} }
    const wsB = { readyState: 1, send: () => {} }
    relay.register('pod-a', wsA)
    relay.register('pod-b', wsB)

    relay.relay('pod-a', 'pod-b', { n: 1 })
    relay.relay('pod-a', 'pod-b', { n: 2 })
    relay.relay('pod-a', 'pod-b', { n: 3 }) // rate-limited

    assert.equal(relay.relayedCount, 2)
    assert.equal(relay.rejectedCount, 1)
  })
})

// ─── Integration tests ───────────────────────────────────────────────

describe('relay server', () => {
  let instance
  let port

  beforeEach(async () => {
    instance = createRelayServer({ port: 0, onLog: () => {} })
    port = await instance.listen(0)
  })

  afterEach(async () => {
    await instance.close()
  })

  // ── HTTP endpoints ───────────────────────────────────────────────

  describe('HTTP', () => {
    it('GET /health returns ok with peer count', async () => {
      const { status, body } = await httpGet(port, '/health')
      assert.equal(status, 200)
      assert.equal(body.status, 'ok')
      assert.equal(body.peers, 0)
    })

    it('GET /stats returns stats object', async () => {
      const { status, body } = await httpGet(port, '/stats')
      assert.equal(status, 200)
      assert.equal(typeof body.peers, 'number')
      assert.equal(typeof body.relayed, 'number')
      assert.equal(typeof body.rejected, 'number')
      assert.equal(typeof body.uptime, 'number')
    })

    it('GET unknown path returns 404', async () => {
      const { status, body } = await httpGet(port, '/nope')
      assert.equal(status, 404)
      assert.equal(body.error, 'not found')
    })
  })

  // ── Registration ─────────────────────────────────────────────────

  describe('registration', () => {
    it('registers a client and confirms', async () => {
      const { ws, messages } = await connect(port)
      send(ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(messages, 1)

      assert.equal(messages[0].type, 'registered')
      assert.equal(messages[0].podId, 'pod-a')
      ws.close()
    })

    it('rejects duplicate podId', async () => {
      const a = await connect(port)
      send(a.ws, { type: 'register', podId: 'pod-dup' })
      await waitForMessages(a.messages, 1)

      const b = await connect(port)
      send(b.ws, { type: 'register', podId: 'pod-dup' })
      await waitForMessages(b.messages, 1)

      assert.equal(b.messages[0].type, 'error')
      assert.ok(b.messages[0].message.includes('already registered'))

      a.ws.close()
      b.ws.close()
    })

    it('rejects missing podId in register message', async () => {
      const { ws, messages } = await connect(port)
      send(ws, { type: 'register' })
      await waitForMessages(messages, 1)

      assert.equal(messages[0].type, 'error')
      assert.ok(messages[0].message.includes('first message'))
      ws.close()
    })

    it('rejects invalid JSON', async () => {
      const { ws, messages } = await connect(port)
      ws.send('not json {{{')
      await waitForMessages(messages, 1)

      assert.equal(messages[0].type, 'error')
      assert.ok(messages[0].message.includes('invalid JSON'))
      ws.close()
    })
  })

  // ── Relay forwarding ─────────────────────────────────────────────

  describe('relay forwarding', () => {
    it('relays envelope from one peer to another', async () => {
      const a = await connect(port)
      const b = await connect(port)

      send(a.ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(a.messages, 1)

      send(b.ws, { type: 'register', podId: 'pod-b' })
      await waitForMessages(b.messages, 1)

      // pod-a relays to pod-b
      send(a.ws, { type: 'relay', target: 'pod-b', envelope: { msg: 'hello' } })
      await waitForMessages(b.messages, 2)

      const relayed = b.messages[1]
      assert.equal(relayed.type, 'relayed')
      assert.equal(relayed.source, 'pod-a')
      assert.deepEqual(relayed.envelope, { msg: 'hello' })

      a.ws.close()
      b.ws.close()
    })

    it('returns error when target peer is unknown', async () => {
      const a = await connect(port)
      send(a.ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(a.messages, 1)

      send(a.ws, { type: 'relay', target: 'pod-ghost', envelope: { msg: 'hi' } })
      await waitForMessages(a.messages, 2)

      const err = a.messages[1]
      assert.equal(err.type, 'error')
      assert.ok(err.message.includes('not found'))

      a.ws.close()
    })

    it('returns error when target field is missing', async () => {
      const a = await connect(port)
      send(a.ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(a.messages, 1)

      send(a.ws, { type: 'relay', envelope: { msg: 'hi' } })
      await waitForMessages(a.messages, 2)

      const err = a.messages[1]
      assert.equal(err.type, 'error')
      assert.ok(err.message.includes('target'))

      a.ws.close()
    })

    it('returns error when envelope field is missing', async () => {
      const a = await connect(port)
      send(a.ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(a.messages, 1)

      send(a.ws, { type: 'relay', target: 'pod-b' })
      await waitForMessages(a.messages, 2)

      const err = a.messages[1]
      assert.equal(err.type, 'error')
      assert.ok(err.message.includes('envelope'))

      a.ws.close()
    })
  })

  // ── Disconnection ────────────────────────────────────────────────

  describe('disconnection', () => {
    it('cleans up peer on disconnect', async () => {
      const a = await connect(port)
      send(a.ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(a.messages, 1)

      let health = await httpGet(port, '/health')
      assert.equal(health.body.peers, 1)

      a.ws.close()
      await new Promise(r => setTimeout(r, 100))

      health = await httpGet(port, '/health')
      assert.equal(health.body.peers, 0)
    })
  })

  // ── Ping ─────────────────────────────────────────────────────────

  describe('ping', () => {
    it('responds to ping with pong', async () => {
      const a = await connect(port)
      send(a.ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(a.messages, 1)

      send(a.ws, { type: 'ping' })
      await waitForMessages(a.messages, 2)

      const pong = a.messages[1]
      assert.equal(pong.type, 'pong')
      assert.equal(typeof pong.timestamp, 'number')

      a.ws.close()
    })
  })

  // ── Unknown message type ─────────────────────────────────────────

  describe('unknown messages', () => {
    it('returns error for unknown message types', async () => {
      const a = await connect(port)
      send(a.ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(a.messages, 1)

      send(a.ws, { type: 'banana' })
      await waitForMessages(a.messages, 2)

      const err = a.messages[1]
      assert.equal(err.type, 'error')
      assert.ok(err.message.includes('unknown'))

      a.ws.close()
    })
  })
})

// ─── Connection limits ──────────────────────────────────────────────

describe('relay connection limits', () => {
  let instance
  let port

  beforeEach(async () => {
    instance = createRelayServer({ port: 0, maxConnections: 2, onLog: () => {} })
    port = await instance.listen(0)
  })

  afterEach(async () => {
    await instance.close()
  })

  it('rejects connections when at capacity', async () => {
    const a = await connect(port)
    const b = await connect(port)
    send(a.ws, { type: 'register', podId: 'pod-a' })
    send(b.ws, { type: 'register', podId: 'pod-b' })
    await waitForMessages(a.messages, 1)
    await waitForMessages(b.messages, 1)

    // Third connection should be rejected
    const c = await connect(port)
    await waitForMessages(c.messages, 1)

    assert.equal(c.messages[0].type, 'error')
    assert.ok(c.messages[0].message.includes('capacity'))

    // Wait for close
    await new Promise(resolve => c.ws.on('close', resolve))

    a.ws.close()
    b.ws.close()
  })
})
