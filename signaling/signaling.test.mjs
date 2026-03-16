/**
 * Tests for the Clawser P2P signaling server.
 *
 * Uses real HTTP + WebSocket connections against a server started on an
 * OS-assigned ephemeral port (port 0).  This avoids mocking and tests
 * the actual protocol end-to-end.
 */

import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from './index.mjs'
import { getIceServers, DEFAULT_STUN_SERVERS } from './stun-turn.mjs'
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

// ─── stun-turn.mjs unit tests ────────────────────────────────────────

describe('stun-turn', () => {
  it('returns default STUN servers when no env is set', () => {
    const servers = getIceServers({})
    assert.deepEqual(servers, DEFAULT_STUN_SERVERS)
  })

  it('parses ICE_SERVERS from env JSON', () => {
    const custom = [{ urls: 'stun:custom.example.com:3478' }]
    const servers = getIceServers({ ICE_SERVERS: JSON.stringify(custom) })
    assert.deepEqual(servers, custom)
  })

  it('falls back to defaults on invalid ICE_SERVERS JSON', () => {
    const servers = getIceServers({ ICE_SERVERS: 'not-json' })
    assert.deepEqual(servers, DEFAULT_STUN_SERVERS)
  })

  it('falls back to defaults on empty ICE_SERVERS array', () => {
    const servers = getIceServers({ ICE_SERVERS: '[]' })
    assert.deepEqual(servers, DEFAULT_STUN_SERVERS)
  })

  it('appends TURN server from env vars', () => {
    const servers = getIceServers({
      TURN_URLS: 'turn:turn.example.com:3478',
      TURN_USERNAME: 'user',
      TURN_CREDENTIAL: 'pass',
    })
    assert.equal(servers.length, 3) // 2 STUN + 1 TURN
    assert.deepEqual(servers[2], {
      urls: 'turn:turn.example.com:3478',
      username: 'user',
      credential: 'pass',
    })
  })

  it('appends TURN without credentials if only TURN_URLS is set', () => {
    const servers = getIceServers({ TURN_URLS: 'turn:turn.example.com:3478' })
    assert.equal(servers.length, 3)
    assert.deepEqual(servers[2], { urls: 'turn:turn.example.com:3478' })
  })
})

// ─── Signaling server integration tests ──────────────────────────────

describe('signaling server', () => {
  let instance
  let port

  beforeEach(async () => {
    instance = createServer({ port: 0 })
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

    it('GET /ice-servers returns ICE configuration', async () => {
      const { status, body } = await httpGet(port, '/ice-servers')
      assert.equal(status, 200)
      assert.ok(Array.isArray(body))
      assert.ok(body.length >= 2) // at least the default STUN servers
    })

    it('GET unknown path returns 404', async () => {
      const { status, body } = await httpGet(port, '/nope')
      assert.equal(status, 404)
      assert.equal(body.error, 'not found')
    })
  })

  // ── Registration ─────────────────────────────────────────────────

  describe('registration', () => {
    it('registers a client and confirms with registered message', async () => {
      const { ws, messages } = await connect(port)
      send(ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(messages, 2) // registered + peers

      assert.equal(messages[0].type, 'registered')
      assert.equal(messages[0].podId, 'pod-a')
      ws.close()
    })

    it('broadcasts peer list after registration', async () => {
      const { ws, messages } = await connect(port)
      send(ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(messages, 2)

      const peerMsg = messages.find(m => m.type === 'peers')
      assert.ok(peerMsg)
      assert.deepEqual(peerMsg.peers, ['pod-a'])
      ws.close()
    })

    it('rejects registration with missing podId', async () => {
      const { ws, messages } = await connect(port)
      send(ws, { type: 'register' })
      await waitForMessages(messages, 1)

      assert.equal(messages[0].type, 'error')
      assert.ok(messages[0].message.includes('first message'))
      ws.close()
    })

    it('rejects non-register first message', async () => {
      const { ws, messages } = await connect(port)
      send(ws, { type: 'offer', target: 'pod-b', sdp: '...' })
      await waitForMessages(messages, 1)

      assert.equal(messages[0].type, 'error')
      ws.close()
    })

    it('rejects duplicate podId', async () => {
      const a = await connect(port)
      send(a.ws, { type: 'register', podId: 'pod-dup' })
      await waitForMessages(a.messages, 2)

      const b = await connect(port)
      send(b.ws, { type: 'register', podId: 'pod-dup' })
      await waitForMessages(b.messages, 1)

      assert.equal(b.messages[0].type, 'error')
      assert.ok(b.messages[0].message.includes('already registered'))

      a.ws.close()
      b.ws.close()
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

  // ── Message forwarding ───────────────────────────────────────────

  describe('forwarding', () => {
    it('forwards offer from source to target with source field', async () => {
      const a = await connect(port)
      const b = await connect(port)

      send(a.ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(a.messages, 2)

      send(b.ws, { type: 'register', podId: 'pod-b' })
      await waitForMessages(b.messages, 2)

      // Clear initial messages
      const bInitialCount = b.messages.length

      // pod-a sends offer to pod-b
      send(a.ws, { type: 'offer', target: 'pod-b', sdp: 'test-sdp' })
      await waitForMessages(b.messages, bInitialCount + 1)

      const forwarded = b.messages[b.messages.length - 1]
      assert.equal(forwarded.type, 'offer')
      assert.equal(forwarded.source, 'pod-a')
      assert.equal(forwarded.sdp, 'test-sdp')
      // target field should not be forwarded (it was destructured out)
      assert.equal(forwarded.target, undefined)

      a.ws.close()
      b.ws.close()
    })

    it('forwards answer messages', async () => {
      const a = await connect(port)
      const b = await connect(port)

      send(a.ws, { type: 'register', podId: 'pod-a' })
      send(b.ws, { type: 'register', podId: 'pod-b' })
      await waitForMessages(a.messages, 3) // registered + peers(a) + peers(a,b)
      await waitForMessages(b.messages, 2) // registered + peers(a,b)

      const aInitialCount = a.messages.length
      send(b.ws, { type: 'answer', target: 'pod-a', sdp: 'answer-sdp' })
      await waitForMessages(a.messages, aInitialCount + 1)

      const forwarded = a.messages[a.messages.length - 1]
      assert.equal(forwarded.type, 'answer')
      assert.equal(forwarded.source, 'pod-b')
      assert.equal(forwarded.sdp, 'answer-sdp')

      a.ws.close()
      b.ws.close()
    })

    it('forwards ice-candidate messages', async () => {
      const a = await connect(port)
      const b = await connect(port)

      send(a.ws, { type: 'register', podId: 'pod-a' })
      send(b.ws, { type: 'register', podId: 'pod-b' })
      await waitForMessages(a.messages, 2)
      await waitForMessages(b.messages, 2)

      const bInitialCount = b.messages.length
      send(a.ws, { type: 'ice-candidate', target: 'pod-b', candidate: { sdpMid: '0' } })
      await waitForMessages(b.messages, bInitialCount + 1)

      const forwarded = b.messages[b.messages.length - 1]
      assert.equal(forwarded.type, 'ice-candidate')
      assert.equal(forwarded.source, 'pod-a')
      assert.deepEqual(forwarded.candidate, { sdpMid: '0' })

      a.ws.close()
      b.ws.close()
    })

    it('forwards generic signal messages', async () => {
      const a = await connect(port)
      const b = await connect(port)

      send(a.ws, { type: 'register', podId: 'pod-a' })
      send(b.ws, { type: 'register', podId: 'pod-b' })
      await waitForMessages(a.messages, 2)
      await waitForMessages(b.messages, 2)

      const bInitialCount = b.messages.length
      send(a.ws, { type: 'signal', target: 'pod-b', data: { foo: 'bar' } })
      await waitForMessages(b.messages, bInitialCount + 1)

      const forwarded = b.messages[b.messages.length - 1]
      assert.equal(forwarded.type, 'signal')
      assert.equal(forwarded.source, 'pod-a')
      assert.deepEqual(forwarded.data, { foo: 'bar' })

      a.ws.close()
      b.ws.close()
    })

    it('returns error when target peer is not found', async () => {
      const a = await connect(port)
      send(a.ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(a.messages, 2)

      const initialCount = a.messages.length
      send(a.ws, { type: 'offer', target: 'pod-ghost', sdp: '...' })
      await waitForMessages(a.messages, initialCount + 1)

      const err = a.messages[a.messages.length - 1]
      assert.equal(err.type, 'error')
      assert.ok(err.message.includes('not found'))

      a.ws.close()
    })

    it('returns error when target field is missing', async () => {
      const a = await connect(port)
      send(a.ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(a.messages, 2)

      const initialCount = a.messages.length
      send(a.ws, { type: 'offer', sdp: '...' })
      await waitForMessages(a.messages, initialCount + 1)

      const err = a.messages[a.messages.length - 1]
      assert.equal(err.type, 'error')
      assert.ok(err.message.includes('target'))

      a.ws.close()
    })

    it('returns error for unknown message types', async () => {
      const a = await connect(port)
      send(a.ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(a.messages, 2)

      const initialCount = a.messages.length
      send(a.ws, { type: 'banana' })
      await waitForMessages(a.messages, initialCount + 1)

      const err = a.messages[a.messages.length - 1]
      assert.equal(err.type, 'error')
      assert.ok(err.message.includes('unknown'))

      a.ws.close()
    })
  })

  // ── Disconnection ────────────────────────────────────────────────

  describe('disconnection', () => {
    it('sends peer-left event when a client leaves', async () => {
      const a = await connect(port)
      const b = await connect(port)

      send(a.ws, { type: 'register', podId: 'pod-a' })
      send(b.ws, { type: 'register', podId: 'pod-b' })
      await waitForMessages(a.messages, 3) // registered + peers + peer-joined
      await waitForMessages(b.messages, 2)

      const aInitialCount = a.messages.length

      // pod-b disconnects
      b.ws.close()

      // pod-a should receive peer-left event
      await waitForMessages(a.messages, aInitialCount + 1)

      const leaveMsg = a.messages.find((m, i) => i >= aInitialCount && m.type === 'peer-left')
      assert.ok(leaveMsg)
      assert.equal(leaveMsg.podId, 'pod-b')

      a.ws.close()
    })

    it('updates health check after disconnect', async () => {
      const a = await connect(port)
      send(a.ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(a.messages, 2)

      let health = await httpGet(port, '/health')
      assert.equal(health.body.peers, 1)

      a.ws.close()

      // Wait a bit for cleanup
      await new Promise(r => setTimeout(r, 100))

      health = await httpGet(port, '/health')
      assert.equal(health.body.peers, 0)
    })
  })

  // ── Ping / keep-alive ────────────────────────────────────────────

  describe('ping', () => {
    it('responds to ping with pong', async () => {
      const a = await connect(port)
      send(a.ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(a.messages, 2)

      const initialCount = a.messages.length
      send(a.ws, { type: 'ping' })
      await waitForMessages(a.messages, initialCount + 1)

      const pong = a.messages[a.messages.length - 1]
      assert.equal(pong.type, 'pong')
      assert.equal(typeof pong.timestamp, 'number')

      a.ws.close()
    })
  })

  // ── Multi-peer scenario ──────────────────────────────────────────

  describe('multi-peer', () => {
    it('tracks three peers and broadcasts correctly', async () => {
      const a = await connect(port)
      const b = await connect(port)
      const c = await connect(port)

      send(a.ws, { type: 'register', podId: 'pod-a' })
      await waitForMessages(a.messages, 2)

      send(b.ws, { type: 'register', podId: 'pod-b' })
      await waitForMessages(b.messages, 2)

      send(c.ws, { type: 'register', podId: 'pod-c' })
      await waitForMessages(c.messages, 2)

      // Health should show 3 peers
      const { body } = await httpGet(port, '/health')
      assert.equal(body.peers, 3)

      // c's peers message should include all three
      const peersMsg = c.messages.find(m => m.type === 'peers')
      assert.ok(peersMsg)
      assert.ok(peersMsg.peers.includes('pod-a'))
      assert.ok(peersMsg.peers.includes('pod-b'))
      assert.ok(peersMsg.peers.includes('pod-c'))

      a.ws.close()
      b.ws.close()
      c.ws.close()
    })
  })
})

// ─── Origin restriction ──────────────────────────────────────────────

describe('origin restriction', () => {
  let instance
  let port

  beforeEach(async () => {
    instance = createServer({ port: 0, origins: 'http://localhost:3000,https://clawser.app' })
    port = await instance.listen(0)
  })

  afterEach(async () => {
    await instance.close()
  })

  it('accepts connections with allowed origin', async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`, {
      headers: { origin: 'http://localhost:3000' },
    })
    const messages = []
    ws.on('message', (raw) => messages.push(JSON.parse(raw.toString())))

    await new Promise((resolve) => ws.on('open', resolve))

    send(ws, { type: 'register', podId: 'pod-allowed' })
    await waitForMessages(messages, 2)

    assert.equal(messages[0].type, 'registered')
    ws.close()
  })

  it('rejects connections with disallowed origin', async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`, {
      headers: { origin: 'http://evil.com' },
    })
    const messages = []
    ws.on('message', (raw) => messages.push(JSON.parse(raw.toString())))

    await new Promise((resolve) => ws.on('open', resolve))

    await waitForMessages(messages, 1)
    assert.equal(messages[0].type, 'error')
    assert.ok(messages[0].message.includes('origin'))

    // Connection should be closed by server
    await new Promise((resolve) => ws.on('close', resolve))
  })
})

// ─── Connection limits ──────────────────────────────────────────────

describe('signaling connection limits', () => {
  let instance
  let port

  beforeEach(async () => {
    instance = createServer({ port: 0, maxConnections: 2 })
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
    await waitForMessages(a.messages, 2)
    await waitForMessages(b.messages, 2)

    // Third connection should be rejected
    const c = await connect(port)
    await waitForMessages(c.messages, 1)

    assert.equal(c.messages[0].type, 'error')
    assert.ok(c.messages[0].message.includes('capacity'))

    await new Promise(resolve => c.ws.on('close', resolve))

    a.ws.close()
    b.ws.close()
  })
})

// ─── Rate limiting ──────────────────────────────────────────────────

describe('signaling rate limiting', () => {
  let instance
  let port

  beforeEach(async () => {
    instance = createServer({ port: 0, maxMessagesPerMinute: 3 })
    port = await instance.listen(0)
  })

  afterEach(async () => {
    await instance.close()
  })

  it('rate limits forwarded messages', async () => {
    const a = await connect(port)
    const b = await connect(port)

    send(a.ws, { type: 'register', podId: 'pod-a' })
    send(b.ws, { type: 'register', podId: 'pod-b' })
    await waitForMessages(a.messages, 2)
    await waitForMessages(b.messages, 2)

    const aInitialCount = a.messages.length

    // Send 4 offers, 4th should be rate limited
    for (let i = 0; i < 4; i++) {
      send(a.ws, { type: 'offer', target: 'pod-b', sdp: `sdp-${i}` })
    }

    // Wait for rate limit error
    await waitForMessages(a.messages, aInitialCount + 1)

    const err = a.messages[a.messages.length - 1]
    assert.equal(err.type, 'error')
    assert.ok(err.message.includes('rate limit'))

    a.ws.close()
    b.ws.close()
  })
})

// ─── Encapsulated peers ─────────────────────────────────────────────

describe('signaling encapsulated peers', () => {
  let instance
  let port

  beforeEach(async () => {
    instance = createServer({ port: 0 })
    port = await instance.listen(0)
  })

  afterEach(async () => {
    await instance.close()
  })

  it('exposes peerCount and listPeers instead of raw peers Map', async () => {
    assert.equal(instance.peerCount, 0)
    assert.deepEqual(instance.listPeers(), [])

    const a = await connect(port)
    send(a.ws, { type: 'register', podId: 'pod-a' })
    await waitForMessages(a.messages, 2)

    assert.equal(instance.peerCount, 1)
    assert.deepEqual(instance.listPeers(), ['pod-a'])

    a.ws.close()
  })
})

// ─── Incremental peer events ────────────────────────────────────────

describe('signaling incremental peer events', () => {
  let instance
  let port

  beforeEach(async () => {
    instance = createServer({ port: 0 })
    port = await instance.listen(0)
  })

  afterEach(async () => {
    await instance.close()
  })

  it('sends peer-joined to existing peers on new registration', async () => {
    const a = await connect(port)
    send(a.ws, { type: 'register', podId: 'pod-a' })
    await waitForMessages(a.messages, 2) // registered + peers

    const aInitialCount = a.messages.length

    const b = await connect(port)
    send(b.ws, { type: 'register', podId: 'pod-b' })
    await waitForMessages(a.messages, aInitialCount + 1)

    const joinMsg = a.messages[a.messages.length - 1]
    assert.equal(joinMsg.type, 'peer-joined')
    assert.equal(joinMsg.podId, 'pod-b')

    // New peer gets full list
    await waitForMessages(b.messages, 2)
    const peersMsg = b.messages.find(m => m.type === 'peers')
    assert.ok(peersMsg)
    assert.ok(peersMsg.peers.includes('pod-a'))
    assert.ok(peersMsg.peers.includes('pod-b'))

    a.ws.close()
    b.ws.close()
  })

  it('sends peer-left to remaining peers on disconnect', async () => {
    const a = await connect(port)
    const b = await connect(port)

    send(a.ws, { type: 'register', podId: 'pod-a' })
    send(b.ws, { type: 'register', podId: 'pod-b' })
    await waitForMessages(a.messages, 3) // registered + peers + peer-joined
    await waitForMessages(b.messages, 2) // registered + peers

    const aInitialCount = a.messages.length

    b.ws.close()
    await waitForMessages(a.messages, aInitialCount + 1)

    const leaveMsg = a.messages[a.messages.length - 1]
    assert.equal(leaveMsg.type, 'peer-left')
    assert.equal(leaveMsg.podId, 'pod-b')

    a.ws.close()
  })
})

// ─── ICE server auth ────────────────────────────────────────────────

describe('signaling /ice-servers auth', () => {
  it('is open when no ICE_API_TOKEN is set', async () => {
    const instance = createServer({ port: 0 })
    const port = await instance.listen(0)

    const res = await fetch(`http://127.0.0.1:${port}/ice-servers`)
    assert.equal(res.status, 200)
    const body = await res.json()
    assert.ok(Array.isArray(body))

    await instance.close()
  })

  it('requires bearer token when ICE_API_TOKEN is set', async () => {
    const instance = createServer({ port: 0, env: { ICE_API_TOKEN: 'secret-token' } })
    const port = await instance.listen(0)

    // No token → 401
    const res1 = await fetch(`http://127.0.0.1:${port}/ice-servers`)
    assert.equal(res1.status, 401)

    // Wrong token → 401
    const res2 = await fetch(`http://127.0.0.1:${port}/ice-servers`, {
      headers: { Authorization: 'Bearer wrong' },
    })
    assert.equal(res2.status, 401)

    // Correct token → 200
    const res3 = await fetch(`http://127.0.0.1:${port}/ice-servers`, {
      headers: { Authorization: 'Bearer secret-token' },
    })
    assert.equal(res3.status, 200)
    const body = await res3.json()
    assert.ok(Array.isArray(body))

    await instance.close()
  })
})

// ─── AUTH_MODE=authenticated ────────────────────────────────────────

describe('signaling AUTH_MODE=authenticated', () => {
  let instance
  let port

  beforeEach(async () => {
    instance = createServer({ port: 0, authMode: 'authenticated' })
    port = await instance.listen(0)
  })

  afterEach(async () => {
    await instance.close()
  })

  it('rejects registration without pubKey and signature', async () => {
    const { ws, messages } = await connect(port)
    const closed = new Promise(resolve => ws.on('close', resolve))
    send(ws, { type: 'register', podId: 'pod-a' })
    await waitForMessages(messages, 1)

    assert.equal(messages[0].type, 'error')
    assert.ok(messages[0].message.includes('pubKey'))

    await closed
  })

  it('rejects registration with invalid signature', async () => {
    // Import webcrypto for key generation
    const { webcrypto } = await import('node:crypto')
    const keyPair = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
    const pubKeyRaw = new Uint8Array(await webcrypto.subtle.exportKey('raw', keyPair.publicKey))
    const pubKeyB64 = btoa(String.fromCharCode(...pubKeyRaw))
    // Sign a different message than podId
    const wrongSig = new Uint8Array(await webcrypto.subtle.sign('Ed25519', keyPair.privateKey, new TextEncoder().encode('wrong-pod-id')))
    const sigB64 = btoa(String.fromCharCode(...wrongSig))

    const { ws, messages } = await connect(port)
    const closed = new Promise(resolve => ws.on('close', resolve))
    send(ws, { type: 'register', podId: 'pod-a', pubKey: pubKeyB64, signature: sigB64 })
    await waitForMessages(messages, 1)

    assert.equal(messages[0].type, 'error')
    assert.ok(messages[0].message.includes('verification failed'))

    await closed
  })

  it('accepts registration with valid signature', async () => {
    const { webcrypto } = await import('node:crypto')
    const keyPair = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
    const pubKeyRaw = new Uint8Array(await webcrypto.subtle.exportKey('raw', keyPair.publicKey))
    const pubKeyB64 = btoa(String.fromCharCode(...pubKeyRaw))
    const podId = 'pod-authenticated'
    const sig = new Uint8Array(await webcrypto.subtle.sign('Ed25519', keyPair.privateKey, new TextEncoder().encode(podId)))
    const sigB64 = btoa(String.fromCharCode(...sig))

    const { ws, messages } = await connect(port)
    send(ws, { type: 'register', podId, pubKey: pubKeyB64, signature: sigB64 })
    await waitForMessages(messages, 2) // registered + peers

    assert.equal(messages[0].type, 'registered')
    assert.equal(messages[0].podId, podId)

    ws.close()
  })
})

// ─── AUTH_MODE=open ─────────────────────────────────────────────────

describe('signaling AUTH_MODE=open', () => {
  it('does not require signature', async () => {
    const instance = createServer({ port: 0, authMode: 'open' })
    const port = await instance.listen(0)

    const { ws, messages } = await connect(port)
    send(ws, { type: 'register', podId: 'pod-open' })
    await waitForMessages(messages, 2)

    assert.equal(messages[0].type, 'registered')

    ws.close()
    await instance.close()
  })
})
