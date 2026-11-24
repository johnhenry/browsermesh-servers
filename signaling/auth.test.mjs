/**
 * Registration modes of the signaling server.
 *
 *  - AUTH_MODE=open: any pod id is accepted; every peer is stamped
 *    `verified: false` so clients can tell.
 *  - AUTH_MODE=authenticated: protocol 2. The server issues a single-use,
 *    short-lived nonce on connect; the client proves possession of the key
 *    whose hash is the pod id by signing the nonce, the pod id, the server's
 *    origin and a purpose string.
 */

import { describe, it, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, webcrypto } from 'node:crypto'
import WebSocket from 'ws'
import { PodIdentity } from '@johnhenry/browsermesh-primitives'
import { createServer } from './index.mjs'
import { registrationMessage, derivePodId, REGISTER_PURPOSE, PROTOCOL_VERSION } from './auth.mjs'

const ORIGIN = 'wss://signal.example.org'

// ─── Client helpers ──────────────────────────────────────────────────

class Client {
  constructor(ws) {
    this.ws = ws
    this.messages = []
    this.waiters = []
    this.closed = new Promise((resolve) => ws.on('close', (code, reason) => {
      this.closeCode = code
      this.closeReason = reason.toString()
      resolve(code)
    }))
    ws.on('message', (raw) => {
      const m = JSON.parse(raw.toString())
      this.messages.push(m)
      for (const w of [...this.waiters]) w.check()
    })
  }

  static async connect(port, headers = {}) {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`, { headers })
    const c = new Client(ws)
    await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject) })
    return c
  }

  send(obj) { this.ws.send(typeof obj === 'string' ? obj : JSON.stringify(obj)) }

  /** Resolve with the first message (already received or future) matching `pred`. */
  waitFor(pred, { from = 0 } = {}) {
    return new Promise((resolve, reject) => {
      const check = () => {
        const m = this.messages.slice(from).find(pred)
        if (m) {
          this.waiters = this.waiters.filter(w => w !== waiter)
          clearTimeout(timer)
          resolve(m)
        }
      }
      const waiter = { check }
      const timer = setTimeout(() => reject(new Error(`no matching message; got ${JSON.stringify(this.messages)}`)), 5000)
      this.waiters.push(waiter)
      check()
    })
  }

  type(t, opts) { return this.waitFor(m => m.type === t, opts) }
  close() { this.ws.close() }
}

const b64 = (bytes) => Buffer.from(bytes).toString('base64')

/** Raw 32-byte public key of a PodIdentity (public-key export only). */
async function rawPublicKey(identity) {
  return new Uint8Array(await webcrypto.subtle.exportKey('raw', identity.keyPair.publicKey))
}

/** Sign a registration the way a correct client does. */
async function signRegistration(identity, { nonce, origin = ORIGIN, purpose = REGISTER_PURPOSE, podId = identity.podId }) {
  const msg = registrationMessage({ purpose, origin, podId, nonce })
  return b64(await identity.sign(new TextEncoder().encode(msg)))
}

/** Build a complete protocol 2 register message. */
async function registerMessage(identity, challenge, overrides = {}) {
  const pub = await rawPublicKey(identity)
  return {
    type: 'register',
    protocol: PROTOCOL_VERSION,
    podId: identity.podId,
    pubKey: b64(pub),
    nonce: challenge.nonce,
    signature: await signRegistration(identity, { nonce: challenge.nonce }),
    ...overrides,
  }
}

// ─── Tests ───────────────────────────────────────────────────────────

describe('auth.mjs', () => {
  it('derives the pod id exactly as PodIdentity does: base64url(SHA-256(raw public key))', async () => {
    const identity = await PodIdentity.generate()
    assert.equal(derivePodId(await rawPublicKey(identity)), identity.podId)
    const raw = new Uint8Array(32).fill(7)
    assert.equal(derivePodId(raw), createHash('sha256').update(raw).digest('base64url'))
    assert.equal(derivePodId(raw).length, 43)
  })

  it('registrationMessage is the documented, unambiguous byte string', () => {
    assert.equal(
      registrationMessage({ purpose: 'register', origin: 'wss://a.example', podId: 'POD', nonce: 'NONCE' }),
      'browsermesh-signaling/2\npurpose:register\norigin:wss://a.example\npodId:POD\nnonce:NONCE',
    )
  })

  it('registrationMessage refuses fields that could shift the boundaries', () => {
    for (const bad of ['a\nb', 'a\rb', '']) {
      assert.throws(() => registrationMessage({ purpose: 'register', origin: ORIGIN, podId: bad, nonce: 'n' }))
      assert.throws(() => registrationMessage({ purpose: 'register', origin: bad, podId: 'p', nonce: 'n' }))
    }
  })
})

describe('AUTH_MODE configuration', () => {
  it('refuses an unknown mode instead of silently running open', () => {
    assert.throws(() => createServer({ port: 0, authMode: 'authenticate' }), /AUTH_MODE/)
    assert.throws(() => createServer({ port: 0, env: { AUTH_MODE: 'strict' } }), /AUTH_MODE/)
  })

  it('authenticated mode needs the server\'s own origin (PUBLIC_ORIGIN)', () => {
    assert.throws(() => createServer({ port: 0, authMode: 'authenticated', env: {} }), /PUBLIC_ORIGIN/)
    assert.throws(() => createServer({ port: 0, authMode: 'authenticated', env: { PUBLIC_ORIGIN: 'not a url' } }), /PUBLIC_ORIGIN/)
    assert.throws(() => createServer({ port: 0, authMode: 'authenticated', env: { PUBLIC_ORIGIN: 'https://x.example' } }), /PUBLIC_ORIGIN/) // http(s) is not a ws origin
    createServer({ port: 0, authMode: 'authenticated', env: { PUBLIC_ORIGIN: ORIGIN } })
  })
})

describe('open mode stamps peers as unverified', () => {
  let instance
  afterEach(async () => { await instance?.close() })

  it('says so in registered, peers, peer-joined and every forwarded message', async () => {
    instance = createServer({ port: 0 })
    const port = await instance.listen(0)
    const a = await Client.connect(port)
    const b = await Client.connect(port)
    a.send({ type: 'register', podId: 'pod-a' })
    const reg = await a.type('registered')
    assert.equal(reg.mode, 'open')
    assert.equal(reg.verified, false)
    const peers = await a.type('peers')
    assert.equal(peers.verified, false)
    b.send({ type: 'register', podId: 'pod-b' })
    const joined = await a.type('peer-joined')
    assert.equal(joined.verified, false)

    // A client cannot claim to be verified, or someone else, in its payload.
    a.send({ type: 'offer', target: 'pod-b', sdp: 's', sourceVerified: true, source: 'pod-x', from: 'pod-x' })
    const offer = await b.type('offer')
    assert.equal(offer.source, 'pod-a')
    assert.equal(offer.sourceVerified, false)
    assert.equal(offer.from, 'pod-a')
    a.close(); b.close()
  })
})

describe('authenticated mode (protocol 2)', () => {
  let instance
  let port
  let nowMs = 1_000_000

  async function start(opts = {}) {
    instance = createServer({
      port: 0,
      authMode: 'authenticated',
      now: () => nowMs,
      env: { PUBLIC_ORIGIN: ORIGIN, ...(opts.env ?? {}) },
      ...opts.server,
    })
    port = await instance.listen(0)
  }
  afterEach(async () => { await instance?.close(); instance = null })

  async function connectAndChallenge() {
    const c = await Client.connect(port)
    const challenge = await c.type('challenge')
    return { c, challenge }
  }

  it('issues a fresh random single-purpose challenge to every connection, and none in open mode', async () => {
    await start()
    const one = await connectAndChallenge()
    const two = await connectAndChallenge()
    const ch = one.challenge
    assert.equal(ch.protocol, PROTOCOL_VERSION)
    assert.equal(ch.purpose, REGISTER_PURPOSE)
    assert.equal(ch.origin, ORIGIN)
    assert.ok(ch.ttlMs > 0 && ch.ttlMs <= 120_000)
    assert.match(ch.nonce, /^[A-Za-z0-9_-]{22,}$/) // >= 128 bits
    assert.notEqual(ch.nonce, two.challenge.nonce)
    one.c.close(); two.c.close()

    await instance.close()
    instance = createServer({ port: 0 })
    port = await instance.listen(0)
    const open = await Client.connect(port)
    open.send({ type: 'register', podId: 'p' })
    await open.type('registered')
    assert.ok(!open.messages.some(m => m.type === 'challenge'))
    open.close()
  })

  it('registers a client whose pod id is the hash of the key it proves', async () => {
    await start()
    const identity = await PodIdentity.generate()
    const { c, challenge } = await connectAndChallenge()
    c.send(await registerMessage(identity, challenge))
    const reg = await c.type('registered')
    assert.equal(reg.podId, identity.podId)
    assert.equal(reg.mode, 'authenticated')
    assert.equal(reg.verified, true)
    assert.deepEqual(instance.listPeers(), [identity.podId])
    c.close()
  })

  it('refuses a pod id that is not the hash of the proven key (any id the key holder likes)', async () => {
    await start()
    const attacker = await PodIdentity.generate()
    const victim = await PodIdentity.generate()
    const { c, challenge } = await connectAndChallenge()
    // Valid signature by the attacker's key over the victim's id.
    c.send(await registerMessage(attacker, challenge, {
      podId: victim.podId,
      signature: await signRegistration(attacker, { nonce: challenge.nonce, podId: victim.podId }),
    }))
    const err = await c.type('error')
    assert.equal(err.code, 'pod-id-mismatch')
    assert.equal(await c.closed, 4401)
    assert.deepEqual(instance.listPeers(), [])
  })

  it('compares the id exactly: no case change, padding, whitespace or prefix is accepted', async () => {
    await start()
    const identity = await PodIdentity.generate()
    const variants = [
      identity.podId.toUpperCase() === identity.podId ? identity.podId.toLowerCase() : identity.podId.toUpperCase(),
      identity.podId + ' ',
      ' ' + identity.podId,
      identity.podId + '=',
      identity.podId.slice(0, -1),
      identity.podId + '\u0000',
      'pod-' + identity.podId,
    ]
    for (const podId of variants) {
      const { c, challenge } = await connectAndChallenge()
      c.send(await registerMessage(identity, challenge, {
        podId,
        signature: await signRegistration(identity, { nonce: challenge.nonce, podId: podId.includes('\u0000') ? 'x' : podId }).catch(() => 'AAAA'),
      }))
      const err = await c.type('error')
      assert.match(err.code, /pod-id-mismatch|bad-pod-id/, JSON.stringify(podId))
      await c.closed
    }
    assert.deepEqual(instance.listPeers(), [])
  })

  it('refuses the old registration form: protocol missing, signature over the bare pod id', async () => {
    await start()
    const identity = await PodIdentity.generate()
    const { c } = await connectAndChallenge()
    const sig = b64(await identity.sign(new TextEncoder().encode(identity.podId)))
    c.send({ type: 'register', podId: identity.podId, pubKey: b64(await rawPublicKey(identity)), signature: sig })
    const err = await c.type('error')
    assert.equal(err.code, 'protocol-unsupported')
    assert.equal(err.required, PROTOCOL_VERSION)
    assert.match(err.message, /protocol 2/)
    assert.equal(await c.closed, 4426)
  })

  it('refuses a plain open-style registration (no key)', async () => {
    await start()
    const { c } = await connectAndChallenge()
    c.send({ type: 'register', podId: 'pod-a' })
    const err = await c.type('error')
    assert.equal(err.code, 'protocol-unsupported')
    await c.closed
    assert.deepEqual(instance.listPeers(), [])
  })

  it('a captured registration is useless on another connection (replay)', async () => {
    await start()
    const identity = await PodIdentity.generate()
    const first = await connectAndChallenge()
    const captured = await registerMessage(identity, first.challenge)
    first.c.send(captured)
    await first.c.type('registered')
    first.c.close()
    await first.c.closed

    const second = await connectAndChallenge()
    assert.notEqual(second.challenge.nonce, first.challenge.nonce)
    second.c.send(captured)
    const err = await second.c.type('error')
    assert.equal(err.code, 'bad-nonce')
    await second.c.closed
    assert.deepEqual(instance.listPeers(), [])
  })

  it('a nonce is single use: after one attempt the connection must start over', async () => {
    await start()
    const identity = await PodIdentity.generate()
    const { c, challenge } = await connectAndChallenge()
    c.send(await registerMessage(identity, challenge, { signature: b64(new Uint8Array(64)) })) // wrong signature burns it
    await c.type('error')
    c.send(await registerMessage(identity, challenge)) // correct, but the nonce is spent
    await c.closed
    assert.deepEqual(instance.listPeers(), [])
    assert.ok(!c.messages.some(m => m.type === 'registered'))
  })

  it('a nonce cannot be spent twice by two registrations sent back to back', async () => {
    await start()
    const identity = await PodIdentity.generate()
    const { c, challenge } = await connectAndChallenge()
    const bad = await registerMessage(identity, challenge, { signature: b64(new Uint8Array(64)) })
    const good = await registerMessage(identity, challenge)
    c.ws.send(JSON.stringify(bad))
    c.ws.send(JSON.stringify(good))
    await c.closed
    assert.ok(!c.messages.some(m => m.type === 'registered'))
    assert.deepEqual(instance.listPeers(), [])
  })

  it('a nonce expires', async () => {
    await start({ env: { AUTH_NONCE_TTL_MS: '5000' } })
    const identity = await PodIdentity.generate()
    const { c, challenge } = await connectAndChallenge()
    assert.equal(challenge.ttlMs, 5000)
    nowMs += 5001
    c.send(await registerMessage(identity, challenge))
    const err = await c.type('error')
    assert.equal(err.code, 'challenge-expired')
    await c.closed
    nowMs += 0
  })

  it('a nonce is still good just inside its lifetime', async () => {
    await start({ env: { AUTH_NONCE_TTL_MS: '5000' } })
    const identity = await PodIdentity.generate()
    const { c, challenge } = await connectAndChallenge()
    nowMs += 4999
    c.send(await registerMessage(identity, challenge))
    await c.type('registered')
    c.close()
  })

  it('the signature must cover the nonce, the pod id, the origin and the purpose', async () => {
    await start()
    const identity = await PodIdentity.generate()
    const other = await PodIdentity.generate()
    const cases = {
      'another nonce': (ch) => signRegistration(identity, { nonce: 'a'.repeat(22) }),
      'another origin': (ch) => signRegistration(identity, { nonce: ch.nonce, origin: 'wss://other.example' }),
      'another purpose': (ch) => signRegistration(identity, { nonce: ch.nonce, purpose: 'connect' }),
      'another pod id': (ch) => signRegistration(identity, { nonce: ch.nonce, podId: other.podId }),
      'the bare pod id': async () => b64(await identity.sign(new TextEncoder().encode(identity.podId))),
      'another key': (ch) => signRegistration(other, { nonce: ch.nonce, podId: identity.podId }),
    }
    for (const [name, sign] of Object.entries(cases)) {
      const { c, challenge } = await connectAndChallenge()
      c.send(await registerMessage(identity, challenge, { signature: await sign(challenge) }))
      const err = await c.type('error')
      assert.equal(err.code, 'bad-signature', name)
      await c.closed
    }
    assert.deepEqual(instance.listPeers(), [])
  })

  it('a client that echoes a different nonce is refused', async () => {
    await start()
    const identity = await PodIdentity.generate()
    const { c, challenge } = await connectAndChallenge()
    c.send(await registerMessage(identity, challenge, { nonce: 'b'.repeat(22) }))
    const err = await c.type('error')
    assert.equal(err.code, 'bad-nonce')
    await c.closed
  })

  it('malformed keys and signatures are refused cleanly', async () => {
    await start()
    const identity = await PodIdentity.generate()
    const bad = [
      { pubKey: 'not base64!!' },
      { pubKey: b64(new Uint8Array(31)) },
      { pubKey: b64(new Uint8Array(33)) },
      { pubKey: 12345 },
      { pubKey: null },
      { signature: 'AAAA' },
      { signature: b64(new Uint8Array(65)) },
      { signature: ['x'] },
      { podId: { toString: 'x' } },
      { podId: 'x'.repeat(5000) },
    ]
    for (const override of bad) {
      const { c, challenge } = await connectAndChallenge()
      c.send(await registerMessage(identity, challenge, override))
      const err = await c.type('error')
      assert.equal(err.type, 'error', JSON.stringify(override))
      await c.closed
    }
    // the server is still up and serving
    const { c, challenge } = await connectAndChallenge()
    c.send(await registerMessage(identity, challenge))
    await c.type('registered')
    c.close()
  })

  it('a message that is not a JSON object cannot crash or confuse the server', async () => {
    await start()
    for (const raw of ['null', '[]', '"str"', '123', 'true']) {
      const c = await Client.connect(port)
      c.send(raw)
      const err = await c.type('error')
      assert.ok(err)
      c.close()
    }
    const open = createServer({ port: 0 })
    const p = await open.listen(0)
    try {
      for (const raw of ['null', '[]', '"str"', '123', 'true']) {
        const c = await Client.connect(p)
        c.send(raw)
        await c.type('error')
        c.send({ type: 'register', podId: 'pod-a' })
        await c.type('registered')
        c.send(raw) // after registration too
        await c.type('error', { from: 2 })
        c.close()
        await c.closed
      }
    } finally {
      await open.close()
    }
  })

  it('stamps forwarded messages and the peer list as verified', async () => {
    await start()
    const ia = await PodIdentity.generate()
    const ib = await PodIdentity.generate()
    const a = await connectAndChallenge()
    a.c.send(await registerMessage(ia, a.challenge))
    await a.c.type('registered')
    const b = await connectAndChallenge()
    b.c.send(await registerMessage(ib, b.challenge))
    await b.c.type('registered')
    const joined = await a.c.type('peer-joined')
    assert.equal(joined.podId, ib.podId)
    assert.equal(joined.verified, true)

    a.c.send({ type: 'offer', target: ib.podId, sdp: 'x', sourceVerified: false })
    const offer = await b.c.type('offer')
    assert.equal(offer.source, ia.podId)
    assert.equal(offer.sourceVerified, true)
    a.c.close(); b.c.close()
  })

  /** Connect, answer the challenge as `identity`, and wait for `registered`. */
  async function registerPod(identity) {
    const { c, challenge } = await connectAndChallenge()
    c.send(await registerMessage(identity, challenge))
    await c.type('registered')
    return c
  }

  /** Everything the server has sent so far has been received once this resolves. */
  async function settle(...clients) {
    for (const c of clients) {
      const from = c.messages.length
      c.send({ type: 'ping' })
      await c.waitFor(m => m.type === 'pong', { from })
    }
  }

  it('with MAX_CONNECTIONS_PER_POD=1 the same key takes over from its stale connection, and is told why', async () => {
    await start({ env: { MAX_CONNECTIONS_PER_POD: '1' } })
    const identity = await PodIdentity.generate()
    const first = await registerPod(identity)
    const second = await registerPod(identity)
    assert.equal(await first.closed, 4409)
    assert.equal(first.closeReason, 'replaced')
    const why = first.messages.find(m => m.type === 'error')
    assert.equal(why.code, 'replaced')
    assert.equal(why.reconnect, false)
    assert.deepEqual(instance.listPeers(), [identity.podId])

    // The old connection closing must not unregister the new one.
    await settle(second)
    assert.deepEqual(instance.listPeers(), [identity.podId])
    second.close()
  })

  it('one pod may hold two connections to the same server: neither is closed, nothing flaps', async () => {
    await start()
    const identity = await PodIdentity.generate()
    const other = await PodIdentity.generate()
    const watcher = await registerPod(other)

    // Model a client that reconnects whenever it is closed: if anything is
    // closed it would show up as a close event here.
    const closes = []
    const first = await registerPod(identity)
    const second = await registerPod(identity)
    for (const c of [first, second]) c.closed.then(code => closes.push(code))
    await settle(first, second, watcher)

    assert.deepEqual(closes, [])
    assert.equal(first.messages.some(m => m.type === 'error'), false)
    assert.equal(second.messages.some(m => m.type === 'error'), false)
    assert.deepEqual(instance.listPeers().sort(), [identity.podId, other.podId].sort())
    assert.equal(instance.peerCount, 2)
    // The second connection of a known pod is not a new peer.
    assert.equal(watcher.messages.filter(m => m.type === 'peer-joined' && m.podId === identity.podId).length, 1)
    assert.equal(second.messages.find(m => m.type === 'registered').verified, true)
    first.close(); second.close(); watcher.close()
  })

  it('a message for the pod is delivered once, to its newest connection, and falls back when that one goes', async () => {
    await start()
    const identity = await PodIdentity.generate()
    const sender = await registerPod(await PodIdentity.generate())
    const first = await registerPod(identity)
    const second = await registerPod(identity)

    sender.send({ type: 'offer', target: identity.podId, sdp: 'one' })
    await settle(sender, first, second)
    assert.equal(second.messages.filter(m => m.type === 'offer').length, 1)
    assert.equal(first.messages.filter(m => m.type === 'offer').length, 0)

    // The newest connection leaves: the pod is still there, via the first.
    second.close()
    await second.closed
    // (The server may not have processed the close yet; an offer sent to the
    // closing connection is lost, so send again until one reaches the first.)
    for (let i = 0; i < 100 && !first.messages.some(m => m.type === 'offer'); i++) {
      sender.send({ type: 'offer', target: identity.podId, sdp: 'two' })
      await settle(sender, first)
    }
    const offer = first.messages.find(m => m.type === 'offer')
    assert.equal(offer.sdp, 'two')
    assert.equal(sender.messages.some(m => m.type === 'peer-left'), false)
    assert.deepEqual(instance.listPeers().includes(identity.podId), true)

    // Only when the last connection goes is the pod announced as gone.
    first.close()
    await first.closed
    await sender.waitFor(m => m.type === 'peer-left' && m.podId === identity.podId)
    assert.equal(instance.listPeers().includes(identity.podId), false)
    sender.close()
  })

  it('a connection beyond the limit replaces the oldest, which is told with a machine-readable reason', async () => {
    await start({ env: { MAX_CONNECTIONS_PER_POD: '2' } })
    const identity = await PodIdentity.generate()
    const watcher = await registerPod(await PodIdentity.generate())
    const first = await registerPod(identity)
    const second = await registerPod(identity)
    const third = await registerPod(identity)

    assert.equal(await first.closed, 4409)
    assert.equal(first.closeReason, 'replaced')
    const why = first.messages.find(m => m.type === 'error')
    assert.equal(why.code, 'replaced')
    assert.equal(why.reconnect, false)
    assert.match(why.message, /newer connection/)

    await settle(second, third, watcher)
    assert.equal(second.ws.readyState, 1)
    assert.equal(third.ws.readyState, 1)
    assert.equal(instance.listPeers().includes(identity.podId), true)
    // The evicted connection closing does not announce the pod as gone.
    assert.equal(watcher.messages.some(m => m.type === 'peer-left'), false)
    second.close(); third.close(); watcher.close()
  })

  it('per-address limits count every connection of a pod', async () => {
    await start({ server: { maxConnectionsPerIp: 2 } })
    const identity = await PodIdentity.generate()
    const first = await registerPod(identity)
    const second = await registerPod(identity)
    const third = await Client.connect(port)
    assert.equal(await third.closed, 4429)
    assert.ok(third.messages.some(m => m.type === 'error' && /too many connections/.test(m.message)))
    first.close(); second.close()
  })

  it('the message rate limit applies to each connection of a pod on its own', async () => {
    await start({ server: { maxMessagesPerMinute: 3 } })
    const identity = await PodIdentity.generate()
    const first = await registerPod(identity)
    const second = await registerPod(identity)
    for (const c of [first, second]) {
      for (let i = 0; i < 3; i++) await settle(c)
      const from = c.messages.length
      c.send({ type: 'ping' })
      const err = await c.waitFor(m => m.type === 'error', { from })
      assert.match(err.message, /rate limit/)
    }
    first.close(); second.close()
  })

  it('refuses a MAX_CONNECTIONS_PER_POD that is not a whole number from 1 to 16', () => {
    for (const v of ['0', '-1', '1.5', 'many', '17', '']) {
      assert.throws(
        () => createServer({ port: 0, authMode: 'authenticated', env: { PUBLIC_ORIGIN: ORIGIN, MAX_CONNECTIONS_PER_POD: v } }),
        /MAX_CONNECTIONS_PER_POD/,
        JSON.stringify(v),
      )
    }
    createServer({ port: 0, authMode: 'authenticated', env: { PUBLIC_ORIGIN: ORIGIN, MAX_CONNECTIONS_PER_POD: '16' } })
  })
})

describe('open mode: one connection per pod id, as before', () => {
  let instance
  afterEach(async () => { await instance?.close(); instance = null })

  it('refuses a second connection for a pod id and leaves the first alone; the limit setting changes nothing', async () => {
    for (const env of [{}, { MAX_CONNECTIONS_PER_POD: '8' }]) {
      instance = createServer({ port: 0, env })
      const port = await instance.listen(0)
      const first = await Client.connect(port)
      first.send({ type: 'register', podId: 'pod-a' })
      await first.type('registered')
      const second = await Client.connect(port)
      second.send({ type: 'register', podId: 'pod-a' })
      const err = await second.waitFor(m => m.type === 'error')
      assert.equal(err.message, 'podId already registered')
      assert.equal(err.code, undefined)
      assert.equal(await second.closed, 4409)
      assert.equal(second.closeReason, 'podId already registered')

      first.send({ type: 'ping' })
      await first.type('pong')
      assert.equal(first.ws.readyState, 1)
      assert.deepEqual(instance.listPeers(), ['pod-a'])
      first.close()
      await instance.close()
    }
  })
})

describe('peer discovery', () => {
  let instance
  afterEach(async () => { await instance?.close() })

  it('PEER_DISCOVERY=none sends no peer list, no joins and no leaves', async () => {
    instance = createServer({ port: 0, env: { PEER_DISCOVERY: 'none' } })
    const port = await instance.listen(0)
    const a = await Client.connect(port)
    const b = await Client.connect(port)
    a.send({ type: 'register', podId: 'pod-a' })
    await a.type('registered')
    b.send({ type: 'register', podId: 'pod-b' })
    await b.type('registered')
    a.send({ type: 'offer', target: 'pod-b', sdp: 'x' })
    await b.type('offer')
    b.close()
    await b.closed
    a.send({ type: 'ping' })
    await a.type('pong')
    assert.deepEqual(a.messages.map(m => m.type).filter(t => ['peers', 'peer-joined', 'peer-left'].includes(t)), [])
    assert.deepEqual(b.messages.map(m => m.type).filter(t => ['peers', 'peer-joined', 'peer-left'].includes(t)), [])
    a.close()
  })

  it('refuses an unknown PEER_DISCOVERY value', () => {
    assert.throws(() => createServer({ port: 0, env: { PEER_DISCOVERY: 'some' } }), /PEER_DISCOVERY/)
  })
})
