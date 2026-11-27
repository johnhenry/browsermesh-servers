/**
 * The wsh pipe-relay route: WebSocket `<base>/r/<rendezvous id>` (`?role=host`
 * for the waiting side), backed by `createPipeRelay()` from
 * `@johnhenry/wsh/pipe-relay`. Off unless enabled. It copies opaque binary
 * frames between two sockets that name the same id, and vouches for nothing.
 */

import { describe, it, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import WebSocket from 'ws'
import { createRelayServer } from './index.mjs'

const ORIGIN = 'https://app.example'
const newId = () => randomBytes(16).toString('base64url')

/**
 * Open a socket and wait for the outcome: { ws }, { status } when the upgrade was refused, or { error }
 * when the connection failed before any response. (ws marks a socket CLOSING before it emits that
 * 'error', so the error must settle the promise whatever the readyState: a failed connect must fail the
 * test that made it, not leave it waiting for an event that never comes.)
 */
function open(port, id, { role, origin = ORIGIN, path = '/r', headers = {} } = {}) {
  const url = `ws://127.0.0.1:${port}${path}/${id}${role ? `?role=${role}` : ''}`
  const ws = new WebSocket(url, { headers: { ...(origin ? { Origin: origin } : {}), ...headers } })
  const frames = []
  const closed = new Promise((resolve) => ws.on('close', (code, reason) => resolve({ code, reason: reason.toString() })))
  ws.on('message', (data, isBinary) => frames.push({ data, isBinary }))
  ws.on('error', () => {})
  return new Promise((resolve) => {
    ws.once('open', () => resolve({ ws, frames, closed }))
    ws.once('unexpected-response', (_req, res) => { res.resume(); resolve({ status: res.statusCode, closed }) })
    ws.once('error', (err) => resolve({ error: err, closed }))
  })
}

function nextFrame(side, n = 1) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('no frame')), 10_000)
    const check = () => {
      if (side.frames.length >= n) { clearTimeout(timer); resolve(side.frames[n - 1]) } else setTimeout(check, 5)
    }
    check()
  })
}

describe('pipe relay route', () => {
  let instance
  afterEach(async () => { await instance?.close(); instance = null })

  async function start({ env = {}, ...opts } = {}) {
    instance = createRelayServer({
      port: 0,
      onLog: () => {},
      env: { PIPE_RELAY: '1', PIPE_ORIGINS: ORIGIN, ...env },
      ...opts,
    })
    return instance.listen(0, '127.0.0.1')
  }

  // ── off by default, configuration ──────────────────────────────

  it('is off unless enabled: the route answers 404 and the JSON relay still works', async () => {
    instance = createRelayServer({ port: 0, onLog: () => {}, env: {} })
    const port = await instance.listen(0, '127.0.0.1')
    const r = await open(port, newId(), { role: 'host' })
    assert.equal(r.status, 404)
    assert.equal(instance.pipe, null)
  })

  it('refuses to start enabled without an origin policy', () => {
    assert.throws(() => createRelayServer({ port: 0, env: { PIPE_RELAY: '1' } }), /PIPE_ORIGINS/)
    // explicit opt-outs are possible
    createRelayServer({ port: 0, env: { PIPE_RELAY: '1', PIPE_ALLOW_ANY_ORIGIN: '1' } })
    createRelayServer({ port: 0, env: { PIPE_RELAY: '1' }, origins: ORIGIN })
  })

  it('rejects nonsense bounds', () => {
    for (const k of ['PIPE_MAX_WAITING', 'PIPE_MAX_BYTES', 'PIPE_IDLE_TIMEOUT_MS']) {
      assert.throws(() => createRelayServer({ port: 0, env: { PIPE_RELAY: '1', PIPE_ORIGINS: ORIGIN, [k]: '-5' } }), new RegExp(k))
      assert.throws(() => createRelayServer({ port: 0, env: { PIPE_RELAY: '1', PIPE_ORIGINS: ORIGIN, [k]: 'abc' } }), new RegExp(k))
    }
  })

  // ── pairing and copying ────────────────────────────────────────

  it('pairs a host and an operator by id and copies binary frames both ways, untouched', async () => {
    const port = await start()
    const id = newId()
    const host = await open(port, id, { role: 'host' })
    const op = await open(port, id)
    assert.ok(host.ws && op.ws)

    const a = Buffer.from([0, 1, 2, 3, 255, 254])
    const b = randomBytes(5000)
    host.ws.send(a)
    op.ws.send(b)
    const gotByOp = await nextFrame(op)
    const gotByHost = await nextFrame(host)
    assert.equal(gotByOp.isBinary, true)
    assert.deepEqual(Buffer.from(gotByOp.data), a)
    assert.deepEqual(Buffer.from(gotByHost.data), b)
    host.ws.close(); op.ws.close()
  })

  it('has no gateway of its own (wsh 0.60 relay-gateway): it states no features, and what an operator sends a host is bytes it copies, never a request it carries out or answers', async () => {
    const port = await start()
    const id = newId()
    const host = await open(port, id, { role: 'host' })
    const op = await open(port, id)
    assert.ok(host.ws && op.ws)

    // Bytes shaped like a gateway open to a host's network: the route copies them to the host and
    // sends the operator nothing of its own (no hello, no features, no answer, no refusal).
    const open1 = Buffer.from(JSON.stringify({ type: 'OpenTcp', host: '127.0.0.1', port: 1 }))
    op.ws.send(open1)
    const got = await nextFrame(host)
    assert.deepEqual(Buffer.from(got.data), open1)
    await new Promise((r) => setTimeout(r, 100))
    assert.equal(op.frames.length, 0)
    assert.equal(host.frames.length, 1)
    host.ws.close(); op.ws.close()
  })

  it('holds what the first side sends until its partner arrives (bounded), then delivers it in order', async () => {
    const port = await start()
    const id = newId()
    const host = await open(port, id, { role: 'host' })
    host.ws.send(Buffer.from('one'))
    host.ws.send(Buffer.from('two'))
    const op = await open(port, id)
    assert.equal(Buffer.from((await nextFrame(op, 1)).data).toString(), 'one')
    assert.equal(Buffer.from((await nextFrame(op, 2)).data).toString(), 'two')
    host.ws.close(); op.ws.close()
  })

  it('ends the other half when one half closes', async () => {
    const port = await start()
    const id = newId()
    const host = await open(port, id, { role: 'host' })
    const op = await open(port, id)
    host.ws.send(Buffer.from('x'))
    await nextFrame(op)
    host.ws.close(1000, 'bye')
    assert.equal((await op.closed).code, 1000)
  })

  it('closes a connection that sends a text frame (binary only)', async () => {
    const port = await start()
    const id = newId()
    const host = await open(port, id, { role: 'host' })
    const op = await open(port, id)
    op.ws.send('this is text')
    assert.equal((await op.closed).code, 1003)
    assert.equal((await host.closed).code, 1003)
  })

  // ── a third party ──────────────────────────────────────────────

  it('a third connection to an established pair\'s id is not paired with it and sees none of its traffic', async () => {
    const port = await start()
    const id = newId()
    const host = await open(port, id, { role: 'host' })
    const op = await open(port, id)
    host.ws.send(Buffer.from('first'))
    await nextFrame(op)

    const intruderOp = await open(port, id)           // same role as the dialler
    const intruderHost = await open(port, id, { role: 'host' })  // same role as the host: pairs with intruderOp, not with the pair
    assert.ok(intruderOp.ws && intruderHost.ws)

    host.ws.send(Buffer.from('secret-from-host'))
    op.ws.send(Buffer.from('secret-from-op'))
    await nextFrame(op, 2)
    await nextFrame(host)

    // The intruders were paired with each other at most; neither saw the pair's frames.
    for (const side of [intruderOp, intruderHost]) {
      for (const f of side.frames) {
        assert.ok(!Buffer.from(f.data).toString().includes('secret'))
      }
    }
    // and nothing they send reaches the pair
    const before = { op: op.frames.length, host: host.frames.length }
    intruderOp.ws.send(Buffer.from('injected'))
    intruderHost.ws.send(Buffer.from('injected-too'))
    await nextFrame(intruderHost)  // the intruders reach each other
    await nextFrame(intruderOp)
    assert.equal(op.frames.length, before.op)
    assert.equal(host.frames.length, before.host)
    for (const s of [host, op, intruderOp, intruderHost]) s.ws.close()
  })

  it('a second waiting half with the same role is refused while the first waits', async () => {
    const port = await start()
    const id = newId()
    const first = await open(port, id, { role: 'host' })
    const second = await open(port, id, { role: 'host' })
    assert.equal((await second.closed).code, 1008)
    // the first is still waiting and still pairs
    const op = await open(port, id)
    first.ws.send(Buffer.from('ok'))
    assert.equal(Buffer.from((await nextFrame(op)).data).toString(), 'ok')
    first.ws.close(); op.ws.close()
  })

  // ── bounds ─────────────────────────────────────────────────────

  it('bounds: a message above maxMessageBytes ends the pipe', async () => {
    const port = await start({ env: { PIPE_MAX_MESSAGE_BYTES: '1024' } })
    const id = newId()
    const host = await open(port, id, { role: 'host' })
    const op = await open(port, id)
    op.ws.send(Buffer.alloc(2048))
    assert.equal((await op.closed).code, 1009)
    await host.closed // the other half is ended too
  })

  it('bounds: total bytes per pipe (maxBytes)', async () => {
    const port = await start({ env: { PIPE_MAX_BYTES: '3000' } })
    const id = newId()
    const host = await open(port, id, { role: 'host' })
    const op = await open(port, id)
    for (let i = 0; i < 4; i++) op.ws.send(Buffer.alloc(1000))
    assert.equal((await host.closed).code, 1008)
  })

  it('bounds: how much a half may send before its partner arrives (earlyBytes)', async () => {
    const port = await start({ env: { PIPE_EARLY_BYTES: '100' } })
    const host = await open(port, newId(), { role: 'host' })
    host.ws.send(Buffer.alloc(500))
    assert.equal((await host.closed).code, 1009)
  })

  it('bounds: halves waiting for a partner (maxWaiting)', async () => {
    const port = await start({ env: { PIPE_MAX_WAITING: '2' } })
    const a = await open(port, newId(), { role: 'host' })
    const b = await open(port, newId(), { role: 'host' })
    const c = await open(port, newId(), { role: 'host' })
    assert.equal((await c.closed).code, 1013)
    // a waiting slot frees when its half goes away
    a.ws.close()
    await a.closed
    const d = await open(port, newId(), { role: 'host' })
    d.ws.send(Buffer.from('x'))
    b.ws.close(); d.ws.close()
  })

  it('bounds: a half waits at most rendezvousTimeoutMs', async () => {
    const port = await start({ env: { PIPE_RENDEZVOUS_TIMEOUT_MS: '100' } })
    const host = await open(port, newId(), { role: 'host' })
    assert.equal((await host.closed).code, 1000)
  })

  it('bounds: a pipe with no traffic closes after idleTimeoutMs', async () => {
    const port = await start({ env: { PIPE_IDLE_TIMEOUT_MS: '1000' } })
    const id = newId()
    const host = await open(port, id, { role: 'host' })
    const op = await open(port, id)
    await host.closed
    await op.closed
  })

  it('bounds: a pipe closes after maxLifetimeMs even if busy', async () => {
    const port = await start({ env: { PIPE_MAX_LIFETIME_MS: '200' } })
    const id = newId()
    const host = await open(port, id, { role: 'host' })
    const op = await open(port, id)
    const timer = setInterval(() => { try { op.ws.send(Buffer.from('x')) } catch { /* closed */ } }, 20)
    await host.closed
    clearInterval(timer)
    await op.closed
  })

  // ── admission ──────────────────────────────────────────────────

  it('refuses a foreign Origin, and a missing one, before the upgrade', async () => {
    const port = await start()
    assert.equal((await open(port, newId(), { role: 'host', origin: 'https://evil.example' })).status, 403)
    assert.equal((await open(port, newId(), { role: 'host', origin: null })).status, 403)
    assert.equal((await open(port, newId(), { role: 'host', origin: `${ORIGIN}.evil.example` })).status, 403)
  })

  it('PIPE_ALLOW_NO_ORIGIN admits clients that send no Origin (non-browser)', async () => {
    const port = await start({ env: { PIPE_ALLOW_NO_ORIGIN: '1' } })
    const r = await open(port, newId(), { role: 'host', origin: null })
    assert.ok(r.ws)
    r.ws.close()
  })

  it('PIPE_ALLOW_ANY_ORIGIN opens it to any origin', async () => {
    const port = await start({ env: { PIPE_ORIGINS: '', PIPE_ALLOW_ANY_ORIGIN: '1' } })
    const r = await open(port, newId(), { role: 'host', origin: 'https://anything.example' })
    assert.ok(r.ws)
    r.ws.close()
  })

  it('refuses malformed ids, other paths and unknown roles', async () => {
    const port = await start()
    assert.equal((await open(port, 'short')).status, 404)
    assert.equal((await open(port, 'a'.repeat(129))).status, 404)
    assert.equal((await open(port, 'bad id with spaces ----')).status, 404)
    assert.equal((await open(port, newId(), { role: 'admin' })).status, 400)
  })

  it('serves under a base path when PIPE_BASE_PATH is set', async () => {
    const port = await start({ env: { PIPE_BASE_PATH: '/mesh' } })
    const id = newId()
    const host = await open(port, id, { role: 'host', path: '/mesh/r' })
    const op = await open(port, id, { path: '/mesh/r' })
    host.ws.send(Buffer.from('hi'))
    assert.equal(Buffer.from((await nextFrame(op)).data).toString(), 'hi')
    assert.equal((await open(port, newId(), { role: 'host', path: '/r' })).status, 404)
    host.ws.close(); op.ws.close()
  })

  it('the authorize hook runs with { id, role, remote } and can refuse; a throwing hook refuses', async () => {
    const seen = []
    let verdict = true
    const port = await start({
      pipe: { authorize: (who) => { seen.push(who); if (verdict === 'throw') throw new Error('boom'); return verdict } },
    })
    const id = newId()
    const ok = await open(port, id, { role: 'host' })
    assert.ok(ok.ws)
    assert.equal(seen.length, 1)
    assert.equal(seen[0].id, id)
    assert.equal(seen[0].role, 'host')
    assert.equal(seen[0].remote.origin, ORIGIN)
    assert.ok(seen[0].remote.address)
    ok.ws.close()

    verdict = false
    const refused = await open(port, newId(), { role: 'host' })
    assert.equal((await refused.closed).code, 1008)
    verdict = 'throw'
    const threw = await open(port, newId(), { role: 'host' })
    assert.equal((await threw.closed).code, 1008)
    verdict = 'yes' // anything but true refuses
    const truthy = await open(port, newId(), { role: 'host' })
    assert.equal((await truthy.closed).code, 1008)
  })

  it('rate limits connections per address', async () => {
    const port = await start({ env: { PIPE_CONNECTS_PER_MINUTE_PER_IP: '3' } })
    const results = []
    for (let i = 0; i < 5; i++) {
      const r = await open(port, newId(), { role: 'host' })
      results.push(r.status ?? 'open')
      r.ws?.close()
    }
    assert.deepEqual(results, ['open', 'open', 'open', 429, 429])
  })

  it('rate limits connections per rendezvous id', async () => {
    const port = await start({ env: { PIPE_CONNECTS_PER_MINUTE_PER_ID: '2' } })
    const id = newId()
    const a = await open(port, id, { role: 'host' })
    const b = await open(port, id)         // pairs
    const c = await open(port, id, { role: 'host' })  // third attempt on this id
    assert.equal((await c.closed).code, 1008)
    a.ws.close(); b.ws.close()
  })

  it('limits concurrent pipe connections per address', async () => {
    const port = await start({ env: { PIPE_MAX_CONNECTIONS_PER_IP: '2' } })
    const a = await open(port, newId(), { role: 'host' })
    const b = await open(port, newId(), { role: 'host' })
    const c = await open(port, newId(), { role: 'host' })
    assert.equal(c.status, 429)
    a.ws.close()
    await a.closed
    // the slot is released once the socket has closed on the server too
    const serverClosed = new Promise((resolve) => setImmediate(resolve))
    await serverClosed
    b.ws.close()
  })

  // ── opacity ────────────────────────────────────────────────────

  it('never logs ids or payload bytes', async () => {
    const lines = []
    const orig = { log: console.log, warn: console.warn, error: console.error, info: console.info }
    for (const k of Object.keys(orig)) console[k] = (...a) => lines.push(a.map(String).join(' '))
    const id = newId()
    try {
      const port = await start({ onLog: (m) => lines.push(m), env: { PIPE_MAX_MESSAGE_BYTES: '4096' } })
      const host = await open(port, id, { role: 'host' })
      const op = await open(port, id)
      host.ws.send(Buffer.from('PAYLOAD-MARKER-123'))
      await nextFrame(op)
      op.ws.send(Buffer.alloc(9000)) // ends the pipe, which the relay would log
      await host.closed
    } finally {
      Object.assign(console, orig)
    }
    const out = lines.join('\n')
    assert.ok(!out.includes('PAYLOAD-MARKER'))
    assert.ok(!out.includes(id))
    assert.ok(!out.includes(id.slice(0, 6)))
  })

  it('does not interfere with the JSON relay on the same port', async () => {
    const port = await start()
    const ws = new WebSocket(`ws://127.0.0.1:${port}`, { headers: { Origin: ORIGIN } })
    const msgs = []
    ws.on('message', (d) => msgs.push(JSON.parse(d.toString())))
    await new Promise((r) => ws.once('open', r))
    ws.send(JSON.stringify({ type: 'register', podId: 'pod-a' }))
    await new Promise((resolve) => { const t = setInterval(() => { if (msgs.length) { clearInterval(t); resolve() } }, 5) })
    assert.equal(msgs[0].type, 'registered')
    ws.close()
  })
})
