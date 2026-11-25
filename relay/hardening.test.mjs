/**
 * Limits and input handling of the relay server: origins, connections per
 * address, messages before registration, every message counted, idle
 * connections, slow receivers, malformed messages, nothing client-sent logged.
 */

import { describe, it, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import WebSocket from 'ws'
import { createRelayServer } from './index.mjs'

class Client {
  constructor(ws) {
    this.ws = ws
    this.messages = []
    this.waiters = []
    this.closed = new Promise((resolve) => ws.on('close', (code) => { this.closeCode = code; resolve(code) }))
    ws.on('message', (raw) => {
      this.messages.push(JSON.parse(raw.toString()))
      for (const w of [...this.waiters]) w()
    })
  }

  static async connect(port, headers = {}) {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`, { headers })
    const c = new Client(ws)
    await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject) })
    return c
  }

  send(o) { this.ws.send(typeof o === 'string' ? o : JSON.stringify(o)) }

  waitFor(pred) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no match in ${JSON.stringify(this.messages.slice(-5))}`)), 20_000)
      const check = () => {
        const m = this.messages.find(pred)
        if (m) { clearTimeout(timer); this.waiters = this.waiters.filter(w => w !== check); resolve(m) }
      }
      this.waiters.push(check)
      check()
    })
  }
}

function rawGet(port, path, headers = {}, method = 'GET') {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf-8') }))
    })
    req.on('error', reject)
    req.end()
  })
}

describe('relay limits and input handling', () => {
  let instance
  afterEach(async () => { await instance?.close(); instance = null })

  async function start(opts = {}) {
    instance = createRelayServer({ port: 0, onLog: () => {}, ...opts })
    return instance.listen(0, '127.0.0.1')
  }

  it('answers a message that is not a JSON object with an error, before and after registering', async () => {
    const port = await start()
    for (const raw of ['null', '[]', '"str"', '123', 'true']) {
      const c = await Client.connect(port)
      c.send(raw)
      await c.waitFor(m => m.type === 'error')
      c.send({ type: 'register', podId: 'pod-a' })
      await c.waitFor(m => m.type === 'registered')
      c.send(raw)
      await c.waitFor(m => m.type === 'error' && m.message === 'messages must be JSON objects' && c.messages.length >= 3)
      c.ws.close()
      await c.closed
    }
    // still serving
    const ok = await Client.connect(port)
    ok.send({ type: 'register', podId: 'pod-ok' })
    await ok.waitFor(m => m.type === 'registered')
    ok.ws.close()
  })

  it('applies an origin allow-list to WebSocket upgrades when ORIGINS is set', async () => {
    const port = await start({ env: { ORIGINS: 'https://app.example' } })
    const good = await Client.connect(port, { Origin: 'https://app.example' })
    good.send({ type: 'register', podId: 'pod-a' })
    await good.waitFor(m => m.type === 'registered')

    for (const headers of [{ Origin: 'https://evil.example' }, {}]) {
      const bad = await Client.connect(port, headers)
      const err = await bad.waitFor(m => m.type === 'error')
      assert.match(err.message, /origin/)
      assert.equal(await bad.closed, 4403)
    }
    good.ws.close()
  })

  it('allows any origin when ORIGINS is not set (unchanged default)', async () => {
    const port = await start()
    const c = await Client.connect(port, { Origin: 'https://anywhere.example' })
    c.send({ type: 'register', podId: 'pod-a' })
    await c.waitFor(m => m.type === 'registered')
    c.ws.close()
  })

  it('never answers HTTP with a wildcard origin; reflects only a listed origin', async () => {
    const port = await start({ env: { ORIGINS: 'https://app.example' } })
    for (const path of ['/health', '/stats', '/nope']) {
      const none = await rawGet(port, path)
      assert.equal(none.headers['access-control-allow-origin'], undefined, path)
      const other = await rawGet(port, path, { Origin: 'https://evil.example' })
      assert.equal(other.headers['access-control-allow-origin'], undefined, path)
      const ok = await rawGet(port, path, { Origin: 'https://app.example' })
      assert.equal(ok.headers['access-control-allow-origin'], 'https://app.example', path)
      assert.match(ok.headers.vary, /Origin/)
    }
    const pre = await rawGet(port, '/stats', { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'GET' }, 'OPTIONS')
    assert.equal(pre.status, 204)
    assert.equal(pre.headers['access-control-allow-origin'], undefined)
  })

  it('limits concurrent connections per client address and frees the slot on close', async () => {
    const port = await start({ maxConnectionsPerIp: 2 })
    const a = await Client.connect(port)
    const b = await Client.connect(port)
    const c = await Client.connect(port)
    await c.waitFor(m => m.type === 'error')
    assert.equal(await c.closed, 4429)
    a.ws.close()
    await a.closed
    const d = await Client.connect(port)
    d.send({ type: 'register', podId: 'pod-d' })
    await d.waitFor(m => m.type === 'registered')
    b.ws.close(); d.ws.close()
  })

  it('limits new connections per client address per minute', async () => {
    const port = await start({ maxConnectsPerMinutePerIp: 2 })
    const a = await Client.connect(port)
    const b = await Client.connect(port)
    const c = await Client.connect(port)
    await c.waitFor(m => m.type === 'error')
    assert.equal(await c.closed, 4429)
    a.ws.close(); b.ws.close()
  })

  it('closes a connection that sends too many messages before registering', async () => {
    const port = await start()
    const c = await Client.connect(port)
    for (let i = 0; i < 20; i++) c.send({ type: 'hello' })
    assert.equal(await c.closed, 4429)
  })

  it('counts every message against the rate limit, pings included', async () => {
    const port = await start({ maxMessagesPerMinute: 3 })
    const c = await Client.connect(port)
    c.send({ type: 'register', podId: 'pod-a' })
    await c.waitFor(m => m.type === 'registered')
    for (let i = 0; i < 5; i++) c.send({ type: 'ping' })
    await c.waitFor(m => m.type === 'error' && /rate limit/.test(m.message))
    assert.equal(c.messages.filter(m => m.type === 'pong').length, 3)
    c.ws.close()
  })

  it('closes a registered connection that stays silent when IDLE_TIMEOUT_MS is set', async () => {
    const port = await start({ idleTimeoutMs: 100 })
    const serverSideClosed = new Promise(resolve => instance.wss.once('connection', ws => ws.once('close', resolve)))
    const c = await Client.connect(port)
    c.send({ type: 'register', podId: 'pod-a' })
    await c.waitFor(m => m.type === 'registered')
    assert.equal(await c.closed, 4408)
    await serverSideClosed
    assert.equal(instance.relay.size, 0)
  })

  it('stamps relayed envelopes as coming from an unverified id', async () => {
    const port = await start()
    const a = await Client.connect(port)
    const b = await Client.connect(port)
    a.send({ type: 'register', podId: 'pod-a' })
    b.send({ type: 'register', podId: 'pod-b' })
    await a.waitFor(m => m.type === 'registered')
    await b.waitFor(m => m.type === 'registered')
    a.send({ type: 'relay', target: 'pod-b', envelope: { n: 1 }, source: 'pod-x', sourceVerified: true })
    const got = await b.waitFor(m => m.type === 'relayed')
    assert.equal(got.source, 'pod-a')
    assert.equal(got.sourceVerified, false)
    assert.deepEqual(got.envelope, { n: 1 })
    a.ws.close(); b.ws.close()
  })

  it('drops a receiver that cannot keep up instead of buffering for it without bound', async () => {
    const port = await start({ maxBufferedBytes: 64 * 1024, maxMessagesPerMinute: 1_000_000 })
    const tx = await Client.connect(port)
    const rx = await Client.connect(port)
    tx.send({ type: 'register', podId: 'tx' })
    rx.send({ type: 'register', podId: 'rx' })
    await tx.waitFor(m => m.type === 'registered')
    await rx.waitFor(m => m.type === 'registered')
    rx.ws._socket.pause()

    const blob = 'x'.repeat(48 * 1024)
    let sent = 0
    const pump = () => {
      while (sent < 3000 && tx.ws.bufferedAmount < 256 * 1024) {
        tx.send({ type: 'relay', target: 'rx', envelope: { blob } })
        sent++
      }
      if (sent < 3000 && !tx.messages.some(m => m.type === 'error')) setImmediate(pump)
    }
    pump()
    const err = await tx.waitFor(m => m.type === 'error')
    assert.match(err.message, /not accepting messages|not found/)
    assert.ok(sent < 3000, 'the server should give up on the receiver long before everything is queued')
    tx.ws.close(); rx.ws.terminate()
  })

  it('logs nothing that a client sent', async () => {
    const lines = []
    const orig = { log: console.log, warn: console.warn, error: console.error, info: console.info }
    for (const k of Object.keys(orig)) console[k] = (...a) => lines.push(a.map(String).join(' '))
    try {
      const port = await start({ onLog: (m) => lines.push(m) })
      const c = await Client.connect(port)
      const marker = 'CLIENT-CONTROLLED-MARKER'
      c.send({ type: 'register', podId: marker })
      await c.waitFor(m => m.type === 'registered')
      c.send({ type: marker })
      c.send({ type: 'relay', target: marker, envelope: {} })
      c.send(`{"broken ${marker}`)
      await c.waitFor(m => m.type === 'error' && /invalid JSON/.test(m.message))
      c.ws.close()
      await c.closed
      await instance.close(); instance = null
    } finally {
      Object.assign(console, orig)
    }
    assert.ok(!lines.join('\n').includes('CLIENT-CONTROLLED-MARKER'))
  })
})
