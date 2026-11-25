/**
 * Limits of the signaling server: connections per address, messages before
 * registration, every message counted, idle connections, slow receivers.
 */

import { describe, it, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import WebSocket from 'ws'
import { createServer } from './index.mjs'

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

  static async connect(port) {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`)
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

describe('signaling limits', () => {
  let instance
  afterEach(async () => { await instance?.close(); instance = null })

  async function start(opts = {}) {
    instance = createServer({ port: 0, ...opts })
    return instance.listen(0, '127.0.0.1')
  }

  it('limits concurrent connections per client address and frees the slot on close', async () => {
    const port = await start({ maxConnectionsPerIp: 2 })
    const a = await Client.connect(port)
    const b = await Client.connect(port)
    const c = await Client.connect(port)
    const err = await c.waitFor(m => m.type === 'error')
    assert.match(err.message, /too many connections/)
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

  it('connection attempts are counted per address even when each connection closes again', async () => {
    const port = await start({ maxConnectsPerMinutePerIp: 3 })
    const seen = []
    for (let i = 0; i < 4; i++) {
      const c = await Client.connect(port)
      c.send({ type: 'register', podId: `pod-${i}` })
      const m = await c.waitFor(x => x.type === 'registered' || x.type === 'error')
      seen.push(m.type)
      c.ws.close()
      await c.closed
    }
    assert.deepEqual(seen, ['registered', 'registered', 'registered', 'error'])
  })

  it('closes a registered connection that stays silent when IDLE_TIMEOUT_MS is set', async () => {
    const port = await start({ idleTimeoutMs: 100 })
    const serverSideClosed = new Promise(resolve => instance.wss.once('connection', ws => ws.once('close', resolve)))
    const c = await Client.connect(port)
    c.send({ type: 'register', podId: 'pod-a' })
    await c.waitFor(m => m.type === 'registered')
    assert.equal(await c.closed, 4408)
    await serverSideClosed
    assert.deepEqual(instance.listPeers(), [])
  })

  it('does not close an idle connection by default', async () => {
    const port = await start()
    const c = await Client.connect(port)
    c.send({ type: 'register', podId: 'pod-a' })
    await c.waitFor(m => m.type === 'registered')
    c.send({ type: 'ping' })
    await c.waitFor(m => m.type === 'pong')
    assert.deepEqual(instance.listPeers(), ['pod-a'])
    c.ws.close()
  })

  it('drops a receiver that cannot keep up instead of buffering for it without bound', async () => {
    const port = await start({ maxBufferedBytes: 64 * 1024, maxMessagesPerMinute: 1_000_000 })
    const tx = await Client.connect(port)
    const rx = await Client.connect(port)
    tx.send({ type: 'register', podId: 'tx' })
    rx.send({ type: 'register', podId: 'rx' })
    await tx.waitFor(m => m.type === 'registered')
    await rx.waitFor(m => m.type === 'registered')
    rx.ws._socket.pause() // rx stops reading from its socket

    const blob = 'x'.repeat(48 * 1024)
    let sent = 0
    const pump = () => {
      // Keep sending until the server reports the receiver gone.
      while (sent < 3000 && tx.ws.bufferedAmount < 256 * 1024) {
        tx.send({ type: 'offer', target: 'rx', sdp: blob })
        sent++
      }
      if (sent < 3000 && !tx.messages.some(m => m.type === 'error')) setImmediate(pump)
    }
    pump()
    const err = await tx.waitFor(m => m.type === 'error')
    assert.match(err.message, /not accepting messages|not found/)
    await tx.waitFor(m => m.type === 'error' && /not found/.test(m.message)).catch(() => {})
    assert.ok(!instance.listPeers().includes('rx'))
    assert.ok(sent < 3000, 'the server should have given up on the receiver long before all messages were queued')
    tx.ws.close(); rx.ws.terminate()
  })
})

describe('signaling does not log what clients send', () => {
  it('writes nothing to the console for client-controlled strings', async () => {
    const lines = []
    const orig = { log: console.log, warn: console.warn, error: console.error, info: console.info }
    for (const k of Object.keys(orig)) console[k] = (...a) => lines.push(a.map(String).join(' '))
    const instance = createServer({ port: 0 })
    try {
      const port = await instance.listen(0, '127.0.0.1')
      const c = await Client.connect(port)
      const marker = 'CLIENT-CONTROLLED-MARKER'
      c.send({ type: 'register', podId: marker })
      await c.waitFor(m => m.type === 'registered')
      c.send({ type: marker })
      c.send({ type: 'offer', target: marker })
      c.send(`{"broken ${marker}`)
      await c.waitFor(m => m.type === 'error' && /invalid JSON/.test(m.message))
      c.ws.close()
      await c.closed
    } finally {
      Object.assign(console, orig)
      await instance.close()
    }
    assert.ok(!lines.join('\n').includes('CLIENT-CONTROLLED-MARKER'))
  })
})
