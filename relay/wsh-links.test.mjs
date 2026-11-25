/**
 * Two real `@johnhenry/browsermesh-transport` wsh peer links (WshPeerLinks)
 * pair through this server's pipe-relay route, in one process, and exchange
 * messages. Needs the Node that @johnhenry/wsh supports (26+); skipped on
 * older Nodes.
 */

import { describe, it, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import WebSocket from 'ws'
import { PodIdentity } from '@johnhenry/browsermesh-primitives'
import { createRelayServer } from './index.mjs'

const ORIGIN = 'https://app.example'
const supported = Number(process.versions.node.split('.')[0]) >= 26

/** ws with an Origin header (as a browser sends), recording every byte a client sends. */
function recordingWebSocket(wire) {
  return class extends WebSocket {
    constructor(url, protocols) {
      super(url, protocols, { origin: ORIGIN })
    }

    send(data, ...rest) {
      wire.push(Buffer.from(typeof data === 'string' ? Buffer.from(data) : data))
      return super.send(data, ...rest)
    }
  }
}

function once(links, event, pred = () => true) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout waiting for ${event}`)), 30_000)
    links.on(event, (payload) => {
      if (pred(payload)) { clearTimeout(timer); resolve(payload) }
    })
  })
}

describe('wsh peer links through the pipe-relay route', { skip: supported ? false : 'needs Node 26+ (@johnhenry/wsh)' }, () => {
  let instance
  const toClose = []
  afterEach(async () => {
    for (const l of toClose.splice(0)) await l.close().catch(() => {})
    await instance?.close()
    instance = null
  })

  it('two pods link through the relay, exchange sealed messages, and a stranger is refused without disturbing them', async () => {
    const { WshPeerLinks } = await import('@johnhenry/browsermesh-transport')
    instance = createRelayServer({
      port: 0,
      onLog: () => {},
      env: { PIPE_RELAY: '1', PIPE_ORIGINS: ORIGIN },
    })
    const port = await instance.listen(0, '127.0.0.1')

    const [a, b, c] = await Promise.all([PodIdentity.generate(), PodIdentity.generate(), PodIdentity.generate()])
    const wire = []
    const WS = recordingWebSocket(wire)
    const relays = [`ws://127.0.0.1:${port}/`]
    const mk = (identity, allowed) => {
      const links = new WshPeerLinks({
        identity,
        relays,
        WebSocket: WS,
        authorize: ({ podId }) => allowed.includes(podId),
        reconnect: { maxAttempts: 0 },
      })
      toClose.push(links)
      return links
    }
    const linkA = mk(a, [b.podId])
    const linkB = mk(b, [a.podId])      // B does not allow C
    const linkC = mk(c, [b.podId])

    await linkB.listen()
    const upA = once(linkA, 'peer-up', (p) => p.podId === b.podId)
    const upB = once(linkB, 'peer-up', (p) => p.podId === a.podId)
    await linkA.connect(b.podId)
    await Promise.all([upA, upB])

    const marker = 'HELLO-SEALED-MARKER'
    const gotByB = once(linkB, 'message')
    await linkA.send(b.podId, { text: marker })
    const m = await gotByB
    assert.equal(m.from, a.podId) // the sender is the authenticated key, not a field in the message
    assert.ok(String(typeof m.data === 'string' ? m.data : Buffer.from(m.data).toString()).includes(marker))

    const gotByA = once(linkA, 'message')
    await linkB.send(a.podId, { text: 'and back' })
    assert.equal((await gotByA).from, b.podId)

    // A stranger dials B's rendezvous id: it is paired with a fresh waiting half of B, which refuses it.
    const refusedAtB = once(linkB, 'refused')
    await assert.rejects(() => linkC.connect(b.podId, { keep: false }))
    assert.ok(await refusedAtB)

    // The established pair is untouched.
    const again = once(linkB, 'message')
    await linkA.send(b.podId, { text: 'still here' })
    assert.equal((await again).from, a.podId)

    // The relay only ever saw ciphertext: the marker is on no frame a client sent.
    assert.ok(wire.length > 0)
    assert.ok(!wire.some(buf => buf.includes(marker)))
    assert.ok(!wire.some(buf => buf.includes(a.podId) && buf.includes('text')))
  })
})
