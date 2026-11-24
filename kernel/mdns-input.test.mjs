/**
 * What MdnsDiscovery does with records it receives from the local network:
 * validates them, bounds what it remembers, and never logs raw network text.
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { MdnsDiscovery } from './mdns.mjs'

const SERVICE = '_clawser._tcp.local'

class FakeMdns extends EventEmitter {
  respond() {}
  query() {}
  destroy() {}
}

async function setup(opts = {}) {
  const fake = new FakeMdns()
  const logs = []
  const mdns = new MdnsDiscovery({ podId: 'me', port: 9, onLog: (m) => logs.push(m), createMdns: () => fake, ...opts })
  await mdns.start()
  return { fake, logs, mdns }
}

function announce(podId, { port = 8787, target = 'host.local', txt, name } = {}) {
  const instance = name ?? `${podId}.${SERVICE}`
  return {
    answers: [
      { type: 'SRV', name: instance, data: { port, target } },
      { type: 'TXT', name: instance, data: txt ?? [`podId=${podId}`, 'label=lab'] },
    ],
  }
}

describe('MdnsDiscovery input handling', () => {
  it('discovers a well-formed peer', async () => {
    const { fake, mdns } = await setup()
    fake.emit('response', announce('pod-ok'))
    assert.deepEqual(mdns.listPeers().map(p => [p.podId, p.host, p.port, p.label]), [['pod-ok', 'host.local', 8787, 'lab']])
    await mdns.stop()
  })

  it('ignores peers whose id, port or host are not sane', async () => {
    const { fake, mdns } = await setup()
    fake.emit('response', announce('bad id with spaces'))
    fake.emit('response', announce('x'.repeat(129)))
    fake.emit('response', announce('pod-nl\nINJECTED'))
    fake.emit('response', announce('pod-esc\u001b[31m'))
    fake.emit('response', announce('pod-port0', { port: 0 }))
    fake.emit('response', announce('pod-port-big', { port: 70000 }))
    fake.emit('response', announce('pod-port-str', { port: '80' }))
    fake.emit('response', announce('pod-host-obj', { target: { evil: 1 } }))
    fake.emit('response', announce('pod-host-long', { target: 'h'.repeat(300) }))
    assert.equal(mdns.peerCount, 0)
    await mdns.stop()
  })

  it('does not let a TXT record set prototype properties or shadow fields', async () => {
    const { fake, mdns } = await setup()
    fake.emit('response', announce('pod-txt', { txt: ['__proto__=polluted', 'constructor=x', 'toString=y', 'podId=pod-txt', 'label=ok'] }))
    assert.equal(({}).polluted, undefined)
    assert.equal(({}).constructor, Object)
    assert.equal(mdns.peerCount, 1)
    assert.equal(mdns.listPeers()[0].label, 'ok')
    await mdns.stop()
  })

  it('a TXT podId that disagrees with the instance name is ignored in favour of the name', async () => {
    const { fake, mdns } = await setup()
    fake.emit('response', announce('pod-real', { txt: ['podId=pod-claimed', 'label=l'] }))
    assert.deepEqual(mdns.listPeers().map(p => p.podId), ['pod-real'])
    await mdns.stop()
  })

  it('bounds the number of peers it remembers', async () => {
    const { fake, mdns } = await setup({ maxPeers: 10 })
    for (let i = 0; i < 100; i++) fake.emit('response', announce(`pod-${i}`))
    assert.equal(mdns.peerCount, 10)
    await mdns.stop()
  })

  it('logs no raw network text: control characters never reach the log', async () => {
    const { fake, logs, mdns } = await setup()
    fake.emit('response', announce('pod-ok', { txt: ['podId=pod-ok', 'label=lab\nFORGED [mdns] line\u001b[31m'] }))
    fake.emit('response', announce('pod-nl\nFORGED'))
    await mdns.stop()
    for (const line of logs) assert.ok(!/[\u0000-\u001f\u007f]/.test(line), JSON.stringify(line))
    assert.ok(!logs.some(l => l.includes('FORGED')))
  })

  it('never throws on malformed records', async () => {
    const { fake, mdns } = await setup()
    for (const response of [{}, { answers: null }, { answers: [null] }, { answers: [{}] }, { answers: [{ type: 'SRV', name: 5 }] }, { answers: [{ type: 'SRV', name: `x.${SERVICE}`, data: null }] }]) {
      fake.emit('response', response)
    }
    assert.equal(mdns.peerCount, 0)
    await mdns.stop()
  })
})
