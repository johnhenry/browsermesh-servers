/**
 * Tests for mDNS/DNS-SD discovery.
 *
 * Tests that two MdnsDiscovery instances on the same machine
 * can discover each other via multicast DNS.
 */

import { describe, it, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { MdnsDiscovery } from './mdns.mjs'

// ─── Construction ────────────────────────────────────────────────────

describe('MdnsDiscovery construction', () => {
  it('throws without podId', () => {
    assert.throws(() => new MdnsDiscovery({ port: 8787 }), /podId/)
  })

  it('throws without port', () => {
    assert.throws(() => new MdnsDiscovery({ podId: 'pod-a' }), /port/)
  })

  it('constructs with required params', () => {
    const mdns = new MdnsDiscovery({ podId: 'pod-a', port: 8787 })
    assert.equal(mdns.podId, 'pod-a')
    assert.equal(mdns.running, false)
    assert.equal(mdns.peerCount, 0)
  })
})

// ─── Lifecycle ───────────────────────────────────────────────────────

describe('MdnsDiscovery lifecycle', () => {
  let instances = []

  afterEach(async () => {
    for (const inst of instances) {
      await inst.stop()
    }
    instances = []
  })

  it('start and stop', async () => {
    const mdns = new MdnsDiscovery({ podId: 'pod-a', port: 8787, onLog: () => {} })
    instances.push(mdns)

    await mdns.start()
    assert.equal(mdns.running, true)

    await mdns.stop()
    assert.equal(mdns.running, false)
  })

  it('start is idempotent', async () => {
    const mdns = new MdnsDiscovery({ podId: 'pod-a', port: 8787, onLog: () => {} })
    instances.push(mdns)

    await mdns.start()
    await mdns.start()
    assert.equal(mdns.running, true)
  })

  it('stop is idempotent', async () => {
    const mdns = new MdnsDiscovery({ podId: 'pod-a', port: 8787, onLog: () => {} })
    instances.push(mdns)

    await mdns.stop()
    assert.equal(mdns.running, false)
  })
})

// ─── Discovery ───────────────────────────────────────────────────────

describe('MdnsDiscovery peer discovery', () => {
  let instances = []

  afterEach(async () => {
    for (const inst of instances) {
      await inst.stop()
    }
    instances = []
  })

  it('two pods discover each other on the same machine', async () => {
    const logs = []
    const discoveredByA = []
    const discoveredByB = []

    const a = new MdnsDiscovery({
      podId: 'pod-alpha',
      port: 9001,
      label: 'alpha',
      onLog: (msg) => logs.push('A: ' + msg),
    })
    const b = new MdnsDiscovery({
      podId: 'pod-beta',
      port: 9002,
      label: 'beta',
      onLog: (msg) => logs.push('B: ' + msg),
    })
    instances.push(a, b)

    a.onPeerDiscovered((peer) => discoveredByA.push(peer))
    b.onPeerDiscovered((peer) => discoveredByB.push(peer))

    await a.start()
    await b.start()

    // Wait for mDNS exchanges (multicast is async)
    await new Promise(r => setTimeout(r, 3000))

    // A should have discovered B
    assert.ok(
      discoveredByA.some(p => p.podId === 'pod-beta'),
      `A should discover B. Found: ${JSON.stringify(discoveredByA)}`
    )

    // B should have discovered A
    assert.ok(
      discoveredByB.some(p => p.podId === 'pod-alpha'),
      `B should discover A. Found: ${JSON.stringify(discoveredByB)}`
    )

    // Verify peer details
    const betaAsSeen = discoveredByA.find(p => p.podId === 'pod-beta')
    assert.equal(betaAsSeen.port, 9002)
    assert.equal(betaAsSeen.label, 'beta')

    const alphaAsSeen = discoveredByB.find(p => p.podId === 'pod-alpha')
    assert.equal(alphaAsSeen.port, 9001)
    assert.equal(alphaAsSeen.label, 'alpha')
  })

  it('does not discover self', async () => {
    const discovered = []
    const mdns = new MdnsDiscovery({
      podId: 'pod-solo',
      port: 9003,
      onLog: () => {},
    })
    instances.push(mdns)

    mdns.onPeerDiscovered((peer) => discovered.push(peer))
    await mdns.start()

    await new Promise(r => setTimeout(r, 2000))

    const selfDiscovery = discovered.filter(p => p.podId === 'pod-solo')
    assert.equal(selfDiscovery.length, 0, 'Should not discover self')
  })

  it('listPeers returns discovered peers', async () => {
    const a = new MdnsDiscovery({ podId: 'pod-x', port: 9004, onLog: () => {} })
    const b = new MdnsDiscovery({ podId: 'pod-y', port: 9005, onLog: () => {} })
    instances.push(a, b)

    await a.start()
    await b.start()

    await new Promise(r => setTimeout(r, 3000))

    const peersA = a.listPeers()
    assert.ok(peersA.length >= 1)
    assert.ok(peersA.some(p => p.podId === 'pod-y'))
  })
})
