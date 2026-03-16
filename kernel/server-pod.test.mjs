import { describe, it, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { mkdtempSync } from 'node:fs'
import { join } from 'node:path'
import { ServerPod } from './server-pod.mjs'
import { EventEmitterTransport } from 'browsermesh-pod'

describe('ServerPod', () => {
  let pod

  afterEach(async () => {
    if (pod && pod.state !== 'shutdown' && pod.state !== 'idle') {
      await pod.stop()
    }
  })

  it('starts and stops cleanly', async () => {
    const logs = []
    pod = new ServerPod({ onLog: (m) => logs.push(m), dataDir: mkdtempSync(join(tmpdir(), 'sp-')) })
    await pod.start()

    assert.equal(pod.state, 'ready')
    assert.ok(pod.podId)
    assert.ok(logs.some(l => l.includes('started')))

    await pod.stop()
    assert.equal(pod.state, 'shutdown')
    assert.ok(logs.some(l => l.includes('stopped')))
  })

  it('uses PodIdentity with Ed25519', async () => {
    pod = new ServerPod({ onLog: () => {}, dataDir: mkdtempSync(join(tmpdir(), 'sp-')) })
    await pod.start()

    // PodIdentity generates base64url podIds (not pod-XXXX hex)
    assert.ok(pod.podId)
    assert.ok(pod.identity)
    assert.equal(typeof pod.identity.podId, 'string')
  })

  it('accepts a pre-existing PodIdentity', async () => {
    const { PodIdentity } = await import('browsermesh-primitives')
    const identity = await PodIdentity.generate()

    pod = new ServerPod({ onLog: () => {}, dataDir: mkdtempSync(join(tmpdir(), 'sp-')) })
    await pod.start({ identity })

    assert.equal(pod.podId, identity.podId)
  })

  it('registers fs and agent services', async () => {
    pod = new ServerPod({ onLog: () => {}, dataDir: mkdtempSync(join(tmpdir(), 'sp-')) })
    await pod.start()

    const services = pod.listServices()
    assert.ok(services.includes('fs'))
    assert.ok(services.includes('agent'))
  })

  it('fs service reads and writes files', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'sp-'))
    pod = new ServerPod({ onLog: () => {}, dataDir })
    await pod.start()

    const writeResult = await pod.callService('fs', 'write', { path: 'test.txt', data: 'hello' }, pod.serviceToken)
    assert.ok(writeResult.success)

    const readResult = await pod.callService('fs', 'read', { path: 'test.txt' }, pod.serviceToken)
    assert.equal(readResult.data, 'hello')
  })

  it('agent service runs in echo mode', async () => {
    pod = new ServerPod({ onLog: () => {}, dataDir: mkdtempSync(join(tmpdir(), 'sp-')) })
    await pod.start()

    const result = await pod.callService('agent', 'run', { message: 'test' }, pod.serviceToken)
    assert.ok(result.response.includes('test'))
  })

  it('rejects service calls with wrong token', async () => {
    pod = new ServerPod({ onLog: () => {}, dataDir: mkdtempSync(join(tmpdir(), 'sp-')) })
    await pod.start()

    const result = await pod.callService('fs', 'list', {}, 'wrong-token')
    assert.equal(result.success, false)
    assert.equal(result.error, 'unauthorized')
  })

  it('can register and unregister custom services', async () => {
    pod = new ServerPod({ onLog: () => {}, dataDir: mkdtempSync(join(tmpdir(), 'sp-')) })
    await pod.start()

    pod.registerService('custom', { ping: () => ({ pong: true }) })
    assert.ok(pod.listServices().includes('custom'))

    const result = await pod.callService('custom', 'ping', {}, pod.serviceToken)
    assert.deepEqual(result, { pong: true })

    pod.unregisterService('custom')
    assert.ok(!pod.listServices().includes('custom'))
  })

  it('toJSON includes Pod fields and server extras', async () => {
    pod = new ServerPod({ onLog: () => {}, dataDir: mkdtempSync(join(tmpdir(), 'sp-')) })
    await pod.start()

    const json = pod.toJSON()
    assert.equal(json.podId, pod.podId)
    assert.equal(json.state, 'ready')
    assert.ok(json.label)
    assert.ok(Array.isArray(json.services))
    assert.ok(json.services.includes('fs'))
  })

  it('two ServerPods discover each other via shared transport bus', async () => {
    const bus = EventEmitterTransport.createBus()
    const t1 = new EventEmitterTransport(bus)
    const t2 = new EventEmitterTransport(bus)

    const dir1 = mkdtempSync(join(tmpdir(), 'sp1-'))
    const dir2 = mkdtempSync(join(tmpdir(), 'sp2-'))

    const pod1 = new ServerPod({ onLog: () => {}, dataDir: dir1 })
    const pod2 = new ServerPod({ onLog: () => {}, dataDir: dir2 })

    // Use TransportDiscovery so they can find each other
    const { TransportDiscovery } = await import('browsermesh-pod')
    const { PodIdentity } = await import('browsermesh-primitives')

    const id1 = await PodIdentity.generate()
    const id2 = await PodIdentity.generate()

    await pod1.start({
      identity: id1,
      transport: t1,
      discovery: new TransportDiscovery({
        transport: t1,
        localPodId: id1.podId,
        localKind: 'server',
        timeout: 200,
      }),
      discoveryTimeout: 200,
    })

    await pod2.start({
      identity: id2,
      transport: t2,
      discovery: new TransportDiscovery({
        transport: t2,
        localPodId: id2.podId,
        localKind: 'server',
        timeout: 200,
      }),
      discoveryTimeout: 200,
    })

    // pod2 should have discovered pod1 (pod1 was already running when pod2 announced)
    assert.ok(pod2.peers.has(id1.podId), 'pod2 should see pod1')

    await pod1.stop()
    await pod2.stop()
    pod = null // skip afterEach cleanup
  })
})
