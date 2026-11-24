/**
 * Service dispatch and token checks of the server kernel, for both
 * PeerNodeServer and ServerPod.
 *
 * A remote caller names a service and a method as strings. Only methods that
 * were declared when the service was registered, on services that are
 * allowed to be called remotely, may be reached; nothing inherited from
 * Object.prototype (or from a handler's class) can be.
 */

import { describe, it, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PeerNodeServer, ServerIdentity } from './index.mjs'
import { ServerPod } from './server-pod.mjs'
import { ServiceRegistry, safeEqual } from './services.mjs'

const INHERITED = [
  'constructor', '__proto__', 'prototype', 'toString', 'toLocaleString', 'valueOf',
  'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable',
  '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__',
]

const dirs = []
function tmp() {
  const d = mkdtempSync(join(tmpdir(), 'svc-'))
  dirs.push(d)
  return d
}
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }) })

/** Builds the two kinds of kernel behind one interface. */
const kinds = {
  PeerNodeServer: async (opts = {}) => new PeerNodeServer({
    identity: await ServerIdentity.generate('t'),
    dataDir: tmp(),
    onLog: () => {},
    ...opts,
  }),
  ServerPod: async (opts = {}) => new ServerPod({ dataDir: tmp(), onLog: () => {}, ...opts }),
}

for (const [kind, make] of Object.entries(kinds)) {
  describe(`${kind}: service dispatch`, () => {
    it('does not reach anything inherited from Object.prototype, by any method name', async () => {
      const k = await make()
      for (const name of ['fs', 'agent']) {
        for (const method of INHERITED) {
          const r = await k.callService(name, method, { path: 'x' }, k.serviceToken)
          assert.equal(r.success, false, `${name}.${method}`)
          assert.match(r.error, /unknown service method/)
        }
      }
    })

    it('does not treat inherited names as services', async () => {
      const k = await make()
      for (const name of INHERITED) {
        const r = await k.callService(name, 'list', {}, k.serviceToken)
        assert.equal(r.success, false, name)
        assert.match(r.error, /unknown service method/)
      }
    })

    it('answers non-string service and method names without throwing', async () => {
      const k = await make()
      for (const bad of [undefined, null, 1, {}, [], ['fs'], { toString: () => 'fs' }]) {
        assert.equal((await k.callService(bad, 'list', {}, k.serviceToken)).success, false)
        assert.equal((await k.callService('fs', bad, {}, k.serviceToken)).success, false)
      }
    })

    it('only reaches methods declared at registration (own enumerable functions), not ones added later', async () => {
      const k = await make()
      const handler = { ping: () => 'pong' }
      k.registerService('custom', handler, { remote: true })
      handler.added = () => 'late'
      assert.equal(await k.callService('custom', 'ping', {}, k.serviceToken), 'pong')
      assert.match((await k.callService('custom', 'added', {}, k.serviceToken)).error, /unknown service method/)
    })

    it('does not reach methods a handler class inherits from its prototype unless they are declared', async () => {
      const k = await make()
      let called = 0
      class Svc {
        secret() { called++; return 'secret' }
        ping() { return 'pong' }
      }
      k.registerService('klass', new Svc(), { remote: true })
      assert.match((await k.callService('klass', 'secret', {}, k.serviceToken)).error, /unknown service method/)
      assert.equal(called, 0)

      k.registerService('klass2', new Svc(), { remote: true, methods: ['ping'] })
      assert.equal(await k.callService('klass2', 'ping', {}, k.serviceToken), 'pong')
      assert.match((await k.callService('klass2', 'secret', {}, k.serviceToken)).error, /unknown service method/)
      assert.equal(called, 0)
    })

    it('refuses to declare a method that does not exist or has a dangerous name', async () => {
      const k = await make()
      assert.throws(() => k.registerService('x', { a() {} }, { methods: ['nope'] }), /method/)
      assert.throws(() => k.registerService('x', { a() {} }, { methods: ['__proto__'] }), /method/)
      assert.throws(() => k.registerService('x', { a() {} }, { methods: ['constructor'] }), /method/)
      assert.throws(() => k.registerService('x', { ['__proto__']: 1, constructor() {} }, { methods: ['constructor'] }), /method/)
    })

    it('a service is remotely callable only if it is on the allow-list', async () => {
      const k = await make()
      let called = 0
      k.registerService('local-only', { run: () => { called++; return 'ran' } })
      assert.ok(k.listServices().includes('local-only'))
      assert.equal(k.getService('local-only').run(), 'ran') // trusted, in-process
      called = 0
      const r = await k.callService('local-only', 'run', {}, k.serviceToken)
      assert.equal(r.success, false)
      assert.match(r.error, /unknown service method/)
      assert.equal(called, 0)

      k.registerService('exposed', { run: () => 'ran' }, { remote: true })
      assert.equal(await k.callService('exposed', 'run', {}, k.serviceToken), 'ran')
      k.unregisterService('exposed')
      assert.match((await k.callService('exposed', 'run', {}, k.serviceToken)).error, /unknown service method/)
    })

    it('the built-in services are on the allow-list by default and can be taken off it', async () => {
      const k = await make()
      assert.deepEqual(await k.callService('fs', 'list', {}, k.serviceToken), [])
      const closed = await make({ remoteServices: [] })
      assert.match((await closed.callService('fs', 'list', {}, closed.serviceToken)).error, /unknown service method/)
      assert.ok(closed.getService('fs').list) // still there for local use
    })

    it('rejects arguments that are not an object before the handler runs', async () => {
      const k = await make()
      let called = 0
      k.registerService('x', { run: () => { called++ } }, { remote: true })
      for (const args of ['str', 5, true, null, ['a']]) {
        const r = await k.callService('x', 'run', args, k.serviceToken)
        assert.equal(r.success, false)
        assert.match(r.error, /args/)
      }
      assert.equal(called, 0)
      await k.callService('x', 'run', undefined, k.serviceToken)
      await k.callService('x', 'run', {}, k.serviceToken)
      assert.equal(called, 2)
    })

    it('a handler that throws rejects the call (unchanged behaviour)', async () => {
      const k = await make()
      k.registerService('boom', { run: () => { throw new Error('inner detail') } }, { remote: true })
      await assert.rejects(() => k.callService('boom', 'run', {}, k.serviceToken))
    })
  })

  describe(`${kind}: service token`, () => {
    it('accepts exactly the token', async () => {
      const k = await make({ serviceToken: 'a-token-of-some-length' })
      assert.deepEqual(await k.callService('fs', 'list', {}, 'a-token-of-some-length'), [])
    })

    it('refuses anything else, of any type or length, without throwing', async () => {
      const k = await make({ serviceToken: 'a-token-of-some-length' })
      for (const bad of [undefined, null, '', 'a', 'a-token-of-some-lengtH', 'a-token-of-some-length ', 'a-token-of-some-length-and-more', 'x'.repeat(100_000), 0, {}, [], ['a-token-of-some-length'], { toString: () => 'a-token-of-some-length' }]) {
        const r = await k.callService('fs', 'list', {}, bad)
        assert.deepEqual(r, { success: false, error: 'unauthorized' })
      }
    })

    it('answers a bad token the same whether or not the service exists', async () => {
      const k = await make()
      const a = await k.callService('fs', 'list', {}, 'nope')
      const b = await k.callService('nonexistent', 'x', {}, 'nope')
      assert.deepEqual(a, b)
    })
  })
}

describe('safeEqual', () => {
  it('is true only for equal strings', () => {
    assert.equal(safeEqual('abc', 'abc'), true)
    assert.equal(safeEqual('abc', 'abd'), false)
    assert.equal(safeEqual('abc', 'abcd'), false)
    assert.equal(safeEqual('', ''), true)
    for (const bad of [undefined, null, 1, {}, []]) {
      assert.equal(safeEqual(bad, 'x'), false)
      assert.equal(safeEqual('x', bad), false)
    }
  })
})

describe('ServiceRegistry', () => {
  it('keeps method tables on null-prototype objects and answers with own properties only', async () => {
    const r = new ServiceRegistry()
    r.register('a', { go: () => 1 }, { remote: true })
    assert.equal(await r.call('a', 'go', undefined), 1)
    assert.equal(Object.getPrototypeOf(r.methodsOf('a')), null)
    assert.deepEqual(Object.keys(r.methodsOf('a')), ['go'])
    assert.equal(r.methodsOf('missing'), undefined)
  })

  it('refuses service names that are empty, too long or not strings', () => {
    const r = new ServiceRegistry()
    for (const bad of ['', 'x'.repeat(65), 5, null, undefined, {}, 'a b', 'a/b', 'a\nb']) {
      assert.throws(() => r.register(bad, { m() {} }), /service name/)
    }
  })
})
