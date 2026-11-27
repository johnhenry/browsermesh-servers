/**
 * What the relay loads from @johnhenry/wsh.
 *
 * The only wsh code the relay ever loads is `@johnhenry/wsh/pipe-relay` (and only when PIPE_RELAY=1).
 * These tests fail if that stops being a self-contained module (an import of another wsh file or a
 * node: builtin would pull in code the relay has not been checked against).
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

describe('@johnhenry/wsh/pipe-relay as the relay loads it', () => {
  it('exports createPipeRelay and works on this Node', async () => {
    const mod = await import('@johnhenry/wsh/pipe-relay')
    assert.equal(typeof mod.createPipeRelay, 'function')
    const relay = mod.createPipeRelay({ onLog: () => {} })
    // 0.53.0 added `retired` to stats(); the relay does not enable retirePaired, so it stays 0.
    const { waiting, pipes } = relay.stats()
    assert.deepEqual({ waiting, pipes }, { waiting: 0, pipes: 0 })
    await relay.close()
  })

  // wsh 0.60 added the feature `relay-gateway` and the option `relay: { carryGateway }` to the FULL wsh
  // relay (`@johnhenry/wsh/server`). This service runs the pipe relay, which parses nothing, so neither
  // exists here: nothing in this service can start carrying gateway messages by a version bump.
  it('has no gateway option or feature: it is the byte-copying pipe relay, not the full wsh relay', async () => {
    const url = import.meta.resolve('@johnhenry/wsh/pipe-relay')
    const source = await readFile(fileURLToPath(url), 'utf-8')
    assert.ok(!/carryGateway|relay-gateway|ServerHello|features/.test(source), 'pipe relay mentions the gateway feature')

    // An option that only the full relay has is ignored: the pipe relay behaves the same with it.
    const { createPipeRelay } = await import('@johnhenry/wsh/pipe-relay')
    const relay = createPipeRelay({ onLog: () => {}, relay: { carryGateway: true }, carryGateway: true })
    const { waiting, pipes } = relay.stats()
    assert.deepEqual({ waiting, pipes }, { waiting: 0, pipes: 0 })
    await relay.close()
  })

  it('this service loads nothing of wsh but the pipe relay (not the server, the relay or the client)', async () => {
    const dir = fileURLToPath(new URL('.', import.meta.url))
    for (const file of ['index.mjs', 'pipe.mjs', 'limits.mjs']) {
      const source = await readFile(dir + file, 'utf-8')
      const specifiers = [...source.matchAll(/['"`](@johnhenry\/wsh[^'"`]*)['"`]/g)].map(m => m[1])
      for (const s of specifiers) assert.equal(s, '@johnhenry/wsh/pipe-relay', `${file} loads ${s}`)
    }
  })

  it('is one file with no static imports, no require and no node: builtins', async () => {
    const url = import.meta.resolve('@johnhenry/wsh/pipe-relay')
    const source = await readFile(fileURLToPath(url), 'utf-8')
    const code = source
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '')
    assert.ok(!/^\s*import\s/m.test(code), 'static import found')
    assert.ok(!/^\s*export\s[^=]*\sfrom\s/m.test(code), 're-export found')
    assert.ok(!/\brequire\s*\(/.test(code), 'require found')
    assert.ok(!/['"`]node:/.test(code), 'node: builtin found')
    // The one dynamic import is the optional listen() half, loaded only when listen() is called.
    const dynamic = [...code.matchAll(/\bimport\s*\(([^)]*)\)/g)].map(m => m[1].trim())
    assert.deepEqual(dynamic, ['NODE_LISTENER'])
  })
})
