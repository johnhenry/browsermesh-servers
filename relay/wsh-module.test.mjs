/**
 * What the relay loads from @johnhenry/wsh, and why that is safe on the Node the Docker image runs.
 *
 * wsh declares `engines.node >=26`, the image runs Node 24. The only wsh code the relay ever loads is
 * `@johnhenry/wsh/pipe-relay` (and only when PIPE_RELAY=1). These tests fail if that stops being a
 * self-contained module (an import of another wsh file or a node: builtin would pull in code that was
 * written for Node 26), and they run on every Node in the CI matrix, so the claim is proved on 24 as well as 26.
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
    assert.deepEqual(relay.stats(), { waiting: 0, pipes: 0 })
    await relay.close()
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
