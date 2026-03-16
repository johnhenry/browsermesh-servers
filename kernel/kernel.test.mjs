/**
 * Tests for the Clawser server-side kernel.
 *
 * Uses real file system operations in a temp directory.
 */

import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  ServerIdentity,
  ServerFileSystem,
  ServerAgent,
  PeerNodeServer,
  createServerKernel,
} from './index.mjs'

// ─── ServerIdentity ──────────────────────────────────────────────────

describe('ServerIdentity', () => {
  it('generates a unique identity', async () => {
    const id = await ServerIdentity.generate('test-node')
    assert.ok(id.podId.startsWith('pod-'))
    assert.equal(id.podId.length, 4 + 32) // 'pod-' + 32 hex chars
    assert.equal(id.label, 'test-node')
    assert.equal(typeof id.created, 'number')
  })

  it('generates different podIds each time', async () => {
    const a = await ServerIdentity.generate()
    const b = await ServerIdentity.generate()
    assert.notEqual(a.podId, b.podId)
  })

  it('serializes and deserializes via JSON', async () => {
    const original = await ServerIdentity.generate('json-test')
    const json = original.toJSON()
    const restored = ServerIdentity.fromJSON(json)

    assert.equal(restored.podId, original.podId)
    assert.equal(restored.label, original.label)
    assert.equal(restored.created, original.created)
  })

  it('constructs with explicit values', () => {
    const id = new ServerIdentity({ podId: 'pod-abc', label: 'custom', created: 1000 })
    assert.equal(id.podId, 'pod-abc')
    assert.equal(id.label, 'custom')
    assert.equal(id.created, 1000)
  })
})

// ─── ServerFileSystem ────────────────────────────────────────────────

describe('ServerFileSystem', () => {
  let tmpDir
  let fs

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'clawser-kernel-test-'))
    fs = new ServerFileSystem(tmpDir)
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('creates root directory if it does not exist', () => {
    const newDir = join(tmpDir, 'subdir', 'nested')
    const fs2 = new ServerFileSystem(newDir)
    assert.equal(fs2.rootDir, newDir)
  })

  it('writes and reads a file', async () => {
    const writeResult = await fs.write('hello.txt', 'world')
    assert.equal(writeResult.success, true)
    assert.equal(typeof writeResult.size, 'number')

    const readResult = await fs.read('hello.txt')
    assert.equal(readResult.data, 'world')
    assert.equal(typeof readResult.size, 'number')
  })

  it('lists directory entries', async () => {
    await fs.write('a.txt', 'aaa')
    await fs.write('b.txt', 'bbb')

    const entries = await fs.list('.')
    const names = entries.map(e => e.name).sort()
    assert.ok(names.includes('a.txt'))
    assert.ok(names.includes('b.txt'))
  })

  it('returns empty list for non-existent directory', async () => {
    const entries = await fs.list('no-such-dir')
    assert.deepEqual(entries, [])
  })

  it('gets file stats', async () => {
    await fs.write('stat-test.txt', 'data')
    const stat = await fs.stat('stat-test.txt')
    assert.ok(stat)
    assert.equal(stat.name, 'stat-test.txt')
    assert.equal(stat.type, 'file')
    assert.equal(typeof stat.size, 'number')
    assert.equal(typeof stat.modified, 'number')
  })

  it('returns null stat for non-existent file', async () => {
    const stat = await fs.stat('no-such-file.txt')
    assert.equal(stat, null)
  })

  it('deletes a file', async () => {
    await fs.write('delete-me.txt', 'bye')
    const result = await fs.delete('delete-me.txt')
    assert.equal(result.success, true)

    const stat = await fs.stat('delete-me.txt')
    assert.equal(stat, null)
  })

  it('returns false when deleting non-existent file', async () => {
    const result = await fs.delete('no-file.txt')
    assert.equal(result.success, false)
  })

  it('creates nested directories on write', async () => {
    await fs.write('deep/nested/file.txt', 'deep')
    const result = await fs.read('deep/nested/file.txt')
    assert.equal(result.data, 'deep')
  })

  it('throws on read of non-existent file', async () => {
    await assert.rejects(
      () => fs.read('missing.txt'),
      (err) => err.message.includes('not found')
    )
  })

  it('prevents path traversal', async () => {
    await assert.rejects(
      () => fs.read('../../etc/passwd'),
      (err) => err.message.includes('traversal')
    )
  })
})

// ─── ServerAgent ─────────────────────────────────────────────────────

describe('ServerAgent', () => {
  it('has a name and system prompt', () => {
    const agent = new ServerAgent({ name: 'test-agent' })
    assert.equal(agent.name, 'test-agent')
    assert.ok(agent.systemPrompt.includes('test-agent'))
  })

  it('run returns an echo response', async () => {
    const agent = new ServerAgent({ name: 'echo' })
    const result = await agent.run('hello')
    assert.ok(result.response.includes('hello'))
    assert.ok(result.usage)
  })

  it('executeTool echo returns text', async () => {
    const agent = new ServerAgent({ name: 'tools' })
    const result = await agent.executeTool('echo', { text: 'hi' })
    assert.equal(result.success, true)
    assert.equal(result.output, 'hi')
  })

  it('executeTool time returns ISO string', async () => {
    const agent = new ServerAgent({ name: 'tools' })
    const result = await agent.executeTool('time', {})
    assert.equal(result.success, true)
    assert.ok(result.output.match(/^\d{4}-\d{2}-\d{2}T/))
  })

  it('executeTool info returns agent info', async () => {
    const agent = new ServerAgent({ name: 'info-agent' })
    const result = await agent.executeTool('info', {})
    assert.equal(result.success, true)
    const info = JSON.parse(result.output)
    assert.equal(info.agent, 'info-agent')
    assert.ok(Array.isArray(info.tools))
  })

  it('executeTool returns error for unknown tool', async () => {
    const agent = new ServerAgent({ name: 'tools' })
    const result = await agent.executeTool('nope', {})
    assert.equal(result.success, false)
    assert.ok(result.output.includes('unknown'))
  })

  it('searchMemories returns empty by default', () => {
    const agent = new ServerAgent({ name: 'mem' })
    const results = agent.searchMemories('anything')
    assert.deepEqual(results, [])
  })

  it('searchMemories finds added memories', () => {
    const agent = new ServerAgent({ name: 'mem' })
    agent.addMemory({ key: 'fact', content: 'The sky is blue' })
    agent.addMemory({ key: 'fact2', content: 'Water is wet' })

    const results = agent.searchMemories('sky')
    assert.equal(results.length, 1)
    assert.ok(results[0].content.includes('sky'))
  })
})

// ─── ServerAgent LLM provider ───────────────────────────────────────

describe('ServerAgent LLM provider', () => {
  it('falls back to echo when no provider configured', async () => {
    const agent = new ServerAgent({ name: 'echo-test' })
    assert.equal(agent.provider, null)
    const result = await agent.run('hello')
    assert.ok(result.response.includes('hello'))
    assert.equal(result.usage.input_tokens, 0)
    // History should be empty in echo mode
    assert.deepEqual(agent.history, [])
  })

  it('falls back to echo when provider set but no apiKey', async () => {
    const agent = new ServerAgent({ name: 'no-key', provider: 'openai' })
    assert.equal(agent.provider, 'openai')
    const result = await agent.run('test')
    assert.ok(result.response.includes('test'))
    assert.deepEqual(agent.history, [])
  })

  it('accepts provider config and tracks history', async () => {
    // We can't call a real API in tests, but we can verify the agent
    // accepts the config and tracks history when provider+key are set.
    // We stub fetch to simulate a response.
    const originalFetch = globalThis.fetch
    globalThis.fetch = async (url, opts) => {
      const body = JSON.parse(opts.body)
      // Verify the request shape
      assert.ok(body.messages.length >= 2) // system + user (via history)
      assert.equal(body.model, 'gpt-4o-mini')
      assert.equal(body.max_tokens, 1024)
      assert.ok(opts.headers['Authorization'].startsWith('Bearer '))
      return {
        ok: true,
        json: async () => ({
          choices: [{ message: { content: 'LLM says hi' } }],
          usage: { prompt_tokens: 10, completion_tokens: 5 },
        }),
      }
    }

    try {
      const agent = new ServerAgent({
        name: 'llm-test',
        provider: 'openai',
        apiKey: 'test-key-123',
      })
      const result = await agent.run('hello from test')
      assert.equal(result.response, 'LLM says hi')
      assert.equal(result.usage.input_tokens, 10)
      assert.equal(result.usage.output_tokens, 5)

      // History should contain user + assistant
      const history = agent.history
      assert.equal(history.length, 2)
      assert.equal(history[0].role, 'user')
      assert.equal(history[0].content, 'hello from test')
      assert.equal(history[1].role, 'assistant')
      assert.equal(history[1].content, 'LLM says hi')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('supports anthropic provider', async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = async (url, opts) => {
      assert.ok(url.includes('anthropic'))
      assert.equal(opts.headers['x-api-key'], 'ant-key')
      assert.equal(opts.headers['anthropic-version'], '2023-06-01')
      const body = JSON.parse(opts.body)
      assert.equal(body.model, 'claude-sonnet-4-20250514')
      assert.ok(body.system)
      return {
        ok: true,
        json: async () => ({
          content: [{ text: 'Claude responds' }],
          usage: { input_tokens: 8, output_tokens: 3 },
        }),
      }
    }

    try {
      const agent = new ServerAgent({
        name: 'anthropic-test',
        provider: 'anthropic',
        apiKey: 'ant-key',
      })
      const result = await agent.run('hi claude')
      assert.equal(result.response, 'Claude responds')
      assert.equal(result.usage.input_tokens, 8)
      assert.equal(result.usage.output_tokens, 3)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('uses custom model when specified', async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = async (_url, opts) => {
      const body = JSON.parse(opts.body)
      assert.equal(body.model, 'gpt-4o')
      return {
        ok: true,
        json: async () => ({
          choices: [{ message: { content: 'ok' } }],
          usage: { prompt_tokens: 1, completion_tokens: 1 },
        }),
      }
    }

    try {
      const agent = new ServerAgent({
        name: 'model-test',
        provider: 'openai',
        apiKey: 'key',
        model: 'gpt-4o',
      })
      await agent.run('test')
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})

// ─── PeerNodeServer ──────────────────────────────────────────────────

describe('PeerNodeServer', () => {
  let tmpDir

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'clawser-peer-test-'))
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('starts and stops', async () => {
    const identity = await ServerIdentity.generate('test')
    const peer = new PeerNodeServer({
      identity,
      dataDir: tmpDir,
      onLog: () => {},
    })

    assert.equal(peer.state, 'stopped')
    await peer.start()
    assert.equal(peer.state, 'running')
    await peer.stop()
    assert.equal(peer.state, 'stopped')
  })

  it('exposes identity properties', async () => {
    const identity = await ServerIdentity.generate('props-test')
    const peer = new PeerNodeServer({
      identity,
      dataDir: tmpDir,
      onLog: () => {},
    })

    assert.equal(peer.podId, identity.podId)
    assert.equal(peer.identity, identity)
  })

  it('has built-in fs and agent services', async () => {
    const identity = await ServerIdentity.generate('svc-test')
    const peer = new PeerNodeServer({
      identity,
      dataDir: tmpDir,
      onLog: () => {},
    })

    const services = peer.listServices()
    assert.ok(services.includes('fs'))
    assert.ok(services.includes('agent'))
  })

  it('registers and lists custom services', async () => {
    const identity = await ServerIdentity.generate('custom-svc')
    const peer = new PeerNodeServer({
      identity,
      dataDir: tmpDir,
      onLog: () => {},
    })

    peer.registerService('compute', { run: async () => ({ result: 42 }) })
    const services = peer.listServices()
    assert.ok(services.includes('compute'))
    assert.equal(peer.getService('compute').run !== undefined, true)
  })

  it('toJSON returns complete state', async () => {
    const identity = await ServerIdentity.generate('json-test')
    const peer = new PeerNodeServer({
      identity,
      dataDir: tmpDir,
      onLog: () => {},
    })

    await peer.start()
    const json = peer.toJSON()

    assert.equal(json.podId, identity.podId)
    assert.equal(json.label, identity.label)
    assert.equal(json.state, 'running')
    assert.ok(Array.isArray(json.services))
    assert.ok(Array.isArray(json.connectedPeers))
    assert.equal(typeof json.created, 'number')

    await peer.stop()
  })

  it('connectedPeers is empty by default', async () => {
    const identity = await ServerIdentity.generate('peers-test')
    const peer = new PeerNodeServer({
      identity,
      dataDir: tmpDir,
      onLog: () => {},
    })

    assert.deepEqual(peer.connectedPeers, [])
  })

  it('start is idempotent', async () => {
    const identity = await ServerIdentity.generate('idem-test')
    const peer = new PeerNodeServer({
      identity,
      dataDir: tmpDir,
      onLog: () => {},
    })

    await peer.start()
    await peer.start() // should not throw
    assert.equal(peer.state, 'running')
    await peer.stop()
  })

  it('stop is idempotent', async () => {
    const identity = await ServerIdentity.generate('idem-stop')
    const peer = new PeerNodeServer({
      identity,
      dataDir: tmpDir,
      onLog: () => {},
    })

    await peer.stop() // should not throw when already stopped
    assert.equal(peer.state, 'stopped')
  })
})

// ─── createServerKernel factory ──────────────────────────────────────

describe('createServerKernel', () => {
  let tmpDir

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'clawser-factory-test-'))
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('creates a kernel with generated identity', async () => {
    const kernel = await createServerKernel({
      dataDir: tmpDir,
      label: 'factory-test',
      onLog: () => {},
    })

    assert.ok(kernel.podId.startsWith('pod-'))
    assert.equal(kernel.identity.label, 'factory-test')
    assert.equal(kernel.state, 'stopped')
  })

  it('creates a kernel with provided identity', async () => {
    const identity = await ServerIdentity.generate('provided')
    const kernel = await createServerKernel({
      identity,
      dataDir: tmpDir,
      onLog: () => {},
    })

    assert.equal(kernel.podId, identity.podId)
  })

  it('fs service works end-to-end', async () => {
    const kernel = await createServerKernel({
      dataDir: tmpDir,
      onLog: () => {},
    })

    const fsSvc = kernel.getService('fs')
    await fsSvc.write({ path: 'test.txt', data: 'hello from kernel' })
    const result = await fsSvc.read({ path: 'test.txt' })
    assert.equal(result.data, 'hello from kernel')
  })

  it('agent service works end-to-end', async () => {
    const kernel = await createServerKernel({
      dataDir: tmpDir,
      agentName: 'kernel-agent',
      onLog: () => {},
    })

    const agentSvc = kernel.getService('agent')
    const result = await agentSvc.run({ message: 'ping' })
    assert.ok(result.response.includes('ping'))
  })
})

// ─── Symlink safety ─────────────────────────────────────────────────

describe('ServerFileSystem symlink safety', () => {
  let tmpDir
  let fs

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'clawser-symlink-test-'))
    fs = new ServerFileSystem(tmpDir)
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('rejects symlinks pointing outside root', async () => {
    const { symlinkSync, writeFileSync } = await import('node:fs')
    // Create a real file outside the root, then symlink to it
    const outsideDir = mkdtempSync(join(tmpdir(), 'clawser-outside-'))
    writeFileSync(join(outsideDir, 'secret.txt'), 'secret data')
    symlinkSync(join(outsideDir, 'secret.txt'), join(tmpDir, 'escape-link'))

    await assert.rejects(
      () => fs.read('escape-link'),
      (err) => err.message.includes('traversal')
    )

    rmSync(outsideDir, { recursive: true, force: true })
  })
})

// ─── Configurable memory limit ──────────────────────────────────────

describe('ServerAgent memory limit', () => {
  it('defaults to 1024', () => {
    const agent = new ServerAgent({ name: 'mem-test' })
    // Fill up to 1024
    for (let i = 0; i < 1024; i++) {
      agent.addMemory({ key: `k${i}`, content: `c${i}` })
    }
    // c0 should still be present (exactly at capacity, no eviction yet)
    assert.equal(agent.searchMemories('c0').length, 1)

    // Adding one more triggers eviction of the oldest (c0)
    agent.addMemory({ key: 'overflow', content: 'overflow' })
    assert.equal(agent.searchMemories('c0').length, 0)
    assert.equal(agent.searchMemories('overflow').length, 1)
  })

  it('respects custom maxMemories', () => {
    const agent = new ServerAgent({ name: 'mem-test', maxMemories: 3 })
    agent.addMemory({ key: 'a', content: 'alpha' })
    agent.addMemory({ key: 'b', content: 'beta' })
    agent.addMemory({ key: 'c', content: 'gamma' })

    // All three present
    assert.equal(agent.searchMemories('alpha').length, 1)
    assert.equal(agent.searchMemories('gamma').length, 1)

    // Adding a 4th should evict the first
    agent.addMemory({ key: 'd', content: 'delta' })
    assert.equal(agent.searchMemories('alpha').length, 0)
    assert.equal(agent.searchMemories('delta').length, 1)
  })

  it('FIFO eviction when at capacity', () => {
    const agent = new ServerAgent({ name: 'fifo', maxMemories: 2 })
    agent.addMemory({ key: 'first', content: 'first-content' })
    agent.addMemory({ key: 'second', content: 'second-content' })
    agent.addMemory({ key: 'third', content: 'third-content' })

    assert.equal(agent.searchMemories('first').length, 0) // evicted
    assert.equal(agent.searchMemories('second').length, 1)
    assert.equal(agent.searchMemories('third').length, 1)
  })
})

// ─── Service auth ───────────────────────────────────────────────────

describe('PeerNodeServer service auth', () => {
  let tmpDir

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'clawser-auth-test-'))
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('callService with valid token succeeds', async () => {
    const identity = await ServerIdentity.generate('auth-test')
    const peer = new PeerNodeServer({
      identity,
      dataDir: tmpDir,
      onLog: () => {},
    })

    const token = peer.serviceToken
    assert.ok(typeof token === 'string')

    const result = await peer.callService('agent', 'run', { message: 'test' }, token)
    assert.ok(result.response.includes('test'))
  })

  it('callService with invalid token returns unauthorized', async () => {
    const identity = await ServerIdentity.generate('auth-test')
    const peer = new PeerNodeServer({
      identity,
      dataDir: tmpDir,
      onLog: () => {},
    })

    const result = await peer.callService('agent', 'run', { message: 'test' }, 'wrong-token')
    assert.equal(result.success, false)
    assert.equal(result.error, 'unauthorized')
  })

  it('callService with missing token returns unauthorized', async () => {
    const identity = await ServerIdentity.generate('auth-test')
    const peer = new PeerNodeServer({
      identity,
      dataDir: tmpDir,
      onLog: () => {},
    })

    const result = await peer.callService('agent', 'run', { message: 'test' }, undefined)
    assert.equal(result.success, false)
    assert.equal(result.error, 'unauthorized')
  })

  it('callService with unknown method returns error', async () => {
    const identity = await ServerIdentity.generate('auth-test')
    const peer = new PeerNodeServer({
      identity,
      dataDir: tmpDir,
      onLog: () => {},
    })

    const token = peer.serviceToken
    const result = await peer.callService('agent', 'nonexistent', {}, token)
    assert.equal(result.success, false)
    assert.ok(result.error.includes('unknown'))
  })

  it('getService still works for local/trusted use', async () => {
    const identity = await ServerIdentity.generate('local-test')
    const peer = new PeerNodeServer({
      identity,
      dataDir: tmpDir,
      onLog: () => {},
    })

    const agentSvc = peer.getService('agent')
    const result = await agentSvc.run({ message: 'local' })
    assert.ok(result.response.includes('local'))
  })

  it('auto-generates serviceToken if not provided', async () => {
    const identity = await ServerIdentity.generate('auto-token')
    const peer = new PeerNodeServer({
      identity,
      dataDir: tmpDir,
      onLog: () => {},
    })

    assert.ok(peer.serviceToken)
    assert.ok(peer.serviceToken.length > 0)
  })

  it('uses provided serviceToken', async () => {
    const identity = await ServerIdentity.generate('custom-token')
    const peer = new PeerNodeServer({
      identity,
      dataDir: tmpDir,
      serviceToken: 'my-custom-token',
      onLog: () => {},
    })

    assert.equal(peer.serviceToken, 'my-custom-token')
    const result = await peer.callService('agent', 'run', { message: 'hi' }, 'my-custom-token')
    assert.ok(result.response.includes('hi'))
  })
})
