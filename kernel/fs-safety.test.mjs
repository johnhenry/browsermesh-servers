/**
 * ServerFileSystem keeps every path inside its root: lexically, through
 * symlinks to existing files, through symlinked directories (also for files
 * that do not exist yet), through dangling symlinks, and not by prefix
 * coincidence with a sibling directory.
 */

import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync, existsSync, readFileSync, realpathSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ServerFileSystem } from './index.mjs'

describe('ServerFileSystem containment', () => {
  let base
  let root
  let outside
  let siblingPrefix
  let fs

  beforeEach(() => {
    base = realpathSync(mkdtempSync(join(tmpdir(), 'fs-safety-')))
    root = join(base, 'data')
    outside = join(base, 'outside')
    siblingPrefix = join(base, 'data-evil') // shares the textual prefix of root
    for (const d of [root, outside, siblingPrefix]) mkdirSync(d)
    writeFileSync(join(outside, 'secret.txt'), 'outside secret')
    writeFileSync(join(siblingPrefix, 'secret.txt'), 'sibling secret')
    fs = new ServerFileSystem(root)
  })

  afterEach(() => { rmSync(base, { recursive: true, force: true }) })

  const traversal = (err) => /traversal|symlink/.test(err.message)

  it('refuses a symlink to a file in a directory whose name starts with the root\'s name', async () => {
    symlinkSync(join(siblingPrefix, 'secret.txt'), join(root, 'link'))
    await assert.rejects(() => fs.read('link'), traversal)
  })

  it('refuses a symlinked directory that points outside, for reads and for files that do not exist yet', async () => {
    symlinkSync(outside, join(root, 'dir'))
    await assert.rejects(() => fs.read('dir/secret.txt'), traversal)
    await assert.rejects(() => fs.write('dir/new.txt', 'x'), traversal)
    assert.equal(existsSync(join(outside, 'new.txt')), false)
    await assert.rejects(() => fs.write('dir/sub/deeper/new.txt', 'x'), traversal)
    assert.equal(existsSync(join(outside, 'sub')), false)
    await assert.rejects(() => fs.list('dir'), traversal)
    await assert.rejects(() => fs.delete('dir/secret.txt'), traversal)
    assert.equal(readFileSync(join(outside, 'secret.txt'), 'utf-8'), 'outside secret')
  })

  it('refuses a dangling symlink that points outside', async () => {
    symlinkSync(join(outside, 'not-yet.txt'), join(root, 'dangling'))
    await assert.rejects(() => fs.write('dangling', 'x'), traversal)
    assert.equal(existsSync(join(outside, 'not-yet.txt')), false)
  })

  it('allows a symlink that stays inside the root', async () => {
    await fs.write('real/a.txt', 'inside')
    symlinkSync(join(root, 'real'), join(root, 'alias'))
    assert.equal((await fs.read('alias/a.txt')).data, 'inside')
    await fs.write('alias/b.txt', 'via alias')
    assert.equal(readFileSync(join(root, 'real', 'b.txt'), 'utf-8'), 'via alias')
  })

  it('refuses lexical escapes and absolute paths', async () => {
    for (const p of ['../outside/secret.txt', '../data-evil/secret.txt', 'a/../../outside/secret.txt', join(outside, 'secret.txt'), '/etc/passwd']) {
      await assert.rejects(() => fs.read(p), traversal, p)
      await assert.rejects(() => fs.write(p, 'x'), traversal, p)
    }
  })

  it('accepts names that merely start with two dots', async () => {
    await fs.write('..hidden.txt', 'ok')
    await fs.write('..dir/..file', 'ok')
    assert.equal((await fs.read('..hidden.txt')).data, 'ok')
    assert.equal((await fs.read('..dir/..file')).data, 'ok')
  })

  it('rejects a path with a NUL byte without crashing', async () => {
    await assert.rejects(() => fs.read('a\0b'))
    await assert.rejects(() => fs.write('a\0b', 'x'))
  })

  it('still reads, writes, lists, stats and deletes inside the root', async () => {
    await fs.write('x/y.txt', 'hello')
    assert.equal((await fs.read('x/y.txt')).data, 'hello')
    assert.deepEqual((await fs.list('x')).map(e => e.name), ['y.txt'])
    assert.equal((await fs.stat('x/y.txt')).size, 5)
    assert.deepEqual(await fs.delete('x/y.txt'), { success: true })
    assert.equal(await fs.stat('x/y.txt'), null)
  })
})
