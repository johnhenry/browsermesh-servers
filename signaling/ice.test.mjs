/**
 * Tests for ICE server configuration: no third-party STUN by default,
 * time-limited TURN credentials (TURN REST API / coturn use-auth-secret),
 * and the access rules of GET /ice-servers.
 */

import { describe, it, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { createHmac } from 'node:crypto'
import { createServer } from './index.mjs'
import {
  getIceServers,
  createTurnCredentials,
  PUBLIC_STUN_SERVERS,
  DEFAULT_TURN_TTL_SECONDS,
  MAX_TURN_TTL_SECONDS,
} from './stun-turn.mjs'
import { RateLimiter, safeEqual, clientIp } from './limits.mjs'

const SECRET = 'a-shared-secret-of-sufficient-length'
const TOKEN = 'secret-token-0123456789'

/** GET with arbitrary headers (fetch would refuse some of them). */
function rawGet(port, path, headers = {}, method = 'GET') {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf-8')
        let body = null
        try { body = JSON.parse(text) } catch { /* not json */ }
        resolve({ status: res.statusCode, headers: res.headers, body, text })
      })
    })
    req.on('error', reject)
    req.end()
  })
}

// ─── stun-turn.mjs ───────────────────────────────────────────────────

describe('stun-turn: defaults', () => {
  it('has no ICE server at all by default (no third-party STUN)', () => {
    assert.deepEqual(getIceServers({}), [])
  })

  it('PUBLIC_STUN_SERVERS is an explicit opt-in', () => {
    assert.ok(PUBLIC_STUN_SERVERS.length > 0)
    assert.deepEqual(getIceServers({ ALLOW_PUBLIC_STUN: '1' }), PUBLIC_STUN_SERVERS)
    assert.deepEqual(getIceServers({ ALLOW_PUBLIC_STUN: 'true' }), PUBLIC_STUN_SERVERS)
    assert.deepEqual(getIceServers({ ALLOW_PUBLIC_STUN: '0' }), [])
  })

  it('STUN_URLS configures the operator\'s own STUN servers', () => {
    const servers = getIceServers({ STUN_URLS: 'stun:stun.example.org:3478, stun:b.example.org:3478' })
    assert.deepEqual(servers, [{ urls: ['stun:stun.example.org:3478', 'stun:b.example.org:3478'] }])
  })

  it('parses ICE_SERVERS from env JSON', () => {
    const custom = [{ urls: 'stun:custom.example.com:3478' }]
    assert.deepEqual(getIceServers({ ICE_SERVERS: JSON.stringify(custom) }), custom)
  })

  it('falls back to no servers on invalid or empty ICE_SERVERS, without echoing it', () => {
    const logged = []
    const orig = console.warn
    console.warn = (...a) => logged.push(a.join(' '))
    try {
      assert.deepEqual(getIceServers({ ICE_SERVERS: 'not-json-credential-xyz123' }), [])
      assert.deepEqual(getIceServers({ ICE_SERVERS: '[]' }), [])
    } finally {
      console.warn = orig
    }
    assert.ok(logged.length >= 1)
    assert.ok(!logged.join('\n').includes('credential-xyz123'))
  })
})

describe('stun-turn: time-limited TURN credentials', () => {
  it('username is "<expiry seconds>:<user>" and credential is base64(HMAC-SHA1(secret, username)) (vector from openssl)', () => {
    // openssl: printf '1700000000:alice' | openssl dgst -sha1 -hmac north -binary | base64
    const now = (1_700_000_000 - 600) * 1000
    const c = createTurnCredentials({ secret: 'north', ttlSeconds: 600, user: 'alice', now })
    assert.equal(c.username, '1700000000:alice')
    assert.equal(c.credential, 'Cd/49soE35ICqcJF/bCTn8Z4OyE=')
    assert.equal(c.expiresAt, 1_700_000_000)
  })

  it('without a user the username is the bare expiry timestamp', () => {
    const now = (1_700_000_000 - 600) * 1000
    const c = createTurnCredentials({ secret: 'north', ttlSeconds: 600, now })
    assert.equal(c.username, '1700000000')
    assert.equal(c.credential, 'CWyHi3zCeWqXBir9thl4m+iZPRY=')
  })

  it('getIceServers adds a TURN entry with fresh credentials from TURN_SECRET', () => {
    const now = 1_700_000_000_000
    const servers = getIceServers({
      TURN_URLS: 'turn:turn.example.org:3478?transport=udp,turns:turn.example.org:5349?transport=tcp',
      TURN_SECRET: SECRET,
    }, now)
    assert.equal(servers.length, 1)
    const turn = servers[0]
    assert.deepEqual(turn.urls, ['turn:turn.example.org:3478?transport=udp', 'turns:turn.example.org:5349?transport=tcp'])
    const [expiry, user] = turn.username.split(':')
    assert.equal(Number(expiry), 1_700_000_000 + DEFAULT_TURN_TTL_SECONDS)
    assert.match(user, /^[0-9a-f]{16}$/)
    const expected = createHmac('sha1', SECRET).update(turn.username).digest('base64')
    assert.equal(turn.credential, expected)
  })

  it('a single TURN url stays a string; two calls give different usernames', () => {
    const env = { TURN_URLS: 'turn:turn.example.org:3478', TURN_SECRET: SECRET }
    const a = getIceServers(env)[0]
    const b = getIceServers(env)[0]
    assert.equal(a.urls, 'turn:turn.example.org:3478')
    assert.notEqual(a.username, b.username)
  })

  it('the default lifetime is short and TURN_TTL_SECONDS is clamped', () => {
    assert.ok(DEFAULT_TURN_TTL_SECONDS <= 600)
    const now = 1_700_000_000_000
    const exp = (env) => Number(getIceServers({ TURN_URLS: 'turn:t.example.org', TURN_SECRET: SECRET, ...env }, now)[0].username.split(':')[0]) - 1_700_000_000
    assert.equal(exp({ TURN_TTL_SECONDS: '120' }), 120)
    assert.equal(exp({ TURN_TTL_SECONDS: '99999999' }), MAX_TURN_TTL_SECONDS)
    assert.equal(exp({ TURN_TTL_SECONDS: '1' }), 60)
    assert.equal(exp({ TURN_TTL_SECONDS: 'abc' }), DEFAULT_TURN_TTL_SECONDS)
  })

  it('refuses a short secret and does not print it', () => {
    assert.throws(
      () => getIceServers({ TURN_URLS: 'turn:t.example.org', TURN_SECRET: 'short-secret' }),
      (err) => err instanceof Error && !err.message.includes('short-secret') && /TURN_SECRET/.test(err.message),
    )
  })

  it('TURN_SECRET takes precedence over the legacy static username/credential', () => {
    const servers = getIceServers({
      TURN_URLS: 'turn:t.example.org', TURN_SECRET: SECRET,
      TURN_USERNAME: 'static-user', TURN_CREDENTIAL: 'static-pass',
    })
    assert.notEqual(servers[0].username, 'static-user')
    assert.notEqual(servers[0].credential, 'static-pass')
  })

  it('legacy static TURN_USERNAME / TURN_CREDENTIAL still work when no secret is set', () => {
    const servers = getIceServers({ TURN_URLS: 'turn:t.example.org', TURN_USERNAME: 'u', TURN_CREDENTIAL: 'p' })
    assert.deepEqual(servers, [{ urls: 'turn:t.example.org', username: 'u', credential: 'p' }])
  })
})

// ─── limits.mjs ──────────────────────────────────────────────────────

describe('limits', () => {
  it('safeEqual compares strings of any length, exactly', () => {
    assert.equal(safeEqual('abc', 'abc'), true)
    assert.equal(safeEqual('abc', 'abd'), false)
    assert.equal(safeEqual('abc', 'abcd'), false)
    assert.equal(safeEqual('', ''), true)
    assert.equal(safeEqual(undefined, 'a'), false)
    assert.equal(safeEqual('a', null), false)
  })

  it('RateLimiter allows `limit` hits per window per key and resets after the window', () => {
    let t = 1000
    const rl = new RateLimiter({ limit: 2, windowMs: 1000, now: () => t })
    assert.equal(rl.hit('a').ok, true)
    assert.equal(rl.hit('a').ok, true)
    const third = rl.hit('a')
    assert.equal(third.ok, false)
    assert.ok(third.retryAfterMs > 0 && third.retryAfterMs <= 1000)
    assert.equal(rl.hit('b').ok, true)
    t += 1001
    assert.equal(rl.hit('a').ok, true)
  })

  it('RateLimiter bounds the number of keys it remembers', () => {
    const rl = new RateLimiter({ limit: 1, windowMs: 60_000, maxKeys: 10 })
    for (let i = 0; i < 100; i++) rl.hit(`k${i}`)
    assert.ok(rl.size <= 10)
  })

  it('clientIp ignores forwarding headers unless the proxy is trusted', () => {
    const req = { socket: { remoteAddress: '10.0.0.1' }, headers: { 'x-forwarded-for': '1.2.3.4, 5.6.7.8', 'fly-client-ip': '9.9.9.9' } }
    assert.equal(clientIp(req, false), '10.0.0.1')
    assert.equal(clientIp(req, true), '9.9.9.9')
    assert.equal(clientIp({ socket: { remoteAddress: '10.0.0.1' }, headers: { 'x-forwarded-for': '1.2.3.4, 5.6.7.8' } }, true), '5.6.7.8')
  })
})

// ─── GET /ice-servers ────────────────────────────────────────────────

describe('GET /ice-servers access', () => {
  let instance
  afterEach(async () => { await instance?.close(); instance = null })

  async function start(env = {}) {
    instance = createServer({ port: 0, env })
    return instance.listen(0)
  }
  const turnEnv = { TURN_URLS: 'turn:turn.example.org:3478', TURN_SECRET: SECRET, ICE_API_TOKEN: TOKEN }

  it('is refused by default: no token, not same-origin', async () => {
    const port = await start(turnEnv)
    const r = await rawGet(port, '/ice-servers')
    assert.equal(r.status, 401)
    assert.ok(!r.text.includes('turn:'))
    assert.ok(!r.text.includes(SECRET))
  })

  it('is refused for a foreign Origin without a token', async () => {
    const port = await start(turnEnv)
    const r = await rawGet(port, '/ice-servers', { Origin: 'https://evil.example' })
    assert.equal(r.status, 401)
    assert.ok(!r.text.includes('turn:'))
  })

  it('a same-origin claim alone gets no TURN credentials when TURN_SECRET is set', async () => {
    const port = await start({ ...turnEnv, STUN_URLS: 'stun:stun.example.org:3478' })
    const claims = [
      { 'Sec-Fetch-Site': 'same-origin' },
      { Origin: `http://127.0.0.1:${port}` },
    ]
    for (const headers of claims) {
      const r = await rawGet(port, '/ice-servers', headers)
      assert.equal(r.status, 200, JSON.stringify(headers))
      assert.deepEqual(r.body, [{ urls: ['stun:stun.example.org:3478'] }])
      assert.ok(!r.text.includes('turn:'))
      assert.ok(!r.text.includes('credential'))
      assert.ok(!r.text.includes('username'))
    }
  })

  it('a same-origin claim alone is refused when there is only TURN to give', async () => {
    const port = await start(turnEnv)
    for (const headers of [{ 'Sec-Fetch-Site': 'same-origin' }, { Origin: `http://127.0.0.1:${port}` }]) {
      const r = await rawGet(port, '/ice-servers', headers)
      assert.equal(r.status, 401, JSON.stringify(headers))
      assert.ok(!r.text.includes('turn:'))
    }
  })

  it('a static ICE_SERVERS list with TURN is not handed to a same-origin claim either', async () => {
    const list = [{ urls: 'stun:s.example.org' }, { urls: 'turns:t.example.org', username: 'u', credential: 'static-cred-xyz' }]
    const port = await start({ ...turnEnv, ICE_SERVERS: JSON.stringify(list) })
    const r = await rawGet(port, '/ice-servers', { 'Sec-Fetch-Site': 'same-origin' })
    assert.deepEqual(r.body, [list[0]])
    assert.ok(!r.text.includes('static-cred-xyz'))
  })

  it('ICE_ALLOW_SAME_ORIGIN_TURN=1 lets a same-origin caller have TURN credentials', async () => {
    const port = await start({ ...turnEnv, ICE_ALLOW_SAME_ORIGIN_TURN: '1' })
    for (const headers of [{ 'Sec-Fetch-Site': 'same-origin' }, { Origin: `http://127.0.0.1:${port}` }]) {
      const r = await rawGet(port, '/ice-servers', headers)
      assert.equal(r.status, 200)
      const turn = r.body.find(s => s.username)
      assert.equal(turn.credential, createHmac('sha1', SECRET).update(turn.username).digest('base64'))
    }
    // The switch widens nothing else: no claim, no answer.
    assert.equal((await rawGet(port, '/ice-servers')).status, 401)
    assert.equal((await rawGet(port, '/ice-servers', { 'Sec-Fetch-Site': 'cross-site' })).status, 401)
  })

  it('without TURN_SECRET the same-origin convenience is unchanged', async () => {
    const port = await start({ STUN_URLS: 'stun:stun.example.org:3478' })
    const r = await rawGet(port, '/ice-servers', { 'Sec-Fetch-Site': 'same-origin' })
    assert.equal(r.status, 200)
    assert.deepEqual(r.body, [{ urls: ['stun:stun.example.org:3478'] }])
  })

  it('the token wins even next to a same-origin claim', async () => {
    const port = await start(turnEnv)
    const r = await rawGet(port, '/ice-servers', { Authorization: `Bearer ${TOKEN}`, 'Sec-Fetch-Site': 'same-origin' })
    assert.equal(r.status, 200)
    assert.ok(r.body.find(s => s.username))
  })

  it('does not treat same-site or cross-site fetch metadata as same-origin', async () => {
    const port = await start(turnEnv)
    for (const v of ['same-site', 'cross-site', 'none']) {
      const r = await rawGet(port, '/ice-servers', { 'Sec-Fetch-Site': v })
      assert.equal(r.status, 401, v)
    }
  })

  it('answers a caller with the right bearer token and returns time-limited TURN credentials', async () => {
    const port = await start({ ...turnEnv, ICE_API_TOKEN: 'secret-token-0123456789' })
    const r = await rawGet(port, '/ice-servers', { Authorization: 'Bearer secret-token-0123456789' })
    assert.equal(r.status, 200)
    assert.equal(r.headers['cache-control'], 'no-store')
    const turn = r.body.find(s => s.username)
    assert.ok(turn)
    assert.match(turn.username, /^\d+:[0-9a-f]{16}$/)
    assert.equal(turn.credential, createHmac('sha1', SECRET).update(turn.username).digest('base64'))
    assert.ok(!r.text.includes(SECRET))
    assert.ok(!r.text.includes('secret-token'))
  })

  it('refuses a wrong token, a token of another length, and a bare scheme', async () => {
    const port = await start({ ...turnEnv, ICE_API_TOKEN: 'secret-token-0123456789' })
    for (const auth of ['Bearer wrong', 'Bearer secret-token-0123456789x', 'Bearer ', 'Bearer', 'secret-token-0123456789', 'Basic secret-token-0123456789']) {
      const r = await rawGet(port, '/ice-servers', { Authorization: auth })
      assert.equal(r.status, 401, auth)
    }
  })

  it('an empty ICE_API_TOKEN does not authenticate an empty bearer', async () => {
    const port = await start({ ICE_API_TOKEN: '', STUN_URLS: 'stun:stun.example.org:3478' })
    const r = await rawGet(port, '/ice-servers', { Authorization: 'Bearer ' })
    assert.equal(r.status, 401)
  })

  it('query strings do not change routing or access', async () => {
    const port = await start(turnEnv)
    assert.equal((await rawGet(port, '/ice-servers?x=1')).status, 401)
    assert.equal((await rawGet(port, '/ice-servers?x=1', { 'Sec-Fetch-Site': 'same-origin' })).status, 401)
    assert.equal((await rawGet(port, '/ice-servers?x=1', { Authorization: `Bearer ${TOKEN}` })).status, 200)
  })

  it('only GET (and OPTIONS) are served', async () => {
    const port = await start(turnEnv)
    const r = await rawGet(port, '/ice-servers', { Authorization: `Bearer ${TOKEN}` }, 'POST')
    assert.equal(r.status, 404)
  })

  it('the rate limit also covers same-origin claims and bearer callers', async () => {
    const port = await start({ ...turnEnv, ICE_RATE_LIMIT_PER_MINUTE: '2' })
    assert.equal((await rawGet(port, '/ice-servers', { 'Sec-Fetch-Site': 'same-origin' })).status, 401)
    assert.equal((await rawGet(port, '/ice-servers', { Authorization: `Bearer ${TOKEN}` })).status, 200)
    assert.equal((await rawGet(port, '/ice-servers', { Authorization: `Bearer ${TOKEN}` })).status, 429)
  })

  it('is rate limited per client address, and refusals count', async () => {
    const port = await start({ ...turnEnv, ICE_RATE_LIMIT_PER_MINUTE: '3' })
    const statuses = []
    for (let i = 0; i < 5; i++) statuses.push((await rawGet(port, '/ice-servers')).status)
    assert.deepEqual(statuses.slice(0, 3), [401, 401, 401])
    assert.deepEqual(statuses.slice(3), [429, 429])
    const limited = await rawGet(port, '/ice-servers')
    assert.ok(Number(limited.headers['retry-after']) >= 1)
  })

  it('does not trust X-Forwarded-For for rate limiting unless TRUST_PROXY is set', async () => {
    const port = await start({ ...turnEnv, ICE_RATE_LIMIT_PER_MINUTE: '1' })
    assert.equal((await rawGet(port, '/ice-servers', { 'X-Forwarded-For': '1.1.1.1' })).status, 401)
    assert.equal((await rawGet(port, '/ice-servers', { 'X-Forwarded-For': '2.2.2.2' })).status, 429)
  })

  it('with TRUST_PROXY each forwarded client has its own budget', async () => {
    const port = await start({ ...turnEnv, ICE_RATE_LIMIT_PER_MINUTE: '1', TRUST_PROXY: '1' })
    assert.equal((await rawGet(port, '/ice-servers', { 'X-Forwarded-For': '1.1.1.1' })).status, 401)
    assert.equal((await rawGet(port, '/ice-servers', { 'X-Forwarded-For': '2.2.2.2' })).status, 401)
    assert.equal((await rawGet(port, '/ice-servers', { 'X-Forwarded-For': '2.2.2.2' })).status, 429)
  })

  it('logs nothing that contains a secret, a token or a credential', async () => {
    const lines = []
    const orig = { log: console.log, warn: console.warn, error: console.error, info: console.info }
    for (const k of Object.keys(orig)) console[k] = (...a) => lines.push(a.map(String).join(' '))
    let body
    try {
      const port = await start({ ...turnEnv, ICE_API_TOKEN: 'secret-token-0123456789' })
      await rawGet(port, '/ice-servers', { Authorization: 'Bearer nope' })
      const ok = await rawGet(port, '/ice-servers', { Authorization: 'Bearer secret-token-0123456789' })
      body = ok.body
    } finally {
      Object.assign(console, orig)
    }
    const out = lines.join('\n')
    const turn = body.find(s => s.username)
    for (const s of [SECRET, 'secret-token-0123456789', turn.credential, turn.username]) {
      assert.ok(!out.includes(s))
    }
  })
})

describe('CORS on /health and /ice-servers', () => {
  let instance
  afterEach(async () => { await instance?.close(); instance = null })

  async function start(env = {}) {
    instance = createServer({ port: 0, env })
    return instance.listen(0)
  }

  it('never answers with a wildcard origin', async () => {
    const port = await start({ ICE_API_TOKEN: 'secret-token-0123456789', ORIGINS: 'https://app.example' })
    for (const path of ['/health', '/ice-servers', '/nope']) {
      const r = await rawGet(port, path, { Origin: 'https://app.example', Authorization: 'Bearer secret-token-0123456789' })
      assert.notEqual(r.headers['access-control-allow-origin'], '*', path)
    }
  })

  it('reflects only an exactly listed origin, with Vary: Origin', async () => {
    const port = await start({ ICE_API_TOKEN: 'secret-token-0123456789', ORIGINS: 'https://app.example' })
    const auth = { Authorization: 'Bearer secret-token-0123456789' }
    const ok = await rawGet(port, '/ice-servers', { ...auth, Origin: 'https://app.example' })
    assert.equal(ok.headers['access-control-allow-origin'], 'https://app.example')
    assert.match(ok.headers.vary ?? '', /Origin/)
    for (const o of ['https://app.example.evil.test', 'https://evil.test', 'http://app.example', 'https://app.example/', 'null']) {
      const r = await rawGet(port, '/ice-servers', { ...auth, Origin: o })
      assert.equal(r.headers['access-control-allow-origin'], undefined, o)
    }
    const none = await rawGet(port, '/health')
    assert.equal(none.headers['access-control-allow-origin'], undefined)
  })

  it('with no ORIGINS configured no origin is granted CORS', async () => {
    const port = await start({ ICE_API_TOKEN: 'secret-token-0123456789' })
    const r = await rawGet(port, '/health', { Origin: 'https://app.example' })
    assert.equal(r.status, 200)
    assert.equal(r.headers['access-control-allow-origin'], undefined)
  })

  it('the token path with TURN configured: listed origin reflected, full answer, unlisted origin not granted', async () => {
    const turn = { TURN_URLS: 'turn:turn.example.org:3478', TURN_SECRET: SECRET, ICE_API_TOKEN: TOKEN, ORIGINS: 'https://app.example' }
    const port = await start(turn)
    const auth = { Authorization: `Bearer ${TOKEN}` }
    const ok = await rawGet(port, '/ice-servers', { ...auth, Origin: 'https://app.example' })
    assert.equal(ok.status, 200)
    assert.equal(ok.headers['access-control-allow-origin'], 'https://app.example')
    assert.match(ok.headers.vary ?? '', /Origin/)
    assert.ok(ok.body.find(s => s.username))
    const other = await rawGet(port, '/ice-servers', { ...auth, Origin: 'https://evil.test' })
    assert.equal(other.status, 200)
    assert.equal(other.headers['access-control-allow-origin'], undefined)
    // A listed origin without the token is a same-origin claim at best: no TURN.
    const noToken = await rawGet(port, '/ice-servers', { Origin: 'https://app.example' })
    assert.equal(noToken.status, 401)
    assert.equal(noToken.headers['access-control-allow-origin'], 'https://app.example')
  })

  it('preflight is answered for a listed origin only and never sends credentials mode with a wildcard', async () => {
    const port = await start({ ORIGINS: 'https://app.example' })
    const ok = await rawGet(port, '/ice-servers', { Origin: 'https://app.example', 'Access-Control-Request-Method': 'GET' }, 'OPTIONS')
    assert.equal(ok.status, 204)
    assert.equal(ok.headers['access-control-allow-origin'], 'https://app.example')
    assert.match(ok.headers['access-control-allow-headers'], /Authorization/i)
    assert.equal(ok.headers['access-control-allow-credentials'], undefined)
    const bad = await rawGet(port, '/ice-servers', { Origin: 'https://evil.test', 'Access-Control-Request-Method': 'GET' }, 'OPTIONS')
    assert.equal(bad.status, 204)
    assert.equal(bad.headers['access-control-allow-origin'], undefined)
  })
})

describe('start-up: TURN credentials need a token', () => {
  const turn = { TURN_URLS: 'turn:turn.example.org:3478', TURN_SECRET: SECRET }

  it('refuses to start when TURN credentials would be handed out and no token is configured', () => {
    for (const env of [turn, { ...turn, ICE_API_TOKEN: '' }]) {
      assert.throws(
        () => createServer({ port: 0, env }),
        (err) => err instanceof Error
          && /ICE_API_TOKEN/.test(err.message)
          && /token is required/.test(err.message)
          && !err.message.includes(SECRET),
      )
    }
  })

  it('starts with a token, or with the explicit same-origin switch', async () => {
    for (const env of [{ ...turn, ICE_API_TOKEN: TOKEN }, { ...turn, ICE_ALLOW_SAME_ORIGIN_TURN: '1' }]) {
      const instance = createServer({ port: 0, env })
      await instance.close()
    }
  })

  it('a switch that is off or not a flag does not count', () => {
    for (const v of ['0', 'no', '', 'maybe']) {
      assert.throws(() => createServer({ port: 0, env: { ...turn, ICE_ALLOW_SAME_ORIGIN_TURN: v } }), /ICE_API_TOKEN/, v)
    }
  })

  it('starts as before when nothing here would hand out TURN credentials', async () => {
    const boots = [
      {},
      { AUTH_MODE: 'open', TRUST_PROXY: '1' },
      { TURN_SECRET: SECRET }, // no TURN_URLS: no credentials are minted
      { TURN_URLS: 'turn:turn.example.org:3478' }, // no secret: legacy static login only
      { TURN_URLS: 'turn:turn.example.org:3478', TURN_USERNAME: 'u', TURN_CREDENTIAL: 'p' },
      { STUN_URLS: 'stun:stun.example.org:3478' },
    ]
    for (const env of boots) {
      const instance = createServer({ port: 0, env })
      await instance.close()
    }
  })
})

describe('the deployed configuration (open mode, no TURN, no token, TRUST_PROXY=1)', () => {
  // The environment of deploy/fly.signaling.toml. Every answer below is what
  // the server gave before the caller check was tightened; the table is the
  // record that nothing changed for this configuration.
  const LIVE = { PORT: '8787', AUTH_MODE: 'open', TRUST_PROXY: '1' }
  let instance
  afterEach(async () => { await instance?.close(); instance = null })

  it('answers every kind of caller exactly as before', async () => {
    instance = createServer({ port: 0, env: LIVE })
    const port = await instance.listen(0)
    const fly = { 'Fly-Client-IP': '203.0.113.7' }
    const cases = [
      ['no claim', {}, 401, { error: 'unauthorized' }],
      ['Sec-Fetch-Site same-origin', { 'Sec-Fetch-Site': 'same-origin' }, 200, []],
      ['Origin host equals Host', { Origin: `http://127.0.0.1:${port}` }, 200, []],
      ['foreign Origin', { Origin: 'https://evil.example' }, 401, { error: 'unauthorized' }],
      ['cross-site', { 'Sec-Fetch-Site': 'cross-site' }, 401, { error: 'unauthorized' }],
      ['a bearer token (none is configured)', { Authorization: 'Bearer anything' }, 401, { error: 'unauthorized' }],
      ['an empty bearer', { Authorization: 'Bearer ' }, 401, { error: 'unauthorized' }],
      ['a bearer with a same-origin claim', { Authorization: 'Bearer anything', 'Sec-Fetch-Site': 'same-origin' }, 200, []],
    ]
    for (const [name, headers, status, body] of cases) {
      const r = await rawGet(port, '/ice-servers', { ...fly, ...headers })
      assert.equal(r.status, status, name)
      assert.deepEqual(r.body, body, name)
      assert.equal(r.headers['cache-control'], 'no-store', name)
      assert.equal(r.headers['access-control-allow-origin'], undefined, name)
    }
    const health = await rawGet(port, '/health', fly)
    assert.equal(health.status, 200)
    assert.deepEqual(health.body, { status: 'ok', peers: 0 })
    assert.equal((await rawGet(port, '/nope', fly)).status, 404)
    assert.equal((await rawGet(port, '/ice-servers', fly, 'POST')).status, 404)
    const pre = await rawGet(port, '/ice-servers', { ...fly, Origin: 'https://app.example' }, 'OPTIONS')
    assert.equal(pre.status, 204)
    assert.equal(pre.headers['access-control-allow-origin'], undefined)
  })

  it('keeps the per-address limit, keyed by the proxy-supplied address', async () => {
    instance = createServer({ port: 0, env: { ...LIVE, ICE_RATE_LIMIT_PER_MINUTE: '2' } })
    const port = await instance.listen(0)
    const a = { 'Fly-Client-IP': '203.0.113.1' }
    const b = { 'Fly-Client-IP': '203.0.113.2' }
    assert.equal((await rawGet(port, '/ice-servers', a)).status, 401)
    assert.equal((await rawGet(port, '/ice-servers', a)).status, 401)
    assert.equal((await rawGet(port, '/ice-servers', a)).status, 429)
    assert.equal((await rawGet(port, '/ice-servers', b)).status, 401)
  })
})
