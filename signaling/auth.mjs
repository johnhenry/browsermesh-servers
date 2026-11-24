/**
 * Registration proof for the signaling server's authenticated mode
 * (protocol 2).
 *
 * The server sends every new connection a challenge:
 *
 *   { type: 'challenge', protocol: 2, purpose: 'register', origin, nonce, ttlMs }
 *
 * The client answers with
 *
 *   { type: 'register', protocol: 2, podId, pubKey, nonce, signature }
 *
 * where `pubKey` is the raw 32-byte Ed25519 public key and `signature` is its
 * signature over `registrationMessage({ purpose, origin, podId, nonce })`.
 * The server accepts only when
 *
 *   - `nonce` is the one it issued on this connection, unused and unexpired,
 *   - `podId` is exactly base64url(SHA-256(pubKey)) -- the same derivation as
 *     `PodIdentity` in @johnhenry/browsermesh-primitives,
 *   - the signature verifies over the string above with the server's own
 *     configured origin.
 *
 * `origin` is the signalling server's `ws://` / `wss://` origin as the client
 * knows it (its own configured URL), never taken from the challenge: that is
 * what stops a server that relays a client's proof to a different server from
 * being accepted there.
 */

import { createHash, webcrypto } from 'node:crypto'

export const PROTOCOL_VERSION = 2
export const REGISTER_PURPOSE = 'register'
export const SIGNED_PREFIX = 'browsermesh-signaling/2'

const POD_ID_RE = /^[A-Za-z0-9_-]{43}$/
const B64_STD_RE = /^[A-Za-z0-9+/]+={0,2}$/
const B64_URL_RE = /^[A-Za-z0-9_-]+$/

function assertField(name, v) {
  if (typeof v !== 'string' || v.length === 0 || /[\r\n]/.test(v)) {
    throw new TypeError(`${name} must be a non-empty string without line breaks`)
  }
}

/**
 * The exact bytes (as a string, UTF-8 encoded for signing) a client signs to
 * register. One field per line; no field may contain a line break, so fields
 * cannot shift into each other.
 *
 * @param {{ purpose: string, origin: string, podId: string, nonce: string }} f
 * @returns {string}
 */
export function registrationMessage({ purpose, origin, podId, nonce }) {
  assertField('purpose', purpose)
  assertField('origin', origin)
  assertField('podId', podId)
  assertField('nonce', nonce)
  return `${SIGNED_PREFIX}\npurpose:${purpose}\norigin:${origin}\npodId:${podId}\nnonce:${nonce}`
}

/**
 * Pod id of a raw Ed25519 public key: base64url(SHA-256(raw key)), 43 chars.
 * @param {Uint8Array} rawPublicKey
 * @returns {string}
 */
export function derivePodId(rawPublicKey) {
  return createHash('sha256').update(rawPublicKey).digest('base64url')
}

/** True for a syntactically valid pod id (43 base64url characters). */
export function isPodId(v) {
  return typeof v === 'string' && POD_ID_RE.test(v)
}

/**
 * Strictly decode base64 (standard, padded or not) or base64url to exactly
 * `length` bytes. Returns null for anything else: other alphabets, stray
 * characters, non-canonical encodings, wrong length.
 *
 * @param {unknown} s
 * @param {number} length
 * @returns {Uint8Array|null}
 */
export function decodeExact(s, length) {
  if (typeof s !== 'string' || s.length > 4 * length) return null
  let buf
  if (B64_STD_RE.test(s)) buf = Buffer.from(s, 'base64')
  else if (B64_URL_RE.test(s)) buf = Buffer.from(s, 'base64url')
  else return null
  if (buf.length !== length) return null
  // Canonical form only: the bytes must encode back to the same text.
  const again = B64_STD_RE.test(s) ? buf.toString('base64') : buf.toString('base64url')
  if (again.replace(/=+$/, '') !== s.replace(/=+$/, '')) return null
  return new Uint8Array(buf)
}

/**
 * Verify a protocol 2 registration. The nonce and its lifetime are the
 * caller's to check (they live on the connection); this checks the key, the
 * id binding and the signature.
 *
 * @param {object} p
 * @param {unknown} p.podId
 * @param {unknown} p.pubKey
 * @param {unknown} p.signature
 * @param {string} p.nonce       — the nonce the server issued
 * @param {string} p.origin      — the server's own origin
 * @returns {Promise<{ ok: true } | { ok: false, code: string, message: string }>}
 */
export async function verifyRegistration({ podId, pubKey, signature, nonce, origin }) {
  if (!isPodId(podId)) {
    return { ok: false, code: 'bad-pod-id', message: 'podId must be the 43-character base64url hash of your public key' }
  }
  const rawKey = decodeExact(pubKey, 32)
  if (!rawKey) return { ok: false, code: 'bad-key', message: 'pubKey must be a 32-byte Ed25519 public key in base64' }
  const sig = decodeExact(signature, 64)
  if (!sig) return { ok: false, code: 'bad-signature', message: 'signature must be a 64-byte Ed25519 signature in base64' }

  // Exact comparison of the claimed id with the id of the key being proven.
  if (derivePodId(rawKey) !== podId) {
    return { ok: false, code: 'pod-id-mismatch', message: 'podId is not the hash of pubKey' }
  }

  try {
    const key = await webcrypto.subtle.importKey('raw', rawKey, { name: 'Ed25519' }, false, ['verify'])
    const data = new TextEncoder().encode(registrationMessage({ purpose: REGISTER_PURPOSE, origin, podId, nonce }))
    const valid = await webcrypto.subtle.verify('Ed25519', key, sig, data)
    if (!valid) return { ok: false, code: 'bad-signature', message: 'signature verification failed' }
  } catch {
    return { ok: false, code: 'bad-key', message: 'public key rejected' }
  }
  return { ok: true }
}
