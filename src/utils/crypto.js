// Cryptographic helpers: symmetric encryption for connector credentials at
// rest, API-key generation/hashing, and HMAC signing for outbound webhooks.
import crypto from 'node:crypto';
import { config } from '../config.js';

const KEY = Buffer.from(config.encryptionKey, 'hex'); // 32 bytes
const ALGO = 'aes-256-gcm';

// Encrypt a UTF-8 string. Output: iv(12).authTag(16).ciphertext, base64.
// Used for connected-app secrets (their API keys) so a DB leak alone does
// not expose downstream credentials.
export function encrypt(plaintext) {
  if (plaintext == null || plaintext === '') return '';
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, KEY, iv);
  const ct = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString('base64');
}

export function decrypt(payload) {
  if (!payload) return '';
  try {
    const buf = Buffer.from(payload, 'base64');
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const ct = buf.subarray(28);
    const decipher = crypto.createDecipheriv(ALGO, KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString(
      'utf8'
    );
  } catch {
    // Tampered or key-rotated payload — return empty rather than throwing
    // so callers degrade gracefully (a missing credential is handled).
    return '';
  }
}

// A new tenant/connector API key. The plaintext is shown to the operator
// exactly once; only the SHA-256 hash is stored.
export function generateApiKey(prefix = 'gsa') {
  return `${prefix}_${crypto.randomBytes(24).toString('hex')}`;
}

export function hashApiKey(key) {
  return crypto.createHash('sha256').update(String(key)).digest('hex');
}

// ── Admin password hashing (scrypt) ──────────────────────────────────
// scrypt is memory-hard, so an offline cracker cannot trade memory for
// speed the way it can against a plain SHA-256. Each password gets its
// own 16-byte random salt; the stored form is `salt:derivedKey` in hex.
// N=2^15 is a sensible interactive cost for a login that runs rarely.
const SCRYPT_KEYLEN = 64;
const SCRYPT_PARAMS = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export function hashPassword(password) {
  if (!password) throw new Error('hashPassword() requires a password');
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(String(password), salt, SCRYPT_KEYLEN, SCRYPT_PARAMS);
  return `${salt.toString('hex')}:${dk.toString('hex')}`;
}

// Verify a password against a stored `salt:derivedKey` hash. The compare
// is constant-time so a timing side-channel cannot reveal how many bytes
// matched. A malformed stored value returns false rather than throwing.
export function verifyPassword(password, stored) {
  if (!password || !stored || typeof stored !== 'string') return false;
  const [saltHex, keyHex] = stored.split(':');
  if (!saltHex || !keyHex) return false;
  let salt, expected;
  try {
    salt = Buffer.from(saltHex, 'hex');
    expected = Buffer.from(keyHex, 'hex');
  } catch {
    return false;
  }
  if (salt.length !== 16 || expected.length !== SCRYPT_KEYLEN) return false;
  const actual = crypto.scryptSync(
    String(password), salt, SCRYPT_KEYLEN, SCRYPT_PARAMS
  );
  return crypto.timingSafeEqual(actual, expected);
}

// An opaque session token. The plaintext goes in the admin's cookie; only
// its SHA-256 hash is stored, so a leaked DB row cannot be replayed.
export function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

export function hashSessionToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

// Constant-time compare to avoid leaking match position via timing.
export function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// HMAC-SHA256 signature for an outbound webhook body. The receiver verifies
// with the same shared secret. Timestamp is folded in to bound replay.
export function signWebhook(secret, timestamp, body) {
  return crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${body}`)
    .digest('hex');
}

// Verify an INBOUND webhook (a connected app calling us). Rejects anything
// older than `toleranceSec` to bound replay attacks.
export function verifyInboundWebhook(
  secret,
  timestamp,
  body,
  signature,
  toleranceSec = 300
) {
  if (!secret || !timestamp || !signature) return false;
  const ts = parseInt(timestamp, 10);
  if (!Number.isFinite(ts)) return false;
  if (Math.abs(Date.now() / 1000 - ts) > toleranceSec) return false;
  const expected = signWebhook(secret, timestamp, body);
  return safeEqual(expected, signature);
}
