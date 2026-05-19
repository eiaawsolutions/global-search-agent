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
