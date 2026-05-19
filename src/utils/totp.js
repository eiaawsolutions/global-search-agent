// TOTP — time-based one-time passwords (RFC 6238) for admin 2FA.
//
// Dependency-free: built entirely on Node's crypto.createHmac. This is the
// same algorithm Google Authenticator / Authy / 1Password / Microsoft
// Authenticator implement, so an admin can enroll with any of them.
//
// The flow:
//   1. generateSecret()  → a fresh base32 secret (stored AES-256-GCM encrypted)
//   2. otpauthUri()      → an otpauth:// URI; the Settings page renders it as a
//                          QR code the admin scans into their authenticator
//   3. verify(secret, code) → checks a 6-digit code, with a ±1 step window so a
//                          small clock skew between phone and server still works
import crypto from 'node:crypto';

// RFC 4648 base32 alphabet (authenticator apps expect this, no padding).
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const STEP_SECONDS = 30; // RFC 6238 default period
const DIGITS = 6;        // 6-digit code — the universal authenticator default
const SKEW_STEPS = 1;    // accept the previous/next step too (±30s clock drift)

// Encode bytes to a base32 string (uppercase, no padding).
function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

// Decode a base32 string back to a Buffer. Whitespace and padding are
// tolerated; an out-of-alphabet character makes the secret invalid.
function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[\s=]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('Invalid base32 character in TOTP secret.');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

// A fresh 20-byte (160-bit) secret, returned base32-encoded. 160 bits is the
// RFC 4226 recommended HOTP/TOTP key length.
export function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

// The HOTP value for a given counter (RFC 4226 §5.3) — the building block
// TOTP layers a time counter on top of.
function hotp(secretBuf, counter) {
  const counterBuf = Buffer.alloc(8);
  // 64-bit big-endian counter. Bit 31 of the high word is never set for any
  // realistic timestamp, so a plain 32-bit write of the low word is safe.
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter >>> 0, 4);
  const digest = crypto.createHmac('sha1', secretBuf).update(counterBuf).digest();
  // Dynamic truncation (RFC 4226 §5.3).
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0');
}

// The current TOTP code for a base32 secret. Mainly used by tests — a real
// authenticator app produces this for the admin.
export function generate(base32Secret, atMs = Date.now()) {
  const counter = Math.floor(atMs / 1000 / STEP_SECONDS);
  return hotp(base32Decode(base32Secret), counter);
}

// Verify a 6-digit code against a base32 secret. Accepts the current step
// plus one step either side (±30s) to absorb clock drift. The compare is
// constant-time so a timing side-channel cannot leak digit-by-digit matches.
// A non-6-digit input is rejected outright — no crypto work, no timing edge.
export function verify(base32Secret, code, atMs = Date.now()) {
  const normalized = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(normalized)) return false;
  let secretBuf;
  try {
    secretBuf = base32Decode(base32Secret);
  } catch {
    return false;
  }
  if (secretBuf.length === 0) return false;
  const counter = Math.floor(atMs / 1000 / STEP_SECONDS);
  for (let w = -SKEW_STEPS; w <= SKEW_STEPS; w++) {
    const candidate = hotp(secretBuf, counter + w);
    // Both strings are the same fixed length, so timingSafeEqual is safe.
    if (
      crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(normalized))
    ) {
      return true;
    }
  }
  return false;
}

// Build the otpauth:// URI an authenticator app imports. `label` shows under
// the account in the app (e.g. the admin username); `issuer` names the
// service. Both are percent-encoded so spaces / punctuation are safe.
export function otpauthUri(base32Secret, { label, issuer }) {
  const safeIssuer = encodeURIComponent(issuer || 'Global Search Agent');
  const safeLabel = encodeURIComponent(label || 'admin');
  const params = new URLSearchParams({
    secret: base32Secret,
    issuer: issuer || 'Global Search Agent',
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  });
  return `otpauth://totp/${safeIssuer}:${safeLabel}?${params.toString()}`;
}
