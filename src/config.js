// Central configuration. Reads .env once at import time and validates the
// security-critical values up front so the process fails fast instead of
// halfway through a request with a confusing error.
import 'dotenv/config';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

function required(name, fallbackForDev) {
  const v = process.env[name];
  if (v && v.trim()) return v.trim();
  if (process.env.NODE_ENV !== 'production' && fallbackForDev !== undefined) {
    return fallbackForDev;
  }
  throw new Error(
    `Missing required env var ${name}. Copy .env.example to .env and set it.`
  );
}

// In dev we synthesize ephemeral secrets so the app boots with zero setup.
// In production both MUST be provided — required() throws otherwise.
const devKey = () => crypto.randomBytes(32).toString('hex');

export const config = {
  root: ROOT,
  port: parseInt(process.env.PORT || '4100', 10),
  env: process.env.NODE_ENV || 'development',
  isProd: process.env.NODE_ENV === 'production',

  dbPath: path.isAbsolute(process.env.DB_PATH || '')
    ? process.env.DB_PATH
    : path.join(ROOT, process.env.DB_PATH || 'data/search-agent.db'),

  // 32-byte hex key → AES-256-GCM for connector credentials at rest.
  encryptionKey: required('ENCRYPTION_KEY', devKey()),
  sessionSecret: required('SESSION_SECRET', devKey()),

  bootstrapTenantName: process.env.BOOTSTRAP_TENANT_NAME || 'Demo Tenant',

  // Optional: pin the bootstrap tenant's API key and webhook secret instead
  // of letting migrate() generate random ones. Set these on a containerized
  // deploy (Railway / Cloud Run) so the credentials are known up front and
  // never lost in scrolled-away logs. If blank, migrate() generates them and
  // prints once. A pinned API key must be >= 24 chars.
  bootstrapApiKey: (process.env.BOOTSTRAP_API_KEY || '').trim(),
  bootstrapWebhookSecret: (process.env.BOOTSTRAP_WEBHOOK_SECRET || '').trim(),

  maxCsvBytes: parseInt(process.env.MAX_CSV_BYTES || '5242880', 10),
  maxCsvRows: parseInt(process.env.MAX_CSV_ROWS || '10000', 10),
  rateLimitPerMin: parseInt(process.env.RATE_LIMIT_PER_MIN || '120', 10),

  // ── Admin / Settings page ──────────────────────────────────────────
  // The Settings page (where the admin chooses which tenant key the public
  // app proxies with) is guarded by a username + password + mandatory TOTP
  // 2FA login. The FIRST admin is created in one of two ways:
  //   • ADMIN_USERNAME + ADMIN_PASSWORD set  → migrate() seeds the admin row
  //     on boot; the admin then completes a one-time 2FA enrollment at login.
  //   • neither set                          → the one-time /setup page
  //     handles first-run enrollment (username + password + 2FA QR).
  // Once an admin exists, /setup is permanently closed regardless of env.
  adminUsername: (process.env.ADMIN_USERNAME || '').trim(),
  adminPassword: process.env.ADMIN_PASSWORD || '',

  // Admin session lifetime — how long a Settings login stays valid before
  // re-authentication is required. Default 12h.
  adminSessionHours: parseInt(process.env.ADMIN_SESSION_HOURS || '12', 10),

  // Brute-force lockout: after this many consecutive failed admin logins the
  // account is locked for the window below. The per-IP API rate limiter is a
  // second, independent layer.
  adminMaxFailedLogins: parseInt(process.env.ADMIN_MAX_FAILED_LOGINS || '5', 10),
  adminLockMinutes: parseInt(process.env.ADMIN_LOCK_MINUTES || '15', 10),

  // A tighter per-IP rate limit specifically for the admin auth endpoints
  // (/api/admin/*) — login, 2FA, setup. Lower than the general API limit
  // because these are guessing targets. Counts every admin request, so keep
  // it comfortably above the handful a real login round-trip needs.
  adminAuthRateLimitPerMin: parseInt(
    process.env.ADMIN_AUTH_RATE_LIMIT_PER_MIN || '30',
    10
  ),

  // SSRF policy. Connectors pointing at private/loopback addresses are
  // refused by default. This escape hatch is for local development and CI
  // (sweeping a mock app on 127.0.0.1) ONLY — it is force-disabled in
  // production regardless of the env var, so it can never weaken a real
  // deployment.
  allowPrivateConnectors:
    process.env.NODE_ENV !== 'production' &&
    process.env.ALLOW_PRIVATE_CONNECTORS === 'true',
};

// Fail fast on a malformed encryption key — a wrong length here would only
// surface later as a cryptic GCM error deep inside a request.
if (Buffer.from(config.encryptionKey, 'hex').length !== 32) {
  throw new Error('ENCRYPTION_KEY must be 64 hex chars (32 bytes).');
}
