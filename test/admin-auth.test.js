// Admin authentication + the no-key console proxy.
//
// Two layers:
//   • Unit  — password hashing (scrypt), TOTP (RFC 6238), and the admin /
//             session / settings DB ops, against a throwaway SQLite file.
//   • HTTP  — the real server in a child process: first-run setup, the
//             two-step password + 2FA login, account lockout, the Settings
//             tenant-key control, and the headline behaviour — that the
//             console connects with NO API key once a proxy tenant is set,
//             and is refused (not crashed) before one is.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

// ── Unit layer ───────────────────────────────────────────────────────
// Isolated DB file, env set before importing the db module (same pattern
// as tenant-isolation.test.js).
process.env.DB_PATH = path.join(os.tmpdir(), `gsa-admin-test-${Date.now()}.db`);
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.SESSION_SECRET = 'd'.repeat(64);

let crypto, totp, dbmod, migrate;

before(async () => {
  crypto = await import('../src/utils/crypto.js');
  totp = await import('../src/utils/totp.js');
  ({ migrate } = await import('../src/db/migrate.js'));
  dbmod = await import('../src/db/index.js');
  migrate({ silent: true });
});

after(() => {
  try {
    fs.rmSync(process.env.DB_PATH, { force: true });
    fs.rmSync(process.env.DB_PATH + '-wal', { force: true });
    fs.rmSync(process.env.DB_PATH + '-shm', { force: true });
  } catch {
    /* best-effort cleanup */
  }
});

test('scrypt password hash verifies the right password and rejects others', () => {
  const hash = crypto.hashPassword('correct horse battery staple');
  assert.ok(hash.includes(':'), 'stored form is salt:key');
  assert.equal(crypto.verifyPassword('correct horse battery staple', hash), true);
  assert.equal(crypto.verifyPassword('wrong password entirely', hash), false);
  // A malformed stored value must fail closed, not throw.
  assert.equal(crypto.verifyPassword('x', 'not-a-valid-hash'), false);
});

test('the same password hashed twice yields different salts (and hashes)', () => {
  const a = crypto.hashPassword('repeated-password-value');
  const b = crypto.hashPassword('repeated-password-value');
  assert.notEqual(a, b, 'random salt makes each hash unique');
  // ...yet both still verify.
  assert.equal(crypto.verifyPassword('repeated-password-value', a), true);
  assert.equal(crypto.verifyPassword('repeated-password-value', b), true);
});

test('session tokens hash deterministically and uniquely', () => {
  const t1 = crypto.generateSessionToken();
  const t2 = crypto.generateSessionToken();
  assert.notEqual(t1, t2, 'tokens are random');
  assert.equal(
    crypto.hashSessionToken(t1),
    crypto.hashSessionToken(t1),
    'hashing is deterministic'
  );
  assert.notEqual(crypto.hashSessionToken(t1), crypto.hashSessionToken(t2));
});

test('TOTP — a code generated for a secret verifies against it', () => {
  const secret = totp.generateSecret();
  const code = totp.generate(secret);
  assert.match(code, /^\d{6}$/, 'a 6-digit code');
  assert.equal(totp.verify(secret, code), true, 'the current code verifies');
});

test('TOTP — a wrong code and a different secret are rejected', () => {
  const secret = totp.generateSecret();
  const wrong = totp.generate(secret) === '000000' ? '111111' : '000000';
  assert.equal(totp.verify(secret, wrong), false);
  // A code from a different secret must not verify.
  const other = totp.generateSecret();
  assert.equal(totp.verify(secret, totp.generate(other)), false);
  // Non-6-digit input is rejected outright.
  assert.equal(totp.verify(secret, '12345'), false);
  assert.equal(totp.verify(secret, 'abcdef'), false);
});

test('TOTP — a ±1 step clock skew still verifies', () => {
  const secret = totp.generateSecret();
  const now = Date.now();
  // A code from the previous 30s step verifies at "now".
  const prev = totp.generate(secret, now - 30_000);
  assert.equal(totp.verify(secret, prev, now), true, 'previous step accepted');
  // A code two steps away does NOT.
  const stale = totp.generate(secret, now - 90_000);
  assert.equal(totp.verify(secret, stale, now), false, 'two steps is too far');
});

test('TOTP — otpauth URI carries the secret and issuer', () => {
  const secret = totp.generateSecret();
  const uri = totp.otpauthUri(secret, { label: 'admin', issuer: 'GSA Test' });
  assert.ok(uri.startsWith('otpauth://totp/'), 'is an otpauth URI');
  assert.ok(uri.includes(`secret=${secret}`), 'embeds the secret');
  assert.ok(uri.includes('issuer=GSA+Test'), 'embeds the issuer');
});

test('admin DB ops — create, look up, enroll, password change', () => {
  const { admins, uuid } = dbmod;
  const id = uuid();
  admins.create({
    id,
    username: 'unit-admin',
    passwordHash: crypto.hashPassword('unit-admin-password'),
  });
  assert.ok(admins.count() >= 1);
  const byName = admins.getByUsername('unit-admin');
  assert.equal(byName.id, id);
  assert.equal(byName.totp_enrolled, 0, 'not enrolled until a code verifies');

  // Enrollment: store the secret, then mark enrolled.
  const secret = totp.generateSecret();
  admins.setTotpSecret(id, crypto.encrypt(secret));
  admins.markTotpEnrolled(id);
  assert.equal(admins.getById(id).totp_enrolled, 1);
  // The stored secret round-trips through decrypt.
  assert.equal(crypto.decrypt(admins.getById(id).totp_secret_enc), secret);

  // Password change.
  admins.setPassword(id, crypto.hashPassword('a-new-password-value'));
  assert.equal(
    crypto.verifyPassword('a-new-password-value', admins.getById(id).password_hash),
    true
  );
});

test('admin DB ops — failed-login counter locks the account at the threshold', () => {
  const { admins, uuid } = dbmod;
  const id = uuid();
  admins.create({
    id,
    username: 'lockout-admin',
    passwordHash: crypto.hashPassword('lockout-admin-password'),
  });
  let res;
  for (let i = 0; i < 3; i++) {
    res = admins.recordFailedLogin(id, { threshold: 3, lockMs: 60_000 });
  }
  assert.equal(res.failed, 3);
  assert.ok(res.lockedUntil, 'locked once the threshold is reached');
  assert.ok(
    new Date(res.lockedUntil).getTime() > Date.now(),
    'lock is in the future'
  );
  // A success clears the counter and the lock.
  admins.recordSuccess(id);
  const after = admins.getById(id);
  assert.equal(after.failed_logins, 0);
  assert.equal(after.locked_until, null);
});

test('session DB ops — create, find by hash, promote, expire, delete', () => {
  const { adminSessions, admins, uuid } = dbmod;
  const adminId = uuid();
  admins.create({
    id: adminId,
    username: 'session-admin',
    passwordHash: crypto.hashPassword('session-admin-password'),
  });
  const token = crypto.generateSessionToken();
  const tokenHash = crypto.hashSessionToken(token);
  adminSessions.create({
    id: uuid(),
    adminId,
    tokenHash,
    stage: 'pending2fa',
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  const found = adminSessions.findByTokenHash(tokenHash);
  assert.ok(found, 'a live session is found');
  assert.equal(found.stage, 'pending2fa');

  // Promote to full.
  adminSessions.promoteToFull(found.id);
  assert.equal(adminSessions.findByTokenHash(tokenHash).stage, 'full');

  // An expired session is treated as absent (and swept).
  const expiredToken = crypto.generateSessionToken();
  const expiredHash = crypto.hashSessionToken(expiredToken);
  adminSessions.create({
    id: uuid(),
    adminId,
    tokenHash: expiredHash,
    stage: 'full',
    expiresAt: new Date(Date.now() - 1000).toISOString(),
  });
  assert.equal(
    adminSessions.findByTokenHash(expiredHash),
    null,
    'an expired session does not resolve'
  );

  // Delete-all drops every session for the admin.
  adminSessions.deleteAllForAdmin(adminId);
  assert.equal(adminSessions.findByTokenHash(tokenHash), null);
});

test('settings DB ops — set, get, and overwrite a key', () => {
  const { settings } = dbmod;
  assert.equal(settings.get('nonexistent_key'), null);
  settings.set('proxy_tenant_id', 'tenant-aaa');
  assert.equal(settings.get('proxy_tenant_id'), 'tenant-aaa');
  // Overwrite.
  settings.set('proxy_tenant_id', 'tenant-bbb');
  assert.equal(settings.get('proxy_tenant_id'), 'tenant-bbb');
  assert.ok(settings.updatedAt('proxy_tenant_id'), 'records an updated_at');
});

// ── HTTP layer ───────────────────────────────────────────────────────
// Boots the real server in a child process with its own DB. Drives the
// admin + proxy flow over HTTP and asserts the end-to-end behaviour.

const PORT = 4196;

function request(method, urlPath, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      {
        host: '127.0.0.1',
        port: PORT,
        method,
        path: urlPath,
        headers: {
          'Content-Type': 'application/json',
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
          ...headers,
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: data ? JSON.parse(data) : {},
          })
        );
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Pull the gsa_admin cookie value out of a Set-Cookie header.
function cookieFrom(res) {
  const sc = res.headers['set-cookie'];
  if (!sc) return null;
  for (const line of sc) {
    const m = line.match(/gsa_admin=([^;]+)/);
    if (m) return m[1];
  }
  return null;
}

test('HTTP — admin setup, 2FA login, and the no-key console proxy', async (t) => {
  const dbPath = path.join(os.tmpdir(), `gsa-admin-http-${Date.now()}.db`);
  const server = spawn(process.execPath, ['src/server.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      DB_PATH: dbPath,
      PORT: String(PORT),
      NODE_ENV: 'development',
      ENCRYPTION_KEY: 'a'.repeat(64),
      SESSION_SECRET: 'b'.repeat(64),
      BOOTSTRAP_TENANT_NAME: 'Admin HTTP Tenant',
      // No ADMIN_USERNAME/PASSWORD — exercise the first-run /setup path.
      ADMIN_USERNAME: '',
      ADMIN_PASSWORD: '',
      // This test makes many /api/admin/* calls in quick succession; raise
      // the per-IP admin rate limit so the network limiter does not mask
      // the behaviour under test. The account-lockout test below still
      // verifies the per-account limit, which is the real defence.
      ADMIN_AUTH_RATE_LIMIT_PER_MIN: '500',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  // Capture the bootstrap tenant key (the key an admin pastes in Settings).
  let bootstrapKey = null;
  let out = '';
  server.stdout.on('data', (d) => {
    out += d.toString();
    const m = out.match(/API key\s*:\s*(gsa_[a-f0-9]+)/);
    if (m) bootstrapKey = m[1];
  });
  server.stderr.on('data', (d) => process.stderr.write(`  [server] ${d}`));

  try {
    // Wait for the port.
    let up = false;
    for (let i = 0; i < 60 && !up; i++) {
      try {
        await request('GET', '/health');
        up = true;
      } catch {
        await sleep(150);
      }
    }
    assert.ok(up, 'server started');
    for (let i = 0; i < 20 && !bootstrapKey; i++) await sleep(100);
    assert.ok(bootstrapKey, 'captured the bootstrap tenant key');

    await t.test('before any admin: /state reports needs_setup', async () => {
      const res = await request('GET', '/api/admin/state');
      assert.equal(res.status, 200);
      assert.equal(res.body.needs_setup, true);
      assert.equal(res.body.authenticated, false);
    });

    await t.test('before a proxy tenant is set: the console is refused with 503', async () => {
      // A no-key /api request is the public console. With no proxy tenant
      // configured it must be refused cleanly — not a 500, not a leak.
      const res = await request('GET', '/api/connectors');
      assert.equal(res.status, 503);
      assert.equal(res.body.code, 'not_configured');
    });

    await t.test('Settings is gated: /api/admin/session needs a session', async () => {
      const res = await request('GET', '/api/admin/session');
      assert.equal(res.status, 401);
    });

    // ── First-run setup ──
    let adminCookie = null;
    let totpSecret = null;

    await t.test('setup rejects a too-short password', async () => {
      const res = await request('POST', '/api/admin/setup', {
        body: { username: 'httpadmin', password: 'short' },
      });
      assert.equal(res.status, 400);
    });

    await t.test('setup creates the admin and returns a 2FA secret', async () => {
      const res = await request('POST', '/api/admin/setup', {
        body: { username: 'httpadmin', password: 'a-strong-password-1' },
      });
      assert.equal(res.status, 201);
      assert.ok(res.body.otpauth_uri?.startsWith('otpauth://'));
      assert.ok(res.body.manual_key, 'returns the manual key');
      totpSecret = res.body.manual_key;
      adminCookie = cookieFrom(res);
      assert.ok(adminCookie, 'a session cookie is set');
    });

    await t.test('a pending2fa session cannot yet reach Settings', async () => {
      // The password step is done but 2FA is not — /session must still 401.
      const res = await request('GET', '/api/admin/session', {
        headers: { Cookie: `gsa_admin=${adminCookie}` },
      });
      assert.equal(res.status, 401, 'half-authenticated session is not full');
    });

    await t.test('setup/verify rejects a wrong code', async () => {
      const res = await request('POST', '/api/admin/setup/verify', {
        headers: { Cookie: `gsa_admin=${adminCookie}` },
        body: { code: '000000' },
      });
      assert.equal(res.status, 401);
    });

    await t.test('setup/verify with the right code completes enrollment', async () => {
      const code = totp.generate(totpSecret);
      const res = await request('POST', '/api/admin/setup/verify', {
        headers: { Cookie: `gsa_admin=${adminCookie}` },
        body: { code },
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.ok, true);
    });

    await t.test('the session is now full — Settings is reachable', async () => {
      const res = await request('GET', '/api/admin/session', {
        headers: { Cookie: `gsa_admin=${adminCookie}` },
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.admin.username, 'httpadmin');
      assert.equal(res.body.proxy_tenant.configured, false);
    });

    await t.test('/setup is closed once an admin exists', async () => {
      const res = await request('POST', '/api/admin/setup', {
        body: { username: 'second', password: 'another-strong-pass-1' },
      });
      assert.equal(res.status, 409, 'no second admin can self-create');
    });

    // ── Set the proxy tenant key ──
    await t.test('setting the tenant key rejects a bad key', async () => {
      const res = await request('PUT', '/api/admin/tenant-key', {
        headers: { Cookie: `gsa_admin=${adminCookie}` },
        body: { api_key: 'gsa_definitely_not_real' },
      });
      assert.equal(res.status, 400);
    });

    await t.test('setting the tenant key with the real key succeeds', async () => {
      const res = await request('PUT', '/api/admin/tenant-key', {
        headers: { Cookie: `gsa_admin=${adminCookie}` },
        body: { api_key: bootstrapKey },
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.proxy_tenant.configured, true);
    });

    // ── The headline behaviour ──
    await t.test('the console now connects with NO API key', async () => {
      // The exact request the browser console makes — no Authorization
      // header, no cookie — now succeeds, proxied through the configured
      // tenant. This is "enter the key once, connected everywhere".
      const res = await request('GET', '/api/connectors');
      assert.equal(res.status, 200, 'no-key request is accepted');
      assert.ok(Array.isArray(res.body.connectors));
    });

    await t.test('an explicit valid key still works (REST API unchanged)', async () => {
      const res = await request('GET', '/api/connectors', {
        headers: { Authorization: `Bearer ${bootstrapKey}` },
      });
      assert.equal(res.status, 200);
    });

    await t.test('an explicit INVALID key is still rejected with 401', async () => {
      const res = await request('GET', '/api/connectors', {
        headers: { Authorization: 'Bearer gsa_invalid_key_value' },
      });
      assert.equal(res.status, 401);
    });

    // ── Logout + login round-trip ──
    await t.test('logout clears the session', async () => {
      const res = await request('POST', '/api/admin/logout', {
        headers: { Cookie: `gsa_admin=${adminCookie}` },
      });
      assert.equal(res.status, 200);
      // The old cookie no longer resolves to a session.
      const after = await request('GET', '/api/admin/session', {
        headers: { Cookie: `gsa_admin=${adminCookie}` },
      });
      assert.equal(after.status, 401);
    });

    await t.test('login is a two-step password + 2FA flow', async () => {
      // Step 1 — password. Wrong password first.
      const bad = await request('POST', '/api/admin/login', {
        body: { username: 'httpadmin', password: 'wrong-password' },
      });
      assert.equal(bad.status, 401);

      // Correct password → a pending2fa session.
      const step1 = await request('POST', '/api/admin/login', {
        body: { username: 'httpadmin', password: 'a-strong-password-1' },
      });
      assert.equal(step1.status, 200);
      assert.equal(step1.body.stage, '2fa');
      const cookie = cookieFrom(step1);
      assert.ok(cookie);

      // That pending session cannot reach Settings yet.
      const mid = await request('GET', '/api/admin/session', {
        headers: { Cookie: `gsa_admin=${cookie}` },
      });
      assert.equal(mid.status, 401);

      // Step 2 — the TOTP code promotes it to a full session.
      const step2 = await request('POST', '/api/admin/verify-2fa', {
        headers: { Cookie: `gsa_admin=${cookie}` },
        body: { code: totp.generate(totpSecret) },
      });
      assert.equal(step2.status, 200);

      const ok = await request('GET', '/api/admin/session', {
        headers: { Cookie: `gsa_admin=${cookie}` },
      });
      assert.equal(ok.status, 200);
      assert.equal(ok.body.admin.username, 'httpadmin');
    });

    await t.test('repeated wrong passwords lock the account', async () => {
      // Default ADMIN_MAX_FAILED_LOGINS is 5. Burn through them.
      let last;
      for (let i = 0; i < 5; i++) {
        last = await request('POST', '/api/admin/login', {
          body: { username: 'httpadmin', password: `wrong-${i}` },
        });
      }
      // The 5th failure should report the lock.
      assert.equal(last.status, 429);
      assert.equal(last.body.code, 'locked');
      // Even the CORRECT password is now refused while locked.
      const correct = await request('POST', '/api/admin/login', {
        body: { username: 'httpadmin', password: 'a-strong-password-1' },
      });
      assert.equal(correct.status, 429, 'lock holds against the right password');
    });
  } finally {
    server.kill('SIGTERM');
    // Give the child a moment to release the DB file before cleanup.
    await sleep(200);
    for (const suffix of ['', '-wal', '-shm']) {
      try {
        fs.rmSync(dbPath + suffix, { force: true });
      } catch {
        /* best-effort */
      }
    }
  }
});
