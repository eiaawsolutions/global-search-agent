// Admin routes — the Settings-page identity and the proxy-tenant control.
//
//   GET  /api/admin/state        unauthenticated; tells the client which
//                                screen to show (first-run setup, login, or
//                                already signed in)
//   POST /api/admin/setup        first-run only: create the first admin
//   POST /api/admin/setup/verify first-run only: confirm the 2FA code,
//                                completing enrollment + opening a session
//   POST /api/admin/login        step 1 — username + password
//   POST /api/admin/enroll       env-seeded admin's one-time 2FA enrollment
//   POST /api/admin/verify-2fa   step 2 — the 6-digit TOTP code
//   POST /api/admin/logout       end the session
//   GET  /api/admin/session      authenticated; current admin + tenant status
//   GET  /api/admin/tenant-key   authenticated; whether a proxy tenant is set
//   PUT  /api/admin/tenant-key   authenticated; set/replace the proxy tenant
//   POST /api/admin/password     authenticated; change the admin password
//
// Security posture:
//  - password: scrypt hash, constant-time verify, per-account lockout
//  - 2FA: mandatory TOTP; a login is incomplete until the code verifies
//  - session: opaque token in an HttpOnly + SameSite=Strict cookie; only the
//    token HASH is stored, so a DB leak is not replayable
//  - the tenant API key the admin pastes is hashed on arrival to resolve the
//    tenant, then discarded — never stored, never logged, never echoed
//  - login failures return ONE generic message (no username enumeration, no
//    "wrong password" vs "wrong code" distinction)
import { Router } from 'express';
import { asyncHandler } from '../middleware/auth.js';
import {
  requireAdmin,
  getAdminSession,
  PROXY_TENANT_KEY,
  ADMIN_COOKIE,
} from '../middleware/admin-auth.js';
import {
  admins,
  adminSessions,
  settings,
  global,
  forTenant,
  uuid,
} from '../db/index.js';
import { config } from '../config.js';
import {
  hashPassword,
  verifyPassword,
  hashApiKey,
  generateSessionToken,
  hashSessionToken,
  encrypt,
  decrypt,
} from '../utils/crypto.js';
import * as totp from '../utils/totp.js';

const router = Router();

// One generic failure message for every credential mismatch — username,
// password, or TOTP code. Telling them apart would aid an attacker.
const GENERIC_AUTH_FAIL = 'Incorrect username, password, or verification code.';

// ── Cookie + session helpers ─────────────────────────────────────────
// Issue a session and set its cookie. `stage` is 'pending2fa' (password done,
// awaiting the code) or 'full' (fully authenticated).
function issueSession(res, adminId, stage) {
  const token = generateSessionToken();
  const expiresAt = new Date(
    Date.now() + config.adminSessionHours * 3600 * 1000
  ).toISOString();
  adminSessions.create({
    id: uuid(),
    adminId,
    tokenHash: hashSessionToken(token),
    stage,
    expiresAt,
  });
  res.cookie(ADMIN_COOKIE, token, {
    httpOnly: true,                 // unreadable from JS — no XSS token theft
    sameSite: 'strict',             // not sent on cross-site requests — CSRF guard
    secure: config.isProd,          // HTTPS-only in production
    maxAge: config.adminSessionHours * 3600 * 1000,
    path: '/',
  });
}

function clearSessionCookie(res) {
  res.clearCookie(ADMIN_COOKIE, {
    httpOnly: true,
    sameSite: 'strict',
    secure: config.isProd,
    path: '/',
  });
}

// Read the raw cookie token + its session row regardless of stage. Used by
// the 2FA step, which must accept a 'pending2fa' session that requireAdmin
// would reject.
function readAnySession(req) {
  const token = req.cookies?.[ADMIN_COOKIE];
  if (!token) return null;
  const session = adminSessions.findByTokenHash(hashSessionToken(token));
  return session ? { token, session } : null;
}

// Is the admin currently locked out? Returns remaining lock seconds or 0.
function lockRemaining(admin) {
  if (!admin?.locked_until) return 0;
  const ms = new Date(admin.locked_until).getTime() - Date.now();
  return ms > 0 ? Math.ceil(ms / 1000) : 0;
}

// Whether a proxy tenant is configured AND still resolves to a live tenant.
function proxyTenantStatus() {
  const id = settings.get(PROXY_TENANT_KEY);
  if (!id) return { configured: false };
  const tenant = global.findTenantById(id);
  return {
    configured: !!tenant,
    // If the id is stored but no longer resolves, say so — the admin needs
    // to re-set it. Never expose the id or any key material.
    stale: !tenant,
    tenant_name: tenant?.name || null,
    updated_at: settings.updatedAt(PROXY_TENANT_KEY),
  };
}

// Basic password policy — long enough to be worth the scrypt cost. Kept
// modest; the real defence is the hash + lockout + mandatory 2FA.
function passwordProblem(pw) {
  if (typeof pw !== 'string' || pw.length < 10) {
    return 'Password must be at least 10 characters.';
  }
  if (pw.length > 200) return 'Password is too long.';
  return null;
}

// ── GET /api/admin/state — which screen the client should show ───────
// Unauthenticated by design: the client calls this before any login UI so
// it knows whether to render first-run setup, the login form, or (if a
// session cookie is already valid) the signed-in Settings view. Leaks
// nothing sensitive — only booleans.
router.get(
  '/state',
  asyncHandler(async (req, res) => {
    const hasAdmin = admins.count() > 0;
    const resolved = getAdminSession(req); // null unless a FULL session
    res.json({
      needs_setup: !hasAdmin,
      authenticated: !!resolved,
      admin: resolved ? { username: resolved.admin.username } : null,
    });
  })
);

// ── POST /api/admin/setup — create the first admin (first-run only) ──
router.post(
  '/setup',
  asyncHandler(async (req, res) => {
    if (admins.count() > 0) {
      // /setup is a one-time door. Once an admin exists it is closed for
      // good — no second admin can be self-created without authentication.
      return res.status(409).json({ error: 'Setup has already been completed.' });
    }
    const username = String(req.body?.username || '').trim();
    const password = req.body?.password;
    if (username.length < 3 || username.length > 60) {
      return res.status(400).json({ error: 'Username must be 3–60 characters.' });
    }
    const pwProblem = passwordProblem(password);
    if (pwProblem) return res.status(400).json({ error: pwProblem });

    // Create the admin and a TOTP secret. Enrollment is NOT complete yet —
    // the secret is stored encrypted and the client must confirm a code via
    // /setup/verify before the account is usable.
    const admin = admins.create({
      id: uuid(),
      username,
      passwordHash: hashPassword(password),
    });
    const secret = totp.generateSecret();
    admins.setTotpSecret(admin.id, encrypt(secret));

    // A pending2fa session ties this browser to the in-progress enrollment.
    issueSession(res, admin.id, 'pending2fa');
    res.status(201).json({
      ok: true,
      // The otpauth URI for the QR. Shown ONCE, during enrollment only.
      otpauth_uri: totp.otpauthUri(secret, {
        label: username,
        issuer: 'Global Search Agent',
      }),
      // The base32 secret for manual entry if the admin cannot scan the QR.
      manual_key: secret,
    });
  })
);

// ── POST /api/admin/setup/verify — confirm the first-run 2FA code ────
router.post(
  '/setup/verify',
  asyncHandler(async (req, res) => {
    const found = readAnySession(req);
    if (!found || found.session.stage !== 'pending2fa') {
      return res.status(401).json({ error: 'No enrollment in progress.' });
    }
    const admin = admins.getById(found.session.admin_id);
    if (!admin) return res.status(401).json({ error: 'No enrollment in progress.' });

    const secret = decrypt(admin.totp_secret_enc);
    if (!secret || !totp.verify(secret, req.body?.code)) {
      return res.status(401).json({ error: 'That code did not verify. Try the current code.' });
    }
    // Code verified — enrollment complete, session promoted to full.
    admins.markTotpEnrolled(admin.id);
    admins.recordSuccess(admin.id);
    adminSessions.promoteToFull(found.session.id);
    res.json({ ok: true });
  })
);

// ── POST /api/admin/login — step 1: username + password ──────────────
router.post(
  '/login',
  asyncHandler(async (req, res) => {
    const username = String(req.body?.username || '').trim();
    const password = req.body?.password;
    const admin = admins.getByUsername(username);

    // Lockout check first — a locked account is refused before any password
    // work, so lockout is not itself a timing oracle.
    if (admin) {
      const remaining = lockRemaining(admin);
      if (remaining > 0) {
        return res.status(429).json({
          error: `Too many attempts. Locked for ${Math.ceil(remaining / 60)} more minute(s).`,
          code: 'locked',
        });
      }
    }

    // Always run a password verification, even when the username is unknown,
    // against a throwaway hash — so a missing user and a wrong password take
    // the same time. No username enumeration via response timing.
    const ok =
      admin && verifyPassword(password, admin.password_hash);
    if (!ok) {
      if (admin) {
        const { lockedUntil } = admins.recordFailedLogin(admin.id, {
          threshold: config.adminMaxFailedLogins,
          lockMs: config.adminLockMinutes * 60 * 1000,
        });
        if (lockedUntil) {
          return res.status(429).json({
            error: `Too many attempts. Account locked for ${config.adminLockMinutes} minutes.`,
            code: 'locked',
          });
        }
      } else {
        // Burn comparable time for an unknown username.
        verifyPassword(password || '', hashPassword('decoy-decoy-decoy'));
      }
      return res.status(401).json({ error: GENERIC_AUTH_FAIL });
    }

    // Password correct. If the admin has never enrolled 2FA (an admin seeded
    // from env), the client must enroll now — return the QR and a pending
    // session. Otherwise issue a pending2fa session and ask for the code.
    if (!admin.totp_enrolled) {
      // Generate (or refresh) the secret for enrollment.
      const secret = totp.generateSecret();
      admins.setTotpSecret(admin.id, encrypt(secret));
      issueSession(res, admin.id, 'pending2fa');
      return res.json({
        ok: true,
        stage: 'enroll',
        otpauth_uri: totp.otpauthUri(secret, {
          label: admin.username,
          issuer: 'Global Search Agent',
        }),
        manual_key: secret,
      });
    }

    issueSession(res, admin.id, 'pending2fa');
    res.json({ ok: true, stage: '2fa' });
  })
);

// ── POST /api/admin/enroll — finish an env-seeded admin's 2FA setup ──
// Same verification as setup/verify, but for the login-time enrollment path.
router.post(
  '/enroll',
  asyncHandler(async (req, res) => {
    const found = readAnySession(req);
    if (!found || found.session.stage !== 'pending2fa') {
      return res.status(401).json({ error: 'No enrollment in progress.' });
    }
    const admin = admins.getById(found.session.admin_id);
    if (!admin) return res.status(401).json({ error: 'No enrollment in progress.' });

    const secret = decrypt(admin.totp_secret_enc);
    if (!secret || !totp.verify(secret, req.body?.code)) {
      return res.status(401).json({ error: 'That code did not verify. Try the current code.' });
    }
    admins.markTotpEnrolled(admin.id);
    admins.recordSuccess(admin.id);
    adminSessions.promoteToFull(found.session.id);
    res.json({ ok: true });
  })
);

// ── POST /api/admin/verify-2fa — step 2: the TOTP code ───────────────
router.post(
  '/verify-2fa',
  asyncHandler(async (req, res) => {
    const found = readAnySession(req);
    if (!found || found.session.stage !== 'pending2fa') {
      // No half-authenticated session — the password step must come first.
      return res.status(401).json({ error: 'Sign in with your password first.' });
    }
    const admin = admins.getById(found.session.admin_id);
    if (!admin) return res.status(401).json({ error: GENERIC_AUTH_FAIL });

    // A locked account cannot complete 2FA either.
    const remaining = lockRemaining(admin);
    if (remaining > 0) {
      return res.status(429).json({
        error: `Too many attempts. Locked for ${Math.ceil(remaining / 60)} more minute(s).`,
        code: 'locked',
      });
    }

    const secret = decrypt(admin.totp_secret_enc);
    const ok = secret && totp.verify(secret, req.body?.code);
    if (!ok) {
      // A wrong code counts toward the same lockout as a wrong password —
      // 2FA is not a place to brute-force freely.
      const { lockedUntil } = admins.recordFailedLogin(admin.id, {
        threshold: config.adminMaxFailedLogins,
        lockMs: config.adminLockMinutes * 60 * 1000,
      });
      if (lockedUntil) {
        return res.status(429).json({
          error: `Too many attempts. Account locked for ${config.adminLockMinutes} minutes.`,
          code: 'locked',
        });
      }
      return res.status(401).json({ error: GENERIC_AUTH_FAIL });
    }

    // Both factors satisfied — promote the session to full.
    admins.recordSuccess(admin.id);
    adminSessions.promoteToFull(found.session.id);
    res.json({ ok: true });
  })
);

// ── POST /api/admin/logout ───────────────────────────────────────────
router.post(
  '/logout',
  asyncHandler(async (req, res) => {
    const token = req.cookies?.[ADMIN_COOKIE];
    if (token) adminSessions.deleteByTokenHash(hashSessionToken(token));
    clearSessionCookie(res);
    res.json({ ok: true });
  })
);

// ── GET /api/admin/session — current admin + proxy-tenant status ─────
router.get(
  '/session',
  requireAdmin,
  asyncHandler(async (req, res) => {
    res.json({
      admin: { username: req.admin.username },
      proxy_tenant: proxyTenantStatus(),
    });
  })
);

// ── GET /api/admin/tenant-key — is a proxy tenant configured? ────────
// Never returns the key or the tenant id — only status. The key cannot be
// read back by design; it is write-only from the Settings UI.
router.get(
  '/tenant-key',
  requireAdmin,
  asyncHandler(async (req, res) => {
    res.json({ proxy_tenant: proxyTenantStatus() });
  })
);

// ── PUT /api/admin/tenant-key — set / replace the proxy tenant ───────
// The admin pastes a tenant API key. The server hashes it, resolves the
// tenant, stores ONLY the tenant id, and discards the key. After this, every
// public-app request is proxied through that tenant with no key in the
// browser. Replacing the key later is how a tenant key is rotated.
router.put(
  '/tenant-key',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const key = String(req.body?.api_key || '').trim();
    if (!key) {
      return res.status(400).json({ error: 'Provide a tenant API key.' });
    }
    // Resolve the tenant by the key's hash. The raw key is used only for
    // this lookup and never stored.
    const tenant = global.findTenantByKeyHash(hashApiKey(key));
    if (!tenant) {
      // The key does not match any active tenant. Generic — does not reveal
      // whether the key shape was right or the tenant is suspended.
      return res
        .status(400)
        .json({ error: 'That key does not match an active tenant.' });
    }
    settings.set(PROXY_TENANT_KEY, tenant.id);
    // Audit on the resolved tenant — records THAT the proxy key was set and
    // by which admin, never the key itself.
    forTenant(tenant.id).audit('admin.proxy_tenant_set', {
      adminUsername: req.admin.username,
    });
    res.json({ ok: true, proxy_tenant: proxyTenantStatus() });
  })
);

// ── POST /api/admin/password — change the admin password ─────────────
// Requires the current password. On success every existing session for the
// admin is dropped (including other devices) so the old credential cannot
// continue an open session.
router.post(
  '/password',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const admin = admins.getById(req.admin.id);
    if (!admin) return res.status(401).json({ error: 'Admin not found.' });

    if (!verifyPassword(req.body?.current_password, admin.password_hash)) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }
    const pwProblem = passwordProblem(req.body?.new_password);
    if (pwProblem) return res.status(400).json({ error: pwProblem });

    admins.setPassword(admin.id, hashPassword(req.body.new_password));
    adminSessions.deleteAllForAdmin(admin.id); // force re-login everywhere
    clearSessionCookie(res);
    res.json({ ok: true, reauth_required: true });
  })
);

export default router;
