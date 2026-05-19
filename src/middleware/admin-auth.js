// Admin authentication + the public-app proxy.
//
// This file holds the two middlewares that make "the admin configures the
// tenant key once, everyone else is connected automatically" work:
//
//   requireAdmin
//     Guards the Settings page and /api/admin/*. A request passes only with
//     a valid, FULLY authenticated admin session cookie — i.e. the password
//     AND the TOTP 2FA step both completed. A 'pending2fa' session (password
//     done, code not yet entered) does NOT pass.
//
//   resolveTenant
//     Replaces the old requireApiKey on /api. It resolves req.repo from one
//     of two sources, in order:
//       1. An explicit API key in the request (Authorization: Bearer / the
//          X-API-Key header) — the original behaviour, kept so the REST API,
//          signed webhooks, tests, and the vistage scripts all keep working.
//       2. NO key present → the admin-configured proxy tenant. This is the
//          public browser console: it sends no credential, and the server
//          attaches the tenant the admin selected in Settings. The tenant
//          API key itself is never sent to the browser.
//     If neither yields a tenant, the request is refused — and when the
//     cause is "no proxy tenant configured yet", the error is specific so
//     the UI can show a clear "ask an administrator to set this up" state.
import {
  global,
  forTenant,
  adminSessions,
  admins,
  settings,
} from '../db/index.js';
import { hashApiKey, hashSessionToken } from '../utils/crypto.js';

// The app_settings key under which the proxy tenant id is stored.
export const PROXY_TENANT_KEY = 'proxy_tenant_id';
// The admin session cookie name.
export const ADMIN_COOKIE = 'gsa_admin';

// Extract a presented API key from the standard places (unchanged from the
// original auth middleware).
function extractKey(req) {
  const auth = req.get('authorization');
  if (auth && /^bearer\s+/i.test(auth)) {
    return auth.replace(/^bearer\s+/i, '').trim();
  }
  const x = req.get('x-api-key');
  if (x) return x.trim();
  return null;
}

// Resolve the admin session attached to a request, or null. Returns the
// session row plus its admin only when the session is present, unexpired,
// and at the 'full' stage. A 'pending2fa' session resolves to null here —
// callers that need the half-authenticated session read the cookie directly.
export function getAdminSession(req) {
  const token = req.cookies?.[ADMIN_COOKIE];
  if (!token) return null;
  const session = adminSessions.findByTokenHash(hashSessionToken(token));
  if (!session || session.stage !== 'full') return null;
  const admin = admins.getById(session.admin_id);
  if (!admin) return null;
  return { session, admin };
}

// Guard for the Settings page and /api/admin/* mutation routes. Requires a
// fully authenticated (password + 2FA) admin session.
export function requireAdmin(req, res, next) {
  const resolved = getAdminSession(req);
  if (!resolved) {
    return res.status(401).json({ error: 'Admin authentication required.' });
  }
  req.admin = { id: resolved.admin.id, username: resolved.admin.username };
  req.adminSession = resolved.session;
  next();
}

// Resolve req.repo for an /api request. Replaces requireApiKey: keeps the
// explicit-key path AND adds the no-key proxy path.
export function resolveTenant(req, res, next) {
  const key = extractKey(req);

  // Path 1 — an explicit API key was presented. Original behaviour.
  if (key) {
    const tenant = global.findTenantByKeyHash(hashApiKey(key));
    if (!tenant) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }
    req.tenant = { id: tenant.id, name: tenant.name, plan: tenant.plan };
    req.repo = forTenant(tenant.id, tenant.webhook_secret);
    req.authVia = 'key';
    return next();
  }

  // Path 2 — no key. Use the admin-configured proxy tenant. This is how the
  // public browser console authenticates: it sends nothing, and the server
  // supplies the tenant the admin chose in Settings.
  const proxyTenantId = settings.get(PROXY_TENANT_KEY);
  if (!proxyTenantId) {
    // Distinct, machine-readable code so the UI can render a precise
    // "not configured — see an administrator" state rather than a generic
    // auth failure. This is not a credential hint: it leaks nothing.
    return res.status(503).json({
      error: 'This console has not been configured yet.',
      code: 'not_configured',
    });
  }
  const tenant = global.findTenantById(proxyTenantId);
  if (!tenant) {
    // The stored tenant id no longer resolves (tenant removed/suspended).
    // Again a configuration problem, not a credential problem.
    return res.status(503).json({
      error: 'The configured tenant is unavailable. An administrator must update Settings.',
      code: 'not_configured',
    });
  }
  req.tenant = { id: tenant.id, name: tenant.name, plan: tenant.plan };
  req.repo = forTenant(tenant.id, tenant.webhook_secret);
  req.authVia = 'proxy';
  next();
}
