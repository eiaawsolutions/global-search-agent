// Global Search Agent — HTTP server entry point.
//
// Wires middleware, routes, and the static web UI. Security posture:
//  - helmet for security headers (CSP, HSTS, no-sniff, frame-deny)
//  - per-tenant rate limiting on the API
//  - API-key auth + tenant scoping on every /api route (except the signed
//    webhook, which authenticates via HMAC over the raw body)
//  - no stack traces or version headers leak to clients
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { config } from './config.js';
import { migrate } from './db/migrate.js';
import rawDb, { adminSessions } from './db/index.js';
import { resolveTenant } from './middleware/admin-auth.js';
import { notFound, errorHandler } from './middleware/errors.js';
import connectorRoutes from './routes/connectors.js';
import searchRoutes from './routes/search.js';
import webhookRoutes from './routes/webhook.js';
import adminRoutes from './routes/admin.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Apply migrations on boot so a fresh checkout is runnable with one command.
migrate({ silent: false });

const app = express();
app.disable('x-powered-by'); // no framework fingerprinting

// ── Security headers ─────────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        // styles: own stylesheet + inline + Google Fonts stylesheet
        // (the console uses Cormorant Garamond, the Claritas display face).
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        // font files served from Google's static host.
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
      },
    },
    hsts: config.isProd ? { maxAge: 31536000, includeSubDomains: true } : false,
  })
);
app.use(cors({ origin: false })); // browser cross-origin off by default

// ── Webhook route — MOUNTED BEFORE the JSON body parser ──────────────
// The HMAC signature is computed over the raw bytes, so this route needs
// the unparsed body. express.raw() gives it a Buffer.
app.use(
  '/api/webhook',
  express.raw({ type: '*/*', limit: '2mb' }),
  webhookRoutes
);

// ── JSON body parsing for the rest of the API ────────────────────────
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false, limit: '2mb' }));

// Cookie parsing — the admin session cookie (gsa_admin) is read from here.
app.use(cookieParser());

// ── Health check (unauthenticated, no tenant data) ───────────────────
// Verifies the SQLite file is reachable so an orchestrator (Railway health
// check / Cloud Run startup probe) restarts the container if the volume
// failed to mount. Returns 503 when the DB is not responding.
app.get('/health', (req, res) => {
  try {
    rawDb.prepare('SELECT 1').get();
    res.json({
      status: 'ok',
      service: 'global-search-agent',
      time: new Date().toISOString(),
    });
  } catch (err) {
    res.status(503).json({ status: 'degraded', error: 'database unavailable' });
  }
});

// ── Per-tenant API rate limiting ─────────────────────────────────────
// Keyed by the presented API key so one noisy tenant cannot exhaust
// another's budget. Unauthenticated requests fall back to the client IP —
// via ipKeyGenerator(), which normalizes IPv6 so a /64 cannot be used to
// trivially bypass the limit.
const apiLimiter = rateLimit({
  windowMs: 60_000,
  limit: config.rateLimitPerMin,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const key =
      req.get('x-api-key') ||
      (req.get('authorization') || '').replace(/^bearer\s+/i, '').trim();
    return key ? `k:${key}` : `ip:${ipKeyGenerator(req.ip)}`;
  },
  message: { error: 'Rate limit exceeded. Slow down.' },
});

// ── Admin authentication endpoints ───────────────────────────────────
// Login / setup / 2FA / Settings management. Mounted BEFORE the tenant
// resolver because admin routes carry their own auth (an admin session
// cookie, not a tenant API key) and the unauthenticated screens (/state,
// /setup, /login) must be reachable with no credential at all.
//
// A dedicated, tighter rate limiter — keyed by client IP — blunts password
// and TOTP guessing at the network layer, on top of the per-account lockout
// inside the routes. Stricter than the general API limit.
const adminLimiter = rateLimit({
  windowMs: 60_000,
  limit: config.adminAuthRateLimitPerMin,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `ip:${ipKeyGenerator(req.ip)}`,
  message: { error: 'Too many requests. Slow down.' },
});
app.use('/api/admin', adminLimiter, adminRoutes);

// ── Authenticated API ────────────────────────────────────────────────
// resolveTenant accepts EITHER an explicit tenant API key (REST clients,
// signed webhooks, tests) OR no key at all — in which case it proxies the
// request through the admin-configured tenant. That proxy path is how the
// public browser console is connected without ever holding a key.
app.use('/api', apiLimiter, resolveTenant);
app.use('/api/connectors', connectorRoutes);
app.use('/api', searchRoutes);

// ── Static web UI ────────────────────────────────────────────────────
// The admin Settings page. Served as a clean /settings path (the file is
// public/settings.html). The page's own script calls /api/admin/state to
// decide which view to render; there is no server-side gate on the HTML
// itself — it is just a shell, and every privileged action behind it
// requires the admin session cookie.
app.get('/settings', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'settings.html'));
});

app.use(express.static(path.join(__dirname, '..', 'public')));

// ── 404 + error handler (must be last) ───────────────────────────────
app.use(notFound);
app.use(errorHandler);

// Bind 0.0.0.0 explicitly — containers (Railway, Cloud Run) route to the
// container IP, not loopback, so binding only 127.0.0.1 would be unreachable.
const HOST = '0.0.0.0';
const server = app.listen(config.port, HOST, () => {
  console.log(
    `▸ Global Search Agent listening on ${HOST}:${config.port}  [${config.env}]`
  );
});

// Expired admin sessions are skipped on read, but sweep them hourly so the
// table does not grow unbounded. unref() keeps the timer from holding the
// process open during a graceful shutdown.
const sessionSweep = setInterval(
  () => {
    try {
      adminSessions.purgeExpired();
    } catch (err) {
      console.error('[session-sweep]', err.message);
    }
  },
  60 * 60 * 1000
);
sessionSweep.unref();

// Graceful shutdown so in-flight sweeps are not cut mid-write.
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    console.log(`\n${sig} received — shutting down.`);
    server.close(() => process.exit(0));
  });
}

export default app;
