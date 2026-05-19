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
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { config } from './config.js';
import { migrate } from './db/migrate.js';
import rawDb from './db/index.js';
import { requireApiKey } from './middleware/auth.js';
import { notFound, errorHandler } from './middleware/errors.js';
import connectorRoutes from './routes/connectors.js';
import searchRoutes from './routes/search.js';
import webhookRoutes from './routes/webhook.js';

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

// ── Authenticated API ────────────────────────────────────────────────
app.use('/api', apiLimiter, requireApiKey);
app.use('/api/connectors', connectorRoutes);
app.use('/api', searchRoutes);

// ── Static web UI ────────────────────────────────────────────────────
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

// Graceful shutdown so in-flight sweeps are not cut mid-write.
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    console.log(`\n${sig} received — shutting down.`);
    server.close(() => process.exit(0));
  });
}

export default app;
