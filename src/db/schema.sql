-- Global Search Agent — schema (SQLite).
-- Multi-tenant: every business table carries tenant_id and all access goes
-- through the tenant-scoped repository in src/db/index.js. SQLite has no
-- native RLS, so isolation is enforced in the data layer and verified by an
-- automated cross-tenant leakage test (test/tenant-isolation.test.js).

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ── Tenants ──────────────────────────────────────────────────────────
-- One row per customer organization consuming the SaaS.
CREATE TABLE IF NOT EXISTS tenants (
  id            TEXT PRIMARY KEY,            -- uuid
  name          TEXT NOT NULL,
  plan          TEXT NOT NULL DEFAULT 'free',-- free | pro | enterprise
  api_key_hash  TEXT NOT NULL UNIQUE,        -- sha256 of the tenant API key
  webhook_secret TEXT NOT NULL,              -- shared secret for HMAC (signing both directions)
  status        TEXT NOT NULL DEFAULT 'active', -- active | suspended
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Connectors ───────────────────────────────────────────────────────
-- A connected application's read API. The agent calls this to fetch
-- candidate records during a sweep, and (on the add-lead CTA) to push a
-- new lead back. Credentials are AES-256-GCM encrypted at rest.
CREATE TABLE IF NOT EXISTS connectors (
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  -- Connector kind selects the transport adapter (src/connectors/registry.js):
  --   generic = the agent's fixed 2-endpoint contract
  --   vistage = adapter for the Vistage / Claritas CRM .svc API (read-only)
  kind            TEXT NOT NULL DEFAULT 'generic',
  base_url        TEXT NOT NULL,             -- e.g. https://crm.example.com/api
  search_path     TEXT NOT NULL DEFAULT '/records/search', -- candidate read endpoint
  create_path     TEXT NOT NULL DEFAULT '/leads',          -- new-lead push endpoint
  -- Optional detail endpoint for ENRICHMENT (generic kind). When set, a
  -- matched finding can be enriched with a profile / group / payment view.
  -- Blank = enrichment unsupported for this generic connector. (vistage uses
  -- its built-in GetDetail and ignores this column.)
  enrich_path     TEXT NOT NULL DEFAULT '',
  auth_type       TEXT NOT NULL DEFAULT 'bearer',          -- bearer | header | none
  auth_header     TEXT NOT NULL DEFAULT 'Authorization',   -- header name when auth_type=header
  credential_enc  TEXT NOT NULL DEFAULT '',  -- encrypted token/key (generic) OR
                                             -- encrypted JSON credential bundle (vistage)
  field_map_json  TEXT NOT NULL DEFAULT '{}',-- maps connected-app fields -> canonical fields
  -- Maps the connected app's DETAIL-record field names -> the enrichment
  -- normalizer's canonical concepts (group, chair, reportsTo, payments,
  -- outstandingAmount, pendingItems, ...). Shallow-merged over the defaults
  -- in src/enrich/normalize.js. Stored as JSON text.
  enrich_field_map_json TEXT NOT NULL DEFAULT '{}',
  -- Kind-specific non-secret settings (e.g. vistage: which member modules to
  -- sweep, the resolved UserToken). Never holds secrets — those go in
  -- credential_enc. Stored as JSON text.
  meta_json       TEXT NOT NULL DEFAULT '{}',
  status          TEXT NOT NULL DEFAULT 'active',
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors(tenant_id);

-- ── Search jobs ──────────────────────────────────────────────────────
-- One sweep run. Holds the user-selected match criteria and rollup counts.
CREATE TABLE IF NOT EXISTS search_jobs (
  id             TEXT PRIMARY KEY,
  tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  connector_id   TEXT NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
  source         TEXT NOT NULL DEFAULT 'api', -- api | csv | webhook
  criteria_json  TEXT NOT NULL,               -- ["email","phone","name",...]
  status         TEXT NOT NULL DEFAULT 'pending', -- pending|running|completed|failed
  total_input    INTEGER NOT NULL DEFAULT 0,
  count_duplicate INTEGER NOT NULL DEFAULT 0,
  count_review   INTEGER NOT NULL DEFAULT 0,
  count_new      INTEGER NOT NULL DEFAULT 0,
  error          TEXT,
  idempotency_key TEXT,                        -- dedupes retried submissions
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_tenant ON search_jobs(tenant_id, created_at DESC);
-- Idempotency: a repeated submission with the same key is a no-op per tenant.
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_idem
  ON search_jobs(tenant_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

-- ── Search results ───────────────────────────────────────────────────
-- One row per input record, with the classification and the EVIDENCE.
-- matched_on_json names exactly which data points triggered a duplicate —
-- this is the audit trail the Lead-Generation Contract requires (evidence
-- over assumption; nothing is fabricated).
CREATE TABLE IF NOT EXISTS search_results (
  id             TEXT PRIMARY KEY,
  job_id         TEXT NOT NULL REFERENCES search_jobs(id) ON DELETE CASCADE,
  tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  input_json     TEXT NOT NULL,               -- the normalized input record
  classification TEXT NOT NULL,               -- duplicate | review | new
  score          REAL NOT NULL DEFAULT 0,     -- aggregate match score 0..1
  matched_record_json TEXT,                   -- the connected-app record it matched
  matched_on_json TEXT NOT NULL DEFAULT '[]', -- [{field,score,inputValue,matchValue}]
  lead_status    TEXT NOT NULL DEFAULT 'none',-- none | added  (CTA state for "new")
  lead_ref       TEXT,                        -- id returned by connector on push
  -- Cached enrichment for a matched finding: the canonical profile/group/
  -- payment object built by src/enrich/normalize.js from a connected-app
  -- detail fetch. NULL until the user enriches the finding; cached so the
  -- CRM detail call runs once per result. Fabricates nothing — every value
  -- inside is CRM-sourced.
  enrichment_json TEXT,
  enriched_at    TEXT,                         -- when enrichment_json was populated
  -- Per-record error reason — when the connector lookup or matcher failed
  -- for this input record, the orchestrator records the reason here. NULL
  -- on a healthy result. Surfaces in the UI so the operator sees the real
  -- cause instead of a misleading "matched on weak signals".
  error          TEXT,
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_results_job ON search_results(job_id, classification);
CREATE INDEX IF NOT EXISTS idx_results_tenant ON search_results(tenant_id);

-- ── Webhook deliveries ───────────────────────────────────────────────
-- Outbound callbacks to a connected app when a job completes. Recorded for
-- observability and retry.
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id           TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  job_id       TEXT REFERENCES search_jobs(id) ON DELETE CASCADE,
  target_url   TEXT NOT NULL,
  event        TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending', -- pending|delivered|failed
  attempts     INTEGER NOT NULL DEFAULT 0,
  last_error   TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  delivered_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_webhooks_tenant ON webhook_deliveries(tenant_id);

-- ── Audit log ────────────────────────────────────────────────────────
-- Append-only trail of consequential actions (job created, lead pushed).
CREATE TABLE IF NOT EXISTS audit_log (
  id          TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL,
  action      TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id, created_at DESC);

-- ── Admins ───────────────────────────────────────────────────────────
-- The console operator(s). An admin is the ONLY identity allowed to open
-- the Settings page and choose which tenant key the public app proxies
-- with. Authentication is password + mandatory TOTP 2FA. The password is
-- stored as a scrypt hash (memory-hard) and the TOTP secret AES-256-GCM
-- encrypted at rest — a DB leak alone yields neither a usable password nor
-- a usable second factor. There is no self-service signup: the first admin
-- is created once via the /setup page (seeded from ADMIN_USERNAME /
-- ADMIN_PASSWORD env), after which /setup is permanently closed.
CREATE TABLE IF NOT EXISTS admins (
  id             TEXT PRIMARY KEY,            -- uuid
  username       TEXT NOT NULL UNIQUE,
  password_hash  TEXT NOT NULL,               -- scrypt: salt:derivedKey (hex)
  totp_secret_enc TEXT NOT NULL DEFAULT '',   -- AES-256-GCM(base32 TOTP secret)
  totp_enrolled  INTEGER NOT NULL DEFAULT 0,  -- 0 until the first 6-digit code verifies
  failed_logins  INTEGER NOT NULL DEFAULT 0,  -- consecutive failures, for lockout
  locked_until   TEXT,                        -- ISO time; login refused until then
  last_login_at  TEXT,
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Admin sessions ───────────────────────────────────────────────────
-- Server-side session for a logged-in admin. The cookie carries an opaque
-- random token; only its SHA-256 hash is stored here, so a DB leak cannot
-- be replayed as a live session. A row exists only after BOTH the password
-- and the TOTP code have been verified — a half-authenticated login (the
-- short window between the password step and the 2FA step) is held in a
-- separate pending row, never a full session.
CREATE TABLE IF NOT EXISTS admin_sessions (
  id           TEXT PRIMARY KEY,             -- uuid
  admin_id     TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  token_hash   TEXT NOT NULL UNIQUE,         -- sha256 of the cookie token
  stage        TEXT NOT NULL DEFAULT 'full', -- 'pending2fa' | 'full'
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin ON admin_sessions(admin_id);

-- ── Application settings ─────────────────────────────────────────────
-- A tiny single-purpose key/value store for instance-wide configuration
-- the admin sets in the Settings page. The one key used today is
-- 'proxy_tenant_id' — the id of the tenant whose API key the public app
-- proxies all of its requests with. The raw tenant API key is NEVER
-- stored here (or anywhere): the admin pastes it once, the server hashes
-- it to resolve the tenant, and only the resolved tenant_id is kept.
CREATE TABLE IF NOT EXISTS app_settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
