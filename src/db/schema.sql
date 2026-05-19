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
  auth_type       TEXT NOT NULL DEFAULT 'bearer',          -- bearer | header | none
  auth_header     TEXT NOT NULL DEFAULT 'Authorization',   -- header name when auth_type=header
  credential_enc  TEXT NOT NULL DEFAULT '',  -- encrypted token/key (generic) OR
                                             -- encrypted JSON credential bundle (vistage)
  field_map_json  TEXT NOT NULL DEFAULT '{}',-- maps connected-app fields -> canonical fields
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
