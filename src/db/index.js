// Database connection + tenant-scoped repository.
//
// SQLite has no row-level security, so multi-tenant isolation is enforced
// HERE: every query that touches a business table goes through `forTenant()`,
// which closes over a tenant_id and injects it into every WHERE clause and
// INSERT. Route handlers must never build raw cross-tenant SQL. The
// invariant is verified by test/tenant-isolation.test.js.
import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { config } from '../config.js';

fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });

const db = new Database(config.dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

export const uuid = () => randomUUID();
export { db as raw };

// ── Global (non-tenant-scoped) operations ────────────────────────────
// Used only at the auth boundary: resolve a tenant from an API key hash.
export const global = {
  findTenantByKeyHash(hash) {
    return db
      .prepare(`SELECT * FROM tenants WHERE api_key_hash = ? AND status = 'active'`)
      .get(hash);
  },
  // Resolve a tenant by id — used by the app-proxy middleware to load the
  // admin-configured tenant. Active-only, so a suspended tenant cannot be
  // proxied even if its id is still stored in app_settings.
  findTenantById(id) {
    if (!id) return null;
    return db
      .prepare(`SELECT * FROM tenants WHERE id = ? AND status = 'active'`)
      .get(id);
  },
  countTenants() {
    return db.prepare('SELECT COUNT(*) AS n FROM tenants').get().n;
  },
  createTenant({ id, name, plan, apiKeyHash, webhookSecret }) {
    db.prepare(
      `INSERT INTO tenants (id, name, plan, api_key_hash, webhook_secret)
       VALUES (?, ?, ?, ?, ?)`
    ).run(id, name, plan || 'free', apiKeyHash, webhookSecret);
  },
};

// ── Admin operations ─────────────────────────────────────────────────
// The Settings-page operator identity. Not tenant-scoped: an admin is an
// instance-level identity, distinct from a tenant. Passwords arrive here
// already scrypt-hashed and TOTP secrets already AES-256-GCM encrypted —
// this layer never sees a plaintext credential.
export const admins = {
  count() {
    return db.prepare('SELECT COUNT(*) AS n FROM admins').get().n;
  },
  create({ id, username, passwordHash }) {
    db.prepare(
      `INSERT INTO admins (id, username, password_hash) VALUES (?, ?, ?)`
    ).run(id, username, passwordHash);
    return this.getById(id);
  },
  getById(id) {
    return db.prepare('SELECT * FROM admins WHERE id = ?').get(id);
  },
  getByUsername(username) {
    return db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
  },
  // Store the (encrypted) TOTP secret during enrollment. Enrollment is not
  // marked complete here — `markTotpEnrolled` does that once a code verifies.
  setTotpSecret(id, totpSecretEnc) {
    db.prepare('UPDATE admins SET totp_secret_enc = ? WHERE id = ?').run(
      totpSecretEnc,
      id
    );
  },
  markTotpEnrolled(id) {
    db.prepare('UPDATE admins SET totp_enrolled = 1 WHERE id = ?').run(id);
  },
  setPassword(id, passwordHash) {
    db.prepare('UPDATE admins SET password_hash = ? WHERE id = ?').run(
      passwordHash,
      id
    );
  },
  // Lockout bookkeeping. recordFailedLogin increments the counter and, once
  // it crosses the threshold, stamps a locked_until time. recordSuccess
  // clears both and records the login.
  recordFailedLogin(id, { threshold, lockMs }) {
    const row = this.getById(id);
    const failed = (row?.failed_logins || 0) + 1;
    const lockedUntil =
      failed >= threshold
        ? new Date(Date.now() + lockMs).toISOString()
        : row?.locked_until || null;
    db.prepare(
      'UPDATE admins SET failed_logins = ?, locked_until = ? WHERE id = ?'
    ).run(failed, lockedUntil, id);
    return { failed, lockedUntil };
  },
  recordSuccess(id) {
    db.prepare(
      `UPDATE admins SET failed_logins = 0, locked_until = NULL,
              last_login_at = datetime('now') WHERE id = ?`
    ).run(id);
  },
};

// ── Admin session operations ─────────────────────────────────────────
// Server-side sessions for the Settings page. The cookie holds an opaque
// token; only its hash is stored, so the DB row is not replayable. A
// session is created at the 'pending2fa' stage after the password step and
// promoted to 'full' once the TOTP code verifies.
export const adminSessions = {
  create({ id, adminId, tokenHash, stage, expiresAt }) {
    db.prepare(
      `INSERT INTO admin_sessions (id, admin_id, token_hash, stage, expires_at)
       VALUES (?, ?, ?, ?, ?)`
    ).run(id, adminId, tokenHash, stage || 'full', expiresAt);
    return id;
  },
  // Look up a live session by the hash of its cookie token. Expired rows are
  // treated as absent (and opportunistically swept) so a stale cookie is
  // never honoured.
  findByTokenHash(tokenHash) {
    const row = db
      .prepare('SELECT * FROM admin_sessions WHERE token_hash = ?')
      .get(tokenHash);
    if (!row) return null;
    if (new Date(row.expires_at).getTime() <= Date.now()) {
      db.prepare('DELETE FROM admin_sessions WHERE id = ?').run(row.id);
      return null;
    }
    return row;
  },
  // Promote a half-authenticated session to full once 2FA passes.
  promoteToFull(id) {
    db.prepare(`UPDATE admin_sessions SET stage = 'full' WHERE id = ?`).run(id);
  },
  deleteByTokenHash(tokenHash) {
    db.prepare('DELETE FROM admin_sessions WHERE token_hash = ?').run(tokenHash);
  },
  // Drop every session for an admin — used after a password change so old
  // cookies cannot continue a session under the old credentials.
  deleteAllForAdmin(adminId) {
    db.prepare('DELETE FROM admin_sessions WHERE admin_id = ?').run(adminId);
  },
  // Housekeeping: clear expired rows. Called on a cheap timer from the server.
  purgeExpired() {
    db.prepare(
      `DELETE FROM admin_sessions WHERE expires_at <= datetime('now')`
    ).run();
  },
};

// ── Application settings (single key/value store) ────────────────────
export const settings = {
  get(key) {
    const row = db.prepare('SELECT value FROM app_settings WHERE key = ?').get(key);
    return row ? row.value : null;
  },
  set(key, value) {
    db.prepare(
      `INSERT INTO app_settings (key, value, updated_at)
       VALUES (?, ?, datetime('now'))
       ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                      updated_at = datetime('now')`
    ).run(key, value);
  },
  // updated_at for a key — surfaced in Settings so the admin sees when the
  // proxy tenant key was last changed.
  updatedAt(key) {
    const row = db
      .prepare('SELECT updated_at FROM app_settings WHERE key = ?')
      .get(key);
    return row ? row.updated_at : null;
  },
};

// ── Tenant-scoped repository ──────────────────────────────────────────
// Returns an object whose every method is already bound to one tenant.
// There is intentionally no method that accepts a tenant_id argument.
// `webhookSecret` is optional; pass it so the webhook dispatcher can sign
// outbound callbacks without the API layer patching the repo afterwards.
export function forTenant(tenantId, webhookSecret = null) {
  if (!tenantId) throw new Error('forTenant() requires a tenant id');

  return {
    tenantId,
    webhookSecret,

    // ---- connectors ----
    listConnectors() {
      return db
        .prepare(
          `SELECT id, name, kind, base_url, search_path, create_path,
                  enrich_path, auth_type, auth_header, field_map_json,
                  enrich_field_map_json, meta_json, status, created_at
           FROM connectors WHERE tenant_id = ? ORDER BY created_at DESC`
        )
        .all(tenantId);
    },
    getConnector(id) {
      return db
        .prepare(`SELECT * FROM connectors WHERE id = ? AND tenant_id = ?`)
        .get(id, tenantId);
    },
    createConnector(c) {
      const id = uuid();
      db.prepare(
        `INSERT INTO connectors
          (id, tenant_id, name, kind, base_url, search_path, create_path,
           enrich_path, auth_type, auth_header, credential_enc, field_map_json,
           enrich_field_map_json, meta_json, status)
         VALUES (@id,@tenant_id,@name,@kind,@base_url,@search_path,@create_path,
           @enrich_path,@auth_type,@auth_header,@credential_enc,@field_map_json,
           @enrich_field_map_json,@meta_json,'active')`
      ).run({
        id,
        tenant_id: tenantId,
        name: c.name,
        kind: c.kind || 'generic',
        base_url: c.base_url,
        search_path: c.search_path || '/records/search',
        create_path: c.create_path || '/leads',
        enrich_path: c.enrich_path || '',
        auth_type: c.auth_type || 'bearer',
        auth_header: c.auth_header || 'Authorization',
        credential_enc: c.credential_enc || '',
        field_map_json: c.field_map_json || '{}',
        enrich_field_map_json: c.enrich_field_map_json || '{}',
        meta_json: c.meta_json || '{}',
      });
      return this.getConnector(id);
    },

    // Persist kind-specific non-secret settings (e.g. a vistage connector's
    // resolved UserToken after first UserLogin). Never used for secrets.
    updateConnectorMeta(id, metaJson) {
      db.prepare(
        `UPDATE connectors SET meta_json = ? WHERE id = ? AND tenant_id = ?`
      ).run(metaJson, id, tenantId);
    },
    // Delete a connector. Tenant-scoped — the WHERE clause prevents one
    // tenant removing another's. Returns true if a row was actually removed.
    // ON DELETE CASCADE drops the connector's jobs and results with it.
    deleteConnector(id) {
      const info = db
        .prepare(`DELETE FROM connectors WHERE id = ? AND tenant_id = ?`)
        .run(id, tenantId);
      return info.changes > 0;
    },

    // ---- search jobs ----
    findJobByIdempotencyKey(key) {
      if (!key) return null;
      return db
        .prepare(
          `SELECT * FROM search_jobs WHERE tenant_id = ? AND idempotency_key = ?`
        )
        .get(tenantId, key);
    },
    createJob(j) {
      const id = uuid();
      db.prepare(
        `INSERT INTO search_jobs
          (id, tenant_id, connector_id, source, criteria_json, status,
           total_input, idempotency_key)
         VALUES (?,?,?,?,?,'pending',?,?)`
      ).run(
        id,
        tenantId,
        j.connectorId,
        j.source || 'api',
        JSON.stringify(j.criteria),
        j.totalInput || 0,
        j.idempotencyKey || null
      );
      return this.getJob(id);
    },
    getJob(id) {
      return db
        .prepare(`SELECT * FROM search_jobs WHERE id = ? AND tenant_id = ?`)
        .get(id, tenantId);
    },
    listJobs(limit = 50) {
      return db
        .prepare(
          `SELECT * FROM search_jobs WHERE tenant_id = ?
           ORDER BY created_at DESC LIMIT ?`
        )
        .all(tenantId, limit);
    },
    updateJobStatus(id, status, extra = {}) {
      db.prepare(
        `UPDATE search_jobs
         SET status = ?, error = ?, total_input = COALESCE(?, total_input),
             count_duplicate = COALESCE(?, count_duplicate),
             count_review = COALESCE(?, count_review),
             count_new = COALESCE(?, count_new),
             completed_at = CASE WHEN ? IN ('completed','failed')
                                 THEN datetime('now') ELSE completed_at END
         WHERE id = ? AND tenant_id = ?`
      ).run(
        status,
        extra.error || null,
        extra.totalInput ?? null,
        extra.countDuplicate ?? null,
        extra.countReview ?? null,
        extra.countNew ?? null,
        status,
        id,
        tenantId
      );
    },

    // ---- results ----
    insertResults(jobId, rows) {
      const stmt = db.prepare(
        `INSERT INTO search_results
          (id, job_id, tenant_id, input_json, classification, score,
           matched_record_json, matched_on_json, error)
         VALUES (?,?,?,?,?,?,?,?,?)`
      );
      const tx = db.transaction((items) => {
        for (const r of items) {
          stmt.run(
            uuid(),
            jobId,
            tenantId,
            JSON.stringify(r.input),
            r.classification,
            r.score,
            r.matchedRecord ? JSON.stringify(r.matchedRecord) : null,
            JSON.stringify(r.matchedOn || []),
            r.error || null
          );
        }
      });
      tx(rows);
    },
    listResults(jobId, classification) {
      const base = `SELECT * FROM search_results
                    WHERE job_id = ? AND tenant_id = ?`;
      if (classification) {
        return db
          .prepare(base + ` AND classification = ? ORDER BY score DESC`)
          .all(jobId, tenantId, classification);
      }
      return db.prepare(base + ` ORDER BY score DESC`).all(jobId, tenantId);
    },
    getResult(id) {
      return db
        .prepare(`SELECT * FROM search_results WHERE id = ? AND tenant_id = ?`)
        .get(id, tenantId);
    },
    markLeadAdded(resultId, leadRef) {
      db.prepare(
        `UPDATE search_results SET lead_status = 'added', lead_ref = ?
         WHERE id = ? AND tenant_id = ?`
      ).run(leadRef || null, resultId, tenantId);
    },
    // Cache the enrichment object for a matched result. Tenant-scoped so one
    // tenant cannot write enrichment onto another's result row.
    saveResultEnrichment(resultId, enrichment) {
      db.prepare(
        `UPDATE search_results
         SET enrichment_json = ?, enriched_at = datetime('now')
         WHERE id = ? AND tenant_id = ?`
      ).run(JSON.stringify(enrichment), resultId, tenantId);
    },

    // ---- webhook deliveries ----
    recordWebhook(w) {
      const id = uuid();
      db.prepare(
        `INSERT INTO webhook_deliveries
          (id, tenant_id, job_id, target_url, event, status, attempts, last_error, delivered_at)
         VALUES (?,?,?,?,?,?,?,?,?)`
      ).run(
        id,
        tenantId,
        w.jobId || null,
        w.targetUrl,
        w.event,
        w.status || 'pending',
        w.attempts || 0,
        w.lastError || null,
        w.deliveredAt || null
      );
      return id;
    },

    // ---- audit ----
    audit(action, detail = {}) {
      db.prepare(
        `INSERT INTO audit_log (id, tenant_id, action, detail_json)
         VALUES (?,?,?,?)`
      ).run(uuid(), tenantId, action, JSON.stringify(detail));
    },
  };
}

export default db;
