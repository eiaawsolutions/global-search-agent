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
          `SELECT id, name, kind, base_url, search_path, create_path, auth_type,
                  auth_header, field_map_json, meta_json, status, created_at
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
           auth_type, auth_header, credential_enc, field_map_json, meta_json,
           status)
         VALUES (@id,@tenant_id,@name,@kind,@base_url,@search_path,@create_path,
           @auth_type,@auth_header,@credential_enc,@field_map_json,@meta_json,
           'active')`
      ).run({
        id,
        tenant_id: tenantId,
        name: c.name,
        kind: c.kind || 'generic',
        base_url: c.base_url,
        search_path: c.search_path || '/records/search',
        create_path: c.create_path || '/leads',
        auth_type: c.auth_type || 'bearer',
        auth_header: c.auth_header || 'Authorization',
        credential_enc: c.credential_enc || '',
        field_map_json: c.field_map_json || '{}',
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
           matched_record_json, matched_on_json)
         VALUES (?,?,?,?,?,?,?,?)`
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
            JSON.stringify(r.matchedOn || [])
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
