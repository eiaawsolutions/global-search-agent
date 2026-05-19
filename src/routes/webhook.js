// Inbound webhook route.
//
// Lets a connected application trigger a sweep by POSTing records, instead
// of calling the JSON API directly. The request MUST be HMAC-signed with the
// tenant's webhook secret — this is the integration path for apps that push
// events ("a new batch of contacts was imported, go dedup them").
//
//   POST /api/webhook/search
//   headers: X-API-Key, X-GSA-Signature, X-GSA-Timestamp
//   body   : { connector_id, criteria[], records[] }
//
// The signature is verified over the RAW body, so this route is mounted
// with a raw body parser (see server.js) — JSON.parse happens here, after
// verification, never before.
import { Router } from 'express';
import { asyncHandler } from '../middleware/auth.js';
import { global, forTenant } from '../db/index.js';
import { hashApiKey, verifyInboundWebhook } from '../utils/crypto.js';
import { config } from '../config.js';
import { sanitizeCriteria, runSweep } from '../sweep/orchestrator.js';

const router = Router();

// POST /api/webhook/search — signed sweep trigger.
router.post(
  '/search',
  asyncHandler(async (req, res) => {
    // 1. Resolve the tenant from the API key.
    const key =
      req.get('x-api-key') ||
      (req.get('authorization') || '').replace(/^bearer\s+/i, '').trim();
    if (!key) return res.status(401).json({ error: 'Authentication required.' });
    const tenant = global.findTenantByKeyHash(hashApiKey(key));
    if (!tenant) return res.status(401).json({ error: 'Invalid credentials.' });

    // 2. Verify the HMAC signature over the raw body. req.body is a Buffer
    //    here because this route uses express.raw().
    const rawBody = Buffer.isBuffer(req.body)
      ? req.body.toString('utf8')
      : typeof req.body === 'string'
        ? req.body
        : JSON.stringify(req.body || {});
    const signatureOk = verifyInboundWebhook(
      tenant.webhook_secret,
      req.get('x-gsa-timestamp'),
      rawBody,
      req.get('x-gsa-signature')
    );
    if (!signatureOk) {
      return res
        .status(401)
        .json({ error: 'Webhook signature verification failed.' });
    }

    // 3. Parse the now-trusted body.
    let payload;
    try {
      payload = JSON.parse(rawBody || '{}');
    } catch {
      return res.status(400).json({ error: 'Body is not valid JSON.' });
    }

    const records = Array.isArray(payload.records) ? payload.records : [];
    if (!records.length) {
      return res.status(400).json({ error: 'No records provided.' });
    }
    if (records.length > config.maxCsvRows) {
      return res
        .status(400)
        .json({ error: `Too many records (limit ${config.maxCsvRows}).` });
    }

    const repo = forTenant(tenant.id, tenant.webhook_secret);
    const connector = payload.connector_id
      ? repo.getConnector(payload.connector_id)
      : null;
    if (!connector) {
      return res.status(400).json({ error: 'Unknown connector_id.' });
    }

    const criteria = sanitizeCriteria(payload.criteria);
    const job = repo.createJob({
      connectorId: connector.id,
      source: 'webhook',
      criteria,
      totalInput: records.length,
      idempotencyKey: payload.idempotency_key || null,
    });
    repo.audit('job.created', {
      jobId: job.id,
      source: 'webhook',
      records: records.length,
    });

    await runSweep({ repo, job, connector, records });
    const finished = repo.getJob(job.id);

    res.status(201).json({
      job_id: finished.id,
      status: finished.status,
      counts: {
        duplicate: finished.count_duplicate,
        review: finished.count_review,
        new: finished.count_new,
      },
    });
  })
);

export default router;
