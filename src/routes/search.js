// Search routes — the core API surface.
//
//   POST /api/search            create a job from a JSON list of records
//   POST /api/search/csv        create a job from an uploaded CSV / name list
//   GET  /api/search/:id        job status + rollup counts
//   GET  /api/search/:id/results  classified results (filterable)
//   POST /api/results/:id/add-lead  the CTA — push a "new" record as a lead
//   GET  /api/results/:id/enrich    fetch + cache the full detail profile
//   GET  /api/jobs              recent jobs for this tenant
import { Router } from 'express';
import multer from 'multer';
import { asyncHandler } from '../middleware/auth.js';
import { config } from '../config.js';
import { parseCsv, parseNameList } from '../ingest/csv.js';
import { sanitizeCriteria, runSweep } from '../sweep/orchestrator.js';
import {
  createLead,
  supportsLeadPush,
  supportsEnrichment,
  fetchEnrichment,
} from '../connectors/client.js';
import { explain } from '../matching/engine.js';

const router = Router();

// CSV upload — memory storage with a hard byte cap (the row cap is enforced
// in the parser). Memory storage is fine: the cap keeps payloads small.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.maxCsvBytes, files: 1 },
});

// Shape a stored result row for API output, including a human explanation.
function publicResult(row) {
  const matchedOn = safeParse(row.matched_on_json, []);
  const verdict = {
    classification: row.classification,
    matchedOn,
  };
  return {
    id: row.id,
    input: safeParse(row.input_json, {}),
    classification: row.classification,
    score: row.score,
    // explain() reads `error` first, then falls through to classification.
    explanation: explain({ ...verdict, error: row.error || null }),
    // Per-record error — surfaces the connector-lookup failure reason or
    // the "no data on any criterion" case. NULL on a healthy result.
    error: row.error || null,
    matched_record: row.matched_record_json
      ? safeParse(row.matched_record_json, null)
      : null,
    // The exact data points that made this a duplicate.
    matched_on: matchedOn,
    // CTA state — only meaningful for `new` results. An `error` flag means
    // we couldn't confirm the record is genuinely new (we never reached the
    // CRM, or had no field to match on); the CTA must stay disabled until
    // the operator fixes the connector and re-sweeps.
    lead_status: row.lead_status,
    lead_ref: row.lead_ref || null,
    can_add_lead:
      row.classification === 'new' &&
      row.lead_status === 'none' &&
      !row.error,
    // Enrichment cache state — meaningful for `duplicate` / `review` (they
    // have a matched record to enrich). `enrichment` is the cached profile
    // object if the finding has been enriched, else null; the UI fetches it
    // on demand via GET /api/results/:id/enrich.
    is_enriched: !!row.enrichment_json,
    enriched_at: row.enriched_at || null,
    enrichment: row.enrichment_json
      ? safeParse(row.enrichment_json, null)
      : null,
  };
}

function jobView(job) {
  return {
    id: job.id,
    connector_id: job.connector_id,
    source: job.source,
    criteria: safeParse(job.criteria_json, []),
    status: job.status,
    total_input: job.total_input,
    counts: {
      duplicate: job.count_duplicate,
      review: job.count_review,
      new: job.count_new,
    },
    error: job.error || null,
    created_at: job.created_at,
    completed_at: job.completed_at || null,
  };
}

// Shared job-creation path used by both the JSON and CSV endpoints.
// Returns the response payload (status 201) or throws an Error with .status.
async function createAndRunJob({ req, records, source }) {
  if (!Array.isArray(records) || records.length === 0) {
    const e = new Error('No input records provided.');
    e.status = 400;
    throw e;
  }
  if (records.length > config.maxCsvRows) {
    const e = new Error(`Too many records (limit ${config.maxCsvRows}).`);
    e.status = 400;
    throw e;
  }

  const connectorId = req.body?.connector_id || req.query?.connector_id;
  const connector = connectorId ? req.repo.getConnector(connectorId) : null;
  if (!connector) {
    const e = new Error('Unknown or missing connector_id.');
    e.status = 400;
    throw e;
  }

  const criteria = sanitizeCriteria(
    parseCriteriaParam(req.body?.criteria ?? req.query?.criteria)
  );

  // Idempotency — a repeated submit with the same key returns the original
  // job instead of running a duplicate sweep.
  const idemKey =
    req.get('idempotency-key') || req.body?.idempotency_key || null;
  if (idemKey) {
    const existing = req.repo.findJobByIdempotencyKey(idemKey);
    if (existing) return { job: jobView(existing), idempotent_replay: true };
  }

  const job = req.repo.createJob({
    connectorId: connector.id,
    source,
    criteria,
    totalInput: records.length,
    idempotencyKey: idemKey,
  });
  req.repo.audit('job.created', {
    jobId: job.id,
    source,
    records: records.length,
    criteria,
  });

  // Run the sweep. For the record counts in scope here (<= maxCsvRows) a
  // synchronous run keeps the API simple and the response self-contained.
  // For very large jobs this is the seam to move onto a queue.
  await runSweep({ repo: req.repo, job, connector, records });

  return { job: jobView(req.repo.getJob(job.id)) };
}

// POST /api/search — JSON body: { connector_id, criteria[], records[] }
router.post(
  '/search',
  asyncHandler(async (req, res) => {
    const records = Array.isArray(req.body?.records) ? req.body.records : null;
    const result = await createAndRunJob({ req, records, source: 'api' });
    res.status(201).json(result);
  })
);

// POST /api/search/csv — multipart upload OR a raw text name list.
//   - file field "file" : a CSV with a header row
//   - OR body field "names" : newline/comma-separated names
router.post(
  '/search/csv',
  upload.single('file'),
  asyncHandler(async (req, res) => {
    let records;
    if (req.file) {
      const text = req.file.buffer.toString('utf8');
      records = parseCsv(text, { maxRows: config.maxCsvRows });
      req._source = 'csv';
    } else if (req.body?.names) {
      records = parseNameList(String(req.body.names), {
        maxRows: config.maxCsvRows,
      });
      req._source = 'csv';
    } else {
      return res
        .status(400)
        .json({ error: 'Provide a CSV file ("file") or a "names" list.' });
    }
    const result = await createAndRunJob({ req, records, source: 'csv' });
    res.status(201).json(result);
  })
);

// GET /api/search/:id — job status.
router.get(
  '/search/:id',
  asyncHandler(async (req, res) => {
    const job = req.repo.getJob(req.params.id);
    if (!job) return res.status(404).json({ error: 'Job not found.' });
    res.json({ job: jobView(job) });
  })
);

// GET /api/search/:id/results?classification=duplicate|review|new
router.get(
  '/search/:id/results',
  asyncHandler(async (req, res) => {
    const job = req.repo.getJob(req.params.id);
    if (!job) return res.status(404).json({ error: 'Job not found.' });
    const filter = ['duplicate', 'review', 'new'].includes(
      req.query.classification
    )
      ? req.query.classification
      : null;
    const rows = req.repo.listResults(job.id, filter);
    res.json({
      job: jobView(job),
      results: rows.map(publicResult),
    });
  })
);

// GET /api/jobs — recent jobs.
router.get(
  '/jobs',
  asyncHandler(async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit || '50', 10) || 50, 200);
    res.json({ jobs: req.repo.listJobs(limit).map(jobView) });
  })
);

// POST /api/results/:id/add-lead — the call-to-action.
// Pushes a `new` result into the connected app as a lead, then flips the
// result's lead_status so the CTA cannot be double-fired. This is the ONLY
// place the agent writes back to a connected app, and only on explicit
// user action — never automatically.
router.post(
  '/results/:id/add-lead',
  asyncHandler(async (req, res) => {
    const result = req.repo.getResult(req.params.id);
    if (!result) return res.status(404).json({ error: 'Result not found.' });

    if (result.classification !== 'new') {
      return res.status(409).json({
        error: 'Only records classified as "new" can be added as leads.',
      });
    }
    if (result.lead_status === 'added') {
      return res
        .status(409)
        .json({ error: 'This lead has already been added.' });
    }
    // If this result was classified `new` because the CRM lookup FAILED (not
    // because nothing matched), we never confirmed the record is actually
    // new — pushing it would risk creating a duplicate in the CRM. Block
    // the CTA until the operator fixes the connector and re-sweeps.
    if (result.error) {
      return res.status(409).json({
        error:
          'Cannot push this record as a lead — the original sweep had a ' +
          'lookup error, so we never confirmed it is new. Re-sweep after ' +
          'fixing the connector.',
      });
    }

    const job = req.repo.getJob(result.job_id);
    const connector = job ? req.repo.getConnector(job.connector_id) : null;
    if (!connector) {
      return res.status(409).json({ error: 'Connector is no longer available.' });
    }
    // Some connector kinds (e.g. vistage) are read-only — fail fast with a
    // clear message instead of a generic upstream error.
    if (!supportsLeadPush(connector)) {
      return res.status(409).json({
        error:
          'This connector is read-only; leads cannot be pushed back to it.',
      });
    }

    const input = safeParse(result.input_json, {});
    let leadRef = null;
    try {
      leadRef = await createLead(connector, input, { repo: req.repo });
    } catch (err) {
      return res
        .status(502)
        .json({ error: `Connected app rejected the lead: ${err.message}` });
    }

    req.repo.markLeadAdded(result.id, leadRef);
    req.repo.audit('lead.added', {
      resultId: result.id,
      jobId: result.job_id,
      leadRef,
    });

    res.json({
      ok: true,
      result_id: result.id,
      lead_ref: leadRef,
      lead_status: 'added',
    });
  })
);

// GET /api/results/:id/enrich — fetch the full DETAIL profile for a matched
// finding. Shapes the connected app's detail record into the canonical
// {profile, linkage (group/leader/chair), meetings, payment (12-month
// grid), outstanding, pending} object. The result is cached on the row so
// the CRM detail call runs once per finding. Pass ?refresh=1 to bypass.
//
// Lead-Generation Contract applied to enrichment: nothing is fabricated.
// Missing scalar fields stay null; months with no source record stay
// "no-record"; an unknown outstanding flag stays null (not false).
router.get(
  '/results/:id/enrich',
  asyncHandler(async (req, res) => {
    const result = req.repo.getResult(req.params.id);
    if (!result) return res.status(404).json({ error: 'Result not found.' });

    // A "new" result has no matched CRM record to enrich against — by design.
    if (result.classification === 'new') {
      return res.status(409).json({
        error:
          'This record is new — there is no matching CRM record to enrich.',
      });
    }
    if (!result.matched_record_json) {
      return res.status(409).json({
        error: 'This finding has no matched record to enrich.',
      });
    }

    // Serve the cache unless the caller explicitly asks to refresh.
    const refresh = req.query.refresh === '1' || req.query.refresh === 'true';
    if (result.enrichment_json && !refresh) {
      return res.json({
        result_id: result.id,
        cached: true,
        enriched_at: result.enriched_at || null,
        enrichment: safeParse(result.enrichment_json, null),
      });
    }

    const job = req.repo.getJob(result.job_id);
    const connector = job ? req.repo.getConnector(job.connector_id) : null;
    if (!connector) {
      return res
        .status(409)
        .json({ error: 'Connector is no longer available.' });
    }
    if (!supportsEnrichment(connector)) {
      return res.status(409).json({
        error:
          'This connector does not support enrichment (no detail endpoint configured).',
      });
    }

    const matchedRecord = safeParse(result.matched_record_json, {});
    let enrichment;
    try {
      enrichment = await fetchEnrichment(connector, matchedRecord, {
        repo: req.repo,
      });
    } catch (err) {
      return res.status(502).json({
        error: `Could not enrich from the connected app: ${err.message}`,
      });
    }

    req.repo.saveResultEnrichment(result.id, enrichment);
    req.repo.audit('result.enriched', {
      resultId: result.id,
      jobId: result.job_id,
      fieldsFound: enrichment?.meta?.fieldsFound?.length || 0,
      fieldsMissing: enrichment?.meta?.fieldsMissing?.length || 0,
    });

    res.json({
      result_id: result.id,
      cached: false,
      enriched_at: new Date().toISOString(),
      enrichment,
    });
  })
);

// ── helpers ──────────────────────────────────────────────────────────
// criteria may arrive as an array, a comma string, or repeated query params.
function parseCriteriaParam(raw) {
  if (Array.isArray(raw)) return raw;
  if (typeof raw === 'string') return raw.split(',');
  return [];
}

function safeParse(json, fallback) {
  try {
    return JSON.parse(json);
  } catch {
    return fallback;
  }
}

export default router;
