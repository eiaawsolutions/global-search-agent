// Sweep orchestrator.
//
// Runs one search job end-to-end: for every input record it asks the
// connected app for candidates, runs the matching engine, and records the
// classified result with its evidence. Then it rolls up the counts and
// (optionally) fires a completion webhook.
//
// Concurrency is bounded so a 10k-row job does not open 10k sockets at once.
import { normalizeRecord, CRITERIA } from '../matching/normalize.js';
import { classifyInput, scorePair, THRESHOLDS } from '../matching/engine.js';
import { fetchCandidates } from '../connectors/client.js';
import { dispatchWebhook } from '../webhooks/dispatcher.js';

const CONCURRENCY = 6; // simultaneous connector calls per job

// Validate + normalize the user-selected criteria. Falls back to all five
// if the caller passes nothing usable.
export function sanitizeCriteria(input) {
  const wanted = Array.isArray(input) ? input : [];
  const clean = wanted
    .map((c) => String(c).toLowerCase().trim())
    .filter((c) => CRITERIA.includes(c));
  // De-dupe while preserving order.
  const seen = new Set();
  const result = clean.filter((c) => (seen.has(c) ? false : seen.add(c)));
  return result.length ? result : [...CRITERIA];
}

// Process one input record against the connected app. `ctx` carries the
// tenant repo so kind-specific adapters (e.g. vistage) can persist resolved
// state such as a UserToken.
async function processRecord(connector, rawRecord, criteria, ctx) {
  const input = normalizeRecord(rawRecord);

  // Build the query the connected app will search on — only the canonical
  // values for the selected criteria, so we don't leak unrelated fields.
  const query = {};
  for (const field of criteria) {
    const val = input.norm[field];
    if (val) query[field] = input.raw[field]; // send the readable value
  }

  // If the input has no value for ANY selected criterion it cannot be
  // matched — classify as new with the honest reason and skip the network
  // call entirely. Setting `error` flags the UI to disable the add-lead
  // CTA (we can't say it's safely new — we never even looked).
  if (Object.keys(query).length === 0) {
    return {
      input: input.raw,
      classification: 'new',
      score: 0,
      matchedRecord: null,
      matchedOn: [],
      error: 'No data on any selected criterion — nothing to match against.',
    };
  }

  let candidates = [];
  try {
    const fetched = await fetchCandidates(connector, query, criteria, 200, ctx);
    // Normalize each candidate so the engine compares like-for-like.
    candidates = fetched.map((c) => {
      const norm = normalizeRecord(c.canonical);
      return { raw: c.raw, norm: norm.norm };
    });
  } catch (err) {
    // A connector failure for one record must not abort the whole job.
    // Surface it on the result card as an honest error so the operator
    // sees the real reason and can fix the connector — NOT a misleading
    // "review — matched on weak signals". The result is classified as
    // `new` (no evidence of a match) but with `error` set so the UI
    // disables the add-lead CTA (we never confirmed the record is new).
    return {
      input: input.raw,
      classification: 'new',
      score: 0,
      matchedRecord: null,
      matchedOn: [],
      error: `Lookup failed against the connected app: ${err.message}`,
    };
  }

  const isNameOnlyQuery =
    Object.keys(query).length === 1 &&
    typeof query.name === 'string' &&
    query.name.trim() !== '';

  if (isNameOnlyQuery && candidates.length > 0) {
    return buildCandidateResults(input, candidates, criteria);
  }

  const verdict = classifyInput(input, candidates, criteria);
  return { input: input.raw, ...verdict };
}

function categorizeCandidate(input, candidate, criteria) {
  const result = scorePair(input, candidate, criteria);
  const effectiveScore = result.strongIdMatch
    ? Math.max(result.aggregate, THRESHOLDS.duplicate)
    : result.aggregate;

  let classification = 'new';
  if (effectiveScore >= THRESHOLDS.duplicate) classification = 'duplicate';
  else if (effectiveScore >= THRESHOLDS.review) classification = 'review';

  if (
    classification === 'duplicate' &&
    !result.strongIdMatch &&
    result.corroboratingFields < 2
  ) {
    classification = 'review';
  }

  if (classification === 'new') {
    return {
      classification,
      score: effectiveScore,
      matchedRecord: null,
      matchedOn: [],
    };
  }

  return {
    classification,
    score: effectiveScore,
    matchedRecord: candidate.raw,
    matchedOn: result.matchedOn,
  };
}

export function buildCandidateResults(input, candidates, criteria) {
  return candidates.map((candidate) => ({
    input: input.raw,
    ...categorizeCandidate(input, candidate, criteria),
  }));
}

// Run the bounded-concurrency pool over all records.
async function runPool(items, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  async function next() {
    while (cursor < items.length) {
      const idx = cursor++;
      results[idx] = await worker(items[idx], idx);
    }
  }
  const workers = Array.from(
    { length: Math.min(CONCURRENCY, items.length) },
    next
  );
  await Promise.all(workers);
  return results.flat();
}

// Execute a job. `repo` is a tenant-scoped repository, `job` the job row,
// `connector` the connector row, `records` the raw input records.
export async function runSweep({ repo, job, connector, records }) {
  repo.updateJobStatus(job.id, 'running', { totalInput: records.length });

  const criteria = JSON.parse(job.criteria_json);
  let results;
  try {
    results = await runPool(records, (rec) =>
      processRecord(connector, rec, criteria, { repo })
    );
  } catch (err) {
    repo.updateJobStatus(job.id, 'failed', { error: err.message });
    repo.audit('job.failed', { jobId: job.id, error: err.message });
    return;
  }

  // Persist every result with its evidence.
  repo.insertResults(job.id, results);

  const counts = { duplicate: 0, review: 0, new: 0 };
  for (const r of results) counts[r.classification]++;

  repo.updateJobStatus(job.id, 'completed', {
    totalInput: records.length,
    countDuplicate: counts.duplicate,
    countReview: counts.review,
    countNew: counts.new,
  });
  repo.audit('job.completed', { jobId: job.id, counts });

  // Best-effort completion webhook back to the connected app.
  await dispatchWebhook({
    repo,
    job,
    event: 'search.completed',
    payload: {
      jobId: job.id,
      totalInput: records.length,
      counts,
    },
  }).catch(() => {});

  return counts;
}
