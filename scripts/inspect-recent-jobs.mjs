// Show the last ~20 jobs and their results, focused on `chung wei ling`
// look-ups. Helps spot whether stale lead_status='added' rows are being
// returned to fresh sweeps.
import db from '../src/db/index.js';

const jobs = db
  .prepare(
    `SELECT id, source, status, total_input, created_at
       FROM search_jobs
       ORDER BY created_at DESC
       LIMIT 10`
  )
  .all();

console.log(`Last ${jobs.length} jobs:\n`);
for (const j of jobs) {
  console.log(`--- ${j.created_at}  job=${j.id}  source=${j.source}  status=${j.status}  input=${j.total_input}`);
  const rows = db
    .prepare(
      `SELECT id, input_json, classification, lead_status, lead_ref
         FROM search_results
         WHERE job_id = ?`
    )
    .all(j.id);
  for (const r of rows) {
    let input = {};
    try { input = JSON.parse(r.input_json || '{}'); } catch {}
    console.log(`     result=${r.id}  name=${JSON.stringify(input.name)}  class=${r.classification}  lead_status=${r.lead_status}  ref=${r.lead_ref || ''}`);
  }
}
