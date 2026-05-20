// Read-only dump of recent lead-push activity.
// For each `search_results` row that was marked lead_status='added', prints
// the input name, the Vistage RecordId we got back (lead_ref), the time it
// was added, and the audit row that recorded the push. Never prints secrets.
//
// Usage:
//   node scripts/inspect-recent-leads.mjs [limit]
import db from '../src/db/index.js';

const limit = parseInt(process.argv[2], 10) || 20;

const rows = db
  .prepare(
    `SELECT id, job_id, input_json, classification, lead_status, lead_ref,
            error, created_at
       FROM search_results
       WHERE lead_status = 'added'
       ORDER BY created_at DESC
       LIMIT ?`
  )
  .all(limit);

console.log(`Recent leads pushed (lead_status='added'): ${rows.length}`);
for (const r of rows) {
  let input = {};
  try { input = JSON.parse(r.input_json || '{}'); } catch {}
  console.log('---');
  console.log(`result_id   : ${r.id}`);
  console.log(`job_id      : ${r.job_id}`);
  console.log(`input.name  : ${input.name || '(none)'}`);
  console.log(`input.email : ${input.email || '(none)'}`);
  console.log(`input.phone : ${input.phone || '(none)'}`);
  console.log(`classification : ${r.classification}`);
  console.log(`lead_status : ${r.lead_status}`);
  console.log(`lead_ref    : ${r.lead_ref || '(null — Vistage did not return a RecordId)'}`);
  console.log(`created_at  : ${r.created_at}`);
}

const audits = db
  .prepare(
    `SELECT action, detail_json, created_at
       FROM audit_log
       WHERE action IN ('lead.added','lead.add_failed')
       ORDER BY created_at DESC
       LIMIT ?`
  )
  .all(limit);

console.log(`\nAudit log lead events: ${audits.length}`);
for (const a of audits) {
  let d = {};
  try { d = JSON.parse(a.detail_json || '{}'); } catch {}
  console.log(`  ${a.created_at}  ${a.action}  ref=${d.leadRef ?? d.lead_ref ?? '(none)'}  result=${d.resultId ?? '(none)'}`);
}
