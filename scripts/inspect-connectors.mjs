// Read-only inspection of every connector row in the active database.
// Surfaces kind, base URL, generic paths, meta_json (modules + UserToken
// presence), and credential-blob length — enough to tell, at a glance,
// whether a connector was registered as Vistage or as Generic, and whether
// its UserToken / modules / default branch are in place.
//
// Never prints secrets. credential_enc is reported only as a byte length.
//
// Usage (locally or on the container):
//   node scripts/inspect-connectors.mjs
import db from '../src/db/index.js';
import { config } from '../src/config.js';

const rows = db
  .prepare(
    `SELECT id, tenant_id, name, kind, base_url, search_path, create_path,
            enrich_path, length(credential_enc) AS cred_bytes, meta_json,
            field_map_json, status, created_at
       FROM connectors
       ORDER BY created_at DESC`
  )
  .all();

console.log(`DB: ${config.dbPath}`);
console.log(`Connectors: ${rows.length}`);
for (const r of rows) {
  let meta = {};
  try { meta = JSON.parse(r.meta_json || '{}'); } catch {}
  const userToken = meta.userToken || null;
  console.log('---');
  console.log(`id           : ${r.id}`);
  console.log(`tenant_id    : ${r.tenant_id}`);
  console.log(`name         : ${r.name}`);
  console.log(`kind         : ${r.kind}`);
  console.log(`base_url     : ${r.base_url}`);
  console.log(`search_path  : ${r.search_path}`);
  console.log(`create_path  : ${r.create_path}`);
  console.log(`enrich_path  : ${r.enrich_path}`);
  console.log(`status       : ${r.status}`);
  console.log(`created_at   : ${r.created_at}`);
  console.log(`cred bytes   : ${r.cred_bytes ?? 0}`);
  console.log(`meta.modules : ${JSON.stringify(meta.modules || null)}`);
  console.log(`meta.userToken present : ${userToken ? 'yes' : 'no'}`);
  if (userToken) {
    console.log(
      `  CompanyId=${userToken.CompanyId} ` +
        `CompanyPrefix=${userToken.CompanyPrefix} ` +
        `UserId=${userToken.UserId} ` +
        `UserModuleId=${userToken.UserModuleId} ` +
        `UserName=${userToken.UserName}`
    );
  }
  console.log(`meta.defaultBranch : ${meta.defaultBranch || '(none)'}`);
}
