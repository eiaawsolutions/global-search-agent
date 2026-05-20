// End-to-end Vistage integration test (Common API V1).
//
// Boots the full agent in-process, registers a `vistage` connector pointed at
// a Claritas Vistage Common API V1 endpoint, and runs a real sweep — proving
// the adapter, orchestrator, and matching engine work against live Vistage
// data.
//
// Run:  node test/vistage-sweep.mjs
// Credentials are read from the environment ONLY — never hardcoded, so this
// file is safe to commit. Set them first (a gitignored .env works):
//   VISTAGE_BASE_URL, VISTAGE_CLIENT_ID, VISTAGE_SECRET_KEY,
//   VISTAGE_COMPANY_ID, VISTAGE_USER_ID, VISTAGE_USER_NAME,
//   VISTAGE_COMPANY_PREFIX (optional), VISTAGE_USER_MODULE_ID (optional)
//
// Not part of `npm test` — it makes live network calls.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const REQUIRED = [
  'VISTAGE_BASE_URL',
  'VISTAGE_CLIENT_ID',
  'VISTAGE_SECRET_KEY',
  'VISTAGE_COMPANY_ID',
  'VISTAGE_USER_ID',
  'VISTAGE_USER_NAME',
];
const missing = REQUIRED.filter((k) => !process.env[k]);
if (missing.length) {
  console.error(
    `Vistage credentials not set. Missing: ${missing.join(', ')}\n` +
      'Set them in the environment (see the header of this file) and retry.'
  );
  process.exit(1);
}

// Isolate this run: ephemeral DB + known bootstrap key, before any import
// of the app reads config.
const tmpDb = path.join(os.tmpdir(), `vistage-sweep-${Date.now()}.db`);
process.env.NODE_ENV = 'development';
process.env.DB_PATH = tmpDb;
process.env.PORT = '4199';
process.env.ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
process.env.SESSION_SECRET = crypto.randomBytes(32).toString('hex');
process.env.BOOTSTRAP_API_KEY = 'gsa_' + crypto.randomBytes(24).toString('hex');

const BASE = process.env.VISTAGE_BASE_URL;
const API = 'http://127.0.0.1:4199';
const KEY = process.env.BOOTSTRAP_API_KEY;

function ok(m) { console.log(`  \x1b[32m✔\x1b[0m ${m}`); }
function bad(m) { console.log(`  \x1b[31mx\x1b[0m ${m}`); }

async function api(method, p, body) {
  const res = await fetch(API + p, {
    method,
    headers: {
      Authorization: `Bearer ${KEY}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

async function main() {
  console.log(`\nVistage sweep integration test (V1) → ${BASE}\n`);

  // Boot the app (applies migrations, creates the bootstrap tenant).
  await import('../src/server.js');
  await new Promise((r) => setTimeout(r, 300)); // let the listener bind

  // 1. Register the Vistage connector with a V1-shaped UserToken.
  console.log('1. POST /api/connectors  (kind=vistage)');
  const reg = await api('POST', '/api/connectors', {
    name: 'Vistage Staging',
    kind: 'vistage',
    base_url: BASE,
    vistage: {
      client_id: process.env.VISTAGE_CLIENT_ID,
      secret_key: process.env.VISTAGE_SECRET_KEY,
    },
    // Staging UserLogin may not be provisioned for API use — supply the
    // V1-shaped pre-known UserToken instead.
    user_token: {
      CompanyId: parseInt(process.env.VISTAGE_COMPANY_ID, 10),
      CompanyPrefix: process.env.VISTAGE_COMPANY_PREFIX || null,
      UserId: process.env.VISTAGE_USER_ID,
      UserModuleId: parseInt(process.env.VISTAGE_USER_MODULE_ID, 10) || 0,
      UserName: process.env.VISTAGE_USER_NAME,
    },
    modules: ['Member', 'Lead'],
  });
  if (reg.status !== 201) {
    bad(`registration failed (${reg.status}): ${JSON.stringify(reg.json)}`);
    process.exitCode = 1;
    return;
  }
  const connectorId = reg.json.connector.id;
  ok(`connector registered (${connectorId})`);
  if (reg.json.reachable) ok('credential probe passed (token acquired)');
  else bad(`probe note: ${reg.json.reachability_note}`);

  // 2. Run a sweep. One input deliberately matches a live staging row
  //    "chung"; one is a clear non-match that should classify as new.
  console.log('2. POST /api/search  (sweep against live Vistage data)');
  const sweep = await api('POST', '/api/search', {
    connector_id: connectorId,
    criteria: ['name'],
    records: [
      { name: 'chung' },
      { name: 'Zzqqxx Nonexistent Person' },
    ],
  });
  if (sweep.status !== 201) {
    bad(`sweep failed (${sweep.status}): ${JSON.stringify(sweep.json)}`);
    process.exitCode = 1;
    return;
  }
  const job = sweep.json.job;
  ok(`job ${job.id} completed — status ${job.status}`);
  console.log(
    `      counts: duplicate=${job.counts.duplicate} ` +
      `review=${job.counts.review} new=${job.counts.new}`
  );

  // 3. Inspect the classified results + evidence.
  console.log('3. GET /api/search/:id/results');
  const out = await api('GET', `/api/search/${job.id}/results`);
  for (const r of out.json.results || []) {
    const ev = (r.matched_on || [])
      .map((m) => `${m.field} ${Math.round(m.score * 100)}%`)
      .join(', ');
    console.log(
      `      "${r.input.name}" → ${r.classification}` +
        (ev ? ` [${ev}]` : '') +
        (r.matched_record
          ? ` vs Vistage row name2="${r.matched_record.name2 ?? ''}"`
          : '')
    );
  }

  const matched = (out.json.results || []).find(
    (r) => r.input.name === 'chung'
  );
  if (matched && matched.classification !== 'new') {
    ok('live Vistage row matched the input record');
  } else {
    bad('expected "chung" to match a live row — check field mapping');
    process.exitCode = 1;
  }

  console.log('\n\x1b[32mVistage sweep integration verified.\x1b[0m\n');
}

main()
  .catch((err) => {
    console.error(`\n\x1b[31mSweep test threw:\x1b[0m ${err.stack}\n`);
    process.exitCode = 1;
  })
  .finally(() => {
    for (const ext of ['', '-wal', '-shm']) {
      try { fs.unlinkSync(tmpDb + ext); } catch {}
    }
    setTimeout(() => process.exit(process.exitCode || 0), 200);
  });
