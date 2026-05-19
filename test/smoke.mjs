// End-to-end smoke test.
//
// Spins up (1) a MOCK connected app implementing the per-app API contract
// with a tiny in-memory "database", and (2) the real Global Search Agent.
// Then drives a full sweep through the HTTP API and asserts the duplicate /
// review / new classification and the add-lead CTA all work end-to-end.
//
// Run:  node test/smoke.mjs    (after `npm install`)
import http from 'node:http';
import { spawn } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const AGENT_PORT = 4199;
const MOCK_PORT = 4198;
let passed = 0;
let failed = 0;

function check(label, cond) {
  if (cond) {
    passed++;
    console.log(`  ✔ ${label}`);
  } else {
    failed++;
    console.error(`  ✖ ${label}`);
  }
}

// ── Mock connected app — the "any application" the agent sweeps ──────
// Its database holds three existing records. It implements:
//   POST /api/records/search  → returns candidate records
//   POST /api/leads           → accepts a new lead
const mockDb = [
  { id: 'c1', full_name: 'Jane Doe', email_address: 'jane.doe@acme.com', phone: '+60123456789', org: 'Acme' },
  { id: 'c2', full_name: 'Ahmad Ismail', email_address: 'ahmad@globex.com', phone: '+60198887777', org: 'Globex' },
  { id: 'c3', full_name: 'Siti Nurhaliza', email_address: 'siti@example.my', phone: '+60177776666', org: 'Example My' },
];
const pushedLeads = [];

const mockServer = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const json = body ? JSON.parse(body) : {};
    if (req.url === '/api/records/search' && req.method === 'POST') {
      // A real app would index on the criteria; the mock just returns all
      // rows and lets the agent's engine do the matching.
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ records: mockDb }));
    } else if (req.url === '/api/leads' && req.method === 'POST') {
      const lead = json.lead || {};
      const id = `lead-${pushedLeads.length + 1}`;
      pushedLeads.push({ id, ...lead });
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ id }));
    } else {
      res.writeHead(404);
      res.end('{}');
    }
  });
});

// ── HTTP helper ─────────────────────────────────────────────────────
function request(port, method, urlPath, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      { host: '127.0.0.1', port, method, path: urlPath, headers: {
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...headers,
      } },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () =>
          resolve({ status: res.statusCode, body: data ? JSON.parse(data) : {} })
        );
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForPort(port, tries = 50) {
  for (let i = 0; i < tries; i++) {
    try {
      await request(port, 'GET', '/health');
      return true;
    } catch {
      await sleep(150);
    }
  }
  throw new Error(`Server on :${port} did not start`);
}

// ── Run ─────────────────────────────────────────────────────────────
async function main() {
  console.log('\n▶ Global Search Agent — end-to-end smoke test\n');

  // Start the mock connected app.
  await new Promise((r) => mockServer.listen(MOCK_PORT, r));
  console.log(`  mock connected-app listening on :${MOCK_PORT}`);

  // Start the agent in a child process with an isolated DB and dev secrets.
  const dbPath = path.join(os.tmpdir(), `gsa-smoke-${Date.now()}.db`);
  const agent = spawn(process.execPath, ['src/server.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(AGENT_PORT),
      NODE_ENV: 'development',
      DB_PATH: dbPath,
      ENCRYPTION_KEY: 'f'.repeat(64),
      SESSION_SECRET: 'e'.repeat(64),
      BOOTSTRAP_TENANT_NAME: 'Smoke Tenant',
      // The mock connected app runs on 127.0.0.1; allow private connector
      // hosts for this local test only (force-disabled in production).
      ALLOW_PRIVATE_CONNECTORS: 'true',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  // Capture the bootstrap API key the agent prints on first migrate.
  let apiKey = null;
  let agentOut = '';
  agent.stdout.on('data', (d) => {
    agentOut += d.toString();
    const m = agentOut.match(/API key\s*:\s*(gsa_[a-f0-9]+)/);
    if (m) apiKey = m[1];
  });
  agent.stderr.on('data', (d) => process.stderr.write(`  [agent] ${d}`));

  try {
    await waitForPort(AGENT_PORT);
    // Give stdout a beat to flush the bootstrap banner.
    for (let i = 0; i < 20 && !apiKey; i++) await sleep(100);
    check('agent booted and printed a bootstrap API key', !!apiKey);
    if (!apiKey) throw new Error('no API key — cannot continue');

    const auth = { Authorization: `Bearer ${apiKey}` };

    // 1. Register the mock app as a connector.
    const reg = await request(AGENT_PORT, 'POST', '/api/connectors', {
      headers: auth,
      body: {
        name: 'Mock CRM',
        base_url: `http://127.0.0.1:${MOCK_PORT}/api`,
        search_path: '/records/search',
        create_path: '/leads',
        auth_type: 'none',
        // Map the mock app's field names → the agent's canonical names.
        field_map: { name: 'full_name', email: 'email_address', company: 'org' },
      },
    });
    check('connector registered (201)', reg.status === 201);
    const connectorId = reg.body.connector?.id;
    check('connector has an id', !!connectorId);

    // 2. Run a sweep: one exact duplicate, one fuzzy (review), one new.
    const sweep = await request(AGENT_PORT, 'POST', '/api/search', {
      headers: auth,
      body: {
        connector_id: connectorId,
        criteria: ['email', 'name', 'phone'],
        records: [
          // Exact email match to c1 → duplicate.
          { name: 'Jane D.', email: 'JANE.DOE@acme.com' },
          // Fuzzy name only, no other signal → review.
          { name: 'Ahmed Ismaill' },
          // Nothing in the mock DB → new lead.
          { name: 'Brand New Lead', email: 'fresh@startup.io', phone: '+60111112222' },
        ],
      },
    });
    check('sweep completed (201)', sweep.status === 201);
    const job = sweep.body.job;
    check('job status is completed', job?.status === 'completed');
    check('1 duplicate detected', job?.counts.duplicate === 1);
    check('1 review detected', job?.counts.review === 1);
    check('1 new detected', job?.counts.new === 1);

    // 3. Fetch results and inspect the evidence.
    const results = await request(
      AGENT_PORT,
      'GET',
      `/api/search/${job.id}/results`,
      { headers: auth }
    );
    check('results fetched (200)', results.status === 200);
    const dup = results.body.results.find((r) => r.classification === 'duplicate');
    check(
      'duplicate reports EMAIL as the matching data point',
      !!dup && dup.matched_on.some((m) => m.field === 'email')
    );
    check(
      'duplicate names the matched record',
      !!dup?.matched_record && /jane/i.test(JSON.stringify(dup.matched_record))
    );

    // 4. The CTA — add the "new" record as a lead.
    const newResult = results.body.results.find((r) => r.classification === 'new');
    check('new result exposes the add-lead CTA', newResult?.can_add_lead === true);
    const add = await request(
      AGENT_PORT,
      'POST',
      `/api/results/${newResult.id}/add-lead`,
      { headers: auth }
    );
    check('add-lead succeeded (200)', add.status === 200);
    check('connected app received the pushed lead', pushedLeads.length === 1);
    check(
      'pushed lead carries the right email',
      pushedLeads[0]?.email === 'fresh@startup.io'
    );

    // 5. CTA is idempotent — a second click is rejected.
    const addAgain = await request(
      AGENT_PORT,
      'POST',
      `/api/results/${newResult.id}/add-lead`,
      { headers: auth }
    );
    check('double add-lead is rejected (409)', addAgain.status === 409);
    check('no duplicate lead pushed', pushedLeads.length === 1);

    // 6. Auth is enforced — no key → 401.
    const noauth = await request(AGENT_PORT, 'GET', '/api/jobs');
    check('unauthenticated API request is rejected (401)', noauth.status === 401);
    // (SSRF rejection is covered by the unit suite in ingest-ssrf.test.js —
    //  this smoke run sets ALLOW_PRIVATE_CONNECTORS so it can reach the mock
    //  app on 127.0.0.1, which would mask an SSRF assertion here.)
  } finally {
    agent.kill('SIGTERM');
    mockServer.close();
  }

  console.log(`\n${failed === 0 ? '✅' : '❌'} smoke test: ${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('smoke test crashed:', err);
  process.exit(1);
});
