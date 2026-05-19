// Cross-tenant data-leakage test — MANDATORY for multi-tenant SaaS.
//
// SQLite has no row-level security; isolation is enforced by the scoped
// repository in src/db/index.js. This test proves a repository bound to
// tenant A can never see, fetch, or mutate tenant B's rows.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// Point the DB at a throwaway file BEFORE importing the db module.
process.env.DB_PATH = path.join(
  os.tmpdir(),
  `gsa-iso-test-${Date.now()}.db`
);
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

let global, forTenant, uuid, migrate;
let tenantA, tenantB;

before(async () => {
  ({ migrate } = await import('../src/db/migrate.js'));
  ({ global, forTenant, uuid } = await import('../src/db/index.js'));
  migrate({ silent: true });

  const { hashApiKey, generateApiKey } = await import('../src/utils/crypto.js');
  tenantA = uuid();
  tenantB = uuid();
  global.createTenant({
    id: tenantA,
    name: 'Tenant A',
    plan: 'pro',
    apiKeyHash: hashApiKey(generateApiKey()),
    webhookSecret: 'secretA',
  });
  global.createTenant({
    id: tenantB,
    name: 'Tenant B',
    plan: 'pro',
    apiKeyHash: hashApiKey(generateApiKey()),
    webhookSecret: 'secretB',
  });
});

test("tenant A cannot list tenant B's connectors", () => {
  const repoA = forTenant(tenantA);
  const repoB = forTenant(tenantB);

  repoB.createConnector({ name: 'B-CRM', base_url: 'https://b.example.com' });

  assert.equal(repoA.listConnectors().length, 0, 'A sees none of B');
  assert.equal(repoB.listConnectors().length, 1, 'B sees its own');
});

test("tenant A cannot fetch tenant B's connector by id", () => {
  const repoA = forTenant(tenantA);
  const repoB = forTenant(tenantB);

  const cB = repoB.createConnector({
    name: 'B-CRM-2',
    base_url: 'https://b2.example.com',
  });
  // Even with B's real connector id, A's scoped repo returns nothing.
  assert.equal(repoA.getConnector(cB.id), undefined);
  assert.ok(repoB.getConnector(cB.id), 'B can fetch its own');
});

test("tenant A cannot read tenant B's jobs or results", () => {
  const repoA = forTenant(tenantA);
  const repoB = forTenant(tenantB);

  const cB = repoB.createConnector({ name: 'B', base_url: 'https://b.example.com' });
  const jobB = repoB.createJob({
    connectorId: cB.id,
    criteria: ['email'],
    totalInput: 1,
  });
  repoB.insertResults(jobB.id, [
    { input: { email: 'secret@b.com' }, classification: 'new', score: 0, matchedOn: [] },
  ]);

  // A cannot get B's job, and gets an empty result set for B's job id.
  assert.equal(repoA.getJob(jobB.id), undefined);
  assert.equal(repoA.listResults(jobB.id).length, 0);
  assert.equal(repoB.listResults(jobB.id).length, 1, 'B sees its own results');
});

test("tenant A cannot mark a lead added on tenant B's result", () => {
  const repoA = forTenant(tenantA);
  const repoB = forTenant(tenantB);

  const cB = repoB.createConnector({ name: 'B', base_url: 'https://b.example.com' });
  const jobB = repoB.createJob({ connectorId: cB.id, criteria: ['email'], totalInput: 1 });
  repoB.insertResults(jobB.id, [
    { input: { email: 'x@b.com' }, classification: 'new', score: 0, matchedOn: [] },
  ]);
  const resultB = repoB.listResults(jobB.id)[0];

  // A's scoped UPDATE is filtered by tenant_id → it changes nothing.
  repoA.markLeadAdded(resultB.id, 'forged-ref');
  const after = repoB.getResult(resultB.id);
  assert.equal(after.lead_status, 'none', "B's result is untouched by A");
  assert.equal(after.lead_ref, null);
});

test('jobs and audit entries are scoped to their tenant', () => {
  const repoA = forTenant(tenantA);
  const repoB = forTenant(tenantB);

  const cA = repoA.createConnector({ name: 'A', base_url: 'https://a.example.com' });
  repoA.createJob({ connectorId: cA.id, criteria: ['name'], totalInput: 5 });

  const aJobs = repoA.listJobs();
  assert.ok(aJobs.every((j) => j.tenant_id === tenantA));
  // B's job list never includes A's jobs.
  assert.ok(repoB.listJobs().every((j) => j.tenant_id === tenantB));
});
