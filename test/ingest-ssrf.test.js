// CSV ingestion + SSRF guard tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCsv, parseNameList } from '../src/ingest/csv.js';
import { assertSafeUrlShape, isPrivate } from '../src/connectors/ssrf-guard.js';

// ── CSV parser ─────────────────────────────────────────────────────
test('parseCsv reads a basic file with a header row', () => {
  const rows = parseCsv('name,email\nJane Doe,jane@acme.com\nAhmad,ahmad@x.com');
  assert.equal(rows.length, 2);
  assert.deepEqual(rows[0], { name: 'Jane Doe', email: 'jane@acme.com' });
});

test('parseCsv handles quoted fields with commas and newlines', () => {
  const csv =
    'name,company\n"Doe, Jane","Acme, Inc."\n"Multi\nline","Globex"';
  const rows = parseCsv(csv);
  assert.equal(rows[0].name, 'Doe, Jane');
  assert.equal(rows[0].company, 'Acme, Inc.');
  assert.equal(rows[1].name, 'Multi\nline');
});

test('parseCsv handles escaped double-quotes', () => {
  const rows = parseCsv('name\n"She said ""hi"""');
  assert.equal(rows[0].name, 'She said "hi"');
});

test('parseCsv strips a BOM and skips blank lines', () => {
  const rows = parseCsv('﻿name\nJane\n\n\nAhmad\n');
  assert.equal(rows.length, 2);
  assert.equal(rows[0].name, 'Jane');
});

test('parseCsv enforces the row cap', () => {
  const big = 'name\n' + Array.from({ length: 50 }, (_, i) => `p${i}`).join('\n');
  assert.throws(() => parseCsv(big, { maxRows: 10 }), /row limit/);
});

test('parseCsv rejects an empty file', () => {
  assert.throws(() => parseCsv(''), /empty/);
});

test('parseNameList splits lines and commas', () => {
  const recs = parseNameList('Jane Doe\nAhmad, Siti\n\nLim Wei');
  assert.deepEqual(
    recs.map((r) => r.name),
    ['Jane Doe', 'Ahmad', 'Siti', 'Lim Wei']
  );
});

// ── SSRF guard ─────────────────────────────────────────────────────
test('isPrivate flags loopback, link-local, and RFC-1918 ranges', () => {
  assert.equal(isPrivate('127.0.0.1'), true);
  assert.equal(isPrivate('169.254.169.254'), true); // cloud metadata
  assert.equal(isPrivate('10.1.2.3'), true);
  assert.equal(isPrivate('192.168.0.5'), true);
  assert.equal(isPrivate('172.16.5.5'), true);
  assert.equal(isPrivate('::1'), true);
  assert.equal(isPrivate('8.8.8.8'), false); // public — allowed
});

test('assertSafeUrlShape rejects private hosts and bad schemes', () => {
  assert.throws(() => assertSafeUrlShape('http://127.0.0.1/api'), /private/i);
  assert.throws(() => assertSafeUrlShape('http://localhost:3000'), /localhost/i);
  assert.throws(() => assertSafeUrlShape('ftp://example.com'), /http/i);
  assert.throws(() => assertSafeUrlShape('http://169.254.169.254/'), /private/i);
  // A public https URL passes.
  assert.ok(assertSafeUrlShape('https://crm.example.com/api'));
});

test('assertSafeUrlShape enforces https when required (production)', () => {
  assert.throws(
    () => assertSafeUrlShape('http://crm.example.com', { requireHttps: true }),
    /https/i
  );
  assert.ok(
    assertSafeUrlShape('https://crm.example.com', { requireHttps: true })
  );
});
