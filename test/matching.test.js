// Matching engine tests — the accuracy-critical core. Verifies normalization,
// the per-field matchers, the weighted aggregation, and the duplicate /
// review / new classification boundaries.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeEmail,
  normalizePhone,
  normalizeName,
  normalizeCompany,
  normalizeRecord,
} from '../src/matching/normalize.js';
import { jaroWinkler, levenshteinSim, tokenSortRatio } from '../src/matching/similarity.js';
import { classifyInput, scorePair } from '../src/matching/engine.js';

// Helper: normalize a plain record into the engine's expected shape.
const rec = (r) => {
  const n = normalizeRecord(r);
  return { raw: n.raw, norm: n.norm };
};

test('normalizeEmail canonicalizes Gmail dots and +tags', () => {
  assert.equal(normalizeEmail('Jane.Doe+sales@Gmail.com'), 'janedoe@gmail.com');
  // Non-Gmail keeps dots (they can be significant).
  assert.equal(normalizeEmail('jane.doe@acme.com'), 'jane.doe@acme.com');
  assert.equal(normalizeEmail('not-an-email'), '');
});

test('normalizePhone produces a stable digit form', () => {
  assert.equal(normalizePhone('+60 12-345 6789'), '60123456789');
  assert.equal(normalizePhone('012-345 6789'), '60123456789'); // trunk 0 → MY code
  // A '+'-prefixed international number keeps its country code.
  assert.equal(normalizePhone('+1 (555) 010-2030'), '15550102030');
  // A leading trunk 0 is swapped for the supplied default country code.
  assert.equal(normalizePhone('0555 010 2030', '1'), '15550102030');
});

test('normalizeName drops honorifics; company drops legal suffixes', () => {
  assert.equal(normalizeName('Dr. Jane Doe'), 'jane doe');
  assert.equal(normalizeName('Datuk Ahmad Ismail'), 'ahmad ismail');
  assert.equal(normalizeCompany('Acme Sdn. Bhd.'), 'acme');
  assert.equal(normalizeCompany('Globex Corporation'), 'globex');
});

test('similarity primitives behave', () => {
  assert.equal(jaroWinkler('martha', 'martha'), 1);
  assert.ok(jaroWinkler('martha', 'marhta') > 0.9); // transposition tolerant
  assert.ok(levenshteinSim('kitten', 'sitting') > 0.5);
  assert.ok(tokenSortRatio('jane doe', 'doe jane') > 0.99); // word order ignored
});

test('exact email match → duplicate with email evidence', () => {
  const input = rec({ name: 'Jane Doe', email: 'jane@acme.com' });
  const candidates = [
    rec({ name: 'J. Doe', email: 'jane@acme.com', company: 'Acme' }),
  ];
  const verdict = classifyInput(input, candidates, ['email', 'name']);
  assert.equal(verdict.classification, 'duplicate');
  assert.ok(verdict.score >= 0.85);
  const emailEvidence = verdict.matchedOn.find((m) => m.field === 'email');
  assert.ok(emailEvidence, 'email must be reported as the matching data point');
  assert.equal(emailEvidence.score, 1);
});

test('phone match survives a missing country code', () => {
  const input = rec({ name: 'Sam Lee', phone: '012-345 6789' });
  const candidates = [rec({ name: 'Samuel Lee', phone: '+60 12 345 6789' })];
  const verdict = classifyInput(input, candidates, ['phone']);
  assert.equal(verdict.classification, 'duplicate');
});

test('a single fuzzy name signal lands in REVIEW, not duplicate', () => {
  // One moderately-fuzzy field and nothing else is ambiguous: it could be the
  // same person, or two different people with similar names. The engine must
  // flag it for a human rather than auto-deciding.
  const input = rec({ name: 'Jonathan Smithe' });
  const candidates = [rec({ name: 'Jon Smith' })];
  const verdict = classifyInput(input, candidates, ['name', 'email']);
  assert.equal(verdict.classification, 'review');
  assert.ok(verdict.score >= 0.6 && verdict.score < 0.85);
});

test('matching company suffixes are normalized away (Trading/Sdn Bhd)', () => {
  // "Acme Global Trading Sdn Bhd" and "Acme Global" are the same company —
  // the normalizer strips legal-form noise, so a same-company + same-name
  // pair is correctly a duplicate.
  const input = rec({ name: 'Jane Doe', company: 'Acme Global' });
  const candidates = [
    rec({ name: 'Jane Doe', company: 'Acme Global Trading Sdn Bhd' }),
  ];
  const verdict = classifyInput(input, candidates, ['name', 'company']);
  assert.equal(verdict.classification, 'duplicate');
});

test('no candidate match → NEW with no fabricated evidence', () => {
  const input = rec({ name: 'Brand New Person', email: 'new@startup.io' });
  const candidates = [rec({ name: 'Someone Else', email: 'else@other.com' })];
  const verdict = classifyInput(input, candidates, ['email', 'name']);
  assert.equal(verdict.classification, 'new');
  // The Lead-Generation Contract: a "new" verdict carries NO matched record
  // and NO evidence — nothing is inferred.
  assert.equal(verdict.matchedRecord, null);
  assert.deepEqual(verdict.matchedOn, []);
});

test('criteria selection is honored — unselected fields do not match', () => {
  const input = rec({ name: 'Jane Doe', email: 'jane@acme.com' });
  const candidates = [rec({ name: 'Totally Different', email: 'jane@acme.com' })];
  // Match on NAME only — the identical email must be ignored.
  const verdict = classifyInput(input, candidates, ['name']);
  assert.equal(verdict.classification, 'new');
});

test('confidence guard: a lone fuzzy name cannot auto-declare a duplicate', () => {
  // "Ahmed Ismaill" vs "Ahmad Ismail" scores very high as a string, but a
  // name is not a unique identifier and there is no corroborating field —
  // the guard must cap this at "review", never "duplicate".
  const input = rec({ name: 'Ahmed Ismaill' });
  const candidates = [rec({ name: 'Ahmad Ismail', email: 'ahmad@globex.com' })];
  const verdict = classifyInput(input, candidates, ['name', 'email', 'phone']);
  assert.equal(verdict.classification, 'review');
});

test('confidence guard: an exact email match alone IS a duplicate', () => {
  // A strong identifier (email) match stands on its own — no corroboration
  // required. This is the counterpart to the guard above.
  const input = rec({ email: 'unique@person.com' });
  const candidates = [rec({ name: 'Different Name', email: 'unique@person.com' })];
  const verdict = classifyInput(input, candidates, ['name', 'email']);
  assert.equal(verdict.classification, 'duplicate');
});

test('empty input on all criteria scores zero (no false match)', () => {
  const input = rec({ company: 'Acme' });
  const candidates = [rec({ name: 'Jane', email: 'jane@acme.com' })];
  const { aggregate } = scorePair(input, candidates[0], ['email', 'phone']);
  assert.equal(aggregate, 0);
});
