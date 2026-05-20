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
import { classifyInput, scorePair, explain } from '../src/matching/engine.js';

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

test('name matching is EXACT — a near-miss spelling is NEW, not a match', () => {
  // Name matching requires 100% identical normalized spelling. A similar but
  // not-identical name is a different person until proven otherwise — it
  // produces NO match and NO evidence (not even "review").
  const input = rec({ name: 'Jonathan Smithe' });
  const candidates = [rec({ name: 'Jon Smith' })];
  const verdict = classifyInput(input, candidates, ['name', 'email']);
  assert.equal(verdict.classification, 'new');
  assert.equal(verdict.score, 0);
});

test('name matching does NOT match on letter-level overlap', () => {
  // Regression for the production bug: "Hui Ng" was matching "chung" at 82%
  // because the matcher used Jaro-Winkler letter similarity. Exact matching
  // means these share no canonical form → score 0 → NEW.
  const input = rec({ name: 'Hui Ng' });
  const candidates = [
    rec({ name: 'chung' }),
    rec({ name: 'Kai Tan' }),
  ];
  const verdict = classifyInput(input, candidates, ['name']);
  assert.equal(verdict.classification, 'new');
  assert.equal(verdict.score, 0);
});

test('name matching is order-sensitive — reversed words do NOT match', () => {
  // "Jane Doe" and "Doe Jane" are treated as different names. Exact + ordered.
  const input = rec({ name: 'Jane Doe' });
  const candidates = [rec({ name: 'Doe Jane' })];
  const verdict = classifyInput(input, candidates, ['name']);
  assert.equal(verdict.classification, 'new');
});

test('a partial name is NOT a match — every word must be present', () => {
  // "John Smith" vs "John Michael Smith" — the middle name makes them
  // different records. No subset/containment matching for names.
  const input = rec({ name: 'John Smith' });
  const candidates = [rec({ name: 'John Michael Smith' })];
  const verdict = classifyInput(input, candidates, ['name']);
  assert.equal(verdict.classification, 'new');
});

test('an identical name (one field, no corroboration) lands in REVIEW', () => {
  // An exact full-name match is real evidence — but a name is not a unique
  // identifier, so on its own it is capped at "review" for a human to decide,
  // never auto-merged to "duplicate".
  const input = rec({ name: 'Jane Doe' });
  const candidates = [rec({ name: 'Jane Doe' })];
  const verdict = classifyInput(input, candidates, ['name']);
  assert.equal(verdict.classification, 'review');
  assert.equal(verdict.score, 1);
});

test('honorifics still normalize away before the exact comparison', () => {
  // Exact matching operates on the NORMALIZED form, so "Dr. Jane Doe" and
  // "Jane Doe" still converge — that is canonicalization, not fuzzy matching.
  const input = rec({ name: 'Dr. Jane Doe' });
  const candidates = [rec({ name: 'Jane Doe' })];
  const verdict = classifyInput(input, candidates, ['name']);
  assert.equal(verdict.classification, 'review');
  assert.equal(verdict.score, 1);
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

test('company matching is EXACT after normalization — extra REAL words do not match', () => {
  // "Acme Global" and "Acme" are different companies. The normalizer drops
  // legal suffixes (Sdn Bhd, Holdings, Group, ...) but NOT real distinguishing
  // words like "Global" — those stay, and strict comparison fails.
  // Strict-criteria rule: if the user asked to match on BOTH name AND company
  // and only one of the two agrees, that's not a duplicate — the weighted
  // aggregate falls below the review threshold and the verdict is NEW.
  const input = rec({ name: 'Jane Doe', company: 'Acme' });
  const candidates = [
    rec({ name: 'Jane Doe', company: 'Acme Global' }),
  ];
  const verdict = classifyInput(input, candidates, ['name', 'company']);
  assert.equal(verdict.classification, 'new');
  // A "new" verdict carries no matched_record and no evidence — exactly the
  // honest-no-fabrication contract.
  assert.equal(verdict.matchedRecord, null);
  assert.deepEqual(verdict.matchedOn, []);
});

test('company matching does NOT match on letter-level overlap', () => {
  // "Acme" vs "Acmex" must not be a partial match. Strict exact only.
  const input = rec({ company: 'Acme' });
  const candidates = [rec({ company: 'Acmex' })];
  const verdict = classifyInput(input, candidates, ['company']);
  assert.equal(verdict.classification, 'new');
  assert.equal(verdict.score, 0);
});

test('location matching is EXACT after normalization — KL is not Kuala Lumpur', () => {
  // Locations no longer match by containment or fuzzy similarity. "KL" is
  // not the same string as "kuala lumpur" — they're different until proven
  // otherwise. Cosmetic punctuation differences still normalize away.
  const input = rec({ location: 'KL' });
  const candidates = [rec({ location: 'Kuala Lumpur' })];
  const verdict = classifyInput(input, candidates, ['location']);
  assert.equal(verdict.classification, 'new');
  assert.equal(verdict.score, 0);
});

test('location matching: identical (after punctuation strip) DOES match', () => {
  // Sanity check that the normalizer is still in play — "Kuala Lumpur," and
  // "Kuala Lumpur" agree after the comma is flattened.
  const input = rec({ name: 'Jane Doe', location: 'Kuala Lumpur,' });
  const candidates = [rec({ name: 'Jane Doe', location: 'Kuala Lumpur' })];
  // Name + location both agree exactly → two corroborating attribute fields,
  // promotes the verdict to duplicate (the corroboration rule).
  const verdict = classifyInput(input, candidates, ['name', 'location']);
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

test('confidence guard: an identical name alone cannot auto-declare a duplicate', () => {
  // Even an EXACT name match is not a unique identifier — with no
  // corroborating field the verdict is capped at "review", never "duplicate".
  const input = rec({ name: 'Ahmad Ismail' });
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

// ── explain() — three honest states, never "weak signals" ───────────
test('explain() surfaces the error reason when one is attached', () => {
  // The error path (connector lookup failed, no data on any criterion, etc.)
  // must surface the real reason verbatim — no misleading "matched on weak
  // signals" wording. Operator sees what to fix.
  const msg = explain({
    classification: 'new',
    matchedOn: [],
    error: 'Lookup failed against the connected app: UserToken missing CompanyId.',
  });
  assert.match(msg, /UserToken missing CompanyId/);
  assert.doesNotMatch(msg, /weak signals/i);
});

test('explain() reports "no matching record" for an honest new verdict', () => {
  const msg = explain({ classification: 'new', matchedOn: [], error: null });
  assert.match(msg, /no matching record/i);
});

test('explain() lists the matched fields for a duplicate verdict', () => {
  const msg = explain({
    classification: 'duplicate',
    matchedOn: [{ field: 'email', score: 1 }, { field: 'name', score: 1 }],
  });
  assert.match(msg, /^Duplicate — matched on email \(100%\), name \(100%\)\.$/);
});

test('explain() never says "weak signals" — the phrase is banned', () => {
  // Belt-and-braces: try every plausible verdict shape and assert the old
  // wording is gone everywhere.
  const cases = [
    { classification: 'new', matchedOn: [] },
    { classification: 'new', matchedOn: [], error: 'boom' },
    { classification: 'duplicate', matchedOn: [{ field: 'email', score: 1 }] },
    { classification: 'review', matchedOn: [{ field: 'name', score: 1 }] },
    // Defensive: a duplicate without evidence should not invent a phrase.
    { classification: 'duplicate', matchedOn: [] },
  ];
  for (const v of cases) {
    assert.doesNotMatch(explain(v), /weak signals/i, JSON.stringify(v));
  }
});
