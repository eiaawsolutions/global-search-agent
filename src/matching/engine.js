// The matching engine.
//
// Given one normalized INPUT record and a list of normalized CANDIDATE
// records (fetched from a connected app), it decides whether the input is a
// DUPLICATE, needs human REVIEW, or is NEW — and reports exactly which data
// points drove the decision.
//
// Design choices:
//  - Deterministic + explainable. No LLM in the hot path. Every score is
//    reproducible and every decision carries its evidence (`matchedOn`).
//  - Criteria-driven. The caller picks which fields to match on (name,
//    email, phone, company, location); only those contribute.
//  - Evidence over assumption. Nothing is inferred or fabricated — this is
//    the Lead-Generation Contract applied to dedup: a "new" verdict means
//    "no evidence of a match", never "probably new".

import {
  jaroWinkler,
  tokenSortRatio,
  tokenContainment,
} from './similarity.js';

// Per-field weight = how much a strong match on that field counts toward the
// aggregate. Email and phone are near-unique identifiers and dominate; name
// and company are fuzzy and supporting; location is weak corroboration only.
export const FIELD_WEIGHTS = {
  email: 0.95,
  phone: 0.9,
  name: 0.6,
  company: 0.55,
  location: 0.4,
};

// Aggregate-score thresholds for the final verdict.
export const THRESHOLDS = {
  duplicate: 0.85, // >= → duplicate
  review: 0.6, // [review, duplicate) → needs a human
  // < review → new
};

// A per-field match score is only considered "evidence" above this floor —
// keeps near-random fuzzy noise out of the matchedOn list.
const EVIDENCE_FLOOR = 0.5;

// "Strong identifier" fields are near-unique to a person: a confirmed match
// on one of these is, on its own, sufficient evidence of a duplicate. The
// fuzzy attribute fields (name, company, location) are NOT — many distinct
// people share a similar name. A confirmed strong-identifier match is one
// scoring at/above this bar.
const STRONG_IDENTIFIERS = new Set(['email', 'phone']);
const STRONG_MATCH_BAR = 0.95;

// ── Per-field matchers ───────────────────────────────────────────────
// Each returns a score in [0,1] for one field of (input, candidate).

function matchEmail(a, b) {
  if (!a.email || !b.email) return 0;
  return a.email === b.email ? 1 : 0; // canonical email: exact or nothing
}

function matchPhone(a, b) {
  if (!a.phone || !b.phone) return 0;
  if (a.phone === b.phone) return 1;
  // Fall back to comparing the national core so a missing country code on
  // one side does not cause a miss.
  if (a.phoneCore && a.phoneCore === b.phoneCore) return 0.97;
  return 0;
}

function matchName(a, b) {
  if (!a.name || !b.name) return 0;
  // Best of: order-insensitive fuzzy (token-sort) and subset containment
  // (handles middle names / partial names). Containment is discounted
  // slightly so a full match always outranks a partial one.
  const sorted = tokenSortRatio(a.name, b.name);
  const contained = tokenContainment(a.name, b.name) * 0.92;
  return Math.max(sorted, contained);
}

function matchCompany(a, b) {
  if (!a.company || !b.company) return 0;
  const sorted = tokenSortRatio(a.company, b.company);
  const contained = tokenContainment(a.company, b.company) * 0.9;
  return Math.max(sorted, contained);
}

function matchLocation(a, b) {
  if (!a.location || !b.location) return 0;
  if (a.location === b.location) return 1;
  // Locations are messy; a containment check ("kuala lumpur" within
  // "kuala lumpur malaysia") plus a fuzzy fallback is enough for a weak
  // corroborating signal.
  const contained = tokenContainment(a.location, b.location);
  return Math.max(contained, jaroWinkler(a.location, b.location) * 0.85);
}

const MATCHERS = {
  email: matchEmail,
  phone: matchPhone,
  name: matchName,
  company: matchCompany,
  location: matchLocation,
};

// ── Pair scoring ─────────────────────────────────────────────────────
// Score one input record against one candidate over the selected criteria.
// The aggregate is a weighted mean over criteria that BOTH records populate
// (an absent field neither helps nor hurts). matchedOn is the evidence list.
export function scorePair(input, candidate, criteria) {
  const fields = [];
  let weightedSum = 0;
  let weightTotal = 0;
  let comparableFields = 0; // criteria both records actually populate
  let strongIdMatch = false; // a confirmed email/phone hit
  let corroboratingFields = 0; // distinct fields scoring as evidence

  for (const field of criteria) {
    const matcher = MATCHERS[field];
    if (!matcher) continue;
    const inHas = !!input.norm[field];
    const candHas = !!candidate.norm[field];
    if (!inHas || !candHas) continue; // field not comparable for this pair
    comparableFields++;

    const score = matcher(input.norm, candidate.norm);
    const weight = FIELD_WEIGHTS[field];
    weightedSum += score * weight;
    weightTotal += weight;

    if (STRONG_IDENTIFIERS.has(field) && score >= STRONG_MATCH_BAR) {
      strongIdMatch = true;
    }
    if (score >= EVIDENCE_FLOOR) {
      corroboratingFields++;
      fields.push({
        field,
        score: round(score),
        inputValue: input.raw[field],
        matchValue: candidate.raw?.[field] ?? candidate.norm[field],
      });
    }
  }

  const aggregate = weightTotal > 0 ? weightedSum / weightTotal : 0;
  return {
    aggregate: round(aggregate),
    matchedOn: fields,
    weightTotal,
    comparableFields,
    strongIdMatch,
    corroboratingFields,
  };
}

// ── Classification ───────────────────────────────────────────────────
// Compare one input against ALL candidates and produce the final verdict.
export function classifyInput(input, candidates, criteria) {
  let best = { aggregate: 0, matchedOn: [], weightTotal: 0 };
  let bestCandidate = null;

  for (const candidate of candidates) {
    const result = scorePair(input, candidate, criteria);
    if (result.aggregate > best.aggregate) {
      best = result;
      bestCandidate = candidate;
    }
    // A perfect score cannot be beaten — stop early.
    if (best.aggregate >= 1) break;
  }

  let classification = 'new';
  if (best.aggregate >= THRESHOLDS.duplicate) classification = 'duplicate';
  else if (best.aggregate >= THRESHOLDS.review) classification = 'review';

  // Confidence guard. A high aggregate driven by a SINGLE fuzzy attribute
  // (a similar name and nothing else) is not enough to auto-declare a
  // duplicate — a name is not a unique identifier. Promote to "duplicate"
  // only when the evidence is genuinely strong:
  //   (a) a confirmed strong-identifier match (exact email or phone), OR
  //   (b) corroboration across at least two distinct fields.
  // Otherwise the verdict is capped at "review" so a human decides. This is
  // the Lead-Generation Contract applied to dedup: verification over
  // assumption — we do not merge records on a hunch.
  if (
    classification === 'duplicate' &&
    !best.strongIdMatch &&
    best.corroboratingFields < 2
  ) {
    classification = 'review';
  }

  // A "new" verdict carries no matched record and no evidence — by design.
  // We never attach a weak partial match to a record we're calling new.
  if (classification === 'new') {
    return {
      classification,
      score: best.aggregate,
      matchedRecord: null,
      matchedOn: [],
    };
  }

  return {
    classification,
    score: best.aggregate,
    matchedRecord: bestCandidate
      ? bestCandidate.raw || bestCandidate.norm
      : null,
    matchedOn: best.matchedOn,
  };
}

// A human-readable one-liner explaining a verdict — surfaced in the UI and
// API so the user sees *why*, not just *what*.
export function explain(result) {
  if (result.classification === 'new') {
    return 'No matching record found in the connected database.';
  }
  const points = result.matchedOn
    .map((m) => `${m.field} (${Math.round(m.score * 100)}%)`)
    .join(', ');
  const verb = result.classification === 'duplicate' ? 'Duplicate' : 'Possible match';
  return `${verb} — matched on ${points || 'weak signals'}.`;
}

function round(n) {
  return Math.round(n * 1000) / 1000;
}
