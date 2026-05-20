// Enrichment normalizer tests — the contract-critical core of "View details".
// Verifies that buildEnrichment() shapes a connected-app detail record into
// the canonical {profile, linkage, meetings, payment, outstanding, pending}
// object WITHOUT fabricating anything: a field the CRM did not return must
// stay null/[]; a payment month with no source record must stay `no-record`,
// never assumed paid. This is the Lead-Generation Contract applied to
// enrichment.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildEnrichment,
  DEFAULT_ENRICH_MAP,
  PAYMENT_STATES,
  ATTENDANCE_STATES,
} from '../src/enrich/normalize.js';

const YEAR = 2026;

test('buildEnrichment fabricates nothing for an empty detail record', () => {
  const en = buildEnrichment({}, {}, { year: YEAR });
  // Every profile scalar is null — not "", not a guess.
  for (const v of Object.values(en.profile)) assert.equal(v, null);
  for (const v of Object.values(en.linkage)) assert.equal(v, null);
  // No meeting records.
  assert.deepEqual(en.meetings, []);
  // No payment data → 12 honest no-record cells, NOT assumed paid.
  assert.equal(en.payment.hasData, false);
  assert.equal(en.payment.grid.length, 12);
  for (const cell of en.payment.grid) {
    assert.equal(cell.status, 'no-record');
    assert.equal(cell.amount, null);
  }
  assert.equal(en.payment.paidMonths, 0);
  // Outstanding unknown → null amount + null flag (not 0, not false).
  assert.equal(en.outstanding.amount, null);
  assert.equal(en.outstanding.isOutstanding, null);
  assert.equal(en.pending.length, 0);
  assert.equal(en.meta.sourcedFromCrm, true);
  assert.ok(en.meta.fieldsMissing.length > 0);
});

test('buildEnrichment maps a Vistage-shaped member detail record', () => {
  const detail = {
    MemberNo: 'VM1585',
    name2: 'Chung Wei Ling',
    Salutation: 'Ms',
    Mobile: '+60123456789',
    Status: 'Active',
    Group: 'Sarawak Group 3',
    GroupNo: 'SG-03',
    GroupType: 'Executive',
    Chair: 'Datuk Lim',
    GroupLeader: 'Datuk Lim',
    Role: 'Member',
    JoinDate: '2019-03-01',
  };
  const en = buildEnrichment(detail, {}, { year: YEAR });
  assert.equal(en.profile.memberNo, 'VM1585');
  assert.equal(en.profile.fullName, 'Chung Wei Ling');
  assert.equal(en.profile.salutation, 'Ms');
  assert.equal(en.profile.phone, '+60123456789');
  assert.equal(en.profile.status, 'Active');
  assert.equal(en.linkage.group, 'Sarawak Group 3');
  assert.equal(en.linkage.groupNumber, 'SG-03');
  assert.equal(en.linkage.groupType, 'Executive');
  assert.equal(en.linkage.chair, 'Datuk Lim');
  assert.equal(en.linkage.groupLeader, 'Datuk Lim');
  assert.equal(en.linkage.role, 'Member');
});

test('payment grid folds dated records into the right months', () => {
  const detail = {
    Currency: 'MYR',
    Payments: [
      { Date: `${YEAR}-01-10`, Amount: 500, Status: 'Paid' },
      { Date: `${YEAR}-02-10`, Amount: 500, Status: 'Paid' },
      { Date: `${YEAR}-03-10`, Amount: 500, Status: 'Overdue' },
    ],
  };
  const en = buildEnrichment(detail, {}, { year: YEAR });
  assert.equal(en.payment.hasData, true);
  assert.equal(en.payment.grid[0].status, 'paid'); // Jan
  assert.equal(en.payment.grid[1].status, 'paid'); // Feb
  assert.equal(en.payment.grid[2].status, 'overdue'); // Mar
  // Months 4–12 stay no-record — never assumed paid.
  for (let i = 3; i < 12; i++) {
    assert.equal(en.payment.grid[i].status, 'no-record');
  }
  assert.equal(en.payment.paidMonths, 2);
  assert.equal(en.payment.overdueMonths, 1);
});

test('two records in one month: the more severe state wins', () => {
  const detail = {
    Payments: [
      { Date: `${YEAR}-01-05`, Amount: 200, Status: 'Paid' },
      { Date: `${YEAR}-01-25`, Amount: 200, Status: 'Overdue' },
    ],
  };
  const en = buildEnrichment(detail, {}, { year: YEAR });
  // Overdue is more severe than paid — it must NOT be overwritten by the
  // earlier paid row simply because of arrival order.
  assert.equal(en.payment.grid[0].status, 'overdue');
});

test('outstanding balance drives the isOutstanding flag honestly', () => {
  const detail = { OutstandingAmount: 1500 };
  const en = buildEnrichment(detail, {}, { year: YEAR });
  assert.equal(en.outstanding.amount, 1500);
  assert.equal(en.outstanding.isOutstanding, true);

  // Explicit false from the CRM is respected.
  const en2 = buildEnrichment(
    { OutstandingAmount: 1500, IsOutstanding: 'false' },
    {},
    { year: YEAR }
  );
  assert.equal(en2.outstanding.isOutstanding, false);
});

test('meetings list shapes a flat array, attendance state classified', () => {
  const detail = {
    Meetings: [
      { Date: '2026-03-15', Type: 'Monthly', Status: 'Attended' },
      { Date: '2026-04-12', Type: 'Monthly', Status: 'Absent' },
      { Date: '2026-05-10', Type: 'AGM', Status: 'Excused with apologies' },
    ],
  };
  const en = buildEnrichment(detail, {}, { year: YEAR });
  assert.equal(en.meetings.length, 3);
  // Sorted newest first.
  assert.equal(en.meetings[0].date, '2026-05-10');
  assert.equal(en.meetings[0].status, 'excused');
  assert.equal(en.meetings[1].status, 'absent');
  assert.equal(en.meetings[2].status, 'attended');
});

test('meetings accepts a numbered-key shape (Meeting1, Meeting2)', () => {
  // Some Claritas detail responses use Meeting1, Meeting2, ... keys nested
  // under a single object instead of a flat array — the shaper handles both.
  const detail = {
    Meetings: {
      Meeting1: { Date: '2026-02-01', Status: 'Attended' },
      Meeting2: { Date: '2026-03-01', Status: 'Absent' },
    },
  };
  const en = buildEnrichment(detail, {}, { year: YEAR });
  assert.equal(en.meetings.length, 2);
  assert.equal(en.meetings[0].date, '2026-03-01');
  assert.equal(en.meetings[0].status, 'absent');
});

test('pending items combine CRM alerts with derived honest flags', () => {
  const detail = {
    PendingItems: 'Annual declaration form pending',
    OutstandingAmount: 800,
    Payments: [{ Date: `${YEAR}-02-01`, Amount: 500, Status: 'Overdue' }],
  };
  const en = buildEnrichment(detail, {}, { year: YEAR });
  const labels = en.pending.map((p) => p.label);
  assert.ok(
    labels.some((l) => /Annual declaration/.test(l)),
    'CRM-authored pending item must be preserved'
  );
  assert.ok(
    en.pending.some(
      (p) => p.source === 'derived' && /overdue/i.test(p.label)
    ),
    'derived overdue flag must be added'
  );
});

test('past renewal date is surfaced as a high-severity derived flag', () => {
  const detail = { RenewalDate: '2025-01-15' };
  const en = buildEnrichment(detail, {}, { year: YEAR });
  assert.ok(
    en.pending.some(
      (p) => p.source === 'derived' && /renewal overdue/i.test(p.label)
    )
  );
});

test('a connector enrich_field_map overrides the default key lookup', () => {
  // The detail record uses non-standard keys; the connector's
  // enrich_field_map tells the normalizer where to find them.
  const detail = { their_member_id: 'ZZ-1', their_name: 'Pat Doe' };
  const en = buildEnrichment(
    detail,
    { memberNo: ['their_member_id'], fullName: ['their_name'] },
    { year: YEAR }
  );
  assert.equal(en.profile.memberNo, 'ZZ-1');
  assert.equal(en.profile.fullName, 'Pat Doe');
});

test('HTML-entity-escaped free text is cleaned, not rendered raw', () => {
  // Vistage's API HTML-escapes some free-text fields; the normalizer must
  // strip the escaping so the UI doesn't render &lt;div&gt; literally.
  const detail = {
    name2: '&lt;b&gt;Jane Doe&lt;/b&gt;',
    Group: 'Klang Valley &amp; Penang',
  };
  const en = buildEnrichment(detail, {}, { year: YEAR });
  assert.equal(en.profile.fullName, 'Jane Doe');
  assert.equal(en.linkage.group, 'Klang Valley & Penang');
});

test('junk amounts do not become 0 — they stay null', () => {
  const detail = { OutstandingAmount: 'not a number lol' };
  const en = buildEnrichment(detail, {}, { year: YEAR });
  assert.equal(en.outstanding.amount, null);
  // And therefore the isOutstanding flag stays null too.
  assert.equal(en.outstanding.isOutstanding, null);
});

test('DEFAULT_ENRICH_MAP exposes every canonical concept the UI renders', () => {
  for (const key of [
    'memberNo', 'fullName', 'email', 'phone',
    'group', 'groupNumber', 'groupType', 'chair', 'groupLeader', 'role',
    'meetings', 'payments', 'outstandingAmount',
  ]) {
    assert.ok(
      Array.isArray(DEFAULT_ENRICH_MAP[key]) && DEFAULT_ENRICH_MAP[key].length,
      `DEFAULT_ENRICH_MAP missing or empty for ${key}`
    );
  }
});

test('exported constants list every state the UI styles', () => {
  // Sanity: the renderer's CSS uses these class suffixes (pay-paid, meet-absent,
  // etc.) so a state added here must be added in app.css too.
  assert.deepEqual(
    PAYMENT_STATES.sort(),
    ['due', 'no-record', 'overdue', 'paid', 'partial'].sort()
  );
  assert.deepEqual(
    ATTENDANCE_STATES.sort(),
    ['absent', 'attended', 'excused', 'late', 'unknown'].sort()
  );
});
