// Enrichment normalizer.
//
// Given a raw DETAIL record fetched from a connected app for ONE matched
// finding, this builds a canonical `enrichment` object the UI renders on the
// "View details" panel: the related user profile, the group they belong to
// (number, type, leader/chair, the role they play), the meeting attendance
// log, a current-calendar-year payment-status-by-month grid, the outstanding
// balance, and any other pending status the operator should see.
//
// CONTRACT — verification over assumption (the Lead-Generation Contract
// applied to enrichment): NOTHING here is fabricated or inferred. Every
// field is populated ONLY from a value the connected app actually returned.
// A field the CRM did not supply stays `null` (scalars) or `[]` (lists).
// Payment months with no source record stay `status: "no-record"` — never
// assumed paid, never assumed missed.
//
// The normalizer is connector-agnostic. Each connector kind hands it a raw
// detail object plus an optional `enrichMap` (the connector's
// enrich_field_map merged with kind defaults); this module does the shaping.

// Canonical month abbreviations for the 12-cell payment grid.
const MONTH_LABELS = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
];

// A payment cell is in one of these states. `no-record` is the honest
// default for any month the CRM did not return a record for.
export const PAYMENT_STATES = ['paid', 'due', 'overdue', 'partial', 'no-record'];

// Words a CRM uses for a settled vs an open payment. Matched
// case-insensitively against whatever status string the CRM returns; an
// unrecognized status is surfaced verbatim rather than coerced.
const PAID_WORDS = ['paid', 'settled', 'complete', 'completed', 'cleared', 'success'];
const OVERDUE_WORDS = ['overdue', 'arrears', 'late', 'past due', 'pastdue'];
const PARTIAL_WORDS = ['partial', 'part paid', 'partpaid', 'instal'];
const DUE_WORDS = ['due', 'pending', 'unpaid', 'outstanding', 'open', 'invoiced'];

// Meeting-attendance states. `unknown` is the honest default for a meeting
// row that carries no status field.
export const ATTENDANCE_STATES = ['attended', 'absent', 'excused', 'late', 'unknown'];
const ATTENDED_WORDS = ['attend', 'present', 'showed', 'show', 'in attendance'];
const ABSENT_WORDS = ['absent', 'no show', 'noshow', 'missed', 'did not attend'];
const EXCUSED_WORDS = ['excused', 'apologies', 'mc', 'medical leave', 'leave'];
const LATE_WORDS = ['late', 'tardy'];

// Severity ranking for "pending" items (high renders first in the UI).
const SEVERITY_RANK = { high: 3, medium: 2, low: 1 };

// ── small helpers ─────────────────────────────────────────────────────

function pick(obj, keys) {
  if (!obj || typeof obj !== 'object') return null;
  for (const k of keys) {
    const v = obj[k];
    if (v != null && String(v).trim() !== '') return String(v).trim();
  }
  return null;
}

function clean(s) {
  if (s == null) return null;
  const out = String(s)
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return out === '' ? null : out;
}

// Parse a money-ish value to a number. Returns null for anything not
// clearly numeric — we never coerce junk into 0 (a real 0 must come from
// the CRM).
function toAmount(v) {
  if (v == null || v === '') return null;
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  const n = parseFloat(String(v).replace(/[^0-9.\-]/g, ''));
  return Number.isFinite(n) ? n : null;
}

function truthy(v) {
  if (v === true) return true;
  if (v === false || v == null) return false;
  const s = String(v).trim().toLowerCase();
  return s === '1' || s === 'true' || s === 'y' || s === 'yes';
}

// Parse a date-like value to a JS Date, returning null on anything we can't
// confidently parse. Accepts ISO, "YYYY-MM-DD", "DD/MM/YYYY" (Malaysian
// convention), and "YYYY-MM" month-only strings.
function toDate(v) {
  if (v == null || v === '') return null;
  if (v instanceof Date && !isNaN(v.getTime())) return v;
  const s = String(v).trim();
  // DD/MM/YYYY
  const dmy = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (dmy) {
    const [, d, m, y] = dmy;
    const dt = new Date(Number(y), Number(m) - 1, Number(d));
    return isNaN(dt.getTime()) ? null : dt;
  }
  // YYYY-MM (month-only)
  const ym = s.match(/^(\d{4})-(\d{1,2})$/);
  if (ym) {
    const dt = new Date(Number(ym[1]), Number(ym[2]) - 1, 1);
    return isNaN(dt.getTime()) ? null : dt;
  }
  const dt = new Date(s);
  return isNaN(dt.getTime()) ? null : dt;
}

// Classify a status string into one of PAYMENT_STATES; returns the verbatim
// string if it matches none of the known buckets (so the UI can surface
// "Refunded" or "Waived" unchanged instead of guessing).
function classifyPaymentStatus(raw, amountPaid, amountDue) {
  const s = String(raw || '').trim().toLowerCase();
  if (!s) {
    // No status text — infer ONLY from the amounts when both are present.
    if (amountPaid != null && amountDue != null) {
      if (amountPaid >= amountDue && amountDue > 0) return 'paid';
      if (amountPaid > 0 && amountPaid < amountDue) return 'partial';
      if (amountPaid === 0 && amountDue > 0) return 'due';
    }
    return null; // genuinely unknown — caller decides
  }
  if (PAID_WORDS.some((w) => s.includes(w))) return 'paid';
  if (OVERDUE_WORDS.some((w) => s.includes(w))) return 'overdue';
  if (PARTIAL_WORDS.some((w) => s.includes(w))) return 'partial';
  if (DUE_WORDS.some((w) => s.includes(w))) return 'due';
  return raw; // surface the verbatim CRM term
}

function classifyAttendance(raw) {
  const s = String(raw || '').trim().toLowerCase();
  if (!s) return 'unknown';
  if (ATTENDED_WORDS.some((w) => s.includes(w))) return 'attended';
  if (ABSENT_WORDS.some((w) => s.includes(w))) return 'absent';
  if (EXCUSED_WORDS.some((w) => s.includes(w))) return 'excused';
  if (LATE_WORDS.some((w) => s.includes(w))) return 'late';
  return raw; // surface the verbatim CRM term
}

// More severe of two statuses wins when two records collide in the same
// month or meeting slot.
const PAYMENT_SEVERITY = { 'no-record': 0, paid: 1, partial: 2, due: 3, overdue: 4 };
function moreSeverePayment(a, b) {
  const sa = PAYMENT_SEVERITY[a] ?? 1.5;
  const sb = PAYMENT_SEVERITY[b] ?? 1.5;
  return sa >= sb ? a : b;
}

// ── default field map ────────────────────────────────────────────────
// Keys are the canonical enrichment concepts; values are the candidate
// field names the normalizer looks for on the raw detail object. A
// connector can override or extend this via its enrich_field_map_json
// (shallow-merged: the connector's value REPLACES the default for that key,
// it does not merge into the array).
export const DEFAULT_ENRICH_MAP = {
  // ── profile ──
  memberNo: ['MemberNo', 'memberNo', 'member_no', 'MemberID', 'MemberId', 'AccountNo'],
  fullName: ['FullName', 'name2', 'name1', 'Name', 'MemberName', 'ContactName', 'full_name'],
  salutation: ['Salutation', 'Title'],
  jobTitle: ['JobTitle', 'Designation', 'Position'],
  email: ['Email', 'EmailAddress', 'Email1'],
  phone: ['Mobile', 'Phone', 'Cell', 'ContactNo'],
  status: ['Status', 'MemberStatus', 'RecStatusName'],
  joinDate: ['JoinDate', 'EnrolledOn', 'StartDate', 'CreatedTS'],
  renewalDate: ['RenewalDate', 'NextRenewal', 'EndDate'],

  // ── group linkage ──
  group: ['Group', 'GroupName'],
  groupNumber: ['GroupNo', 'GroupNumber', 'GroupCode'],
  groupType: ['GroupType', 'GroupCategory'],
  chair: ['Chair', 'ChairName', 'GroupChair'],
  groupLeader: ['GroupLeader', 'Leader', 'GroupLead'],
  reportsTo: ['ReportsTo', 'Manager', 'Supervisor'],
  role: ['Role', 'MemberRole', 'PositionInGroup'],

  // ── meetings ──
  // A flat list field (Meetings/MeetingHistory/Attendance) OR a numbered
  // shape ({ Meeting1: {...}, Meeting2: {...} }) — both are read.
  meetings: ['Meetings', 'MeetingHistory', 'Attendance', 'MeetingAttendance'],

  // ── payments ──
  payments: ['Payments', 'PaymentHistory', 'PaymentSchedule', 'Invoices', 'BillingHistory'],
  currency: ['Currency', 'CurrencyCode'],
  outstandingAmount: ['OutstandingAmount', 'Outstanding', 'BalanceDue', 'Balance'],
  isOutstanding: ['IsOutstanding', 'HasOutstanding', 'OutstandingFlag'],

  // ── pending alerts (free-form list of CRM-authored notes/flags) ──
  pendingItems: ['PendingItems', 'Alerts', 'Notes', 'OutstandingItems'],
};

// Shallow-merge an override map (from the connector's enrich_field_map_json)
// onto the defaults. Each value must be an array of candidate keys; an
// override REPLACES, not merges, the default array — operators get full
// control of which fields are tried.
function buildFieldMap(override) {
  if (!override || typeof override !== 'object') return DEFAULT_ENRICH_MAP;
  const merged = { ...DEFAULT_ENRICH_MAP };
  for (const [k, v] of Object.entries(override)) {
    if (Array.isArray(v) && v.length) merged[k] = v;
    else if (typeof v === 'string') merged[k] = [v];
  }
  return merged;
}

// ── meetings normalizer ──────────────────────────────────────────────
// Accepts either an array of meeting rows OR an object of numbered keys
// ({ Meeting1, Meeting2, ... }). Returns [{ date, type, status, notes }],
// sorted newest first.
function shapeMeetings(rawList) {
  let rows = [];
  if (Array.isArray(rawList)) {
    rows = rawList;
  } else if (rawList && typeof rawList === 'object') {
    rows = Object.values(rawList);
  } else {
    return [];
  }

  const out = [];
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    const date = toDate(r.Date ?? r.MeetingDate ?? r.date ?? r.HeldOn);
    const status = classifyAttendance(
      r.Status ?? r.Attendance ?? r.AttendanceStatus ?? r.status
    );
    const type = clean(r.Type ?? r.MeetingType ?? r.type ?? null);
    const notes = clean(r.Notes ?? r.Remarks ?? r.notes ?? null);
    if (!date && !status && !type && !notes) continue; // empty row
    out.push({
      date: date ? date.toISOString().slice(0, 10) : null,
      type,
      status,
      notes,
    });
  }
  // Newest first; rows with no date sink to the bottom but are kept.
  out.sort((a, b) => {
    if (!a.date && !b.date) return 0;
    if (!a.date) return 1;
    if (!b.date) return -1;
    return b.date.localeCompare(a.date);
  });
  return out;
}

// ── payment grid builder ─────────────────────────────────────────────
// Given a list of payment rows and the target calendar year, produces a
// 12-cell grid. Months with no source record stay `no-record`. Two records
// in the same month collide to the MORE SEVERE state (overdue > due >
// partial > paid).
function buildPaymentGrid(rawList, year) {
  const grid = MONTH_LABELS.map((label, i) => ({
    month: i + 1,
    label,
    status: 'no-record',
    amount: null,
    paidAmount: null,
    dueDate: null,
    paidDate: null,
  }));

  let hasData = false;
  let paidMonths = 0;
  let overdueMonths = 0;
  let dueMonths = 0;
  let partialMonths = 0;

  const rows = Array.isArray(rawList) ? rawList : [];
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    const dueDate = toDate(r.DueDate ?? r.Date ?? r.dueDate ?? r.InvoiceDate);
    const paidDate = toDate(r.PaidDate ?? r.SettledDate ?? r.paidDate);
    // Anchor the row to a calendar month — prefer the due date, fall back
    // to the paid date.
    const anchor = dueDate || paidDate;
    if (!anchor) continue;
    if (anchor.getFullYear() !== year) continue; // outside this year's grid

    const amountDue = toAmount(r.Amount ?? r.AmountDue ?? r.Total ?? r.amount);
    const amountPaid = toAmount(r.AmountPaid ?? r.PaidAmount ?? r.paid);
    const status = classifyPaymentStatus(r.Status ?? r.status, amountPaid, amountDue);
    if (status == null) continue; // genuinely unknown; never invent a state

    const idx = anchor.getMonth();
    const cell = grid[idx];
    const merged = moreSeverePayment(cell.status, status);
    cell.status = merged;
    cell.amount = amountDue ?? cell.amount;
    cell.paidAmount = amountPaid ?? cell.paidAmount;
    cell.dueDate = dueDate ? dueDate.toISOString().slice(0, 10) : cell.dueDate;
    cell.paidDate = paidDate ? paidDate.toISOString().slice(0, 10) : cell.paidDate;
    hasData = true;
  }

  for (const cell of grid) {
    if (cell.status === 'paid') paidMonths++;
    else if (cell.status === 'overdue') overdueMonths++;
    else if (cell.status === 'due') dueMonths++;
    else if (cell.status === 'partial') partialMonths++;
  }

  return {
    year,
    grid,
    hasData,
    paidMonths,
    overdueMonths,
    dueMonths,
    partialMonths,
  };
}

// ── pending items ────────────────────────────────────────────────────
// CRM-authored alerts merged with the normalizer's honest derived flags
// (e.g. "outstanding balance > 0" or "renewal date is in the past").
function buildPending(detail, fmap, payment, outstanding) {
  const out = [];

  // 1. CRM-authored: a string array, a comma string, or a list of objects.
  const rawList = pick(detail, fmap.pendingItems);
  if (rawList) {
    const items = Array.isArray(rawList)
      ? rawList
      : String(rawList).split(/\s*[;|]\s*|\n+/);
    for (const item of items) {
      const label =
        typeof item === 'object'
          ? clean(item.label ?? item.title ?? item.note)
          : clean(item);
      if (label) out.push({ label, severity: 'medium', source: 'crm' });
    }
  }
  // Also accept the detail's actual array values, in case the connector
  // mapped pendingItems to a nested object on the detail row.
  for (const k of fmap.pendingItems) {
    const v = detail?.[k];
    if (Array.isArray(v)) {
      for (const item of v) {
        const label =
          typeof item === 'object'
            ? clean(item.label ?? item.title ?? item.note)
            : clean(item);
        if (label && !out.some((x) => x.label === label)) {
          out.push({ label, severity: 'medium', source: 'crm' });
        }
      }
    }
  }

  // 2. Derived: outstanding balance.
  if (outstanding.isOutstanding === true && outstanding.amount != null) {
    out.push({
      label: `Outstanding balance ${outstanding.currency || ''} ${outstanding.amount}`.trim(),
      severity: 'high',
      source: 'derived',
    });
  } else if (outstanding.amount != null && outstanding.amount > 0) {
    out.push({
      label: `Outstanding balance ${outstanding.currency || ''} ${outstanding.amount}`.trim(),
      severity: 'high',
      source: 'derived',
    });
  }

  // 3. Derived: overdue payment months.
  if (payment.overdueMonths > 0) {
    out.push({
      label: `${payment.overdueMonths} overdue payment month${payment.overdueMonths === 1 ? '' : 's'} this year`,
      severity: 'high',
      source: 'derived',
    });
  }

  // 4. Derived: renewal date in the past.
  const renewal = toDate(pick(detail, fmap.renewalDate));
  if (renewal && renewal.getTime() < Date.now()) {
    out.push({
      label: `Renewal overdue (${renewal.toISOString().slice(0, 10)})`,
      severity: 'high',
      source: 'derived',
    });
  }

  // Sort high → medium → low; stable within rank.
  out.sort(
    (a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0)
  );
  return out;
}

// ── main entry ────────────────────────────────────────────────────────
export function buildEnrichment(detail, enrichMapOverride = {}, opts = {}) {
  const fmap = buildFieldMap(enrichMapOverride);
  const year = Number.isFinite(opts.year)
    ? opts.year
    : new Date().getFullYear();
  const d = detail && typeof detail === 'object' ? detail : {};

  // ── profile ──
  const profile = {
    memberNo: pick(d, fmap.memberNo),
    fullName: clean(pick(d, fmap.fullName)),
    salutation: pick(d, fmap.salutation),
    jobTitle: clean(pick(d, fmap.jobTitle)),
    email: pick(d, fmap.email),
    phone: pick(d, fmap.phone),
    status: pick(d, fmap.status),
    joinDate: pick(d, fmap.joinDate),
    renewalDate: pick(d, fmap.renewalDate),
  };

  // ── linkage ──
  const linkage = {
    group: clean(pick(d, fmap.group)),
    groupNumber: pick(d, fmap.groupNumber),
    groupType: pick(d, fmap.groupType),
    chair: clean(pick(d, fmap.chair)),
    groupLeader: clean(pick(d, fmap.groupLeader)),
    reportsTo: clean(pick(d, fmap.reportsTo)),
    role: pick(d, fmap.role),
  };

  // ── meetings ──
  const meetingsRaw = (() => {
    for (const k of fmap.meetings) {
      const v = d?.[k];
      if (v) return v;
    }
    return null;
  })();
  const meetings = shapeMeetings(meetingsRaw);

  // ── payments ──
  const paymentsRaw = (() => {
    for (const k of fmap.payments) {
      const v = d?.[k];
      if (Array.isArray(v)) return v;
    }
    return [];
  })();
  const currency = pick(d, fmap.currency);
  const payment = {
    currency,
    ...buildPaymentGrid(paymentsRaw, year),
  };

  // ── outstanding ──
  const outstandingAmount = toAmount(pick(d, fmap.outstandingAmount));
  const outstandingFlagRaw = pick(d, fmap.isOutstanding);
  const outstanding = {
    amount: outstandingAmount,
    currency,
    // Tri-state: true / false / null (unknown). Never default to false when
    // the CRM didn't say.
    isOutstanding:
      outstandingFlagRaw != null
        ? truthy(outstandingFlagRaw)
        : outstandingAmount != null
          ? outstandingAmount > 0
          : null,
  };

  // ── pending ──
  const pending = buildPending(d, fmap, payment, outstanding);

  // ── meta: which canonical concepts the CRM actually delivered ──
  const fieldsFound = [];
  const fieldsMissing = [];
  const check = (label, present) =>
    (present ? fieldsFound : fieldsMissing).push(label);
  check('memberNo', !!profile.memberNo);
  check('fullName', !!profile.fullName);
  check('email', !!profile.email);
  check('phone', !!profile.phone);
  check('group', !!linkage.group);
  check('chair', !!linkage.chair || !!linkage.groupLeader);
  check('meetings', meetings.length > 0);
  check('payment', payment.hasData);
  check('outstanding', outstanding.amount != null);

  return {
    profile,
    linkage,
    meetings,
    payment,
    outstanding,
    pending,
    meta: {
      sourcedFromCrm: true,
      fieldsFound,
      fieldsMissing,
    },
  };
}
