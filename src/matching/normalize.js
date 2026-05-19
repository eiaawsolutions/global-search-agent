// Field normalization. Matching accuracy lives or dies here: two records
// that are "the same" must reduce to identical (or near-identical) canonical
// forms before any comparison happens. Each normalizer is deterministic and
// pure — same input always yields the same output.

// Lowercase, collapse whitespace, strip accents/diacritics.
function basic(s) {
  if (s == null) return '';
  return String(s)
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '') // combining marks
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

// Email: lowercase; for Gmail-class providers strip dots and +tags in the
// local part since they all route to one inbox. Other providers keep the
// local part intact (a dot can be significant there).
const DOT_AND_PLUS_AGNOSTIC = new Set([
  'gmail.com',
  'googlemail.com',
]);

export function normalizeEmail(raw) {
  const e = basic(raw);
  const at = e.lastIndexOf('@');
  if (at <= 0) return ''; // not a usable email — treated as "no value"
  let local = e.slice(0, at);
  const domain = e.slice(at + 1);
  if (!domain.includes('.')) return '';
  local = local.split('+')[0];
  if (DOT_AND_PLUS_AGNOSTIC.has(domain)) local = local.replace(/\./g, '');
  return `${local}@${domain}`;
}

// Phone → digits only, then a best-effort E.164-ish canonical form.
// We do not depend on a full libphonenumber: the comparison only needs a
// stable canonical key, and the matcher also compares the last 7-9 digits
// so a missing country code still matches.
export function normalizePhone(raw, defaultCountry = '60') {
  if (raw == null) return '';
  let d = String(raw).replace(/[^\d+]/g, '');
  if (!d) return '';
  if (d.startsWith('+')) return d.slice(1).replace(/\D/g, '');
  d = d.replace(/\D/g, '');
  // Local format starting with a trunk 0 → swap for default country code.
  if (d.startsWith('0')) d = defaultCountry + d.slice(1);
  return d;
}

// The comparable "national core" of a phone — the trailing significant
// digits — so +60 12-345 6789 and 012-345 6789 still line up.
export function phoneCore(normalized) {
  if (!normalized) return '';
  return normalized.length > 9 ? normalized.slice(-9) : normalized;
}

// Person name: normalized, with a few honorifics dropped so "Dr. Jane Doe"
// and "Jane Doe" converge. Order is preserved (handled by token-sort in the
// matcher, not here).
const HONORIFICS = new Set([
  'mr', 'mrs', 'ms', 'miss', 'dr', 'prof', 'sir', 'madam', 'mdm',
  'datuk', 'dato', 'datin', 'tan', 'sri', 'haji', 'hajjah',
]);

export function normalizeName(raw) {
  const tokens = basic(raw)
    .replace(/[.,]/g, ' ')
    .split(' ')
    .filter((t) => t && !HONORIFICS.has(t));
  return tokens.join(' ');
}

// Company name: normalized, with legal-suffix noise removed so
// "Acme Sdn. Bhd." and "Acme" converge.
const COMPANY_SUFFIXES = new Set([
  'sdn', 'bhd', 'sdnbhd', 'inc', 'incorporated', 'llc', 'ltd', 'limited',
  'corp', 'corporation', 'co', 'company', 'plc', 'gmbh', 'ag', 'pte',
  'group', 'holdings', 'enterprise', 'enterprises', 'trading',
]);

export function normalizeCompany(raw) {
  const tokens = basic(raw)
    .replace(/[.,&]/g, ' ')
    .split(' ')
    .filter((t) => t && !COMPANY_SUFFIXES.has(t));
  return tokens.join(' ');
}

// Location: normalized; punctuation flattened. Kept loose because location
// is a low-weight, supporting signal — not a primary key.
export function normalizeLocation(raw) {
  return basic(raw).replace(/[.,/]/g, ' ').replace(/\s+/g, ' ').trim();
}

// Normalize a whole record to canonical fields. Unknown input keys are
// mapped via a few common aliases so callers can pass loosely-shaped data.
const ALIASES = {
  name: ['name', 'full_name', 'fullname', 'contact_name', 'person'],
  email: ['email', 'email_address', 'e-mail', 'mail'],
  phone: ['phone', 'phone_number', 'mobile', 'tel', 'telephone', 'contact'],
  company: ['company', 'company_name', 'organization', 'organisation', 'org', 'employer'],
  location: ['location', 'city', 'address', 'region', 'country', 'state'],
};

function pick(record, canonical) {
  for (const key of ALIASES[canonical]) {
    for (const rk of Object.keys(record)) {
      if (rk.toLowerCase() === key) return record[rk];
    }
  }
  return record[canonical];
}

export function normalizeRecord(record = {}) {
  const raw = {
    name: pick(record, 'name') ?? '',
    email: pick(record, 'email') ?? '',
    phone: pick(record, 'phone') ?? '',
    company: pick(record, 'company') ?? '',
    location: pick(record, 'location') ?? '',
  };
  return {
    raw, // original-ish values, for display
    norm: {
      name: normalizeName(raw.name),
      email: normalizeEmail(raw.email),
      phone: normalizePhone(raw.phone),
      phoneCore: phoneCore(normalizePhone(raw.phone)),
      company: normalizeCompany(raw.company),
      location: normalizeLocation(raw.location),
    },
  };
}

export const CRITERIA = ['name', 'email', 'phone', 'company', 'location'];
