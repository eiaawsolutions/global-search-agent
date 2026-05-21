// Vistage / Claritas CRM adapter (Common API V1).
//
// The Vistage CRM exposes a SOAP-style `.svc` JSON API that does NOT implement
// the agent's generic 2-endpoint contract. This adapter bridges the gap: it
// signs requests, manages the access token, logs in once to obtain a
// UserToken, pulls Lead/Member/Contact/Account records via GetList for the
// matching engine, and pushes new leads back via Save (V1 addition).
//
// Auth (per the Vistage Common API V1 spec):
//   client_id  header = Client ID
//   t          header = 13-digit Unix epoch in MILLISECONDS
//   sign       header = HMAC-SHA256 hex, UPPER CASE
//     Signature 1 (GET /token)  : text = ClientID + t
//     Signature 2 (everything)  : text = ClientID + AccessToken + t
//     key for both = Secret Key
//
// Function endpoints in V1 take the CompanyId as a path segment:
//   POST /GetList/{CompanyId}    POST /Save/{CompanyId}    POST /UserLogin
// The adapter resolves CompanyId from the operator-supplied or UserLogin-
// derived UserToken — there is no other source of truth.
import crypto from 'node:crypto';
import { decrypt } from '../utils/crypto.js';
import { config } from '../config.js';
import { assertSafeUrl } from './ssrf-guard.js';

const REQUEST_TIMEOUT_MS = 15_000;

// Modules GetList can search per Common API V1. The connector's meta.modules
// narrows which of these to sweep; default sweeps the contact-bearing
// modules (Member + Lead). Field validation in routes/connectors.js rejects
// anything not in this list.
export const VISTAGE_MODULES = ['Lead', 'Member', 'Contact', 'Account'];

// LeadStatus codes per the V1 spec (`Save - Lead`). Exposed so the route
// handler that builds a Save payload uses the same enum the adapter knows.
export const LEAD_STATUS = {
  NEW: '1',
  WARM: '2',
  COLD: '3',
  CONVERTED: '4',
  NOT_INTERESTED: '7',
  INVALID: '8',
  NOT_SUITABLE: '9',
  RELEASED: '10',
};

// In-process token cache, keyed by connector id. The access token is valid
// for ~expire_time minutes; we refresh a minute early to avoid edge races.
// A process restart simply re-authenticates — no persistence needed.
const tokenCache = new Map(); // connectorId -> { token, expiresAt }

// ── credential bundle ────────────────────────────────────────────────
// A vistage connector stores its secrets as an encrypted JSON bundle in
// credential_enc: { clientId, secretKey, userName, password }. userName/
// password are optional (used only if the operator wants UserLogin to
// resolve the UserToken; otherwise a pre-known UserToken is supplied at
// registration).
function readCredentials(connector) {
  const raw = decrypt(connector.credential_enc);
  if (!raw) {
    throw new Error('Vistage connector has no stored credentials.');
  }
  let bundle;
  try {
    bundle = JSON.parse(raw);
  } catch {
    throw new Error('Vistage connector credential bundle is corrupt.');
  }
  if (!bundle.clientId || !bundle.secretKey) {
    throw new Error('Vistage credentials must include clientId and secretKey.');
  }
  return bundle;
}

// ── signing ───────────────────────────────────────────────────────────
function hmacUpper(secretKey, text) {
  return crypto
    .createHmac('sha256', secretKey)
    .update(text, 'utf8')
    .digest('hex')
    .toUpperCase();
}

// Signature 1 — token acquisition only.
function sign1(clientId, secretKey, t) {
  return hmacUpper(secretKey, `${clientId}${t}`);
}

// Signature 2 — every authenticated function call.
function sign2(clientId, secretKey, accessToken, t) {
  return hmacUpper(secretKey, `${clientId}${accessToken}${t}`);
}

function joinUrl(base, path) {
  return base.replace(/\/+$/, '') + '/' + String(path).replace(/^\/+/, '');
}

// ── transport ─────────────────────────────────────────────────────────
// One guarded request with a hard timeout. SSRF re-checked on every call.
async function vistageFetch(url, { method, headers, body }) {
  await assertSafeUrl(url, {
    requireHttps: config.isProd,
    allowPrivate: config.allowPrivateConnectors,
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method,
      headers: {
        Accept: 'application/json',
        'User-Agent': 'GlobalSearchAgent/1.0',
        ...headers,
      },
      body,
      signal: controller.signal,
      redirect: 'error', // a redirect could dodge the SSRF check
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(`Vistage responded ${res.status}: ${text.slice(0, 200)}`);
    }
    let json;
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      throw new Error('Vistage returned a non-JSON response.');
    }
    // The API signals failure in-band with success:false even on HTTP 200.
    // Surface as much of the response as possible so operators can diagnose
    // a rejection without re-tracing the call: msg → code → a trimmed view
    // of `data` / the entire body. "unknown" hides the real reason and is
    // banned here.
    if (json && json.success === false) {
      const bits = [];
      if (json.msg) bits.push(`msg=${json.msg}`);
      if (json.code) bits.push(`code=${json.code}`);
      if (!bits.length) {
        // Last resort — include the raw payload (capped) so the operator
        // sees fields like data.errors, data.field, server hint, etc.
        const dump = JSON.stringify(json).slice(0, 300);
        bits.push(`body=${dump}`);
      }
      throw new Error(`Vistage API error: ${bits.join(' ')}`);
    }
    return json;
  } catch (err) {
    if (err.name === 'AbortError') throw new Error('Vistage request timed out.');
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// ── access token ──────────────────────────────────────────────────────
async function getAccessToken(connector, creds) {
  const cached = tokenCache.get(connector.id);
  if (cached && cached.expiresAt > Date.now()) return cached.token;

  const t = String(Date.now()); // 13-digit ms epoch
  const url = joinUrl(connector.base_url, 'token');
  const body = await vistageFetch(url, {
    method: 'GET',
    headers: {
      client_id: creds.clientId,
      t,
      sign: sign1(creds.clientId, creds.secretKey, t),
    },
  });

  const token = body?.result?.access_token;
  if (!token) throw new Error('Vistage /token did not return an access_token.');

  // expire_time is in minutes (string). Refresh 60s early; clamp sanely.
  // Staging returns "0" sometimes — fall back to 20 minutes.
  const mins = parseInt(body.result.expire_time || '0', 10);
  const ttlMs = (Number.isFinite(mins) && mins > 0 ? mins : 20) * 60_000;
  tokenCache.set(connector.id, {
    token,
    expiresAt: Date.now() + Math.max(ttlMs - 60_000, 60_000),
  });
  return token;
}

// Authenticated POST to a function endpoint, signed with Signature 2. The
// V1 function endpoints take the CompanyId as a path segment, except
// UserLogin which is company-agnostic.
async function postFunction(connector, creds, accessToken, fnPath, payload) {
  const t = String(Date.now());
  const url = joinUrl(connector.base_url, fnPath);
  return vistageFetch(url, {
    method: 'POST',
    headers: {
      client_id: creds.clientId,
      t,
      sign: sign2(creds.clientId, creds.secretKey, accessToken, t),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
}

// ── user token ────────────────────────────────────────────────────────
// GetList / Save all require a V1-shaped UserToken:
//   { CompanyId, CompanyPrefix, UserId, UserModuleId, UserName }
// We resolve it once and cache it on the connector's meta_json (non-secret)
// so later sweeps skip the extra round-trip.
async function resolveUserToken(connector, creds, accessToken, repo) {
  const meta = safeParse(connector.meta_json);
  if (meta.userToken && meta.userToken.UserId && meta.userToken.CompanyId) {
    return meta.userToken;
  }

  if (!creds.userName || !creds.password) {
    throw new Error(
      'Vistage connector needs userName + password (or a pre-known user_token) to obtain a UserToken.'
    );
  }
  const login = await postFunction(
    connector,
    creds,
    accessToken,
    'UserLogin',
    { UserName: creds.userName, Password: creds.password }
  );
  const d = login?.data;
  if (!d || !d.UserId) {
    throw new Error('Vistage UserLogin did not return a user.');
  }
  const userToken = userTokenFromLogin(d);
  if (!userToken.CompanyId) {
    throw new Error(
      'Vistage UserLogin response is missing CompanyId — supply user_token at registration.'
    );
  }
  // Persist the resolved token (non-secret) for subsequent sweeps.
  if (repo && typeof repo.updateConnectorMeta === 'function') {
    meta.userToken = userToken;
    repo.updateConnectorMeta(connector.id, JSON.stringify(meta));
  }
  return userToken;
}

// Shape a UserLogin response into the V1 UserToken. Field names vary across
// Claritas instances; try the most common candidates and fall back to nulls
// so the caller can spot a missing piece.
function userTokenFromLogin(d) {
  return {
    CompanyId: parseInt(d.CompanyId ?? d.companyId ?? d.CompanyID, 10) || 0,
    CompanyPrefix: d.CompanyPrefix ?? d.companyPrefix ?? null,
    UserId: d.UserId,
    UserModuleId:
      parseInt(d.UserModuleId ?? d.userModuleId ?? d.UserModuleID, 10) || 0,
    UserName: d.UserName,
  };
}

function companyIdFor(userToken) {
  const id = parseInt(userToken?.CompanyId, 10);
  return Number.isFinite(id) && id > 0 ? id : 0;
}

// ── candidate mapping ─────────────────────────────────────────────────
// Vistage GetList rows are { id, name1, name2, cell:{...} }. Field order
// below reflects the staging row shape verified against
// teststudio.claritascrm.com: contact name lands in `name2`, phone in
// `cell.Mobile`. Member rows carry no email or company at the row level.
// The connector's field_map (if supplied) overrides this. Nothing is
// fabricated — a field with no source value stays empty.
const FIELD_CANDIDATES = {
  name: ['FullName', 'name2', 'name1', 'Name', 'MemberName', 'ContactName'],
  email: ['Email', 'EmailAddress', 'Email1'],
  phone: ['Mobile', 'Phone', 'Cell', 'ContactNo', 'PhoneNo'],
  company: ['Company', 'CompanyName', 'Organisation', 'Organization'],
  location: ['Location', 'Address', 'City', 'State'],
};

function pick(obj, keys) {
  for (const k of keys) {
    if (obj && obj[k] != null && String(obj[k]).trim() !== '') {
      return String(obj[k]).trim();
    }
  }
  return '';
}

// Strip the HTML-entity escaping the Vistage API applies to free-text fields.
function deEntity(s) {
  return String(s || '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function rowToCanonical(row, fieldMap) {
  // A GetList row carries an inner `cell` object plus top-level name1/name2.
  const flat = { ...(row.cell || {}), ...row };
  const out = {};
  for (const field of ['email', 'phone', 'company', 'location']) {
    const mapped = fieldMap?.[field];
    let val =
      mapped && flat[mapped] != null
        ? String(flat[mapped])
        : pick(flat, FIELD_CANDIDATES[field]);
    if (field === 'location' || field === 'company') val = deEntity(val);
    out[field] = val;
  }
  // Name is handled specially. Vistage's GetList returns the name as a pair —
  // `name1` (first whitespace token of the stored FirstName) and `name2` (the
  // remainder). Save splits whatever we send on the first whitespace. So a
  // lead we pushed as "chung wei ling" comes back with name1="chung",
  // name2="wei ling". Picking either field alone loses half the name; the
  // strict-after-normalization matcher then can't close the dedup loop.
  // Always reconstruct from name1 + name2; fall back to FullName / Name /
  // MemberName / ContactName / explicit field_map only when the pair is empty
  // (older Vistage instances or non-Lead modules that surface a single field).
  if (fieldMap?.name && flat[fieldMap.name] != null) {
    out.name = String(flat[fieldMap.name]);
  } else {
    const n1 = String(flat.name1 || '').trim();
    const n2 = String(flat.name2 || '').trim();
    const joined = [n1, n2].filter(Boolean).join(' ');
    out.name =
      joined ||
      pick(flat, ['FullName', 'Name', 'MemberName', 'ContactName', 'display']);
  }
  return out;
}

// ── public API (matches the generic client surface) ───────────────────

// Map canonical criteria → the Vistage SearchField the server-side LIKE
// filter understands. Verified empirically against the staging API:
// `Name`, `name1`, `name2`, `MemberName` are NOT real columns (return
// "Invalid column name"); `FullName`, `FirstName`, `LastName`, `Email`,
// `Mobile`, `Company`, `BusinessCity`, `BusinessState`, `MemberNo` are
// valid on the Member/Lead/Contact modules. Account uses different columns
// (no `FullName`), so we use module-specific maps. When a criterion has no
// usable column on a given module, we skip the query (cheaper than letting
// the server reject it with success:false).
const SEARCH_FIELDS_BY_MODULE = {
  Member: {
    name: 'FullName',
    email: 'Email',
    phone: 'Mobile',
    company: 'Account',
    location: 'BusinessCity',
  },
  Lead: {
    name: 'FullName',
    email: 'Email',
    phone: 'Mobile',
    company: 'Company',
    location: 'BusinessCity',
  },
  Contact: {
    name: 'FullName',
    email: 'Email',
    phone: 'Mobile',
    company: 'Account',
    location: 'BusinessCity',
  },
  // Account is a company-centric module — no FullName / Email / Mobile.
  // Only company/location criteria translate. Name/email/phone are skipped.
  Account: {
    company: 'AccName',
    location: 'BusinessCity',
  },
};

// Token + UserToken caches survive across input records in a sweep so
// auth doesn't re-handshake on every query. The connector-wide list
// cache is GONE — we no longer pull the whole table; each input record
// runs its own server-side SearchParams query.

// Fetch candidate records for one input query. For each module configured
// on the connector, and each selected criterion that has a usable
// SearchField on that module, issue ONE GetList with the SearchParams set
// to a LIKE filter on that field. Union all returned rows into a candidate
// set; the orchestrator's matching engine then runs the strict-after-
// normalization comparison against this much smaller, much more relevant
// set than the old "pull-everything" approach.
//
// This fixes two problems the previous design had:
//   1. GetList only returns ~1000 rows by default — older Members (Philip
//      Law VM0468, Khou Be'ng Hooi VM0526, etc.) lived outside the window
//      and were silently invisible to the matcher.
//   2. Concurrent GetList calls across sweep workers raced into Vistage's
//      response builder and triggered "An item with the same key has
//      already been added" .NET errors. Targeted per-input queries are
//      narrow, fast, and don't collide.
export async function fetchCandidates(
  connector,
  query,
  criteria,
  limit = 200,
  ctx = {}
) {
  const creds = readCredentials(connector);
  const accessToken = await getAccessToken(connector, creds);
  const userToken = await resolveUserToken(
    connector,
    creds,
    accessToken,
    ctx.repo
  );
  const companyId = companyIdFor(userToken);
  if (!companyId) {
    throw new Error(
      'Vistage UserToken is missing CompanyId — cannot build the GetList path.'
    );
  }

  const meta = safeParse(connector.meta_json);
  const modules =
    Array.isArray(meta.modules) && meta.modules.length
      ? meta.modules.filter((m) => VISTAGE_MODULES.includes(m))
      : ['Member', 'Lead'];
  const fieldMap = safeParse(connector.field_map_json);

  // Per-input dedup: a row Vistage returns under name AND email
  // SearchParams shouldn't be matched twice. Key by module + record id.
  const byId = new Map();

  for (const module of modules) {
    const fieldsForModule = SEARCH_FIELDS_BY_MODULE[module] || {};

    // Each criterion that has a non-empty value AND a usable SearchField
    // becomes its own GetList query. We OR the results together: a row that
    // matches ANY criterion is a candidate the matcher will evaluate.
    const queries = [];
    for (const criterion of criteria) {
      const val = String(query?.[criterion] || '').trim();
      if (!val) continue;
      const searchField = fieldsForModule[criterion];
      if (!searchField) continue;
      queries.push({ criterion, searchField, val });
    }
    if (queries.length === 0) continue;

    for (const q of queries) {
      const resp = await postFunction(
        connector,
        creds,
        accessToken,
        `GetList/${companyId}`,
        {
          Module: module,
          PageNo: 0,
          RecordPerPage: 0,
          SearchParams: [
            { SearchField: 'RecStatus', SearchVal: '2', SearchVal2: '' },
            { SearchField: q.searchField, SearchVal: q.val, SearchVal2: '' },
          ],
          SortName: 'CreatedTS',
          SortOrder: 2,
          UserToken: userToken,
        }
      );
      const list = Array.isArray(resp?.data?.rows) ? resp.data.rows : [];
      for (const r of list) {
        const id = String(r.id || r.Id || '').toLowerCase();
        if (!id) continue;
        const key = `${module}:${id}`;
        if (byId.has(key)) continue;
        byId.set(key, {
          raw: { ...r, _vistage_module: module },
          canonical: rowToCanonical(r, fieldMap),
        });
      }
    }
  }

  return Array.from(byId.values()).slice(0, limit);
}

// ── enrichment (GetDetail) ────────────────────────────────────────────
// Resolve the DETAIL view of one matched row for the enrichment normalizer
// (profile / group / leader / meetings / payments / outstanding).
//
// Vistage Common API V1 does NOT expose a GetDetail endpoint — the PDF only
// documents /token, /GetList, and /Save. GetList already returns every cell
// field we need, including the nested `cell` block. So the V1 path is: use
// what the sweep already retrieved. No extra HTTP call, no extra token spend,
// no 404 from a non-existent endpoint.
//
// If a future Common API version exposes GetDetail (or Vistage ships a
// Profile endpoint), the right place to add it is here — gated on a feature
// flag in meta_json, e.g. meta.detailEndpoint. For now, we trust GetList.
export async function fetchDetail(connector, matchedRecord, _ctx = {}) {
  if (!matchedRecord || typeof matchedRecord !== 'object') {
    throw new Error(
      'Vistage enrichment needs the matched record — none was supplied.'
    );
  }

  // Flatten the GetList shape: top-level columns + the inner `cell` block.
  // The normalizer expects one flat object so its field map sees everything
  // at the same level. Keep the module hint so downstream callers can tell
  // a Member-derived detail from a Lead-derived one.
  const flat = { ...(matchedRecord.cell || {}), ...matchedRecord };
  delete flat.cell;

  if (Object.keys(flat).length === 0) {
    throw new Error(
      'Vistage matched record has no cell payload to enrich from.'
    );
  }
  return flat;
}

// Create a Lead via Save (V1 addition). Maps the agent's canonical lead
// fields onto the Vistage Lead module's fields. The route handler passes
// the canonical input (name/email/phone/company/location); we split `name`
// into FirstName/LastName best-effort, and default LeadStatus=New and
// Qualified=No so nothing the CRM treats as a positive signal is
// fabricated. Branch falls back to the connector's meta.defaultBranch.
//
// Returns the new lead's id when the API surfaces one; null otherwise. The
// route handler still records `lead_status='added'` so the CTA is idempotent.
export async function createLead(connector, lead, ctx = {}) {
  if (!lead || typeof lead !== 'object') {
    throw new Error('createLead requires a canonical lead object.');
  }

  const creds = readCredentials(connector);
  const accessToken = await getAccessToken(connector, creds);
  const userToken = await resolveUserToken(
    connector,
    creds,
    accessToken,
    ctx.repo
  );
  const companyId = companyIdFor(userToken);
  if (!companyId) {
    throw new Error(
      'Vistage UserToken is missing CompanyId — cannot build the Save path.'
    );
  }

  const meta = safeParse(connector.meta_json);
  // Per V1 PDF §2.5: the Save body is `{Module, data}` where `data` carries
  // only the lead fields. UserToken is NOT nested under `data` (that was a
  // copy-paste from GetList that caused the staging server to reply
  // success:false with no msg). We carry the UserToken in the body root so
  // it's still available if the server needs it, but never inside `data`.
  //
  // Name handling: Vistage Lead's `name1` (the field GetList surfaces on
  // every row) is populated from FirstName only — LastName lives separately
  // and isn't returned as a raw string by GetList. That means if we split
  // "chung wei ling" into FirstName=chung + LastName="wei ling", the next
  // sweep of "chung wei ling" sees only `name1=chung` and can't close the
  // dedup loop under strict-after-normalization matching. So we push the
  // FULL input name into FirstName (LastName gets a single space because
  // Vistage rejects an empty LastName). This keeps round-trip dedup working.
  const fullName = String(lead.name || '').trim();
  const data = {
    LeadStatus: LEAD_STATUS.NEW,
    Qualified: '0',
    FirstName: fullName,
    LastName: ' ',
    Branch: meta.defaultBranch || '',
    Mobile: lead.phone || '',
    Email: lead.email || '',
    Company: lead.company || '',
  };

  const resp = await postFunction(
    connector,
    creds,
    accessToken,
    `Save/${companyId}`,
    { Module: 'Lead', data, UserToken: userToken }
  );

  // No connector-wide list cache to bust any more: fetchCandidates now
  // queries Vistage per-input via SearchParams, so the just-saved row
  // shows up automatically on the next sweep without any client-side
  // invalidation.

  // V1 spec shows the request shape but not the response shape; check the
  // common Claritas response keys for the new row id. If none surface, the
  // route handler records null and the audit still notes the push.
  const newId =
    resp?.data?.id ??
    resp?.data?.RecordId ??
    resp?.result?.id ??
    resp?.id ??
    null;
  return newId != null ? String(newId) : null;
}

function splitName(name) {
  const s = String(name || '').trim();
  if (!s) return { first: '', last: '' };
  const parts = s.split(/\s+/);
  if (parts.length === 1) return { first: parts[0], last: '' };
  return { first: parts[0], last: parts.slice(1).join(' ') };
}

// Connectivity probe used at registration time: authenticate + (if
// userName/password supplied) log in. Proves the credential bundle and the
// base URL are both good.
export async function probe(connector) {
  try {
    const creds = readCredentials(connector);
    const accessToken = await getAccessToken(connector, creds);
    if (creds.userName && creds.password) {
      await resolveUserToken(connector, creds, accessToken, null);
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

function safeParse(json) {
  try {
    return JSON.parse(json || '{}');
  } catch {
    return {};
  }
}
