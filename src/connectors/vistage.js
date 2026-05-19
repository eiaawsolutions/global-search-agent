// Vistage / Claritas CRM adapter.
//
// The Vistage CRM exposes a SOAP-style `.svc` JSON API that does NOT implement
// the agent's generic 2-endpoint contract. This adapter bridges the gap: it
// signs requests, manages the access token, logs in once to obtain a
// UserToken, and pulls member/prospect records via GetList so the matching
// engine can compare them against the tenant's input list.
//
// Auth (per the Vistage API v0.2 spec):
//   client_id  header = Client ID
//   t          header = 13-digit Unix epoch in MILLISECONDS
//   sign       header = HMAC-SHA256 hex, UPPER CASE
//     Signature 1 (GET /token)  : text = ClientID + t
//     Signature 2 (everything)  : text = ClientID + AccessToken + t
//     key for both = Secret Key
//
// This adapter is READ-ONLY. The Vistage spec has no endpoint that cleanly
// creates a contact-style lead (SaveTargetLead is a meeting-attendance row,
// not a contact), so createLead is intentionally unsupported.
import crypto from 'node:crypto';
import { decrypt } from '../utils/crypto.js';
import { config } from '../config.js';
import { assertSafeUrl } from './ssrf-guard.js';

const REQUEST_TIMEOUT_MS = 15_000;

// Member modules that GetList can return contact-like records for. The
// connector's meta.modules narrows this; default sweeps the live members.
export const VISTAGE_MEMBER_MODULES = [
  'ActiveMember',
  'InWaitingMember',
  'LOAMember',
  'TerminatedMember',
  'Prospect',
];

// In-process token cache, keyed by connector id. The access token is valid
// for ~expire_time minutes; we refresh a minute early to avoid edge races.
// A process restart simply re-authenticates — no persistence needed.
const tokenCache = new Map(); // connectorId -> { token, expiresAt }

// ── credential bundle ────────────────────────────────────────────────
// A vistage connector stores its secrets as an encrypted JSON bundle in
// credential_enc: { clientId, secretKey, userName, password }.
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
    if (json && json.success === false) {
      throw new Error(
        `Vistage API error: ${json.msg || json.code || 'unknown'}`
      );
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
// Returns a valid access token, fetching a fresh one if the cache is empty
// or near expiry.
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
  const mins = parseInt(body.result.expire_time || '0', 10);
  const ttlMs = (Number.isFinite(mins) && mins > 0 ? mins : 20) * 60_000;
  tokenCache.set(connector.id, {
    token,
    expiresAt: Date.now() + Math.max(ttlMs - 60_000, 60_000),
  });
  return token;
}

// Authenticated POST to a function endpoint, signed with Signature 2.
async function postFunction(connector, creds, accessToken, fnName, payload) {
  const t = String(Date.now());
  const url = joinUrl(connector.base_url, fnName);
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
// GetList / GetDetail require a UserToken obtained from UserLogin. We resolve
// it once and cache it on the connector's meta_json (non-secret) so later
// sweeps skip the extra round-trip.
async function resolveUserToken(connector, creds, accessToken, repo) {
  const meta = safeParse(connector.meta_json);
  if (meta.userToken && meta.userToken.UserId) return meta.userToken;

  if (!creds.userName || !creds.password) {
    throw new Error(
      'Vistage connector needs userName + password to obtain a UserToken.'
    );
  }
  const login = await postFunction(connector, creds, accessToken, 'UserLogin', {
    UserName: creds.userName,
    Password: creds.password,
  });
  const d = login?.data;
  if (!d || !d.UserId) {
    throw new Error('Vistage UserLogin did not return a user.');
  }
  const userToken = {
    FirstName: d.FirstName ?? null,
    FullName: d.FullName ?? null,
    LastName: d.LastName ?? null,
    Role: parseInt(d.RoleId, 10) || 0,
    UserId: d.UserId,
    UserName: d.UserName,
  };
  // Persist the resolved token (non-secret) for subsequent sweeps.
  if (repo && typeof repo.updateConnectorMeta === 'function') {
    meta.userToken = userToken;
    repo.updateConnectorMeta(connector.id, JSON.stringify(meta));
  }
  return userToken;
}

// ── candidate mapping ─────────────────────────────────────────────────
// Vistage GetList rows are { id, name1, name2, cell:{...} }. Field order
// below reflects the ACTUAL staging member-row shape (verified against
// teststudio.claritascrm.com): the member's name lands in `name2`, the phone
// in `Mobile`. Member rows carry no email or company — those only appear via
// GetDetail. The connector's field_map (if supplied) overrides this.
// Nothing is fabricated — a field with no source value stays empty.
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
  for (const field of ['name', 'email', 'phone', 'company', 'location']) {
    const mapped = fieldMap?.[field];
    let val =
      mapped && flat[mapped] != null
        ? String(flat[mapped])
        : pick(flat, FIELD_CANDIDATES[field]);
    if (field === 'location' || field === 'company') val = deEntity(val);
    out[field] = val;
  }
  // Fall back to the row's display name if nothing else gave us a name.
  if (!out.name) out.name = pick(flat, ['name1', 'name2', 'display']);
  return out;
}

// ── public API (matches the generic client surface) ───────────────────

// Fetch candidate records for one input query. The Vistage API has no
// targeted search, so the adapter pulls the configured member modules once,
// caches them for the duration of the sweep, and lets the matching engine
// do the comparison. Caching is keyed per connector + token generation.
const listCache = new Map(); // connectorId -> { rows, expiresAt }

export async function fetchCandidates(
  connector,
  _query,
  _criteria,
  limit = 200,
  ctx = {}
) {
  const cached = listCache.get(connector.id);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.rows.slice(0, limit);
  }

  const creds = readCredentials(connector);
  const accessToken = await getAccessToken(connector, creds);
  const userToken = await resolveUserToken(
    connector,
    creds,
    accessToken,
    ctx.repo
  );

  const meta = safeParse(connector.meta_json);
  const modules =
    Array.isArray(meta.modules) && meta.modules.length
      ? meta.modules.filter((m) => VISTAGE_MEMBER_MODULES.includes(m))
      : ['ActiveMember', 'Prospect'];
  const fieldMap = safeParse(connector.field_map_json);

  const rows = [];
  for (const module of modules) {
    // PageNo/RecordPerPage = 0 returns the full set per the spec examples.
    const resp = await postFunction(connector, creds, accessToken, 'GetList', {
      Module: module,
      PageNo: 0,
      Record: null,
      RecordPerPage: 0,
      SearchParams: [],
      SortName: 'CreatedTS',
      SortOrder: 2,
      UserToken: userToken,
    });
    const list = Array.isArray(resp?.data?.rows) ? resp.data.rows : [];
    for (const r of list) {
      rows.push({
        raw: { ...r, _vistage_module: module },
        canonical: rowToCanonical(r, fieldMap),
      });
    }
  }

  // Cache for 2 minutes — long enough to serve every input record in one
  // sweep without re-pulling, short enough to stay fresh between sweeps.
  listCache.set(connector.id, {
    rows,
    expiresAt: Date.now() + 120_000,
  });
  return rows.slice(0, limit);
}

// Read-only connector: lead push-back is not supported by the Vistage API.
export async function createLead() {
  throw new Error(
    'Lead creation is not supported for Vistage connectors (read-only).'
  );
}

// Connectivity probe used at registration time: authenticate + log in.
// Proves the credential bundle and the staging URL are both good.
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
