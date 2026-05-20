// Connector client — the per-app API contract.
//
// The agent never touches a connected app's database directly. Instead each
// connected app exposes two HTTP endpoints, and the agent speaks this small,
// fixed contract to them:
//
//   SEARCH  (read candidates)
//     POST {base_url}{search_path}
//     body : { criteria: ["email","name",...], query: { email, name, ... },
//              limit: 200 }
//     resp : { records: [ { ...app fields... }, ... ] }
//
//   CREATE  (push a new lead — only on the user's CTA click)
//     POST {base_url}{create_path}
//     body : { lead: { name, email, phone, company, location, source } }
//     resp : { id: "<app-side id>" }   (id optional)
//
// A `field_map` on the connector translates the connected app's own field
// names into our canonical names, so the contract works against any schema.
//
// Connectors come in KINDS. `generic` (this file) is the fixed 2-endpoint
// contract above. Other kinds — e.g. `vistage` — bring their own transport
// adapter. The exported fetchCandidates/createLead/probe below dispatch on
// connector.kind so the sweep orchestrator stays kind-agnostic.
import { decrypt } from '../utils/crypto.js';
import { config } from '../config.js';
import { assertSafeUrl } from './ssrf-guard.js';
import * as vistage from './vistage.js';

const REQUEST_TIMEOUT_MS = 12_000;

// Apply a connector's field_map to one raw app record → canonical shape.
// field_map is { canonicalField: "appFieldName" }. Unmapped canonical
// fields fall back to a same-name lookup.
function applyFieldMap(record, fieldMap) {
  const out = {};
  for (const canonical of ['name', 'email', 'phone', 'company', 'location']) {
    const appKey = fieldMap?.[canonical];
    if (appKey && record[appKey] != null) {
      out[canonical] = record[appKey];
    } else if (record[canonical] != null) {
      out[canonical] = record[canonical];
    } else {
      out[canonical] = '';
    }
  }
  return out;
}

// Build the auth header for an outbound request to the connected app.
function authHeaders(connector) {
  const token = decrypt(connector.credential_enc);
  if (!token || connector.auth_type === 'none') return {};
  if (connector.auth_type === 'header') {
    return { [connector.auth_header || 'Authorization']: token };
  }
  // default: bearer
  return { Authorization: `Bearer ${token}` };
}

// One guarded fetch with a hard timeout. `path` is appended to base_url.
async function call(connector, path, body) {
  const target = joinUrl(connector.base_url, path);
  // SSRF guard — re-resolve DNS on every call (a host could rebind).
  await assertSafeUrl(target, {
    requireHttps: config.isProd,
    allowPrivate: config.allowPrivateConnectors,
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(target, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'User-Agent': 'GlobalSearchAgent/1.0',
        ...authHeaders(connector),
      },
      body: JSON.stringify(body),
      signal: controller.signal,
      redirect: 'error', // a redirect could dodge the SSRF check
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(
        `Connector responded ${res.status}: ${text.slice(0, 200)}`
      );
    }
    try {
      return text ? JSON.parse(text) : {};
    } catch {
      throw new Error('Connector returned a non-JSON response.');
    }
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error('Connector request timed out.');
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// Fetch candidate records via the generic 2-endpoint contract.
// `query` is the canonical input fields; the connected app decides how to
// search (it sees the criteria so it can index appropriately). Returns an
// array of canonical-shaped candidate records.
async function fetchCandidatesGeneric(connector, query, criteria, limit = 200) {
  const data = await call(connector, connector.search_path, {
    criteria,
    query,
    limit,
  });
  const records = Array.isArray(data?.records) ? data.records : [];
  const fieldMap = safeParse(connector.field_map_json);
  return records.slice(0, limit).map((r) => ({
    raw: r, // keep the app's original record for display
    canonical: applyFieldMap(r, fieldMap),
  }));
}

// Push one new lead via the generic contract. Called only from the add-lead
// CTA handler — never automatically. Returns the app-side id if provided.
// The generic adapter ignores ctx; vistage uses it for the UserToken repo.
async function createLeadGeneric(connector, lead, _ctx) {
  const data = await call(connector, connector.create_path, {
    lead: {
      name: lead.name || '',
      email: lead.email || '',
      phone: lead.phone || '',
      company: lead.company || '',
      location: lead.location || '',
      source: 'global-search-agent',
    },
  });
  return data?.id ? String(data.id) : null;
}

// Lightweight connectivity probe for the generic contract.
async function probeGeneric(connector) {
  try {
    await assertSafeUrl(joinUrl(connector.base_url, connector.search_path), {
      requireHttps: config.isProd,
      allowPrivate: config.allowPrivateConnectors,
    });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

// ── kind dispatch ─────────────────────────────────────────────────────
// The sweep orchestrator and route handlers call these; they route to the
// adapter for the connector's kind. Adding a CRM = adding one adapter module
// and one case here.
const ADAPTERS = {
  generic: {
    fetchCandidates: fetchCandidatesGeneric,
    createLead: createLeadGeneric,
    probe: probeGeneric,
  },
  vistage: {
    fetchCandidates: vistage.fetchCandidates,
    createLead: vistage.createLead,
    probe: vistage.probe,
  },
};

function adapterFor(connector) {
  const a = ADAPTERS[connector.kind || 'generic'];
  if (!a) throw new Error(`Unknown connector kind: ${connector.kind}`);
  return a;
}

// Fetch candidate records for one input query. `ctx` carries optional
// cross-cutting state (e.g. the tenant repo) some adapters need.
export function fetchCandidates(connector, query, criteria, limit = 200, ctx) {
  return adapterFor(connector).fetchCandidates(
    connector,
    query,
    criteria,
    limit,
    ctx || {}
  );
}

// Push one new lead. Generic connectors POST to the contract's create_path;
// vistage (Common API V1) calls Save - Lead. `ctx` carries cross-cutting
// state (e.g. the tenant repo) so the adapter can resolve a cached UserToken.
export function createLead(connector, lead, ctx) {
  return adapterFor(connector).createLead(connector, lead, ctx || {});
}

// Reachability / credential probe at registration time.
export function probe(connector) {
  return adapterFor(connector).probe(connector);
}

// Whether a connector kind supports the add-lead CTA at all. Vistage gained
// lead push in Common API V1 (Save endpoint); previously it was read-only.
export function supportsLeadPush(connector) {
  const kind = connector.kind || 'generic';
  return kind === 'generic' || kind === 'vistage';
}

function joinUrl(base, path) {
  return base.replace(/\/+$/, '') + '/' + String(path).replace(/^\/+/, '');
}

function safeParse(json) {
  try {
    return JSON.parse(json || '{}');
  } catch {
    return {};
  }
}
