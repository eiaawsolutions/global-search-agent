// Vistage connectivity test — exercises the real Vistage / Claritas CRM
// Common API V1 through the same wire format the adapter uses. NOT part of
// `npm test` (it makes live network calls); run it explicitly:
//
//   node test/vistage-connect.mjs
//
// Credentials are read from the environment ONLY — never hardcoded, so this
// file is safe to commit. Set them before running (a gitignored .env works):
//   VISTAGE_BASE_URL    e.g. https://teststudio.claritascrm.com/api/CommonService.svc
//   VISTAGE_CLIENT_ID   the API client id
//   VISTAGE_SECRET_KEY  the API secret key (HMAC signing key)
//   VISTAGE_USERNAME    optional — the API user (UserLogin)
//   VISTAGE_PASSWORD    optional — the API password (UserLogin)
//   VISTAGE_COMPANY_ID  the company id (e.g. 3 on staging) — V1 path segment
//
// Optional fallback UserToken (when UserLogin is not provisioned on the
// instance):
//   VISTAGE_USER_ID         the UserId GUID
//   VISTAGE_USER_NAME       the username the UserToken impersonates
//   VISTAGE_COMPANY_PREFIX  e.g. VT
//   VISTAGE_USER_MODULE_ID  e.g. 64
//
// It prints, step by step: token acquisition, UserLogin, and a GetList pull
// from each V1 module — so a failure pinpoints exactly which call broke.
import crypto from 'node:crypto';

const REQUIRED = [
  'VISTAGE_BASE_URL',
  'VISTAGE_CLIENT_ID',
  'VISTAGE_SECRET_KEY',
  'VISTAGE_COMPANY_ID',
];
const missing = REQUIRED.filter((k) => !process.env[k]);
if (missing.length) {
  console.error(
    `Vistage credentials not set. Missing: ${missing.join(', ')}\n` +
      'Set them in the environment (see the header of this file) and retry.'
  );
  process.exit(1);
}

const BASE = process.env.VISTAGE_BASE_URL;
const CLIENT_ID = process.env.VISTAGE_CLIENT_ID;
const SECRET_KEY = process.env.VISTAGE_SECRET_KEY;
const USERNAME = process.env.VISTAGE_USERNAME || '';
const PASSWORD = process.env.VISTAGE_PASSWORD || '';
const COMPANY_ID = parseInt(process.env.VISTAGE_COMPANY_ID, 10);

const TIMEOUT_MS = 15_000;

function hmacUpper(text) {
  return crypto
    .createHmac('sha256', SECRET_KEY)
    .update(text, 'utf8')
    .digest('hex')
    .toUpperCase();
}
const join = (p) => BASE.replace(/\/+$/, '') + '/' + p.replace(/^\/+/, '');

async function req(url, { method, headers, body }) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method,
      headers: { Accept: 'application/json', ...headers },
      body,
      signal: ctrl.signal,
    });
    const text = await res.text();
    let json;
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      throw new Error(`non-JSON (${res.status}): ${text.slice(0, 160)}`);
    }
    return { status: res.status, json };
  } finally {
    clearTimeout(timer);
  }
}

function ok(msg) { console.log(`  \x1b[32m✔\x1b[0m ${msg}`); }
function bad(msg) { console.log(`  \x1b[31mx\x1b[0m ${msg}`); }

async function main() {
  console.log(`\nVistage connectivity test (Common API V1) → ${BASE}\n`);

  // ── 1. token ─────────────────────────────────────────────────────
  console.log('1. GET /token');
  let t = String(Date.now());
  const tok = await req(join('token'), {
    method: 'GET',
    headers: {
      client_id: CLIENT_ID,
      t,
      sign: hmacUpper(`${CLIENT_ID}${t}`), // Signature 1
    },
  });
  if (tok.json?.success !== true || !tok.json?.result?.access_token) {
    bad(`token failed (HTTP ${tok.status}): ${JSON.stringify(tok.json)}`);
    process.exitCode = 1;
    return;
  }
  const accessToken = tok.json.result.access_token;
  ok(`access_token acquired (expires in ${tok.json.result.expire_time} min)`);

  const sign2 = (tt) => hmacUpper(`${CLIENT_ID}${accessToken}${tt}`);
  const post = async (fnPath, payload) => {
    const tt = String(Date.now());
    return req(join(fnPath), {
      method: 'POST',
      headers: {
        client_id: CLIENT_ID,
        t: tt,
        sign: sign2(tt),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
  };

  // ── 2. UserLogin or pre-known UserToken ──────────────────────────
  // V1 UserToken shape: { CompanyId, CompanyPrefix, UserId, UserModuleId,
  // UserName }. UserLogin is the cleanest source; fallback comes from env
  // when UserLogin is not provisioned for API use.
  console.log('2. POST /UserLogin');
  let userToken;
  if (USERNAME && PASSWORD) {
    const login = await post('UserLogin', {
      UserName: USERNAME,
      Password: PASSWORD,
    });
    if (login.json?.success === true && login.json?.data?.UserId) {
      const d = login.json.data;
      ok(`logged in as ${d.UserName} (UserId ${d.UserId})`);
      userToken = {
        CompanyId: parseInt(d.CompanyId, 10) || COMPANY_ID,
        CompanyPrefix: d.CompanyPrefix ?? null,
        UserId: d.UserId,
        UserModuleId: parseInt(d.UserModuleId, 10) || 0,
        UserName: d.UserName,
      };
    } else {
      bad(
        `UserLogin rejected — falling back to env UserToken. ` +
          `(${JSON.stringify(login.json?.data || login.json)})`
      );
    }
  } else {
    bad('UserLogin skipped — no VISTAGE_USERNAME/VISTAGE_PASSWORD set.');
  }

  if (!userToken) {
    if (process.env.VISTAGE_USER_ID && process.env.VISTAGE_USER_NAME) {
      userToken = {
        CompanyId: COMPANY_ID,
        CompanyPrefix: process.env.VISTAGE_COMPANY_PREFIX || null,
        UserId: process.env.VISTAGE_USER_ID,
        UserModuleId: parseInt(process.env.VISTAGE_USER_MODULE_ID, 10) || 0,
        UserName: process.env.VISTAGE_USER_NAME,
      };
      ok(`fallback UserToken in use (UserId ${userToken.UserId})`);
    } else {
      bad(
        'UserLogin failed and no fallback token in env ' +
          '(set VISTAGE_USER_ID + VISTAGE_USER_NAME). Cannot continue.'
      );
      process.exit(1);
    }
  }

  // ── 3. GetList per V1 module ─────────────────────────────────────
  const modules = ['Lead', 'Member', 'Contact', 'Account'];
  console.log(
    `3. POST /GetList/${userToken.CompanyId}  (${modules.join(', ')})`
  );
  for (const Module of modules) {
    const list = await post(`GetList/${userToken.CompanyId}`, {
      Module,
      PageNo: 0,
      RecordPerPage: 0,
      SearchParams: [
        { SearchField: 'RecStatus', SearchVal: '2', SearchVal2: '' },
      ],
      SortName: 'CreatedTS',
      SortOrder: 2,
      UserToken: userToken,
    });
    if (list.json?.success !== true) {
      bad(`${Module}: ${JSON.stringify(list.json).slice(0, 200)}`);
      continue;
    }
    const rows = list.json?.data?.rows || [];
    ok(`${Module}: ${list.json?.data?.total ?? rows.length} record(s)`);
    if (rows[0]) {
      const sample = { ...(rows[0].cell || {}), ...rows[0] };
      delete sample.cell;
      console.log(`      sample keys: ${Object.keys(sample).join(', ')}`);
    }
  }

  console.log('\n\x1b[32mVistage Common API V1 connection verified.\x1b[0m\n');
}

main().catch((err) => {
  console.error(`\n\x1b[31mConnection test threw:\x1b[0m ${err.message}\n`);
  process.exitCode = 1;
});
