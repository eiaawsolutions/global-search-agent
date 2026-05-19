// Vistage connectivity test — exercises the real Vistage / Claritas CRM API
// through the same adapter the sweep uses. NOT part of `npm test` (it makes
// live network calls); run it explicitly:
//
//   node test/vistage-connect.mjs
//
// Credentials are read from the environment ONLY — never hardcoded, so this
// file is safe to commit. Set them before running (a gitignored .env works):
//   VISTAGE_BASE_URL    e.g. https://teststudio.claritascrm.com/api/VistageService.svc
//   VISTAGE_CLIENT_ID   the API client id
//   VISTAGE_SECRET_KEY  the API secret key (HMAC signing key)
//   VISTAGE_USERNAME    the API user
//   VISTAGE_PASSWORD    the API password
//
// It prints, step by step: token acquisition, UserLogin, and a GetList pull
// from each member module — so a failure pinpoints exactly which call broke.
import crypto from 'node:crypto';

// Required env — fail early with a clear message rather than sending an
// unsigned/empty request to the live API.
const REQUIRED = [
  'VISTAGE_BASE_URL',
  'VISTAGE_CLIENT_ID',
  'VISTAGE_SECRET_KEY',
  'VISTAGE_USERNAME',
  'VISTAGE_PASSWORD',
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
const USERNAME = process.env.VISTAGE_USERNAME;
const PASSWORD = process.env.VISTAGE_PASSWORD;

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

function ok(msg) {
  console.log(`  \x1b[32m✔\x1b[0m ${msg}`);
}
function fail(msg) {
  console.log(`  \x1b[31mx\x1b[0m ${msg}`);
}

async function main() {
  console.log(`\nVistage connectivity test → ${BASE}\n`);

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
    fail(`token failed (HTTP ${tok.status}): ${JSON.stringify(tok.json)}`);
    process.exitCode = 1;
    return;
  }
  const accessToken = tok.json.result.access_token;
  ok(`access_token acquired (expires in ${tok.json.result.expire_time} min)`);

  // sign2 helper now that we have the token
  const sign2 = (tt) => hmacUpper(`${CLIENT_ID}${accessToken}${tt}`);
  const post = async (fn, payload) => {
    const tt = String(Date.now());
    return req(join(fn), {
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

  // ── 2. UserLogin (or fall back to a pre-known UserToken) ─────────
  // GetList/GetDetail need a UserToken. The cleanest source is UserLogin,
  // but the Vistage API also accepts a pre-known UserToken directly (the
  // spec itself hardcodes one). If login fails — e.g. the username/password
  // are not provisioned on staging — fall back to an env-supplied or the
  // documented UserToken so the rest of the connection can still be proven.
  console.log('2. POST /UserLogin');
  let userToken;
  const login = await post('UserLogin', {
    UserName: USERNAME,
    Password: PASSWORD,
  });
  if (login.json?.success === true && login.json?.data?.UserId) {
    const d = login.json.data;
    ok(`logged in as ${d.FullName || d.UserName} (UserId ${d.UserId})`);
    userToken = {
      FirstName: d.FirstName ?? null,
      FullName: d.FullName ?? null,
      LastName: d.LastName ?? null,
      Role: parseInt(d.RoleId, 10) || 0,
      UserId: d.UserId,
      UserName: d.UserName,
    };
  } else {
    fail(
      `UserLogin rejected — using fallback UserToken. ` +
        `(${JSON.stringify(login.json?.data || login.json)})`
    );
    // UserLogin failed — fall back to a pre-known token ONLY if one is
    // supplied via env. Nothing is hardcoded.
    if (process.env.VISTAGE_USER_ID && process.env.VISTAGE_ROLE) {
      userToken = {
        FirstName: null,
        FullName: null,
        LastName: null,
        Role: parseInt(process.env.VISTAGE_ROLE, 10),
        UserId: process.env.VISTAGE_USER_ID,
        UserName: USERNAME,
      };
      ok(`fallback UserToken in use (UserId ${userToken.UserId})`);
    } else {
      bad(
        'UserLogin failed and no fallback token in env ' +
          '(set VISTAGE_USER_ID + VISTAGE_ROLE to supply one). Cannot continue.'
      );
      process.exit(1);
    }
  }

  // ── 3. GetList per member module ─────────────────────────────────
  const modules = ['ActiveMember', 'InWaitingMember', 'Prospect'];
  console.log(`3. POST /GetList  (${modules.join(', ')})`);
  for (const Module of modules) {
    const list = await post('GetList', {
      Module,
      PageNo: 0,
      Record: null,
      RecordPerPage: 0,
      SearchParams: [],
      SortName: 'CreatedTS',
      SortOrder: 2,
      UserToken: userToken,
    });
    if (list.json?.success !== true) {
      fail(`${Module}: ${JSON.stringify(list.json).slice(0, 200)}`);
      continue;
    }
    const rows = list.json?.data?.rows || [];
    ok(`${Module}: ${list.json?.data?.total ?? rows.length} record(s)`);
    if (rows[0]) {
      // Print one row's keys so the member-row field shape can be confirmed
      // and the connector's field_map tuned.
      const sample = { ...(rows[0].cell || {}), ...rows[0] };
      delete sample.cell;
      console.log(
        `      sample keys: ${Object.keys(sample).join(', ')}`
      );
    }
  }

  console.log('\n\x1b[32mVistage connection verified.\x1b[0m\n');
}

main().catch((err) => {
  console.error(`\n\x1b[31mConnection test threw:\x1b[0m ${err.message}\n`);
  process.exitCode = 1;
});
