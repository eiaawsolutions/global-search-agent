// Settings page controller.
//
// Drives the six views in settings.html — loading, first-run setup, login,
// 2FA enrollment, 2FA verification, and the signed-in Settings panel — and
// talks to the /api/admin/* endpoints. All session state lives in an
// HttpOnly cookie the server sets; this script never sees or stores a token,
// a password, or the tenant API key beyond the keystroke that submits it.
'use strict';

const $ = (sel) => document.querySelector(sel);

// ── View switching ──────────────────────────────────────────────────
function showView(name) {
  document.querySelectorAll('.view').forEach((v) => {
    v.classList.toggle('is-active', v.dataset.view === name);
  });
  // Move focus to the first input of the shown view for keyboard users.
  const first = document.querySelector(`.view[data-view="${name}"] input`);
  if (first) setTimeout(() => first.focus(), 30);
}

function setMsg(id, kind, text) {
  const el = $('#' + id);
  if (!el) return;
  el.className = 'auth-msg' + (kind ? ' ' + kind : '');
  el.textContent = text || '';
}

// ── API helper ──────────────────────────────────────────────────────
// Same-origin fetch with cookies. Returns parsed JSON; throws an Error
// carrying .status and .code on a non-2xx response.
async function adminApi(path, { method = 'GET', body } = {}) {
  const opts = { method, credentials: 'same-origin', headers: {} };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch('/api/admin' + path, opts);
  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { error: 'Unexpected server response.' };
  }
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status}).`);
    err.status = res.status;
    err.code = data.code;
    throw err;
  }
  return data;
}

// ── TOTP enrollment QR ──────────────────────────────────────────────
// Render the 2FA enrollment screen from a /setup or /login response. The QR
// is generated SERVER-SIDE (the `qrcode` library) and arrives as an SVG
// string in `data.qr_svg`; the browser only drops that static SVG into the
// DOM — no client-side QR library, so the strict CSP (script-src 'self')
// stays intact. The SVG is server-generated, contains only <path>/<rect>
// geometry (no scripts, no user-controlled attributes), so assigning it as
// innerHTML is safe. `data.manual_key` is shown for manual entry.
function renderEnrollment(data) {
  const box = $('#enrollQr');
  if (data && data.qr_svg) {
    box.classList.remove('is-empty');
    box.innerHTML = data.qr_svg; // trusted, server-rendered static SVG
  } else {
    // No QR — never block enrollment; the manual key below still works.
    box.classList.add('is-empty');
    box.textContent = 'Use the setup key →';
  }
  $('#enrollKey').textContent = (data && data.manual_key) || '';
}

// ── Bootstrap — decide which screen to show ─────────────────────────
async function boot() {
  let state;
  try {
    state = await adminApi('/state');
  } catch {
    setMsg('loginMsg', 'err', 'Could not reach the server. Reload to retry.');
    showView('login');
    return;
  }
  if (state.needs_setup) {
    showView('setup');
  } else if (state.authenticated) {
    await enterSettings();
  } else {
    showView('login');
  }
}

// Load the signed-in Settings view and populate the tenant-key status.
async function enterSettings() {
  showView('settings');
  try {
    const data = await adminApi('/session');
    $('#whoami').textContent = data.admin?.username || '—';
    renderTenantStatus(data.proxy_tenant);
  } catch (err) {
    // Session expired between /state and /session — fall back to login.
    if (err.status === 401) return showView('login');
    setMsg('tenantMsg', 'err', err.message);
  }
}

// Paint the proxy-tenant status pill.
function renderTenantStatus(status) {
  const pill = $('#tenantPill');
  const text = $('#tenantPillText');
  if (status && status.configured) {
    pill.className = 'status-pill is-set';
    text.textContent = status.tenant_name
      ? `Connected · ${status.tenant_name}`
      : 'Tenant key configured';
  } else if (status && status.stale) {
    pill.className = 'status-pill is-unset';
    text.textContent = 'Configured tenant unavailable — set a new key';
  } else {
    pill.className = 'status-pill is-unset';
    text.textContent = 'Not configured — the console cannot connect yet';
  }
}

// ── First-run setup ─────────────────────────────────────────────────
$('#setupForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const username = String(fd.get('username') || '').trim();
  const password = String(fd.get('password') || '');
  const confirm = String(fd.get('confirm') || '');
  if (password !== confirm) {
    return setMsg('setupMsg', 'err', 'The two passwords do not match.');
  }
  const btn = e.target.querySelector('button');
  btn.disabled = true;
  setMsg('setupMsg', '', 'Creating…');
  try {
    const data = await adminApi('/setup', {
      method: 'POST',
      body: { username, password },
    });
    // Move straight into 2FA enrollment with the returned QR + secret.
    renderEnrollment(data);
    enrollMode = 'setup';
    setMsg('enrollMsg', '', '');
    showView('enroll');
  } catch (err) {
    setMsg('setupMsg', 'err', err.message);
  } finally {
    btn.disabled = false;
  }
});

// ── Login (step 1) ──────────────────────────────────────────────────
$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const btn = e.target.querySelector('button');
  btn.disabled = true;
  setMsg('loginMsg', '', 'Checking…');
  try {
    const data = await adminApi('/login', {
      method: 'POST',
      body: {
        username: String(fd.get('username') || '').trim(),
        password: String(fd.get('password') || ''),
      },
    });
    e.target.reset();
    if (data.stage === 'enroll') {
      // An env-seeded admin signing in for the first time — enroll 2FA now.
      renderEnrollment(data);
      enrollMode = 'login';
      setMsg('enrollMsg', '', '');
      showView('enroll');
    } else {
      // Enrolled — go to the code step.
      setMsg('twofaMsg', '', '');
      showView('twofa');
    }
  } catch (err) {
    setMsg('loginMsg', 'err', err.message);
  } finally {
    btn.disabled = false;
  }
});

// ── 2FA enrollment verification ─────────────────────────────────────
// `enrollMode` records whether we reached enrollment from first-run setup
// or from an env-seeded admin's first login — they hit different endpoints.
let enrollMode = 'setup';

$('#enrollForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const code = String(new FormData(e.target).get('code') || '').trim();
  const btn = e.target.querySelector('button');
  btn.disabled = true;
  setMsg('enrollMsg', '', 'Verifying…');
  try {
    const endpoint = enrollMode === 'login' ? '/enroll' : '/setup/verify';
    await adminApi(endpoint, { method: 'POST', body: { code } });
    // Enrollment done — the session is now full.
    await enterSettings();
  } catch (err) {
    setMsg('enrollMsg', 'err', err.message);
  } finally {
    btn.disabled = false;
  }
});

// ── 2FA verification (step 2) ───────────────────────────────────────
$('#twofaForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const code = String(new FormData(e.target).get('code') || '').trim();
  const btn = e.target.querySelector('button');
  btn.disabled = true;
  setMsg('twofaMsg', '', 'Verifying…');
  try {
    await adminApi('/verify-2fa', { method: 'POST', body: { code } });
    e.target.reset();
    await enterSettings();
  } catch (err) {
    setMsg('twofaMsg', 'err', err.message);
    // A locked account must restart from the password step.
    if (err.code === 'locked') {
      setTimeout(() => showView('login'), 1800);
    }
  } finally {
    btn.disabled = false;
  }
});

// ── Save / replace the proxy tenant key ─────────────────────────────
$('#tenantForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = e.target.querySelector('input[name="api_key"]');
  const key = String(input.value || '').trim();
  if (!key) return setMsg('tenantMsg', 'err', 'Paste a tenant API key.');
  const btn = e.target.querySelector('button');
  btn.disabled = true;
  setMsg('tenantMsg', '', 'Saving…');
  try {
    const data = await adminApi('/tenant-key', {
      method: 'PUT',
      body: { api_key: key },
    });
    input.value = ''; // never leave the key sitting in the field
    renderTenantStatus(data.proxy_tenant);
    setMsg(
      'tenantMsg',
      'ok',
      'Saved. The console is now connected for every visitor.'
    );
  } catch (err) {
    if (err.status === 401) return showView('login');
    setMsg('tenantMsg', 'err', err.message);
  } finally {
    btn.disabled = false;
  }
});

// ── Change password ─────────────────────────────────────────────────
$('#passwordForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const btn = e.target.querySelector('button');
  btn.disabled = true;
  setMsg('passwordMsg', '', 'Updating…');
  try {
    await adminApi('/password', {
      method: 'POST',
      body: {
        current_password: String(fd.get('current_password') || ''),
        new_password: String(fd.get('new_password') || ''),
      },
    });
    e.target.reset();
    setMsg('passwordMsg', 'ok', 'Password updated. Signing you out…');
    // The server dropped every session — return to login.
    setTimeout(() => {
      setMsg('loginMsg', 'ok', 'Password changed. Sign in with the new one.');
      showView('login');
    }, 1400);
  } catch (err) {
    if (err.status === 401 && /current password/i.test(err.message)) {
      setMsg('passwordMsg', 'err', err.message);
    } else if (err.status === 401) {
      showView('login');
    } else {
      setMsg('passwordMsg', 'err', err.message);
    }
  } finally {
    btn.disabled = false;
  }
});

// ── Sign out ────────────────────────────────────────────────────────
$('#logoutBtn').addEventListener('click', async () => {
  try {
    await adminApi('/logout', { method: 'POST' });
  } catch {
    /* even if the call fails, fall through to the login screen */
  }
  setMsg('loginMsg', '', '');
  showView('login');
});

// Keep the code inputs digit-only as the user types.
document.querySelectorAll('.code-input').forEach((input) => {
  input.addEventListener('input', () => {
    input.value = input.value.replace(/\D/g, '').slice(0, 6);
  });
});

document.addEventListener('DOMContentLoaded', boot);
