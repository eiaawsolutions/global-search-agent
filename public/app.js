// Global Search Agent — console front-end.
// Vanilla JS, no build step. Talks to the same-origin API with the tenant's
// API key. All server values are inserted via textContent / DOM nodes —
// never innerHTML with response data — so a malicious connected-app record
// cannot inject script (defense in depth alongside the CSP).
'use strict';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = {
  apiKey: localStorage.getItem('gsa_api_key') || '',
  connectors: [],
  activeTab: 'paste',
  lastJob: null,
  results: [],
  filter: 'all',
};

// ── API helper ─────────────────────────────────────────────────────
async function api(path, { method = 'GET', body, form } = {}) {
  const headers = { Authorization: `Bearer ${state.apiKey}` };
  let payload;
  if (form) {
    payload = form; // FormData — let the browser set the boundary
  } else if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  const res = await fetch(`/api${path}`, { method, headers, body: payload });
  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { error: 'Unexpected server response.' };
  }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status}).`);
  return data;
}

// ── Connection / API key ───────────────────────────────────────────
async function connect() {
  const key = $('#apiKey').value.trim();
  if (!key) return setKeyStatus('idle', 'not connected');
  state.apiKey = key;
  setKeyStatus('idle', 'checking…');
  try {
    const data = await api('/connectors');
    state.connectors = data.connectors || [];
    localStorage.setItem('gsa_api_key', key);
    setKeyStatus('ok', 'connected');
    renderConnectors();
    refreshRunButton();
  } catch (err) {
    setKeyStatus('err', 'invalid key');
    state.connectors = [];
    renderConnectors();
    refreshRunButton();
  }
}

function setKeyStatus(kind, text) {
  const el = $('#keyStatus');
  const tone = kind === 'ok' ? 'ok' : kind === 'err' ? 'err' : 'idle';
  el.className = `state state-${tone}`;
  el.textContent = text;
}

// ── Connectors ─────────────────────────────────────────────────────
function renderConnectors() {
  const sel = $('#connectorSelect');
  sel.innerHTML = '';
  if (!state.connectors.length) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = state.apiKey ? 'No connectors — add one →' : 'Connect first';
    sel.appendChild(opt);
    return;
  }
  for (const c of state.connectors) {
    const opt = document.createElement('option');
    opt.value = c.id;
    opt.textContent = `${c.name} (${c.base_url})`;
    sel.appendChild(opt);
  }
}

async function registerConnector(form) {
  const fd = new FormData(form);
  const body = {
    name: fd.get('name'),
    base_url: fd.get('base_url'),
    search_path: fd.get('search_path') || undefined,
    create_path: fd.get('create_path') || undefined,
    auth_type: fd.get('auth_type'),
    credential: fd.get('credential') || undefined,
  };
  const data = await api('/connectors', { method: 'POST', body });
  state.connectors.unshift(data.connector);
  renderConnectors();
  $('#connectorSelect').value = data.connector.id;
  refreshRunButton();
  return data;
}

// ── Criteria ───────────────────────────────────────────────────────
function selectedCriteria() {
  return $$('#criteria input:checked').map((i) => i.value);
}

// ── Run a sweep ────────────────────────────────────────────────────
function refreshRunButton() {
  const ok =
    !!state.apiKey &&
    !!$('#connectorSelect').value &&
    selectedCriteria().length > 0;
  $('#runBtn').disabled = !ok;
}

async function runSweep() {
  const connectorId = $('#connectorSelect').value;
  const criteria = selectedCriteria();
  if (!connectorId || !criteria.length) return;

  const btn = $('#runBtn');
  const msg = $('#runMsg');
  btn.disabled = true;
  btn.innerHTML = '<span class="turning"></span> Sweeping the register…';
  msg.className = 'runmsg';
  msg.textContent = '';

  try {
    let data;
    if (state.activeTab === 'upload') {
      const file = $('#csvFile').files[0];
      if (!file) throw new Error('Choose a CSV file first.');
      const fd = new FormData();
      fd.append('file', file);
      fd.append('connector_id', connectorId);
      fd.append('criteria', criteria.join(','));
      data = await api('/search/csv', { method: 'POST', form: fd });
    } else if (state.activeTab === 'json') {
      const raw = $('#jsonInput').value.trim();
      if (!raw) throw new Error('Paste a JSON array of records.');
      let records;
      try {
        records = JSON.parse(raw);
      } catch {
        throw new Error('Input is not valid JSON.');
      }
      if (!Array.isArray(records)) throw new Error('JSON must be an array.');
      data = await api('/search', {
        method: 'POST',
        body: { connector_id: connectorId, criteria, records },
      });
    } else {
      const names = $('#pasteInput').value.trim();
      if (!names) throw new Error('Paste at least one name.');
      const fd = new FormData();
      fd.append('names', names);
      fd.append('connector_id', connectorId);
      fd.append('criteria', criteria.join(','));
      data = await api('/search/csv', { method: 'POST', form: fd });
    }

    state.lastJob = data.job;
    msg.className = 'runmsg ok';
    msg.textContent = data.idempotent_replay
      ? 'An earlier, identical enquiry was returned.'
      : `${data.job.total_input} name(s) considered.`;
    await loadResults(data.job.id);
    // Carry the eye gently down to the findings.
    document
      .getElementById('findings')
      ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    msg.className = 'runmsg err';
    msg.textContent = err.message;
  } finally {
    btn.innerHTML = 'Sweep the register';
    refreshRunButton();
  }
}

// ── Results ────────────────────────────────────────────────────────
async function loadResults(jobId) {
  const data = await api(`/search/${jobId}/results`);
  state.lastJob = data.job;
  state.results = data.results || [];
  state.filter = 'all';
  renderResults();
}

// The four summary figures, in register vocabulary.
const SUMMARY_FIGURES = [
  { key: 'total', label: 'considered' },
  { key: 'duplicate', label: 'already kept' },
  { key: 'review', label: 'for your eye' },
  { key: 'new', label: 'newly found' },
];

function renderResults() {
  const job = state.lastJob;
  const area = $('#resultsArea');
  area.innerHTML = '';

  const summary = $('#summary');
  if (!job) {
    area.appendChild(emptyState());
    $('#filterbar').hidden = true;
    summary.hidden = true;
    summary.innerHTML = '';
    return;
  }

  // Summary — serif numerals with a quiet uppercase caption beneath each.
  const c = job.counts;
  const figureValue = { total: job.total_input, ...c };
  summary.hidden = false;
  summary.innerHTML = '';
  for (const f of SUMMARY_FIGURES) {
    const item = el('div', 's-item');
    const num = el('span', 's-num');
    num.textContent = figureValue[f.key] ?? 0;
    const lab = el('span', 's-label');
    lab.textContent = f.label;
    item.append(num, lab);
    summary.appendChild(item);
  }

  // Filters.
  const fb = $('#filterbar');
  fb.hidden = false;
  fb.querySelector('[data-count="duplicate"]').textContent = c.duplicate;
  fb.querySelector('[data-count="review"]').textContent = c.review;
  fb.querySelector('[data-count="new"]').textContent = c.new;
  $$('.register-filter').forEach((f) =>
    f.classList.toggle('is-active', f.dataset.filter === state.filter)
  );

  const visible =
    state.filter === 'all'
      ? state.results
      : state.results.filter((r) => r.classification === state.filter);

  if (!visible.length) {
    const e = el('div', 'repose');
    const line = el('p', 'repose-line italic');
    line.textContent = 'Nothing rests in this category.';
    e.appendChild(line);
    area.appendChild(e);
    return;
  }
  for (const r of visible) area.appendChild(resultCard(r));
}

function emptyState() {
  const d = el('div', 'repose');
  d.id = 'emptyState';
  const line = el('p', 'repose-line italic');
  line.textContent = 'No enquiry has yet been made.';
  const note = el('p', 'aside');
  note.textContent =
    'Enter your tenant key above, choose a register and its marks, then sweep.';
  d.append(line, note);
  return d;
}

// The register's words for each verdict.
const VERDICT_WORD = {
  duplicate: 'Already kept',
  review: 'For your eye',
  new: 'Newly found',
};

// Build one finding — a register entry. Every value from the server goes
// through DOM text nodes, never string-concatenated HTML, so a hostile
// connected-app record cannot inject script (defence in depth with the CSP).
function resultCard(r) {
  const entry = el('article', 'finding');

  // Left column — the verdict, a small uppercase mark above a short rule.
  const verdict = el('div', `finding-verdict v-${r.classification}`);
  const rule = el('span', 'verdict-rule');
  verdict.appendChild(rule);
  verdict.appendChild(
    document.createTextNode(VERDICT_WORD[r.classification] || 'Considered')
  );
  entry.appendChild(verdict);

  // Right column — the subject, the reasoning, the evidence, the action.
  const body = el('div', 'finding-body');

  const inp = r.input || {};
  const name = el('p', 'finding-name');
  name.textContent = inp.name || inp.email || inp.phone || 'An unnamed record';
  const aside = inp.company || (inp.name ? inp.email : '');
  if (aside) {
    const sec = el('span', 'secondary');
    sec.textContent = '  ·  ' + aside;
    name.appendChild(sec);
  }
  body.appendChild(name);

  if (r.explanation) {
    const says = el('p', 'finding-says');
    says.textContent = r.explanation;
    body.appendChild(says);
  }

  // Evidence — the marks that decided the verdict, set as a small ledger.
  if (r.matched_on && r.matched_on.length) {
    const ev = el('div', 'evidence');
    for (const m of r.matched_on) {
      const row = el('div', 'evidence-row');
      const f = el('span', 'ev-field');
      f.textContent = m.field;
      const vals = el('span', 'ev-values');
      const iv = document.createTextNode(String(m.inputValue ?? '—'));
      const arrow = el('span', 'arrow');
      arrow.textContent = 'answers to';
      const mv = el('span', 'match');
      mv.textContent = String(m.matchValue ?? '—');
      vals.append(iv, arrow, mv);
      const sc = el('span', 'ev-score');
      sc.textContent = Math.round((m.score || 0) * 100) + ' per cent';
      row.append(f, vals, sc);
      ev.appendChild(row);
    }
    body.appendChild(ev);

    // The aggregate accord — one hairline bar with a small italic figure.
    const accord = el('div', 'ev-accord');
    const track = el('div', 'ev-accord-track');
    const fill = document.createElement('i');
    fill.style.width = Math.round((r.score || 0) * 100) + '%';
    track.appendChild(fill);
    const fig = el('span', 'ev-accord-figure');
    fig.textContent = 'accord, ' + Math.round((r.score || 0) * 100) + ' per cent';
    accord.append(track, fig);
    body.appendChild(accord);
  }

  // The action — only on a newly-found record, and link-styled, never a slab.
  if (r.classification === 'new') {
    const act = el('div', 'finding-act');
    if (r.lead_status === 'added') {
      const flag = el('span', 'kept-flag');
      flag.textContent =
        'Entered into the lead listing' +
        (r.lead_ref ? ` · ref ${r.lead_ref}` : '');
      act.appendChild(flag);
    } else {
      const btn = el('button', 'link-action');
      btn.textContent = 'Enter into the lead listing';
      btn.addEventListener('click', () => addLead(r.id, btn));
      act.appendChild(btn);
    }
    body.appendChild(act);
  }

  entry.appendChild(body);
  return entry;
}

// Fire the call to action — enter a newly-found record into the connected
// register's lead listing.
async function addLead(resultId, btn) {
  btn.disabled = true;
  btn.innerHTML = '<span class="turning"></span> Entering…';
  try {
    const data = await api(`/results/${resultId}/add-lead`, { method: 'POST' });
    // Reflect the new state in the in-memory result and re-render.
    const r = state.results.find((x) => x.id === resultId);
    if (r) {
      r.lead_status = 'added';
      r.lead_ref = data.lead_ref;
    }
    renderResults();
  } catch (err) {
    btn.disabled = false;
    btn.textContent = 'Enter into the lead listing';
    flashError(err.message);
  }
}

function flashError(text) {
  const msg = $('#runMsg');
  msg.className = 'runmsg err';
  msg.textContent = text;
}

// ── small DOM helpers ──────────────────────────────────────────────
function el(tag, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  return node;
}

// ── wiring ─────────────────────────────────────────────────────────
function init() {
  if (state.apiKey) {
    $('#apiKey').value = state.apiKey;
    connect();
  }

  $('#saveKey').addEventListener('click', connect);
  $('#apiKey').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') connect();
  });

  // Criteria + connector change → re-evaluate the run button.
  $('#criteria').addEventListener('change', refreshRunButton);
  $('#connectorSelect').addEventListener('change', refreshRunButton);

  // Input tabs (the ledger tabs).
  $$('.ledger-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      state.activeTab = tab.dataset.tab;
      $$('.ledger-tab').forEach((t) =>
        t.classList.toggle('is-active', t === tab)
      );
      $$('.tabpane').forEach((p) =>
        p.classList.toggle('is-hidden', p.dataset.pane !== state.activeTab)
      );
    });
  });

  // Finding filters.
  $('#filterbar').addEventListener('click', (e) => {
    const f = e.target.closest('.register-filter');
    if (!f) return;
    state.filter = f.dataset.filter;
    renderResults();
  });

  $('#runBtn').addEventListener('click', runSweep);

  // Dropzone.
  const dz = $('#dropzone');
  const fileInput = $('#csvFile');
  dz.addEventListener('dragover', (e) => {
    e.preventDefault();
    dz.classList.add('dragover');
  });
  dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
  dz.addEventListener('drop', (e) => {
    e.preventDefault();
    dz.classList.remove('dragover');
    if (e.dataTransfer.files[0]) {
      fileInput.files = e.dataTransfer.files;
      $('#dzText').textContent = e.dataTransfer.files[0].name;
    }
  });
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) $('#dzText').textContent = fileInput.files[0].name;
  });

  // Connector dialog.
  const dialog = $('#connectorDialog');
  $('#newConnectorBtn').addEventListener('click', () => {
    if (!state.apiKey) return flashError('Enter your tenant key first.');
    $('#connectorErr').textContent = '';
    $('#connectorForm').reset();
    dialog.showModal();
  });
  $('#connectorForm').addEventListener('submit', async (e) => {
    // The dialog form uses method="dialog"; intercept the "save" submit.
    if (e.submitter && e.submitter.value === 'save') {
      e.preventDefault();
      const save = $('#connectorSave');
      save.disabled = true;
      save.innerHTML = '<span class="turning"></span> Entering…';
      try {
        await registerConnector(e.target);
        dialog.close();
      } catch (err) {
        $('#connectorErr').textContent = err.message;
      } finally {
        save.disabled = false;
        save.textContent = 'Enter the register';
      }
    }
  });

  refreshRunButton();
  armReveals();
}

// v9 motion — sections rise gently into view as the page is read. Mirrors
// the framer-motion whileInView reveals of the Claritas site. Sections opt
// in by carrying the `reveal` class; the observer adds `is-shown` once.
function armReveals() {
  const targets = $$('.reveal');
  if (!targets.length) return;
  // No IntersectionObserver, or motion is unwelcome → just show everything.
  if (
    !('IntersectionObserver' in window) ||
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  ) {
    targets.forEach((t) => t.classList.add('is-shown'));
    return;
  }
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-shown');
          observer.unobserve(entry.target);
        }
      }
    },
    { rootMargin: '-80px' }
  );
  targets.forEach((t) => observer.observe(t));
}

document.addEventListener('DOMContentLoaded', init);
