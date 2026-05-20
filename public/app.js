// Global Search Agent — console front-end.
// Vanilla JS, no build step. Talks to the same-origin API. The console no
// longer holds a tenant API key: an administrator configures the key in the
// Settings page, and the server proxies every request through that tenant.
// So requests carry NO credential — the key never reaches the browser.
// All server values are inserted via textContent / DOM nodes — never
// innerHTML with response data — so a malicious connected-app record cannot
// inject script (defense in depth alongside the CSP).
'use strict';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = {
  // 'idle' before the first check, 'ok' once connected, 'unconfigured' when
  // no admin has set a tenant key yet, 'err' on an unexpected failure.
  connection: 'idle',
  connectors: [],
  activeTab: 'paste',
  lastJob: null,
  results: [],
  filter: 'all',
};

// ── API helper ─────────────────────────────────────────────────────
// No Authorization header — the server attaches the admin-configured tenant.
// `credentials: same-origin` is set so the request is consistent with the
// rest of the app; the API itself needs no cookie. A non-2xx response throws
// an Error carrying .status and .code so callers can react to a specific
// "not configured yet" state.
async function api(path, { method = 'GET', body, form } = {}) {
  const headers = {};
  let payload;
  if (form) {
    payload = form; // FormData — let the browser set the boundary
  } else if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  const res = await fetch(`/api${path}`, {
    method,
    headers,
    body: payload,
    credentials: 'same-origin',
  });
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

// ── Connection ─────────────────────────────────────────────────────
// The console connects automatically on load — no key entry. It simply
// asks the API for the tenant's connectors; the server resolves the tenant
// from the admin-configured key. The three outcomes:
//   • success            → connected; the connector list is populated
//   • 503 not_configured → no admin has set a tenant key yet; show a calm
//                          "ask an administrator" state with a Settings link
//   • anything else      → an unexpected error; show a retry-able state
async function autoConnect() {
  setKeyStatus('idle', 'connecting…');
  try {
    const data = await api('/connectors');
    state.connectors = data.connectors || [];
    state.connection = 'ok';
    setKeyStatus('ok', 'connected');
    renderConnectors();
    refreshRunButton();
  } catch (err) {
    state.connectors = [];
    if (err.code === 'not_configured') {
      state.connection = 'unconfigured';
      setKeyStatus('err', 'not configured');
    } else {
      state.connection = 'err';
      setKeyStatus('err', 'connection error');
    }
    renderConnectors();
    refreshRunButton();
    // Re-render the results panel so its empty state reflects the connection
    // problem (the static HTML placeholder assumes a normal "no sweep yet").
    renderResults();
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
    // The placeholder explains *why* the list is empty, per connection state.
    opt.textContent =
      state.connection === 'unconfigured'
        ? 'Not configured — see Settings'
        : state.connection === 'err'
          ? 'Connection error — reload'
          : state.connection === 'ok'
            ? 'No connectors — add one →'
            : 'Connecting…';
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
    enrich_path: fd.get('enrich_path') || undefined,
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
    state.connection === 'ok' &&
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
  btn.innerHTML = '<span class="turning"></span> Sweeping…';
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
      ? 'An earlier, identical sweep was returned.'
      : `${data.job.total_input} record(s) checked.`;
    await loadResults(data.job.id);
    document
      .getElementById('findings')
      ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    msg.className = 'runmsg err';
    msg.textContent = err.message;
  } finally {
    btn.innerHTML = 'Sweep database';
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

// The four summary figures.
const SUMMARY_FIGURES = [
  { key: 'total', label: 'checked' },
  { key: 'duplicate', label: 'duplicates' },
  { key: 'review', label: 'review' },
  { key: 'new', label: 'new leads' },
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
  $$('.filter').forEach((f) =>
    f.classList.toggle('is-active', f.dataset.filter === state.filter)
  );

  const visible =
    state.filter === 'all'
      ? state.results
      : state.results.filter((r) => r.classification === state.filter);

  if (!visible.length) {
    const e = el('div', 'empty');
    const line = el('p', 'empty-title');
    line.textContent = 'Nothing in this category.';
    e.appendChild(line);
    area.appendChild(e);
    return;
  }
  for (const r of visible) area.appendChild(resultCard(r));
}

function emptyState() {
  const d = el('div', 'empty');
  d.id = 'emptyState';
  const line = el('p', 'empty-title');
  const note = el('p', 'empty-note');

  // When no administrator has configured the tenant key yet, the console
  // cannot do anything useful — say so plainly and point to Settings,
  // rather than showing sweep instructions that would just fail.
  if (state.connection === 'unconfigured') {
    line.textContent = 'This console is not configured yet.';
    note.textContent =
      'An administrator needs to set the tenant key in Settings before ' +
      'sweeps can run. ';
    const link = el('a', 'text-link-inline');
    link.href = '/settings';
    link.textContent = 'Open Settings →';
    note.appendChild(link);
  } else if (state.connection === 'err') {
    line.textContent = 'Could not connect.';
    note.textContent =
      'The console could not reach the service. Reload the page to retry.';
  } else {
    line.textContent = 'No sweep run yet.';
    note.textContent =
      'Choose a connected application and match criteria, paste or upload ' +
      'your records, then sweep.';
  }
  d.append(line, note);
  return d;
}

// The label shown for each verdict.
const VERDICT_WORD = {
  duplicate: 'Duplicate',
  review: 'Review',
  new: 'New lead',
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
    // An `error` on the result means the sweep couldn't complete the lookup
    // for this record. Render it as a red, prominent note so the operator
    // sees the actual reason (e.g. "Vistage UserToken missing CompanyId")
    // — never as a misleading "matched on weak signals".
    const says = el('p', r.error ? 'finding-says finding-error' : 'finding-says');
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
      arrow.textContent = '→';
      const mv = el('span', 'match');
      mv.textContent = String(m.matchValue ?? '—');
      vals.append(iv, arrow, mv);
      const sc = el('span', 'ev-score');
      sc.textContent = Math.round((m.score || 0) * 100) + '%';
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
    fig.textContent = Math.round((r.score || 0) * 100) + '% match';
    accord.append(track, fig);
    body.appendChild(accord);
  }

  // The action — only on a newly-found record, and link-styled, never a slab.
  // When the result has an `error` we suppress the CTA: we never confirmed
  // the record is genuinely new, so pushing it could create a duplicate in
  // the connected app.
  if (r.classification === 'new') {
    const act = el('div', 'finding-act');
    if (r.lead_status === 'added') {
      const flag = el('span', 'kept-flag');
      flag.textContent =
        'Added to lead listing' + (r.lead_ref ? ` · ref ${r.lead_ref}` : '');
      act.appendChild(flag);
    } else if (r.error) {
      // The CRM lookup never completed for this row, so we can't claim it
      // is new. Disabled CTA + an honest aside, instead of letting the
      // operator push a possibly-duplicate record.
      const flag = el('span', 'kept-flag kept-flag-blocked');
      flag.textContent = 'Re-sweep after fixing the connector to enable lead push.';
      act.appendChild(flag);
    } else {
      const btn = el('button', 'link-action');
      btn.textContent = 'Add to lead listing';
      btn.addEventListener('click', () => addLead(r.id, btn));
      act.appendChild(btn);
    }
    body.appendChild(act);
  }

  // Enrichment — a "View details" control on EVERY matched finding
  // (duplicate / review), since enrichment needs a record in the CRM to look
  // up. The button is always present and ready to work; clicking it expands
  // an inline profile panel and fetches on demand. If the connector cannot
  // enrich yet (e.g. detail-endpoint parameters not yet configured), the
  // panel shows a clear "not yet available" notice instead of the button
  // being hidden — the control stays in place, ready for when it is wired.
  if (r.classification === 'duplicate' || r.classification === 'review') {
    const act = el('div', 'finding-act');
    const btn = el('button', 'view-details');
    const caret = el('span', 'vd-caret');
    caret.textContent = '▸';
    const label = el('span', 'vd-label');
    label.textContent = 'View details';
    btn.append(caret, label);

    // The expandable panel host; populated on first open.
    const panel = el('div', 'enrich-panel');
    panel.hidden = true;
    let loaded = false;

    const setOpen = (open) => {
      panel.hidden = !open;
      btn.classList.toggle('is-open', open);
      caret.textContent = open ? '▾' : '▸';
      label.textContent = open ? 'Hide details' : 'View details';
    };

    btn.addEventListener('click', async () => {
      if (!panel.hidden) {
        setOpen(false);
        return;
      }
      setOpen(true);
      if (loaded) return;

      // If the result already carries enrichment from the results load, use
      // it directly — no fetch needed.
      if (r.enrichment) {
        renderEnrichment(panel, r.enrichment, r);
        loaded = true;
        return;
      }
      // Loading state while the connected app's detail record is fetched.
      panel.textContent = '';
      const loading = el('p', 'enrich-loading');
      loading.append(
        el('span', 'turning'),
        document.createTextNode(' Looking up the linked record…')
      );
      panel.appendChild(loading);
      try {
        const data = await api(`/results/${r.id}/enrich`);
        r.enrichment = data.enrichment;
        r.is_enriched = true;
        r.enriched_at = data.enriched_at || r.enriched_at;
        renderEnrichment(panel, data.enrichment, r);
        loaded = true;
      } catch (err) {
        // Enrichment not available yet (connector has no detail endpoint /
        // parameters not adjusted) or the connected app rejected the call.
        // Show an honest, in-place notice — the button remains for a retry.
        panel.textContent = '';
        renderEnrichUnavailable(panel, err.message);
        // Leave `loaded` false so a later click retries once the API is wired.
      }
    });

    act.appendChild(btn);
    body.appendChild(act);
    body.appendChild(panel);
  }

  entry.appendChild(body);
  return entry;
}

// In-place notice shown when a finding cannot be enriched yet — the connector
// has no detail endpoint configured, or the CRM detail parameters have not
// been adjusted. Honest, not a dead end: the View-details button stays put so
// the same click works the moment enrichment is wired up.
function renderEnrichUnavailable(host, message) {
  host.textContent = '';
  const box = el('div', 'enrich-pending-setup');
  const title = el('p', 'eps-title');
  title.textContent = 'Linked profile not available yet';
  box.appendChild(title);
  const note = el('p', 'eps-note');
  note.textContent =
    'Once the connector’s detail-record parameters are set, this panel ' +
    'will show the related profile, linked group & chair, reporting line, ' +
    'this year’s payment status by month, outstanding balance, and any ' +
    'items needing attention — all pulled live from the connected CRM.';
  box.appendChild(note);
  if (message) {
    const reason = el('p', 'eps-reason');
    reason.textContent = message;
    box.appendChild(reason);
  }
  host.appendChild(box);
}

// ── Enrichment panel ───────────────────────────────────────────────
// Render the canonical enrichment object into an inline profile panel.
// Every value is inserted via textContent / DOM nodes — never innerHTML with
// CRM data — so a hostile connected-app record cannot inject script. A field
// the CRM did not provide is shown as a muted "not provided by the CRM"
// rather than blank or a guessed value.
const MONTH_LABELS = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
];

function renderEnrichment(host, en, result) {
  host.textContent = '';
  if (!en) {
    const e = el('p', 'enrich-error');
    e.textContent = 'No enrichment data returned.';
    host.appendChild(e);
    return;
  }

  // ── Identity header ──
  const profile = en.profile || {};
  const head = el('div', 'enrich-head');
  const avatar = el('div', 'enrich-avatar');
  if (profile.photoUrl) {
    const img = document.createElement('img');
    img.src = profile.photoUrl;
    img.alt = '';
    img.referrerPolicy = 'no-referrer';
    img.addEventListener('error', () => {
      avatar.textContent = initialsOf(profile.fullName);
    });
    avatar.appendChild(img);
  } else {
    avatar.textContent = initialsOf(profile.fullName);
  }
  head.appendChild(avatar);

  const idCol = el('div', 'enrich-id');
  const nm = el('p', 'enrich-name');
  nm.textContent =
    [profile.salutation, profile.fullName].filter(Boolean).join(' ') ||
    'Linked record';
  idCol.appendChild(nm);
  const sub = el('p', 'enrich-sub');
  const subBits = [profile.jobTitle, profile.companyName].filter(Boolean);
  sub.textContent = subBits.length ? subBits.join(' · ') : 'Role not provided by the CRM';
  idCol.appendChild(sub);
  // Member no + status as small marks.
  const marks = el('div', 'enrich-marks');
  if (profile.memberNo) marks.appendChild(mark(profile.memberNo, 'id'));
  if (profile.status) marks.appendChild(mark(profile.status, statusTone(profile.status)));
  if (marks.childNodes.length) idCol.appendChild(marks);
  head.appendChild(idCol);
  host.appendChild(head);

  // ── Contact + linkage grid ──
  const link = en.linkage || {};
  const facts = el('div', 'enrich-facts');
  facts.appendChild(fact('Email', profile.email));
  facts.appendChild(fact('Phone', profile.phone));
  facts.appendChild(fact('Group / chapter', link.group));
  facts.appendChild(fact('Group number', link.groupNumber));
  facts.appendChild(fact('Group type', link.groupType));
  facts.appendChild(fact('Group leader', link.groupLeader || link.chair));
  facts.appendChild(fact('Group chair', link.chair));
  facts.appendChild(fact('Role in group', link.role));
  facts.appendChild(fact('Reports to', link.reportsTo));
  facts.appendChild(fact('Member since', profile.joinDate));
  host.appendChild(facts);

  // ── Payment status by month (current calendar year) ──
  const pay = en.payment || {};
  const paySec = el('div', 'enrich-section');
  const payTitle = el('p', 'enrich-section-title');
  payTitle.textContent = `Payment status by month — ${pay.year || ''}`;
  paySec.appendChild(payTitle);

  if (!pay.hasData) {
    const none = el('p', 'enrich-none');
    none.textContent =
      'No payment or invoice records were returned by the CRM for this member.';
    paySec.appendChild(none);
  } else {
    const grid = el('div', 'pay-grid');
    const cells = Array.isArray(pay.grid) ? pay.grid : [];
    for (let i = 0; i < 12; i++) {
      const c = cells[i] || { status: 'no-record', label: MONTH_LABELS[i] };
      const cell = el('div', `pay-cell pay-${c.status}`);
      const mlab = el('span', 'pay-month');
      mlab.textContent = c.label || MONTH_LABELS[i];
      const st = el('span', 'pay-state');
      st.textContent = PAY_WORD[c.status] || c.status;
      cell.append(mlab, st);
      if (c.amount != null) {
        const amt = el('span', 'pay-amount');
        amt.textContent = formatMoney(c.amount, pay.currency);
        cell.appendChild(amt);
      }
      // Title carries the CRM's own wording for the status, if any.
      if (c.statusLabel) cell.title = c.statusLabel;
      grid.appendChild(cell);
    }
    paySec.appendChild(grid);

    // A one-line tally under the grid.
    const tally = el('p', 'pay-tally');
    tally.textContent =
      `${pay.paidMonths} paid · ${pay.dueMonths} due · ${pay.overdueMonths} overdue` +
      ` · ${12 - pay.paidMonths - pay.dueMonths - pay.overdueMonths} no record`;
    paySec.appendChild(tally);
  }
  host.appendChild(paySec);

  // ── Meeting attendance ──
  // Newest-first list of meetings the CRM returned. Each row shows the
  // date, type (if any), and an attendance state. Empty list = the CRM
  // didn't return any meeting rows for this member — we say that honestly
  // rather than guessing zero attendance.
  const meetings = Array.isArray(en.meetings) ? en.meetings : [];
  const meetSec = el('div', 'enrich-section');
  const meetTitle = el('p', 'enrich-section-title');
  meetTitle.textContent = `Meeting attendance${meetings.length ? ` (${meetings.length})` : ''}`;
  meetSec.appendChild(meetTitle);
  if (!meetings.length) {
    const none = el('p', 'enrich-none');
    none.textContent = 'No meeting records returned by the CRM.';
    meetSec.appendChild(none);
  } else {
    const list = el('ul', 'meet-list');
    for (const m of meetings.slice(0, 24)) {
      const li = el('li', `meet-item meet-${m.status || 'unknown'}`);
      const dot = el('span', 'meet-dot');
      li.appendChild(dot);
      const date = el('span', 'meet-date');
      date.textContent = m.date || 'undated';
      li.appendChild(date);
      const type = el('span', 'meet-type');
      type.textContent = m.type || '';
      li.appendChild(type);
      const st = el('span', 'meet-state');
      st.textContent = ATTEND_WORD[m.status] || m.status || 'unknown';
      li.appendChild(st);
      if (m.notes) li.title = m.notes;
      list.appendChild(li);
    }
    meetSec.appendChild(list);
    if (meetings.length > 24) {
      const more = el('p', 'meet-more');
      more.textContent = `+ ${meetings.length - 24} earlier meetings`;
      meetSec.appendChild(more);
    }
  }
  host.appendChild(meetSec);

  // ── Outstanding balance ──
  const out = en.outstanding || {};
  const outRow = el('div', 'enrich-outstanding');
  const outLab = el('span', 'out-label');
  outLab.textContent = 'Outstanding balance';
  outRow.appendChild(outLab);
  const outVal = el('span', 'out-value');
  if (out.amount == null) {
    outVal.textContent = 'Not provided by the CRM';
    outVal.classList.add('out-unknown');
  } else if (out.amount > 0) {
    outVal.textContent = formatMoney(out.amount, out.currency);
    outVal.classList.add('out-due');
  } else {
    outVal.textContent = formatMoney(0, out.currency) + ' — clear';
    outVal.classList.add('out-clear');
  }
  outRow.appendChild(outVal);
  host.appendChild(outRow);

  // ── Pending items needing attention ──
  const pending = Array.isArray(en.pending) ? en.pending : [];
  const pendSec = el('div', 'enrich-section');
  const pendTitle = el('p', 'enrich-section-title');
  pendTitle.textContent = 'Needs attention';
  pendSec.appendChild(pendTitle);
  if (!pending.length) {
    const none = el('p', 'enrich-none');
    none.textContent = 'Nothing flagged by the CRM.';
    pendSec.appendChild(none);
  } else {
    const list = el('ul', 'pend-list');
    for (const p of pending) {
      const li = el('li', `pend-item pend-${p.severity || 'info'}`);
      const dot = el('span', 'pend-dot');
      li.appendChild(dot);
      const txt = el('span', 'pend-text');
      txt.textContent = p.label + (p.due ? ` — due ${p.due}` : '');
      li.appendChild(txt);
      // Tag whether this is a CRM-authored alert or a derived summary.
      const tag = el('span', 'pend-tag');
      tag.textContent = p.source === 'derived' ? 'derived' : 'CRM';
      li.appendChild(tag);
      list.appendChild(li);
    }
    pendSec.appendChild(list);
  }
  host.appendChild(pendSec);

  // ── Provenance footer — honesty about what the CRM did/didn't give us ──
  const meta = en.meta || {};
  const foot = el('p', 'enrich-foot');
  const missing = Array.isArray(meta.fieldsMissing) ? meta.fieldsMissing.length : 0;
  foot.textContent =
    missing > 0
      ? `Sourced live from the connected CRM. ${missing} field(s) were not provided and are shown as such — nothing is inferred.`
      : 'Sourced live from the connected CRM.';
  if (result && result.enriched_at) {
    foot.textContent += ` Last refreshed ${formatTime(result.enriched_at)}.`;
  }
  host.appendChild(foot);
}

// Canonical payment-state → display word.
const PAY_WORD = {
  paid: 'Paid',
  due: 'Due',
  overdue: 'Overdue',
  partial: 'Partial',
  'no-record': 'No record',
};

// Canonical attendance-state → display word.
const ATTEND_WORD = {
  attended: 'Attended',
  absent: 'Absent',
  excused: 'Excused',
  late: 'Late',
  unknown: 'Unknown',
};

function initialsOf(name) {
  if (!name) return '?';
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0].toUpperCase())
    .join('');
}

function statusTone(status) {
  const s = String(status).toLowerCase();
  if (/active|current/.test(s)) return 'ok';
  if (/lapse|expir|terminat|inactive|suspend/.test(s)) return 'bad';
  return 'id';
}

function formatMoney(amount, currency) {
  const n = Number(amount);
  const num = Number.isFinite(n)
    ? n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })
    : String(amount);
  return currency ? `${currency} ${num}` : num;
}

function formatTime(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

// A small fact row: label + value, with an honest placeholder when absent.
function fact(label, value) {
  const row = el('div', 'fact');
  const l = el('span', 'fact-label');
  l.textContent = label;
  const v = el('span', 'fact-value');
  if (value == null || value === '') {
    v.textContent = 'Not provided by the CRM';
    v.classList.add('fact-empty');
  } else {
    v.textContent = String(value);
  }
  row.append(l, v);
  return row;
}

// A small pill mark (member no, status).
function mark(text, tone) {
  const m = el('span', `enrich-mark mark-${tone || 'id'}`);
  m.textContent = String(text);
  return m;
}

// Fire the call to action — enter a newly-found record into the connected
// register's lead listing.
async function addLead(resultId, btn) {
  btn.disabled = true;
  btn.innerHTML = '<span class="turning"></span> Adding…';
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
    btn.textContent = 'Add to lead listing';
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
  // Connect automatically — the server supplies the admin-configured
  // tenant, so there is no key to enter and nothing to remember.
  autoConnect();

  // Criteria + connector change → re-evaluate the run button.
  $('#criteria').addEventListener('change', refreshRunButton);
  $('#connectorSelect').addEventListener('change', refreshRunButton);

  // Input tabs.
  $$('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      state.activeTab = tab.dataset.tab;
      $$('.tab').forEach((t) => t.classList.toggle('is-active', t === tab));
      $$('.tabpane').forEach((p) =>
        p.classList.toggle('is-hidden', p.dataset.pane !== state.activeTab)
      );
    });
  });

  // Finding filters.
  $('#filterbar').addEventListener('click', (e) => {
    const f = e.target.closest('.filter');
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
    // Adding a connector needs a live connection. If the console is not
    // configured yet, point the user to Settings rather than failing in the
    // dialog.
    if (state.connection !== 'ok') {
      return flashError(
        state.connection === 'unconfigured'
          ? 'Not configured yet — an administrator must set the tenant key in Settings.'
          : 'Not connected. Reload the page and try again.'
      );
    }
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
      save.innerHTML = '<span class="turning"></span> Adding…';
      try {
        await registerConnector(e.target);
        dialog.close();
      } catch (err) {
        $('#connectorErr').textContent = err.message;
      } finally {
        save.disabled = false;
        save.textContent = 'Add connector';
      }
    }
  });

  refreshRunButton();
}

document.addEventListener('DOMContentLoaded', init);
