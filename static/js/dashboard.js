(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const csrf = $('meta[name=csrf]').content;
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const COLORS = ['#123B34', '#B7791F', '#1F7A55', '#6B8F84', '#E3A93B', '#8C4A2F', '#44726A', '#C9B07A'];
  let ME = null;
  const loaded = {};

  async function api(path, opts = {}) {
    const o = { method: 'GET', headers: {}, ...opts };
    if (o.method !== 'GET') o.headers['X-CSRF-Token'] = csrf;
    if (o.json) { o.headers['Content-Type'] = 'application/json'; o.body = JSON.stringify(o.json); }
    const r = await fetch(path, o);
    if (r.status === 401) { location.href = '/login'; throw new Error('Signed out'); }
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || 'Something went wrong.');
    return data;
  }
  function toast(msg, err) {
    const t = document.createElement('div');
    t.className = 'toast' + (err ? ' err' : '');
    t.setAttribute('role', err ? 'alert' : 'status');
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 4200);
  }
  const fail = (e) => toast(e.message, true);
  const fmtTime = (s) => (s || '').replace('T', ' ').replace('Z', '');
  const fmtSize = (n) => (n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB');
  const pill = (text, kind) => `<span class="pill ${kind}">${esc(text)}</span>`;
  const outPill = (o) => pill(o, o === 'Success' ? 'ok' : o === 'Denied' ? 'warn' : 'bad');

  // ---------- charts (plain SVG/HTML, no libraries) ----------
  const NS = 'http://www.w3.org/2000/svg';
  function lineChart(el, items) {
    const W = 560, H = 220, L = 34, B = 28, T = 12, R = 10;
    const max = Math.max(1, ...items.map((i) => i.value));
    const top = Math.ceil(max / 5) * 5 || 5;
    const x = (i) => L + (i * (W - L - R)) / Math.max(1, items.length - 1);
    const y = (v) => T + (1 - v / top) * (H - T - B);
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Line chart of admissions per month: ' + items.map((i) => `${i.label} ${i.value}`).join(', '));
    let g = '';
    for (let k = 0; k <= 4; k++) {
      const v = (top * k) / 4;
      g += `<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" stroke="#E1E9E5"/><text x="${L - 6}" y="${y(v) + 4}" text-anchor="end">${Math.round(v)}</text>`;
    }
    items.forEach((it, i) => { if (i % 2 === 0 || items.length < 7) g += `<text x="${x(i)}" y="${H - 8}" text-anchor="middle">${esc(it.label)}</text>`; });
    const pts = items.map((it, i) => `${x(i)},${y(it.value)}`).join(' ');
    g += `<polyline points="${pts}" fill="none" stroke="#123B34" stroke-width="2.5" stroke-linejoin="round"/>`;
    items.forEach((it, i) => { g += `<circle cx="${x(i)}" cy="${y(it.value)}" r="3.5" fill="#B7791F"><title>${esc(it.label)}: ${it.value}</title></circle>`; });
    svg.innerHTML = g;
    el.replaceChildren(svg);
  }
  function barList(el, items, unit = '') {
    if (!items.length) { el.innerHTML = '<p class="empty">Not enough data to show without exposing individuals.</p>'; return; }
    const max = Math.max(...items.map((i) => i.value));
    el.innerHTML = items.map((i) => `<div class="bar-row"><span>${esc(i.label)}</span><div class="bar"><i style="width:${(100 * i.value) / max}%"></i></div><b>${i.value}${unit}</b></div>`).join('');
  }
  function columns(el, items) {
    const max = Math.max(1, ...items.map((i) => i.value || 0));
    el.innerHTML = '<div class="cols">' + items.map((i) => {
      const h = i.suppressed ? 22 : (100 * i.value) / max;
      return `<div class="col"><b>${i.suppressed ? '&lt;5' : i.value}</b><i class="${i.suppressed ? 'sup' : ''}" style="height:${h * 0.78}%"></i><span>${esc(i.label)}</span></div>`;
    }).join('') + '</div>';
  }
  function donut(el, items) {
    if (!items.length) { el.innerHTML = '<p class="empty">No data.</p>'; return; }
    const total = items.reduce((a, b) => a + b.value, 0);
    let acc = 0, arcs = '';
    const r = 62, c = 2 * Math.PI * r;
    items.forEach((it, i) => {
      const len = (it.value / total) * c;
      arcs += `<circle r="${r}" cx="84" cy="84" fill="none" stroke="${COLORS[i % COLORS.length]}" stroke-width="26" stroke-dasharray="${len} ${c - len}" stroke-dashoffset="${-acc}" transform="rotate(-90 84 84)"/>`;
      acc += len;
    });
    el.innerHTML = `<div class="donut-wrap"><svg viewBox="0 0 168 168" role="img" aria-label="Donut chart">${arcs}</svg><ul class="legend">` +
      items.map((it, i) => `<li><i style="background:${COLORS[i % COLORS.length]}"></i>${esc(it.label)}<b>${Math.round((100 * it.value) / total)}%</b></li>`).join('') + '</ul></div>';
  }
  function ring(pct) {
    const r = 46, c = 2 * Math.PI * r, col = pct === 100 ? '#1F7A55' : pct >= 70 ? '#B7791F' : '#B8372B';
    return `<svg viewBox="0 0 110 110" role="img" aria-label="Compliance score ${pct} percent"><circle cx="55" cy="55" r="${r}" fill="none" stroke="#E1E9E5" stroke-width="10"/><circle cx="55" cy="55" r="${r}" fill="none" stroke="${col}" stroke-width="10" stroke-linecap="round" stroke-dasharray="${(pct / 100) * c} ${c}" transform="rotate(-90 55 55)"/><text x="55" y="62" text-anchor="middle" style="font:800 24px var(--display);fill:#16231F">${pct}%</text></svg>`;
  }

  // ---------- views ----------
  const VIEWS = [
    { id: 'overview', label: 'Overview', need: [], load: loadOverview },
    { id: 'analytics', label: 'Analytics', need: ['analytics:Read'], load: loadAnalytics },
    { id: 'patients', label: 'Patients', need: ['patients:ReadFull', 'patients:ReadPartial', 'patients:ListDeidentified'], load: loadPatients },
    { id: 'documents', label: 'Files in S3', need: ['documents:Upload', 'documents:Download'], load: loadDocuments },
    { id: 'access', label: 'Access (IAM)', need: ['iam:Read'], load: loadAccess },
    { id: 'compliance', label: 'Compliance (Config)', need: ['compliance:Read'], load: loadCompliance },
    { id: 'audit', label: 'Audit trail (CloudTrail)', need: ['audit:Read'], load: loadAudit },
  ];
  const allowed = (v) => !v.need.length || v.need.some((a) => ME.permissions.includes(a));

  function show(id) {
    const v = VIEWS.find((x) => x.id === id && allowed(x)) || VIEWS[0];
    VIEWS.forEach((x) => { $('#view-' + x.id).hidden = x.id !== v.id; });
    document.querySelectorAll('#nav a').forEach((a) => (a.getAttribute('href') === '#' + v.id ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current')));
    $('#title').textContent = v.label;
    v.load().catch(fail);
  }

  async function loadOverview() {
    const d = await api('/api/overview');
    if (d.limited) {
      $('#kpis').innerHTML = `<div class="banner" style="margin:0;border-radius:0">Welcome, ${esc(d.name)}. Your account is new and has no access to patient data yet. Ask an administrator to assign your role, then sign in again.</div>`;
      $('#ov-line').innerHTML = '<p class="empty">Nothing to show until a role is assigned.</p>';
      $('#sys').innerHTML = '';
      return;
    }
    const k = [`<div class="kpi"><b>${d.patients}</b><span>Patients</span></div>`,
      `<div class="kpi"><b>${d.admissions_30d}</b><span>Admissions, last 30 days</span></div>`,
      `<div class="kpi"><b>${d.documents}</b><span>Encrypted files</span></div>`];
    if (d.compliance_score !== null) k.push(`<div class="kpi ${d.compliance_score === 100 ? 'good' : 'bad'}"><b>${d.compliance_score}%</b><span>Config compliance</span></div>`);
    if (d.events_24h !== null) k.push(`<div class="kpi"><b>${d.events_24h}</b><span>Events, 24 hours</span></div>`, `<div class="kpi ${d.denied_24h ? 'bad' : ''}"><b>${d.denied_24h}</b><span>Denied, 24 hours</span></div>`);
    $('#kpis').innerHTML = k.join('');
    const s = d.system;
    $('#sys').innerHTML = `<dt>Database</dt><dd>${esc(s.database)}</dd><dt>Encryption key</dt><dd class="mono">${esc(s.kms.alias || 'KMS key')}<br>${esc(s.kms.key_id)}</dd><dt>Key type</dt><dd>${esc(s.kms.spec)}</dd><dt>File storage</dt><dd>${esc(s.storage.bucket)}<br><small>${esc(s.storage.encryption)}</small></dd>`;
    if (ME.permissions.includes('analytics:Read')) { const a = await api('/api/analytics'); lineChart($('#ov-line'), a.months); }
    else $('#ov-line').innerHTML = '<p class="empty">Your role does not include analytics.</p>';
  }

  async function loadAnalytics() {
    const a = await api('/api/analytics');
    $('#mincell').textContent = a.min_cell;
    $('#an-kpis').innerHTML = `<div class="kpi"><b>${a.admissions}</b><span>Admissions</span></div><div class="kpi"><b>${a.readmission_rate}%</b><span>Readmission rate</span></div>`;
    lineChart($('#an-line'), a.months);
    donut($('#an-dept'), a.departments);
    barList($('#an-diag'), a.diagnoses);
    barList($('#an-los'), a.los, ' d');
    columns($('#an-age'), a.age_bands);
    donut($('#an-gender'), a.genders);
  }

  // patients
  let ptPage = 1, ptTimer = null;
  async function loadPatients() {
    const q = $('#pt-q').value.trim();
    const d = await api(`/api/patients?page=${ptPage}&q=${encodeURIComponent(q)}`);
    const text = { full: 'Full access: names, IDs and notes are decrypted when you open a record. Each open is logged.',
      partial: 'Partial access: you can see names and masked ID numbers. Notes and contact details stay hidden.',
      deidentified: 'De-identified view: names and IDs are not decrypted for your role.' }[d.level];
    $('#pt-banner').textContent = text;
    $('#pt-new').hidden = !ME.permissions.includes('patients:Create');
    const ident = d.level !== 'deidentified';
    $('#pt-head').innerHTML = `<tr><th>MRN</th>${ident ? '<th>Name</th>' : ''}<th>Age</th><th>Gender</th><th>Blood</th><th>City</th><th>Registered</th>${ident ? '<th></th>' : ''}</tr>`;
    $('#pt-body').innerHTML = d.patients.length ? d.patients.map((p) => `<tr><td class="mono">${esc(p.mrn)}</td>${ident ? `<td>${esc(p.name)}</td>` : ''}<td>${p.age}</td><td>${esc(p.gender)}</td><td>${esc(p.blood_group || '')}</td><td>${esc(p.city || '')}</td><td>${esc(p.created_at)}</td>${ident ? `<td><button class="btn ghost small" data-open="${esc(p.mrn)}" type="button">Open</button></td>` : ''}</tr>`).join('') : `<tr><td colspan="8" class="empty">No patients match your search.</td></tr>`;
    $('#pt-page').textContent = `Page ${d.page} of ${d.pages} · ${d.total} patients`;
    $('#pt-prev').disabled = d.page <= 1;
    $('#pt-next').disabled = d.page >= d.pages;
  }
  $('#pt-q').addEventListener('input', () => { clearTimeout(ptTimer); ptTimer = setTimeout(() => { ptPage = 1; loadPatients().catch(fail); }, 300); });
  $('#pt-prev').addEventListener('click', () => { ptPage--; loadPatients().catch(fail); });
  $('#pt-next').addEventListener('click', () => { ptPage++; loadPatients().catch(fail); });
  $('#pt-body').addEventListener('click', async (e) => {
    const b = e.target.closest('[data-open]');
    if (!b) return;
    try {
      const p = await api('/api/patients/' + encodeURIComponent(b.dataset.open));
      $('#dp-title').textContent = p.name;
      const rows = [['MRN', `<span class="mono">${esc(p.mrn)}</span>`], ['National ID', esc(p.national_id)], ['Age / gender', `${p.age}, ${esc(p.gender)}`], ['Blood group', esc(p.blood_group || 'Unknown')], ['City', esc(p.city || '')]];
      if (p.level === 'full') rows.push(['Phone', esc(p.phone)], ['Address', esc(p.address)], ['Notes', esc(p.notes)]);
      rows.push(['Files in S3', p.documents], ['Data key', `<span class="mono">${esc(p.key_id)}</span>`]);
      $('#dp-body').innerHTML = `<dl class="facts">${rows.map((r) => `<dt>${r[0]}</dt><dd>${r[1]}</dd>`).join('')}</dl><h3 style="margin:1.4rem 0 .6rem;font-size:1.05rem">Admissions</h3><table class="data"><thead><tr><th>Department</th><th>Diagnosis</th><th>Admitted</th><th>Discharged</th><th>Outcome</th></tr></thead><tbody>${p.admissions.map((a) => `<tr><td>${esc(a.department)}</td><td>${esc(a.diagnosis)}</td><td>${esc(a.admit_date)}</td><td>${esc(a.discharge_date || '')}</td><td>${esc(a.outcome)}</td></tr>`).join('')}</tbody></table>`;
      $('#dlg-patient').showModal();
    } catch (err) { fail(err); }
  });
  $('#pt-new').addEventListener('click', () => $('#dlg-new').showModal());
  $('#new-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const body = Object.fromEntries(new FormData(e.target).entries());
    try {
      const r = await api('/api/patients', { method: 'POST', json: body });
      $('#dlg-new').close(); e.target.reset(); toast('Saved and encrypted as ' + r.mrn);
      ptPage = 1; loadPatients().catch(fail);
    } catch (err) { fail(err); }
  });

  // documents
  async function loadDocuments() {
    const mrn = $('#dc-q').value.trim();
    const d = await api('/api/documents' + (mrn ? '?mrn=' + encodeURIComponent(mrn) : ''));
    $('#dc-upload').hidden = !ME.permissions.includes('documents:Upload');
    $('#dc-body').innerHTML = d.documents.length ? d.documents.map((x) => `<tr><td>${esc(x.filename)}<br><span class="mono" style="color:var(--muted)">${esc(x.s3_key)}</span></td><td class="mono">${esc(x.mrn)}</td><td>${fmtSize(x.size_bytes)}</td><td>${esc(fmtTime(x.uploaded_at))}<br><small>${esc(x.uploaded_by)}</small></td><td>${d.can_download ? `<a class="btn ghost small" href="/api/documents/${x.id}/download">Download</a>` : pill('Upload only', 'mute')}</td></tr>`).join('') : '<tr><td colspan="5" class="empty">No files yet. Upload a report on the right.</td></tr>';
  }
  let dcTimer = null;
  $('#dc-q').addEventListener('input', () => { clearTimeout(dcTimer); dcTimer = setTimeout(() => loadDocuments().catch(fail), 300); });
  $('#dc-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/api/documents', { method: 'POST', body: new FormData(e.target) });
      toast('File encrypted and stored'); e.target.reset(); loadDocuments().catch(fail);
    } catch (err) { fail(err); }
  });

  // IAM
  async function loadAccess() {
    const d = await api('/api/iam');
    const acts = Object.keys(d.actions);
    $('#iam-matrix').innerHTML = `<thead><tr><th>Action</th>${d.roles.map((r) => `<th class="role">${esc(r.label)}</th>`).join('')}</tr></thead><tbody>` +
      acts.map((a) => `<tr><td>${esc(d.actions[a])}<br><span class="mono" style="color:var(--muted)">${esc(a)}</span></td>${d.roles.map((r) => r.deny.includes(a) ? '<td class="cell deny">Deny</td>' : r.allow.includes(a) ? '<td class="cell allow">Allow</td>' : '<td class="cell none">–</td>').join('')}</tr>`).join('') + '</tbody>';
    $('#iam-roles').innerHTML = d.roles.map((r) => `<details><summary>${esc(r.label)}</summary><p class="hint" style="margin:.5rem 0 0">${esc(r.summary)}</p><pre class="policy">${esc(JSON.stringify(r.policy, null, 2))}</pre></details>`).join('');
    const roleCell = (u) => d.can_manage ? `<select class="role-pick" data-user="${esc(u.username)}" aria-label="Role for ${esc(u.full_name)}">${d.assignable.map((r) => `<option value="${esc(r.id)}"${r.id === u.role ? ' selected' : ''}>${esc(r.label)}</option>`).join('')}</select>` : esc(u.role);
    $('#iam-users').innerHTML = d.users.map((u) => `<tr><td>${esc(u.full_name)}<br><span class="mono">${esc(u.username)}</span></td><td>${roleCell(u)}</td><td>${u.mfa_enabled ? pill('On', 'ok') : pill('Off', 'bad')}</td><td>${esc(fmtTime(u.last_login) || 'Never')}</td></tr>`).join('');
  }

  $('#iam-users').addEventListener('change', async (e) => {
    const sel = e.target.closest('select[data-user]');
    if (!sel) return;
    try {
      await api('/api/iam/users/' + encodeURIComponent(sel.dataset.user) + '/role', { method: 'POST', json: { role: sel.value } });
      toast('Role updated. It applies on that user\'s next page load.');
    } catch (err) { fail(err); loadAccess().catch(fail); }
  });

  // compliance
  function renderCompliance(d) {
    $('#cp-score').innerHTML = `${ring(d.score)}<div><h2 style="font-size:1.3rem">${d.score === 100 ? 'All rules pass' : 'Some rules need attention'}</h2><p class="hint" style="margin:.3rem 0 .8rem">Last evaluated: ${esc(fmtTime(d.last_evaluated) || 'on startup')}</p>${d.can_manage ? '<button class="btn" id="cp-eval" type="button">Re-evaluate all rules</button>' : ''}</div>`;
    const note = $('#cp-note');
    note.hidden = !d.demo_controls;
    note.textContent = 'Demo controls: turn a setting off to simulate a misconfiguration, watch the rule fail, then apply the fix. Every change is logged.';
    $('#cp-rules').innerHTML = d.rules.map((r) => {
      const bad = r.status === 'NON_COMPLIANT';
      const acts = [];
      if (d.can_manage && d.demo_controls) {
        if (r.state) acts.push(`<button class="btn ${r.setting_on ? 'danger' : 'ghost'} small" data-toggle="${esc(r.state)}" type="button">${r.setting_on ? 'Simulate drift: turn off' : 'Turn on'}</button>`);
        if (bad) acts.push(`<button class="btn small" data-fix="${esc(r.id)}" type="button">Apply fix</button>`);
      }
      return `<div class="rule"><div><h3>${esc(r.title)}</h3><p class="meta">${esc(r.service)} · <span class="mono">${esc(r.id)}</span></p><p class="meta">${esc(r.detail)}${bad ? '. ' + esc(r.fix) : ''}</p></div>${pill(r.status.replace('_', ' ').toLowerCase(), r.status === 'COMPLIANT' ? 'ok' : bad ? 'bad' : 'mute')}${acts.length ? `<div class="acts">${acts.join('')}</div>` : ''}</div>`;
    }).join('');
  }
  async function loadCompliance() { renderCompliance(await api('/api/compliance')); }
  $('#view-compliance').addEventListener('click', async (e) => {
    try {
      if (e.target.id === 'cp-eval') renderCompliance(await api('/api/compliance/evaluate', { method: 'POST' }));
      const t = e.target.closest('[data-toggle]');
      if (t) renderCompliance(await api('/api/compliance/toggle', { method: 'POST', json: { state: t.dataset.toggle } }));
      const f = e.target.closest('[data-fix]');
      if (f) { renderCompliance(await api('/api/compliance/remediate', { method: 'POST', json: { rule: f.dataset.fix } })); toast('Fix applied'); }
    } catch (err) { fail(err); }
  });

  // audit
  let auTimer = null;
  function auditRows(rows, real) {
    $('#au-body').innerHTML = rows.length ? rows.map((e) => `<tr><td class="mono">${esc(fmtTime(e.event_time))}</td><td><strong>${esc(e.event_name)}</strong><br><small>${esc(e.event_source)}</small></td><td>${esc(e.username)}<br><small>${esc(e.role || '')}${e.source_ip ? ' · ' + esc(e.source_ip) : ''}</small></td><td class="mono">${esc(e.resource)}</td><td>${real ? pill('CloudTrail', 'mute') : outPill(e.outcome)}</td><td>${esc(e.detail || '')}</td></tr>`).join('') : '<tr><td colspan="6" class="empty">No events match.</td></tr>';
  }
  async function loadAudit() {
    const d = await api(`/api/audit?q=${encodeURIComponent($('#au-q').value.trim())}&outcome=${encodeURIComponent($('#au-out').value)}&limit=120`);
    $('#au-ct').hidden = !d.cloudtrail;
    auditRows(d.events, false);
  }
  const reAudit = () => { clearTimeout(auTimer); auTimer = setTimeout(() => loadAudit().catch(fail), 300); };
  $('#au-q').addEventListener('input', reAudit);
  $('#au-out').addEventListener('change', reAudit);
  $('#au-ct').addEventListener('click', async () => { try { auditRows((await api('/api/audit/cloudtrail')).events, true); } catch (e) { fail(e); } });

  document.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => b.closest('dialog').close()));

  // ---------- start ----------
  (async () => {
    ME = await api('/api/me');
    const nav = $('#nav');
    nav.innerHTML = VIEWS.filter(allowed).map((v) => `<a href="#${v.id}">${esc(v.label)}</a>`).join('');
    window.addEventListener('hashchange', () => show(location.hash.slice(1)));
    show(location.hash.slice(1));
  })().catch(fail);
})();
