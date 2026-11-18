// Sudo-Z UI controller.
import { CATALOG, NOT_ACCEPTED_HELP, availability } from './catalog.js';
import { markdown, csv, timelineCsv, findingsCsv, indicatorsCsv, leadsCsv, programsCsv, mitreSummary, indicatorLabel, defang } from './report.js';
import { Grid, datasets } from './grid.js';
import { PROGRAM_COLUMNS } from './ioc/programs.js';

const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => {
  if (v == null) return '';
  if (v instanceof Uint8Array) v = Array.from(v.subarray(0, 48), (b) => b.toString(16).padStart(2, '0')).join(' ') + (v.length > 48 ? ' …' : '');
  else if (Array.isArray(v)) v = v.join(' | ');
  return String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
};
const fmtSize = (n) => (n >= 1 << 30 ? (n / (1 << 30)).toFixed(2) + ' GB' : n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + ' MB' : n >= 1024 ? (n / 1024).toFixed(1) + ' KB' : n + ' B');
const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_SHORT = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW', info: 'INFO' };
const isTimeCol = (c) => /time|created|modified|accessed|last|first|start|end|deleted|write|logon|run|when|date|visit/i.test(c);

const S = { staged: [], rep: null, tab: 'sitrep', f: { sev: new Set(['critical', 'high', 'medium', 'low', 'info']), q: '', cat: '' }, tl: { q: '', tool: '', page: 0 }, ind: { q: '', type: '', defang: true }, art: { q: '' }, inv: { q: '' }, grid: { ds: null, tagsBy: {}, widthsBy: {}, q: '', filters: {}, hidden: new Set(), collapsed: new Set(), group: -1 } };

// ---------------------------------------------------------------- clock
setInterval(() => { $('#clock').textContent = new Date().toISOString().slice(11, 19) + ' UTC'; }, 1000);

// ---------------------------------------------------------------- intake
const drop = $('#drop'), input = $('#file');
drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
drop.addEventListener('dragleave', () => drop.classList.remove('over'));
drop.addEventListener('drop', async (e) => {
  e.preventDefault(); drop.classList.remove('over');
  const items = [...(e.dataTransfer.items || [])];
  const files = [];
  const walkEntry = (entry, path) => new Promise((res) => {
    if (!entry) return res();
    if (entry.isFile) entry.file((f) => { files.push({ file: f, name: path + f.name }); res(); }, () => res());
    else if (entry.isDirectory) {
      const rd = entry.createReader(); const all = [];
      const next = () => rd.readEntries(async (ents) => { if (!ents.length) { for (const en of all) await walkEntry(en, path + entry.name + '/'); res(); } else { all.push(...ents); next(); } }, () => res());
      next();
    } else res();
  });
  if (items.length && items[0].webkitGetAsEntry) { await Promise.all(items.map((it) => walkEntry(it.webkitGetAsEntry(), ''))); }
  else for (const f of e.dataTransfer.files) files.push({ file: f, name: f.name });
  stage(files);
});
drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') input.click(); });
input.addEventListener('change', () => { stage([...input.files].map((f) => ({ file: f, name: f.webkitRelativePath || f.name }))); input.value = ''; });

function stage(list) {
  for (const x of list) { x.size = x.size ?? x.file.size; if (!S.staged.some((s) => s.name === x.name && s.size === x.size)) S.staged.push(x); }
  renderStaged();
}
function renderStaged() {
  const el = $('#staged');
  if (!S.staged.length) el.innerHTML = '<div class="muted">No files staged.</div>';
  else {
    const tot = S.staged.reduce((n, s) => n + s.size, 0);
    el.innerHTML = S.staged.map((s) => `<div class="f"><span title="${esc(s.name)}">${esc(s.name)}</span><span>${s.http ? 'IN PLACE ' : ''}${fmtSize(s.size)}</span></div>`).join('') + `<div class="f" style="border-top:1px solid var(--line);margin-top:4px;padding-top:2px"><span class="muted">${S.staged.length} file(s)</span><span>${fmtSize(tot)}</span></div>`;
  }
  $('#run').disabled = !S.staged.length; $('#clear').disabled = !S.staged.length;
}
$('#clear').addEventListener('click', () => { S.staged = []; renderStaged(); });

$('#run').addEventListener('click', async () => {
  const btn = $('#run'); btn.disabled = true; $('#clear').disabled = true;
  $('#progress').hidden = false; setProg(0, 'reading files');
  const files = [];
  for (const s of S.staged) files.push(s.http ? { name: s.name, http: s.http } : { name: s.name, file: s.file }); // the worker reads them (disk images lazily)
  let worker;
  try { worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' }); }
  catch { worker = null; }
  const done = (rep) => { S.rep = rep; setProg(1, `done in ${(rep.meta.durationMs / 1000).toFixed(1)}s`); btn.disabled = false; $('#clear').disabled = false; onReport(); };
  if (worker) {
    worker.onmessage = (e) => {
      const m = e.data;
      if (m.type === 'progress') setProg(m.p, m.label);
      else if (m.type === 'done') { done(m.rep); worker.terminate(); }
      else if (m.type === 'error') { setProg(0, 'ERROR: ' + m.message); console.error(m.stack); btn.disabled = false; worker.terminate(); }
    };
    worker.onerror = async (e) => { console.warn('worker failed, running on main thread', e); worker.terminate(); await mainThread(files, done); };
    worker.postMessage({ files });
  } else await mainThread(files, done);
});
async function mainThread(files, done) {
  const { analyze } = await import('./engine.js');
  const { fromBlob } = await import('./image/source.js');
  const inputs = [];
  const { fromHttp } = await import('./image/source.js');
  for (const f of files) if (f.http) inputs.push({ name: f.name, src: fromHttp(`/api/image/read?path=${encodeURIComponent(f.http.path)}`, f.http.size, f.name, { 'X-Sudo-Z': '1' }) }); else inputs.push(/\.(e01|e\d\d|raw|dd|img|\d{3}|vhdx?|qcow2?)$/i.test(f.name) || f.file.size > 512 * 1024 ** 2 ? { name: f.name, src: fromBlob(f.file, f.name) } : { name: f.name, data: new Uint8Array(await f.file.arrayBuffer()) });
  try { done(await analyze(inputs, { onProgress: setProg })); }
  catch (e) { setProg(0, 'ERROR: ' + e.message); $('#run').disabled = false; }
}
function setProg(p, label) { $('#pfill').style.width = Math.round(p * 100) + '%'; $('#plabel').textContent = label || ''; }

// ---------------------------------------------------------------- tabs + exports
$('#tabs').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-tab]'); if (!b) return;
  S.tab = b.dataset.tab; [...$('#tabs').querySelectorAll('button[data-tab]')].forEach((x) => x.classList.toggle('on', x === b)); render();
});
$('#exports').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-exp]'); if (!b || !S.rep) return;
  const stamp = S.rep.meta.generated.replace(/[:.]/g, '').slice(0, 15);
  const map = {
    md: () => [markdown(S.rep, { defanged: S.ind.defang }), `sudo-z_report_${stamp}.md`, 'text/markdown'],
    json: () => [JSON.stringify(S.rep, (k, v) => (typeof v === 'bigint' ? v.toString() : v instanceof Uint8Array ? Array.from(v.subarray(0, 512), (x) => x.toString(16).padStart(2, '0')).join('') : v), 1), `sudo-z_report_${stamp}.json`, 'application/json'],
    findings: () => [findingsCsv(S.rep), `sudo-z_findings_${stamp}.csv`, 'text/csv'],
    programs: () => [programsCsv(S.rep), `sudo-z_programs_${stamp}.csv`, 'text/csv'],
    leads: () => [leadsCsv(S.rep), `sudo-z_leads_${stamp}.csv`, 'text/csv'],
    ioc: () => [indicatorsCsv(S.rep), `sudo-z_ioc_${stamp}.csv`, 'text/csv'],
    timeline: () => [timelineCsv(S.rep), `sudo-z_timeline_${stamp}.csv`, 'text/csv'],
  };
  const [data, name, type] = map[b.dataset.exp]();
  download(data, name, type);
});
function download(data, name, type) {
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([data], { type })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

function onReport() {
  const r = S.rep;
  $('#n-leads').textContent = (r.leads || []).length; $('#n-prog').textContent = (r.programs || []).length || ''; S.grid.ds = null; S.gridWant = null; S.grid.tagsBy = {}; S.grid.widthsBy = {}; $('#n-findings').textContent = r.findings.length; $('#n-ind').textContent = r.indicators.length; $('#n-tl').textContent = r.timeline.length;
  $('#n-art').textContent = r.files.filter((f) => f.status !== 'rejected').length; $('#n-rej').textContent = r.files.filter((f) => f.status === 'rejected' || f.status === 'partial').length;
  $('#exports').hidden = false;
  S.tab = 'sitrep'; [...$('#tabs').querySelectorAll('button[data-tab]')].forEach((x) => x.classList.toggle('on', x.dataset.tab === 'sitrep'));
  render();
}

function render() {
  const v = $('#view');
  if (S.tab === 'tools') return (v.innerHTML = toolsView());
  if (!S.rep) return (v.innerHTML = idleView());
  ({ sitrep: sitrepView, investigate: investigateView, grid: gridView, findings: findingsView, indicators: indicatorsView, timeline: timelineView, artifacts: artifactsView, rejected: rejectedView })[S.tab](v);
}

// ---------------------------------------------------------------- idle
function idleView() {
  return `<div class="idle"><h1>AWAITING ARTIFACTS</h1>
  <p>Sudo-Z takes the Eric Zimmerman forensic toolset (EvtxECmd, PECmd, LECmd, JLECmd, RECmd, AmcacheParser, AppCompatCacheParser, SBECmd, MFTECmd, RBCmd, SQLECmd, WxTCmd, bstrings, Hasher and more) and folds it into one browser console that does not just parse, it <b style="color:var(--amber)">hunts</b>. Every artifact is routed to the parser that accepts it, normalised, then run through shared detection logic so a malicious path in a Run key, a Prefetch file and a Sysmon event all get graded the same way and land in one IOC report.</p>
  <div class="steps">
    <div><b>01 / DROP</b>One file, many files, a folder, or a KAPE triage .zip. Nested zips are opened.</div>
    <div><b>02 / ROUTE</b>Each file is identified by signature, not just name, and sent to the matching tool. Unsupported files are hashed, string-scanned and listed with a reason.</div>
    <div><b>03 / HUNT</b>Persistence, execution, credential access, lateral movement, defence evasion and C2 rules with MITRE ATT&amp;CK mapping.</div>
    <div><b>04 / REPORT</b>SITREP, findings, IOC list, super timeline and per-artifact tables. Export Markdown, JSON or Timeline Explorer-ready CSV.</div>
  </div>
  <p class="muted">Nothing is uploaded. Parsing runs in a Web Worker on this machine; the page works offline once loaded.</p></div>`;
}

// ---------------------------------------------------------------- SITREP
function sitrepView(v) {
  const r = S.rep;
  const cls = r.severity.critical ? 'crit' : r.severity.high ? 'high' : r.severity.medium ? 'med' : 'ok';
  const cats = new Map(); for (const f of r.findings) if (f.sev !== 'info') cats.set(f.category, (cats.get(f.category) || 0) + 1);
  const catRows = [...cats].sort((a, b) => b[1] - a[1]); const maxCat = Math.max(1, ...catRows.map((c) => c[1]));
  const mitre = mitreSummary(r).slice(0, 24);
  const top = r.findings.filter((f) => f.sev === 'critical' || f.sev === 'high').slice(0, 15);
  const types = new Map(); for (const i of r.indicators) types.set(i.type, (types.get(i.type) || 0) + 1);
  v.innerHTML = `
  <div class="verdict ${cls}"><span class="v">${esc(r.verdict)}</span><span class="meta">${r.counts.files} files · ${r.counts.parsed} parsed · ${r.counts.partial} partial · ${r.counts.rejected} not accepted · ${r.counts.errors} errors · ${(r.meta.durationMs / 1000).toFixed(1)}s</span></div>
  <div class="kpis">${SEVS.map((s) => `<div class="kpi ${s}" data-sev="${s}"><div class="k">${s.toUpperCase()}</div><div class="n">${r.severity[s] || 0}</div></div>`).join('')}</div>
  <div class="cols">
    <div>
      <div class="box"><div class="ph"><span class="code">A</span> ENGAGEMENT WINDOW</div><div class="body kv">
        <div>High/crit first</div><div>${esc(r.window.attackFirst || 'n/a')}</div>
        <div>High/crit last</div><div>${esc(r.window.attackLast || 'n/a')}</div>
        <div>Evidence from</div><div>${esc(r.window.first || 'n/a')}</div>
        <div>Evidence to</div><div>${esc(r.window.last || 'n/a')}</div>
        <div>Hosts</div><div>${r.hosts.length ? r.hosts.map((h) => `<span class="chip">${esc(h)}</span>`).join(' ') : 'n/a'}</div>
        <div>Accounts</div><div>${r.users.length ? r.users.slice(0, 30).map((h) => `<span class="chip">${esc(h)}</span>`).join(' ') : 'n/a'}</div>
      </div></div>
      <div class="box"><div class="ph"><span class="code">B</span> ACTIVITY BY TACTIC</div><div class="body bars">${catRows.map(([c, n]) => `<div class="row"><span>${esc(c)}</span><span class="track"><span class="fill" style="width:${(n / maxCat) * 100}%"></span></span><span class="n">${n}</span></div>`).join('') || '<span class="muted">No findings.</span>'}</div></div>
      <div class="box"><div class="ph"><span class="code">C</span> MITRE ATT&amp;CK</div><div class="body chips">${mitre.map((m) => `<a class="chip" target="_blank" rel="noopener" href="https://attack.mitre.org/techniques/${m.id.replace('.', '/')}/" title="${m.count} finding(s), worst ${m.worst}"><span class="sev ${m.worst}" style="min-width:0;border:0;padding:0 3px">${m.id}</span> ×${m.count}</a>`).join('') || '<span class="muted">none</span>'}</div></div>
      <div class="box"><div class="ph"><span class="code">D</span> INDICATOR TYPES</div><div class="body chips">${[...types].sort((a, b) => b[1] - a[1]).map(([t, n]) => `<span class="chip t" data-ind="${esc(t)}">${esc(indicatorLabel(t))} <b style="color:var(--amber);font-weight:400">${n}</b></span>`).join('') || '<span class="muted">none</span>'}</div></div>
    </div>
    <div>
      <div class="box"><div class="ph"><span class="code">L</span> LEADS TO INVESTIGATE <a class="more" href="#" data-go="investigate">ALL ${(r.leads || []).length} &gt;</a></div><div class="body">${(r.leads || []).length ? r.leads.slice(0, 6).map((l, i) => leadRow(l, i, true)).join('') : '<span class="muted">No correlated leads. Check FINDINGS for single-artifact hits.</span>'}</div></div>
      ${progBox(r)}
      <div class="box"><div class="ph"><span class="code">E</span> PRIORITY FINDINGS</div><div class="body">${top.length ? top.map(findingRow).join('') : '<span class="muted">No high or critical findings.</span>'}</div></div>
      <div class="box"><div class="ph"><span class="code">F</span> COVERAGE</div><div class="body">${coverage(r)}</div></div>
    </div>
  </div>`;
  v.querySelectorAll('.kpi').forEach((k) => k.addEventListener('click', () => { S.f.sev = new Set([k.dataset.sev]); switchTab('findings'); }));
  v.querySelectorAll('[data-go]').forEach((a) => a.addEventListener('click', (e) => { e.preventDefault(); switchTab(a.dataset.go); }));
  v.querySelectorAll('[data-prog]').forEach((a) => a.addEventListener('click', () => { openGrid('programs', { q: '', filters: { 2: '=' + a.dataset.prog } }); }));
  bindLeads(v);
  v.querySelectorAll('[data-ind]').forEach((k) => k.addEventListener('click', () => { S.ind.type = k.dataset.ind; switchTab('indicators'); }));
  bindFindings(v);
}
function coverage(r) {
  const by = new Map();
  for (const f of r.files) { const k = f.tool || '-'; const e = by.get(k) || { n: 0, st: new Set() }; e.n++; e.st.add(f.status); by.set(k, e); }
  return `<table class="t"><tr><th>TOOL</th><th>FILES</th><th>STATUS</th></tr>${[...by].sort((a, b) => b[1].n - a[1].n).map(([t, e]) => `<tr><td>${esc(t)}</td><td>${e.n}</td><td>${[...e.st].map((s) => `<span class="st ${s}">${s.toUpperCase()}</span>`).join(' ')}</td></tr>`).join('')}</table>`;
}
function switchTab(t) { S.tab = t; [...$('#tabs').querySelectorAll('button[data-tab]')].forEach((x) => x.classList.toggle('on', x.dataset.tab === t)); render(); }

// ---------------------------------------------------------------- FINDINGS
function findingRow(f, i) {
  const mitre = (f.mitre || []).filter(Boolean).map((m) => `<a target="_blank" rel="noopener" href="https://attack.mitre.org/techniques/${m.replace('.', '/')}/">${m}</a>`).join('');
  return `<div class="fd ${f.sev}"><div class="hd"><span class="sev ${f.sev}">${SEV_SHORT[f.sev]}</span><span class="title">${esc(f.title)}</span><span class="when">${esc(f.time ? f.time.replace('T', ' ').slice(0, 19) : '')}</span></div>
  <div class="bd"><div class="kv"><div>CATEGORY</div><div>${esc(f.category)}</div><div>TOOL</div><div>${esc(f.tool)}</div><div>SOURCE</div><div>${esc(f.file)}</div>${f.detail ? `<div>WHY</div><div>${esc(f.detail)}</div>` : ''}${mitre ? `<div>ATT&amp;CK</div><div class="mitre">${mitre}</div>` : ''}${f.next ? `<div>NEXT</div><div class="next">${esc(f.next)}</div>` : ''}</div>${f.evidence ? `<pre class="ev">${esc(f.evidence)}</pre>` : ''}</div></div>`;
}
function bindFindings(root) { root.querySelectorAll('.fd .hd').forEach((h) => h.addEventListener('click', () => h.parentElement.classList.toggle('open'))); }

function findingsView(v) {
  const r = S.rep;
  const cats = [...new Set(r.findings.map((f) => f.category))].sort();
  const list = r.findings.filter((f) => S.f.sev.has(f.sev) && (!S.f.cat || f.category === S.f.cat) && (!S.f.q || `${f.title} ${f.detail} ${f.evidence} ${f.file} ${f.tool} ${(f.mitre || []).join(' ')}`.toLowerCase().includes(S.f.q.toLowerCase())));
  const shown = list.slice(0, 1500);
  v.innerHTML = `<div class="toolbar">${SEVS.map((s) => `<button class="tog ${s} ${S.f.sev.has(s) ? 'on' : ''}" data-s="${s}">${SEV_SHORT[s]} ${r.severity[s] || 0}</button>`).join('')}
    <select id="fcat"><option value="">ALL CATEGORIES</option>${cats.map((c) => `<option ${c === S.f.cat ? 'selected' : ''}>${esc(c)}</option>`).join('')}</select>
    <input type="search" id="fq" placeholder="filter: text, path, T1059, tool…" value="${esc(S.f.q)}">
    <button class="tog on" id="fexp">EXPAND ALL</button>
    <span class="count">${list.length} shown${list.length > shown.length ? ' (first 1500 rendered)' : ''}</span></div>
    <div id="flist">${shown.map(findingRow).join('') || '<div class="muted">No findings match.</div>'}</div>`;
  v.querySelectorAll('.tog[data-s]').forEach((b) => b.addEventListener('click', () => { const s = b.dataset.s; S.f.sev.has(s) ? S.f.sev.delete(s) : S.f.sev.add(s); findingsView(v); }));
  $('#fcat').addEventListener('change', (e) => { S.f.cat = e.target.value; findingsView(v); });
  const q = $('#fq'); q.addEventListener('input', debounce(() => { S.f.q = q.value; findingsView(v); $('#fq').focus(); $('#fq').setSelectionRange(q.value.length, q.value.length); }, 250));
  $('#fexp').addEventListener('click', () => { const open = !v.querySelector('.fd.open'); v.querySelectorAll('.fd').forEach((f) => f.classList.toggle('open', open)); });
  bindFindings(v);
}

// ---------------------------------------------------------------- GRID (Timeline Explorer style)
function progBox(r) {
  const top = (r.programs || []).filter((p) => p.risk >= 25).slice(0, 8);
  const uns = (r.programs || []).filter((p) => p.signState === 'unsigned' || p.signState === 'invalid').length;
  return `<div class="box"><div class="ph"><span class="code">P</span> PROGRAMS TO REVIEW <a class="more" href="#" data-go="grid">GRID ${(r.programs || []).length} &gt;</a></div><div class="body">
    ${top.length ? `<table class="t prog"><tr><th>RISK</th><th>PROGRAM</th><th>SIGNATURE</th><th>WHERE</th><th>WHY</th></tr>${top.map((p) => `<tr data-prog="${esc(p.name)}" class="sv-${p.level}"><td class="num"><span class="sev ${p.level}">${p.risk}</span></td><td>${esc(p.name)}</td><td class="${p.signState}">${esc(p.signature.slice(0, 40))}</td><td>${esc(p.location)}</td><td class="muted">${esc(p.reasons.slice(0, 90))}</td></tr>`).join('')}</table>` : '<span class="muted">No program scored 25 or more.</span>'}
    <div class="fine">${uns} unsigned or invalid-signature binaries. Signature data comes from Sysmon 6/7, Autoruns, Sigcheck, Amcache and the PE files themselves.</div></div></div>`;
}
const PROG_CHIPS = [['ALL', {}], ['RISK ≥ 45', { 0: '>=45' }], ['UNSIGNED', { 3: '/^(unsigned|signature not valid)/' }], ['USER-WRITABLE', { 4: '=User-writable' }], ['PERSISTS', { 10: '/./' }], ['HAS FINDINGS', { 11: '>0' }], ['LOLBINS', { 2: '/^(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|msiexec|wmic|msbuild|installutil)\\.exe$/' }]];
let GRID = null;
function openGrid(id, preset) {
  S.gridWant = id;
  if (preset) Object.assign(S.grid, { ds: id, q: preset.q || '', filters: { ...preset.filters }, sort: null, group: -1, hidden: new Set(), collapsed: new Set(), sel: null, tagOnly: false });
  switchTab('grid');
}
function gridView(v) {
  const all = datasets(S.rep, PROGRAM_COLUMNS);
  const want = S.gridWant || S.grid.ds;
  const id = want && all.some((d) => d.id === want) ? want : all[0].id;
  const groups = [...new Set(all.map((d) => d.group))];
  v.innerHTML = `<div class="toolbar g-pick"><select id="gds">${groups.map((g) => `<optgroup label="${esc(g)}">${all.filter((d) => d.group === g).map((d) => `<option value="${esc(d.id)}" ${d.id === id ? 'selected' : ''}>${esc(d.label)}</option>`).join('')}</optgroup>`).join('')}</select>
    ${id === 'programs' ? `<span class="chips">${PROG_CHIPS.map(([l, f], i) => `<button class="tog ${JSON.stringify(f) === JSON.stringify(S.grid.filters || {}) ? 'on' : ''}" data-chip="${i}">${l}</button>`).join('')}</span>` : ''}
    <span class="count">click a header to sort · type under it to filter · tag rows with □</span></div><div id="grid" class="dgrid"></div>`;
  const ds = all.find((d) => d.id === id);
  GRID = new Grid($('#grid'), S.grid, { onPivot: (q) => { S.inv.q = q; switchTab('investigate'); } });
  GRID.open(ds);
  $('#gds').addEventListener('change', (e) => { S.gridWant = e.target.value; gridView(v); });
  v.querySelectorAll('[data-chip]').forEach((b) => b.addEventListener('click', () => { S.grid.filters = { ...PROG_CHIPS[+b.dataset.chip][1] }; S.grid.q = ''; gridView(v); }));
}

// ---------------------------------------------------------------- INVESTIGATE
function leadRow(l, i, compact) {
  const mitre = (l.mitre || []).filter(Boolean).map((m) => `<a target="_blank" rel="noopener" href="https://attack.mitre.org/techniques/${m.replace('.', '/')}/">${m}</a>`).join('');
  const ents = (l.entities || []).filter(Boolean).slice(0, 12).map((e) => `<span class="chip t" data-pivot="${esc(e)}" title="pivot on this">${esc(e)}</span>`).join(' ');
  const rel = (l.related || []).length ? `<table class="t rel"><tr><th>TIME (UTC)</th><th>SOURCE</th><th>EVENT</th><th>DESCRIPTION</th></tr>${l.related.slice(0, compact ? 0 : 60).map((e) => `<tr><td>${esc(e.time)}</td><td>${esc(e.tool)}</td><td>${esc(e.type)}</td><td>${esc(String(e.desc || '').slice(0, 300))}</td></tr>`).join('')}</table>` : '';
  return `<div class="fd lead ${l.sev}"><div class="hd"><span class="sev ${l.sev}">${SEV_SHORT[l.sev]}</span><span class="title"><span class="kind">${esc(l.kind.toUpperCase())}</span> ${esc(l.title)}</span><span class="when">${esc(l.category || '')}</span></div>
  <div class="bd"><div class="kv"><div>WHY</div><div>${esc(l.why)}</div><div>NEXT</div><div class="next">${esc(l.next)}</div>${mitre ? `<div>ATT&amp;CK</div><div class="mitre">${mitre}</div>` : ''}${ents ? `<div>PIVOT</div><div>${ents}</div>` : ''}</div>${l.evidence ? `<pre class="ev">${esc(l.evidence)}</pre>` : ''}${compact ? '' : rel}</div></div>`;
}
function bindLeads(root) {
  root.querySelectorAll('[data-pivot]').forEach((c) => c.addEventListener('click', (e) => { e.stopPropagation(); S.inv.q = c.dataset.pivot; switchTab('investigate'); }));
}
function investigateView(v) {
  const r = S.rep; const leads = r.leads || [];
  const q = S.inv.q.trim().toLowerCase();
  let pivot = '';
  if (q) {
    const hit = (s) => String(s || '').toLowerCase().includes(q);
    const fs = r.findings.filter((f) => hit(`${f.title} ${f.detail} ${f.evidence} ${f.file}`));
    const is = r.indicators.filter((i) => hit(`${i.value} ${i.context}`));
    const ts = r.timeline.filter((e) => hit(`${e.type} ${e.desc} ${e.file}`));
    const ls = leads.filter((l) => hit(`${l.title} ${l.evidence} ${(l.entities || []).join(' ')}`));
    const times = [...fs.map((f) => f.time), ...ts.map((e) => e.time)].filter(Boolean).sort();
    pivot = `<div class="box"><div class="ph"><span class="code">P</span> PIVOT: "${esc(S.inv.q)}" · ${ls.length} leads · ${fs.length} findings · ${is.length} indicators · ${ts.length} timeline events${times.length ? ` · ${esc(times[0])} to ${esc(times[times.length - 1])}` : ''}</div><div class="body">
      ${fs.length ? `<h4>FINDINGS</h4>${fs.slice(0, 100).map(findingRow).join('')}` : ''}
      ${is.length ? `<h4>INDICATORS</h4><div id="pind"></div>` : ''}
      ${ts.length ? `<h4>TIMELINE</h4><div id="ptl"></div>` : ''}
      ${!fs.length && !is.length && !ts.length ? '<span class="muted">No matches.</span>' : ''}</div></div>`;
    v.innerHTML = '';
    S._piv = { is, ts };
  }
  v.innerHTML = `<div class="toolbar"><input type="search" id="invq" placeholder="pivot on anything: file name, hash, user, IP, path, T1053…" value="${esc(S.inv.q)}" style="flex:1">
    ${S.inv.q ? '<button class="tog on" id="invclr">CLEAR</button>' : ''}<button class="tog on" id="lexp">EXPAND LEADS</button>
    <span class="count">${leads.length} leads</span></div>
    ${pivot}
    <div class="box"><div class="ph"><span class="code">L</span> LEADS: correlated across artifacts, things a single tool would not show</div><div class="body">${leads.length ? leads.map((l, i) => leadRow(l, i, false)).join('') : '<span class="muted">No correlated leads were built. That usually means there were no high or critical findings to anchor on, or the evidence covers only one artifact type.</span>'}</div></div>`;
  if (q && S._piv) {
    if (S._piv.is.length) table($('#pind'), ['TYPE', 'VALUE', 'COUNT', 'CONTEXT'], S._piv.is.map((i) => [indicatorLabel(i.type), i.value, i.count, i.context]), { name: 'pivot_indicators' });
    if (S._piv.ts.length) table($('#ptl'), ['TIME (UTC)', 'SOURCE', 'EVENT', 'DESCRIPTION', 'FILE'], S._piv.ts.map((e) => [e.time, e.tool, e.type, e.desc, e.file.split('/').pop()]), { name: 'pivot_timeline', pageSize: 200 });
  }
  const inp = $('#invq');
  inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') { S.inv.q = inp.value; investigateView(v); } });
  inp.addEventListener('input', debounce(() => { if (inp.value.length === 0 || inp.value.length >= 3) { S.inv.q = inp.value; investigateView(v); const n = $('#invq'); n.focus(); n.setSelectionRange(n.value.length, n.value.length); } }, 400));
  $('#invclr')?.addEventListener('click', () => { S.inv.q = ''; investigateView(v); });
  $('#lexp').addEventListener('click', () => { const open = !v.querySelector('.lead.open'); v.querySelectorAll('.lead').forEach((f) => f.classList.toggle('open', open)); });
  bindFindings(v); bindLeads(v);
}

// ---------------------------------------------------------------- INDICATORS
function indicatorsView(v) {
  const r = S.rep;
  const types = [...new Set(r.indicators.map((i) => i.type))];
  const list = r.indicators.filter((i) => (!S.ind.type || i.type === S.ind.type) && (!S.ind.q || `${i.value} ${i.context} ${i.sources.join(' ')}`.toLowerCase().includes(S.ind.q.toLowerCase())));
  const fmt = (i) => (S.ind.defang && /^(ipv4|domain|url|email)$/.test(i.type) ? defang(i.value) : i.value);
  v.innerHTML = `<div class="toolbar"><select id="itype"><option value="">ALL TYPES</option>${types.map((t) => `<option value="${esc(t)}" ${t === S.ind.type ? 'selected' : ''}>${esc(indicatorLabel(t))}</option>`).join('')}</select>
    <input type="search" id="iq" placeholder="filter indicators…" value="${esc(S.ind.q)}">
    <button class="tog ${S.ind.defang ? 'on' : ''}" id="idef">DEFANG</button>
    <button class="tog on" id="icopy">COPY VISIBLE VALUES</button>
    <span class="count">${list.length} indicators</span></div>
    <div id="itbl"></div>`;
  table($('#itbl'), ['TYPE', 'VALUE', 'COUNT', 'SOURCES', 'CONTEXT'], list.map((i) => [indicatorLabel(i.type), fmt(i), i.count, i.sources.slice(0, 4).join(' | ') + (i.sources.length > 4 ? ` (+${i.sources.length - 4})` : ''), i.context]), { name: 'indicators' });
  $('#itype').addEventListener('change', (e) => { S.ind.type = e.target.value; indicatorsView(v); });
  const q = $('#iq'); q.addEventListener('input', debounce(() => { S.ind.q = q.value; indicatorsView(v); $('#iq').focus(); }, 250));
  $('#idef').addEventListener('click', () => { S.ind.defang = !S.ind.defang; indicatorsView(v); });
  $('#icopy').addEventListener('click', (e) => { navigator.clipboard?.writeText(list.map(fmt).join('\n')); e.target.textContent = 'COPIED'; setTimeout(() => (e.target.textContent = 'COPY VISIBLE VALUES'), 1200); });
}

// ---------------------------------------------------------------- TIMELINE
function timelineView(v) {
  const r = S.rep;
  const tools = [...new Set(r.timeline.map((e) => e.tool))].sort();
  const list = r.timeline.filter((e) => (!S.tl.tool || e.tool === S.tl.tool) && (!S.tl.q || `${e.type} ${e.desc} ${e.file} ${e.time}`.toLowerCase().includes(S.tl.q.toLowerCase())));
  v.innerHTML = `<div class="toolbar"><select id="ttool"><option value="">ALL SOURCES</option>${tools.map((t) => `<option ${t === S.tl.tool ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select>
    <input type="search" id="tq" placeholder="filter: 2024-03-01, psexec, RDP, 4624…" value="${esc(S.tl.q)}">
    <span class="count">${list.length} events (super timeline, UTC)</span></div><div id="ttbl"></div>`;
  table($('#ttbl'), ['TIME (UTC)', 'SOURCE', 'EVENT', 'DESCRIPTION', 'FILE'], list.map((e) => [e.time, e.tool, e.type, e.desc, e.file.split('/').pop()]), { name: 'timeline', pageSize: 300 });
  $('#ttool').addEventListener('change', (e) => { S.tl.tool = e.target.value; timelineView(v); });
  const q = $('#tq'); q.addEventListener('input', debounce(() => { S.tl.q = q.value; timelineView(v); $('#tq').focus(); }, 300));
}

// ---------------------------------------------------------------- ARTIFACTS
function artifactsView(v) {
  const r = S.rep;
  const list = r.files.filter((f) => f.status !== 'rejected' && (!S.art.q || `${f.name} ${f.tool} ${f.artifact}`.toLowerCase().includes(S.art.q.toLowerCase())));
  v.innerHTML = `<div class="toolbar"><input type="search" id="aq" placeholder="filter by file, tool, artifact…" value="${esc(S.art.q)}"><span class="count">${list.length} artifacts</span></div>
  ${list.map((f, i) => `<div class="art" data-i="${r.files.indexOf(f)}"><div class="hd"><span class="st ${f.status}">${f.status.toUpperCase()}</span><span style="color:var(--amber)">${esc(f.tool)}</span><span class="nm" title="${esc(f.name)}">${esc(f.name)}</span><span class="sm">${esc(f.artifact)} · ${esc(f.summary)}</span></div><div class="bd"></div></div>`).join('')}`;
  v.querySelectorAll('.art > .hd').forEach((h) => h.addEventListener('click', () => {
    const a = h.parentElement; a.classList.toggle('open');
    const bd = a.querySelector('.bd'); if (bd.dataset.done) return; bd.dataset.done = 1;
    const f = r.files[+a.dataset.i];
    bd.innerHTML = `<div class="hashes">${f.hashes ? `MD5 <b>${f.hashes.md5}</b> · SHA1 <b>${f.hashes.sha1 || ''}</b> · SHA256 <b>${f.hashes.sha256 || ''}</b>` : ''} · ${fmtSize(f.size)} · ${f.ms} ms</div>${(f.notes || []).map((n) => `<div class="note">${esc(n)}</div>`).join('')}<div class="tbls"></div>`;
    const host = bd.querySelector('.tbls');
    f.tables.forEach((t, ti) => {
      const d = document.createElement('div');
      d.innerHTML = `<div class="subt"><span>▸ ${esc(t.title)}</span><span class="muted">${t.rows.length} rows</span><span class="x"><button data-csv>CSV</button></span></div>${t.note ? `<div class="tnote">${esc(t.note)}</div>` : ''}<div class="tb"></div>`;
      host.appendChild(d);
      d.querySelector('[data-csv]').addEventListener('click', () => download(csv(t.columns, t.rows), `${f.name.split('/').pop()}_${t.title.replace(/[^a-z0-9]+/gi, '_')}.csv`, 'text/csv'));
      if (t.rows.length) table(d.querySelector('.tb'), t.columns, t.rows, { pageSize: 100 });
      else d.querySelector('.tb').innerHTML = '<div class="muted">empty</div>';
    });
  }));
  const q = $('#aq'); q.addEventListener('input', debounce(() => { S.art.q = q.value; artifactsView(v); $('#aq').focus(); }, 250));
}

// ---------------------------------------------------------------- REJECTED
function rejectedView(v) {
  const r = S.rep;
  const rej = r.files.filter((f) => f.status === 'rejected');
  const part = r.files.filter((f) => f.status === 'partial' || f.status === 'error');
  v.innerHTML = `<div class="box"><div class="ph"><span class="code">R1</span> NOT ACCEPTED BY ANY EZ TOOL (${rej.length})</div><div class="body" id="rj"></div></div>
  <div class="box"><div class="ph"><span class="code">R2</span> PARTIAL / ERRORS (${part.length})</div><div class="body" id="pt"></div></div>
  <div class="box"><div class="ph"><span class="code">R3</span> WHAT CANNOT BE ACCEPTED, AND WHAT TO DO</div><div class="body"><table class="t"><tr><th>INPUT</th><th>HANDLING</th></tr>${NOT_ACCEPTED_HELP.map((x) => `<tr><td>${esc(x[0])}</td><td>${esc(x[1])}</td></tr>`).join('')}</table></div></div>`;
  if (rej.length) table($('#rj'), ['FILE', 'SIZE', 'REASON', 'FALLBACK'], rej.map((f) => [f.name, fmtSize(f.size || 0), f.reason, f.tables?.length ? 'hashed + bstrings' : f.hashes ? 'hashed' : 'none']), {}); else $('#rj').innerHTML = '<span class="muted">Every file was accepted by a parser.</span>';
  if (part.length) table($('#pt'), ['FILE', 'STATUS', 'TOOL', 'WHAT HAPPENED'], part.map((f) => [f.name, f.status, f.tool, [f.artifact, ...(f.notes || [])].join(' | ')]), {}); else $('#pt').innerHTML = '<span class="muted">None.</span>';
}

// ---------------------------------------------------------------- TOOLS
function toolsView() {
  const lbl = { full: 'IMPLEMENTED', partial: 'PARTIAL', strings: 'STRINGS ONLY', none: 'NOT IMPLEMENTED', 'n/a': 'GUI / N/A' };
  return `<div class="intent"><h2>INTENT: ONE CONSOLE TO RULE THEM ALL</h2>
  <p>Eric Zimmerman's tools are the standard for Windows artifact parsing, but each one handles a single artifact type and produces CSV that still has to be read, filtered and correlated by hand in Timeline Explorer. Sudo-Z collapses that workflow: drop a KAPE collection or a pile of artifacts, and every file is identified, routed to the right parser, normalised into one super timeline and graded by one detection engine.</p>
  <p>The goal is IOC spotting, not just parsing. The same path and command-line heuristics (LOLBins, user-writable execution paths, masquerading, offensive tool names, encoded PowerShell, download cradles, credential dumping, shadow copy deletion, log clearing) run against Prefetch, Amcache, ShimCache, BAM, UserAssist, services, Run keys, scheduled tasks, LNKs, jump lists, $MFT, browser history and every event log. When two independent artifacts agree that a suspicious binary ran, Sudo-Z raises a correlation finding.</p>
  <p class="muted">Sudo-Z runs as a static GitHub Pages site. The original tools are Windows .NET executables and cannot run in a browser, so each parser here is an independent JavaScript implementation of the same file formats. Use the original tools to validate anything that goes in a legal or HR report.</p></div>
  <div class="intent"><h2>WEBSITE vs HOME INSTALL</h2><p>The GitHub Pages site runs everything Sudo-Z rebuilt in JavaScript. The home install (one command, see README) adds a local server that can also run programs a browser cannot: <b>Volatility 3</b> on memory images and the <b>original Eric Zimmerman tools</b> on an artifact folder. Each tool below lists where it is available.</p></div>
  ${CATALOG.map((c) => { const [pg, hm] = availability(c); return `<div class="tool"><div class="tn"><b>${esc(c.tool)}</b><span class="st ${c.status === 'n/a' ? 'na' : c.status}">${lbl[c.status]}</span></div><div class="acc">ACCEPTS: ${esc(c.accepts)}</div><div class="acc"><span style="color:var(--fg)">PAGES:</span> ${esc(pg)} &nbsp;·&nbsp; <span style="color:var(--amber)">HOME:</span> ${esc(hm)}</div><p>${esc(c.what)}</p><p class="sz">${esc(c.sudoz)}</p></div>`; }).join('')}`;
}

// ---------------------------------------------------------------- generic paginated table
function table(host, cols, rows, { pageSize = 200, name } = {}) {
  let page = 0;
  const timeIdx = cols.map((c, i) => (isTimeCol(c) ? i : -1)).filter((i) => i >= 0);
  const draw = () => {
    const pages = Math.max(1, Math.ceil(rows.length / pageSize));
    const slice = rows.slice(page * pageSize, page * pageSize + pageSize);
    host.innerHTML = `<table class="t"><thead><tr>${cols.map((c) => `<th>${esc(String(c).toUpperCase())}</th>`).join('')}</tr></thead><tbody>${slice.map((r) => `<tr>${r.map((c, i) => {
      if (cols[i] === 'Severity' || cols[i] === 'SEVERITY') return `<td class="nw"><span class="sev ${esc(c)}">${esc(SEV_SHORT[c] || c)}</span></td>`;
      return `<td class="${timeIdx.includes(i) && typeof c === 'string' && /^\d{4}-\d\d-\d\d/.test(c) ? 'time' : typeof c === 'number' ? 'num' : ''}">${esc(c)}</td>`;
    }).join('')}</tr>`).join('')}</tbody></table>${pages > 1 ? `<div class="pager"><button data-p="-1" ${page === 0 ? 'disabled' : ''}>◂ PREV</button><span>page ${page + 1} / ${pages} · ${rows.length} rows</span><button data-p="1" ${page >= pages - 1 ? 'disabled' : ''}>NEXT ▸</button></div>` : ''}`;
    host.querySelectorAll('[data-p]').forEach((b) => b.addEventListener('click', () => { page += +b.dataset.p; draw(); }));
  };
  draw();
}
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

render();

// ---------------------------------------------------------------- home install: local engine (Volatility 3, original EZ tools)
const LOCAL = { caps: null, mine: new Set(), loaded: new Set(), auto: true, flash: '', timer: 0 };
const api = async (path, body) => {
  const r = await fetch(path, { method: body ? 'POST' : 'GET', headers: { 'X-Sudo-Z': '1', ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  if (!r.ok || j.error) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
};
async function initLocal() {
  const host = $('#local');
  try {
    if (!/^(localhost|127\.0\.0\.1|\[::1\])$/.test(location.hostname)) throw new Error('hosted');
    LOCAL.caps = await api('/api/caps');
  } catch {
    host.innerHTML = `<div class="localbox"><div class="ph"><span class="code">00B</span> HOME-ONLY TOOLS</div><div class="lb hint">Memory analysis with <b style="color:var(--amber)">Volatility 3</b> and running the <b style="color:var(--amber)">original EZ tools</b> need the home install, because a browser cannot run Python or Windows programs. Install with one command (see README), run <code>sudo-z setup</code>, then <code>sudo-z</code>.<br><br>Here you can still drop Volatility 3 JSON output (<code>vol -r json ... &gt; windows.pslist.json</code>).<br><br><b style="color:var(--amber)">Disk images</b> (E01, VHD, VHDX, raw/dd, QCOW2) work here too: drop them in and the triage files are pulled out of each NTFS volume without uploading or loading the whole image. Running <b style="color:var(--amber)">KAPE</b> itself needs the home install on Windows.</div></div>`;
    return;
  }
  $('#mode').textContent = 'HOME ENGINE'; $('#mode').classList.add('home');
  renderLocal();
}
const KAPE_DEFAULT_TARGETS = ['!SANS_Triage', 'KapeTriage', '!BasicCollection', 'EventLogs', 'RegistryHives', 'FileSystem'];
function renderLocal() {
  const c = LOCAL.caps; const v = c.vol3; const ez = c.ez; const k = c.kape || { windows: false };
  const targets = [...new Set([...KAPE_DEFAULT_TARGETS, ...(k.targets || [])])];
  const kOk = k.windows && k.available;
  $('#local').innerHTML = `<div class="localbox"><div class="ph"><span class="code">00B</span> LOCAL ENGINE</div><div class="lb">
    <div class="cap"><span>Volatility 3</span><span class="${v.available ? 'ok' : 'no'}">${v.available ? 'v' + esc(v.version) : 'not installed'}</span></div>
    <div class="cap"><span>Original EZ tools</span><span class="${ez.tools.length ? 'ok' : 'no'}">${ez.tools.length ? ez.tools.length + ' found' : 'not installed'}</span></div>
    <div class="cap"><span>KAPE</span><span class="${kOk ? 'ok' : 'no'}">${!k.windows ? 'Windows only' : k.available ? (k.admin ? 'ready (admin)' : 'ready (asks for admin)') : 'not found'}</span></div>
    <div class="cap"><span>Disk images</span><span class="ok">E01 VHD VHDX raw QCOW2</span></div>

    <div class="sec">DISK IMAGE</div>
    <input type="text" id="imgPath" placeholder="image path, e.g. D:\\case\\disk.E01">
    <button class="btn" id="runImg">ANALYSE IMAGE</button>
    <div class="hint">Read in place, never copied. Pulls the KAPE-style triage set out of every NTFS volume. E01 segments next to it are picked up.</div>

    <div class="sec">KAPE COLLECTION</div>
    <input type="text" id="kapeSrc" placeholder="C:  or  E:\\mounted  or  D:\\case\\disk.vhdx" ${kOk ? '' : 'disabled'}>
    <select id="kapeTarget" ${kOk ? '' : 'disabled'}>${targets.map((t) => `<option>${esc(t)}</option>`).join('')}</select>
    <label class="chk"><input type="checkbox" id="kapeMod" ${kOk ? '' : 'disabled'}> also run !EZParser modules (CSV for Timeline Explorer)</label>
    <label class="chk"><input type="checkbox" id="kapeVss" ${kOk ? '' : 'disabled'}> include volume shadow copies</label>
    <button class="btn" id="runKape" ${kOk ? '' : 'disabled'}>RUN KAPE</button>
    <div class="hint">${!k.windows ? 'KAPE runs on Windows. Here, use ANALYSE IMAGE, or drop KAPE output collected elsewhere.' : k.available ? 'Runs in the background. VHD/VHDX are mounted read-only first. Results load into the console when it finishes.' : `Download KAPE from Kroll (free, registration required) and unzip it to <code>${esc(c.runs.replace(/runs$/, 'kape'))}</code> or <code>C:\\KAPE</code>, then <a href="#" id="rescan">RESCAN</a>.`}</div>

    <div class="sec">MEMORY IMAGE</div>
    <input type="text" id="memPath" placeholder="memory image path, e.g. D:\\case\\mem.raw" ${v.available ? '' : 'disabled'}>
    <button class="btn" id="runVol" ${v.available ? '' : 'disabled'}>RUN VOLATILITY 3</button>
    ${v.available ? '' : '<div class="hint">Install: <code>sudo-z setup vol</code>, then restart sudo-z.</div>'}

    <div class="sec">ORIGINAL EZ TOOLS</div>
    <input type="text" id="ezPath" placeholder="artifact folder (KAPE / Velociraptor output)" ${ez.tools.length ? '' : 'disabled'}>
    <button class="btn" id="runEz" ${ez.tools.length ? '' : 'disabled'}>RUN ORIGINAL EZ TOOLS</button>
    ${ez.tools.length ? '' : `<div class="hint">Install: <code>sudo-z setup ez</code>${c.os === 'Windows' ? '' : ' (needs pwsh + .NET 10 off Windows)'}.</div>`}

    <div class="sec">BACKGROUND JOBS <label class="chk" style="float:right;margin:0"><input type="checkbox" id="autoLoad" ${LOCAL.auto ? 'checked' : ''}> auto-load</label></div>
    <div class="jobs" id="jobs"><div class="muted">No jobs yet.</div></div>
    <div class="hint">Jobs keep running if you close this tab. Outputs: ${esc(c.runs)}</div>
  </div></div>`;
  $('#runImg').addEventListener('click', () => analyseImagePath($('#imgPath').value));
  $('#runKape')?.addEventListener('click', () => startJob('kape', { source: $('#kapeSrc').value, target: $('#kapeTarget').value, modules: $('#kapeMod').checked, vss: $('#kapeVss').checked }));
  $('#runVol')?.addEventListener('click', () => startJob('vol3', { image: $('#memPath').value }));
  $('#runEz')?.addEventListener('click', () => startJob('ez', { path: $('#ezPath').value }));
  $('#autoLoad').addEventListener('change', (e) => { LOCAL.auto = e.target.checked; });
  $('#rescan')?.addEventListener('click', async (e) => { e.preventDefault(); LOCAL.caps = await api('/api/rescan', {}); renderLocal(); });
  pollJobs();
}

const ENDPOINT = { vol3: '/api/vol3/run', ez: '/api/ez/run', kape: '/api/kape/run' };
async function startJob(kind, body) {
  try { const j = await api(ENDPOINT[kind], body); LOCAL.mine.add(j.id); LOCAL.flash = ''; }
  catch (e) { LOCAL.flash = e.message; }
  pollJobs();
}

/** Disk image by path: read in place through the local server, analysed in the worker like a dropped file. */
async function analyseImagePath(path) {
  path = path.trim().replace(/^"|"$/g, '');
  if (!path) return;
  try {
    const st = await api(`/api/image/stat?path=${encodeURIComponent(path)}`);
    stage(st.segments.map((g) => ({ name: g.name, size: g.size, http: { path: g.path, size: g.size } })));
    LOCAL.flash = `${st.segments.length} image segment(s) staged`;
    pollJobs();
    $('#run').click();
  } catch (e) { LOCAL.flash = e.message; pollJobs(); }
}

const ago = (t) => { const s = Math.max(0, Math.round(Date.now() / 1000 - t)); return s < 90 ? s + 's' : s < 5400 ? Math.round(s / 60) + 'm' : Math.round(s / 3600) + 'h'; };
async function pollJobs() {
  clearTimeout(LOCAL.timer);
  const el = $('#jobs'); if (!el) return;
  let jobs = [];
  try { jobs = await api('/api/jobs'); } catch (e) { el.innerHTML = `<div class="bad">${esc(e.message)}</div>`; return; }
  el.innerHTML = (LOCAL.flash ? `<div class="flash">${esc(LOCAL.flash)}</div>` : '') + (jobs.length ? jobs.slice(0, 12).map((j) => {
    const src = String(j.source || '').split(/[\\/]/).filter(Boolean).pop() || j.source || '';
    const st = j.status === 'running' ? 'RUN' : j.status === 'done' ? 'DONE' : 'FAIL';
    const pct = j.total ? Math.round((j.done / j.total) * 100) : null;
    const loadable = j.status === 'done' && (j.kind === 'vol3' || j.kind === 'kape' || j.kind === 'ez');
    return `<div class="jb ${j.status}"><div class="r"><span><b>${esc(j.kind.toUpperCase())}</b> ${esc(src)}</span><span class="st">${st}${j.status === 'running' && pct != null ? ' ' + pct + '%' : ''} · ${ago(j.started)}</span></div>
      ${j.status === 'running' ? `<div class="bar"><span style="width:${pct ?? 30}%" class="${pct == null ? 'ind' : ''}"></span></div><div class="cur">${esc(j.current || '')}</div>` : ''}
      ${j.error ? `<div class="bad">${esc(j.error)}</div>` : ''}
      ${j.status !== 'running' ? `<div class="acts">${loadable ? `<button class="tog on" data-load="${j.id}">${LOCAL.loaded.has(j.id) ? 'RELOAD' : 'LOAD'} INTO CONSOLE</button>` : ''}<button class="tog" data-open="${j.id}">OPEN FOLDER</button></div>` : ''}</div>`;
  }).join('') : '<div class="muted">No jobs yet.</div>');
  el.querySelectorAll('[data-load]').forEach((b) => b.addEventListener('click', () => loadJob(b.dataset.load)));
  el.querySelectorAll('[data-open]').forEach((b) => b.addEventListener('click', () => api('/api/open', { job: b.dataset.open }).catch((e) => { LOCAL.flash = e.message; pollJobs(); })));
  // auto-load jobs started from this page when they finish
  for (const j of jobs) if (LOCAL.auto && LOCAL.mine.has(j.id) && j.status === 'done' && !LOCAL.loaded.has(j.id) && (j.kind === 'vol3' || j.kind === 'kape' || j.kind === 'ez')) loadJob(j.id);
  if (jobs.some((j) => j.status === 'running')) LOCAL.timer = setTimeout(pollJobs, 1500);
}

/** Pull a finished job's outputs into the staging list and run the analysis. */
async function loadJob(id) {
  if (LOCAL.loading) return; LOCAL.loading = true; LOCAL.loaded.add(id);
  try {
    const job = await api(`/api/job/${id}`);
    const files = []; let skipped = 0;
    // EZ runner and KAPE !EZParser output: the CSVs Timeline Explorer would open
    const list = job.kind === 'ez' ? job.results.flatMap((r) => (r.files || []).filter((x) => /\.csv$/i.test(x)).map((file) => ({ file, csv: true })))
      : [...job.results, ...(job.modules || []).map((file) => ({ file, csv: true }))];
    for (const r of list) {
      if (!r.file) continue;
      if (r.size > 1.5 * 1024 ** 3) { skipped++; continue; }
      LOCAL.flash = `loading ${job.kind} output ${files.length + 1}/${list.length}`; $('#jobs .flash') && ($('#jobs .flash').textContent = LOCAL.flash);
      const res = await fetch(`/api/job/${id}/file/${r.file.split('/').map(encodeURIComponent).join('/')}`, { headers: { 'X-Sudo-Z': '1' } });
      if (!res.ok) continue;
      const blob = await res.blob(); if (blob.size <= 4) continue;
      const name = job.kind === 'vol3' ? `memory/${r.file}` : r.csv ? `ezcsv/${r.file.replace(/^mout\//, '')}` : `kape/${r.file.replace(/^tout\//, '')}`;
      files.push({ file: new File([blob], name.split('/').pop()), name });
    }
    LOCAL.flash = `${files.length} file(s) from ${job.kind} staged${skipped ? `, ${skipped} over 1.5 GB skipped` : ''}`;
    stage(files);
    if (files.length && !$('#run').disabled) $('#run').click();
  } catch (e) { LOCAL.flash = e.message; }
  LOCAL.loading = false;
  pollJobs();
}
initLocal();
