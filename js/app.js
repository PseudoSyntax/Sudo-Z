// Sudo-Z UI controller.
import { CATALOG, NOT_ACCEPTED_HELP } from './catalog.js';
import { markdown, csv, timelineCsv, findingsCsv, indicatorsCsv, mitreSummary, indicatorLabel, defang } from './report.js';

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

const S = { staged: [], rep: null, tab: 'sitrep', f: { sev: new Set(['critical', 'high', 'medium', 'low', 'info']), q: '', cat: '' }, tl: { q: '', tool: '', page: 0 }, ind: { q: '', type: '', defang: true }, art: { q: '' } };

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
  for (const x of list) if (!S.staged.some((s) => s.name === x.name && s.file.size === x.file.size)) S.staged.push(x);
  renderStaged();
}
function renderStaged() {
  const el = $('#staged');
  if (!S.staged.length) el.innerHTML = '<div class="muted">No files staged.</div>';
  else {
    const tot = S.staged.reduce((n, s) => n + s.file.size, 0);
    el.innerHTML = S.staged.map((s) => `<div class="f"><span title="${esc(s.name)}">${esc(s.name)}</span><span>${fmtSize(s.file.size)}</span></div>`).join('') + `<div class="f" style="border-top:1px solid var(--line);margin-top:4px;padding-top:2px"><span class="muted">${S.staged.length} file(s)</span><span>${fmtSize(tot)}</span></div>`;
  }
  $('#run').disabled = !S.staged.length; $('#clear').disabled = !S.staged.length;
}
$('#clear').addEventListener('click', () => { S.staged = []; renderStaged(); });

$('#run').addEventListener('click', async () => {
  const btn = $('#run'); btn.disabled = true; $('#clear').disabled = true;
  $('#progress').hidden = false; setProg(0, 'reading files');
  const files = [];
  for (const s of S.staged) files.push({ name: s.name, buf: await s.file.arrayBuffer() });
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
    worker.postMessage({ files }, files.map((f) => f.buf));
  } else await mainThread(files, done);
});
async function mainThread(files, done) {
  const { analyze } = await import('./engine.js');
  try { done(await analyze(files.map((f) => ({ name: f.name, data: new Uint8Array(f.buf) })), { onProgress: setProg })); }
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
  $('#n-findings').textContent = r.findings.length; $('#n-ind').textContent = r.indicators.length; $('#n-tl').textContent = r.timeline.length;
  $('#n-art').textContent = r.files.filter((f) => f.status !== 'rejected').length; $('#n-rej').textContent = r.files.filter((f) => f.status === 'rejected' || f.status === 'partial').length;
  $('#exports').hidden = false;
  S.tab = 'sitrep'; [...$('#tabs').querySelectorAll('button[data-tab]')].forEach((x) => x.classList.toggle('on', x.dataset.tab === 'sitrep'));
  render();
}

function render() {
  const v = $('#view');
  if (S.tab === 'tools') return (v.innerHTML = toolsView());
  if (!S.rep) return (v.innerHTML = idleView());
  ({ sitrep: sitrepView, findings: findingsView, indicators: indicatorsView, timeline: timelineView, artifacts: artifactsView, rejected: rejectedView })[S.tab](v);
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
      <div class="box"><div class="ph"><span class="code">E</span> PRIORITY FINDINGS</div><div class="body">${top.length ? top.map(findingRow).join('') : '<span class="muted">No high or critical findings.</span>'}</div></div>
      <div class="box"><div class="ph"><span class="code">F</span> COVERAGE</div><div class="body">${coverage(r)}</div></div>
    </div>
  </div>`;
  v.querySelectorAll('.kpi').forEach((k) => k.addEventListener('click', () => { S.f.sev = new Set([k.dataset.sev]); switchTab('findings'); }));
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
  <div class="bd"><div class="kv"><div>CATEGORY</div><div>${esc(f.category)}</div><div>TOOL</div><div>${esc(f.tool)}</div><div>SOURCE</div><div>${esc(f.file)}</div>${f.detail ? `<div>WHY</div><div>${esc(f.detail)}</div>` : ''}${mitre ? `<div>ATT&amp;CK</div><div class="mitre">${mitre}</div>` : ''}</div>${f.evidence ? `<pre class="ev">${esc(f.evidence)}</pre>` : ''}</div></div>`;
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
  ${CATALOG.map((c) => `<div class="tool"><div class="tn"><b>${esc(c.tool)}</b><span class="st ${c.status === 'n/a' ? 'na' : c.status}">${lbl[c.status]}</span></div><div class="acc">ACCEPTS: ${esc(c.accepts)}</div><p>${esc(c.what)}</p><p class="sz">${esc(c.sudoz)}</p></div>`).join('')}`;
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
