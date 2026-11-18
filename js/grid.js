import { macbRows } from './ioc/macb.js';
// GRID: a Timeline Explorer style data grid over any table in the report.
// Virtual scrolling (100k+ rows), click-to-sort, per-column filters
// (text, !not, =exact, >n, <n, /regex/), global search, group by column,
// row tagging, column chooser, resizable columns, detail pane, CSV export.

const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const ROW_H = 22;
const SEVS = ['critical', 'high', 'medium', 'low', 'info'];

/** Datasets the grid can open, from a report. */
/** Every "All MFT entries" table in the report (native $MFT and MFTECmd CSV). */
export const mftAllTables = (rep) => rep.files.flatMap((f) => (f.tables || []).filter((t) => t.title === 'All MFT entries' && t.columns.length >= 17 && t.rows?.length));

export function datasets(rep, programColumns) {
  const ds = [];
  if (rep.programs?.length) ds.push({ id: 'programs', group: 'Overview', label: `Programs (${rep.programs.length})`, cols: programColumns.map((c) => c[1]), rows: () => rep.programs.map((p) => programColumns.map((c) => p[c[0]] ?? '')), sevCol: 1, keyCols: [2, 5] });
  if (rep.execution?.coverage?.length) ds.push({ id: 'execcov', group: 'Overview', label: 'Execution evidence coverage (5 artifacts)', cols: ['Artifact', 'Status', 'Files', 'Entries', 'First', 'Last', 'Users', 'Expected file', 'KAPE target', 'Proves', 'Limits', 'Note'], rows: () => rep.execution.coverage.map((c) => [c.artifact, c.state, c.files, c.entries, c.first, c.last, c.users, c.expected, c.kape, c.proves, c.limits, c.note]) });
  ds.push({ id: 'findings', group: 'Overview', label: `Findings (${rep.findings.length})`, cols: ['Severity', 'Time', 'Category', 'Title', 'Tool', 'Source', 'ATT&CK', 'Next', 'Evidence'], rows: () => rep.findings.map((f) => [f.sev, f.time || '', f.category, f.title, f.tool, f.file, (f.mitre || []).join(' '), f.next || '', f.evidence || '']), sevCol: 0 });
  ds.push({ id: 'timeline', group: 'Overview', label: `Super timeline (${rep.timeline.length})`, cols: ['Time (UTC)', 'Source', 'Event', 'Description', 'File'], rows: () => rep.timeline.map((e) => [e.time, e.tool, e.type, e.desc, e.file]) });
  ds.push({ id: 'indicators', group: 'Overview', label: `Indicators (${rep.indicators.length})`, cols: ['Type', 'Value', 'Count', 'Sources', 'Context'], rows: () => rep.indicators.map((i) => [i.type, i.value, i.count, i.sources.join(' | '), i.context || '']) });
  if (rep.leads?.length) ds.push({ id: 'leads', group: 'Overview', label: `Leads (${rep.leads.length})`, cols: ['Severity', 'Kind', 'Title', 'Why', 'Next', 'Evidence'], rows: () => rep.leads.map((l) => [l.sev, l.kind, l.title, l.why, l.next, l.evidence || '']), sevCol: 0 });
  const m = rep.macb;
  if (m) {
    if (m.anomalies?.length) ds.push({ id: 'macb-anom', group: 'MACB (file times)', label: `MACB anomalies (${m.anomalies.length})`, cols: ['Severity', 'Rule', 'Path', 'Detail', '$SI B', '$SI M', '$SI A', '$SI C', '$FN B', 'Entry', 'Content B', 'Content M', 'Source'], rows: () => m.anomalies.map((a) => [a.sev, a.title, a.path, a.detail, a.siB || '', a.siM || '', a.siA || '', a.siC || '', a.fnB || '', a.entry || '', a.embB || '', a.embM || '', a.source || '']), sevCol: 0, keyCols: [2] });
    if (m.embedded?.length) ds.push({ id: 'macb-emb', group: 'MACB (file times)', label: `File times from content and other artifacts (${m.embedded.length})`, cols: ['Path', 'Source', 'Kind', 'B (born/created)', 'M (modified/saved)', 'A (accessed)', 'Other', 'Author', 'Last saved by', 'Application', 'FS source', 'FS B', 'FS M', 'FS entry', 'Recorded entry', 'Verdict', 'File'], rows: () => m.embedded.map((e) => [e.path, e.source, e.kind, e.B, e.M, e.A, e.other, e.author, e.lastBy, e.app, e.fsSource, e.fsB, e.fsM, e.fsEntry, e.recEntry, e.verdict, e.file]), keyCols: [0] });
    if (m.clusters?.length) ds.push({ id: 'macb-burst', group: 'MACB (file times)', label: `Bursts: many files born or modified in one minute (${m.clusters.length})`, cols: ['Kind', 'Minute (UTC)', 'Files', 'Executables', 'Folders', 'Top folder', 'Top extension', 'In attack window'], rows: () => m.clusters.map((c) => [c.kind, c.minute, c.files, c.executables, c.folders, c.topFolder, c.topExt, c.inWindow ? 'Yes' : '']) });
  }
  const mftTables = mftAllTables(rep);
  if (mftTables.length) {
    const n = mftTables.reduce((k, t) => k + t.rows.length, 0);
    ds.push({ id: 'macb-tl', group: 'MACB (file times)', label: `MACB timeline, mactime style ($SI + $FN, ${n} records)`, cols: ['Time (UTC)', 'MACB', 'Attr', 'Size', 'Entry-Seq', 'InUse', 'Type', 'Path'], rows: () => { const all = []; for (const t of mftTables) all.push(...macbRows(t).rows); all.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)); return all.slice(0, 2000000); } });
  }
  rep.files.forEach((f, fi) => (f.tables || []).forEach((t, ti) => {
    if (!t.rows?.length) return;
    const csv = /CSV/.test(f.artifact || '') || /CSV/.test(t.title);
    ds.push({ id: `t:${fi}:${ti}`, group: csv ? 'Tool CSVs (Timeline Explorer)' : 'Artifact tables', label: `${f.name.split('/').pop()} › ${t.title} (${t.rows.length})`, cols: t.columns, rows: () => t.rows, sevCol: t.columns.findIndex((c) => /^severity$/i.test(c)) });
  }));
  return ds;
}

const cellText = (v) => (v == null ? '' : v instanceof Uint8Array ? Array.from(v.subarray(0, 32), (b) => b.toString(16).padStart(2, '0')).join(' ') : Array.isArray(v) ? v.join(' | ') : String(v));
const num = (s) => (s !== '' && !isNaN(+s) ? +s : null);

function matcher(expr) {
  expr = expr.trim(); if (!expr) return null;
  if (/^\/.+\/[a-z]*$/i.test(expr)) { try { const m = expr.match(/^\/(.+)\/([a-z]*)$/i); const rx = new RegExp(m[1], m[2] || 'i'); return (s) => rx.test(s); } catch { return null; } }
  if (expr[0] === '!') { const x = expr.slice(1).toLowerCase(); return (s) => !s.toLowerCase().includes(x); }
  if (expr[0] === '=') { const x = expr.slice(1).toLowerCase(); return (s) => s.toLowerCase() === x; }
  if (/^[<>]=?/.test(expr)) {
    const op = expr.match(/^[<>]=?/)[0]; const x = expr.slice(op.length).trim(); const xn = num(x);
    const cmp = (s) => { const sn = num(s); return xn != null && sn != null ? sn - xn : s.localeCompare(x); };
    return op === '>' ? (s) => s !== '' && cmp(s) > 0 : op === '>=' ? (s) => s !== '' && cmp(s) >= 0 : op === '<' ? (s) => s !== '' && cmp(s) < 0 : (s) => s !== '' && cmp(s) <= 0;
  }
  const x = expr.toLowerCase(); return (s) => s.toLowerCase().includes(x);
}

export class Grid {
  constructor(host, state, { onPivot } = {}) { this.host = host; this.S = state; this.onPivot = onPivot; }

  open(ds) {
    const S = this.S;
    if (S.ds !== ds.id) { Object.assign(S, { ds: ds.id, q: '', filters: {}, sort: null, group: -1, hidden: new Set(), collapsed: new Set(), sel: null, tagOnly: false }); }
    S.tags = S.tagsBy[ds.id] || (S.tagsBy[ds.id] = new Set());
    this.ds = ds;
    this.data = ds.rows().map((r) => r.map(cellText));
    this.cols = ds.cols.map(String);
    this.widths = S.widthsBy[ds.id] || (S.widthsBy[ds.id] = this.cols.map((c, i) => {
      let w = c.length * 8 + 26;
      for (let k = 0; k < Math.min(this.data.length, 200); k++) w = Math.max(w, Math.min(420, (this.data[k][i] || '').length * 7 + 16));
      return Math.max(60, Math.min(w, 420));
    }));
    this.joined = null;
    this.compute(); this.draw();
  }

  compute() {
    const S = this.S; const d = this.data;
    let idx = d.map((_, i) => i);
    if (S.q) { const m = matcher(S.q); if (!this.joined) this.joined = d.map((r) => r.join('\u0001')); if (m) idx = idx.filter((i) => m(this.joined[i])); }
    for (const [c, e] of Object.entries(S.filters)) { const m = matcher(e); if (m) idx = idx.filter((i) => m(d[i][c] || '')); }
    if (S.tagOnly) idx = idx.filter((i) => S.tags.has(i));
    if (S.sort) {
      const { col, dir } = S.sort;
      idx.sort((a, b) => { const x = d[a][col], y = d[b][col]; const xn = num(x), yn = num(y); const r = xn != null && yn != null ? xn - yn : x.localeCompare(y); return r * dir; });
    }
    this.view = [];
    if (S.group >= 0) {
      const groups = new Map();
      for (const i of idx) { const k = d[i][S.group] || '(blank)'; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(i); }
      const keys = [...groups.keys()].sort((a, b) => groups.get(b).length - groups.get(a).length || a.localeCompare(b));
      for (const k of keys) { const list = groups.get(k); this.view.push({ g: k, n: list.length }); if (!S.collapsed.has(k)) for (const i of list) this.view.push(i); }
    } else this.view = idx;
    this.count = idx.length;
  }

  visibleCols() { return this.cols.map((c, i) => i).filter((i) => !this.S.hidden.has(i)); }

  draw() {
    const S = this.S; const vc = this.visibleCols(); const W = 26 + vc.reduce((n, i) => n + this.widths[i], 0);
    const sevCol = this.ds.sevCol;
    this.host.innerHTML = `
      <div class="g-top">
        <input type="search" class="g-q" placeholder="search all columns (text, !not, =exact, >n, /regex/)" value="${esc(S.q)}">
        <select class="g-group"><option value="-1">GROUP BY: none</option>${this.cols.map((c, i) => `<option value="${i}" ${S.group === i ? 'selected' : ''}>GROUP BY: ${esc(c)}</option>`).join('')}</select>
        <button class="tog ${S.tagOnly ? 'on' : ''}" data-act="tagonly" title="show tagged rows only">TAGGED ${S.tags.size}</button>
        <button class="tog" data-act="cols">COLUMNS</button>
        <button class="tog" data-act="clear">CLEAR FILTERS</button>
        <button class="tog" data-act="export">EXPORT VIEW</button>
        <span class="count">${this.count.toLocaleString()} of ${this.data.length.toLocaleString()} rows</span>
      </div>
      <div class="g-colmenu" hidden>${this.cols.map((c, i) => `<label><input type="checkbox" data-col="${i}" ${S.hidden.has(i) ? '' : 'checked'}> ${esc(c)}</label>`).join('')}</div>
      <div class="g-wrap">
        <div class="g-scroll">
          <div class="g-head" style="width:${W}px"><div class="g-c g-tag">#</div>${vc.map((i) => `<div class="g-c" style="width:${this.widths[i]}px" data-sort="${i}">${esc(this.cols[i])}${S.sort?.col === i ? (S.sort.dir > 0 ? ' ▲' : ' ▼') : ''}<span class="g-rs" data-rs="${i}"></span></div>`).join('')}</div>
          <div class="g-filt" style="width:${W}px"><div class="g-c g-tag"></div>${vc.map((i) => `<div class="g-c" style="width:${this.widths[i]}px"><input data-f="${i}" value="${esc(S.filters[i] || '')}" placeholder="filter"></div>`).join('')}</div>
          <div class="g-body" style="height:${this.view.length * ROW_H}px;width:${W}px"></div>
        </div>
        <div class="g-detail" ${S.sel == null ? 'hidden' : ''}></div>
      </div>`;
    const scroll = this.host.querySelector('.g-scroll'); const body = this.host.querySelector('.g-body');
    const paint = () => {
      const top = Math.max(0, scroll.scrollTop - 60); const first = Math.max(0, Math.floor(top / ROW_H) - 10); const last = Math.min(this.view.length, first + Math.ceil(scroll.clientHeight / ROW_H) + 30);
      let h = '';
      for (let k = first; k < last; k++) {
        const v = this.view[k];
        if (typeof v === 'object') { h += `<div class="g-r g-grp" style="top:${k * ROW_H}px;width:${W}px" data-grp="${esc(v.g)}">${S.collapsed.has(v.g) ? '▸' : '▾'} ${esc(this.cols[S.group])}: <b>${esc(v.g)}</b> <span>(${v.n})</span></div>`; continue; }
        const r = this.data[v]; const sev = sevCol >= 0 ? (r[sevCol] || '').toLowerCase() : '';
        h += `<div class="g-r ${SEVS.includes(sev) ? 'sv-' + sev : ''} ${S.sel === v ? 'sel' : ''} ${S.tags.has(v) ? 'tagged' : ''}" style="top:${k * ROW_H}px;width:${W}px" data-row="${v}"><div class="g-c g-tag" data-tag="${v}">${S.tags.has(v) ? '■' : '□'}</div>${vc.map((i) => `<div class="g-c" style="width:${this.widths[i]}px" title="${esc(r[i].slice(0, 600))}">${i === sevCol && sev ? `<span class="sev ${esc(sev)}">${({ critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW', info: 'INFO' })[sev]}</span>` : esc(r[i].slice(0, 400))}</div>`).join('')}</div>`;
      }
      body.innerHTML = h;
    };
    scroll.addEventListener('scroll', () => { requestAnimationFrame(paint); });
    paint();
    if (S.sel != null) this.detail();
    // events
    const q = this.host.querySelector('.g-q');
    q.addEventListener('input', deb(() => { S.q = q.value; this.compute(); this.redraw('.g-q'); }, 250));
    this.host.querySelector('.g-group').addEventListener('change', (e) => { S.group = +e.target.value; S.collapsed = new Set(); this.compute(); this.draw(); });
    this.host.querySelectorAll('[data-f]').forEach((inp) => inp.addEventListener('input', deb(() => { const c = +inp.dataset.f; if (inp.value) S.filters[c] = inp.value; else delete S.filters[c]; this.compute(); this.redraw(`[data-f="${c}"]`); }, 250)));
    this.host.querySelectorAll('[data-sort]').forEach((h) => h.addEventListener('click', (e) => { if (e.target.dataset.rs) return; const c = +h.dataset.sort; S.sort = S.sort?.col === c ? (S.sort.dir > 0 ? { col: c, dir: -1 } : null) : { col: c, dir: 1 }; this.compute(); this.draw(); }));
    this.host.querySelectorAll('[data-rs]').forEach((h) => h.addEventListener('mousedown', (e) => {
      e.preventDefault(); e.stopPropagation(); const c = +h.dataset.rs; const x0 = e.clientX; const w0 = this.widths[c];
      const mv = (ev) => { this.widths[c] = Math.max(40, w0 + ev.clientX - x0); }; const up = () => { removeEventListener('mousemove', mv); removeEventListener('mouseup', up); this.draw(); };
      addEventListener('mousemove', mv); addEventListener('mouseup', up);
    }));
    body.addEventListener('click', (e) => {
      const tag = e.target.closest('[data-tag]'); if (tag) { const i = +tag.dataset.tag; S.tags.has(i) ? S.tags.delete(i) : S.tags.add(i); this.host.querySelector('[data-act="tagonly"]').textContent = `TAGGED ${S.tags.size}`; paint(); return; }
      const g = e.target.closest('[data-grp]'); if (g) { const k = g.dataset.grp; S.collapsed.has(k) ? S.collapsed.delete(k) : S.collapsed.add(k); this.compute(); this.draw(); return; }
      const row = e.target.closest('[data-row]'); if (row) { S.sel = +row.dataset.row; paint(); this.detail(); }
    });
    this.host.querySelector('.g-top').addEventListener('click', (e) => {
      const a = e.target.closest('[data-act]')?.dataset.act; if (!a) return;
      if (a === 'cols') this.host.querySelector('.g-colmenu').hidden ^= 1;
      if (a === 'clear') { S.q = ''; S.filters = {}; S.tagOnly = false; this.compute(); this.draw(); }
      if (a === 'tagonly') { S.tagOnly = !S.tagOnly; this.compute(); this.draw(); }
      if (a === 'export') this.exportCsv();
    });
    this.host.querySelectorAll('[data-col]').forEach((c) => c.addEventListener('change', () => { const i = +c.dataset.col; c.checked ? S.hidden.delete(i) : S.hidden.add(i); this.draw(); this.host.querySelector('.g-colmenu').hidden = false; }));
  }

  /** Re-render after a filter change but keep focus and caret in the input being typed in. */
  redraw(sel) {
    const el = this.host.querySelector(sel); const pos = el?.selectionStart;
    this.draw();
    const n = this.host.querySelector(sel); if (n) { n.focus(); try { n.setSelectionRange(pos, pos); } catch { } }
  }

  detail() {
    const S = this.S; const el = this.host.querySelector('.g-detail'); const r = this.data[S.sel]; if (!el || !r) return;
    el.hidden = false;
    const keys = (this.ds.keyCols || [0, 1]).map((i) => r[i]).filter(Boolean);
    el.innerHTML = `<div class="g-dh"><b>ROW ${S.sel + 1}</b><span><button class="tog" data-d="pivot">PIVOT</button> <button class="tog" data-d="copy">COPY</button> <button class="tog" data-d="close">✕</button></span></div>
      <div class="kv">${this.cols.map((c, i) => `<div>${esc(c)}</div><div>${esc(r[i])}</div>`).join('')}</div>`;
    el.querySelector('[data-d="close"]').addEventListener('click', () => { S.sel = null; el.hidden = true; this.host.querySelectorAll('.g-r.sel').forEach((x) => x.classList.remove('sel')); });
    el.querySelector('[data-d="copy"]').addEventListener('click', (e) => { navigator.clipboard?.writeText(this.cols.map((c, i) => `${c}: ${r[i]}`).join('\n')); e.target.textContent = 'COPIED'; });
    el.querySelector('[data-d="pivot"]').addEventListener('click', () => this.onPivot?.(String(keys.find((k) => /\.(exe|dll|sys|ps1|bat)$/i.test(k)) || keys[0] || '').split(/[\\/]/).pop()));
  }

  exportCsv() {
    const vc = this.visibleCols(); const q = (v) => (/[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
    const lines = [vc.map((i) => q(this.cols[i])).join(',')];
    for (const v of this.view) if (typeof v === 'number') lines.push(vc.map((i) => q(this.data[v][i] || '')).join(','));
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([lines.join('\r\n')], { type: 'text/csv' })); a.download = `sudo-z_grid_${this.S.ds.replace(/[^\w]+/g, '_')}.csv`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
}
function deb(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
