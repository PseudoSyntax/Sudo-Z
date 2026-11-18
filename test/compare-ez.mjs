// Cross-validate Sudo-Z's JavaScript parsers against the original EZ tools.
// usage: node test/compare-ez.mjs <ez-output-dir> <sudo-z report.json> [--strict]
// Writes a markdown table to stdout (CI appends it to the job summary).
import fs from 'node:fs';
import path from 'node:path';

const [ezDir, repPath] = process.argv.slice(2);
const strict = process.argv.includes('--strict');
const rep = JSON.parse(fs.readFileSync(repPath, 'utf8'));

function walk(d, out = []) { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); e.isDirectory() ? walk(p, out) : out.push(p); } return out; }
const csvFiles = walk(ezDir).filter((f) => /\.csv$/i.test(f));

function parseCsv(file) {
  let t = fs.readFileSync(file, 'utf8').replace(/^﻿/, '');
  const rows = []; let row = [], cell = '', q = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (q) { if (c === '"') { if (t[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(cell); cell = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && t[i + 1] === '\n') i++; row.push(cell); cell = ''; if (row.length > 1 || row[0] !== '') rows.push(row); row = []; }
    else cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  const head = rows.shift() || [];
  return rows.map((r) => Object.fromEntries(head.map((h, i) => [h.toLowerCase(), r[i] ?? ''])));
}
const csvBy = (rx) => csvFiles.filter((f) => rx.test(path.basename(f))).flatMap((f) => parseCsv(f));
const base = (p) => String(p || '').split(/[\\/]/).pop().toLowerCase();
const sz = (pred) => rep.files.filter((f) => f.status !== 'rejected' && pred(f));
const table = (f, rx) => f.tables.find((t) => rx.test(t.title));

const results = [];
const add = (tool, item, ez, mine, note = '') => {
  const ok = ez === mine || (typeof ez === 'number' && typeof mine === 'number' && ez > 0 && Math.abs(ez - mine) / ez <= 0.02);
  results.push({ tool, item, ez, mine, ok, note });
};

// EvtxECmd: records per log file
const evtx = csvBy(/EvtxECmd_Output\.csv$/i);
if (evtx.length) {
  const per = new Map(); for (const r of evtx) per.set(base(r.sourcefile), (per.get(base(r.sourcefile)) || 0) + 1);
  for (const f of sz((f) => f.tool === 'EvtxECmd')) { const n = table(f, /^All events/)?.rows.length ?? 0; const e = per.get(base(f.name)); if (e !== undefined) add('EvtxECmd', base(f.name), e, n); }
}
// PECmd: run count per prefetch file
const pf = csvBy(/PECmd_Output\.csv$/i);
for (const f of sz((f) => f.tool === 'PECmd')) {
  const e = pf.find((r) => base(r.sourcefilename) === base(f.name));
  const mine = table(f, /Prefetch summary/)?.rows.find((r) => r[0] === 'Run count')?.[1];
  if (e) add('PECmd', base(f.name) + ' run count', Number(e.runcount), Number(mine));
}
// AppCompatCacheParser: ShimCache entries
const shim = csvBy(/AppCompatCache\.csv$|AppCompatCacheParser.*\.csv$/i);
for (const f of sz((f) => /RECmd/.test(f.tool) && table(f, /ShimCache/))) {
  const cs = new Set(shim.map((r) => r.controlset)); const first = [...cs].sort()[0];
  add('AppCompatCacheParser', base(f.name) + ' entries', shim.filter((r) => r.controlset === first).length, table(f, /ShimCache/).rows.length, `ControlSet ${first} of ${[...cs].join(',')}`);
}
// AmcacheParser: SHA1 overlap
const am = csvBy(/Amcache.*FileEntries\.csv$/i);
for (const f of sz((f) => f.tool === 'AmcacheParser')) {
  const mine = new Set((table(f, /Amcache file entries/)?.rows || []).map((r) => String(r[2] || '').toLowerCase()).filter(Boolean));
  const ez = new Set(am.map((r) => String(r.sha1 || '').toLowerCase()).filter(Boolean));
  const both = [...ez].filter((h) => mine.has(h)).length;
  add('AmcacheParser', base(f.name) + ' SHA1s', ez.size, mine.size, `${both} in common`);
}
// MFTECmd: non-ADS file records
const mftCsv = csvFiles.filter((f) => /MFTECmd_\$MFT_Output\.csv$/i.test(path.basename(f)));
for (const f of sz((f) => f.tool === 'MFTECmd' && /^\$MFT$/.test(f.artifact))) {
  const rows = mftCsv.flatMap(parseCsv).filter((r) => !/true/i.test(r.isads));
  add('MFTECmd', base(f.name) + ' records', rows.length, table(f, /All MFT entries/)?.rows.length ?? 0);
}
// RBCmd: deleted items
const rb = csvBy(/RBCmd_Output\.csv$/i);
const myRb = sz((f) => f.tool === 'RBCmd').reduce((n, f) => n + (f.artifact.includes('INFO2') ? table(f, /Deleted items/).rows.length : 1), 0);
if (rb.length || myRb) add('RBCmd', 'deleted items', rb.length, myRb);
// LECmd: shortcuts parsed + target agreement
const le = csvBy(/LECmd_Output\.csv$/i);
for (const f of sz((f) => f.tool === 'LECmd')) {
  const e = le.find((r) => base(r.sourcefile) === base(f.name));
  const mine = table(f, /Shortcut details/)?.rows.find((r) => r[0] === 'Target')?.[1] || '';
  if (e) { const ez = e.localpath || e.networkpath || e.targetidabsolutepath || ''; add('LECmd', base(f.name) + ' target', base(ez), base(mine)); }
}
// JLECmd: entries per jump list
const jl = csvBy(/(Automatic|Custom)Destinations\.csv$/i);
for (const f of sz((f) => f.tool === 'JLECmd')) {
  const e = jl.filter((r) => base(r.sourcefile) === base(f.name)).length;
  if (e || jl.length) add('JLECmd', base(f.name) + ' entries', e, table(f, /Jump list entries/)?.rows.length ?? 0);
}
// SrumECmd: network usage rows
const srum = csvBy(/NetworkUsages.*\.csv$/i);
for (const f of sz((f) => f.tool === 'SrumECmd')) add('SrumECmd', 'NetworkUsages rows', srum.length, table(f, /SRUM network usage records/)?.rows.length ?? 0);
// WxTCmd: activities
const wx = csvBy(/_Activity\.csv$/i);
for (const f of sz((f) => f.tool === 'WxTCmd')) add('WxTCmd', 'Activity rows', wx.length, table(f, /Timeline activities/)?.rows.length ?? 0);
// SBECmd: shellbags
const sb = csvFiles.filter((f) => /SBECmd|ShellBags|UsrClass|NTUSER/i.test(f) && /\.csv$/i.test(f) && /SBECmd/i.test(f)).flatMap(parseCsv);
const mySb = sz((f) => /SBECmd/.test(f.tool)).reduce((n, f) => n + f.tables.filter((t) => /^ShellBags/.test(t.title)).reduce((m, t) => m + t.rows.length, 0), 0);
if (sb.length || mySb) add('SBECmd', 'shellbag entries', sb.length, mySb);

let md = '## Sudo-Z vs original EZ tools\n\n| Tool | Item | EZ tool | Sudo-Z | Match | Note |\n|---|---|---|---|---|---|\n';
for (const r of results) md += `| ${r.tool} | ${r.item} | ${r.ez} | ${r.mine} | ${r.ok ? 'yes' : '**NO**'} | ${r.note} |\n`;
const bad = results.filter((r) => !r.ok).length;
md += `\n${results.length - bad}/${results.length} comparisons match. EZ CSV files found: ${csvFiles.length}.\n`;
console.log(md);
fs.writeFileSync(path.join(path.dirname(repPath), 'comparison.json'), JSON.stringify(results, null, 1));
if (strict && bad) process.exit(1);
