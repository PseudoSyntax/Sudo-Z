// Run Sudo-Z on the original EZ tools' CSV output and compare it with Sudo-Z's own parse of the same evidence.
// usage: node test/compare-csv.mjs <native report.json> <csv report.json>
import fs from 'node:fs';
const [a, b] = process.argv.slice(2).map((p) => JSON.parse(fs.readFileSync(p, 'utf8')));
let fail = 0;
const kinds = new Map(); for (const f of b.files) if (/CSV/.test(f.artifact || '')) kinds.set(f.artifact, (kinds.get(f.artifact) || 0) + 1);
console.log('| CSV type | files |\n|---|---|'); for (const [k, n] of kinds) console.log(`| ${k} | ${n} |`);
const errs = b.files.filter((f) => f.status === 'error'); if (errs.length) { console.log(`\nERROR parsing ${errs.length} CSV(s): ${errs.map((f) => f.name + ' ' + (f.notes || []).join(' ')).join('; ')}`); fail++; }
for (const need of ['EvtxECmd CSV', 'PECmd CSV', 'Amcache file entries CSV', 'AppCompatCacheParser CSV', 'MFTECmd $MFT CSV', 'RECmd batch CSV', 'SrumECmd CSV']) if (!kinds.has(need)) { console.log(`MISSING: no ${need} recognised`); fail++; }
const flagged = (r) => new Set((r.programs || []).filter((p) => p.risk >= 25).map((p) => p.name.toLowerCase()));
const fa = flagged(a), fb = flagged(b); const both = [...fa].filter((x) => fb.has(x));
console.log(`\nPrograms scored >= 25: native ${fa.size}, from EZ CSVs ${fb.size}, in both ${both.length}`);
console.log(`Only native: ${[...fa].filter((x) => !fb.has(x)).slice(0, 30).join(', ')}`);
console.log(`Only CSV: ${[...fb].filter((x) => !fa.has(x)).slice(0, 30).join(', ')}`);
console.log(`Findings: native ${a.findings.length}, from EZ CSVs ${b.findings.length}; timeline ${a.timeline.length} vs ${b.timeline.length}`);
if (!b.findings.length || !b.programs?.length) { console.log('FAIL: CSV import produced no findings or programs'); fail++; }
process.exit(fail ? 1 : 0);
