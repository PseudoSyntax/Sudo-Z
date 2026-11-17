#!/usr/bin/env node
// Headless Sudo-Z: same engine as the web UI.
// usage: node cli/sudo-z.mjs <file|dir|zip>... [-o outdir] [--no-defang]
import fs from 'node:fs';
import path from 'node:path';
if (!globalThis.crypto?.subtle) globalThis.crypto = (await import('node:crypto')).webcrypto;
const { analyze } = await import('../js/engine.js');
const { markdown, timelineCsv, findingsCsv, indicatorsCsv } = await import('../js/report.js');

const args = process.argv.slice(2);
let out = 'sudo-z-out'; let defanged = true; const targets = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '-o') out = args[++i];
  else if (args[i] === '--no-defang') defanged = false;
  else if (args[i] === '-h' || args[i] === '--help') { console.log('usage: node cli/sudo-z.mjs <file|dir|zip>... [-o outdir] [--no-defang]'); process.exit(0); }
  else targets.push(args[i]);
}
if (!targets.length) { console.error('no input. usage: node cli/sudo-z.mjs <file|dir|zip>... [-o outdir]'); process.exit(1); }

const inputs = [];
const walk = (p, rel) => {
  const st = fs.statSync(p);
  if (st.isDirectory()) for (const e of fs.readdirSync(p)) walk(path.join(p, e), rel ? `${rel}/${e}` : e);
  else inputs.push({ name: rel || path.basename(p), data: new Uint8Array(fs.readFileSync(p)) });
};
for (const t of targets) walk(t, fs.statSync(t).isDirectory() ? path.basename(path.resolve(t)) : '');

const rep = await analyze(inputs, { onProgress: (p, l) => process.stderr.write(`\r[${String(Math.round(p * 100)).padStart(3)}%] ${String(l).slice(0, 90).padEnd(90)}`) });
process.stderr.write('\n');
fs.mkdirSync(out, { recursive: true });
fs.writeFileSync(path.join(out, 'report.md'), markdown(rep, { defanged }));
fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(rep, (k, v) => (typeof v === 'bigint' ? v.toString() : v instanceof Uint8Array ? Buffer.from(v.subarray(0, 512)).toString('hex') : v)));
fs.writeFileSync(path.join(out, 'findings.csv'), findingsCsv(rep));
fs.writeFileSync(path.join(out, 'indicators.csv'), indicatorsCsv(rep));
fs.writeFileSync(path.join(out, 'timeline.csv'), timelineCsv(rep));
const s = rep.severity;
console.log(`${rep.verdict}  crit ${s.critical} high ${s.high} med ${s.medium} low ${s.low}  | ${rep.counts.files} files (${rep.counts.rejected} not accepted) | ${rep.indicators.length} indicators | ${rep.timeline.length} timeline events`);
for (const f of rep.findings.filter((x) => x.sev === 'critical' || x.sev === 'high').slice(0, 25)) console.log(`  [${f.sev.toUpperCase().padEnd(8)}] ${f.title}`);
console.log(`reports written to ${path.resolve(out)}`);
