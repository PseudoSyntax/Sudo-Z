// Windows executables (submitted directly, or pulled out of a disk image from
// a user-writable folder): hash, PE type, embedded Authenticode signer, and a
// grade that combines location, name tricks and the signature.
import { peInfo } from '../parsers/pe.js';
import { classifyPath, baseName, maxSev } from '../ioc/heuristics.js';
import { runGeneric } from './artifacts.js';

const T = (title, columns, rows, note) => ({ title, columns, rows, note });

export function runPe(u8, f, ctx, meta = {}) {
  const pi = peInfo(u8);
  const path = meta.winPath || f.name;
  const sha1 = meta.sha1 || '';
  ctx.sign({ path, sha1, signed: pi.signed, signer: pi.signer, publisher: pi.org, status: pi.signed ? 'embedded signature (not verified)' : 'no embedded signature', kind: pi.kind, source: meta.fromImage ? 'PE file (disk image)' : 'PE file (submitted)', file: f.name, time: meta.si?.created || '' });
  const pc = classifyPath(path);
  const sig = pi.signed ? `signed by ${pi.signer || 'unknown signer'}${pi.issuer ? ` (issuer ${pi.issuer})` : ''}` : 'no embedded signature';
  if (meta.fromImage) {
    ctx.event({ time: meta.si?.created, tool: 'Sigcheck', file: f.name, type: `${pi.kind === 'dll' ? 'DLL' : 'Program'} present in user-writable folder ($SI created)`, desc: `${path} [${sig}]` });
    // catalog-signed Windows binaries carry no embedded signature, but they do not live in user folders
    let sev = maxSev(pc.sev, pi.signed ? null : pi.kind === 'driver' ? 'high' : 'medium');
    if (sev) ctx.finding({ sev, category: pi.signed ? 'Execution' : 'Unsigned Binary', tool: 'Sigcheck', file: f.name, time: meta.si?.created, title: `${pi.signed ? 'Program' : 'Unsigned ' + (pi.kind === 'dll' ? 'DLL' : pi.kind === 'driver' ? 'driver' : 'program')} in user-writable folder: ${baseName(path)}`, detail: [sig, ...pc.reasons].join('; '), evidence: `${path}\nSHA1 ${sha1}\nbuilt ${pi.compiled} (${pi.machine})`, mitre: pi.kind === 'dll' ? ['T1574.002'] : ['T1204.002'] });
    if (!pi.signed && sha1) ctx.indicators.add('sha1_unsigned_review', sha1, f.name, path);
  } else {
    ctx.finding({ sev: pc.sev || 'info', category: 'Submitted Binary', tool: 'Hasher', file: f.name, title: `Executable submitted: ${baseName(f.name)} (${pi.signed ? 'signed: ' + (pi.signer || '?') : 'unsigned'})`, detail: 'Pivot on the hashes in your threat intel / sandbox.' + (pc.reasons.length ? ' ' + pc.reasons.join('; ') : ''), evidence: sha1 ? `SHA1 ${sha1}` : '' });
  }
  const tables = [T('PE summary', ['Property', 'Value'], [['Path', path], ['Type', pi.kind], ['Machine', pi.machine], ['Compiled (header)', pi.compiled], ['Embedded signature', pi.signed ? 'yes (not verified)' : 'no'], ['Signer', pi.signer], ['Signer organisation', pi.org], ['Issuer', pi.issuer]])];
  let notes = [];
  if (!meta.fromImage) { const g = runGeneric(u8, f, ctx, 'strings'); tables.push(...(g.tables || [])); notes = g.notes || []; }
  return { tool: 'Hasher + Sigcheck', artifact: `Windows ${pi.kind === 'dll' ? 'DLL' : pi.kind === 'driver' ? 'driver' : 'executable'}`, summary: `${pi.machine} ${pi.kind}, ${sig}`, tables, notes };
}
