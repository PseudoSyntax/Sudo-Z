// Office and PDF documents: the timestamps stored inside the file (created, last saved, last printed),
// who wrote it, and features that run code or pull content from elsewhere.
import { parseOoxml, parseOleDoc, parsePdfMeta } from '../parsers/docmeta.js';
import { classifyPath, baseName } from '../ioc/heuristics.js';
import { runGeneric } from './artifacts.js';
import { winPathOf, USER_WRITABLE } from '../ioc/macb.js';

const T = (title, columns, rows, note) => ({ title, columns, rows, note });

export async function runDoc(u8, f, ctx, kind, meta = {}) {
  const d = kind === 'ooxml' ? await parseOoxml(u8) : kind === 'ole' ? parseOleDoc(u8) : parsePdfMeta(u8);
  const path = winPathOf(f.name, meta.winPath) || f.name;
  const name = baseName(f.name);
  const flags = [];
  const uw = USER_WRITABLE.test(path) || /\\(downloads|desktop|temp|inetcache|content\.outlook)\\/i.test(path);
  if (d.macros) {
    flags.push('VBA macros');
    ctx.finding({ sev: uw || /\.(docm|xlsm|pptm|dotm|xltm)$/i.test(name) ? 'high' : 'medium', category: 'Initial Access', tool: 'Sudo-Z docmeta', file: f.name, time: d.modified || meta.si?.created, title: `Document contains VBA macros: ${name}`, detail: `Macro documents are a common first stage. Author ${d.author || '?'}, last saved by ${d.lastBy || '?'} at ${d.modified || '?'}. Extract with olevba and check the AutoOpen / Document_Open code.`, evidence: path, mitre: ['T1204.002', 'T1137'] });
  }
  for (const x of d.external) {
    const remoteTpl = /attachedTemplate/i.test(x.type);
    flags.push(remoteTpl ? 'remote template' : `external ${x.type}`);
    if (/^(https?|file|\\\\)/i.test(x.target) || /^\\\\/.test(x.target)) {
      ctx.indicators.add(/^https?:/i.test(x.target) ? 'url' : 'unc', x.target, f.name, `${remoteTpl ? 'remote template' : 'external ' + x.type} in ${name}`);
      ctx.finding({ sev: remoteTpl || /oleObject|frame/i.test(x.type) ? 'high' : 'medium', category: 'Initial Access', tool: 'Sudo-Z docmeta', file: f.name, time: d.modified, title: `${remoteTpl ? 'Remote template injection' : `External ${x.type} link`} in ${name}`, detail: remoteTpl ? 'The document loads its template from a remote location when opened. Used to fetch macro templates past mail filters.' : 'The document references content outside itself (OLE link, frame or image) that Office fetches when opened. Used for NTLM hash theft and follow-on payloads.', evidence: `${x.part}\n${x.target}`, mitre: remoteTpl ? ['T1221'] : ['T1187', 'T1204.002'] });
    }
  }
  if (d.oleObjects) flags.push(`${d.oleObjects} embedded OLE object(s)`);
  if (d.activeX) flags.push('ActiveX');
  if (d.format === 'PDF') {
    if (d.javascript) flags.push(`JavaScript x${d.javascript}`);
    if (d.openAction) flags.push(`auto action x${d.openAction}`);
    if (d.launch) flags.push(`Launch x${d.launch}`);
    if (d.embedded) flags.push(`embedded file x${d.embedded}`);
    if (+d.revision > 0) flags.push(`${d.revision} incremental update(s)`);
    const risky = d.launch || (d.javascript && d.openAction) || (d.embedded && d.openAction);
    if (risky || d.javascript) ctx.finding({ sev: risky ? 'high' : 'medium', category: 'Initial Access', tool: 'Sudo-Z docmeta', file: f.name, time: d.modified, title: `PDF with ${[d.javascript && 'JavaScript', d.openAction && 'an automatic action', d.launch && 'a Launch action', d.embedded && 'an embedded file'].filter(Boolean).join(', ')}: ${name}`, detail: 'Benign PDFs rarely run code when opened. Inspect with pdfid / pdf-parser.', evidence: path, mitre: ['T1204.002'] });
  }
  const times = [['created', d.created, `Document created (${d.format} metadata)`], ['modified', d.modified, `Document last saved (${d.format} metadata)`], ['printed', d.printed, `Document last printed (${d.format} metadata)`]];
  for (const [, t, type] of times) if (t) ctx.event({ time: t, tool: 'Sudo-Z docmeta', file: f.name, type, desc: `${path}${d.lastBy || d.author ? ` (${d.lastBy || d.author})` : ''}` });
  ctx.fileTimes({ path, source: `${d.format} document metadata`, kind: 'embedded', file: f.name, B: d.created || '', M: d.modified || '', extra: { doc: true, printed: d.printed || '', author: d.author, lastBy: d.lastBy, app: d.app, flags } });
  const pc = classifyPath(path);
  const g = runGeneric(u8, f, ctx, 'Document strings');
  const rows = [['Format', d.format], ['Original path', path], ['Created (metadata)', d.created], ['Last saved (metadata)', d.modified], ['Last printed (metadata)', d.printed], ['Author', d.author], ['Last saved by', d.lastBy], ['Title', d.title], ['Revision / updates', d.revision], ['Editing minutes', d.editMinutes], ['Application', d.app], ['Company', d.company], ['Template', d.template], ['Flags', flags.join('; ')], ['Location', pc.reasons.join('; ')]];
  if (d.format === 'PDF') rows.push(['XMP created', d.xmpCreated], ['XMP modified', d.xmpModified], ['Encrypted', d.encrypted ? 'yes' : 'no']);
  return {
    tool: 'Sudo-Z docmeta', artifact: `${d.format === 'PDF' ? 'PDF' : 'Office'} document (${d.format})`,
    summary: `created ${d.created || '?'}, saved ${d.modified || '?'}${d.author ? ` by ${d.lastBy || d.author}` : ''}${flags.length ? ` [${flags.join(', ')}]` : ''}`,
    tables: [T('Document metadata', ['Field', 'Value'], rows.filter((r) => r[1] !== '' && r[1] != null)), ...(d.external.length ? [T('External relationships', ['Type', 'Target', 'Part'], d.external.map((x) => [x.type, x.target, x.part]))] : []), ...g.tables],
    notes: ['Times stored inside the document are compared with the file system times in the MACB analysis. They move with the file when it is copied, so they show when the content was made, not when it arrived.'],
  };
}
