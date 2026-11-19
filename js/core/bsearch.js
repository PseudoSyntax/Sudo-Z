// bstrings, the search half: stream any file (or a whole disk / memory image,
// read in chunks) through an ASCII + UTF-16LE string scanner with bstrings'
// options: min/max length (-m/-x), ASCII or Unicode only (-a/-u), a string to
// look for (--ls), a regex (--lr, including every bstrings built-in pattern by
// name), a list of strings (--fs), "only the matched part" (--ro), and the
// offset and encoding of every hit (--off).

// bstrings' built-in patterns (BuiltInPatterns.cs), translated to JavaScript.
// bstrings applies them case-insensitively.
export const BUILTIN = {
  guid: ['Finds GUIDs', String.raw`\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b`],
  usPhone: ['Finds US phone numbers', String.raw`\(?\b[2-9][0-9]{2}\)?[-. ]?[2-9][0-9]{2}[-. ]?[0-9]{4}\b`],
  unc: ['Finds UNC paths', String.raw`^\\\\(?<server>[a-z0-9 %._-]+)\\(?<share>[a-z0-9 $%._-]+)`],
  mac: ['Finds MAC addresses', String.raw`\b[0-9A-F]{2}([-:]?)(?:[0-9A-F]{2}\1){4}[0-9A-F]{2}\b`],
  ssn: ['Finds US Social Security Numbers', String.raw`\b(?!000)(?!666)[0-8][0-9]{2}[- ](?!00)[0-9]{2}[- ](?!0000)[0-9]{4}\b`],
  cc: ['Finds credit card numbers', String.raw`^[ -]*(?:4[ -]*(?:\d[ -]*){11}(?:(?:\d[ -]*){3})?\d|5[ -]*[1-5](?:[ -]*[0-9]){14}|6[ -]*(?:0[ -]*1[ -]*1|5[ -]*\d[ -]*\d)(?:[ -]*[0-9]){12}|3[ -]*[47](?:[ -]*[0-9]){13}|3[ -]*(?:0[ -]*[0-5]|[68][ -]*[0-9])(?:[ -]*[0-9]){11}|(?:2[ -]*1[ -]*3[ -]*1|1[ -]*8[ -]*0[ -]*0|3[ -]*5(?:[ -]*[0-9]){3})(?:[ -]*[0-9]){11})[ -]*$`],
  ipv4: ['Finds IP version 4 addresses', String.raw`\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b`],
  ipv6: ['Finds IP version 6 addresses', String.raw`(?<![:.\w])(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}(?![:.\w])`],
  email: ['Finds embedded email addresses', String.raw`\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,6}\b`],
  zip: ['Finds zip codes', String.raw`^\b[0-9]{5}(?:-[0-9]{4})?\b$`],
  urlUser: ['Finds usernames in URLs', String.raw`^[a-z0-9+\-.]+://(?<user>[a-z0-9\-._~%!$&'()*+,;=]+)@`],
  url3986: ['Finds URLs according to RFC 3986', String.raw`^[a-z][a-z0-9+\-.]*://([a-z0-9\-._~%!$&'()*+,;=]+@)?(?<host>[a-z0-9\-._~%]+|\[[a-f0-9:.]+\]|\[v[a-f0-9][a-z0-9\-._~%!$&'()*+,;=:]+\])(:[0-9]+)?(/[a-z0-9\-._~%!$&'()*+,;=:@]+)*/?(\?[a-z0-9\-._~%!$&'()*+,;=:@/?]*)?(#[a-z0-9\-._~%!$&'()*+,;=:@/?]*)?$`],
  xml: ['Finds XML/HTML tags', String.raw`^<([A-Z][A-Z0-9]*)\b[^>]*>(.*?)</\1>$`],
  sid: ['Finds Microsoft Security Identifiers (SID)', String.raw`^S-\d-\d+-(\d+-){1,14}\d+$`],
  win_path: ['Finds Windows style paths (C:\\folder1\\folder2\\file.txt)', String.raw`(?:"?[a-zA-Z]:|\\\\[^\\/:*?<>|]+\\[^\\/:*?<>|]*)\\(?:[^\\/:*?<>|]+\\)*\w([^\\/:*?<>|])*`],
  var_set: ['Finds environment variables being set (OS=Windows_NT)', String.raw`^[a-z_0-9]+=[\\/:*?<>|;\- _a-z0-9]+`],
  reg_path: ['Finds paths related to Registry hives', String.raw`([a-z0-9]\\)*(software|sam|system|security)\\[a-z0-9\\]+`],
  b64: ['Finds valid formatted base 64 strings', String.raw`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$`],
  bitlocker: ['Finds Bitlocker recovery keys', String.raw`[0-9]{6}?-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}`],
  bitcoin: ['Finds BitCoin wallet addresses', String.raw`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`],
  aeon: ['Finds Aeon wallet addresses', String.raw`Wm[st]{1}[0-9a-zA-Z]{94}`],
  bytecoin: ['Finds ByteCoin wallet addresses', String.raw`2[0-9AB][0-9a-zA-Z]{93}`],
  dashcoin: ['Finds DashCoin wallet addresses (D*)', String.raw`D[0-9a-zA-Z]{94}`],
  dashcoin2: ['Finds DashCoin wallet addresses (7|X)*', String.raw`(7|X)[a-zA-Z0-9]{33}`],
  fantomcoin: ['Finds Fantomcoin wallet addresses', String.raw`6[0-9a-zA-Z]{94}`],
  monero: ['Finds Monero wallet addresses', String.raw`4[0-9AB][0-9a-zA-Z]{93}|4[0-9AB][0-9a-zA-Z]{104}`],
  sumokoin: ['Finds SumoKoin wallet addresses', String.raw`Sumoo[0-9a-zA-Z]{94}`],
  // Sudo-Z additions for CTF and DFIR work (not in bstrings)
  flag: ['CTF flags: word{...}, GUIDs excluded (Sudo-Z)', String.raw`\b[A-Za-z0-9_]{2,16}\{(?![0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-)[^{}\s]{3,120}\}`],
  pwsh_enc: ['PowerShell -EncodedCommand payloads (Sudo-Z)', String.raw`-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}`],
  ntlm: ['NTLM / LM hashes and hashdump lines (Sudo-Z)', String.raw`\b[^:\s]{1,64}:\d+:[a-f0-9]{32}:[a-f0-9]{32}:::|\$NT\$[a-f0-9]{32}`],
  implant: ['Meterpreter, Cobalt Strike and reflective loader strings (Sudo-Z)', String.raw`\bmetsrv(\.x(64|86))?\.dll\b|\bReflectiveLoader\b|\bcore_(channel_open|loadlib|negotiate_tlv_encryption|channel_write|patch_url)\b|\bstdapi_(sys_process_execute|fs_stat|railgun_api|sys_config_getuid)\b|\bextapi_clipboard_get_data\b|\bmeterpreter\b|\bmsfvenom\b|\bbeacon_(initialize|command)\b`],
  url: ['Finds URLs anywhere in a string, defanged ones too (Sudo-Z; url3986 only matches a whole string)', String.raw`\b(?:h(?:tt|xx)ps?|ftps?|smb|ldaps?|ws{1,2}s?):\/\/[^\s"'<>\\)\]}]{3,500}`],
  b64_blob: ['Finds long base64 blobs anywhere in a string (Sudo-Z)', String.raw`[A-Za-z0-9+/]{60,}={0,2}`],
  domain: ['Finds bare domain names (Sudo-Z)', String.raw`\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|co|uk|de|fr|nl|br|in|info|biz|top|xyz|club|online|site|shop|live|icu|cc|tk|ml|ga|cf|gq|pw|su|onion|me|tv|us|ca|au|jp|kr|pl|it|es|se|no|fi|dk|ch|at|be|cz|ro|gr|pt|hu|ua|tr|il|za|mx|ar|cl|id|th|vn|my|sg|hk|tw|nz|ie|dev|app|cloud|zip|mov)\b`],
  onion: ['Finds Tor .onion addresses (Sudo-Z)', String.raw`\b[a-z2-7]{16}\.onion\b|\b[a-z2-7]{56}\.onion\b`],
  md5: ['Finds MD5 hashes (Sudo-Z)', String.raw`\b[a-f0-9]{32}\b`],
  sha1: ['Finds SHA1 hashes (Sudo-Z)', String.raw`\b[a-f0-9]{40}\b`],
  sha256: ['Finds SHA256 hashes (Sudo-Z)', String.raw`\b[a-f0-9]{64}\b`],
  jwt: ['Finds JSON web tokens (Sudo-Z)', String.raw`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`],
  cve: ['Finds CVE identifiers (Sudo-Z)', String.raw`\bCVE-(19|20)\d{2}-\d{4,7}\b`],
  useragent: ['Finds HTTP User-Agent strings (Sudo-Z)', String.raw`Mozilla\/[45]\.0 \([^)]{3,120}\)[^\r\n]{0,200}`],
  http_req: ['Finds HTTP request lines and Host headers (Sudo-Z)', String.raw`^(?:GET|POST|PUT|HEAD|OPTIONS|DELETE|PATCH|CONNECT) \/[^\s]{0,300} HTTP\/[01]\.[019]|^Host:\s*[a-z0-9.\-:\[\]]+`],
  run_key: ['Finds Run / autostart registry paths (Sudo-Z)', String.raw`(?:software\\)?microsoft\\windows\\currentversion\\(run|runonce|runonceex|runservices|policies\\explorer\\run)[^\r\n]{0,200}`],
  lolbin_cmd: ['Finds LOLBin command lines (Sudo-Z)', String.raw`\b(?:rundll32|regsvr32|mshta|certutil|bitsadmin|wmic|msiexec|installutil|regasm|regsvcs|cmstp|odbcconf|forfiles|pcalua|conhost|wscript|cscript|curl|wget|msbuild)(?:\.exe)?\b[^\r\n]{0,250}`],
  priv_ip: ['Finds private and loopback IPv4 addresses (Sudo-Z)', String.raw`\b(?:10(?:\.\d{1,3}){3}|127(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2})\b`],
  port_url: ['Finds host:port pairs (Sudo-Z)', String.raw`\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]):\d{1,5}\b|\b[a-z0-9][a-z0-9.-]{2,60}\.[a-z]{2,10}:\d{2,5}\b`],
  privkey: ['Private keys and tokens (Sudo-Z)', String.raw`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}`],
};

const isPrint = (c) => c >= 0x20 && c <= 0x7e;

/**
 * Stateful scanner: feed it consecutive chunks; it emits every string with its absolute offset.
 * emit(text, offset, 'A' | 'U')
 */
export class StringScanner {
  constructor({ min = 3, max = 0, ascii = true, unicode = true } = {}, emit) {
    this.min = Math.max(1, min); this.max = max > 0 ? max : 0; this.ascii = ascii; this.unicode = unicode; this.emit = emit;
    this.a = { start: -1, s: '' };
    this.u = [{ start: -1, s: '' }, { start: -1, s: '' }];
    this.pending = null; // carry byte for UTF-16 pairs that cross a chunk edge
  }
  _flush(run, enc) {
    if (run.start >= 0 && run.s.length >= this.min) {
      if (this.max && run.s.length > this.max) for (let i = 0; i < run.s.length; i += this.max) { const part = run.s.slice(i, i + this.max); if (part.length >= this.min) this.emit(part, run.start + (enc === 'U' ? i * 2 : i), enc); }
      else this.emit(run.s, run.start, enc);
    }
    run.start = -1; run.s = '';
  }
  feed(u8, base) {
    const n = u8.length;
    if (this.ascii) {
      const r = this.a; let i0 = -1;
      for (let i = 0; i < n; i++) {
        if (isPrint(u8[i])) { if (r.start < 0) r.start = base + i; if (i0 < 0) i0 = i; }
        else { if (i0 >= 0) { r.s += latin1(u8, i0, i); i0 = -1; } if (r.start >= 0) this._flush(r, 'A'); }
      }
      if (i0 >= 0) r.s += latin1(u8, i0, n);
    }
    if (this.unicode) {
      // work on pairs at absolute even and odd offsets; carry the last byte to the next chunk
      let buf = u8, b0 = base;
      if (this.pending) { buf = new Uint8Array(n + 1); buf[0] = this.pending.byte; buf.set(u8, 1); b0 = this.pending.off; }
      const m = buf.length;
      for (let p = 0; p < 2; p++) {
        const r = this.u[(b0 + p) % 2];
        let codes = [];
        for (let i = p; i + 1 < m; i += 2) {
          const lo = buf[i], hi = buf[i + 1];
          if (hi === 0 && isPrint(lo)) { if (r.start < 0) r.start = b0 + i; codes.push(lo); if (codes.length > 8192) { r.s += String.fromCharCode(...codes); codes = []; } }
          else { if (codes.length) { r.s += String.fromCharCode(...codes); codes = []; } if (r.start >= 0) this._flush(r, 'U'); }
        }
        if (codes.length) r.s += String.fromCharCode(...codes);
      }
      // the byte at the end with no partner yet: every pair must end by m-1, so carry the last byte if m is odd relative to each parity
      this.pending = { byte: buf[m - 1], off: b0 + m - 1 };
      // pairs that started at m-1 will be completed next time; pairs at m-2 were already handled
    }
  }
  end() { if (this.ascii) this._flush(this.a, 'A'); if (this.unicode) { this._flush(this.u[0], 'U'); this._flush(this.u[1], 'U'); } }
}
function latin1(u8, a, b) { let s = ''; for (let i = a; i < b; i += 8192) s += String.fromCharCode(...u8.subarray(i, Math.min(b, i + 8192))); return s; }

/** Build the matcher for a search. Returns {test(s) -> null | [{match, pattern}]} */
export function buildMatcher(o) {
  const ci = !o.caseSensitive;
  if (o.mode === 'all') return () => [{ match: null, pattern: '' }];
  if (o.mode === 'text') { const q = ci ? o.query.toLowerCase() : o.query; return (s) => { const i = (ci ? s.toLowerCase() : s).indexOf(q); return i >= 0 ? [{ match: s.substr(i, q.length), pattern: 'ls', index: i }] : null; }; }
  if (o.mode === 'list') { const qs = o.query.split(/\r?\n/).map((x) => x.trim()).filter(Boolean).map((x) => (ci ? x.toLowerCase() : x)); return (s) => { const t = ci ? s.toLowerCase() : s; for (const q of qs) { const i = t.indexOf(q); if (i >= 0) return [{ match: s.substr(i, q.length), pattern: 'fs', index: i }]; } return null; }; }
  // builtin mode can carry an extra regex of your own; regex mode takes one per line
  const list = o.mode === 'builtin'
    ? [...o.patterns.map((n) => [n, BUILTIN[n][1]]), ...String(o.query || '').split(/\r?\n/).map((x) => x.trim()).filter(Boolean).map((x, i) => [`custom${i ? i + 1 : ''}`, x])]
    : String(o.query || '').split(/\r?\n/).map((x) => x.trim()).filter(Boolean).map((x, i) => [i ? `lr${i + 1}` : 'lr', x]);
  const rxs = list.map(([n, src]) => [n, new RegExp(src, ci ? 'gi' : 'g')]);
  if (!rxs.length) return () => null;
  const matcher = (s) => {
    let out = null;
    for (const [n, rx] of rxs) {
      rx.lastIndex = 0;
      if (o.onlyMatch) { let m; let guard = 0; while ((m = rx.exec(s)) && guard++ < 200) { (out ||= []).push({ match: m[0], pattern: n, index: m.index }); if (!m[0].length) rx.lastIndex++; } }
      else if (rx.test(s)) { (out ||= []).push({ match: null, pattern: n }); break; }
    }
    return out;
  };
  return matcher;
}

/**
 * Search files. files: [{name, data?: Uint8Array, src?: {size, read(off,len)}}]
 * Returns {rows: [[file, offset, enc, length, text, pattern]], scanned, truncated}
 */
export async function searchStrings(files, o, onProgress = () => {}) {
  const base = buildMatcher(o);
  // grep -v: keep the strings that match nothing
  const match = o.invert ? (s) => (base(s) ? null : [{ match: null, pattern: 'not matched' }]) : base;
  const limit = o.limit || 1000000;
  const rows = []; let scanned = 0; let truncated = false;
  const filt = o.fileFilter ? (() => { try { return new RegExp(o.fileFilter, 'i'); } catch { const x = o.fileFilter.toLowerCase(); return { test: (n) => n.toLowerCase().includes(x) }; } })() : null;
  const todo = files.filter((f) => (!filt || filt.test(f.name)) && (f.data || (o.images && f.src)) && (!o.maxSize || (f.data ? f.data.length : f.src.size) <= o.maxSize));
  const total = todo.reduce((n, f) => n + (f.data ? f.data.length : f.src.size), 0) || 1;
  for (const f of todo) {
    if (rows.length >= limit) { truncated = true; break; }
    const sc = new StringScanner(o, (s, off, enc) => {
      if (rows.length >= limit) { truncated = true; return; }
      const hits = match(s); if (!hits) return;
      for (const h of hits) {
        const text = h.match != null && o.onlyMatch ? h.match : s;
        const at = h.index != null && o.onlyMatch ? off + h.index * (enc === 'U' ? 2 : 1) : off;
        rows.push([f.name, at, enc, text.length, text.length > 4000 ? text.slice(0, 4000) + '…' : text, h.pattern]);
      }
    });
    const size = f.data ? f.data.length : f.src.size;
    const CH = 16 * 1024 * 1024;
    for (let off = 0; off < size; off += CH) {
      const chunk = f.data ? f.data.subarray(off, Math.min(size, off + CH)) : await f.src.read(off, Math.min(CH, size - off));
      sc.feed(chunk, off); scanned += chunk.length;
      onProgress(scanned / total, f.name);
      if (rows.length >= limit) { truncated = true; break; }
      await new Promise((r) => setTimeout(r, 0));
    }
    sc.end();
  }
  // grep -l and grep -c: collapse to one row per file
  if (o.output === 'files' || o.output === 'count') {
    const per = new Map();
    for (const r of rows) { const e = per.get(r[0]) || { n: 0, pats: new Map(), first: r[1] }; e.n++; e.pats.set(r[5], (e.pats.get(r[5]) || 0) + 1); per.set(r[0], e); }
    const out = [...per].map(([name, e]) => [name, e.n, [...e.pats].sort((a, b) => b[1] - a[1]).map(([p, n]) => `${p} (${n})`).join(', '), e.first]).sort((a, b) => b[1] - a[1]);
    return { rows: out, scanned, truncated, files: todo.length, output: o.output, columns: ['File', 'Matches', 'Patterns', 'First offset'], searched: todo.map((f) => f.name) };
  }
  return { rows, scanned, truncated, files: todo.length };
}
