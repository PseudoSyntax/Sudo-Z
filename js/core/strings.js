// bstrings equivalent: pull ASCII and UTF-16LE strings out of any binary and
// run the built in regex patterns over them.

const MAX_SCAN = 64 * 1024 * 1024; // 64 MB per file

export function extractStrings(u8, { min = 5, maxStrings = 400000 } = {}) {
  const n = Math.min(u8.length, MAX_SCAN);
  const out = [];
  const pr = (c) => (c >= 0x20 && c < 0x7f) || c === 9;
  // ASCII
  let start = -1;
  for (let i = 0; i <= n; i++) {
    const c = i < n ? u8[i] : 0;
    if (pr(c)) { if (start < 0) start = i; }
    else if (start >= 0) {
      if (i - start >= min) {
        let s = ''; for (let j = start; j < i; j++) s += String.fromCharCode(u8[j]);
        out.push(s); if (out.length >= maxStrings) return { strings: out, truncated: true };
      }
      start = -1;
    }
  }
  // UTF-16LE (two alignments)
  for (let align = 0; align < 2; align++) {
    start = -1;
    for (let i = align; i + 1 <= n; i += 2) {
      const c = i + 1 < n ? u8[i] : 0, hi = i + 1 < n ? u8[i + 1] : 1;
      if (hi === 0 && pr(c)) { if (start < 0) start = i; }
      else if (start >= 0) {
        if ((i - start) / 2 >= min) {
          let s = ''; for (let j = start; j < i; j += 2) s += String.fromCharCode(u8[j]);
          out.push(s); if (out.length >= maxStrings) return { strings: out, truncated: true };
        }
        start = -1;
      }
    }
  }
  return { strings: out, truncated: u8.length > MAX_SCAN };
}

// Keyword hits that matter regardless of format (offensive tooling, ransom notes, etc.)
export const KEYWORD_RULES = [
  { id: 'mimikatz', rx: /\b(mimikatz|sekurlsa::|lsadump::|kerberos::golden|privilege::debug|gentilkiwi|mimilib|mimidrv)\b/i, sev: 'critical', title: 'Mimikatz strings present' },
  { id: 'cobalt', rx: /\b(beacon\.(dll|x64)|ReflectiveLoader|%COMSPEC% \/C|cobaltstrike|\\\\\.\\pipe\\(msagent_|MSSE-|postex_|status_)\w*)/i, sev: 'critical', title: 'Cobalt Strike style beacon strings' },
  { id: 'ps-offense', rx: /\b(Invoke-Mimikatz|Invoke-Kerberoast|Invoke-ShareFinder|Invoke-BloodHound|Invoke-Shellcode|Invoke-ReflectivePEInjection|Invoke-TokenManipulation|Get-GPPPassword|PowerView|PowerSploit|Empire|Invoke-Obfuscation|Out-Minidump|MiniDumpWriteDump|Invoke-SMBExec|Invoke-WMIExec|Invoke-TheHash|PowerUp|Nishang)\b/i, sev: 'high', title: 'Offensive PowerShell framework strings' },
  { id: 'cradle', rx: /(IEX|Invoke-Expression)\s*\(?\s*\(?\s*(New-Object\s+(System\.)?Net\.WebClient|\[System\.Net\.WebClient\]|iwr|Invoke-WebRequest|irm)|DownloadString\(|DownloadFile\(|Net\.WebClient\)\.Download/i, sev: 'high', title: 'PowerShell download cradle' },
  { id: 'ransom', rx: /(your (important )?files (have been|are) encrypted|decrypt(ion)? (key|tool|your files)|bitcoin wallet|\.onion\b.{0,60}(decrypt|key|pay)|HOW_TO_DECRYPT|RESTORE_FILES|readme_for_decrypt)/i, sev: 'critical', title: 'Ransom note language' },
  { id: 'shadow', rx: /(vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete\s+(catalog|systemstatebackup)|bcdedit.{0,40}recoveryenabled\s+no)/i, sev: 'critical', title: 'Shadow copy / backup destruction command' },
  { id: 'cred-tools', rx: /\b(lazagne|rubeus|kekeo|safetykatz|sharphound|bloodhound|nanodump|procdump.{0,40}lsass|comsvcs(\.dll)?.{0,20}minidump|pypykatz|secretsdump|ntdsutil.{0,30}ifm)\b/i, sev: 'high', title: 'Credential theft tooling strings' },
  { id: 'webshell', rx: /(eval\s*\(\s*(base64_decode|gzinflate|str_rot13)|<%@\s*Page[^>]+%>.{0,300}(Process\.Start|cmd\.exe)|China Chopper|antsword|behinder|godzilla)/is, sev: 'high', title: 'Web shell markers' },
];

export function runBstrings(u8) {
  const { strings, truncated } = extractStrings(u8);
  const hits = [];
  const seen = new Set();
  for (const s of strings) {
    for (const k of KEYWORD_RULES) {
      if (k.rx.test(s)) {
        const key = k.id + '|' + s.slice(0, 120);
        if (!seen.has(key) && hits.filter((h) => h.id === k.id).length < 25) { seen.add(key); hits.push({ id: k.id, sev: k.sev, title: k.title, text: s.slice(0, 400) }); }
      }
    }
  }
  return { count: strings.length, truncated, hits, text: strings.join('\n') };
}
