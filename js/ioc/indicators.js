// Atomic indicator extraction (IPs, domains, URLs, emails, hashes, UNC paths,
// encoded PowerShell). Shared by bstrings and every artifact parser so a URL in
// an event log and a URL in a jump list land in the same indicator table.

export const RX = {
  url: /\b(?:https?|ftp|hxxps?):\/\/[^\s"'<>`\\|^{}]{3,2048}/gi,
  ipv4: /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])/g,
  email: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g,
  unc: /\\\\[A-Za-z0-9._$-]{1,64}\\[A-Za-z0-9._$ -]{1,80}(?:\\[^\s\\"'<>|*?]{1,200})*/g,
  domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|co|me|cc|tk|ml|ga|cf|gq|pw|su|onion|online|site|club|live|app|dev|cloud|link|in|us|uk|de|fr|br|ir|kp)\b/gi,
  md5: /\b[a-f0-9]{32}\b/gi,
  sha1: /\b[a-f0-9]{40}\b/gi,
  sha256: /\b[a-f0-9]{64}\b/gi,
  btc: /\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g,
  encPs: /-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+([A-Za-z0-9+/=]{20,})/gi,
};

// Domains we never report on their own (noise from Windows artifacts).
const BENIGN_DOMAINS = /(^|\.)(microsoft\.com|microsoft\.net|windows\.net|windows\.com|msftconnecttest\.com|live\.net|aka\.ms|windowsupdate\.com|msftncsi\.com|office\.com|office365\.com|live\.com|bing\.com|msn\.com|skype\.com|azure\.com|azureedge\.net|msedge\.net|akamaitechnologies\.com|akamaiedge\.net|digicert\.com|verisign\.com|symantec\.com|google\.com|gstatic\.com|googleapis\.com|mozilla\.org|mozilla\.com|w3\.org|xmlsoap\.org|adobe\.com|apple\.com|schemas\.microsoft\.com|sectigo\.com|globalsign\.com|entrust\.net|usertrust\.com|comodoca\.com|letsencrypt\.org|thawte\.com|geotrust\.com|openxmlformats\.org|purl\.org|ns\.adobe\.com)$/i;
const FILE_EXT_TLD = /\.(exe|dll|sys|com|bat|cmd|ps1|vbs|js|jse|lnk|tmp|log|dat|ini|xml|txt|zip|rar|7z|pf|evtx|db|in|me|io|co)$/i;

export function isPrivateIp(ip) {
  const p = ip.split('.').map(Number);
  return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || p[0] >= 224 || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
    ip === '255.255.255.255';
}

function looksLikeVersion(ip, ctx) {
  // 6.1.7601.17514 style version strings produce false IPs
  const p = ip.split('.').map(Number);
  if (p[0] < 1) return true;
  if (ctx && /\d\.\d+\.\d+\.\d+\.\d/.test(ctx)) return true;
  return false;
}

/** Collects indicators into a shared store keyed by type+value. */
export class IndicatorStore {
  constructor() { this.map = new Map(); }
  add(type, value, source, context = '') {
    if (!value) return;
    value = String(value).trim().replace(/[).,;'"\]]+$/, '');
    if (!value || value.length > 2100) return;
    const key = `${type}|${value.toLowerCase()}`;
    let e = this.map.get(key);
    if (!e) { e = { type, value, count: 0, sources: new Set(), context: context.slice(0, 300) }; this.map.set(key, e); }
    e.count++;
    if (source) e.sources.add(source);
  }
  list() {
    return [...this.map.values()].map((e) => ({ ...e, sources: [...e.sources] }))
      .sort((a, b) => a.type.localeCompare(b.type) || b.count - a.count);
  }
}

/** Scan arbitrary text and add atomic indicators. */
export function extractFromText(text, store, source, { hashes = false } = {}) {
  if (!text || text.length < 6) return;
  for (const m of text.matchAll(RX.url)) {
    const u = m[0];
    store.add('url', u, source, text.slice(Math.max(0, m.index - 60), m.index + 160));
    const host = u.replace(/^[a-z]+:\/\//i, '').split(/[/:?#]/)[0].toLowerCase();
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) { if (!isPrivateIp(host)) store.add('ipv4', host, source, u); }
    else if (host.includes('.') && !BENIGN_DOMAINS.test(host)) store.add('domain', host, source, u);
  }
  for (const m of text.matchAll(RX.ipv4)) {
    const ip = m[0];
    const ctx = text.slice(Math.max(0, m.index - 12), m.index + ip.length + 12);
    if (!isPrivateIp(ip) && !looksLikeVersion(ip, ctx)) store.add('ipv4', ip, source, text.slice(Math.max(0, m.index - 80), m.index + 80));
  }
  for (const m of text.matchAll(RX.email)) {
    if (!/\.(png|jpg|gif|dll|exe)$/i.test(m[0])) store.add('email', m[0], source);
  }
  for (const m of text.matchAll(RX.unc)) {
    if (!/^\\\\\?\\|^\\\\\.\\/.test(m[0])) store.add('unc', m[0], source);
  }
  for (const m of text.matchAll(RX.encPs)) {
    const dec = decodePsB64(m[1]);
    store.add('encoded_powershell', m[1].slice(0, 120) + (m[1].length > 120 ? '…' : ''), source, dec ? dec.slice(0, 300) : '');
    if (dec) extractFromText(dec, store, source + ' (decoded -enc)');
  }
  for (const m of text.matchAll(RX.btc)) {
    if (/^(bc1|[13])/.test(m[0]) && /[a-z]/.test(m[0]) && /[A-Z0-9]/.test(m[0]) && m[0].length >= 26) {
      // low confidence, only keep near wallet wording
      const ctx = text.slice(Math.max(0, m.index - 80), m.index).toLowerCase();
      if (/bitcoin|btc|wallet|ransom|pay/.test(ctx)) store.add('btc_wallet', m[0], source);
    }
  }
  if (hashes) {
    for (const m of text.matchAll(RX.sha256)) store.add('sha256', m[0].toLowerCase(), source);
  }
}

/** Domain scan is separate because it is noisy; used on command lines and URLs only. */
export function extractDomains(text, store, source) {
  if (!text) return;
  for (const m of text.matchAll(RX.domain)) {
    const d = m[0].toLowerCase();
    if (BENIGN_DOMAINS.test(d) || FILE_EXT_TLD.test(d) && !/\.(io|co|in|me)$/.test(d)) continue;
    store.add('domain', d, source, text.slice(Math.max(0, m.index - 60), m.index + 100));
  }
}

export function decodePsB64(b64) {
  try {
    const bin = atob(b64.replace(/[^A-Za-z0-9+/=]/g, ''));
    const u8 = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    // PowerShell -enc is UTF-16LE
    let zeros = 0; for (let i = 1; i < Math.min(u8.length, 200); i += 2) if (u8[i] === 0) zeros++;
    const txt = zeros > Math.min(u8.length, 200) / 4 ? new TextDecoder('utf-16le').decode(u8) : new TextDecoder().decode(u8);
    return /[\x20-\x7e]{6,}/.test(txt) ? txt : null;
  } catch { return null; }
}
