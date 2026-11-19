// VirusTotal lookups, one item at a time, only when the analyst clicks.
//
// Sudo-Z's whole point is that nothing leaves the machine, so this is the one place
// that breaks it and it has to be deliberate every time:
//   * nothing is ever sent automatically, in bulk, or on page load
//   * one click sends one value: a hash, a domain, an IP or a URL
//   * files are never uploaded, only their hash is sent (a hash lookup tells VirusTotal
//     you hold a file with that hash, which is itself worth thinking about on a real case)
//   * the API key lives in this browser's localStorage and is never written into a
//     report, an export or an artifact
//
// Without a key there is still a button: it opens the VirusTotal page for the value in a
// new tab, so the lookup happens in the analyst's own browser session and Sudo-Z sends
// nothing at all.

const API = 'https://www.virustotal.com/api/v3';
const KEY = 'sudoz.vt.key';

export const getKey = () => { try { return localStorage.getItem(KEY) || ''; } catch { return ''; } };
export const setKey = (k) => { try { k ? localStorage.setItem(KEY, k.trim()) : localStorage.removeItem(KEY); return true; } catch { return false; } };

export const isHash = (v) => /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(String(v || '').trim());
export const isIp = (v) => /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(String(v || '').trim());
export const isDomain = (v) => /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i.test(String(v || '').trim());
export const isUrl = (v) => /^[a-z][a-z0-9+.-]*:\/\//i.test(String(v || '').trim());

/** Undo the defanging Sudo-Z does for display, so a copied indicator still looks up. */
export const refang = (v) => String(v || '').trim()
  .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.').replace(/\[:\]/g, ':').replace(/^h(xx|XX)p/, 'http').replace(/\[@\]|\(at\)/gi, '@');

/** The VirusTotal page for anything at all: exact pages where we can, search where we cannot. */
export function guiUrl(value) {
  const k = kindOf(value);
  if (k) return k.gui;
  const v = refang(value).trim();
  return v ? `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}` : '';
}

/** What kind of thing is this, and where does it live on VirusTotal? */
export function kindOf(value) {
  const v = refang(value);
  if (isHash(v)) return { kind: 'file', path: `files/${v}`, gui: `https://www.virustotal.com/gui/file/${v}`, value: v };
  if (isIp(v)) return { kind: 'ip_address', path: `ip_addresses/${v}`, gui: `https://www.virustotal.com/gui/ip-address/${v}`, value: v };
  if (isUrl(v)) { const id = b64url(v); return { kind: 'url', path: `urls/${id}`, gui: `https://www.virustotal.com/gui/url/${id}`, value: v }; }
  if (isDomain(v)) return { kind: 'domain', path: `domains/${v}`, gui: `https://www.virustotal.com/gui/domain/${v}`, value: v };
  return null;
}
// VirusTotal identifies a URL by its unpadded base64url
function b64url(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = ''; for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const n = (v) => (typeof v === 'number' ? v : 0);

/** Pull the parts worth showing out of a v3 response. */
export function summarise(kind, data) {
  const a = data?.data?.attributes || {};
  const st = a.last_analysis_stats || {};
  const out = {
    kind,
    malicious: n(st.malicious), suspicious: n(st.suspicious), undetected: n(st.undetected), harmless: n(st.harmless), timeout: n(st.timeout),
    reputation: a.reputation, firstSeen: iso(a.first_submission_date || a.creation_date), lastSeen: iso(a.last_analysis_date || a.last_modification_date),
    names: (a.names || []).slice(0, 8), label: a.popular_threat_classification?.suggested_threat_label || '',
    families: (a.popular_threat_classification?.popular_threat_name || []).map((x) => x.value).slice(0, 5),
    tags: (a.tags || []).slice(0, 10), size: a.size, type: a.type_description || a.type_tag,
    engines: Object.entries(a.last_analysis_results || {}).filter(([, r]) => r && (r.category === 'malicious' || r.category === 'suspicious'))
      .map(([e, r]) => `${e}: ${r.result}`).slice(0, 12),
  };
  out.total = out.malicious + out.suspicious + out.undetected + out.harmless + out.timeout;
  if (kind === 'file') {
    const pe = a.pe_info || {};
    out.hashes = [['MD5', a.md5], ['SHA1', a.sha1], ['SHA256', a.sha256], ['Vhash', a.vhash], ['Authentihash', a.authentihash],
      ['Imphash', pe.imphash], ['Rich PE header hash', pe.rich_pe_header_hash], ['SSDEEP', a.ssdeep], ['TLSH', a.tlsh]]
      .filter(([, v]) => v).map(([k, v]) => [k, String(v)]);
    out.signer = a.signature_info?.['signers'] || '';
    out.product = a.signature_info?.product || '';
  }
  if (kind === 'domain' || kind === 'ip_address') {
    out.registrar = a.registrar || ''; out.asOwner = a.as_owner || ''; out.country = a.country || '';
    out.categories = Object.entries(a.categories || {}).map(([k, v]) => `${k}: ${v}`).slice(0, 6);
  }
  return out;
}
const iso = (sec) => (sec ? new Date(sec * 1000).toISOString().replace('T', ' ').slice(0, 19) : '');

/** critical / high / medium / clean, from the engine counts */
export function verdict(s) {
  if (!s || !s.total) return { sev: 'info', text: 'not in VirusTotal' };
  const bad = s.malicious + s.suspicious;
  if (s.malicious >= 10) return { sev: 'critical', text: `${s.malicious}/${s.total} malicious` };
  if (s.malicious >= 3) return { sev: 'high', text: `${s.malicious}/${s.total} malicious` };
  if (bad >= 1) return { sev: 'medium', text: `${s.malicious} malicious, ${s.suspicious} suspicious of ${s.total}` };
  return { sev: 'low', text: `clean, ${s.total} engines` };
}

/**
 * One lookup. Tries the browser first; if the browser cannot reach VirusTotal (CORS on a
 * static site, a blocked network), falls back to the home server when one is running.
 * @returns {{ok, summary, error, via}}
 */
export async function lookup(value, { key = getKey(), local = false, signal } = {}) {
  const k = kindOf(value);
  if (!k) return { ok: false, error: 'not a hash, domain, IP or URL' };
  if (!key) return { ok: false, error: 'no API key', gui: k.gui };
  const direct = async () => {
    const res = await fetch(`${API}/${k.path}`, { headers: { 'x-apikey': key, accept: 'application/json' }, signal });
    if (res.status === 404) return { ok: true, summary: null, notFound: true, via: 'browser', gui: k.gui };
    if (res.status === 401) throw new Error('VirusTotal rejected the API key');
    if (res.status === 429) throw new Error('VirusTotal rate limit reached (the free key allows 4 lookups a minute)');
    if (!res.ok) throw new Error(`VirusTotal returned ${res.status}`);
    return { ok: true, summary: summarise(k.kind, await res.json()), via: 'browser', gui: k.gui };
  };
  const viaServer = async () => {
    const res = await fetch('/api/vt/lookup', {
      method: 'POST', headers: { 'content-type': 'application/json', 'X-Sudo-Z': '1' },
      body: JSON.stringify({ path: k.path, key }), signal,
    });
    const j = await res.json();
    if (j.error) throw new Error(j.error);
    if (j.notFound) return { ok: true, summary: null, notFound: true, via: 'home server', gui: k.gui };
    return { ok: true, summary: summarise(k.kind, j.data), via: 'home server', gui: k.gui };
  };
  try { return await direct(); }
  catch (e) {
    if (e.name === 'AbortError') return { ok: false, error: 'cancelled', gui: k.gui };
    // a CORS or network failure gives a TypeError with no status; anything else is a real answer
    if (local && e instanceof TypeError) { try { return await viaServer(); } catch (e2) { return { ok: false, error: e2.message, gui: k.gui }; } }
    return { ok: false, error: e instanceof TypeError ? 'the browser could not reach VirusTotal (its API blocks cross-origin calls from a static site). Use the home install, or open the VirusTotal page instead.' : e.message, gui: k.gui };
  }
}
