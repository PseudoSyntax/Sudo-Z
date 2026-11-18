// Minimal PE reader: type, build time, and the embedded Authenticode signature
// (who signed it). The signature is located and its certificates read; the
// file hash inside it is not re-computed, so "signed" means "carries a
// signature", not "signature verified".

const le16 = (b, o) => b[o] | (b[o + 1] << 8);
const le32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

export const isPe = (u8) => u8.length > 0x40 && u8[0] === 0x4d && u8[1] === 0x5a && (() => { const o = le32(u8, 0x3c); return o + 4 < u8.length && u8[o] === 0x50 && u8[o + 1] === 0x45 && !u8[o + 2] && !u8[o + 3]; })();

// --- tiny DER walker
function tlv(b, o) {
  const tag = b[o]; let len = b[o + 1]; let h = 2;
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[o + 2 + i]; h = 2 + n; }
  return { tag, start: o + h, end: o + h + len, next: o + h + len };
}
function kids(b, t) { const out = []; let o = t.start; while (o < t.end && o < b.length) { const k = tlv(b, o); if (k.end > b.length) break; out.push(k); o = k.next; } return out; }
const U8 = new TextDecoder(); const U16BE = (u) => { let s = ''; for (let i = 0; i + 1 < u.length; i += 2) s += String.fromCharCode((u[i] << 8) | u[i + 1]); return s; };
function nameField(b, t, oid = '550403') { // CN by default; 55040a = O
  for (const set of kids(b, t)) for (const seq of kids(b, set)) {
    const [o, v] = kids(b, seq); if (!o || !v) continue;
    const hex = Array.from(b.subarray(o.start, o.end), (x) => x.toString(16).padStart(2, '0')).join('');
    if (hex === oid) return v.tag === 0x1e ? U16BE(b.subarray(v.start, v.end)) : U8.decode(b.subarray(v.start, v.end));
  }
  return '';
}

/** Certificates in a PKCS#7 SignedData blob: [{subject, issuer, org}] */
function certs(b) {
  try {
    const ci = tlv(b, 0); const [, ctx0] = kids(b, ci); if (!ctx0) return [];
    const sd = kids(b, ctx0)[0]; const parts = kids(b, sd);
    const certSet = parts.find((p) => p.tag === 0xa0); if (!certSet) return [];
    return kids(b, certSet).map((c) => {
      const tbs = kids(b, c)[0]; const f = kids(b, tbs); const i = f[0].tag === 0xa0 ? 1 : 0;
      const issuer = f[i + 2], subject = f[i + 4];
      return { subject: nameField(b, subject), issuer: nameField(b, issuer), org: nameField(b, subject, '55040a') };
    });
  } catch { return []; }
}

export function peInfo(u8) {
  const pe = le32(u8, 0x3c);
  const machine = le16(u8, pe + 4); const time = le32(u8, pe + 8); const chars = le16(u8, pe + 22);
  const opt = pe + 24; const magic = le16(u8, opt); const p64 = magic === 0x20b;
  const subsystem = le16(u8, opt + 68);
  const ddir = opt + (p64 ? 112 : 96);
  const certOff = le32(u8, ddir + 4 * 8), certLen = le32(u8, ddir + 4 * 8 + 4);
  const info = {
    machine: { 0x14c: 'x86', 0x8664: 'x64', 0xaa64: 'ARM64', 0x1c0: 'ARM' }[machine] || '0x' + machine.toString(16),
    compiled: time ? new Date(time * 1000).toISOString() : '',
    kind: subsystem === 1 ? 'driver' : chars & 0x2000 ? 'dll' : 'exe',
    signed: false, signer: '', issuer: '', org: '',
  };
  if (certOff && certLen > 8 && certOff + 8 <= u8.length) {
    info.signed = true;
    const type = le16(u8, certOff + 6);
    if (type === 2) {
      const list = certs(u8.subarray(certOff + 8, Math.min(u8.length, certOff + certLen)));
      const issuers = new Set(list.map((c) => c.issuer));
      const leaf = list.find((c) => c.subject && !issuers.has(c.subject) && !/time.?stamp|tsa\b|timestamping/i.test(c.subject)) || list.find((c) => !/time.?stamp/i.test(c.subject));
      if (leaf) { info.signer = leaf.subject; info.issuer = leaf.issuer; info.org = leaf.org; }
    }
  }
  return info;
}
