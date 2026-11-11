/* LightDrawer receipt core: shared helpers. Plain script (no modules) so the
   offline verifier can inline everything into one HTML file. */
'use strict';
const LD_VERSION = '0.1.0';
const _te = new TextEncoder();
const _td = new TextDecoder('utf-8', { fatal: false });
function utf8(s) { return _te.encode(s); }
function utf8dec(b) { return _td.decode(b); }
function toHex(b) { return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(''); }
function fromHex(h) {
  h = h.trim().toLowerCase();
  if (h.length % 2 || /[^0-9a-f]/.test(h)) throw new Error('bad hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function toB64(b) { let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000)); return btoa(s); }
function fromB64(s) { const bin = atob(s.replace(/\s+/g, '')); const o = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) o[i] = bin.charCodeAt(i); return o; }
function concat(...arrs) { let n = 0; for (const a of arrs) n += a.length; const o = new Uint8Array(n); let p = 0; for (const a of arrs) { o.set(a, p); p += a.length; } return o; }
function bytesEq(a, b) { if (!a || !b || a.length !== b.length) return false; for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; }
async function digest(alg, data) { return new Uint8Array(await crypto.subtle.digest(alg, data)); }
const sha256 = (d) => digest('SHA-256', d);
const sha1 = (d) => digest('SHA-1', d);
function pemToDer(pem) { return fromB64(pem.replace(/-----(BEGIN|END)[^-]+-----/g, '').replace(/\s+/g, '')); }
function derToPem(der, label) { const b = toB64(der).replace(/(.{64})/g, '$1\n'); return `-----BEGIN ${label}-----\n${b.trim()}\n-----END ${label}-----\n`; }
function escHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
/* check record used by every verifier step: status = pass | fail | warn | info | skip */
function chk(id, status, title, detail) { return { id, status, title, detail: detail || '' }; }
