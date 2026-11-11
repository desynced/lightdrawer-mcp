/* Minimal DER (ASN.1) reader/writer: enough for RFC 3161 and X.509. */
function derRead(buf, pos = 0) {
  const start = pos;
  const b0 = buf[pos++];
  if (b0 === undefined) throw new Error('DER: truncated');
  const cls = b0 >> 6, constructed = !!(b0 & 0x20);
  let tagNum = b0 & 0x1f;
  if (tagNum === 0x1f) { tagNum = 0; let c; do { c = buf[pos++]; tagNum = (tagNum << 7) | (c & 0x7f); } while (c & 0x80); }
  let len = buf[pos++];
  if (len & 0x80) { const n = len & 0x7f; if (n === 0 || n > 4) throw new Error('DER: bad length'); len = 0; for (let i = 0; i < n; i++) len = len * 256 + buf[pos++]; }
  const cs = pos, end = pos + len;
  if (end > buf.length) throw new Error('DER: length past end');
  const node = { tag: b0, cls, constructed, tagNum, start, cs, end, raw: buf.subarray(start, end), content: buf.subarray(cs, end) };
  if (constructed) { node.children = []; let p = cs; while (p < end) { const c = derRead(buf, p); node.children.push(c); p = c.end; } }
  return node;
}
function derParse(bytes) { const n = derRead(bytes, 0); return n; }
function derOid(node) {
  const c = node.content; const parts = [];
  const first = c[0]; parts.push(Math.floor(first / 40) > 2 ? 2 : Math.floor(first / 40)); parts.push(first - parts[0] * 40);
  let v = 0n;
  for (let i = 1; i < c.length; i++) { v = (v << 7n) | BigInt(c[i] & 0x7f); if (!(c[i] & 0x80)) { parts.push(v.toString()); v = 0n; } }
  return parts.join('.');
}
function derInt(node) { let v = 0n; for (const x of node.content) v = (v << 8n) | BigInt(x); if (node.content[0] & 0x80) v -= 1n << BigInt(node.content.length * 8); return v; }
function derTime(node) {
  const s = utf8dec(node.content);
  let m;
  if (node.tagNum === 23) { m = /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s); if (!m) throw new Error('bad UTCTime'); const y = +m[1] < 50 ? 2000 + +m[1] : 1900 + +m[1]; return new Date(Date.UTC(y, m[2] - 1, m[3], m[4], m[5], m[6])); }
  m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(?:\.(\d+))?Z$/.exec(s); if (!m) throw new Error('bad GeneralizedTime ' + s);
  const ms = m[7] ? Math.round(+('0.' + m[7]) * 1000) : 0;
  return new Date(Date.UTC(m[1], m[2] - 1, m[3], m[4], m[5], m[6], ms));
}
function derStr(node) { return utf8dec(node.content); }
/* encoders */
function derLen(n) { if (n < 0x80) return Uint8Array.of(n); const b = []; while (n > 0) { b.unshift(n & 0xff); n = Math.floor(n / 256); } return Uint8Array.of(0x80 | b.length, ...b); }
function derEnc(tag, content) { return concat(Uint8Array.of(tag), derLen(content.length), content); }
function derSeq(...items) { return derEnc(0x30, concat(...items)); }
function derNull() { return Uint8Array.of(5, 0); }
function derOctets(b) { return derEnc(0x04, b); }
function derBool(v) { return Uint8Array.of(1, 1, v ? 0xff : 0); }
function derIntBytes(b) { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.subarray(i); if (b[0] & 0x80) b = concat(Uint8Array.of(0), b); return derEnc(0x02, b); }
function derOidEnc(str) {
  const p = str.split('.').map((x) => BigInt(x)); const out = [Number(p[0] * 40n + p[1])];
  for (let i = 2; i < p.length; i++) { let v = p[i]; const t = [Number(v & 0x7fn)]; v >>= 7n; while (v > 0n) { t.unshift(Number(v & 0x7fn) | 0x80); v >>= 7n; } out.push(...t); }
  return derEnc(0x06, Uint8Array.from(out));
}
const OID = {
  sha1: '1.3.14.3.2.26', sha256: '2.16.840.1.101.3.4.2.1', sha384: '2.16.840.1.101.3.4.2.2', sha512: '2.16.840.1.101.3.4.2.3',
  rsaEncryption: '1.2.840.113549.1.1.1', sha256WithRSA: '1.2.840.113549.1.1.11', sha384WithRSA: '1.2.840.113549.1.1.12', sha512WithRSA: '1.2.840.113549.1.1.13',
  ecPublicKey: '1.2.840.10045.2.1', p256: '1.2.840.10045.3.1.7', p384: '1.3.132.0.34', p521: '1.3.132.0.35',
  ecdsaSha256: '1.2.840.10045.4.3.2', ecdsaSha384: '1.2.840.10045.4.3.3', ecdsaSha512: '1.2.840.10045.4.3.4',
  signedData: '1.2.840.113549.1.7.2', tstInfo: '1.2.840.113549.1.9.16.1.4', contentType: '1.2.840.113549.1.9.3', messageDigest: '1.2.840.113549.1.9.4',
  signingCertificate: '1.2.840.113549.1.9.16.2.12', signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
};
const HASH_BY_OID = { [OID.sha1]: 'SHA-1', [OID.sha256]: 'SHA-256', [OID.sha384]: 'SHA-384', [OID.sha512]: 'SHA-512' };
