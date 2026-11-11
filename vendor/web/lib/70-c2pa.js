/* Read-only C2PA (Content Credentials) inspection. Finds the JUMBF manifest store,
   decodes the active claim (CBOR) and the signer certificate name. It does NOT
   validate C2PA signatures, hash bindings, or trust lists. Use c2patool or
   https://contentcredentials.org/verify for full validation. */
function cborDecode(b) {
  let p = 0;
  const u = (n) => { let v = 0; for (let i = 0; i < n; i++) v = v * 256 + b[p++]; return v; };
  const len = (ai) => (ai < 24 ? ai : ai === 24 ? u(1) : ai === 25 ? u(2) : ai === 26 ? u(4) : ai === 27 ? u(8) : ai === 31 ? -1 : (() => { throw new Error('CBOR: bad length'); })());
  const item = (depth) => {
    if (depth > 64) throw new Error('CBOR: too deep');
    if (p >= b.length) throw new Error('CBOR: truncated');
    const ib = b[p++], mt = ib >> 5, ai = ib & 31;
    if (mt === 7) {
      if (ai === 20) return false; if (ai === 21) return true; if (ai === 22 || ai === 23) return null;
      if (ai === 25) { const h = u(2); const e = (h >> 10) & 31, f = h & 1023; const v = e === 0 ? f * 2 ** -24 : e === 31 ? (f ? NaN : Infinity) : (1 + f / 1024) * 2 ** (e - 15); return h & 0x8000 ? -v : v; }
      if (ai === 26) { const v = new DataView(b.buffer, b.byteOffset + p, 4).getFloat32(0); p += 4; return v; }
      if (ai === 27) { const v = new DataView(b.buffer, b.byteOffset + p, 8).getFloat64(0); p += 8; return v; }
      if (ai === 31) return Symbol.for('break');
      return undefined;
    }
    const n = len(ai);
    switch (mt) {
      case 0: return n; case 1: return -1 - n;
      case 2: case 3: {
        if (n < 0) { const chunks = []; for (;;) { const c = item(depth + 1); if (c === Symbol.for('break')) break; chunks.push(typeof c === 'string' ? utf8(c) : c); } const all = concat(...chunks); return mt === 2 ? all : utf8dec(all); }
        const s = b.subarray(p, p + n); p += n; return mt === 2 ? s : utf8dec(s);
      }
      case 4: { const a = []; if (n < 0) { for (;;) { const v = item(depth + 1); if (v === Symbol.for('break')) break; a.push(v); } } else for (let i = 0; i < n; i++) a.push(item(depth + 1)); return a; }
      case 5: { const m = new Map(); const add = () => { const k = item(depth + 1); if (k === Symbol.for('break')) return false; m.set(k, item(depth + 1)); return true; }; if (n < 0) { while (add()); } else for (let i = 0; i < n; i++) add(); return m; }
      case 6: return { tag: n, value: item(depth + 1) };
    }
  };
  return item(0);
}
function cborToPlain(v, depth = 0) {
  if (depth > 12) return '…';
  if (v instanceof Map) { const o = {}; for (const [k, x] of v) o[String(k)] = cborToPlain(x, depth + 1); return o; }
  if (Array.isArray(v)) return v.map((x) => cborToPlain(x, depth + 1));
  if (v instanceof Uint8Array) return `<${v.length} bytes>`;
  if (v && typeof v === 'object' && 'tag' in v) return cborToPlain(v.value, depth + 1);
  return v;
}
function jumbfBoxes(b, start = 0, end = b.length) {
  const out = []; let p = start;
  while (p + 8 <= end) {
    const dv = new DataView(b.buffer, b.byteOffset + p);
    let size = dv.getUint32(0); const type = String.fromCharCode(b[p + 4], b[p + 5], b[p + 6], b[p + 7]); let hdr = 8;
    if (size === 1) { size = Number(dv.getBigUint64(8)); hdr = 16; } else if (size === 0) size = end - p;
    if (size < hdr || p + size > end) break;
    const box = { type, start: p, cs: p + hdr, end: p + size };
    if (type === 'jumb') {
      box.children = jumbfBoxes(b, box.cs, box.end);
      const d = box.children[0];
      if (d && d.type === 'jumd') { const toggles = b[d.cs + 16]; box.uuid = toHex(b.subarray(d.cs, d.cs + 16)); if (toggles & 2) { let q = d.cs + 17; let s = q; while (q < d.end && b[q] !== 0) q++; box.label = utf8dec(b.subarray(s, q)); } }
    }
    out.push(box); p += size;
  }
  return out;
}
function c2paExtractStore(b) {
  // JPEG: APP11 segments carrying JUMBF (ISO 19566-5)
  if (b[0] === 0xff && b[1] === 0xd8) {
    const groups = {}; let p = 2;
    while (p + 4 < b.length && b[p] === 0xff) {
      const m = b[p + 1]; if (m === 0xda || m === 0xd9) break;
      const L = (b[p + 2] << 8) | b[p + 3]; const seg = b.subarray(p + 4, p + 2 + L);
      if (m === 0xeb && seg[0] === 0x4a && seg[1] === 0x50) {
        const en = (seg[2] << 8) | seg[3]; const z = new DataView(seg.buffer, seg.byteOffset + 4).getUint32(0);
        let payload = seg.subarray(8); if (z > 1) { const lbox = new DataView(payload.buffer, payload.byteOffset).getUint32(0); payload = payload.subarray(lbox === 1 ? 16 : 8); }
        (groups[en] = groups[en] || []).push({ z, payload });
      }
      p += 2 + L;
    }
    for (const en of Object.keys(groups)) { const data = concat(...groups[en].sort((a, b2) => a.z - b2.z).map((x) => x.payload)); const boxes = jumbfBoxes(data); if (boxes[0] && boxes[0].label === 'c2pa') return { container: 'JPEG APP11', data, box: boxes[0] }; }
  }
  // PNG: caBX chunk
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) {
    let p = 8;
    while (p + 12 <= b.length) {
      const L = new DataView(b.buffer, b.byteOffset + p).getUint32(0); const t = utf8dec(b.subarray(p + 4, p + 8));
      if (t === 'caBX') { const data = b.subarray(p + 8, p + 8 + L); const boxes = jumbfBoxes(data); if (boxes[0] && boxes[0].label === 'c2pa') return { container: 'PNG caBX', data, box: boxes[0] }; }
      p += 12 + L;
    }
  }
  // Fallback (BMFF/RIFF/PDF/etc.): look for a 'jumb' box whose description label is 'c2pa'
  const pat = utf8('jumb');
  for (let i = 4; i + 40 < b.length; i++) {
    if (b[i] !== pat[0] || b[i + 1] !== pat[1] || b[i + 2] !== pat[2] || b[i + 3] !== pat[3]) continue;
    const s = i - 4; const boxes = jumbfBoxes(b, s, b.length);
    if (boxes[0] && boxes[0].label === 'c2pa') return { container: 'embedded JUMBF', data: b, box: boxes[0] };
  }
  return null;
}
function c2paInspect(fileBytes) {
  const store = c2paExtractStore(fileBytes);
  if (!store) return { present: false };
  const b = store.data; const manifests = store.box.children.filter((x) => x.type === 'jumb');
  const read = (m) => {
    const sub = Object.fromEntries((m.children || []).filter((x) => x.type === 'jumb').map((x) => [x.label, x]));
    const claimBox = sub['c2pa.claim.v2'] || sub['c2pa.claim'];
    const out = { label: m.label, assertions: sub['c2pa.assertions'] ? sub['c2pa.assertions'].children.filter((x) => x.type === 'jumb').map((x) => x.label) : [] };
    try {
      const cb = claimBox.children.find((x) => x.type === 'cbor');
      const c = cborToPlain(cborDecode(b.subarray(cb.cs, cb.end)));
      out.claimVersion = sub['c2pa.claim.v2'] ? 2 : 1;
      out.generator = c.claim_generator || (Array.isArray(c.claim_generator_info) ? c.claim_generator_info.map((g) => [g.name, g.version].filter(Boolean).join(' ')).join(', ') : c.claim_generator_info && c.claim_generator_info.name) || null;
      out.title = c['dc:title'] || null; out.format = c['dc:format'] || null; out.instanceID = c.instanceID || null;
    } catch (e) { out.claimError = e.message; }
    try {
      const sb = sub['c2pa.signature'].children.find((x) => x.type === 'cbor');
      let cose = cborDecode(b.subarray(sb.cs, sb.end)); if (cose && cose.tag === 18) cose = cose.value;
      const prot = cose[0] && cose[0].length ? cborDecode(cose[0]) : new Map(); const unprot = cose[1] || new Map();
      let x5 = prot.get(33) || unprot.get(33) || unprot.get('x5chain'); if (Array.isArray(x5)) x5 = x5[0];
      if (x5 instanceof Uint8Array) { const cert = x509Parse(x5); out.signer = cert.subject; out.signerIssuer = cert.issuer; out.signerValidity = `${cert.notBefore.toISOString().slice(0, 10)} – ${cert.notAfter.toISOString().slice(0, 10)}`; }
      out.hasTimestamp = !!(unprot.get && (unprot.get('sigTst') || unprot.get('sigTst2')));
    } catch (e) { out.signatureError = e.message; }
    return out;
  };
  const list = manifests.map(read);
  return { present: true, container: store.container, manifestCount: list.length, active: list[list.length - 1], manifests: list, validated: false };
}
function c2paChecks(info) {
  if (!info) return [chk('c2pa', 'skip', 'C2PA: original file not supplied', '')];
  if (!info.present) return [chk('c2pa', 'info', 'No C2PA Content Credentials found in the file', 'Absence proves nothing; most files have none, and many platforms strip them.')];
  const a = info.active || {};
  return [
    chk('c2pa', 'info', `C2PA Content Credentials present (${info.manifestCount} manifest${info.manifestCount === 1 ? '' : 's'}, ${info.container})`,
      [a.generator && `Made with: ${a.generator}`, a.title && `Title: ${a.title}`, a.signer && `Signed by (as claimed in cert): ${a.signer}`, a.signerIssuer && `Cert issuer: ${a.signerIssuer}`, a.assertions && a.assertions.length && `Assertions: ${a.assertions.join(', ')}`].filter(Boolean).join(' · ')),
    chk('c2pa.validation', 'warn', 'C2PA signatures were read, not validated', 'LightDrawer only reads Content Credentials. Validate with c2patool or contentcredentials.org/verify.'),
  ];
}

/* Read Content Credentials from a File/Blob without loading the whole file.
   JPEG APP11, PNG caBX, and a generic JUMBF scan almost always live near the
   start, so only the first C2PA_HEAD_BYTES (16 MiB) are read. */
async function c2paInspectSource(source) {
  let bytes, scannedAll = true;
  if (source instanceof Uint8Array) bytes = source;
  else if (source && typeof source.slice === 'function') {
    const n = Math.min(source.size, C2PA_HEAD_BYTES);
    scannedAll = source.size <= C2PA_HEAD_BYTES;
    bytes = new Uint8Array(await source.slice(0, n).arrayBuffer());
  } else throw new Error('c2paInspectSource: expected a File, Blob, or Uint8Array');
  const info = c2paInspect(bytes);
  if (!scannedAll && !info.present) info.note = 'Looked at the first ' + formatBytes(C2PA_HEAD_BYTES) + ' only; a Content Credentials store later in the file would not be seen.';
  return info;
}
