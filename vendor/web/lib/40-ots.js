/* OpenTimestamps: build, parse, serialize, upgrade, and check .ots proofs.
   Format reference: python-opentimestamps (core/serialize.py, timestamp.py, op.py). */
const OTS_MAGIC = Uint8Array.from([0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]);
const OTS_PENDING = '83dfe30d2ef90c8e', OTS_BITCOIN = '0588960d73d71901', OTS_LITECOIN = '06869a0d73d71b45', OTS_ETHEREUM = '30fe8087b5c7ead7';
const OTS_OPS = { 0x08: 'sha256', 0x02: 'sha1', 0x03: 'ripemd160', 0x67: 'keccak256', 0xf0: 'append', 0xf1: 'prepend', 0xf2: 'reverse', 0xf3: 'hexlify' };
const OTS_DEFAULT_CALENDARS = ['https://a.pool.opentimestamps.org', 'https://b.pool.opentimestamps.org', 'https://a.pool.eternitywall.com'];
class OtsReader {
  constructor(b) { this.b = b; this.p = 0; }
  byte() { if (this.p >= this.b.length) throw new Error('OTS: truncated'); return this.b[this.p++]; }
  bytes(n) { if (this.p + n > this.b.length) throw new Error('OTS: truncated'); const r = this.b.subarray(this.p, this.p + n); this.p += n; return r; }
  varuint() { let v = 0, s = 0, c; do { c = this.byte(); v += (c & 0x7f) * 2 ** s; s += 7; } while (c & 0x80); return v; }
  varbytes(max = 8192) { const n = this.varuint(); if (n > max) throw new Error('OTS: varbytes too long'); return this.bytes(n); }
}
function otsVaruint(n) { const o = []; do { let c = n % 128; n = Math.floor(n / 128); if (n) c |= 0x80; o.push(c); } while (n); return Uint8Array.from(o); }
function otsVarbytes(b) { return concat(otsVaruint(b.length), b); }
async function otsApply(op, arg, msg) {
  switch (op) {
    case 0x08: return sha256(msg);
    case 0x02: return sha1(msg);
    case 0x03: return ripemd160(msg);
    case 0xf0: return concat(msg, arg);
    case 0xf1: return concat(arg, msg);
    case 0xf2: return Uint8Array.from(msg).reverse();
    case 0xf3: return utf8(toHex(msg));
    default: throw new Error('OTS op not supported here: ' + (OTS_OPS[op] || op.toString(16)));
  }
}
/* node = { msg, atts: [{tag, payload}], ops: [{op, arg, node}] } */
async function otsReadTimestamp(r, msg, depth = 0) {
  if (depth > 256) throw new Error('OTS: too deep');
  const node = { msg, atts: [], ops: [] };
  const item = async (tag) => {
    if (tag === 0x00) { const t = toHex(r.bytes(8)); node.atts.push({ tag: t, payload: r.varbytes() }); }
    else {
      if (!OTS_OPS[tag]) throw new Error('OTS: unknown op 0x' + tag.toString(16));
      const arg = tag === 0xf0 || tag === 0xf1 ? r.varbytes(4096) : null;
      const next = await otsApply(tag, arg, msg);
      node.ops.push({ op: tag, arg, node: await otsReadTimestamp(r, next, depth + 1) });
    }
  };
  let tag = r.byte();
  while (tag === 0xff) { await item(r.byte()); tag = r.byte(); }
  await item(tag);
  return node;
}
function otsWriteTimestamp(node) {
  const items = [];
  const atts = node.atts.slice().sort((a, b) => (a.tag + toHex(a.payload)).localeCompare(b.tag + toHex(b.payload)));
  for (const a of atts) items.push(concat(Uint8Array.of(0), fromHex(a.tag), otsVarbytes(a.payload)));
  for (const o of node.ops) items.push(concat(Uint8Array.of(o.op), o.arg ? otsVarbytes(o.arg) : new Uint8Array(0), otsWriteTimestamp(o.node)));
  const out = []; items.forEach((it, i) => { if (i < items.length - 1) out.push(Uint8Array.of(0xff)); out.push(it); });
  return concat(...out);
}
async function otsParseDetached(bytes) {
  const r = new OtsReader(bytes);
  if (!bytesEq(r.bytes(OTS_MAGIC.length), OTS_MAGIC)) throw new Error('not an OpenTimestamps proof (bad magic)');
  const ver = r.varuint(); if (ver !== 1) throw new Error('unsupported .ots version ' + ver);
  const hashOp = r.byte(); if (hashOp !== 0x08) throw new Error('only SHA-256 detached proofs are supported, got ' + (OTS_OPS[hashOp] || hashOp));
  const d = Uint8Array.from(r.bytes(32));
  const root = await otsReadTimestamp(r, d);
  if (r.p !== bytes.length) throw new Error('OTS: trailing bytes');
  return { digest: d, root };
}
function otsSerializeDetached(digestBytes, root) { return concat(OTS_MAGIC, otsVaruint(1), Uint8Array.of(0x08), digestBytes, otsWriteTimestamp(root)); }
function otsMerge(into, from) {
  for (const a of from.atts) if (!into.atts.some((x) => x.tag === a.tag && bytesEq(x.payload, a.payload))) into.atts.push(a);
  for (const o of from.ops) {
    const ex = into.ops.find((x) => x.op === o.op && bytesEq(x.arg || new Uint8Array(0), o.arg || new Uint8Array(0)));
    if (ex) otsMerge(ex.node, o.node); else into.ops.push(o);
  }
}
/* Parse a calendar response (a timestamp that starts at `msg`). */
async function otsParseCalendarResponse(bytes, msg) { const r = new OtsReader(bytes); const n = await otsReadTimestamp(r, msg); return n; }
function otsWalk(node, fn, path = []) { fn(node, path); for (const o of node.ops) otsWalk(o.node, fn, path.concat(o)); }
function otsAttestations(root) {
  const out = [];
  otsWalk(root, (n) => { for (const a of n.atts) {
    const r = new OtsReader(a.payload); let info;
    if (a.tag === OTS_PENDING) info = { kind: 'pending', uri: utf8dec(r.varbytes(1000)) };
    else if (a.tag === OTS_BITCOIN) info = { kind: 'bitcoin', height: r.varuint() };
    else if (a.tag === OTS_LITECOIN) info = { kind: 'litecoin', height: r.varuint() };
    else if (a.tag === OTS_ETHEREUM) info = { kind: 'ethereum', height: r.varuint() };
    else info = { kind: 'unknown', tag: a.tag };
    out.push(Object.assign(info, { msg: n.msg, node: n, att: a }));
  } });
  return out;
}
function otsCalendarAllowed(uri) { return /^https:\/\/[a-z0-9.-]+(:\d+)?$/i.test(uri) && /(opentimestamps\.org|eternitywall\.com|catallaxy\.com)$/i.test(new URL(uri).hostname); }
/* Upgrade pending attestations. fetchUpgrade(calendarUri, commitmentHex) -> Uint8Array|null */
async function otsUpgrade(root, fetchUpgrade) {
  const report = [];
  for (const a of otsAttestations(root).filter((x) => x.kind === 'pending')) {
    if (!otsCalendarAllowed(a.uri)) { report.push({ uri: a.uri, status: 'refused (calendar not on allowlist)' }); continue; }
    try {
      const resp = await fetchUpgrade(a.uri, toHex(a.msg));
      if (!resp) { report.push({ uri: a.uri, status: 'still pending' }); continue; }
      const sub = await otsParseCalendarResponse(resp, a.msg);
      const complete = otsAttestations(sub).some((x) => x.kind === 'bitcoin');
      otsMerge(a.node, sub);
      if (complete) a.node.atts = a.node.atts.filter((x) => x !== a.att);
      report.push({ uri: a.uri, status: complete ? 'upgraded: Bitcoin attestation added' : 'calendar answered, not yet in Bitcoin' });
    } catch (e) { report.push({ uri: a.uri, status: 'error: ' + e.message }); }
  }
  return report;
}
/* Verify. lookupBlock(height) -> { merkleRootHex (RPC/display byte order), time } or null when offline. */
async function otsVerify(otsBytes, expectedDigest, lookupBlock) {
  const checks = [];
  let p;
  try { p = await otsParseDetached(otsBytes); } catch (e) { return { checks: [chk('ots.parse', 'fail', 'OpenTimestamps proof could not be read', e.message)] }; }
  checks.push(chk('ots.digest', bytesEq(p.digest, expectedDigest) ? 'pass' : 'fail', 'OpenTimestamps proof is for this statement hash', toHex(p.digest)));
  const atts = otsAttestations(p.root);
  const pend = atts.filter((a) => a.kind === 'pending'), btc = atts.filter((a) => a.kind === 'bitcoin');
  let earliest = null;
  for (const a of btc) {
    if (!lookupBlock) { checks.push(chk('ots.btc.' + a.height, 'info', `Claims Bitcoin block ${a.height}`, 'Not checked offline. Enable online checks, or run: ots verify statement.json.ots')); continue; }
    try {
      const blk = await lookupBlock(a.height);
      const ok = blk && toHex(Uint8Array.from(a.msg).reverse()) === blk.merkleRootHex;
      checks.push(chk('ots.btc.' + a.height, ok ? 'pass' : 'fail', `Bitcoin block ${a.height} commits to this hash`, blk ? `block time ${new Date(blk.time * 1000).toISOString()} (explorer: ${blk.source})` : 'block not found'));
      if (ok && (!earliest || blk.time < earliest.time)) earliest = { height: a.height, time: blk.time };
    } catch (e) { checks.push(chk('ots.btc.' + a.height, 'warn', `Could not look up Bitcoin block ${a.height}`, e.message)); }
  }
  if (!btc.length) checks.push(chk('ots.pending', pend.length ? 'warn' : 'fail', pend.length ? 'OpenTimestamps proof is still pending (not yet in Bitcoin)' : 'No attestations in OpenTimestamps proof',
    pend.length ? `Calendars: ${pend.map((a) => a.uri).join(', ')}. Usually confirms in ~1–6 hours; then upgrade the proof.` : ''));
  else if (pend.length) checks.push(chk('ots.pendingOther', 'info', 'Some calendar branches are still pending', pend.map((a) => a.uri).join(', ')));
  return { checks, earliest, pending: pend.map((a) => a.uri), bitcoinHeights: btc.map((a) => a.height), parsed: p };
}
/* Block lookup using public Esplora APIs (CORS-enabled). Two explorers must agree when both answer. */
async function otsEsploraLookup(height, fetchFn = fetch) {
  const bases = ['https://blockstream.info/api', 'https://mempool.space/api'];
  const results = [];
  for (const base of bases) {
    try {
      const h = (await (await fetchFn(`${base}/block-height/${height}`)).text()).trim();
      if (!/^[0-9a-f]{64}$/.test(h)) continue;
      const j = await (await fetchFn(`${base}/block/${h}`)).json();
      results.push({ merkleRootHex: j.merkle_root, time: j.timestamp, source: new URL(base).hostname });
    } catch (e) { /* next */ }
  }
  if (!results.length) throw new Error('no block explorer reachable');
  if (results.length > 1 && results[0].merkleRootHex !== results[1].merkleRootHex) throw new Error('explorers disagree');
  return Object.assign(results[0], { source: results.map((r) => r.source).join(' + ') });
}
