/* Certificate Transparency (CT) extra witness.
   Digests collected in time-window sub-batches are Merkle-tree'd (RFC 6962).
   Each sub-batch root R is encoded as a DNS name:
     <first 32 hex chars of R>.<last 32 hex chars of R>.ct.lightdrawer.org
   A later certificate covering up to 100 of those names is the public witness
   (its SCTs / CT-log entries). This file is the shared browser + script logic.
   Hostname choice: two hex labels (32 + 32) instead of a single base32 label.
   Hex matches the fingerprints already shown in the UI, each label is well under
   the 63-character DNS limit, and anyone can split a SHA-256 in half and read
   the name. Full FQDN is 87 characters, under the 253-character DNS limit. */
const CT_DEFAULTS = {
  subBatchMs: 15 * 60 * 1000,
  anchorEveryMs: 6 * 60 * 60 * 1000,
  maxSansPerCert: 100,
  hostnameSuffix: 'ct.lightdrawer.org',
  acmeStagingDirectory: 'https://acme-staging-v02.api.letsencrypt.org/directory',
  acmeProductionDirectories: [
    'https://acme-v02.api.letsencrypt.org/directory',
    'https://acme-v01.api.letsencrypt.org/directory',
  ],
};
const CT_LE_CERTS_PER_WEEK = 50;
const CT_LE_HEADROOM_TARGET = 28; // 4 certs/day * 7 = 28, leaving 22 for retries
function ctConfigNormalize(cfg) {
  const raw = {};
  for (const [k, v] of Object.entries(cfg || {})) if (v !== undefined) raw[k] = v;
  const c = Object.assign({}, CT_DEFAULTS, raw);
  if (c.subBatchMs < 60 * 1000) throw new Error('sub-batch window must be at least 1 minute');
  if (c.anchorEveryMs < c.subBatchMs) throw new Error('anchor interval must be at least one sub-batch');
  if (c.maxSansPerCert < 1 || c.maxSansPerCert > 100) throw new Error('max SANs per cert must be 1–100 (Let\'s Encrypt identifier limit)');
  c.hostnameSuffix = String(c.hostnameSuffix).toLowerCase().replace(/^\.+|\.+$/g, '');
  const warnings = [];
  const weekly = ctWeeklyCertEstimate(c.anchorEveryMs);
  if (weekly > CT_LE_HEADROOM_TARGET) warnings.push(`This schedule requests about ${weekly} certificates per week. Let's Encrypt allows ${CT_LE_CERTS_PER_WEEK} new certificates per registered domain per 7 days (refill: 1 every 202 minutes). Default (every 6 hours) is ${CT_LE_HEADROOM_TARGET}/week, leaving room for retries.`);
  const sansPerAnchor = Math.ceil(c.anchorEveryMs / c.subBatchMs);
  if (sansPerAnchor > c.maxSansPerCert) warnings.push(`A ${c.anchorEveryMs} ms anchor with ${c.subBatchMs} ms sub-batches would produce ${sansPerAnchor} names, above maxSansPerCert=${c.maxSansPerCert}. Extra sub-batches wait for the next certificate.`);
  return { config: c, warnings, weekly, sansPerAnchor: Math.min(sansPerAnchor, c.maxSansPerCert) };
}
function ctWeeklyCertEstimate(anchorEveryMs) {
  return Math.ceil((7 * 24 * 60 * 60 * 1000) / anchorEveryMs);
}
function ctRootToHostname(rootHex, suffix) {
  const h = String(rootHex).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('root must be 32-byte SHA-256 hex');
  suffix = (suffix || CT_DEFAULTS.hostnameSuffix).toLowerCase().replace(/^\.+|\.+$/g, '');
  return h.slice(0, 32) + '.' + h.slice(32) + '.' + suffix;
}
function ctHostnameToRoot(hostname, suffix) {
  const hn = String(hostname).toLowerCase().replace(/\.$/, '');
  suffix = (suffix || CT_DEFAULTS.hostnameSuffix).toLowerCase().replace(/^\.+|\.+$/g, '');
  if (!hn.endsWith('.' + suffix)) throw new Error('hostname does not use the expected suffix ' + suffix);
  const labels = hn.slice(0, hn.length - suffix.length - 1).split('.');
  if (labels.length !== 2 || !/^[0-9a-f]{32}$/.test(labels[0]) || !/^[0-9a-f]{32}$/.test(labels[1])) throw new Error('hostname is not two 32-character hex labels encoding a SHA-256');
  return labels[0] + labels[1];
}
function ctLargestPowerOf2LessThan(n) {
  let k = 1;
  while ((k << 1) < n) k <<= 1;
  return k;
}
async function ctMerkleTreeHash(leafHashes) {
  const n = leafHashes.length;
  if (n === 0) return sha256(new Uint8Array(0));
  if (n === 1) return leafHashes[0];
  const k = ctLargestPowerOf2LessThan(n);
  const left = await ctMerkleTreeHash(leafHashes.slice(0, k));
  const right = await ctMerkleTreeHash(leafHashes.slice(k));
  return sha256(concat(Uint8Array.of(1), left, right));
}
async function ctAuditPath(index, leafHashes) {
  const n = leafHashes.length;
  if (n <= 1) return [];
  const k = ctLargestPowerOf2LessThan(n);
  if (index < k) {
    const path = await ctAuditPath(index, leafHashes.slice(0, k));
    path.push(await ctMerkleTreeHash(leafHashes.slice(k)));
    return path;
  }
  const path = await ctAuditPath(index - k, leafHashes.slice(k));
  path.push(await ctMerkleTreeHash(leafHashes.slice(0, k)));
  return path;
}
async function ctRootFromPath(leafHash, index, treeSize, path) {
  if (treeSize === 0) throw new Error('empty tree');
  if (index < 0 || index >= treeSize) throw new Error('leaf index out of range');
  if (treeSize === 1) return { root: leafHash, used: 0 };
  const k = ctLargestPowerOf2LessThan(treeSize);
  if (index < k) {
    const inner = await ctRootFromPath(leafHash, index, k, path);
    const right = path[inner.used];
    if (!right) throw new Error('Merkle path too short');
    return { root: await sha256(concat(Uint8Array.of(1), inner.root, right)), used: inner.used + 1 };
  }
  const inner = await ctRootFromPath(leafHash, index - k, treeSize - k, path);
  const left = path[inner.used];
  if (!left) throw new Error('Merkle path too short');
  return { root: await sha256(concat(Uint8Array.of(1), left, inner.root)), used: inner.used + 1 };
}
async function ctMerkleBuild(digestHexes) {
  const uniq = [...new Set(digestHexes.map((d) => String(d).toLowerCase()))].sort();
  if (uniq.some((d) => !/^[0-9a-f]{64}$/.test(d))) throw new Error('each digest must be 64 hex chars');
  const leafHashes = [];
  for (const d of uniq) leafHashes.push(await sha256(concat(Uint8Array.of(0), fromHex(d))));
  const root = await ctMerkleTreeHash(leafHashes);
  const proofs = {};
  for (let i = 0; i < uniq.length; i++) {
    const path = await ctAuditPath(i, leafHashes);
    proofs[uniq[i]] = { index: i, path: path.map(toHex) };
  }
  return { root: toHex(root), tree_size: uniq.length, leaves: uniq, proofs };
}
async function ctMerkleVerify(digestHex, index, pathHexes, rootHex, treeSize) {
  const digest = String(digestHex).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error('digest must be 64 hex chars');
  const leaf = await sha256(concat(Uint8Array.of(0), fromHex(digest)));
  const path = (pathHexes || []).map(fromHex);
  const got = await ctRootFromPath(leaf, index, treeSize, path);
  if (got.used !== path.length) throw new Error('Merkle path has unused extra hashes');
  return bytesEq(got.root, fromHex(rootHex));
}
function ctNewState(cfg) {
  const { config, warnings } = ctConfigNormalize(cfg);
  return { config, warnings, pending: [], sub_batches: [], certs: [], last_anchor_at: null };
}
function ctWindowStart(ts, subBatchMs) { return Math.floor(ts / subBatchMs) * subBatchMs; }
function ctSubmit(state, digest, now) {
  const d = String(digest).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(d)) throw new Error('digest must be 64 hex chars');
  const t = (now || new Date()).getTime ? (now instanceof Date ? now : new Date(now)) : new Date(now);
  if (state.pending.some((p) => p.digest === d)) return { added: false, reason: 'already pending' };
  if (state.sub_batches.some((b) => b.leaves.includes(d))) return { added: false, reason: 'already in a batch' };
  state.pending.push({ digest: d, received_at: t.toISOString() });
  return { added: true };
}
async function ctCloseDueSubBatches(state, now, opts) {
  const includeOpen = !!(opts && opts.includeOpen);
  const ms = state.config.subBatchMs;
  const nowMs = (now instanceof Date ? now : new Date(now || Date.now())).getTime();
  const currentStart = ctWindowStart(nowMs, ms);
  const groups = new Map(), keep = [];
  for (const p of state.pending) {
    const ws = ctWindowStart(Date.parse(p.received_at), ms);
    if (ws < currentStart || includeOpen) {
      if (!groups.has(ws)) groups.set(ws, []);
      groups.get(ws).push(p);
    } else keep.push(p);
  }
  const closed = [];
  for (const [ws, items] of [...groups.entries()].sort((a, b) => a[0] - b[0])) {
    const tree = await ctMerkleBuild(items.map((i) => i.digest));
    const hostname = ctRootToHostname(tree.root, state.config.hostnameSuffix);
    const batch = {
      id: new Date(ws).toISOString(),
      opened_at: new Date(ws).toISOString(),
      closed_at: new Date(ws + ms).toISOString(),
      root: tree.root,
      tree_size: tree.tree_size,
      leaves: tree.leaves,
      proofs: tree.proofs,
      hostname,
      published: false,
      cert_id: null,
    };
    state.sub_batches.push(batch);
    closed.push(batch);
  }
  state.pending = keep;
  return closed;
}
function ctPlanAnchor(state, now, opts) {
  const force = !!(opts && opts.force);
  const cfg = state.config;
  const nowMs = (now instanceof Date ? now : new Date(now || Date.now())).getTime();
  if (!force && state.last_anchor_at) {
    if (nowMs - Date.parse(state.last_anchor_at) < cfg.anchorEveryMs) return null;
  }
  const unpublished = state.sub_batches.filter((b) => !b.published);
  if (!unpublished.length) return null;
  const chosen = unpublished.slice(0, cfg.maxSansPerCert);
  return { hostnames: chosen.map((b) => b.hostname), batch_ids: chosen.map((b) => b.id), roots: chosen.map((b) => b.root) };
}
function ctRecordIssuance(state, plan, issued) {
  const id = (issued && issued.issuedAt) || new Date().toISOString();
  const cert = {
    id,
    issued_at: id,
    hostnames: plan.hostnames.slice(),
    certificate_pem: issued.certPem,
    chain_pems: (issued.chainPems || []).slice(),
    scts: (issued.scts || []).slice(),
  };
  state.certs.push(cert);
  state.last_anchor_at = cert.issued_at;
  for (const bid of plan.batch_ids) {
    const b = state.sub_batches.find((x) => x.id === bid);
    if (b) { b.published = true; b.cert_id = id; }
  }
  return cert;
}
function ctPendingEntry(digestHex, extra) {
  return Object.assign({
    lightdrawer_ct: 1,
    status: 'pending',
    digest: String(digestHex).toLowerCase(),
    submitted_at: new Date().toISOString(),
    note: 'This fingerprint is waiting to be included in the next certificate-log stamp. Sub-batches close about every 15 minutes; a certificate covering those batches is requested about every 6 hours. Re-check later with verify.html (upgrade) or GET /api/ct/upgrade?digest=' + String(digestHex).toLowerCase() + '.',
  }, extra || {});
}
function ctUpgradeFromState(state, digest) {
  const d = String(digest).toLowerCase();
  for (const b of state.sub_batches) {
    if (!b.leaves.includes(d)) continue;
    const proof = b.proofs[d];
    const merkle = { leaf_index: proof.index, tree_size: b.tree_size, path: proof.path, root: b.root, algorithm: 'RFC 6962 SHA-256' };
    if (!b.published) {
      return { lightdrawer_ct: 1, status: 'pending', digest: d, sub_batch_id: b.id, hostname: b.hostname, merkle, note: 'Sub-batch is closed; waiting for the next certificate-log stamp.' };
    }
    const cert = state.certs.find((c) => c.id === b.cert_id);
    return {
      lightdrawer_ct: 1,
      status: 'anchored',
      digest: d,
      merkle,
      hostname: b.hostname,
      certificate_pem: cert && cert.certificate_pem,
      chain_pems: (cert && cert.chain_pems) || [],
      scts: (cert && cert.scts) || [],
      crtsh_url: 'https://crt.sh/?q=' + encodeURIComponent(b.hostname),
      sub_batch: { id: b.id, opened_at: b.opened_at, closed_at: b.closed_at },
      issued_at: cert && cert.issued_at,
    };
  }
  if (state.pending.some((p) => p.digest === d)) return ctPendingEntry(d);
  return null;
}

/* --- SCT parsing (RFC 6962) --- */
function ctU16enc(n) { return Uint8Array.of((n >> 8) & 255, n & 255); }
function ctU24enc(n) { return Uint8Array.of((n >> 16) & 255, (n >> 8) & 255, n & 255); }
function ctU64enc(n) {
  const o = new Uint8Array(8); let v = BigInt(n);
  for (let i = 7; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; }
  return o;
}
function ctReadU16(b, o) { return (b[o] << 8) | b[o + 1]; }
function ctReadU64(b, o) { let v = 0n; for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(b[o + i]); return Number(v); }
function ctParseSct(raw) {
  if (raw.length < 43) throw new Error('SCT too short');
  let o = 0;
  const version = raw[o++];
  const logId = raw.subarray(o, o + 32); o += 32;
  const timestampMs = ctReadU64(raw, o); o += 8;
  const extLen = ctReadU16(raw, o); o += 2;
  if (o + extLen + 4 > raw.length) throw new Error('SCT extensions overrun');
  const extensions = raw.subarray(o, o + extLen); o += extLen;
  const hashAlg = raw[o++], sigAlg = raw[o++];
  const sigLen = ctReadU16(raw, o); o += 2;
  if (o + sigLen > raw.length) throw new Error('SCT signature overrun');
  const signature = raw.subarray(o, o + sigLen);
  return { version, logId, timestampMs, extensions, hashAlg, sigAlg, signature, raw };
}
function ctParseSctList(bytes) {
  if (!bytes || bytes.length < 2) return [];
  let list = bytes;
  if (list[0] === 0x04) { try { list = derParse(list).content; } catch (e) { /* not DER-wrapped */ } }
  if (list.length < 2) return [];
  const listLen = ctReadU16(list, 0);
  let off = 2, end = 2 + listLen;
  if (end > list.length) { end = list.length; }
  const scts = [];
  while (off + 2 <= end) {
    const n = ctReadU16(list, off); off += 2;
    if (off + n > list.length) break;
    scts.push(ctParseSct(list.subarray(off, off + n)));
    off += n;
  }
  return scts;
}
function ctSctSignedData(sct, entryType, signedEntry) {
  return concat(
    Uint8Array.of(sct.version & 0xff),
    Uint8Array.of(0),
    ctU64enc(sct.timestampMs),
    ctU16enc(entryType),
    entryType === 0 ? concat(ctU24enc(signedEntry.length), signedEntry) : signedEntry,
    ctU16enc(sct.extensions.length),
    sct.extensions
  );
}
function ctLogIdHex(log) {
  if (log && log.log_id) {
    try { return toHex(fromB64(log.log_id)); } catch (e) { return ''; }
  }
  return '';
}
function ctLookupLog(trust, logId) {
  const idHex = toHex(logId);
  const logs = (trust && trust.ctLogs) || [];
  for (const log of logs) {
    if (ctLogIdHex(log) === idHex) return log;
  }
  return null;
}
/* Rebuild the precertificate TBSCertificate from an issued leaf by removing the
   embedded SCT list extension (OID 1.3.6.1.4.1.11129.2.4.2). RFC 6962 SCTs that
   Let's Encrypt embeds are signatures over this reconstructed TBS plus the
   issuer's SPKI hash, not over the final certificate. Other TBS fields keep
   their original DER encoding. */
function ctPrecertTbsFromCert(cert) {
  const SCT_OID = '1.3.6.1.4.1.11129.2.4.2';
  const tbs = derParse(cert.der).children[0];
  let extIdx = -1;
  for (let i = 0; i < tbs.children.length; i++) {
    if (tbs.children[i].tag === 0xa3) { extIdx = i; break; }
  }
  if (extIdx < 0) return cert.tbsRaw;
  const extSeq = tbs.children[extIdx].children[0];
  const kept = [];
  let removed = false;
  for (const ext of extSeq.children) {
    if (derOid(ext.children[0]) === SCT_OID) { removed = true; continue; }
    kept.push(ext.raw);
  }
  if (!removed) return cert.tbsRaw;
  const newWrap = derEnc(0xa3, derEnc(0x30, concat(...kept)));
  const parts = [];
  for (let i = 0; i < tbs.children.length; i++) parts.push(i === extIdx ? newWrap : tbs.children[i].raw);
  return derEnc(0x30, concat(...parts));
}
async function ctPrecertSignedData(sct, leaf, issuer) {
  if (!issuer) return null;
  const tbs = ctPrecertTbsFromCert(leaf);
  const issuerKeyHash = await sha256(issuer.spkiRaw);
  return ctSctSignedData(sct, 1, concat(issuerKeyHash, ctU24enc(tbs.length), tbs));
}
async function ctVerifySctSignature(sct, signedData, log) {
  if (!log || !log.key) return false;
  const spki = fromB64(log.key);
  let parsed;
  try { parsed = { spkiRaw: spki, keyAlgOid: OID.ecPublicKey, curveOid: OID.p256 }; } catch (e) { return false; }
  try {
    const inner = derParse(spki);
    const alg = inner.children[0];
    parsed.keyAlgOid = derOid(alg.children[0]);
    parsed.curveOid = alg.children[1] && alg.children[1].tag === 0x06 ? derOid(alg.children[1]) : OID.p256;
    parsed.spkiRaw = spki;
  } catch (e) { /* use defaults */ }
  const sigAlg = sct.sigAlg === 1 ? OID.sha256WithRSA : OID.ecdsaSha256;
  try {
    return await verifyWithSpki(parsed.spkiRaw, parsed.keyAlgOid, parsed.curveOid, sigAlg, 'SHA-256', sct.signature, signedData);
  } catch (e) { return false; }
}

function ctSplitPems(pemText) {
  const out = [], re = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let m; while ((m = re.exec(pemText || ''))) out.push(m[0] + '\n');
  return out;
}
async function ctVerifyChain(certs, trust) {
  if (!certs.length) return { ok: false, detail: 'no certificates' };
  const extras = ((trust && trust.isrgRoots) || []).map((r) => x509Parse(pemToDer(r.pem || r)));
  const extraTest = ((trust && trust.extraRoots) || []).map((r) => x509Parse(typeof r === 'string' ? pemToDer(r) : r));
  const roots = extras.concat(extraTest);
  for (let i = 0; i < certs.length - 1; i++) {
    try {
      if (!(await x509VerifyIssuedBy(certs[i], certs[i + 1]))) return { ok: false, detail: 'chain signature failed at index ' + i };
    } catch (e) { return { ok: false, detail: e.message }; }
  }
  const last = certs[certs.length - 1];
  for (const root of roots) {
    try {
      if (bytesEq(last.spkiRaw, root.spkiRaw) || (await x509VerifyIssuedBy(last, root)) || bytesEq(last.der, root.der)) {
        return { ok: true, detail: root.subject || 'pinned root' };
      }
    } catch (e) { /* try next */ }
    if (bytesEq(last.subjectRaw, root.subjectRaw) && bytesEq(last.spkiRaw, root.spkiRaw)) return { ok: true, detail: root.subject || 'pinned root' };
  }
  if (certs.length === 1 && extraTest.some((r) => bytesEq(r.der, certs[0].der))) return { ok: true, detail: 'test root (self-signed fixture)' };
  return { ok: false, detail: 'did not chain to a pinned public CA root' };
}

async function ctVerify(entry, statementDigestHex, trust) {
  const checks = [];
  const times = [];
  try {
    if (!entry || entry.lightdrawer_ct !== 1) {
      checks.push(chk('ct.parse', 'fail', 'ct.json is not a LightDrawer certificate-log proof', ''));
      return { checks, times };
    }
    const digest = String(statementDigestHex).toLowerCase();
    if (entry.digest && entry.digest.toLowerCase() !== digest) {
      checks.push(chk('ct.digest', 'fail', 'Proof is for a different fingerprint', entry.digest));
      return { checks, times };
    }
    checks.push(chk('ct.digest', 'pass', 'Proof is about this statement fingerprint', digest));
    if (entry.status === 'pending') {
      checks.push(chk('ct.pending', 'info', 'Certificate-log stamp is still pending', entry.note || 'Come back after the next stamp (about every 6 hours) and use upgrade.'));
      return { checks, times };
    }
    if (entry.status !== 'anchored') {
      checks.push(chk('ct.status', 'fail', 'Unknown ct.json status', String(entry.status)));
      return { checks, times };
    }
    const m = entry.merkle || {};
    const pathOk = await ctMerkleVerify(digest, m.leaf_index, m.path, m.root, m.tree_size);
    checks.push(chk('ct.merkle', pathOk ? 'pass' : 'fail', pathOk ? 'Fingerprint is in the batch Merkle tree' : 'Merkle path does not reach the claimed batch root', `index ${m.leaf_index} of ${m.tree_size}, root ${m.root}`));
    if (!pathOk) return { checks, times };
    let hostRoot;
    try { hostRoot = ctHostnameToRoot(entry.hostname, (trust && trust.ctHostnameSuffix) || CT_DEFAULTS.hostnameSuffix); }
    catch (e) { checks.push(chk('ct.hostname', 'fail', 'Anchor hostname does not encode a SHA-256', e.message)); return { checks, times }; }
    const hostOk = hostRoot === String(m.root).toLowerCase();
    checks.push(chk('ct.hostname', hostOk ? 'pass' : 'fail', hostOk ? 'Hostname is the batch root written as two hex labels' : 'Hostname does not match the Merkle root', entry.hostname));
    if (!hostOk) return { checks, times };
    if (!entry.certificate_pem) {
      checks.push(chk('ct.cert', 'fail', 'No certificate in this proof', ''));
      return { checks, times };
    }
    const pems = ctSplitPems(entry.certificate_pem).concat((entry.chain_pems || []).flatMap(ctSplitPems));
    const certs = pems.map((p) => x509Parse(pemToDer(p)));
    const leaf = certs[0];
    const sans = x509SANs(leaf);
    const sanOk = sans.map((s) => s.toLowerCase()).includes(String(entry.hostname).toLowerCase());
    checks.push(chk('ct.san', sanOk ? 'pass' : 'fail', sanOk ? 'Certificate names this batch root' : 'Certificate does not list the expected name', sans.join(', ') || '(no DNS names)'));
    if (!sanOk) return { checks, times };
    checks.push(chk('ct.notbefore', 'info', 'Certificate notBefore (CA clock; Let\'s Encrypt often backdates by about an hour for clock skew)', leaf.notBefore.toISOString()));
    const chain = await ctVerifyChain(certs, trust || {});
    checks.push(chk('ct.chain', chain.ok ? 'pass' : 'warn', chain.ok ? 'Certificate chains to a pinned CA root' : 'Certificate issuer was not checked against a pinned public CA root', chain.detail));
    let scts = [];
    const embedded = x509SctListBytes(leaf);
    if (embedded) { try { scts = ctParseSctList(embedded); } catch (e) { checks.push(chk('ct.sct.parse', 'warn', 'Could not parse SCTs embedded in the certificate', e.message)); } }
    if (!scts.length && entry.scts && entry.scts.length) {
      for (const s of entry.scts) {
        if (s.raw_b64) { try { scts.push(ctParseSct(fromB64(s.raw_b64))); } catch (e) { /* skip */ } }
      }
    }
    if (!scts.length) {
      checks.push(chk('ct.sct', chain.ok ? 'info' : 'warn', 'No Signed Certificate Timestamps to check', 'A Let\'s Encrypt certificate normally embeds SCTs. Without a verified SCT or a trusted chain, this PEM alone is not a public witness.'));
    }
    let anySct = false;
    for (const sct of scts) {
      const log = ctLookupLog(trust || {}, sct.logId);
      let verified = false, how = '';
      if (log) {
        const signedX509 = ctSctSignedData(sct, 0, leaf.der);
        if (await ctVerifySctSignature(sct, signedX509, log)) { verified = true; how = 'x509_entry'; }
        if (!verified) {
          const signedPrecert = certs[1] ? await ctPrecertSignedData(sct, leaf, certs[1]) : null;
          if (signedPrecert && await ctVerifySctSignature(sct, signedPrecert, log)) { verified = true; how = 'precert_entry'; }
        }
      }
      const name = (log && (log.name || log.description)) || ('log ' + toHex(sct.logId).slice(0, 16) + '…');
      const when = new Date(sct.timestampMs).toISOString();
      const title = verified ? 'SCT signature checks out (' + name + ')' : (log ? 'SCT signature did not verify against ' + name : 'SCT from an unknown log (key not in the bundled list)');
      const extras = [when];
      if (verified) extras.push(how === 'precert_entry' ? 'precertificate SCT' : 'x509_entry SCT');
      if (log && log.mmd) extras.push('this log advertises MMD ' + log.mmd + 's');
      checks.push(chk('ct.sct.' + toHex(sct.logId).slice(0, 8), verified ? 'pass' : (log ? 'warn' : 'info'), title, extras.join('; ')));
      if (verified) { anySct = true; times.push({ source: 'Certificate Transparency SCT (' + name + ')', time: new Date(sct.timestampMs), note: 'SCT timestamp: the log first saw this certificate no later than this moment. The log may take up to its maximum merge delay (commonly 24 hours) to show it in a queryable tree.' }); }
    }
    if (chain.ok) {
      times.push({ source: 'Certificate notBefore (certificate-log stamp)', time: leaf.notBefore, note: 'CA-stated start time; may be backdated slightly. Prefer a verified SCT timestamp when one is available.' });
    }
    if (!anySct && !chain.ok) {
      checks.push(chk('ct.witness', 'fail', 'No trusted witness: neither a pinned CA chain nor a verified SCT', 'A self-signed or unknown certificate that happens to name the batch root is not enough.'));
    }
    if (entry.crtsh_url) checks.push(chk('ct.crtsh', 'info', 'Look up this name on crt.sh (online)', entry.crtsh_url));
    return { checks, times };
  } catch (err) {
    checks.push(chk('ct.parse', 'fail', 'Certificate-log proof could not be checked', err.message));
    return { checks, times };
  }
}
