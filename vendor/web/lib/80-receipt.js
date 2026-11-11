/* Receipt = one ZIP per file: statement.json (what is stamped), proofs, cover page,
   trust anchors, and a copy of the offline verifier. Hash-only: the original file is
   never put in the receipt and never leaves the browser. */
const PROVENANCE_FIELDS = [
  ['source_url', 'Source URL', 'Where you found it online, if anywhere.'],
  ['source_archive_url', 'Archived copy URL', 'A perma.cc, Wayback, or Arweave link you made, if any.'],
  ['collected_at', 'Collected at', 'When you collected it (date and time, with time zone).'],
  ['collector', 'Collector', 'Name, role, or handle of the person who collected it.'],
  ['collection_method', 'How you collected it', 'e.g. browser save, screen capture, platform download.'],
  ['collector_notes', 'Notes', 'Anything a later reviewer should know.'],
];
async function buildStatement({ name, size, mediaType, sha256Hex, provenance, c2pa }) {
  const prov = {};
  for (const [k] of PROVENANCE_FIELDS) if (provenance && provenance[k] && String(provenance[k]).trim()) prov[k] = String(provenance[k]).trim();
  const st = {
    lightdrawer_receipt: '1',
    about: 'The timestamps in this receipt cover the exact bytes of this statement.json, which records the SHA-256 of the file below.',
    subject: { name, size, media_type: mediaType || 'application/octet-stream', sha256: sha256Hex },
  };
  if (Object.keys(prov).length) st.provenance = Object.assign({ framework: 'Berkeley Protocol on Digital Open Source Investigations (fields are the collector\'s own statements)' }, prov);
  if (c2pa && c2pa.present) st.c2pa_observed = { present: true, generator: c2pa.active && c2pa.active.generator || null, signer_as_claimed: c2pa.active && c2pa.active.signer || null, validated: false };
  st.claimed_created_at = new Date().toISOString();
  const bytes = utf8(JSON.stringify(st, null, 2) + '\n');
  return { statement: st, bytes, digest: await sha256(bytes) };
}
/* stampFn(digestBytes, tsqBytes) -> { ots: { [calendarUrl]: Uint8Array }, tsr: Uint8Array|null, errors: [] } */
async function makeReceipt({ fileMeta, provenance, c2pa, stampFn, rekor, verifierHtml, trustFiles, fetchFn }) {
  const s = await buildStatement(Object.assign({}, fileMeta, { provenance, c2pa }));
  const { tsq, nonceHex } = tsaBuildRequest(s.digest);
  const res = await stampFn(s.digest, tsq);
  const errors = (res.errors || []).slice();
  // OpenTimestamps: merge every calendar answer into one detached proof
  const root = { msg: s.digest, atts: [], ops: [] }; const cals = [];
  for (const [cal, bytes] of Object.entries(res.ots || {})) {
    try { otsMerge(root, await otsParseCalendarResponse(bytes, s.digest)); cals.push(cal); } catch (e) { errors.push(`OpenTimestamps ${cal}: ${e.message}`); }
  }
  const otsBytes = cals.length ? otsSerializeDetached(s.digest, root) : null;
  let tsaResult = null;
  if (res.tsr) { tsaResult = await tsaVerify(res.tsr, s.digest, TRUST, nonceHex); if (tsaResult.checks.some((c) => c.status === 'fail')) errors.push('RFC 3161 response failed local verification'); }
  let rekorEntry = null, rekorResult = null;
  if (rekor) {
    try { rekorEntry = await rekorCreateEntry(s.bytes, fetchFn); rekorResult = await rekorVerify(rekorEntry, s.bytes, TRUST); }
    catch (e) { errors.push('Rekor: ' + e.message); }
  }
  const index = {
    lightdrawer_receipt: '1', tool: 'LightDrawer receipt ' + LD_VERSION, made_at_claimed: s.statement.claimed_created_at,
    statement_sha256: toHex(s.digest), subject: s.statement.subject,
    proofs: {
      opentimestamps: otsBytes ? { file: 'proofs/statement.json.ots', calendars: cals, status: 'pending at creation; upgrade after ~1–6 h' } : null,
      rfc3161: res.tsr ? { file: 'proofs/statement.json.tsr', tsa: 'https://freetsa.org/tsr', gen_time: tsaResult && tsaResult.genTime && tsaResult.genTime.toISOString(), nonce: nonceHex } : null,
      rekor: rekorEntry ? { file: 'proofs/rekor-entry.json', log: REKOR_URL, uuid: rekorResult && rekorResult.uuid, log_index: rekorResult && rekorResult.logIndex, integrated_time: rekorResult && rekorResult.time && new Date(rekorResult.time * 1000).toISOString() } : null,
      ct: null,
    },
    errors,
  };
  const ct = (res.ct && res.ct.status === 'anchored') ? res.ct : ctPendingEntry(toHex(s.digest));
  index.proofs.ct = {
    file: 'proofs/ct.json',
    status: ct.status,
    hostname: ct.hostname || null,
    note: ct.status === 'pending'
      ? 'Waiting for the next certificate-log stamp (about every 6 hours; 15-minute sub-batches).'
      : 'Anchored in Certificate Transparency logs via a public certificate whose name is the batch root.',
  };
  const files = [
    { name: 'README.html', data: utf8(coverHtml(s.statement, index)) },
    { name: 'README.txt', data: utf8(coverText(s.statement, index)) },
    { name: 'statement.json', data: s.bytes },
    { name: 'receipt.json', data: utf8(JSON.stringify(index, null, 2) + '\n') },
  ];
  if (otsBytes) files.push({ name: 'proofs/statement.json.ots', data: otsBytes });
  if (res.tsr) files.push({ name: 'proofs/statement.json.tsr', data: res.tsr });
  if (rekorEntry) files.push({ name: 'proofs/rekor-entry.json', data: utf8(JSON.stringify(rekorEntry, null, 2) + '\n') });
  files.push({ name: 'proofs/ct.json', data: utf8(JSON.stringify(ct, null, 2) + '\n') });
  for (const [n, d] of Object.entries(trustFiles || {})) files.push({ name: 'trust/' + n, data: d });
  if (verifierHtml) files.push({ name: 'verify.html', data: verifierHtml });
  return { zip: zipWrite(files), index, statement: s.statement, statementDigest: s.digest, errors, otsBytes, tsr: res.tsr, rekorEntry };
}
/* files: { name: Uint8Array } from zipRead. original: { name, bytes } or null.
   opts: { lookupBlock, fetchUpgrade } (both optional; omit for fully offline). */
async function verifyReceipt(files, original, opts = {}) {
  const out = { sections: [], times: [] };
  const sec = (title, checks) => { out.sections.push({ title, checks }); return checks; };
  const stBytes = files['statement.json'];
  if (!stBytes) { sec('Receipt', [chk('receipt', 'fail', 'No statement.json in this receipt', '')]); return out; }
  let st; try { st = JSON.parse(utf8dec(stBytes)); } catch (e) { sec('Receipt', [chk('receipt', 'fail', 'statement.json is not valid JSON', e.message)]); return out; }
  const d = await sha256(stBytes); out.statement = st; out.statementDigestHex = toHex(d);
  const rc = [chk('statement', st.lightdrawer_receipt === '1' && st.subject && /^[0-9a-f]{64}$/.test(st.subject.sha256) ? 'pass' : 'fail', 'Statement is well-formed', `statement.json SHA-256 ${toHex(d)}`)];
  if (original) {
    const src = original.file || original.bytes;
    const fh = toHex(await sha256Source(src, { onProgress: opts.onHashProgress }));
    rc.push(chk('file.hash', fh === st.subject.sha256 ? 'pass' : 'fail', fh === st.subject.sha256 ? 'Your file matches the receipt (same SHA-256)' : 'Your file does NOT match the receipt', `file ${fh}`));
    const origSize = original.file ? original.file.size : (original.size != null ? original.size : original.bytes.length);
    if (origSize !== st.subject.size) rc.push(chk('file.size', 'warn', 'File size differs from the receipt', `${origSize} vs ${st.subject.size}`));
  } else rc.push(chk('file.hash', 'skip', 'Original file not supplied, so the file itself was not checked', `Receipt is for SHA-256 ${st.subject.sha256}`));
  sec('File and statement', rc);
  // RFC 3161
  if (files['proofs/statement.json.tsr']) {
    let nonce = null; try { nonce = JSON.parse(utf8dec(files['receipt.json'])).proofs.rfc3161.nonce; } catch (e) { /* optional */ }
    const r = await tsaVerify(files['proofs/statement.json.tsr'], d, TRUST, nonce);
    sec('RFC 3161 timestamp (FreeTSA)', r.checks);
    if (r.genTime && !r.checks.some((c) => c.status === 'fail')) out.times.push({ source: 'RFC 3161 (FreeTSA)', time: r.genTime });
  } else sec('RFC 3161 timestamp (FreeTSA)', [chk('tsa', 'skip', 'No RFC 3161 token in this receipt', '')]);
  // OpenTimestamps
  if (files['proofs/statement.json.ots']) {
    let ots = files['proofs/statement.json.ots']; const extra = [];
    if (opts.fetchUpgrade) {
      try {
        const p = await otsParseDetached(ots);
        if (otsAttestations(p.root).some((a) => a.kind === 'pending') && !otsAttestations(p.root).some((a) => a.kind === 'bitcoin')) {
          const rep = await otsUpgrade(p.root, opts.fetchUpgrade);
          for (const x of rep) extra.push(chk('ots.upgrade', /upgraded/.test(x.status) ? 'pass' : 'info', 'Upgrade from ' + x.uri, x.status));
          const up = otsSerializeDetached(p.digest, p.root);
          if (!bytesEq(up, ots)) { ots = up; out.upgradedOts = up; }
        }
      } catch (e) { extra.push(chk('ots.upgrade', 'warn', 'Could not upgrade proof', e.message)); }
    }
    const r = await otsVerify(ots, d, opts.lookupBlock);
    sec('OpenTimestamps (Bitcoin)', extra.concat(r.checks));
    if (r.earliest) out.times.push({ source: `Bitcoin block ${r.earliest.height} (OpenTimestamps)`, time: new Date(r.earliest.time * 1000), note: 'block times can be off by up to ~2 hours' });
  } else sec('OpenTimestamps (Bitcoin)', [chk('ots', 'skip', 'No OpenTimestamps proof in this receipt', '')]);
  // Certificate Transparency (extra witness; pending until a batch is certified)
  if (files['proofs/ct.json']) {
    const extra = [];
    let ctBytes = files['proofs/ct.json'];
    if (opts.fetchCtUpgrade) {
      try {
        let cur; try { cur = JSON.parse(utf8dec(ctBytes)); } catch (e) { cur = null; }
        if (!cur || cur.status === 'pending') {
          const up = await opts.fetchCtUpgrade(toHex(d));
          if (up) {
            const ub = typeof up === 'string' ? utf8(up) : (up instanceof Uint8Array ? up : utf8(JSON.stringify(up, null, 2) + '\n'));
            ctBytes = ub; files['proofs/ct.json'] = ub; out.upgradedCt = ub;
            extra.push(chk('ct.upgrade', 'pass', 'Fetched the certificate-log inclusion data', ''));
          } else extra.push(chk('ct.upgrade', 'info', 'Certificate-log stamp not ready yet', 'Try again after the next stamp (about every 6 hours).'));
        }
      } catch (e) { extra.push(chk('ct.upgrade', 'warn', 'Could not upgrade the certificate-log proof', e.message)); }
    }
    let ctObj; try { ctObj = JSON.parse(utf8dec(ctBytes)); } catch (e) { ctObj = null; }
    const r = ctObj ? await ctVerify(ctObj, toHex(d), TRUST) : { checks: [chk('ct', 'fail', 'ct.json is not valid JSON', '')], times: [] };
    extra.push(...r.checks);
    sec('Certificate Transparency (public certificate log)', extra);
    for (const tm of (r.times || [])) out.times.push(tm);
  } else sec('Certificate Transparency (public certificate log)', [chk('ct', 'skip', 'No certificate-log proof in this receipt', '')]);
  // Rekor
  if (files['proofs/rekor-entry.json']) {
    let e; try { e = JSON.parse(utf8dec(files['proofs/rekor-entry.json'])); } catch (err) { e = null; }
    const r = e ? await rekorVerify(e, stBytes, TRUST) : { checks: [chk('rekor', 'fail', 'rekor-entry.json is not valid JSON', '')] };
    sec('Sigstore Rekor transparency log', r.checks);
    if (r.time && !r.checks.some((c) => c.status === 'fail')) out.times.push({ source: 'Sigstore Rekor', time: new Date(r.time * 1000) });
  }
  // Provenance (claims, not verified facts)
  if (st.provenance) sec('Provenance (collector\'s statements)', [chk('prov', 'info', 'Fixed at timestamp time, not independently verified', Object.entries(st.provenance).filter(([k]) => k !== 'framework').map(([k, v]) => `${k}: ${v}`).join(' · '))]);
  // C2PA
  let c2 = null; if (original) { try { c2 = await c2paInspectSource(original.file || original.bytes); } catch (e) { c2 = { present: true, error: e.message }; } }
  sec('C2PA Content Credentials (read only)', c2 && c2.error ? [chk('c2pa', 'warn', 'C2PA data present but unreadable', c2.error)] : c2paChecks(original ? c2 : null));
  out.c2pa = c2;
  out.times.sort((a, b) => a.time - b.time);
  const all = out.sections.flatMap((s) => s.checks);
  out.verdict = all.some((c) => c.status === 'fail') ? 'fail' : out.times.length ? 'pass' : 'incomplete';
  return out;
}
