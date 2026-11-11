/* Optional Sigstore Rekor (v1 API) "hashedrekord" entry for the statement hash.
   An ephemeral P-256 key signs the statement; the key is discarded. The entry only
   shows the hash was logged publicly at integratedTime. It says nothing about who. */
const REKOR_URL = 'https://rekor.sigstore.dev';
function ecdsaRawToDer(raw) {
  const n = raw.length / 2;
  const int = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.subarray(i); if (b[0] & 0x80) b = concat(Uint8Array.of(0), b); return derEnc(0x02, b); };
  return derSeq(int(raw.subarray(0, n)), int(raw.subarray(n)));
}
async function rekorCreateEntry(statementBytes, fetchFn = fetch, base = REKOR_URL) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const sig = ecdsaRawToDer(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, statementBytes)));
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  const body = { apiVersion: '0.0.1', kind: 'hashedrekord', spec: {
    data: { hash: { algorithm: 'sha256', value: toHex(await sha256(statementBytes)) } },
    signature: { content: toB64(sig), publicKey: { content: toB64(utf8(derToPem(spki, 'PUBLIC KEY'))) } } } };
  const r = await fetchFn(base + '/api/v1/log/entries', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (r.status !== 201) throw new Error('Rekor returned HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
  return r.json(); // { "<uuid>": { body, integratedTime, logID, logIndex, verification } }
}
async function rekorRootFromProof(index, size, leaf, hashes) {
  index = BigInt(index); size = BigInt(size);
  if (index >= size) throw new Error('index beyond tree size');
  const x = index ^ (size - 1n); const inner = x === 0n ? 0 : x.toString(2).length;
  const node = (l, r) => sha256(concat(Uint8Array.of(1), l, r));
  if (hashes.length < inner) throw new Error('proof too short');
  let h = leaf;
  for (let i = 0; i < inner; i++) h = ((index >> BigInt(i)) & 1n) === 0n ? await node(h, hashes[i]) : await node(hashes[i], h);
  for (let i = inner; i < hashes.length; i++) h = await node(hashes[i], h);
  return h;
}
/* entryJson: the object Rekor returned. trust: { rekorPubPem } */
async function rekorVerify(entryJson, statementBytes, trust) {
  const checks = [];
  try {
    const uuid = Object.keys(entryJson)[0]; const e = entryJson[uuid];
    const pubDer = pemToDer(trust.rekorPubPem);
    const logId = toHex(await sha256(pubDer));
    checks.push(chk('rekor.logid', e.logID === logId ? 'pass' : 'fail', 'Entry is from the bundled Rekor log key', 'rekor.sigstore.dev (' + logId.slice(0, 16) + '…)'));
    const bodyBytes = fromB64(e.body); const body = JSON.parse(utf8dec(bodyBytes));
    const wantHex = toHex(await sha256(statementBytes));
    const okKind = body.kind === 'hashedrekord' && body.spec.data.hash.algorithm === 'sha256' && body.spec.data.hash.value === wantHex;
    checks.push(chk('rekor.hash', okKind ? 'pass' : 'fail', 'Rekor entry records this statement hash', body.spec && body.spec.data.hash.value));
    try {
      const pem = utf8dec(fromB64(body.spec.signature.publicKey.content));
      let spki = pemToDer(pem), keyAlg = OID.ecPublicKey, curve = OID.p256;
      if (/CERTIFICATE/.test(pem)) { const c = x509Parse(spki); spki = c.spkiRaw; keyAlg = c.keyAlgOid; curve = c.curveOid; }
      const ok = await verifyWithSpki(spki, keyAlg, curve, keyAlg === OID.ecPublicKey ? OID.ecdsaSha256 : OID.sha256WithRSA, 'SHA-256', fromB64(body.spec.signature.content), statementBytes);
      checks.push(chk('rekor.entrysig', ok ? 'pass' : 'fail', 'Entry signature (throwaway key) matches the statement', 'Proves nothing about identity.'));
    } catch (err) { checks.push(chk('rekor.entrysig', 'warn', 'Entry signature not checked', err.message)); }
    const rk = await crypto.subtle.importKey('spki', pubDer, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const canon = `{"body":${JSON.stringify(e.body)},"integratedTime":${e.integratedTime},"logID":${JSON.stringify(e.logID)},"logIndex":${e.logIndex}}`;
    const setOk = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, rk, ecdsaDerToRaw(fromB64(e.verification.signedEntryTimestamp), 32), utf8(canon));
    checks.push(chk('rekor.set', setOk ? 'pass' : 'fail', 'Rekor signed the entry time (SET)', new Date(e.integratedTime * 1000).toISOString()));
    const ip = e.verification.inclusionProof;
    if (ip) {
      const leaf = await sha256(concat(Uint8Array.of(0), bodyBytes));
      const root = await rekorRootFromProof(ip.logIndex, ip.treeSize, leaf, ip.hashes.map(fromHex));
      const rootOk = toHex(root) === ip.rootHash;
      checks.push(chk('rekor.inclusion', rootOk ? 'pass' : 'fail', 'Merkle inclusion proof reaches the logged tree root', `tree size ${ip.treeSize}`));
      if (ip.checkpoint) {
        const [text, sigs] = ip.checkpoint.split('\n\n');
        const lines = text.split('\n');
        const cpOk = lines[1] === String(ip.treeSize) && toHex(fromB64(lines[2])) === ip.rootHash;
        let sigOk = false;
        for (const line of sigs.trim().split('\n')) {
          const m = /^\u2014 (\S+) (\S+)$/.exec(line); if (!m) continue;
          const raw = fromB64(m[2]);
          try { sigOk = sigOk || await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, rk, ecdsaDerToRaw(raw.subarray(4), 32), utf8(text + '\n')); } catch (err) { /* */ }
        }
        checks.push(chk('rekor.checkpoint', cpOk && sigOk ? 'pass' : 'fail', 'Log checkpoint is signed by Rekor and matches the proof', lines[0]));
      }
    } else checks.push(chk('rekor.inclusion', 'warn', 'No inclusion proof stored', ''));
    checks.push(chk('rekor.time', 'info', 'Rekor integrated time (UTC)', new Date(e.integratedTime * 1000).toISOString()));
    checks.push(chk('rekor.consistency', 'info', 'Not checked offline: that this tree is consistent with Rekor\'s current tree', 'Use rekor-cli verify or a Sigstore monitor online.'));
    return { checks, time: e.integratedTime, uuid, logIndex: e.logIndex };
  } catch (err) { checks.push(chk('rekor.parse', 'fail', 'Rekor entry could not be checked', err.message)); return { checks }; }
}
