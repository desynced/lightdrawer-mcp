/* RFC 3161 trusted timestamp: build a request, verify a response offline. */
function tsaBuildRequest(digestBytes) {
  const nonce = crypto.getRandomValues(new Uint8Array(8)); nonce[0] &= 0x7f; if (nonce[0] === 0) nonce[0] = 1;
  const tsq = derSeq(
    derIntBytes(Uint8Array.of(1)),
    derSeq(derSeq(derOidEnc(OID.sha256), derNull()), derOctets(digestBytes)),
    derIntBytes(nonce),
    derBool(true), // certReq: ask the TSA to embed its certificate
  );
  return { tsq, nonceHex: toHex(nonce) };
}
function tsaParseResponse(tsr) {
  const resp = derParse(tsr);
  const status = Number(derInt(resp.children[0].children[0]));
  const out = { status, granted: status === 0 || status === 1 };
  if (!resp.children[1]) return out;
  const ci = resp.children[1];
  if (derOid(ci.children[0]) !== OID.signedData) throw new Error('token is not CMS SignedData');
  const sd = ci.children[1].children[0];
  let k = 1; const digestAlgs = sd.children[k++]; const encap = sd.children[k++];
  let certs = [];
  if (sd.children[k] && sd.children[k].tag === 0xa0) { certs = sd.children[k].children.map((c) => c.raw); k++; }
  if (sd.children[k] && sd.children[k].tag === 0xa1) k++;
  const signerInfos = sd.children[k];
  if (derOid(encap.children[0]) !== OID.tstInfo) throw new Error('encapsulated content is not TSTInfo');
  const eContent = encap.children[1].children[0].content;
  const tst = derParse(eContent).children;
  let j = 0; j++; // version
  const policy = derOid(tst[j++]);
  const mi = tst[j++];
  const imprintAlg = derOid(mi.children[0].children[0]);
  const imprint = mi.children[1].content;
  const serial = derInt(tst[j++]);
  const genTime = derTime(tst[j++]);
  let nonce = null, tsaName = null;
  for (; j < tst.length; j++) {
    const n = tst[j];
    if (n.tag === 0x02) nonce = derInt(n);
    else if (n.tag === 0xa0) { try { tsaName = x509Name(n.children[0].children[0]); } catch (e) { /* ignore */ } }
  }
  const si = signerInfos.children[0].children;
  let s = 1; const sid = si[s++]; const digestAlgOid = derOid(si[s++].children[0]);
  let signedAttrs = null; if (si[s].tag === 0xa0) signedAttrs = si[s++];
  const sigAlgOid = derOid(si[s++].children[0]);
  const signature = si[s++].content;
  const attrs = {};
  if (signedAttrs) for (const a of signedAttrs.children) attrs[derOid(a.children[0])] = a.children[1].children[0];
  let sidSerialHex = null; if (sid.tag === 0x30) sidSerialHex = toHex(sid.children[1].content).replace(/^00/, '');
  return Object.assign(out, { policy, imprintAlg, imprint, serial, genTime, nonce, tsaName, certs, eContent, digestAlgOid, signedAttrs, attrs, sigAlgOid, signature, sidSerialHex });
}
/* trust = { rootPem, rootSha256, tsaCertPem? }. Returns { checks, genTime }. */
async function tsaVerify(tsr, expectedDigest, trust, expectedNonceHex) {
  const checks = [];
  let p;
  try { p = tsaParseResponse(tsr); } catch (e) { return { checks: [chk('tsa.parse', 'fail', 'RFC 3161 token could not be read', e.message)] }; }
  if (!p.granted) return { checks: [chk('tsa.status', 'fail', 'TSA did not grant the timestamp', 'status ' + p.status)] };
  checks.push(chk('tsa.imprint', p.imprintAlg === OID.sha256 && bytesEq(p.imprint, expectedDigest) ? 'pass' : 'fail',
    'RFC 3161 token covers this statement hash', 'token imprint ' + toHex(p.imprint)));
  if (expectedNonceHex) checks.push(chk('tsa.nonce', p.nonce !== null && p.nonce === BigInt('0x' + expectedNonceHex) ? 'pass' : 'warn', 'Nonce matches the request', ''));
  // signed attributes bind the TSTInfo
  const hashName = HASH_BY_OID[p.digestAlgOid];
  const md = p.attrs[OID.messageDigest];
  const mdOk = md && hashName && bytesEq(md.content, await digest(hashName, p.eContent));
  checks.push(chk('tsa.messageDigest', mdOk ? 'pass' : 'fail', 'Signed attributes match the timestamp content', hashName || p.digestAlgOid));
  // find signer cert
  const root = x509Parse(pemToDer(trust.rootPem));
  const rootFp = toHex(await sha256(root.der));
  checks.push(chk('tsa.rootPin', rootFp === trust.rootSha256 ? 'pass' : 'fail', 'Bundled TSA root matches pinned fingerprint', rootFp));
  const candidates = p.certs.map((d) => x509Parse(d));
  if (trust.tsaCertPem) candidates.push(x509Parse(pemToDer(trust.tsaCertPem)));
  const signedAttrsDer = p.signedAttrs ? concat(Uint8Array.of(0x31), p.signedAttrs.raw.subarray(1)) : p.eContent;
  let signer = null;
  for (const c of candidates) {
    if (bytesEq(c.der, root.der)) continue;
    try { if (await verifyWithSpki(c.spkiRaw, c.keyAlgOid, c.curveOid, p.sigAlgOid, hashName, p.signature, signedAttrsDer)) { signer = c; break; } } catch (e) { /* try next */ }
  }
  checks.push(chk('tsa.signature', signer ? 'pass' : 'fail', 'TSA signature is valid', signer ? signer.subject : 'no certificate verified the signature'));
  if (signer) {
    if (p.sidSerialHex) checks.push(chk('tsa.sid', signer.serialHex.replace(/^00/, '') === p.sidSerialHex ? 'pass' : 'warn', 'Signer identifier matches certificate', ''));
    const ess = p.attrs[OID.signingCertificateV2] || p.attrs[OID.signingCertificate];
    if (ess) {
      try {
        const id = ess.children[0].children[0];
        let alg = 'SHA-1', hashNode = id.children[0];
        if (p.attrs[OID.signingCertificateV2]) { if (id.children[0].tag === 0x30) { alg = HASH_BY_OID[derOid(id.children[0].children[0])]; hashNode = id.children[1]; } else alg = 'SHA-256'; }
        checks.push(chk('tsa.ess', bytesEq(hashNode.content, await digest(alg, signer.der)) ? 'pass' : 'fail', 'Signed attributes name this signing certificate', ''));
      } catch (e) { checks.push(chk('tsa.ess', 'warn', 'Signing-certificate attribute unreadable', e.message)); }
    }
    let chainOk = false; try { chainOk = await x509VerifyIssuedBy(signer, root); } catch (e) { /* */ }
    checks.push(chk('tsa.chain', chainOk ? 'pass' : 'fail', 'TSA certificate chains to the pinned root', root.subject));
    const inValidity = p.genTime >= signer.notBefore && p.genTime <= signer.notAfter;
    checks.push(chk('tsa.validity', inValidity ? 'pass' : 'fail', 'Timestamp falls inside the TSA certificate validity', `${signer.notBefore.toISOString()} – ${signer.notAfter.toISOString()}`));
  }
  checks.push(chk('tsa.time', 'info', 'TSA time (UTC)', p.genTime.toISOString()));
  checks.push(chk('tsa.revocation', 'info', 'Not checked offline: certificate revocation (CRL/OCSP)', 'Run openssl with -crl_check online if you need this.'));
  return { checks, genTime: p.genTime, serial: p.serial.toString() };
}
