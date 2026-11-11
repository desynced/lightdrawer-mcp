/* X.509 parsing and signature checks with WebCrypto. */
const NAME_OIDS = { '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '1.2.840.113549.1.9.1': 'emailAddress', '2.5.4.13': 'description' };
function x509Name(node) {
  const parts = [];
  for (const set of node.children || []) for (const atv of set.children || []) { const k = NAME_OIDS[derOid(atv.children[0])] || derOid(atv.children[0]); parts.push(`${k}=${derStr(atv.children[1])}`); }
  return parts.join(', ');
}
function x509Parse(der) {
  const cert = derParse(der);
  const [tbs, sigAlg, sigVal] = cert.children;
  let i = 0; const t = tbs.children;
  if (t[0].tag === 0xa0) i++; // version
  const serial = t[i++], tbsSigAlg = t[i++], issuer = t[i++], validity = t[i++], subject = t[i++], spki = t[i++];
  const spkiAlg = spki.children[0];
  return {
    der, tbsRaw: tbs.raw, serialHex: toHex(serial.content), sigAlgOid: derOid(sigAlg.children[0]), sigValue: sigVal.content.subarray(1),
    issuer: x509Name(issuer), subject: x509Name(subject), issuerRaw: issuer.raw, subjectRaw: subject.raw,
    notBefore: derTime(validity.children[0]), notAfter: derTime(validity.children[1]),
    spkiRaw: spki.raw, keyAlgOid: derOid(spkiAlg.children[0]), curveOid: spkiAlg.children[1] && spkiAlg.children[1].tag === 0x06 ? derOid(spkiAlg.children[1]) : null,
  };
}
function ecdsaDerToRaw(sig, size) {
  const n = derParse(sig); const out = new Uint8Array(size * 2);
  [0, 1].forEach((k) => { let v = n.children[k].content; while (v.length > size && v[0] === 0) v = v.subarray(1); if (v.length > size) throw new Error('ECDSA int too long'); out.set(v, size * (k + 1) - v.length); });
  return out;
}
const CURVES = { [OID.p256]: ['P-256', 32], [OID.p384]: ['P-384', 48], [OID.p521]: ['P-521', 66] };
/* Verify `sig` over `data` with SubjectPublicKeyInfo `spkiRaw`. sigAlgOid may be an
   explicit sig alg (ecdsa-with-SHAxxx, shaxxxWithRSA) or rsaEncryption + hashName. */
async function verifyWithSpki(spkiRaw, keyAlgOid, curveOid, sigAlgOid, hashName, sig, data) {
  const map = { [OID.ecdsaSha256]: 'SHA-256', [OID.ecdsaSha384]: 'SHA-384', [OID.ecdsaSha512]: 'SHA-512', [OID.sha256WithRSA]: 'SHA-256', [OID.sha384WithRSA]: 'SHA-384', [OID.sha512WithRSA]: 'SHA-512' };
  const hash = map[sigAlgOid] || hashName;
  if (!hash) throw new Error('unsupported signature algorithm ' + sigAlgOid);
  if (keyAlgOid === OID.ecPublicKey) {
    const c = CURVES[curveOid]; if (!c) throw new Error('unsupported curve ' + curveOid);
    const key = await crypto.subtle.importKey('spki', spkiRaw, { name: 'ECDSA', namedCurve: c[0] }, false, ['verify']);
    return crypto.subtle.verify({ name: 'ECDSA', hash }, key, ecdsaDerToRaw(sig, c[1]), data);
  }
  if (keyAlgOid === OID.rsaEncryption) {
    const key = await crypto.subtle.importKey('spki', spkiRaw, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']);
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, data);
  }
  throw new Error('unsupported key algorithm ' + keyAlgOid);
}
async function x509VerifyIssuedBy(cert, issuer) {
  return verifyWithSpki(issuer.spkiRaw, issuer.keyAlgOid, issuer.curveOid, cert.sigAlgOid, null, cert.sigValue, cert.tbsRaw);
}

/* Extensions and SANs. Re-parses the cert so existing x509Parse callers stay unchanged. */
function x509Extensions(cert) {
  const tbs = derParse(cert.der).children[0];
  const out = [];
  for (const n of tbs.children) {
    if (n.tag !== 0xa3) continue;
    const seq = n.children[0];
    for (const ext of seq.children) {
      const oid = derOid(ext.children[0]);
      let i = 1, critical = false;
      if (ext.children[i] && ext.children[i].tag === 0x01) { critical = ext.children[i].content[0] !== 0; i++; }
      out.push({ oid, critical, value: ext.children[i].content });
    }
  }
  return out;
}
function x509SANs(cert) {
  const ext = x509Extensions(cert).find((e) => e.oid === '2.5.29.17');
  if (!ext) return [];
  const names = [];
  const seq = derParse(ext.value);
  for (const n of seq.children || []) {
    if (n.cls === 2 && n.tagNum === 2) names.push(utf8dec(n.content)); // dNSName [2]
  }
  return names;
}
function x509SctListBytes(cert) {
  const ext = x509Extensions(cert).find((e) => e.oid === '1.3.6.1.4.1.11129.2.4.2');
  return ext ? ext.value : null;
}
