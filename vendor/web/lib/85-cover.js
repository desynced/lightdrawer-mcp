/* Plain-language cover page for a receipt (README.html + README.txt). */
function coverModel(st, idx) {
  const p = idx.proofs || {};
  const proved = [];
  if (p.rfc3161) proved.push(['RFC 3161 timestamp from FreeTSA (freetsa.org)', p.rfc3161.gen_time ? p.rfc3161.gen_time.replace('T', ' ').replace(/\.\d+Z$/, 'Z').replace('Z', ' UTC') : 'see token', 'Signed by one third-party timestamp authority. Checkable now.']);
  if (p.opentimestamps) proved.push(['OpenTimestamps → Bitcoin', 'Pending when made', 'Calendars put the hash into a Bitcoin transaction, usually within ~1–6 hours. Upgrade the proof after that; then nobody needs to be trusted except the Bitcoin chain.']);
  if (p.rekor) proved.push(['Sigstore Rekor public log', p.rekor.integrated_time ? p.rekor.integrated_time.replace('T', ' ').replace(/\.\d+Z$/, 'Z').replace('Z', ' UTC') : '', 'Public, append-only transparency log. Entry index ' + p.rekor.log_index + '. Signed with a throwaway key: shows when, not who.']);
  if (p.ct) proved.push(['Certificate Transparency (public HTTPS certificate logs)', p.ct.status === 'anchored' ? 'See proofs/ct.json' : 'Pending when made', 'LightDrawer batches fingerprints and names a later certificate after the batch root. Those certificates appear in public Certificate Transparency logs. This is an extra witness, not a replacement for Bitcoin.']);
  const verify = [
    ['Check your file', `sha256sum "${st.subject.name}"`, `Must print ${st.subject.sha256}. If not, this receipt is not about your file.`],
    ['Check the statement', 'sha256sum statement.json', `Must print ${idx.statement_sha256}. Every proof below is about this hash.`],
  ];
  if (p.rfc3161) verify.push(['RFC 3161 (OpenSSL)', 'openssl ts -verify -data statement.json -in proofs/statement.json.tsr -CAfile trust/freetsa-cacert.pem -untrusted trust/freetsa-tsa.crt', `Prefer certificates downloaded yourself from https://freetsa.org/files/. Root SHA-256 fingerprint: ${TRUST.rootSha256}.`]);
  if (p.opentimestamps) verify.push(['OpenTimestamps', 'pip install opentimestamps-client\nots upgrade proofs/statement.json.ots\nots verify -f statement.json proofs/statement.json.ots', 'Or drop statement.json and the .ots file on https://opentimestamps.org. "Pending" just means Bitcoin has not confirmed yet; try again in a few hours. `ots verify` needs a Bitcoin node, or use the website.']);
  if (p.rekor) verify.push(['Sigstore Rekor', `curl https://rekor.sigstore.dev/api/v1/log/entries/${p.rekor.uuid}`, 'Or search the hash on https://search.sigstore.dev. The entry\'s data.hash.value must equal the statement hash.']);
  if (p.ct) verify.push(['Certificate Transparency', 'See HOW-IT-WORKS.md: check proofs/ct.json, recompute the Merkle root from digest + path, confirm the certificate SAN encodes that root, then look the hostname up on https://crt.sh', 'Pending means the batch has not been written into a certificate yet. The offline verifier can upgrade this the same way it upgrades an OpenTimestamps proof.']);
  verify.push(['All at once, offline', 'Open verify.html in any modern browser', 'Drop this ZIP (and optionally the original file). It re-hashes and checks every proof without contacting LightDrawer.']);
  const limits = [
    'It proves the file (and this statement) existed no later than the times above. The file may be older.',
    'It does not prove who made the file, that it is authentic, unedited before stamping, or that what it shows is true.',
    'Provenance fields are the collector\'s own statements, fixed in time by the stamps, not verified facts.',
    'Hash only: the file is not stored anywhere by LightDrawer. Keep the original. Lose it and the receipt can no longer be tied to any content. Changing one bit changes the hash.',
    'FreeTSA is a single authority: you trust its key. Bitcoin anchoring removes that once confirmed. Rekor is run by Sigstore/OpenSSF. The certificate-log stamp depends on Let\'s Encrypt and public CT logs remaining available (crt.sh and other archives keep copies). It is an extra witness, not a replacement for Bitcoin.',
    'C2PA Content Credentials, if noted, were read but not validated.',
  ];
  return { proved, verify, limits };
}
function coverHtml(st, idx) {
  const m = coverModel(st, idx);
  const row = (cells) => '<tr>' + cells.map((c) => `<td>${escHtml(c)}</td>`).join('') + '</tr>';
  const prov = st.provenance ? Object.entries(st.provenance).map(([k, v]) => row([k, v])).join('') : '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Receipt: ${escHtml(st.subject.name)}</title>
<style>body{font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;color:#111}h1{font-size:1.6rem;margin:0 0 .25rem}h2{font-size:1.15rem;margin-top:2rem;border-bottom:1px solid #ddd;padding-bottom:.25rem}code,pre{font:13px/1.4 ui-monospace,Menlo,Consolas,monospace;background:#f4f4f4;border-radius:4px}pre{padding:.6rem;white-space:pre-wrap;word-break:break-all}code{padding:0 .2rem;word-break:break-all}table{border-collapse:collapse;width:100%}td{border-top:1px solid #eee;padding:.4rem .5rem .4rem 0;vertical-align:top}td:first-child{font-weight:600;width:14rem}.box{border:2px solid #111;padding:1rem;border-radius:6px}.muted{color:#555}li{margin:.3rem 0}</style></head><body>
<h1>LightDrawer receipt</h1><p class="muted">For <strong>${escHtml(st.subject.name)}</strong> (${escHtml(String(st.subject.size))} bytes, ${escHtml(st.subject.media_type)})</p>
<div class="box"><strong>In one sentence:</strong> a file whose fingerprint (SHA-256) is <code>${escHtml(st.subject.sha256)}</code> existed no later than the times below. That is all this receipt proves.</div>
<h2>What is proven, and when</h2><table>${m.proved.map(row).join('') || row(['No proofs', '', 'Creation failed; see receipt.json'])}</table>
<p class="muted">Each proof covers <code>statement.json</code> (SHA-256 <code>${escHtml(idx.statement_sha256)}</code>), which contains the file fingerprint${st.provenance ? ' and the provenance notes below' : ''}.</p>
${prov ? `<h2>Provenance (collector's statements)</h2><table>${prov}</table>` : ''}
<h2>What this does not prove</h2><ul>${m.limits.map((l) => `<li>${escHtml(l)}</li>`).join('')}</ul>
<h2>How to verify without LightDrawer</h2>${m.verify.map(([t, cmd, note]) => `<h3>${escHtml(t)}</h3><pre>${escHtml(cmd)}</pre><p class="muted">${escHtml(note)}</p>`).join('')}
<h2>Archiving the source</h2><p>LightDrawer does not publish or store files. If the source is a public web page, archive it yourself, e.g. <a href="https://perma.cc">perma.cc</a>, <a href="https://web.archive.org/save">Wayback Machine</a>, or Arweave, and record that link in the provenance fields of your next receipt.</p>
<h2>Files in this receipt</h2><ul><li><code>statement.json</code>: the exact bytes that were timestamped</li><li><code>proofs/</code>: OpenTimestamps <code>.ots</code>, RFC 3161 <code>.tsr</code>${idx.proofs && idx.proofs.rekor ? ', Rekor entry' : ''}${idx.proofs && idx.proofs.ct ? ', certificate-log proof (ct.json)' : ''}</li><li><code>trust/</code>: copies of the public certificates/keys used (convenience copies; fetch your own)</li><li><code>verify.html</code>: offline verifier</li><li><code>receipt.json</code>: machine-readable index</li></ul>
<p class="muted">Made with ${escHtml(idx.tool)}. Device clock said ${escHtml(st.claimed_created_at)} (not a proof).</p></body></html>`;
}
function coverText(st, idx) {
  const m = coverModel(st, idx);
  const L = [];
  L.push('LIGHTDRAWER RECEIPT', '', `File: ${st.subject.name} (${st.subject.size} bytes)`, `SHA-256: ${st.subject.sha256}`, `Statement SHA-256: ${idx.statement_sha256}`, '');
  L.push('In one sentence: a file with this fingerprint existed no later than the times below. That is all this receipt proves.', '');
  L.push('WHAT IS PROVEN, AND WHEN'); for (const [a, b, c] of m.proved) L.push(`- ${a}: ${b}`, `  ${c}`); L.push('');
  if (st.provenance) { L.push("PROVENANCE (collector's statements)"); for (const [k, v] of Object.entries(st.provenance)) L.push(`- ${k}: ${v}`); L.push(''); }
  L.push('WHAT THIS DOES NOT PROVE'); for (const l of m.limits) L.push('- ' + l); L.push('');
  L.push('HOW TO VERIFY WITHOUT LIGHTDRAWER'); for (const [t, cmd, note] of m.verify) L.push(`* ${t}`, cmd.split('\n').map((x) => '    ' + x).join('\n'), '  ' + note, ''); 
  L.push('LightDrawer does not store or publish files. Archive public sources yourself (perma.cc, web.archive.org/save, Arweave).');
  return L.join('\n') + '\n';
}
