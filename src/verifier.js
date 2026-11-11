import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const vendorRoot = join(dirname(fileURLToPath(import.meta.url)), '..', 'vendor');

const EXPORTED = [
  'toHex',
  'fromHex',
  'utf8',
  'utf8dec',
  'sha256',
  'toB64',
  'zipRead',
  'verifyReceipt',
  'tsaBuildRequest',
];

function readTrust() {
  const rd = (p) => readFileSync(join(vendorRoot, p), 'utf8');
  const pemDer = (pem) => Buffer.from(pem.replace(/-----(BEGIN|END)[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  const rootPem = rd('trust/freetsa-cacert.pem');
  const tsaPem = rd('trust/freetsa-tsa.crt');
  const rekorPem = rd('trust/rekor.sigstore.dev.pub');
  const rootSha256 = createHash('sha256').update(pemDer(rootPem)).digest('hex');
  let ctLogs = [];
  try {
    ctLogs = JSON.parse(rd('trust/ct-logs.json')).logs || [];
  } catch {
    ctLogs = [];
  }
  const isrgRoots = [];
  for (const name of ['isrg-root-x1.pem', 'isrg-root-x2.pem']) {
    try {
      isrgRoots.push({ name, pem: rd('trust/' + name) });
    } catch {
      /* optional */
    }
  }
  return { rootPem, rootSha256, tsaCertPem: tsaPem, rekorPubPem: rekorPem, ctLogs, isrgRoots };
}

let cached = null;

/**
 * Load LightDrawer's offline verifier (vendored from desynced/lightdrawer @ a9ae10f / 1.3.1).
 * The lib files are plain scripts, concatenated and evaluated the same way LightDrawer's tests do.
 */
export function loadVerifier() {
  if (cached) return cached;
  const libDir = join(vendorRoot, 'web', 'lib');
  const libs = readdirSync(libDir).filter((f) => f.endsWith('.js')).sort();
  const core = libs.map((f) => `/* ---- ${f} ---- */\n` + readFileSync(join(libDir, f), 'utf8')).join('\n');
  const trust = readTrust();
  const trustJs = `const TRUST = ${JSON.stringify(trust)};\nconst TRUST_FILES = {};\n`;
  cached = new Function(`${core}\n${trustJs}\nreturn { ${EXPORTED.join(', ')} };`)();
  return cached;
}
