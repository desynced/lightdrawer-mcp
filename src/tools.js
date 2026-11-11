import { readdir, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { MCP_STAMP_PATH, MCP_STAMP_TIMEOUT_MS, origin, getStampKey, stampKeyConfigured, VERSION } from './config.js';
import { normalizeHash, readFileBytes, sha256Bytes, sha256File, sha256Text, utf8Bytes } from './hash.js';
import { loadVerifier } from './verifier.js';

const FETCH_TIMEOUT_MS = 20000;

function userAgent() {
  return `lightdrawer-mcp/${VERSION}`;
}

function nonempty(value) {
  return value != null && String(value).length > 0;
}

function picked(args, keys) {
  return keys.filter((k) => nonempty(args[k]));
}

export function fail(message, extra = {}) {
  return { ok: false, error: message, ...extra };
}

export async function fetchJson(url, opts = {}) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), opts.timeoutMs || FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      ...opts,
      signal: ac.signal,
      headers: {
        'user-agent': userAgent(),
        ...(opts.headers || {}),
      },
    });
    const text = await res.text();
    let body = null;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = null;
      }
    }
    return { status: res.status, ok: res.ok, body, text };
  } finally {
    clearTimeout(timer);
  }
}

function receiptPageUrl(hash) {
  return `${origin()}/r/${hash}`;
}

function fragmentHandoffUrl(hash) {
  return `${origin()}/#digest=${hash}`;
}

function expectHandoffUrl(hash) {
  return `${origin()}/?expect=${hash}`;
}

export async function hashFileOrText({ file, text }) {
  if (nonempty(file) && nonempty(text)) {
    throw new Error('Provide a file or text, not both.');
  }
  if (nonempty(file)) {
    const hash = await sha256File(file);
    const info = await stat(file);
    return { hash, source: 'file', file: String(file), bytes: info.size };
  }
  if (nonempty(text)) {
    const bytes = utf8Bytes(text);
    return { hash: sha256Text(text), source: 'text', bytes: bytes.length };
  }
  throw new Error('Provide a file path or some text.');
}

export const STAMP_DESCRIPTION = `Hash a file or some text locally (SHA-256) and timestamp that fingerprint with LightDrawer. The file or text never leaves this machine — only the 64-character hash is used.

This tool returns a browser link so you can finish stamping on LightDrawer: open the link, drop the same file, complete the human check, and download the receipt. The recommended link uses #digest=<hash>, which stays in the URL fragment and is not sent to any server.

Provide exactly one of "file" (a local path) or "text".`;

export const VERIFY_DESCRIPTION = `Verify a LightDrawer receipt ZIP (or an extracted receipt folder) on this machine using LightDrawer's offline verifier. Optionally pass the original "file" or "text" to check that it matches the receipt.

This checks: the statement is well-formed; the original file or text hash matches if supplied; the OpenTimestamps proof (offline: digest and structure, including any claimed Bitcoin block); the RFC 3161 FreeTSA token (signature and pinned root); the Certificate Transparency proof, including Let's Encrypt precertificate SCTs against bundled log keys; and a Rekor entry if the receipt has one.

This does not: upload anything; look up Bitcoin blocks online; upgrade pending proofs; check FreeTSA revocation lists; or validate C2PA Content Credentials (they are read only).

Provide "receipt" (a path). Optionally provide "file" or "text", but not both.`;

export const LOOKUP_DESCRIPTION = `Look up whether LightDrawer has a public record for a SHA-256 fingerprint. Uses the public lookup API and also returns the page https://lightdrawer.org/r/<hash>.

For receipts made on the LightDrawer website, the fingerprint in /r/<hash> is the SHA-256 of statement.json inside the receipt, not the original file's hash. Pass "receipt" to read that fingerprint from a receipt ZIP, or pass "hash" if you already have it.

If you pass "file" or "text", this tool hashes it locally and looks up that hash. That finds stamps of the file or text itself (for example a hash that was stamped directly). It will not find a website-made receipt unless you pass the statement.json hash or the receipt file.

Provide exactly one of "hash", "file", "text", or "receipt".`;

// Same JSON body as a keyed POST /api/stamp: { digest, tsq? }.
// Never include file bytes, text, or a stamp key in this object.
function buildStampBody(hash) {
  const body = { digest: hash };
  try {
    const verifier = loadVerifier();
    const { tsq } = verifier.tsaBuildRequest(verifier.fromHex(hash));
    body.tsq = verifier.toB64(tsq);
  } catch {
    /* tsq is optional; digest alone is a valid stamp body */
  }
  return body;
}

function handoffResult(hashed) {
  return {
    ok: true,
    mode: 'browser_handoff',
    hash: hashed.hash,
    source: hashed.source,
    file: hashed.file || null,
    bytes: hashed.bytes,
    handoff: {
      fragment_url: fragmentHandoffUrl(hashed.hash),
      expect_url: expectHandoffUrl(hashed.hash),
    },
    instructions: [
      'Only the SHA-256 fingerprint was computed here. The file or text never left this machine.',
      'Open the fragment_url. The hash after #digest= stays in the browser and is not sent to any server.',
      hashed.source === 'text'
        ? 'Save the exact same text (UTF-8) to a file and drop that file on LightDrawer so the fingerprint matches.'
        : 'Drop the same file on LightDrawer to confirm it.',
      'Complete the human check on the site and download your receipt.',
    ],
  };
}

function stampSuccess(hashed, res) {
  const ots = res.body.ots && typeof res.body.ots === 'object' ? res.body.ots : {};
  return {
    ok: true,
    mode: 'api',
    hash: hashed.hash,
    source: hashed.source,
    file: hashed.file || null,
    bytes: hashed.bytes,
    receipt_url: receiptPageUrl(hashed.hash),
    ots_calendars: Object.keys(ots),
    rfc3161: !!res.body.tsr,
    errors: Array.isArray(res.body.errors) ? res.body.errors : [],
    notes: [
      'Only the SHA-256 fingerprint was sent to LightDrawer. The file or text was not uploaded.',
      'This stamps the file or text hash itself. Receipts made in the LightDrawer browser app stamp a statement.json that wraps the file hash, so their /r/ links use a different fingerprint (the SHA-256 of statement.json).',
    ],
  };
}

function interpretStampResponse(hashed, res) {
  if (res.status === 401) {
    return fail('LightDrawer rejected the stamp key (invalid or revoked).', { hash: hashed.hash, status: 401 });
  }
  if (res.status === 429) {
    return fail('LightDrawer rate-limited this stamp request. Try again in a minute.', { hash: hashed.hash, status: 429 });
  }
  if (!res.body || typeof res.body !== 'object') {
    return fail('LightDrawer returned an unexpected stamp response.', { hash: hashed.hash, status: res.status });
  }
  if (!res.ok) {
    const message = typeof res.body.error === 'string' ? res.body.error : 'LightDrawer could not stamp this hash.';
    return fail(message, { hash: hashed.hash, status: res.status });
  }
  return stampSuccess(hashed, res);
}

// Statuses that mean the reserved open lane is not available yet.
const MCP_STAMP_UNAVAILABLE = new Set([403, 404, 405]);

export async function stamp(args = {}, { fetchImpl = fetchJson } = {}) {
  const keys = picked(args, ['file', 'text']);
  if (keys.length !== 1) return fail('Provide exactly one of file or text.');
  let hashed;
  try {
    hashed = await hashFileOrText({ file: args.file, text: args.text });
  } catch (err) {
    return fail(err.message);
  }

  const body = buildStampBody(hashed.hash);
  const key = getStampKey();
  if (key) {
    let res;
    try {
      res = await fetchImpl(`${origin()}/api/stamp`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${key}`,
        },
        body: JSON.stringify(body),
      });
    } catch (err) {
      return fail('Could not reach LightDrawer to stamp this hash.', {
        hash: hashed.hash,
        detail: err && err.name === 'AbortError' ? 'The request timed out.' : 'Network error.',
      });
    }
    return interpretStampResponse(hashed, res);
  }

  // Keyless default: try the reserved future open lane first so that
  // lane can ship later with zero config change. POST only the hash
  // (same body as /api/stamp: { digest, tsq? }), never file bytes,
  // and never an Authorization header. Today /api/mcp/stamp 404s;
  // 404, 405, 403, or a network error fall back silently to the
  // browser hand-off (#digest=).
  let res;
  try {
    res = await fetchImpl(`${origin()}${MCP_STAMP_PATH}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      timeoutMs: MCP_STAMP_TIMEOUT_MS,
    });
  } catch {
    return handoffResult(hashed);
  }
  if (MCP_STAMP_UNAVAILABLE.has(res.status)) return handoffResult(hashed);
  return interpretStampResponse(hashed, res);
}

async function readReceiptFiles(receiptPath, verifier) {
  const info = await stat(receiptPath);
  if (info.isDirectory()) {
    const files = {};
    async function walk(dir, prefix, depth) {
      if (depth > 4) return;
      for (const entry of await readdir(dir, { withFileTypes: true })) {
        if (entry.name === '.' || entry.name === '..') continue;
        const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
        const full = join(dir, entry.name);
        if (entry.isDirectory()) await walk(full, rel, depth + 1);
        else files[rel] = new Uint8Array(await readFile(full));
      }
    }
    await walk(receiptPath, '', 0);
    return files;
  }
  if (!info.isFile()) throw new Error(`Not a receipt file or folder: ${receiptPath}`);
  const bytes = new Uint8Array(await readFile(receiptPath));
  return verifier.zipRead(bytes);
}

function summarizeVerify(result) {
  const sections = (result.sections || []).map((section) => ({
    title: section.title,
    checks: (section.checks || []).map((c) => ({
      id: c.id,
      status: c.status,
      title: c.title,
      detail: c.detail || '',
    })),
  }));
  const times = (result.times || []).map((t) => ({
    source: t.source,
    time: t.time instanceof Date ? t.time.toISOString() : t.time,
    note: t.note || '',
  }));
  return {
    verdict: result.verdict,
    statement_sha256: result.statementDigestHex || null,
    subject: result.statement && result.statement.subject ? result.statement.subject : null,
    sections,
    times,
  };
}

const VERIFY_LIMITS = [
  'Ran LightDrawer\'s offline verifier locally. Nothing was uploaded.',
  'OpenTimestamps proofs are checked offline (digest and structure, including any claimed Bitcoin block). Live Bitcoin block lookup is not performed.',
  'Pending OpenTimestamps or certificate-log proofs are not upgraded over the network.',
  'FreeTSA revocation (CRL/OCSP) is not checked. Only the pinned FreeTSA root is trusted.',
  'C2PA Content Credentials are read, not validated.',
];

export async function verify(args = {}) {
  if (!nonempty(args.receipt)) return fail('Provide a receipt path (a .zip file or an extracted receipt folder).');
  const extras = picked(args, ['file', 'text']);
  if (extras.length > 1) return fail('Provide a file or text to check against the receipt, not both.');

  let verifier;
  try {
    verifier = loadVerifier();
  } catch (err) {
    return fail('Could not load the offline verifier.', { detail: String(err && err.message ? err.message : err) });
  }

  let files;
  try {
    files = await readReceiptFiles(String(args.receipt), verifier);
  } catch (err) {
    return fail(`Could not read the receipt: ${err.message}`);
  }
  if (!files['statement.json']) {
    return fail('This does not look like a LightDrawer receipt (no statement.json).', { receipt: String(args.receipt) });
  }

  let original = null;
  try {
    if (nonempty(args.file)) {
      original = { bytes: await readFileBytes(args.file), name: String(args.file) };
    } else if (nonempty(args.text)) {
      original = { bytes: utf8Bytes(args.text), name: 'text' };
    }
  } catch (err) {
    return fail(err.message);
  }

  const result = await verifier.verifyReceipt(files, original, {});
  const summary = summarizeVerify(result);
  return {
    ok: true,
    verdict: summary.verdict,
    receipt: String(args.receipt),
    ...summary,
    limits: VERIFY_LIMITS,
  };
}

export async function statementHashFromReceipt(receiptPath) {
  const verifier = loadVerifier();
  const files = await readReceiptFiles(receiptPath, verifier);
  const statement = files['statement.json'];
  if (!statement) throw new Error('This does not look like a LightDrawer receipt (no statement.json).');
  return sha256Bytes(Buffer.from(statement));
}

export async function lookup(args = {}, { fetchImpl = fetchJson } = {}) {
  const keys = picked(args, ['hash', 'file', 'text', 'receipt']);
  if (keys.length !== 1) return fail('Provide exactly one of hash, file, text, or receipt.');

  let hash = null;
  let source = keys[0];
  try {
    if (keys[0] === 'hash') {
      hash = normalizeHash(args.hash);
      if (!hash) return fail('hash must be a 64-character SHA-256 hex string.');
    } else if (keys[0] === 'file') {
      hash = await sha256File(args.file);
    } else if (keys[0] === 'text') {
      hash = sha256Text(args.text);
    } else {
      hash = await statementHashFromReceipt(String(args.receipt));
    }
  } catch (err) {
    return fail(err.message);
  }

  const url = `${origin()}/api/lookup?digest=${hash}`;
  const page = receiptPageUrl(hash);
  let res;
  try {
    res = await fetchImpl(url, { method: 'GET', headers: { accept: 'application/json' } });
  } catch (err) {
    return fail('Could not reach LightDrawer to look up this fingerprint.', {
      hash,
      receipt_url: page,
      detail: err && err.name === 'AbortError' ? 'The request timed out.' : 'Network error.',
    });
  }

  if (res.status === 400 || (res.body && res.body.error && res.status === 400)) {
    return fail('LightDrawer said this fingerprint is not a valid SHA-256.', { hash, status: res.status, receipt_url: page });
  }

  const record = res.body && typeof res.body === 'object' ? res.body : null;
  const found = !!(record && record.found === true);
  if (!record) {
    return fail('LightDrawer returned an unexpected lookup response.', { hash, status: res.status, receipt_url: page });
  }

  return {
    ok: true,
    found,
    hash,
    source,
    receipt_url: page,
    status: found ? record.status || null : 'not_found',
    record,
    notes: [
      'For receipts made on the LightDrawer website, the fingerprint in the /r/ link is the SHA-256 of statement.json, not of the original file alone.',
      source === 'file' || source === 'text'
        ? 'This lookup used the SHA-256 of the file or text itself. That will not match a website-made receipt unless you pass the receipt file or its statement.json hash.'
        : 'Anyone can open the receipt_url. It shows only the fingerprint and timestamps, never a file.',
    ],
  };
}

export function formatToolResult(result) {
  return JSON.stringify(result, null, 2);
}

export { receiptPageUrl, fragmentHandoffUrl, expectHandoffUrl, stampKeyConfigured };
