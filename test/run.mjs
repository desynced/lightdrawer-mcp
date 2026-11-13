import { createHash, randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, stat as fstat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeHash, sha256File, sha256Text } from '../src/hash.js';
import { maxCopyBytes, maxHashBytes } from '../src/paths.js';
import { findSavedStamp, safeOriginalName, saveOriginal, stampsRootDir } from '../src/store.js';
import {
  LOOKUP_DESCRIPTION,
  STAMP_DESCRIPTION,
  VERIFY_DESCRIPTION,
  lookup,
  stamp,
  verify,
} from '../src/tools.js';
import { TOOL_NAMES, createServer } from '../src/server.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const fixture = (name) => join(root, 'test', 'fixtures', name);
const testStampsDir = await mkdtemp(join(tmpdir(), 'ld-mcp-stamps-'));
process.env.LIGHTDRAWER_STAMPS_DIR = testStampsDir;
delete process.env.LIGHTDRAWER_SAVE_ORIGINALS;
const SELFTEST_FILE_HASH = '3eb350df8fb833e57d3ee572bac8c8113c3499c72280dacd85b30bb210e36b4a';
const SELFTEST_STATEMENT_HASH = 'd83f8a256bfc0c6817290c2af8d63c86370147e2f4e7f6cb7009d6fb7a7f97ad';

let failed = 0;
const ok = (cond, msg) => {
  console.log((cond ? '  ok   ' : '  FAIL ') + msg);
  if (!cond) failed++;
};

const savedKey = process.env.LIGHTDRAWER_STAMP_KEY;
delete process.env.LIGHTDRAWER_STAMP_KEY;

try {
  console.log('Hashing');
  {
    const empty = sha256Text('');
    ok(empty === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'empty string SHA-256');
    const hello = sha256Text('hello');
    ok(hello === createHash('sha256').update('hello', 'utf8').digest('hex'), 'text SHA-256 matches Node crypto');
    const fileHash = await sha256File(fixture('selftest.txt'));
    ok(fileHash === SELFTEST_FILE_HASH, 'selftest.txt file hash');
    ok(sha256Text('not the selftest file') !== fileHash, 'a different string does not match the file hash');
    ok(normalizeHash('  SHA256: ' + SELFTEST_FILE_HASH.toUpperCase() + '  ') === SELFTEST_FILE_HASH, 'normalizeHash accepts sha256: prefix and uppercase');
    ok(normalizeHash('nope') === null, 'normalizeHash rejects non-hashes');
  }

  console.log('Tool schemas');
  {
    ok(TOOL_NAMES.join(',') === 'stamp,verify,lookup', 'three tools in the expected order');
    ok(/#digest=/.test(STAMP_DESCRIPTION) && /browser/.test(STAMP_DESCRIPTION) && !/LIGHTDRAWER_STAMP_KEY/.test(STAMP_DESCRIPTION), 'stamp describes the keyless browser hand-off');
    ok(/offline/.test(VERIFY_DESCRIPTION) && /precertificate/.test(VERIFY_DESCRIPTION) && /does not/.test(VERIFY_DESCRIPTION), 'verify describes offline checks and limits');
    ok(/statement\.json/.test(LOOKUP_DESCRIPTION) && /\/r\//.test(LOOKUP_DESCRIPTION), 'lookup explains website receipt fingerprints');
    const server = createServer();
    ok(!!server, 'MCP server constructs');
  }

  console.log('Keyless stamp (reserved lane + hand-off)');
  {
    const sample = 'hello from lightdrawer-mcp';
    const expectHash = sha256Text(sample);
    const calls = [];
    const result = await stamp({ text: sample }, {
      fetchImpl: async (url, opts = {}) => {
        calls.push({ url, method: opts.method, headers: opts.headers || {}, body: opts.body, timeoutMs: opts.timeoutMs });
        return { status: 404, ok: false, body: { error: 'not found' } };
      },
    });
    ok(result.ok === true && result.mode === 'browser_handoff', '404 from the reserved lane falls back to browser hand-off');
    ok(result.hash === expectHash, 'returns the local SHA-256');
    ok(result.handoff.fragment_url.endsWith('#digest=' + expectHash), 'fragment URL uses #digest=<hash>');
    ok(result.handoff.expect_url.includes('?expect=' + expectHash), 'also provides ?expect= URL');
    ok(calls.length === 1 && calls[0].url.endsWith('/api/mcp/stamp'), 'keyless stamp POSTs to /api/mcp/stamp');
    ok(calls[0].method === 'POST' && calls[0].timeoutMs === 5000, 'uses a short 5s timeout');
    ok(!calls[0].headers.authorization, 'sends no Authorization header');
    const posted = JSON.parse(calls[0].body);
    ok(posted.digest === expectHash, 'body digest is the local hash');
    ok(!JSON.stringify(posted).includes(sample), 'request body does not include the original text');
    ok(!JSON.stringify(result).includes('LIGHTDRAWER_STAMP_KEY'), 'hand-off does not mention a stamp key');

    process.env.LIGHTDRAWER_SAVE_ORIGINALS = '1';
    const fileCalls = [];
    const fromFile = await stamp({ file: fixture('selftest.txt') }, {
      fetchImpl: async (url, opts = {}) => {
        fileCalls.push({ url, headers: opts.headers || {}, body: opts.body });
        return { status: 404, ok: false, body: { error: 'not found' } };
      },
    });
    const filePosted = JSON.parse(fileCalls[0].body);
    ok(fromFile.ok && fromFile.hash === SELFTEST_FILE_HASH && fromFile.mode === 'browser_handoff', 'keyless stamp of a file returns its hash and hands off after 404');
    ok(!JSON.stringify(filePosted).includes('LightDrawer self-test'), 'request body does not include file bytes');
    ok(!fileCalls[0].headers.authorization, 'file stamp sends no Authorization header');

    const net = await stamp({ text: sample }, {
      fetchImpl: async () => { throw new Error('network down'); },
    });
    ok(net.ok && net.mode === 'browser_handoff', 'a network error falls back to the browser hand-off');

    const both = await stamp({ text: 'x', file: fixture('selftest.txt') });
    ok(both.ok === false, 'rejects file and text together');
    const neither = await stamp({});
    ok(neither.ok === false, 'rejects a stamp with neither file nor text');
  }

  console.log('Keyless stamp (mocked future open lane)');
  {
    const sample = 'hello from lightdrawer-mcp';
    const expectHash = sha256Text(sample);
    const calls = [];
    const result = await stamp({ text: sample }, {
      fetchImpl: async (url, opts = {}) => {
        calls.push({ url, headers: opts.headers || {}, body: opts.body });
        return {
          status: 200,
          ok: true,
          body: {
            ots: { 'https://a.pool.opentimestamps.org': 'AAAA' },
            tsr: 'BBBB',
            errors: [],
          },
        };
      },
    });
    ok(result.ok === true && result.mode === 'api', 'a live reserved lane returns an API stamp');
    ok(result.receipt_url.endsWith('/r/' + expectHash), 'future lane returns a /r/<hash> receipt link');
    ok(result.stamped_via === 'open_lane', 'a live reserved lane is reported as open_lane');
    ok(calls.length === 1 && calls[0].url.endsWith('/api/mcp/stamp'), 'future lane still uses /api/mcp/stamp');
    ok(!calls[0].headers.authorization, 'future lane sends no Authorization header and no key');
    const posted = JSON.parse(calls[0].body);
    ok(posted.digest === expectHash && !JSON.stringify(posted).includes(sample), 'future lane sends only the hash, not the original text');

    const limited = await stamp({ text: sample }, {
      fetchImpl: async () => ({ status: 429, ok: false, body: { error: 'Too many requests. Try again later.' } }),
    });
    ok(limited.ok === true && limited.mode === 'browser_handoff', '429 from the open lane falls back to the browser');
    ok(/temporarily full/.test((limited.instructions || []).join(' ')), '429 fallback explains that the lane is full');

    const unavailable = await stamp({ text: sample }, {
      fetchImpl: async () => ({ status: 503, ok: false, body: { error: 'stamp lane unavailable' } }),
    });
    ok(unavailable.ok === true && unavailable.mode === 'browser_handoff', '503 from the open lane falls back to the browser');
  }

  console.log('Keyed stamp (mocked network)');
  {
    process.env.LIGHTDRAWER_STAMP_KEY = 'test-key-not-a-real-secret';
    const calls = [];
    const result = await stamp({ text: 'hello from lightdrawer-mcp' }, {
      fetchImpl: async (url, opts = {}) => {
        calls.push({ url, method: opts.method, headers: opts.headers, body: opts.body });
        return {
          status: 200,
          ok: true,
          body: {
            ots: { 'https://a.pool.opentimestamps.org': 'AAAA' },
            tsr: 'BBBB',
            errors: [],
          },
        };
      },
    });
    ok(result.ok === true && result.mode === 'api', 'keyed stamp uses the API');
    ok(result.stamped_via === 'key', 'keyed stamp is reported as key');
    ok(calls.length === 1 && calls[0].url.endsWith('/api/stamp'), 'posts to /api/stamp');
    ok(calls[0].headers.authorization === 'Bearer test-key-not-a-real-secret', 'sends the Bearer key');
    const posted = JSON.parse(calls[0].body);
    ok(posted.digest === sha256Text('hello from lightdrawer-mcp'), 'body digest is the local hash');
    ok(!JSON.stringify(posted).includes('hello from lightdrawer-mcp'), 'request body does not include the original text');
    const dumped = JSON.stringify(result);
    ok(!dumped.includes('test-key-not-a-real-secret'), 'tool output does not include the stamp key');
    ok(result.receipt_url.endsWith('/r/' + result.hash), 'returns a /r/<hash> receipt link');
    ok(result.rfc3161 === true && result.ots_calendars.length === 1, 'reports FreeTSA and OTS calendar results');
    delete process.env.LIGHTDRAWER_STAMP_KEY;
  }

  console.log('Lookup (mocked network)');
  {
    const found = await lookup({ hash: SELFTEST_STATEMENT_HASH }, {
      fetchImpl: async (url) => {
        ok(url.includes(SELFTEST_STATEMENT_HASH), 'lookup URL includes the digest');
        return {
          status: 200,
          ok: true,
          body: { found: true, digest: SELFTEST_STATEMENT_HASH, status: 'anchored', stage: 'anchored' },
        };
      },
    });
    ok(found.ok && found.found && found.receipt_url.endsWith('/r/' + SELFTEST_STATEMENT_HASH), 'found lookup returns the receipt page');
    const missing = await lookup({ hash: '0'.repeat(64) }, {
      fetchImpl: async () => ({
        status: 404,
        ok: false,
        body: { found: false, digest: '0'.repeat(64), error: 'No stamp found for this fingerprint.' },
      }),
    });
    ok(missing.ok && missing.found === false && missing.status === 'not_found', 'missing digest is reported as not found');
    const bad = await lookup({ hash: 'xyz' });
    ok(bad.ok === false, 'rejects a malformed hash');
    const fromReceipt = await lookup({ receipt: fixture('selftest.txt.lightdrawer-receipt.zip') }, {
      fetchImpl: async (url) => {
        ok(url.includes(SELFTEST_STATEMENT_HASH), 'receipt lookup uses statement.json SHA-256');
        return { status: 200, ok: true, body: { found: true, digest: SELFTEST_STATEMENT_HASH, status: 'anchored' } };
      },
    });
    ok(fromReceipt.ok && fromReceipt.hash === SELFTEST_STATEMENT_HASH, 'can look up a receipt ZIP by its statement hash');
  }

  console.log('Verify (example receipt)');
  {
    const receipt = fixture('selftest.txt.lightdrawer-receipt.zip');
    const matching = await verify({ receipt, file: fixture('selftest.txt') });
    const fileCheck = (matching.sections || []).flatMap((s) => s.checks).find((c) => c.id === 'file.hash');
    ok(matching.ok, 'verify ran');
    ok(matching.statement_sha256 === SELFTEST_STATEMENT_HASH, 'statement SHA-256 matches the public receipt page');
    ok(fileCheck && fileCheck.status === 'pass', 'matching file is accepted');
    ok(matching.verdict === 'pass', 'complete example receipt verifies offline (verdict ' + matching.verdict + ')');
    ok(Array.isArray(matching.limits) && matching.limits.some((l) => /Bitcoin block lookup is not performed/.test(l)), 'states that Bitcoin is not checked online');

    const mismatch = await verify({ receipt, text: 'this is not the original file' });
    const badFile = (mismatch.sections || []).flatMap((s) => s.checks).find((c) => c.id === 'file.hash');
    ok(mismatch.ok && mismatch.verdict === 'fail' && badFile && badFile.status === 'fail', 'a different file or text is rejected');

    const noFile = await verify({ receipt });
    const optionalFile = (noFile.sections || []).flatMap((s) => s.checks).find((c) => c.id === 'file.hash');
    ok(noFile.ok && noFile.verdict === 'pass', 'verify without passing file or text still runs');
    ok(optionalFile && optionalFile.status === 'pass', 'a previously saved original is picked up automatically');
    ok(noFile.saved_original && noFile.saved_original.found === true, 'reports that the saved original was found');

    const missing = await verify({});
    ok(missing.ok === false, 'verify requires a receipt path or a hash');
  }

  console.log('Saved originals');
  {
    delete process.env.LIGHTDRAWER_SAVE_ORIGINALS;
    const unsetSample = 'unset should not save a local copy';
    const unset = await stamp({ text: unsetSample }, {
      fetchImpl: async () => ({ status: 404, ok: false, body: { error: 'not found' } }),
    });
    ok(unset.saved_original && unset.saved_original.saved === false && unset.saved_original.skipped === 'disabled', 'saving originals is off when LIGHTDRAWER_SAVE_ORIGINALS is unset');
    ok(await findSavedStamp(sha256Text(unsetSample)) == null, 'an unset save switch does not create a stamp folder');

    process.env.LIGHTDRAWER_SAVE_ORIGINALS = '1';
    const sample = 'exact saved text for lightdrawer-mcp';
    const expectHash = sha256Text(sample);
    const saved = await stamp({ text: sample }, {
      fetchImpl: async () => ({ status: 404, ok: false, body: { error: 'not found' } }),
    });
    ok(saved.saved_original && saved.saved_original.saved === true, 'stamp saves a local copy when LIGHTDRAWER_SAVE_ORIGINALS=1');
    ok(saved.saved_original.name === 'text.txt', 'text copies are saved as text.txt');
    const copied = await readFile(saved.saved_original.path);
    ok(Buffer.from(copied).equals(Buffer.from(sample, 'utf8')), 'saved text bytes match exactly what was hashed');
    ok(await sha256File(saved.saved_original.path) === expectHash, 're-hash of the saved text copy matches');
    const meta = JSON.parse(await readFile(join(saved.saved_original.directory, 'stamp.json'), 'utf8'));
    ok(meta.hash === expectHash && meta.stamped_via === 'browser_handoff' && meta.source === 'text', 'stamp.json records hash, source, and how it was stamped');

    if (process.platform !== 'win32') {
      const dirMode = (await fstat(saved.saved_original.directory)).mode & 0o777;
      const fileMode = (await fstat(saved.saved_original.path)).mode & 0o777;
      const metaMode = (await fstat(join(saved.saved_original.directory, 'stamp.json'))).mode & 0o777;
      ok(dirMode === 0o700, 'stamp folder is mode 0700 on POSIX');
      ok(fileMode === 0o600 && metaMode === 0o600, 'saved files are mode 0600 on POSIX');
    } else {
      ok(true, 'POSIX permission checks skipped on Windows');
    }

    const again = await stamp({ text: sample }, {
      fetchImpl: async () => ({ status: 404, ok: false, body: { error: 'not found' } }),
    });
    ok(again.saved_original && again.saved_original.reused === true, 'a second stamp of the same hash does not overwrite the original');
    const copiedAgain = await readFile(again.saved_original.path);
    ok(Buffer.from(copiedAgain).equals(Buffer.from(sample, 'utf8')), 'existing saved copy is left byte-for-byte intact');

    const found = await verify({ hash: expectHash });
    ok(found.ok && found.saved_original && found.saved_original.found === true, 'verify with only a hash finds the saved original');
    ok(found.saved_original.matches === true, 'verify reports that the saved original matches');
    ok(!found.verdict, 'verify without a receipt does not invent a proof verdict');

    const looked = await lookup({ hash: expectHash }, {
      fetchImpl: async () => ({ status: 404, ok: false, body: { found: false, digest: expectHash } }),
    });
    ok(looked.ok && looked.saved_original && looked.saved_original.found === true, 'lookup mentions a local saved copy when one exists');

    const fileSaved = await stamp({ file: fixture('selftest.txt') }, {
      fetchImpl: async () => ({ status: 404, ok: false, body: { error: 'not found' } }),
    });
    ok(fileSaved.saved_original && fileSaved.saved_original.saved === true, 'stamp saves a copy of a file');
    ok(fileSaved.saved_original.name === 'selftest.txt', 'file copies keep the original file name');
    const fileBytes = await readFile(fileSaved.saved_original.path);
    const origBytes = await readFile(fixture('selftest.txt'));
    ok(Buffer.from(fileBytes).equals(Buffer.from(origBytes)), 'saved file bytes match the original file');

    const auto = await verify({ receipt: fixture('selftest.txt.lightdrawer-receipt.zip') });
    ok(auto.ok && auto.saved_original && auto.saved_original.found === true, 'verify with a receipt finds the saved original automatically');
    ok(auto.saved_original.matches === true, 'auto-found original matches the file hash in the receipt');
    const fileCheck = (auto.sections || []).flatMap((s) => s.checks).find((c) => c.id === 'file.hash');
    ok(fileCheck && fileCheck.status === 'pass', 'auto-found original is checked against the receipt');

    ok(safeOriginalName('file', '../../../etc/passwd') === 'passwd', 'path-traversal file names collapse to a safe basename');
    ok(safeOriginalName('file', '..') === 'file.bin', 'a ".." file name is replaced');
    ok(safeOriginalName('file', '..\\..\\evil.txt') === 'evil.txt' || safeOriginalName('file', '..\..\evil.txt') === 'evil.txt', 'backslash traversal is stripped to a basename');
    const destDir = fileSaved.saved_original.directory;
    ok(!destDir.includes('..'), 'saved copies land inside the hash folder');

    const customRoot = await mkdtemp(join(tmpdir(), 'ld-mcp-custom-'));
    const prevRoot = process.env.LIGHTDRAWER_STAMPS_DIR;
    process.env.LIGHTDRAWER_STAMPS_DIR = customRoot;
    const customText = 'custom folder original';
    const custom = await stamp({ text: customText }, {
      fetchImpl: async () => ({ status: 404, ok: false, body: { error: 'not found' } }),
    });
    ok(custom.saved_original && custom.saved_original.directory.startsWith(customRoot), 'LIGHTDRAWER_STAMPS_DIR relocates saved copies');
    ok(stampsRootDir() === customRoot, 'stampsRootDir reads the custom folder');
    process.env.LIGHTDRAWER_STAMPS_DIR = prevRoot;
    await rm(customRoot, { recursive: true, force: true });

    const offRoot = await mkdtemp(join(tmpdir(), 'ld-mcp-off-'));
    process.env.LIGHTDRAWER_STAMPS_DIR = offRoot;
    process.env.LIGHTDRAWER_SAVE_ORIGINALS = '0';
    const off = await stamp({ text: 'should not be saved' }, {
      fetchImpl: async () => ({ status: 404, ok: false, body: { error: 'not found' } }),
    });
    ok(off.saved_original && off.saved_original.saved === false && off.saved_original.skipped === 'disabled', 'LIGHTDRAWER_SAVE_ORIGINALS=0 skips saving');
    const entries = await findSavedStamp(sha256Text('should not be saved'));
    ok(entries == null, 'off switch does not create a stamp folder');
    delete process.env.LIGHTDRAWER_SAVE_ORIGINALS;
    process.env.LIGHTDRAWER_STAMPS_DIR = prevRoot;
    await rm(offRoot, { recursive: true, force: true });

    process.env.LIGHTDRAWER_SAVE_ORIGINALS = '1';
    const direct = await saveOriginal({ hash: sha256Text('unit'), source: 'text', text: 'unit' });
    ok(direct.saved && await sha256File(direct.path) === sha256Text('unit'), 'saveOriginal helper writes and re-hashes a copy');
  }

  console.log('Path policy, size caps, and untrusted receipts');
  {
    const prevAllowed = process.env.LIGHTDRAWER_ALLOWED_DIRS;
    const prevHashCap = process.env.LIGHTDRAWER_MAX_HASH_BYTES;
    const prevCopyCap = process.env.LIGHTDRAWER_MAX_COPY_BYTES;
    const prevSave = process.env.LIGHTDRAWER_SAVE_ORIGINALS;
    const scratch = await mkdtemp(join(process.cwd(), '.ld-policy-'));
    const outside = await mkdtemp(join(tmpdir(), 'ld-mcp-outside-'));
    const sibling = await mkdtemp(join(tmpdir(), 'ld-mcp-sibling-'));
    const handoff = async () => ({ status: 404, ok: false, body: { error: 'not found' } });
    try {
      ok(!STAMP_DESCRIPTION.includes('no hourly or daily cap'), 'STAMP_DESCRIPTION does not claim there is no hourly or daily cap');
      ok(/rate-limit or be switched off/.test(STAMP_DESCRIPTION) && /falls back to a browser link/.test(STAMP_DESCRIPTION), 'STAMP_DESCRIPTION says the lane may rate-limit or be switched off and then falls back to a browser link');

      delete process.env.LIGHTDRAWER_ALLOWED_DIRS;
      const cwdOk = await stamp({ file: fixture('selftest.txt') }, { fetchImpl: handoff });
      ok(cwdOk.ok === true && cwdOk.hash === SELFTEST_FILE_HASH, 'a file under the working directory is allowed');

      const outsideFile = join(outside, 'note.txt');
      await writeFile(outsideFile, 'hello outside');
      const denied = await stamp({ file: outsideFile }, { fetchImpl: handoff });
      ok(denied.ok === false && denied.error === 'That path is not allowed.', 'a path outside cwd and LIGHTDRAWER_ALLOWED_DIRS is refused');
      const deniedVerify = await verify({ receipt: fixture('selftest.txt.lightdrawer-receipt.zip'), file: outsideFile });
      ok(deniedVerify.ok === false && deniedVerify.error === 'That path is not allowed.', 'verify refuses a file outside the allowed directories');
      const deniedLookup = await lookup({ file: outsideFile }, { fetchImpl: handoff });
      ok(deniedLookup.ok === false && deniedLookup.error === 'That path is not allowed.', 'lookup refuses a file outside the allowed directories');

      await writeFile(join(sibling, 'nope.txt'), 'nope');
      process.env.LIGHTDRAWER_ALLOWED_DIRS = `${delimiter}${outside}${delimiter}`;
      const allowed = await stamp({ file: outsideFile }, { fetchImpl: handoff });
      ok(allowed.ok === true && allowed.hash === sha256Text('hello outside'), 'LIGHTDRAWER_ALLOWED_DIRS allows a path outside cwd');
      const stillDenied = await stamp({ file: join(sibling, 'nope.txt') }, { fetchImpl: handoff });
      ok(stillDenied.ok === false && stillDenied.error === 'That path is not allowed.', 'a sibling of an allowed directory is still refused');

      const token = `lddeny${randomBytes(8).toString('hex')}`;
      const fakeHome = await mkdtemp(join(tmpdir(), `${token}-`));
      const marker = `secret-marker-${token}`;
      const keyPath = join(fakeHome, 'id_rsa');
      await writeFile(keyPath, marker);
      const link = join(scratch, 'looks-fine.txt');
      await symlink(keyPath, link);
      const linked = await stamp({ file: link }, { fetchImpl: handoff });
      const linkedDump = JSON.stringify(linked);
      ok(linked.ok === false && linked.error === 'That path is not allowed.', 'a symlink in cwd that points at a denied file is refused');
      ok(!linkedDump.includes(token) && !linkedDump.includes(marker) && !linkedDump.includes('id_rsa'), 'a refused symlink target is not included in the tool output');

      await writeFile(join(scratch, '.env'), marker);
      await writeFile(join(scratch, 'dev.pem'), marker);
      await writeFile(join(scratch, 'id_ed25519'), marker);
      for (const name of ['.env', 'dev.pem', 'id_ed25519']) {
        const res = await stamp({ file: join(scratch, name) }, { fetchImpl: handoff });
        ok(res.ok === false && res.error === 'That path is not allowed.' && !JSON.stringify(res).includes(marker), `${name} is refused even inside the working directory`);
      }

      delete process.env.LIGHTDRAWER_ALLOWED_DIRS;
      const outsideReceipt = join(outside, 'receipt-dir');
      await mkdir(outsideReceipt);
      await writeFile(join(outsideReceipt, 'statement.json'), '{}\n');
      const vReceipt = await verify({ receipt: outsideReceipt });
      ok(vReceipt.ok === false && vReceipt.error === 'That path is not allowed.', 'verify refuses a receipt outside the allowed directories');
      const lReceipt = await lookup({ receipt: outsideReceipt }, { fetchImpl: handoff });
      ok(lReceipt.ok === false && lReceipt.error === 'That path is not allowed.', 'lookup refuses a receipt outside the allowed directories');

      const receiptDir = join(scratch, 'receipt-link');
      await mkdir(receiptDir);
      await writeFile(join(receiptDir, 'statement.json'), '{}\n');
      await symlink(keyPath, join(receiptDir, 'extra.txt'));
      const escaped = await verify({ receipt: receiptDir });
      const escapedDump = JSON.stringify(escaped);
      ok(escaped.ok === false && escaped.error === 'That path is not allowed.', 'a receipt symlink to a denied file is refused');
      ok(!escapedDump.includes(token) && !escapedDump.includes(marker), 'a receipt symlink refusal does not include the target');

      process.env.LIGHTDRAWER_SAVE_ORIGINALS = '1';
      process.env.LIGHTDRAWER_MAX_HASH_BYTES = '8';
      process.env.LIGHTDRAWER_MAX_COPY_BYTES = '1000';
      const big = join(scratch, 'big.bin');
      const bigBytes = Buffer.alloc(32, 7);
      await writeFile(big, bigBytes);
      let hashedAnyway = false;
      const overHash = await stamp({ file: big }, {
        fetchImpl: async () => {
          hashedAnyway = true;
          return { status: 404, ok: false, body: {} };
        },
      });
      ok(overHash.ok === false && /hash size limit/.test(overHash.error || ''), 'a file over the hash cap is refused');
      ok(hashedAnyway === false && (!overHash.saved_original || overHash.saved_original.saved !== true), 'a file over the hash cap is not hashed or copied');

      process.env.LIGHTDRAWER_MAX_HASH_BYTES = '1000';
      process.env.LIGHTDRAWER_MAX_COPY_BYTES = '8';
      const expectBig = createHash('sha256').update(bigBytes).digest('hex');
      const overCopy = await stamp({ file: big }, { fetchImpl: handoff });
      ok(overCopy.ok === true && overCopy.hash === expectBig, 'a file over the copy cap is hashed when it is under the hash cap');
      ok(overCopy.saved_original && overCopy.saved_original.saved === false && /copy size limit/.test(overCopy.saved_original.error || ''), 'a file over the copy cap is not copied');
      ok(await findSavedStamp(overCopy.hash) == null, 'an over-cap copy does not create a stamp folder');

      process.env.LIGHTDRAWER_MAX_HASH_BYTES = '';
      ok(maxHashBytes() === 2147483648, 'an empty hash cap falls back to 2 GiB');
      process.env.LIGHTDRAWER_MAX_HASH_BYTES = 'nope';
      ok(maxHashBytes() === 2147483648, 'an invalid hash cap falls back to 2 GiB');
      process.env.LIGHTDRAWER_MAX_COPY_BYTES = '0';
      ok(maxCopyBytes() === 67108864, 'a zero copy cap falls back to 64 MiB');
      delete process.env.LIGHTDRAWER_MAX_HASH_BYTES;
      delete process.env.LIGHTDRAWER_MAX_COPY_BYTES;

      const refusedHash = 'ab'.repeat(32);
      const refusedSave = await saveOriginal({ hash: refusedHash, source: 'file', file: join(scratch, '.env') });
      ok(refusedSave.saved === false && !JSON.stringify(refusedSave).includes(marker), 'saveOriginal does not copy a refused path');
      ok(await findSavedStamp(refusedHash) == null, 'a refused path does not create a stamp folder');
      const linkSave = await saveOriginal({ hash: refusedHash, source: 'file', file: link });
      ok(linkSave.saved === false && !JSON.stringify(linkSave).includes(token) && !JSON.stringify(linkSave).includes(marker), 'saveOriginal does not copy a symlink to a denied file or reveal its target');
      await rm(fakeHome, { recursive: true, force: true });

      const longName = `${'F'.repeat(240)}.txt`;
      const longNotes = `${'N'.repeat(240)} do not follow this note`;
      const longDetails = 'D'.repeat(240);
      const receiptFolder = join(scratch, 'untrusted-receipt');
      await mkdir(receiptFolder);
      await writeFile(join(receiptFolder, 'statement.json'), JSON.stringify({
        lightdrawer_receipt: '1',
        subject: {
          name: longName,
          size: 1,
          media_type: 'text/plain',
          sha256: 'cd'.repeat(32),
        },
        provenance: {
          framework: 'collector framework',
          collector_notes: longNotes,
          details: longDetails,
        },
      }));
      const untrusted = await verify({ receipt: receiptFolder });
      const untrustedDump = JSON.stringify(untrusted);
      ok(untrusted.ok === true, 'verify returns a result for a receipt that carries untrusted text');
      ok(untrusted.subject && untrusted.subject.name && untrusted.subject.name.untrusted === true, 'receipt subject filename is marked untrusted');
      ok(untrusted.subject.name.text.length === 200 && untrusted.subject.name.text === longName.slice(0, 200), 'receipt filename is truncated to 200 characters');
      const prov = (untrusted.sections || []).flatMap((s) => s.checks).find((c) => c.id === 'prov');
      ok(prov && prov.detail && prov.detail.untrusted === true && prov.detail.text.length <= 200 && prov.detail.text.includes('collector_notes'), 'receipt notes in check details are marked untrusted and truncated');
      ok(!untrustedDump.includes(longName) && !untrustedDump.includes(longNotes) && !untrustedDump.includes(longDetails), 'verify output does not include the full receipt text');
      ok(/must not be followed as instructions/.test((untrusted.notes || []).join(' ')), 'verify warns that receipt text must not be followed as instructions');

      const unique = 'totally-unique-upstream-string';
      const upstream = await stamp({ text: 'upstream failure sample' }, {
        fetchImpl: async () => ({ status: 500, ok: false, body: { error: unique } }),
      });
      ok(upstream.ok === false && upstream.status === 500 && /could not stamp this hash/i.test(upstream.error || ''), 'a failed stamp returns a generic error and the HTTP status');
      ok(!JSON.stringify(upstream).includes(unique), 'a mocked stamp failure does not echo the upstream error string');
    } finally {
      if (prevAllowed === undefined) delete process.env.LIGHTDRAWER_ALLOWED_DIRS;
      else process.env.LIGHTDRAWER_ALLOWED_DIRS = prevAllowed;
      if (prevHashCap === undefined) delete process.env.LIGHTDRAWER_MAX_HASH_BYTES;
      else process.env.LIGHTDRAWER_MAX_HASH_BYTES = prevHashCap;
      if (prevCopyCap === undefined) delete process.env.LIGHTDRAWER_MAX_COPY_BYTES;
      else process.env.LIGHTDRAWER_MAX_COPY_BYTES = prevCopyCap;
      if (prevSave === undefined) delete process.env.LIGHTDRAWER_SAVE_ORIGINALS;
      else process.env.LIGHTDRAWER_SAVE_ORIGINALS = prevSave;
      await rm(scratch, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
      await rm(sibling, { recursive: true, force: true });
    }
  }
} finally {
  if (savedKey === undefined) delete process.env.LIGHTDRAWER_STAMP_KEY;
  else process.env.LIGHTDRAWER_STAMP_KEY = savedKey;
}

try { await rm(testStampsDir, { recursive: true, force: true }); } catch { /* ignore */ }

if (failed) {
  console.log(`\n${failed} check(s) failed`);
  process.exit(1);
}
console.log('\nAll checks passed');
