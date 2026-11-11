import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeHash, sha256File, sha256Text } from '../src/hash.js';
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
    ok(calls.length === 1 && calls[0].url.endsWith('/api/mcp/stamp'), 'future lane still uses /api/mcp/stamp');
    ok(!calls[0].headers.authorization, 'future lane sends no Authorization header and no key');
    const posted = JSON.parse(calls[0].body);
    ok(posted.digest === expectHash && !JSON.stringify(posted).includes(sample), 'future lane sends only the hash, not the original text');
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
    const skipped = (noFile.sections || []).flatMap((s) => s.checks).find((c) => c.id === 'file.hash');
    ok(noFile.ok && skipped && skipped.status === 'skip', 'original file is optional');

    const missing = await verify({});
    ok(missing.ok === false, 'verify requires a receipt path');
  }
} finally {
  if (savedKey === undefined) delete process.env.LIGHTDRAWER_STAMP_KEY;
  else process.env.LIGHTDRAWER_STAMP_KEY = savedKey;
}

if (failed) {
  console.log(`\n${failed} check(s) failed`);
  process.exit(1);
}
console.log('\nAll checks passed');
