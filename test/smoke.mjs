import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256Text } from '../src/hash.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const SELFTEST_STATEMENT_HASH = 'd83f8a256bfc0c6817290c2af8d63c86370147e2f4e7f6cb7009d6fb7a7f97ad';

function startServer() {
  const env = { ...process.env };
  delete env.LIGHTDRAWER_STAMP_KEY;
  const child = spawn(process.execPath, [join(root, 'src', 'index.js')], {
    cwd: root,
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const pending = [];
  const rl = createInterface({ input: child.stdout });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      console.error('non-JSON stdout:', line);
      return;
    }
    if (msg.id == null) return;
    const next = pending.find((p) => p.id === msg.id);
    if (next) {
      next.resolve(msg);
    }
  });
  child.stderr.on('data', (buf) => {
    const s = String(buf).trim();
    if (s) console.error('[server]', s);
  });
  return {
    child,
    send(id, method, params) {
      const payload = { jsonrpc: '2.0', id, method };
      if (params !== undefined) payload.params = params;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('timed out waiting for ' + method)), 25000);
        pending.push({
          id,
          resolve: (msg) => {
            clearTimeout(timer);
            resolve(msg);
          },
        });
        child.stdin.write(JSON.stringify(payload) + '\n');
      });
    },
    notify(method, params) {
      const payload = { jsonrpc: '2.0', method };
      if (params !== undefined) payload.params = params;
      child.stdin.write(JSON.stringify(payload) + '\n');
    },
    async close() {
      child.stdin.end();
      await new Promise((resolve) => child.once('exit', resolve));
    },
  };
}

function parseToolText(msg) {
  const text = msg.result && msg.result.content && msg.result.content[0] && msg.result.content[0].text;
  if (!text) throw new Error('missing tool text: ' + JSON.stringify(msg));
  return JSON.parse(text);
}

const server = startServer();
let failed = 0;
const ok = (cond, msg) => {
  console.log((cond ? '  ok   ' : '  FAIL ') + msg);
  if (!cond) failed++;
};

try {
  const init = await server.send(1, 'initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'lightdrawer-mcp-smoke', version: '0.1.0' },
  });
  ok(init.result && init.result.serverInfo && init.result.serverInfo.name === 'lightdrawer-mcp', 'initialize reports lightdrawer-mcp');
  ok(init.result.capabilities && init.result.capabilities.tools, 'server advertises tools');
  server.notify('notifications/initialized');

  const listed = await server.send(2, 'tools/list');
  const names = (listed.result.tools || []).map((t) => t.name);
  ok(names.join(',') === 'stamp,verify,lookup', 'tools/list returns stamp, verify, lookup');
  const stampTool = listed.result.tools.find((t) => t.name === 'stamp');
  ok(stampTool && /#digest=/.test(stampTool.description), 'stamp tool describes the #digest= browser hand-off');

  const looked = await server.send(3, 'tools/call', {
    name: 'lookup',
    arguments: { hash: SELFTEST_STATEMENT_HASH },
  });
  const lookupBody = parseToolText(looked);
  ok(lookupBody.ok && lookupBody.found === true, 'live lookup finds the example receipt hash');
  ok(lookupBody.receipt_url === 'https://lightdrawer.org/r/' + SELFTEST_STATEMENT_HASH, 'live lookup returns the public receipt link');

  const sample = 'lightdrawer-mcp smoke ' + Date.now();
  const stamped = await server.send(4, 'tools/call', {
    name: 'stamp',
    arguments: { text: sample },
  });
  const stampBody = parseToolText(stamped);
  ok(stampBody.ok && stampBody.mode === 'browser_handoff', 'keyless stamp over stdio returns a browser hand-off');
  ok(stampBody.hash === sha256Text(sample), 'keyless stamp hash matches the text');
  ok(stampBody.handoff.fragment_url.endsWith('#digest=' + stampBody.hash), 'keyless stamp includes #digest= hand-off link');
} catch (err) {
  console.log('  FAIL smoke test error: ' + (err && err.message ? err.message : err));
  failed++;
} finally {
  await server.close();
}

if (failed) {
  console.log(`\n${failed} smoke check(s) failed`);
  process.exit(1);
}
console.log('\nSmoke test passed');
