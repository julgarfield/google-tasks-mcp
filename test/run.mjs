// Test runner: `npm test`.
//
// Builds a throwaway copy of the Worker whose five Google endpoint URLs point at the in-memory
// mock in mock-google.mjs, runs it in the local Workers runtime (wrangler dev) with fake
// credentials and a throwaway KV directory, and drives it over HTTP the way an MCP client would.
// It cannot reach your Google account: the copy contains no Google endpoint, and the credentials
// are fake. Nothing here deploys or touches production.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startMockGoogle } from './mock-google.mjs';
import { runTests } from './e2e.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const build = path.join(root, '.test-build');
const WORKER_PORT = 8799, MOCK_PORT = 9099;
const mockBase = `http://localhost:${MOCK_PORT}`;

fs.rmSync(build, { recursive: true, force: true });
fs.mkdirSync(path.join(build, 'src'), { recursive: true });
for (const file of fs.readdirSync(path.join(root, 'src'))) {
  let text = fs.readFileSync(path.join(root, 'src', file), 'utf8');
  if (file === 'google.ts') {
    const swaps = {
      'https://accounts.google.com/o/oauth2/v2/auth': `${mockBase}/auth`,
      'https://oauth2.googleapis.com/token': `${mockBase}/token`,
      'https://oauth2.googleapis.com/revoke': `${mockBase}/revoke`,
      'https://openidconnect.googleapis.com/v1/userinfo': `${mockBase}/userinfo`,
      'https://tasks.googleapis.com/tasks/v1': `${mockBase}/tasks/v1`,
    };
    for (const [from, to] of Object.entries(swaps)) {
      if (!text.includes(`'${from}'`)) throw new Error(`google.ts no longer contains ${from}; update test/run.mjs`);
      text = text.replace(`'${from}'`, `'${to}'`);
    }
    for (const host of ['accounts.google.com', 'oauth2.googleapis.com', 'openidconnect.googleapis.com', 'tasks.googleapis.com']) {
      if (text.includes(host)) throw new Error(`Refusing to run: test build still references ${host}`);
    }
  }
  fs.writeFileSync(path.join(build, 'src', file), text);
}
fs.writeFileSync(path.join(build, 'wrangler.jsonc'), JSON.stringify({
  name: 'google-tasks-mcp-test', main: 'src/index.ts', compatibility_date: '2026-11-01',
  kv_namespaces: [{ binding: 'OAUTH_KV', id: 'test-only' }],
}, null, 2));
fs.writeFileSync(path.join(build, '.dev.vars'), [
  'GOOGLE_CLIENT_ID=test-client-id', 'GOOGLE_CLIENT_SECRET=test-client-secret', 'ALLOWED_EMAIL=Owner@Example.com',
  `PUBLIC_URL=http://localhost:${WORKER_PORT}`,
  'ALLOWED_REDIRECT_URIS=https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback,https://chatgpt.com/connector_platform_oauth_redirect,http://localhost:6274/oauth/callback',
].join('\n') + '\n');

const mock = await startMockGoogle(MOCK_PORT);
const logPath = path.join(build, 'worker.log');
const log = fs.openSync(logPath, 'w');
const wrangler = spawn(path.join(root, 'node_modules', '.bin', 'wrangler'),
  ['dev', '--port', String(WORKER_PORT), '--persist-to', path.join(build, 'state'), '--config', path.join(build, 'wrangler.jsonc')],
  { cwd: build, stdio: ['ignore', log, log], env: { ...process.env, CI: '1', WRANGLER_SEND_METRICS: 'false', NO_COLOR: '1' } });

let code = 1;
try {
  const base = `http://localhost:${WORKER_PORT}`;
  for (let i = 0; ; i++) {
    try { if ((await fetch(base + '/')).ok) break; } catch {}
    if (i > 120) throw new Error('Worker did not start; see .test-build/worker.log');
    await new Promise((r) => setTimeout(r, 500));
  }
  code = await runTests({ base, mock, stateDir: path.join(build, 'state'), logPath });
} catch (error) {
  console.error(error);
} finally {
  wrangler.kill('SIGTERM');
  mock.close();
}
process.exit(code);
