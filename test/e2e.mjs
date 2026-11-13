import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { SECRETS } from './mock-google.mjs';

const G_READ = 'https://www.googleapis.com/auth/tasks.readonly', G_WRITE = 'https://www.googleapis.com/auth/tasks';
const CLAUDE = 'https://claude.ai/api/mcp/auth_callback';

export async function runTests({ base: B, mock, stateDir, logPath }) {
  const S = mock.state;
  const results = []; const issuedSecrets = new Set();
  async function test(name, fn) {
    try { await fn(); results.push(true); console.log(`ok   - ${name}`); }
    catch (error) { results.push(false); console.log(`FAIL - ${name}\n       ${String(error?.message ?? error).split('\n').join('\n       ')}`); }
  }
  const cookiesOf = (res) => res.headers.getSetCookie().map((c) => c.split(';')[0]).filter((c) => !c.endsWith('='));
  const post = (url, body, headers = {}) => fetch(url, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(body) });

  async function register(redirectUris, extra = {}) {
    return fetch(`${B}/oauth/register`, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'Test <script>alert(1)</script>', redirect_uris: redirectUris, grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none', ...extra }) });
  }
  /** Walks the browser part of the flow. Returns wherever it stopped. */
  async function authorize(client, { redirect = CLAUDE, write = true, consentCookie = true, callbackCookie = true, decision = 'approve', scope = 'tasks.readonly tasks.write' } = {}) {
    const verifier = crypto.randomBytes(32).toString('base64url');
    const q = new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: redirect, state: 'st123', scope,
      code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', resource: `${B}/mcp` });
    let res = await fetch(`${B}/authorize?${q}`, { redirect: 'manual' });
    if (res.status !== 200) return { stage: 'consent-page', res };
    const html = await res.text(); const page = { html, headers: res.headers };
    let jar = cookiesOf(res);
    res = await post(`${B}/authorize`, { handle: html.match(/name="handle" value="([^"]+)"/)[1], decision, ...(write ? { write: '1' } : {}) }, { cookie: consentCookie ? jar.join('; ') : '' });
    if (res.status !== 302 || !res.headers.get('location').startsWith('http://localhost:9099')) return { stage: 'decision', res, page };
    jar = [...jar, ...cookiesOf(res)];
    const googleUrl = res.headers.get('location');
    res = await fetch(googleUrl, { redirect: 'manual' });
    res = await fetch(res.headers.get('location'), { redirect: 'manual', headers: { cookie: callbackCookie ? jar.join('; ') : '' } });
    return { stage: 'callback', res, page, verifier, googleUrl, redirect };
  }
  /** Full connection as a new client: register, authorize, exchange the code. */
  async function connect(options = {}) {
    const client = await (await register([options.redirect ?? CLAUDE], options.registerExtra)).json();
    const a = await authorize(client, options);
    assert.equal(a.stage, 'callback'); assert.equal(a.res.status, 302, 'callback should redirect to the client');
    const code = new URL(a.res.headers.get('location')).searchParams.get('code'); issuedSecrets.add(code);
    const r = await post(`${B}/oauth/token`, { grant_type: 'authorization_code', client_id: client.client_id, code, redirect_uri: a.redirect, code_verifier: a.verifier, resource: `${B}/mcp` });
    assert.equal(r.status, 200); const tok = await r.json(); issuedSecrets.add(tok.access_token); issuedSecrets.add(tok.refresh_token);
    return { client, tok, googleUrl: a.googleUrl };
  }
  let rpcId = 0;
  async function rpc(conn, method, params) {
    const res = await fetch(`${B}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${conn.tok.access_token}` },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }) });
    return { status: res.status, body: res.status === 200 ? await res.json() : await res.text() };
  }
  /** Calls a tool. Returns { isError, data } where data is parsed JSON, or the error text. */
  async function call(conn, name, args = {}) {
    const x = await rpc(conn, 'tools/call', { name, arguments: args });
    assert.equal(x.status, 200, JSON.stringify(x));
    if (x.body.error) return { isError: true, data: x.body.error.message, protocolError: true };
    const r = x.body.result; return { isError: !!r.isError, data: r.isError ? r.content[0].text : JSON.parse(r.content[0].text) };
  }
  const writes = () => S.writes.length;
  const lastWrite = () => S.writes.at(-1);
  const expireGoogleAccessTokens = () => S.tokens.clear();
  const noWrite = async (fn) => { const before = writes(); const out = await fn(); assert.equal(writes(), before, 'expected no write to Google'); return out; };

  // ============================================================== discovery and registration
  let asm;
  await test('401 challenge, protected-resource and authorization-server metadata', async () => {
    const r = await fetch(`${B}/mcp`, { method: 'POST' });
    assert.equal(r.status, 401); assert.match(r.headers.get('www-authenticate'), /resource_metadata=.*scope="tasks.readonly tasks.write"/);
    const prm = await (await fetch(`${B}/.well-known/oauth-protected-resource/mcp`)).json();
    assert.equal(prm.resource, `${B}/mcp`); assert.deepEqual(prm.authorization_servers, [B]);
    asm = await (await fetch(`${B}/.well-known/oauth-authorization-server`)).json();
    assert.equal(asm.registration_endpoint, `${B}/oauth/register`); assert.deepEqual(asm.code_challenge_methods_supported, ['S256']);
    assert.deepEqual(asm.scopes_supported, ['tasks.readonly', 'tasks.write']);
  });
  await test('registration: Claude and ChatGPT callbacks accepted, anything else refused', async () => {
    for (const ok of [[CLAUDE], ['https://claude.com/api/mcp/auth_callback'], ['https://chatgpt.com/connector_platform_oauth_redirect'], ['https://chatgpt.com/connector/oauth/abc_123-XY']]) assert.equal((await register(ok)).status, 201, ok[0]);
    for (const bad of [['https://evil.example/cb'], [CLAUDE, 'https://evil.example/cb'], ['https://chatgpt.com/connector/oauth/a/b'], ['https://chatgpt.com/connector/oauth/abc?x=1'], ['https://chatgpt.com.evil.example/connector/oauth/abc'], []]) assert.equal((await register(bad)).status, 400, String(bad));
  });

  // ============================================================== connections
  let writer, reader, chatgpt;
  await test('connect with write access: asks Google for the full Tasks scope, issues both MCP scopes', async () => {
    writer = await connect();
    const g = new URL(writer.googleUrl).searchParams;
    assert.equal(g.get('scope'), `openid email ${G_WRITE}`); assert.equal(g.get('access_type'), 'offline'); assert.equal(g.get('prompt'), 'consent'); assert.equal(g.get('code_challenge_method'), 'S256');
    assert.equal(writer.tok.scope, 'tasks.readonly tasks.write'); assert.equal(writer.tok.expires_in, 3000);
  });
  await test('connect with "allow changes" unticked: asks Google for read-only, issues only tasks.readonly', async () => {
    reader = await connect({ write: false });
    assert.equal(new URL(reader.googleUrl).searchParams.get('scope'), `openid email ${G_READ}`);
    assert.equal(reader.tok.scope, 'tasks.readonly');
  });
  await test('ChatGPT per-connector callback completes the whole flow (registration and /authorize agree)', async () => {
    chatgpt = await connect({ redirect: 'https://chatgpt.com/connector/oauth/abc_123-XY' });
    assert.equal(chatgpt.tok.scope, 'tasks.readonly tasks.write');
    assert.equal((await call(chatgpt, 'list_task_lists')).data.count, 3);
  });
  await test('a client registered before the upgrade (scope "tasks.readonly", requesting only that) still gets write when the owner allows it', async () => {
    const old = await connect({ registerExtra: { scope: 'tasks.readonly' }, scope: 'tasks.readonly' });
    assert.equal(old.tok.scope, 'tasks.readonly tasks.write');
  });
  await test('consent page: escapes client name, shows redirect host, write checkbox, cannot be framed', async () => {
    const client = await (await register([CLAUDE])).json(); const a = await authorize(client);
    assert.ok(!a.page.html.includes('<script>alert')); assert.ok(a.page.html.includes('claude.ai')); assert.match(a.page.html, /name="write" value="1" checked/);
    assert.match(a.page.headers.get('content-security-policy'), /frame-ancestors 'none'/); assert.equal(a.page.headers.get('x-frame-options'), 'DENY');
  });
  await test('consent and callback are bound to the browser; cancel and Google denial go back as access_denied', async () => {
    const client = await (await register([CLAUDE])).json();
    let a = await authorize(client, { consentCookie: false }); assert.equal(a.stage, 'decision'); assert.equal(a.res.status, 400);
    a = await authorize(client, { callbackCookie: false }); assert.equal(a.res.status, 400); assert.equal(a.res.headers.get('location'), null);
    a = await authorize(client, { decision: 'deny' }); assert.match(a.res.headers.get('location'), /error=access_denied/);
    S.denyAtGoogle = true; a = await authorize(client); S.denyAtGoogle = false; assert.match(a.res.headers.get('location'), /^https:\/\/claude\.ai\/api\/mcp\/auth_callback\?error=access_denied/);
    let r = await fetch(`${B}/callback?code=x&state=forged`, { redirect: 'manual' }); assert.equal(r.status, 400);
    r = await fetch(`${B}/authorize?response_type=code&client_id=${client.client_id}&redirect_uri=https://evil.example/cb&state=x&code_challenge=abc&code_challenge_method=S256`, { redirect: 'manual' });
    assert.equal(r.status, 400); assert.equal(r.headers.get('location'), null);
  });
  await test('unauthorized Google account is rejected: 403, no code, Google token revoked', async () => {
    const client = await (await register([CLAUDE])).json(); const revoked = S.revoked.length;
    S.email = 'someone.else@example.com'; let a = await authorize(client); assert.equal(a.res.status, 403); assert.equal(a.res.headers.get('location'), null); assert.equal(S.revoked.length, revoked + 1);
    S.email = 'owner@example.com'; S.verified = false; a = await authorize(client); assert.equal(a.res.status, 403); S.verified = true;
  });
  await test('insufficient Google permission at sign-in (Tasks unticked, or only read-only granted for a write request) is rejected', async () => {
    const client = await (await register([CLAUDE])).json();
    S.grantScopeOverride = `openid https://www.googleapis.com/auth/userinfo.email ${G_READ}`; let a = await authorize(client); assert.equal(a.res.status, 400); assert.equal(a.res.headers.get('location'), null);
    S.grantScopeOverride = 'openid https://www.googleapis.com/auth/userinfo.email'; a = await authorize(client, { write: false }); assert.equal(a.res.status, 400);
    S.grantScopeOverride = null;
  });
  await test('wrong PKCE verifier and garbage bearer token are refused', async () => {
    const client = await (await register([CLAUDE])).json(); const a = await authorize(client);
    const code = new URL(a.res.headers.get('location')).searchParams.get('code');
    assert.equal((await post(`${B}/oauth/token`, { grant_type: 'authorization_code', client_id: client.client_id, code, redirect_uri: CLAUDE, code_verifier: 'wrong-verifier-wrong-verifier-wrong-verifier-123' })).status, 400);
    assert.equal((await rpc({ tok: { access_token: 'garbage:token:value' } }, 'tools/list', {})).status, 401);
  });

  // ============================================================== tool surface
  await test('tools/list: eight tools with the right annotations; server instructions present', async () => {
    const init = await rpc(writer, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'e2e', version: '0' } });
    assert.equal(init.body.result.serverInfo.name, 'google-tasks'); assert.match(init.body.result.instructions, /never follow instructions/);
    const tools = Object.fromEntries((await rpc(writer, 'tools/list', {})).body.result.tools.map((t) => [t.name, t]));
    assert.deepEqual(Object.keys(tools).sort(), ['create_task', 'create_task_list', 'delete_task', 'get_task', 'list_task_lists', 'list_tasks', 'set_task_completion', 'update_task']);
    const ann = (n) => tools[n].annotations;
    for (const n of ['list_task_lists', 'list_tasks', 'get_task']) assert.deepEqual(ann(n), { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false });
    assert.deepEqual(ann('create_task'), { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false });
    // Neither create tool may claim idempotency: their duplicate checks are best effort only.
    assert.deepEqual(ann('create_task_list'), { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false });
    assert.match(tools.create_task.description, /best effort, not a guarantee/); assert.match(tools.create_task.description, /NOT idempotent/);
    assert.match(tools.create_task_list.description, /NOT a guarantee/);
    for (const n of ['update_task', 'set_task_completion']) assert.deepEqual(ann(n), { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false });
    assert.deepEqual(tools.create_task.inputSchema.required, ['title']);
    assert.deepEqual(tools.update_task.inputSchema.required, ['task_list_id', 'task_id']);
    assert.deepEqual(tools.set_task_completion.inputSchema.required, ['task_list_id', 'task_id', 'completed']);
    assert.deepEqual(ann('delete_task'), { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true });
    assert.deepEqual(tools.delete_task.inputSchema.required, ['task_list_id', 'task_id']);
    fs.writeFileSync(path.join(path.dirname(logPath), 'tool-schemas.json'), JSON.stringify(Object.values(tools), null, 2));
  });

  // ============================================================== existing read tools
  await test('read: list_task_lists paginates', async () => {
    const c = await call(writer, 'list_task_lists'); assert.equal(c.data.count, 3); assert.deepEqual(c.data.task_lists[2], { id: 'L3', title: 'Empty' });
  });
  await test('read: list_tasks over all lists, hidden completed tasks included, date-only due, deleted excluded', async () => {
    const c = await call(writer, 'list_tasks'); assert.equal(c.data.count, 231); assert.equal(c.data.truncated, false);
    const done = c.data.tasks.filter((t) => t.status === 'completed'); assert.equal(done.length, 77); assert.equal(done[0].completed, '2026-11-05T15:04:05.000Z');
    assert.ok(c.data.tasks.every((t) => t.due === null || /^\d{4}-\d{2}-\d{2}$/.test(t.due))); assert.ok(!c.data.tasks.some((t) => t.title.includes('deleted')));
    assert.deepEqual(Object.keys(c.data.tasks[0]), ['id', 'title', 'notes', 'due', 'status', 'completed', 'updated', 'parent', 'list_id', 'list_title']);
  });
  await test('read: include_completed=false; inclusive due_min/due_max; single-day window; bad dates refused', async () => {
    let c = await call(writer, 'list_tasks', { include_completed: false }); assert.equal(c.data.count, 154); assert.ok(c.data.tasks.every((t) => t.status === 'needsAction'));
    c = await call(writer, 'list_tasks', { task_list_id: 'L1', due_min: '2026-11-10', due_max: '2026-11-12' });
    assert.ok(c.data.tasks.every((t) => t.due >= '2026-11-10' && t.due <= '2026-11-12' && t.list_id === 'L1'));
    assert.ok(c.data.tasks.some((t) => t.due === '2026-11-10') && c.data.tasks.some((t) => t.due === '2026-11-12'));
    c = await call(writer, 'list_tasks', { due_min: '2026-12-01', due_max: '2026-12-01' }); assert.equal(c.data.count, 1); assert.equal(c.data.tasks[0].id, 'x1');
    for (const bad of ['11/10/2026', '2026-02-30', '2026-13-01']) assert.ok((await call(writer, 'list_tasks', { due_min: bad })).isError, bad);
  });
  await test('read: 300-task cap sets truncated', async () => {
    const extra = Array.from({ length: 400 }, (_, i) => ({ id: `big${i}`, title: 'bulk', status: 'needsAction', updated: '2026-11-01T00:00:00.000Z' }));
    mock.tasks().L3.push(...extra);
    const c = await call(writer, 'list_tasks'); assert.equal(c.data.count, 300); assert.equal(c.data.truncated, true);
    mock.tasks().L3.length = 0;
  });
  await test('read: get_task, 404 as clean error, GET /mcp is 405', async () => {
    let c = await call(writer, 'get_task', { task_list_id: 'L1', task_id: 't3' }); assert.equal(c.data.status, 'completed'); assert.equal(c.data.due, '2026-11-04'); assert.equal(c.data.list_title, 'MATH 234');
    c = await call(writer, 'get_task', { task_list_id: 'L1', task_id: 'nope' }); assert.ok(c.isError); assert.match(c.data, /Not found/);
    assert.equal((await fetch(`${B}/mcp`, { headers: { authorization: `Bearer ${writer.tok.access_token}` } })).status, 405);
  });
  await test('read tools still work on a read-only connection', async () => {
    assert.equal((await call(reader, 'list_tasks', { task_list_id: 'L2' })).data.count, 1);
    assert.equal((await call(reader, 'get_task', { task_list_id: 'L2', task_id: 'x1' })).data.id, 'x1');
  });

  // ============================================================== write access control
  await test('read-only connection: every write tool is refused with a reconnect message and Google is never called', async () => {
    const calls = S.taskCalls;
    for (const [name, args] of [['create_task', { title: 'x', task_list_id: 'L3' }], ['update_task', { task_list_id: 'L2', task_id: 'x1', title: 'y' }], ['set_task_completion', { task_list_id: 'L2', task_id: 'x1', completed: true }], ['create_task_list', { title: 'z' }], ['delete_task', { task_list_id: 'L2', task_id: 'x1' }]]) {
      const c = await noWrite(() => call(reader, name, args)); assert.ok(c.isError, name); assert.match(c.data, /read-only access.*reconnect/s, name);
    }
    assert.equal(S.taskCalls, calls);
  });
  await test('Google itself reporting insufficient permission on a write gives the reconnect message', async () => {
    S.failWrites = { status: 403, reason: 'insufficientPermissions' };
    const c = await noWrite(() => call(writer, 'create_task', { title: 'perm', task_list_id: 'L3' })); S.failWrites = null;
    assert.ok(c.isError); assert.match(c.data, /read-only access/);
  });

  // ============================================================== create_task
  let made;
  await test('create_task: no list given and several lists exist -> refuses and names them; nothing created', async () => {
    const c = await noWrite(() => call(writer, 'create_task', { title: 'Needs a list' })); assert.ok(c.isError); assert.match(c.data, /3 task lists/); assert.match(c.data, /"id":"L2"/);
  });
  await test('create_task with a due date: stored as midnight UTC of that date, returned date-only with id', async () => {
    const c = await call(writer, 'create_task', { title: '  Problem set 9  ', task_list_id: 'L3', notes: 'ch. 14', due: '2026-11-20' });
    assert.equal(c.data.created, true); made = c.data.task;
    assert.ok(made.id); assert.equal(made.title, 'Problem set 9'); assert.equal(made.due, '2026-11-20'); assert.equal(made.notes, 'ch. 14'); assert.equal(made.status, 'needsAction'); assert.equal(made.completed, null); assert.equal(made.list_id, 'L3');
    assert.deepEqual(lastWrite().body, { title: 'Problem set 9', notes: 'ch. 14', due: '2026-11-20T00:00:00.000Z' });
  });
  await test('create_task without a due date: no due is sent or invented', async () => {
    const c = await call(writer, 'create_task', { title: 'No date', task_list_id: 'L3' });
    assert.equal(c.data.created, true); assert.equal(c.data.task.due, null); assert.deepEqual(lastWrite().body, { title: 'No date' });
  });
  await test('create_task repeated with the same arguments (a retry) returns the first task and creates nothing', async () => {
    for (let i = 0; i < 3; i++) {
      const c = await noWrite(() => call(writer, 'create_task', { title: 'Problem set 9', task_list_id: 'L3', notes: 'ch. 14', due: '2026-11-20' }));
      assert.equal(c.data.created, false); assert.equal(c.data.task.id, made.id);
    }
    assert.equal(mock.tasks().L3.filter((t) => t.title === 'Problem set 9').length, 1);
  });
  await test('create_task: a different due date is a different task; allow_duplicate=true forces a second copy', async () => {
    let c = await call(writer, 'create_task', { title: 'Problem set 9', task_list_id: 'L3', notes: 'ch. 14', due: '2026-11-21' }); assert.equal(c.data.created, true); assert.notEqual(c.data.task.id, made.id);
    c = await call(writer, 'create_task', { title: 'Problem set 9', task_list_id: 'L3', notes: 'ch. 14', due: '2026-11-20', allow_duplicate: true }); assert.equal(c.data.created, true); assert.notEqual(c.data.task.id, made.id);
  });
  await test('create_task: an old identical task (outside the 10-minute window) does not block a new one', async () => {
    mock.tasks().L3.push({ id: 'old1', title: 'Weekly review', status: 'needsAction', updated: '2026-01-01T00:00:00.000Z' });
    const c = await call(writer, 'create_task', { title: 'Weekly review', task_list_id: 'L3' }); assert.equal(c.data.created, true); assert.notEqual(c.data.task.id, 'old1');
  });
  await test('REGRESSION create_task: an existing task just edited to look identical is NOT mistaken for a retry', async () => {
    // Made by this server under another title, then renamed: its "updated" time is seconds old.
    const first = (await call(writer, 'create_task', { title: 'Draft outline', task_list_id: 'L3' })).data.task;
    await call(writer, 'update_task', { task_list_id: 'L3', task_id: first.id, title: 'Final outline' });
    const c = await call(writer, 'create_task', { title: 'Final outline', task_list_id: 'L3' });
    assert.equal(c.data.created, true); assert.notEqual(c.data.task.id, first.id);
    assert.equal(mock.tasks().L3.filter((t) => t.title === 'Final outline').length, 2);
  });
  await test('REGRESSION create_task: an identical task just added outside this server is NOT mistaken for a retry', async () => {
    mock.tasks().L3.unshift({ id: 'hand1', title: 'Typed in the app', status: 'needsAction', updated: new Date().toISOString() });
    const c = await call(writer, 'create_task', { title: 'Typed in the app', task_list_id: 'L3' }); assert.equal(c.data.created, true); assert.notEqual(c.data.task.id, 'hand1');
  });
  await test('REGRESSION create_task: retry protection lapses once the first task was edited, completed or deleted', async () => {
    for (const change of ['edit', 'complete', 'delete']) {
      const args = { title: `Lapse ${change}`, task_list_id: 'L3', due: '2026-12-05' };
      const first = (await call(writer, 'create_task', args)).data.task;
      assert.equal((await noWrite(() => call(writer, 'create_task', args))).data.created, false, 'unchanged -> treated as retry');
      if (change === 'edit') await call(writer, 'update_task', { task_list_id: 'L3', task_id: first.id, due: '2026-12-06' });
      if (change === 'complete') await call(writer, 'set_task_completion', { task_list_id: 'L3', task_id: first.id, completed: true });
      if (change === 'delete') mock.tasks().L3.splice(mock.tasks().L3.findIndex((t) => t.id === first.id), 1);
      const again = await call(writer, 'create_task', args); assert.equal(again.data.created, true, change); assert.notEqual(again.data.task.id, first.id);
    }
  });
  await test('REGRESSION create_task: simultaneous identical calls are not guaranteed to be deduplicated (and the tool does not claim to be)', async () => {
    const args = { title: 'Fired twice at once', task_list_id: 'L3' };
    const both = await Promise.all([call(writer, 'create_task', args), call(writer, 'create_task', args)]);
    assert.ok(both.every((c) => !c.isError && typeof c.data.created === 'boolean'));
    const made = mock.tasks().L3.filter((t) => t.title === args.title).length;
    assert.ok(made === 1 || made === 2, `expected 1 or 2 tasks, got ${made}`);
    console.log(`       (this run: ${made} task${made === 1 ? '' : 's'} created by 2 overlapping calls)`);
    // a later, non-overlapping retry is still caught
    assert.equal((await noWrite(() => call(writer, 'create_task', args))).data.created, false);
  });
  await test('create_task with a parent: subtask created; invalid parent gives a clean error', async () => {
    let c = await call(writer, 'create_task', { title: 'Part (a)', task_list_id: 'L3', parent_task_id: made.id }); assert.equal(c.data.created, true); assert.equal(c.data.task.parent, made.id);
    c = await noWrite(() => call(writer, 'create_task', { title: 'Part (b)', task_list_id: 'L3', parent_task_id: 'no-such-task' })); assert.ok(c.isError); assert.match(c.data, /HTTP 400/);
  });
  await test('create_task input validation: empty title, malformed or impossible dates, unknown list; nothing created', async () => {
    for (const args of [{ title: '   ', task_list_id: 'L3' }, { title: '', task_list_id: 'L3' }, { task_list_id: 'L3' }, { title: 'x', task_list_id: 'L3', due: '11/20/2026' }, { title: 'x', task_list_id: 'L3', due: '2026-02-30' }, { title: 'x', task_list_id: 'L3', due: '2026-11-20T09:00:00Z' }, { title: 'x'.repeat(1025), task_list_id: 'L3' }]) {
      const c = await noWrite(() => call(writer, 'create_task', args)); assert.ok(c.isError, JSON.stringify(args).slice(0, 60));
    }
    const c = await noWrite(() => call(writer, 'create_task', { title: 'x', task_list_id: 'NOPE' })); assert.ok(c.isError); assert.match(c.data, /Not found/);
  });
  await test('create_task defaults to the only list when exactly one exists', async () => {
    const saved = mock.lists().splice(1);
    try { const c = await call(writer, 'create_task', { title: 'Single list default' }); assert.equal(c.data.created, true); assert.equal(c.data.task.list_id, 'L1'); }
    finally { mock.lists().push(...saved); }
  });

  // ============================================================== update_task
  await test('update_task: changing only the title sends only the title; notes and due are preserved', async () => {
    const c = await call(writer, 'update_task', { task_list_id: 'L3', task_id: made.id, title: 'Problem set 9 (revised)' });
    assert.equal(c.data.changed, true); assert.deepEqual(c.data.changed_fields, ['title']); assert.deepEqual(c.data.previous, { title: 'Problem set 9' });
    assert.deepEqual(lastWrite(), { op: 'patch', id: made.id, body: { title: 'Problem set 9 (revised)' } });
    assert.equal(c.data.task.notes, 'ch. 14'); assert.equal(c.data.task.due, '2026-11-20');
  });
  await test('update_task: changing only the due date preserves title and notes; date stays date-only', async () => {
    const c = await call(writer, 'update_task', { task_list_id: 'L3', task_id: made.id, due: '2026-12-31' });
    assert.deepEqual(lastWrite().body, { due: '2026-12-31T00:00:00.000Z' }); assert.equal(c.data.task.due, '2026-12-31'); assert.equal(c.data.task.title, 'Problem set 9 (revised)'); assert.equal(c.data.task.notes, 'ch. 14'); assert.deepEqual(c.data.previous, { due: '2026-11-20' });
  });
  await test('update_task with the values it already has writes nothing', async () => {
    const c = await noWrite(() => call(writer, 'update_task', { task_list_id: 'L3', task_id: made.id, title: 'Problem set 9 (revised)', due: '2026-12-31' })); assert.equal(c.data.changed, false);
  });
  await test('update_task clear_due removes the due date and keeps the notes', async () => {
    const c = await call(writer, 'update_task', { task_list_id: 'L3', task_id: made.id, clear_due: true });
    assert.deepEqual(lastWrite(), { op: 'patch', id: made.id, body: { due: null } }); assert.equal(c.data.task.due, null); assert.equal(c.data.task.notes, 'ch. 14'); assert.deepEqual(c.data.previous, { due: '2026-12-31' });
    assert.equal(c.data.task.title, 'Problem set 9 (revised)');
  });
  await test('update_task clear_notes removes the notes and keeps the title', async () => {
    const c = await call(writer, 'update_task', { task_list_id: 'L3', task_id: made.id, clear_notes: true });
    assert.deepEqual(lastWrite().body, { notes: null }); assert.equal(c.data.task.notes, null); assert.equal(c.data.task.title, 'Problem set 9 (revised)');
    assert.equal((await noWrite(() => call(writer, 'update_task', { task_list_id: 'L3', task_id: made.id, clear_notes: true, clear_due: true }))).data.changed, false);
  });
  await test('REGRESSION update_task clear: verified by reading the task back; a clear that did not persist is reported, never forced', async () => {
    const id = { task_list_id: 'L3', task_id: made.id };
    await call(writer, 'update_task', { ...id, notes: 'temp', due: '2026-12-01' });
    // A successful clear is PATCH (null) followed by a GET, and the result reflects the stored task.
    let calls = S.taskCalls; let n = writes();
    let c = await call(writer, 'update_task', { ...id, clear_due: true });
    assert.equal(c.data.task.due, null); assert.equal(writes(), n + 1); assert.equal(S.taskCalls - calls, 4, 'get task, get list, PATCH, verifying GET');
    await call(writer, 'update_task', { ...id, due: '2026-12-01' });

    // Google ignores the null: accurate error, one PATCH, no replacement, everything else intact.
    S.ignoreNullPatch = true; n = writes();
    c = await call(writer, 'update_task', { ...id, clear_due: true });
    assert.ok(c.isError); assert.match(c.data, /did not remove the due date: it is still set/); assert.match(c.data, /Nothing else was changed/); assert.match(c.data, /No further attempt/);
    assert.equal(writes(), n + 1); assert.deepEqual(lastWrite(), { op: 'patch', id: made.id, body: { due: null } });
    let t = (await call(writer, 'get_task', id)).data; assert.equal(t.due, '2026-12-01'); assert.equal(t.notes, 'temp'); assert.equal(t.title, 'Problem set 9 (revised)');

    // Mixed call: the title change is saved and said to be saved; the failed clear is named.
    c = await call(writer, 'update_task', { ...id, title: 'Problem set 9 (final)', clear_due: true, clear_notes: true });
    assert.ok(c.isError); assert.match(c.data, /did not remove the notes or due date: they are still set/); assert.match(c.data, /other changes in this call were saved \(title\)/);
    t = (await call(writer, 'get_task', id)).data; assert.equal(t.title, 'Problem set 9 (final)'); assert.equal(t.due, '2026-12-01'); assert.equal(t.notes, 'temp');
    S.ignoreNullPatch = false;
    await call(writer, 'update_task', { ...id, title: 'Problem set 9 (revised)' });

    // The PATCH response claims the field is gone but it was not stored: only the read-back catches it.
    S.patchNullNotPersisted = true;
    c = await call(writer, 'update_task', { ...id, clear_notes: true }); S.patchNullNotPersisted = false;
    assert.ok(c.isError); assert.match(c.data, /did not remove the notes: it is still set/);
    assert.equal((await call(writer, 'get_task', id)).data.notes, 'temp');

  });
  await test('REGRESSION update_task clear: if the verifying read fails, the result says unverified rather than success', async () => {
    const id = { task_list_id: 'L3', task_id: made.id };
    S.failGetAfterPatch = { status: 503, reason: 'backendError' };
    const c = await call(writer, 'update_task', { ...id, clear_due: true }); S.failGetAfterPatch = null;
    assert.ok(c.isError); assert.match(c.data, /was sent to Google.*reading the task back to confirm it failed/s);
    assert.equal((await call(writer, 'get_task', id)).data.due, null);
    await call(writer, 'update_task', { ...id, due: '2026-12-01' });
    assert.ok(!S.writes.some((w) => w.op === 'put'));
  });
  await test('update_task refuses ambiguous or accidental input: nothing to change, notes+clear_notes, due+clear_due, empty strings, bad date', async () => {
    const id = { task_list_id: 'L3', task_id: made.id };
    for (const args of [{}, { notes: 'a', clear_notes: true }, { due: '2026-12-02', clear_due: true }, { notes: '' }, { title: '' }, { title: '   ' }, { due: '' }, { due: 'tomorrow' }, { due: '2026-02-30' }]) {
      const c = await noWrite(() => call(writer, 'update_task', { ...id, ...args })); assert.ok(c.isError, JSON.stringify(args));
    }
    assert.equal((await call(writer, 'get_task', id)).data.notes, 'temp');
  });
  await test('update_task: invalid ids and deleted tasks give clean errors, no write', async () => {
    let c = await noWrite(() => call(writer, 'update_task', { task_list_id: 'L3', task_id: 'nope', title: 'x' })); assert.ok(c.isError); assert.match(c.data, /Not found/);
    c = await noWrite(() => call(writer, 'update_task', { task_list_id: 'NOPE', task_id: made.id, title: 'x' })); assert.ok(c.isError);
    c = await noWrite(() => call(writer, 'update_task', { task_list_id: 'L2', task_id: 'x2', title: 'x' })); assert.ok(c.isError); assert.match(c.data, /deleted/);
    c = await noWrite(() => call(writer, 'update_task', { task_id: made.id, title: 'x' })); assert.ok(c.isError);
  });

  // ============================================================== set_task_completion
  await test('set_task_completion true: sends only the status; Google supplies the completion time', async () => {
    const c = await call(writer, 'set_task_completion', { task_list_id: 'L3', task_id: made.id, completed: true });
    assert.equal(c.data.changed, true); assert.equal(c.data.status, 'completed'); assert.ok(c.data.completed); assert.deepEqual(lastWrite().body, { status: 'completed' });
    assert.equal(c.data.task.title, 'Problem set 9 (revised)'); assert.equal(c.data.task.notes, 'temp');
    made.completedAt = c.data.completed;
  });
  await test('set_task_completion on an already-completed task writes nothing and keeps the original completion time', async () => {
    const c = await noWrite(() => call(writer, 'set_task_completion', { task_list_id: 'L3', task_id: made.id, completed: true }));
    assert.equal(c.data.changed, false); assert.equal(c.data.status, 'completed'); assert.equal(c.data.completed, made.completedAt);
  });
  await test('set_task_completion false reopens; repeating it writes nothing', async () => {
    let c = await call(writer, 'set_task_completion', { task_list_id: 'L3', task_id: made.id, completed: false });
    assert.equal(c.data.changed, true); assert.equal(c.data.status, 'needsAction'); assert.equal(c.data.completed, null); assert.deepEqual(lastWrite().body, { status: 'needsAction', completed: null });
    c = await noWrite(() => call(writer, 'set_task_completion', { task_list_id: 'L3', task_id: made.id, completed: false })); assert.equal(c.data.changed, false);
  });
  await test('set_task_completion: reopening a task completed (and hidden) in the Google app works', async () => {
    const c = await call(writer, 'set_task_completion', { task_list_id: 'L1', task_id: 't0', completed: false }); assert.equal(c.data.status, 'needsAction');
    assert.equal((await call(writer, 'set_task_completion', { task_list_id: 'L1', task_id: 't0', completed: true })).data.status, 'completed');
  });
  await test('set_task_completion: invalid ids, deleted task, non-boolean value', async () => {
    let c = await noWrite(() => call(writer, 'set_task_completion', { task_list_id: 'L3', task_id: 'nope', completed: true })); assert.ok(c.isError); assert.match(c.data, /Not found/);
    c = await noWrite(() => call(writer, 'set_task_completion', { task_list_id: 'L2', task_id: 'x2', completed: true })); assert.ok(c.isError); assert.match(c.data, /deleted/);
    c = await noWrite(() => call(writer, 'set_task_completion', { task_list_id: 'L3', task_id: made.id, completed: 'yes' })); assert.ok(c.isError);
    c = await noWrite(() => call(writer, 'set_task_completion', { task_list_id: 'L3', task_id: made.id })); assert.ok(c.isError);
  });

  // ============================================================== create_task_list
  await test('REGRESSION create_task_list: simultaneous identical calls may both create (best effort only; annotation is not idempotent)', async () => {
    const both = await Promise.all([call(writer, 'create_task_list', { title: 'Twice at once' }), call(writer, 'create_task_list', { title: 'Twice at once' })]);
    assert.ok(both.every((c) => !c.isError));
    const made = mock.lists().filter((l) => l.title === 'Twice at once').length; assert.ok(made === 1 || made === 2);
    console.log(`       (this run: ${made} list${made === 1 ? '' : 's'} created by 2 overlapping calls)`);
  });
  await test('create_task_list creates once; repeating returns the existing list', async () => {
    let c = await call(writer, 'create_task_list', { title: 'M E 201' }); assert.equal(c.data.created, true); const id = c.data.task_list.id;
    c = await noWrite(() => call(writer, 'create_task_list', { title: 'M E 201' })); assert.equal(c.data.created, false); assert.equal(c.data.task_list.id, id);
    assert.ok((await noWrite(() => call(writer, 'create_task_list', { title: ' ' }))).isError);
  });

  // ============================================================== Google errors and limits
  await test('rate limit on a write (429, and 403 rateLimitExceeded): clear message, one attempt only, nothing created', async () => {
    for (const f of [{ status: 429, reason: 'RATE_LIMIT_EXCEEDED' }, { status: 403, reason: 'rateLimitExceeded' }]) {
      S.failWrites = f; const calls = S.taskCalls;
      const c = await noWrite(() => call(writer, 'create_task', { title: 'rate limited', task_list_id: 'L3' })); S.failWrites = null;
      assert.ok(c.isError); assert.match(c.data, /rate limit or quota.*nothing was changed/s);
      assert.equal(S.taskCalls - calls, 2, 'get list + one insert attempt, no retry');
    }
  });
  await test('Google 5xx on a write says the outcome is unknown; 5xx on a read is a clean error', async () => {
    S.failWrites = { status: 503, reason: 'backendError' };
    let c = await call(writer, 'update_task', { task_list_id: 'L3', task_id: made.id, title: 'will fail' }); S.failWrites = null;
    assert.ok(c.isError); assert.match(c.data, /may or may not have been applied/);
    S.failNextTasksCall = { status: 500, reason: 'backendError' };
    c = await call(writer, 'list_task_lists'); assert.ok(c.isError); assert.match(c.data, /HTTP 500/);
  });
  await test('error text from Google is never passed through', async () => {
    S.failNextTasksCall = { status: 400, reason: 'invalid' };
    const c = await call(writer, 'get_task', { task_list_id: 'L3', task_id: made.id }); assert.ok(c.isError); assert.ok(!c.data.includes(SECRETS.title));
  });

  // ============================================================== tokens
  await test('expired Google access token before a write: refreshed once, the write happens exactly once', async () => {
    expireGoogleAccessTokens(); const before = writes();
    const c = await call(writer, 'create_task', { title: 'After expiry', task_list_id: 'L3' }); assert.equal(c.data.created, true); assert.equal(writes(), before + 1);
    assert.equal(mock.tasks().L3.filter((t) => t.title === 'After expiry').length, 1);
  });
  await test('refresh_token grant rotates our token, refreshes the Google token, and keeps write access', async () => {
    const before = S.tokenCalls;
    const r = await post(`${B}/oauth/token`, { grant_type: 'refresh_token', client_id: writer.client.client_id, refresh_token: writer.tok.refresh_token }); assert.equal(r.status, 200);
    writer.tok = await r.json(); issuedSecrets.add(writer.tok.access_token); issuedSecrets.add(writer.tok.refresh_token);
    assert.equal(S.tokenCalls, before + 1); assert.equal(writer.tok.scope, 'tasks.readonly tasks.write');
    assert.equal((await call(writer, 'set_task_completion', { task_list_id: 'L3', task_id: made.id, completed: true })).data.changed, true);
  });
  await test('a client that narrows its token to tasks.readonly cannot write with it', async () => {
    const r = await post(`${B}/oauth/token`, { grant_type: 'refresh_token', client_id: chatgpt.client.client_id, refresh_token: chatgpt.tok.refresh_token, scope: 'tasks.readonly' }); assert.equal(r.status, 200);
    const narrowed = { tok: await r.json() }; assert.equal(narrowed.tok.scope, 'tasks.readonly');
    const c = await noWrite(() => call(narrowed, 'create_task', { title: 'narrow', task_list_id: 'L3' })); assert.ok(c.isError); assert.match(c.data, /read-only access/);
    assert.ok((await noWrite(() => call(narrowed, 'delete_task', { task_list_id: 'L2', task_id: 'x1' }))).isError);
    assert.equal((await call(narrowed, 'list_task_lists')).isError, false);
  });
  await test('delete_task: deletes only the exact id, accepts empty 204 and repeats without another write', async () => {
    const args = { title: 'Delete fixture', task_list_id: 'L3' };
    const first = (await call(writer, 'create_task', args)).data.task;
    const other = (await call(writer, 'create_task', { ...args, allow_duplicate: true })).data.task;
    const id = { task_list_id: 'L3', task_id: first.id };
    const n = writes(); const c = await call(writer, 'delete_task', id);
    assert.equal(c.isError, false); assert.deepEqual(c.data, { deleted: true, changed: true, ...id });
    assert.equal(writes(), n + 1); assert.deepEqual(lastWrite(), { op: 'delete', id: first.id });
    assert.equal(mock.tasks().L3.find(t => t.id === first.id).deleted, true);
    assert.ok(!mock.tasks().L3.find(t => t.id === other.id).deleted);
    assert.equal((await noWrite(() => call(writer, 'delete_task', id))).data.changed, false);
    // Google may return 404 instead of a tombstone on later reads.
    mock.tasks().L3.splice(mock.tasks().L3.findIndex(t => t.id === first.id), 1);
    assert.equal((await noWrite(() => call(writer, 'delete_task', id))).data.changed, false);
  });
  await test('delete_task: rejects invalid list and empty ids without deleting', async () => {
    for (const id of [{ task_list_id: 'bad-list', task_id: 'x1' }, { task_list_id: '', task_id: 'x1' }, { task_list_id: 'L2', task_id: '' }]) {
      assert.ok((await noWrite(() => call(writer, 'delete_task', id))).isError);
    }
  });
  await test('delete_task: completed/hidden task can be deleted', async () => {
    mock.tasks().L3.push({ id: 'done-delete', title: 'Done', status: 'completed', hidden: true });
    const c = await call(writer, 'delete_task', { task_list_id: 'L3', task_id: 'done-delete' });
    assert.equal(c.data.changed, true);
  });
  await test('delete_task: Google scope denial and rate limit do not delete', async () => {
    for (const failure of [{ status: 403, reason: 'insufficientPermissions' }, { status: 429, reason: 'rateLimitExceeded' }]) {
      S.failWrites = failure; const n = S.taskCalls;
      try {
        const c = await noWrite(() => call(writer, 'delete_task', { task_list_id: 'L2', task_id: 'x1' }));
        assert.ok(c.isError); assert.equal(S.taskCalls - n, 3, 'get list, get task, one DELETE attempt');
      } finally { S.failWrites = null; }
    }
  });
  await test('delete_task: 5xx gives unknown outcome and is not blindly retried', async () => {
    S.failWrites = { status: 503, reason: 'backendError' }; const n = S.taskCalls;
    try {
      const c = await noWrite(() => call(writer, 'delete_task', { task_list_id: 'L2', task_id: 'x1' }));
      assert.ok(c.isError); assert.match(c.data, /may or may not have been applied/);
      assert.equal(S.taskCalls - n, 3);
    } finally { S.failWrites = null; }
  });
  await test('delete_task: read failure never sends a DELETE', async () => {
    S.failNextTasksCall = { status: 503, reason: 'backendError' };
    assert.ok((await noWrite(() => call(writer, 'delete_task', { task_list_id: 'L2', task_id: 'x1' }))).isError);
  });
  await test('delete_task: expired Google access refreshes once and deletes once', async () => {
    mock.tasks().L3.push({ id: 'expire-delete', title: 'Expiry fixture', status: 'needsAction' });
    expireGoogleAccessTokens(); const n = writes(); const tokens = S.tokenCalls;
    const c = await call(writer, 'delete_task', { task_list_id: 'L3', task_id: 'expire-delete' });
    assert.equal(c.data.changed, true); assert.equal(writes(), n + 1); assert.equal(S.tokenCalls, tokens + 1);
  });
  await test('revoked Google access: tool calls say reconnect; token refresh returns invalid_grant and the grant is ended', async () => {
    S.refreshDead = true; expireGoogleAccessTokens();
    let c = await noWrite(() => call(writer, 'create_task', { title: 'revoked', task_list_id: 'L3' })); assert.ok(c.isError); assert.match(c.data, /expired or been revoked/);
    c = await call(writer, 'list_tasks'); assert.ok(c.isError); assert.match(c.data, /expired or been revoked/);
    const r = await post(`${B}/oauth/token`, { grant_type: 'refresh_token', client_id: writer.client.client_id, refresh_token: writer.tok.refresh_token });
    assert.equal(r.status, 400); assert.equal((await r.json()).error, 'invalid_grant');
    assert.equal((await rpc(writer, 'tools/list', {})).status, 401);
    S.refreshDead = false;
  });

  // ============================================================== leakage
  await test('no secrets or task contents in stored state or worker logs', async () => {
    const needles = [SECRETS.refreshToken, SECRETS.googleCode, SECRETS.title, SECRETS.notes, 'ga-SENTINEL-ACCESS', 'owner@example.com', 'test-client-secret', 'Problem set 9', 'Final outline', 'Fired twice at once', ...[...issuedSecrets].filter(Boolean)];
    const files = [logPath]; const walk = (dir) => { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); e.isDirectory() ? walk(p) : files.push(p); } };
    // Only what the server itself stores (KV) and logs. `wrangler dev` also keeps a local request
    // trace under state/v3/observability that records full URLs; that is the dev tool on your own
    // machine, not the Worker, and production has no observability configured.
    walk(path.join(stateDir, 'v3', 'kv'));
    let sawGrant = false;
    for (const file of files) {
      const text = fs.readFileSync(file).toString('latin1');
      if (text.includes('encryptedProps')) sawGrant = true;
      for (const needle of needles) assert.ok(!text.includes(needle), `${path.basename(file)} contains ${needle.slice(0, 12)}…`);
    }
    assert.ok(sawGrant, 'expected to find stored grant records to inspect');
    assert.ok(files.some((file) => fs.readFileSync(file).toString('latin1').includes('recent-create:')), 'expected retry-protection records in KV');
    assert.ok(issuedSecrets.size >= 10);
  });

  await test('REGRESSION no PUT (full replacement) was ever sent to Google during the whole run', async () => {
    assert.ok(S.writes.length > 30); assert.deepEqual([...new Set(S.writes.map((w) => w.op))].sort(), ['delete', 'insert', 'insertList', 'patch']);
  });

  const failed = results.filter((ok) => !ok).length;
  console.log(`\n${results.length - failed} passed, ${failed} failed`);
  return failed ? 1 : 0;
}
