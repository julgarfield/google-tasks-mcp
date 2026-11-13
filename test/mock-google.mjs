// A stand-in for Google's OAuth and Tasks API endpoints, used only by the automated tests.
// It keeps everything in memory. The tests never talk to the real Google.
import http from 'node:http';
import crypto from 'node:crypto';

export const SECRETS = {
  refreshToken: 'gr-SENTINEL-REFRESH-TOKEN',
  googleCode: 'gcode-SENTINEL-AUTH-CODE',
  title: 'SENTINELTITLE',
  notes: 'SENTINELNOTE',
};
const READ = 'https://www.googleapis.com/auth/tasks.readonly';
const WRITE = 'https://www.googleapis.com/auth/tasks';

export function startMockGoogle(port) {
  const state = {
    email: 'owner@example.com', verified: true, refreshDead: false, denyAtGoogle: false,
    grantScopeOverride: null,   // simulate the user unticking a permission on Google's screen
    failNextTasksCall: null,    // e.g. { status: 429, reason: 'rateLimitExceeded' }, applied once
    failWrites: null,           // same shape, applied to every write until cleared
    ignoreNullPatch: false,     // simulate an API that does not clear fields on PATCH null
    failGetAfterPatch: null,    // fail the first task GET that follows a PATCH (the verifying read)
    patchNullNotPersisted: false, // simulate a PATCH whose response shows the field cleared although it was not stored
    challenge: null, pendingScope: null, lastAuth: null,
    tokens: new Map(),          // access token -> scope string
    refreshScope: null, n: 0, tokenCalls: 0, taskCalls: 0, writes: [], revoked: [],
  };
  let lists, tasks, seq;
  function reset() {
    seq = 0;
    lists = [{ id: 'L1', title: 'MATH 234' }, { id: 'L2', title: 'COMP SCI 220' }, { id: 'L3', title: 'Empty' }];
    tasks = { L1: [], L2: [], L3: [] };
    for (let i = 0; i < 230; i++) {
      const done = i % 3 === 0;
      tasks.L1.push({ kind: 'tasks#task', id: `t${i}`, etag: `"e${i}"`, title: `${SECRETS.title} hw ${i}`, notes: i % 5 ? undefined : SECRETS.notes,
        status: done ? 'completed' : 'needsAction', due: i < 200 ? `2026-11-${String((i % 28) + 1).padStart(2, '0')}T00:00:00.000Z` : undefined,
        completed: done ? '2026-11-05T15:04:05.000Z' : undefined, hidden: done ? true : undefined, updated: '2026-11-06T01:02:03.000Z', position: String(i).padStart(20, '0') });
    }
    tasks.L2.push({ id: 'x1', title: `${SECRETS.title} lab`, status: 'needsAction', due: '2026-12-01T00:00:00.000Z', updated: '2026-11-01T00:00:00.000Z' });
    tasks.L2.push({ id: 'x2', title: `${SECRETS.title} deleted`, status: 'needsAction', deleted: true, updated: '2026-11-01T00:00:00.000Z' });
  }
  reset();

  const form = (req) => new Promise((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => r(new URLSearchParams(d))); });
  const jsonBody = (req) => new Promise((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => { try { r(JSON.parse(d || '{}')); } catch { r(null); } }); });
  const json = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
  const apiError = (res, status, reason) => json(res, status, { error: { code: status, message: `mock ${SECRETS.title} message that must never be surfaced`, errors: [{ reason, message: 'x' }], status: reason } });
  const issue = (scope) => { const t = `ga-SENTINEL-ACCESS-${++state.n}`; state.tokens.set(t, scope); return t; };

  const server = http.createServer(async (req, res) => {
    const u = new URL(req.url, `http://localhost:${port}`);
    if (u.pathname === '/auth') {
      state.lastAuth = Object.fromEntries(u.searchParams); state.challenge = u.searchParams.get('code_challenge');
      state.pendingScope = state.grantScopeOverride ?? u.searchParams.get('scope').replace('email', 'https://www.googleapis.com/auth/userinfo.email');
      const back = new URL(u.searchParams.get('redirect_uri'));
      if (state.denyAtGoogle) back.searchParams.set('error', 'access_denied'); else back.searchParams.set('code', SECRETS.googleCode);
      back.searchParams.set('state', u.searchParams.get('state'));
      res.writeHead(302, { location: back.toString() }); return res.end();
    }
    if (u.pathname === '/token') {
      const p = await form(req); state.tokenCalls++;
      if (p.get('client_id') !== 'test-client-id' || p.get('client_secret') !== 'test-client-secret') return json(res, 401, { error: 'invalid_client' });
      if (p.get('grant_type') === 'authorization_code') {
        const ch = crypto.createHash('sha256').update(p.get('code_verifier') ?? '').digest('base64url');
        if (p.get('code') !== SECRETS.googleCode || ch !== state.challenge) return json(res, 400, { error: 'invalid_grant' });
        state.refreshScope = state.pendingScope;
        return json(res, 200, { access_token: issue(state.pendingScope), expires_in: 3599, refresh_token: SECRETS.refreshToken, token_type: 'Bearer', scope: state.pendingScope });
      }
      if (state.refreshDead || p.get('refresh_token') !== SECRETS.refreshToken) return json(res, 400, { error: 'invalid_grant' });
      return json(res, 200, { access_token: issue(state.refreshScope), expires_in: 3599, token_type: 'Bearer', scope: state.refreshScope });
    }
    if (u.pathname === '/revoke') { state.revoked.push((await form(req)).get('token')); return json(res, 200, {}); }
    if (u.pathname === '/userinfo') return json(res, 200, { sub: '123', email: state.email, email_verified: state.verified });

    if (u.pathname.startsWith('/tasks/v1')) {
      state.taskCalls++;
      const tok = (req.headers.authorization ?? '').replace('Bearer ', '');
      const scope = state.tokens.get(tok);
      if (!scope) return json(res, 401, { error: { code: 401, status: 'UNAUTHENTICATED' } });
      const isWrite = req.method !== 'GET';
      if (state.failNextTasksCall) { const f = state.failNextTasksCall; state.failNextTasksCall = null; return apiError(res, f.status, f.reason); }
      if (isWrite && state.failWrites) return apiError(res, state.failWrites.status, state.failWrites.reason);
      const scopes = scope.split(' ');
      if (!scopes.includes(WRITE) && (isWrite || !scopes.includes(READ))) return apiError(res, 403, 'insufficientPermissions');

      const path = decodeURIComponent(u.pathname.slice('/tasks/v1'.length));
      const q = u.searchParams;
      const page = (items, size) => { const start = Number(q.get('pageToken') ?? 0); const end = start + size;
        return { items: items.slice(start, end), ...(end < items.length ? { nextPageToken: String(end) } : {}) }; };
      const now = () => new Date().toISOString();
      let m;

      if (path === '/users/@me/lists' && req.method === 'GET') return json(res, 200, page(lists, 2));
      if (path === '/users/@me/lists' && req.method === 'POST') {
        const b = await jsonBody(req); if (!b?.title) return apiError(res, 400, 'invalid');
        const l = { id: `NL${++seq}`, title: b.title }; lists.push(l); tasks[l.id] = []; state.writes.push({ op: 'insertList', id: l.id }); return json(res, 200, l);
      }
      if ((m = path.match(/^\/users\/@me\/lists\/([^/]+)$/)) && req.method === 'GET') { const l = lists.find((x) => x.id === m[1]); return l ? json(res, 200, l) : apiError(res, 404, 'notFound'); }

      if ((m = path.match(/^\/lists\/([^/]+)\/tasks$/))) {
        if (!tasks[m[1]]) return apiError(res, 404, 'notFound');
        if (req.method === 'GET') {
          let items = tasks[m[1]].filter((t) => !t.deleted);
          if (q.get('showCompleted') === 'false') items = items.filter((t) => t.status !== 'completed');
          if (q.get('showHidden') !== 'true') items = items.filter((t) => !t.hidden);
          if (q.get('dueMin')) items = items.filter((t) => t.due && t.due >= q.get('dueMin'));
          if (q.get('dueMax')) items = items.filter((t) => t.due && t.due <= q.get('dueMax'));
          if (q.get('updatedMin')) items = items.filter((t) => t.updated >= q.get('updatedMin'));
          return json(res, 200, page(items, Math.min(Number(q.get('maxResults') ?? 20), 100)));
        }
        if (req.method === 'POST') {
          const b = await jsonBody(req); if (!b || typeof b.title !== 'string') return apiError(res, 400, 'invalid');
          const parent = q.get('parent');
          if (parent && !tasks[m[1]].some((t) => t.id === parent && !t.parent)) return apiError(res, 400, 'invalid');
          // Like Google, keep only the date part of `due`.
          const t = { kind: 'tasks#task', id: `N${++seq}`, etag: `"n${seq}"`, title: b.title, ...(b.notes ? { notes: b.notes } : {}),
            ...(b.due ? { due: `${b.due.slice(0, 10)}T00:00:00.000Z` } : {}), ...(parent ? { parent } : {}), status: 'needsAction', updated: now() };
          tasks[m[1]].unshift(t); state.writes.push({ op: 'insert', id: t.id, body: b }); return json(res, 200, t);
        }
      }
      if ((m = path.match(/^\/lists\/([^/]+)\/tasks\/([^/]+)$/))) {
        const t = (tasks[m[1]] ?? []).find((x) => x.id === m[2]);
        if (!t) return apiError(res, 404, 'notFound');
        if (req.method === 'GET') { const afterPatch = state.justPatched; state.justPatched = false; if (state.failGetAfterPatch && afterPatch) return apiError(res, state.failGetAfterPatch.status, state.failGetAfterPatch.reason); return json(res, 200, t); }
        if (req.method === 'DELETE') {
          let body = ''; for await (const chunk of req) body += chunk;
          if (body) return apiError(res, 400, 'invalid');
          t.deleted = true;
          state.writes.push({ op: 'delete', id: t.id });
          res.writeHead(204); return res.end();
        }
        if (req.method === 'PATCH' || req.method === 'PUT') {
          const b = await jsonBody(req); if (!b) return apiError(res, 400, 'invalid');
          state.writes.push({ op: req.method.toLowerCase(), id: t.id, body: b });
          const before = { ...t }; state.justPatched = req.method === 'PATCH';
          if (req.method === 'PUT') { for (const k of ['title', 'notes', 'due']) { if (k in b) t[k] = b[k]; else delete t[k]; } }
          else for (const [k, v] of Object.entries(b)) {
            if (!['title', 'notes', 'due', 'status', 'completed'].includes(k)) continue;
            if (v === null) { if (!((state.ignoreNullPatch || state.patchNullNotPersisted) && (k === 'notes' || k === 'due'))) delete t[k]; }
            else t[k] = k === 'due' ? `${v.slice(0, 10)}T00:00:00.000Z` : v;
          }
          if (t.status === 'completed' && !t.completed) t.completed = now();
          if (t.status === 'needsAction') { delete t.completed; delete t.hidden; }
          t.updated = now();
          if (req.method === 'PATCH' && state.patchNullNotPersisted) {
            const shown = { ...t }; const kept = {};
            for (const k of ['notes', 'due']) if (b[k] === null && before[k] !== undefined) { kept[k] = before[k]; delete shown[k]; }
            Object.assign(t, kept); return json(res, 200, shown);
          }
          return json(res, 200, t);
        }
      }
      return apiError(res, 404, 'notFound');
    }
    json(res, 404, {});
  });
  return new Promise((resolve) => server.listen(port, () => resolve({ state, reset, tasks: () => tasks, lists: () => lists, close: () => server.close() })));
}
