// Google OAuth (upstream) and Google Tasks API v1 client: reads (GET), create (POST) and partial
// update (PATCH), and task deletion (DELETE). No PUT or task-list deletion.
// Nothing in this file logs tokens, response bodies or task contents.

import type { Env, Props } from './types';

export const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
export const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const GOOGLE_REVOKE_URL = 'https://oauth2.googleapis.com/revoke';
export const GOOGLE_USERINFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo';
export const TASKS_API_BASE = 'https://tasks.googleapis.com/tasks/v1';

// Google's scopes (not to be confused with this server's own MCP scopes in types.ts).
export const GOOGLE_TASKS_READ = 'https://www.googleapis.com/auth/tasks.readonly';
export const GOOGLE_TASKS_WRITE = 'https://www.googleapis.com/auth/tasks'; // read and write

/** Ask Google for the least that the owner's choice on the consent page needs. */
export function googleScopes(write: boolean): string[] {
  return ['openid', 'email', write ? GOOGLE_TASKS_WRITE : GOOGLE_TASKS_READ];
}

// Cloudflare's free plan allows 50 outbound requests per invocation. Stay well under it so one
// tool call can never exhaust the limit (the budget also covers a token refresh retry).
const MAX_GOOGLE_CALLS_PER_REQUEST = 40;
const PAGE_SIZE = 100; // API maximum for tasks.list

export function callbackUrl(env: Env): string {
  return `${new URL(env.PUBLIC_URL).origin}/callback`;
}

// ---------------------------------------------------------------------------------------------
// OAuth
// ---------------------------------------------------------------------------------------------

export function googleAuthorizeUrl(env: Env, state: string, codeChallenge: string, write: boolean): string {
  const url = new URL(GOOGLE_AUTH_URL);
  url.search = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: callbackUrl(env),
    response_type: 'code',
    scope: googleScopes(write).join(' '),
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    access_type: 'offline', // ask for a refresh token
    prompt: 'consent', // Google only returns a refresh token when consent is shown
    login_hint: env.ALLOWED_EMAIL,
  }).toString();
  return url.toString();
}

export interface GoogleTokens {
  accessToken: string;
  accessTokenExpiresAt: number; // epoch seconds
  refreshToken?: string;
  scope: string;
}

export type RefreshResult =
  | { ok: true; accessToken: string; accessTokenExpiresAt: number }
  | { ok: false; revoked: boolean };

async function tokenRequest(env: Env, params: Record<string, string>): Promise<Response> {
  return fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      ...params,
    }),
  });
}

function expiresAt(expiresIn: unknown): number {
  const seconds = typeof expiresIn === 'number' && expiresIn > 0 ? expiresIn : 3600;
  return Math.floor(Date.now() / 1000) + seconds;
}

/** Exchanges Google's authorization code. Returns null on any failure. */
export async function exchangeGoogleCode(env: Env, code: string, verifier: string): Promise<GoogleTokens | null> {
  const res = await tokenRequest(env, {
    grant_type: 'authorization_code',
    code,
    code_verifier: verifier,
    redirect_uri: callbackUrl(env),
  });
  if (!res.ok) {
    const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    const errorCode = typeof data.error === 'string' && /^[a-z_]+$/.test(data.error)
      ? data.error : 'unknown';
    console.warn('google_token_exchange_failed', res.status, errorCode);
    return null;
  }
  const body = (await res.json()) as Record<string, unknown>;
  if (typeof body.access_token !== 'string') return null;
  return {
    accessToken: body.access_token,
    accessTokenExpiresAt: expiresAt(body.expires_in),
    refreshToken: typeof body.refresh_token === 'string' ? body.refresh_token : undefined,
    scope: typeof body.scope === 'string' ? body.scope : '',
  };
}

/** Gets a new Google access token. `revoked` means the refresh token is dead for good. */
export async function refreshGoogleToken(env: Env, refreshToken: string): Promise<RefreshResult> {
  let res: Response;
  try {
    res = await tokenRequest(env, { grant_type: 'refresh_token', refresh_token: refreshToken });
  } catch {
    return { ok: false, revoked: false };
  }
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    return { ok: false, revoked: body.error === 'invalid_grant' };
  }
  const body = (await res.json()) as Record<string, unknown>;
  if (typeof body.access_token !== 'string') return { ok: false, revoked: false };
  return { ok: true, accessToken: body.access_token, accessTokenExpiresAt: expiresAt(body.expires_in) };
}

/** The verified email of the account behind an access token, lowercased, or null. */
export async function fetchVerifiedEmail(accessToken: string): Promise<string | null> {
  const res = await fetch(GOOGLE_USERINFO_URL, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!res.ok) return null;
  const body = (await res.json()) as Record<string, unknown>;
  if (typeof body.email !== 'string' || body.email_verified !== true) return null;
  return body.email.toLowerCase();
}

/** Best effort: used to throw away tokens for an account that isn't the owner's. */
export async function revokeGoogleToken(token: string): Promise<void> {
  try {
    await fetch(GOOGLE_REVOKE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token }),
    });
  } catch {
    // ignore
  }
}

// ---------------------------------------------------------------------------------------------
// Tasks API
// ---------------------------------------------------------------------------------------------

export class GoogleApiError extends Error {
  constructor(
    readonly status: number,
    /** The refresh token is dead: the connector has to be reconnected. */
    readonly reauthorize = false,
    /** Google's machine-readable reason codes (never message text), e.g. "rateLimitExceeded". */
    readonly reasons: string[] = []
  ) {
    super(`Google Tasks API error ${status}`);
  }

  get insufficientScope(): boolean {
    return this.status === 403 && this.reasons.some((r) => r === 'insufficientPermissions' || r === 'ACCESS_TOKEN_SCOPE_INSUFFICIENT');
  }

  get rateLimited(): boolean {
    return (
      this.status === 429 ||
      (this.status === 403 && this.reasons.some((r) => /^(userRateLimitExceeded|rateLimitExceeded|quotaExceeded|dailyLimitExceeded|RATE_LIMIT_EXCEEDED)$/.test(r)))
    );
  }
}

export class BudgetExceededError extends Error {}

/** Pulls only short code-like reason strings out of a Google error body. Messages are dropped. */
async function errorReasons(res: Response): Promise<string[]> {
  const body = (await res.json().catch(() => null)) as { error?: { status?: unknown; errors?: unknown; details?: unknown } } | null;
  const error = body?.error;
  const found: unknown[] = [error?.status];
  for (const list of [error?.errors, error?.details]) {
    if (Array.isArray(list)) for (const item of list) found.push((item as { reason?: unknown } | null)?.reason);
  }
  return found.filter((r): r is string => typeof r === 'string' && /^[A-Za-z_]{1,60}$/.test(r));
}

export interface TaskList {
  id: string;
  title: string;
}

/** A task as returned by the Tasks API (only the fields this server reads). */
export interface RawTask {
  id: string;
  title?: string;
  notes?: string;
  due?: string;
  status?: string;
  completed?: string;
  updated?: string;
  parent?: string;
  deleted?: boolean;
}

/** Fields this server may write. `null` clears a field in a PATCH. */
export interface TaskWrite {
  title?: string;
  notes?: string | null;
  due?: string | null;
  status?: 'needsAction' | 'completed';
  completed?: null;
}

export interface ListTasksOptions {
  includeCompleted: boolean;
  /** RFC 3339 timestamps, passed straight to the API. */
  dueMin?: string;
  dueMax?: string;
}

// Access token refreshed mid-request, kept in memory only so a warm isolate doesn't refresh twice.
let refreshed: { forRefreshToken: string; accessToken: string; accessTokenExpiresAt: number } | null = null;

export class GoogleTasksClient {
  private calls = 0;
  private accessToken: string;

  constructor(
    private readonly env: Env,
    private readonly props: Props
  ) {
    const now = Math.floor(Date.now() / 1000);
    const cached =
      refreshed && refreshed.forRefreshToken === props.refreshToken && refreshed.accessTokenExpiresAt > now + 60
        ? refreshed
        : null;
    this.accessToken = cached && cached.accessTokenExpiresAt > props.accessTokenExpiresAt ? cached.accessToken : props.accessToken;
  }

  private spend(): void {
    if (this.calls >= MAX_GOOGLE_CALLS_PER_REQUEST) throw new BudgetExceededError();
    this.calls++;
  }

  /**
   * One Tasks API call. Never retried on its own, except once after a 401: a 401 means Google
   * rejected the token before doing anything, so repeating even a POST cannot create a duplicate.
   */
  private async request<T>(method: 'GET' | 'POST' | 'PATCH' | 'DELETE', path: string, params?: Record<string, string>, body?: unknown): Promise<T> {
    const url = new URL(TASKS_API_BASE + path);
    if (params) url.search = new URLSearchParams(params).toString();
    const send = () =>
      fetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });

    this.spend();
    let res = await send();

    if (res.status === 401) {
      // The access token expired or was dropped: refresh once and retry.
      this.spend();
      const result = await refreshGoogleToken(this.env, this.props.refreshToken);
      if (!result.ok) throw new GoogleApiError(401, result.revoked);
      refreshed = { forRefreshToken: this.props.refreshToken, ...result };
      this.accessToken = result.accessToken;
      this.spend();
      res = await send();
    }

    if (!res.ok) throw new GoogleApiError(res.status, false, await errorReasons(res));
    // Google's delete endpoint returns an empty successful response, not JSON.
    if (method === 'DELETE') return undefined as T;
    return (await res.json()) as T;
  }

  private get<T>(path: string, params?: Record<string, string>): Promise<T> {
    return this.request<T>('GET', path, params);
  }

  /** All task lists, following nextPageToken. */
  async listTaskLists(): Promise<TaskList[]> {
    const lists: TaskList[] = [];
    let pageToken: string | undefined;
    do {
      const page = await this.get<{ items?: TaskList[]; nextPageToken?: string }>('/users/@me/lists', {
        maxResults: String(PAGE_SIZE),
        ...(pageToken ? { pageToken } : {}),
      });
      for (const list of page.items ?? []) lists.push({ id: list.id, title: list.title ?? '' });
      pageToken = page.nextPageToken;
    } while (pageToken);
    return lists;
  }

  async getTaskList(taskListId: string): Promise<TaskList> {
    const list = await this.get<TaskList>(`/users/@me/lists/${encodeURIComponent(taskListId)}`);
    return { id: list.id, title: list.title ?? '' };
  }

  /**
   * Tasks in one list, following nextPageToken. `onPage` receives each page; return false to stop.
   *
   * showHidden matters: a task checked off in Google's own apps is marked hidden, and the API
   * leaves hidden tasks out unless showHidden=true, even with showCompleted=true.
   */
  async listTasks(taskListId: string, options: ListTasksOptions, onPage: (tasks: RawTask[]) => boolean): Promise<void> {
    let pageToken: string | undefined;
    do {
      const page = await this.get<{ items?: RawTask[]; nextPageToken?: string }>(
        `/lists/${encodeURIComponent(taskListId)}/tasks`,
        {
          maxResults: String(PAGE_SIZE),
          showCompleted: String(options.includeCompleted),
          showHidden: String(options.includeCompleted),
          showDeleted: 'false',
          ...(options.dueMin ? { dueMin: options.dueMin } : {}),
          ...(options.dueMax ? { dueMax: options.dueMax } : {}),
          ...(pageToken ? { pageToken } : {}),
        }
      );
      if (!onPage(page.items ?? [])) return;
      pageToken = page.nextPageToken;
    } while (pageToken);
  }

  async getTask(taskListId: string, taskId: string): Promise<RawTask> {
    return this.get<RawTask>(`/lists/${encodeURIComponent(taskListId)}/tasks/${encodeURIComponent(taskId)}`);
  }

  // ---- writes (need Google's full Tasks scope) -------------------------------------------------

  async insertTaskList(title: string): Promise<TaskList> {
    const list = await this.request<TaskList>('POST', '/users/@me/lists', undefined, { title });
    return { id: list.id, title: list.title ?? '' };
  }

  async insertTask(taskListId: string, task: TaskWrite, parentTaskId?: string): Promise<RawTask> {
    return this.request<RawTask>('POST', `/lists/${encodeURIComponent(taskListId)}/tasks`, parentTaskId ? { parent: parentTaskId } : undefined, task);
  }

  /** PATCH: only the fields present in `changes` are touched. */
  async patchTask(taskListId: string, taskId: string, changes: TaskWrite): Promise<RawTask> {
    return this.request<RawTask>('PATCH', `/lists/${encodeURIComponent(taskListId)}/tasks/${encodeURIComponent(taskId)}`, undefined, changes);
  }

  async deleteTask(taskListId: string, taskId: string): Promise<void> {
    return this.request<void>('DELETE', `/lists/${encodeURIComponent(taskListId)}/tasks/${encodeURIComponent(taskId)}`);
  }
}
