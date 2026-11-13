// Best-effort memory of what create_task itself created in the last few minutes, so that a retried
// call can be recognised without guessing from task contents.
//
// What is stored (in the existing OAUTH_KV namespace, under its own key prefix, expiring on its own):
//   key   recent-create:<HMAC-SHA256 of list id, title, notes, due date, parent>
//   value the id of the task that call created
// The HMAC is keyed with a server secret, so KV holds no task text and nothing that can be turned
// back into it.
//
// This is NOT a guarantee. KV has no atomic check-and-set and is eventually consistent, so two calls
// that overlap, or a retry that arrives before the first call has finished, can both create a task.

import type { Env } from './types';

export const RECENT_CREATE_TTL_SECONDS = 600;
const PREFIX = 'recent-create:';

export interface CreateRequest {
  listId: string;
  title: string;
  notes: string | null;
  due: string | null;
  parent: string | null;
}

export class RecentCreates {
  constructor(private readonly env: Env) {}

  private async key(request: CreateRequest): Promise<string> {
    const encoder = new TextEncoder();
    const hmacKey = await crypto.subtle.importKey('raw', encoder.encode(this.env.GOOGLE_CLIENT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const message = JSON.stringify([request.listId, request.title, request.notes, request.due, request.parent]);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, encoder.encode(message)));
    return PREFIX + Array.from(mac, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  /** Id of the task an identical create_task call made recently, if this server remembers one. */
  async find(request: CreateRequest): Promise<string | null> {
    try {
      return await this.env.OAUTH_KV.get(await this.key(request));
    } catch {
      return null; // storage trouble must not block creating a task
    }
  }

  async remember(request: CreateRequest, taskId: string): Promise<void> {
    try {
      await this.env.OAUTH_KV.put(await this.key(request), taskId, { expirationTtl: RECENT_CREATE_TTL_SECONDS });
    } catch {
      // The task exists either way; only the retry protection for it is lost.
    }
  }
}
