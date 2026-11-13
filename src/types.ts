import type { OAuthHelpers } from '@cloudflare/workers-oauth-provider';

export interface Env {
  /** KV namespace used by the OAuth provider (clients, grants, token hashes, encrypted props). */
  OAUTH_KV: KVNamespace;
  /** Injected by the OAuth provider for the /authorize and /callback handlers. */
  OAUTH_PROVIDER: OAuthHelpers;

  /** Public origin of this Worker, e.g. https://google-tasks-mcp.example.workers.dev */
  PUBLIC_URL: string;
  /** The only Google account allowed to connect. */
  ALLOWED_EMAIL: string;
  /** Comma-separated OAuth redirect URIs that MCP clients may use. */
  ALLOWED_REDIRECT_URIS: string;

  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
}

/**
 * Stored with the grant by the OAuth provider, encrypted with a key that only the holder of a
 * valid token (Claude) can unwrap. Decrypted into ctx.props for each authenticated /mcp request.
 */
export interface Props {
  email: string;
  refreshToken: string;
  accessToken: string;
  accessTokenExpiresAt: number; // epoch seconds
  /**
   * True only when Google granted the full Tasks scope for this grant. Grants made before write
   * support have no value here and stay read-only until the connector is reconnected.
   */
  canWrite?: boolean;
}

/**
 * Scopes this server issues to MCP clients (Claude, ChatGPT). These are this server's own names.
 * They are not Google's: Google's scopes are requested by the server in google.ts.
 *   tasks.readonly  list and read tasks
 *   tasks.write     create, edit, complete and reopen tasks (needs Google's full Tasks scope)
 */
export const SCOPE_READ = 'tasks.readonly';
export const SCOPE_WRITE = 'tasks.write';

export function allowedEmail(env: Env): string {
  return env.ALLOWED_EMAIL.trim().toLowerCase();
}

export function allowedRedirectUris(env: Env): string[] {
  return env.ALLOWED_REDIRECT_URIS.split(',')
    .map((uri) => uri.trim())
    .filter(Boolean);
}

/** ChatGPT's per-connector callback: https://chatgpt.com/connector/oauth/<id> */
function isChatGPTCallback(uri: string): boolean {
  try {
    const url = new URL(uri);
    return url.origin === 'https://chatgpt.com'
      && url.search === ''
      && url.hash === ''
      && /^\/connector\/oauth\/[A-Za-z0-9_-]+$/.test(url.pathname);
  } catch {
    return false;
  }
}

/** The one redirect URI rule, used both at client registration and at /authorize. */
export function isAllowedRedirectUri(env: Env, uri: string): boolean {
  return allowedRedirectUris(env).includes(uri) || isChatGPTCallback(uri);
}
