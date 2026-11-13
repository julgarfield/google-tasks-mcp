// Entry point. One Worker plays two roles:
//  - OAuth 2.1 authorization server toward Claude and ChatGPT (metadata, dynamic client registration, PKCE,
//    token endpoint), provided by @cloudflare/workers-oauth-provider;
//  - MCP resource server at /mcp, which calls Google Tasks with the owner's Google token.

import { GrantType, OAuthError, OAuthProvider } from '@cloudflare/workers-oauth-provider';

import { authHandler } from './auth';
import { refreshGoogleToken } from './google';
import { mcpHandler } from './mcp';
import { isAllowedRedirectUri, SCOPE_READ, SCOPE_WRITE, type Env, type Props } from './types';

const DAY = 86_400;
const REQUIRED_CONFIG = ['PUBLIC_URL', 'ALLOWED_EMAIL', 'ALLOWED_REDIRECT_URIS', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'] as const;

function buildProvider(env: Env): OAuthProvider<Env> {
  const origin = new URL(env.PUBLIC_URL).origin;

  return new OAuthProvider<Env>({
    apiRoute: '/mcp',
    apiHandler: mcpHandler,
    defaultHandler: authHandler,
    authorizeEndpoint: '/authorize',
    tokenEndpoint: '/oauth/token',
    clientRegistrationEndpoint: '/oauth/register',

    // The identity every token is bound to: this is the URL pasted into Claude.
    resourceMetadata: {
      resource: `${origin}/mcp`,
      authorization_servers: [origin],
      resource_name: 'Google Tasks',
    },
    scopesSupported: [SCOPE_READ, SCOPE_WRITE],
    // Advertised so clients ask for both. What is actually granted is decided on the consent page
    // (auth.ts), and write tools check the token's scope on every call (mcp.ts).
    requiredScopes: [SCOPE_READ, SCOPE_WRITE],

    // Google access tokens last an hour. Ours last 50 minutes, so each of our access tokens is
    // issued together with a Google token that outlives it (see tokenExchangeCallback).
    accessTokenTTL: 50 * 60,
    // The connection stays alive as long as Claude uses it at least once every 30 days.
    refreshTokenTTL: 30 * DAY,
    refreshTokenIdleTTL: 30 * DAY,

    // Dynamic registration is open to the internet by design, so only register clients that
    // redirect to an allowlisted URI (Claude's callback). Others can't even get a client_id.
    clientRegistrationCallback: async ({ clientMetadata }) => {
      const uris = clientMetadata.redirect_uris;
      if (!Array.isArray(uris) || uris.length === 0 || !uris.every((uri) => typeof uri === 'string' && isAllowedRedirectUri(env, uri))) {
        return { code: 'invalid_redirect_uri', description: 'Redirect URI not allowed', status: 400 };
      }
    },

    // When Claude refreshes its token, refresh the Google token too. If Google says the refresh
    // token is dead, end the grant so Claude asks the user to reconnect instead of failing calls.
    tokenExchangeCallback: async ({ grantType, props, env }) => {
      if (grantType !== GrantType.REFRESH_TOKEN) return;
      const current = props as Props;
      const result = await refreshGoogleToken(env, current.refreshToken);
      if (!result.ok && result.revoked) {
        throw new OAuthError('invalid_grant', { description: 'Google access was revoked or has expired' });
      }
      if (!result.ok) {
        throw new OAuthError('temporarily_unavailable', { description: 'Google is unavailable', statusCode: 503 });
      }
      const next: Props = { ...current, accessToken: result.accessToken, accessTokenExpiresAt: result.accessTokenExpiresAt };
      return { newProps: next };
    },

    // Log which check failed, never the request or any token.
    onError({ code, status, internal }) {
      console.warn('oauth_error', status, code, internal?.category, internal?.reason);
    },
  });
}

let provider: { builtFor: string; instance: OAuthProvider<Env> } | undefined;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const missing = REQUIRED_CONFIG.filter((name) => !env[name]);
    if (missing.length > 0 || !env.OAUTH_KV) {
      const names = [...missing, ...(env.OAUTH_KV ? [] : ['OAUTH_KV (KV binding)'])];
      return new Response(`Server is not configured. Missing: ${names.join(', ')}\n`, { status: 500 });
    }

    // Built on first request because the public URL comes from configuration.
    const key = `${env.PUBLIC_URL}|${env.ALLOWED_REDIRECT_URIS}`;
    if (!provider || provider.builtFor !== key) provider = { builtFor: key, instance: buildProvider(env) };
    return provider.instance.fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
