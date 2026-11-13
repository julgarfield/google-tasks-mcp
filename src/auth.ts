// Everything that isn't /mcp or a provider-owned OAuth endpoint: the consent page (/authorize)
// and the return from Google (/callback).
//
// Flow: client -> GET /authorize (consent page) -> POST /authorize -> Google sign-in
//       -> GET /callback (check the account, store the grant) -> back to the client with a code.

import { AuthorizationError, authorizationErrorRedirect, type ConsentDescription } from '@cloudflare/workers-oauth-provider';

import { exchangeGoogleCode, fetchVerifiedEmail, GOOGLE_TASKS_READ, GOOGLE_TASKS_WRITE, googleAuthorizeUrl, revokeGoogleToken } from './google';
import { allowedEmail, isAllowedRedirectUri, SCOPE_READ, SCOPE_WRITE, type Env, type Props } from './types';

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);

const PAGE_STYLE =
  'body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a}' +
  'small{color:#555}button{font:inherit;padding:.5rem 1.25rem;margin-right:.5rem;border-radius:.4rem;border:1px solid #888;cursor:pointer}' +
  '.warn{background:#fff4e5;border:1px solid #e0a040;padding:.75rem;border-radius:.4rem}';

function page(title: string, body: string, status: number, headers = new Headers()): Response {
  headers.set('Content-Type', 'text/html; charset=utf-8');
  headers.set('Cache-Control', 'no-store');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Referrer-Policy', 'no-referrer');
  if (!headers.has('Content-Security-Policy')) {
    headers.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'");
  }
  const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>${PAGE_STYLE}</style><h1>${escapeHtml(title)}</h1>${body}</html>`;
  return new Response(html, { status, headers });
}

function errorPage(message: string, status = 400): Response {
  return page('Could not connect', `<p>${escapeHtml(message)}</p>`, status);
}

function consentPage(details: ConsentDescription, handle: string, headers: Headers): Response {
  const body = `
<p><strong>${escapeHtml(details.clientName)}</strong> wants access to your Google Tasks through this server.</p>
<p>This app registered itself, so its name is not verified. Access will be sent to <strong>${escapeHtml(details.redirectHost)}</strong>.</p>
${details.redirectIsLoopback ? '<p class="warn"><strong>This sends access to an app on your own computer.</strong> Continue only if you just started connecting from it.</p>' : ''}
<p>Continue only if you started this from Claude or ChatGPT (or your own test tool) a moment ago. Next you will sign in with Google.</p>
<form method="post">
  <input type="hidden" name="handle" value="${escapeHtml(handle)}">
  <p><label><input type="checkbox" name="write" value="1" checked> Also allow creating, editing, completing, reopening and deleting tasks.</label><br>
  <small>Untick to give this app read-only access. Write access includes task deletion. Task lists cannot be deleted here.</small></p>
  <button name="decision" value="approve">Continue to Google</button>
  <button name="decision" value="deny">Cancel</button>
</form>`;
  return page('Connect Google Tasks', body, 200, headers);
}

function redirect(location: string, headers = new Headers()): Response {
  headers.set('Location', location);
  headers.set('Cache-Control', 'no-store');
  return new Response(null, { status: 302, headers });
}

async function s256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** GET /authorize: validate the request and show the consent page. */
async function showConsent(request: Request, env: Env): Promise<Response> {
  const oauth = env.OAUTH_PROVIDER;
  const authRequest = await oauth.parseAuthRequest(request);

  // Belt and braces: registration already refuses other redirect URIs (see index.ts).
  if (!isAllowedRedirectUri(env, authRequest.redirectUri)) {
    return errorPage('This app is not allowed to connect to this server.', 403);
  }

  const details = await oauth.describeConsent(authRequest);
  const consent = await oauth.beginConsent(authRequest);
  return consentPage(details, consent.handle, consent.headers);
}

/** POST /authorize: the user decided. Only on approval does the Google redirect start. */
async function handleDecision(request: Request, env: Env): Promise<Response> {
  const oauth = env.OAUTH_PROVIDER;
  const form = await request.formData();
  const handle = String(form.get('handle') ?? '');

  if (form.get('decision') !== 'approve') {
    const denied = await oauth.denyConsent(request, handle);
    return redirect(denied.redirectTo, denied.headers);
  }

  // The authorization request comes back from storage, bound to this browser; nothing is
  // trusted from the form except the one-time handle.
  // The owner chooses here, per client, whether it may change tasks. That choice decides both
  // the scopes this server will issue and which Google scope is requested next.
  const write = form.get('write') === '1';
  const approved = await oauth.approveConsent(request, handle, { scope: write ? [SCOPE_READ, SCOPE_WRITE] : [SCOPE_READ] });

  const verifier = crypto.randomUUID() + crypto.randomUUID(); // PKCE for the Google leg
  const upstream = await oauth.beginUpstream(approved.request, { data: { verifier, write }, headers: approved.headers });
  return redirect(googleAuthorizeUrl(env, upstream.state, await s256(verifier), write), upstream.headers);
}

/** GET /callback: Google sent the user back. */
async function handleCallback(request: Request, env: Env): Promise<Response> {
  const oauth = env.OAUTH_PROVIDER;
  const params = new URL(request.url).searchParams;

  // Refused unless `state` matches the cookie set when this browser approved the consent page.
  const resumed = await oauth.finishUpstream<{ verifier: string; write?: boolean }>(request);

  const code = params.get('code');
  if (params.get('error') || !code) {
    return redirect(authorizationErrorRedirect(resumed.request, 'access_denied'), resumed.headers);
  }

  const tokens = await exchangeGoogleCode(env, code, resumed.data.verifier);
  if (!tokens) return errorPage('Google sign-in failed. Start again from the app you were connecting.', 502);

  // The owner check. Everything else about this server depends on it.
  const email = await fetchVerifiedEmail(tokens.accessToken);
  if (email !== allowedEmail(env)) {
    await revokeGoogleToken(tokens.refreshToken ?? tokens.accessToken);
    return errorPage('This connector is private. That Google account is not allowed to use it.', 403);
  }

  // Check what Google actually granted (its consent screen lets permissions be unticked), not
  // what was asked for. Google's full Tasks scope also covers reading.
  const write = resumed.data.write === true;
  const granted = tokens.scope.split(' ');
  if (!granted.includes(write ? GOOGLE_TASKS_WRITE : GOOGLE_TASKS_READ)) {
    return errorPage('Google Tasks access was not granted. Start again and leave the Tasks permission ticked on the Google screen.');
  }
  if (!tokens.refreshToken) {
    return errorPage('Google did not return a refresh token. Remove this app at myaccount.google.com/connections, then start again.');
  }

  const props: Props = {
    email,
    refreshToken: tokens.refreshToken,
    accessToken: tokens.accessToken,
    accessTokenExpiresAt: tokens.accessTokenExpiresAt,
    canWrite: write,
  };
  const { redirectTo } = await oauth.completeAuthorization({
    request: resumed.request,
    userId: 'owner', // single-user server; kept free of personal data because KV stores it unencrypted
    metadata: {},
    scope: write ? [SCOPE_READ, SCOPE_WRITE] : [SCOPE_READ],
    props, // encrypted at rest by the provider
  });
  return redirect(redirectTo, resumed.headers);
}

export const authHandler = {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    try {
      if (pathname === '/authorize' && request.method === 'GET') return await showConsent(request, env);
      if (pathname === '/authorize' && request.method === 'POST') return await handleDecision(request, env);
      if (pathname === '/callback' && request.method === 'GET') return await handleCallback(request, env);
    } catch (error) {
      if (error instanceof AuthorizationError) {
        // redirectTo is set only when the client and its redirect URI were validated.
        if (error.redirectTo) return redirect(error.redirectTo);
        return errorPage(`${error.description} Start again from the app you were connecting.`);
      }
      throw error;
    }

    if (pathname === '/' && request.method === 'GET') {
      return new Response('Google Tasks MCP server (private). The MCP endpoint is /mcp.\n', {
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      });
    }
    return new Response('Not found\n', { status: 404 });
  },
};
