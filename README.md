# Google Tasks MCP server (private)

A remote MCP server that lets Claude and ChatGPT read and manage your Google Tasks: list tasks, see what is done, create tasks, edit them, and complete or reopen them. It runs as one Cloudflare Worker and is added as a custom connector.

Upgrading a deployed read-only version? Follow [UPGRADE.md](UPGRADE.md).

It is built for exactly one person. Only the Google account in `ALLOWED_EMAIL` can connect. Task deletion is available; task-list deletion is not.

## Tools

| Tool | What it does | Annotations |
| --- | --- | --- |
| `list_task_lists` | Id and title of each list. | read-only |
| `list_tasks` | Tasks from one list or all lists, optionally filtered by due date, with or without completed ones. | read-only |
| `get_task` | One task by list id and task id. | read-only |
| `create_task` | Adds one task (title; optional list, notes, due date, parent). | write, additive, not idempotent |
| `update_task` | Changes title, notes and/or due date of one task; can clear notes or due date. | write, destructive (overwrites), idempotent |
| `delete_task` | Deletes a task by exact task/list ids. No undo tool. | write, destructive, idempotent |
| `set_task_completion` | Marks one task done or reopens it. | write, destructive (overwrites), idempotent |
| `create_task_list` | Adds an empty list. | write, additive, not idempotent |

`delete_task` has `openWorldHint: true` because assigned tasks can affect Docs/Chat; other tools have `openWorldHint: false`. Each task comes back as `id`, `title`, `notes`, `due`, `status`, `completed`, `updated`, `parent`, `list_id`, `list_title`.

- `status` is `needsAction` or `completed`.
- `due` is a date (`YYYY-MM-DD`). The Tasks API does not expose a due time. Writes store midnight UTC of that date, which is how Google itself stores it, and reads return only the date.
- `list_tasks` returns at most 300 tasks per call and sets `truncated: true` when there were more.

### How the write tools stay safe for agents

- **Ids only.** Existing tasks are addressed by `task_list_id` and `task_id`. No tool matches by title, so the server never chooses between similar tasks.
- **Retry protection is best effort, and says so.** When `create_task` creates a task it remembers, for 10 minutes, a keyed hash of the call (list, title, notes, due date, parent) and the new task's id. An identical call inside that window gets that task back (`created: false`) only if the task is still open and unchanged. Tasks made elsewhere, or edited to look the same, are never matched. `allow_duplicate: true` skips the check. `create_task_list` returns an existing list with the same title. Neither is a guarantee: there is no atomic check, so calls that overlap in time can both create. Both tools are therefore annotated `idempotentHint: false`, and their descriptions tell the agent to check before retrying after an unclear failure.
- **Nothing is overwritten by accident.** `update_task` sends Google a PATCH containing only the fields that actually change. Empty strings are refused; removing notes or a due date takes an explicit `clear_notes` or `clear_due`, sent as `null`. After a clear the task is read back; if the field is still set the tool reports exactly that (and which other changes were saved) and stops. A task is never replaced wholesale. The result includes the previous values.
- **Idempotent where it is true.** `update_task` and `set_task_completion` state an end result, so repeating or overlapping calls leave the same state; those two are `idempotentHint: true`.
- **No invented dates or times.** A due date is set only when passed. Completion time is never sent; Google stamps it. Completing an already-completed task writes nothing, so the original time is kept.
- **No blind retries of writes.** A failed write is attempted once. On a 5xx the tool says the outcome is unknown and to check before retrying.
- **Untrusted content.** The server instructions and tool descriptions tell the model that titles and notes are data, not instructions.
- **Approval is the host's job.** Write tools are marked `readOnlyHint: false`, and the two that overwrite data `destructiveHint: true`, so Claude and ChatGPT can ask you before running them. The server has no way to skip that.

### Two layers of scope

| Layer | Scopes | Decided by |
| --- | --- | --- |
| This server → Claude/ChatGPT (MCP) | `tasks.readonly`, `tasks.write` | The checkbox on this server's consent page, per client |
| Google → this server | `.../auth/tasks.readonly` or `.../auth/tasks` | Requested to match that checkbox; what Google actually granted is checked at sign-in |

A write tool runs only if the caller's token carries `tasks.write` **and** the grant records that Google gave the full Tasks scope. Otherwise it changes nothing and says the connector must be reconnected. Connections made before write support have neither and keep working read-only.

## How it works

```
Claude / ChatGPT ──OAuth 2.1 + PKCE──▶ this Worker ──OAuth──▶ Google
Claude / ChatGPT ──POST /mcp (Bearer)─▶ this Worker ──Tasks API v1──▶ Google
```

- Toward Claude the Worker is an OAuth authorization server: protected resource metadata (RFC 9728), authorization server metadata (RFC 8414), dynamic client registration (RFC 7591), PKCE with S256. That part is [`@cloudflare/workers-oauth-provider`](https://github.com/cloudflare/workers-oauth-provider).
- Toward Google the Worker is an OAuth client with the `tasks` scope, or `tasks.readonly` for a connection you made read-only (plus `openid email`, to check who signed in).
- `/mcp` is the MCP Streamable HTTP endpoint, served by the official MCP TypeScript SDK in stateless mode.

### Why TypeScript on Cloudflare Workers

Both official SDKs can serve Streamable HTTP. The difference is the authorization server. In Python you would implement the SDK's provider interface yourself (client, code and token storage, encryption, the consent step) and then need a host with a persistent disk or database, which is where the free options run out. On Workers that whole layer is a maintained library, storage is the free KV tier, and HTTPS comes with the `workers.dev` URL. Less security-critical code written by hand was the deciding factor.

### Security properties

- **Owner only.** After Google sign-in the Worker reads the account's verified email and compares it to `ALLOWED_EMAIL`. Any other account gets a 403, no code is issued, and the Google token is revoked. The check is repeated on every `/mcp` request.
- **Refresh token encrypted at rest.** The Google refresh token lives in the grant's `props`, which the provider encrypts with AES-GCM under a key that can only be unwrapped with a valid token held by Claude. KV holds token hashes and ciphertext, so reading KV alone reveals nothing usable.
- **Only known callbacks can register.** Dynamic registration is open to the internet by design, so the Worker refuses any client whose redirect URI is not in `ALLOWED_REDIRECT_URIS` or of the form `https://chatgpt.com/connector/oauth/<id>`. The same rule is applied again at `/authorize`.
- **Consent before Google.** `/authorize` shows a page naming the client and where access will be sent, bound to your browser with a `__Host-` cookie. The Google redirect only starts after you approve, and the callback is refused in any other browser. This is the MCP spec's defence against the confused deputy problem.
- **No logging of tokens or task contents.** The only log lines are OAuth error categories (for example `oauth_error 400 invalid_grant refresh-token-grant refresh_token_expired`). Workers Logs is left off because it would store callback URLs.
- **Task deletion, no replacements.** `delete_task` uses DELETE for an exact task id, requires write access, and is annotated destructive. Deleting assigned tasks also deletes their original in Docs/Chat. Deleting a parent may remove subtasks. There is no undo tool or task-list delete tool, and no PUT fallback.
- **Retry records hold no task text.** They live in the same KV namespace under `recent-create:`, as an HMAC plus a task id, and expire after 10 minutes.

## Files

```
src/index.ts    wiring: OAuth provider options, redirect allowlist, token refresh hook
src/auth.ts     /authorize consent page and /callback from Google
src/google.ts   Google OAuth calls and the Tasks API client (pagination, showHidden)
src/mcp.ts      the tools and the /mcp handler
src/recent-creates.ts  10-minute record of tasks create_task made (retry protection)
test/           mock Google + end-to-end tests (`npm test`)
src/types.ts    config and stored props
wrangler.jsonc  Worker config (no secrets)
```

## Configuration

| Name | Where | Value |
| --- | --- | --- |
| `GOOGLE_CLIENT_ID` | secret | From the Google OAuth client. |
| `GOOGLE_CLIENT_SECRET` | secret | From the Google OAuth client. |
| `ALLOWED_EMAIL` | secret | The one Google account allowed to connect. |
| `PUBLIC_URL` | `wrangler.jsonc` | The Worker's origin, e.g. `https://google-tasks-mcp.yourname.workers.dev`. No trailing slash, no `/mcp`. |
| `ALLOWED_REDIRECT_URIS` | `wrangler.jsonc` | Comma-separated. Defaults to Claude's two callback URLs. |
| `OAUTH_KV` | `wrangler.jsonc` | KV namespace binding. |

Locally, all of these except the KV binding come from `.dev.vars`.

---

## Setup

You need Node.js 22 or newer, a Google account, and a free Cloudflare account.

```sh
npm install
```

### 1. Google Cloud

Google has moved these screens around more than once. The current home is **Google Auth Platform** in the Cloud console; older guides call the same thing "OAuth consent screen".

1. Go to <https://console.cloud.google.com/> and create a project (any name, for example `tasks-mcp`). Make sure it is selected in the top bar.
2. **Enable the API:** APIs & Services → Library → search "Google Tasks API" → Enable.
3. **Consent screen:** Google Auth Platform → Get started.
   - App name: anything. Support email: yours.
   - Audience: **External**.
   - Contact email: yours. Accept the policy and create.
4. **Scopes:** Google Auth Platform → Data Access → Add or remove scopes → add `https://www.googleapis.com/auth/tasks`, `https://www.googleapis.com/auth/tasks.readonly`, `openid` and `.../auth/userinfo.email` → Save.
5. **Test user:** Google Auth Platform → Audience → Test users → add the Google account whose tasks you want (the same address you will put in `ALLOWED_EMAIL`).
6. **Client:** Google Auth Platform → Clients → Create client.
   - Application type: **Web application**.
   - Authorized redirect URIs: add `http://localhost:8787/callback` now. You will add the production one in step 4 below.
   - Create, then copy the client ID and client secret.

> **Testing mode expires your connection every 7 days.** While the app's publishing status is "Testing", Google issues refresh tokens that die after a week, and you would have to reconnect in Claude each time. To avoid it: Audience → **Publish app** (status becomes "In production"). You do not need to submit for verification for personal use. The only cost is a "Google hasn't verified this app" screen during sign-in, where you choose Advanced → Go to (app name). Do this before your final connect, because tokens issued while in Testing keep their 7-day life.

> **School or work accounts:** if your tasks are in a Google Workspace account (for example a university address), the organization's admin may block unverified third-party apps. You would see "Access blocked" at Google sign-in, and only the admin can change that.

### 2. Test locally with MCP Inspector

```sh
cp .dev.vars.example .dev.vars
```

Edit `.dev.vars`: paste the client ID and secret, and set `ALLOWED_EMAIL`. Leave `PUBLIC_URL` and `ALLOWED_REDIRECT_URIS` as they are. Then:

```sh
npm run dev          # Worker on http://localhost:8787
```

In a second terminal:

```sh
npx @modelcontextprotocol/inspector     # opens http://localhost:6274
```

In the Inspector:

1. Transport Type: **Streamable HTTP**. URL: `http://localhost:8787/mcp`.
2. Click **Connect**. The Inspector registers itself, then your browser shows this server's consent page (with a warning that access goes to an app on your computer, which is expected here) and then Google sign-in.
3. Back in the Inspector: Tools → List Tools should show the eight tools. Run `list_task_lists`, then `list_tasks` with no arguments.
4. Check off a task in Google Tasks, run `list_tasks` again, and confirm it shows `"status": "completed"` with a `completed` time.

Use Chrome or Firefox for this. The consent cookies are marked `Secure`, which Safari does not accept on `http://localhost`.

A quick check that needs no browser:

```sh
curl -i -X POST http://localhost:8787/mcp
# HTTP/1.1 401 ... WWW-Authenticate: Bearer realm="OAuth", resource_metadata="http://localhost:8787/.well-known/oauth-protected-resource/mcp", scope="tasks.readonly tasks.write"
curl http://localhost:8787/.well-known/oauth-authorization-server
```

`wrangler dev` prints a warning that CIMD is disabled. That is expected: this server uses dynamic client registration only.

### 3. Deploy to Cloudflare

```sh
npx wrangler login
npx wrangler kv namespace create OAUTH_KV
```

Paste the printed `id` into `wrangler.jsonc` in place of `REPLACE_WITH_KV_NAMESPACE_ID`. Then:

```sh
npx wrangler deploy
```

The output ends with your URL, like `https://google-tasks-mcp.yourname.workers.dev`. Put that origin into `PUBLIC_URL` in `wrangler.jsonc`, set the secrets, and deploy again:

```sh
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put ALLOWED_EMAIL
npx wrangler deploy
```

Check it:

```sh
curl -i -X POST https://google-tasks-mcp.yourname.workers.dev/mcp
# expect 401 with a resource_metadata URL on your workers.dev host
```

A `500 Server is not configured. Missing: ...` response names whichever setting is still absent.

### 4. Add the production redirect URI at Google

Google Auth Platform → Clients → your client → Authorized redirect URIs → add:

```
https://google-tasks-mcp.yourname.workers.dev/callback
```

### 5. Add the connector in Claude

claude.ai → Settings → Connectors → Add custom connector. Paste exactly:

```
https://google-tasks-mcp.yourname.workers.dev/mcp
```

No trailing slash. Leave the advanced OAuth client ID and secret fields empty; Claude registers itself. Click Connect, approve the consent page, sign in with Google. Do the first connect in a desktop browser. Once connected it works in the mobile and desktop apps too.

Then ask Claude something like "Which of my tasks due this week are still open?"

---

## Troubleshooting

To see why the server refused something, run `npx wrangler tail` while you retry. It prints lines like `oauth_error 401 invalid_token protected-resource token_expired`. Tail output is live only and shows request URLs, so close it when you are done.

**Auth loop, or Claude says it could not connect**

- `PUBLIC_URL` must equal the origin of the URL you pasted into Claude, and the pasted URL must end in `/mcp` with no trailing slash. A mismatch makes token requests fail with `invalid_target`.
- Google shows `redirect_uri_mismatch`: the Google client is missing `<PUBLIC_URL>/callback`, or it differs by a character.
- Google shows "Access blocked" or `access_denied`: in Testing status, the account is not listed under Test users. On a school or work account, the admin may block the app.
- "This connector is private": you signed in with a Google account other than `ALLOWED_EMAIL`. Check the secret for typos.
- "Google did not return a refresh token": remove the app at <https://myaccount.google.com/connections> and connect again.
- A "page expired / start again" style error on the consent page or callback: the flow took over ten minutes, the page was reused, or it finished in a different browser from the one that started it (in-app browsers on phones do this). Start again from Claude in one desktop browser.
- Registration fails for a client other than Claude (Claude Code, another MCP client): its redirect URI is not in `ALLOWED_REDIRECT_URIS`. Add it there only if you mean to allow that client.

**401s**

- One 401 at the start of every connection is normal. It is how Claude discovers the OAuth endpoints.
- Worked for a week, then stopped: the Google app is still in Testing status. See the note in step 1, publish, and reconnect.
- Worked, then stopped after a long gap: the grant expires after 30 days without use. Reconnect.
- You revoked the app in your Google account, or changed `GOOGLE_CLIENT_SECRET`: reconnect. The next time Claude refreshes its token the server sees Google's `invalid_grant`, ends the grant, and Claude asks you to reconnect.
- A tool result saying Google refused the request with 403: the Tasks API is not enabled in the Cloud project, or the Tasks permission was unticked on Google's consent screen.

**Missing completed tasks**

- This server already sends `showCompleted=true` and `showHidden=true`. Tasks checked off in Google's apps are flagged hidden, and without `showHidden` the API silently drops them.
- A completed task that was then deleted (for example with "Delete all completed tasks") is gone from the API. Deleted tasks are never returned.
- If `truncated` is `true`, the 300-task cap or the per-request Google call budget was hit. Ask for one list, a due-date range, or `include_completed=false`.
- With `due_min` or `due_max` set, tasks that have no due date are excluded.
- Tasks assigned to you from Google Docs or Chat spaces are not requested (the API needs `showAssigned=true` for those).
- Make sure the tasks are in the same Google account as `ALLOWED_EMAIL`.

## Disconnecting

- Remove the connector in Claude settings.
- Revoke the app at <https://myaccount.google.com/connections>.
- To wipe all server-side state, delete the keys in the `OAUTH_KV` namespace (Cloudflare dashboard → Storage & Databases → KV), or delete the namespace.

## Limits worth knowing

- Cloudflare's free plan allows 50 outbound requests per invocation, so one tool call makes at most 40 Google API calls. With 100 tasks per page that is far more than the 300-task cap needs, but an account with more than about 35 lists would see `truncated` on an all-lists query.
- Free KV allows 1,000 writes a day. Normal use writes a handful of keys per hour, plus one per created task. The registration endpoint is public: requests with a disallowed redirect URI are refused before anything is stored, but a stranger registering clients with Claude's own redirect URI would write one key each (they expire after 90 days and give no access). If that ever exhausts the quota, the symptom is failed connects until the next day.

## Tests

```sh
npm run typecheck
npm test
```

`npm test` builds a throwaway copy of the Worker whose Google endpoints point at an in-memory mock (`test/mock-google.mjs`), runs it in the local Workers runtime with fake credentials, and drives it over HTTP like an MCP client. It cannot reach your Google account and does not touch production.

After testing locally with real credentials (`npm run dev`), delete the `.wrangler/` folder: wrangler's local request trace keeps full URLs, including used one-time OAuth codes.
