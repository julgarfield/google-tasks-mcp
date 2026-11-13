# Upgrading the deployed read-only server to read + write

Nothing here changes the public URL, the KV namespace binding, the secrets or the redirect allowlist. The only new stored data is a 10-minute retry record per created task (a keyed hash and a task id) in the existing KV namespace. Existing Claude and ChatGPT connections keep working read-only after the deploy; each gains write access when you reconnect it.

Order matters: Google first, then deploy, then reconnect.

## 1. Google Cloud: allow the write scope

Console → select the project → **Google Auth Platform → Data Access → Add or remove scopes**.

1. In "Manually add scopes" paste `https://www.googleapis.com/auth/tasks` → Add to table → Update.
2. Keep the existing `tasks.readonly`, `openid` and `userinfo.email` entries.
3. **Save**.

Nothing else changes: same OAuth client, same client secret, same redirect URIs, same test users or publishing status. The Tasks API is already enabled. If the app is "In production" and unverified you will see the same "Google hasn't verified this app" screen as before, now listing "Create, edit, organize, and delete all your tasks". That wording is Google's description of the scope; this server now supports deleting tasks, but not task lists.

## 2. Put the new files in your local project

Replace `src/auth.ts`, `src/google.ts`, `src/index.ts`, `src/mcp.ts`, `src/types.ts`, `package.json`, `.gitignore`, `README.md`; add `src/recent-creates.ts`, `test/` and this file. `wrangler.jsonc`, `package-lock.json` and `tsconfig.json` are unchanged, and no dependency was added or updated.

## 3. Check, then deploy

```sh
npm ci
npm run typecheck
npm test                      # mocked Google only
npx wrangler deploy --dry-run # builds, uploads nothing
npx wrangler deploy
```

Do not run `wrangler secret put`: the stored secrets stay as they are.

Verify:

```sh
curl -si -X POST https://google-tasks-mcp.taskbridge-io.workers.dev/mcp | grep -i www-authenticate
# ... scope="tasks.readonly tasks.write"
```

To undo: `npx wrangler rollback` returns to the previous version. Connections made after the upgrade keep working on the old code as read-only.

## 4. Reconnect each client

Until you do this, the write tools answer "This connection has read-only access ... reconnect" and change nothing.

**Claude** (claude.ai → Settings → Connectors → your Google Tasks connector)

1. Disconnect, then Connect.
2. On this server's page leave "Also allow creating, editing, completing and reopening tasks" ticked → Continue to Google.
3. On Google's screen approve the Tasks permission.
4. Back in the connector's settings, check the tool list shows eight tools and set the permission for the five write tools to ask for approval (the default for tools that are not read-only).
5. Start a new chat. Open chats keep the old tool list.

**ChatGPT** (Settings → Apps / Connectors → your connector; names vary by version)

1. Disconnect and reconnect (or delete and re-create with the same URL), with the same ticks as above.
2. Press **Refresh** on the connector's details page. ChatGPT does not pick up new tools until you do.
3. Check the five write tools are listed and enabled. If you refreshed on an earlier build, refresh again: one annotation and two descriptions changed. ChatGPT asks for confirmation before write actions; leave that on.
4. Start a new chat.

To keep one client read-only, untick the box on this server's consent page when connecting it.

## 5. End-to-end test with a disposable task

Do this once in Claude and once in ChatGPT, approving each write when asked. It touches only one new list and one new task.

1. "Create a Google Tasks list called `MCP test`." → `create_task_list`, `created: true`.
2. "Add a task `MCP write test - delete me` to the MCP test list, due 2026-12-31." → `create_task`. Note the task id. In Google Tasks the task shows Dec 31 with no time.
3. Send the same request again, after the first has finished. → `created: false`, same id, still one task in Google Tasks. (Best effort: it covers a repeat of a finished call within 10 minutes, not two calls running at once.)
4. "Rename that task to `MCP write test 2`." → `update_task`; due date still Dec 31.
5. "Set its notes to `hello`." Then "Remove its due date." → notes stay `hello`, due is `null`. **This is the step to watch**: clearing is a PATCH with `null`, after which the server reads the task back. Against real Google this is unverified. If Google keeps the field you get an error saying the due date "is still set" and nothing else happens; the server does not force it. Tell me if you see that.
6. "Clear its notes." → notes `null`, title unchanged.
7. "Mark it complete." → `status: completed` with a `completed` time. Repeat → `changed: false`, same time.
8. "Reopen it." → `status: needsAction`, `completed: null`.
9. "List the tasks in MCP test." → the read tools still work and show the task.
10. Clean up by hand in Google Tasks: delete the `MCP test` list. The server cannot delete task lists.

Optional: while it runs, `npx wrangler tail` should show no task text and no tokens, only request lines and any `oauth_error ...` codes. Close it afterwards.

## If something is off

- Write tools still say read-only after reconnecting: the box on the consent page was unticked, or the client reused an old session. Disconnect fully, reconnect, start a new chat.
- Google shows an error about the scope: step 1 was not saved, or you are signed in to a different Google account.
- ChatGPT does not list the new tools: Refresh on the connector details page, then a new chat.
- Reads broke: `npx wrangler rollback`, then tell me what `npx wrangler tail` printed.
