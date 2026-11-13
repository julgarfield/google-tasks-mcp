# Task deletion upgrade (v2.2)

Adds delete_task with exact task_list_id and task_id. Requires both the existing write-enabled grant and tasks.write scope. Destructive and idempotent annotations; assigned tasks can affect their original in Docs/Chat, so openWorldHint is true. The client controls approval prompts; annotations do not enforce a confirmation dialog. No bulk-delete or task-list delete tool.

A successful DELETE has an empty response. Already absent/deleted tasks return changed=false; a bad list id returns an error. No automatic retry on 5xx/network failure; inspect task state before retrying. Parent deletion may also remove subtasks. No undo tool.

## Deploy

No deployment has been performed as part of preparing this upgrade. Keep the existing wrangler.jsonc, secrets, KV and Google scopes. Existing write-enabled connections already have the required Google permission.

From your local project:

```sh
cd /Users/juliangarfield/Downloads/google-tasks-mcp
npm run typecheck
npm test
npx wrangler deploy --dry-run
npx wrangler deploy
```

Then refresh the Google Tasks tool list in ChatGPT and Claude and start new chats. Look for delete_task (eight tools total). If refresh is unavailable, reconnect the existing connector. Do not uninstall unless necessary. Leave approval prompts enabled for deletion.

## Disposable test (user-run only)

Create a new uniquely named disposable task in the existing test list. Confirm the exact list and task, request deletion of that task only, approve the action, then verify it is absent in Google Tasks. Repeat in the other client with a different disposable task. Do not use real tasks for testing.

## Rollback

The previously reported working v2.1 deployment was 30e8d938-2b8d-40b9-a7eb-0d69473bec02. Confirm it is the desired version, then use:

```sh
npx wrangler rollback 30e8d938-2b8d-40b9-a7eb-0d69473bec02
```

Rollback removes the tool from server code but does not restore deleted tasks. Refresh client tool metadata afterward.
