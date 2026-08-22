# Runtime policy overlay v2.6.0

`START.cmd` launches `start-notion-mcp-v21.ps1`, which starts `runtime-patches\gateway-v21.py`. That entry point loads `gateway-v21-core.py`, installs this overlay on top of the base server in `gateway\`, and then runs the unchanged server entry point. All launchers use OAuth 2.1 Authorization Code + PKCE; the legacy static-token mode has been removed.

The overlay lives outside `gateway\` on purpose: gateway sources and its config directory are themselves protected, so policy changes never require editing protected files in place.

The local control panel is available only on `127.0.0.1:8876`. It provides file authorization, browsing, search, approval, audit, and trash features without activation codes, license checks, encryption, or build restrictions.

## Permission behavior

- **Level 1 — Read:** read, list, and search.
- **Level 2 — Development:** create/overwrite/append/move/copy files and run general local Python, shell, test, build, or compiler commands.
- **Level 3 — Project maintenance:** Level 2 plus deletion of ordinary small files through `delete_path` (trash by default).
- **Level 4 — High risk:** directory deletion, permanent deletion, large/protected targets, and visibly destructive cleanup/system commands; every attempt requires explicit approval.
- Deleting a drive root or the active authorized root itself is always forbidden.

## Important command boundary

Level-2 commands execute under the current Windows account and are **not an OS sandbox**. The policy detects common deletion/cleanup patterns and requires Level 4 for them, but arbitrary Python or shell code can disguise its effects. Only authorize trusted projects, and use `delete_path` rather than shell/Python for deletion so size, directory, approval, trash, and audit rules remain enforceable.

## Command timeout behavior

- `run_command` waits synchronously for at most about 15 seconds.
- Longer commands continue as bounded background jobs and return a `job_id` with `status: running`.
- Query with `get_command_status`; use `list_command_jobs` if the job ID was lost. Do not rerun an active command.
- Identical recent commands are reused for 120 seconds unless `force_new: true` is explicit.
- At most two command jobs run concurrently. Output streams to files under `gateway\logs\command-jobs` and is truncated on return; each job still obeys the 300-second limit.
- A command that reads an entire large game container into memory is rejected as resource-intensive; read it in chunks instead.
- Audit entries redact common tokens and record job ID, PID, status, duration, timeout, and exit code.

## Approval behavior

- Action tools remain discoverable in fresh chats. Client-side connection settings control outer confirmation behavior; choose Always allow or Run automatically there for trusted routine tools. The gateway remains the enforcement point and still applies per-call Level 4 approval to truly high-risk operations.
- Local popup duration: 120 seconds.
- No response: the current attempt executes nothing.
- To stay below the quick-tunnel timeout, the MCP request waits synchronously for at most about 85 seconds. The desktop popup can continue to 120 seconds.
- If the request returns while the popup remains open, the agent must stop polling and wait for the user.
- Approval can only be granted in the native desktop dialog or local console. `confirm_action` can record a denial but cannot grant access.
- Explicit denial must not be retried automatically.

## OAuth and tunnel behavior

1. Double-click `STOP.cmd`.
2. Double-click `START.cmd` to start the gateway and Cloudflare Tunnel.
3. Add the displayed MCP URL in your client and select OAuth. The gateway uses dynamic client registration, PKCE S256, short-lived access tokens, and rotating refresh tokens.
4. A Quick Tunnel URL remains available while the gateway and tunnel processes are running, but changes after a full stop or restart.
5. For a fixed URL across reconnects and restarts, run `SETUP-STABLE-TUNNEL.cmd` once and configure a Cloudflare-managed domain. Then restart with `STOP.cmd` and `START.cmd`.
