# Toolgate

One local MCP endpoint for all your AI agents. Claude Code, Codex, Gemini CLI or your own agent connect to `http://localhost:7777/mcp`; behind it sit any number of MCP servers, databases and APIs. Credentials live in the gateway's encrypted vault, and **agents never see secret values**.

```
Claude Code / Codex / Gemini CLI / your agent
              │  Authorization: Bearer agw_…  (one token per agent)
              ▼
      Toolgate ── vault (AES-256-GCM)       admin panel (/ui)
      5 meta tools     policy (per server/agent)  approvals
      or native tools  audit log (SQLite)         key pools + API proxy
              │
     ┌────────┼──────────┬────────────────┐
  stdio MCP  HTTP MCP   HTTP MCP + OAuth   built-in (Gemini TTS)
  (postgres, (github,   (cloudflare,
   sqlite…)   docs…)     notion…)
```

Single Go binary, no cgo, SQLite storage, embedded web UI. Runs on macOS and Linux (Windows: `serve` only).

[Türkçe README](README.tr.md)

## Why

- **One place for credentials.** API keys and OAuth tokens are entered in the panel, encrypted at rest, and injected into upstream requests. An agent that needs a key gets a link for *you* to fill in; the value never passes through a chat.
- **OS-level isolation.** The recommended install runs the gateway as its own login-less system user. Agents running as you (even with shell access) can't read the vault, the database, the master key, or the gateway's process environment.
- **Small context.** By default an agent sees 5 meta tools and discovers the real ones by search, instead of loading hundreds of tool schemas.
- **You stay in control.** Changes an agent makes that alter what a server runs or where data goes need your approval; upstream tools that change their description or schema are hidden until you approve them (tool pinning against rug-pulls).
- **Everything is logged** with configurable retention and argument privacy.

## Install

Building needs Go 1.27+ (any Go ≥ 1.21 fetches the right toolchain by itself).

```bash
git clone <this repo> toolgate && cd toolgate
./scripts/install.sh            # builds, then: sudo bin/toolgate install
```

`toolgate install` sets everything up by itself and prints each step before running it (`--dry-run` shows the plan only). Re-run it to upgrade; your data is kept.

### Isolated (recommended, needs an administrator account)

`sudo toolgate install`

| | macOS | Linux |
|---|---|---|
| Service user | hidden `_toolgate` (uid 450–499, no shell, no password) | system user `toolgate` (`nologin`) |
| Service | LaunchDaemon `io.github.nekinci.toolgate` | systemd unit `toolgate.service` with sandboxing (`ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges`, `PrivateTmp`, no capabilities…) |
| Data, vault, master key (0700) | `/Library/Application Support/Toolgate` | `/var/lib/toolgate` |
| Files made by built-in tools (world-readable, service-writable) | `/Users/Shared/Toolgate/outputs` | `/var/lib/toolgate-outputs` |
| Binary | `/usr/local/libexec/toolgate/toolgate`, linked from `/usr/local/bin` | same |
| Logs | `sudo tail "/Library/Application Support/Toolgate/gateway.log"` | `journalctl -u toolgate` |

The installer asks for an admin panel password (or reads it with `--password-stdin`). stdio MCP servers run as the service user too, so they can't touch your files; to give one access to a folder (e.g. a filesystem server), grant that user read permission on it.

### Per-user (no root)

`toolgate install --user` runs the gateway as you (LaunchAgent / `systemd --user`). On macOS the master key goes into your login Keychain. Simpler, but anything running as you can read the data directory. Sign in with the link from `toolgate admin-url`. On Linux, `loginctl enable-linger $USER` keeps it running after you log out.

### Other commands

```bash
toolgate status                   # which install exists, does it answer
sudo toolgate uninstall           # stop and remove the service, keep data
sudo toolgate uninstall --purge   # also delete data and the service user (irreversible)
toolgate migrate-export -out DIR  # copy database + master key for another install
sudo toolgate install --from DIR  # ...and import it into a fresh isolated install
toolgate serve -data DIR          # run in the foreground (any OS, e.g. under your own supervisor)
```

Moving from a per-user to an isolated install: run `toolgate migrate-export -out ~/agw-export` as yourself, then `sudo toolgate install --from ~/agw-export`. The export (which holds the master key in plain text) is deleted once it has been copied; your old `~/.toolgate` is only deleted if you add `--remove-old-data`.

The vault never silently replaces a master key it can't read: if the database has encrypted data and the key is missing, the gateway refuses to start instead of creating a new one.

## Connecting agents

In the panel, **Agents → Add agent** gives a **pairing code** (e.g. `VCGM-FRW8`; single use, valid 10 minutes) together with a ready-made command for each client. The command exchanges the code at `POST /pair` and writes the token straight into the client's config, so the token never shows on screen or in a chat:

```bash
T=$(curl -fsS http://localhost:7777/pair -d code=VCGM-FRW8 -d format=token) && \
  claude mcp add --scope user --transport http gateway http://localhost:7777/mcp --header "Authorization: Bearer $T"
```

- Commands for Claude Code, Codex (`codex mcp add … --bearer-token-env-var`) and Gemini CLI. The "Give to agent" tab produces a message you paste into another agent's chat so it runs the command itself; "Other" gives a `curl` that returns JSON.
- With an invalid or expired code `curl -f` fails and the rest of the command doesn't run, so no broken config is written.
- Exchanging a code mints a new token for that agent and invalidates the previous one. Requesting a new code cancels the old one. Codes are kept only in memory, hashed; after 20 wrong attempts `/pair` locks for 10 minutes.
- You can still choose to see the token directly ("show the token instead of a pairing code", or "show new token" on an existing agent).
- **Token lifetime:** never, 30/90/180 days or 1 year, per agent and per app. Counted from when a token is minted or the lifetime is changed. Expired tokens are refused with a message telling the agent to ask you for a new code; in the last 7 days the agent's instructions carry a warning so it can tell you, and the panel flags tokens 14 days ahead.

## What an agent sees

**Lazy mode (default)** exposes 5 meta tools; real tools are found by search so the context stays small:

| Tool | What it does |
|---|---|
| `overview` | All servers, their state, tool counts and sample tools. The same summary is sent as MCP `instructions`. |
| `search_tools` | Keyword search over every upstream tool (two passes, below). Tools hidden by policy, waiting for approval or on disabled servers never appear. |
| `describe_tools` | Input schemas and annotations of chosen tools. |
| `call_tool` | `server.tool` + arguments. Checked against policy, logged, routed upstream. |
| `manage` | Only for agents with `can_manage`: add/edit servers, search and install from the catalog, start an OAuth login, request a secret, restrict tools, read the audit log. |

**Tool presentation** is chosen per agent (Agents → agent → Tool presentation), falling back to the panel default:

- `lazy`: the 5 meta tools above.
- `direct`: every tool the agent may use is listed natively as `<server>__<tool>` with its real schema (names fit `[A-Za-z0-9_-]{1,64}`; long ones are shortened with a hash). `overview` and, if allowed, `manage` stay. At most 128 tools are listed; beyond that `search_tools`/`describe_tools`/`call_tool` are added and the instructions say so.
- `auto`: `direct` while the agent sees 40 tools or fewer, `lazy` above that.
- `?tools=lazy|direct|auto` on the MCP URL overrides the setting for one client.
- Direct tools go through exactly the same path as `call_tool`: policy, pinning, approval and audit are identical. The agent form shows each mode's measured footprint (tools and KB of `tools/list` + instructions).

**Search** first runs a *strict* pass: every meaningful query word (stop words dropped) must appear in the tool name, description, or the connection's id/name/description/purpose, exactly, by stem (`issues` ≈ `issue`) or as a prefix; `snake_case` and `camelCase` are split into words. If that finds nothing, a *loose* pass accepts any word, a small synonym table (`add` ≈ `create`, `ticket` ≈ `issue`, `mail` ≈ `email`…) and one typo (two in long words). Results carry `match: strict|loose|none` and, for `loose`/`none`, a `note` telling the agent what to do next.

**Missed searches** are counted per day and grouped by normalized query, with the last agent and time. The "Tool searches" box on the Activity page shows them — a query that keeps failing usually means a missing connection, and "Search catalog" looks it up directly. With audit argument mode `none`, query text isn't stored, only counted.

**Connection purpose:** each connection can have a short purpose written in the panel ("company account, production"). It is prefixed to tool descriptions as `[purpose]`, shown in `overview` and `instructions`, and matched by search, so an agent picks the right one of two similar connections. Only you can set it — a value sent by an agent is ignored. Max 160 characters.

**OAuth, "just leave me the login":** an agent installs a server with `manage catalog_install`. If the server needs OAuth, the gateway returns a login link for the agent to hand you; the callback lands on `localhost:7777/oauth/callback`, the gateway stores the token in the vault, finishes connecting and refreshes it from then on. Dynamic Client Registration is supported; a pre-registered OAuth app works via `oauth_client_id` + `oauth_client_secret_ref`.

**When a secret is needed:** `manage request_secret` returns a link to the panel with the right entry open. You type the value there.

## Admin panel (`/ui`)

English and Turkish (switch in the sidebar; follows the browser language by default).

- **Connections:** state, connect/disconnect, OAuth sign-in, tool list. Unchecked tools are hidden from every agent; "read-only only" shortcut; JSON editing and stderr logs.
- **Tool playground:** "Try" on any tool opens a form generated from its input schema (enums as selects, numbers, line-per-item arrays, JSON for nested objects; required fields first), with a raw JSON toggle. Calls are real, run as admin or with a chosen agent's restrictions, or as a permission dry-run. Tools with `destructiveHint` ask for confirmation; tools awaiting approval can't be tried. Images and audio are shown inline. These calls are logged as `ui:test` / `ui:test:<agent>` and kept apart from agent usage. Deep link: `#c/<id>?tab=tools&try=<tool>`.
- **Catalog:** recommended gateway templates, the Claude connector directory (~320 entries, cached, refreshed every 12 h), your own templates, and the official MCP Registry (search only). Install dialogs handle auth choice, required steps and fields such as region or URL, and wait for the login to finish. One connector can be installed several times under different ids (`pg-prod`, `pg-staging`…).
  - GitHub doesn't support dynamic client registration: "Sign in with GitHub" walks you through creating an OAuth App once (callback `http://localhost:7777/oauth/callback`), or use a fine-grained PAT.
- **Vault:** secrets are write-only. Shows which server uses which secret and what's missing.
- **Agents:** tokens and pairing codes, allow/deny globs, manage permission, tool presentation, "what does it see?" preview. **Apps** (API proxy) live here too.
- **Activity (audit):** every call, action, connection and OAuth event. Settings: retention (default 90 days, or `-audit-retention-days N`) and argument privacy — `full` (values, with secret-looking keys masked, plus a short result excerpt), `keys` (argument names only; default) or `none`. Management actions are always kept, masked, as a security record.

## Key pools

Several API keys for one service form a pool (Vault → Key pools → Add pool). A pool has an id, a provider and a secret name prefix: a pool with prefix `OPENAI_API_KEY` takes `OPENAI_API_KEY` and `OPENAI_API_KEY_*`. Calls are spread over the keys (least busy, least recently used first); a rate-limited key rests for the time the provider says, per model; an invalid key is disabled until you replace it. Removing a pool doesn't delete keys.

| Provider | Key goes into | Cool-down |
|---|---|---|
| Gemini | `x-goog-api-key` | `RetryInfo.retryDelay`; a daily quota (`…PerDay…`) until Pacific midnight |
| OpenAI | `Authorization: Bearer …` | `Retry-After`, else `x-ratelimit-reset-*`; `insufficient_quota` disables the key |
| Anthropic | `x-api-key` (+ `anthropic-version`) | `retry-after`, else `anthropic-ratelimit-*-reset`; 529 is transient |
| ElevenLabs | `xi-api-key` | `Retry-After`; `quota_exceeded` 24 h |
| Custom | header and prefix you choose | `Retry-After` on 429 (else 60 s) |

Everywhere: 401/403 = invalid, 5xx/408 = transient (another key after 10 s).

## API proxy for your own programs

Your own scripts can use pooled keys without ever holding a real key. Add an **App** (Agents page), pick the pools it may use, and pair it or take its `agp_…` token. Keep using the provider's SDK; change only the base URL and the API key:

| Provider | Base URL | API key |
|---|---|---|
| OpenAI | `http://localhost:7777/proxy/<pool>/v1` (`OPENAI_BASE_URL`) | app token (`OPENAI_API_KEY`) |
| Anthropic | `http://localhost:7777/proxy/<pool>` (`ANTHROPIC_BASE_URL`) | app token |
| Gemini (google-genai) | `http_options={"base_url": "http://localhost:7777/proxy/gemini"}` | app token |
| ElevenLabs | `base_url="http://localhost:7777/proxy/<pool>"` | app token |
| Custom | `http://localhost:7777/proxy/<pool>/<path>` | `Authorization: Bearer agp_…` |

- The app token is accepted wherever SDKs put keys (`Authorization: Bearer`, `x-api-key`, `x-goog-api-key`, `xi-api-key`, `?key=`). An unknown token, or a pool the app may not use, never reaches the provider (401/403).
- All client credential headers, `?key=`, cookies and `X-Forwarded-*` are stripped; the pooled key is set where the provider expects it. `Set-Cookie` isn't passed back.
- Rotation matches the built-in tools: on 429/quota, an invalid key or a server error, the request is retried with the next key as long as nothing was sent to the client yet. When every key is resting the gateway answers `429` with `Retry-After`. Client errors (400…) are passed through unchanged.
- Responses, SSE included, are streamed. Request bodies are buffered (max 32 MB) so they can be retried.
- Paths can't contain `.`/`..` segments; the target is always the pool's base URL, which can only be `https` or `http://localhost` and is changed only in the panel.
- App tokens don't grant MCP or panel access, and agent tokens don't work on the proxy. Each request is logged as `app:<id>` with pool, method, path, status, the key's *name* and attempt count — never bodies, tokens or key values.

## Built-in Gemini server

`gemini` runs inside the gateway (`transport: builtin`) on the `gemini` key pool (vault secrets named `GEMINI_API_KEY` / `GEMINI_API_KEY_*`).

- `gemini.tts`: single voice (`text`, `voice`, `style`) or dialogue (`turns`, `speakers`). Long text is split and spread across keys in parallel and joined into one WAV file. Uses the Interactions API and falls back to `generateContent` for older models.
- `gemini.voices`, `gemini.models`, `gemini.pool_status`.
- Output files go to `-output-dir` (default `<data>/outputs`; isolated installs use the shared outputs directory above), from where agents copy them.
- Agents can disable the built-in server but not change or delete it.

## Security model

- **Network:** listens on localhost only. Requests whose `Host` isn't localhost are refused (DNS rebinding), and `/api` checks `Origin`.
- **Panel:** password sign-in (PBKDF2-SHA256, 600k iterations); `HttpOnly`, `SameSite=Strict` session cookie, 30 min idle / 12 h max; state-changing requests also need an `X-AGW` header (CSRF); failed attempts are rate-limited. Scripts may use `X-Admin-Token` (the token lives in the data directory).
- **Tokens:** agent and app tokens are stored as SHA-256 hashes.
- **Vault:** AES-256-GCM, with the secret name as additional data. The master key is in the service user's data directory (isolated) or the macOS Keychain (per-user). OAuth tokens are vault entries too (`oauth:<server>`).
- **Approvals:** any change an agent makes through `manage` that alters what a server runs or where it sends data (command, args, env, URL, headers, OAuth client) is inactive until you approve it in the panel, which shows a before/after diff and which secret goes to which domain. Rejecting restores the last approved config (or removes a never-approved server). Approving a URL change drops the stored OAuth session. Fixed-URL installs from the gateway templates or the Claude directory are approved automatically.
- **Tool pinning:** each upstream tool's name, description and schema are hashed. A new tool, or one whose description/schema changes later (e.g. a description that starts giving agents instructions), is hidden from `search_tools`, `describe_tools`, `overview`, direct mode and `call_tool` until you approve it; the agent gets an approval link instead. Rejecting adds it to `deny_tools`. Unknown tools are never forwarded blindly.
- **Agent limits:** an agent can create a secret but not overwrite one, can't use `${secret:…}` in parameters, can hide tools but not unhide them, can disable servers but not enable them, can't set a connection purpose, and templates it adds are flagged in the panel.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Configuration reference

```jsonc
{
  "id": "pg-prod", "name": "Prod DB", "description": "what agents see",
  "purpose": "Company production database (read-only)",  // panel only
  "transport": "stdio",                 // or "http"
  "command": "uvx", "args": ["postgres-mcp", "--access-mode=restricted"],
  "env": { "DATABASE_URI": "${secret:PG_PROD_DATABASE_URI}" },
  // http: "url", "headers": {"Authorization": "Bearer ${secret:X}"}, "auth": "auto|oauth|none"
  "allow_tools": [], "deny_tools": ["execute_*"],
  "enabled": true
}
```

`serve` flags (also as env vars): `-addr` (`TOOLGATE_ADDR`, default `127.0.0.1:7777`), `-data` (`TOOLGATE_DATA`, default `~/.toolgate`), `-key-store keychain|file` (`TOOLGATE_KEY_STORE`), `-output-dir` (`TOOLGATE_OUTPUT_DIR`), `-audit-retention-days`.

## Development

```bash
go vet ./... && go test -race ./...
source scripts/dev.sh; gwstart      # throwaway instance on :7790 with temp data; gwstop to stop
go run ./testdata/mockoauth         # fake OAuth server + MCP to test the login flow without a browser
```

CI runs the tests on Linux and macOS and does a real isolated install, upgrade and purge on both. See [CONTRIBUTING.md](CONTRIBUTING.md).

Dependencies: the official [`modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk) (MCP client/server, OAuth), `golang.org/x/oauth2` and `modernc.org/sqlite` (pure Go).

## License

[MIT](LICENSE)
