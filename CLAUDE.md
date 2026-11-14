# Toolgate

Local MCP gateway in Go (`localhost:7777`). Agents only know this address; the gateway brokers N upstream MCP servers, the vault, the catalog, OAuth flows, approvals and the audit log. Details in [README.md](README.md). Machine-specific notes, if any, are in `CLAUDE.local.md` (not committed).

## Build and test

- `go vet . && go test -count=1 . && go build -o bin/toolgate .`
- Throwaway server (port 7790, temp data): `source scripts/dev.sh; gwstart`, then `tc gemini.pool_status '{}'` or `api GET /api/servers`; `gwstop` to stop.
- UI screenshots: headless Chrome on `http://localhost:7790/ui/#token=<admin token>&go=vault` (`go=` picks the page, `lang=en|tr` the language).
- Installer: `go run . install --dry-run` prints the plan without changing anything (`install.go`; macOS launchd and Linux systemd, isolated or `--user`).

## Rules

- Agents must never see secret values. Never ask the user to paste a secret into the chat; values are entered only in the panel. Don't log or print tokens.
- The vault must **never** silently create a new master key in place of one it can't read. Key loading stays fail-safe; that's what the `vault_check` meta row is for.
- Destructive steps (delete, reset, purge) only after the previous step succeeded, in an explicit order. Data was lost once during a migration because of this.
- Security-relevant changes an agent makes (command, URL, headers, OAuth client) wait for user approval (`approval.go`). Agents can't loosen restrictions.
- UI text: English source strings, Turkish in the `TR` table in `ui/index.html`. Add both.
- Pure-Go dependencies only (no cgo); keep it a single binary.

## Key pools and Gemini

- Vault secrets named `<PREFIX>` / `<PREFIX>_*` form a key pool. A rate-limited key rests per scope (model); an invalid key is disabled. `keypool.go` (pool, rotation) and `keypool_providers.go` (Gemini/OpenAI/Anthropic/ElevenLabs/custom adapters, `Pools` registry). The Gemini pool's id is `gemini` and its prefix `GEMINI_API_KEY` is fixed; its counters stay in the legacy `gemini_usage`/`gemini_invalid` meta keys.
- `gemini.tts` (`geminitts.go`): Interactions API, falls back to `generateContent` for older models. Long text is split evenly and spread over keys in parallel; output is WAV.
- `/proxy/<pool>/...` (`proxy.go`, `proxyapps.go`): for the user's own programs; one `agp_` token per app, keys stay in the gateway, same rotation as the pool. App tokens are managed only in the panel.
