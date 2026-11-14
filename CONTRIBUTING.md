# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Build and test

```bash
go vet ./... && go test -race ./...
go build -o bin/toolgate .
```

A throwaway instance (port 7790, temporary data, never touches a real install):

```bash
source scripts/dev.sh
gwstart                      # builds and starts; prints the panel link
tc gemini.pool_status '{}'   # call a tool as the first-run agent
api GET /api/servers         # call the admin API
gwstop
```

The installer can be inspected without changing anything:
`go run . install --dry-run` (and `--user --dry-run`).

## Guidelines

- **Secrets never reach agents, logs or stdout.** No token, key or secret value
  in log lines, error messages, audit rows or test output.
- **Fail safe.** The vault must never replace a master key it can't read.
  Destructive steps (delete, reset, purge) run only after the previous step
  succeeded, in an explicit order.
- **Agents can't loosen restrictions.** A change through `manage` that alters
  what a server runs or where data goes goes through the approval flow
  (`approval.go`).
- Keep it a single static binary: pure-Go dependencies only (no cgo).
- UI text lives in `ui/index.html`; English is the source language and Turkish
  strings are in the `TR` table. Add both when you add UI text.
- Add tests next to the code (`*_test.go`); `go test` must pass without
  network access or real API keys.
