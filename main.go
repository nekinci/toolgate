package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const version = "0.1.0"

//go:embed ui
var uiFS embed.FS

func main() {
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		cmd, args := os.Args[1], os.Args[2:]
		switch cmd {
		case "serve":
			serve(args)
		case "agent":
			agentCmd(args)
		case "admin-url":
			adminURL(args)
		case "set-password":
			setPasswordCmd(args)
		case "migrate-export":
			migrateExport(args)
		case "install":
			installCmd(args)
		case "uninstall":
			uninstallCmd(args)
		case "status":
			statusCmd(args)
		case "help":
			fmt.Print(usage)
		case "version":
			fmt.Println("toolgate", version)
		default:
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		return
	}
	serve(os.Args[1:])
}

const usage = `usage: toolgate <command> [flags]

  serve            run the gateway in the foreground (default command)
  install          set it up as a background service
                     sudo toolgate install   isolated: own system user, data unreadable by agents
                     toolgate install --user  runs as you, no root needed
  uninstall        remove the service (--purge also deletes data)
  status           show the install and whether the gateway answers
  admin-url        print a sign-in link for the panel (user installs)
  set-password     set the panel password (first line of stdin)
  agent create ID  create an agent and print its token [--manage] [--allow ...] [--deny ...]
  migrate-export   copy the database and master key to -out DIR for another install
  version          print the version

Run "toolgate <command> -h" for the flags of a command.
`

type common struct {
	dataDir string
	addr    string
	keyMode string
}

func parseCommon(fsName string, args []string) (*common, *flag.FlagSet) {
	home, _ := os.UserHomeDir()
	c := &common{}
	f := flag.NewFlagSet(fsName, flag.ExitOnError)
	f.StringVar(&c.dataDir, "data", envOr("TOOLGATE_DATA", defaultDataDir(home)), "data directory")
	f.StringVar(&c.addr, "addr", envOr("TOOLGATE_ADDR", "127.0.0.1:7777"), "listen address (keep it on localhost)")
	f.StringVar(&c.keyMode, "key-store", envOr("TOOLGATE_KEY_STORE", ""), "master key store: keychain or file")
	return c, f
}

// envOr reads TOOLGATE_* settings; the AGW_* names from before the rename
// still work.
func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	if old, ok := strings.CutPrefix(k, "TOOLGATE_"); ok {
		if v := os.Getenv("AGW_" + old); v != "" {
			return v
		}
	}
	return def
}

// defaultDataDir is ~/.toolgate, or ~/.agent-gateway when only that (from
// before the rename) exists.
func defaultDataDir(home string) string {
	cur := filepath.Join(home, ".toolgate")
	if old := filepath.Join(home, ".agent-gateway"); !fileExists(cur) && fileExists(old) {
		return old
	}
	return cur
}

func (c *common) baseURL() string {
	_, port, _ := net.SplitHostPort(c.addr)
	return "http://localhost:" + port
}

func openAll(c *common) (*Store, *Vault) {
	if err := os.MkdirAll(c.dataDir, 0o700); err != nil {
		fatal(err)
	}
	store, err := OpenStore(filepath.Join(c.dataDir, "gateway.db"))
	if err != nil {
		fatal(err)
	}
	vault, err := NewVault(store, c.dataDir, c.keyMode)
	if err != nil {
		fatal(err)
	}
	return store, vault
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func loadAdminToken(dataDir string) string {
	p := filepath.Join(dataDir, "admin.token")
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) > 10 {
		return strings.TrimSpace(string(b))
	}
	t := newToken("adm_")
	if err := os.WriteFile(p, []byte(t), 0o600); err != nil {
		fatal(err)
	}
	return t
}

func adminURL(args []string) {
	c, f := parseCommon("admin-url", args)
	_ = f.Parse(args)
	fmt.Printf("%s/ui/#token=%s\n", c.baseURL(), loadAdminToken(c.dataDir))
}

func agentCmd(args []string) {
	if len(args) < 2 || args[0] != "create" {
		fmt.Fprintln(os.Stderr, "usage: toolgate agent create <id> [--manage] [--allow 'github.*,postgres-*.query'] [--deny '...']")
		os.Exit(2)
	}
	id := args[1]
	c, f := parseCommon("agent", args[2:])
	manage := f.Bool("manage", false, "allow this agent to configure the gateway")
	allow := f.String("allow", "", "comma separated allow globs on server.tool")
	deny := f.String("deny", "", "comma separated deny globs on server.tool")
	_ = f.Parse(args[2:])
	store, _ := openAll(c)
	if !idRe.MatchString(id) {
		fatal(errors.New("invalid agent id"))
	}
	a := &Agent{ID: id, Name: id, CanManage: *manage, Allow: splitList(*allow), Deny: splitList(*deny), CreatedAt: now()}
	if old, err := store.GetAgent(id); err == nil {
		a.CreatedAt = old.CreatedAt
	}
	tok := newToken("agw_")
	if err := store.PutAgent(a, hashToken(tok)); err != nil {
		fatal(err)
	}
	fmt.Println(tok)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func serve(args []string) {
	c, f := parseCommon("serve", args)
	outFlag := f.String("output-dir", envOr("TOOLGATE_OUTPUT_DIR", ""), "where built-in tools (TTS, images) write files; default <data>/outputs")
	retention := f.Int("audit-retention-days", 0, "delete audit rows older than this many days (overrides the panel setting; default 90)")
	_ = f.Parse(args)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	store, vault := openAll(c)
	adminTok := loadAdminToken(c.dataDir)
	store.MigrateApprovals()
	store.MigrateToolPins()
	if *retention > 0 {
		store.auditRetentionFlag = min(*retention, maxAuditRetentionDays)
	}

	// First run: create a managing agent for Claude Code.
	if agents, _ := store.ListAgents(); len(agents) == 0 {
		tok := newToken("agw_")
		a := &Agent{ID: "claude-code", Name: "Claude Code", CanManage: true, CreatedAt: now()}
		if err := store.PutAgent(a, hashToken(tok)); err != nil {
			fatal(err)
		}
		p := filepath.Join(c.dataDir, "first-run.txt")
		msg := fmt.Sprintf("Agent 'claude-code' token: %s\n\nRegister with Claude Code (all projects):\n  claude mcp add --scope user --transport http gateway %s/mcp --header \"Authorization: Bearer %s\"\n", tok, c.baseURL(), tok)
		_ = os.WriteFile(p, []byte(msg), 0o600)
		// Never print the token itself: stderr usually ends up in a log file.
		fmt.Fprintf(os.Stderr, "first run: agent 'claude-code' created; token and registration command are in %s\n", p)
	}

	mgr := NewManager(store, vault, c.baseURL(), log)
	cat := NewCatalog(store, vault, c.dataDir, c.baseURL(), log)
	g := &Gateway{store: store, vault: vault, mgr: mgr, catalog: cat, baseURL: c.baseURL(), pairings: NewPairings()}
	outDir := *outFlag
	if outDir == "" {
		outDir = filepath.Join(c.dataDir, "outputs")
	}
	g.pools = NewPools(store, vault)
	g.gemini = &Gemini{pool: g.pools.Get("gemini"), OutDir: outDir, link: func(n string) string { return g.secretLink(n, "Gemini API key") }}
	mgr.Builtins = map[string]func() *mcp.Server{"gemini": g.gemini.Server}
	ensureBuiltins(g)
	authn := NewAdminAuth(c.dataDir, adminTok)
	admin := &Admin{g: g, authn: authn}

	mux := http.NewServeMux()
	type agentKey struct{}
	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		a, _ := r.Context().Value(agentKey{}).(*Agent)
		if a == nil {
			return nil
		}
		return g.ServerFor(a, r.URL.Query().Get("tools"))
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, Logger: log})

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" {
			tok = r.Header.Get("X-Gateway-Token")
		}
		a, err := store.AgentByTokenHash(hashToken(tok))
		if tok == "" || err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid or missing gateway token (Authorization: Bearer agw_...)"}`)
			return
		}
		if tokenExpired(a.ExpiresAt) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			msg, _ := json.Marshal(fmt.Sprintf("gateway token for agent %q expired on %s; ask the user for a new pairing code or token in the gateway panel (Agents)", a.ID, a.ExpiresAt))
			fmt.Fprintf(w, `{"error":%s}`, msg)
			return
		}
		if a.LastSeen == "" || time.Since(parseTime(a.LastSeen)) > time.Minute {
			a.LastSeen = now()
			_ = store.PutAgent(a, "")
		}
		mcpHandler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), agentKey{}, a)))
	})
	mux.HandleFunc("GET /oauth/callback", mgr.HandleCallback)
	mux.HandleFunc("/proxy/{pool}/{rest...}", g.handleProxy)
	mux.HandleFunc("POST /pair", g.handlePair)
	authn.Register(mux)
	admin.Register(mux)
	sub, _ := fs.Sub(uiFS, "ui")
	mux.Handle("GET /ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("GET /ui/icon/{host}", iconHandler(cat))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ui/", http.StatusFound) })
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })

	srv := &http.Server{Addr: c.addr, Handler: hostGuard(c.addr, mux), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go mgr.ReapIdle(ctx)
	go store.RunAuditRetention(ctx, log)
	go cat.Run(ctx)
	mgr.Warmup()

	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("toolgate listening", "addr", c.addr, "ui", c.baseURL()+"/ui/ (run `toolgate admin-url` for the login link)", "vault", vault.KeySource)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(err)
	}
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// hostGuard rejects requests whose Host isn't localhost (DNS rebinding
// protection) and cross-site browser requests to the API.
func hostGuard(addr string, next http.Handler) http.Handler {
	_, port, _ := net.SplitHostPort(addr)
	allowed := map[string]bool{"localhost:" + port: true, "127.0.0.1:" + port: true, "[::1]:" + port: true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed[r.Host] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && strings.HasPrefix(r.URL.Path, "/api/") {
			if !allowed[strings.TrimPrefix(strings.TrimPrefix(o, "http://"), "https://")] {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
