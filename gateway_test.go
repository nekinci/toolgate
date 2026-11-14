package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func testEnv(t *testing.T) (*Store, *Vault, *Catalog) {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVault(s, dir, "file")
	if err != nil {
		t.Fatal(err)
	}
	return s, v, NewCatalog(s, v, dir, "http://localhost:7777", nil)
}

func TestPolicy(t *testing.T) {
	srv := &ServerConfig{ID: "pg-prod", Enabled: true, DenyTools: []string{"drop_*"}}
	ro := &Agent{ID: "ro", Allow: []string{"pg-*.query", "github.*"}, Deny: []string{"github.delete_*"}}
	cases := []struct {
		agent *Agent
		tool  string
		want  bool
	}{
		{nil, "query", true},
		{nil, "drop_table", false},
		{ro, "query", true},
		{ro, "execute", false},
		{ro, "drop_table", false},
	}
	for _, c := range cases {
		if got := Decide(c.agent, srv, c.tool).Allowed; got != c.want {
			t.Errorf("Decide(%v, %s) = %v, want %v", c.agent, c.tool, got, c.want)
		}
	}
	gh := &ServerConfig{ID: "github", Enabled: true}
	if Decide(ro, gh, "delete_repo").Allowed {
		t.Error("deny must win over allow")
	}
	if !Decide(ro, gh, "create_issue").Allowed {
		t.Error("github.* should allow create_issue")
	}
	if ServerVisible(ro, &ServerConfig{ID: "slack", Enabled: true}) {
		t.Error("slack should be invisible to ro")
	}
	if (&ServerConfig{ID: "x", Enabled: false}).Enabled || Decide(nil, &ServerConfig{ID: "x"}, "a").Allowed {
		t.Error("disabled server must deny")
	}
}

func TestVaultRoundTripAndResolve(t *testing.T) {
	_, v, _ := testEnv(t)
	if err := v.Set("API_KEY", "s3cr3t", false, "n"); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get("API_KEY")
	if err != nil || got != "s3cr3t" {
		t.Fatalf("get = %q, %v", got, err)
	}
	missing := map[string]bool{}
	if r := v.Resolve("Bearer ${secret:API_KEY} ${secret:NOPE}", missing); r != "Bearer s3cr3t " || !missing["NOPE"] {
		t.Fatalf("resolve = %q missing=%v", r, missing)
	}
	var ct []byte
	_ = v.store.db.QueryRow(`SELECT ct FROM secrets WHERE name='API_KEY'`).Scan(&ct)
	if strings.Contains(string(ct), "s3cr3t") {
		t.Fatal("secret stored in plaintext")
	}
	if err := v.Set("bad name", "x", false, ""); err == nil {
		t.Fatal("expected invalid name error")
	}
}

func TestCatalogInstallMultipleInstances(t *testing.T) {
	s, v, c := testEnv(t)
	var pg *CatalogEntry
	for _, e := range builtinCatalog() {
		if e.ID == "builtin:postgres" {
			pg = e
		}
	}
	cfg, missing, err := c.Install(pg, "pg-prod", "", map[string]string{"database_uri": "postgresql://u:p@h/db"})
	if err != nil || len(missing) != 0 {
		t.Fatalf("install: %v missing=%v", err, missing)
	}
	if cfg.Env["DATABASE_URI"] != "${secret:PG_PROD_DATABASE_URI}" {
		t.Fatalf("env = %v", cfg.Env)
	}
	if cfg.Args[1] != "--access-mode=restricted" {
		t.Fatalf("default param not applied: %v", cfg.Args)
	}
	if got, _ := v.Get("PG_PROD_DATABASE_URI"); got != "postgresql://u:p@h/db" {
		t.Fatalf("secret not stored: %q", got)
	}
	cfg2, missing2, err := c.Install(pg, "pg-staging", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing2) != 1 || missing2[0] != "PG_STAGING_DATABASE_URI" {
		t.Fatalf("missing2 = %v", missing2)
	}
	if _, _, err := c.Install(pg, "pg-prod", "", nil); err == nil {
		t.Fatal("duplicate id must fail")
	}
	servers, _ := s.ListServers()
	if len(servers) != 2 || cfg2.ID != "pg-staging" {
		t.Fatalf("servers = %d", len(servers))
	}
}

func TestGithubOptionalHeaderDropped(t *testing.T) {
	_, _, c := testEnv(t)
	e := &CatalogEntry{ID: "user:x", Name: "X", Template: ServerConfig{ID: "x", Transport: "http", URL: "https://x/mcp",
		Headers: map[string]string{"Authorization": "Bearer {{token}}"}}, Params: []CatalogParam{{Name: "token", Secret: true}}}
	cfg, missing, err := c.Install(e, "", "", nil)
	if err != nil || len(missing) != 0 {
		t.Fatal(err, missing)
	}
	if _, ok := cfg.Headers["Authorization"]; ok {
		t.Fatalf("empty optional bearer header should be dropped: %v", cfg.Headers)
	}
}

func TestRegistryToEntry(t *testing.T) {
	raw := `{"name":"io.github.acme/weather-mcp","description":"Weather","version":"1.2.0",
	 "packages":[{"registryType":"npm","identifier":"@acme/weather-mcp","version":"1.2.0","transport":{"type":"stdio"},
	   "environmentVariables":[{"name":"WEATHER_API_KEY","isSecret":true,"isRequired":true,"description":"key"}]}]}`
	var s regServer
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatal(err)
	}
	e := registryToEntry("registry", s, nil)
	if e == nil || e.Template.Command != "npx" || e.Template.Args[1] != "@acme/weather-mcp@1.2.0" {
		t.Fatalf("entry = %+v", e)
	}
	if e.Template.ID != "weather-mcp" || e.Template.Env["WEATHER_API_KEY"] != "{{weather_api_key}}" || !e.Params[0].Secret {
		t.Fatalf("template = %+v params=%+v", e.Template, e.Params)
	}
	remote := `{"name":"com.notion/mcp","remotes":[{"type":"streamable-http","url":"https://mcp.notion.com/mcp"}]}`
	_ = json.Unmarshal([]byte(remote), &s)
	s.Packages = nil
	e = registryToEntry("claude", s, nil)
	if e.Template.ID != "notion" || e.Template.Transport != "http" {
		t.Fatalf("remote entry = %+v", e.Template)
	}
}

func TestSearchRanking(t *testing.T) {
	s, v, c := testEnv(t)
	g := &Gateway{store: s, vault: v, catalog: c, mgr: NewManager(s, v, "http://localhost:1", nil)}
	_ = s.PutServer(&ServerConfig{ID: "gh", Transport: "http", URL: "https://x", Enabled: true})
	_ = s.ReplaceTools("gh", []CachedTool{
		{ServerID: "gh", Name: "create_issue", Description: "Create a new issue", Schema: json.RawMessage(`{}`)},
		{ServerID: "gh", Name: "list_commits", Description: "List commits of a branch", Schema: json.RawMessage(`{}`)},
	})
	s.AfterIndex("gh", false, 2)
	hits := g.search(nil, SearchIn{Query: "issue create"})
	if len(hits) == 0 || hits[0].Tool != "gh.create_issue" {
		t.Fatalf("hits = %+v", hits)
	}
	if hits := g.search(&Agent{ID: "a", Deny: []string{"gh.create_*"}}, SearchIn{Query: "issue"}); len(hits) != 0 {
		t.Fatalf("denied tool leaked into search: %+v", hits)
	}
}
