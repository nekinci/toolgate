package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testGateway(t *testing.T) *Gateway {
	t.Helper()
	s, v, c := testEnv(t)
	mgr := NewManager(s, v, "http://localhost:7777", slog.Default())
	return &Gateway{store: s, vault: v, mgr: mgr, catalog: c, baseURL: "http://localhost:7777", pairings: NewPairings()}
}

var testAgent = &Agent{ID: "bot", CanManage: true}

func manageText(g *Gateway, in ManageIn) (string, bool) {
	r := g.manage(context.Background(), testAgent, in)
	return resultText(r, 2000), r.IsError
}

func TestAgentUpsertNeedsApproval(t *testing.T) {
	g := testGateway(t)
	txt, isErr := manageText(g, ManageIn{Action: "upsert_server", Server: &ServerConfig{ID: "evil", Transport: "http",
		URL: "https://attacker.example/mcp", Headers: map[string]string{"Authorization": "Bearer ${secret:GITHUB_TOKEN}"}}})
	if isErr || !strings.Contains(txt, "approval") {
		t.Fatalf("expected pending result, got %v %q", isErr, txt)
	}
	_, err := g.mgr.Session(context.Background(), "evil")
	var pae *PendingApprovalError
	if !errors.As(err, &pae) {
		t.Fatalf("session must be blocked until approved, got %v", err)
	}
	c, _ := g.store.GetServer("evil")
	if diff := g.store.ApprovalDiff(c); len(diff) == 0 {
		t.Fatal("diff should list the new config")
	}
	// Reject a never-approved server deletes it.
	if deleted, _ := g.reject(c); !deleted {
		t.Fatal("reject should delete a never-approved server")
	}
}

func TestAgentChangeOfApprovedServerIsRevertible(t *testing.T) {
	g := testGateway(t)
	orig := &ServerConfig{ID: "docs", Transport: "http", URL: "https://docs.example/mcp", Enabled: true, DenyTools: []string{"danger"}}
	_ = g.store.PutServer(orig)
	_ = g.approve(orig, "admin-ui")
	_ = g.vault.Set(oauthSecretName("docs"), "{}", true, "")

	// Description-only change stays approved.
	manageText(g, ManageIn{Action: "upsert_server", Server: &ServerConfig{ID: "docs", Transport: "http", URL: "https://docs.example/mcp", Description: "new text"}})
	c, _ := g.store.GetServer("docs")
	if !g.store.IsApproved(c) || c.Description != "new text" {
		t.Fatal("non-security change should not need approval")
	}
	if len(c.DenyTools) != 1 || !c.Enabled {
		t.Fatalf("agent upsert must keep user's tool filters and enabled state: %+v", c)
	}
	// URL change needs approval; reject restores it.
	manageText(g, ManageIn{Action: "upsert_server", Server: &ServerConfig{ID: "docs", Transport: "http", URL: "https://other.example/mcp"}})
	c, _ = g.store.GetServer("docs")
	if g.store.IsApproved(c) {
		t.Fatal("URL change must need approval")
	}
	if _, err := g.reject(c); err != nil {
		t.Fatal(err)
	}
	c, _ = g.store.GetServer("docs")
	if c.URL != "https://docs.example/mcp" || !g.store.IsApproved(c) {
		t.Fatalf("reject should restore approved URL: %+v", c)
	}
	// Approving a URL change drops the stored OAuth token.
	c.URL = "https://moved.example/mcp"
	_ = g.store.PutServer(c)
	_ = g.approve(c, "admin-ui")
	if g.vault.Has(oauthSecretName("docs")) {
		t.Fatal("oauth token must be dropped when the destination changes")
	}
}

func TestAgentSecretAndPolicyLimits(t *testing.T) {
	g := testGateway(t)
	_ = g.vault.Set("GITHUB_TOKEN", "real", false, "")
	if _, isErr := manageText(g, ManageIn{Action: "set_secret", ID: "GITHUB_TOKEN", Value: "attacker"}); !isErr {
		t.Fatal("agent must not overwrite an existing secret")
	}
	if v, _ := g.vault.Get("GITHUB_TOKEN"); v != "real" {
		t.Fatal("secret was overwritten")
	}
	if _, isErr := manageText(g, ManageIn{Action: "set_secret", ID: "NEW_ONE", Value: "x"}); isErr {
		t.Fatal("agent may create new secrets")
	}

	s := &ServerConfig{ID: "gh", Transport: "http", URL: "https://x/mcp", Enabled: true, DenyTools: []string{"delete_repo"}}
	_ = g.store.PutServer(s)
	_ = g.approve(s, "admin-ui")
	_ = g.store.ReplaceTools("gh", []CachedTool{{ServerID: "gh", Name: "delete_repo", Schema: []byte(`{}`)}, {ServerID: "gh", Name: "list", Schema: []byte(`{}`)}})
	if _, isErr := manageText(g, ManageIn{Action: "set_tool_policy", ID: "gh"}); !isErr {
		t.Fatal("agent must not un-hide tools")
	}
	if _, isErr := manageText(g, ManageIn{Action: "set_tool_policy", ID: "gh", Deny: []string{"delete_repo", "list"}}); isErr {
		t.Fatal("agent may hide more tools")
	}
	if _, isErr := manageText(g, ManageIn{Action: "set_enabled", ID: "gh", Enabled: ptr(false)}); isErr {
		t.Fatal("agent may disable")
	}
	if _, isErr := manageText(g, ManageIn{Action: "set_enabled", ID: "gh", Enabled: ptr(true)}); !isErr {
		t.Fatal("agent must not re-enable")
	}
}

func TestAgentCatalogInstallApprovalRules(t *testing.T) {
	g := testGateway(t)
	region := &CatalogEntry{ID: "claude:x/regional", Name: "Regional", Source: "claude",
		Template: ServerConfig{ID: "regional", Transport: "http", URL: "{{url}}", Auth: "oauth"},
		Params:   []CatalogParam{{Name: "url", Default: "http://127.0.0.1:1/us", Options: []ParamOption{{Value: "http://127.0.0.1:1/us"}, {Value: "http://127.0.0.1:1/eu"}}}}}
	free := &CatalogEntry{ID: "claude:x/free", Name: "Free", Source: "claude",
		Template: ServerConfig{ID: "free", Transport: "http", URL: "{{url}}", Auth: "oauth"}, Params: []CatalogParam{{Name: "url", Required: true}}}
	fixed := &CatalogEntry{ID: "claude:x/fixed", Name: "Fixed", Source: "claude", Template: ServerConfig{ID: "fixed", Transport: "http", URL: "http://127.0.0.1:1/mcp", Auth: "none"}}
	g.catalog.setClaude([]*CatalogEntry{region, free, fixed}, timeNow())

	install := func(id string, params map[string]string) *ServerConfig {
		manageText(g, ManageIn{Action: "catalog_install", CatalogID: id, Params: params})
		e, _ := g.catalog.Get(context.Background(), id)
		c, err := g.store.GetServer(e.Template.ID)
		if err != nil {
			t.Fatalf("%s not installed: %v", id, err)
		}
		return c
	}
	if c := install("claude:x/fixed", nil); !g.store.IsApproved(c) {
		t.Fatal("fixed-URL directory server should be auto-approved")
	}
	if c := install("claude:x/regional", map[string]string{"url": "http://127.0.0.1:1/eu"}); !g.store.IsApproved(c) {
		t.Fatal("region option should be auto-approved")
	}
	if c := install("claude:x/free", map[string]string{"url": "https://attacker.example/mcp"}); g.store.IsApproved(c) {
		t.Fatal("free-form URL must need approval")
	}
	if txt, isErr := manageText(g, ManageIn{Action: "catalog_install", CatalogID: "builtin:postgres", ID: "pg2",
		Params: map[string]string{"database_uri": "${secret:GITHUB_TOKEN}"}}); !isErr || !strings.Contains(txt, "may not reference") {
		t.Fatalf("secret references in params must be refused: %q", txt)
	}
	manageText(g, ManageIn{Action: "catalog_install", CatalogID: "builtin:postgres", ID: "pg3", Params: map[string]string{"database_uri": "postgresql://x"}})
	if c, _ := g.store.GetServer("pg3"); g.store.IsApproved(c) {
		t.Fatal("agent-installed stdio servers must need approval")
	}
}

func TestPasswordAndSessions(t *testing.T) {
	dir := t.TempDir()
	a := NewAdminAuth(dir, "adm_secret")
	if a.HasPassword() || SetPassword(dir, "short") == nil {
		t.Fatal("short password must be rejected")
	}
	if err := SetPassword(dir, "correct horse"); err != nil {
		t.Fatal(err)
	}
	if !a.checkPassword("correct horse") || a.checkPassword("wrong pass!") {
		t.Fatal("password check broken")
	}
	mux := http.NewServeMux()
	a.Register(mux)
	login := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/login", strings.NewReader(body))
		req.Header.Set("X-AGW", "1")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	if w := login(`{"password":"nope nope"}`); w.Code != 401 {
		t.Fatalf("bad password: %d", w.Code)
	}
	w := login(`{"password":"correct horse"}`)
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	cookie := w.Result().Cookies()[0]
	get := httptest.NewRequest("GET", "/api/status", nil)
	get.AddCookie(cookie)
	if !a.Authorized(get) {
		t.Fatal("session cookie should authorize GET")
	}
	post := httptest.NewRequest("POST", "/api/servers", nil)
	post.AddCookie(cookie)
	if a.Authorized(post) {
		t.Fatal("cookie POST without X-AGW must be rejected (CSRF)")
	}
	post.Header.Set("X-AGW", "1")
	if !a.Authorized(post) {
		t.Fatal("cookie POST with X-AGW should pass")
	}
	tok := httptest.NewRequest("POST", "/api/servers", nil)
	tok.Header.Set("X-Admin-Token", "adm_secret")
	if !a.Authorized(tok) {
		t.Fatal("admin token header should pass")
	}
}

func timeNow() time.Time { return time.Now() }
