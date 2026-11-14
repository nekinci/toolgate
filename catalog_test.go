package main

import (
	"encoding/json"
	"testing"
)

func TestGithubAuthOptions(t *testing.T) {
	_, v, c := testEnv(t)
	gh := githubEntry()

	cfg, missing, err := c.Install(gh, "", "oauth", map[string]string{"client_id": "Iv1.abc", "client_secret": "shh"})
	if err != nil || len(missing) != 0 {
		t.Fatal(err, missing)
	}
	if cfg.Auth != "oauth" || cfg.OAuthClientID != "Iv1.abc" || cfg.OAuthClientSecretRef != "GITHUB_CLIENT_SECRET" || len(cfg.Headers) != 0 {
		t.Fatalf("oauth cfg = %+v", cfg)
	}
	if s, _ := v.Get("GITHUB_CLIENT_SECRET"); s != "shh" {
		t.Fatalf("client secret not stored: %q", s)
	}
	if len(cfg.OAuthScopes) == 0 {
		t.Fatal("scopes missing")
	}

	cfg2, missing, err := c.Install(gh, "github-pat", "pat", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Auth != "none" || cfg2.Headers["Authorization"] != "Bearer ${secret:GITHUB_PAT_TOKEN}" || len(missing) != 1 {
		t.Fatalf("pat cfg = %+v missing=%v", cfg2, missing)
	}
	if _, _, err := c.Install(gh, "x", "nope", nil); err == nil {
		t.Fatal("unknown auth option must fail")
	}
	if _, _, err := c.Install(gh, "github-3", "oauth", nil); err == nil {
		t.Fatal("missing client_id must fail")
	}
}

func TestClaudeDirectoryEntry(t *testing.T) {
	raw := `{"server":{"name":"com.amplitude/mcp","description":"long text","remotes":[{"type":"streamable-http","url":"{url}"}]},
	 "_meta":{"com.anthropic.api/mcp-registry":{"displayName":"Amplitude","oneLiner":"Product analytics","isAuthless":false,
	   "author":{"url":"https://amplitude.com/"},"toolNames":["a","b"],
	   "urlOptions":[{"url":"https://mcp.amplitude.com/mcp","label":"United States"},{"url":"https://mcp.eu.amplitude.com/mcp","label":"EU"}]}}}`
	var item struct {
		Server regServer                  `json:"server"`
		Meta   map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal([]byte(raw), &item); err != nil {
		t.Fatal(err)
	}
	e := registryToEntry("claude", item.Server, item.Meta)
	if e.Name != "Amplitude" || e.Description != "Product analytics" || e.Icon != "amplitude.com" || e.Template.ID != "amplitude" {
		t.Fatalf("entry = %+v", e)
	}
	if e.Template.URL != "{{url}}" || len(e.Params) != 1 || len(e.Params[0].Options) != 2 || e.Params[0].Default != "https://mcp.amplitude.com/mcp" {
		t.Fatalf("url param = %+v / %s", e.Params, e.Template.URL)
	}
	if e.Auth[0].Kind != "oauth" || e.Template.Auth != "oauth" {
		t.Fatalf("auth = %+v", e.Auth)
	}
	_, _, c := testEnv(t)
	cfg, _, err := c.Install(e, "", "", map[string]string{"url": "https://mcp.eu.amplitude.com/mcp"})
	if err != nil || cfg.URL != "https://mcp.eu.amplitude.com/mcp" {
		t.Fatalf("install: %v %+v", err, cfg)
	}
}

func TestInstalledDetectionByURL(t *testing.T) {
	e := &CatalogEntry{ID: "claude:x", Template: ServerConfig{Transport: "http", URL: "https://mcp.example.com/mcp"}}
	servers := []*ServerConfig{{ID: "mine", Transport: "http", URL: "https://mcp.example.com/mcp/"}, {ID: "other", URL: "https://b"}}
	if got := installedFor(e, servers); len(got) != 1 || got[0] != "mine" {
		t.Fatalf("installed = %v", got)
	}
}
