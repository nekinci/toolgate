package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// CatalogParam is a value the user supplies when installing a template.
type CatalogParam struct {
	Name        string        `json:"name"`
	Label       string        `json:"label,omitempty"`
	Description string        `json:"description,omitempty"`
	Secret      bool          `json:"secret,omitempty"`
	Required    bool          `json:"required,omitempty"`
	Default     string        `json:"default,omitempty"`
	HelpURL     string        `json:"help_url,omitempty"`
	Options     []ParamOption `json:"options,omitempty"`
}

type ParamOption struct {
	Value       string `json:"value"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

// AuthOption is one way of authenticating to a catalog entry.
// Kind: oauth (automatic sign-in), oauth_app (sign-in after registering an
// OAuth app once), token (API key / PAT), credentials (connection info), none,
// auto (unknown; gateway tries OAuth if the server asks for it).
type AuthOption struct {
	ID          string         `json:"id"`
	Label       string         `json:"label"`
	Kind        string         `json:"kind"`
	Description string         `json:"description,omitempty"`
	SetupURL    string         `json:"setup_url,omitempty"` // may contain {{base_url}}
	SetupLabel  string         `json:"setup_label,omitempty"`
	SetupSteps  []string       `json:"setup_steps,omitempty"` // may contain {{base_url}}
	Template    *ServerConfig  `json:"template,omitempty"`    // fields overriding the entry template
	Params      []CatalogParam `json:"params,omitempty"`
}

// CatalogEntry is an installable server template. Template strings may use
// {{param}} placeholders; secret params become ${secret:NAME} references.
type CatalogEntry struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Long        string         `json:"long,omitempty"`
	Source      string         `json:"source"` // builtin | user | claude | registry
	Homepage    string         `json:"homepage,omitempty"`
	Icon        string         `json:"icon,omitempty"` // domain used for the favicon
	Template    ServerConfig   `json:"template"`
	Params      []CatalogParam `json:"params,omitempty"`
	Auth        []AuthOption   `json:"auth,omitempty"`
	Tools       []string       `json:"tools,omitempty"`
	Requires    []string       `json:"requires,omitempty"` // commands needed on PATH
	Featured    bool           `json:"featured,omitempty"`
	AddedBy     string         `json:"added_by,omitempty"` // agent id when an agent added a user template
	Order       int            `json:"-"`

	// Filled per response.
	Installed []string `json:"installed,omitempty"`
	Missing   []string `json:"missing_commands,omitempty"`
}

func (e *CatalogEntry) authOptions() []AuthOption {
	if len(e.Auth) > 0 {
		return e.Auth
	}
	kind := "none"
	for _, p := range e.Params {
		if p.Secret {
			kind = "token"
		}
	}
	if e.Template.Transport == "http" && kind == "none" && e.Template.Auth != "none" {
		kind = "auto"
	}
	if e.Template.Auth == "oauth" {
		kind = "oauth"
	}
	return []AuthOption{{ID: "default", Label: authLabel(kind), Kind: kind}}
}

func authLabel(kind string) string {
	return map[string]string{"oauth": "Sign in with account (OAuth)", "oauth_app": "Sign in with account (OAuth app)", "token": "API key / token",
		"credentials": "Connection details", "none": "No sign-in needed", "auto": "Sign in with account if needed"}[kind]
}

type Catalog struct {
	store   *Store
	vault   *Vault
	http    *http.Client
	dataDir string
	baseURL string
	log     *slog.Logger

	mu        sync.RWMutex
	claude    []*CatalogEntry
	claudeAt  time.Time
	remote    map[string]*CatalogEntry // registry entries seen in searches
	iconHosts map[string]bool
}

func NewCatalog(store *Store, vault *Vault, dataDir, baseURL string, log *slog.Logger) *Catalog {
	if log == nil {
		log = slog.Default()
	}
	c := &Catalog{store: store, vault: vault, http: &http.Client{Timeout: 20 * time.Second}, dataDir: dataDir, baseURL: baseURL,
		log: log, remote: map[string]*CatalogEntry{}, iconHosts: map[string]bool{}}
	for _, e := range builtinCatalog() {
		c.iconHosts[e.Icon] = true
	}
	return c
}

func githubEntry() *CatalogEntry {
	scopes := []string{"repo", "read:org", "read:user", "user:email", "gist", "notifications", "read:project"}
	return &CatalogEntry{ID: "builtin:github", Name: "GitHub", Source: "builtin", Featured: true, Icon: "github.com",
		Homepage:    "https://github.com/github/github-mcp-server",
		Description: "Repos, issues, pull requests, Actions and code search (GitHub's official MCP server).",
		Template:    ServerConfig{ID: "github", Transport: "http", URL: "https://api.githubcopilot.com/mcp/"},
		Auth: []AuthOption{
			{ID: "oauth", Label: "Sign in with GitHub (OAuth)", Kind: "oauth_app",
				Description: "GitHub does not support automatic client registration. Create your own OAuth app once; after that, signing in is a single click in the browser.",
				SetupLabel:  "Create app on GitHub",
				SetupURL:    "https://github.com/settings/applications/new?oauth_application[name]=Toolgate&oauth_application[url]={{base_url}}&oauth_application[callback_url]={{base_url}}/oauth/callback",
				SetupSteps: []string{
					"Open GitHub's new OAuth App page with the \"Create app on GitHub\" button below.",
					"Application name: Toolgate · Homepage URL: {{base_url}} · Authorization callback URL: {{base_url}}/oauth/callback",
					"Click \"Register application\", then create a secret with \"Generate a new client secret\".",
					"Paste the Client ID and Client secret below; clicking \"Add and connect\" opens the GitHub sign-in screen.",
				},
				Template: &ServerConfig{Auth: "oauth", OAuthClientID: "{{client_id}}", OAuthClientSecretRef: "{{client_secret}}", OAuthScopes: scopes},
				Params: []CatalogParam{{Name: "client_id", Label: "Client ID", Required: true},
					{Name: "client_secret", Label: "Client secret", Secret: true, Required: true}}},
			{ID: "pat", Label: "Personal access token (PAT)", Kind: "token",
				Description: "Quickest: create a token with the required scopes preselected and paste it.",
				SetupURL:    "https://github.com/settings/tokens/new?scopes=repo,read:org,read:user,user:email,gist,notifications,read:project&description=Toolgate",
				Template:    &ServerConfig{Auth: "none", Headers: map[string]string{"Authorization": "Bearer {{token}}"}},
				Params:      []CatalogParam{{Name: "token", Label: "Token", Secret: true, Required: true, Description: "ghp_… or github_pat_…"}}},
		}}
}

// googleOAuthSteps are the one-time Google Cloud steps for Google's hosted
// MCP servers, which don't support automatic client registration.
func googleOAuthSteps(apiName, apiID string, scopes []string) []string {
	return []string{
		"In Google Cloud Console, pick a project or create a new one.",
		fmt.Sprintf("Under APIs & Services > Library, enable %s (%s).", apiName, apiID),
		"Google Auth Platform > Audience: user type \"External\", status \"Testing\"; add your own Google account under Test users.",
		"Data Access: add these scopes: " + strings.Join(scopes, ", "),
		"Clients > Create client: type \"Web application\", set the Authorized redirect URI to {{base_url}}/oauth/callback and tick \"Use this client for an AI-powered agent\".",
		"Paste the resulting Client ID and Client secret below; clicking \"Add and connect\" opens the Google sign-in screen.",
	}
}

func gmailEntry() *CatalogEntry {
	scopes := []string{"https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/gmail.compose", "https://www.googleapis.com/auth/gmail.labels"}
	short := []string{"gmail.modify", "gmail.compose", "gmail.labels"}
	return &CatalogEntry{ID: "builtin:gmail", Name: "Gmail", Source: "builtin", Featured: true, Icon: "gmail.com",
		Homepage:    "https://developers.google.com/workspace/gmail/api/guides/configure-mcp-server",
		Description: "Google's official Gmail MCP server: search and read email, create drafts, manage labels. It cannot send email.",
		Template:    ServerConfig{ID: "gmail", Transport: "http", URL: "https://gmailmcp.googleapis.com/mcp/v1"},
		Auth: []AuthOption{{ID: "oauth", Label: "Sign in with Google (OAuth)", Kind: "oauth_app",
			Description: "Google does not support automatic client registration. Create an OAuth client in Google Cloud once. Gmail MCP may currently be part of the Google Workspace Developer Preview.",
			SetupURL:    "https://console.cloud.google.com/apis/library/gmailmcp.googleapis.com",
			SetupLabel:  "Open Google Cloud Console",
			SetupSteps:  googleOAuthSteps("the Gmail MCP API and the Gmail API", "gmailmcp.googleapis.com, gmail.googleapis.com", short),
			Template:    &ServerConfig{Auth: "oauth", OAuthClientID: "{{client_id}}", OAuthClientSecretRef: "{{client_secret}}", OAuthScopes: scopes},
			Params: []CatalogParam{{Name: "client_id", Label: "Client ID", Required: true, Description: "…apps.googleusercontent.com"},
				{Name: "client_secret", Label: "Client secret", Secret: true, Required: true}}}},
	}
}

func builtinCatalog() []*CatalogEntry {
	return []*CatalogEntry{
		githubEntry(),
		{ID: "builtin:cloudflare", Name: "Cloudflare", Source: "builtin", Featured: true, Icon: "cloudflare.com",
			Homepage:    "https://github.com/cloudflare/mcp",
			Description: "The whole Cloudflare API (DNS, Workers, R2, D1, Zero Trust…). You choose which account and permissions to grant when signing in.",
			Template:    ServerConfig{ID: "cloudflare-api", Transport: "http", URL: "https://mcp.cloudflare.com/mcp", Auth: "oauth"},
			Auth:        []AuthOption{{ID: "oauth", Label: "Sign in with Cloudflare", Kind: "oauth", Description: "Clicking Add opens Cloudflare's account and permission picker."}}},
		gmailEntry(),
		{ID: "builtin:cloudflare-docs", Name: "Cloudflare Docs", Source: "builtin", Icon: "cloudflare.com",
			Description: "Search the Cloudflare documentation. No sign-in needed.",
			Template:    ServerConfig{ID: "cloudflare-docs", Transport: "http", URL: "https://docs.mcp.cloudflare.com/mcp", Auth: "none"}},
		{ID: "builtin:postgres", Name: "PostgreSQL", Source: "builtin", Featured: true, Icon: "postgresql.org", Requires: []string{"uvx"},
			Homepage:    "https://github.com/crystaldba/postgres-mcp",
			Description: "Query PostgreSQL and inspect schemas. Install once per database (pg-prod, pg-staging…).",
			Template: ServerConfig{ID: "postgres", Transport: "stdio", Command: "uvx", Args: []string{"postgres-mcp", "--access-mode={{access_mode}}"},
				Env: map[string]string{"DATABASE_URI": "{{database_uri}}"}},
			Params: []CatalogParam{{Name: "database_uri", Label: "Connection URI", Secret: true, Required: true, Description: "postgresql://user:password@host:5432/db"},
				{Name: "access_mode", Label: "Access", Default: "restricted", Options: []ParamOption{{"restricted", "Read-only", ""}, {"unrestricted", "Read and write", ""}}}},
			Auth: []AuthOption{{ID: "default", Label: "Connection details", Kind: "credentials"}}},
		{ID: "builtin:mysql", Name: "MySQL", Source: "builtin", Icon: "mysql.com", Requires: []string{"uvx"},
			Description: "Query MySQL. Install once per database.",
			Template: ServerConfig{ID: "mysql", Transport: "stdio", Command: "uvx", Args: []string{"mysql-mcp-server"},
				Env: map[string]string{"MYSQL_HOST": "{{host}}", "MYSQL_PORT": "{{port}}", "MYSQL_USER": "{{user}}", "MYSQL_PASSWORD": "{{password}}", "MYSQL_DATABASE": "{{database}}"}},
			Params: []CatalogParam{{Name: "host", Label: "Host", Required: true, Default: "127.0.0.1"}, {Name: "port", Label: "Port", Default: "3306"},
				{Name: "user", Label: "User", Required: true}, {Name: "password", Label: "Password", Secret: true, Required: true}, {Name: "database", Label: "Database", Required: true}},
			Auth: []AuthOption{{ID: "default", Label: "Connection details", Kind: "credentials"}}},
		{ID: "builtin:sqlite", Name: "SQLite", Source: "builtin", Icon: "sqlite.org", Requires: []string{"uvx"},
			Description: "Query a local SQLite file.",
			Template:    ServerConfig{ID: "sqlite", Transport: "stdio", Command: "uvx", Args: []string{"mcp-server-sqlite", "--db-path", "{{path}}"}},
			Params:      []CatalogParam{{Name: "path", Label: "File path", Required: true, Description: "Full path to the .db file"}}},
		{ID: "builtin:filesystem", Name: "Filesystem", Source: "builtin", Icon: "modelcontextprotocol.io", Requires: []string{"npx"},
			Description: "Read and write files under one folder.",
			Template:    ServerConfig{ID: "files", Transport: "stdio", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem", "{{path}}"}},
			Params:      []CatalogParam{{Name: "path", Label: "Allowed folder", Required: true}}},
		{ID: "builtin:fetch", Name: "Fetch", Source: "builtin", Icon: "modelcontextprotocol.io", Requires: []string{"uvx"},
			Description: "Fetch web pages as markdown.",
			Template:    ServerConfig{ID: "fetch", Transport: "stdio", Command: "uvx", Args: []string{"mcp-server-fetch"}}},
		{ID: "builtin:memory", Name: "Memory", Source: "builtin", Icon: "modelcontextprotocol.io", Requires: []string{"npx"},
			Description: "A persistent knowledge graph shared by all agents.",
			Template:    ServerConfig{ID: "memory", Transport: "stdio", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-memory"}}},
		{ID: "builtin:everything", Name: "Everything (test)", Source: "builtin", Icon: "modelcontextprotocol.io", Requires: []string{"npx"},
			Description: "MCP reference test server with sample tools. Handy for trying out the gateway.",
			Template:    ServerConfig{ID: "everything", Transport: "stdio", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-everything"}}},
	}
}

// featuredClaude are popular Claude-directory connectors shown on the
// "Featured" tab (only those present in the directory are shown).
var featuredClaude = []string{"Notion", "Linear", "Atlassian Rovo", "Sentry", "Vercel", "Supabase", "Stripe", "Hugging Face",
	"Cloudflare Developer Platform", "Figma", "Asana", "HubSpot", "Canva", "Zapier", "Intercom", "monday.com", "Box", "PayPal", "Netlify", "Airtable"}

// ---- Claude connector directory (cached locally) ----

const claudeDirURL = "https://api.anthropic.com/mcp-registry/v0/servers"
const registryURL = "https://registry.modelcontextprotocol.io/v0/servers"

type claudeCache struct {
	FetchedAt time.Time       `json:"fetched_at"`
	Entries   []*CatalogEntry `json:"entries"`
}

func (c *Catalog) cachePath() string { return filepath.Join(c.dataDir, "claude-directory.json") }

// Run loads the cached Claude directory and refreshes it every 12h.
func (c *Catalog) Run(ctx context.Context) {
	if b, err := os.ReadFile(c.cachePath()); err == nil {
		var cc claudeCache
		if json.Unmarshal(b, &cc) == nil {
			c.setClaude(cc.Entries, cc.FetchedAt)
		}
	}
	for {
		c.mu.RLock()
		age := time.Since(c.claudeAt)
		c.mu.RUnlock()
		if age > 12*time.Hour {
			if err := c.RefreshClaude(ctx); err != nil {
				c.log.Warn("claude directory refresh failed", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Minute):
		}
	}
}

func (c *Catalog) setClaude(es []*CatalogEntry, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.claude, c.claudeAt = es, at
	for _, e := range es {
		if e.Icon != "" {
			c.iconHosts[e.Icon] = true
		}
	}
}

func (c *Catalog) RefreshClaude(ctx context.Context) error {
	var all []*CatalogEntry
	cursor := ""
	for page := 0; page < 40; page++ {
		v := url.Values{"visibility": {"commercial"}, "limit": {"100"}}
		if cursor != "" {
			v.Set("cursor", cursor)
		}
		rr, err := c.getRegistry(ctx, claudeDirURL+"?"+v.Encode())
		if err != nil {
			return err
		}
		for _, item := range rr.Servers {
			if e := registryToEntry("claude", item.Server, item.Meta); e != nil {
				all = append(all, e)
			}
		}
		cursor = rr.Metadata.NextCursor
		if cursor == "" {
			break
		}
	}
	if len(all) == 0 {
		return fmt.Errorf("directory returned no entries")
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Order != all[j].Order {
			return all[i].Order < all[j].Order
		}
		return strings.ToLower(all[i].Name) < strings.ToLower(all[j].Name)
	})
	now := time.Now()
	c.setClaude(all, now)
	b, _ := json.Marshal(claudeCache{FetchedAt: now, Entries: all})
	_ = os.WriteFile(c.cachePath(), b, 0o600)
	c.log.Info("claude directory refreshed", "entries", len(all))
	return nil
}

// ---- queries ----

func (c *Catalog) AddUser(e *CatalogEntry) error {
	e.Source = "user"
	if e.Name == "" {
		return fmt.Errorf("catalog entry needs a name")
	}
	if e.ID == "" {
		e.ID = slug(e.Name)
	}
	if !strings.HasPrefix(e.ID, "user:") {
		e.ID = "user:" + e.ID
	}
	if e.Template.ID == "" {
		e.Template.ID = slug(e.Name)
	}
	if e.Template.Transport != "stdio" && e.Template.Transport != "http" {
		return fmt.Errorf("template.transport must be stdio or http")
	}
	return c.store.PutCatalog(e)
}

func (c *Catalog) local() []*CatalogEntry {
	out := builtinCatalog()
	user, _ := c.store.ListCatalog()
	return append(out, user...)
}

func (c *Catalog) claudeEntries() []*CatalogEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.claude
}

func (c *Catalog) ClaudeInfo() (int, time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.claude), c.claudeAt
}

func score(e *CatalogEntry, q []string) float64 {
	if len(q) == 0 {
		return 1
	}
	name := strings.ToLower(e.Name + " " + e.ID)
	desc := strings.ToLower(e.Description + " " + e.Long + " " + strings.Join(e.Tools, " "))
	s := 0.0
	for _, w := range q {
		hit := false
		if strings.Contains(name, w) {
			s += 3
			hit = true
		}
		if strings.Contains(desc, w) {
			s += 1
			hit = true
		}
		if !hit {
			return 0 // every word must match somewhere
		}
	}
	if strings.EqualFold(e.Name, strings.Join(q, " ")) {
		s += 5
	}
	return s
}

type SearchResult struct {
	Entries []*CatalogEntry `json:"entries"`
	Total   int             `json:"total"`
	Errors  []string        `json:"errors,omitempty"`
}

// Search: source = all (builtin+user+claude), featured, builtin, user,
// claude, registry (open MCP Registry, query required).
func (c *Catalog) Search(ctx context.Context, query, source string, offset, limit int) SearchResult {
	if source == "" {
		source = "all"
	}
	if limit <= 0 || limit > 200 {
		limit = 30
	}
	q := words(query)
	var pool []*CatalogEntry
	var errs []string
	switch source {
	case "featured":
		for _, e := range c.local() {
			if e.Featured || e.Source == "user" {
				pool = append(pool, e)
			}
		}
		byName := map[string]*CatalogEntry{}
		for _, e := range c.dedupeAgainstLocal(c.claudeEntries()) {
			byName[strings.ToLower(e.Name)] = e
		}
		for _, n := range featuredClaude {
			if e := byName[strings.ToLower(n)]; e != nil {
				pool = append(pool, e)
			}
		}
	case "builtin", "user":
		for _, e := range c.local() {
			if e.Source == source {
				pool = append(pool, e)
			}
		}
	case "claude":
		pool = c.claudeEntries()
	case "registry":
		if query == "" {
			return SearchResult{Entries: []*CatalogEntry{}, Errors: []string{"Type something to search the community registry."}}
		}
		es, err := c.searchRegistry(ctx, query, 40)
		if err != nil {
			errs = append(errs, "MCP Registry: "+err.Error())
		}
		pool = c.dedupeAgainstKnown(es)
	default: // all
		pool = append(c.local(), c.dedupeAgainstLocal(c.claudeEntries())...)
	}
	type scored struct {
		e *CatalogEntry
		s float64
		i int
	}
	var hits []scored
	for i, e := range pool {
		if s := score(e, q); s > 0 {
			if e.Source == "builtin" || e.Source == "user" {
				s += 0.5
			}
			hits = append(hits, scored{e, s, i})
		}
	}
	if len(q) > 0 {
		sort.SliceStable(hits, func(i, j int) bool { return hits[i].s > hits[j].s })
	}
	total := len(hits)
	if offset > total {
		offset = total
	}
	end := min(total, offset+limit)
	servers, _ := c.store.ListServers()
	out := make([]*CatalogEntry, 0, end-offset)
	for _, h := range hits[offset:end] {
		cp := *h.e
		cp.Auth = cp.authOptions()
		cp.Installed = installedFor(&cp, servers)
		for _, cmd := range cp.Requires {
			if _, err := lookPath(cmd); err != nil {
				cp.Missing = append(cp.Missing, cmd)
			}
		}
		out = append(out, &cp)
	}
	return SearchResult{Entries: out, Total: total, Errors: errs}
}

func normURL(u string) string { return strings.TrimRight(strings.ToLower(u), "/") }

func installedFor(e *CatalogEntry, servers []*ServerConfig) []string {
	var out []string
	for _, s := range servers {
		if e.Template.Transport == "http" && !strings.Contains(e.Template.URL, "{") {
			if normURL(s.URL) == normURL(e.Template.URL) {
				out = append(out, s.ID)
			}
		} else if s.CatalogID == e.ID {
			out = append(out, s.ID)
		}
	}
	return out
}

func (c *Catalog) dedupeAgainstLocal(es []*CatalogEntry) []*CatalogEntry {
	seen := map[string]bool{}
	for _, e := range c.local() {
		if e.Template.URL != "" {
			seen[normURL(e.Template.URL)] = true
		}
	}
	var out []*CatalogEntry
	for _, e := range es {
		if e.Template.URL != "" && seen[normURL(e.Template.URL)] {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (c *Catalog) dedupeAgainstKnown(es []*CatalogEntry) []*CatalogEntry {
	seen := map[string]bool{}
	for _, e := range append(c.local(), c.claudeEntries()...) {
		if e.Template.URL != "" {
			seen[normURL(e.Template.URL)] = true
		}
	}
	var out []*CatalogEntry
	for _, e := range es {
		if e.Template.URL != "" && seen[normURL(e.Template.URL)] {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (c *Catalog) Get(ctx context.Context, id string) (*CatalogEntry, error) {
	for _, e := range c.local() {
		if e.ID == id {
			return e, nil
		}
	}
	for _, e := range c.claudeEntries() {
		if e.ID == id {
			return e, nil
		}
	}
	c.mu.RLock()
	e := c.remote[id]
	c.mu.RUnlock()
	if e != nil {
		return e, nil
	}
	if src, name, ok := strings.Cut(id, ":"); ok && src == "registry" {
		es, err := c.searchRegistry(ctx, name, 30)
		if err != nil {
			return nil, err
		}
		for _, e := range es {
			if e.ID == id {
				return e, nil
			}
		}
	}
	return nil, fmt.Errorf("catalog entry %q not found", id)
}

// IconFor picks an icon host for an installed server (catalog entry icon,
// else the server URL's host) and allows the icon proxy to fetch it.
func (c *Catalog) IconFor(s *ServerConfig) string {
	icon := ""
	if s.CatalogID != "" {
		for _, e := range append(builtinCatalog(), c.claudeEntries()...) {
			if e.ID == s.CatalogID {
				icon = e.Icon
				break
			}
		}
	}
	if icon == "" && s.URL != "" {
		icon = hostOf(s.URL)
	}
	if icon == "" && s.Transport == "builtin" && s.Command == "gemini" {
		icon = "gemini.google.com"
	}
	if icon != "" {
		c.mu.Lock()
		c.iconHosts[icon] = true
		c.mu.Unlock()
	}
	return icon
}

// KnownIconHost reports whether the icon proxy may fetch a favicon for host.
func (c *Catalog) KnownIconHost(h string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.iconHosts[h]
}

// --- registry (server.json) parsing ---

type regInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	IsRequired  bool   `json:"isRequired"`
	IsSecret    bool   `json:"isSecret"`
	Default     string `json:"default"`
	Value       string `json:"value"`
	ValueHint   string `json:"valueHint"`
	Type        string `json:"type"`
}

type regServer struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Version     string `json:"version"`
	WebsiteURL  string `json:"websiteUrl"`
	Repository  struct {
		URL string `json:"url"`
	} `json:"repository"`
	Remotes []struct {
		Type    string     `json:"type"`
		URL     string     `json:"url"`
		Headers []regInput `json:"headers"`
	} `json:"remotes"`
	Packages []struct {
		RegistryType string `json:"registryType"`
		Identifier   string `json:"identifier"`
		Version      string `json:"version"`
		Transport    struct {
			Type string `json:"type"`
		} `json:"transport"`
		EnvironmentVariables []regInput `json:"environmentVariables"`
		PackageArguments     []regInput `json:"packageArguments"`
	} `json:"packages"`
}

type regResponse struct {
	Servers []struct {
		Server regServer                  `json:"server"`
		Meta   map[string]json.RawMessage `json:"_meta"`
	} `json:"servers"`
	Metadata struct {
		NextCursor string `json:"nextCursor"`
	} `json:"metadata"`
}

func (c *Catalog) getRegistry(ctx context.Context, u string) (*regResponse, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var rr regResponse
	return &rr, json.NewDecoder(resp.Body).Decode(&rr)
}

func (c *Catalog) searchRegistry(ctx context.Context, query string, limit int) ([]*CatalogEntry, error) {
	v := url.Values{"search": {query}, "limit": {fmt.Sprint(limit)}, "version": {"latest"}}
	rr, err := c.getRegistry(ctx, registryURL+"?"+v.Encode())
	if err != nil {
		return nil, err
	}
	var out []*CatalogEntry
	seen := map[string]bool{}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, item := range rr.Servers {
		if seen[item.Server.Name] {
			continue
		}
		seen[item.Server.Name] = true
		if e := registryToEntry("registry", item.Server, item.Meta); e != nil {
			out = append(out, e)
			c.remote[e.ID] = e
			if e.Icon != "" {
				c.iconHosts[e.Icon] = true
			}
		}
	}
	return out, nil
}

var braceVar = regexp.MustCompile(`\{([A-Za-z0-9_]+)\}`)

func hostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Host == "" {
		return ""
	}
	h := strings.TrimPrefix(strings.ToLower(p.Hostname()), "www.")
	// prefer the registrable-looking part for mcp.* / api.* subdomains
	parts := strings.Split(h, ".")
	if len(parts) > 2 && (parts[0] == "mcp" || parts[0] == "api" || parts[0] == "app" || parts[0] == "bindings" || parts[0] == "docs") {
		h = strings.Join(parts[1:], ".")
	}
	return h
}

type claudeMeta struct {
	DisplayName    string   `json:"displayName"`
	OneLiner       string   `json:"oneLiner"`
	ToolNames      []string `json:"toolNames"`
	IsAuthless     bool     `json:"isAuthless"`
	IconURL        string   `json:"iconUrl"`
	Documentation  string   `json:"documentation"`
	SortOrder      int      `json:"sortOrder"`
	RequiredFields []struct {
		Field     string `json:"field"`
		SourceURL string `json:"sourceUrl"`
	} `json:"requiredFields"`
	URLOptions []struct {
		URL         string `json:"url"`
		Label       string `json:"label"`
		Description string `json:"description"`
	} `json:"urlOptions"`
	Author struct {
		URL string `json:"url"`
	} `json:"author"`
}

func registryToEntry(src string, s regServer, meta map[string]json.RawMessage) *CatalogEntry {
	e := &CatalogEntry{ID: src + ":" + s.Name, Name: firstNonEmpty(s.Title, s.Name), Description: s.Description, Source: src,
		Homepage: firstNonEmpty(s.WebsiteURL, s.Repository.URL)}
	var cm *claudeMeta
	if raw, ok := meta["com.anthropic.api/mcp-registry"]; ok {
		var m claudeMeta
		if json.Unmarshal(raw, &m) == nil {
			cm = &m
			e.Name = firstNonEmpty(m.DisplayName, e.Name)
			if m.OneLiner != "" {
				e.Long = e.Description
				e.Description = m.OneLiner
			}
			e.Tools = m.ToolNames
			e.Order = m.SortOrder
			e.Homepage = firstNonEmpty(m.Documentation, e.Homepage, m.Author.URL)
			e.Icon = firstNonEmpty(hostOf(m.Author.URL), hostOf(m.IconURL))
		}
	}
	base := s.Name
	if i := strings.LastIndexAny(base, "/."); i >= 0 && i < len(base)-1 {
		base = base[i+1:]
	}
	if base == "mcp" || base == "server" || base == "mcp-server" || base == "remote" {
		parts := strings.FieldsFunc(s.Name, func(r rune) bool { return r == '/' || r == '.' })
		if len(parts) >= 2 {
			base = parts[len(parts)-2]
		}
	}
	if cm != nil && cm.DisplayName != "" {
		base = cm.DisplayName
	}
	id := slug(base)
	params := map[string]*CatalogParam{}
	var order []string
	addParam := func(in regInput, name string) string {
		pn := strings.ReplaceAll(slug(name), "-", "_")
		if _, ok := params[pn]; !ok {
			params[pn] = &CatalogParam{Name: pn, Label: name, Description: in.Description, Secret: in.IsSecret, Required: in.IsRequired, Default: in.Default}
			order = append(order, pn)
		}
		return "{{" + pn + "}}"
	}
	finish := func(t ServerConfig, kind string) *CatalogEntry {
		e.Template = t
		for _, n := range order {
			e.Params = append(e.Params, *params[n])
		}
		if e.Icon == "" {
			e.Icon = firstNonEmpty(hostOf(s.WebsiteURL), hostOf(t.URL))
		}
		if kind != "" {
			e.Auth = []AuthOption{{ID: "default", Label: authLabel(kind), Kind: kind}}
		}
		return e
	}
	for _, r := range s.Remotes {
		if r.Type != "streamable-http" && r.Type != "http" {
			continue
		}
		t := ServerConfig{ID: id, Transport: "http", URL: r.URL, Auth: "auto"}
		if braceVar.MatchString(r.URL) {
			t.URL = braceVar.ReplaceAllStringFunc(r.URL, func(m string) string {
				name := braceVar.FindStringSubmatch(m)[1]
				p := regInput{Name: name, IsRequired: true}
				ph := addParam(p, name)
				pn := strings.Trim(ph, "{}")
				if cm != nil {
					for _, o := range cm.URLOptions {
						params[pn].Options = append(params[pn].Options, ParamOption{Value: o.URL, Label: o.Label, Description: o.Description})
					}
					if len(params[pn].Options) > 0 {
						params[pn].Default = params[pn].Options[0].Value
						params[pn].Label = "Region"
					}
					for _, f := range cm.RequiredFields {
						if f.Field == name {
							params[pn].HelpURL = f.SourceURL
							params[pn].Label = "Server URL"
							params[pn].Description = "The MCP URL specific to your account (see the instructions at the link)"
						}
					}
				}
				return ph
			})
		}
		hasSecretHeader := false
		for _, h := range r.Headers {
			if t.Headers == nil {
				t.Headers = map[string]string{}
			}
			if h.IsSecret {
				hasSecretHeader = true
			}
			if h.Value != "" && braceVar.MatchString(h.Value) {
				t.Headers[h.Name] = braceVar.ReplaceAllStringFunc(h.Value, func(m string) string {
					return addParam(h, braceVar.FindStringSubmatch(m)[1])
				})
			} else if h.Value != "" {
				t.Headers[h.Name] = h.Value
			} else {
				t.Headers[h.Name] = addParam(h, h.Name)
			}
		}
		kind := "auto"
		switch {
		case hasSecretHeader:
			kind, t.Auth = "token", "none"
		case cm != nil && cm.IsAuthless:
			kind, t.Auth = "none", "none"
		case cm != nil:
			kind, t.Auth = "oauth", "oauth"
		}
		return finish(t, kind)
	}
	for _, p := range s.Packages {
		if p.Transport.Type != "" && p.Transport.Type != "stdio" {
			continue
		}
		t := ServerConfig{ID: id, Transport: "stdio", Env: map[string]string{}}
		switch p.RegistryType {
		case "npm":
			ident := p.Identifier
			if p.Version != "" {
				ident += "@" + p.Version
			}
			t.Command, t.Args = "npx", []string{"-y", ident}
			e.Requires = []string{"npx"}
		case "pypi":
			ident := p.Identifier
			if p.Version != "" {
				ident += "==" + p.Version
			}
			t.Command, t.Args = "uvx", []string{ident}
			e.Requires = []string{"uvx"}
		case "oci":
			img := p.Identifier
			if p.Version != "" && !strings.Contains(img, ":") {
				img += ":" + p.Version
			}
			t.Command, t.Args = "docker", []string{"run", "-i", "--rm"}
			for _, ev := range p.EnvironmentVariables {
				t.Args = append(t.Args, "-e", ev.Name)
			}
			t.Args = append(t.Args, img)
			e.Requires = []string{"docker"}
		default:
			continue
		}
		secret := false
		for _, ev := range p.EnvironmentVariables {
			t.Env[ev.Name] = addParam(ev, ev.Name)
			secret = secret || ev.IsSecret
		}
		for _, a := range p.PackageArguments {
			val := a.Value
			if val == "" {
				val = addParam(a, firstNonEmpty(a.Name, a.ValueHint, "arg"))
			}
			if a.Type == "named" && a.Name != "" {
				t.Args = append(t.Args, a.Name, val)
			} else {
				t.Args = append(t.Args, val)
			}
		}
		kind := "none"
		if secret {
			kind = "token"
		}
		return finish(t, kind)
	}
	return nil // nothing installable
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	// Fold Turkish letters to ASCII so Turkish names still give readable slugs.
	s = strings.NewReplacer("ı", "i", "ş", "s", "ğ", "g", "ü", "u", "ö", "o", "ç", "c").Replace(strings.ToLower(s))
	s = nonSlug.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-")
	}
	if s == "" {
		s = "server"
	}
	return s
}

var placeholder = regexp.MustCompile(`\{\{([A-Za-z0-9_]+)\}\}`)

func mergeTemplate(base ServerConfig, o *ServerConfig) ServerConfig {
	t := base
	if o == nil {
		return t
	}
	if o.Auth != "" {
		t.Auth = o.Auth
	}
	if o.URL != "" {
		t.URL = o.URL
	}
	if o.Headers != nil {
		t.Headers = map[string]string{}
		for k, v := range o.Headers {
			t.Headers[k] = v
		}
	}
	if o.OAuthClientID != "" {
		t.OAuthClientID = o.OAuthClientID
	}
	if o.OAuthClientSecretRef != "" {
		t.OAuthClientSecretRef = o.OAuthClientSecretRef
	}
	if len(o.OAuthScopes) > 0 {
		t.OAuthScopes = o.OAuthScopes
	}
	if o.Env != nil {
		env := map[string]string{}
		for k, v := range t.Env {
			env[k] = v
		}
		for k, v := range o.Env {
			env[k] = v
		}
		t.Env = env
	}
	return t
}

func (e *CatalogEntry) option(authID string) AuthOption {
	opts := e.authOptions()
	for _, o := range opts {
		if o.ID == authID {
			return o
		}
	}
	return opts[0]
}

// secretParamNames maps secret params to the vault names Install would use.
func (e *CatalogEntry) secretParamNames(instanceID, authID string) map[string]string {
	o := e.option(authID)
	t := mergeTemplate(e.Template, o.Template)
	if instanceID != "" {
		t.ID = instanceID
	}
	if t.ID == "" {
		t.ID = slug(e.Name)
	}
	out := map[string]string{}
	for _, p := range append(append([]CatalogParam{}, e.Params...), o.Params...) {
		if p.Secret {
			out[p.Name] = strings.ToUpper(strings.ReplaceAll(t.ID+"_"+p.Name, "-", "_"))
		}
	}
	return out
}

// urlIsFixed reports whether the installed URL can only be one the catalog
// defines (no free-form address chosen by the caller).
func (e *CatalogEntry) urlIsFixed(authID string, params map[string]string) bool {
	o := e.option(authID)
	t := mergeTemplate(e.Template, o.Template)
	for _, m := range placeholder.FindAllStringSubmatch(t.URL, -1) {
		var def *CatalogParam
		for _, p := range append(append([]CatalogParam{}, e.Params...), o.Params...) {
			if p.Name == m[1] {
				p := p
				def = &p
			}
		}
		if def == nil || len(def.Options) == 0 {
			return false
		}
		v := params[m[1]]
		if v == "" {
			v = def.Default
		}
		ok := false
		for _, opt := range def.Options {
			ok = ok || opt.Value == v
		}
		if !ok {
			return false
		}
	}
	return true
}

// Install turns a catalog entry into a saved server config. Secret params are
// stored in the vault under <ID>_<PARAM>; missing secret names are returned.
func (c *Catalog) Install(e *CatalogEntry, instanceID, authID string, params map[string]string) (*ServerConfig, []string, error) {
	opts := e.authOptions()
	opt := opts[0]
	if authID != "" {
		found := false
		for _, o := range opts {
			if o.ID == authID {
				opt, found = o, true
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("unknown auth option %q", authID)
		}
	}
	t := mergeTemplate(e.Template, opt.Template)
	if instanceID != "" {
		t.ID = instanceID
	}
	if t.ID == "" {
		t.ID = slug(e.Name)
	}
	if !idRe.MatchString(t.ID) {
		return nil, nil, fmt.Errorf("invalid server id %q", t.ID)
	}
	if _, err := c.store.GetServer(t.ID); err == nil {
		return nil, nil, fmt.Errorf("server %q already exists; pass a different id (e.g. %s-2) to install another instance", t.ID, t.ID)
	}
	allParams := append(append([]CatalogParam{}, e.Params...), opt.Params...)
	secretName := func(p string) string {
		return strings.ToUpper(strings.ReplaceAll(t.ID+"_"+p, "-", "_"))
	}
	var missing []string
	values := map[string]string{}
	secretNames := map[string]string{}
	for _, p := range allParams {
		v := strings.TrimSpace(params[p.Name])
		if p.Secret {
			name := secretName(p.Name)
			secretNames[p.Name] = name
			if v != "" {
				if err := c.vault.Set(name, v, false, e.Name+" "+firstNonEmpty(p.Label, p.Name)); err != nil {
					return nil, nil, err
				}
			} else if !c.vault.Has(name) {
				if p.Required {
					missing = append(missing, name)
				} else {
					values[p.Name] = ""
					continue
				}
			}
			values[p.Name] = "${secret:" + name + "}"
			continue
		}
		if v == "" {
			v = p.Default
		}
		if v == "" && p.Required {
			return nil, nil, fmt.Errorf("%q gerekli (%s)", firstNonEmpty(p.Label, p.Name), p.Description)
		}
		values[p.Name] = v
	}
	sub := func(s string) string {
		return placeholder.ReplaceAllStringFunc(s, func(m string) string {
			name := placeholder.FindStringSubmatch(m)[1]
			if v, ok := values[name]; ok {
				return v
			}
			return strings.TrimSpace(params[name])
		})
	}
	t.Command = sub(t.Command)
	t.URL = sub(t.URL)
	t.OAuthClientID = sub(t.OAuthClientID)
	if m := placeholder.FindStringSubmatch(t.OAuthClientSecretRef); m != nil {
		t.OAuthClientSecretRef = secretNames[m[1]]
	}
	args := make([]string, 0, len(t.Args))
	for _, a := range t.Args {
		if v := sub(a); v != "" || a == "" {
			args = append(args, v)
		}
	}
	t.Args = args
	if t.Env != nil {
		env := map[string]string{}
		for k, v := range t.Env {
			if s := sub(v); s != "" {
				env[k] = s
			}
		}
		t.Env = env
	}
	if t.Headers != nil {
		h := map[string]string{}
		for k, v := range t.Headers {
			if s := sub(v); strings.TrimSpace(strings.TrimPrefix(s, "Bearer")) != "" {
				h[k] = s
			}
		}
		t.Headers = h
	}
	t.Name = e.Name
	if instanceID != "" && instanceID != e.Template.ID {
		t.Name = e.Name + " (" + instanceID + ")"
	}
	t.Description = truncate(e.Description, 240)
	t.CatalogID = e.ID
	t.Enabled = true
	t.CreatedAt = ""
	t.Purpose = ""
	if old, err := c.store.GetServer(t.ID); err == nil {
		t.Purpose = old.Purpose // reinstalling keeps what the user wrote
	}
	if err := c.store.PutServer(&t); err != nil {
		return nil, nil, err
	}
	return &t, missing, nil
}

func compactEntries(es []*CatalogEntry) []map[string]any {
	out := []map[string]any{}
	for _, e := range es {
		m := map[string]any{"catalog_id": e.ID, "name": e.Name, "source": e.Source, "description": truncate(e.Description, 160),
			"transport": e.Template.Transport, "default_id": e.Template.ID}
		var auth []map[string]any
		for _, o := range e.authOptions() {
			a := map[string]any{"auth": o.ID, "kind": o.Kind, "label": o.Label}
			var ps []string
			for _, p := range append(append([]CatalogParam{}, e.Params...), o.Params...) {
				s := p.Name
				if p.Secret {
					s += " (secret: user enters it in the UI)"
				}
				ps = append(ps, s)
			}
			if len(ps) > 0 {
				a["params"] = ps
			}
			auth = append(auth, a)
		}
		m["auth_options"] = auth
		if len(e.Tools) > 0 {
			m["tools"] = len(e.Tools)
		}
		if len(e.Installed) > 0 {
			m["installed_as"] = e.Installed
		}
		if len(e.Missing) > 0 {
			m["missing_commands"] = e.Missing
		}
		out = append(out, m)
	}
	return out
}
