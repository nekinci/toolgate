package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Gateway exposes a small fixed set of meta-tools to agents and routes calls
// to the upstream servers.
type Gateway struct {
	store    *Store
	vault    *Vault
	mgr      *Manager
	catalog  *Catalog
	gemini   *Gemini
	pools    *Pools
	pairings *Pairings
	baseURL  string
}

func textResult(format string, a ...any) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, a...)}}}
}

func errResult(format string, a ...any) *mcp.CallToolResult {
	r := textResult(format, a...)
	r.IsError = true
	return r
}

func jsonResult(v any) *mcp.CallToolResult {
	b, _ := json.MarshalIndent(v, "", "  ")
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}
}

// ---- summaries shown to agents ----

type serverSummary struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Purpose     string   `json:"purpose,omitempty"`
	Status      string   `json:"status"`
	ToolCount   int      `json:"tool_count"`
	SampleTools []string `json:"sample_tools,omitempty"`
	Note        string   `json:"note,omitempty"`
}

func (g *Gateway) summaries(agent *Agent) []serverSummary {
	servers, _ := g.store.ListServers()
	all, _ := g.store.Tools("")
	byServer := map[string][]CachedTool{}
	for _, t := range all {
		byServer[t.ServerID] = append(byServer[t.ServerID], t)
	}
	var out []serverSummary
	for _, s := range servers {
		if !s.Enabled || !ServerVisible(agent, s) {
			continue
		}
		st := g.mgr.Status(s.ID)
		sum := serverSummary{ID: s.ID, Name: s.Name, Description: s.Description, Purpose: s.Purpose, Status: st.Status}
		pendingTools := 0
		for _, t := range byServer[s.ID] {
			if !Decide(agent, s, t.Name).Allowed {
				continue
			}
			if t.Pending != "" {
				pendingTools++
				continue
			}
			sum.ToolCount++
			if len(sum.SampleTools) < 8 {
				sum.SampleTools = append(sum.SampleTools, t.Name)
			}
		}
		switch {
		case len(byServer[s.ID]) == 0 && st.Status == StatusAuthRequired:
			sum.Note = "needs user sign-in; use manage action=connect to get the login link"
		case len(byServer[s.ID]) == 0:
			sum.Note = "tools not indexed yet; use manage action=connect"
		}
		if !g.store.IsApproved(s) {
			sum.Note = "waiting for the user's approval: " + g.approvalLink(s.ID)
		} else if pendingTools > 0 {
			sum.Note = fmt.Sprintf("%d new or changed tools are hidden until the user reviews them: %s", pendingTools, g.approvalLink(s.ID))
		} else if g.mgr.Status(s.ID).AuthIssue == "client_required" {
			sum.Note = "needs an OAuth client registered by the user: " + g.baseURL + "/ui/#c/" + s.ID + "?tab=settings"
		} else if g.mgr.NeedsLogin(s) {
			sum.Note = "not signed in yet; use manage action=connect to get a login link for the user"
		} else if s.Transport == "builtin" && s.Command == "gemini" && g.gemini != nil && len(g.gemini.pool.Keys()) == 0 {
			sum.Note = "no Gemini API keys yet; the user can add them here: " + g.secretLink("GEMINI_API_KEY_1", "")
		} else if m := g.mgr.missingSecrets(s); len(m) > 0 {
			sum.Note = "missing secrets: " + strings.Join(m, ", ") + " (user must enter them in the gateway UI)"
		}
		out = append(out, sum)
	}
	return out
}

func (g *Gateway) instructions(agent *Agent) string {
	return g.instructionsFor(agent, ToolModeLazy, false)
}

func (g *Gateway) instructionsFor(agent *Agent, mode string, capped bool) string {
	var b strings.Builder
	b.WriteString("Toolgate: one endpoint in front of many MCP servers, databases and APIs. Credentials live in the gateway vault; you never see or need raw secrets.\n")
	if mode == ToolModeDirect {
		b.WriteString("Each connected server's tools are listed directly, named <server>__<tool>. Use overview for the full picture")
		if capped {
			fmt.Fprintf(&b, "; only the first %d tools are listed, find the rest with search_tools and run them with call_tool (name = \"server.tool\")", DirectMaxTools)
		}
	} else {
		b.WriteString("Workflow: search_tools (find) -> describe_tools (get input schema) -> call_tool (run, name = \"server.tool\"). Use overview for the full picture")
	}
	if agent != nil && agent.CanManage {
		b.WriteString(" and manage to add/configure servers, install from the catalog, or start an OAuth login (give the returned link to the user)")
	}
	b.WriteString(".\n")
	if agent != nil && agent.ExpiresAt != "" {
		if left := time.Until(parseTime(agent.ExpiresAt)); left > 0 && left < 7*24*time.Hour {
			fmt.Fprintf(&b, "Note: your gateway token expires on %s. Tell the user so they can renew it in the gateway panel (Agents) before it stops working.\n", agent.ExpiresAt)
		}
	}
	b.WriteString("Connected servers:\n")
	sums := g.summaries(agent)
	if len(sums) == 0 {
		b.WriteString("- (none yet")
		if agent != nil && agent.CanManage {
			b.WriteString("; use manage action=catalog_search to find and install one")
		}
		b.WriteString(")\n")
	}
	for _, s := range sums {
		fmt.Fprintf(&b, "- %s", s.ID)
		if s.Purpose != "" {
			fmt.Fprintf(&b, " (purpose: %s)", s.Purpose)
		}
		if s.Description != "" {
			fmt.Fprintf(&b, " — %s", truncate(s.Description, 90))
		}
		fmt.Fprintf(&b, " [%d tools", s.ToolCount)
		if len(s.SampleTools) > 0 {
			fmt.Fprintf(&b, ": %s", strings.Join(s.SampleTools[:min(len(s.SampleTools), 5)], ", "))
			if s.ToolCount > 5 {
				b.WriteString(", …")
			}
		}
		b.WriteString("]")
		if s.Note != "" {
			fmt.Fprintf(&b, " (%s)", s.Note)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// ---- inputs ----

type OverviewIn struct{}

type SearchIn struct {
	Query  string `json:"query,omitempty" jsonschema:"keywords describing what you want to do; empty lists everything"`
	Server string `json:"server,omitempty" jsonschema:"restrict to one server id"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max results (default 20, max 100)"`
}

type DescribeIn struct {
	Tools []string `json:"tools" jsonschema:"full tool names like github.create_issue"`
}

type CallIn struct {
	Tool      string         `json:"tool" jsonschema:"full tool name: server.tool"`
	Arguments map[string]any `json:"arguments,omitempty" jsonschema:"arguments matching the tool's input schema"`
}

type ManageIn struct {
	Action    string            `json:"action" jsonschema:"one of: list_servers, get_server, upsert_server, remove_server, set_enabled, set_tool_policy, connect, disconnect, reset_auth, refresh_tools, catalog_search, catalog_install, catalog_add, list_secrets, set_secret, request_secret, audit"`
	ID        string            `json:"id,omitempty" jsonschema:"server id (or secret name for set_secret/request_secret)"`
	Server    *ServerConfig     `json:"server,omitempty" jsonschema:"full server config for upsert_server"`
	Enabled   *bool             `json:"enabled,omitempty"`
	Allow     []string          `json:"allow,omitempty" jsonschema:"set_tool_policy: allow globs on upstream tool names"`
	Deny      []string          `json:"deny,omitempty" jsonschema:"set_tool_policy: deny globs on upstream tool names"`
	Query     string            `json:"query,omitempty" jsonschema:"catalog_search query / audit filter"`
	Source    string            `json:"source,omitempty" jsonschema:"catalog_search source: all (default), builtin, user, claude, registry"`
	CatalogID string            `json:"catalog_id,omitempty" jsonschema:"catalog_install: entry id from catalog_search"`
	Auth      string            `json:"auth,omitempty" jsonschema:"catalog_install: auth option id from catalog_search auth_options (default: first)"`
	Params    map[string]string `json:"params,omitempty" jsonschema:"catalog_install: template parameters; secret params may be omitted and entered by the user in the UI"`
	Entry     *CatalogEntry     `json:"entry,omitempty" jsonschema:"catalog_add: entry to add to the user catalog"`
	Value     string            `json:"value,omitempty" jsonschema:"set_secret: value (write-only, never returned)"`
	Note      string            `json:"note,omitempty" jsonschema:"set_secret/request_secret: what the secret is for"`
	Limit     int               `json:"limit,omitempty"`
}

// ---- server construction ----

// ServerFor builds the MCP server presented to one agent.
// ServerFor builds the MCP server an agent talks to. override is the
// optional ?tools= mode from the request URL (see toolmode.go).
func (g *Gateway) ServerFor(agent *Agent, override string) *mcp.Server {
	mode := g.EffectiveToolMode(agent, override)
	capped := mode == ToolModeDirect && len(g.directTools(agent)) > DirectMaxTools
	instr := g.instructionsFor(agent, mode, capped)
	s := mcp.NewServer(&mcp.Implementation{Name: "toolgate", Version: version},
		&mcp.ServerOptions{Instructions: instr})
	howTo := "search_tools -> describe_tools -> call_tool(tool=\"server.tool\")"
	if mode == ToolModeDirect {
		howTo = "call the <server>__<tool> tools directly"
	}

	mcp.AddTool(s, &mcp.Tool{
		Name:        "overview",
		Description: "Everything you can do through this gateway: servers, their status, tool counts and sample tools, plus notes about missing sign-ins or secrets. Call this first in a new task.\n\nCurrent snapshot:\n" + instr,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in OverviewIn) (*mcp.CallToolResult, any, error) {
		g.audit(agent, "overview", "", nil, "ok", 0, "")
		return jsonResult(map[string]any{"servers": g.summaries(agent), "can_manage": agent.CanManage,
			"tool_mode": mode, "how_to": howTo}), nil, nil
	})
	if mode == ToolModeDirect {
		g.addDirectTools(s, agent)
	}
	if mode == ToolModeDirect && !capped {
		g.addManage(s, agent)
		return s
	}

	mcp.AddTool(s, &mcp.Tool{
		Name:        "search_tools",
		Description: "Search all tools across connected servers by keywords. Returns full names (server.tool) with short descriptions and match = strict (all keywords matched), loose (partial/fuzzy fallback) or none. Use describe_tools to get schemas.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in SearchIn) (*mcp.CallToolResult, any, error) {
		res, mode := g.searchMode(agent, in)
		g.store.RecordSearch(agent.ID, in.Query, in.Server, mode)
		g.audit(agent, "search_tools", in.Server, in, "ok", 0, fmt.Sprintf("%d results (%s)", len(res), mode))
		out := map[string]any{"results": res, "match": mode}
		switch mode {
		case SearchLoose:
			out["note"] = "No tool matched all keywords; these are partial or fuzzy matches. Check the descriptions before calling, or search again with other words."
		case SearchNone:
			out["note"] = g.missNote(agent, in)
		}
		return jsonResult(out), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "describe_tools",
		Description: "Get the full input schema and annotations of one or more tools (server.tool).",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in DescribeIn) (*mcp.CallToolResult, any, error) {
		var out []any
		for _, full := range in.Tools {
			srv, t, err := g.resolveTool(agent, full)
			if err != nil {
				out = append(out, map[string]any{"tool": full, "error": err.Error()})
				continue
			}
			m := map[string]any{"tool": srv.ID + "." + t.Name, "description": purposePrefix(srv) + t.Description,
				"inputSchema": t.Schema, "annotations": t.Annotations}
			if srv.Purpose != "" {
				m["connection_purpose"] = srv.Purpose
			}
			out = append(out, m)
		}
		g.audit(agent, "describe_tools", "", in, "ok", 0, "")
		return jsonResult(out), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "call_tool",
		Description: "Run a tool on an upstream server. tool = \"server.tool\" (see search_tools), arguments = object matching its input schema. If the server needs a sign-in, the result contains a login link to give to the user.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in CallIn) (*mcp.CallToolResult, any, error) {
		return g.Call(ctx, agent, in.Tool, in.Arguments), nil, nil
	})

	g.addManage(s, agent)
	return s
}

func (g *Gateway) addManage(s *mcp.Server, agent *Agent) {
	if agent.CanManage {
		mcp.AddTool(s, &mcp.Tool{
			Name: "manage",
			Description: "Configure the gateway. Actions: list_servers | get_server{id} | upsert_server{server} | remove_server{id} | set_enabled{id,enabled} | " +
				"set_tool_policy{id,allow,deny} | connect{id} (returns status or an OAuth login link for the user) | disconnect{id} | reset_auth{id} | refresh_tools{id} | " +
				"catalog_search{query,source} | catalog_install{catalog_id,id,params} | catalog_add{entry} | list_secrets | set_secret{id,value,note} (write-only) | " +
				"request_secret{id,note} (returns a UI link where the user types the value) | audit{limit,query}. " +
				"Reference secrets in configs as ${secret:NAME}. Never ask the user to paste secrets into chat if request_secret can be used. " +
				"Safety rules: changes to what a server runs or where it sends credentials wait for the user's approval (you get a link to pass on); agents can create but not overwrite secrets, can hide but not un-hide tools, and can turn servers off but not on.",
		}, func(ctx context.Context, req *mcp.CallToolRequest, in ManageIn) (*mcp.CallToolResult, any, error) {
			start := time.Now()
			res := g.manage(ctx, agent, in)
			status := "ok"
			if res.IsError {
				status = "error"
			}
			safe := in
			safe.Value = ""
			g.audit(agent, "manage."+in.Action, firstNonEmpty(in.ID, in.CatalogID), safe, status, time.Since(start).Milliseconds(), resultText(res, 300))
			return res, nil, nil
		})
	}
}

func ptr[T any](v T) *T { return &v }

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

func resultText(r *mcp.CallToolResult, n int) string {
	var b strings.Builder
	for _, c := range r.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			b.WriteString(t.Text)
		}
	}
	return truncate(b.String(), n)
}

// ---- search ----

func splitTool(full string) (string, string, error) {
	i := strings.Index(full, ".")
	if i <= 0 || i == len(full)-1 {
		return "", "", fmt.Errorf("tool name must look like server.tool, got %q", full)
	}
	return full[:i], full[i+1:], nil
}

func (g *Gateway) resolveTool(agent *Agent, full string) (*ServerConfig, *CachedTool, error) {
	sid, tname, err := splitTool(full)
	if err != nil {
		return nil, nil, err
	}
	srv, err := g.store.GetServer(sid)
	if err != nil {
		return nil, nil, err
	}
	if d := Decide(agent, srv, tname); !d.Allowed {
		return nil, nil, fmt.Errorf("tool %s is not allowed: %s", full, d.Reason)
	}
	tools, _ := g.store.Tools(sid)
	for i := range tools {
		if tools[i].Name == tname {
			if tools[i].Pending != "" {
				return srv, nil, &ToolPendingError{Server: sid, Tool: tname, Kind: tools[i].Pending, Link: g.approvalLink(sid)}
			}
			return srv, &tools[i], nil
		}
	}
	return srv, nil, fmt.Errorf("tool %s not found (server tools may need refresh: manage action=refresh_tools)", full)
}

// Call runs an upstream tool with policy and audit. agent may be a synthetic
// UI agent for testing.
func (g *Gateway) Call(ctx context.Context, agent *Agent, full string, args map[string]any) *mcp.CallToolResult {
	start := time.Now()
	finish := func(r *mcp.CallToolResult, status, detail string) *mcp.CallToolResult {
		g.audit(agent, "call_tool", full, args, status, time.Since(start).Milliseconds(), detail)
		return r
	}
	sid, tname, err := splitTool(full)
	if err != nil {
		return finish(errResult("%v", err), "error", err.Error())
	}
	srv, err := g.store.GetServer(sid)
	if err != nil {
		return finish(errResult("%v", err), "error", err.Error())
	}
	if d := Decide(agent, srv, tname); !d.Allowed {
		return finish(errResult("Tool %s is blocked by gateway policy: %s", full, d.Reason), "denied", d.Reason)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	err = g.ensureToolApproved(ctx, sid, tname)
	var res *mcp.CallToolResult
	if err == nil {
		res, err = g.mgr.CallTool(ctx, sid, tname, args)
	}
	var tpe *ToolPendingError
	var tnf *toolNotFoundError
	var are *AuthRequiredError
	var mse *MissingSecretsError
	var pae *PendingApprovalError
	var oce *OAuthClientRequiredError
	switch {
	case errors.As(err, &tpe):
		what := "changed its description or input schema since the user approved it"
		if tpe.Kind == ToolNew {
			what = "is new on this server"
		}
		return finish(errResult("Tool %s %s, so the gateway hides it until the user reviews the change. Ask the user to review and approve it here, then retry:\n%s", full, what, tpe.Link), "pending_approval", "tool "+tpe.Kind)
	case errors.As(err, &tnf):
		return finish(errResult("%v", err), "error", err.Error())
	case errors.As(err, &oce):
		return finish(errResult("Server %q can't sign in yet: the service doesn't support automatic OAuth registration, so the user must register an OAuth client once and enter its client ID and secret here (the page shows the steps), then retry:\n%s", sid, g.baseURL+"/ui/#c/"+sid+"?tab=settings"), "error", "oauth client required")
	case errors.As(err, &pae):
		return finish(errResult("Server %q has configuration changes waiting for the user's approval. Ask the user to review and approve them here, then retry:\n%s", sid, pae.Link), "pending_approval", "")
	case errors.As(err, &are):
		return finish(errResult("Server %q needs the user to sign in. Show the user this link and ask them to open it, then retry the same call:\n%s", sid, are.URL), "auth_required", "")
	case errors.As(err, &mse):
		return finish(errResult("Server %q is missing secrets %s. Ask the user to enter them here: %s", sid, strings.Join(mse.Names, ", "), g.secretLink(mse.Names[0], "")), "error", mse.Error())
	case err != nil:
		return finish(errResult("Upstream error from %s: %v", sid, err), "error", err.Error())
	}
	status := "ok"
	if res.IsError {
		status = "tool_error"
	}
	return finish(res, status, resultText(res, 300))
}

func (g *Gateway) secretLink(name, note string) string {
	u := g.baseURL + "/ui/#secrets?new=" + name
	if note != "" {
		u += "&note=" + strings.ReplaceAll(note, " ", "+")
	}
	return u
}

var sensitiveKey = regexp.MustCompile(`(?i)(pass|secret|token|key|auth|credential|cookie)`)

func redact(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range x {
			if sensitiveKey.MatchString(k) {
				out[k] = "[redacted]"
			} else {
				out[k] = redact(val)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = redact(x[i])
		}
		return out
	}
	return v
}

func (g *Gateway) audit(agent *Agent, action, target string, args any, status string, ms int64, detail string) {
	var a any = args
	if b, err := json.Marshal(args); err == nil {
		var generic any
		if json.Unmarshal(b, &generic) == nil {
			a = redact(generic)
		}
	}
	if privacyScoped(action) {
		mode := g.store.AuditArgsMode()
		a = shapeAuditArgs(mode, a)
		if dropsResultDetail(mode, action, status) {
			detail = ""
		}
	}
	b, _ := json.Marshal(a)
	name := "unknown"
	if agent != nil {
		name = agent.ID
	}
	g.store.Audit(AuditEntry{Agent: name, Action: action, Target: target, Args: truncate(string(b), 2000),
		Status: status, DurationMS: ms, Detail: detail})
}

type toolNotFoundError struct{ full string }

func (e *toolNotFoundError) Error() string {
	return fmt.Sprintf("tool %s not found on the server (use search_tools to find the right name)", e.full)
}

// ensureToolApproved makes sure the tool is known (indexed) and its current
// description/schema is the version the user approved. Unknown tools are
// looked up once by connecting/re-indexing; they are never forwarded blindly.
func (g *Gateway) ensureToolApproved(ctx context.Context, sid, tname string) error {
	find := func() *CachedTool {
		tools, _ := g.store.Tools(sid)
		for i := range tools {
			if tools[i].Name == tname {
				return &tools[i]
			}
		}
		return nil
	}
	t := find()
	if t == nil {
		// the first connect indexes the tools; otherwise re-index once
		if _, err := g.mgr.Session(ctx, sid); err != nil {
			return err
		}
		if t = find(); t == nil {
			if _, err := g.mgr.Refresh(ctx, sid); err != nil {
				return err
			}
			t = find()
		}
		if t == nil {
			return &toolNotFoundError{full: sid + "." + tname}
		}
	}
	if t.Pending != "" {
		return &ToolPendingError{Server: sid, Tool: tname, Kind: t.Pending, Link: g.approvalLink(sid)}
	}
	return nil
}
