package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// How upstream tools are presented to an agent:
//
//   - lazy:   5 meta tools (overview, search_tools, describe_tools, call_tool,
//     manage). Tiny context, the agent discovers tools on demand.
//   - direct: every tool the agent may use is a native MCP tool named
//     <server>__<tool>, with its real schema. No discovery step, but the
//     whole list sits in the agent's context.
//   - auto:   direct while the agent sees at most AutoDirectMaxTools tools,
//     lazy above that.
//
// The mode comes from (first match): ?tools= on the /mcp URL, the agent's
// own setting, the gateway default (panel; lazy unless changed). Policy,
// pinning, approval and audit are identical in every mode: direct tools call
// the same Gateway.Call as call_tool.

const (
	ToolModeLazy   = "lazy"
	ToolModeDirect = "direct"
	ToolModeAuto   = "auto"

	AutoDirectMaxTools = 40
	// DirectMaxTools caps native tools in direct mode; the rest stay
	// reachable through search_tools / call_tool, which are then added.
	DirectMaxTools = 128
)

func validToolMode(m string) bool {
	return m == ToolModeLazy || m == ToolModeDirect || m == ToolModeAuto
}

func (s *Store) ToolModeDefault() string {
	if m := s.Meta("tool_mode_default"); validToolMode(m) {
		return m
	}
	return ToolModeLazy
}

func (s *Store) SetToolModeDefault(m string) error {
	if !validToolMode(m) {
		return fmt.Errorf("tool mode must be lazy, direct or auto")
	}
	s.SetMeta("tool_mode_default", m)
	return nil
}

// configuredMode is the mode before "auto" is resolved.
func (g *Gateway) configuredMode(agent *Agent, override string) string {
	switch {
	case validToolMode(override):
		return override
	case agent != nil && validToolMode(agent.ToolMode):
		return agent.ToolMode
	}
	return g.store.ToolModeDefault()
}

// EffectiveToolMode resolves auto into lazy or direct.
func (g *Gateway) EffectiveToolMode(agent *Agent, override string) string {
	m := g.configuredMode(agent, override)
	if m == ToolModeAuto {
		if len(g.directTools(agent)) <= AutoDirectMaxTools {
			return ToolModeDirect
		}
		return ToolModeLazy
	}
	return m
}

type directTool struct {
	Name   string // MCP name, e.g. github__create_issue
	Full   string // gateway name, e.g. github.create_issue
	Server *ServerConfig
	Tool   CachedTool
}

var toolNameBad = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// directName maps server + tool to a name every MCP client accepts
// (^[a-zA-Z0-9_-]{1,64}$). Overlong names keep a hash suffix.
func directName(server, tool string) string {
	n := toolNameBad.ReplaceAllString(server, "_") + "__" + toolNameBad.ReplaceAllString(tool, "_")
	if len(n) > 64 {
		h := sha256.Sum256([]byte(server + "." + tool))
		n = n[:55] + "_" + hex.EncodeToString(h[:])[:8]
	}
	return n
}

// directTools lists what an agent may call right now: enabled, approved
// servers; allowed by policy; not waiting for review. Sorted by name.
func (g *Gateway) directTools(agent *Agent) []directTool {
	servers, _ := g.store.ListServers()
	byID := map[string]*ServerConfig{}
	for _, s := range servers {
		if s.Enabled && ServerVisible(agent, s) && g.store.IsApproved(s) {
			byID[s.ID] = s
		}
	}
	all, _ := g.store.Tools("")
	var out []directTool
	used := map[string]bool{}
	for _, t := range all {
		srv := byID[t.ServerID]
		if srv == nil || t.Pending != "" || !Decide(agent, srv, t.Name).Allowed {
			continue
		}
		base := directName(srv.ID, t.Name)
		name := base
		for i := 2; used[name]; i++ { // a_b + c and a + b_c can collide
			name = fmt.Sprintf("%s_%d", base[:min(len(base), 60)], i)
		}
		used[name] = true
		out = append(out, directTool{Name: name, Full: srv.ID + "." + t.Name, Server: srv, Tool: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// objectSchema returns the upstream schema as an object schema the SDK
// accepts (some servers send {} or omit "type").
func objectSchema(raw json.RawMessage) map[string]any {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil || m == nil {
		m = map[string]any{}
	}
	if m["type"] != "object" {
		m["type"] = "object"
	}
	return m
}

func (d directTool) mcpTool() *mcp.Tool {
	t := &mcp.Tool{
		Name:        d.Name,
		Title:       firstNonEmpty(d.Server.Name, d.Server.ID) + ": " + d.Tool.Name,
		Description: purposePrefix(d.Server) + d.Tool.Description,
		InputSchema: objectSchema(d.Tool.Schema),
	}
	if len(d.Tool.Annotations) > 0 {
		var a mcp.ToolAnnotations
		if json.Unmarshal(d.Tool.Annotations, &a) == nil {
			a.Title = ""
			t.Annotations = &a
		}
	}
	return t
}

// addDirectTools registers native tools; it reports whether the cap cut the
// list (then the caller keeps the lazy meta tools as a way to the rest).
func (g *Gateway) addDirectTools(s *mcp.Server, agent *Agent) (capped bool) {
	tools := g.directTools(agent)
	if len(tools) > DirectMaxTools {
		tools, capped = tools[:DirectMaxTools], true
	}
	for _, d := range tools {
		full := d.Full
		s.AddTool(d.mcpTool(), func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var args map[string]any
			if raw := req.Params.Arguments; len(raw) > 0 && string(raw) != "null" {
				if err := json.Unmarshal(raw, &args); err != nil {
					return errResult("arguments must be a JSON object: %v", err), nil
				}
			}
			return g.Call(ctx, agent, full, args), nil
		})
	}
	return capped
}

// ModeFootprint measures what an agent's tools/list costs in each mode by
// listing tools from an in-memory session, exactly as a client would see it.
type ModeFootprint struct {
	Tools int `json:"tools"`
	Bytes int `json:"bytes"`
}

func (g *Gateway) measureMode(ctx context.Context, agent *Agent, mode string) (ModeFootprint, error) {
	srv := g.ServerFor(agent, mode)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		return ModeFootprint{}, err
	}
	defer ss.Close()
	cl := mcp.NewClient(&mcp.Implementation{Name: "measure", Version: "0"}, nil)
	cs, err := cl.Connect(ctx, ct, nil)
	if err != nil {
		return ModeFootprint{}, err
	}
	defer cs.Close()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		return ModeFootprint{}, err
	}
	b, _ := json.Marshal(res.Tools)
	init := cs.InitializeResult()
	n := len(b)
	if init != nil {
		n += len(init.Instructions)
	}
	return ModeFootprint{Tools: len(res.Tools), Bytes: n}, nil
}
