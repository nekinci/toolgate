package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func listToolNames(t *testing.T, g *Gateway, a *Agent, override string) ([]string, *mcp.ClientSession) {
	t.Helper()
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := g.ServerFor(a, override).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range res.Tools {
		names = append(names, x.Name)
	}
	sort.Strings(names)
	return names, cs
}

func TestDirectName(t *testing.T) {
	if n := directName("cloudflare-api", "dns.records/list"); n != "cloudflare-api__dns_records_list" {
		t.Fatal(n)
	}
	long := directName("a-very-long-server-name-here", strings.Repeat("x", 80))
	if len(long) != 64 || long == directName("a-very-long-server-name-here", strings.Repeat("x", 81)) {
		t.Fatalf("long name %q (%d)", long, len(long))
	}
}

func TestToolModes(t *testing.T) {
	g := pinTestServer(t) // gh: create_issue, list ({} schema)
	a := &Agent{ID: "bot", CanManage: true}

	lazy, _ := listToolNames(t, g, a, "")
	if strings.Join(lazy, ",") != "call_tool,describe_tools,manage,overview,search_tools" {
		t.Fatalf("default should be lazy: %v", lazy)
	}
	a.ToolMode = ToolModeDirect
	direct, cs := listToolNames(t, g, a, "")
	if strings.Join(direct, ",") != "gh__create_issue,gh__list,manage,overview" {
		t.Fatalf("direct: %v", direct)
	}
	if strings.Contains(cs.InitializeResult().Instructions, "search_tools (find)") {
		t.Fatal("direct-mode instructions still describe the lazy workflow")
	}
	// ?tools= override wins over the agent setting
	if names, _ := listToolNames(t, g, a, "lazy"); len(names) != 5 {
		t.Fatalf("override: %v", names)
	}
	// a direct call goes through Gateway.Call: audited as call_tool on gh.create_issue
	_, _ = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "gh__create_issue", Arguments: map[string]any{"title": "x"}})
	list, _ := g.store.ListAudit(5, "bot", "")
	if len(list) == 0 || list[0].Action != "call_tool" || list[0].Target != "gh.create_issue" {
		t.Fatalf("direct call not routed through Call: %+v", list)
	}

	// policy and pinning apply: denied and pending tools are not listed
	a.Deny = []string{"gh.list"}
	index(g.store, "gh", false,
		CachedTool{Name: "create_issue", Description: "Create an issue", Schema: json.RawMessage(`{"type":"object","properties":{"title":{"type":"string"}}}`)},
		CachedTool{Name: "list", Description: "List things", Schema: json.RawMessage(`{}`)},
		CachedTool{Name: "sneaky", Description: "new tool", Schema: json.RawMessage(`{}`)})
	if names, _ := listToolNames(t, g, a, ""); strings.Join(names, ",") != "gh__create_issue,manage,overview" {
		t.Fatalf("policy/pending leak: %v", names)
	}

	// auto: direct while small
	a.ToolMode = ToolModeAuto
	if m := g.EffectiveToolMode(a, ""); m != ToolModeDirect {
		t.Fatalf("auto small = %s", m)
	}
	// gateway default applies when the agent has none
	a.ToolMode = ""
	_ = g.store.SetToolModeDefault(ToolModeDirect)
	if m := g.EffectiveToolMode(a, ""); m != ToolModeDirect {
		t.Fatalf("default = %s", m)
	}
}

func TestDirectModeCap(t *testing.T) {
	g := testGateway(t)
	s := &ServerConfig{ID: "big", Transport: "http", URL: "https://x/mcp", Enabled: true}
	_ = g.store.PutServer(s)
	_ = g.approve(s, "admin-ui")
	var tools []CachedTool
	for i := 0; i < DirectMaxTools+5; i++ {
		tools = append(tools, CachedTool{Name: fmt.Sprintf("t%03d", i), Description: "d", Schema: json.RawMessage(`{"type":"object"}`)})
	}
	index(g.store, "big", false, tools...)
	a := &Agent{ID: "bot", ToolMode: ToolModeAuto}
	if m := g.EffectiveToolMode(a, ""); m != ToolModeLazy {
		t.Fatalf("auto with many tools = %s", m)
	}
	a.ToolMode = ToolModeDirect
	names, cs := listToolNames(t, g, a, "")
	if len(names) != DirectMaxTools+4 { // + overview, search_tools, describe_tools, call_tool
		t.Fatalf("capped direct lists %d tools", len(names))
	}
	if !strings.Contains(cs.InitializeResult().Instructions, "only the first") {
		t.Fatal("cap not explained in instructions")
	}
	fp, err := g.measureMode(context.Background(), a, ToolModeLazy)
	if err != nil || fp.Tools != 4 || fp.Bytes == 0 {
		t.Fatalf("measure lazy: %+v %v", fp, err)
	}
}
