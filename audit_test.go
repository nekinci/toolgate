package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func lastAudit(t *testing.T, g *Gateway, action string) AuditEntry {
	t.Helper()
	list, _ := g.store.ListAuditFiltered(50, "", action, "")
	for _, e := range list {
		if e.Action == action {
			return e
		}
	}
	t.Fatalf("no %s row", action)
	return AuditEntry{}
}

func TestAuditArgsModes(t *testing.T) {
	g := testGateway(t)
	if g.store.AuditArgsMode() != AuditArgsKeys {
		t.Fatal("default must be keys")
	}
	ag := &Agent{ID: "bot"}
	args := map[string]any{"title": "private title", "api_token": "tok", "arguments": map[string]any{"q": "hello"}}

	g.audit(ag, "call_tool", "x.y", args, "ok", 1, "result text with data")
	e := lastAudit(t, g, "call_tool")
	if strings.Contains(e.Args, "private") || strings.Contains(e.Args, "hello") || !strings.Contains(e.Args, `"title"`) || !strings.Contains(e.Args, `"q"`) || e.Detail != "" {
		t.Fatalf("keys mode stored %q / %q", e.Args, e.Detail)
	}
	g.audit(ag, "call_tool", "x.y", args, "error", 1, "upstream error")
	if e := lastAudit(t, g, "call_tool"); e.Detail != "upstream error" {
		t.Fatal("gateway errors keep their detail")
	}

	_ = g.store.SetAuditSettings(0, AuditArgsFull)
	g.audit(ag, "call_tool", "x.y", args, "ok", 1, "result")
	e = lastAudit(t, g, "call_tool")
	if !strings.Contains(e.Args, "private title") || strings.Contains(e.Args, `"tok"`) || e.Detail != "result" {
		t.Fatalf("full mode stored %q / %q", e.Args, e.Detail)
	}

	_ = g.store.SetAuditSettings(0, AuditArgsNone)
	g.audit(ag, "call_tool", "x.y", args, "ok", 1, "result")
	if e := lastAudit(t, g, "call_tool"); e.Args != "{}" {
		t.Fatalf("none mode stored %q", e.Args)
	}
	// config changes keep (masked) arguments regardless of mode
	g.audit(ag, "manage.upsert_server", "s", map[string]any{"url": "https://x"}, "ok", 1, "")
	if e := lastAudit(t, g, "manage.upsert_server"); !strings.Contains(e.Args, "https://x") {
		t.Fatalf("manage args must be kept: %q", e.Args)
	}

	// scrubbing rewrites the full-mode rows
	_ = g.store.SetAuditSettings(0, AuditArgsKeys)
	if n, err := g.store.ScrubAuditArgs(); err != nil || n == 0 {
		t.Fatalf("scrub: %d %v", n, err)
	}
	list, _ := g.store.ListAuditFiltered(100, "", "", "")
	for _, e := range list {
		if strings.Contains(e.Args, "private title") {
			t.Fatalf("scrub left %q", e.Args)
		}
	}
	if err := g.store.SetAuditSettings(0, "bogus"); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

func TestAuditRetention(t *testing.T) {
	g := testGateway(t)
	if d, fixed := g.store.AuditRetentionDays(); d != 90 || fixed {
		t.Fatalf("default retention = %d %v", d, fixed)
	}
	old := time.Now().Add(-100 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	mid := time.Now().Add(-20 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	g.store.Audit(AuditEntry{TS: old, Agent: "a", Action: "old", Args: "{}", Status: "ok"})
	g.store.Audit(AuditEntry{TS: mid, Agent: "a", Action: "mid", Args: "{}", Status: "ok"})
	g.store.Audit(AuditEntry{Agent: "a", Action: "new", Args: "{}", Status: "ok"})
	if n, _ := g.store.PruneAudit(); n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	if err := g.store.SetAuditSettings(10, ""); err != nil {
		t.Fatal(err)
	}
	if n, _ := g.store.PruneAudit(); n != 1 {
		t.Fatalf("pruned %d, want 1 (the 20-day-old row)", n)
	}
	if g.store.AuditSettings().Rows != 1 {
		t.Fatal("the fresh row must stay")
	}
	g.store.auditRetentionFlag = 30
	if d, fixed := g.store.AuditRetentionDays(); d != 30 || !fixed || g.store.SetAuditSettings(5, "") == nil {
		t.Fatal("flag must override and lock the setting")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g.store.RunAuditRetention(ctx, g.mgr.log) // returns after one pass
}
