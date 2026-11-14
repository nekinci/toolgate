package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (g *Gateway) manage(ctx context.Context, agent *Agent, in ManageIn) *mcp.CallToolResult {
	switch in.Action {
	case "list_servers":
		servers, _ := g.store.ListServers()
		var out []any
		for _, s := range servers {
			t, _ := g.store.Tools(s.ID)
			row := map[string]any{"id": s.ID, "name": s.Name, "transport": s.Transport, "enabled": s.Enabled,
				"status": g.mgr.Status(s.ID).Status, "tools": len(t), "missing_secrets": g.mgr.missingSecrets(s)}
			if p := len(g.store.PendingToolChanges(s)); p > 0 {
				row["tools_pending_review"] = p
				row["review_link"] = g.approvalLink(s.ID)
			}
			out = append(out, row)
		}
		return jsonResult(out)

	case "get_server":
		s, err := g.store.GetServer(in.ID)
		if err != nil {
			return errResult("%v", err)
		}
		st := g.mgr.Status(s.ID)
		st.Stderr = truncateTail(st.Stderr, 1500)
		return jsonResult(map[string]any{"config": s, "status": st, "required_secrets": RequiredSecrets(s), "missing_secrets": g.mgr.missingSecrets(s)})

	case "upsert_server":
		if in.Server == nil {
			return errResult("upsert_server needs server")
		}
		cfg := *in.Server
		cfg.CatalogID = ""
		cfg.Purpose = "" // user-owned: shown to every agent, so agents can't write it
		if cfg.Transport == "builtin" {
			return errResult("built-in servers are managed by the gateway itself")
		}
		if old, err := g.store.GetServer(cfg.ID); err == nil && old.Transport == "builtin" {
			return errResult("%s is a built-in server; it can't be replaced (use set_enabled or set_tool_policy)", cfg.ID)
		}
		if old, err := g.store.GetServer(cfg.ID); err == nil {
			// Agents may not loosen what the user set: keep enabled state and
			// tool filters of an existing server.
			cfg.Enabled = old.Enabled
			cfg.AllowTools, cfg.DenyTools = old.AllowTools, old.DenyTools
			cfg.CatalogID = old.CatalogID
			cfg.Purpose = old.Purpose
			if in.Enabled != nil && !*in.Enabled {
				cfg.Enabled = false
			}
		} else {
			cfg.Enabled = in.Enabled == nil || *in.Enabled
		}
		if err := g.store.PutServer(&cfg); err != nil {
			return errResult("%v", err)
		}
		g.mgr.Disconnect(cfg.ID)
		if !g.store.IsApproved(&cfg) {
			return g.pendingResult(&cfg)
		}
		return g.afterSave(ctx, &cfg)

	case "remove_server":
		if old, err := g.store.GetServer(in.ID); err != nil {
			return errResult("%v", err)
		} else if old.Transport == "builtin" {
			return errResult("%s is a built-in server; agents can disable it (set_enabled) but not remove it", in.ID)
		}
		g.mgr.Disconnect(in.ID)
		if err := g.store.DeleteServer(in.ID); err != nil {
			return errResult("%v", err)
		}
		return textResult("removed %s", in.ID)

	case "set_enabled":
		s, err := g.store.GetServer(in.ID)
		if err != nil {
			return errResult("%v", err)
		}
		if in.Enabled == nil {
			return errResult("set_enabled needs enabled")
		}
		if *in.Enabled && !s.Enabled {
			return errResult("Only the user can turn a server back on. Ask them to enable it here: %s", g.approvalLink(s.ID))
		}
		s.Enabled = *in.Enabled
		if err := g.store.PutServer(s); err != nil {
			return errResult("%v", err)
		}
		if !s.Enabled {
			g.mgr.Disconnect(s.ID)
		}
		return textResult("%s enabled=%v", s.ID, s.Enabled)

	case "set_tool_policy":
		s, err := g.store.GetServer(in.ID)
		if err != nil {
			return errResult("%v", err)
		}
		next := *s
		next.AllowTools, next.DenyTools = in.Allow, in.Deny
		if newly := newlyExposed(g.store, s, &next); len(newly) > 0 {
			return errResult("Agents can only hide tools, not un-hide them (would expose: %s). Ask the user to change it here: %s", strings.Join(newly, ", "), g.approvalLink(s.ID))
		}
		if err := g.store.PutServer(&next); err != nil {
			return errResult("%v", err)
		}
		return textResult("policy for %s: allow=%v deny=%v", s.ID, next.AllowTools, next.DenyTools)

	case "connect", "refresh_tools":
		s, err := g.store.GetServer(in.ID)
		if err != nil {
			return errResult("%v", err)
		}
		return g.connectResult(ctx, s)

	case "disconnect":
		g.mgr.Disconnect(in.ID)
		return textResult("disconnected %s", in.ID)

	case "reset_auth":
		g.mgr.ForgetOAuth(in.ID)
		return textResult("stored OAuth tokens for %s deleted; next connect starts a new login", in.ID)

	case "catalog_search":
		limit := in.Limit
		if limit <= 0 {
			limit = 12
		}
		r := g.catalog.Search(ctx, in.Query, in.Source, 0, limit)
		res := map[string]any{"entries": compactEntries(r.Entries), "total": r.Total,
			"note": "source: all (builtin + user + Claude directory, default), registry (open community registry). Install with catalog_install{catalog_id, auth, params}."}
		if len(r.Errors) > 0 {
			res["source_errors"] = r.Errors
		}
		return jsonResult(res)

	case "catalog_install":
		if in.CatalogID == "" {
			return errResult("catalog_install needs catalog_id")
		}
		entry, err := g.catalog.Get(ctx, in.CatalogID)
		if err != nil {
			return errResult("%v", err)
		}
		uiLink := g.baseURL + "/ui/#catalog?install=" + url.QueryEscape(entry.ID)
		for _, o := range entry.authOptions() {
			if (in.Auth == "" || in.Auth == o.ID) && o.Kind == "oauth_app" && in.Params["client_id"] == "" {
				return textResult("%s needs a one-time OAuth app registration (%s). Give the user this link; the gateway UI walks them through it and opens the sign-in:\n%s\nAlternatively install with a different auth option (see catalog_search auth_options).", entry.Name, o.Label, uiLink)
			}
			if in.Auth == "" || in.Auth == o.ID {
				break
			}
		}
		for k, v := range in.Params {
			if strings.Contains(v, "${secret:") {
				return errResult("parameter %q may not reference vault secrets", k)
			}
		}
		// Never let an agent overwrite or silently reuse an existing secret.
		reused := false
		for p, name := range entry.secretParamNames(in.ID, in.Auth) {
			if g.vault.Has(name) {
				if in.Params[p] != "" {
					return errResult("secret %s already exists; only the user can change it in the UI: %s", name, g.secretLink(name, ""))
				}
				reused = true
			}
		}
		cfg, missing, err := g.catalog.Install(entry, in.ID, in.Auth, in.Params)
		if err != nil {
			return errResult("%v\nThe user can also finish the setup in the UI: %s", err, uiLink)
		}
		g.mgr.Disconnect(cfg.ID)
		// Auto-approve only remote servers from trusted catalogs whose address
		// the agent could not choose freely; everything else waits for the user.
		safe := (entry.Source == "builtin" || entry.Source == "claude") && cfg.Transport == "http" &&
			entry.urlIsFixed(in.Auth, in.Params) && !reused
		if safe {
			_ = g.store.PutApproval(cfg, "auto:"+agent.ID)
		} else {
			if len(missing) > 0 {
				return textResult("Installed %q as server %s. Before it can run, the user must (1) approve it and (2) enter missing secrets %s, both here: %s",
					entry.Name, cfg.ID, strings.Join(missing, ", "), g.approvalLink(cfg.ID))
			}
			return g.pendingResult(cfg)
		}
		if len(missing) > 0 {
			var links []string
			for _, m := range missing {
				links = append(links, fmt.Sprintf("- %s: %s", m, g.secretLink(m, entry.Name)))
			}
			return textResult("Installed %q as server %s, but it needs secrets the user must enter in the gateway UI (do not ask for them in chat):\n%s\nAfter the user saves them, call manage action=connect id=%s.",
				entry.Name, cfg.ID, strings.Join(links, "\n"), cfg.ID)
		}
		return g.afterSave(ctx, cfg)

	case "catalog_add":
		if in.Entry == nil {
			return errResult("catalog_add needs entry")
		}
		e := *in.Entry
		e.AddedBy = agent.ID
		if err := g.catalog.AddUser(&e); err != nil {
			return errResult("%v", err)
		}
		return textResult("added catalog entry %s", e.ID)

	case "list_secrets":
		list, err := g.vault.List(false)
		if err != nil {
			return errResult("%v", err)
		}
		return jsonResult(map[string]any{"secrets": list, "note": "values are never returned"})

	case "set_secret":
		if in.ID == "" || in.Value == "" {
			return errResult("set_secret needs id (name) and value")
		}
		if strings.HasPrefix(in.ID, "oauth:") {
			return errResult("oauth:* secrets are managed by the gateway")
		}
		if g.vault.Has(in.ID) {
			return errResult("secret %s already exists. Agents can only create new secrets; ask the user to change it here: %s", in.ID, g.secretLink(in.ID, ""))
		}
		if err := g.vault.Set(in.ID, in.Value, false, in.Note); err != nil {
			return errResult("%v", err)
		}
		return textResult("secret %s saved (write-only). Reference it as ${secret:%s}", in.ID, in.ID)

	case "request_secret":
		if !secretNameRe.MatchString(in.ID) {
			return errResult("request_secret needs a valid id (secret name)")
		}
		return textResult("Ask the user to open this link and enter the value for %s:\n%s\nReference it in configs as ${secret:%s}.", in.ID, g.secretLink(in.ID, in.Note), in.ID)

	case "audit":
		list, err := g.store.ListAudit(in.Limit, "", in.Query)
		if err != nil {
			return errResult("%v", err)
		}
		return jsonResult(list)
	}
	return errResult("unknown action %q", in.Action)
}

func (g *Gateway) pendingResult(cfg *ServerConfig) *mcp.CallToolResult {
	return textResult("Saved %s, but it changes what runs or where credentials are sent, so it is waiting for the user's approval. "+
		"Give the user this link to review and approve it; it starts working right after:\n%s", cfg.ID, g.approvalLink(cfg.ID))
}

// newlyExposed lists upstream tools that `next` would expose but `cur` hides.
func newlyExposed(store *Store, cur, next *ServerConfig) []string {
	tools, _ := store.Tools(cur.ID)
	var out []string
	for _, t := range tools {
		if !Decide(nil, cur, t.Name).Allowed && Decide(nil, next, t.Name).Allowed {
			out = append(out, t.Name)
		}
	}
	if len(tools) == 0 && (len(cur.DenyTools) > 0 || len(cur.AllowTools) > 0) {
		// Without a tool list we can't compare; only allow pure additions to deny.
		for _, d := range cur.DenyTools {
			if !anyMatch(next.DenyTools, d) {
				out = append(out, d)
			}
		}
		if len(next.AllowTools) == 0 && len(cur.AllowTools) > 0 {
			out = append(out, "(allow list removed)")
		}
	}
	return out
}

func (g *Gateway) afterSave(ctx context.Context, cfg *ServerConfig) *mcp.CallToolResult {
	if !cfg.Enabled {
		return textResult("saved %s (disabled)", cfg.ID)
	}
	if missing := g.mgr.missingSecrets(cfg); len(missing) > 0 {
		var links []string
		for _, m := range missing {
			links = append(links, fmt.Sprintf("- %s: %s", m, g.secretLink(m, cfg.Name)))
		}
		return textResult("saved %s. Missing secrets the user must enter:\n%s", cfg.ID, strings.Join(links, "\n"))
	}
	r := g.connectResult(ctx, cfg)
	r.Content = append([]mcp.Content{&mcp.TextContent{Text: "saved " + cfg.ID + "."}}, r.Content...)
	return r
}

func (g *Gateway) connectResult(ctx context.Context, s *ServerConfig) *mcp.CallToolResult {
	n, err := g.mgr.Refresh(ctx, s.ID)
	var are *AuthRequiredError
	var mse *MissingSecretsError
	var pae *PendingApprovalError
	var oce *OAuthClientRequiredError
	if err == nil && g.mgr.NeedsLogin(s) {
		lctx, cancel := context.WithTimeout(ctx, 50*time.Second)
		err = g.mgr.Login(lctx, s.ID)
		cancel()
	}
	switch {
	case errors.As(err, &oce):
		return errResult("%s can't sign in automatically: the user must register an OAuth client once and enter its client ID and secret here (steps are shown): %s", s.ID, g.baseURL+"/ui/#c/"+s.ID+"?tab=settings")
	case errors.As(err, &pae):
		return g.pendingResult(s)
	case errors.As(err, &are):
		return textResult("Server %s needs the user to sign in. Give the user this link; the gateway finishes the connection automatically when they complete it:\n%s", s.ID, are.URL)
	case errors.As(err, &mse):
		return errResult("Missing secrets %s. User can enter them at %s", strings.Join(mse.Names, ", "), g.secretLink(mse.Names[0], s.Name))
	case err != nil:
		st := g.mgr.Status(s.ID)
		msg := fmt.Sprintf("connect failed: %v", err)
		if st.Stderr != "" {
			msg += "\nserver stderr (tail):\n" + truncateTail(st.Stderr, 1200)
		}
		return errResult("%s", msg)
	}
	tools, _ := g.store.Tools(s.ID)
	var names, pending []string
	for _, t := range tools {
		if !Decide(nil, s, t.Name).Allowed {
			continue
		}
		if t.Pending != "" {
			pending = append(pending, t.Name)
		} else {
			names = append(names, t.Name)
		}
	}
	msg := fmt.Sprintf("connected %s: %d tools (%d exposed): %s", s.ID, n, len(names), strings.Join(names, ", "))
	if len(pending) > 0 {
		msg += fmt.Sprintf("\n%d new or changed tools (%s) are hidden until the user reviews them here: %s", len(pending), strings.Join(pending, ", "), g.approvalLink(s.ID))
	}
	return textResult("%s", msg)
}

func truncateTail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
