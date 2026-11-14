package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func newToken(prefix string) string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

type Admin struct {
	g     *Gateway
	authn *AdminAuth
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	return dec.Decode(v)
}

func (a *Admin) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.authn.Authorized(r) {
			writeErr(w, http.StatusUnauthorized, errors.New("login required"))
			return
		}
		next(w, r)
	}
}

var uiAgent = &Agent{ID: "admin-ui", Name: "Admin UI", CanManage: true}

// UITestActor is the audit actor for tool calls made from the panel playground.
const UITestActor = "ui:test"

func (a *Admin) Register(mux *http.ServeMux) {
	h := func(pattern string, f http.HandlerFunc) { mux.HandleFunc(pattern, a.auth(f)) }
	g := a.g

	h("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		servers, _ := g.store.ListServers()
		agents, _ := g.store.ListAgents()
		tools, _ := g.store.Tools("")
		writeJSON(w, 200, map[string]any{"version": version, "servers": len(servers), "agents": len(agents), "tools": len(tools),
			"vault": g.vault.KeySource, "base_url": g.baseURL, "summaries": g.summaries(nil), "instructions": g.instructions(nil)})
	})

	// servers
	h("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		servers, err := g.store.ListServers()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		stats := g.store.ServerStats(24 * time.Hour)
		out := []map[string]any{}
		for _, s := range servers {
			t, _ := g.store.Tools(s.ID)
			exposed := 0
			for _, x := range t {
				if x.Pending == "" && Decide(nil, s, x.Name).Allowed {
					exposed++
				}
			}
			st := stats[s.ID]
			changes := g.store.PendingToolChanges(s)
			out = append(out, map[string]any{"tool_changes": changes, "tools_fingerprint": ToolsFingerprint(changes), "config": s, "status": g.mgr.Status(s.ID), "tool_count": len(t), "exposed_count": exposed,
				"missing_secrets": g.mgr.missingSecrets(s), "required_secrets": RequiredSecrets(s),
				"icon": g.catalog.IconFor(s), "calls_24h": st.Calls, "errors_24h": st.Errors, "last_call": st.Last,
				"has_oauth_token": g.vault.Has(oauthSecretName(s.ID)),
				"needs_login":     g.mgr.NeedsLogin(s), "pending_approval": !g.store.IsApproved(s), "fingerprint": Fingerprint(s), "approval_diff": pendingDiff(g.store, s), "approval": approvalInfo(g.store, s.ID)})
		}
		writeJSON(w, 200, out)
	})
	h("POST /api/servers", func(w http.ResponseWriter, r *http.Request) {
		var c ServerConfig
		if err := readJSON(r, &c); err != nil {
			writeErr(w, 400, err)
			return
		}
		old, oldErr := g.store.GetServer(c.ID)
		if err := g.store.PutServer(&c); err != nil {
			writeErr(w, 400, err)
			return
		}
		// Saving from the panel approves what the user just typed. Saving an
		// unchanged config (e.g. toggling enabled) must not silently approve
		// an agent's pending change.
		if oldErr != nil || Fingerprint(old) != Fingerprint(&c) {
			_ = g.approve(&c, "admin-ui")
		}
		g.mgr.Disconnect(c.ID)
		g.audit(uiAgent, "ui.upsert_server", c.ID, c, "ok", 0, "")
		writeJSON(w, 200, c)
	})
	h("DELETE /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		g.mgr.Disconnect(id)
		if err := g.store.DeleteServer(id); err != nil {
			writeErr(w, 500, err)
			return
		}
		g.audit(uiAgent, "ui.remove_server", id, nil, "ok", 0, "")
		writeJSON(w, 200, map[string]string{"ok": id})
	})
	h("POST /api/servers/{id}/connect", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		n, err := g.mgr.Refresh(ctx, id)
		var are *AuthRequiredError
		if errors.As(err, &are) {
			writeJSON(w, 200, map[string]any{"auth_url": are.URL})
			return
		}
		if err != nil {
			writeJSON(w, 200, map[string]any{"error": err.Error(), "status": g.mgr.Status(id)})
			return
		}
		writeJSON(w, 200, map[string]any{"tools": n})
	})
	h("POST /api/servers/{id}/login", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		err := g.mgr.Login(ctx, id)
		var are *AuthRequiredError
		var oce *OAuthClientRequiredError
		switch {
		case errors.As(err, &are):
			writeJSON(w, 200, map[string]any{"auth_url": are.URL})
		case errors.As(err, &oce):
			writeJSON(w, 200, map[string]any{"client_required": true, "error": "This service does not support automatic client registration; enter an OAuth client (Client ID and secret) first."})
		case err != nil:
			writeJSON(w, 200, map[string]any{"error": err.Error()})
		default:
			writeJSON(w, 200, map[string]any{"logged_in": true})
		}
	})
	h("POST /api/servers/{id}/oauth-client", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ClientID     string   `json:"client_id"`
			ClientSecret string   `json:"client_secret"`
			Scopes       []string `json:"scopes"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		c, err := g.SetOAuthClient(r.PathValue("id"), in.ClientID, in.ClientSecret, in.Scopes)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		g.audit(uiAgent, "ui.set_oauth_client", c.ID, map[string]any{"client_id": c.OAuthClientID}, "ok", 0, "")
		writeJSON(w, 200, map[string]any{"ok": c.ID})
	})
	h("POST /api/servers/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		c, err := g.store.GetServer(r.PathValue("id"))
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		var in struct {
			Fingerprint      string  `json:"fingerprint"`
			ToolsFingerprint *string `json:"tools_fingerprint"`
		}
		_ = readJSON(r, &in)
		if in.Fingerprint != "" && in.Fingerprint != Fingerprint(c) {
			writeErr(w, 409, errors.New("the configuration changed while you were reviewing it; reload the page and check again"))
			return
		}
		changes := g.store.PendingToolChanges(c)
		if in.ToolsFingerprint != nil && *in.ToolsFingerprint != ToolsFingerprint(changes) {
			writeErr(w, 409, errors.New("the tools changed again while you were reviewing them; reload the page and check again"))
			return
		}
		if !g.store.IsApproved(c) {
			if err := g.approve(c, "admin-ui"); err != nil {
				writeErr(w, 500, err)
				return
			}
		}
		pinned := 0
		if len(changes) > 0 {
			names := make([]string, 0, len(changes))
			for _, ch := range changes {
				names = append(names, ch.Name)
			}
			n, err := g.store.PinTools(c.ID, "admin-ui", names)
			if err != nil {
				writeErr(w, 500, err)
				return
			}
			pinned = n
		}
		g.audit(uiAgent, "ui.approve", c.ID, nil, "ok", 0, fmt.Sprintf("%d tools pinned", pinned))
		writeJSON(w, 200, map[string]any{"ok": c.ID, "tools_pinned": pinned})
	})
	h("POST /api/servers/{id}/reject", func(w http.ResponseWriter, r *http.Request) {
		c, err := g.store.GetServer(r.PathValue("id"))
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		var deleted bool
		if g.store.IsApproved(c) {
			// only tool changes are pending: keep those tools hidden for good
			// (added to deny_tools; the user can re-enable them in the tools tab)
			err = g.rejectToolChanges(c)
		} else {
			deleted, err = g.reject(c)
		}
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		g.audit(uiAgent, "ui.reject", c.ID, nil, "ok", 0, map[bool]string{true: "deleted", false: "reverted"}[deleted])
		writeJSON(w, 200, map[string]bool{"deleted": deleted})
	})
	h("POST /api/servers/{id}/disconnect", func(w http.ResponseWriter, r *http.Request) {
		g.mgr.Disconnect(r.PathValue("id"))
		writeJSON(w, 200, map[string]string{"ok": "disconnected"})
	})
	h("POST /api/servers/{id}/reset-auth", func(w http.ResponseWriter, r *http.Request) {
		g.mgr.ForgetOAuth(r.PathValue("id"))
		writeJSON(w, 200, map[string]string{"ok": "reset"})
	})
	h("GET /api/servers/{id}/tools", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		srv, err := g.store.GetServer(id)
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		tools, _ := g.store.Tools(id)
		out := []map[string]any{}
		for _, t := range tools {
			out = append(out, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": t.Schema,
				"annotations": t.Annotations, "exposed": Decide(nil, srv, t.Name).Allowed, "pending": t.Pending})
		}
		writeJSON(w, 200, out)
	})

	// secrets (values are write-only)
	h("GET /api/secrets", func(w http.ResponseWriter, r *http.Request) {
		list, err := g.vault.List(r.URL.Query().Get("system") == "1")
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		// also show referenced-but-missing secrets
		servers, _ := g.store.ListServers()
		have := map[string]bool{}
		for _, s := range list {
			have[s.Name] = true
		}
		usedBy := map[string][]string{}
		for _, s := range servers {
			for _, n := range RequiredSecrets(s) {
				usedBy[n] = append(usedBy[n], s.ID)
				if !have[n] {
					have[n] = true
					list = append(list, SecretMeta{Name: n, HasValue: false})
				}
			}
		}
		out := []map[string]any{}
		for _, s := range list {
			out = append(out, map[string]any{"name": s.Name, "system": s.System, "note": s.Note, "updated_at": s.UpdatedAt,
				"has_value": s.HasValue, "used_by": usedBy[s.Name]})
		}
		writeJSON(w, 200, out)
	})
	h("POST /api/secrets", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Name, Value, Note string }
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		if in.Value == "" {
			writeErr(w, 400, errors.New("value is empty"))
			return
		}
		if err := g.vault.Set(in.Name, in.Value, false, in.Note); err != nil {
			writeErr(w, 400, err)
			return
		}
		g.audit(uiAgent, "ui.set_secret", in.Name, nil, "ok", 0, "")
		if p := g.poolFor(in.Name); p != nil {
			p.KeyChanged(in.Name)
		}
		// servers waiting for this secret can connect now
		servers, _ := g.store.ListServers()
		for _, s := range servers {
			for _, n := range RequiredSecrets(s) {
				if n == in.Name {
					g.mgr.Disconnect(s.ID)
				}
			}
		}
		writeJSON(w, 200, map[string]string{"ok": in.Name})
	})
	h("DELETE /api/secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		n := r.PathValue("name")
		if err := g.vault.Delete(n); err != nil {
			writeErr(w, 500, err)
			return
		}
		g.audit(uiAgent, "ui.delete_secret", n, nil, "ok", 0, "")
		if p := g.poolFor(n); p != nil {
			p.KeyChanged(n)
		}
		writeJSON(w, 200, map[string]string{"ok": n})
	})

	// key pools (names and state only; values stay write-only)
	h("GET /api/pools", func(w http.ResponseWriter, r *http.Request) {
		out := []map[string]any{}
		apps, _ := g.store.ListProxyApps()
		for _, p := range g.pools.List() {
			cfg := p.Config()
			prov := providerFor(cfg.Provider)
			nApps := 0
			for _, a := range apps {
				if a.Allows(cfg.ID) {
					nApps++
				}
			}
			row := map[string]any{"config": cfg, "keys": p.Status(), "next_name": p.NextKeyName(), "can_check": p.CanCheck(),
				"provider": prov, "header": firstNonEmpty(cfg.Header, prov.Header), "apps": nApps}
			if cfg.ID == "gemini" && g.gemini != nil {
				srv, err := g.store.GetServer("gemini")
				row["output_dir"], row["server"], row["enabled"] = g.gemini.OutDir, err == nil, err == nil && srv.Enabled
			}
			out = append(out, row)
		}
		writeJSON(w, 200, map[string]any{"pools": out, "providers": poolProviders})
	})
	h("POST /api/pools", func(w http.ResponseWriter, r *http.Request) {
		var in PoolConfig
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		cfg, err := g.pools.Put(in)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		g.audit(uiAgent, "ui.put_pool", cfg.ID, cfg, "ok", 0, "")
		writeJSON(w, 200, cfg)
	})
	h("DELETE /api/pools/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := g.pools.Delete(id); err != nil {
			writeErr(w, 400, err)
			return
		}
		g.audit(uiAgent, "ui.delete_pool", id, nil, "ok", 0, "secrets kept")
		writeJSON(w, 200, map[string]string{"ok": id})
	})
	h("POST /api/pools/{id}/check", func(w http.ResponseWriter, r *http.Request) {
		p := g.pools.Get(r.PathValue("id"))
		var in struct{ Name string }
		if p == nil {
			writeErr(w, 404, errors.New("pool not found"))
			return
		}
		if err := readJSON(r, &in); err != nil || !p.Owns(in.Name) {
			writeErr(w, 400, errors.New("name must be a key of this pool"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		err := p.Check(ctx, in.Name)
		g.audit(uiAgent, "ui.pool_check", in.Name, nil, map[bool]string{true: "ok", false: "error"}[err == nil], 0, "")
		if err != nil {
			writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	// agents
	h("GET /api/agents", func(w http.ResponseWriter, r *http.Request) {
		list, err := g.store.ListAgents()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		if list == nil {
			list = []*Agent{}
		}
		writeJSON(w, 200, list)
	})
	h("POST /api/agents", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Agent
			Pair bool `json:"pair"` // new agent: return a pairing code instead of the token
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := validTTL(in.TokenTTLDays); err != nil {
			writeErr(w, 400, err)
			return
		}
		if !idRe.MatchString(in.ID) {
			writeErr(w, 400, errors.New("invalid agent id"))
			return
		}
		if in.ToolMode != "" && !validToolMode(in.ToolMode) {
			writeErr(w, 400, errors.New("tool_mode must be lazy, direct, auto or empty"))
			return
		}
		ag := in.Agent
		existing, err := g.store.GetAgent(ag.ID)
		if err == nil {
			ag.CreatedAt, ag.LastSeen, ag.ExpiresAt = existing.CreatedAt, existing.LastSeen, existing.ExpiresAt
			if ag.TokenTTLDays != existing.TokenTTLDays { // a new lifetime counts from now
				ag.ExpiresAt = expiryFrom(ag.TokenTTLDays)
			}
			if err := g.store.PutAgent(&ag, ""); err != nil {
				writeErr(w, 500, err)
				return
			}
			g.audit(uiAgent, "ui.update_agent", ag.ID, ag, "ok", 0, "")
			writeJSON(w, 200, map[string]any{"agent": ag})
			return
		}
		ag.CreatedAt, ag.LastSeen = now(), ""
		ag.ExpiresAt = expiryFrom(ag.TokenTTLDays)
		tok := newToken("agw_")
		if err := g.store.PutAgent(&ag, hashToken(tok)); err != nil {
			writeErr(w, 500, err)
			return
		}
		g.audit(uiAgent, "ui.create_agent", ag.ID, ag, "ok", 0, "")
		if in.Pair { // the token above is discarded; the client gets its own through the code
			code, exp := g.pairings.New("agent", ag.ID)
			writeJSON(w, 200, map[string]any{"agent": ag, "pairing": map[string]any{"code": code, "expires_at": exp.UTC().Format(time.RFC3339)}})
			return
		}
		writeJSON(w, 200, map[string]any{"agent": ag, "token": tok})
	})
	h("POST /api/agents/{id}/rotate", func(w http.ResponseWriter, r *http.Request) {
		ag, err := g.store.GetAgent(r.PathValue("id"))
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		tok, _, err := g.mintFor("agent", ag.ID)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		g.pairings.Cancel("agent", ag.ID)
		g.audit(uiAgent, "ui.rotate_agent_token", ag.ID, nil, "ok", 0, "")
		ag, _ = g.store.GetAgent(ag.ID)
		writeJSON(w, 200, map[string]any{"agent": ag, "token": tok})
	})
	h("POST /api/agents/{id}/pair", func(w http.ResponseWriter, r *http.Request) {
		ag, err := g.store.GetAgent(r.PathValue("id"))
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		code, exp := g.pairings.New("agent", ag.ID)
		g.audit(uiAgent, "ui.create_pairing", ag.ID, nil, "ok", 0, "")
		writeJSON(w, 200, map[string]any{"code": code, "expires_at": exp.UTC().Format(time.RFC3339)})
	})
	h("DELETE /api/agents/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		g.pairings.Cancel("agent", id)
		if err := g.store.DeleteAgent(id); err != nil {
			writeErr(w, 500, err)
			return
		}
		g.audit(uiAgent, "ui.delete_agent", id, nil, "ok", 0, "")
		writeJSON(w, 200, map[string]string{"ok": id})
	})

	// catalog
	// proxy apps (tokens for the user's own programs; see proxy.go)
	h("GET /api/apps", func(w http.ResponseWriter, r *http.Request) {
		list, err := g.store.ListProxyApps()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, list)
	})
	h("POST /api/apps", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ProxyApp
			Pair bool `json:"pair"`
		}
		if err := readJSON(r, &body); err != nil {
			writeErr(w, 400, err)
			return
		}
		in := body.ProxyApp
		if err := validTTL(in.TokenTTLDays); err != nil {
			writeErr(w, 400, err)
			return
		}
		in.Name = strings.TrimSpace(in.Name)
		for _, p := range in.Pools {
			if g.pools.Get(p) == nil {
				writeErr(w, 400, fmt.Errorf("no key pool %q", p))
				return
			}
		}
		if old, err := g.store.GetProxyApp(in.ID); err == nil {
			in.CreatedAt, in.LastUsed, in.ExpiresAt = old.CreatedAt, old.LastUsed, old.ExpiresAt
			if in.TokenTTLDays != old.TokenTTLDays {
				in.ExpiresAt = expiryFrom(in.TokenTTLDays)
			}
			if err := g.store.PutProxyApp(&in, ""); err != nil {
				writeErr(w, 400, err)
				return
			}
			g.audit(uiAgent, "ui.update_app", in.ID, in, "ok", 0, "")
			writeJSON(w, 200, map[string]any{"app": in})
			return
		}
		in.CreatedAt, in.LastUsed = now(), ""
		in.ExpiresAt = expiryFrom(in.TokenTTLDays)
		tok := newToken(proxyTokenPrefix)
		if err := g.store.PutProxyApp(&in, hashToken(tok)); err != nil {
			writeErr(w, 400, err)
			return
		}
		g.audit(uiAgent, "ui.create_app", in.ID, in, "ok", 0, "")
		if body.Pair {
			code, exp := g.pairings.New("app", in.ID)
			writeJSON(w, 200, map[string]any{"app": in, "pairing": map[string]any{"code": code, "expires_at": exp.UTC().Format(time.RFC3339)}})
			return
		}
		writeJSON(w, 200, map[string]any{"app": in, "token": tok})
	})
	h("POST /api/apps/{id}/rotate", func(w http.ResponseWriter, r *http.Request) {
		app, err := g.store.GetProxyApp(r.PathValue("id"))
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		tok, _, err := g.mintFor("app", app.ID)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		g.pairings.Cancel("app", app.ID)
		g.audit(uiAgent, "ui.rotate_app_token", app.ID, nil, "ok", 0, "")
		app, _ = g.store.GetProxyApp(app.ID)
		writeJSON(w, 200, map[string]any{"app": app, "token": tok})
	})
	h("POST /api/apps/{id}/pair", func(w http.ResponseWriter, r *http.Request) {
		app, err := g.store.GetProxyApp(r.PathValue("id"))
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		code, exp := g.pairings.New("app", app.ID)
		g.audit(uiAgent, "ui.create_pairing", "app:"+app.ID, nil, "ok", 0, "")
		writeJSON(w, 200, map[string]any{"code": code, "expires_at": exp.UTC().Format(time.RFC3339)})
	})
	h("DELETE /api/apps/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		g.pairings.Cancel("app", id)
		if err := g.store.DeleteProxyApp(id); err != nil {
			writeErr(w, 500, err)
			return
		}
		g.audit(uiAgent, "ui.delete_app", id, nil, "ok", 0, "")
		writeJSON(w, 200, map[string]string{"ok": id})
	})

	h("GET /api/catalog", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		offset, _ := strconv.Atoi(q.Get("offset"))
		res := g.catalog.Search(r.Context(), q.Get("q"), q.Get("source"), offset, limit)
		n, at := g.catalog.ClaudeInfo()
		writeJSON(w, 200, map[string]any{"entries": res.Entries, "total": res.Total, "errors": res.Errors,
			"claude_count": n, "claude_fetched_at": at, "base_url": g.baseURL})
	})
	h("GET /api/catalog/entry", func(w http.ResponseWriter, r *http.Request) {
		e, err := g.catalog.Get(r.Context(), r.URL.Query().Get("id"))
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		cp := *e
		cp.Auth = cp.authOptions()
		servers, _ := g.store.ListServers()
		cp.Installed = installedFor(&cp, servers)
		for _, cmd := range cp.Requires {
			if _, err := lookPath(cmd); err != nil {
				cp.Missing = append(cp.Missing, cmd)
			}
		}
		writeJSON(w, 200, cp)
	})
	h("POST /api/catalog/refresh", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		if err := g.catalog.RefreshClaude(ctx); err != nil {
			writeErr(w, 502, err)
			return
		}
		n, _ := g.catalog.ClaudeInfo()
		writeJSON(w, 200, map[string]any{"claude_count": n})
	})
	h("POST /api/catalog", func(w http.ResponseWriter, r *http.Request) {
		var e CatalogEntry
		if err := readJSON(r, &e); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := g.catalog.AddUser(&e); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, e)
	})
	h("DELETE /api/catalog/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !strings.HasPrefix(id, "user:") {
			writeErr(w, 400, errors.New("only user entries can be deleted"))
			return
		}
		_ = g.store.DeleteCatalog(id)
		writeJSON(w, 200, map[string]string{"ok": id})
	})
	h("POST /api/catalog/install", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			CatalogID string            `json:"catalog_id"`
			ID        string            `json:"id"`
			Auth      string            `json:"auth"`
			Params    map[string]string `json:"params"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		e, err := g.catalog.Get(r.Context(), in.CatalogID)
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		cfg, missing, err := g.catalog.Install(e, in.ID, in.Auth, in.Params)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		_ = g.approve(cfg, "admin-ui")
		g.audit(uiAgent, "ui.catalog_install", cfg.ID, map[string]any{"catalog_id": in.CatalogID}, "ok", 0, "")
		writeJSON(w, 200, map[string]any{"server": cfg, "missing_secrets": missing})
	})

	// testing & policy
	h("POST /api/test", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Agent     string         `json:"agent"`
			Tool      string         `json:"tool"`
			Arguments map[string]any `json:"arguments"`
			DryRun    bool           `json:"dry_run"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		// Playground calls are audited as "ui:test" (or "ui:test:<agent>" when
		// run with an agent's restrictions) so they never look like agent use.
		ag := &Agent{ID: UITestActor, Name: "Panel playground", CanManage: true}
		if in.Agent != "" {
			found, err := g.store.GetAgent(in.Agent)
			if err != nil {
				writeErr(w, 404, err)
				return
			}
			cp := *found
			cp.ID = UITestActor + ":" + found.ID
			ag = &cp
		}
		sid, tname, err := splitTool(in.Tool)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		srv, err := g.store.GetServer(sid)
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		d := Decide(ag, srv, tname)
		if in.DryRun {
			writeJSON(w, 200, map[string]any{"policy": d})
			return
		}
		start := time.Now()
		res := g.Call(r.Context(), ag, in.Tool, in.Arguments)
		writeJSON(w, 200, map[string]any{"policy": d, "result": res, "duration_ms": time.Since(start).Milliseconds()})
	})
	h("GET /api/agents/{id}/view", func(w http.ResponseWriter, r *http.Request) {
		ag, err := g.store.GetAgent(r.PathValue("id"))
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		configured := g.configuredMode(ag, "")
		eff := g.EffectiveToolMode(ag, "")
		modes := map[string]ModeFootprint{}
		for _, m := range []string{ToolModeLazy, ToolModeDirect} {
			fp, err := g.measureMode(r.Context(), ag, m)
			if err != nil {
				writeErr(w, 500, err)
				return
			}
			modes[m] = fp
		}
		writeJSON(w, 200, map[string]any{"instructions": g.instructionsFor(ag, eff, eff == ToolModeDirect && len(g.directTools(ag)) > DirectMaxTools),
			"summaries": g.summaries(ag), "tool_mode": configured, "effective_mode": eff, "modes": modes,
			"auto_max": AutoDirectMaxTools, "direct_max": DirectMaxTools, "auto_mode": g.EffectiveToolMode(ag, ToolModeAuto)})
	})

	h("GET /api/search-stats", func(w http.ResponseWriter, r *http.Request) {
		days, _ := strconv.Atoi(r.URL.Query().Get("days"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if days <= 0 {
			days = 30
		}
		totals, misses, err := g.store.SearchStats(days, limit)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]any{"days": days, "totals": totals, "misses": misses,
			"records_queries": g.store.AuditArgsMode() != AuditArgsNone})
	})
	h("DELETE /api/search-misses", func(w http.ResponseWriter, r *http.Request) {
		q, srv := r.URL.Query().Get("query"), r.URL.Query().Get("server")
		n, err := g.store.DismissSearchMiss(q, srv)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		g.audit(uiAgent, "ui.dismiss_search_miss", srv, nil, "ok", 0, fmt.Sprintf("%d removed", n))
		writeJSON(w, 200, map[string]int64{"removed": n})
	})
	h("GET /api/settings/tools", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"default_mode": g.store.ToolModeDefault(), "auto_max": AutoDirectMaxTools, "direct_max": DirectMaxTools})
	})
	h("POST /api/settings/tools", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			DefaultMode string `json:"default_mode"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := g.store.SetToolModeDefault(in.DefaultMode); err != nil {
			writeErr(w, 400, err)
			return
		}
		g.audit(uiAgent, "ui.tool_mode_default", "", in, "ok", 0, "")
		writeJSON(w, 200, map[string]string{"default_mode": in.DefaultMode})
	})
	h("GET /api/settings/audit", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, g.store.AuditSettings())
	})
	h("POST /api/settings/audit", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			RetentionDays int    `json:"retention_days"`
			Args          string `json:"args"`
			ScrubExisting bool   `json:"scrub_existing"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		if _, fixed := g.store.AuditRetentionDays(); fixed {
			in.RetentionDays = 0 // fixed by flag; still allow changing the args mode
		}
		if err := g.store.SetAuditSettings(in.RetentionDays, in.Args); err != nil {
			writeErr(w, 400, err)
			return
		}
		pruned, err := g.store.PruneAudit()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		scrubbed := 0
		if in.ScrubExisting {
			if scrubbed, err = g.store.ScrubAuditArgs(); err != nil {
				writeErr(w, 500, err)
				return
			}
		}
		st := g.store.AuditSettings()
		g.audit(uiAgent, "ui.audit_settings", "", map[string]any{"retention_days": st.RetentionDays, "args": st.Args, "scrub_existing": in.ScrubExisting}, "ok", 0,
			fmt.Sprintf("%d pruned, %d scrubbed", pruned, scrubbed))
		writeJSON(w, 200, map[string]any{"settings": st, "pruned": pruned, "scrubbed": scrubbed})
	})

	h("GET /api/audit", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		list, err := g.store.ListAuditFiltered(limit, q.Get("agent"), q.Get("q"), q.Get("server"))
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		if list == nil {
			list = []AuditEntry{}
		}
		writeJSON(w, 200, list)
	})
}

func pendingDiff(store *Store, c *ServerConfig) []DiffRow {
	if store.IsApproved(c) {
		return []DiffRow{}
	}
	return store.ApprovalDiff(c)
}

func approvalInfo(store *Store, id string) map[string]any {
	a, err := store.GetApproval(id)
	if err != nil {
		return nil
	}
	return map[string]any{"approved_at": a.ApprovedAt, "approved_by": a.ApprovedBy}
}

func (g *Gateway) poolFor(secret string) *KeyPool {
	if g.pools == nil {
		return nil
	}
	return g.pools.ForSecret(secret)
}
