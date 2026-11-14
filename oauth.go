package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"
)

type pendingAuth struct {
	server string
	ch     chan *auth.AuthorizationResult
}

type savedOAuth struct {
	Config oauth2.Config `json:"config"`
	Token  *oauth2.Token `json:"token"`
}

func oauthSecretName(serverID string) string { return "oauth:" + serverID }

func (m *Manager) loadOAuth(id string) *savedOAuth {
	raw, err := m.vault.Get(oauthSecretName(id))
	if err != nil {
		return nil
	}
	var s savedOAuth
	if json.Unmarshal([]byte(raw), &s) != nil || s.Token == nil {
		return nil
	}
	return &s
}

func (m *Manager) saveOAuth(id string, cfg *oauth2.Config, tok *oauth2.Token) {
	b, _ := json.Marshal(savedOAuth{Config: *cfg, Token: tok})
	if err := m.vault.Set(oauthSecretName(id), string(b), true, "OAuth token for "+id); err != nil {
		m.log.Error("save oauth token", "server", id, "err", err)
	}
}

// ForgetOAuth deletes stored tokens so the next connect starts a fresh login.
func (m *Manager) ForgetOAuth(id string) {
	_ = m.vault.Delete(oauthSecretName(id))
	m.Disconnect(id)
}

type persistingTS struct {
	mu   sync.Mutex
	base oauth2.TokenSource
	last string
	save func(*oauth2.Token)
}

func (p *persistingTS) Token() (*oauth2.Token, error) {
	t, err := p.base.Token()
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	changed := t.AccessToken != p.last
	p.last = t.AccessToken
	p.mu.Unlock()
	if changed {
		p.save(t)
	}
	return t, nil
}

func (m *Manager) redirectURL() string { return m.baseURL + "/oauth/callback" }

func (m *Manager) oauthHandler(cfg *ServerConfig, c *conn) (*auth.AuthorizationCodeHandler, error) {
	id := cfg.ID
	wrap := func(oc *oauth2.Config, tok *oauth2.Token) oauth2.TokenSource {
		occ := *oc
		return &persistingTS{base: occ.TokenSource(context.Background(), tok), last: tok.AccessToken,
			save: func(t *oauth2.Token) { m.saveOAuth(id, &occ, t) }}
	}
	hc := &auth.AuthorizationCodeHandlerConfig{
		RedirectURL:         m.redirectURL(),
		RequestRefreshToken: true,
		AuthorizationCodeFetcher: func(ctx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
			u, err := url.Parse(args.URL)
			if err != nil {
				return nil, err
			}
			state := u.Query().Get("state")
			p := &pendingAuth{server: id, ch: make(chan *auth.AuthorizationResult, 1)}
			m.mu.Lock()
			m.pending[state] = p
			m.mu.Unlock()
			defer func() {
				m.mu.Lock()
				delete(m.pending, state)
				m.mu.Unlock()
			}()
			c.mu.Lock()
			c.status, c.authURL = StatusAuthRequired, args.URL
			c.mu.Unlock()
			m.store.Audit(AuditEntry{Agent: "gateway", Action: "oauth_required", Target: id, Args: "{}", Status: "pending"})
			select {
			case r := <-p.ch:
				c.mu.Lock()
				c.status, c.authURL = StatusConnecting, ""
				c.mu.Unlock()
				return r, nil
			case <-time.After(15 * time.Minute):
				return nil, errors.New("authorization timed out (15 min); call connect again for a new login link")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		NewTokenSource: func(ctx context.Context, oc *oauth2.Config, tok *oauth2.Token) (oauth2.TokenSource, error) {
			m.saveOAuth(id, oc, tok)
			m.store.Audit(AuditEntry{Agent: "gateway", Action: "oauth_complete", Target: id, Args: "{}", Status: "ok"})
			return wrap(oc, tok), nil
		},
	}
	if len(cfg.OAuthScopes) > 0 {
		scopes := cfg.OAuthScopes
		hc.ScopeFilter = func([]string) []string { return scopes }
	}
	if cfg.OAuthClientID != "" {
		cc := &oauthex.ClientCredentials{ClientID: cfg.OAuthClientID}
		if cfg.OAuthClientSecretRef != "" {
			sec, err := m.vault.Get(cfg.OAuthClientSecretRef)
			if err != nil {
				return nil, err
			}
			cc.ClientSecretAuth = &oauthex.ClientSecretAuth{ClientSecret: sec}
		}
		hc.PreregisteredClient = cc
	} else {
		hc.DynamicClientRegistrationConfig = &auth.DynamicClientRegistrationConfig{
			Metadata: &oauthex.ClientRegistrationMetadata{
				RedirectURIs:            []string{m.redirectURL()},
				ClientName:              "Toolgate",
				GrantTypes:              []string{"authorization_code", "refresh_token"},
				ResponseTypes:           []string{"code"},
				TokenEndpointAuthMethod: "none",
			},
		}
	}
	if saved := m.loadOAuth(id); saved != nil {
		hc.InitialTokenSource = wrap(&saved.Config, saved.Token)
	}
	return auth.NewAuthorizationCodeHandler(hc)
}

// HandleCallback receives the OAuth redirect from the browser.
func (m *Manager) HandleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	m.mu.Lock()
	p := m.pending[state]
	m.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if p == nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, callbackPage("This sign-in link is invalid or has expired.", "Ask the agent for a new link.", false))
		return
	}
	if e := q.Get("error"); e != "" {
		msg := e
		if d := q.Get("error_description"); d != "" {
			msg += ": " + d
		}
		m.store.Audit(AuditEntry{Agent: "gateway", Action: "oauth_complete", Target: p.server, Args: "{}", Status: "error", Detail: msg})
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, callbackPage("Sign-in was denied", msg, false))
		return
	}
	select {
	case p.ch <- &auth.AuthorizationResult{Code: q.Get("code"), State: state, Iss: q.Get("iss")}:
	default:
	}
	fmt.Fprint(w, callbackPage("Connected: "+p.server, "You can close this tab. The agent can carry on.", true))
}

func callbackPage(title, msg string, ok bool) string {
	color := "#b42318"
	if ok {
		color = "#067647"
	}
	return `<!doctype html><meta charset="utf-8"><title>Toolgate</title>
<body style="font-family:-apple-system,system-ui,sans-serif;display:grid;place-items:center;height:100vh;margin:0;background:#f6f6f4">
<div style="background:#fff;padding:32px 40px;border-radius:12px;border:1px solid #e4e4e0;max-width:420px">
<h2 style="margin:0 0 8px;color:` + color + `">` + html.EscapeString(title) + `</h2><p style="margin:0;color:#444">` + html.EscapeString(msg) + `</p></div>`
}
