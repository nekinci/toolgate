package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OAuthClientRequiredError: the server's authorization server doesn't allow
// automatic client registration, so the user must register an OAuth client
// once and enter its client ID/secret.
type OAuthClientRequiredError struct{ Server string }

func (e *OAuthClientRequiredError) Error() string {
	return fmt.Sprintf("server %q needs an OAuth client (client ID and secret) registered by the user; the service doesn't support automatic registration", e.Server)
}

func isClientRegistrationErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no configured client registration") ||
		(strings.Contains(s, "registration") && (strings.Contains(s, "not supported") || strings.Contains(s, "no registration endpoint")))
}

func (m *Manager) setAuthIssue(id, issue string) {
	c := m.get(id)
	c.mu.Lock()
	c.authIssue = issue
	c.mu.Unlock()
}

// NeedsLogin: an OAuth server without a stored session. Some servers list
// tools without auth, so "connected" alone doesn't mean signed in.
func (m *Manager) NeedsLogin(cfg *ServerConfig) bool {
	if cfg.Transport != "http" || cfg.Auth != "oauth" {
		return false
	}
	if _, ok := cfg.Headers["Authorization"]; ok {
		return false
	}
	return !m.vault.Has(oauthSecretName(cfg.ID))
}

// Login starts (or reports) the OAuth sign-in for a server even when the
// server doesn't demand it up front. Returns *AuthRequiredError with the
// login URL, *OAuthClientRequiredError, or nil when already signed in.
func (m *Manager) Login(ctx context.Context, id string) error {
	cfg, err := m.store.GetServer(id)
	if err != nil {
		return err
	}
	if cfg.Transport != "http" {
		return errors.New("this server runs locally and has no sign-in")
	}
	if _, err := m.Session(ctx, id); err != nil {
		if isClientRegistrationErr(err) {
			m.setAuthIssue(id, "client_required")
			return &OAuthClientRequiredError{Server: id}
		}
		return err // includes *AuthRequiredError when the server asked on connect
	}
	if m.vault.Has(oauthSecretName(id)) {
		return nil
	}
	c := m.get(id)
	c.mu.Lock()
	h := c.oauth
	pending := c.authURL
	c.mu.Unlock()
	if pending != "" {
		return &AuthRequiredError{Server: id, URL: pending}
	}
	if h == nil {
		return errors.New("this server is configured without OAuth (header or no auth)")
	}
	missing := map[string]bool{}
	u := m.vault.Resolve(cfg.URL, missing)
	done := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, u, nil)
		resp := &http.Response{StatusCode: http.StatusUnauthorized, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}
		err := h.Authorize(context.Background(), req, resp)
		c.mu.Lock()
		c.authURL = ""
		if err == nil && c.session != nil {
			c.status = StatusConnected
			c.authIssue = ""
		} else if err != nil {
			if isClientRegistrationErr(err) {
				c.authIssue = "client_required"
			}
			if c.session != nil {
				c.status = StatusConnected
			}
			c.err = err.Error()
		}
		c.mu.Unlock()
		if err == nil {
			m.Disconnect(id) // reconnect with the new token on next use
		}
		done <- err
	}()
	t := time.NewTicker(150 * time.Millisecond)
	defer t.Stop()
	deadline := time.After(45 * time.Second)
	for {
		select {
		case err := <-done:
			if isClientRegistrationErr(err) {
				return &OAuthClientRequiredError{Server: id}
			}
			return err
		case <-t.C:
			c.mu.Lock()
			u := c.authURL
			c.mu.Unlock()
			if u != "" {
				return &AuthRequiredError{Server: id, URL: u}
			}
		case <-deadline:
			return errors.New("sign-in did not start within 45s")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// SetOAuthClient stores a user-registered OAuth client for a server and
// resets its session so the next sign-in uses the new client.
func (g *Gateway) SetOAuthClient(id, clientID, clientSecret string, scopes []string) (*ServerConfig, error) {
	c, err := g.store.GetServer(id)
	if err != nil {
		return nil, err
	}
	if c.Transport != "http" {
		return nil, errors.New("OAuth clients apply to remote (http) servers only")
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, errors.New("client ID gerekli")
	}
	c.OAuthClientID = clientID
	if clientSecret = strings.TrimSpace(clientSecret); clientSecret != "" {
		name := strings.ToUpper(strings.ReplaceAll(c.ID+"_OAUTH_CLIENT_SECRET", "-", "_"))
		if err := g.vault.Set(name, clientSecret, false, c.Name+" OAuth client secret"); err != nil {
			return nil, err
		}
		c.OAuthClientSecretRef = name
	}
	if len(scopes) > 0 {
		c.OAuthScopes = scopes
	}
	c.Auth = "oauth"
	delete(c.Headers, "Authorization")
	if err := g.store.PutServer(c); err != nil {
		return nil, err
	}
	if err := g.approve(c, "admin-ui"); err != nil {
		return nil, err
	}
	g.mgr.ForgetOAuth(id)
	g.mgr.setAuthIssue(id, "")
	return c, nil
}
