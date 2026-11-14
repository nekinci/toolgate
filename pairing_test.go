package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func pairPost(g *Gateway, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/pair", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	g.handlePair(w, req)
	return w
}

func TestPairingCodes(t *testing.T) {
	p := NewPairings()
	code, exp := p.New("agent", "bot")
	if len(code) != 9 || code[4] != '-' || time.Until(exp) > pairingTTL {
		t.Fatalf("code %q exp %v", code, exp)
	}
	// newest code replaces older ones for the same target
	code2, _ := p.New("agent", "bot")
	if _, err := p.Take(code); err == nil {
		t.Fatal("old code still valid")
	}
	// case and dashes don't matter; single use
	if e, err := p.Take(strings.ToLower(strings.ReplaceAll(code2, "-", " "))); err != nil || e.ID != "bot" {
		t.Fatalf("take: %+v %v", e, err)
	}
	if _, err := p.Take(code2); err == nil {
		t.Fatal("code used twice")
	}
	// expiry
	c3, _ := p.New("app", "x")
	p.nowFn = func() time.Time { return time.Now().Add(pairingTTL + time.Second) }
	if _, err := p.Take(c3); err == nil {
		t.Fatal("expired code accepted")
	}
	// lockout after too many wrong codes, even for a valid one
	p.nowFn = time.Now
	good, _ := p.New("agent", "y")
	for i := 0; i < pairingMaxFails; i++ {
		_, _ = p.Take("AAAA-AAAA")
	}
	if _, err := p.Take(good); err != errPairingLocked {
		t.Fatalf("not locked: %v", err)
	}
}

func TestPairExchangeAndExpiry(t *testing.T) {
	g := testGateway(t)
	call := adminMux(t, g)
	w := call("POST", "/api/agents", `{"id":"laptop","name":"Laptop","token_ttl_days":30,"pair":true}`)
	if w.Code != 200 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var cr struct {
		Agent   Agent
		Token   string
		Pairing struct{ Code string }
	}
	_ = json.Unmarshal(w.Body.Bytes(), &cr)
	if cr.Token != "" || cr.Pairing.Code == "" {
		t.Fatalf("pair create should return a code, not a token: %s", w.Body)
	}
	if d := time.Until(parseTime(cr.Agent.ExpiresAt)); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Fatalf("expires_at %q", cr.Agent.ExpiresAt)
	}
	pw := pairPost(g, url.Values{"code": {cr.Pairing.Code}, "format": {"token"}})
	tok := pw.Body.String()
	if pw.Code != 200 || !strings.HasPrefix(tok, "agw_") || strings.Contains(tok, "\n") {
		t.Fatalf("exchange: %d %q", pw.Code, tok)
	}
	if a, err := g.store.AgentByTokenHash(hashToken(tok)); err != nil || a.ID != "laptop" {
		t.Fatalf("issued token doesn't authenticate: %v", err)
	}
	if pw := pairPost(g, url.Values{"code": {cr.Pairing.Code}}); pw.Code != 400 {
		t.Fatalf("reuse: %d", pw.Code)
	}
	// a second pairing replaces the token
	w = call("POST", "/api/agents/laptop/pair", ``)
	var pr struct{ Code string }
	_ = json.Unmarshal(w.Body.Bytes(), &pr)
	pw = pairPost(g, url.Values{"code": {pr.Code}})
	var out map[string]any
	_ = json.Unmarshal(pw.Body.Bytes(), &out)
	if pw.Code != 200 || out["mcp_url"] != "http://localhost:7777/mcp" || out["token"] == tok {
		t.Fatalf("json exchange: %d %s", pw.Code, pw.Body)
	}
	if _, err := g.store.AgentByTokenHash(hashToken(tok)); err == nil {
		t.Fatal("old token still valid after re-pairing")
	}
	// changing the lifetime restarts it; 0 = never
	a, _ := g.store.GetAgent("laptop")
	b, _ := json.Marshal(map[string]any{"id": "laptop", "name": "Laptop", "token_ttl_days": 0, "expires_at": "2000-01-01T00:00:00Z"})
	call("POST", "/api/agents", string(b))
	if a2, _ := g.store.GetAgent("laptop"); a2.ExpiresAt != "" || a.ExpiresAt == "" {
		t.Fatalf("ttl change: before %q after %q", a.ExpiresAt, a2.ExpiresAt)
	}
	if !tokenExpired("2000-01-01T00:00:00Z") || tokenExpired("") || tokenExpired(expiryFrom(1)) {
		t.Fatal("tokenExpired")
	}
}

func TestExpiredAppTokenRefused(t *testing.T) {
	g, gw, tok, seen := proxyEnv(t, func(w http.ResponseWriter, r *http.Request) {})
	a, _ := g.store.GetProxyApp("myapp")
	a.ExpiresAt = "2000-01-01T00:00:00Z"
	_ = g.store.PutProxyApp(a, "")
	resp, body := doProxy(t, "GET", gw+"/proxy/oai/v1/models", "", map[string]string{"Authorization": "Bearer " + tok})
	if resp.StatusCode != 401 || !strings.Contains(body, "expired") || len(*seen) != 0 {
		t.Fatalf("expired app: %d %s", resp.StatusCode, body)
	}
}

func TestExpiryNoteInInstructions(t *testing.T) {
	g := testGateway(t)
	a := &Agent{ID: "bot", ExpiresAt: time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)}
	if !strings.Contains(g.instructions(a), "token expires on") {
		t.Fatal("no expiry note")
	}
	a.ExpiresAt = time.Now().Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if strings.Contains(g.instructions(a), "token expires on") {
		t.Fatal("note shown too early")
	}
}
