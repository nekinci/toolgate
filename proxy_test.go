package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type seenReq struct {
	Path, Query, Auth, XAPIKey, Cookie, Model string
}

// proxyEnv: an OpenAI-style fake upstream, an "oai" pool with two keys and an
// app allowed to use it. The handler is served through a real mux so path
// values work like in main.go.
func proxyEnv(t *testing.T, upstream http.HandlerFunc) (*Gateway, string, string, *[]seenReq) {
	t.Helper()
	var mu sync.Mutex
	seen := []seenReq{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var x struct{ Model string }
		_ = json.Unmarshal(b, &x)
		mu.Lock()
		seen = append(seen, seenReq{r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get("X-Api-Key"), r.Header.Get("Cookie"), x.Model})
		mu.Unlock()
		upstream(w, r)
	}))
	t.Cleanup(up.Close)

	g := testGateway(t)
	g.pools = NewPools(g.store, g.vault)
	if _, err := g.pools.Put(PoolConfig{ID: "oai", Provider: "openai", Prefix: "OAI_KEY", BaseURL: up.URL}); err != nil {
		t.Fatal(err)
	}
	_ = g.vault.Set("OAI_KEY_1", "sk-real-1", false, "")
	_ = g.vault.Set("OAI_KEY_2", "sk-real-2", false, "")
	tok := newToken(proxyTokenPrefix)
	if err := g.store.PutProxyApp(&ProxyApp{ID: "myapp", Name: "My app", Pools: []string{"oai"}, CreatedAt: now()}, hashToken(tok)); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/{pool}/{rest...}", g.handleProxy)
	gw := httptest.NewServer(mux)
	t.Cleanup(gw.Close)
	return g, gw.URL, tok, &seen
}

func doProxy(t *testing.T, method, url, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestProxyAuthAndCredentialSwap(t *testing.T) {
	g, gw, tok, seen := proxyEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "upstream=1")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	u := gw + "/proxy/oai/v1/chat/completions"
	if resp, _ := doProxy(t, "POST", u, `{}`, nil); resp.StatusCode != 401 {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
	if resp, _ := doProxy(t, "POST", u, `{}`, map[string]string{"Authorization": "Bearer agp_wrong"}); resp.StatusCode != 401 {
		t.Fatalf("bad token: %d", resp.StatusCode)
	}
	if len(*seen) != 0 {
		t.Fatal("unauthenticated request reached upstream")
	}
	resp, body := doProxy(t, "POST", u+"?key="+tok+"&x=1", `{"model":"gpt-x"}`,
		map[string]string{"Authorization": "Bearer " + tok, "X-Api-Key": "client-key", "Cookie": "a=b"})
	if resp.StatusCode != 200 || body != `{"ok":true}` {
		t.Fatalf("proxied: %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Set-Cookie") != "" {
		t.Fatal("upstream Set-Cookie passed through")
	}
	s := (*seen)[0]
	if s.Path != "/v1/chat/completions" || s.Query != "x=1" || s.XAPIKey != "" || s.Cookie != "" || s.Model != "gpt-x" {
		t.Fatalf("upstream saw %+v", s)
	}
	if s.Auth != "Bearer sk-real-1" && s.Auth != "Bearer sk-real-2" {
		t.Fatalf("upstream auth = %q", s.Auth)
	}
	// token in x-api-key (Anthropic SDK style) also works
	if resp, _ := doProxy(t, "GET", gw+"/proxy/oai/v1/models", "", map[string]string{"X-Api-Key": tok}); resp.StatusCode != 200 {
		t.Fatalf("x-api-key token: %d", resp.StatusCode)
	}
	// audit: actor app:myapp, key name but never the token or key value
	list, _ := g.store.ListAudit(10, "app:myapp", "")
	if len(list) == 0 {
		t.Fatal("proxy call not audited")
	}
	for _, e := range list {
		all := e.Target + e.Args + e.Detail
		if strings.Contains(all, tok) || strings.Contains(all, "sk-real") {
			t.Fatalf("secret in audit: %+v", e)
		}
	}
}

func TestProxyPoolNotAllowed(t *testing.T) {
	g, gw, tok, seen := proxyEnv(t, func(w http.ResponseWriter, r *http.Request) {})
	if _, err := g.pools.Put(PoolConfig{ID: "other", Provider: "openai", Prefix: "OTHER_KEY", BaseURL: "https://api.openai.com"}); err != nil {
		t.Fatal(err)
	}
	if resp, _ := doProxy(t, "GET", gw+"/proxy/other/v1/models", "", map[string]string{"Authorization": "Bearer " + tok}); resp.StatusCode != 403 {
		t.Fatalf("other pool: %d", resp.StatusCode)
	}
	if resp, _ := doProxy(t, "GET", gw+"/proxy/nope/v1/models", "", map[string]string{"Authorization": "Bearer " + tok}); resp.StatusCode != 404 {
		t.Fatalf("missing pool: %d", resp.StatusCode)
	}
	if len(*seen) != 0 {
		t.Fatal("denied request reached upstream")
	}
}

func TestProxyRotatesOnRateLimit(t *testing.T) {
	var mu sync.Mutex
	limited := map[string]bool{}
	_, gw, tok, seen := proxyEnv(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		k := r.Header.Get("Authorization")
		if !limited[k] && len(limited) == 0 { // the first key used gets rate limited once
			limited[k] = true
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(429)
			_, _ = io.WriteString(w, `{"error":{"message":"Rate limit reached","type":"requests","code":"rate_limit_exceeded"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":"`+k+`"}`)
	})
	resp, body := doProxy(t, "POST", gw+"/proxy/oai/v1/chat/completions", `{"model":"m"}`, map[string]string{"Authorization": "Bearer " + tok})
	if resp.StatusCode != 200 || len(*seen) != 2 || (*seen)[0].Auth == (*seen)[1].Auth {
		t.Fatalf("no rotation: %d %s %+v", resp.StatusCode, body, *seen)
	}
	// the limited key is cooling down for model m: the next call goes to the other key directly
	_, _ = doProxy(t, "POST", gw+"/proxy/oai/v1/chat/completions", `{"model":"m"}`, map[string]string{"Authorization": "Bearer " + tok})
	if len(*seen) != 3 || (*seen)[2].Auth != (*seen)[1].Auth {
		t.Fatalf("cooling key reused: %+v", *seen)
	}
}

func TestProxyRequestErrorNotRetried(t *testing.T) {
	_, gw, tok, seen := proxyEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"error":{"message":"bad model","type":"invalid_request_error"}}`)
	})
	resp, body := doProxy(t, "POST", gw+"/proxy/oai/v1/chat/completions", `{}`, map[string]string{"Authorization": "Bearer " + tok})
	if resp.StatusCode != 400 || !strings.Contains(body, "bad model") || len(*seen) != 1 {
		t.Fatalf("got %d %s after %d upstream calls", resp.StatusCode, body, len(*seen))
	}
}

func TestProxyAllKeysLimited(t *testing.T) {
	_, gw, tok, seen := proxyEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(429)
		_, _ = io.WriteString(w, `{"error":{"message":"Rate limit reached"}}`)
	})
	resp, _ := doProxy(t, "POST", gw+"/proxy/oai/v1/x", `{"model":"m"}`, map[string]string{"Authorization": "Bearer " + tok})
	if resp.StatusCode != 429 || len(*seen) != 2 {
		t.Fatalf("got %d after %d calls", resp.StatusCode, len(*seen))
	}
	// both keys cool now: the gateway answers itself with Retry-After
	resp, body := doProxy(t, "POST", gw+"/proxy/oai/v1/x", `{"model":"m"}`, map[string]string{"Authorization": "Bearer " + tok})
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" || !strings.Contains(body, "gateway_no_key") || len(*seen) != 2 {
		t.Fatalf("got %d %s (retry-after %q) after %d calls", resp.StatusCode, body, resp.Header.Get("Retry-After"), len(*seen))
	}
}

func TestProxyStreamsSSE(t *testing.T) {
	release := make(chan struct{})
	_, gw, tok, _ := proxyEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-release // the first event must reach the client before the stream ends
		_, _ = io.WriteString(w, "data: two\n\n")
	})
	req, _ := http.NewRequest("POST", gw+"/proxy/oai/v1/chat/completions", strings.NewReader(`{"stream":true}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	line, _ := br.ReadString('\n')
	if line != "data: one\n" {
		t.Fatalf("first line %q", line)
	}
	close(release)
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "data: two") {
		t.Fatalf("rest %q", rest)
	}
}

func TestProxyPathAndScope(t *testing.T) {
	for _, bad := range []string{"..%2f..%2fetc", "a/%2e%2e/b", "%2fabs"} {
		if _, err := proxyPath(bad); err == nil {
			t.Errorf("path %q accepted", bad)
		}
	}
	if p, err := proxyPath("v1beta/models/gemini-2.5-flash:generateContent"); err != nil || p != "/v1beta/models/gemini-2.5-flash:generateContent" {
		t.Fatalf("good path: %q %v", p, err)
	}
	if s := proxyScope("gemini", "/v1beta/models/gemini-2.5-flash:streamGenerateContent", nil); s != "gemini-2.5-flash" {
		t.Fatalf("gemini scope %q", s)
	}
	if s := proxyScope("openai", "/v1/chat/completions", []byte(`{"model":"gpt-x"}`)); s != "gpt-x" {
		t.Fatalf("body scope %q", s)
	}
	for _, c := range []struct {
		u  string
		ok bool
	}{{"https://api.x.com", true}, {"http://localhost:8080", true}, {"http://127.0.0.1", true},
		{"http://localhost.evil.com", false}, {"http://api.x.com", false}, {"https://u:p@x.com", false}, {"ftp://x", false}} {
		if validPoolBaseURL(c.u) != c.ok {
			t.Errorf("validPoolBaseURL(%q) != %v", c.u, c.ok)
		}
	}
}
