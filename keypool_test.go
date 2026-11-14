package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPoolsMigrationKeepsGeminiState(t *testing.T) {
	s, v, _ := testEnv(t)
	for _, n := range []string{"GEMINI_API_KEY_1", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3", "GEMINI_API_KEY_4", "GEMINI_OTHER", "OPENAI_API_KEY"} {
		_ = v.Set(n, "v-"+n, false, "")
	}
	// state written by the old Gemini-only pool
	s.SetMeta("gemini_usage", `{"GEMINI_API_KEY_2":{"day":"`+today()+`","calls":7,"total_calls":42}}`)
	s.SetMeta("gemini_invalid", `{"GEMINI_API_KEY_3":"API key not valid"}`)

	ps := NewPools(s, v)
	gp := ps.Get("gemini")
	if gp == nil || gp.Config().Prefix != "GEMINI_API_KEY" {
		t.Fatal("default gemini pool missing")
	}
	if got := strings.Join(gp.Keys(), ","); got != "GEMINI_API_KEY_1,GEMINI_API_KEY_2,GEMINI_API_KEY_3,GEMINI_API_KEY_4" {
		t.Fatalf("keys = %s", got)
	}
	st := map[string]PoolKeyStatus{}
	for _, k := range gp.Status() {
		st[k.Name] = k
	}
	if st["GEMINI_API_KEY_2"].Usage.TotalCalls != 42 || st["GEMINI_API_KEY_2"].Usage.Calls != 7 || st["GEMINI_API_KEY_3"].State != "invalid" {
		t.Fatalf("old counters lost: %+v", st)
	}
	if gp.NextKeyName() != "GEMINI_API_KEY_5" {
		t.Fatalf("next = %s", gp.NextKeyName())
	}
	// reopening keeps the same config and doesn't duplicate
	if n := len(NewPools(s, v).List()); n != 1 {
		t.Fatalf("pools after reopen = %d", n)
	}
	if ps.ForSecret("GEMINI_API_KEY_4") != gp || ps.ForSecret("GEMINI_OTHER") != nil {
		t.Fatal("ForSecret")
	}
}

func TestPoolsPutValidation(t *testing.T) {
	s, v, _ := testEnv(t)
	_ = v.Set("OPENAI_API_KEY_1", "x", false, "")
	ps := NewPools(s, v)
	if _, err := ps.Put(PoolConfig{ID: "gemini", Provider: "gemini", Prefix: "GOOGLE_KEY"}); err == nil {
		t.Fatal("gemini prefix must be fixed")
	}
	if _, err := ps.Put(PoolConfig{ID: "gemini", Name: "Google", Provider: "gemini", Prefix: "GEMINI_API_KEY"}); err != nil {
		t.Fatalf("renaming gemini pool: %v", err)
	}
	if ps.Get("gemini").label() != "Google" {
		t.Fatal("rename not applied in place")
	}
	if err := ps.Delete("gemini"); err == nil {
		t.Fatal("gemini pool must not be deletable")
	}
	cfg, err := ps.Put(PoolConfig{ID: "openai", Provider: "openai"})
	if err != nil || cfg.Prefix != "OPENAI_API_KEY" || cfg.Name != "OpenAI" {
		t.Fatalf("preset defaults: %+v %v", cfg, err)
	}
	if _, err := ps.Put(PoolConfig{ID: "o2", Provider: "openai", Prefix: "OPENAI_API_KEY_ORG"}); err == nil {
		t.Fatal("overlapping prefix accepted")
	}
	if _, err := ps.Put(PoolConfig{ID: "c", Provider: "custom", Prefix: "MY_KEY"}); err == nil {
		t.Fatal("custom pool without header accepted")
	}
	if _, err := ps.Put(PoolConfig{ID: "c", Provider: "custom", Prefix: "MY_KEY", Header: "X-Key", BaseURL: "http://evil.example"}); err == nil {
		t.Fatal("plain http base url accepted")
	}
	if _, err := ps.Put(PoolConfig{ID: "c", Provider: "bogus", Prefix: "MY_KEY"}); err == nil {
		t.Fatal("unknown provider accepted")
	}
	if err := ps.Delete("openai"); err != nil {
		t.Fatal(err)
	}
	if !v.Has("OPENAI_API_KEY_1") {
		t.Fatal("deleting a pool must keep its secrets")
	}
	if NewPools(s, v).Get("openai") != nil {
		t.Fatal("delete not persisted")
	}
}

func TestProviderErrorParsing(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	hdr := func(kv ...string) http.Header {
		h := http.Header{}
		for i := 0; i < len(kv); i += 2 {
			h.Set(kv[i], kv[i+1])
		}
		return h
	}
	// Gemini: wrapped in an array, per-day quota -> next Pacific midnight
	e := parseGeminiAPIError(429, nil, []byte(`[{"error":{"code":429,"message":"quota","status":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.rpc.QuotaFailure","violations":[{"quotaId":"GenerateRequestsPerDayPerProjectPerModel"}]},{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"33s"}]}}]`), now)
	if e.Kind != "rate" || !e.Daily || !e.Until.Equal(nextQuotaReset(now)) || e.Retry != 33*time.Second {
		t.Fatalf("gemini: %+v", e)
	}
	if e := parseGeminiAPIError(400, nil, []byte(`{"error":{"code":400,"message":"API key not valid","status":"INVALID_ARGUMENT","details":[{"reason":"API_KEY_INVALID"}]}}`), now); e.Kind != "invalid" {
		t.Fatalf("gemini invalid: %+v", e)
	}
	if e := parseGeminiAPIError(400, nil, []byte(`{"error":{"code":400,"message":"bad voice","status":"INVALID_ARGUMENT"}}`), now); e.Kind != "request" {
		t.Fatalf("gemini request: %+v", e)
	}
	// OpenAI
	if e := parseOpenAIError(429, hdr("Retry-After", "7"), []byte(`{"error":{"message":"slow down","type":"requests","code":"rate_limit_exceeded"}}`), now); e.Kind != "rate" || e.Retry != 7*time.Second {
		t.Fatalf("openai retry-after: %+v", e)
	}
	if e := parseOpenAIError(429, hdr("x-ratelimit-remaining-tokens", "0", "x-ratelimit-reset-tokens", "6m0s", "x-ratelimit-reset-requests", "20ms"), []byte(`{}`), now); e.Retry != 6*time.Minute {
		t.Fatalf("openai reset headers: %+v", e)
	}
	if e := parseOpenAIError(429, nil, []byte(`{"error":{"message":"You exceeded your current quota","type":"insufficient_quota","code":"insufficient_quota"}}`), now); e.Kind != "invalid" {
		t.Fatalf("openai insufficient_quota: %+v", e)
	}
	if e := parseOpenAIError(401, nil, []byte(`{"error":{"message":"Incorrect API key"}}`), now); e.Kind != "invalid" {
		t.Fatalf("openai 401: %+v", e)
	}
	// Anthropic
	if e := parseAnthropicError(429, hdr("retry-after", "12"), []byte(`{"type":"error","error":{"type":"rate_limit_error","message":"x"}}`), now); e.Kind != "rate" || e.Retry != 12*time.Second {
		t.Fatalf("anthropic retry-after: %+v", e)
	}
	if e := parseAnthropicError(429, hdr("anthropic-ratelimit-tokens-reset", now.Add(90*time.Second).Format(time.RFC3339)), []byte(`{}`), now); e.Retry != 90*time.Second {
		t.Fatalf("anthropic reset: %+v", e)
	}
	if e := parseAnthropicError(529, nil, []byte(`{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`), now); e.Kind != "transient" {
		t.Fatalf("anthropic 529: %+v", e)
	}
	// ElevenLabs
	if e := parseElevenLabsError(401, nil, []byte(`{"detail":{"status":"quota_exceeded","message":"This request exceeds your quota"}}`), now); e.Kind != "rate" || !e.Daily {
		t.Fatalf("elevenlabs quota: %+v", e)
	}
	if e := parseElevenLabsError(401, nil, []byte(`{"detail":{"status":"invalid_api_key","message":"Invalid API key"}}`), now); e.Kind != "invalid" {
		t.Fatalf("elevenlabs invalid: %+v", e)
	}
	// custom: HTTP-date Retry-After
	if e := parseGenericError(429, hdr("Retry-After", now.Add(30*time.Second).Format(http.TimeFormat)), []byte(`{"error":"busy"}`), now); e.Kind != "rate" || e.Retry != 30*time.Second || e.Message != "busy" {
		t.Fatalf("custom: %+v", e)
	}
}

// A custom pool puts the key in the configured header and rotates past a
// rate-limited key, honoring Retry-After.
func TestCustomPoolHeaderAndRotation(t *testing.T) {
	s, v, _ := testEnv(t)
	_ = v.Set("ACME_KEY_1", "k1", false, "")
	_ = v.Set("ACME_KEY_2", "k2", false, "")
	var mu sync.Mutex
	seen := map[string]int{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "" {
			t.Error("key must never be in the URL")
		}
		auth := r.Header.Get("X-Acme-Auth")
		mu.Lock()
		seen[auth]++
		mu.Unlock()
		if auth == "Token k1" {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(429)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()
	ps := NewPools(s, v)
	if _, err := ps.Put(PoolConfig{ID: "acme", Provider: "custom", Prefix: "ACME_KEY", Header: "X-Acme-Auth", HeaderPrefix: "Token ", BaseURL: "http://127.0.0.1", CheckPath: "/ping"}); err != nil {
		t.Fatal(err)
	}
	p := ps.Get("acme")
	p.base = ts.URL
	for i := 0; i < 3; i++ {
		body, key, err := p.Do(context.Background(), "default", 0, func(ctx context.Context, k string) ([]byte, error) { return p.get(ctx, k, "/x") })
		if err != nil || key != "ACME_KEY_2" || !strings.Contains(string(body), "ok") {
			t.Fatalf("call %d: %s %v", i, key, err)
		}
	}
	if seen["Token k1"] != 1 {
		t.Fatalf("rate-limited key retried: %v", seen)
	}
	for _, st := range p.Status() {
		if st.Name == "ACME_KEY_1" {
			until, _ := time.Parse(time.RFC3339, st.Until)
			if st.State != "cooling" || time.Until(until) < 100*time.Second {
				t.Fatalf("Retry-After not honored: %+v", st)
			}
		}
	}
	if !p.CanCheck() || p.Check(context.Background(), "ACME_KEY_2") != nil {
		t.Fatal("check should pass with key 2")
	}
	if p.Check(context.Background(), "GEMINI_API_KEY_1") == nil {
		t.Fatal("check must refuse foreign keys")
	}
	// usage of a non-gemini pool is stored under its own meta key
	if s.Meta("pool:acme:usage") == "" || strings.Contains(s.Meta("gemini_usage"), "ACME") {
		t.Fatal("usage stored in the wrong place")
	}
}

// The Gemini pool sends its key in x-goog-api-key.
func TestGeminiPoolHeader(t *testing.T) {
	s, v, _ := testEnv(t)
	_ = v.Set("GEMINI_API_KEY_1", "gk", false, "")
	got := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("x-goog-api-key")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()
	p := NewPools(s, v).Get("gemini")
	p.base = ts.URL
	if err := p.Check(context.Background(), "GEMINI_API_KEY_1"); err != nil || got != "gk" {
		t.Fatalf("header = %q err=%v", got, err)
	}
}
