package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PoolConfig is one user-defined key pool. Stored in meta "key_pools".
type PoolConfig struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"` // gemini | openai | anthropic | elevenlabs | custom
	Prefix   string `json:"prefix"`   // secret names: PREFIX or PREFIX_*
	// custom provider (or overrides): which header carries the key, e.g.
	// "Authorization" with prefix "Bearer ".
	Header       string `json:"header,omitempty"`
	HeaderPrefix string `json:"header_prefix,omitempty"`
	BaseURL      string `json:"base_url,omitempty"`
	CheckPath    string `json:"check_path,omitempty"` // GET path used by "Dene"
	CreatedAt    string `json:"created_at,omitempty"`
}

// poolProvider adapts a pool to one API: where the key goes and what errors
// mean (rate limit → wait how long, invalid key, transient, bad request).
type poolProvider struct {
	ID           string            `json:"id"`
	Label        string            `json:"label"`
	Prefix       string            `json:"prefix"` // suggested secret prefix
	Header       string            `json:"header"`
	ValuePrefix  string            `json:"value_prefix,omitempty"`
	ExtraHeaders map[string]string `json:"-"`
	BaseURL      string            `json:"base_url,omitempty"`
	CheckPath    string            `json:"check_path,omitempty"`
	KeyURL       string            `json:"key_url,omitempty"` // where users get keys
	Hint         string            `json:"hint,omitempty"`
	parse        func(code int, h http.Header, body []byte, now time.Time) *PoolAPIError
}

var poolProviders = []*poolProvider{
	{ID: "gemini", Label: "Gemini", Prefix: "GEMINI_API_KEY", Header: "x-goog-api-key", BaseURL: geminiAPIBase,
		CheckPath: "/v1beta/models?pageSize=1", KeyURL: "https://aistudio.google.com/apikey",
		Hint:  "Keys in the same Google Cloud project share one quota; to get more quota, use keys from different projects. The daily quota resets at midnight Pacific time.",
		parse: parseGeminiAPIError},
	{ID: "openai", Label: "OpenAI", Prefix: "OPENAI_API_KEY", Header: "Authorization", ValuePrefix: "Bearer ", BaseURL: "https://api.openai.com",
		CheckPath: "/v1/models", KeyURL: "https://platform.openai.com/api-keys",
		Hint:  "Keys in the same organization share one rate limit.",
		parse: parseOpenAIError},
	{ID: "anthropic", Label: "Anthropic", Prefix: "ANTHROPIC_API_KEY", Header: "x-api-key", BaseURL: "https://api.anthropic.com",
		ExtraHeaders: map[string]string{"anthropic-version": "2023-06-01"},
		CheckPath:    "/v1/models?limit=1", KeyURL: "https://console.anthropic.com/settings/keys",
		Hint:  "Keys in the same organization share one rate limit.",
		parse: parseAnthropicError},
	{ID: "elevenlabs", Label: "ElevenLabs", Prefix: "ELEVENLABS_API_KEY", Header: "xi-api-key", BaseURL: "https://api.elevenlabs.io",
		CheckPath: "/v1/user", KeyURL: "https://elevenlabs.io/app/settings/api-keys",
		parse: parseElevenLabsError},
	{ID: "custom", Label: "Custom", Prefix: "", Header: "", parse: parseGenericError},
}

func providerFor(id string) *poolProvider {
	for _, p := range poolProviders {
		if p.ID == id {
			return p
		}
	}
	return poolProviders[len(poolProviders)-1] // custom
}

func defaultGeminiPool() PoolConfig {
	return PoolConfig{ID: "gemini", Name: "Gemini", Provider: "gemini", Prefix: "GEMINI_API_KEY"}
}

// ---- shared header helpers ----

// retryAfter parses Retry-After as seconds or an HTTP date.
func retryAfter(h http.Header, now time.Time) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
		return time.Duration(f * float64(time.Second))
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// genericKind: the HTTP-status-only part every provider shares.
func genericKind(code int) string {
	switch {
	case code == 429:
		return "rate"
	case code == 401 || code == 403:
		return "invalid"
	case code >= 500 || code == 408:
		return "transient"
	}
	return "request"
}

func baseError(code int, body []byte) *PoolAPIError {
	return &PoolAPIError{HTTP: code, Status: http.StatusText(code), Message: strings.TrimSpace(truncate(string(body), 400)), Kind: genericKind(code)}
}

// parseGenericError: custom pools. 429 waits Retry-After (60s by default).
func parseGenericError(code int, h http.Header, body []byte, now time.Time) *PoolAPIError {
	e := baseError(code, body)
	var env struct {
		Error any `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil {
		switch x := env.Error.(type) {
		case string:
			e.Message = x
		case map[string]any:
			if m, ok := x["message"].(string); ok && m != "" {
				e.Message = m
			}
		}
	}
	e.Retry = retryAfter(h, now)
	return e
}

// ---- Gemini ----

// parseGeminiAPIError understands Google's error envelope (sometimes wrapped
// in an array) with RetryInfo / QuotaFailure / ErrorInfo details. A per-day
// quota resets at midnight Pacific time.
func parseGeminiAPIError(code int, _ http.Header, body []byte, now time.Time) *PoolAPIError {
	e := &PoolAPIError{HTTP: code, Message: strings.TrimSpace(truncate(string(body), 400))}
	var env struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
			Details []struct {
				Type       string `json:"@type"`
				Reason     string `json:"reason"`
				RetryDelay string `json:"retryDelay"`
				Violations []struct {
					QuotaID string `json:"quotaId"`
				} `json:"violations"`
			} `json:"details"`
		} `json:"error"`
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' { // some endpoints wrap the error in an array
		var arr []json.RawMessage
		if json.Unmarshal(trimmed, &arr) == nil && len(arr) > 0 {
			trimmed = arr[0]
		}
	}
	if json.Unmarshal(trimmed, &env) == nil && env.Error.Message != "" {
		e.Message, e.Status = env.Error.Message, env.Error.Status
		for _, d := range env.Error.Details {
			if d.Reason != "" {
				e.Reason = d.Reason
			}
			if d.RetryDelay != "" {
				if dur, err := time.ParseDuration(d.RetryDelay); err == nil {
					e.Retry = dur
				}
			}
			for _, v := range d.Violations {
				if v.QuotaID != "" {
					e.QuotaID = v.QuotaID
				}
			}
		}
	}
	switch {
	case e.HTTP == 429 || e.Status == "RESOURCE_EXHAUSTED":
		e.Kind = "rate"
		if strings.Contains(strings.ToLower(e.QuotaID), "perday") {
			e.Daily, e.Until = true, nextQuotaReset(now)
		}
	case e.Reason == "API_KEY_INVALID" || e.Reason == "API_KEY_EXPIRED" || e.HTTP == 401:
		e.Kind = "invalid"
	case e.HTTP == 403:
		// API not enabled, key restricted, region blocked: unusable as-is.
		e.Kind = "invalid"
	case e.HTTP >= 500 || e.HTTP == 408:
		e.Kind = "transient"
	default:
		e.Kind = "request"
	}
	return e
}

// parseGeminiError is kept for callers that only have status + body.
func parseGeminiError(code int, body []byte) *PoolAPIError {
	return parseGeminiAPIError(code, http.Header{}, body, time.Now())
}

// ---- OpenAI ----

// parseOpenAIError: Retry-After, else x-ratelimit-reset-{requests,tokens}
// (durations like "6m0s", "20ms"). insufficient_quota is a billing problem,
// not a rate limit: the key is unusable until the user fixes it.
func parseOpenAIError(code int, h http.Header, body []byte, now time.Time) *PoolAPIError {
	e := baseError(code, body)
	var env struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    any    `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil && env.Error.Message != "" {
		e.Message, e.Status = env.Error.Message, env.Error.Type
		if s, ok := env.Error.Code.(string); ok {
			e.Reason = s
		}
	}
	if e.Reason == "insufficient_quota" || e.Status == "insufficient_quota" {
		e.Kind = "invalid"
		return e
	}
	if e.Kind == "rate" {
		e.Retry = retryAfter(h, now)
		if e.Retry == 0 {
			e.Retry = openAIResetWait(h)
		}
	}
	return e
}

func openAIResetWait(h http.Header) time.Duration {
	parse := func(k string) time.Duration {
		v := strings.TrimSpace(h.Get(k))
		if v == "" {
			return 0
		}
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return time.Duration(f * float64(time.Second))
		}
		return 0
	}
	req, tok := parse("x-ratelimit-reset-requests"), parse("x-ratelimit-reset-tokens")
	switch {
	case h.Get("x-ratelimit-remaining-requests") == "0" && req > 0:
		return req
	case h.Get("x-ratelimit-remaining-tokens") == "0" && tok > 0:
		return tok
	}
	return max(req, tok)
}

// ---- Anthropic ----

// parseAnthropicError: retry-after seconds, else the earliest
// anthropic-ratelimit-*-reset (RFC 3339). 529 (overloaded) is transient.
func parseAnthropicError(code int, h http.Header, body []byte, now time.Time) *PoolAPIError {
	e := baseError(code, body)
	var env struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil && env.Error.Message != "" {
		e.Message, e.Status, e.Reason = env.Error.Message, env.Error.Type, env.Error.Type
	}
	if e.Status == "overloaded_error" {
		e.Kind = "transient"
	}
	if e.Kind == "rate" {
		e.Retry = retryAfter(h, now)
		if e.Retry == 0 {
			var until time.Time
			for _, k := range []string{"anthropic-ratelimit-requests-reset", "anthropic-ratelimit-tokens-reset", "anthropic-ratelimit-input-tokens-reset", "anthropic-ratelimit-output-tokens-reset"} {
				if t, err := time.Parse(time.RFC3339, h.Get(k)); err == nil && t.After(now) && (until.IsZero() || t.Before(until)) {
					until = t
				}
			}
			if !until.IsZero() {
				e.Retry = until.Sub(now)
			}
		}
	}
	return e
}

// ---- ElevenLabs ----

// parseElevenLabsError: {"detail":{"status":..., "message":...}}.
// quota_exceeded means the plan's characters are used up: wait a day.
func parseElevenLabsError(code int, h http.Header, body []byte, now time.Time) *PoolAPIError {
	e := baseError(code, body)
	var env struct {
		Detail any `json:"detail"`
	}
	if json.Unmarshal(body, &env) == nil {
		switch d := env.Detail.(type) {
		case string:
			e.Message = d
		case map[string]any:
			if s, _ := d["status"].(string); s != "" {
				e.Reason, e.Status = s, s
			}
			if m, _ := d["message"].(string); m != "" {
				e.Message = m
			}
		}
	}
	switch e.Reason {
	case "quota_exceeded":
		e.Kind, e.Daily, e.Until = "rate", true, now.Add(24*time.Hour)
	case "invalid_api_key", "missing_permissions":
		e.Kind = "invalid"
	case "too_many_concurrent_requests", "system_busy":
		e.Kind = "rate"
	}
	if e.Kind == "rate" && e.Until.IsZero() {
		e.Retry = retryAfter(h, now)
		if e.Retry == 0 {
			e.Retry = 5 * time.Second
		}
	}
	return e
}

// ---- pool registry ----

// Pools holds every configured pool. The Gemini pool always exists (the
// built-in gemini server uses it) and keeps the id "gemini".
type Pools struct {
	store *Store
	vault *Vault
	mu    sync.Mutex
	pools map[string]*KeyPool
}

var (
	poolIDRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	poolPrefixRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)
	headerNameRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

func NewPools(store *Store, vault *Vault) *Pools {
	ps := &Pools{store: store, vault: vault, pools: map[string]*KeyPool{}}
	var cfgs []PoolConfig
	if raw := store.Meta("key_pools"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfgs)
	}
	hasGemini := false
	for _, c := range cfgs {
		if c.ID == "gemini" {
			hasGemini = true
		}
		ps.pools[c.ID] = newKeyPool(store, vault, c)
	}
	if !hasGemini {
		g := defaultGeminiPool()
		g.CreatedAt = now()
		ps.pools[g.ID] = newKeyPool(store, vault, g)
		ps.saveLocked()
	}
	return ps
}

func (ps *Pools) saveLocked() {
	cfgs := make([]PoolConfig, 0, len(ps.pools))
	for _, p := range ps.pools {
		cfgs = append(cfgs, p.Config())
	}
	sort.Slice(cfgs, func(i, j int) bool { return cfgs[i].ID < cfgs[j].ID })
	b, _ := json.Marshal(cfgs)
	ps.store.SetMeta("key_pools", string(b))
}

func (ps *Pools) Get(id string) *KeyPool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.pools[id]
}

// List returns pools ordered with Gemini first, then by name.
func (ps *Pools) List() []*KeyPool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	out := make([]*KeyPool, 0, len(ps.pools))
	for _, p := range ps.pools {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Config(), out[j].Config()
		if (a.ID == "gemini") != (b.ID == "gemini") {
			return a.ID == "gemini"
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return out
}

// ForSecret returns the pool a secret belongs to, if any.
func (ps *Pools) ForSecret(name string) *KeyPool {
	for _, p := range ps.List() {
		if p.Owns(name) {
			return p
		}
	}
	return nil
}

func prefixesOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"_") || strings.HasPrefix(b, a+"_")
}

// Put adds or updates a pool. The Gemini pool's id, provider and prefix are
// fixed so the existing GEMINI_API_KEY* secrets keep working.
func (ps *Pools) Put(c PoolConfig) (PoolConfig, error) {
	c.ID = strings.TrimSpace(c.ID)
	c.Name = strings.TrimSpace(c.Name)
	c.Prefix = strings.ToUpper(strings.TrimSpace(c.Prefix))
	c.Header = strings.TrimSpace(c.Header)
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	c.CheckPath = strings.TrimSpace(c.CheckPath)
	if !poolIDRe.MatchString(c.ID) {
		return c, errors.New("pool id: lowercase letters, digits and dashes")
	}
	prov := providerFor(c.Provider)
	if prov.ID != c.Provider {
		return c, fmt.Errorf("unknown provider %q", c.Provider)
	}
	if c.Name == "" {
		c.Name = prov.Label
	}
	if c.Prefix == "" {
		c.Prefix = prov.Prefix
	}
	if !poolPrefixRe.MatchString(c.Prefix) {
		return c, errors.New("secret prefix: uppercase letters, digits and underscores, e.g. OPENAI_API_KEY")
	}
	if c.Provider == "custom" {
		if !headerNameRe.MatchString(c.Header) {
			return c, errors.New("custom pools need the header name that carries the key, e.g. Authorization")
		}
	} else if c.Header != "" && !headerNameRe.MatchString(c.Header) {
		return c, errors.New("invalid header name")
	}
	if strings.ContainsAny(c.HeaderPrefix, "\r\n") {
		return c, errors.New("invalid header value prefix")
	}
	if c.BaseURL != "" && !validPoolBaseURL(c.BaseURL) {
		return c, errors.New("base URL must be https (or http://localhost)")
	}
	if c.CheckPath != "" && !strings.HasPrefix(c.CheckPath, "/") {
		return c, errors.New("check path must start with /")
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if old, ok := ps.pools[c.ID]; ok {
		oc := old.Config()
		c.CreatedAt = oc.CreatedAt
		if c.ID == "gemini" && (c.Provider != oc.Provider || c.Prefix != oc.Prefix) {
			return c, errors.New("the Gemini pool's provider and prefix can't be changed (the built-in gemini server and existing keys use them)")
		}
	} else {
		c.CreatedAt = now()
	}
	for id, p := range ps.pools {
		if id != c.ID && prefixesOverlap(p.Config().Prefix, c.Prefix) {
			return c, fmt.Errorf("prefix %s overlaps pool %q (%s)", c.Prefix, id, p.Config().Prefix)
		}
	}
	if old, ok := ps.pools[c.ID]; ok {
		old.setConfig(c)
	} else {
		ps.pools[c.ID] = newKeyPool(ps.store, ps.vault, c)
	}
	ps.saveLocked()
	return c, nil
}

// Delete removes a pool's configuration. Its secrets stay in the vault.
func (ps *Pools) Delete(id string) error {
	if id == "gemini" {
		return errors.New("the Gemini pool is used by the built-in gemini server and can't be removed")
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, ok := ps.pools[id]; !ok {
		return fmt.Errorf("pool %q not found", id)
	}
	delete(ps.pools, id)
	ps.saveLocked()
	return nil
}

// validPoolBaseURL: https anywhere, or plain http only to this machine. Keys
// are sent to this URL, so "http://localhost.example.com" must not pass.
func validPoolBaseURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}
