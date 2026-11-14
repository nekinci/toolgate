package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// KeyPool rotates calls across every vault secret that belongs to the pool:
// secrets named PREFIX or PREFIX_* (e.g. GEMINI_API_KEY, GEMINI_API_KEY_2).
// Rate limits are tracked per key and scope (usually the model), so a key that
// hit one model's quota can still serve others. What a provider's errors mean,
// how long to wait and which header carries the key come from its adapter
// (keypool_providers.go).
type KeyPool struct {
	vault *Vault
	store *Store
	base  string // API base URL; overridable in tests
	hc    *http.Client

	mu       sync.Mutex
	cfg      PoolConfig
	prov     *poolProvider
	cool     map[string]coolState // key|scope -> cooldown
	invalid  map[string]string    // key -> reason (until the key is replaced)
	inflight map[string]int
	lastUsed map[string]time.Time
	usage    map[string]*keyUsage // key -> usage (today + total)
	loaded   bool
}

type coolState struct {
	Until  time.Time
	Reason string
	Daily  bool
}

type keyUsage struct {
	Day         string `json:"day"`
	Calls       int    `json:"calls"`
	Errors      int    `json:"errors"`
	RateLimited int    `json:"rate_limited"`
	Chars       int    `json:"chars"`
	TotalCalls  int    `json:"total_calls"`
	LastUsed    string `json:"last_used,omitempty"`
}

const geminiAPIBase = "https://generativelanguage.googleapis.com"

// IsGeminiKeyName reports whether a secret belongs to the default Gemini pool.
func IsGeminiKeyName(n string) bool { return poolKeyMatch("GEMINI_API_KEY", n) }

// poolKeyMatch: name is PREFIX or PREFIX_<A-Z0-9_>.
func poolKeyMatch(prefix, name string) bool {
	if name == prefix {
		return true
	}
	rest, ok := strings.CutPrefix(name, prefix+"_")
	return ok && rest != "" && poolSuffixRe.MatchString(rest)
}

var poolSuffixRe = regexp.MustCompile(`^[A-Z0-9_]+$`)

func newKeyPool(store *Store, vault *Vault, cfg PoolConfig) *KeyPool {
	p := &KeyPool{vault: vault, store: store, hc: &http.Client{Timeout: 4 * time.Minute},
		cool: map[string]coolState{}, invalid: map[string]string{}, inflight: map[string]int{},
		lastUsed: map[string]time.Time{}, usage: map[string]*keyUsage{}}
	p.setConfig(cfg)
	return p
}

// NewGeminiPool returns a standalone pool with the default Gemini config.
func NewGeminiPool(store *Store, vault *Vault) *KeyPool {
	return newKeyPool(store, vault, defaultGeminiPool())
}

func (p *KeyPool) setConfig(cfg PoolConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = cfg
	p.prov = providerFor(cfg.Provider)
	p.base = strings.TrimRight(firstNonEmpty(cfg.BaseURL, p.prov.BaseURL), "/")
}

func (p *KeyPool) Config() PoolConfig {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg
}

func (p *KeyPool) label() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return firstNonEmpty(p.cfg.Name, p.prov.Label)
}

// Owns reports whether a secret name belongs to this pool.
func (p *KeyPool) Owns(name string) bool {
	return poolKeyMatch(p.Config().Prefix, name)
}

// Keys lists the pool's secret names (never values), sorted.
func (p *KeyPool) Keys() []string {
	prefix := p.Config().Prefix
	list, _ := p.vault.List(false)
	var out []string
	for _, s := range list {
		if poolKeyMatch(prefix, s.Name) && s.HasValue {
			out = append(out, s.Name)
		}
	}
	sort.Strings(out)
	return out
}

// NextKeyName suggests the next free secret name (PREFIX_1, PREFIX_2, …).
func (p *KeyPool) NextKeyName() string {
	prefix := p.Config().Prefix
	have := map[string]bool{}
	for _, k := range p.Keys() {
		have[k] = true
	}
	for i := 1; ; i++ {
		if n := fmt.Sprintf("%s_%d", prefix, i); !have[n] {
			return n
		}
	}
}

// pacific midnight is when Gemini daily quotas reset.
func nextQuotaReset(t time.Time) time.Time {
	loc, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		loc = time.FixedZone("PT", -8*3600)
	}
	lt := t.In(loc)
	return time.Date(lt.Year(), lt.Month(), lt.Day()+1, 0, 0, 0, 0, loc)
}

func today() string { return time.Now().In(time.Local).Format("2006-01-02") }

// metaKeys: the Gemini pool keeps the names it had before pools were
// generalized, so existing usage counters and invalid marks carry over.
func (p *KeyPool) metaKeys() (usage, invalid string) {
	if id := p.cfg.ID; id != "gemini" {
		return "pool:" + id + ":usage", "pool:" + id + ":invalid"
	}
	return "gemini_usage", "gemini_invalid"
}

func (p *KeyPool) loadUsage() {
	if p.loaded {
		return
	}
	p.loaded = true
	uk, ik := p.metaKeys()
	if raw := p.store.Meta(uk); raw != "" {
		_ = json.Unmarshal([]byte(raw), &p.usage)
	}
	if raw := p.store.Meta(ik); raw != "" {
		_ = json.Unmarshal([]byte(raw), &p.invalid)
	}
	if p.usage == nil {
		p.usage = map[string]*keyUsage{}
	}
	if p.invalid == nil {
		p.invalid = map[string]string{}
	}
}

func (p *KeyPool) saveLocked() {
	uk, ik := p.metaKeys()
	b, _ := json.Marshal(p.usage)
	p.store.SetMeta(uk, string(b))
	b, _ = json.Marshal(p.invalid)
	p.store.SetMeta(ik, string(b))
}

func (p *KeyPool) usageLocked(key string) *keyUsage {
	u := p.usage[key]
	if u == nil {
		u = &keyUsage{}
		p.usage[key] = u
	}
	if d := today(); u.Day != d {
		u.Day, u.Calls, u.Errors, u.RateLimited, u.Chars = d, 0, 0, 0, 0
	}
	return u
}

// KeyChanged clears the invalid/cooldown marks of a key that was replaced.
func (p *KeyPool) KeyChanged(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.loadUsage()
	delete(p.invalid, name)
	for k := range p.cool {
		if strings.HasPrefix(k, name+"|") {
			delete(p.cool, k)
		}
	}
	p.saveLocked()
}

// NoKeyError: every key is cooling down, invalid, or the pool is empty.
type NoKeyError struct {
	Pool      string // human label, e.g. "Gemini"
	Empty     bool
	NextReady time.Time
	Reasons   []string
}

func (e *NoKeyError) Error() string {
	label := firstNonEmpty(e.Pool, "Gemini")
	if e.Empty {
		return "no " + label + " API keys in the gateway vault"
	}
	s := "all " + label + " API keys are rate limited or unusable for this model"
	if !e.NextReady.IsZero() {
		s += fmt.Sprintf("; the next key is available in %s (at %s)", time.Until(e.NextReady).Round(time.Second), e.NextReady.Local().Format("15:04"))
	}
	if len(e.Reasons) > 0 {
		s += " [" + strings.Join(e.Reasons, "; ") + "]"
	}
	return s
}

// acquire picks the least busy, least recently used key that is free for scope.
func (p *KeyPool) acquire(scope string, skip map[string]bool) (string, string, error) {
	keys := p.Keys()
	label := p.label()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.loadUsage()
	if len(keys) == 0 {
		return "", "", &NoKeyError{Pool: label, Empty: true}
	}
	now := time.Now()
	var best string
	var next time.Time
	var reasons []string
	for _, k := range keys {
		if skip[k] {
			continue
		}
		if r, bad := p.invalid[k]; bad {
			reasons = append(reasons, k+": "+r)
			continue
		}
		if c, ok := p.cool[k+"|"+scope]; ok && c.Until.After(now) {
			if next.IsZero() || c.Until.Before(next) {
				next = c.Until
			}
			reasons = append(reasons, k+": "+c.Reason)
			continue
		}
		if best == "" || p.inflight[k] < p.inflight[best] ||
			(p.inflight[k] == p.inflight[best] && p.lastUsed[k].Before(p.lastUsed[best])) {
			best = k
		}
	}
	if best == "" {
		return "", "", &NoKeyError{Pool: label, NextReady: next, Reasons: reasons}
	}
	val, err := p.vault.Get(best)
	if err != nil {
		return "", "", err
	}
	p.inflight[best]++
	p.lastUsed[best] = now
	return best, val, nil
}

// PoolAPIError is an upstream API error, already classified by the
// provider adapter.
type PoolAPIError struct {
	Label   string // provider label for messages
	HTTP    int
	Status  string
	Message string
	Reason  string // provider reason code, e.g. API_KEY_INVALID, insufficient_quota
	Kind    string // rate | invalid | transient | request
	Retry   time.Duration
	Until   time.Time // absolute reset time (daily quota), if known
	Daily   bool
	QuotaID string
}

// geminiAPIError is the old name, kept for the Gemini tools.
type geminiAPIError = PoolAPIError

func (e *PoolAPIError) Error() string {
	return fmt.Sprintf("%s API %d %s: %s", firstNonEmpty(e.Label, "upstream"), e.HTTP, e.Status, e.Message)
}

// classify: "rate" (cool down this key for this scope), "invalid" (key
// unusable), "transient" (try another key briefly), or "request" (the request
// itself is wrong; don't retry).
func (e *PoolAPIError) classify() string {
	if e.Kind == "" {
		return "request"
	}
	return e.Kind
}

func (p *KeyPool) release(key, scope string, chars int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.loadUsage()
	if p.inflight[key] > 0 {
		p.inflight[key]--
	}
	u := p.usageLocked(key)
	u.Calls++
	u.TotalCalls++
	u.LastUsed = now()
	var ge *PoolAPIError
	if err == nil {
		u.Chars += chars
	} else if errors.As(err, &ge) {
		u.Errors++
		switch ge.classify() {
		case "rate":
			u.RateLimited++
			c := coolState{Reason: "rate limited", Daily: ge.Daily}
			switch {
			case !ge.Until.IsZero() && ge.Until.After(time.Now()):
				c.Until = ge.Until
			case ge.Retry > 0:
				c.Until = time.Now().Add(ge.Retry + time.Second)
			default:
				c.Until = time.Now().Add(60 * time.Second)
			}
			if ge.Daily {
				c.Reason = "daily quota reached"
			}
			p.cool[key+"|"+scope] = c
		case "invalid":
			p.invalid[key] = truncate(ge.Message, 160)
		case "transient":
			p.cool[key+"|"+scope] = coolState{Until: time.Now().Add(10 * time.Second), Reason: "server error"}
		}
	} else {
		u.Errors++
	}
	p.saveLocked()
}

// Do runs fn with pool keys until one succeeds, rotating past rate-limited,
// invalid and failing keys. fn returns the response body or *PoolAPIError.
func (p *KeyPool) Do(ctx context.Context, scope string, chars int, fn func(ctx context.Context, key string) ([]byte, error)) ([]byte, string, error) {
	skip := map[string]bool{}
	var lastErr error
	for attempt := 0; attempt < 12; attempt++ {
		name, val, err := p.acquire(scope, skip)
		if err != nil {
			if lastErr != nil {
				var nk *NoKeyError
				if errors.As(err, &nk) && !nk.Empty {
					return nil, "", fmt.Errorf("%v (last error: %v)", err, lastErr)
				}
			}
			return nil, "", err
		}
		body, err := fn(ctx, val)
		p.release(name, scope, chars, err)
		if err == nil {
			return body, name, nil
		}
		lastErr = err
		var ge *PoolAPIError
		if !errors.As(err, &ge) {
			if ctx.Err() != nil {
				return nil, name, err
			}
			skip[name] = true // network error: try another key
			continue
		}
		if ge.classify() == "request" {
			return nil, name, err
		}
		skip[name] = true
	}
	return nil, "", lastErr
}

// authorize puts the key where the provider expects it (never in the URL).
func (p *KeyPool) authorize(req *http.Request, key string) {
	p.mu.Lock()
	name, prefix := p.prov.Header, p.prov.ValuePrefix
	if p.cfg.Header != "" {
		name, prefix = p.cfg.Header, p.cfg.HeaderPrefix
	}
	extra := p.prov.ExtraHeaders
	p.mu.Unlock()
	req.Header.Set(name, prefix+key)
	for k, v := range extra {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
}

// post sends JSON to the provider API (path relative to the pool's base URL).
func (p *KeyPool) post(ctx context.Context, key, path string, body any) ([]byte, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	p.authorize(req, key)
	return p.send(req)
}

func (p *KeyPool) get(ctx context.Context, key, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+path, nil)
	if err != nil {
		return nil, err
	}
	p.authorize(req, key)
	return p.send(req)
}

func (p *KeyPool) send(req *http.Request) ([]byte, error) {
	resp, err := p.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		p.mu.Lock()
		prov, label := p.prov, firstNonEmpty(p.cfg.Name, p.prov.Label)
		p.mu.Unlock()
		e := prov.parse(resp.StatusCode, resp.Header, body, time.Now())
		e.Label = label
		return nil, e
	}
	return body, nil
}

// ---- status for the UI and agents ----

type PoolKeyStatus struct {
	Name     string            `json:"name"`
	Note     string            `json:"note,omitempty"`
	State    string            `json:"state"` // ready, cooling, daily, invalid
	Reason   string            `json:"reason,omitempty"`
	Until    string            `json:"until,omitempty"`
	Cooling  map[string]string `json:"cooling,omitempty"` // scope -> until
	Usage    keyUsage          `json:"usage"`
	InFlight int               `json:"in_flight"`
}

func (p *KeyPool) Status() []PoolKeyStatus {
	list, _ := p.vault.List(false)
	notes := map[string]string{}
	for _, s := range list {
		notes[s.Name] = s.Note
	}
	keys := p.Keys()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.loadUsage()
	now := time.Now()
	out := []PoolKeyStatus{}
	for _, k := range keys {
		st := PoolKeyStatus{Name: k, Note: notes[k], State: "ready", InFlight: p.inflight[k]}
		st.Usage = *p.usageLocked(k)
		if r, bad := p.invalid[k]; bad {
			st.State, st.Reason = "invalid", r
		}
		for ck, c := range p.cool {
			name, scope, _ := strings.Cut(ck, "|")
			if name != k || !c.Until.After(now) {
				continue
			}
			if st.Cooling == nil {
				st.Cooling = map[string]string{}
			}
			st.Cooling[scope] = c.Until.UTC().Format(time.RFC3339)
			if st.State == "ready" || (st.State == "cooling" && c.Daily) {
				st.State, st.Reason, st.Until = "cooling", c.Reason+" ("+scope+")", c.Until.UTC().Format(time.RFC3339)
				if c.Daily {
					st.State = "daily"
				}
			}
		}
		out = append(out, st)
	}
	return out
}

// CanCheck reports whether the pool knows a cheap request to validate a key.
func (p *KeyPool) CanCheck() bool {
	c := p.Config()
	return firstNonEmpty(c.CheckPath, p.prov.CheckPath) != "" && p.base != ""
}

// Check validates one key with a cheap authenticated request.
func (p *KeyPool) Check(ctx context.Context, name string) error {
	if !p.Owns(name) {
		return fmt.Errorf("%s is not a key of this pool", name)
	}
	if !p.CanCheck() {
		return errors.New("this pool has no check request configured")
	}
	val, err := p.vault.Get(name)
	if err != nil {
		return err
	}
	_, err = p.get(ctx, val, firstNonEmpty(p.Config().CheckPath, p.prov.CheckPath))
	p.mu.Lock()
	p.loadUsage()
	var ge *PoolAPIError
	if err == nil {
		delete(p.invalid, name)
	} else if errors.As(err, &ge) && ge.classify() == "invalid" {
		p.invalid[name] = truncate(ge.Message, 160)
	}
	p.saveLocked()
	p.mu.Unlock()
	return err
}
