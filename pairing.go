package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---- token expiry ----
//
// Agents and proxy apps may have a token lifetime (token_ttl_days, 0 = never
// expires). expires_at is set whenever a token is minted (create, rotate,
// pairing) and when the lifetime is changed in the panel (counted from that
// moment). An expired token is refused with a message that says how to get a
// new one; nothing else about the agent or app changes.

const maxTokenTTLDays = 3650

func expiryFrom(days int) string {
	if days <= 0 {
		return ""
	}
	return time.Now().UTC().AddDate(0, 0, days).Format(time.RFC3339)
}

func tokenExpired(expiresAt string) bool {
	if expiresAt == "" {
		return false
	}
	t := parseTime(expiresAt)
	return !t.IsZero() && time.Now().After(t)
}

func validTTL(days int) error {
	if days < 0 || days > maxTokenTTLDays {
		return fmt.Errorf("token lifetime must be 0 (never) to %d days", maxTokenTTLDays)
	}
	return nil
}

// ---- pairing codes ----
//
// A pairing code is a short, single-use, 10-minute code (e.g. K7QM-3XPA) the
// panel shows instead of a token. Whatever runs on the client side exchanges
// it once at POST /pair for a fresh token, so the token goes straight into
// the client's config and never appears on screen or in a chat. Exchanging a
// code mints a new token for that agent/app; its previous token stops
// working. Codes live only in memory (hashed). After too many wrong codes
// the endpoint locks for a while; 40 random bits per code, 10 minutes and
// the lockout make guessing hopeless.

const (
	pairingTTL        = 10 * time.Minute
	pairingAlphabet   = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no 0/O, 1/I
	pairingMaxFails   = 20
	pairingLockWindow = 10 * time.Minute
)

type pairingEntry struct {
	Kind    string // "agent" or "app"
	ID      string
	Expires time.Time
}

type Pairings struct {
	mu     sync.Mutex
	codes  map[string]pairingEntry // sha256(normalized code) -> entry
	fails  []time.Time
	nowFn  func() time.Time
	locked time.Time
}

func NewPairings() *Pairings {
	return &Pairings{codes: map[string]pairingEntry{}, nowFn: time.Now}
}

func normalizePairingCode(c string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(c) {
		if strings.ContainsRune(pairingAlphabet, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func pairingHash(c string) string {
	h := sha256.Sum256([]byte(normalizePairingCode(c)))
	return hex.EncodeToString(h[:])
}

// New creates a code for kind/id. Older unused codes for the same target
// are dropped, so only the latest one works.
func (p *Pairings) New(kind, id string) (string, time.Time) {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	var code []byte
	for i, x := range buf {
		if i == 4 {
			code = append(code, '-')
		}
		code = append(code, pairingAlphabet[int(x)%len(pairingAlphabet)])
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.nowFn()
	for h, e := range p.codes {
		if (e.Kind == kind && e.ID == id) || now.After(e.Expires) {
			delete(p.codes, h)
		}
	}
	exp := now.Add(pairingTTL)
	p.codes[pairingHash(string(code))] = pairingEntry{Kind: kind, ID: id, Expires: exp}
	return string(code), exp
}

var (
	errPairingLocked  = errors.New("too many wrong pairing codes; try again in a few minutes")
	errPairingInvalid = errors.New("invalid or expired pairing code")
)

// Take consumes a code (single use).
func (p *Pairings) Take(code string) (pairingEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.nowFn()
	if now.Before(p.locked) {
		return pairingEntry{}, errPairingLocked
	}
	h := pairingHash(code)
	e, ok := p.codes[h]
	if ok {
		delete(p.codes, h)
	}
	if !ok || now.After(e.Expires) {
		recent := p.fails[:0]
		for _, t := range p.fails {
			if now.Sub(t) < pairingLockWindow {
				recent = append(recent, t)
			}
		}
		p.fails = append(recent, now)
		if len(p.fails) >= pairingMaxFails {
			p.locked, p.fails = now.Add(pairingLockWindow), nil
		}
		return pairingEntry{}, errPairingInvalid
	}
	return e, nil
}

// Cancel drops any open code for kind/id.
func (p *Pairings) Cancel(kind, id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for h, e := range p.codes {
		if e.Kind == kind && e.ID == id {
			delete(p.codes, h)
		}
	}
}

// handlePair is POST /pair (no auth; localhost only through hostGuard).
// Body: JSON {"code": "…"} or form code=…; format=token returns only the
// token as plain text, for $(curl …) in setup commands.
func (g *Gateway) handlePair(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var code, format string
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var in struct{ Code, Format string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		code, format = in.Code, in.Format
	} else {
		_ = r.ParseForm()
		code, format = r.PostForm.Get("code"), r.PostForm.Get("format")
	}
	fail := func(code int, err error) {
		if format == "token" {
			http.Error(w, err.Error(), code)
			return
		}
		writeErr(w, code, err)
	}
	e, err := g.pairings.Take(code)
	if err != nil {
		g.audit(&Agent{ID: "gateway"}, "pair", "", nil, "denied", 0, err.Error())
		if errors.Is(err, errPairingLocked) {
			fail(http.StatusTooManyRequests, err)
		} else {
			fail(http.StatusBadRequest, err)
		}
		return
	}
	tok, out, err := g.mintFor(e.Kind, e.ID)
	if err != nil {
		fail(http.StatusNotFound, err)
		return
	}
	g.audit(&Agent{ID: map[string]string{"agent": e.ID, "app": "app:" + e.ID}[e.Kind]}, "pair", e.ID, nil, "ok", 0, "token issued through a pairing code")
	if format == "token" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprint(w, tok)
		return
	}
	out["token"] = tok
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, out)
}

// mintFor issues a fresh token for an agent or app (replacing the old one)
// and restarts its lifetime.
func (g *Gateway) mintFor(kind, id string) (string, map[string]any, error) {
	switch kind {
	case "agent":
		a, err := g.store.GetAgent(id)
		if err != nil {
			return "", nil, err
		}
		tok := newToken("agw_")
		a.ExpiresAt = expiryFrom(a.TokenTTLDays)
		if err := g.store.PutAgent(a, hashToken(tok)); err != nil {
			return "", nil, err
		}
		return tok, map[string]any{"kind": "agent", "id": a.ID, "mcp_url": g.baseURL + "/mcp",
			"header": "Authorization: Bearer <token>", "expires_at": a.ExpiresAt}, nil
	case "app":
		a, err := g.store.GetProxyApp(id)
		if err != nil {
			return "", nil, err
		}
		tok := newToken(proxyTokenPrefix)
		a.ExpiresAt = expiryFrom(a.TokenTTLDays)
		if err := g.store.PutProxyApp(a, hashToken(tok)); err != nil {
			return "", nil, err
		}
		urls := map[string]string{}
		for _, p := range a.Pools {
			urls[p] = g.baseURL + "/proxy/" + p
		}
		return tok, map[string]any{"kind": "app", "id": a.ID, "proxy_urls": urls, "expires_at": a.ExpiresAt}, nil
	}
	return "", nil, fmt.Errorf("unknown pairing kind %q", kind)
}
