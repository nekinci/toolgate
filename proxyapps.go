package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ProxyApp is one of the user's own programs that calls a provider API
// through /proxy/<pool>/… with its own token (agp_…). The app never sees a
// provider key; the gateway picks one from the pool per request. App tokens
// grant nothing else: no MCP access, no admin API.
type ProxyApp struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Pools     []string `json:"pools"` // pool ids this app may use
	CreatedAt string   `json:"created_at"`
	LastUsed  string   `json:"last_used,omitempty"`
	// token lifetime, as for agents (pairing.go)
	TokenTTLDays int    `json:"token_ttl_days,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
}

const proxyTokenPrefix = "agp_"

func (a *ProxyApp) Allows(pool string) bool {
	for _, p := range a.Pools {
		if p == pool {
			return true
		}
	}
	return false
}

func (s *Store) PutProxyApp(a *ProxyApp, tokenHash string) error {
	if !idRe.MatchString(a.ID) {
		return fmt.Errorf("invalid app id %q: use lowercase letters, digits and dashes", a.ID)
	}
	sort.Strings(a.Pools)
	b, _ := json.Marshal(a)
	if tokenHash == "" {
		res, err := s.db.Exec(`UPDATE proxy_apps SET data=? WHERE id=?`, string(b), a.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("app %q not found", a.ID)
		}
		return nil
	}
	_, err := s.db.Exec(`INSERT INTO proxy_apps(id,data,token_hash) VALUES(?,?,?)
		ON CONFLICT(id) DO UPDATE SET data=excluded.data, token_hash=excluded.token_hash`, a.ID, string(b), tokenHash)
	return err
}

func (s *Store) GetProxyApp(id string) (*ProxyApp, error) {
	var data string
	if err := s.db.QueryRow(`SELECT data FROM proxy_apps WHERE id=?`, id).Scan(&data); err != nil {
		return nil, fmt.Errorf("app %q not found", id)
	}
	var a ProxyApp
	return &a, json.Unmarshal([]byte(data), &a)
}

func (s *Store) ProxyAppByTokenHash(h string) (*ProxyApp, error) {
	var data string
	if err := s.db.QueryRow(`SELECT data FROM proxy_apps WHERE token_hash=?`, h).Scan(&data); err != nil {
		return nil, errors.New("unknown app token")
	}
	var a ProxyApp
	return &a, json.Unmarshal([]byte(data), &a)
}

func (s *Store) ListProxyApps() ([]*ProxyApp, error) {
	rows, err := s.db.Query(`SELECT data FROM proxy_apps ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ProxyApp{}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var a ProxyApp
		if json.Unmarshal([]byte(data), &a) == nil {
			out = append(out, &a)
		}
	}
	return out, rows.Err()
}

func (s *Store) DeleteProxyApp(id string) error {
	_, err := s.db.Exec(`DELETE FROM proxy_apps WHERE id=?`, id)
	return err
}

// touchProxyApp records last use at most once a minute per app.
var proxyTouch = struct {
	sync.Mutex
	last map[string]time.Time
}{last: map[string]time.Time{}}

func (s *Store) touchProxyApp(a *ProxyApp) {
	proxyTouch.Lock()
	if time.Since(proxyTouch.last[a.ID]) < time.Minute {
		proxyTouch.Unlock()
		return
	}
	proxyTouch.last[a.ID] = time.Now()
	proxyTouch.Unlock()
	a.LastUsed = now()
	_ = s.PutProxyApp(a, "")
}
