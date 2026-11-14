package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AdminAuth protects the admin API and UI. Two ways in:
//   - X-Admin-Token header (scripts; the token file lives in the data dir)
//   - a session cookie obtained with the admin password (or the token) via
//     POST /api/login.
type AdminAuth struct {
	dataDir string
	token   string

	mu       sync.Mutex
	sessions map[string]*adminSession
	fails    []time.Time
}

type adminSession struct {
	created, last time.Time
}

const (
	sessionCookie   = "agw_session"
	sessionIdle     = 30 * time.Minute
	sessionAbsolute = 12 * time.Hour
	pbkdfIter       = 600_000
)

type passwordFile struct {
	Salt  string `json:"salt"`
	Hash  string `json:"hash"`
	Iter  int    `json:"iter"`
	SetAt string `json:"set_at"`
}

func NewAdminAuth(dataDir, token string) *AdminAuth {
	return &AdminAuth{dataDir: dataDir, token: token, sessions: map[string]*adminSession{}}
}

func passwordPath(dataDir string) string { return filepath.Join(dataDir, "admin-password.json") }

// SetPassword stores a PBKDF2-SHA256 hash of the admin password.
func SetPassword(dataDir, pw string) error {
	if len([]rune(pw)) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	h, err := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, 32)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(passwordFile{Salt: hex.EncodeToString(salt), Hash: hex.EncodeToString(h), Iter: pbkdfIter, SetAt: now()})
	return os.WriteFile(passwordPath(dataDir), b, 0o600)
}

func (a *AdminAuth) HasPassword() bool {
	_, err := os.Stat(passwordPath(a.dataDir))
	return err == nil
}

func (a *AdminAuth) checkPassword(pw string) bool {
	b, err := os.ReadFile(passwordPath(a.dataDir))
	if err != nil {
		return false
	}
	var pf passwordFile
	if json.Unmarshal(b, &pf) != nil {
		return false
	}
	salt, _ := hex.DecodeString(pf.Salt)
	want, _ := hex.DecodeString(pf.Hash)
	got, err := pbkdf2.Key(sha256.New, pw, salt, pf.Iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

func (a *AdminAuth) tokenOK(t string) bool {
	return t != "" && subtle.ConstantTimeCompare([]byte(t), []byte(a.token)) == 1
}

func (a *AdminAuth) throttled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	cut := time.Now().Add(-5 * time.Minute)
	keep := a.fails[:0]
	for _, t := range a.fails {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	a.fails = keep
	return len(a.fails) >= 8
}

func (a *AdminAuth) fail() {
	a.mu.Lock()
	a.fails = append(a.fails, time.Now())
	a.mu.Unlock()
}

func (a *AdminAuth) newSession(w http.ResponseWriter) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	a.mu.Lock()
	a.sessions[id] = &adminSession{created: time.Now(), last: time.Now()}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionAbsolute.Seconds())})
}

func (a *AdminAuth) sessionOK(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[c.Value]
	if s == nil {
		return false
	}
	if time.Since(s.last) > sessionIdle || time.Since(s.created) > sessionAbsolute {
		delete(a.sessions, c.Value)
		return false
	}
	s.last = time.Now()
	return true
}

// Authorized reports whether the request may use the admin API. Cookie
// sessions must also send the X-AGW header on state-changing requests, which
// browsers won't add cross-site without a CORS preflight (CSRF protection).
func (a *AdminAuth) Authorized(r *http.Request) bool {
	if a.tokenOK(r.Header.Get("X-Admin-Token")) {
		return true
	}
	if !a.sessionOK(r) {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-AGW") != "1" {
		return false
	}
	return true
}

func (a *AdminAuth) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"authenticated": a.Authorized(r), "password_set": a.HasPassword()})
	})
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-AGW") != "1" {
			writeErr(w, 400, errors.New("missing X-AGW header"))
			return
		}
		if a.throttled() {
			writeErr(w, http.StatusTooManyRequests, errors.New("too many failed attempts; try again in a few minutes"))
			return
		}
		var in struct {
			Password string `json:"password"`
			Token    string `json:"token"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		ok := (in.Password != "" && a.checkPassword(in.Password)) || a.tokenOK(in.Token)
		if !ok {
			a.fail()
			time.Sleep(400 * time.Millisecond)
			writeErr(w, http.StatusUnauthorized, errors.New("invalid password or link"))
			return
		}
		a.newSession(w)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookie); err == nil {
			a.mu.Lock()
			delete(a.sessions, c.Value)
			a.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
}
