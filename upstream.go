package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	StatusIdle         = "idle"
	StatusConnecting   = "connecting"
	StatusConnected    = "connected"
	StatusAuthRequired = "auth_required"
	StatusError        = "error"
	StatusDisabled     = "disabled"
)

type AuthRequiredError struct {
	Server string
	URL    string
}

func (e *AuthRequiredError) Error() string {
	return fmt.Sprintf("server %q needs the user to sign in: %s", e.Server, e.URL)
}

type conn struct {
	mu        sync.Mutex
	session   *mcp.ClientSession
	status    string
	err       string
	authURL   string
	lastUsed  time.Time
	connectAt time.Time
	done      chan struct{}
	stderr    *ringBuffer
	gen       int // increments on every connect attempt; stale goroutines check it
	oauth     *auth.AuthorizationCodeHandler
	authIssue string // "client_required" when the server's OAuth needs a registered client
}

type ConnStatus struct {
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
	AuthURL   string `json:"auth_url,omitempty"`
	LastUsed  string `json:"last_used,omitempty"`
	ConnectAt string `json:"connected_at,omitempty"`
	Stderr    string `json:"stderr,omitempty"`
	AuthIssue string `json:"auth_issue,omitempty"`
}

type Manager struct {
	store   *Store
	vault   *Vault
	baseURL string
	log     *slog.Logger

	mu      sync.Mutex
	conns   map[string]*conn
	pending map[string]*pendingAuth // oauth state -> pending flow

	IdleTimeout time.Duration
	Builtins    map[string]func() *mcp.Server // built-in servers by name (transport "builtin")
}

func NewManager(store *Store, vault *Vault, baseURL string, log *slog.Logger) *Manager {
	return &Manager{store: store, vault: vault, baseURL: baseURL, log: log,
		conns: map[string]*conn{}, pending: map[string]*pendingAuth{}, IdleTimeout: 20 * time.Minute}
}

func (m *Manager) get(id string) *conn {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.conns[id]
	if !ok {
		c = &conn{status: StatusIdle, stderr: newRingBuffer(8192)}
		m.conns[id] = c
	}
	return c
}

func (m *Manager) Status(id string) ConnStatus {
	cfg, err := m.store.GetServer(id)
	c := m.get(id)
	c.mu.Lock()
	defer c.mu.Unlock()
	st := ConnStatus{Status: c.status, Error: c.err, AuthURL: c.authURL, Stderr: c.stderr.String(), AuthIssue: c.authIssue}
	if err == nil && !cfg.Enabled {
		st.Status = StatusDisabled
	}
	if !c.lastUsed.IsZero() {
		st.LastUsed = c.lastUsed.UTC().Format(time.RFC3339)
	}
	if !c.connectAt.IsZero() && c.session != nil {
		st.ConnectAt = c.connectAt.UTC().Format(time.RFC3339)
	}
	return st
}

// Session returns a live session, connecting lazily. If the server needs an
// interactive OAuth login, it returns *AuthRequiredError with the login URL
// while the connection keeps waiting in the background for the callback.
func (m *Manager) Session(ctx context.Context, id string) (*mcp.ClientSession, error) {
	cfg, err := m.store.GetServer(id)
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, fmt.Errorf("server %q is disabled", id)
	}
	if !m.store.IsApproved(cfg) {
		m.Disconnect(id)
		return nil, &PendingApprovalError{Server: id, Link: m.baseURL + "/ui/#c/" + id + "?review=1"}
	}
	if missing := m.missingSecrets(cfg); len(missing) > 0 {
		return nil, &MissingSecretsError{Server: id, Names: missing}
	}
	c := m.get(id)
	c.mu.Lock()
	if c.session != nil {
		c.lastUsed = time.Now()
		s := c.session
		c.mu.Unlock()
		return s, nil
	}
	if c.status != StatusConnecting && c.status != StatusAuthRequired {
		c.status, c.err, c.authURL = StatusConnecting, "", ""
		c.done = make(chan struct{})
		c.gen++
		go m.connect(cfg, c, c.gen, c.done)
	}
	done := c.done
	c.mu.Unlock()

	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-done:
			c.mu.Lock()
			s, e := c.session, c.err
			c.mu.Unlock()
			if s != nil {
				return s, nil
			}
			return nil, fmt.Errorf("connect %q: %s", id, e)
		case <-tick.C:
			c.mu.Lock()
			u := c.authURL
			c.mu.Unlock()
			if u != "" {
				return nil, &AuthRequiredError{Server: id, URL: u}
			}
		case <-deadline.C:
			return nil, fmt.Errorf("connect %q: still connecting after 45s, try again shortly", id)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (m *Manager) missingSecrets(cfg *ServerConfig) []string {
	out := []string{}
	for _, n := range RequiredSecrets(cfg) {
		if !m.vault.Has(n) {
			out = append(out, n)
		}
	}
	return out
}

func (m *Manager) connect(cfg *ServerConfig, c *conn, gen int, done chan struct{}) {
	defer close(done)
	fail := func(err error) {
		c.mu.Lock()
		if c.gen == gen {
			c.status, c.err, c.authURL = StatusError, err.Error(), ""
		}
		c.mu.Unlock()
		m.log.Warn("upstream connect failed", "server", cfg.ID, "err", err)
		m.store.Audit(AuditEntry{Agent: "gateway", Action: "connect", Target: cfg.ID, Args: "{}", Status: "error", Detail: err.Error()})
	}
	transport, err := m.transport(cfg, c)
	if err != nil {
		fail(err)
		return
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "toolgate", Version: version}, nil)
	start := time.Now()
	session, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		fail(err)
		return
	}
	c.mu.Lock()
	if c.gen != gen { // superseded (e.g. disconnected while connecting)
		c.mu.Unlock()
		session.Close()
		return
	}
	c.session, c.status, c.err, c.authURL = session, StatusConnected, "", ""
	c.connectAt, c.lastUsed = time.Now(), time.Now()
	c.mu.Unlock()
	m.store.Audit(AuditEntry{Agent: "gateway", Action: "connect", Target: cfg.ID, Args: "{}", Status: "ok", DurationMS: time.Since(start).Milliseconds()})

	go func() {
		_ = session.Wait()
		c.mu.Lock()
		if c.session == session {
			c.session = nil
			if c.status == StatusConnected {
				c.status = StatusIdle
			}
		}
		c.mu.Unlock()
	}()
	if err := m.indexTools(context.Background(), cfg.ID, session); err != nil {
		m.log.Warn("list tools failed", "server", cfg.ID, "err", err)
	}
}

func (m *Manager) indexTools(ctx context.Context, id string, s *mcp.ClientSession) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var tools []CachedTool
	for t, err := range s.Tools(ctx, nil) {
		if err != nil {
			return err
		}
		sch, _ := json.Marshal(t.InputSchema)
		var ann []byte
		if t.Annotations != nil {
			ann, _ = json.Marshal(t.Annotations)
		}
		desc := t.Description
		if desc == "" && t.Title != "" {
			desc = t.Title
		}
		tools = append(tools, CachedTool{ServerID: id, Name: t.Name, Description: desc, Schema: sch, Annotations: ann})
	}
	if err := m.store.ReplaceTools(id, tools); err != nil {
		return err
	}
	builtin := false
	if cfg, err := m.store.GetServer(id); err == nil {
		builtin = cfg.Transport == "builtin"
	}
	if n := m.store.AfterIndex(id, builtin, len(tools)); n > 0 {
		m.log.Info("pinned tools", "server", id, "count", n, "builtin", builtin)
	}
	return nil
}

func (m *Manager) Refresh(ctx context.Context, id string) (int, error) {
	s, err := m.Session(ctx, id)
	if err != nil {
		return 0, err
	}
	if err := m.indexTools(ctx, id, s); err != nil {
		return 0, err
	}
	t, _ := m.store.Tools(id)
	return len(t), nil
}

func (m *Manager) Disconnect(id string) {
	c := m.get(id)
	c.mu.Lock()
	s := c.session
	c.session = nil
	c.gen++
	c.oauth = nil
	c.status, c.err, c.authURL = StatusIdle, "", ""
	c.mu.Unlock()
	if s != nil {
		_ = s.Close()
	}
	m.mu.Lock()
	for k, p := range m.pending {
		if p.server == id {
			delete(m.pending, k)
		}
	}
	m.mu.Unlock()
}

func (m *Manager) CallTool(ctx context.Context, id, tool string, args map[string]any) (*mcp.CallToolResult, error) {
	for attempt := 0; attempt < 2; attempt++ {
		s, err := m.Session(ctx, id)
		if err != nil {
			return nil, err
		}
		res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		if err == nil {
			return res, nil
		}
		if isClientRegistrationErr(err) {
			m.setAuthIssue(id, "client_required")
			return nil, &OAuthClientRequiredError{Server: id}
		}
		if attempt == 0 && isConnErr(err) {
			m.Disconnect(id)
			continue
		}
		return nil, err
	}
	return nil, errors.New("unreachable")
}

func isConnErr(err error) bool {
	if errors.Is(err, mcp.ErrConnectionClosed) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "closed") || strings.Contains(s, "eof") || strings.Contains(s, "broken pipe") || strings.Contains(s, "session not found")
}

// ReapIdle closes sessions that were unused for IdleTimeout.
func (m *Manager) ReapIdle(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		m.mu.Lock()
		ids := make([]string, 0, len(m.conns))
		for id := range m.conns {
			ids = append(ids, id)
		}
		m.mu.Unlock()
		for _, id := range ids {
			c := m.get(id)
			c.mu.Lock()
			idle := c.session != nil && time.Since(c.lastUsed) > m.IdleTimeout
			c.mu.Unlock()
			if idle {
				m.log.Info("closing idle upstream", "server", id)
				m.Disconnect(id)
			}
		}
	}
}

// Warmup indexes enabled servers that have no cached tools yet.
func (m *Manager) Warmup() {
	servers, _ := m.store.ListServers()
	for _, s := range servers {
		if !s.Enabled || !m.store.IsApproved(s) {
			continue
		}
		if t, _ := m.store.Tools(s.ID); len(t) > 0 {
			continue
		}
		go func(id string) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			_, _ = m.Session(ctx, id)
		}(s.ID)
	}
}

func (m *Manager) transport(cfg *ServerConfig, c *conn) (mcp.Transport, error) {
	missing := map[string]bool{}
	r := func(s string) string { return m.vault.Resolve(s, missing) }
	switch cfg.Transport {
	case "stdio":
		args := make([]string, len(cfg.Args))
		for i, a := range cfg.Args {
			args[i] = r(a)
		}
		bin, err := lookPath(r(cfg.Command))
		if err != nil {
			return nil, fmt.Errorf("command %q not found in PATH (%s)", cfg.Command, extendedPath())
		}
		cmd := exec.Command(bin, args...)
		env := os.Environ()
		env = append(env, "PATH="+extendedPath())
		keys := make([]string, 0, len(cfg.Env))
		for k := range cfg.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			env = append(env, k+"="+r(cfg.Env[k]))
		}
		cmd.Env = env
		c.stderr.Reset()
		cmd.Stderr = c.stderr
		if len(missing) > 0 {
			return nil, &MissingSecretsError{Server: cfg.ID, Names: keysOf(missing)}
		}
		return &mcp.CommandTransport{Command: cmd}, nil
	case "builtin":
		mk := m.Builtins[cfg.Command]
		if mk == nil {
			return nil, fmt.Errorf("built-in server %q is not available", cfg.Command)
		}
		st, ct := mcp.NewInMemoryTransports()
		if _, err := mk().Connect(context.Background(), st, nil); err != nil {
			return nil, err
		}
		return ct, nil
	case "http":
		headers := map[string]string{}
		for k, v := range cfg.Headers {
			headers[k] = r(v)
		}
		u := r(cfg.URL)
		if len(missing) > 0 {
			return nil, &MissingSecretsError{Server: cfg.ID, Names: keysOf(missing)}
		}
		t := &mcp.StreamableClientTransport{
			Endpoint:   u,
			HTTPClient: &http.Client{Transport: &headerRT{base: http.DefaultTransport, headers: headers}},
		}
		_, hasAuthz := headers["Authorization"]
		if cfg.Auth == "oauth" || ((cfg.Auth == "" || cfg.Auth == "auto") && !hasAuthz) {
			h, err := m.oauthHandler(cfg, c)
			if err != nil {
				return nil, err
			}
			c.mu.Lock()
			c.oauth = h
			c.mu.Unlock()
			t.OAuthHandler = h
		}
		return t, nil
	}
	return nil, fmt.Errorf("unknown transport %q", cfg.Transport)
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func extendedPath() string {
	p := os.Getenv("PATH")
	home, _ := os.UserHomeDir()
	for _, extra := range []string{"/opt/homebrew/bin", "/usr/local/bin", home + "/.local/bin", home + "/.cargo/bin", home + "/go/bin", home + "/sdk/go/bin"} {
		if !strings.Contains(":"+p+":", ":"+extra+":") {
			p += ":" + extra
		}
	}
	return p
}

func lookPath(file string) (string, error) {
	if strings.Contains(file, "/") {
		return file, nil
	}
	for _, dir := range strings.Split(extendedPath(), ":") {
		if dir == "" {
			continue
		}
		p := dir + "/" + file
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", exec.ErrNotFound
}

type headerRT struct {
	base    http.RoundTripper
	headers map[string]string
}

func (h *headerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if len(h.headers) == 0 {
		return h.base.RoundTrip(r)
	}
	r = r.Clone(r.Context())
	for k, v := range h.headers {
		r.Header.Set(k, v)
	}
	return h.base.RoundTrip(r)
}

type ringBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func newRingBuffer(max int) *ringBuffer { return &ringBuffer{max: max} }

func (b *ringBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = b.buf[len(b.buf)-b.max:]
	}
	return len(p), nil
}

func (b *ringBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

func (b *ringBuffer) Reset() {
	b.mu.Lock()
	b.buf = nil
	b.mu.Unlock()
}
