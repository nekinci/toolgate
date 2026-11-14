package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ServerConfig describes one upstream MCP server behind the gateway.
type ServerConfig struct {
	ID          string `json:"id" jsonschema:"unique slug: lowercase letters, digits and dashes (e.g. postgres-prod)"`
	Name        string `json:"name,omitempty" jsonschema:"human readable name"`
	Description string `json:"description,omitempty" jsonschema:"what this server is for; shown to agents"`
	Purpose     string `json:"purpose,omitempty" jsonschema:"set by the user in the gateway panel: which account, environment or project this connection is for. Ignored when sent by an agent."`
	Transport   string `json:"transport" jsonschema:"stdio or http"`

	Command string            `json:"command,omitempty" jsonschema:"stdio: executable, e.g. npx or uvx"`
	Args    []string          `json:"args,omitempty" jsonschema:"stdio: arguments; may contain ${secret:NAME}"`
	Env     map[string]string `json:"env,omitempty" jsonschema:"stdio: env vars; values may contain ${secret:NAME}"`

	URL     string            `json:"url,omitempty" jsonschema:"http: streamable HTTP endpoint"`
	Headers map[string]string `json:"headers,omitempty" jsonschema:"http: extra headers; values may contain ${secret:NAME}"`

	Auth                 string   `json:"auth,omitempty" jsonschema:"http auth: auto (default, OAuth on 401), oauth, or none"`
	OAuthClientID        string   `json:"oauth_client_id,omitempty" jsonschema:"pre-registered OAuth client id (otherwise dynamic registration is used)"`
	OAuthClientSecretRef string   `json:"oauth_client_secret_ref,omitempty" jsonschema:"name of the vault secret holding the OAuth client secret"`
	OAuthScopes          []string `json:"oauth_scopes,omitempty" jsonschema:"OAuth scopes to request instead of discovered ones"`

	Enabled    bool     `json:"enabled,omitempty"`
	AllowTools []string `json:"allow_tools,omitempty" jsonschema:"glob patterns of upstream tool names to expose; empty = all"`
	DenyTools  []string `json:"deny_tools,omitempty" jsonschema:"glob patterns of upstream tool names to hide"`
	CatalogID  string   `json:"catalog_id,omitempty"`
	CreatedAt  string   `json:"created_at,omitempty"`
	UpdatedAt  string   `json:"updated_at,omitempty"`
}

type Agent struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Allow     []string `json:"allow,omitempty"` // patterns on "server.tool"; empty = all
	Deny      []string `json:"deny,omitempty"`
	CanManage bool     `json:"can_manage"`
	ToolMode  string   `json:"tool_mode,omitempty"` // lazy | direct | auto; "" = gateway default
	// token lifetime (pairing.go): days, 0 = never; expires_at is set when a token is minted
	TokenTTLDays int    `json:"token_ttl_days,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	CreatedAt    string `json:"created_at"`
	LastSeen     string `json:"last_seen,omitempty"`
}

type CachedTool struct {
	ServerID    string          `json:"server"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"inputSchema"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
	// Pending is "new" or "changed" when this version of the tool is not the
	// one the user approved (see toolpins.go). Computed, not stored.
	Pending string `json:"pending,omitempty"`
}

type AuditEntry struct {
	ID         int64  `json:"id"`
	TS         string `json:"ts"`
	Agent      string `json:"agent"`
	Action     string `json:"action"`
	Target     string `json:"target"`
	Args       string `json:"args"`
	Status     string `json:"status"`
	DurationMS int64  `json:"duration_ms"`
	Detail     string `json:"detail"`
}

type Store struct {
	db                 *sql.DB
	auditRetentionFlag int // -audit-retention-days; 0 = use the panel setting
}

const schema = `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS secrets(name TEXT PRIMARY KEY, nonce BLOB NOT NULL, ct BLOB NOT NULL, system INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS servers(id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tools(server_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL, schema TEXT NOT NULL, annotations TEXT NOT NULL DEFAULT '', PRIMARY KEY(server_id, name));
CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY, data TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS catalog(id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, agent TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, args TEXT NOT NULL, status TEXT NOT NULL, duration_ms INTEGER NOT NULL, detail TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
CREATE TABLE IF NOT EXISTS approvals(server_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, snapshot TEXT NOT NULL, approved_at TEXT NOT NULL, approved_by TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS search_stats(day TEXT PRIMARY KEY, total INTEGER NOT NULL DEFAULT 0, strict INTEGER NOT NULL DEFAULT 0, loose INTEGER NOT NULL DEFAULT 0, miss INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS search_misses(query TEXT NOT NULL, server TEXT NOT NULL, count INTEGER NOT NULL, last_agent TEXT NOT NULL, first_at TEXT NOT NULL, last_at TEXT NOT NULL, PRIMARY KEY(query, server));
CREATE TABLE IF NOT EXISTS proxy_apps(id TEXT PRIMARY KEY, data TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS tool_pins(server_id TEXT NOT NULL, name TEXT NOT NULL, hash TEXT NOT NULL, description TEXT NOT NULL, schema TEXT NOT NULL, pinned_at TEXT NOT NULL, pinned_by TEXT NOT NULL, PRIMARY KEY(server_id, name));
`

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Store{db: db}, nil
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)

func (c *ServerConfig) Validate() error {
	c.Purpose = strings.Join(strings.Fields(c.Purpose), " ")
	if n := len([]rune(c.Purpose)); n > MaxPurposeLen {
		return fmt.Errorf("purpose is too long (%d characters, max %d)", n, MaxPurposeLen)
	}
	if !idRe.MatchString(c.ID) {
		return fmt.Errorf("invalid id %q: use lowercase letters, digits and dashes", c.ID)
	}
	switch c.Transport {
	case "stdio":
		if c.Command == "" {
			return errors.New("stdio server needs a command")
		}
	case "http":
		if !strings.HasPrefix(c.URL, "http://") && !strings.HasPrefix(c.URL, "https://") {
			return errors.New("http server needs an http(s) url")
		}
	case "builtin":
		if !builtinServers[c.Command] {
			return fmt.Errorf("unknown built-in server %q", c.Command)
		}
	default:
		return errors.New("transport must be stdio or http")
	}
	switch c.Auth {
	case "", "auto", "oauth", "none":
	default:
		return errors.New("auth must be auto, oauth or none")
	}
	if c.Name == "" {
		c.Name = c.ID
	}
	return nil
}

// ---- servers ----

func (s *Store) PutServer(c *ServerConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if old, err := s.GetServer(c.ID); err == nil && old.CreatedAt != "" {
		c.CreatedAt = old.CreatedAt
	} else if c.CreatedAt == "" {
		c.CreatedAt = now()
	}
	c.UpdatedAt = now()
	b, _ := json.Marshal(c)
	_, err := s.db.Exec(`INSERT INTO servers(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, c.ID, string(b))
	return err
}

func (s *Store) GetServer(id string) (*ServerConfig, error) {
	var data string
	if err := s.db.QueryRow(`SELECT data FROM servers WHERE id=?`, id).Scan(&data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("server %q not found", id)
		}
		return nil, err
	}
	var c ServerConfig
	return &c, json.Unmarshal([]byte(data), &c)
}

func (s *Store) ListServers() ([]*ServerConfig, error) {
	rows, err := s.db.Query(`SELECT data FROM servers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ServerConfig
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var c ServerConfig
		if json.Unmarshal([]byte(data), &c) == nil {
			out = append(out, &c)
		}
	}
	return out, rows.Err()
}

func (s *Store) DeleteServer(id string) error {
	s.DeleteApproval(id)
	s.deleteToolPins(id)
	if _, err := s.db.Exec(`DELETE FROM tools WHERE server_id=?`, id); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM servers WHERE id=?`, id)
	return err
}

// ---- tool cache ----

func (s *Store) ReplaceTools(serverID string, tools []CachedTool) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM tools WHERE server_id=?`, serverID); err != nil {
		return err
	}
	for _, t := range tools {
		if _, err := tx.Exec(`INSERT INTO tools(server_id,name,description,schema,annotations) VALUES(?,?,?,?,?)`,
			serverID, t.Name, t.Description, string(t.Schema), string(t.Annotations)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Tools(serverID string) ([]CachedTool, error) {
	q := `SELECT t.server_id,t.name,t.description,t.schema,t.annotations,COALESCE(p.hash,'') FROM tools t
		LEFT JOIN tool_pins p ON p.server_id=t.server_id AND p.name=t.name`
	var args []any
	if serverID != "" {
		q += ` WHERE t.server_id=?`
		args = append(args, serverID)
	}
	rows, err := s.db.Query(q+` ORDER BY t.server_id,t.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CachedTool
	for rows.Next() {
		var t CachedTool
		var sch, ann, pin string
		if err := rows.Scan(&t.ServerID, &t.Name, &t.Description, &sch, &ann, &pin); err != nil {
			return nil, err
		}
		t.Schema = json.RawMessage(sch)
		if ann != "" {
			t.Annotations = json.RawMessage(ann)
		}
		switch {
		case pin == "":
			t.Pending = ToolNew
		case pin != t.Hash():
			t.Pending = ToolChanged
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ---- agents ----

func (s *Store) PutAgent(a *Agent, tokenHash string) error {
	b, _ := json.Marshal(a)
	if tokenHash == "" {
		_, err := s.db.Exec(`UPDATE agents SET data=? WHERE id=?`, string(b), a.ID)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO agents(id,data,token_hash) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data, token_hash=excluded.token_hash`, a.ID, string(b), tokenHash)
	return err
}

func (s *Store) AgentByTokenHash(h string) (*Agent, error) {
	var data string
	if err := s.db.QueryRow(`SELECT data FROM agents WHERE token_hash=?`, h).Scan(&data); err != nil {
		return nil, err
	}
	var a Agent
	return &a, json.Unmarshal([]byte(data), &a)
}

func (s *Store) GetAgent(id string) (*Agent, error) {
	var data string
	if err := s.db.QueryRow(`SELECT data FROM agents WHERE id=?`, id).Scan(&data); err != nil {
		return nil, fmt.Errorf("agent %q not found", id)
	}
	var a Agent
	return &a, json.Unmarshal([]byte(data), &a)
}

func (s *Store) ListAgents() ([]*Agent, error) {
	rows, err := s.db.Query(`SELECT data FROM agents ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Agent
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var a Agent
		if json.Unmarshal([]byte(data), &a) == nil {
			out = append(out, &a)
		}
	}
	return out, rows.Err()
}

func (s *Store) DeleteAgent(id string) error {
	_, err := s.db.Exec(`DELETE FROM agents WHERE id=?`, id)
	return err
}

// ---- user catalog ----

func (s *Store) PutCatalog(e *CatalogEntry) error {
	b, _ := json.Marshal(e)
	_, err := s.db.Exec(`INSERT INTO catalog(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, e.ID, string(b))
	return err
}

func (s *Store) ListCatalog() ([]*CatalogEntry, error) {
	rows, err := s.db.Query(`SELECT data FROM catalog ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CatalogEntry
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var e CatalogEntry
		if json.Unmarshal([]byte(data), &e) == nil {
			out = append(out, &e)
		}
	}
	return out, rows.Err()
}

func (s *Store) DeleteCatalog(id string) error {
	_, err := s.db.Exec(`DELETE FROM catalog WHERE id=?`, id)
	return err
}

// ---- audit ----

func (s *Store) Audit(e AuditEntry) {
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	_, _ = s.db.Exec(`INSERT INTO audit(ts,agent,action,target,args,status,duration_ms,detail) VALUES(?,?,?,?,?,?,?,?)`,
		e.TS, e.Agent, e.Action, e.Target, e.Args, e.Status, e.DurationMS, e.Detail)
}

type ServerStat struct {
	Calls  int    `json:"calls"`
	Errors int    `json:"errors"`
	Last   string `json:"last"`
}

// ServerStats aggregates call_tool audit rows per server for the window.
func (s *Store) ServerStats(window time.Duration) map[string]ServerStat {
	out := map[string]ServerStat{}
	since := time.Now().Add(-window).UTC().Format(time.RFC3339Nano)
	rows, err := s.db.Query(`SELECT substr(target,1,instr(target,'.')-1) AS sid, count(*),
		sum(CASE WHEN status IN ('error','tool_error') THEN 1 ELSE 0 END), max(ts)
		FROM audit WHERE action='call_tool' AND ts>=? AND instr(target,'.')>0 GROUP BY sid`, since)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var st ServerStat
		if rows.Scan(&id, &st.Calls, &st.Errors, &st.Last) == nil {
			out[id] = st
		}
	}
	// last call ever (outside the window too)
	rows2, err := s.db.Query(`SELECT substr(target,1,instr(target,'.')-1) AS sid, max(ts) FROM audit WHERE action='call_tool' AND instr(target,'.')>0 GROUP BY sid`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var id, last string
			if rows2.Scan(&id, &last) == nil {
				st := out[id]
				st.Last = last
				out[id] = st
			}
		}
	}
	return out
}

func (s *Store) ListAudit(limit int, agent, q string) ([]AuditEntry, error) {
	return s.ListAuditFiltered(limit, agent, q, "")
}

func (s *Store) ListAuditFiltered(limit int, agent, q, server string) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	query := `SELECT id,ts,agent,action,target,args,status,duration_ms,detail FROM audit WHERE 1=1`
	var args []any
	if server != "" {
		query += ` AND (target=? OR target LIKE ?)`
		args = append(args, server, server+".%")
	}
	if agent != "" {
		// "ui:test" also matches "ui:test:<agent>" (playground runs as an agent)
		query += ` AND (agent=? OR (? = 'ui:test' AND agent LIKE 'ui:test:%'))`
		args = append(args, agent, agent)
	}
	if q != "" {
		query += ` AND (target LIKE ? OR action LIKE ? OR detail LIKE ?)`
		like := "%" + q + "%"
		args = append(args, like, like, like)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Agent, &e.Action, &e.Target, &e.Args, &e.Status, &e.DurationMS, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
