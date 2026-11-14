package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// securityView is the part of a server config that decides what runs and
// where credentials go. Any change to it by an agent needs user approval.
type securityView struct {
	Transport            string            `json:"transport"`
	Command              string            `json:"command,omitempty"`
	Args                 []string          `json:"args,omitempty"`
	Env                  map[string]string `json:"env,omitempty"`
	URL                  string            `json:"url,omitempty"`
	Headers              map[string]string `json:"headers,omitempty"`
	Auth                 string            `json:"auth,omitempty"`
	OAuthClientID        string            `json:"oauth_client_id,omitempty"`
	OAuthClientSecretRef string            `json:"oauth_client_secret_ref,omitempty"`
	OAuthScopes          []string          `json:"oauth_scopes,omitempty"`
}

func viewOf(c *ServerConfig) securityView {
	auth := c.Auth
	if auth == "" {
		auth = "auto"
	}
	if c.Transport == "stdio" || c.Transport == "builtin" {
		auth = "" // not used for local processes
	}
	v := securityView{Transport: c.Transport, Command: c.Command, Args: c.Args, Env: c.Env, URL: c.URL, Headers: c.Headers,
		Auth: auth, OAuthClientID: c.OAuthClientID, OAuthClientSecretRef: c.OAuthClientSecretRef, OAuthScopes: c.OAuthScopes}
	if len(v.Args) == 0 {
		v.Args = nil
	}
	if len(v.Env) == 0 {
		v.Env = nil
	}
	if len(v.Headers) == 0 {
		v.Headers = nil
	}
	if len(v.OAuthScopes) == 0 {
		v.OAuthScopes = nil
	}
	return v
}

// Fingerprint hashes the security-relevant config (json sorts map keys).
func Fingerprint(c *ServerConfig) string {
	b, _ := json.Marshal(viewOf(c))
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Approval struct {
	ServerID    string       `json:"server_id"`
	Fingerprint string       `json:"fingerprint"`
	Snapshot    securityView `json:"snapshot"`
	ApprovedAt  string       `json:"approved_at"`
	ApprovedBy  string       `json:"approved_by"`
}

func (s *Store) GetApproval(id string) (*Approval, error) {
	var a Approval
	var snap string
	err := s.db.QueryRow(`SELECT server_id,fingerprint,snapshot,approved_at,approved_by FROM approvals WHERE server_id=?`, id).
		Scan(&a.ServerID, &a.Fingerprint, &snap, &a.ApprovedAt, &a.ApprovedBy)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(snap), &a.Snapshot)
	return &a, nil
}

func (s *Store) PutApproval(c *ServerConfig, by string) error {
	snap, _ := json.Marshal(viewOf(c))
	_, err := s.db.Exec(`INSERT INTO approvals(server_id,fingerprint,snapshot,approved_at,approved_by) VALUES(?,?,?,?,?)
		ON CONFLICT(server_id) DO UPDATE SET fingerprint=excluded.fingerprint, snapshot=excluded.snapshot, approved_at=excluded.approved_at, approved_by=excluded.approved_by`,
		c.ID, Fingerprint(c), string(snap), now(), by)
	return err
}

func (s *Store) DeleteApproval(id string) {
	_, _ = s.db.Exec(`DELETE FROM approvals WHERE server_id=?`, id)
}

func (s *Store) Meta(k string) string {
	var v string
	_ = s.db.QueryRow(`SELECT v FROM meta WHERE k=?`, k).Scan(&v)
	return v
}

func (s *Store) SetMeta(k, v string) {
	_, _ = s.db.Exec(`INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
}

// MigrateApprovals approves every existing server exactly once, when the
// approval feature is first introduced. Later, unapproved servers stay so.
func (s *Store) MigrateApprovals() {
	if s.Meta("approvals_migrated") != "" {
		return
	}
	servers, _ := s.ListServers()
	for _, c := range servers {
		if _, err := s.GetApproval(c.ID); errors.Is(err, sql.ErrNoRows) {
			_ = s.PutApproval(c, "migration")
		}
	}
	s.SetMeta("approvals_migrated", now())
}

// IsApproved reports whether the current config matches what the user approved.
func (s *Store) IsApproved(c *ServerConfig) bool {
	a, err := s.GetApproval(c.ID)
	return err == nil && a.Fingerprint == Fingerprint(c)
}

type DiffRow struct {
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

func showList(v []string) string { return strings.Join(v, " ") }

func showMap(m map[string]string, sep string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		out = append(out, k+sep+m[k])
	}
	return strings.Join(out, "\n")
}

// ApprovalDiff lists what changed since the last approval (all fields for a
// never-approved server).
func (s *Store) ApprovalDiff(c *ServerConfig) []DiffRow {
	var before securityView
	if a, err := s.GetApproval(c.ID); err == nil {
		before = a.Snapshot
	}
	after := viewOf(c)
	rows := []DiffRow{}
	add := func(field, b, a string) {
		if b != a {
			rows = append(rows, DiffRow{field, b, a})
		}
	}
	add("transport", before.Transport, after.Transport)
	add("command", before.Command, after.Command)
	add("args", showList(before.Args), showList(after.Args))
	add("env", showMap(before.Env, "="), showMap(after.Env, "="))
	add("url", before.URL, after.URL)
	add("headers", showMap(before.Headers, ": "), showMap(after.Headers, ": "))
	add("auth", before.Auth, after.Auth)
	add("oauth_client_id", before.OAuthClientID, after.OAuthClientID)
	add("oauth_client_secret_ref", before.OAuthClientSecretRef, after.OAuthClientSecretRef)
	add("oauth_scopes", showList(before.OAuthScopes), showList(after.OAuthScopes))
	return rows
}

type PendingApprovalError struct {
	Server string
	Link   string
}

func (e *PendingApprovalError) Error() string {
	return fmt.Sprintf("server %q has configuration changes waiting for the user's approval: %s", e.Server, e.Link)
}

// approve records the current config as approved. When the destination or
// OAuth client changed, stored OAuth tokens are dropped so they can't be
// sent to the new destination.
func (g *Gateway) approve(c *ServerConfig, by string) error {
	prev, err := g.store.GetApproval(c.ID)
	if err == nil {
		now := viewOf(c)
		if prev.Snapshot.URL != now.URL || prev.Snapshot.OAuthClientID != now.OAuthClientID || prev.Snapshot.Transport != now.Transport {
			_ = g.vault.Delete(oauthSecretName(c.ID))
		}
	}
	if err := g.store.PutApproval(c, by); err != nil {
		return err
	}
	g.mgr.Disconnect(c.ID)
	return nil
}

// reject restores the last approved security settings, or deletes a server
// that was never approved.
func (g *Gateway) reject(c *ServerConfig) (deleted bool, err error) {
	a, err := g.store.GetApproval(c.ID)
	if err != nil {
		g.mgr.Disconnect(c.ID)
		return true, g.store.DeleteServer(c.ID)
	}
	v := a.Snapshot
	c.Transport, c.Command, c.Args, c.Env, c.URL, c.Headers = v.Transport, v.Command, v.Args, v.Env, v.URL, v.Headers
	c.Auth, c.OAuthClientID, c.OAuthClientSecretRef, c.OAuthScopes = v.Auth, v.OAuthClientID, v.OAuthClientSecretRef, v.OAuthScopes
	g.mgr.Disconnect(c.ID)
	return false, g.store.PutServer(c)
}

func (g *Gateway) approvalLink(id string) string { return g.baseURL + "/ui/#c/" + id + "?review=1" }

// rejectToolChanges hides every new/changed tool that is waiting for review by
// adding it to the server's deny_tools.
func (g *Gateway) rejectToolChanges(c *ServerConfig) error {
	changes := g.store.PendingToolChanges(c)
	if len(changes) == 0 {
		return nil
	}
	for _, ch := range changes {
		if !anyMatch(c.DenyTools, ch.Name) {
			c.DenyTools = append(c.DenyTools, ch.Name)
		}
	}
	return g.store.PutServer(c)
}
