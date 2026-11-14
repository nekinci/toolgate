package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Tool pinning: every upstream tool's name + description + input schema is
// hashed and the user-approved version is stored in tool_pins. A connected
// server that later changes a tool's description or schema (e.g. to smuggle
// instructions to agents) or adds a new tool gets that tool hidden from agents
// until the user approves it in the panel.
//
// Pinned automatically (trust on first use):
//   - all tools seen the first time a server is indexed,
//   - built-in servers (their tools are compiled into the gateway),
//   - every tool cached when this feature was introduced (one-time migration).

const (
	ToolNew     = "new"
	ToolChanged = "changed"
)

// canonicalJSON re-encodes JSON so that equal documents hash equally
// (object keys sorted, no insignificant whitespace).
func canonicalJSON(b []byte) []byte {
	if len(bytes.TrimSpace(b)) == 0 {
		return []byte("null")
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return b
	}
	out, err := json.Marshal(v)
	if err != nil {
		return b
	}
	return out
}

// ToolHash identifies what an agent is told about a tool.
func ToolHash(name, description string, schema []byte) string {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write([]byte(description))
	h.Write([]byte{0})
	h.Write(canonicalJSON(schema))
	return hex.EncodeToString(h.Sum(nil))
}

func (t *CachedTool) Hash() string { return ToolHash(t.Name, t.Description, t.Schema) }

type ToolPin struct {
	ServerID    string          `json:"server"`
	Name        string          `json:"name"`
	Hash        string          `json:"hash"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"inputSchema"`
	PinnedAt    string          `json:"pinned_at"`
	PinnedBy    string          `json:"pinned_by"`
}

func (s *Store) GetToolPin(serverID, name string) (*ToolPin, error) {
	var p ToolPin
	var sch string
	err := s.db.QueryRow(`SELECT server_id,name,hash,description,schema,pinned_at,pinned_by FROM tool_pins WHERE server_id=? AND name=?`, serverID, name).
		Scan(&p.ServerID, &p.Name, &p.Hash, &p.Description, &sch, &p.PinnedAt, &p.PinnedBy)
	if err != nil {
		return nil, err
	}
	p.Schema = json.RawMessage(sch)
	return &p, nil
}

// PinTools records the current cached version of the given tools (all
// pending tools of the server when names is nil) as approved.
func (s *Store) PinTools(serverID, by string, names []string) (int, error) {
	tools, err := s.Tools(serverID)
	if err != nil {
		return 0, err
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n := 0
	ts := now()
	for _, t := range tools {
		if names != nil && !want[t.Name] {
			continue
		}
		if names == nil && t.Pending == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO tool_pins(server_id,name,hash,description,schema,pinned_at,pinned_by) VALUES(?,?,?,?,?,?,?)
			ON CONFLICT(server_id,name) DO UPDATE SET hash=excluded.hash, description=excluded.description, schema=excluded.schema, pinned_at=excluded.pinned_at, pinned_by=excluded.pinned_by`,
			serverID, t.Name, t.Hash(), t.Description, string(t.Schema), ts, by); err != nil {
			return 0, err
		}
		n++
	}
	return n, tx.Commit()
}

func (s *Store) deleteToolPins(serverID string) {
	_, _ = s.db.Exec(`DELETE FROM tool_pins WHERE server_id=?`, serverID)
	_, _ = s.db.Exec(`DELETE FROM meta WHERE k=?`, pinsInitKey(serverID))
}

func pinsInitKey(serverID string) string { return "pins_init:" + serverID }

// AfterIndex pins tools automatically on a server's first non-empty index
// and always for built-in servers. Returns how many tools were pinned.
func (s *Store) AfterIndex(serverID string, builtin bool, toolCount int) int {
	first := s.Meta(pinsInitKey(serverID)) == ""
	if !builtin && !(first && toolCount > 0) {
		return 0
	}
	by := "first-index"
	if builtin {
		by = "builtin"
	}
	n, err := s.PinTools(serverID, by, nil)
	if err == nil && toolCount > 0 && first {
		s.SetMeta(pinsInitKey(serverID), now())
	}
	return n
}

// MigrateToolPins pins every tool that is cached when pinning is first
// introduced, so an existing install keeps working unchanged.
func (s *Store) MigrateToolPins() {
	if s.Meta("tool_pins_migrated") != "" {
		return
	}
	servers, _ := s.ListServers()
	for _, c := range servers {
		tools, _ := s.Tools(c.ID)
		if len(tools) == 0 {
			continue
		}
		if _, err := s.PinTools(c.ID, "migration", nil); err != nil {
			return // try again on next start
		}
		s.SetMeta(pinsInitKey(c.ID), now())
	}
	s.SetMeta("tool_pins_migrated", now())
}

// ToolChange is one tool waiting for the user's review.
type ToolChange struct {
	Name              string          `json:"name"`
	Kind              string          `json:"kind"` // new | changed
	Description       string          `json:"description"`
	Schema            json.RawMessage `json:"inputSchema"`
	BeforeDescription string          `json:"before_description,omitempty"`
	BeforeSchema      json.RawMessage `json:"before_schema,omitempty"`
	PinnedAt          string          `json:"pinned_at,omitempty"`
}

// PendingToolChanges lists new/changed tools of a server that the server's
// own policy would expose (hidden tools need no review).
func (s *Store) PendingToolChanges(c *ServerConfig) []ToolChange {
	out := []ToolChange{}
	tools, _ := s.Tools(c.ID)
	for _, t := range tools {
		if t.Pending == "" || anyMatch(c.DenyTools, t.Name) || (len(c.AllowTools) > 0 && !anyMatch(c.AllowTools, t.Name)) {
			continue
		}
		ch := ToolChange{Name: t.Name, Kind: t.Pending, Description: t.Description, Schema: t.Schema}
		if p, err := s.GetToolPin(c.ID, t.Name); err == nil {
			ch.BeforeDescription, ch.BeforeSchema, ch.PinnedAt = p.Description, p.Schema, p.PinnedAt
		}
		out = append(out, ch)
	}
	return out
}

// ToolsFingerprint identifies the exact set of pending tool versions the user
// is looking at, so an approval can't cover a change made while reviewing.
func ToolsFingerprint(changes []ToolChange) string {
	if len(changes) == 0 {
		return ""
	}
	hs := make([]string, 0, len(changes))
	for _, c := range changes {
		hs = append(hs, c.Name+"="+ToolHash(c.Name, c.Description, c.Schema))
	}
	sort.Strings(hs)
	h := sha256.New()
	for _, x := range hs {
		h.Write([]byte(x))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

type ToolPendingError struct {
	Server, Tool, Kind, Link string
}

func (e *ToolPendingError) Error() string {
	what := "changed since the user approved it"
	if e.Kind == ToolNew {
		what = "is new"
	}
	return fmt.Sprintf("tool %s.%s %s and is hidden until the user reviews it: %s", e.Server, e.Tool, what, e.Link)
}
