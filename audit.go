package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// Audit privacy and retention.
//
// audit_args (meta) decides how much of an agent's tool arguments is stored:
//   full – everything (sensitive-looking keys masked), as before
//   keys – only argument names (default)
//   none – nothing
// It applies to agent tool use (call_tool, search_tools, describe_tools, …).
// Configuration changes (manage.*, ui.*) are security events and keep their
// (masked) arguments. In keys/none mode the excerpt of a successful tool
// result is not stored either.
//
// Rows older than the retention period (default 90 days) are deleted
// periodically. The -audit-retention-days flag overrides the panel setting.

const (
	AuditArgsFull = "full"
	AuditArgsKeys = "keys"
	AuditArgsNone = "none"

	DefaultAuditRetentionDays = 90
	maxAuditRetentionDays     = 3650
)

func validAuditArgsMode(m string) bool {
	return m == AuditArgsFull || m == AuditArgsKeys || m == AuditArgsNone
}

func (s *Store) AuditArgsMode() string {
	if m := s.Meta("audit_args"); validAuditArgsMode(m) {
		return m
	}
	return AuditArgsKeys
}

// AuditRetentionDays returns the effective retention and whether it is fixed
// by the command-line flag.
func (s *Store) AuditRetentionDays() (int, bool) {
	if s.auditRetentionFlag > 0 {
		return s.auditRetentionFlag, true
	}
	if n, err := strconv.Atoi(s.Meta("audit_retention_days")); err == nil && n > 0 {
		return n, false
	}
	return DefaultAuditRetentionDays, false
}

type AuditSettings struct {
	RetentionDays  int    `json:"retention_days"`
	RetentionFixed bool   `json:"retention_fixed"`
	Args           string `json:"args"`
	Rows           int    `json:"rows"`
	Oldest         string `json:"oldest,omitempty"`
}

func (s *Store) AuditSettings() AuditSettings {
	d, fixed := s.AuditRetentionDays()
	out := AuditSettings{RetentionDays: d, RetentionFixed: fixed, Args: s.AuditArgsMode()}
	var oldest *string
	_ = s.db.QueryRow(`SELECT count(*), min(ts) FROM audit`).Scan(&out.Rows, &oldest)
	if oldest != nil {
		out.Oldest = *oldest
	}
	return out
}

func (s *Store) SetAuditSettings(days int, args string) error {
	if args != "" {
		if !validAuditArgsMode(args) {
			return errors.New("args must be full, keys or none")
		}
		s.SetMeta("audit_args", args)
	}
	if days != 0 {
		if days < 1 || days > maxAuditRetentionDays {
			return errors.New("retention must be between 1 and 3650 days")
		}
		if s.auditRetentionFlag > 0 {
			return errors.New("retention is fixed by the -audit-retention-days flag")
		}
		s.SetMeta("audit_retention_days", strconv.Itoa(days))
	}
	return nil
}

// PruneAudit deletes rows older than the retention period.
func (s *Store) PruneAudit() (int64, error) {
	days, _ := s.AuditRetentionDays()
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`DELETE FROM audit WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	s.pruneSearchStats(time.Now().Add(-time.Duration(days) * 24 * time.Hour))
	return res.RowsAffected()
}

// RunAuditRetention prunes now and then every hour until ctx ends.
func (s *Store) RunAuditRetention(ctx context.Context, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if n, err := s.PruneAudit(); err != nil {
			log.Warn("audit prune failed", "err", err)
		} else if n > 0 {
			log.Info("audit pruned", "rows", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// privacyScoped reports whether the args-mode applies to this action.
func privacyScoped(action string) bool {
	return !strings.HasPrefix(action, "manage.") && !strings.HasPrefix(action, "ui.")
}

// shapeAuditArgs turns already-redacted generic JSON args into what the mode
// allows to be stored.
func shapeAuditArgs(mode string, generic any) any {
	switch mode {
	case AuditArgsNone:
		return map[string]any{}
	case AuditArgsKeys:
		m, ok := generic.(map[string]any)
		if !ok {
			return map[string]any{}
		}
		out := map[string]any{}
		for k, v := range m {
			// call_tool wraps the real arguments; keep their names one level down
			if inner, ok := v.(map[string]any); ok && k == "arguments" {
				out[k] = shapeAuditArgs(mode, inner)
				continue
			}
			out[k] = "…"
		}
		return out
	}
	return generic
}

// ScrubAuditArgs rewrites stored rows to the current mode (for users who
// switch from full to keys/none and want old rows cleaned too).
func (s *Store) ScrubAuditArgs() (int, error) {
	mode := s.AuditArgsMode()
	if mode == AuditArgsFull {
		return 0, nil
	}
	if mode == AuditArgsNone {
		s.scrubSearchMisses() // missed-search rows keep query text
	}
	rows, err := s.db.Query(`SELECT id, action, args, status, detail FROM audit WHERE action NOT LIKE 'manage.%' AND action NOT LIKE 'ui.%'`)
	if err != nil {
		return 0, err
	}
	type upd struct {
		id           int64
		args, detail string
	}
	var ups []upd
	for rows.Next() {
		var id int64
		var action, args, status, detail string
		if rows.Scan(&id, &action, &args, &status, &detail) != nil {
			continue
		}
		var generic any
		newArgs := "{}"
		if json.Unmarshal([]byte(args), &generic) == nil {
			b, _ := json.Marshal(shapeAuditArgs(mode, generic))
			newArgs = string(b)
		}
		newDetail := detail
		if dropsResultDetail(mode, action, status) {
			newDetail = ""
		}
		if newArgs != args || newDetail != detail {
			ups = append(ups, upd{id, newArgs, newDetail})
		}
	}
	rows.Close()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for _, u := range ups {
		if _, err := tx.Exec(`UPDATE audit SET args=?, detail=? WHERE id=?`, u.args, u.detail, u.id); err != nil {
			return 0, err
		}
	}
	return len(ups), tx.Commit()
}

func dropsResultDetail(mode, action, status string) bool {
	return mode != AuditArgsFull && action == "call_tool" && status == "ok"
}
