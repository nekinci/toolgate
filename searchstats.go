package main

import (
	"strings"
	"time"
)

// Search statistics: per-day counters for every search_tools call (by which
// pass answered it) and an aggregated list of missed searches, i.e. queries
// that found nothing in either pass. The miss list shows the user what agents
// looked for and couldn't find. Query text is kept unless the audit argument
// mode is "none"; both tables follow the audit retention period.

const maxMissQueryLen = 200

// normalizeMissQuery folds case and punctuation so "Send Email" and
// "send-email" are one row.
func normalizeMissQuery(q string) string {
	n := strings.Join(words(q), " ")
	if r := []rune(n); len(r) > maxMissQueryLen {
		n = string(r[:maxMissQueryLen])
	}
	return n
}

// RecordSearch counts one search_tools call. mode is one of the Search*
// constants; empty-query listings (SearchAll) are not counted.
func (s *Store) RecordSearch(agentID, query, server, mode string) {
	if mode == SearchAll {
		return
	}
	col := map[string]string{SearchStrict: "strict", SearchLoose: "loose", SearchNone: "miss"}[mode]
	if col == "" {
		return
	}
	ts := time.Now().UTC()
	day := ts.Format("2006-01-02")
	_, _ = s.db.Exec(`INSERT INTO search_stats(day,total,`+col+`) VALUES(?,1,1)
		ON CONFLICT(day) DO UPDATE SET total=total+1, `+col+`=`+col+`+1`, day)
	if mode != SearchNone || s.AuditArgsMode() == AuditArgsNone {
		return
	}
	q := normalizeMissQuery(query)
	if q == "" {
		return
	}
	now := ts.Format(time.RFC3339Nano)
	_, _ = s.db.Exec(`INSERT INTO search_misses(query,server,count,last_agent,first_at,last_at) VALUES(?,?,1,?,?,?)
		ON CONFLICT(query,server) DO UPDATE SET count=count+1, last_agent=excluded.last_agent, last_at=excluded.last_at`,
		q, server, agentID, now, now)
}

type SearchTotals struct {
	Total  int `json:"total"`
	Strict int `json:"strict"`
	Loose  int `json:"loose"`
	Miss   int `json:"miss"`
}

type SearchMiss struct {
	Query     string `json:"query"`
	Server    string `json:"server,omitempty"`
	Count     int    `json:"count"`
	LastAgent string `json:"last_agent"`
	FirstAt   string `json:"first_at"`
	LastAt    string `json:"last_at"`
}

// SearchStats returns totals for the last `days` days and the most frequent
// missed searches seen in that window.
func (s *Store) SearchStats(days, limit int) (SearchTotals, []SearchMiss, error) {
	if days <= 0 {
		days = 30
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	since := time.Now().UTC().AddDate(0, 0, -days+1)
	var t SearchTotals
	err := s.db.QueryRow(`SELECT COALESCE(SUM(total),0),COALESCE(SUM(strict),0),COALESCE(SUM(loose),0),COALESCE(SUM(miss),0)
		FROM search_stats WHERE day >= ?`, since.Format("2006-01-02")).Scan(&t.Total, &t.Strict, &t.Loose, &t.Miss)
	if err != nil {
		return t, nil, err
	}
	rows, err := s.db.Query(`SELECT query,server,count,last_agent,first_at,last_at FROM search_misses
		WHERE last_at >= ? ORDER BY count DESC, last_at DESC LIMIT ?`, since.Format(time.RFC3339Nano), limit)
	if err != nil {
		return t, nil, err
	}
	defer rows.Close()
	misses := []SearchMiss{}
	for rows.Next() {
		var m SearchMiss
		if err := rows.Scan(&m.Query, &m.Server, &m.Count, &m.LastAgent, &m.FirstAt, &m.LastAt); err != nil {
			return t, nil, err
		}
		misses = append(misses, m)
	}
	return t, misses, rows.Err()
}

// DismissSearchMiss deletes one miss row, or every row when query is "".
func (s *Store) DismissSearchMiss(query, server string) (int64, error) {
	if query == "" {
		res, err := s.db.Exec(`DELETE FROM search_misses`)
		if err != nil {
			return 0, err
		}
		return res.RowsAffected()
	}
	res, err := s.db.Exec(`DELETE FROM search_misses WHERE query=? AND server=?`, normalizeMissQuery(query), server)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// pruneSearchStats applies the audit retention to the search tables.
func (s *Store) pruneSearchStats(cutoff time.Time) {
	_, _ = s.db.Exec(`DELETE FROM search_stats WHERE day < ?`, cutoff.UTC().Format("2006-01-02"))
	_, _ = s.db.Exec(`DELETE FROM search_misses WHERE last_at < ?`, cutoff.UTC().Format(time.RFC3339Nano))
}

// scrubSearchMisses drops stored query text (used when the audit mode is
// switched to "none" with scrub_existing).
func (s *Store) scrubSearchMisses() {
	_, _ = s.db.Exec(`DELETE FROM search_misses`)
}
