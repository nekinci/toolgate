package main

import (
	"encoding/json"
	"testing"
	"time"
)

func searchFixture(t *testing.T) *Gateway {
	g := testGateway(t)
	add := func(id string, tools ...CachedTool) {
		_ = g.store.PutServer(&ServerConfig{ID: id, Transport: "http", URL: "https://x/" + id, Enabled: true})
		index(g.store, id, false, tools...)
	}
	add("gh",
		CachedTool{Name: "create_issue", Description: "Create a new issue in a repository", Schema: json.RawMessage(`{}`)},
		CachedTool{Name: "create_branch", Description: "Create a branch", Schema: json.RawMessage(`{}`)},
		CachedTool{Name: "listCommits", Description: "List commits of a branch", Schema: json.RawMessage(`{}`)})
	add("mail",
		CachedTool{Name: "send_message", Description: "Send an email", Schema: json.RawMessage(`{}`)})
	return g
}

func names(h []searchHit) []string {
	var out []string
	for _, x := range h {
		out = append(out, x.Tool)
	}
	return out
}

func TestSearchStrictRequiresAllWords(t *testing.T) {
	g := searchFixture(t)
	hits, mode := g.searchMode(nil, SearchIn{Query: "create issue"})
	if mode != SearchStrict || len(hits) != 1 || hits[0].Tool != "gh.create_issue" {
		t.Fatalf("mode=%s hits=%v", mode, names(hits))
	}
	// stems and stop words: "issues" ~ "issue", "a"/"the" ignored
	if hits, mode := g.searchMode(nil, SearchIn{Query: "create the issues"}); mode != SearchStrict || len(hits) != 1 {
		t.Fatalf("stem: mode=%s hits=%v", mode, names(hits))
	}
	// camelCase tool names split into words
	if hits, mode := g.searchMode(nil, SearchIn{Query: "commits"}); mode != SearchStrict || len(hits) == 0 || hits[0].Tool != "gh.listCommits" {
		t.Fatalf("camel: mode=%s hits=%v", mode, names(hits))
	}
}

func TestSearchLooseFallback(t *testing.T) {
	g := searchFixture(t)
	// synonym: "add ticket" -> create_issue
	hits, mode := g.searchMode(nil, SearchIn{Query: "add ticket"})
	if mode != SearchLoose || len(hits) == 0 || hits[0].Tool != "gh.create_issue" {
		t.Fatalf("synonym: mode=%s hits=%v", mode, names(hits))
	}
	// typo
	if hits, mode := g.searchMode(nil, SearchIn{Query: "repostory"}); mode != SearchLoose || len(hits) == 0 || hits[0].Tool != "gh.create_issue" {
		t.Fatalf("typo: mode=%s hits=%v", mode, names(hits))
	}
	// partial: one of two words matches
	if _, mode := g.searchMode(nil, SearchIn{Query: "email calendar"}); mode != SearchLoose {
		t.Fatalf("partial: mode=%s", mode)
	}
	if hits, mode := g.searchMode(nil, SearchIn{Query: "kubernetes pods"}); mode != SearchNone || len(hits) != 0 {
		t.Fatalf("miss: mode=%s hits=%v", mode, names(hits))
	}
	if _, mode := g.searchMode(nil, SearchIn{}); mode != SearchAll {
		t.Fatalf("empty: mode=%s", mode)
	}
}

func TestSearchSkipsDisabledServers(t *testing.T) {
	g := searchFixture(t)
	s, _ := g.store.GetServer("mail")
	s.Enabled = false
	_ = g.store.PutServer(s)
	if hits := g.search(nil, SearchIn{Query: "email"}); len(hits) != 0 {
		t.Fatalf("disabled server leaked: %v", names(hits))
	}
}

func TestEditDistance(t *testing.T) {
	for _, c := range []struct {
		a, b string
		k    int
		want bool
	}{{"repostory", "repository", 1, true}, {"kitten", "sittin", 2, true}, {"kitten", "sitting", 2, false}, {"abc", "abc", 0, true}} {
		if got := editDistanceAtMost(c.a, c.b, c.k); got != c.want {
			t.Errorf("%s/%s k=%d: %v", c.a, c.b, c.k, got)
		}
	}
}

func TestSearchMissRecording(t *testing.T) {
	g := searchFixture(t)
	s := g.store
	s.RecordSearch("bot", "create issue", "", SearchStrict)
	s.RecordSearch("bot", "add ticket", "", SearchLoose)
	s.RecordSearch("bot", "Kubernetes  Pods", "", SearchNone)
	s.RecordSearch("other", "kubernetes-pods", "", SearchNone)
	s.RecordSearch("bot", "", "", SearchAll) // listings are not counted
	tot, misses, err := s.SearchStats(30, 0)
	if err != nil {
		t.Fatal(err)
	}
	if tot != (SearchTotals{Total: 4, Strict: 1, Loose: 1, Miss: 2}) {
		t.Fatalf("totals = %+v", tot)
	}
	if len(misses) != 1 || misses[0].Query != "kubernetes pods" || misses[0].Count != 2 || misses[0].LastAgent != "other" {
		t.Fatalf("misses = %+v", misses)
	}
	if n, _ := s.DismissSearchMiss("KUBERNETES pods", ""); n != 1 {
		t.Fatalf("dismiss removed %d", n)
	}

	// mode "none": counted, but query text is not stored; scrub clears old rows
	s.RecordSearch("bot", "jira board", "", SearchNone)
	if err := s.SetAuditSettings(0, AuditArgsNone); err != nil {
		t.Fatal(err)
	}
	s.RecordSearch("bot", "secret project name", "", SearchNone)
	_, misses, _ = s.SearchStats(30, 0)
	for _, m := range misses {
		if m.Query == "secret project name" {
			t.Fatal("query text stored in none mode")
		}
	}
	if _, err := s.ScrubAuditArgs(); err != nil {
		t.Fatal(err)
	}
	if tot, misses, _ := s.SearchStats(30, 0); len(misses) != 0 || tot.Miss != 4 {
		t.Fatalf("after scrub: %+v %+v", tot, misses)
	}

	// retention prunes old rows
	old := time.Now().AddDate(0, 0, -200).UTC()
	_, _ = s.db.Exec(`INSERT INTO search_stats(day,total,miss) VALUES(?,5,5)`, old.Format("2006-01-02"))
	_, _ = s.db.Exec(`INSERT INTO search_misses VALUES('old one','',3,'bot',?,?)`, old.Format(time.RFC3339Nano), old.Format(time.RFC3339Nano))
	if _, err := s.PruneAudit(); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM search_misses WHERE query='old one'`).Scan(&n)
	_ = s.db.QueryRow(`SELECT COUNT(*) + ? FROM search_stats WHERE day=?`, n, old.Format("2006-01-02")).Scan(&n)
	if n != 0 {
		t.Fatal("old search rows not pruned")
	}
}
