package main

import (
	"regexp"
	"sort"
	"strings"
)

// Tool search runs in two passes:
//
//   - strict: every significant query word must match the tool (name,
//     description, server id/name/description/purpose) exactly, by stem or as
//     a prefix. This keeps "create issue" from returning every "create_*".
//   - loose: only when strict finds nothing. Any word may match, and matching
//     also accepts a small verb/noun synonym table and one typo (two for long
//     words).
//
// A search that finds nothing in either pass is a "missed search"; those are
// counted (searchstats.go) so the user can see what agents looked for and
// couldn't find, usually a sign that a connection is missing.

const (
	SearchAll    = "all"    // empty query: everything, no ranking
	SearchStrict = "strict" // every keyword matched
	SearchLoose  = "loose"  // partial / fuzzy matches only
	SearchNone   = "none"   // nothing found
)

type searchHit struct {
	Tool        string  `json:"tool"`
	Description string  `json:"description"`
	score       float64 `json:"-"`
}

var (
	wordRe  = regexp.MustCompile(`[\p{L}\p{N}]+`)
	camelRe = regexp.MustCompile(`(\p{Ll})(\p{Lu})`)
)

// words lowercases and splits on punctuation, snake_case and camelCase.
func words(s string) []string {
	s = camelRe.ReplaceAllString(s, "$1 $2")
	s = strings.ToLower(strings.NewReplacer("_", " ", "-", " ", ".", " ", "/", " ").Replace(s))
	return wordRe.FindAllString(s, -1)
}

var stopWords = map[string]bool{
	"a": true, "an": true, "the": true, "to": true, "of": true, "for": true, "in": true, "on": true, "and": true,
	"or": true, "with": true, "my": true, "me": true, "i": true, "from": true, "by": true, "at": true, "into": true,
	"is": true, "it": true, "this": true, "that": true, "some": true, "via": true, "using": true, "tool": true, "tools": true,
}

// queryWords drops stop words, unless that would leave nothing.
func queryWords(q string) []string {
	all := words(q)
	var out []string
	seen := map[string]bool{}
	for _, w := range all {
		if !stopWords[w] && !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	if len(out) == 0 {
		return all
	}
	return out
}

// stem strips a few English suffixes so "issues"/"issue", "listing"/"list",
// "created"/"create" compare equal.
func stem(w string) string {
	if len(w) <= 3 {
		return w
	}
	for _, suf := range []string{"ies", "ing", "ed", "es", "er", "s", "e"} {
		if strings.HasSuffix(w, suf) && len(w)-len(suf) >= 3 {
			r := strings.TrimSuffix(w, suf)
			if suf == "ies" {
				r += "y"
			}
			return r
		}
	}
	return w
}

// synonym groups for the loose pass (common tool verbs and nouns).
var synonymGroups = [][]string{
	{"create", "add", "new", "make", "insert", "open", "post", "write"},
	{"delete", "remove", "drop", "destroy", "erase", "rm"},
	{"update", "edit", "modify", "change", "set", "patch", "rename"},
	{"get", "read", "fetch", "show", "view", "retrieve", "describe", "info", "details"},
	{"list", "find", "search", "query", "lookup", "browse", "ls"},
	{"send", "post", "publish", "notify", "reply"},
	{"email", "mail", "message", "inbox", "gmail"},
	{"file", "document", "doc", "attachment"},
	{"repo", "repository", "project"},
	{"pr", "pull", "merge"},
	{"issue", "ticket", "bug", "task"},
	{"user", "member", "account", "person", "people"},
	{"run", "execute", "exec", "invoke", "start", "trigger"},
	{"deploy", "deployment", "release", "publish"},
	{"db", "database", "sql", "table"},
	{"speech", "tts", "voice", "audio", "speak"},
	{"image", "picture", "photo", "img"},
	{"dns", "domain", "record", "zone"},
}

var synonyms = func() map[string]map[string]bool {
	m := map[string]map[string]bool{}
	for _, g := range synonymGroups {
		for _, a := range g {
			if m[a] == nil {
				m[a] = map[string]bool{}
			}
			for _, b := range g {
				if a != b {
					m[a][b] = true
				}
			}
		}
	}
	return m
}()

// editDistanceAtMost reports whether a and b are within k edits (k <= 2).
func editDistanceAtMost(a, b string, k int) bool {
	ra, rb := []rune(a), []rune(b)
	if d := len(ra) - len(rb); d > k || -d > k {
		return false
	}
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		best := cur[0]
		for j := 1; j <= len(rb); j++ {
			c := 1
			if ra[i-1] == rb[j-1] {
				c = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+c)
			best = min(best, cur[j])
		}
		if best > k {
			return false
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)] <= k
}

// wordMatch scores how well query word q matches text word x (0 = no match).
func wordMatch(q, x string, loose bool) float64 {
	switch {
	case q == x:
		return 1
	case stem(q) == stem(x):
		return 0.9
	case len(q) >= 3 && strings.HasPrefix(x, q):
		return 0.6
	case len(q) > 3 && strings.Contains(x, q):
		return 0.5
	}
	if !loose {
		return 0
	}
	if synonyms[q][x] || synonyms[stem(q)][x] || synonyms[q][stem(x)] {
		return 0.5
	}
	if len(q) >= 5 && len(x) >= 4 {
		k := 1
		if len(q) >= 9 {
			k = 2
		}
		if editDistanceAtMost(q, x, k) {
			return 0.4
		}
	}
	return 0
}

func bestMatch(q string, ws []string, loose bool) float64 {
	best := 0.0
	for _, x := range ws {
		if m := wordMatch(q, x, loose); m > best {
			best = m
			if best == 1 {
				break
			}
		}
	}
	return best
}

type searchDoc struct {
	hit               searchHit
	name, desc, sname []string
}

// scoreDoc returns the doc's score and whether every query word matched.
func scoreDoc(d *searchDoc, q []string, loose bool) (float64, bool) {
	score, all := 0.0, true
	for _, w := range q {
		n, ds, sv := bestMatch(w, d.name, loose), bestMatch(w, d.desc, loose), bestMatch(w, d.sname, loose)
		if n+ds+sv == 0 {
			all = false
			continue
		}
		score += 3*n + ds + 0.8*sv
	}
	return score, all
}

// searchMode runs the two-pass search and reports which pass produced the hits.
func (g *Gateway) searchMode(agent *Agent, in SearchIn) ([]searchHit, string) {
	limit := in.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	servers, _ := g.store.ListServers()
	srvByID := map[string]*ServerConfig{}
	for _, s := range servers {
		srvByID[s.ID] = s
	}
	tools, _ := g.store.Tools(in.Server)
	q := queryWords(in.Query)
	var docs []*searchDoc
	for _, t := range tools {
		srv := srvByID[t.ServerID]
		if srv == nil || !srv.Enabled || t.Pending != "" || !Decide(agent, srv, t.Name).Allowed {
			continue
		}
		docs = append(docs, &searchDoc{
			hit:   searchHit{Tool: t.ServerID + "." + t.Name, Description: purposePrefix(srv) + truncate(t.Description, 200)},
			name:  words(t.Name),
			desc:  words(t.Description),
			sname: words(srv.ID + " " + srv.Name + " " + srv.Description + " " + srv.Purpose),
		})
	}
	if len(q) == 0 {
		hits := make([]searchHit, 0, len(docs))
		for _, d := range docs {
			hits = append(hits, d.hit)
		}
		if len(hits) > limit {
			hits = hits[:limit]
		}
		return hits, SearchAll
	}
	run := func(loose bool) []searchHit {
		hits := []searchHit{}
		for _, d := range docs {
			score, all := scoreDoc(d, q, loose)
			if score == 0 || (!loose && !all) {
				continue
			}
			h := d.hit
			h.score = score
			hits = append(hits, h)
		}
		sort.SliceStable(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
		if len(hits) > limit {
			hits = hits[:limit]
		}
		return hits
	}
	if hits := run(false); len(hits) > 0 {
		return hits, SearchStrict
	}
	if hits := run(true); len(hits) > 0 {
		return hits, SearchLoose
	}
	return []searchHit{}, SearchNone
}

func (g *Gateway) search(agent *Agent, in SearchIn) []searchHit {
	hits, _ := g.searchMode(agent, in)
	return hits
}

// missNote tells the agent what to do when a search found nothing.
func (g *Gateway) missNote(agent *Agent, in SearchIn) string {
	var ids []string
	for _, s := range g.summaries(agent) {
		if in.Server == "" || s.ID == in.Server {
			ids = append(ids, s.ID)
		}
	}
	note := "No tool matched. "
	if in.Server != "" {
		note += "Try again without the server filter, or with other keywords. "
	} else {
		note += "Try other keywords (an empty query lists every tool). "
	}
	if len(ids) > 0 && in.Server == "" {
		note += "Connected servers: " + strings.Join(ids, ", ") + ". "
	}
	if agent != nil && agent.CanManage {
		note += "If none of them fits, manage action=catalog_search can find a server to install (the user approves it)."
	} else {
		note += "If none of them fits, tell the user which capability is missing; the gateway records missed searches for them."
	}
	return note
}
