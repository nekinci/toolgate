package main

import (
	"path"
	"strings"
)

// globMatch matches a simple glob where '*' matches any run of characters
// (including dots) and '?' a single character. Case-insensitive.
func globMatch(pattern, name string) bool {
	pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern == name
	}
	// path.Match treats '/' specially only; tool names contain no '/'.
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}

func anyMatch(patterns []string, name string) bool {
	for _, p := range patterns {
		if globMatch(strings.TrimSpace(p), name) {
			return true
		}
	}
	return false
}

// PolicyDecision explains why a tool is or isn't allowed.
type PolicyDecision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// Decide checks server-level and agent-level rules for "server.tool".
// Deny always wins; an empty allow list means "everything".
func Decide(agent *Agent, srv *ServerConfig, tool string) PolicyDecision {
	full := srv.ID + "." + tool
	if !srv.Enabled {
		return PolicyDecision{false, "server is disabled"}
	}
	if anyMatch(srv.DenyTools, tool) {
		return PolicyDecision{false, "hidden by server deny_tools"}
	}
	if len(srv.AllowTools) > 0 && !anyMatch(srv.AllowTools, tool) {
		return PolicyDecision{false, "not in server allow_tools"}
	}
	if agent != nil {
		if anyMatch(agent.Deny, full) {
			return PolicyDecision{false, "denied for agent " + agent.ID}
		}
		if len(agent.Allow) > 0 && !anyMatch(agent.Allow, full) {
			return PolicyDecision{false, "not in allow list of agent " + agent.ID}
		}
	}
	return PolicyDecision{true, "allowed"}
}

// ServerVisible reports whether an agent can see a server at all
// (i.e. at least one pattern could match one of its tools).
func ServerVisible(agent *Agent, srv *ServerConfig) bool {
	if agent == nil {
		return true
	}
	if anyMatch(agent.Deny, srv.ID+".*") {
		return false
	}
	if len(agent.Allow) == 0 {
		return true
	}
	for _, p := range agent.Allow {
		p = strings.ToLower(strings.TrimSpace(p))
		prefix := strings.SplitN(p, ".", 2)[0]
		if globMatch(prefix, srv.ID) {
			return true
		}
	}
	return false
}
