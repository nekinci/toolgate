package main

// MaxPurposeLen caps the user-written connection purpose. It is prepended to
// every tool description an agent sees, so it has to stay short.
const MaxPurposeLen = 160

// purposePrefix returns "[purpose] " for tool descriptions, or "" when the
// connection has no purpose. Purpose is user-owned (agents can't set it), so
// it is safe to show next to upstream text: it tells agents which of several
// similar connections (two Cloudflare accounts, prod vs staging) a tool is on.
func purposePrefix(s *ServerConfig) string {
	if s == nil || s.Purpose == "" {
		return ""
	}
	return "[" + s.Purpose + "] "
}
