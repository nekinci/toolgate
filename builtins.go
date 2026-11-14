package main

// builtinServers are servers implemented inside the gateway (transport "builtin").
var builtinServers = map[string]bool{"gemini": true}

// ensureBuiltins registers built-in servers once. If the user removes one
// later it stays removed (it can be re-added from the catalog).
func ensureBuiltins(g *Gateway) {
	if g.store.Meta("builtin:gemini") != "" {
		return
	}
	if _, err := g.store.GetServer("gemini"); err != nil {
		cfg := geminiServerConfig()
		if err := g.store.PutServer(cfg); err != nil {
			return
		}
		_ = g.approve(cfg, "gateway")
	}
	g.store.SetMeta("builtin:gemini", "1")
}

func geminiServerConfig() *ServerConfig {
	return &ServerConfig{ID: "gemini", Name: "Gemini", Transport: "builtin", Command: "gemini", Enabled: true,
		Description: "Gemini API through the gateway's key pool: text to speech (single voice or 2-speaker dialogue, long texts), voices, models. Keys rotate automatically on rate limits."}
}
