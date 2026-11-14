// mockoauth is a tiny OAuth 2.1 authorization server + protected MCP server
// used to test the gateway's OAuth client flow end to end. /authorize
// auto-approves, so following the login link with curl completes the flow.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7795", "listen address")
	openList := flag.Bool("open-list", false, "serve initialize/tools/list without a token (like Gmail MCP)")
	noDCR := flag.Bool("no-dcr", false, "no dynamic client registration (like Google); requires client mock-client/mock-secret")
	flag.Parse()
	base := "http://" + *addr
	var mu sync.Mutex
	valid := map[string]bool{}
	var n atomic.Int64
	issue := func() map[string]any {
		i := n.Add(1)
		at := fmt.Sprintf("at-%d", i)
		mu.Lock()
		valid[at] = true
		mu.Unlock()
		return map[string]any{"access_token": at, "refresh_token": fmt.Sprintf("rt-%d", i), "token_type": "Bearer", "expires_in": 3600, "scope": "read offline_access"}
	}
	j := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]any{"resource": base + "/mcp", "authorization_servers": []string{base}, "scopes_supported": []string{"read"}})
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]any{"resource": base + "/mcp", "authorization_servers": []string{base}, "scopes_supported": []string{"read"}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		meta := map[string]any{"issuer": base, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token",
			"registration_endpoint": base + "/register", "response_types_supported": []string{"code"},
			"grant_types_supported": []string{"authorization_code", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"}, "scopes_supported": []string{"read", "offline_access"}}
		if *noDCR {
			delete(meta, "registration_endpoint")
		}
		j(w, meta)
	})
	mux.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		m["client_id"] = "mock-client"
		w.WriteHeader(201)
		j(w, m)
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		log.Printf("authorize client=%s scope=%q", q.Get("client_id"), q.Get("scope"))
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=mock-code&state="+q.Get("state"), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		id, sec, basic := r.BasicAuth()
		if !basic {
			id, sec = r.Form.Get("client_id"), r.Form.Get("client_secret")
		}
		log.Printf("token grant=%s client=%s secret_ok=%v", r.Form.Get("grant_type"), id, sec == "mock-secret")
		if *noDCR && (id != "mock-client" || sec != "mock-secret") {
			http.Error(w, `{"error":"invalid_client"}`, 401)
			return
		}
		j(w, issue())
	})
	mux.HandleFunc("POST /revoke-all", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		valid = map[string]bool{}
		mu.Unlock()
		fmt.Fprint(w, "ok")
	})

	srv := mcp.NewServer(&mcp.Implementation{Name: "mock-protected", Version: "1"}, nil)
	type in struct{}
	mcp.AddTool(srv, &mcp.Tool{Name: "whoami", Description: "Returns the access token used for this call"},
		func(ctx context.Context, req *mcp.CallToolRequest, _ in) (*mcp.CallToolResult, any, error) {
			tok := strings.TrimPrefix(req.Extra.Header.Get("Authorization"), "Bearer ")
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "token=" + tok}}}, nil, nil
		})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		ok := valid[tok]
		mu.Unlock()
		if !ok && *openList && r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			var msg struct {
				Method string `json:"method"`
			}
			_ = json.Unmarshal(body, &msg)
			if msg.Method == "initialize" || msg.Method == "tools/list" || strings.HasPrefix(msg.Method, "notifications/") {
				h.ServeHTTP(w, r)
				return
			}
		}
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+base+`/.well-known/oauth-protected-resource/mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
	log.Printf("mock oauth+mcp on %s", base)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
