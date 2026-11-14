package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// HTTP proxy for the user's own apps: /proxy/<pool>/<provider path>.
//
// An app keeps using its provider SDK and only changes the base URL and the
// API key: the key it sends is its gateway app token (agp_…), in whatever
// header the SDK uses (Authorization: Bearer, x-api-key, x-goog-api-key,
// xi-api-key or ?key=). The gateway checks the token, strips every
// credential the client sent, puts a key from the pool where the provider
// expects it and forwards the request. Rate-limited, invalid or failing keys
// are rotated exactly like the built-in Gemini tools do, as long as nothing
// has been sent back to the app yet. Successful responses (including SSE
// streams) are piped through unbuffered.

const (
	maxProxyBody     = 32 << 20 // request bodies are buffered so they can be retried on another key
	maxProxyErrBody  = 1 << 20
	maxProxyAttempts = 12
)

// credential carriers stripped from every proxied request
var proxyCredHeaders = []string{"Authorization", "X-Api-Key", "X-Goog-Api-Key", "Xi-Api-Key", "Api-Key", "Proxy-Authorization"}

var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade"}

var proxyClient = &http.Client{
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 10 * time.Minute, // long non-streaming generations
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   16,
		ForceAttemptHTTP2:     true,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// proxyTarget is what the proxy needs from a pool, read under its lock.
func (p *KeyPool) proxyTarget() (base string, prov *poolProvider, label, header string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	header = p.prov.Header
	if p.cfg.Header != "" {
		header = p.cfg.Header
	}
	return p.base, p.prov, firstNonEmpty(p.cfg.Name, p.prov.Label), header
}

// proxyToken finds the app token in any of the places SDKs put an API key.
func proxyToken(r *http.Request, extraHeader string) string {
	hs := append([]string{}, proxyCredHeaders...)
	if extraHeader != "" {
		hs = append(hs, extraHeader)
	}
	for _, h := range hs {
		for _, v := range r.Header.Values(h) {
			v = strings.TrimSpace(v)
			if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
				v = strings.TrimSpace(v[7:])
			}
			if strings.HasPrefix(v, proxyTokenPrefix) {
				return v
			}
		}
	}
	if v := r.URL.Query().Get("key"); strings.HasPrefix(v, proxyTokenPrefix) {
		return v
	}
	return ""
}

// proxyError answers in the OpenAI-style error shape most SDKs print.
func proxyError(w http.ResponseWriter, code int, kind, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": msg, "type": kind, "code": code}})
}

var geminiModelRe = regexp.MustCompile(`/models/([^/:?]+)`)

// proxyScope is the cooldown scope (the model) of a request, like the
// built-in tools use: a key rate limited on one model can serve another.
func proxyScope(provider, path string, body []byte) string {
	if m := geminiModelRe.FindStringSubmatch(path); m != nil {
		return m[1]
	}
	if len(body) > 0 && len(body) < 4<<20 && bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		var x struct {
			Model string `json:"model"`
		}
		if json.Unmarshal(body, &x) == nil && x.Model != "" {
			return x.Model
		}
	}
	return "proxy"
}

// proxyPath validates the part after /proxy/<pool> and returns it escaped.
func proxyPath(escapedRest string) (string, error) {
	dec, err := url.PathUnescape(escapedRest)
	if err != nil {
		return "", errors.New("bad path encoding")
	}
	for _, seg := range strings.Split(dec, "/") {
		if seg == ".." || seg == "." {
			return "", errors.New("path may not contain . or .. segments")
		}
	}
	if strings.ContainsAny(dec, "\\\x00") || strings.HasPrefix(dec, "/") {
		return "", errors.New("bad path")
	}
	return "/" + escapedRest, nil
}

func (g *Gateway) handleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	poolID := r.PathValue("pool")
	pool := g.pools.Get(poolID)
	if pool == nil {
		proxyError(w, http.StatusNotFound, "gateway_error", fmt.Sprintf("no key pool %q in the gateway", poolID))
		return
	}
	base, prov, label, keyHeader := pool.proxyTarget()
	tok := proxyToken(r, keyHeader)
	if tok == "" {
		proxyError(w, http.StatusUnauthorized, "gateway_auth", "missing gateway app token: use the app token (agp_…) as the API key")
		return
	}
	app, err := g.store.ProxyAppByTokenHash(hashToken(tok))
	if err != nil {
		proxyError(w, http.StatusUnauthorized, "gateway_auth", "invalid gateway app token")
		return
	}
	if tokenExpired(app.ExpiresAt) {
		proxyError(w, http.StatusUnauthorized, "gateway_auth", fmt.Sprintf("gateway app token for %q expired on %s; get a new one in the gateway panel (Agents > Uygulamalar)", app.ID, app.ExpiresAt))
		return
	}
	actor := &Agent{ID: "app:" + app.ID, Name: app.Name}
	escRest := strings.TrimPrefix(r.URL.EscapedPath(), "/proxy/"+poolID)
	escRest = strings.TrimPrefix(escRest, "/")
	target := fmt.Sprintf("%s %s /%s", poolID, r.Method, truncate(escRest, 200))
	audit := func(status string, code int, key string, tries int, note string) {
		d := fmt.Sprintf("HTTP %d", code)
		if key != "" {
			d += " · key " + key
		}
		if tries > 1 {
			d += fmt.Sprintf(" · %d attempts", tries)
		}
		if note != "" {
			d += " · " + note
		}
		g.audit(actor, "proxy", target, nil, status, time.Since(start).Milliseconds(), d)
	}
	if !app.Allows(poolID) {
		audit("denied", 403, "", 0, "pool not allowed for this app")
		proxyError(w, http.StatusForbidden, "gateway_denied", fmt.Sprintf("app %q may not use the %q pool (change it in the gateway panel)", app.ID, poolID))
		return
	}
	g.store.touchProxyApp(app)
	if base == "" {
		audit("error", 502, "", 0, "pool has no base URL")
		proxyError(w, http.StatusBadGateway, "gateway_error", fmt.Sprintf("pool %q has no API base URL configured", poolID))
		return
	}
	path, err := proxyPath(escRest)
	if err != nil {
		audit("denied", 400, "", 0, err.Error())
		proxyError(w, http.StatusBadRequest, "gateway_error", err.Error())
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxProxyBody+1))
	if err != nil {
		proxyError(w, http.StatusBadRequest, "gateway_error", "reading request body: "+err.Error())
		return
	}
	if len(body) > maxProxyBody {
		audit("error", 413, "", 0, "body too large")
		proxyError(w, http.StatusRequestEntityTooLarge, "gateway_error", fmt.Sprintf("request body over %d MB", maxProxyBody>>20))
		return
	}
	q := r.URL.Query()
	q.Del("key")
	targetURL := base + path
	if enc := q.Encode(); enc != "" {
		targetURL += "?" + enc
	}
	scope := proxyScope(prov.ID, path, body)

	skip := map[string]bool{}
	var last *bufferedResponse
	var lastKey string
	tries := 0
	for attempt := 0; attempt < maxProxyAttempts; attempt++ {
		name, val, err := pool.acquire(scope, skip)
		if err != nil {
			if last != nil { // every key failed: give the app the provider's last answer
				audit(statusFor(last.code), last.code, lastKey, tries, "no more keys")
				last.write(w)
				return
			}
			var nk *NoKeyError
			if errors.As(err, &nk) {
				if !nk.NextReady.IsZero() {
					w.Header().Set("Retry-After", fmt.Sprint(int(time.Until(nk.NextReady).Seconds())+1))
				}
				code := http.StatusTooManyRequests
				if nk.Empty {
					code = http.StatusServiceUnavailable
				}
				audit("error", code, "", tries, "no usable key")
				proxyError(w, code, "gateway_no_key", err.Error())
				return
			}
			audit("error", 500, "", tries, "vault: "+err.Error())
			proxyError(w, http.StatusInternalServerError, "gateway_error", "could not read a key from the vault")
			return
		}
		tries++
		req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bytes.NewReader(body))
		if err != nil {
			pool.release(name, scope, 0, err)
			audit("error", 500, name, tries, err.Error())
			proxyError(w, http.StatusInternalServerError, "gateway_error", err.Error())
			return
		}
		copyProxyRequestHeaders(req.Header, r.Header, keyHeader)
		req.ContentLength = int64(len(body))
		pool.authorize(req, val)

		resp, err := proxyClient.Do(req)
		if err != nil {
			pool.release(name, scope, 0, err)
			if r.Context().Err() != nil {
				audit("error", 499, name, tries, "client went away")
				return
			}
			skip[name] = true
			lastKey = name
			continue
		}
		if resp.StatusCode >= 400 {
			eb, _ := io.ReadAll(io.LimitReader(resp.Body, maxProxyErrBody))
			resp.Body.Close()
			pe := prov.parse(resp.StatusCode, resp.Header, eb, time.Now())
			pe.Label = label
			pool.release(name, scope, 0, pe)
			last = &bufferedResponse{code: resp.StatusCode, header: resp.Header, body: eb}
			lastKey = name
			if k := pe.classify(); k == "rate" || k == "invalid" || k == "transient" {
				skip[name] = true
				continue
			}
			audit(statusFor(resp.StatusCode), resp.StatusCode, name, tries, "")
			last.write(w)
			return
		}
		// success: stream it through
		copyProxyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		n, cerr := copyFlushing(w, resp.Body)
		resp.Body.Close()
		pool.release(name, scope, 0, nil)
		note := fmt.Sprintf("%d bytes", n)
		if cerr != nil {
			note += " · stream cut: " + truncate(cerr.Error(), 80)
		}
		audit("ok", resp.StatusCode, name, tries, note)
		return
	}
	if last != nil {
		audit(statusFor(last.code), last.code, lastKey, tries, "gave up")
		last.write(w)
		return
	}
	audit("error", 502, lastKey, tries, "upstream unreachable")
	proxyError(w, http.StatusBadGateway, "gateway_error", "could not reach the provider API with any key")
}

func statusFor(code int) string {
	switch {
	case code < 400:
		return "ok"
	case code == 429:
		return "rate_limited"
	default:
		return "error"
	}
}

type bufferedResponse struct {
	code   int
	header http.Header
	body   []byte
}

func (b *bufferedResponse) write(w http.ResponseWriter) {
	copyProxyResponseHeaders(w.Header(), b.header)
	w.Header().Del("Content-Length")
	w.WriteHeader(b.code)
	_, _ = w.Write(b.body)
}

func copyProxyRequestHeaders(dst, src http.Header, keyHeader string) {
	for k, vs := range src {
		dst[k] = append([]string(nil), vs...)
	}
	for _, h := range hopHeaders {
		dst.Del(h)
	}
	for _, h := range proxyCredHeaders {
		dst.Del(h)
	}
	if keyHeader != "" {
		dst.Del(keyHeader)
	}
	for _, h := range []string{"Cookie", "Host", "Accept-Encoding", "Content-Length", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip", "Origin", "Referer"} {
		dst.Del(h)
	}
}

func copyProxyResponseHeaders(dst, src http.Header) {
	for k, vs := range src {
		dst[k] = append([]string(nil), vs...)
	}
	for _, h := range hopHeaders {
		dst.Del(h)
	}
	dst.Del("Set-Cookie")
	dst.Del("Alt-Svc")
}

// copyFlushing copies and flushes after every read so SSE streams arrive as
// they are produced.
func copyFlushing(w http.ResponseWriter, r io.Reader) (int64, error) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	var n int64
	for {
		m, err := r.Read(buf)
		if m > 0 {
			if _, werr := w.Write(buf[:m]); werr != nil {
				return n, werr
			}
			n += int64(m)
			_ = rc.Flush()
		}
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}
