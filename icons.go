package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var hostRe = regexp.MustCompile(`^[a-z0-9.-]{3,100}$`)

// iconHandler serves cached favicons for catalog entries. Only hosts that
// appear in the catalog are fetched, so it can't be used as an open proxy.
func iconHandler(c *Catalog) http.HandlerFunc {
	dir := filepath.Join(c.dataDir, "icons")
	_ = os.MkdirAll(dir, 0o700)
	var mu sync.Mutex
	failed := map[string]time.Time{}
	client := &http.Client{Timeout: 8 * time.Second}
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		if !hostRe.MatchString(host) || !c.KnownIconHost(host) {
			http.NotFound(w, r)
			return
		}
		p := filepath.Join(dir, host+".png")
		if b, err := os.ReadFile(p); err == nil {
			w.Header().Set("Content-Type", http.DetectContentType(b))
			w.Header().Set("Cache-Control", "public, max-age=604800")
			_, _ = w.Write(b)
			return
		}
		mu.Lock()
		if t, ok := failed[host]; ok && time.Since(t) < 6*time.Hour {
			mu.Unlock()
			http.NotFound(w, r)
			return
		}
		mu.Unlock()
		for _, src := range []string{
			"https://www.google.com/s2/favicons?sz=64&domain=" + host,
			"https://icons.duckduckgo.com/ip3/" + host + ".ico",
		} {
			resp, err := client.Get(src)
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
			resp.Body.Close()
			if resp.StatusCode == 200 && len(b) > 100 {
				_ = os.WriteFile(p, b, 0o600)
				w.Header().Set("Content-Type", http.DetectContentType(b))
				w.Header().Set("Cache-Control", "public, max-age=604800")
				_, _ = w.Write(b)
				return
			}
		}
		mu.Lock()
		failed[host] = time.Now()
		mu.Unlock()
		http.NotFound(w, r)
	}
}
