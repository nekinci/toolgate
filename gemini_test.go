package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeGemini emulates the Gemini API. Behaviour per key value:
// "k-rate" → 429 with retryDelay, "k-daily" → 429 per-day quota,
// "k-bad" → 400 API_KEY_INVALID, anything else → audio.
type fakeGemini struct {
	mu     sync.Mutex
	hits   map[string]int
	bodies []map[string]any
	legacy bool // model only supports generateContent
}

func (f *fakeGemini) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("x-goog-api-key")
		if r.URL.Query().Get("key") != "" {
			t.Error("API key must not be sent in the URL")
		}
		f.mu.Lock()
		if f.hits == nil {
			f.hits = map[string]int{}
		}
		f.hits[key]++
		f.mu.Unlock()
		switch key {
		case "k-rate":
			w.WriteHeader(429)
			io.WriteString(w, `{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","message":"quota","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"30s"}]}}`)
			return
		case "k-daily":
			w.WriteHeader(429)
			io.WriteString(w, `{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","message":"daily","details":[{"@type":"type.googleapis.com/google.rpc.QuotaFailure","violations":[{"quotaId":"GenerateRequestsPerDayPerProjectPerModel-FreeTier"}]}]}}`)
			return
		case "k-bad":
			w.WriteHeader(400)
			io.WriteString(w, `[{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"API key not valid.","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID"}]}}]`)
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1beta/models") {
			io.WriteString(w, `{"models":[{"name":"models/gemini-3.8-flash-tts"},{"name":"models/gemini-3.8-flash"}]}`)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.bodies = append(f.bodies, body)
		f.mu.Unlock()
		pcm := make([]byte, 4800) // 0.1 s at 24 kHz
		switch {
		case r.URL.Path == "/v1beta/interactions" && f.legacy:
			w.WriteHeader(404)
			io.WriteString(w, `{"error":{"code":404,"status":"NOT_FOUND","message":"not found"}}`)
		case r.URL.Path == "/v1beta/interactions":
			wav := base64.StdEncoding.EncodeToString(wavFile(pcm, 24000))
			io.WriteString(w, `{"steps":[{"type":"model_output","content":[{"type":"audio","data":"`+wav+`"}]}]}`)
		case strings.HasSuffix(r.URL.Path, ":generateContent"):
			d := base64.StdEncoding.EncodeToString(pcm)
			io.WriteString(w, `{"candidates":[{"content":{"parts":[{"inlineData":{"mimeType":"audio/L16;codec=pcm;rate=24000","data":"`+d+`"}}]}}]}`)
		default:
			w.WriteHeader(404)
		}
	})
}

func geminiEnv(t *testing.T, keys map[string]string) (*Gemini, *fakeGemini) {
	t.Helper()
	s, v, _ := testEnv(t)
	for n, val := range keys {
		if err := v.Set(n, val, false, ""); err != nil {
			t.Fatal(err)
		}
	}
	f := &fakeGemini{}
	ts := httptest.NewServer(f.handler(t))
	t.Cleanup(ts.Close)
	p := NewGeminiPool(s, v)
	p.base = ts.URL
	return &Gemini{pool: p, OutDir: t.TempDir(), link: func(n string) string { return "link:" + n }}, f
}

func TestGeminiPoolRotation(t *testing.T) {
	g, f := geminiEnv(t, map[string]string{"GEMINI_API_KEY_1": "k-rate", "GEMINI_API_KEY_2": "k-bad", "GEMINI_API_KEY_3": "k-daily", "GEMINI_API_KEY_4": "k-ok", "OTHER": "x"})
	if n := len(g.pool.Keys()); n != 4 {
		t.Fatalf("pool should see 4 keys, got %d", n)
	}
	out, err := g.TTS(context.Background(), TTSIn{Text: "Hello world.", Model: "gemini-3.8-flash-tts"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.KeysUsed) != 1 || out.KeysUsed[0] != "GEMINI_API_KEY_4" {
		t.Fatalf("expected the working key, got %v", out.KeysUsed)
	}
	st := map[string]PoolKeyStatus{}
	for _, s := range g.pool.Status() {
		st[s.Name] = s
	}
	if st["GEMINI_API_KEY_1"].State != "cooling" || st["GEMINI_API_KEY_2"].State != "invalid" || st["GEMINI_API_KEY_3"].State != "daily" || st["GEMINI_API_KEY_4"].State != "ready" {
		t.Fatalf("states: %+v", st)
	}
	until, _ := time.Parse(time.RFC3339, st["GEMINI_API_KEY_1"].Until)
	if d := time.Until(until); d < 20*time.Second || d > 40*time.Second {
		t.Fatalf("retryDelay not honored: %v", d)
	}
	// second call: only the good key is tried
	before := f.hits["k-rate"] + f.hits["k-bad"] + f.hits["k-daily"]
	if _, err := g.TTS(context.Background(), TTSIn{Text: "Tekrar.", Model: "gemini-3.8-flash-tts"}); err != nil {
		t.Fatal(err)
	}
	if after := f.hits["k-rate"] + f.hits["k-bad"] + f.hits["k-daily"]; after != before {
		t.Fatalf("cooling/invalid keys were retried")
	}
	// cooldown is per model: a different model may use key 1 again
	if _, _, err := g.pool.acquire("gemini-other", map[string]bool{"GEMINI_API_KEY_4": true, "GEMINI_API_KEY_3": true}); err != nil {
		t.Fatalf("key 1 should be free for another model: %v", err)
	}
	// replacing a key clears its invalid mark
	g.pool.KeyChanged("GEMINI_API_KEY_2")
	for _, s := range g.pool.Status() {
		if s.Name == "GEMINI_API_KEY_2" && s.State != "ready" {
			t.Fatal("replaced key should be ready")
		}
	}
}

func TestGeminiAllLimited(t *testing.T) {
	g, _ := geminiEnv(t, map[string]string{"GEMINI_API_KEY": "k-rate"})
	_, err := g.TTS(context.Background(), TTSIn{Text: "x", Model: "m-tts"})
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("want rate-limited error, got %v", err)
	}
	g2, _ := geminiEnv(t, nil)
	r := g2.noKeyResult(func() error { _, err := g2.TTS(context.Background(), TTSIn{Text: "x", Model: "m"}); return err }())
	if !strings.Contains(resultText(r, 500), "link:GEMINI_API_KEY_1") {
		t.Fatalf("empty pool should point to the vault: %s", resultText(r, 500))
	}
}

func TestGeminiTTSChunksAndWAV(t *testing.T) {
	g, f := geminiEnv(t, map[string]string{"GEMINI_API_KEY_A": "k1", "GEMINI_API_KEY_B": "k2"})
	long := strings.Repeat("This long sentence will be read on a radio show. ", 200) // ~10k chars
	out, err := g.TTS(context.Background(), TTSIn{Text: long, Voice: "Puck", Style: "warm radio host", Filename: "../../etc/bolum 1.wav"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Chunks < 4 || len(out.KeysUsed) != 2 {
		t.Fatalf("expected parallel chunks over 2 keys: %+v", out)
	}
	if out.Model != "gemini-3.8-flash-tts" {
		t.Fatalf("default model from list: %s", out.Model)
	}
	if !strings.HasPrefix(out.Path, g.OutDir) || !strings.HasSuffix(out.Path, "bolum-1.wav") {
		t.Fatalf("path escaped or unsanitized: %s", out.Path)
	}
	b, _ := os.ReadFile(out.Path)
	pcm, rate, err := toPCM(audioBlob{data: b})
	if err != nil || rate != 24000 || len(pcm) != out.Chunks*4800+(out.Chunks-1)*12000 {
		t.Fatalf("bad wav: rate=%d len=%d err=%v", rate, len(pcm), err)
	}
	fi, _ := os.Stat(out.Path)
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("output must be readable by the user: %v", fi.Mode())
	}
	body := f.bodies[0]
	sc := body["generation_config"].(map[string]any)["speech_config"].([]any)[0].(map[string]any)
	if sc["voice"] != "Puck" {
		t.Fatalf("voice not sent: %v", body)
	}
	ann := body["input"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)["annotations"].([]any)[0].(map[string]any)
	if ann["style"] != "warm radio host" {
		t.Fatalf("style not sent: %v", ann)
	}
}

func TestGeminiDialogue(t *testing.T) {
	g, f := geminiEnv(t, map[string]string{"GEMINI_API_KEY_1": "k1"})
	in := TTSIn{Model: "gemini-3.8-flash-tts", Speakers: []TTSSpeaker{{"Alice", "Puck"}, {"Bob", "Kore"}},
		Turns: []TTSTurn{{Speaker: "Alice", Text: "Good morning!"}, {Speaker: "Bob", Text: "Good morning, Alice <laugh>", Style: "cheerful"}}}
	if _, err := g.TTS(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	body := f.bodies[0]
	content := body["input"].([]any)[0].(map[string]any)["content"].([]any)
	if len(content) != 2 {
		t.Fatalf("one content item per turn: %v", content)
	}
	spk := body["generation_config"].(map[string]any)["speech_config"].(map[string]any)["speakers"].([]any)
	if len(spk) != 2 {
		t.Fatalf("speakers: %v", spk)
	}
	// unknown speaker is rejected
	in.Turns = append(in.Turns, TTSTurn{Speaker: "Carol", Text: "x"})
	if _, err := g.TTS(context.Background(), in); err == nil {
		t.Fatal("speaker without voice should fail")
	}
	// 3 speakers → turn-by-turn single-speaker requests
	in.Speakers = append(in.Speakers, TTSSpeaker{"Carol", "Charon"})
	f.bodies = nil
	out, err := g.TTS(context.Background(), in)
	if err != nil || out.Chunks != 3 {
		t.Fatalf("3 speakers: %+v %v", out, err)
	}
}

func TestGeminiLegacyFallback(t *testing.T) {
	g, f := geminiEnv(t, map[string]string{"GEMINI_API_KEY_1": "k1"})
	f.legacy = true
	out, err := g.TTS(context.Background(), TTSIn{Text: "Legacy model.", Model: "gemini-3.9-tts"})
	if err != nil || out.DurationSeconds != 0.1 {
		t.Fatalf("fallback to generateContent: %+v %v", out, err)
	}
	// old models go straight to generateContent
	f.bodies = nil
	if _, err := g.TTS(context.Background(), TTSIn{Text: "x", Model: "gemini-2.5-flash-preview-tts"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.bodies[0]["contents"]; !ok {
		t.Fatalf("expected generateContent body: %v", f.bodies[0])
	}
}

func TestSplitText(t *testing.T) {
	// Deliberately non-ASCII (Turkish) text: splitting must count runes, not bytes.
	s := strings.Repeat("Kısa cümle. ", 1000)
	parts := splitText(s, 500)
	joined := strings.Join(parts, " ")
	if strings.Count(joined, "Kısa cümle.") != 1000 {
		t.Fatal("text lost while splitting")
	}
	for _, p := range parts {
		if len([]rune(p)) > 500 {
			t.Fatalf("chunk too long: %d", len([]rune(p)))
		}
	}
	// balanced: 1500 chars with max 1000 → two chunks of ~750, not 1000+500
	bal := splitText(strings.Repeat("Bir iki üç. ", 125), 1000)
	if len(bal) != 2 || len([]rune(bal[0])) > 900 {
		t.Fatalf("unbalanced chunks: %d / %d", len(bal), len([]rune(bal[0])))
	}
	nospace := strings.Repeat("a", 1200)
	if ps := splitText(nospace, 500); strings.Join(ps, "") != nospace {
		t.Fatal("unbroken text lost")
	}
}

func TestGeminiBuiltinServer(t *testing.T) {
	s, v, cat := testEnv(t)
	_ = v.Set("GEMINI_API_KEY_1", "k1", false, "")
	f := &fakeGemini{}
	ts := httptest.NewServer(f.handler(t))
	defer ts.Close()
	mgr := NewManager(s, v, "http://localhost:7777", slog.Default())
	g := &Gateway{store: s, vault: v, mgr: mgr, catalog: cat, baseURL: "http://localhost:7777"}
	pool := NewGeminiPool(s, v)
	pool.base = ts.URL
	g.gemini = &Gemini{pool: pool, OutDir: t.TempDir(), link: func(n string) string { return n }}
	mgr.Builtins = map[string]func() *mcp.Server{"gemini": g.gemini.Server}
	ensureBuiltins(g)
	agent := &Agent{ID: "a", CanManage: true}
	r := g.Call(context.Background(), agent, "gemini.tts", map[string]any{"text": "Merhaba", "model": "gemini-3.8-flash-tts"})
	if r.IsError {
		t.Fatalf("call failed: %s", resultText(r, 500))
	}
	if !strings.Contains(resultText(r, 2000), ".wav") {
		t.Fatalf("no path: %s", resultText(r, 2000))
	}
	// agents can't replace or remove the built-in server
	res := g.manage(context.Background(), agent, ManageIn{Action: "upsert_server", Server: &ServerConfig{ID: "gemini", Transport: "http", URL: "https://evil.example/mcp"}})
	if !res.IsError {
		t.Fatal("agent replaced built-in server")
	}
	res = g.manage(context.Background(), agent, ManageIn{Action: "remove_server", ID: "gemini"})
	if !res.IsError {
		t.Fatal("agent removed built-in server")
	}
	// removal by the user sticks across restarts
	_ = s.DeleteServer("gemini")
	ensureBuiltins(g)
	if _, err := s.GetServer("gemini"); err == nil {
		t.Fatal("removed built-in came back")
	}
}
