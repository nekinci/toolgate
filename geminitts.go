package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Gemini is the gateway's built-in "gemini" server: tools that call the
// Gemini API with keys from the pool. Outputs are written to OutDir.
type Gemini struct {
	pool   *KeyPool
	OutDir string
	link   func(path string) string // UI link for adding a key

	mu       sync.Mutex
	models   []string
	modelsAt time.Time
}

var preferredTTS = []string{"gemini-3.8-flash-tts", "gemini-3.8-flash-lite-tts", "gemini-3.1-flash-tts-preview", "gemini-2.5-flash-preview-tts", "gemini-2.5-pro-preview-tts"}

var geminiVoices = [][2]string{
	{"Zephyr", "Bright"}, {"Puck", "Upbeat"}, {"Charon", "Informative"}, {"Kore", "Firm"}, {"Fenrir", "Excitable"},
	{"Leda", "Youthful"}, {"Orus", "Firm"}, {"Aoede", "Breezy"}, {"Callirrhoe", "Easy-going"}, {"Autonoe", "Bright"},
	{"Enceladus", "Breathy"}, {"Iapetus", "Clear"}, {"Umbriel", "Easy-going"}, {"Algieba", "Smooth"}, {"Despina", "Smooth"},
	{"Erinome", "Clear"}, {"Algenib", "Gravelly"}, {"Rasalgethi", "Informative"}, {"Laomedeia", "Upbeat"}, {"Achernar", "Soft"},
	{"Alnilam", "Firm"}, {"Schedar", "Even"}, {"Gacrux", "Mature"}, {"Pulcherrima", "Forward"}, {"Achird", "Friendly"},
	{"Zubenelgenubi", "Casual"}, {"Vindemiatrix", "Gentle"}, {"Sadachbia", "Lively"}, {"Sadaltager", "Knowledgeable"}, {"Sulafat", "Warm"},
}

// TTSModels lists TTS-capable models available to the pool's keys (cached).
func (g *Gemini) TTSModels(ctx context.Context) ([]string, error) {
	g.mu.Lock()
	if len(g.models) > 0 && time.Since(g.modelsAt) < 6*time.Hour {
		m := g.models
		g.mu.Unlock()
		return m, nil
	}
	g.mu.Unlock()
	body, _, err := g.pool.Do(ctx, "models.list", 0, func(ctx context.Context, key string) ([]byte, error) {
		return g.pool.get(ctx, key, "/v1beta/models?pageSize=1000")
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	_ = json.Unmarshal(body, &resp)
	var out []string
	for _, m := range resp.Models {
		n := strings.TrimPrefix(m.Name, "models/")
		if strings.Contains(n, "tts") {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	g.mu.Lock()
	g.models, g.modelsAt = out, time.Now()
	g.mu.Unlock()
	return out, nil
}

func (g *Gemini) defaultTTSModel(ctx context.Context) string {
	ms, err := g.TTSModels(ctx)
	if err == nil {
		have := map[string]bool{}
		for _, m := range ms {
			have[m] = true
		}
		for _, p := range preferredTTS {
			if have[p] {
				return p
			}
		}
		if len(ms) > 0 {
			return ms[len(ms)-1]
		}
	}
	return preferredTTS[0]
}

// ---- tool inputs ----

type TTSTurn struct {
	Speaker string `json:"speaker" jsonschema:"speaker name, must match one of speakers[].speaker"`
	Text    string `json:"text" jsonschema:"what this speaker says, verbatim; inline tags like <laugh> or <short pause> are allowed"`
	Style   string `json:"style,omitempty" jsonschema:"optional delivery for this turn, e.g. excited or whispering"`
}

type TTSSpeaker struct {
	Speaker string `json:"speaker"`
	Voice   string `json:"voice" jsonschema:"prebuilt voice name, e.g. Kore or Puck (see gemini.voices)"`
}

type TTSIn struct {
	Text     string       `json:"text,omitempty" jsonschema:"single-speaker transcript, read verbatim. Long text is split into chunks automatically"`
	Voice    string       `json:"voice,omitempty" jsonschema:"single-speaker voice (default Kore)"`
	Style    string       `json:"style,omitempty" jsonschema:"sustained delivery for the whole text, e.g. warm radio host, calm and slow. Don't put stage directions in text"`
	Turns    []TTSTurn    `json:"turns,omitempty" jsonschema:"dialogue: one item per speaker turn (use instead of text)"`
	Speakers []TTSSpeaker `json:"speakers,omitempty" jsonschema:"dialogue voices, one per speaker"`
	Model    string       `json:"model,omitempty" jsonschema:"TTS model id; default is the newest available (see gemini.models)"`
	Filename string       `json:"filename,omitempty" jsonschema:"output file name (.wav); default tts-<time>.wav"`
}

type TTSOut struct {
	Path            string   `json:"path"`
	DurationSeconds float64  `json:"duration_seconds"`
	SampleRate      int      `json:"sample_rate"`
	Bytes           int      `json:"bytes"`
	Model           string   `json:"model"`
	Chunks          int      `json:"chunks"`
	KeysUsed        []string `json:"keys_used"`
	Note            string   `json:"note,omitempty"`
}

// ---- chunking ----

const ttsChunkChars = 3000

var sentenceEnd = regexp.MustCompile(`([.!?…]["'”’)]?)\s+`)

// splitText splits long text into chunks at paragraph, then sentence, then
// word boundaries.
func splitText(s string, max int) []string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) <= max {
		return []string{s}
	}
	var pieces []string
	for _, para := range regexp.MustCompile(`\n\s*\n`).Split(s, -1) {
		para = strings.TrimSpace(para)
		if para == "" {
			continue
		}
		if len([]rune(para)) <= max {
			pieces = append(pieces, para)
			continue
		}
		idx := sentenceEnd.FindAllStringSubmatchIndex(para, -1)
		start := 0
		for _, m := range idx {
			pieces = append(pieces, strings.TrimSpace(para[start:m[3]]))
			start = m[1]
		}
		if start < len(para) {
			pieces = append(pieces, strings.TrimSpace(para[start:]))
		}
	}
	// break any remaining oversize piece on words
	var flat []string
	for _, p := range pieces {
		for len([]rune(p)) > max {
			r := []rune(p)
			cut := max
			for i := max; i > max/2; i-- {
				if r[i] == ' ' {
					cut = i
					break
				}
			}
			flat = append(flat, strings.TrimSpace(string(r[:cut])))
			p = strings.TrimSpace(string(r[cut:]))
		}
		if p != "" {
			flat = append(flat, p)
		}
	}
	// Aim for equal-sized chunks so parallel requests finish together.
	total := len([]rune(s))
	n := (total + max - 1) / max
	target := (total + n - 1) / n
	var out []string
	cur := ""
	for _, p := range flat {
		sep := " "
		if cur == "" {
			sep = ""
		}
		next := len([]rune(cur)) + len([]rune(p)) + 1
		if cur != "" && (next > max || (len([]rune(cur)) >= target*9/10 && len(out) < n-1)) {
			out = append(out, cur)
			cur, sep = "", ""
		}
		cur += sep + p
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

type ttsJob struct {
	text     string    // single speaker
	turns    []TTSTurn // dialogue
	voice    string
	speakers []TTSSpeaker
	style    string
}

func (j ttsJob) chars() int {
	n := len([]rune(j.text))
	for _, t := range j.turns {
		n += len([]rune(t.Text))
	}
	return n
}

func planTTS(in TTSIn) ([]ttsJob, error) {
	voice := firstNonEmpty(in.Voice, "Kore")
	if len(in.Turns) == 0 {
		if strings.TrimSpace(in.Text) == "" {
			return nil, errors.New("give text (single speaker) or turns (dialogue)")
		}
		var jobs []ttsJob
		for _, c := range splitText(in.Text, ttsChunkChars) {
			jobs = append(jobs, ttsJob{text: c, voice: voice, style: in.Style})
		}
		return jobs, nil
	}
	voices := map[string]string{}
	for _, s := range in.Speakers {
		voices[s.Speaker] = s.Voice
	}
	seen := []string{}
	for i, t := range in.Turns {
		if strings.TrimSpace(t.Text) == "" {
			return nil, fmt.Errorf("turns[%d] has no text", i)
		}
		if _, ok := voices[t.Speaker]; !ok {
			return nil, fmt.Errorf("turns[%d]: speaker %q has no voice in speakers", i, t.Speaker)
		}
		if !contains(seen, t.Speaker) {
			seen = append(seen, t.Speaker)
		}
	}
	var jobs []ttsJob
	if len(seen) > 2 {
		// One request supports at most 2 speakers: synthesize turn by turn.
		for _, t := range in.Turns {
			for _, c := range splitText(t.Text, ttsChunkChars) {
				jobs = append(jobs, ttsJob{text: c, voice: voices[t.Speaker], style: firstNonEmpty(t.Style, in.Style)})
			}
		}
		return jobs, nil
	}
	spk := []TTSSpeaker{}
	for _, s := range seen {
		spk = append(spk, TTSSpeaker{Speaker: s, Voice: voices[s]})
	}
	cur := ttsJob{speakers: spk, style: in.Style}
	for _, t := range in.Turns {
		if cur.chars()+len(t.Text) > ttsChunkChars && len(cur.turns) > 0 {
			jobs = append(jobs, cur)
			cur = ttsJob{speakers: spk, style: in.Style}
		}
		cur.turns = append(cur.turns, t)
	}
	if len(cur.turns) > 0 {
		jobs = append(jobs, cur)
	}
	if len(spk) == 1 { // a "dialogue" with one speaker is a monologue
		for i := range jobs {
			var parts []string
			for _, t := range jobs[i].turns {
				parts = append(parts, t.Text)
			}
			jobs[i] = ttsJob{text: strings.Join(parts, "\n\n"), voice: spk[0].Voice, style: in.Style}
		}
	}
	return jobs, nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// ---- request bodies ----

func interactionsBody(model string, j ttsJob) map[string]any {
	ann := func(speaker, style string) []any {
		m := map[string]any{"type": "speech_metadata"}
		if speaker != "" {
			m["speaker"] = speaker
		}
		if style != "" {
			m["style"] = style
		}
		if len(m) == 1 {
			return nil
		}
		return []any{m}
	}
	item := func(text, speaker, style string) map[string]any {
		it := map[string]any{"type": "text", "text": text}
		if a := ann(speaker, style); a != nil {
			it["annotations"] = a
		}
		return it
	}
	var content []any
	var speech any
	if len(j.turns) > 0 {
		for _, t := range j.turns {
			content = append(content, item(t.Text, t.Speaker, firstNonEmpty(t.Style, j.style)))
		}
		var spk []any
		for _, s := range j.speakers {
			spk = append(spk, map[string]any{"speaker": s.Speaker, "voice": s.Voice})
		}
		speech = map[string]any{"speakers": spk}
	} else {
		content = []any{item(j.text, "", j.style)}
		speech = []any{map[string]any{"voice": j.voice}}
	}
	return map[string]any{
		"model":             model,
		"input":             []any{map[string]any{"type": "user_input", "content": content}},
		"response_format":   map[string]any{"type": "audio"},
		"generation_config": map[string]any{"speech_config": speech},
	}
}

// generateContentBody is the older TTS API, used for models that don't take
// the Interactions API.
func generateContentBody(j ttsJob) map[string]any {
	var text string
	var speech map[string]any
	if len(j.turns) > 0 {
		var b strings.Builder
		for _, t := range j.turns {
			fmt.Fprintf(&b, "%s: %s\n", t.Speaker, t.Text)
		}
		text = b.String()
		var cfgs []any
		for _, s := range j.speakers {
			cfgs = append(cfgs, map[string]any{"speaker": s.Speaker,
				"voiceConfig": map[string]any{"prebuiltVoiceConfig": map[string]any{"voiceName": s.Voice}}})
		}
		speech = map[string]any{"multiSpeakerVoiceConfig": map[string]any{"speakerVoiceConfigs": cfgs}}
	} else {
		text = j.text
		speech = map[string]any{"voiceConfig": map[string]any{"prebuiltVoiceConfig": map[string]any{"voiceName": j.voice}}}
	}
	if j.style != "" {
		text = "Say this in a " + j.style + " way:\n" + text
	}
	return map[string]any{
		"contents":         []any{map[string]any{"parts": []any{map[string]any{"text": text}}}},
		"generationConfig": map[string]any{"responseModalities": []string{"AUDIO"}, "speechConfig": speech},
	}
}

// ---- audio decoding ----

type audioBlob struct {
	data []byte
	mime string
}

// findAudio pulls base64 audio out of an Interactions or generateContent
// response.
func findAudio(body []byte) ([]audioBlob, error) {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, err
	}
	var out []audioBlob
	add := func(data, mime string) {
		if b, err := base64.StdEncoding.DecodeString(data); err == nil && len(b) > 0 {
			out = append(out, audioBlob{data: b, mime: mime})
		}
	}
	root, _ := v.(map[string]any)
	// Interactions: steps[type=model_output].content[type=audio].data
	if steps, ok := root["steps"].([]any); ok {
		for _, s := range steps {
			sm, _ := s.(map[string]any)
			if sm["type"] != "model_output" {
				continue
			}
			cs, _ := sm["content"].([]any)
			for _, c := range cs {
				cm, _ := c.(map[string]any)
				if cm["type"] == "audio" {
					d, _ := cm["data"].(string)
					m, _ := cm["mime_type"].(string)
					add(d, m)
				}
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	// generateContent: candidates[].content.parts[].inlineData
	// or anything else: search recursively for {type: audio, data} / inlineData.
	var walk func(x any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			if id, ok := t["inlineData"].(map[string]any); ok {
				d, _ := id["data"].(string)
				m, _ := id["mimeType"].(string)
				add(d, m)
				return
			}
			if t["type"] == "audio" {
				if d, ok := t["data"].(string); ok {
					m, _ := t["mime_type"].(string)
					add(d, m)
					return
				}
			}
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k])
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	if len(out) == 0 {
		return nil, fmt.Errorf("no audio in response: %s", truncate(string(body), 300))
	}
	return out, nil
}

// toPCM returns raw 16-bit mono PCM and its sample rate.
func toPCM(b audioBlob) ([]byte, int, error) {
	d := b.data
	if len(d) >= 12 && string(d[:4]) == "RIFF" && string(d[8:12]) == "WAVE" {
		rate, ch, bits := 24000, 1, 16
		var pcm []byte
		for i := 12; i+8 <= len(d); {
			id := string(d[i : i+4])
			n := int(binary.LittleEndian.Uint32(d[i+4 : i+8]))
			body := d[i+8 : min(len(d), i+8+n)]
			switch id {
			case "fmt ":
				if len(body) >= 16 {
					ch = int(binary.LittleEndian.Uint16(body[2:4]))
					rate = int(binary.LittleEndian.Uint32(body[4:8]))
					bits = int(binary.LittleEndian.Uint16(body[14:16]))
				}
			case "data":
				pcm = body
			}
			i += 8 + n + n%2
		}
		if ch != 1 || bits != 16 {
			return nil, 0, fmt.Errorf("unexpected WAV format: %d channels, %d bits", ch, bits)
		}
		return pcm, rate, nil
	}
	rate := 24000
	if m := regexp.MustCompile(`rate=(\d+)`).FindStringSubmatch(b.mime); m != nil {
		rate, _ = strconv.Atoi(m[1])
	}
	return d, rate, nil
}

func wavFile(pcm []byte, rate int) []byte {
	h := make([]byte, 44)
	copy(h[0:], "RIFF")
	binary.LittleEndian.PutUint32(h[4:], uint32(36+len(pcm)))
	copy(h[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(h[16:], 16)
	binary.LittleEndian.PutUint16(h[20:], 1) // PCM
	binary.LittleEndian.PutUint16(h[22:], 1) // mono
	binary.LittleEndian.PutUint32(h[24:], uint32(rate))
	binary.LittleEndian.PutUint32(h[28:], uint32(rate*2))
	binary.LittleEndian.PutUint16(h[32:], 2)
	binary.LittleEndian.PutUint16(h[34:], 16)
	copy(h[36:], "data")
	binary.LittleEndian.PutUint32(h[40:], uint32(len(pcm)))
	return append(h, pcm...)
}

// ---- synthesis ----

func useInteractions(model string) bool {
	// The older preview models predate the Interactions API.
	return !strings.HasPrefix(model, "gemini-2.") && !strings.HasPrefix(model, "gemini-3.1-")
}

func (g *Gemini) synth(ctx context.Context, model string, j ttsJob) ([]byte, int, string, error) {
	body, key, err := g.pool.Do(ctx, model, j.chars(), func(ctx context.Context, key string) ([]byte, error) {
		if useInteractions(model) {
			b, err := g.pool.post(ctx, key, "/v1beta/interactions", interactionsBody(model, j))
			var ge *geminiAPIError
			if err == nil || !errors.As(err, &ge) || ge.classify() != "request" || ge.HTTP != 404 {
				return b, err
			}
			// 404: endpoint not available for this model; try the older API.
		}
		return g.pool.post(ctx, key, "/v1beta/models/"+model+":generateContent", generateContentBody(j))
	})
	if err != nil {
		return nil, 0, key, err
	}
	blobs, err := findAudio(body)
	if err != nil {
		return nil, 0, key, err
	}
	var pcm []byte
	rate := 0
	for _, b := range blobs {
		p, r, err := toPCM(b)
		if err != nil {
			return nil, 0, key, err
		}
		if rate != 0 && r != rate {
			return nil, 0, key, fmt.Errorf("mixed sample rates %d/%d", rate, r)
		}
		rate = r
		pcm = append(pcm, p...)
	}
	return pcm, rate, key, nil
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func (g *Gemini) outPath(name, prefix, ext string) (string, error) {
	if err := os.MkdirAll(g.OutDir, 0o755); err != nil {
		return "", err
	}
	_ = os.Chmod(g.OutDir, 0o755)
	name = strings.TrimSuffix(filepath.Base(name), filepath.Ext(name))
	name = strings.Trim(unsafeName.ReplaceAllString(name, "-"), "-.")
	if name == "" {
		name = prefix + "-" + time.Now().Format("20060102-150405")
	}
	p := filepath.Join(g.OutDir, name+ext)
	for i := 2; ; i++ {
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			return p, nil
		}
		p = filepath.Join(g.OutDir, fmt.Sprintf("%s-%d%s", name, i, ext))
	}
}

// TTS synthesizes speech, spreading chunks across pool keys in parallel.
func (g *Gemini) TTS(ctx context.Context, in TTSIn) (*TTSOut, error) {
	jobs, err := planTTS(in)
	if err != nil {
		return nil, err
	}
	model := in.Model
	if model == "" {
		model = g.defaultTTSModel(ctx)
	}
	type res struct {
		pcm  []byte
		rate int
		key  string
		err  error
	}
	results := make([]res, len(jobs))
	par := min(max(len(g.pool.Keys()), 1), 4)
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j ttsJob) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				results[i].err = ctx.Err()
				return
			}
			pcm, rate, key, err := g.synth(ctx, model, j)
			results[i] = res{pcm, rate, key, err}
			if err != nil {
				cancel()
			}
		}(i, j)
	}
	wg.Wait()
	var pcm []byte
	rate := 0
	keys := []string{}
	for i, r := range results {
		if r.err != nil && !errors.Is(r.err, context.Canceled) {
			return nil, fmt.Errorf("chunk %d/%d: %w", i+1, len(jobs), r.err)
		}
	}
	for i, r := range results {
		if r.err != nil {
			return nil, fmt.Errorf("chunk %d/%d: %w", i+1, len(jobs), r.err)
		}
		if rate != 0 && r.rate != rate {
			return nil, fmt.Errorf("chunks came back with different sample rates")
		}
		rate = r.rate
		if i > 0 && rate > 0 { // short gap between chunks so sentences don't run together
			pcm = append(pcm, make([]byte, rate*2*25/100)...)
		}
		pcm = append(pcm, r.pcm...)
		if !contains(keys, r.key) {
			keys = append(keys, r.key)
		}
	}
	p, err := g.outPath(in.Filename, "tts", ".wav")
	if err != nil {
		return nil, err
	}
	wav := wavFile(pcm, rate)
	if err := os.WriteFile(p, wav, 0o644); err != nil {
		return nil, err
	}
	_ = os.Chmod(p, 0o644) // the daemon runs with umask 077
	out := &TTSOut{Path: p, SampleRate: rate, Bytes: len(wav), Model: model, Chunks: len(jobs), KeysUsed: keys,
		DurationSeconds: float64(len(pcm)) / float64(rate*2)}
	out.DurationSeconds = float64(int(out.DurationSeconds*10)) / 10
	out.Note = "16-bit mono WAV. Copy it into your project (e.g. cp) if you need it there."
	return out, nil
}

// ---- MCP server ----

func (g *Gemini) noKeyResult(err error) *mcp.CallToolResult {
	var nk *NoKeyError
	if errors.As(err, &nk) && nk.Empty {
		return errResult("No Gemini API keys in the gateway yet. Ask the user to add one here (they can add several; the gateway rotates between them):\n%s", g.link("GEMINI_API_KEY_1"))
	}
	return errResult("%v", err)
}

func (g *Gemini) Server() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "gemini", Version: version}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "tts", Description: "Text to speech with Gemini. Single speaker: give text (+ voice, style). Dialogue/podcast: give turns [{speaker, text}] and speakers [{speaker, voice}]. Long text is split and synthesized in parallel across the gateway's API keys, then joined into one WAV file. Returns the file path (in the gateway's shared output folder) and duration. Text is read verbatim: put delivery in style, not in text; inline tags like <laugh>, <sigh>, <short pause> work."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in TTSIn) (*mcp.CallToolResult, any, error) {
			out, err := g.TTS(ctx, in)
			if err != nil {
				return g.noKeyResult(err), nil, nil
			}
			return jsonResult(out), nil, nil
		})
	type empty struct{}
	mcp.AddTool(s, &mcp.Tool{Name: "voices", Description: "List Gemini's prebuilt TTS voices and their character (e.g. Kore = firm, Puck = upbeat)."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, any, error) {
			var out []map[string]string
			for _, v := range geminiVoices {
				out = append(out, map[string]string{"voice": v[0], "character": v[1]})
			}
			return jsonResult(out), nil, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "models", Description: "List the TTS models the gateway's Gemini keys can use, and which one is the default."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, any, error) {
			ms, err := g.TTSModels(ctx)
			if err != nil {
				return g.noKeyResult(err), nil, nil
			}
			return jsonResult(map[string]any{"tts_models": ms, "default": g.defaultTTSModel(ctx)}), nil, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "pool_status", Description: "Show the gateway's Gemini API key pool: how many keys, which are ready, rate limited (and until when) or invalid, and today's usage. Key values are never shown."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, any, error) {
			st := g.pool.Status()
			if len(st) == 0 {
				return g.noKeyResult(&NoKeyError{Empty: true}), nil, nil
			}
			return jsonResult(map[string]any{"keys": st, "output_dir": g.OutDir}), nil, nil
		})
	return s
}
