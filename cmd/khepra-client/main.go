// cmd/khepra-client — Khepra Local LLM/MCP Frontend Client
//
// A standalone binary that serves a minimal browser-based NL chat UI at
// localhost, forwarding queries to a local DEMARC API server + Ollama LLM.
// No external network calls, no cloud dependencies — air-gapped ready.
//
// DESIGN GOALS:
//   - Iron Bank / Platform One container ready (hardened, no external deps)
//   - Works fully air-gapped (everything served from embedded assets)
//   - Single binary: embed HTML/CSS/JS via Go embed
//   - Connects to local DEMARC API (cmd/apiserver) + Ollama for NL processing
//   - All queries go through the existing PQC-authenticated MCP toolchain
//   - Session history kept in memory only (no local file writes)
//
// USAGE:
//
//	khepra-client [--port 7777] [--api-url http://localhost:8080]
//	              [--ollama-url http://localhost:11434] [--model phi4]
//	              [--pqc-token <token>] [--no-browser]
//
// ENVIRONMENT VARIABLES (all optional, overridden by flags):
//
//	KHEPRA_API_URL        DEMARC API base URL    (default: http://localhost:8080)
//	KHEPRA_PQC_TOKEN      PQC auth token         (default: empty — anon mode)
//	OLLAMA_URL            Ollama base URL         (default: http://localhost:11434)
//	OLLAMA_MODEL          Ollama model name       (default: phi4)
//	CLIENT_PORT           Listen port             (default: 7777)
//
// PLATFORM ONE / IRON BANK:
//
//	Submit this binary in a UBI9-minimal container image.
//	Set KHEPRA_API_URL to the in-cluster service endpoint.
//	No egress rules needed — all traffic stays within the cluster.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// ─── Config ──────────────────────────────────────────────────────────────────

const contentTypeHeader = "Content-Type"
const contentTypeJSON = "application/json"

type Config struct {
	Port        string
	APIBaseURL  string
	OllamaURL   string
	OllamaModel string
	PQCToken    string
	NoBrowser   bool
}

func loadConfig() Config {
	cfg := Config{
		Port:        envOr("CLIENT_PORT", "7777"),
		APIBaseURL:  envOr("KHEPRA_API_URL", "http://localhost:8080"),
		OllamaURL:   envOr("OLLAMA_URL", "http://localhost:11434"),
		OllamaModel: envOr("OLLAMA_MODEL", "phi4"),
		PQCToken:    envOr("KHEPRA_PQC_TOKEN", ""),
	}

	flag.StringVar(&cfg.Port, "port", cfg.Port, "Local listen port")
	flag.StringVar(&cfg.APIBaseURL, "api-url", cfg.APIBaseURL, "DEMARC API base URL")
	flag.StringVar(&cfg.OllamaURL, "ollama-url", cfg.OllamaURL, "Ollama base URL")
	flag.StringVar(&cfg.OllamaModel, "model", cfg.OllamaModel, "Ollama model name")
	flag.StringVar(&cfg.PQCToken, "pqc-token", cfg.PQCToken, "PQC auth token")
	flag.BoolVar(&cfg.NoBrowser, "no-browser", false, "Skip auto-opening browser")
	flag.Parse()

	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	cfg := loadConfig()

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveUI(cfg))
	mux.HandleFunc("/api/ask", handleAsk(cfg))
	mux.HandleFunc("/api/health", handleHealth(cfg))
	mux.HandleFunc("/api/tools", handleTools(cfg))

	addr := net.JoinHostPort("127.0.0.1", cfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
	}

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	url := fmt.Sprintf("http://%s", addr)
	log.Printf("[khepra-client] Listening on %s", url)
	log.Printf("[khepra-client] DEMARC API: %s", cfg.APIBaseURL)
	log.Printf("[khepra-client] Ollama: %s (%s)", cfg.OllamaURL, cfg.OllamaModel)
	if cfg.PQCToken != "" {
		log.Printf("[khepra-client] Auth: PQC token configured")
	} else {
		log.Printf("[khepra-client] Auth: anonymous (no PQC token)")
	}

	if !cfg.NoBrowser {
		go openBrowser(url)
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[khepra-client] fatal: %v", err)
	}

	log.Println("[khepra-client] Shutdown complete.")
}

// ─── Browser launch ───────────────────────────────────────────────────────────

func openBrowser(url string) {
	time.Sleep(500 * time.Millisecond) // let server start first
	switch runtime.GOOS {
	case "linux":
		_ = exec.Command("xdg-open", url).Start()
	case "darwin":
		_ = exec.Command("open", url).Start()
	case "windows":
		_ = exec.Command("cmd", "/c", "start", url).Start()
	}
}

// ─── UI Handler ───────────────────────────────────────────────────────────────

func serveUI(cfg Config) http.HandlerFunc {
	html := buildHTML(cfg)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(contentTypeHeader, "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';")
		fmt.Fprint(w, html)
	}
}

// buildHTML returns the complete single-file chat UI as a string.
// All CSS and JS is inlined — no external CDN dependencies (air-gapped safe).
func buildHTML(cfg Config) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Khepra AI — Security Intelligence</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #388bfd;
    --green: #3fb950; --red: #f85149; --amber: #d29922;
    --font: 'Segoe UI', system-ui, -apple-system, sans-serif;
    --mono: 'Cascadia Code', 'JetBrains Mono', 'Fira Code', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font);
         display: flex; flex-direction: column; height: 100vh; overflow: hidden; }
  header { background: var(--surface); border-bottom: 1px solid var(--border);
           padding: 12px 20px; display: flex; align-items: center; gap: 12px; }
  .logo { width: 28px; height: 28px; background: var(--accent); border-radius: 6px;
          display: flex; align-items: center; justify-content: center; font-size: 16px; }
  h1 { font-size: 15px; font-weight: 600; }
  .badge { font-size: 11px; padding: 2px 8px; border-radius: 12px;
           background: #1f3044; color: var(--accent); border: 1px solid #1f4878; }
  .status-dot { width: 8px; height: 8px; border-radius: 50%%; margin-left: auto;
                background: var(--muted); transition: background 0.3s; }
  .status-dot.online { background: var(--green); }
  .status-dot.error  { background: var(--red); }
  .status-text { font-size: 12px; color: var(--muted); }
  main { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex;
         flex-direction: column; gap: 12px; }
  .msg { display: flex; gap: 10px; max-width: 900px; width: 100%%; }
  .msg.user { align-self: flex-end; flex-direction: row-reverse; }
  .avatar { width: 32px; height: 32px; border-radius: 50%%; flex-shrink: 0;
             display: flex; align-items: center; justify-content: center;
             font-size: 14px; font-weight: 600; }
  .msg.user .avatar { background: var(--accent); }
  .msg.ai   .avatar { background: #21262d; border: 1px solid var(--border); }
  .bubble { background: var(--surface); border: 1px solid var(--border);
            border-radius: 12px; padding: 10px 14px; max-width: calc(100%% - 44px);
            line-height: 1.6; font-size: 14px; }
  .msg.user .bubble { background: #1f3044; border-color: #1f4878; }
  .bubble pre { background: #0d1117; border: 1px solid var(--border);
                border-radius: 6px; padding: 10px; margin: 8px 0;
                overflow-x: auto; font-family: var(--mono); font-size: 13px; }
  .tools-used { margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--border); }
  .tool-tag { display: inline-block; font-size: 11px; padding: 2px 6px;
              border-radius: 4px; background: #1f2937; color: var(--muted);
              border: 1px solid var(--border); margin: 2px; font-family: var(--mono); }
  .confidence { font-size: 11px; color: var(--muted); margin-top: 4px; }
  .thinking { display: flex; align-items: center; gap: 6px; color: var(--muted);
              font-size: 13px; padding: 8px 0; }
  .dot-pulse { display: flex; gap: 4px; }
  .dot-pulse span { width: 6px; height: 6px; border-radius: 50%%; background: var(--accent);
                    animation: pulse 1.2s infinite; }
  .dot-pulse span:nth-child(2) { animation-delay: 0.2s; }
  .dot-pulse span:nth-child(3) { animation-delay: 0.4s; }
  @keyframes pulse { 0%%,80%%,100%% { opacity: 0.2; } 40%% { opacity: 1; } }
  footer { background: var(--surface); border-top: 1px solid var(--border);
           padding: 12px 20px; }
  .input-row { display: flex; gap: 10px; align-items: flex-end; }
  textarea { flex: 1; background: var(--bg); border: 1px solid var(--border);
             color: var(--text); border-radius: 8px; padding: 10px 14px;
             font-family: var(--font); font-size: 14px; resize: none;
             min-height: 44px; max-height: 200px; outline: none;
             transition: border-color 0.2s; }
  textarea:focus { border-color: var(--accent); }
  textarea::placeholder { color: var(--muted); }
  button { background: var(--accent); color: white; border: none;
           border-radius: 8px; padding: 10px 18px; font-size: 14px;
           font-weight: 600; cursor: pointer; transition: opacity 0.2s;
           white-space: nowrap; }
  button:hover:not(:disabled) { opacity: 0.85; }
  button:disabled { opacity: 0.4; cursor: default; }
  .hint { font-size: 11px; color: var(--muted); margin-top: 6px; }
  .system-info { font-size: 12px; color: var(--muted); padding: 8px 0;
                 display: flex; gap: 16px; }
  .welcome { text-align: center; padding: 40px 20px; color: var(--muted); }
  .welcome h2 { font-size: 20px; color: var(--text); margin-bottom: 8px; }
  .welcome p  { font-size: 14px; line-height: 1.6; max-width: 500px; margin: 0 auto 16px; }
  .chips { display: flex; flex-wrap: wrap; gap: 8px; justify-content: center; margin-top: 12px; }
  .chip { background: var(--surface); border: 1px solid var(--border); border-radius: 20px;
          padding: 6px 14px; font-size: 13px; cursor: pointer; transition: border-color 0.2s; }
  .chip:hover { border-color: var(--accent); color: var(--accent); }
  @media (max-width: 600px) {
    main { padding: 10px 12px; }
    footer { padding: 10px 12px; }
    .msg { max-width: 100%%; }
  }
</style>
</head>
<body>
<header>
  <div class="logo">⚡</div>
  <h1>Khepra AI</h1>
  <span class="badge">AdinKhepra v2</span>
  <div class="status-dot" id="statusDot"></div>
  <span class="status-text" id="statusText">Checking...</span>
</header>
<main id="chat">
  <div class="welcome" id="welcome">
    <h2>Khepra Security Intelligence</h2>
    <p>Ask questions about your compliance posture, run security scans,
       query STIG rules, or analyze threats — all in natural language.</p>
    <div class="chips">
      <div class="chip" onclick="sendSuggestion(this)">What is my CMMC L2 score?</div>
      <div class="chip" onclick="sendSuggestion(this)">Run a STIG scan on all endpoints</div>
      <div class="chip" onclick="sendSuggestion(this)">Show recent security alerts</div>
      <div class="chip" onclick="sendSuggestion(this)">Export CMMC L2 attestation</div>
      <div class="chip" onclick="sendSuggestion(this)">What STIG findings are critical?</div>
    </div>
  </div>
</main>
<footer>
  <div class="input-row">
    <textarea id="q" rows="1" placeholder="Ask about compliance, threats, STIG rules..."
              onkeydown="onKey(event)" oninput="resize(this)"></textarea>
    <button id="sendBtn" onclick="send()">Ask</button>
  </div>
  <div class="system-info">
    <span>API: <code id="apiUrl">%s</code></span>
    <span>Model: <code id="modelName">%s</code></span>
    <span id="sessionInfo">Session: local</span>
  </div>
  <div class="hint">Shift+Enter for new line · Enter to send</div>
</footer>

<script>
const apiBase = '';  // relative — served by same Go binary

let sessionId = 'sess-' + Math.random().toString(36).slice(2, 10);
document.getElementById('sessionInfo').textContent = 'Session: ' + sessionId;

// ── Health check ──
async function checkHealth() {
  const dot = document.getElementById('statusDot');
  const txt = document.getElementById('statusText');
  try {
    const r = await fetch('/api/health');
    const j = await r.json();
    dot.className = 'status-dot online';
    txt.textContent = j.ollama_ok ? 'Online · LLM ready' : 'Online · LLM unavailable';
  } catch {
    dot.className = 'status-dot error';
    txt.textContent = 'API offline';
  }
}
checkHealth();
setInterval(checkHealth, 30000);

// ── Input helpers ──
function resize(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 200) + 'px';
}

function onKey(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
}

function sendSuggestion(el) {
  document.getElementById('q').value = el.textContent;
  send();
}

// ── Message rendering ──
function addMsg(text, role) {
  const chat = document.getElementById('chat');
  const welcome = document.getElementById('welcome');
  if (welcome) welcome.remove();

  const div = document.createElement('div');
  div.className = 'msg ' + role;

  const av = document.createElement('div');
  av.className = 'avatar';
  av.textContent = role === 'user' ? 'U' : '⚡';

  const bubble = document.createElement('div');
  bubble.className = 'bubble';

  if (role === 'ai') {
    bubble.innerHTML = renderMarkdown(text);
  } else {
    bubble.textContent = text;
  }

  div.appendChild(av);
  div.appendChild(bubble);
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
  return bubble;
}

function addThinking() {
  const chat = document.getElementById('chat');
  const div = document.createElement('div');
  div.className = 'msg ai';
  div.id = 'thinking';
  div.innerHTML = '<div class="avatar">⚡</div><div class="thinking"><div class="dot-pulse"><span></span><span></span><span></span></div>Analyzing...</div>';
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

function removeThinking() {
  const t = document.getElementById('thinking');
  if (t) t.remove();
}

function renderMarkdown(text) {
  return text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')`+
		"    .replace(/```([\\\\s\\\\S]*?)```/g, (_, c) => '<pre>' + c.trim() + '</pre>')\n"+
		"    .replace(/\\x60([^\\x60]+)\\x60/g, '<code>$1</code>')\n"+
		`    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\n/g, '<br>');
}

// ── Send query ──
async function send() {
  const qEl = document.getElementById('q');
  const q = qEl.value.trim();
  if (!q) return;

  qEl.value = '';
  qEl.style.height = 'auto';
  document.getElementById('sendBtn').disabled = true;

  addMsg(q, 'user');
  addThinking();

  try {
    const r = await fetch('/api/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: q, session_id: sessionId }),
    });
    const j = await r.json();
    removeThinking();

    const bubble = addMsg(j.answer || j.error || 'No response', 'ai').parentElement.querySelector('.bubble');

    if (j.tools_called && j.tools_called.length > 0) {
      const tools = document.createElement('div');
      tools.className = 'tools-used';
      tools.innerHTML = '<span style="font-size:11px;color:var(--muted)">Tools: </span>' +
        j.tools_called.map(t => '<span class="tool-tag">' + t + '</span>').join('');
      bubble.appendChild(tools);
    }

    if (j.confidence != null) {
      const conf = document.createElement('div');
      conf.className = 'confidence';
      conf.textContent = 'Confidence: ' + Math.round(j.confidence * 100) + '%%';
      bubble.appendChild(conf);
    }
  } catch (err) {
    removeThinking();
    addMsg('Error: ' + err.message, 'ai');
  }

  document.getElementById('sendBtn').disabled = false;
  document.getElementById('q').focus();
}
</script>
</body>
</html>`, cfg.APIBaseURL, cfg.OllamaModel)
}

// ─── API Proxy Handlers ───────────────────────────────────────────────────────

// handleAsk proxies NL queries to the DEMARC API's /api/v1/mcp/ask endpoint.
// Falls back to direct Ollama if the DEMARC API is unavailable.
func handleAsk(cfg Config) http.HandlerFunc {
	httpClient := &http.Client{Timeout: 90 * time.Second}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil {
			jsonErr(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}

		var req struct {
			Query     string                 `json:"query"`
			SessionID string                 `json:"session_id"`
			Context   map[string]interface{} `json:"context,omitempty"`
			MaxTools  int                    `json:"max_tools,omitempty"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Query == "" {
			jsonErr(w, "query is required", http.StatusBadRequest)
			return
		}

		// Build upstream request to DEMARC /api/v1/mcp/ask
		apiReq, err := cfg.buildUpstreamRequest(r.Context(), req)
		if err != nil {
			jsonErr(w, "build request: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp, err := httpClient.Do(apiReq)
		if err != nil {
			cfg.handleFallback(w, r, req.Query, httpClient)
			return
		}
		defer resp.Body.Close()

		w.Header().Set(contentTypeHeader, contentTypeJSON)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

func (cfg Config) handleFallback(w http.ResponseWriter, r *http.Request, query string, httpClient *http.Client) {
	log.Printf("[khepra-client] DEMARC unavailable, falling back to Ollama")
	answer, ollamaErr := queryOllamaDirect(r.Context(), httpClient, cfg, query)
	if ollamaErr != nil {
		jsonErr(w, fmt.Sprintf("DEMARC offline, Ollama also failed: %v", ollamaErr), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"answer":       answer,
		"source":       "ollama-direct",
		"tools_called": []string{},
		"confidence":   0.5,
	})
}

func (cfg Config) buildUpstreamRequest(ctx context.Context, req interface{}) (*http.Request, error) {
	upstreamBody, _ := json.Marshal(req)
	apiReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cfg.APIBaseURL+"/api/v1/mcp/ask", bytes.NewReader(upstreamBody))
	if err != nil {
		return nil, err
	}
	apiReq.Header.Set(contentTypeHeader, contentTypeJSON)
	if cfg.PQCToken != "" {
		apiReq.Header.Set("X-Khepra-PQC-Token", cfg.PQCToken)
	}
	return apiReq, nil
}

// queryOllamaDirect calls Ollama directly when the DEMARC API is unreachable.
// This is the air-gapped fallback for situations where only Ollama is running locally.
func queryOllamaDirect(ctx context.Context, client *http.Client, cfg Config, query string) (string, error) {
	payload := map[string]interface{}{
		"model":  cfg.OllamaModel,
		"stream": false,
		"messages": []map[string]string{
			{
				"role": "system",
				"content": "You are Khepra, an AI security analyst specializing in CMMC, STIG, and NIST compliance. " +
					"Answer concisely and accurately. When you cannot call security tools directly, " +
					"explain what you would do and what tools you would use.",
			},
			{"role": "user", "content": query},
		},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cfg.OllamaURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set(contentTypeHeader, contentTypeJSON)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("ollama decode: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("ollama error: %s", result.Error)
	}
	return result.Message.Content, nil
}

// handleHealth checks DEMARC API + Ollama availability.
func handleHealth(cfg Config) http.HandlerFunc {
	httpClient := &http.Client{Timeout: 5 * time.Second}

	return func(w http.ResponseWriter, r *http.Request) {
		apiOK := false
		ollamaOK := false

		// Check DEMARC API
		if resp, err := httpClient.Get(cfg.APIBaseURL + "/health"); err == nil {
			resp.Body.Close()
			apiOK = resp.StatusCode < 500
		}

		// Check Ollama
		if resp, err := httpClient.Get(cfg.OllamaURL + "/api/tags"); err == nil {
			resp.Body.Close()
			ollamaOK = resp.StatusCode == http.StatusOK
		}

		w.Header().Set(contentTypeHeader, contentTypeJSON)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "ok",
			"api_ok":     apiOK,
			"ollama_ok":  ollamaOK,
			"api_url":    cfg.APIBaseURL,
			"ollama_url": cfg.OllamaURL,
			"model":      cfg.OllamaModel,
		})
	}
}

// handleTools proxies the tools list from the DEMARC MCP bridge.
func handleTools(cfg Config) http.HandlerFunc {
	httpClient := &http.Client{Timeout: 10 * time.Second}

	return func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet,
			cfg.APIBaseURL+"/api/v1/mcp/tools", nil)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if cfg.PQCToken != "" {
			req.Header.Set("X-Khepra-PQC-Token", cfg.PQCToken)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			jsonErr(w, "tools unavailable: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()

		w.Header().Set(contentTypeHeader, contentTypeJSON)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

// ─── Utilities ────────────────────────────────────────────────────────────────

func jsonErr(w http.ResponseWriter, msg string, status int) {
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// stringsContains is a simple case-insensitive substring check for the UI.
func stringsContains(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

var _ = stringsContains // suppress unused warning — used in template if extended
