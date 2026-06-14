// Package g0dm0d3 implements the AdinKhepra AI brain layer.
//
// G0DM0D3 provides a pluggable AI provider abstraction with sovereign-first
// design — the primary backend is always local Ollama (zero egress, air-gap
// compatible). External APIs are strictly opt-in via env vars.
//
// Provider priority order:
//   1. Ollama (local, loopback-only — sovereign default, gemma3/phi4)
//   2. Anthropic Claude (BYOK — ANTHROPIC_API_KEY or Khepra license)
//   3. Offline rule-based mode (zero-dependency air-gap fallback)
//
// OpenRouter has been removed. It violated the sovereign boundary by routing
// CUI data through a third-party proxy — incompatible with CMMC Level 2.
//
// Security invariant: ALL external AI API calls are isolated to this package.
// No other package in the codebase may call api.anthropic.com or similar.
// The core engine (DAG, STIG, ASAF, PQC) operates independently.
package g0dm0d3

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/llm/ollama"
)

// ── Package-level constants ─────────────────────────────

const (
	contentTypeJSON    = "application/json"
	headerContentType  = "Content-Type"
	sseDataFmt         = "data: %s\n\n"
	sseDone            = "data: [DONE]\n\n"
)

// ── AI Provider Abstraction ──────────────────────────────

// AIProvider is the pluggable interface for LLM backends
type AIProvider interface {
	Chat(messages []Message, stream bool) (string, error)
	StreamChat(messages []Message, w io.Writer) error
	Name() string
}

// Message is a single chat turn
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ── Provider 1: Anthropic (Claude) ─────────────────────

// AnthropicProvider connects to the Anthropic Messages API
type AnthropicProvider struct {
	APIKey string
	Model  string // Default: "claude-sonnet-4-6"
}

func (p *AnthropicProvider) Name() string { return "Anthropic Claude" }

func (p *AnthropicProvider) Chat(messages []Message, stream bool) (string, error) {
	reqBody := map[string]interface{}{
		"model":      p.Model,
		"max_tokens": 4096,
		"messages":   messages,
		"system": `You are the AdinKhepra AI — a cybersecurity intelligence 
assistant specialized in CMMC, STIG, NIST 800-171, PQC migration, and 
zero-trust architecture. You have direct access to the AdinKhepra ASAF 
engine running on this system. When users ask about their compliance status, 
scan results, or security posture, you answer based on real data from the 
local DAG audit trail. You are concise, technically precise, and DoD-aware.
You never reveal internal API keys or infrastructure details.`,
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequest("POST",
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("AnthropicProvider.Chat: %w", err)
	}
	req.Header.Set("x-api-key", p.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set(headerContentType, contentTypeJSON)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("AnthropicProvider.Chat: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("AnthropicProvider.Chat: %s (HTTP %d)", result.Error.Message, resp.StatusCode)
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("AnthropicProvider.Chat: empty response")
	}
	return result.Content[0].Text, nil
}

func (p *AnthropicProvider) StreamChat(messages []Message, w io.Writer) error {
	reqBody := map[string]interface{}{
		"model":      p.Model,
		"max_tokens": 4096,
		"messages":   messages,
		"stream":     true,
		"system": `You are the AdinKhepra AI — a cybersecurity intelligence 
assistant. Concise, technically precise, DoD-aware.`,
	}
	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST",
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("x-api-key", p.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set(headerContentType, contentTypeJSON)

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("AnthropicProvider.StreamChat: %w", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			processStreamChunk(string(buf[:n]), w)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(w, sseDone)
	return nil
}

// processStreamChunk parses one read-buffer chunk from an Anthropic SSE stream
// and writes any text deltas to w.
func processStreamChunk(chunk string, w io.Writer) {
	for _, line := range strings.Split(chunk, "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		var event map[string]interface{}
		if json.Unmarshal([]byte(data), &event) != nil {
			continue
		}
		delta, ok := event["delta"].(map[string]interface{})
		if !ok {
			continue
		}
		text, ok := delta["text"].(string)
		if !ok {
			continue
		}
		fmt.Fprintf(w, sseDataFmt, text)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
}

// ── Provider 2: Ollama (local, sovereign) ───────────────
//
// OllamaProvider wraps pkg/llm/ollama and satisfies the AIProvider interface.
// It is the sovereign-default LLM backend: loopback-only, zero egress, no API
// key required. Preferred models: gemma3 (fast), phi4 (reasoning).
//
// URL is read from ADINKHEPRA_LLM_URL (default: http://localhost:11434).
// Model is read from ADINKHEPRA_LLM_MODEL (default: gemma3).

const (
	ollamaSystemPrompt = `You are Papyrus — the AdinKhepra AI security intelligence assistant.
You are embedded in the AdinKhepra ASAF (AI Security Action Flight-Recorder) engine.
You specialize in CMMC 2.0, NIST 800-171, STIG, PQC migration, and zero-trust architecture.
You have direct access to the live DAG audit trail injected into every prompt as [SYSTEM CONTEXT].
When asked about compliance status, scan results, or DAG nodes, answer from that live context.
Be concise, technically precise, and DoD-aware. Never reveal internal keys or infrastructure details.
You run fully offline — no data leaves this machine.`
)

// OllamaProvider connects to a local Ollama instance (loopback only).
type OllamaProvider struct {
	client *ollama.Client
	model  string
}

func newOllamaProvider() *OllamaProvider {
	url := os.Getenv("ADINKHEPRA_LLM_URL")
	if url == "" {
		url = "http://localhost:11434"
	}
	model := os.Getenv("ADINKHEPRA_LLM_MODEL")
	if model == "" {
		// Auto-discover the best available model from the running Ollama instance.
		// Preference: gemma3:4b (fast, 3.3GB) > phi4:latest (9.1GB) > gemma3 (alias)
		model = discoverOllamaModel(url)
	}
	return &OllamaProvider{
		client: ollama.NewClient(url, model, ""),
		model:  model,
	}
}

// discoverOllamaModel delegates to the canonical implementation in pkg/llm/ollama.
func discoverOllamaModel(baseURL string) string {
	return ollama.DiscoverModel(baseURL)
}

func (p *OllamaProvider) Name() string { return "Ollama (" + p.model + ", local)" }

func (p *OllamaProvider) Chat(messages []Message, _ bool) (string, error) {
	// Flatten conversation history into a single prompt for Ollama /api/generate.
	// Ollama chat API (/api/chat) is preferred for multi-turn — use /api/generate
	// with explicit role prefixes as the compatibility path.
	var sb strings.Builder
	for _, m := range messages {
		switch m.Role {
		case "user":
			sb.WriteString("User: ")
		case "assistant":
			sb.WriteString("Assistant: ")
		default:
			sb.WriteString(m.Role)
			sb.WriteString(": ")
		}
		sb.WriteString(m.Content)
		sb.WriteString("\n")
	}
	sb.WriteString("Assistant:")

	resp, err := p.client.Generate(sb.String(), ollamaSystemPrompt)
	if err != nil {
		return "", fmt.Errorf("OllamaProvider.Chat: %w", err)
	}
	return strings.TrimSpace(resp), nil
}

func (p *OllamaProvider) StreamChat(messages []Message, w io.Writer) error {
	resp, err := p.Chat(messages, false)
	if err != nil {
		return err
	}
	// Emit as a single SSE event — streaming word-by-word requires Ollama /api/chat
	// with stream:true, which is a future enhancement.
	fmt.Fprintf(w, sseDataFmt, resp)
	fmt.Fprintf(w, sseDone)
	return nil
}

// ── Provider 3: Offline (No LLM, rule-based) ────────────

// OfflineProvider provides basic rule-based responses without any AI backend
type OfflineProvider struct{}

func (p *OfflineProvider) Name() string { return "Offline (Rule-Based)" }

func (p *OfflineProvider) Chat(messages []Message, stream bool) (string, error) {
	if len(messages) == 0 {
		return "AdinKhepra running in offline mode. No AI provider configured.", nil
	}
	last := strings.ToLower(messages[len(messages)-1].Content)

	switch {
	case strings.Contains(last, "stig") || strings.Contains(last, "scan"):
		return "Run `adinkhepra scan` to start a full STIG assessment. Results will appear in the DAG viewer at /api/dag/nodes.", nil
	case strings.Contains(last, "watch") || strings.Contains(last, "asaf"):
		return "Run `adinkhepra watch` to start the ASAF wrapper. It will record all AI agent activity to the tamper-proof DAG.", nil
	case strings.Contains(last, "license"):
		return "Check your license status with `adinkhepra license status`. Enterprise licenses include AI API budget.", nil
	case strings.Contains(last, "pqc") || strings.Contains(last, "quantum"):
		return "AdinKhepra uses Dilithium3 (FIPS 204) for signing and Kyber-1024 (FIPS 203) for key exchange. Run `adinkhepra scan` for a PQC inventory.", nil
	case strings.Contains(last, "help"):
		return "Commands: scan, watch, report, serve, harden, license, keygen. Run `adinkhepra --help` for full usage.", nil
	case strings.Contains(last, "dag") || strings.Contains(last, "audit"):
		return "The DAG is your flight recorder — every action is content-addressed (SHA-256), Dilithium3-signed, and AES-256-GCM encrypted at rest. View it at http://localhost:45444/api/dag/nodes", nil
	default:
		return "I'm running in air-gap offline mode. Start Ollama locally (`ollama serve`) for full AI capabilities — no external API key required. Or set ANTHROPIC_API_KEY for Claude (BYOK). In offline mode I can guide you through AdinKhepra commands.", nil
	}
}

func (p *OfflineProvider) StreamChat(messages []Message, w io.Writer) error {
	resp, _ := p.Chat(messages, false)
	fmt.Fprintf(w, sseDataFmt, resp)
	fmt.Fprintf(w, sseDone)
	return nil
}

// ── Factory: Sovereign-first provider selection ─────────

// NewBestAvailableProvider returns the highest-priority available AI backend.
// This function NEVER returns an error — offline mode is always the fallback.
//
// Selection order (sovereign-first):
//  1. Ollama local — zero egress, no key, works air-gapped (requires `ollama serve`)
//  2. Anthropic Claude — BYOK, external call isolated to this package
//  3. Offline rule-based — absolute fallback, zero dependencies
func NewBestAvailableProvider() AIProvider {
	// Priority 1: Ollama (local, loopback-only — sovereign default)
	// Probe the health endpoint; if Ollama is running, use it.
	ollp := newOllamaProvider()
	if ollp.client.CheckHealth() {
		return ollp
	}

	// Priority 2: Anthropic Claude (BYOK — from env or Khepra license)
	if key := getAnthropicKey(); key != "" {
		return &AnthropicProvider{
			APIKey: key,
			Model:  "claude-sonnet-4-6",
		}
	}

	// Priority 3: Offline — always works, zero dependencies, zero egress
	return &OfflineProvider{}
}

// getAnthropicKey checks env, then license file, then ~/.khepra/keys/
func getAnthropicKey() string {
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		return key
	}
	if key := loadKeyFromLicense("anthropic_api_key"); key != "" {
		return key
	}
	return ""
}

func loadKeyFromLicense(field string) string {
	home, _ := os.UserHomeDir()
	data, err := os.ReadFile(home + "/.khepra/license_claims.json")
	if err != nil {
		return ""
	}
	var claims map[string]string
	if err := json.Unmarshal(data, &claims); err != nil {
		return ""
	}
	return claims[field]
}

// ── G0DM0D3 Server: HTTP Handler ─────────────────────────

// G0DM0D3Server is the local AI brain HTTP handler
type G0DM0D3Server struct {
	Provider AIProvider
	DAG      *dag.PersistentMemory // Live DAG for system context

	mu      sync.Mutex
	History []Message        // In-memory session history
	tools   map[string]Tool  // KHEPRA native tool panel (keyed by tool name)
}

// NewServer creates a G0DM0D3 server with the best available AI provider
func NewServer(dagStore *dag.PersistentMemory) *G0DM0D3Server {
	return &G0DM0D3Server{
		Provider: NewBestAvailableProvider(),
		DAG:      dagStore,
		History:  make([]Message, 0),
	}
}

// HandleChat is the HTTP handler for /api/g0dm0d3/chat
//
// Accepts POST with body: {"message":"...","stream":false}
// Returns 405 on GET with usage hint (audit fix: was silently routing to provider).
func (s *G0DM0D3Server) HandleChat(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", headerContentType)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Audit fix: GET hits were silently routed to the LLM and returned empty errors.
	// Return a clear 405 with usage instructions instead.
	if r.Method != "POST" {
		w.Header().Set(headerContentType, contentTypeJSON)
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"error":    "method not allowed — use POST",
			"usage":    `POST /api/g0dm0d3/chat`,
			"body":     `{"message":"your question here","stream":false}`,
			"provider": s.Provider.Name(),
		})
		return
	}

	var req struct {
		Message string `json:"message"`
		Stream  bool   `json:"stream"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	// Inject live system context
	systemContext := s.getSystemContext()
	userMsg := Message{Role: "user", Content: systemContext + req.Message}

	s.mu.Lock()
	s.History = append(s.History, userMsg)
	history := make([]Message, len(s.History))
	copy(history, s.History)
	s.mu.Unlock()

	if req.Stream {
		w.Header().Set(headerContentType, "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		if err := s.Provider.StreamChat(history, w); err != nil {
			fmt.Fprintf(w, "data: [ERROR] %s\n\n", err.Error())
		}
		return
	}

	resp, err := s.Provider.Chat(history, false)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Auto-execute any [TOOL:xxx] directives the AI embedded in its response.
	resp = s.executeToolDirectives(resp)

	s.mu.Lock()
	s.History = append(s.History, Message{Role: "assistant", Content: resp})
	s.mu.Unlock()

	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"response": resp,
		"provider": s.Provider.Name(),
	})
}

// HandleStatus returns the current AI provider status
func (s *G0DM0D3Server) HandleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerContentType, contentTypeJSON)
	w.Header().Set("Access-Control-Allow-Origin", "*")

	dagNodeCount := 0
	if s.DAG != nil {
		dagNodeCount = len(s.DAG.All())
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"provider":  s.Provider.Name(),
		"status":    "active",
		"dag_nodes": dagNodeCount,
		"version":   "1.0",
		"engine":    "G0DM0D3",
	})
}

// getSystemContext pulls live data from the DAG to inject into the AI prompt.
// This makes G0DM0D3 a contextually-aware agent — not a static chatbot.
func (s *G0DM0D3Server) getSystemContext() string {
	if s.DAG == nil {
		return "[SYSTEM: AdinKhepra ASAF Engine — no DAG connected]\n\nUser query: "
	}

	allNodes := s.DAG.All()
	nodeCount := len(allNodes)

	// Gather recent node summary (last 5 actions)
	recentSummary := ""
	start := nodeCount - 5
	if start < 0 {
		start = 0
	}
	for _, n := range allNodes[start:] {
		recentSummary += fmt.Sprintf("  - %s: %s [%s]\n", n.Time, n.Action, n.Symbol)
	}

	// Count ASAF sessions
	asafSessions := 0
	for _, n := range allNodes {
		if strings.HasPrefix(n.Action, "ASAF_SESSION_START") {
			asafSessions++
		}
	}

	return fmt.Sprintf(`[SYSTEM CONTEXT — LIVE DATA]
AdinKhepra ASAF Engine active.
DAG nodes: %d | ASAF sessions recorded: %d
Recent activity:
%s
[END SYSTEM CONTEXT]

User query: `, nodeCount, asafSessions, recentSummary)
}
