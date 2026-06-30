package llm

// byok.go — BYOK (Bring Your Own Key) OpenRouter backend.
//
// DetectWithKey probes the OpenRouter API with the caller's key to confirm
// it is valid, then returns a BYOKBackend that routes Chat calls through
// OpenRouter's /v1/chat/completions endpoint.
//
// This is the Path 1.5 (BYOK) path in mcp_handlers.go — activated when the
// caller supplies an X-OpenRouter-Key header. Zero infra required server-side.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	openrouterBase  = "https://openrouter.ai/api/v1"
	byokDefaultModel = "openai/gpt-4o-mini" // cost-effective default for NL queries
)

// BYOKBackend is a lightweight OpenRouter client for caller-supplied API keys.
type BYOKBackend struct {
	Name   string // e.g. "openai/gpt-4o-mini"
	apiKey string
	client *http.Client
}

// DetectWithKey validates the caller-supplied OpenRouter API key and returns a
// ready-to-use BYOKBackend. Returns an error if the key is invalid or
// OpenRouter is unreachable.
func DetectWithKey(ctx context.Context, apiKey string) (*BYOKBackend, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("llm: empty API key")
	}
	// Light validation: list available models (fast, cheap endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		openrouterBase+"/models", nil)
	if err != nil {
		return nil, fmt.Errorf("llm: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("HTTP-Referer", "https://souhimbou.ai")
	req.Header.Set("X-Title", "SouHimBou AI")

	c := &http.Client{Timeout: 8 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("llm: openrouter probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("llm: invalid OpenRouter key")
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("llm: openrouter unavailable (%d)", resp.StatusCode)
	}

	return &BYOKBackend{
		Name:   byokDefaultModel,
		apiKey: apiKey,
		client: c,
	}, nil
}

// Chat calls OpenRouter's /v1/chat/completions with the given system prompt and
// user query. Returns the assistant reply text.
func (b *BYOKBackend) Chat(ctx context.Context, systemPrompt, userQuery string) (string, error) {
	payload := map[string]any{
		"model": b.Name,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userQuery},
		},
		"max_tokens": 600,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		openrouterBase+"/chat/completions",
		bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("llm byok: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("HTTP-Referer", "https://souhimbou.ai")
	req.Header.Set("X-Title", "SouHimBou AI")

	resp, err := b.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("llm byok: request: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("llm byok: openrouter %d: %s", resp.StatusCode, raw)
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("llm byok: parse response: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("llm byok: no choices in response")
	}
	return result.Choices[0].Message.Content, nil
}
