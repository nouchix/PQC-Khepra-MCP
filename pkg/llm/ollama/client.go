// Package ollama implements the llm.Provider interface backed by a local
// Ollama inference server (loopback-only, sovereign-default).
//
// Ollama is the primary AI backend for KHEPRA — it runs locally, requires
// zero egress, and is air-gap compatible. It satisfies the sovereign boundary
// required for CMMC Level 2 / CUI workloads.
//
// # Quick Start
//
//	client := ollama.NewClient("http://localhost:11434", "gemma3:12b", "")
//	response, err := client.Generate("Explain ML-KEM-768", "")
//
// # Model Discovery
//
//	model, err := ollama.DiscoverModel("http://localhost:11434")
package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is an Ollama HTTP client implementing llm.Provider.
type Client struct {
	baseURL    string
	model      string
	apiKey     string // unused for local Ollama; reserved for future auth
	httpClient *http.Client
}

// NewClient creates a new Ollama client.
//   - baseURL: Ollama server URL (default: "http://localhost:11434")
//   - model:   Model identifier (e.g. "gemma3:12b", "phi4:latest")
//   - apiKey:  Reserved for future bearer auth; pass "" for local Ollama
func NewClient(baseURL, model, apiKey string) *Client {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	if model == "" {
		model = "gemma3:12b"
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

// ModelName returns the configured Ollama model identifier.
func (c *Client) ModelName() string { return c.model }

// Generate sends prompt + systemPrompt to Ollama and returns the full response.
func (c *Client) Generate(prompt, systemPrompt string) (string, error) {
	return c.generate(context.Background(), prompt, systemPrompt)
}

// GenerateStream sends prompt + systemPrompt to Ollama and streams token chunks.
func (c *Client) GenerateStream(ctx context.Context, prompt, systemPrompt string) (<-chan string, error) {
	ch := make(chan string, 64)
	go func() {
		defer close(ch)
		body, err := json.Marshal(map[string]any{
			"model":  c.model,
			"prompt": prompt,
			"system": systemPrompt,
			"stream": true,
		})
		if err != nil {
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/generate", bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		dec := json.NewDecoder(resp.Body)
		for {
			var chunk struct {
				Response string `json:"response"`
				Done     bool   `json:"done"`
			}
			if err := dec.Decode(&chunk); err != nil {
				return
			}
			if chunk.Response != "" {
				select {
				case ch <- chunk.Response:
				case <-ctx.Done():
					return
				}
			}
			if chunk.Done {
				return
			}
		}
	}()
	return ch, nil
}

func (c *Client) generate(ctx context.Context, prompt, systemPrompt string) (string, error) {
	body, err := json.Marshal(map[string]any{
		"model":  c.model,
		"prompt": prompt,
		"system": systemPrompt,
		"stream": false,
	})
	if err != nil {
		return "", fmt.Errorf("ollama: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("ollama: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama: HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("ollama: decode response: %w", err)
	}
	return result.Response, nil
}

// DiscoverModel queries the Ollama server for available models and returns
// the first available model name. Falls back to "gemma3:12b" if none found or
// if the server is unreachable.
func DiscoverModel(baseURL string) string {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(strings.TrimRight(baseURL, "/") + "/api/tags")
	if err != nil {
		return "gemma3:12b"
	}
	defer resp.Body.Close()
	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || len(result.Models) == 0 {
		return "gemma3:12b"
	}
	return result.Models[0].Name
}

// CheckHealth probes the Ollama server and returns true if it is reachable.
func (c *Client) CheckHealth() bool {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, c.baseURL+"/api/tags", nil)
	if err != nil {
		return false
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
