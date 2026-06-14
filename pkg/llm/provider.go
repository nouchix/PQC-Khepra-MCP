// Package llm provides the LLM provider abstraction for KHEPRA.
//
// Design: Sovereign-first. All external LLM calls are isolated to this package
// and its sub-packages. The core engine (DAG, STIG, ASAF, PQC) operates
// independently of this package and has zero LLM dependency.
package llm

import "context"

// Provider is the interface that all LLM backends implement.
// A Provider takes a user prompt + optional system prompt and returns
// a generated text response.
type Provider interface {
	// Generate calls the underlying LLM with the given prompt and system context.
	// Returns the generated text or an error.
	Generate(prompt, systemPrompt string) (string, error)

	// GenerateStream is the streaming variant — writes chunks to the channel.
	// Callers should range over the channel until it is closed.
	// Cancellable via ctx.
	GenerateStream(ctx context.Context, prompt, systemPrompt string) (<-chan string, error)

	// ModelName returns the identifier of the active model (e.g. "gemma3:12b").
	ModelName() string

	// CheckHealth probes the underlying LLM backend and returns true if it is
	// reachable and ready to serve requests.
	CheckHealth() bool
}
