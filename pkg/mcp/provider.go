// Package mcp — provider.go
//
// Open-core provider hook. A build can add tools that this public repository
// does not contain: a private module registers a ToolProvider from an init
// function, and the server installs every registered provider at startup
// (InstallProviders) — the specs go into the tool registry, the handlers into
// the executor, and each tool's maturity into tools/list. Public builds
// register no providers, so they list only the community tools.
//
// Provided tools are compiled into the binary, so they carry the binary's
// trust; they are not part of the signed release manifest. A provider may not
// shadow a manifest tool or another provider's tool.
//
// IP: SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.
package mcp

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
)

// ProvidedTool is one tool a provider adds.
type ProvidedTool struct {
	Spec     ToolSpec
	Handler  func(ctx context.Context, call MCPToolCall) (any, []string, error)
	Maturity ToolMaturity // published in tools/list like the built-in tools
}

// ToolProvider supplies tools from outside this repository.
type ToolProvider interface {
	Name() string
	Tools() []ProvidedTool
}

var (
	providersMu      sync.RWMutex
	providers        = map[string]ToolProvider{}
	providedMaturity = map[string]ToolMaturity{}
)

// RegisterProvider makes p available to InstallProviders. Call it from an
// init function. It panics on a nil provider or a duplicate name.
func RegisterProvider(p ToolProvider) {
	if p == nil || p.Name() == "" {
		panic("mcp: RegisterProvider: nil or unnamed provider")
	}
	providersMu.Lock()
	defer providersMu.Unlock()
	if _, dup := providers[p.Name()]; dup {
		panic("mcp: RegisterProvider: duplicate provider " + p.Name())
	}
	providers[p.Name()] = p
}

// RegisteredProviders returns the registered providers, sorted by name.
func RegisteredProviders() []ToolProvider {
	providersMu.RLock()
	defer providersMu.RUnlock()
	out := make([]ToolProvider, 0, len(providers))
	for _, p := range providers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// InstallProviders adds every registered provider's tools to reg and exec.
// It returns the number of tools installed.
func InstallProviders(reg *ManifestRegistry, exec *Executor, logger *log.Logger) (int, error) {
	n := 0
	for _, p := range RegisteredProviders() {
		for _, t := range p.Tools() {
			if t.Handler == nil {
				return n, fmt.Errorf("mcp: provider %s: tool %q has no handler", p.Name(), t.Spec.Name)
			}
			spec := t.Spec
			meta := make(map[string]any, len(spec.Meta)+1)
			for k, v := range spec.Meta {
				meta[k] = v
			}
			meta["provider"] = p.Name()
			spec.Meta = meta
			if err := reg.RegisterProvided(spec); err != nil {
				return n, fmt.Errorf("mcp: provider %s: %w", p.Name(), err)
			}
			exec.RegisterFunc(spec.Name, t.Handler)
			if t.Maturity.Status != "" {
				providersMu.Lock()
				providedMaturity[spec.Name] = t.Maturity
				providersMu.Unlock()
			}
			n++
		}
		if logger != nil {
			logger.Printf("[PROVIDER] %s installed", p.Name())
		}
	}
	return n, nil
}

// RegisterProvided adds a tool compiled into this binary by a ToolProvider.
// It may not shadow any tool already registered.
func (r *ManifestRegistry) RegisterProvided(spec ToolSpec) error {
	if err := validateToolSpec(spec); err != nil {
		return fmt.Errorf("provided tool %q: %w", spec.Name, err)
	}
	if _, exists := r.byName[spec.Name]; exists {
		return fmt.Errorf("provided tool %q would shadow an existing tool — refused", spec.Name)
	}
	r.byName[spec.Name] = spec
	return nil
}

// providedMaturityOf returns the maturity a provider declared for name.
func providedMaturityOf(name string) (ToolMaturity, bool) {
	providersMu.RLock()
	defer providersMu.RUnlock()
	m, ok := providedMaturity[name]
	return m, ok
}
