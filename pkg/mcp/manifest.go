package mcp

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ─── Manifest Store & Verifier Interfaces ──────────────────────────────────────

// ManifestStore loads a signed manifest from a backing store (file, embedded, KMS).
type ManifestStore interface {
	LoadSignedManifest(ctx context.Context) (*SignedToolManifest, error)
}

// ManifestVerifier performs PQC cryptographic verification of the manifest signature.
// The production implementation should use pkg/adinkra.VerifySignature.
type ManifestVerifier interface {
	Verify(manifest *SignedToolManifest) error
}

// ─── Manifest Registry ─────────────────────────────────────────────────────────

// ManifestRegistry holds the verified, pinned tool definitions.
// Loaded once at startup — the server refuses to start if verification fails (AD-007).
type ManifestRegistry struct {
	manifest *SignedToolManifest
	byName   map[string]ToolSpec
}

// LoadRegistry loads, validates, and verifies a signed tool manifest.
// This is called once at server startup. If any step fails, the server must not start.
//
// Validation checks (fail-closed):
//  1. Manifest is non-nil with version and revision
//  2. Timestamp is valid and not in the future (5min clock skew tolerance)
//  3. At least one tool is defined
//  4. PQC signature verifies against the pinned public key
//  5. Each tool spec passes structural validation
//  6. No duplicate tool names
func LoadRegistry(ctx context.Context, store ManifestStore, verifier ManifestVerifier) (*ManifestRegistry, error) {
	m, err := store.LoadSignedManifest(ctx)
	if err != nil {
		return nil, fmt.Errorf("mcp/manifest: load signed manifest: %w", err)
	}
	if m == nil {
		return nil, errors.New("mcp/manifest: manifest is nil")
	}

	// Structural validation
	if m.Version == "" || m.Revision == "" {
		return nil, errors.New("mcp/manifest: missing version or revision")
	}
	if m.GeneratedAt.IsZero() || m.GeneratedAt.After(time.Now().Add(5*time.Minute)) {
		return nil, errors.New("mcp/manifest: timestamp invalid or in the future")
	}
	if len(m.Tools) == 0 {
		return nil, errors.New("mcp/manifest: contains no tools — fail-closed")
	}

	// PQC signature verification (AD-007)
	if err := verifier.Verify(m); err != nil {
		return nil, fmt.Errorf("mcp/manifest: PQC signature verification failed: %w", err)
	}

	// Build tool index with dedup + validation
	r := &ManifestRegistry{
		manifest: m,
		byName:   make(map[string]ToolSpec, len(m.Tools)),
	}
	for _, t := range m.Tools {
		if err := validateToolSpec(t); err != nil {
			return nil, fmt.Errorf("mcp/manifest: invalid tool %q: %w", t.Name, err)
		}
		if _, exists := r.byName[t.Name]; exists {
			return nil, fmt.Errorf("mcp/manifest: duplicate tool name: %s", t.Name)
		}
		r.byName[t.Name] = t
	}

	return r, nil
}

// validateToolSpec checks that a tool definition is structurally complete.
func validateToolSpec(t ToolSpec) error {
	if t.Name == "" {
		return errors.New("missing name")
	}
	if t.Description == "" {
		return errors.New("missing description")
	}
	if t.Scope == "" {
		return errors.New("missing scope")
	}
	if t.SchemaVersion == "" {
		return errors.New("missing schema_version")
	}
	if t.SchemaHash == "" {
		return errors.New("missing schema_hash")
	}
	if t.RiskClass != RiskReadOnly && t.RiskClass != RiskSandboxed && t.RiskClass != RiskDestructive {
		return fmt.Errorf("invalid risk class: %s", t.RiskClass)
	}
	if t.TimeoutMs <= 0 {
		return errors.New("timeout_ms must be positive")
	}
	return nil
}

// ─── Registry Queries ──────────────────────────────────────────────────────────

// GetTool returns a registered tool spec by name.
func (r *ManifestRegistry) GetTool(name string) (ToolSpec, bool) {
	t, ok := r.byName[name]
	return t, ok
}

// ListTools returns all registered tool specs.
func (r *ManifestRegistry) ListTools() []ToolSpec {
	out := make([]ToolSpec, 0, len(r.byName))
	for _, t := range r.byName {
		out = append(out, t)
	}
	return out
}

// ToolCount returns the number of registered tools.
func (r *ManifestRegistry) ToolCount() int {
	return len(r.byName)
}

// Version returns the manifest version string.
func (r *ManifestRegistry) Version() string {
	if r.manifest == nil {
		return ""
	}
	return r.manifest.Version
}

// ValidatePinnedSchema checks that a tool call matches the pinned schema version and hash.
// This prevents schema mutation attacks where an attacker modifies tool descriptions
// to trick the LLM into passing different data.
func (r *ManifestRegistry) ValidatePinnedSchema(toolName, schemaVersion, schemaHash string) error {
	t, ok := r.byName[toolName]
	if !ok {
		return fmt.Errorf("mcp/manifest: tool %q not registered", toolName)
	}
	if t.SchemaVersion != schemaVersion {
		return fmt.Errorf("mcp/manifest: schema version mismatch for %q: got %s want %s",
			toolName, schemaVersion, t.SchemaVersion)
	}
	if t.SchemaHash != schemaHash {
		return fmt.Errorf("mcp/manifest: schema hash mismatch for %q", toolName)
	}
	return nil
}
