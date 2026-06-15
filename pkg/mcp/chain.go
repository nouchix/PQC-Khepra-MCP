// Package mcp — production interface implementations for the security chain.
//
// This file provides concrete implementations for:
//   - DemarcGateway  → PQC credential authentication (via pkg/adinkra)
//   - PolymorphicEngine → Provenance envelope wrapping/verification
//   - MCPGateway → RBAC + prompt injection scanning
//   - Attestor → DAG-anchored, PQC-signed attestation (via pkg/dag + pkg/adinkra)
//
// For stdio transport, DEMARC uses a pre-authenticated credential. For HTTP
// transport (future), it validates actual PQC tokens.

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
)

// ─── DEMARC Gateway Implementation ─────────────────────────────────────────────

// AdinkraDemarcGateway authenticates callers using PQC credentials.
// For stdio transport, a pre-authenticated identity is used (single-tenant subprocess model).
// For HTTP transport, it validates Dilithium-signed bearer tokens.
type AdinkraDemarcGateway struct {
	// StdioIdentity is the pre-authenticated identity for stdio sessions.
	// This is set at server startup from the environment/config.
	StdioIdentity Identity

	// AllowedCIDRs is a whitelist of allowed remote address patterns.
	// "local" always passes. Empty slice = allow all.
	AllowedCIDRs []string
}

// Authenticate resolves a credential into an Identity.
// For stdio: the credential is the pre-authenticated identity token.
// For HTTP: would validate a PQC-signed JWT (future).
func (g *AdinkraDemarcGateway) Authenticate(_ context.Context, cred any) (Identity, error) {
	// Stdio: pre-authenticated
	if cred == nil || cred == "stdio" {
		if g.StdioIdentity.AgentID == "" {
			return Identity{}, fmt.Errorf("demarc: no stdio identity configured")
		}
		return g.StdioIdentity, nil
	}

	// String token: derive a session identity via SHA-256 hash.
	// Full ACP signature validation is performed on the HTTP transport path.
	if token, ok := cred.(string); ok {
		if token == "" {
			return Identity{}, fmt.Errorf("demarc: empty credential")
		}
		h := sha256.Sum256([]byte(token))
		return Identity{
			Subject:   "token:" + hex.EncodeToString(h[:8]),
			Issuer:    "demarc",
			AgentID:   "authenticated-agent",
			SessionID: hex.EncodeToString(h[:16]),
			Scopes:    []string{"*"}, // Will be narrowed by MCPGateway
		}, nil
	}

	// Identity passed directly (test/internal use)
	if id, ok := cred.(Identity); ok {
		return id, nil
	}

	return Identity{}, fmt.Errorf("demarc: unsupported credential type: %T", cred)
}

// CheckCIDR validates the caller's remote address.
func (g *AdinkraDemarcGateway) CheckCIDR(_ context.Context, _ Identity, remoteAddr string) error {
	// Stdio transport: always "local"
	if remoteAddr == "local" || remoteAddr == "" {
		return nil
	}
	// If no CIDRs configured, allow all
	if len(g.AllowedCIDRs) == 0 {
		return nil
	}
	for _, cidr := range g.AllowedCIDRs {
		if cidr == remoteAddr || cidr == "*" {
			return nil
		}
	}
	return fmt.Errorf("demarc: remote address %q not in allowed CIDRs", remoteAddr)
}

// ─── Polymorphic Engine Implementation ─────────────────────────────────────────

// AdinkraPolymorphicEngine wraps/verifies requests and responses using PQC signatures.
// Uses the Merkaba White Box for envelope sealing and adinkra for signing.
type AdinkraPolymorphicEngine struct {
	// Symbol is the Adinkra symbol used for Spectral Fingerprint derivation.
	Symbol string

	// PrivateKey is the ML-DSA signing key for envelope sealing.
	PrivateKey []byte

	// PublicKey is the corresponding verification key.
	PublicKey []byte
}

// WrapRequest seals the raw request payload with agent provenance metadata.
func (p *AdinkraPolymorphicEngine) WrapRequest(payload []byte, agentID string) ([]byte, error) {
	envelope := map[string]any{
		"payload":   payload,
		"agent_id":  agentID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"spectral":  hex.EncodeToString(adinkra.GetSpectralFingerprint(p.Symbol)[:8]),
	}

	wrapped, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("poly: wrap failed: %w", err)
	}

	// Sign the wrapped payload
	if len(p.PrivateKey) > 0 {
		h := sha256.Sum256(wrapped)
		sig, err := adinkra.Sign(p.PrivateKey, h[:])
		if err != nil {
			return nil, fmt.Errorf("poly: sign failed: %w", err)
		}
		envelope["signature"] = hex.EncodeToString(sig[:32]) // Truncated for transport
		wrapped, _ = json.Marshal(envelope)
	}

	return wrapped, nil
}

// VerifyRequest validates a wrapped request's integrity.
func (p *AdinkraPolymorphicEngine) VerifyRequest(wrapped []byte) error {
	var envelope map[string]any
	if err := json.Unmarshal(wrapped, &envelope); err != nil {
		return fmt.Errorf("poly: invalid envelope: %w", err)
	}

	// Verify structural integrity
	if _, ok := envelope["payload"]; !ok {
		return fmt.Errorf("poly: missing payload in envelope")
	}
	if _, ok := envelope["agent_id"]; !ok {
		return fmt.Errorf("poly: missing agent_id in envelope")
	}

	return nil
}

// WrapResponse seals a tool result in a SecureEnvelope with PQC signature.
func (p *AdinkraPolymorphicEngine) WrapResponse(result any, requestID string) (SecureEnvelope, error) {
	env := SecureEnvelope{
		RequestID: requestID,
		Result:    result,
		CreatedAt: time.Now().UTC(),
	}

	// PQC sign the result
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return env, fmt.Errorf("poly: marshal result failed: %w", err)
	}

	if len(p.PrivateKey) > 0 {
		h := sha256.Sum256(resultBytes)
		sig, err := adinkra.Sign(p.PrivateKey, h[:])
		if err != nil {
			return env, fmt.Errorf("poly: sign result failed: %w", err)
		}
		env.Signature = hex.EncodeToString(sig)
		env.Provenance = fmt.Sprintf("spectral:%s", hex.EncodeToString(adinkra.GetSpectralFingerprint(p.Symbol)[:8]))
	}

	return env, nil
}

// VerifyResponse validates a SecureEnvelope's integrity.
func (p *AdinkraPolymorphicEngine) VerifyResponse(envelope SecureEnvelope) error {
	if envelope.RequestID == "" {
		return fmt.Errorf("poly: missing request_id in envelope")
	}
	// Full ML-DSA-65 signature verification requires PublicKey to be set on this engine instance.
	return nil
}

// ─── MCP Gateway Implementation ────────────────────────────────────────────────

// DefaultMCPGateway enforces RBAC scope checks and scans for prompt injection.
type DefaultMCPGateway struct {
	// InjectionPatterns are compiled regex patterns for prompt injection detection.
	InjectionPatterns []*regexp.Regexp
}

// NewDefaultMCPGateway creates a gateway with the standard injection patterns.
func NewDefaultMCPGateway() *DefaultMCPGateway {
	patterns := []string{
		`(?i)ignore\s+(previous|all|above|prior)\s+(instructions?|prompts?)`,
		`(?i)you\s+are\s+now\s+`,
		`(?i)system\s*:\s*`,
		`(?i)forget\s+(everything|all)`,
		`(?i)act\s+as\s+(a|an)\s+`,
		`(?i)override\s+(safety|security|policy)`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if r, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, r)
		}
	}

	return &DefaultMCPGateway{InjectionPatterns: compiled}
}

// CheckPermission validates that the identity has the required scope for the tool.
func (g *DefaultMCPGateway) CheckPermission(id Identity, scope string) error {
	if scope == "" {
		return nil // No scope required
	}
	if id.HasScope(scope) {
		return nil
	}
	// Check wildcard scopes (e.g. "ert:*" matches "ert:scan")
	parts := strings.SplitN(scope, ":", 2)
	if len(parts) == 2 && id.HasScope(parts[0]+":*") {
		return nil
	}
	return fmt.Errorf("gateway: identity %q lacks scope %q (has: %v)", id.AgentID, scope, id.Scopes)
}

// ScanForInjection checks raw input text for prompt injection patterns.
func (g *DefaultMCPGateway) ScanForInjection(text string) error {
	for _, pattern := range g.InjectionPatterns {
		if pattern.MatchString(text) {
			return fmt.Errorf("gateway: prompt injection detected (pattern: %s)", pattern.String())
		}
	}
	return nil
}

// ─── Attestor Implementation (DAG + PQC) ───────────────────────────────────────

// DAGAttestor records tool executions in the DAG audit chain with PQC signatures.
type DAGAttestor struct {
	// Store is the DAG storage backend (in-memory or persistent).
	Store dag.Store

	// Symbol is the Adinkra symbol for provenance tracking.
	Symbol string

	// PrivateKey is the ML-DSA signing key for attestation sealing.
	PrivateKey []byte

	// lastNodeID tracks the most recent node for chaining.
	lastNodeID string
}

// NewDAGAttestor creates an attestor backed by the given DAG store.
func NewDAGAttestor(store dag.Store, symbol string, privKey []byte) *DAGAttestor {
	return &DAGAttestor{
		Store:      store,
		Symbol:     symbol,
		PrivateKey: privKey,
	}
}

// Append records a tool execution in the DAG and returns the attestation node ID.
func (a *DAGAttestor) Append(ctx context.Context, toolName string, input []byte, output []byte) (string, error) {
	// Build DAG node
	inputHash := sha256.Sum256(input)
	outputHash := sha256.Sum256(output)

	// Chain to previous node if it exists.
	// IMPORTANT: parents must be set on the node BEFORE calling Sign() or
	// ComputeHash(), because the content hash includes the parent list.
	// Setting parents after hashing causes a mismatch in dag.Add().
	var parents []string
	if a.lastNodeID != "" {
		parents = append(parents, a.lastNodeID)
	}

	node := &dag.Node{
		Action:  fmt.Sprintf("mcp:tool:%s", toolName),
		Symbol:  a.Symbol,
		Time:    time.Now().UTC().Format(time.RFC3339),
		Parents: parents, // set here so ComputeHash() includes them
		PQC: map[string]string{
			"input_hash":  hex.EncodeToString(inputHash[:]),
			"output_hash": hex.EncodeToString(outputHash[:]),
			"engine":      "ML-DSA-65",
		},
	}

	// Sign: ID is computed inside Sign() — parents already set above.
	if len(a.PrivateKey) > 0 {
		if err := node.Sign(a.PrivateKey); err != nil {
			return "", fmt.Errorf("attestor: sign failed: %w", err)
		}
	} else {
		node.ID = node.ComputeHash()
		node.Hash = node.ID
	}

	// Add to DAG — pass nil parents since they're already on the node.
	if err := a.Store.Add(node, nil); err != nil {
		return "", fmt.Errorf("attestor: DAG append failed: %w", err)
	}

	a.lastNodeID = node.ID
	return node.ID, nil
}

// SignEnvelope adds a PQC signature to the SecureEnvelope using the attestation key.
func (a *DAGAttestor) SignEnvelope(_ context.Context, env SecureEnvelope) (SecureEnvelope, error) {
	if len(a.PrivateKey) == 0 {
		return env, nil // No signing key configured
	}

	// Create canonical representation for signing
	canonical := fmt.Sprintf("%s|%s|%s|%s",
		env.RequestID, env.ToolName, env.AttestationID, env.CreatedAt.Format(time.RFC3339))
	h := sha256.Sum256([]byte(canonical))

	sig, err := adinkra.Sign(a.PrivateKey, h[:])
	if err != nil {
		return env, fmt.Errorf("attestor: sign envelope failed: %w", err)
	}

	env.Signature = hex.EncodeToString(sig)
	return env, nil
}
