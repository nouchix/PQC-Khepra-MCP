// Package mcp — per-invocation ephemeral credentials.
//
// ASD/CISA "Careful Adoption of Agentic AI Services" requires that agentic AI
// services not accumulate long-lived credentials. Each tool invocation receives
// a short-lived (5-minute TTL), HMAC-signed capability token that encodes:
//   - Which scan profile is permitted
//   - Which target is permitted
//   - Which calling agent identity is bound
//   - Expiry time
//
// The ML-DSA-65 license key is the root of trust; invocation tokens are derived
// from it via HMAC-SHA256. This prevents credential reuse across sessions and
// contains blast radius if a token is leaked.
//
// Token flow:
//   Router.HandleToolCall → IssueInvocationToken → attach to MCPToolCall
//   → Executor.Execute   → VerifyInvocationToken (token must not be expired
//                           and must match the tool being executed)

package mcp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	// InvocationTokenTTL is the maximum lifetime of a per-invocation token.
	// 5 minutes: enough for any single scan to complete; too short for reuse.
	InvocationTokenTTL = 5 * time.Minute
)

// InvocationToken is a short-lived, HMAC-signed capability token issued
// per tool invocation. Implements ASD/CISA ephemeral credential requirement.
type InvocationToken struct {
	TokenID   string    `json:"token_id"`   // UUID, unique per invocation
	AgentID   string    `json:"agent_id"`   // Bound calling agent identity
	ToolName  string    `json:"tool_name"`  // Permitted tool (must match invocation)
	Profile   string    `json:"profile"`    // Permitted scan profile (may be "")
	Target    string    `json:"target"`     // Permitted target (may be "")
	IssuedAt  time.Time `json:"issued_at"`  // Issue timestamp (UTC)
	ExpiresAt time.Time `json:"expires_at"` // IssuedAt + InvocationTokenTTL
	HMAC      string    `json:"hmac"`       // HMAC-SHA256(rootKey, canonical payload)
}

// canonical returns the deterministic payload bytes for HMAC computation.
// The HMAC field itself is excluded from the canonical form.
func (t InvocationToken) canonical() ([]byte, error) {
	payload := struct {
		TokenID   string `json:"token_id"`
		AgentID   string `json:"agent_id"`
		ToolName  string `json:"tool_name"`
		Profile   string `json:"profile"`
		Target    string `json:"target"`
		IssuedAt  string `json:"issued_at"`
		ExpiresAt string `json:"expires_at"`
	}{
		TokenID:   t.TokenID,
		AgentID:   t.AgentID,
		ToolName:  t.ToolName,
		Profile:   t.Profile,
		Target:    t.Target,
		IssuedAt:  t.IssuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt: t.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	return json.Marshal(payload)
}

// IssueInvocationToken mints a new per-invocation token.
// rootKey is derived from the ML-DSA-65 license key (caller responsibility).
// For stdio sessions with no specific profile/target, pass empty strings.
func IssueInvocationToken(rootKey []byte, agentID, toolName, profile, target string) (*InvocationToken, error) {
	if len(rootKey) == 0 {
		return nil, fmt.Errorf("invocation_token: rootKey is required")
	}
	if agentID == "" {
		return nil, fmt.Errorf("invocation_token: agentID is required")
	}
	if toolName == "" {
		return nil, fmt.Errorf("invocation_token: toolName is required")
	}

	now := time.Now().UTC()
	tok := &InvocationToken{
		TokenID:   uuid.New().String(),
		AgentID:   agentID,
		ToolName:  toolName,
		Profile:   profile,
		Target:    target,
		IssuedAt:  now,
		ExpiresAt: now.Add(InvocationTokenTTL),
	}

	canonical, err := tok.canonical()
	if err != nil {
		return nil, fmt.Errorf("invocation_token: canonicalize: %w", err)
	}

	mac := hmac.New(sha256.New, rootKey)
	mac.Write(canonical)
	tok.HMAC = hex.EncodeToString(mac.Sum(nil))

	return tok, nil
}

// VerifyInvocationToken validates a token against the root key and the
// tool being invoked. Returns an error if:
//   - The HMAC is invalid (tampering detected)
//   - The token has expired (TTL exceeded)
//   - The token's ToolName does not match actualToolName (wrong tool)
//   - The token's AgentID does not match the caller identity
func VerifyInvocationToken(rootKey []byte, tok *InvocationToken, actualToolName, actualAgentID string) error {
	if tok == nil {
		return fmt.Errorf("invocation_token: nil token")
	}

	// Recompute HMAC
	canonical, err := tok.canonical()
	if err != nil {
		return fmt.Errorf("invocation_token: canonicalize for verify: %w", err)
	}
	mac := hmac.New(sha256.New, rootKey)
	mac.Write(canonical)
	expected := hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison (timing-safe)
	tokHMAC, err := hex.DecodeString(tok.HMAC)
	if err != nil {
		return fmt.Errorf("invocation_token: invalid HMAC encoding")
	}
	expectedBytes, _ := hex.DecodeString(expected)
	if !hmac.Equal(tokHMAC, expectedBytes) {
		return fmt.Errorf("invocation_token: HMAC verification failed — token may have been tampered with")
	}

	// Expiry check
	if time.Now().UTC().After(tok.ExpiresAt) {
		return fmt.Errorf("invocation_token: token expired at %s (TTL: %s)",
			tok.ExpiresAt.Format(time.RFC3339), InvocationTokenTTL)
	}

	// Tool binding check
	if tok.ToolName != actualToolName {
		return fmt.Errorf("invocation_token: token bound to tool %q cannot be used for %q — reuse rejected",
			tok.ToolName, actualToolName)
	}

	// Agent identity binding check
	if tok.AgentID != actualAgentID {
		return fmt.Errorf("invocation_token: token bound to agent %q cannot be used by %q",
			tok.AgentID, actualAgentID)
	}

	return nil
}

// DeriveRootKey derives the HMAC root key from the ML-DSA-65 license key.
// Uses HMAC-SHA256(licenseKey, "khepra-invocation-token-v1") as the domain separator.
// This ensures the invocation token key is distinct from the signing key
// even if they share the same material.
func DeriveRootKey(licenseKey []byte) []byte {
	const domain = "khepra-invocation-token-v1"
	mac := hmac.New(sha256.New, licenseKey)
	mac.Write([]byte(domain))
	return mac.Sum(nil)
}
