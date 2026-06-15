// Package tools contains MCP tool implementations for the Khepra Protocol.
//
// Each tool wraps an existing package capability and exposes it through
// the MCP tool interface. Tools are registered with the Executor and
// dispatched by the Router according to their risk classification.
package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/acp"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
)

// ─── acp_status (Read-Only) ────────────────────────────────────────────────────
//
// Returns the current state of the Agent Control Plane: active credentials,
// audit chain hash, and credential expiry warnings. This is a pure read-only
// tool with no side effects.

// ACPStatusTool wraps pkg/acp.AgentControlPlane for MCP exposure.
type ACPStatusTool struct {
	controlPlane *acp.AgentControlPlane
}

// NewACPStatusTool creates an acp_status tool backed by the given control plane.
func NewACPStatusTool(cp *acp.AgentControlPlane) *ACPStatusTool {
	return &ACPStatusTool{controlPlane: cp}
}

// ACPStatusResponse is the structured output of the acp_status tool.
type ACPStatusResponse struct {
	ActiveCredentials int                      `json:"active_credentials"`
	Credentials       []ACPCredentialSummary   `json:"credentials"`
	AuditChainHash    string                   `json:"audit_chain_hash"`
	ExpiryWarnings    []string                 `json:"expiry_warnings,omitempty"`
	Timestamp         string                   `json:"timestamp"`
}

// ACPCredentialSummary is a safe projection of an AgentCredential (no private keys).
type ACPCredentialSummary struct {
	ID              string   `json:"id"`
	AgentID         string   `json:"agent_id"`
	Symbol          string   `json:"symbol"`
	Scopes          []string `json:"scopes"`
	IssuedAt        string   `json:"issued_at"`
	ExpiresAt       string   `json:"expires_at"`
	SecondsRemaining int64   `json:"seconds_remaining"`
	DAGVertex       string   `json:"dag_vertex"`
}

// Handle implements mcp.ToolHandler for acp_status.
func (t *ACPStatusTool) Handle(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if t.controlPlane == nil {
		return nil, nil, fmt.Errorf("acp_status: control plane not initialized")
	}

	creds := t.controlPlane.ListCredentials()
	var warnings []string
	summaries := make([]ACPCredentialSummary, 0, len(creds))

	for _, c := range creds {
		remaining := c.SecondsUntilExpiry()

		// Warn on credentials expiring within 10 minutes.
		if remaining < 600 && remaining > 0 {
			warnings = append(warnings, fmt.Sprintf("credential %s expires in %d seconds", c.ID, remaining))
		}

		summaries = append(summaries, ACPCredentialSummary{
			ID:              c.ID,
			AgentID:         c.AgentID,
			Symbol:          c.Symbol,
			Scopes:          c.Scopes,
			IssuedAt:        c.IssuedAt.UTC().Format(time.RFC3339),
			ExpiresAt:       c.ExpiresAt.UTC().Format(time.RFC3339),
			SecondsRemaining: remaining,
			DAGVertex:       c.DAGVertex,
		})
	}

	chainHash := t.controlPlane.AuditChainHash()

	resp := &ACPStatusResponse{
		ActiveCredentials: len(summaries),
		Credentials:       summaries,
		AuditChainHash:    fmt.Sprintf("%x", chainHash),
		ExpiryWarnings:    warnings,
		Timestamp:         time.Now().UTC().Format(time.RFC3339Nano),
	}

	return resp, warnings, nil
}

// ─── acp_issue (Destructive — requires confirmation) ───────────────────────────

// ACPIssueTool wraps pkg/acp.AgentControlPlane.IssueCredential for MCP.
type ACPIssueTool struct {
	controlPlane *acp.AgentControlPlane
}

// NewACPIssueTool creates an acp_issue tool.
func NewACPIssueTool(cp *acp.AgentControlPlane) *ACPIssueTool {
	return &ACPIssueTool{controlPlane: cp}
}

// Handle implements mcp.ToolHandler for acp_issue.
func (t *ACPIssueTool) Handle(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if t.controlPlane == nil {
		return nil, nil, fmt.Errorf("acp_issue: control plane not initialized")
	}

	agentID, _ := call.Args["agent_id"].(string)
	symbol, _ := call.Args["symbol"].(string)
	if agentID == "" {
		return nil, nil, fmt.Errorf("acp_issue: agent_id is required")
	}
	if symbol == "" {
		symbol = "Nkyinkyim"
	}

	// Extract scopes from args.
	var scopes []string
	if scopeArg, ok := call.Args["scopes"].([]any); ok {
		for _, s := range scopeArg {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
	}
	if len(scopes) == 0 {
		scopes = []string{"ert:scan"} // Minimum default scope
	}

	// Extract TTL (default 1 hour).
	ttl := acp.DefaultCredentialTTL
	if ttlMin, ok := call.Args["ttl_minutes"].(float64); ok && ttlMin > 0 {
		ttl = time.Duration(ttlMin) * time.Minute
	}

	cred, err := t.controlPlane.IssueCredential(agentID, symbol, scopes, ttl)
	if err != nil {
		return nil, nil, fmt.Errorf("acp_issue: %w", err)
	}

	return &ACPCredentialSummary{
		ID:              cred.ID,
		AgentID:         cred.AgentID,
		Symbol:          cred.Symbol,
		Scopes:          cred.Scopes,
		IssuedAt:        cred.IssuedAt.UTC().Format(time.RFC3339),
		ExpiresAt:       cred.ExpiresAt.UTC().Format(time.RFC3339),
		SecondsRemaining: cred.SecondsUntilExpiry(),
		DAGVertex:       cred.DAGVertex,
	}, nil, nil
}

// ─── acp_revoke (Destructive) ──────────────────────────────────────────────────

// ACPRevokeTool wraps pkg/acp.AgentControlPlane.RevokeCredential for MCP.
type ACPRevokeTool struct {
	controlPlane *acp.AgentControlPlane
}

// NewACPRevokeTool creates an acp_revoke tool.
func NewACPRevokeTool(cp *acp.AgentControlPlane) *ACPRevokeTool {
	return &ACPRevokeTool{controlPlane: cp}
}

// Handle implements mcp.ToolHandler for acp_revoke.
func (t *ACPRevokeTool) Handle(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	credID, _ := call.Args["credential_id"].(string)
	if credID == "" {
		return nil, nil, fmt.Errorf("acp_revoke: credential_id is required")
	}

	if err := t.controlPlane.RevokeCredential(credID); err != nil {
		return nil, nil, fmt.Errorf("acp_revoke: %w", err)
	}

	return map[string]any{
		"status":        "revoked",
		"credential_id": credID,
		"revoked_at":    time.Now().UTC().Format(time.RFC3339),
	}, nil, nil
}
